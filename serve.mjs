#!/usr/bin/env node
// serve.mjs — GHOSTPAY local server: static files + relayer endpoints.
//
//   RUNNER_PK=0x… node serve.mjs                              (PORT=8791)
//   TOR_PROXY=socks5://127.0.0.1:9050 RPC_URLS=https://a,https://b node serve.mjs
//
//   POST /announce  {stealth, ephPub, viewTag}  → announce(1, stealth, ephPub, metadata) on the
//                                                 ERC-5564 announcer from a runner wallet.
//   POST /sweep     <sweep artifact JSON>        → relay.mjs broadcast logic (type-4 / eip3009).
//
// Networking: every JSON-RPC call goes through rpcCall() with per-call random endpoint
// rotation (RPC_URLS, comma-separated) and optional Tor routing (TOR_PROXY, via
// socks-proxy-agent on a plain node https request; undici/fetch has no socks support).
// Broadcasting is eth_sendRawTransaction of locally signed transactions, preceded by a
// random jitter (announce 2-15s, sweep 5-45s) to break timing correlation between the
// browser request and the onchain broadcast.
//
// Runners: runners.local.json ([{"address","key"},…], random per request, preferring a
// different runner than the previous one) if present, else RUNNER_PK, else the endpoints
// return 503. Static serving works without a runner. Errors are clean JSON ({error}),
// never stack traces. Keys are never logged.
import http from 'http';
import https from 'https';
import { createServer } from 'http';
import { readFile, stat } from 'fs/promises';
import { extname, join, normalize, sep } from 'path';
import { fileURLToPath } from 'url';
import { ethers } from 'ethers';

// type-4 (EIP-7702) txs and authorizationList only exist in ethers >= 6.14 (see relay.mjs).
{
  const [maj, min] = ethers.version.split('.').map(Number);
  if (maj < 6 || (maj === 6 && min < 14)) {
    console.error('serve.mjs needs ethers >= 6.14 for EIP-7702 (type-4) txs; found', ethers.version);
    process.exit(1);
  }
}

const ROOT = fileURLToPath(new URL('.', import.meta.url));
const PORT = parseInt(process.env.PORT || '8791', 10);
const RPC_URLS = (process.env.RPC_URLS || process.env.RPC_URL || 'https://rpc.flashbots.net,https://eth.drpc.org,https://eth.merkle.io')
  .split(',').map(s => s.trim()).filter(Boolean);
const TOR_PROXY = process.env.TOR_PROXY || null;
const ANNOUNCER = '0x55649E01B5Df198D18D95b5cc5051630cfD45564'; // ERC-5564 announcer, mainnet (ANNOUNCER const in index.html)
const CHAIN_ID = 1;

// ── runners: runners.local.json (optional pool) or RUNNER_PK (single) ──
async function loadRunners() {
  try {
    const raw = JSON.parse(await readFile(new URL('./runners.local.json', import.meta.url), 'utf8'));
    if (Array.isArray(raw) && raw.length) {
      const wallets = [];
      for (const r of raw) {
        try { wallets.push(new ethers.Wallet(r.key)); }
        catch { console.warn('runners.local.json: skipping entry with an unparseable key (address field:', r && r.address, ')'); }
      }
      if (wallets.length) return wallets;
    }
    console.warn('runners.local.json: present but no usable entries — falling back to RUNNER_PK.');
  } catch { /* missing or malformed: fall through to RUNNER_PK */ }
  if (process.env.RUNNER_PK) {
    try { return [new ethers.Wallet(process.env.RUNNER_PK)]; }
    catch { console.error('RUNNER_PK is set but not a valid private key.'); return []; }
  }
  return [];
}
const runners = await loadRunners();
let lastRunner = null;
function pickRunner() {
  if (runners.length === 1) return runners[0];
  // prefer a different runner than the previous request when the pool allows it
  const pool = runners.filter(w => w !== lastRunner);
  return pool[Math.floor(Math.random() * pool.length)];
}
if (!runners.length) console.warn('no runner configured — /announce and /sweep return 503; static serving still works. Set RUNNER_PK or provide runners.local.json.');
else console.log('runners:', runners.map(w => w.address).join(', '));

// ── rpcCall: all Ethereum JSON-RPC, random endpoint per call, optional Tor ──
let torAgent = null;
if (TOR_PROXY) {
  const { SocksProxyAgent } = await import('socks-proxy-agent');
  torAgent = new SocksProxyAgent(TOR_PROXY);
}
function rpcCallOnce(url, method, params) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method, params });
    const u = new URL(url);
    const mod = u.protocol === 'http:' ? http : https;
    const req = mod.request({
      hostname: u.hostname,
      port: u.port || (u.protocol === 'http:' ? 80 : 443),
      path: u.pathname + u.search,
      method: 'POST',
      headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) },
      agent: torAgent || undefined,
      timeout: 20000,
    }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        try {
          const j = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          if (j.error) return reject(new Error(j.error.message || 'rpc error'));
          resolve(j.result);
        } catch {
          reject(new Error('bad rpc response from ' + u.hostname + ' (http ' + res.statusCode + ')'));
        }
      });
    });
    req.on('timeout', () => req.destroy(new Error('rpc timeout (20s)')));
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}
let lastEndpointHost = null; // for the one-line broadcast log (best-effort, single-user server)
async function rpcCall(method, params) {
  const order = RPC_URLS.slice().sort(() => Math.random() - 0.5);
  let lastErr;
  for (const url of order) {
    try {
      const result = await rpcCallOnce(url, method, params);
      lastEndpointHost = new URL(url).hostname;
      return result;
    } catch (e) { lastErr = e; }
  }
  throw lastErr;
}
const getNonce = addr => rpcCall('eth_getTransactionCount', [addr, 'pending']).then(x => parseInt(x, 16));
const getBalance = addr => rpcCall('eth_getBalance', [addr, 'latest']).then(BigInt);
// 2x fee bump, same as relay.mjs: sweeps must land even in a fee spike.
async function feeBump() {
  const gasPrice = BigInt(await rpcCall('eth_gasPrice', []));
  const fh = await rpcCall('eth_feeHistory', ['0x1', 'latest', [50]]).catch(() => null);
  const reward = fh && fh.reward && fh.reward[0] && fh.reward[0][0] ? BigInt(fh.reward[0][0]) : 1500000000n;
  // gasPrice and reward may come from DIFFERENT endpoints (random rotation), so the
  // priority fee can exceed the max fee. Base both on the larger value and clamp.
  const maxFee = (gasPrice > reward ? gasPrice : reward) * 2n;
  const priority = reward * 2n;
  return { maxFeePerGas: maxFee, maxPriorityFeePerGas: priority < maxFee ? priority : maxFee };
}
async function estimateGas(from, tx) {
  const call = { from, to: tx.to, data: tx.data || '0x' };
  // geth (post-Pectra) accounts for the delegation when the authorization list is
  // included; nodes that reject the field fall through to the type-4 fixed limit below.
  if (tx.authorizationList) call.authorizationList = tx.authorizationList.map(a => ({
    chainId: '0x' + BigInt(a.chainId).toString(16),
    address: a.address,
    nonce: '0x' + BigInt(a.nonce).toString(16),
    yParity: '0x' + a.signature.yParity.toString(16),
    r: a.signature.r,
    s: a.signature.s,
  }));
  try {
    const est = await rpcCall('eth_estimateGas', [call]);
    return BigInt(est) * 3n / 2n; // 50% headroom: delegation + sweep logic varies
  } catch (e) {
    // a call with data to a not-yet-delegated EOA estimates at plain-call cost, which
    // would brick a type-4 sweep out of gas; use a fixed limit instead (unused gas is refunded).
    if (tx.type === 4) return 500000n;
    throw new Error('gas estimation failed (' + errMsg(e) + ') — the runner is likely unfunded or the tx would revert');
  }
}

// ── broadcast: populate via rpcCall, sign locally, jitter, eth_sendRawTransaction ──
async function broadcast(runner, tx, jitterRange, label) {
  tx.chainId = CHAIN_ID;
  tx.nonce = await getNonce(runner.address);
  Object.assign(tx, await feeBump());
  if (!tx.gasLimit) tx.gasLimit = await estimateGas(runner.address, tx);
  const signed = await runner.signTransaction(tx);
  const delayedSec = Math.round(jitterRange[0] + Math.random() * (jitterRange[1] - jitterRange[0]));
  await new Promise(r => setTimeout(r, delayedSec * 1000));
  const hash = await rpcCall('eth_sendRawTransaction', [signed]);
  console.log(`broadcast ${label}: endpoint=${lastEndpointHost} runner=${runner.address} delay=${delayedSec}s hash=${hash}`);
  return { hash, runner: runner.address, delayedSec };
}

const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.mjs': 'text/javascript',
  '.css': 'text/css', '.json': 'application/json', '.sol': 'text/plain; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8', '.md': 'text/plain; charset=utf-8',
  '.png': 'image/png', '.svg': 'image/svg+xml', '.ico': 'image/x-icon',
};

function sendJson(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) });
  res.end(body);
}
const errMsg = e => (e && (e.shortMessage || e.reason || e.message)) || String(e);

async function readBody(req) {
  const chunks = []; let size = 0;
  for await (const c of req) {
    size += c.length;
    if (size > 1024 * 1024) throw Object.assign(new Error('body too large'), { status: 400 });
    chunks.push(c);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw Object.assign(new Error('body is not valid JSON'), { status: 400 });
  }
}

async function handleAnnounce(body) {
  const { stealth, ephPub, viewTag } = body || {};
  if (!ethers.isAddress(stealth)) throw Object.assign(new Error('bad stealth address'), { status: 400 });
  if (typeof ephPub !== 'string' || !/^0x[0-9a-fA-F]{66}$/.test(ephPub)) throw Object.assign(new Error('bad ephPub (expected 33-byte compressed point)'), { status: 400 });
  const tag = Number(viewTag);
  if (!Number.isInteger(tag) || tag < 0 || tag > 255) throw Object.assign(new Error('bad viewTag (expected 0-255)'), { status: 400 });
  const iface = new ethers.Interface(['function announce(uint256,address,bytes,bytes)']);
  // metadata is the 1-byte view tag as bytes — exactly how the app's announce call encodes it,
  // and how scan() decodes it (AbiCoder decode of ['bytes','bytes'] from log data).
  const data = iface.encodeFunctionData('announce', [1, stealth, ephPub, Uint8Array.from([tag])]);
  const runner = pickRunner();
  lastRunner = runner;
  return broadcast(runner, { to: ANNOUNCER, data }, [2, 15], 'announce');
}

async function handleSweep(artifact) {
  if (!artifact || typeof artifact !== 'object') throw Object.assign(new Error('missing artifact'), { status: 400 });
  if (artifact.kind === 'eip3009') {
    const iface = new ethers.Interface([
      'function transferWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, uint8 v, bytes32 r, bytes32 s)']);
    const sig = ethers.Signature.from(artifact.signature);
    const data = iface.encodeFunctionData('transferWithAuthorization', [
      artifact.from, artifact.to, artifact.value, artifact.validAfter, artifact.validBefore, artifact.nonce,
      sig.v, sig.r, sig.s]);
    const runner = pickRunner();
    lastRunner = runner;
    return broadcast(runner, { to: artifact.token, data }, [5, 45], 'sweep/eip3009');
  }
  if (artifact.kind === 'eip7702-sweep') {
    // ethers does not treat a bare {chainId,address,nonce,yParity,r,s} object as carrying the
    // signature — it serializes r/s as ZERO. Wrap it explicitly (proven construction from relay.mjs).
    const a = artifact.authorization;
    const authorization = {
      chainId: a.chainId,
      address: a.address,
      nonce: a.nonce,
      signature: ethers.Signature.from({ r: a.r, s: a.s, yParity: a.yParity }),
    };
    // preflight: log what we were asked to do and catch the two common reverts with clear errors.
    const bal = await getBalance(artifact.stealthAddress);
    const nonce = await getNonce(artifact.stealthAddress);
    console.log(`sweep request: stealth=${artifact.stealthAddress} balance=${ethers.formatEther(bal)} ETH nonce=${nonce} authNonce=${a.nonce} data=${String(artifact.data).slice(0, 10)}`);
    if (Number(a.nonce) !== nonce) {
      throw Object.assign(new Error(`stale authorization: stealth EOA nonce is ${nonce} but the artifact was signed for ${a.nonce} — re-scan and SIGN SWEEP again in the app`), { status: 400 });
    }
    const PP_MIN = ethers.parseEther('0.01');
    if (String(artifact.data).startsWith('0x3b25c4fa') && bal < PP_MIN) {
      throw Object.assign(new Error(`stealth balance ${ethers.formatEther(bal)} ETH is below the Privacy Pools 0.01 ETH minimum — top up the stealth address first`), { status: 400 });
    }
    const runner = pickRunner();
    lastRunner = runner;
    try {
      return await broadcast(runner, {
        type: 4,
        to: artifact.stealthAddress,
        data: artifact.data,
        authorizationList: [authorization],
      }, [5, 45], 'sweep/7702');
    } catch (e) {
      console.error('sweep broadcast failed:', errMsg(e), '| revert data:', e.data || (e.info && e.info.error && e.info.error.data) || '(none)');
      throw e;
    }
  }
  throw Object.assign(new Error('unknown artifact kind: ' + artifact.kind), { status: 400 });
}

async function serveStatic(req, res, pathname) {
  let rel;
  try { rel = decodeURIComponent(pathname); } catch { sendJson(res, 400, { error: 'bad path' }); return; }
  const file = normalize(join(ROOT, rel === '/' ? 'index.html' : rel));
  if (file !== ROOT && !file.startsWith(ROOT.endsWith(sep) ? ROOT : ROOT + sep)) { sendJson(res, 403, { error: 'forbidden' }); return; }
  try {
    const st = await stat(file);
    if (st.isDirectory()) { sendJson(res, 403, { error: 'forbidden' }); return; }
    const data = await readFile(file);
    res.writeHead(200, { 'Content-Type': MIME[extname(file).toLowerCase()] || 'application/octet-stream', 'Content-Length': data.length });
    res.end(data);
  } catch {
    sendJson(res, 404, { error: 'not found' });
  }
}

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost');
    if (req.method === 'POST' && (url.pathname === '/announce' || url.pathname === '/sweep')) {
      if (!runners.length) return sendJson(res, 503, { error: 'relayer not configured: set RUNNER_PK or provide runners.local.json and restart serve.mjs (static serving is unaffected)' });
      try {
        const body = await readBody(req);
        const out = url.pathname === '/announce' ? await handleAnnounce(body) : await handleSweep(body);
        sendJson(res, 200, out);
      } catch (e) {
        sendJson(res, e.status || 500, { error: errMsg(e) });
      }
      return;
    }
    if (req.method === 'GET' || req.method === 'HEAD') return serveStatic(req, res, url.pathname);
    sendJson(res, 405, { error: 'method not allowed' });
  } catch (e) {
    sendJson(res, 500, { error: errMsg(e) });
  }
});

server.listen(PORT, () => console.log(
  `GHOSTPAY serving ${ROOT} on http://localhost:${PORT}/ (rpc: ${RPC_URLS.map(u => new URL(u).hostname).join(', ')}${TOR_PROXY ? ', rpc via Tor ' + TOR_PROXY : ''})`));
