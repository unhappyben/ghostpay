#!/usr/bin/env node
// serve.mjs — GHOSTPAY local server: static files + relayer endpoints.
//
//   RUNNER_PK=0x… node serve.mjs            (PORT=8791, RPC_URL optional)
//
//   POST /announce  {stealth, ephPub, viewTag}  → announce(1, stealth, ephPub, metadata) on the
//                                                 ERC-5564 announcer from the runner wallet.
//   POST /sweep     <sweep artifact JSON>        → relay.mjs broadcast logic (type-4 / eip3009).
//
// Static serving works without RUNNER_PK; the endpoints then return 503 with a clear message.
// Errors are always clean JSON ({error}), never stack traces.
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
const RPC_URL = process.env.RPC_URL || 'https://eth.drpc.org'; // set RPC_URL to your own endpoint (paid keys stay out of the repo)
const ANNOUNCER = '0x55649E01B5Df198D18D95b5cc5051630cfD45564'; // ERC-5564 announcer, mainnet (ANNOUNCER const in index.html)
const CHAIN_ID = 1;

const provider = new ethers.JsonRpcProvider(RPC_URL, CHAIN_ID);
const runner = process.env.RUNNER_PK ? new ethers.Wallet(process.env.RUNNER_PK, provider) : null;
if (!runner) console.warn('RUNNER_PK unset — /announce and /sweep return 503; static serving still works.');
else console.log('runner:', runner.address);

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

// 2x fee bump, same as relay.mjs: sweeps must land even in a fee spike.
async function feeBump() {
  const fee = await provider.getFeeData();
  return { maxFeePerGas: fee.maxFeePerGas * 2n, maxPriorityFeePerGas: fee.maxPriorityFeePerGas * 2n };
}

async function handleAnnounce(body) {
  const { stealth, ephPub, viewTag } = body || {};
  if (!ethers.isAddress(stealth)) throw Object.assign(new Error('bad stealth address'), { status: 400 });
  if (typeof ephPub !== 'string' || !/^0x[0-9a-fA-F]{66}$/.test(ephPub)) throw Object.assign(new Error('bad ephPub (expected 33-byte compressed point)'), { status: 400 });
  const tag = Number(viewTag);
  if (!Number.isInteger(tag) || tag < 0 || tag > 255) throw Object.assign(new Error('bad viewTag (expected 0-255)'), { status: 400 });
  const ann = new ethers.Contract(ANNOUNCER, ['function announce(uint256,address,bytes,bytes)'], runner);
  // metadata is the 1-byte view tag as bytes — exactly how the app's announce call encodes it,
  // and how scan() decodes it (AbiCoder decode of ['bytes','bytes'] from log data).
  const tx = await ann.announce(1, stealth, ephPub, Uint8Array.from([tag]), await feeBump());
  return { hash: tx.hash };
}

async function handleSweep(artifact) {
  if (!artifact || typeof artifact !== 'object') throw Object.assign(new Error('missing artifact'), { status: 400 });
  if (artifact.kind === 'eip3009') {
    const usdc = new ethers.Contract(artifact.token, [
      'function transferWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, uint8 v, bytes32 r, bytes32 s)'],
      runner);
    const sig = ethers.Signature.from(artifact.signature);
    const tx = await usdc.transferWithAuthorization(
      artifact.from, artifact.to, artifact.value, artifact.validAfter, artifact.validBefore, artifact.nonce,
      sig.v, sig.r, sig.s, await feeBump());
    return { hash: tx.hash };
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
    const bal = await provider.getBalance(artifact.stealthAddress);
    const nonce = await provider.getTransactionCount(artifact.stealthAddress);
    console.log(`sweep request: stealth=${artifact.stealthAddress} balance=${ethers.formatEther(bal)} ETH nonce=${nonce} authNonce=${a.nonce} data=${String(artifact.data).slice(0, 10)}`);
    if (Number(a.nonce) !== nonce) {
      throw Object.assign(new Error(`stale authorization: stealth EOA nonce is ${nonce} but the artifact was signed for ${a.nonce} — re-scan and SIGN SWEEP again in the app`), { status: 400 });
    }
    const PP_MIN = ethers.parseEther('0.01');
    if (String(artifact.data).startsWith('0x3b25c4fa') && bal < PP_MIN) {
      throw Object.assign(new Error(`stealth balance ${ethers.formatEther(bal)} ETH is below the Privacy Pools 0.01 ETH minimum — top up the stealth address first`), { status: 400 });
    }
    try {
      const tx = await runner.sendTransaction({
        type: 4,
        chainId: artifact.chainId,
        to: artifact.stealthAddress,
        data: artifact.data,
        authorizationList: [authorization],
        ...await feeBump(),
      });
      console.log('sweep sent:', tx.hash);
      return { hash: tx.hash };
    } catch (e) {
      console.error('sweep broadcast failed:', e.message, '| revert data:', e.data || (e.info && e.info.error && e.info.error.data) || '(none)');
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
      if (!runner) return sendJson(res, 503, { error: 'relayer not configured: set RUNNER_PK and restart serve.mjs (static serving is unaffected)' });
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

server.listen(PORT, () => console.log(`GHOSTPAY serving ${ROOT} on http://localhost:${PORT}/ (rpc: ${RPC_URL})`));
