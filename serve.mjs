#!/usr/bin/env node
// serve.mjs — GHOSTPAY local server: static files + relayer endpoints.
//
//   RUNNER_PK=0x… node serve.mjs                              (PORT=8791)
//   TOR_PROXY=socks5://127.0.0.1:9050 RPC_URLS=https://a,https://b node serve.mjs
//
//   POST /announce  {stealth, ephPub, viewTag, metadata?} → announce(1, stealth, ephPub, metadata) on
//                                                 the ERC-5564 announcer from a runner wallet. metadata
//                                                 is optional 0x-hex (1-1024 bytes, e.g. viewTag +
//                                                 encrypted memo); default is the 1-byte viewTag.
//   POST /sweep     <sweep artifact JSON>        → relay.mjs broadcast logic (type-4 / eip3009 /
//                                                 eip7702-intent / eip7702-intent-batch). A batch sweep
//                                                 shares one tx: the swept addresses are linked onchain.
//   POST /pp-withdraw <withdrawal payload>       → Privacy Pools withdrawal relay (PP_RELAY=1 only,
//                                                 else 503). Same payload shape the app sends to
//                                                 fastrelay.xyz: {chainId, scope, withdrawal, proof,
//                                                 publicSignals, feeCommitment?}. The circuit binds the
//                                                 fee recipient + relayFeeBPS via the context signal:
//                                                 the fee recipient must be one of this server's runner
//                                                 addresses and relayFeeBPS must not exceed PP_FEE_BPS
//                                                 (default 25). The runner pays gas; the fee accrues
//                                                 onchain to the runner inside the withdrawal itself.
//   GET  /health    relayer status JSON (runners, sweeperV2, batchRelayer, feeOwner, tor,
//                                                 endpoints; never keys).
//                                                 With PP_RELAY=1 it also advertises ppRelay + ppFeeBps
//                                                 so the app can discover this relay and price proofs.
//   GET  /fee       {minFeeBps}: relayer fee floor for intent sweeps (MIN_FEE_BPS, default 30).
//   GET  /price     ETH + USDC USD prices proxied from CoinGecko with a 60s cache, so the price
//                                                 fetch stays out of the user's browser.
//   GET  /status/0x…  tx receipt status: confirmed | failed | pending.
//
// Fee ledger: every successful fee-bearing broadcast appends one JSON line to fees.jsonl
// ({ts, kind, feeBps, estFeeWei, txHash, runner}; see fees.mjs, run `node fees.mjs` for the
// revenue report). Announce requests carry no fee and are never logged.
//
// Fee auto-forward (FEE_OWNER): every FEE_SWEEP_MINUTES (default 60, first sweep 5 min after
// boot) each runner sends its ETH balance above FEE_RESERVE_ETH (default 0.005) to FEE_OWNER
// as a type-2 transfer, logged to fees.jsonl as kind "fee-forward". Unset disables it.
//
// Networking: every JSON-RPC call goes through rpcCall() with per-call random endpoint
// rotation (RPC_URLS, comma-separated) and optional Tor routing (TOR_PROXY, via
// socks-proxy-agent on a plain node https request; undici/fetch has no socks support).
// Broadcasting is eth_sendRawTransaction of locally signed transactions over BROADCAST_URLS
// (comma-separated, default https://rpc.flashbots.net; used ONLY for broadcasts, every read
// stays on the RPC_URLS rotation), preceded by a random jitter (announce 2-15s, sweep 5-45s)
// to break timing correlation between the browser request and the onchain broadcast.
//
// Abuse protection: per-IP token buckets on the write endpoints (/announce 10/min, /sweep
// and /pp-withdraw 5/min; 429 with Retry-After, in-memory, reset on restart). With
// GHOSTPAY_API_TOKEN set, /sweep and /pp-withdraw also require 'authorization: Bearer
// <token>' (constant-time compare, 401 otherwise); /announce and the GET endpoints stay
// open. GET /health reports rateLimited/authRequired, never the token itself.
//
// Runners: runners.local.json ([{"address","key"},…], random per request, preferring a
// different runner than the previous one) if present, else RUNNER_PK, else the endpoints
// return 503. Static serving works without a runner. Errors are clean JSON ({error}),
// never stack traces. Keys are never logged.
import http from 'http';
import https from 'https';
import { createServer } from 'http';
import { createHash, timingSafeEqual } from 'crypto';
import { readFile, writeFile, appendFile, stat } from 'fs/promises';
import { extname, join, normalize, sep } from 'path';
import { fileURLToPath } from 'url';
import { ethers } from 'ethers';
import { logFee } from './fees.mjs';

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
const BROADCAST_URLS = (process.env.BROADCAST_URLS || 'https://rpc.flashbots.net?fast=true')
  .split(',').map(s => s.trim()).filter(Boolean);
const TOR_PROXY = process.env.TOR_PROXY || null;
const ANNOUNCER = '0x55649E01B5Df198D18D95b5cc5051630cfD45564'; // ERC-5564 announcer, mainnet (ANNOUNCER const in index.html)
const CHAIN_ID = 1;
const MIN_FEE_BPS = Number.isFinite(parseInt(process.env.MIN_FEE_BPS, 10)) ? parseInt(process.env.MIN_FEE_BPS, 10) : 30;
// fee auto-forward: runner fees accrue onchain (tx.origin on intent sweeps, feeRecipient on
// pp withdrawals). Unset FEE_OWNER disables the forwarder entirely; a bad address fails boot.
const FEE_OWNER = (() => {
  const v = process.env.FEE_OWNER;
  if (!v) return null;
  if (!ethers.isAddress(v)) { console.error('FEE_OWNER is set but not a valid 0x address.'); process.exit(1); }
  return ethers.getAddress(v);
})();
const FEE_RESERVE_ETH = Number(process.env.FEE_RESERVE_ETH) > 0 ? Number(process.env.FEE_RESERVE_ETH) : 0.005;
const FEE_SWEEP_MINUTES = parseInt(process.env.FEE_SWEEP_MINUTES, 10) > 0 ? parseInt(process.env.FEE_SWEEP_MINUTES, 10) : 60;
const SWEEPER_V2 = process.env.SWEEPER_V2 || null;    // SweeperV2 deployed: gates eip7702-intent sweeps
const BATCH_RELAYER = process.env.BATCH_RELAYER || null; // BatchRelayer deployed: gates eip7702-intent-batch
const PP_RELAY = process.env.PP_RELAY === '1';        // gates POST /pp-withdraw (Privacy Pools withdrawal relay)
const PP_FEE_BPS = Number.isFinite(parseInt(process.env.PP_FEE_BPS, 10)) ? parseInt(process.env.PP_FEE_BPS, 10) : 25;
const PP_ENTRYPOINT = '0x6818809EefCe719E480a7526D76bD3e561526b46'; // Privacy Pools entrypoint, mainnet
const PP_SCOPE = 4916574638117198869413701114161172350986437430914933850166949084132905299523n; // mainnet ETH pool scope
const SNARK_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// ── abuse protection: the write endpoints cost the runner gas, so a public relayer needs
// a brake. Per-IP token buckets (Map keyed by endpoint + IP, refilled lazily, in-memory
// so they reset on restart: a brake, not a quota). Limited requests get 429 + Retry-After.
const RATE_LIMITS = { '/announce': 10, '/sweep': 5, '/pp-withdraw': 5 }; // requests per minute per IP
const rateBuckets = new Map(); // '<path>|<ip>' -> { tokens, last }
// returns 0 when the request may proceed, else seconds until a token refills (Retry-After)
function rateLimit(path, ip) {
  const cap = RATE_LIMITS[path];
  const now = Date.now();
  if (rateBuckets.size > 10000) { // bound memory against source-IP sprays
    for (const [k, v] of rateBuckets) if (now - v.last > 10 * 60 * 1000) rateBuckets.delete(k);
  }
  const key = path + '|' + ip;
  let b = rateBuckets.get(key);
  if (!b) { b = { tokens: cap, last: now }; rateBuckets.set(key, b); }
  b.tokens = Math.min(cap, b.tokens + (now - b.last) * cap / 60000);
  b.last = now;
  if (b.tokens < 1) return Math.ceil((1 - b.tokens) * 60000 / cap / 1000);
  b.tokens -= 1;
  return 0;
}
// optional shared-secret auth (GHOSTPAY_API_TOKEN): /sweep and /pp-withdraw require
// 'authorization: Bearer <token>' when set; /announce and the GET endpoints stay open.
const API_TOKEN = process.env.GHOSTPAY_API_TOKEN || null;
function checkApiToken(req) {
  const header = req.headers.authorization || '';
  const presented = header.startsWith('Bearer ') ? header.slice(7) : '';
  // hash both sides so timingSafeEqual never leaks the length of either string
  const a = createHash('sha256').update(presented).digest();
  const b = createHash('sha256').update(API_TOKEN).digest();
  return timingSafeEqual(a, b);
}
if (API_TOKEN) console.log('api auth on: /sweep and /pp-withdraw require Authorization: Bearer <GHOSTPAY_API_TOKEN> (the token itself is never logged)');

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
if (!runners.length) console.warn('no runner configured — /announce, /sweep and /pp-withdraw return 503; static serving still works. Set RUNNER_PK or provide runners.local.json.');
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
async function rpcCall(method, params) {
  const order = RPC_URLS.slice().sort(() => Math.random() - 0.5);
  let lastErr;
  for (const url of order) {
    try {
      return await rpcCallOnce(url, method, params);
    } catch (e) { lastErr = e; }
  }
  throw lastErr;
}
// broadcasts go ONLY to BROADCAST_URLS (random order per broadcast), never to the read rotation.
async function broadcastRawTx(signed) {
  const order = BROADCAST_URLS.slice().sort(() => Math.random() - 0.5);
  let lastErr;
  for (const url of order) {
    try {
      const hash = await rpcCallOnce(url, 'eth_sendRawTransaction', [signed]);
      return { hash, host: new URL(url).hostname };
    } catch (e) { lastErr = e; }
  }
  throw lastErr;
}
const getNonce = addr => rpcCall('eth_getTransactionCount', [addr, 'pending']).then(x => parseInt(x, 16));
const getBalance = addr => rpcCall('eth_getBalance', [addr, 'latest']).then(BigInt);
// /health runner balances: 30s cache, best-effort per runner (an RPC failure yields null
// for that runner, never a failed health check).
let balCache = { ts: 0, map: {} };
async function runnerBalances() {
  if (Date.now() - balCache.ts < 30000) return balCache.map;
  const map = {};
  for (const w of runners) {
    map[w.address] = await getBalance(w.address).then(b => Number(b) / 1e18).catch(() => null);
  }
  balCache = { ts: Date.now(), map };
  return map;
}
// 2x fee bump, same as relay.mjs: sweeps must land even in a fee spike.
// priority fee floor (MIN_PRIORITY_WEI, default 0.1 gwei): at ultra-low gas prices a 2x
// bump produces a priority fee so small that builders skip the tx entirely (Protect dropped
// two announces and a sweep this way on 2026-09-12). The floor costs cents per tx and buys
// prompt inclusion.
const MIN_PRIORITY_WEI = BigInt(process.env.MIN_PRIORITY_WEI || '100000000');
async function feeBump() {
  const gasPrice = BigInt(await rpcCall('eth_gasPrice', []));
  const fh = await rpcCall('eth_feeHistory', ['0x1', 'latest', [50]]).catch(() => null);
  const reward = fh && fh.reward && fh.reward[0] && fh.reward[0][0] ? BigInt(fh.reward[0][0]) : 1500000000n;
  // gasPrice and reward may come from DIFFERENT endpoints (random rotation), so the
  // priority fee can exceed the max fee. Base both on the larger value and clamp.
  let priority = reward * 2n;
  if (priority < MIN_PRIORITY_WEI) priority = MIN_PRIORITY_WEI;
  let maxFee = (gasPrice > reward ? gasPrice : reward) * 2n;
  if (maxFee < priority) maxFee = priority;
  return { maxFeePerGas: maxFee, maxPriorityFeePerGas: priority };
}
async function estimateGas(from, tx, label) {
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
    // the fallback applies ONLY to the proven v1 eip7702-sweep flow: an intent sweep that
    // fails estimation is malformed or would revert, and must never burn runner gas onchain.
    if (tx.type === 4 && label !== 'sweep/7702-intent' && label !== 'sweep/7702-intent-batch') return 500000n;
    throw new Error('gas estimation failed (' + errMsg(e) + ') — the runner is likely unfunded or the tx would revert');
  }
}

// ── broadcast: populate via rpcCall, sign locally, jitter, eth_sendRawTransaction ──
// Runner nonces are tracked locally: our broadcasts go to Flashbots Protect's PRIVATE
// mempool, which public endpoints cannot see, so their 'pending' nonce goes stale after
// the first in-flight tx and would hand out the same nonce twice (two announces lost to
// this on 2026-09-12). Seed once from the network, then increment on every accepted send.
const nonceCache = new Map(); // runner address (lowercase) -> next nonce
async function nextNonce(runner) {
  const a = runner.address.toLowerCase();
  if (!nonceCache.has(a)) nonceCache.set(a, await getNonce(runner.address));
  return nonceCache.get(a);
}
async function broadcast(runner, tx, jitterRange, label) {
  tx.chainId = CHAIN_ID;
  tx.nonce = await nextNonce(runner);
  Object.assign(tx, await feeBump());
  if (!tx.gasLimit) tx.gasLimit = await estimateGas(runner.address, tx, label);
  // affordability preflight: Flashbots Protect ACCEPTS unfunded transactions (returns a
  // hash, then never includes them), so an empty runner produces phantom "pending" txs
  // that explorers never find. Refuse loudly instead of broadcasting into the void.
  const cost = tx.gasLimit * tx.maxFeePerGas + BigInt(tx.value || 0);
  const bal = await getBalance(runner.address);
  if (bal < cost) {
    throw Object.assign(new Error(`runner ${runner.address} cannot afford this broadcast: balance ${ethers.formatEther(bal)} ETH, needs ~${ethers.formatEther(cost)} ETH for gas · fund the runner and retry`), { status: 400 });
  }
  const signed = await runner.signTransaction(tx);
  const delayedSec = Math.round(jitterRange[0] + Math.random() * (jitterRange[1] - jitterRange[0]));
  await new Promise(r => setTimeout(r, delayedSec * 1000));
  const { hash, host } = await broadcastRawTx(signed);
  nonceCache.set(runner.address.toLowerCase(), tx.nonce + 1); // only after the send was accepted
  console.log(`broadcast ${label}: broadcast=${host} runner=${runner.address} delay=${delayedSec}s hash=${hash}`);
  return { hash, runner: runner.address, delayedSec };
}

const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.mjs': 'text/javascript',
  '.css': 'text/css', '.json': 'application/json', '.sol': 'text/plain; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8', '.md': 'text/plain; charset=utf-8',
  '.png': 'image/png', '.svg': 'image/svg+xml', '.ico': 'image/x-icon',
};

function sendJson(res, code, obj, headers = {}) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body), ...headers });
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

async function handleAnnounce(body, attempts = 1) {
  const { stealth, ephPub, viewTag } = body || {};
  if (!ethers.isAddress(stealth)) throw Object.assign(new Error('bad stealth address'), { status: 400 });
  if (typeof ephPub !== 'string' || !/^0x[0-9a-fA-F]{66}$/.test(ephPub)) throw Object.assign(new Error('bad ephPub (expected 33-byte compressed point)'), { status: 400 });
  // optional packed metadata (viewTag + encrypted memo) is used verbatim; otherwise the
  // metadata is the 1-byte view tag as bytes — exactly how the app's announce call encodes it,
  // and how scan() decodes it (AbiCoder decode of ['bytes','bytes'] from log data).
  let metadata;
  if (body.metadata !== undefined && body.metadata !== null) {
    if (typeof body.metadata !== 'string' || !/^0x(?:[0-9a-fA-F]{2}){1,1024}$/.test(body.metadata)) {
      throw Object.assign(new Error('bad metadata (expected 0x-prefixed hex, 1-1024 bytes)'), { status: 400 });
    }
    metadata = body.metadata;
  } else {
    const tag = Number(viewTag);
    if (!Number.isInteger(tag) || tag < 0 || tag > 255) throw Object.assign(new Error('bad viewTag (expected 0-255)'), { status: 400 });
    metadata = Uint8Array.from([tag]);
  }
  const iface = new ethers.Interface(['function announce(uint256,address,bytes,bytes)']);
  const data = iface.encodeFunctionData('announce', [1, stealth, ephPub, metadata]);
  const runner = pickRunner();
  lastRunner = runner;
  const out = await broadcast(runner, { to: ANNOUNCER, data }, [2, 15], 'announce');
  await journalBroadcast({ kind: 'announce', hash: out.hash, runner: runner.address, attempts,
    payload: { stealth, ephPub, metadata: ethers.hexlify(metadata) } });
  return out;
}

// ── broadcast journal + reaper: find failed broadcasts and rebroadcast them ──
// Announces are deterministic from (stealth, ephPub, metadata), so any broadcast with no
// onchain receipt after a grace window can be rebuilt and re-sent with a fresh nonce.
// Exists because Flashbots Protect silently drops transactions it cannot include: two
// announces were lost that way on 2026-09-12 (before local nonce tracking). The reaper
// checks the journal every 5 minutes, confirms what landed, and rebroadcasts the rest,
// up to 4 attempts per payload. Sweeps are not journaled: their artifacts stay valid in
// the app and retrying is a user decision. Journal: broadcasts.jsonl (gitignored).
const JOURNAL_FILE = new URL('./broadcasts.jsonl', import.meta.url);
const REAPER_GRACE_MS = 6 * 60 * 1000;   // Protect can take a few minutes to include
const REAPER_MAX_ATTEMPTS = 4;
async function journalBroadcast(entry) {
  try { await appendFile(JOURNAL_FILE, JSON.stringify({ ts: Date.now(), ...entry }) + '\n'); }
  catch (e) { console.error('journal write failed:', errMsg(e)); }
}
async function readJournal() {
  try {
    const raw = await readFile(JOURNAL_FILE, 'utf8');
    return raw.split('\n').filter(Boolean).map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
  } catch { return []; }
}
async function writeJournal(entries) {
  const cutoff = Date.now() - 7 * 24 * 60 * 60 * 1000; // drop completed entries after a week
  const keep = entries.filter(e => !e.done || e.ts > cutoff);
  try { await writeFile(JOURNAL_FILE, keep.length ? keep.map(e => JSON.stringify(e)).join('\n') + '\n' : ''); }
  catch (e) { console.error('journal write failed:', errMsg(e)); }
}
async function reaperTick() {
  const entries = await readJournal();
  let changed = false;
  for (const e of entries) {
    if (e.done) continue;
    const rcpt = await rpcCall('eth_getTransactionReceipt', [e.hash]).catch(() => null);
    if (rcpt) {
      e.done = true; e.finalStatus = rcpt.status === '0x1' ? 'confirmed' : 'reverted'; changed = true;
      if (e.finalStatus === 'reverted') console.error(`reaper: ${e.kind} tx REVERTED onchain: ${e.hash} (payload kept in the journal, needs a manual look)`);
      continue;
    }
    if (Date.now() - e.ts < REAPER_GRACE_MS) continue;
    if ((e.attempts || 1) >= REAPER_MAX_ATTEMPTS) {
      e.done = true; e.finalStatus = 'given-up'; changed = true;
      console.error(`reaper: gave up on ${e.kind} ${e.hash} after ${e.attempts} broadcasts (payload kept in the journal)`);
      continue;
    }
    if (e.kind !== 'announce' && e.kind !== 'sweep-intent') { e.done = true; e.finalStatus = 'untracked'; changed = true; continue; }
    try {
      console.log(`reaper: no receipt for ${e.kind} ${e.hash} after grace, rebroadcasting (attempt ${(e.attempts || 1) + 1})`);
      const out = e.kind === 'announce'
        ? await handleAnnounce({ stealth: e.payload.stealth, ephPub: e.payload.ephPub, metadata: e.payload.metadata }, (e.attempts || 1) + 1)
        : await handleSweep(e.payload, (e.attempts || 1) + 1);
      e.done = true; e.finalStatus = 'replaced'; e.replacedBy = out.hash; changed = true;
    } catch (err) { console.error('reaper: rebroadcast failed:', errMsg(err)); }
  }
  if (changed) {
    // rebroadcasts appended fresh journal lines during this tick; re-read and fold the
    // done-markings in by hash so nothing is lost or duplicated
    const latest = await readJournal();
    for (const e of latest) {
      const u = entries.find(x => x.hash === e.hash);
      if (u && u.done) Object.assign(e, { done: u.done, finalStatus: u.finalStatus, replacedBy: u.replacedBy });
    }
    await writeJournal(latest);
  }
}
if (runners.length) {
  const first = setTimeout(() => { reaperTick(); setInterval(reaperTick, 5 * 60 * 1000).unref(); }, 10 * 60 * 1000);
  first.unref();
}

// ── SweeperV2 intents: an EIP-712 SweepIntent signed by the stealth key, executed via
// executeSweep(intent, sig) on the stealth EOA once delegated to SweeperV2 (type-4 tx). ──
const INTENT_TYPES = { SweepIntent: [
  { name: 'action', type: 'uint8' },
  { name: 'token', type: 'address' },
  { name: 'destination', type: 'address' },
  { name: 'precommitment', type: 'uint256' },
  { name: 'feeBps', type: 'uint256' },
  { name: 'deadline', type: 'uint256' },
] };
const intentDomain = stealthAddress =>
  ({ name: 'GhostpaySweeper', version: '1', chainId: CHAIN_ID, verifyingContract: stealthAddress });
// tuple components are named so encodeFunctionData accepts an intent object; the selector
// (0x89cb3125) is identical to the unnamed-components ABI since names never enter the canonical type.
const SWEEPER_IFACE = new ethers.Interface(['function executeSweep((uint8 action,address token,address destination,uint256 precommitment,uint256 feeBps,uint256 deadline) intent, bytes sig)']);
const BATCH_IFACE = new ethers.Interface(['function relay(address[] targets, bytes[] datas)']);

// ethers does not treat a bare {chainId,address,nonce,yParity,r,s} object as carrying the
// signature — it serializes r/s as ZERO. Wrap it explicitly (proven construction from relay.mjs).
function wrapAuthorization(a) {
  return {
    chainId: a.chainId,
    address: a.address,
    nonce: a.nonce,
    signature: ethers.Signature.from({ r: a.r, s: a.s, yParity: a.yParity }),
  };
}

// preflight: the intent must be signed by the stealth key itself, unexpired, and pay the fee floor.
function verifyIntent(sweep) {
  const { stealthAddress, intent, signature } = sweep || {};
  if (!ethers.isAddress(stealthAddress)) throw Object.assign(new Error('bad stealthAddress'), { status: 400 });
  if (!intent || typeof intent !== 'object') throw Object.assign(new Error('missing intent'), { status: 400 });
  let digest;
  try {
    digest = ethers.TypedDataEncoder.hash(intentDomain(stealthAddress), INTENT_TYPES, intent);
  } catch (e) {
    throw Object.assign(new Error('bad intent: ' + errMsg(e)), { status: 400 });
  }
  let recovered;
  try { recovered = ethers.recoverAddress(digest, signature); }
  catch { throw Object.assign(new Error('bad intent signature'), { status: 400 }); }
  if (recovered.toLowerCase() !== stealthAddress.toLowerCase()) {
    throw Object.assign(new Error(`intent signer ${recovered} does not match stealthAddress ${stealthAddress}`), { status: 400 });
  }
  if (BigInt(intent.deadline) <= BigInt(Math.floor(Date.now() / 1000))) {
    throw Object.assign(new Error('intent deadline has passed — sign a fresh sweep in the app'), { status: 400 });
  }
  if (BigInt(intent.feeBps) < BigInt(MIN_FEE_BPS)) {
    throw Object.assign(new Error(`intent feeBps ${intent.feeBps} is below the relayer minimum of ${MIN_FEE_BPS}`), { status: 400 });
  }
}

async function handleSweep(artifact, attempts = 1) {
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
    const authorization = wrapAuthorization(artifact.authorization);
    const a = artifact.authorization;
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
  if (artifact.kind === 'eip7702-intent') {
    if (!SWEEPER_V2) throw Object.assign(new Error('eip7702-intent sweeps are unavailable: SWEEPER_V2 is not configured on this relayer'), { status: 503 });
    verifyIntent(artifact);
    const data = SWEEPER_IFACE.encodeFunctionData('executeSweep', [artifact.intent, artifact.signature]);
    // fee estimate for the ledger: stealth balance * feeBps / 10000, best-effort (a failed
    // balance read skips the ledger line, it never blocks the broadcast).
    const bal = await getBalance(artifact.stealthAddress).catch(() => null);
    const runner = pickRunner();
    lastRunner = runner;
    const out = await broadcast(runner, {
      type: 4,
      to: artifact.stealthAddress,
      data,
      authorizationList: [wrapAuthorization(artifact.authorization)],
    }, [5, 45], 'sweep/7702-intent');
    // journal for the reaper: a dropped intent sweep is safe to rebroadcast (if the original
    // somehow lands too, the replay fails on the consumed auth nonce, it cannot double-sweep)
    await journalBroadcast({ kind: 'sweep-intent', hash: out.hash, runner: runner.address, attempts, payload: artifact });
    if (bal !== null) await logFee({
      kind: 'sweep-intent', feeBps: Number(artifact.intent.feeBps),
      estFeeWei: (bal * BigInt(artifact.intent.feeBps) / 10000n).toString(),
      txHash: out.hash, runner: out.runner,
    });
    return out;
  }
  if (artifact.kind === 'eip7702-intent-batch') {
    // one tx sweeps many stealth EOAs: cheaper per sweep, but the batch links them onchain.
    if (!BATCH_RELAYER) throw Object.assign(new Error('eip7702-intent-batch sweeps are unavailable: BATCH_RELAYER is not configured on this relayer'), { status: 503 });
    const sweeps = artifact.sweeps;
    if (!Array.isArray(sweeps) || sweeps.length < 1 || sweeps.length > 20) {
      throw Object.assign(new Error('bad sweeps (expected 1-20 entries)'), { status: 400 });
    }
    const targets = [], datas = [], authorizationList = [];
    for (const s of sweeps) {
      verifyIntent(s);
      targets.push(s.stealthAddress);
      datas.push(SWEEPER_IFACE.encodeFunctionData('executeSweep', [s.intent, s.signature]));
      authorizationList.push(wrapAuthorization(s.authorization));
    }
    const data = BATCH_IFACE.encodeFunctionData('relay', [targets, datas]);
    // best-effort per-sweep fee estimates (see eip7702-intent above).
    const bals = await Promise.all(sweeps.map(s => getBalance(s.stealthAddress).catch(() => null)));
    const runner = pickRunner();
    lastRunner = runner;
    const out = await broadcast(runner, {
      type: 4,
      to: BATCH_RELAYER,
      data,
      authorizationList,
    }, [5, 45], 'sweep/7702-intent-batch');
    for (let i = 0; i < sweeps.length; i++) {
      if (bals[i] === null) continue;
      await logFee({
        kind: 'sweep-intent-batch', feeBps: Number(sweeps[i].intent.feeBps),
        estFeeWei: (bals[i] * BigInt(sweeps[i].intent.feeBps) / 10000n).toString(),
        txHash: out.hash, runner: out.runner,
      });
    }
    return out;
  }
  throw Object.assign(new Error('unknown artifact kind: ' + artifact.kind), { status: 400 });
}

// ── /pp-withdraw: Privacy Pools withdrawal relay (PP_RELAY=1). The groth16 circuit binds the
// RelayData (recipient, feeRecipient, relayFeeBPS) and scope into the context public signal, so
// accepting a proof here means accepting exactly the fee terms the user proved. The runner pays
// gas; the fee accrues onchain to feeRecipient inside the withdrawal (Entrypoint.relay). ──
const PP_ENTRYPOINT_IFACE = new ethers.Interface([
  'function relay((address processooor,bytes data) withdrawal, (uint256[2] pA,uint256[2][2] pB,uint256[2] pC,uint256[8] pubSignals) proof, uint256 scope)']);
const isDecStr = s => typeof s === 'string' && /^[0-9]+$/.test(s);

async function handlePpWithdraw(body) {
  const fail = msg => { throw Object.assign(new Error(msg), { status: 400 }); };
  if (!body || typeof body !== 'object') fail('missing withdrawal payload');
  if (Number(body.chainId) !== CHAIN_ID) fail(`bad chainId (expected ${CHAIN_ID})`);
  let scope;
  try { scope = BigInt(body.scope); } catch { fail('bad scope (expected a decimal string)'); }
  if (scope !== PP_SCOPE) fail('unsupported scope: this relay serves only the mainnet ETH Privacy Pool');
  const w = body.withdrawal;
  if (!w || typeof w !== 'object') fail('missing withdrawal struct');
  if (!ethers.isAddress(w.processooor)) fail('bad withdrawal.processooor');
  const processooor = ethers.getAddress(w.processooor);
  if (processooor !== ethers.getAddress(PP_ENTRYPOINT)) fail('unsupported processooor: withdrawals must go through the Privacy Pools entrypoint');
  if (typeof w.data !== 'string' || !/^0x(?:[0-9a-fA-F]{2})+$/.test(w.data)) fail('bad withdrawal.data (expected 0x-prefixed abi-encoded RelayData)');
  let recipient, feeRecipient, relayFeeBPS;
  try {
    [recipient, feeRecipient, relayFeeBPS] = ethers.AbiCoder.defaultAbiCoder().decode(
      ['tuple(address recipient, address feeRecipient, uint256 relayFeeBPS)'], w.data)[0];
  } catch { fail('bad withdrawal.data (expected abi.encode(address recipient, address feeRecipient, uint256 relayFeeBPS))'); }
  const runnerAddrs = runners.map(r => r.address.toLowerCase());
  if (!runnerAddrs.includes(feeRecipient.toLowerCase())) {
    fail(`relayer address ${feeRecipient} is not one of this relayer's runners — re-quote against GET /health (runners + ppFeeBps) and re-prove`);
  }
  if (relayFeeBPS > BigInt(PP_FEE_BPS)) fail(`relayFeeBPS ${relayFeeBPS} exceeds this relayer's fee of ${PP_FEE_BPS} bps — re-quote against GET /health and re-prove`);
  const p = body.proof;
  if (!p || typeof p !== 'object') fail('missing proof');
  if (p.protocol !== 'groth16' || p.curve !== 'bn128') fail('unsupported proof (expected groth16 on bn128)');
  if (!Array.isArray(p.pi_a) || !p.pi_a.slice(0, 2).every(isDecStr)) fail('bad proof.pi_a (expected 2 decimal strings)');
  if (!Array.isArray(p.pi_b) || p.pi_b.length < 2 ||
      p.pi_b.slice(0, 2).some(r => !Array.isArray(r) || !r.slice(0, 2).every(isDecStr))) fail('bad proof.pi_b (expected a 2x2 matrix of decimal strings)');
  if (!Array.isArray(p.pi_c) || !p.pi_c.slice(0, 2).every(isDecStr)) fail('bad proof.pi_c (expected 2 decimal strings)');
  const pub = body.publicSignals;
  if (!Array.isArray(pub) || pub.length !== 8 || !pub.every(isDecStr)) fail('bad publicSignals (expected 8 decimal strings)');
  if (pub.some(s => BigInt(s) >= SNARK_FIELD)) fail('public signal out of range (>= snark scalar field)');
  // the context signal binds the proof to this exact withdrawal data + scope (pp-crypto.mjs construction)
  const context = BigInt(ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
    ['tuple(address,bytes)', 'uint256'], [[processooor, w.data], scope]))) % SNARK_FIELD;
  if (BigInt(pub[7]) !== context) fail('context mismatch: the proof is not bound to this withdrawal data and scope');
  const withdrawnValue = BigInt(pub[2]);
  if (withdrawnValue === 0n) fail('withdrawnValue public signal is zero');
  // snarkjs JSON to circom solidity verifier layout: swap the two Fq2 coordinates inside pi_b.
  const proof = [
    [p.pi_a[0], p.pi_a[1]],
    [[p.pi_b[0][1], p.pi_b[0][0]], [p.pi_b[1][1], p.pi_b[1][0]]],
    [p.pi_c[0], p.pi_c[1]],
    pub,
  ];
  const data = PP_ENTRYPOINT_IFACE.encodeFunctionData('relay', [[processooor, w.data], proof, scope]);
  const runner = pickRunner();
  lastRunner = runner;
  // gas estimation inside broadcast() simulates the full withdraw incl. proof verification,
  // so an invalid proof fails here with a clean error instead of burning gas onchain.
  const out = await broadcast(runner, { to: PP_ENTRYPOINT, data }, [5, 45], 'pp-withdraw');
  const estFeeWei = withdrawnValue * relayFeeBPS / 10000n;
  await logFee({ kind: 'pp-withdraw', feeBps: Number(relayFeeBPS), estFeeWei: estFeeWei.toString(), txHash: out.hash, runner: out.runner });
  return { ...out, txHash: out.hash, recipient, feeBps: Number(relayFeeBPS), feeWei: estFeeWei.toString() };
}

// ── /price: CoinGecko proxy with a 60s cache, so the price fetch stays out of the browser ──
let priceCache = { at: 0, data: null };
function handlePrice() {
  if (priceCache.data && Date.now() - priceCache.at < 60000) return Promise.resolve(priceCache.data);
  const url = 'https://api.coingecko.com/api/v3/simple/price?ids=ethereum,usd-coin&vs_currencies=usd';
  return new Promise((resolve, reject) => {
    const fail = msg => reject(Object.assign(new Error('price feed unavailable (' + msg + ')'), { status: 503 }));
    const req = https.get(url, { agent: torAgent || undefined, timeout: 10000, headers: { accept: 'application/json', 'user-agent': 'ghostpay-relayer/1.0 (+https://github.com/unhappyben/ghostpay)' } }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        if (res.statusCode !== 200) return fail('http ' + res.statusCode);
        try {
          const data = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          priceCache = { at: Date.now(), data };
          resolve(data);
        } catch { fail('bad response'); }
      });
    });
    req.on('timeout', () => req.destroy(Object.assign(new Error('timeout'))));
    req.on('error', e => fail(errMsg(e)));
  });
}

async function handleStatus(hash) {
  const receipt = await rpcCall('eth_getTransactionReceipt', [hash]);
  if (!receipt) return { status: 'pending' };
  const out = { status: receipt.status === '0x1' ? 'confirmed' : 'failed' };
  if (receipt.blockNumber) out.blockNumber = parseInt(receipt.blockNumber, 16);
  return out;
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

// ── fee auto-forward: every FEE_SWEEP_MINUTES each runner sends its ETH balance above
// FEE_RESERVE_ETH to FEE_OWNER as a plain type-2 transfer via the broadcast machinery
// (rpcCall rotation, feeBump, BROADCAST_URLS). No jitter: fee sweeps are the operator's
// own money movement, not user traffic. Errors log one line and wait for the next tick;
// a failed sweep never crashes the server. ──
async function forwardRunnerFees(runner) {
  const reserveWei = ethers.parseEther(String(FEE_RESERVE_ETH));
  const bal = await getBalance(runner.address);
  if (bal <= reserveWei) {
    console.log(`fee-forward: runner=${runner.address} balance=${ethers.formatEther(bal)} ETH at/below reserve ${FEE_RESERVE_ETH} ETH (nothing to forward)`);
    return;
  }
  const amount = bal - reserveWei;
  const tx = { to: FEE_OWNER, value: amount, gasLimit: 21000n, chainId: CHAIN_ID, nonce: await getNonce(runner.address) };
  Object.assign(tx, await feeBump());
  const signed = await runner.signTransaction(tx);
  const { hash, host } = await broadcastRawTx(signed);
  console.log(`fee-forward: runner=${runner.address} amount=${ethers.formatEther(amount)} ETH broadcast=${host} hash=${hash}`);
  await logFee({ kind: 'fee-forward', estFeeWei: amount.toString(), txHash: hash, runner: runner.address });
}
async function feeSweepTick() {
  for (const runner of runners) {
    try { await forwardRunnerFees(runner); }
    catch (e) { console.error(`fee-forward failed: runner=${runner.address} ${errMsg(e)}`); }
  }
}
if (FEE_OWNER && runners.length) {
  const first = setTimeout(() => {
    feeSweepTick();
    setInterval(feeSweepTick, FEE_SWEEP_MINUTES * 60 * 1000).unref();
  }, 5 * 60 * 1000);
  first.unref();
  console.log(`fee auto-forward on: owner=${FEE_OWNER} reserve=${FEE_RESERVE_ETH} ETH every=${FEE_SWEEP_MINUTES}min (first sweep 5 min after boot)`);
}

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost');
    if (req.method === 'POST' && (url.pathname === '/announce' || url.pathname === '/sweep' || url.pathname === '/pp-withdraw')) {
      const ip = req.socket.remoteAddress || 'unknown';
      const retryAfter = rateLimit(url.pathname, ip);
      if (retryAfter > 0) {
        console.log(`rate limit: 429 ${url.pathname} ip=${ip} retry-after=${retryAfter}s`);
        return sendJson(res, 429, { error: `rate limit exceeded: ${url.pathname} allows ${RATE_LIMITS[url.pathname]} requests per minute per IP` }, { 'Retry-After': String(retryAfter) });
      }
      if (API_TOKEN && url.pathname !== '/announce' && !checkApiToken(req)) {
        return sendJson(res, 401, { error: 'unauthorized: this relayer requires Authorization: Bearer <token> on ' + url.pathname });
      }
      if (url.pathname === '/pp-withdraw' && !PP_RELAY) {
        return sendJson(res, 503, { error: 'pp withdrawal relay is disabled on this server: restart serve.mjs with PP_RELAY=1 to enable POST /pp-withdraw' });
      }
      if (!runners.length) return sendJson(res, 503, { error: 'relayer not configured: set RUNNER_PK or provide runners.local.json and restart serve.mjs (static serving is unaffected)' });
      try {
        const body = await readBody(req);
        const out = url.pathname === '/announce' ? await handleAnnounce(body)
          : url.pathname === '/sweep' ? await handleSweep(body)
          : await handlePpWithdraw(body);
        sendJson(res, 200, out);
      } catch (e) {
        sendJson(res, e.status || 500, { error: errMsg(e) });
      }
      return;
    }
    if (req.method === 'GET') {
      if (url.pathname === '/health') {
        return sendJson(res, 200, {
          ok: true, chainId: CHAIN_ID,
          runners: runners.map(w => w.address), runnerCount: runners.length,
          runnerBalances: await runnerBalances(),
          sweeperV2: SWEEPER_V2, batchRelayer: BATCH_RELAYER, minFeeBps: MIN_FEE_BPS,
          ppRelay: PP_RELAY, ...(PP_RELAY ? { ppFeeBps: PP_FEE_BPS } : {}),
          feeOwner: FEE_OWNER,
          rateLimited: true, ...(API_TOKEN ? { authRequired: true } : {}),
          tor: !!TOR_PROXY, endpoints: RPC_URLS.map(u => new URL(u).hostname),
        });
      }
      if (url.pathname === '/fee') return sendJson(res, 200, { minFeeBps: MIN_FEE_BPS });
      if (url.pathname === '/price') {
        try { return sendJson(res, 200, await handlePrice()); }
        catch (e) { return sendJson(res, e.status || 500, { error: errMsg(e) }); }
      }
      if (url.pathname.startsWith('/status/')) {
        const m = url.pathname.match(/^\/status\/(0x[0-9a-fA-F]{64})$/);
        if (!m) return sendJson(res, 400, { error: 'bad tx hash (expected 0x + 64 hex characters)' });
        try { return sendJson(res, 200, await handleStatus(m[1])); }
        catch (e) { return sendJson(res, e.status || 500, { error: errMsg(e) }); }
      }
    }
    if (req.method === 'GET' || req.method === 'HEAD') return serveStatic(req, res, url.pathname);
    sendJson(res, 405, { error: 'method not allowed' });
  } catch (e) {
    sendJson(res, 500, { error: errMsg(e) });
  }
});

server.listen(PORT, () => console.log(
  `GHOSTPAY serving ${ROOT} on http://localhost:${PORT}/ (rpc: ${RPC_URLS.map(u => new URL(u).hostname).join(', ')}, broadcast: ${BROADCAST_URLS.map(u => new URL(u).hostname).join(', ')}${TOR_PROXY ? ', rpc via Tor ' + TOR_PROXY : ''})`));
