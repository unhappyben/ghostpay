#!/usr/bin/env node
// notify.mjs — GHOSTPAY watch-only payment notifier.
//
//   node notify.mjs                     (reads ./notify.local.json)
//   node notify.mjs /path/to/conf.json
//   RPC_URLS=https://a,https://b TOR_PROXY=socks5://127.0.0.1:9050 node notify.mjs
//
// Watches the ERC-5564 announcer (mainnet) for Announcement logs, runs the exact
// ownership check the app's scanner runs (index.html check(): ECDH shared secret
// from the viewing key, view-tag filter, stealth-address reconstruction from the
// spend public key), and pushes one message per NEW payment to Telegram or a
// webhook. Read-only: the spend key is never needed and never touched.
//
// Setup — notify.local.json (gitignored, keep it private):
//
//   {
//     "viewingKey": "0x…64 hex…",          // the app's viewPriv (keccak256(sig ‖ "|view"))
//     "spendPub":   "0x…66 hex…",          // the app's spendPub (33-byte compressed point)
//     "telegram": { "botToken": "…", "chatId": "…" },   // OR:
//     "webhook": "https://example.org/ghostpay",
//     "pollSeconds": 60,                    // optional, default 60, minimum 5
//     "fromBlock": 23000000,                // optional; default: current block (no backfill)
//     "legacy": false                       // true to scan pre-2026-09-08 sha256 announcements
//   }
//
// viewingKey reveals your incoming payment history to anyone who holds it (that is
// the point of a viewing key), so treat notify.local.json like a key file: it is
// listed in .gitignore, do not commit it, do not paste it anywhere.
//
// Telegram bot: message @BotFather in Telegram, send /newbot, follow the prompts,
// copy the token into botToken. Then message your new bot once and open
// https://api.telegram.org/bot<TOKEN>/getUpdates to find your chat id ("chat":{"id":…}).
// A webhook instead receives one POST per payment with JSON {stealth, txHash, blockNumber}.
//
// State: notify-state.json (gitignored) records the last processed block, seen
// payment keys, and any notifications pending retry, so restarts never re-notify.
//
// Networking: every JSON-RPC call goes through rpcCall() with per-call random
// endpoint rotation (RPC_URLS, comma-separated) and optional Tor routing
// (TOR_PROXY, via socks-proxy-agent) — the same pattern as serve.mjs. Errors are
// clean one-liners, never stack traces. Keys are never logged.
import http from 'http';
import https from 'https';
import { readFileSync, writeFileSync, renameSync } from 'fs';
import { join } from 'path';
import { fileURLToPath } from 'url';
import { ethers } from 'ethers';

const ROOT = fileURLToPath(new URL('.', import.meta.url));
const CONFIG_PATH = process.argv[2] || join(ROOT, 'notify.local.json');
const STATE_PATH = join(ROOT, 'notify-state.json');
const RPC_URLS = (process.env.RPC_URLS || process.env.RPC_URL || 'https://rpc.flashbots.net,https://eth.drpc.org,https://eth.merkle.io')
  .split(',').map(s => s.trim()).filter(Boolean);
const TOR_PROXY = process.env.TOR_PROXY || null;
const ANNOUNCER = '0x55649E01B5Df198D18D95b5cc5051630cfD45564'; // ERC-5564 announcer, mainnet (ANNOUNCER const in index.html)
const SEEN_CAP = 5000; // seen payment keys retained in notify-state.json

const die = msg => { console.error('notify: ' + msg); process.exit(1); };
const errMsg = e => (e && (e.shortMessage || e.reason || e.message)) || String(e);
const sleep = ms => new Promise(r => setTimeout(r, ms));

// ── config: validate everything up front, clean one-line errors, no stack traces ──
let cfg;
try { cfg = JSON.parse(readFileSync(CONFIG_PATH, 'utf8')); }
catch (e) {
  die(e.code === 'ENOENT'
    ? 'cannot read config ' + CONFIG_PATH + ' · create it from the example in the header of notify.mjs'
    : CONFIG_PATH + ' is not valid JSON: ' + errMsg(e));
}
if (typeof cfg.viewingKey !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(cfg.viewingKey))
  die('"viewingKey" must be a 0x-prefixed 32-byte hex string (the app calls it viewPriv)');
if (typeof cfg.spendPub !== 'string' || !/^0x[0-9a-fA-F]{66}$/.test(cfg.spendPub))
  die('"spendPub" must be a 0x-prefixed 33-byte compressed public key (the app calls it spendPub)');
const hasTelegram = cfg.telegram && typeof cfg.telegram === 'object';
const hasWebhook = typeof cfg.webhook === 'string' && /^https?:\/\//.test(cfg.webhook);
if (hasTelegram === hasWebhook)
  die('set exactly one delivery target: "telegram": {"botToken","chatId"} or "webhook": "https://…"');
if (hasTelegram && (!cfg.telegram.botToken || !cfg.telegram.chatId))
  die('"telegram" needs both "botToken" and "chatId" (see the BotFather setup in the header of notify.mjs)');
const POLL_SECONDS = cfg.pollSeconds == null ? 60 : Number(cfg.pollSeconds);
if (!Number.isInteger(POLL_SECONDS) || POLL_SECONDS < 5)
  die('"pollSeconds" must be an integer >= 5 (default 60)');
if (cfg.fromBlock != null && (!Number.isInteger(cfg.fromBlock) || cfg.fromBlock < 0))
  die('"fromBlock" must be a non-negative integer block number');
const LEGACY = cfg.legacy === true;
try { new ethers.SigningKey(cfg.viewingKey); } catch { die('"viewingKey" is not a valid secp256k1 scalar'); }
try { ethers.SigningKey.computePublicKey(cfg.spendPub); } catch { die('"spendPub" is not a valid secp256k1 point'); }

// ── state: last processed block + seen payment keys + pending retries ──
let state = { lastBlock: null, seen: [], pending: [] };
try { state = Object.assign(state, JSON.parse(readFileSync(STATE_PATH, 'utf8'))); } catch { /* missing or malformed: start fresh */ }
if (!Array.isArray(state.seen)) state.seen = [];
if (!Array.isArray(state.pending)) state.pending = [];
const seen = new Set(state.seen);
function saveState() {
  while (state.seen.length > SEEN_CAP) seen.delete(state.seen.shift());
  const tmp = STATE_PATH + '.tmp';
  writeFileSync(tmp, JSON.stringify(state, null, 2));
  renameSync(tmp, STATE_PATH);
}

// ── rpcCall: all Ethereum JSON-RPC, random endpoint per call, optional Tor (same as serve.mjs) ──
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
    try { return await rpcCallOnce(url, method, params); }
    catch (e) { lastErr = e; }
  }
  throw lastErr;
}

// ── ownership check: mirrors index.html check() exactly (ERC-5564 scheme 1) ──
// shared-secret hash is keccak256 per spec; legacy:true scans pre-2026-09-08 sha256 announcements.
// noble's getSharedSecret(priv, pub, true) returns the COMPRESSED ECDH point, so the
// uncompressed point ethers returns is re-compressed before hashing, else the scheme diverges.
const schemeHash = h => LEGACY ? ethers.sha256(h) : ethers.keccak256(h);
const viewKey = new ethers.SigningKey(cfg.viewingKey);
function check(ephPub, addr) {
  const shHex = schemeHash(ethers.SigningKey.computePublicKey(viewKey.computeSharedSecret(ephPub), true));
  const stealthPub = ethers.SigningKey.addPoints(cfg.spendPub, new ethers.SigningKey(shHex).publicKey);
  return { match: ethers.computeAddress(stealthPub).toLowerCase() === addr.toLowerCase(), viewTag: parseInt(shHex.slice(2, 4), 16) };
}

// ── log scan: 100k-block chunks, split to 10k on failure, 3 retries per chunk (mirrors scan()) ──
const TOPIC0 = ethers.id('Announcement(uint256,address,address,bytes,bytes)');
const T1 = ethers.zeroPadValue('0x01', 32); // scheme id 1
async function scanRange(fromBlock, latest) {
  const ranges = [];
  for (let f = fromBlock; f <= latest; f += 100000) ranges.push([f, Math.min(f + 99999, latest), 0]);
  const logs = []; let failed = 0;
  while (ranges.length) {
    const r = ranges.shift(); const [f, t] = [r[0], r[1]];
    try {
      const res = await rpcCall('eth_getLogs', [{ address: ANNOUNCER, topics: [TOPIC0, T1], fromBlock: '0x' + f.toString(16), toBlock: '0x' + t.toString(16) }]);
      logs.push(...res);
    } catch {
      if (t - f + 1 > 10000) { for (let g = f; g <= t; g += 10000) ranges.push([g, Math.min(g + 9999, t), 0]); }
      else if (r[2] < 3) { r[2]++; ranges.push(r); await sleep(600); }
      else { failed++; }
    }
  }
  return { logs, failed };
}

// ── delivery: Telegram sendMessage or generic webhook, via Tor when configured ──
function postJson(url, payload) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(payload);
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
        const text = Buffer.concat(chunks).toString('utf8');
        let j = null;
        try { j = JSON.parse(text); } catch { /* non-JSON body */ }
        if (res.statusCode >= 400) return reject(new Error((j && j.description) || 'http ' + res.statusCode + ' from ' + u.hostname));
        resolve(j);
      });
    });
    req.on('timeout', () => req.destroy(new Error('request timeout (20s)')));
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}
async function deliver(p) {
  if (hasTelegram) {
    const text = 'ghostpay: payment received\nstealth: ' + p.stealth + '\nblock: ' + p.blockNumber + '\ntx: https://etherscan.io/tx/' + p.txHash;
    const j = await postJson('https://api.telegram.org/bot' + cfg.telegram.botToken + '/sendMessage',
      { chat_id: cfg.telegram.chatId, text, disable_web_page_preview: true });
    if (!j || !j.ok) throw new Error('telegram: ' + ((j && j.description) || 'send failed'));
  } else {
    await postJson(cfg.webhook, { stealth: p.stealth, txHash: p.txHash, blockNumber: p.blockNumber });
  }
  console.log('notified: stealth ' + p.stealth + ' · block ' + p.blockNumber + ' · tx ' + p.txHash);
}

const keyOf = p => p.txHash.toLowerCase() + ':' + p.stealth.toLowerCase();
async function flushPending() {
  const retry = [];
  for (const p of state.pending) {
    try { await deliver(p); seen.add(keyOf(p)); state.seen.push(keyOf(p)); }
    catch (e) { console.error('delivery failed: ' + errMsg(e) + ' · will retry next poll'); retry.push(p); }
  }
  state.pending = retry;
}

async function poll() {
  await flushPending();
  const latest = parseInt(await rpcCall('eth_blockNumber', []), 16);
  const from = state.lastBlock != null ? state.lastBlock + 1
    : (cfg.fromBlock != null ? cfg.fromBlock : latest);
  if (from > latest) { console.log('poll: up to date at block ' + latest.toLocaleString()); return; }
  const { logs, failed } = await scanRange(from, latest);
  let fresh = 0, matched = 0;
  for (const l of logs) {
    let r, addr;
    try {
      const [ephPub, metadata] = ethers.AbiCoder.defaultAbiCoder().decode(['bytes', 'bytes'], l.data);
      addr = '0x' + l.topics[2].slice(-40);
      r = check(ephPub, addr);
      if (metadata.length >= 3 && parseInt(metadata.slice(2, 4), 16) !== r.viewTag) continue;
    } catch { continue; } // malformed log or off-curve point: not ours either way
    if (!r.match) continue;
    matched++;
    const p = { stealth: addr, txHash: l.transactionHash, blockNumber: parseInt(l.blockNumber, 16) };
    if (seen.has(keyOf(p))) continue;
    fresh++;
    try { await deliver(p); seen.add(keyOf(p)); state.seen.push(keyOf(p)); }
    catch (e) { console.error('delivery failed: ' + errMsg(e) + ' · queued for retry'); state.pending.push(p); }
  }
  // advance the cursor only on a fully clean scan, so unreachable ranges are never skipped for good
  if (!failed) state.lastBlock = latest;
  saveState();
  console.log('poll: blocks ' + from.toLocaleString() + ' → ' + latest.toLocaleString()
    + ' · ' + logs.length + ' announcement(s) · ' + matched + ' matched · ' + fresh + ' new'
    + (failed ? ' · ' + failed + ' range(s) unreachable, cursor held' : ''));
}

console.log('notify: watching announcements for spendPub ' + cfg.spendPub.slice(0, 10) + '…'
  + ' · delivery: ' + (hasTelegram ? 'telegram chat ' + cfg.telegram.chatId : 'webhook ' + new URL(cfg.webhook).hostname)
  + ' · rpc: ' + RPC_URLS.map(u => new URL(u).hostname).join(', ')
  + (TOR_PROXY ? ' via Tor ' + TOR_PROXY : '')
  + ' · poll every ' + POLL_SECONDS + 's' + (LEGACY ? ' · legacy sha256 scheme' : ''));
while (true) {
  try { await poll(); }
  catch (e) { console.error('poll failed: ' + errMsg(e) + ' · retrying in ' + POLL_SECONDS + 's'); }
  await sleep(POLL_SECONDS * 1000);
}
