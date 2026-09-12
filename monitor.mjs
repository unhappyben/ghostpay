#!/usr/bin/env node
// monitor.mjs — GHOSTPAY relayer monitor (no deps), run from cron, e.g. every 6h:
//
//   23 */6 * * * cd /opt/ghostpay && /usr/bin/node monitor.mjs >> monitor.log 2>&1
//
// Reads fees.jsonl + broadcasts.jsonl (missing or malformed files are tolerated),
// computes fees earned/forwarded since the last run (cursor in monitor-state.json),
// summarizes reaper activity (confirmed / replaced / given-up / …), reads runner
// balances over RPC (RPC_URLS rotation, optional TOR_PROXY), and sends a Telegram
// digest using notify.mjs's plain-https delivery. ALERTs go out as a separate loud
// message when a runner balance drops below 2x FEE_RESERVE_ETH (default 0.01 ETH)
// or when the reaper gives up on a broadcast. Read-only: it never sends a transaction
// and never touches a key.
//
// Telegram: TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID env, or monitor.local.json
// (gitignored, keep it private):
//
//   { "telegram": { "botToken": "…", "chatId": "…" } }
//
// With neither, the digest prints to stdout instead and the run still succeeds.
//
// Runners: RUNNER_ADDRESSES=0x…,0x… env or repeated --runner 0x… flags.
// Overrides (for testing): FEES_FILE, BROADCASTS_FILE, STATE_FILE env.
// Errors are clean one-liners, never stack traces. Keys are never logged.
import http from 'http';
import https from 'https';
import { readFileSync, writeFileSync, renameSync } from 'fs';
import { join } from 'path';
import { fileURLToPath } from 'url';

const ROOT = fileURLToPath(new URL('.', import.meta.url));
const FEES_FILE = process.env.FEES_FILE || join(ROOT, 'fees.jsonl');
const BROADCASTS_FILE = process.env.BROADCASTS_FILE || join(ROOT, 'broadcasts.jsonl');
const STATE_FILE = process.env.STATE_FILE || join(ROOT, 'monitor-state.json');
const LOCAL_CONFIG = join(ROOT, 'monitor.local.json');
const RPC_URLS = (process.env.RPC_URLS || process.env.RPC_URL || 'https://rpc.flashbots.net,https://eth.drpc.org,https://eth.merkle.io')
  .split(',').map(s => s.trim()).filter(Boolean);
const TOR_PROXY = process.env.TOR_PROXY || null;
// alert threshold: any runner below 2x the fee reserve can no longer both pay gas and
// forward fees (serve.mjs FEE_RESERVE_ETH, default mirrored here as 0.01)
const FEE_RESERVE_ETH = Number(process.env.FEE_RESERVE_ETH) > 0 ? Number(process.env.FEE_RESERVE_ETH) : 0.01;
const LOW_BALANCE_ETH = 2 * FEE_RESERVE_ETH;
const GIVEN_UP_CAP = 1000; // alerted given-up hashes retained in monitor-state.json

const die = msg => { console.error('monitor: ' + msg); process.exit(1); };
const errMsg = e => (e && (e.shortMessage || e.reason || e.message)) || String(e);

// ── runners: RUNNER_ADDRESSES env (comma-separated) or repeated --runner flags ──
const isAddr = s => typeof s === 'string' && /^0x[0-9a-fA-F]{40}$/.test(s);
const runnerInputs = (process.env.RUNNER_ADDRESSES || '').split(',').map(s => s.trim()).filter(Boolean);
for (let i = 2; i < process.argv.length; i++) {
  const a = process.argv[i];
  if (a === '--runner') {
    const v = process.argv[++i];
    if (!isAddr(v)) die('--runner needs a 0x-prefixed 20-byte address, got: ' + (v || '(missing)'));
    runnerInputs.push(v);
  } else if (a.startsWith('--runner=')) {
    const v = a.slice('--runner='.length);
    if (!isAddr(v)) die('--runner needs a 0x-prefixed 20-byte address, got: ' + v);
    runnerInputs.push(v);
  } else {
    die('unknown argument: ' + a + ' (supported: --runner 0x…, repeatable)');
  }
}
const runners = [];
for (const a of runnerInputs) {
  if (!isAddr(a)) die('bad runner address (expected 0x + 40 hex characters): ' + a);
  if (!runners.some(r => r.toLowerCase() === a.toLowerCase())) runners.push(a);
}

// ── telegram: env first, else monitor.local.json; missing means print to stdout ──
let botToken = process.env.TELEGRAM_BOT_TOKEN || null;
let chatId = process.env.TELEGRAM_CHAT_ID || null;
if (!botToken || !chatId) {
  try {
    const raw = JSON.parse(readFileSync(LOCAL_CONFIG, 'utf8'));
    const t = raw && raw.telegram;
    if (t && t.botToken && t.chatId) { botToken = String(t.botToken); chatId = String(t.chatId); }
  } catch (e) {
    if (e.code !== 'ENOENT') console.error('monitor: ' + LOCAL_CONFIG + ' is not valid JSON: ' + errMsg(e) + ' · falling back to stdout');
  }
}
const hasTelegram = !!(botToken && chatId);

// ── state: last-run cursor + given-up hashes already alerted ──
let state = { lastRun: null, alertedGivenUp: [] };
try { state = Object.assign(state, JSON.parse(readFileSync(STATE_FILE, 'utf8'))); } catch { /* missing or malformed: start fresh */ }
if (!Array.isArray(state.alertedGivenUp)) state.alertedGivenUp = [];
function saveState() {
  while (state.alertedGivenUp.length > GIVEN_UP_CAP) state.alertedGivenUp.shift();
  const tmp = STATE_FILE + '.tmp';
  writeFileSync(tmp, JSON.stringify(state, null, 2));
  renameSync(tmp, STATE_FILE);
}

// ── journals: one JSON object per line, missing files and bad lines tolerated ──
function readJsonl(path) {
  try {
    return readFileSync(path, 'utf8').split('\n').filter(Boolean)
      .map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
  } catch { return []; }
}
// fees.jsonl stamps ISO strings (fees.mjs logFee); broadcasts.jsonl stamps ms epoch (serve.mjs)
const tsMs = t => {
  if (typeof t === 'number' && Number.isFinite(t)) return t;
  const p = Date.parse(t);
  return Number.isFinite(p) ? p : null;
};

// wei -> trimmed ETH decimal string (BigInt math, same as fees.mjs)
function formatEth(wei) {
  const w = BigInt(wei);
  const whole = w / 10n ** 18n;
  const frac = (w % 10n ** 18n).toString().padStart(18, '0').replace(/0+$/, '');
  return frac ? `${whole}.${frac}` : whole.toString();
}
const fmtNum = n => n.toFixed(6).replace(/0+$/, '').replace(/\.$/, '');

// ── rpcCall: random endpoint per call, optional Tor (same pattern as notify.mjs) ──
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

// ── delivery: Telegram sendMessage over plain https (notify.mjs pattern) ──
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
async function sendTelegram(text) {
  const j = await postJson('https://api.telegram.org/bot' + botToken + '/sendMessage',
    { chat_id: chatId, text, disable_web_page_preview: true });
  if (!j || !j.ok) throw new Error('telegram: ' + ((j && j.description) || 'send failed'));
}

async function main() {
  const nowIso = new Date().toISOString();
  const sinceMs = state.lastRun != null ? Date.parse(state.lastRun) : null;
  const window = sinceMs == null ? '(first run: all time)' : 'since ' + state.lastRun;

  // fees: earned = everything except fee-forward (the forward lines are outflows to the
  // owner, not revenue; same split as fees.mjs)
  const feeEntries = readJsonl(FEES_FILE).filter(e => e.kind && e.estFeeWei != null);
  const totals = entries => {
    const t = { earned: 0n, earnedN: 0, forwarded: 0n, forwardedN: 0 };
    for (const e of entries) {
      let w;
      try { w = BigInt(e.estFeeWei); } catch { continue; }
      if (e.kind === 'fee-forward') { t.forwarded += w; t.forwardedN++; } else { t.earned += w; t.earnedN++; }
    }
    return t;
  };
  const newFees = sinceMs == null ? feeEntries
    : feeEntries.filter(e => { const t = tsMs(e.ts); return t != null && t > sinceMs; });
  const tNew = totals(newFees);
  const tAll = totals(feeEntries);

  // reaper: finalStatus counts over the window, plus in-flight (not yet done) entries
  const journal = readJsonl(BROADCASTS_FILE);
  const recent = sinceMs == null ? journal
    : journal.filter(e => { const t = tsMs(e.ts); return t != null && t > sinceMs; });
  const counts = { confirmed: 0, replaced: 0, reverted: 0, givenUp: 0, untracked: 0, inflight: 0 };
  for (const e of recent) {
    if (!e.done) { counts.inflight++; continue; }
    if (e.finalStatus === 'confirmed') counts.confirmed++;
    else if (e.finalStatus === 'replaced') counts.replaced++;
    else if (e.finalStatus === 'reverted') counts.reverted++;
    else if (e.finalStatus === 'given-up') counts.givenUp++;
    else counts.untracked++;
  }
  // a given-up entry alerts once, ever: the journal keeps it for a week, so re-alerting
  // every cron run would be noise. The state file records which hashes already fired.
  const newGivenUp = journal.filter(e => e.finalStatus === 'given-up' && e.hash
    && !state.alertedGivenUp.includes(String(e.hash).toLowerCase()));

  // runner balances (best-effort per runner: an RPC failure yields null, never a failed run)
  const balances = [];
  for (const addr of runners) {
    try {
      const hex = await rpcCall('eth_getBalance', [addr, 'latest']);
      balances.push({ addr, eth: Number(BigInt(hex)) / 1e18 });
    } catch (e) {
      balances.push({ addr, eth: null, error: errMsg(e) });
    }
  }

  // alerts: low runner balance (every run while low) + newly given-up broadcasts (once)
  const alerts = [];
  for (const b of balances) {
    if (b.eth != null && b.eth < LOW_BALANCE_ETH) {
      alerts.push('runner ' + b.addr + ' balance ' + fmtNum(b.eth) + ' ETH is below 2x FEE_RESERVE_ETH ('
        + fmtNum(LOW_BALANCE_ETH) + ' ETH) · fund the runner');
    }
  }
  for (const e of newGivenUp) {
    alerts.push('reaper gave up on ' + (e.kind || 'broadcast') + ' ' + e.hash + ' after '
      + (e.attempts || 1) + ' attempt(s) · payload kept in broadcasts.jsonl, needs a manual look');
  }

  const lines = [];
  lines.push('ghostpay monitor · ' + nowIso.slice(0, 16).replace('T', ' ') + 'Z');
  lines.push('fees ' + window + ': earned ' + formatEth(tNew.earned) + ' ETH (' + tNew.earnedN + ')'
    + ' · forwarded ' + formatEth(tNew.forwarded) + ' ETH (' + tNew.forwardedN + ')');
  lines.push('fees all time: earned ' + formatEth(tAll.earned) + ' ETH (' + tAll.earnedN + ')'
    + ' · forwarded ' + formatEth(tAll.forwarded) + ' ETH (' + tAll.forwardedN + ')');
  lines.push('reaper ' + window + ': confirmed ' + counts.confirmed + ' · replaced ' + counts.replaced
    + ' · reverted ' + counts.reverted + ' · given-up ' + counts.givenUp
    + ' · untracked ' + counts.untracked + ' · in-flight ' + counts.inflight);
  if (runners.length) {
    for (const b of balances) {
      lines.push('runner ' + b.addr + ': ' + (b.eth == null
        ? 'balance unavailable (' + b.error + ')'
        : fmtNum(b.eth) + ' ETH' + (b.eth < LOW_BALANCE_ETH ? ' LOW (threshold ' + fmtNum(LOW_BALANCE_ETH) + ' ETH)' : '')));
    }
  } else {
    lines.push('runners: none configured (set RUNNER_ADDRESSES or pass --runner 0x…)');
  }
  lines.push('alerts: ' + (alerts.length ? alerts.length + ' (sent separately)' : 'none'));
  const digest = lines.join('\n');
  const alertText = alerts.length ? 'GHOSTPAY ALERT\n' + alerts.map(a => '· ' + a).join('\n') : null;

  if (hasTelegram) {
    try {
      if (alertText) await sendTelegram(alertText);
      await sendTelegram(digest);
      console.log('monitor: digest sent to telegram chat ' + chatId + (alerts.length ? ' · ' + alerts.length + ' alert(s)' : ''));
    } catch (e) {
      console.error('monitor: telegram delivery failed: ' + errMsg(e) + ' · digest follows');
      console.log(digest);
      if (alertText) console.log(alertText);
      process.exitCode = 1;
    }
  } else {
    console.log('monitor: telegram not configured (set TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID or monitor.local.json) · digest follows');
    console.log(digest);
    if (alertText) console.log(alertText);
  }

  state.lastRun = nowIso;
  for (const e of newGivenUp) state.alertedGivenUp.push(String(e.hash).toLowerCase());
  try { saveState(); }
  catch (e) { console.error('monitor: state write failed: ' + errMsg(e)); process.exitCode = 1; }
}

main().catch(e => { console.error('monitor: ' + errMsg(e)); process.exit(1); });
