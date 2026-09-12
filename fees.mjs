#!/usr/bin/env node
// fees.mjs — ghostpay relayer fee ledger (no deps).
//
// serve.mjs appends one JSON line per fee-bearing request to fees.jsonl via logFee():
//   {ts, kind: "sweep-intent"|"sweep-intent-batch"|"pp-withdraw", feeBps, estFeeWei, txHash, runner}
//   sweep-intent / sweep-intent-batch: estFeeWei = stealth ETH balance * feeBps / 10000,
//     estimated at preflight from the balance fetched before broadcast. A batch writes one
//     line per swept stealth address, all sharing one txHash. For token sweeps the stealth
//     ETH balance is not the swept asset, so the estimate is rough.
//   pp-withdraw: estFeeWei = withdrawnValue (public signal) * relayFeeBPS / 10000, the fee
//     the Privacy Pools entrypoint pays the runner inside the withdrawal itself.
// Announce requests carry no fee and are never logged.
//
//   node fees.mjs                  report
//   FEES_FILE=/path/to.jsonl node fees.mjs
import { readFile, appendFile } from 'fs/promises';
import https from 'https';
import { fileURLToPath, pathToFileURL } from 'url';

const FEES_FILE = process.env.FEES_FILE || fileURLToPath(new URL('./fees.jsonl', import.meta.url));

// called by serve.mjs after every successful fee-bearing broadcast; never throws.
export async function logFee(entry) {
  try {
    await appendFile(FEES_FILE, JSON.stringify({ ts: new Date().toISOString(), ...entry }) + '\n');
  } catch (e) {
    console.warn('fee ledger append failed:', e.message);
  }
}

// wei -> trimmed ETH decimal string (BigInt math, no ethers).
function formatEth(wei) {
  const w = BigInt(wei);
  const whole = w / 10n ** 18n;
  const frac = (w % 10n ** 18n).toString().padStart(18, '0').replace(/0+$/, '');
  return frac ? `${whole}.${frac}` : whole.toString();
}
const fmtUsd = n => '$' + n.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });

// same source as serve.mjs GET /price: CoinGecko, 60s cache, fail soft (null).
let priceCache = { at: 0, usd: null };
function ethUsd() {
  if (priceCache.usd != null && Date.now() - priceCache.at < 60000) return Promise.resolve(priceCache.usd);
  const url = 'https://api.coingecko.com/api/v3/simple/price?ids=ethereum&vs_currencies=usd';
  return new Promise(resolve => {
    const req = https.get(url, { timeout: 10000, headers: { accept: 'application/json', 'user-agent': 'ghostpay-fees/1.0' } }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        try {
          const j = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          const usd = j && j.ethereum && j.ethereum.usd;
          if (typeof usd !== 'number') return resolve(null);
          priceCache = { at: Date.now(), usd };
          resolve(usd);
        } catch { resolve(null); }
      });
    });
    req.on('timeout', () => req.destroy());
    req.on('error', () => resolve(null));
  });
}

// Monday 00:00 local time of the week containing ts.
function mondayOf(ts) {
  const d = new Date(ts);
  d.setHours(0, 0, 0, 0);
  d.setDate(d.getDate() - ((d.getDay() + 6) % 7));
  return d;
}
const dateStr = d => d.toISOString().slice(0, 10);

async function main() {
  let lines = [];
  try {
    lines = (await readFile(FEES_FILE, 'utf8')).split('\n').filter(Boolean);
  } catch {
    console.log('GHOSTPAY fee ledger: no ' + FEES_FILE + ' yet (no fee-bearing requests logged).');
    return;
  }
  const entries = [];
  for (const l of lines) {
    try {
      const e = JSON.parse(l);
      if (e && e.kind && e.estFeeWei != null) entries.push(e);
    } catch { /* skip malformed lines */ }
  }

  const byKind = new Map();
  let total = 0n;
  for (const e of entries) {
    const k = byKind.get(e.kind) || { wei: 0n, n: 0 };
    k.wei += BigInt(e.estFeeWei); k.n++;
    byKind.set(e.kind, k);
    total += BigInt(e.estFeeWei);
  }

  // weekly buckets: the last 8 Mondays up to this week.
  const weeks = [];
  const thisMonday = mondayOf(Date.now());
  for (let i = 7; i >= 0; i--) {
    const m = new Date(thisMonday);
    m.setDate(m.getDate() - i * 7);
    weeks.push({ start: m, wei: 0n, n: 0 });
  }
  for (const e of entries) {
    const t = Date.parse(e.ts);
    if (!Number.isFinite(t)) continue;
    const m = mondayOf(t);
    const w = weeks.find(w => w.start.getTime() === m.getTime());
    if (w) { w.wei += BigInt(e.estFeeWei); w.n++; }
  }
  const last4 = weeks.slice(-4).reduce((a, w) => a + w.wei, 0n);
  const arr = last4 * 13n; // 4 weeks annualized: 52 / 4

  const usd = await ethUsd();
  const usdOf = wei => usd == null ? null : fmtUsd(Number(formatEth(wei)) * usd);

  console.log(`GHOSTPAY fee ledger · ${FEES_FILE} · ${entries.length} entries`);
  const kinds = ['sweep-intent', 'sweep-intent-batch', 'pp-withdraw'];
  console.log('totals: ' + kinds.map(k => {
    const v = byKind.get(k) || { wei: 0n, n: 0 };
    return `${k} ${formatEth(v.wei)} ETH (${v.n})`;
  }).join(' · '));
  console.log(`total: ${formatEth(total)} ETH` + (usd == null ? ' (USD unavailable: price fetch failed)'
    : ` ≈ ${usdOf(total)} (ETH ${fmtUsd(usd)})`));
  console.log('weekly (last 8 weeks, week starting):');
  for (const w of weeks) console.log(`  ${dateStr(w.start)}: ${formatEth(w.wei)} ETH (${w.n})`);
  console.log(`ARR run-rate (last 4 weeks x 13): ${formatEth(arr)} ETH` + (usd == null ? '' : ` ≈ ${usdOf(arr)}`));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(e => { console.error('fees.mjs: ' + (e && e.message || e)); process.exit(1); });
}
