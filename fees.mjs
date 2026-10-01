#!/usr/bin/env node
// fees.mjs — ghostpay relayer fee ledger (no deps).
//
// serve.mjs appends one JSON line per fee-bearing request to fees.jsonl via logFee():
//   {ts, kind: "sweep-intent"|"sweep-intent-batch"|"pp-withdraw", feeBps, estFeeWei, txHash, runner}
//   sweep-intent / sweep-intent-batch: estFeeWei = stealth ETH balance * feeBps / 10000,
//     estimated at preflight from the balance fetched before broadcast. A batch writes one
//     line per swept stealth address, all sharing one txHash.
//   Token sweeps (intent actions 2/3) and USDC withdrawals add asset + assetSymbol +
//     assetDecimals, and estFeeWei is denominated in that asset's base units. Those lines
//     are kept out of the ETH totals and reported per asset at the end.
//   pp-withdraw: estFeeWei = withdrawnValue (public signal) * relayFeeBPS / 10000, the fee
//     the Privacy Pools entrypoint pays the runner inside the withdrawal itself. ETH pool
//     withdrawals carry asset = the ETH sentinel and count as ETH.
//   fee-forward: written by the serve.mjs auto-forwarder when a runner sweeps its accrued
//     fees to FEE_OWNER; estFeeWei is the forwarded amount (an outflow, not revenue). These
//     lines feed the forward totals below and are excluded from the revenue + ARR math.
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

// fee asset of a ledger line: estFeeWei is denominated in it. Lines without an asset
// field (and the ETH sentinel) are ETH at 18 decimals, exactly as before the token pools.
const ETH_SENTINEL = '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';
const KNOWN_ASSETS = new Map([
  ['0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48', { sym: 'USDC', dec: 6 }],
]);
function assetOf(e) {
  const a = typeof e.asset === 'string' ? e.asset.toLowerCase() : '';
  if (!a || a === ETH_SENTINEL) return { key: 'ETH', sym: 'ETH', dec: 18 };
  const k = KNOWN_ASSETS.get(a);
  if (k) return { key: k.sym, ...k };
  return { key: a, sym: e.assetSymbol || a.slice(0, 10), dec: Number.isFinite(e.assetDecimals) ? e.assetDecimals : 18 };
}

// wei -> trimmed ETH decimal string (BigInt math, no ethers).
function formatEth(wei) {
  const w = BigInt(wei);
  const whole = w / 10n ** 18n;
  const frac = (w % 10n ** 18n).toString().padStart(18, '0').replace(/0+$/, '');
  return frac ? `${whole}.${frac}` : whole.toString();
}
// base units -> trimmed decimal string at the asset's precision (BigInt math).
function formatUnits(units, dec) {
  const w = BigInt(units), d = 10n ** BigInt(dec);
  const whole = w / d;
  const frac = (w % d).toString().padStart(dec, '0').replace(/0+$/, '');
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

  // fee-forward lines are outflows to the owner, not revenue: they feed the forward
  // totals at the end and stay out of the earned totals, weekly buckets, and ARR.
  const forwards = entries.filter(e => e.kind === 'fee-forward');
  const earned = entries.filter(e => e.kind !== 'fee-forward');
  // token-denominated lines (a non-ETH asset field) never enter the ETH totals: they are
  // reported per asset at the end. Lines without an asset field are ETH, as before.
  const ethEarned = earned.filter(e => assetOf(e).key === 'ETH');
  const tokEarned = earned.filter(e => assetOf(e).key !== 'ETH');

  const byKind = new Map();
  let total = 0n;
  for (const e of ethEarned) {
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
  for (const e of ethEarned) {
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

  // token-denominated fees: per-asset totals, never mixed into the ETH totals above.
  if (tokEarned.length) {
    const byAsset = new Map();
    for (const e of tokEarned) {
      const a = assetOf(e);
      const cur = byAsset.get(a.key) || { sym: a.sym, dec: a.dec, units: 0n, n: 0 };
      cur.units += BigInt(e.estFeeWei); cur.n++;
      byAsset.set(a.key, cur);
    }
    console.log('token fees (not in the ETH totals): '
      + [...byAsset.values()].map(a => `${formatUnits(a.units, a.dec)} ${a.sym} (${a.n})`).join(' · '));
  }

  let fwdTotal = 0n, fwdLast = null;
  for (const e of forwards) {
    fwdTotal += BigInt(e.estFeeWei);
    if (!fwdLast || e.ts > fwdLast) fwdLast = e.ts;
  }
  console.log(`fee-forward: ${formatEth(fwdTotal)} ETH forwarded to owner (${forwards.length})` + (fwdLast ? ` · last ${fwdLast}` : ''));
  console.log(`runner holdings (earned minus forwarded): ${formatEth(total - fwdTotal)} ETH` + (usd == null ? '' : ` ≈ ${usdOf(total - fwdTotal)}`));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(e => { console.error('fees.mjs: ' + (e && e.message || e)); process.exit(1); });
}
