// gp-invoices.mjs · GHOSTPAY invoice suite module (docs/GP-API.md), storage schema v4.
// Renders into the shell's tab mounts inside #gp-invoices on invoices.html: INVOICES
// (plus ESTIMATES), CUSTOMERS, ITEMS, RECURRING, SETTINGS over six localStorage
// registries: gp-profile, gp-clients, gp-items, gp-invoices, gp-estimates, gp-recurring.
// Invoices pin a pre-derived stealth address in a self-contained hash-param URL
// pointing at the homepage pay panel; payment status reconciles from GP payment
// events, summing multiple payments to the same pinned address into PARTIAL/PAID.
// On the homepage the same file runs without the suite mounts and keeps only its
// pay-a-ghost enhancement (memo format unchanged). Pure helpers are exported so a
// node smoke test can exercise migration, totals math and recurrence without a DOM.

// window.GP is captured lazily: app-core's own module graph takes time to evaluate,
// so on slow loads this module can evaluate before window.GP is
// assembled. boot() retries below instead of giving up.
let GP = typeof window !== 'undefined' ? window.GP || null : null;

// ── memo crypto ──
// Metadata format v2 (backward compatible: 1-byte metadata = bare view tag, no memo):
//   byte 0        view tag (unchanged, scanners filter on it exactly as before)
//   bytes 1..33   R: compressed ephemeral memo key (33 bytes)
//   bytes 34..45  AES-GCM nonce (12 bytes, random)
//   bytes 46..    AES-GCM ciphertext + tag of the UTF-8 memo
// Key agreement: S = keccak256(ECDH(r, viewPub)) mirrors the scheme-1 shared-secret
// derivation, but against the recipient's viewing key instead of the payment ephemeral
// key, so a payer can encrypt even for invoices that pin a pre-derived stealth address.
// AES key = keccak256(S || "memo"). Decryption needs only the viewing key.
const MEMO_TAG = Uint8Array.from([0x6d, 0x65, 0x6d, 0x6f]); // "memo"
const MEMO_OVERHEAD = 1 + 33 + 12 + 16; // tag + R + nonce + GCM tag
const METADATA_MAX = 1024; // serve.mjs /announce limit

const cat = (...as) => {
  const u = new Uint8Array(as.reduce((s, a) => s + a.length, 0));
  let o = 0;
  for (const a of as) { u.set(a, o); o += a.length; }
  return u;
};

export async function packMemoMetadata({ viewPub, viewTag, memo, crypto: C }) {
  if (!crypto.subtle) throw new Error('memos need a secure context (https or localhost): this page is plain http, so the memo cannot be encrypted. Clear the memo field to pay without it.');
  const pub = typeof viewPub === 'string' ? C.buf(viewPub) : viewPub;
  const r = C.mod(BigInt(C.hex(C.secp256k1.utils.randomPrivateKey())));
  const R = C.secp256k1.getPublicKey(r, true);
  const S = C.keccak_256(C.secp256k1.getSharedSecret(r, pub, true));
  const keyBytes = C.keccak_256(cat(S, MEMO_TAG));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const aesKey = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, aesKey, new TextEncoder().encode(memo)));
  const out = cat(Uint8Array.from([viewTag & 0xff]), R, nonce, ct);
  if (out.length > METADATA_MAX) throw new Error('memo too long: packed metadata exceeds the 1024-byte announcer limit');
  return C.hex(out);
}

export async function unpackMemoMetadata({ viewPriv, metadata, crypto: C }) {
  const md = typeof metadata === 'string' ? C.buf(metadata) : metadata;
  if (!md || md.length < MEMO_OVERHEAD) return null; // 1-byte view tag (legacy) or too short: no memo
  try {
    const R = md.slice(1, 34), nonce = md.slice(34, 46), ct = md.slice(46);
    const S = C.keccak_256(C.secp256k1.getSharedSecret(C.buf(viewPriv), R, true));
    const keyBytes = C.keccak_256(cat(S, MEMO_TAG));
    const aesKey = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, aesKey, ct);
    return new TextDecoder().decode(pt);
  } catch {
    return null; // not a memo, wrong key, or corrupt: treat as no memo
  }
}

// ── ENS namehash (EIP-137, recursive keccak256, no deps) ──
export function namehash(name, keccak) {
  let node = new Uint8Array(32);
  const n = (name || '').trim().toLowerCase().replace(/\.+$/, '');
  if (n) {
    for (const label of n.split('.').reverse()) {
      node = keccak(cat(node, keccak(new TextEncoder().encode(label))));
    }
  }
  return '0x' + [...node].map(x => x.toString(16).padStart(2, '0')).join('');
}

// ── pure suite helpers (exported for the node smoke test) ──

// gp-profile, schema v4. v4 adds taxNumber (VAT / tax id printed on documents).
export const DEFAULT_PROFILE = {
  name: '', contact: '', addressLines: [], token: 'USDC', prefix: 'GP-', next: 1,
  terms: 'payment due on receipt', taxPct: null, taxNumber: '', accentColor: null, footerNote: '',
};

const round2 = n => Math.round((n + Number.EPSILON) * 100) / 100;
const round6 = n => Math.round(n * 1e6) / 1e6;

// Line items → subtotal/discount/tax/total, schema v4 (Moneybird-style per-line tax).
// Rounding rules: each line rounds on its own (gross, then its per-line discount, then
// the net), rounded nets sum into per-rate bases, and tax rounds once per rate group.
// Per-line it.taxPct / it.discountPct win; the taxPct/discountPct arguments are only
// defaults for lines that carry no own rate (legacy callers, recurring templates).
// taxLines is the grouped tax block: [{ rate, base, amount }] sorted by rate.
export function computeTotals(items, taxPct, discountPct) {
  const defTax = parseFloat(taxPct);
  const defDisc = parseFloat(discountPct);
  const groups = new Map(); // rate → sum of rounded line nets
  let subtotal = 0, discountAmount = 0;
  for (const it of items || []) {
    const gross = round2((parseFloat(it.qty) || 0) * (parseFloat(it.unitPrice) || 0));
    const dp = it.discountPct != null && it.discountPct !== '' ? parseFloat(it.discountPct) : defDisc;
    const disc = Number.isFinite(dp) && dp > 0 ? round2(gross * dp / 100) : 0;
    const net = round2(gross - disc);
    const tp = it.taxPct != null && it.taxPct !== '' ? parseFloat(it.taxPct) : defTax;
    const rate = Number.isFinite(tp) && tp > 0 ? tp : 0;
    subtotal = round2(subtotal + gross);
    discountAmount = round2(discountAmount + disc);
    if (rate > 0) groups.set(rate, round2((groups.get(rate) || 0) + net));
  }
  const taxLines = [...groups.entries()]
    .sort((a, b) => a[0] - b[0])
    .map(([rate, base]) => ({ rate, base, amount: round2(base * rate / 100) }));
  const taxAmount = round2(taxLines.reduce((s, tl) => s + tl.amount, 0));
  return {
    subtotal,
    discountPct: Number.isFinite(defDisc) && defDisc > 0 ? defDisc : null, discountAmount,
    taxPct: Number.isFinite(defTax) && defTax > 0 ? defTax : null, taxAmount,
    taxLines,
    total: round2(subtotal - discountAmount + taxAmount),
  };
}

// The grouped tax block of a stored record. v4 records carry taxLines; anything older
// synthesizes one group from the stored invoice-level rate and stored totals (issued
// numbers never shift), falling back to computing from the items when there are no
// stored totals. Lines with a nonpositive or nonnumeric rate are dropped.
// Same contract as taxLinesOf in gp-reports.mjs, duplicated so both files stay
// importable on their own.
export function taxLinesOf(rec) {
  if (rec && Array.isArray(rec.taxLines)) {
    return rec.taxLines
      .map(tl => ({ rate: +tl.rate, base: +tl.base, amount: +tl.amount }))
      .filter(tl => Number.isFinite(tl.rate) && tl.rate > 0 && Number.isFinite(tl.base) && Number.isFinite(tl.amount));
  }
  const rate = Number(rec && rec.taxPct) || 0;
  if (rate > 0 && Number.isFinite(rec.subtotal)) {
    return [{ rate, base: round2(rec.subtotal - (Number(rec.discountAmount) || 0)), amount: Number(rec.taxAmount) || 0 }];
  }
  return computeTotals(rec ? rec.items : [], rec && rec.taxPct, rec && rec.discountPct).taxLines;
}

// Document numbers come from the profile counter: prefix + zero-padded counter.
// Invoices and estimates share the sequence.
export function allocateNumber(profile) {
  const p = profile || {};
  const prefix = typeof p.prefix === 'string' && p.prefix ? p.prefix : 'GP-';
  const n = Number.isFinite(+p.next) && +p.next > 0 ? Math.floor(+p.next) : 1;
  return { number: prefix + String(n).padStart(4, '0'), next: n + 1 };
}

// Derived payment state from the summed payments to the pinned stealth address:
// nothing → null, below total → PARTIAL, at/over total → PAID. Never stored.
export function paymentState(rec, paidSum) {
  const paid = paidSum ?? (Number.isFinite(rec.paidAmount) ? rec.paidAmount : 0);
  if (!(paid > 0)) return null;
  return paid + 1e-9 >= (Number(rec.total) || 0) ? 'PAID' : 'PARTIAL';
}

// Effective status. Terminal stored states pass through (PAID, ACCEPTED, DECLINED).
// OVERDUE is derived (SENT past expiry), PARTIAL is derived (payments below total),
// PAID can also be derived when the summed payments reach the total. DRAFT → SENT is
// manual; PAID normally arrives via GP payment events.
export function invStatus(rec, now, paidSum) {
  if (!rec) return 'DRAFT';
  if (rec.kind === 'estimate') {
    if (rec.status === 'ACCEPTED' || rec.status === 'DECLINED') return rec.status;
    if (rec.status === 'SENT' && rec.expiry && (now ?? Date.now()) > rec.expiry) return 'OVERDUE';
    return rec.status || 'DRAFT';
  }
  if (rec.status === 'PAID') return 'PAID';
  if (rec.status === 'SENT') {
    const ps = paymentState(rec, paidSum);
    if (ps) return ps;
    if (rec.expiry && (now ?? Date.now()) > rec.expiry) return 'OVERDUE';
    return 'SENT';
  }
  return rec.status || 'DRAFT';
}

// Profile upgrade to schema v4. Idempotent: existing fields keep their values, missing
// fields get defaults. A legacy string address becomes one address line. v4 adds
// taxNumber (VAT / tax id); there are deliberately no bank fields: the invoice's
// stealth address is the payment detail.
export function migrateProfile(p) {
  const out = { ...DEFAULT_PROFILE, ...(p || {}) };
  out.addressLines = Array.isArray(out.addressLines)
    ? out.addressLines.map(String)
    : (typeof out.addressLines === 'string' && out.addressLines ? out.addressLines.split('\n') : []);
  out.token = out.token === 'ETH' ? 'ETH' : 'USDC';
  out.taxPct = Number.isFinite(+out.taxPct) && +out.taxPct > 0 ? +out.taxPct : null;
  out.taxNumber = typeof out.taxNumber === 'string' ? out.taxNumber : '';
  out.accentColor = typeof out.accentColor === 'string' && out.accentColor ? out.accentColor : null;
  out.footerNote = typeof out.footerNote === 'string' ? out.footerNote : '';
  out.next = Number.isFinite(+out.next) && +out.next > 0 ? Math.floor(+out.next) : 1;
  return out;
}

// v1/v2 → v3 record upgrade. v1 records were { id, amount, token, note,
// stealthAddress, created, url, status: 'UNPAID'|'PAID', expiry }: the amount becomes
// a single line item, UNPAID becomes SENT (the link was already handed out), a number
// is assigned. v2 fields carry over; the v3 additions (discount, paidAmount,
// estimateOf, kind) get defaults. kind is 'invoice' or 'estimate'.
function migrateV3(rec, number, kind) {
  const amount = parseFloat(rec.amount) || 0;
  const items = Array.isArray(rec.items) && rec.items.length
    ? rec.items.map(it => ({ description: it.description || 'item', qty: parseFloat(it.qty) || 0, unitPrice: parseFloat(it.unitPrice) || 0 }))
    : [{ description: rec.note || kind, qty: 1, unitPrice: amount }];
  const t = computeTotals(items, rec.taxPct, rec.discountPct);
  const st = String(rec.status || '').toUpperCase();
  const status = kind === 'estimate'
    ? (['DRAFT', 'SENT', 'ACCEPTED', 'DECLINED'].includes(st) ? st : 'SENT')
    : (st === 'PAID' ? 'PAID' : (st === 'DRAFT' ? 'DRAFT' : 'SENT'));
  return {
    v: 3,
    id: rec.id || 'inv-' + Date.now().toString(36),
    number: rec.number || number || rec.id,
    clientId: rec.clientId || null,
    clientName: rec.clientName || '',
    items,
    token: rec.token === 'ETH' ? 'ETH' : 'USDC',
    subtotal: Number.isFinite(rec.subtotal) ? rec.subtotal : t.subtotal,
    taxPct: rec.taxPct ?? t.taxPct,
    taxAmount: Number.isFinite(rec.taxAmount) ? rec.taxAmount : t.taxAmount,
    discountPct: rec.discountPct ?? t.discountPct,
    discountAmount: Number.isFinite(rec.discountAmount) ? rec.discountAmount : t.discountAmount,
    total: Number.isFinite(rec.total) ? rec.total : t.total,
    note: rec.note || '',
    stealthAddress: rec.stealthAddress || '',
    created: rec.created || Date.now(),
    url: rec.url || '',
    expiry: rec.expiry || null,
    status,
    sentAt: rec.sentAt || null,
    paidAt: rec.paidAt || null,
    paidTx: rec.paidTx || null,
    paidAmount: Number.isFinite(rec.paidAmount) ? rec.paidAmount : null,
    estimateOf: rec.estimateOf || null,
    kind,
  };
}

// v3 → v4 record upgrade: additive. Each line gains taxPct/discountPct (seeded from the
// legacy invoice-level rates) and the record gains taxLines, synthesized from the stored
// v3 totals so the issued document's numbers never shift by a rounding cent. taxLines
// on a v3 record (hand-written) is sanitized and kept.
function upgradeV4(rec) {
  const items = rec.items.map(it => ({
    ...it,
    taxPct: Number.isFinite(+it.taxPct) && +it.taxPct >= 0 ? +it.taxPct : (rec.taxPct > 0 ? rec.taxPct : 0),
    discountPct: Number.isFinite(+it.discountPct) && +it.discountPct > 0 ? +it.discountPct : (rec.discountPct > 0 ? rec.discountPct : null),
  }));
  const taxLines = Array.isArray(rec.taxLines)
    ? taxLinesOf({ taxLines: rec.taxLines })
    : (rec.taxPct > 0
      ? [{ rate: rec.taxPct, base: round2(rec.subtotal - (rec.discountAmount || 0)), amount: rec.taxAmount || 0 }]
      : []);
  return { ...rec, v: 4, items, taxLines };
}

// Any older record → v4. Idempotent: v4 records pass through untouched.
export function migrateInvoice(rec, number, kind) {
  kind = kind === 'estimate' ? 'estimate' : 'invoice';
  if (rec && rec.v === 4) return rec;
  return upgradeV4(rec && rec.v === 3 ? { ...rec, kind } : migrateV3(rec, number, kind));
}

// Whole-registry migration: legacy records without a number get one in creation order
// and the profile counter advances past them (numbered records keep their number and
// burn nothing). Idempotent: v4 records pass through untouched.
export function migrateRegistry(records, profile, kind) {
  const p = migrateProfile(profile);
  const out = (records || []).map(r => (r && r.v === 4 ? r : null));
  const legacy = (records || [])
    .map((r, i) => ({ r, i }))
    .filter(x => x.r && x.r.v !== 4)
    .sort((a, b) => (a.r.created || 0) - (b.r.created || 0));
  for (const { r, i } of legacy) {
    let number = r.number;
    if (!number) {
      const a = allocateNumber(p);
      p.next = a.next;
      number = a.number;
    }
    out[i] = migrateInvoice(r, number, kind);
  }
  return { records: out.filter(Boolean), profile: p };
}

// Recurring templates: the run after `date` every N weeks (7-day steps) or N calendar
// months. GENERATE NOW advances nextDate by exactly one period so a backlog can be
// caught up one invoice at a time.
export function nextRecurrence(date, everyN, unit) {
  const n = Number.isFinite(+everyN) && +everyN > 0 ? Math.floor(+everyN) : 1;
  const d = new Date(Number(date) || Date.now());
  if (unit === 'months') {
    const day = d.getDate();
    d.setMonth(d.getMonth() + n);
    // jan 31 + 1 month would roll into march: clamp to the last day of the target month
    if (d.getDate() !== day) d.setDate(0);
  } else {
    d.setDate(d.getDate() + 7 * n);
  }
  return d.getTime();
}

// ── everything below runs only in the browser with window.GP present ──

const INV_KEY = 'gp-invoices';
const EST_KEY = 'gp-estimates';
const REC_KEY = 'gp-recurring';
const ITEMS_KEY = 'gp-items';
const MEMO_KEY = 'gp-invoice-memos';
const PROFILE_KEY = 'gp-profile';
const CLIENTS_KEY = 'gp-clients';
const ENS_PUBLIC_RESOLVER = '0x231b0Ee14048e9dCcD1d247744d114a4EB5E8E63';

const lsGet = (k, d) => { try { return JSON.parse(localStorage.getItem(k)) ?? d; } catch { return d; } };
const lsSet = (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* best-effort */ } };

const loadProfile = () => migrateProfile(lsGet(PROFILE_KEY, {}));
const saveProfile = p => lsSet(PROFILE_KEY, migrateProfile(p));
const loadClients = () => lsGet(CLIENTS_KEY, []);
const saveClients = c => lsSet(CLIENTS_KEY, c);
const loadItems = () => lsGet(ITEMS_KEY, []);
const saveItems = c => lsSet(ITEMS_KEY, c);
const loadRecurring = () => lsGet(REC_KEY, []);
const saveRecurring = r => lsSet(REC_KEY, r);
const loadMemos = () => lsGet(MEMO_KEY, {});
const saveMemos = m => lsSet(MEMO_KEY, m);
const memos = typeof localStorage !== 'undefined' ? loadMemos() : {};

// Registry loads migrate legacy records on the way out and persist the result once.
function loadReg(key, kind) {
  const raw = lsGet(key, []);
  if (!raw.some(r => r && r.v !== 4)) return raw;
  const { records, profile } = migrateRegistry(raw, loadProfile(), kind);
  lsSet(key, records);
  saveProfile(profile);
  return records;
}
const loadInv = () => loadReg(INV_KEY, 'invoice');
const saveInv = inv => lsSet(INV_KEY, inv);
const loadEst = () => loadReg(EST_KEY, 'estimate');
const saveEst = est => lsSet(EST_KEY, est);

// ── formatting ──
const fmtAmt = (n, token) => token === 'ETH'
  ? String(parseFloat(Number(n).toFixed(6)))
  : Number(n).toFixed(2);
const fmtUsd = (amount, token, ethPrice) => {
  const v = token === 'USDC' ? Number(amount) : (ethPrice == null ? null : Number(amount) * ethPrice);
  if (v == null || !Number.isFinite(v)) return null;
  return '$' + v.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
};
const fmtDate = ts => new Date(ts).toISOString().slice(0, 10);
const dateInputVal = ts => {
  const d = new Date(ts);
  return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
};
const escHtml = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const monogram = name => {
  const w = (name || '').trim().split(/\s+/).filter(Boolean);
  return (w.length ? w.slice(0, 2).map(x => x[0]).join('') : 'GP').toUpperCase();
};

// One-click reminder for overdue invoices: a short polite message with the payment
// link, copied to the clipboard (no email backend). Pure, so the smoke test can build it.
export function reminderText(rec, profile) {
  const p = profile || {};
  const lines = [
    'hi ' + (rec.clientName || 'there') + ',',
    '',
    'reminder: invoice ' + rec.number + ' for ' + fmtAmt(rec.total, rec.token) + ' ' + rec.token
      + (rec.expiry ? ' was due on ' + fmtDate(rec.expiry) + ' and is still open.' : ' is still open.'),
    '',
  ];
  if (rec.url) lines.push('pay here: ' + rec.url, '');
  lines.push('thanks,', p.name || 'ghostpay');
  return lines.join('\n');
}

// ── qrcode-generator: same vendored module the core uses, loaded lazily so this file
// stays importable under plain node (no DOM, no network) for the smoke test.
let qrLib = null;
async function getQr() {
  qrLib ??= (await import('./vendor/qrcode-generator.mjs')).default;
  return qrLib;
}
async function drawQr(canvas, text) {
  const qrcode = await getQr();
  const qr = qrcode(0, 'M');
  qr.addData(text);
  qr.make();
  const n = qr.getModuleCount(), scale = 4;
  canvas.width = canvas.height = n * scale;
  const ctx = canvas.getContext('2d');
  ctx.fillStyle = '#fff';
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = '#000';
  for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) if (qr.isDark(r, c)) ctx.fillRect(c * scale, r * scale, scale, scale);
}
async function qrDataUrl(text) {
  const cv = document.createElement('canvas');
  await drawQr(cv, text);
  return cv.toDataURL('image/png');
}

function copyBtn(text, btn, label) {
  navigator.clipboard.writeText(text).then(
    () => { btn.textContent = 'COPIED ✓'; setTimeout(() => { btn.textContent = label; }, 1200); },
    () => GP.toast('copy failed: clipboard unavailable')
  );
}

function download(filename, text, type) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], { type: type || 'application/octet-stream' }));
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
}

// USD price: the relayer proxies CoinGecko at ./price (60s cache); fall back to the
// price the status strip last saw.
let priceCache = { at: 0, usd: null };
async function ethUsd() {
  if (priceCache.usd != null && Date.now() - priceCache.at < 60000) return priceCache.usd;
  try {
    const r = await fetch('./price');
    if (r.ok) {
      const j = await r.json();
      const usd = j && j.ethereum && typeof j.ethereum.usd === 'number' ? j.ethereum.usd
        : (j && typeof j.usd === 'number' ? j.usd : null);
      if (usd != null) { priceCache = { at: Date.now(), usd }; return usd; }
    }
  } catch { /* relayer offline: use the strip price below */ }
  return GP.state.ethPriceUsd ?? null;
}

// ── invoice suite UI ──
// Renders into the shell's tab mounts. Every renderer is defensive: a missing mount
// means the view is skipped, so the shell can land tabs in any order. Styles come from
// frag-invoices.html: fetched and injected into #gp-invoices (the shell links only
// gp-ui.css), with an embedded copy below for static file:// opens.
async function injectFrag() {
  if (document.getElementById('gpinv-styles')) return;
  const container = document.getElementById('gp-invoices');
  if (!container) return;
  let html = null;
  try { const r = await fetch('./frag-invoices.html'); if (r.ok) html = await r.text(); } catch { /* static open: use the embedded copy */ }
  container.insertAdjacentHTML('afterbegin', html || FRAG_FALLBACK);
}

// offline fallback: identical copy of frag-invoices.html
const FRAG_FALLBACK = `<style id="gpinv-styles">
  #gp-invoices h3 { font-size:11px; letter-spacing:.25em; color:#888; font-weight:400; margin:24px 0 10px; }
  #gp-invoices .gpinv-box { border:1px solid #333; padding:16px; }
  #gp-invoices .gpinv-grid { display:grid; grid-template-columns:1fr 1fr; gap:14px; }
  #gp-invoices .gpinv-lbl { font-size:10px; letter-spacing:.2em; color:#666; margin-bottom:4px; }
  #gp-invoices .gpinv-muted { color:#777; }
  #gp-invoices .gpinv-mono { font-size:11px; color:#777; word-break:break-all; }
  #gp-invoices .gpinv-mg { width:46px; height:46px; border:1px solid #fff; display:flex; flex:none;
    align-items:center; justify-content:center; font-weight:700; letter-spacing:.1em; }
  #gp-invoices .gpinv-tablewrap { overflow-x:auto; }
  #gp-invoices table { width:100%; border-collapse:collapse; font-size:12px; }
  #gp-invoices th { text-align:left; font-size:10px; letter-spacing:.2em; color:#777; font-weight:400;
    padding:6px 10px 6px 0; border-bottom:1px solid #333; white-space:nowrap; }
  #gp-invoices td { padding:10px 10px 10px 0; border-bottom:1px solid #222; vertical-align:top; }
  #gp-invoices .gpinv-rowbtn { cursor:pointer; }
  #gp-invoices .gpinv-rowbtn:hover td { background:#0d0d0d; }
  #gp-invoices .gpinv-detail td { background:#0a0a0a; padding:16px; }
  #gp-invoices td input, #gp-invoices td select { margin-top:0; padding:8px 10px; font-size:12px; }
  /* status pills: same idiom as the inbox (outline, dim, solid) */
  #gp-invoices .gpinv-pill { display:inline-block; border:1px solid #fff; padding:2px 8px; font-size:10px;
    letter-spacing:.15em; white-space:nowrap; }
  #gp-invoices .gpinv-pill.dim { border-color:#444; color:#888; }
  #gp-invoices .gpinv-pill.solid { background:#fff; color:#000; font-weight:700; }
  #gp-invoices .gpinv-actions { display:flex; gap:8px; margin-top:14px; flex-wrap:wrap; }
  #gp-invoices .gpinv-actions button { width:auto; flex:1 1 auto; padding:10px 14px; font-size:11px; }
  #gp-invoices .gpinv-x { width:auto; padding:6px 12px; font-size:13px; min-height:0; }
  #gp-invoices .gpinv-empty { color:#888; font-size:12px; border:1px dashed #333; padding:18px;
    text-align:center; margin-top:4px; }
  /* status filter row */
  #gp-invoices .gpinv-filter { display:flex; gap:6px; flex-wrap:wrap; margin:16px 0 12px; }
  #gp-invoices .gpinv-filter button { width:auto; padding:6px 12px; font-size:10px; letter-spacing:.15em; }
  #gp-invoices .gpinv-filter button.on { background:#fff; color:#000; font-weight:700; border-color:#fff; }
  /* INVOICES / ESTIMATES sub-switch (only when the shell has no #tab-estimates mount) */
  #gp-invoices .gpinv-sub { display:flex; border:1px solid #333; margin-bottom:16px; }
  #gp-invoices .gpinv-sub button { background:#000; color:#888; border:0; border-right:1px solid #333;
    padding:10px 6px; font-size:10px; letter-spacing:.15em; font-weight:400; flex:1; width:auto; }
  #gp-invoices .gpinv-sub button:last-child { border-right:0; }
  #gp-invoices .gpinv-sub button.on { background:#fff; color:#000; font-weight:700; }
  /* editor save/cancel bar stays reachable on long forms */
  #gp-invoices .gpinv-sticky { position:sticky; bottom:0; background:#000; border-top:1px solid #333;
    padding:12px 0 8px; z-index:5; }
  @media (max-width:700px) {
    #gp-invoices .gpinv-grid { grid-template-columns:1fr; }
    #gp-invoices .gpinv-actions { flex-direction:column; }
    #gp-invoices .gpinv-actions button { width:100%; }
    #gp-invoices .gpinv-sub button, #gp-invoices .gpinv-filter button { min-height:44px; }
  }
</style>`;

async function initSuite() {
  await injectFrag();
  const $ = id => document.getElementById(id);
  const C = GP.crypto;
  const mounts = {
    invoices: $('tab-invoices'), estimates: $('tab-estimates'),
    customers: $('tab-customers'), items: $('tab-items'),
    recurring: $('tab-recurring'), settings: $('tab-settings'),
  };

  // view state (in-memory only)
  let invKind = 'invoice';       // sub-view inside #tab-invoices when there is no #tab-estimates mount
  let invFilter = 'ALL', estFilter = 'ALL';
  let showForm = false, formKind = 'invoice', editId = null;
  let formRows = [{ description: '', qty: 1, unitPrice: '', discPct: '', taxPct: '0' }];
  let formDraft = {};
  let recFormOpen = false, recEditId = null;
  let recRows = [{ description: '', qty: 1, unitPrice: '', discPct: '', taxPct: '0' }];
  let recDraft = {};
  let itemEditId = null;
  let itemDraft = { name: '', description: '', unitPrice: '', token: 'USDC', taxPct: '', discPct: '' };
  let openId = null, qrFor = null, recOpen = null;

  // status pills: same idiom as the inbox (outline default, dim for inactive,
  // solid for terminal-good)
  const pill = st => {
    const dim = st === 'DRAFT' || st === 'DECLINED' || st === 'PAUSED';
    const solid = st === 'PAID' || st === 'ACCEPTED' || st === 'DUE';
    return '<span class="gpinv-pill' + (dim ? ' dim' : '') + (solid ? ' solid' : '') + '">' + st + '</span>';
  };

  const findRec = id => loadInv().find(x => x.id === id) || loadEst().find(x => x.id === id) || null;

  // links point at the homepage: the payer lands on the pay panel, not the app
  function buildUrl({ amount, token, note, id, number, expiry, st, eph, vt }) {
    return location.origin + '/#' + GP.state.meta
      + '?pay=' + encodeURIComponent(amount + ' ' + token + (note ? ' · ' + note : ''))
      + '&inv=' + id + '&num=' + encodeURIComponent(number)
      + (expiry ? '&exp=' + expiry : '')
      + '&st=' + st + '&eph=' + eph + '&vt=' + vt;
  }
  // editing keeps the pinned stealth address: st/eph/vt ride inside the existing URL
  function parsePinned(url) {
    const q = String(url || '');
    const p = new URLSearchParams(q.includes('?') ? q.slice(q.indexOf('?') + 1) : '');
    return { st: p.get('st'), eph: p.get('eph'), vt: p.get('vt') };
  }

  // ── shared line-items editor (invoices, estimates, recurring templates) ──
  // Each row carries a tax rate picker (0% / 9% / 21% / custom, defaulting to the
  // profile rate) and an optional per-line discount %.
  const TAX_PRESETS = ['0', '9', '21'];
  function taxCellHtml(r, i, pref) {
    const rateStr = r.taxPct == null || r.taxPct === '' ? '' : String(r.taxPct);
    const sel = r._taxpick ?? (rateStr === '' ? '0' : (TAX_PRESETS.includes(rateStr) ? rateStr : 'custom'));
    return '<select data-row="' + i + '" data-f="taxpick" data-pref="' + pref + '" style="margin-top:0">'
      + TAX_PRESETS.map(v => '<option value="' + v + '"' + (sel === v ? ' selected' : '') + '>' + v + '%</option>').join('')
      + '<option value="custom"' + (sel === 'custom' ? ' selected' : '') + '>custom…</option>'
      + '</select>'
      + (sel === 'custom'
        ? '<input data-row="' + i + '" data-f="taxcustom" data-pref="' + pref + '" type="number" min="0" step="any" placeholder="%" value="' + escHtml(rateStr) + '" style="margin-top:6px">'
        : '');
  }

  function rowsTableHtml(rows, token, catalog, pref) {
    return '<div class="gpinv-tablewrap"><table id="gpinv-' + pref + '-items"><thead><tr>'
      + '<th style="width:34%">DESCRIPTION</th><th>QTY</th><th>UNIT PRICE</th><th>DISC %</th><th>TAX</th><th style="text-align:right">AMOUNT</th><th></th>'
      + '</tr></thead><tbody>'
      + rows.map((r, i) =>
          '<tr><td>'
          + '<select data-row="' + i + '" data-f="pick" data-pref="' + pref + '" style="margin-top:0;margin-bottom:6px">'
          + '<option value="">catalog item…</option>'
          + catalog.map((c, ci) =>
              '<option value="' + ci + '"' + (r._pick === String(ci) ? ' selected' : '') + '>'
              + escHtml(c.name) + ' · ' + fmtAmt(c.unitPrice, c.token) + ' ' + c.token + '</option>'
            ).join('')
          + '</select>'
          + '<input data-row="' + i + '" data-f="description" data-pref="' + pref + '" placeholder="description" value="' + escHtml(r.description) + '"></td>'
          + '<td><input data-row="' + i + '" data-f="qty" data-pref="' + pref + '" type="number" min="0" step="any" value="' + escHtml(r.qty) + '"></td>'
          + '<td><input data-row="' + i + '" data-f="unitPrice" data-pref="' + pref + '" type="number" min="0" step="any" placeholder="0.00" value="' + escHtml(r.unitPrice) + '"></td>'
          + '<td><input data-row="' + i + '" data-f="discPct" data-pref="' + pref + '" type="number" min="0" step="any" placeholder="0" value="' + escHtml(r.discPct ?? '') + '"></td>'
          + '<td style="white-space:nowrap">' + taxCellHtml(r, i, pref) + '</td>'
          + '<td style="text-align:right;white-space:nowrap" data-rowamt="' + i + '" data-pref="' + pref + '">' + fmtAmt((parseFloat(r.qty) || 0) * (parseFloat(r.unitPrice) || 0), token) + '</td>'
          + '<td style="width:1%"><button class="ghost gpinv-x" data-iact="' + pref + '-del-row" data-row="' + i + '" title="remove row">×</button></td></tr>'
        ).join('')
      + '</tbody></table></div>'
      + '<button class="ghost" data-iact="' + pref + '-add-row" style="width:auto;padding:8px 14px;font-size:11px;margin-top:10px">+ ADD ROW</button>';
  }

  function readRows(pref) {
    const rows = [];
    const tbl = $('gpinv-' + pref + '-items');
    if (!tbl) return null;
    tbl.querySelectorAll('tbody tr').forEach(tr => {
      const get = f => { const el = tr.querySelector('[data-f="' + f + '"]'); return el ? el.value : ''; };
      const taxpick = get('taxpick') || '0';
      rows.push({
        description: get('description').trim(), qty: get('qty'), unitPrice: get('unitPrice'),
        discPct: get('discPct'),
        taxPct: taxpick === 'custom' ? get('taxcustom') : taxpick,
        _pick: get('pick'), _taxpick: taxpick,
      });
    });
    return rows;
  }

  // v4 totals block: subtotal, total discount, one line per tax rate (rate · base ·
  // amount), grand total. The whole block rewrites on each keystroke (no inputs inside).
  function totalsInnerHtml(pref, t, token) {
    return '<div>subtotal · <b>' + fmtAmt(t.subtotal, token) + '</b></div>'
      + (t.discountAmount > 0 ? '<div>discount · −<b>' + fmtAmt(t.discountAmount, token) + '</b></div>' : '')
      + (t.taxLines || []).map(tl =>
          '<div>tax ' + tl.rate + '% on ' + fmtAmt(tl.base, token) + ' · <b>' + fmtAmt(tl.amount, token) + '</b></div>'
        ).join('')
      + '<div style="font-size:16px;margin-top:4px">total · <b>' + fmtAmt(t.total, token) + '</b> ' + token + '</div>'
      + '<div class="status" style="margin-top:2px" id="gpinv-' + pref + '-usd"></div>';
  }

  function totalsBlockHtml(pref, t, token) {
    return '<div style="margin-top:14px;text-align:right;font-size:12px" id="gpinv-' + pref + '-totals">'
      + totalsInnerHtml(pref, t, token)
      + '</div>';
  }

  // own attribute mutations (style toggles, link previews) must not retrigger the
  // tab-swap observer below: it would re-render mid-keystroke and drop focus
  let selfTouch = 0;
  const touchSelf = () => { selfTouch = Date.now(); };

  function paintTotals(pref, rows, token) {
    touchSelf();
    const t = computeTotals(rows, null, null);
    rows.forEach((r, i) => {
      const cell = document.querySelector('[data-rowamt="' + i + '"][data-pref="' + pref + '"]');
      if (cell) cell.textContent = fmtAmt((parseFloat(r.qty) || 0) * (parseFloat(r.unitPrice) || 0), token);
    });
    const box = $('gpinv-' + pref + '-totals');
    if (box) box.innerHTML = totalsInnerHtml(pref, t, token);
    const usdEl = $('gpinv-' + pref + '-usd');
    if (usdEl) {
      const direct = fmtUsd(t.total, token, GP.state.ethPriceUsd);
      if (direct) usdEl.textContent = '≈ ' + direct + ' usd';
      else ethUsd().then(px => {
        const u = fmtUsd(t.total, token, px);
        if (usdEl.isConnected) usdEl.textContent = u ? '≈ ' + u + ' usd' : 'usd estimate unavailable (relayer price feed offline)';
      });
    }
    return t;
  }

  // ── invoice / estimate editor ──
  // new rows default to the profile tax rate
  const blankRow = () => ({ description: '', qty: 1, unitPrice: '', discPct: '', taxPct: String(loadProfile().taxPct ?? 0) });

  function startForm(kind, rec) {
    const p = loadProfile();
    showForm = true;
    formKind = kind;
    editId = rec ? rec.id : null;
    formRows = rec
      ? rec.items.map(it => ({
          description: it.description, qty: it.qty, unitPrice: it.unitPrice,
          taxPct: it.taxPct > 0 ? String(it.taxPct) : '0',
          discPct: it.discountPct > 0 ? String(it.discountPct) : '',
        }))
      : [blankRow()];
    formDraft = {
      clientId: rec ? rec.clientId || '' : '',
      token: rec ? rec.token : p.token,
      note: rec ? rec.note : '',
      expDays: rec && rec.expiry ? Math.max(1, Math.round((rec.expiry - Date.now()) / 86400000)) : '',
    };
  }

  function editorHtml() {
    const kind = formKind;
    const p = loadProfile();
    const clients = loadClients();
    const catalog = loadItems();
    const d = formDraft;
    return '<h3>' + (editId ? 'EDIT ' : 'NEW ') + kind.toUpperCase() + '</h3>'
      + '<div class="gpinv-box">'
      + '<div class="gpinv-lbl">CLIENT</div>'
      + '<select id="gpinv-f-client" style="margin-top:4px"><option value="">no client</option>'
      + clients.map(c => '<option value="' + escHtml(c.id) + '"' + (d.clientId === c.id ? ' selected' : '') + '>' + escHtml(c.name) + '</option>').join('')
      + '</select>'
      + '<div class="gpinv-lbl" style="margin-top:14px">LINE ITEMS · TAX RATE PER ROW, DEFAULT ' + escHtml(String(p.taxPct ?? 0)) + '% FROM YOUR PROFILE</div>'
      + rowsTableHtml(formRows, d.token, catalog, 'f')
      + totalsBlockHtml('f', computeTotals(formRows, null, null), d.token)
      + '<div class="gpinv-lbl" style="margin-top:14px">TOKEN</div>'
      + '<select id="gpinv-f-token" style="margin-top:4px">'
      + ['USDC', 'ETH'].map(t => '<option' + (d.token === t ? ' selected' : '') + '>' + t + '</option>').join('')
      + '</select>'
      + '<input id="gpinv-f-note" placeholder="note (optional: prefills the payer\'s encrypted memo)" value="' + escHtml(d.note) + '">'
      + '<input id="gpinv-f-exp" type="number" min="0" placeholder="expires in days (optional: blank = never)" value="' + escHtml(d.expDays) + '">'
      + '<div class="gpinv-actions gpinv-sticky">'
      + '<button data-iact="save-form">' + (editId ? 'SAVE CHANGES' : 'CREATE ' + kind.toUpperCase()) + '</button>'
      + '<button class="ghost" data-iact="toggle-form">CANCEL</button>'
      + '</div>'
      + '<div class="status" id="gpinv-f-st"></div>'
      + '</div>';
  }

  function syncFormFromDom() {
    const rows = readRows('f');
    if (rows) formRows = rows;
    const m = { 'gpinv-f-client': 'clientId', 'gpinv-f-token': 'token', 'gpinv-f-note': 'note', 'gpinv-f-exp': 'expDays' };
    for (const [id, k] of Object.entries(m)) {
      const el = $(id);
      if (el) formDraft[k] = el.value;
    }
  }

  // ── record detail (shared by invoices and estimates) ──
  function detailHtml(rec) {
    const kind = rec.kind === 'estimate' ? 'estimate' : 'invoice';
    const st = invStatus(rec);
    const memo = memos[(rec.stealthAddress || '').toLowerCase()] || '';
    const anyDisc = rec.items.some(it => it.discountPct > 0);
    const itemRows = rec.items.map(it =>
      '<tr><td>' + escHtml(it.description || 'item') + '</td>'
      + '<td>' + escHtml(it.qty) + '</td>'
      + '<td>' + fmtAmt(it.unitPrice, rec.token) + '</td>'
      + (anyDisc ? '<td>' + (it.discountPct > 0 ? it.discountPct + '%' : '<span class="gpinv-muted">·</span>') + '</td>' : '')
      + '<td>' + (it.taxPct > 0 ? it.taxPct + '%' : '0%') + '</td>'
      + '<td style="text-align:right">' + fmtAmt((parseFloat(it.qty) || 0) * (parseFloat(it.unitPrice) || 0), rec.token) + '</td></tr>'
    ).join('');
    const tls = taxLinesOf(rec);
    return '<div class="gpinv-lbl">' + kind.toUpperCase() + ' ' + escHtml(rec.number) + ' · ' + pill(st) + '</div>'
      + '<div class="gpinv-muted" style="font-size:12px">'
      + 'created ' + fmtDate(rec.created)
      + (rec.clientName ? ' · client: ' + escHtml(rec.clientName) : '')
      + (rec.expiry ? ' · ' + (kind === 'invoice' ? 'due ' : 'valid until ') + fmtDate(rec.expiry) : ' · no expiry')
      + (rec.sentAt ? ' · sent ' + fmtDate(rec.sentAt) : '')
      + (rec.paidAt ? ' · paid ' + fmtDate(rec.paidAt) : '')
      + (rec.estimateOf ? ' · converted from estimate' : '')
      + '</div>'
      + '<div class="gpinv-tablewrap" style="margin-top:12px"><table><thead><tr>'
      + '<th style="width:40%">DESCRIPTION</th><th>QTY</th><th>UNIT PRICE</th>' + (anyDisc ? '<th>DISC</th>' : '') + '<th>TAX</th><th style="text-align:right">AMOUNT</th>'
      + '</tr></thead><tbody>' + itemRows + '</tbody></table></div>'
      + '<div style="margin-top:10px;text-align:right;font-size:12px">'
      + '<div>subtotal · ' + fmtAmt(rec.subtotal, rec.token) + ' ' + rec.token + '</div>'
      + (rec.discountAmount > 0 ? '<div>discount · −' + fmtAmt(rec.discountAmount, rec.token) + ' ' + rec.token + '</div>' : '')
      + tls.map(tl => '<div>tax ' + tl.rate + '% on ' + fmtAmt(tl.base, rec.token) + ' · ' + fmtAmt(tl.amount, rec.token) + ' ' + rec.token + '</div>').join('')
      + '<div style="font-size:16px;margin-top:2px"><b>' + fmtAmt(rec.total, rec.token) + ' ' + rec.token + '</b></div>'
      + '<div class="status" style="margin-top:2px" data-usd data-amt="' + rec.total + '" data-token="' + rec.token + '"></div>'
      + (st === 'PARTIAL' ? '<div class="status" style="color:#fff">paid so far · ' + fmtAmt(rec.paidAmount, rec.token) + ' ' + rec.token + ' · remaining ' + fmtAmt(round2(rec.total - rec.paidAmount), rec.token) + ' ' + rec.token + '</div>' : '')
      + '</div>'
      + (rec.note ? '<div class="status">note: ' + escHtml(rec.note) + '</div>' : '')
      + (memo ? '<div class="status" style="color:#fff">payment memo: ' + escHtml(memo) + '</div>' : '')
      + (rec.paidTx ? '<div class="status">payment tx: <a href="https://etherscan.io/tx/' + escHtml(rec.paidTx) + '" target="_blank" rel="noopener">' + escHtml(rec.paidTx.slice(0, 18)) + '…</a></div>' : '')
      + '<div class="gpinv-lbl" style="margin-top:12px">PINNED STEALTH ADDRESS</div>'
      + '<div class="gpinv-mono">' + escHtml(rec.stealthAddress) + '</div>'
      + '<div class="gpinv-mono" style="margin-top:6px">' + escHtml(rec.url) + '</div>'
      + (qrFor === rec.id ? '<div style="margin-top:12px;text-align:center"><canvas data-qr style="background:#fff;padding:14px;image-rendering:pixelated;max-width:100%"></canvas></div>' : '')
      + '<div class="gpinv-actions">'
      + '<button class="ghost" data-iact="view" data-id="' + escHtml(rec.id) + '">VIEW LINK</button>'
      + '<button class="ghost" data-iact="qr" data-id="' + escHtml(rec.id) + '">QR</button>'
      + '<button class="ghost" data-iact="copy" data-id="' + escHtml(rec.id) + '">COPY LINK</button>'
      + (kind === 'invoice' && st === 'OVERDUE' ? '<button class="ghost" data-iact="remind" data-id="' + escHtml(rec.id) + '">REMINDER</button>' : '')
      + '<button class="ghost" data-iact="dup" data-id="' + escHtml(rec.id) + '">DUPLICATE</button>'
      + '<button class="ghost" data-iact="print" data-id="' + escHtml(rec.id) + '">PRINT / PDF</button>'
      + (st === 'DRAFT' ? '<button class="ghost" data-iact="edit" data-id="' + escHtml(rec.id) + '">EDIT</button>' : '')
      + (st === 'DRAFT' ? '<button class="ghost" data-iact="sent" data-id="' + escHtml(rec.id) + '">MARK SENT</button>' : '')
      + (kind === 'estimate' && st === 'SENT' ? '<button class="ghost" data-iact="accept" data-id="' + escHtml(rec.id) + '">MARK ACCEPTED</button>' : '')
      + (kind === 'estimate' && st === 'SENT' ? '<button class="ghost" data-iact="decline" data-id="' + escHtml(rec.id) + '">MARK DECLINED</button>' : '')
      + (kind === 'estimate' && (st === 'SENT' || st === 'ACCEPTED') ? '<button data-iact="convert" data-id="' + escHtml(rec.id) + '">CONVERT TO INVOICE</button>' : '')
      + (st === 'DRAFT' ? '<button class="ghost" data-iact="del" data-id="' + escHtml(rec.id) + '">DELETE</button>' : '')
      + '</div>';
  }

  // ── document list (shared by invoices and estimates) ──
  function listHtml(kind) {
    const reg = kind === 'estimate' ? loadEst() : loadInv();
    const filter = kind === 'estimate' ? estFilter : invFilter;
    const filters = kind === 'estimate'
      ? ['ALL', 'DRAFT', 'SENT', 'ACCEPTED', 'DECLINED', 'OVERDUE']
      : ['ALL', 'DRAFT', 'SENT', 'PARTIAL', 'OVERDUE', 'PAID'];
    const rows = [...reg].sort((a, b) => b.created - a.created);
    const shown = filter === 'ALL' ? rows : rows.filter(r => invStatus(r) === filter);
    const noun = kind === 'estimate' ? 'estimate' : 'invoice';
    return '<div class="gpinv-actions" style="margin-top:0">'
      + '<button data-iact="toggle-form" data-k="' + kind + '">' + (showForm && formKind === kind ? 'CANCEL' : 'NEW ' + noun.toUpperCase()) + '</button>'
      + '</div>'
      + (showForm && formKind === kind ? editorHtml() : '')
      + '<div class="gpinv-filter">'
      + filters.map(f => '<button class="ghost' + (filter === f ? ' on' : '') + '" data-iact="filter" data-k="' + kind + '" data-f="' + f + '">' + f + '</button>').join('')
      + '</div>'
      + (rows.length === 0
        ? '<div class="gpinv-empty">no ' + noun + 's yet: press NEW ' + noun.toUpperCase() + ' to create your first one. '
          + (kind === 'invoice' ? 'tip: add clients under CUSTOMERS and reusable lines under ITEMS first, then pick them here.' : 'estimates share the client list and item catalog with invoices.') + '</div>'
        : shown.length === 0
          ? '<div class="gpinv-empty">nothing with status ' + filter + ': pick another filter above.</div>'
          : '<div class="gpinv-tablewrap"><table><thead><tr>'
            + '<th>NUMBER</th><th>CLIENT</th><th>DATE</th><th>' + (kind === 'invoice' ? 'DUE' : 'VALID UNTIL') + '</th>'
            + '<th style="text-align:right">TOTAL</th><th style="text-align:right">USD</th><th style="text-align:right">STATUS</th>'
            + '</tr></thead><tbody>'
            + shown.map(rec =>
                '<tr class="gpinv-rowbtn" data-iact="open" data-id="' + escHtml(rec.id) + '">'
                + '<td><b>' + escHtml(rec.number) + '</b></td>'
                + '<td>' + (rec.clientName ? escHtml(rec.clientName) : '<span class="gpinv-muted">·</span>') + '</td>'
                + '<td style="white-space:nowrap">' + fmtDate(rec.created) + '</td>'
                + '<td style="white-space:nowrap">' + (rec.expiry ? fmtDate(rec.expiry) : '<span class="gpinv-muted">·</span>') + '</td>'
                + '<td style="text-align:right;white-space:nowrap">' + fmtAmt(rec.total, rec.token) + ' ' + rec.token + '</td>'
                + '<td style="text-align:right;white-space:nowrap" data-usd data-amt="' + rec.total + '" data-token="' + rec.token + '"></td>'
                + '<td style="text-align:right">' + pill(invStatus(rec)) + '</td></tr>'
                + (openId === rec.id ? '<tr class="gpinv-detail"><td colspan="7">' + detailHtml(rec) + '</td></tr>' : '')
              ).join('')
            + '</tbody></table></div>');
  }

  // ── tab: INVOICES (with the ESTIMATES sub-switch when the shell has no separate mount) ──
  function renderInvoices() {
    const el = mounts.invoices;
    if (!el) return;
    const kindSwitch = mounts.estimates ? '' :
      '<div class="gpinv-sub">'
      + '<button data-iact="kind" data-k="invoice"' + (invKind === 'invoice' ? ' class="on"' : '') + '>INVOICES</button>'
      + '<button data-iact="kind" data-k="estimate"' + (invKind === 'estimate' ? ' class="on"' : '') + '>ESTIMATES</button>'
      + '</div>';
    el.innerHTML = kindSwitch + listHtml(mounts.estimates ? 'invoice' : invKind);
    afterRender(el);
  }

  // ── tab: ESTIMATES (only when the shell provides a dedicated mount) ──
  function renderEstimates() {
    const el = mounts.estimates;
    if (!el) return;
    el.innerHTML = listHtml('estimate');
    afterRender(el);
  }

  // ── tab: CUSTOMERS ──
  function renderCustomers() {
    const el = mounts.customers;
    if (!el) return;
    const clients = loadClients();
    const inv = loadInv();
    const now = Date.now();
    el.innerHTML =
      '<h3>ADD CUSTOMER</h3>'
      + '<div class="gpinv-box">'
      + '<input id="gpinv-c-name" placeholder="name" style="margin-top:0">'
      + '<input id="gpinv-c-contact" placeholder="contact (email, telegram, …)">'
      + '<textarea id="gpinv-c-addr" rows="2" placeholder="address lines (optional, one per line: printed on invoices)"></textarea>'
      + '<input id="gpinv-c-vat" placeholder="VAT / tax number (optional: printed under the bill-to block)">'
      + '<input id="gpinv-c-notes" placeholder="notes (optional)">'
      + '<button data-iact="add-client" style="margin-top:14px">ADD CUSTOMER</button>'
      + '<div class="status" id="gpinv-c-st"></div>'
      + '</div>'
      + '<h3>CUSTOMERS</h3>'
      + (clients.length
        ? '<div class="gpinv-tablewrap"><table><thead><tr>'
          + '<th>NAME</th><th>CONTACT</th><th style="text-align:right">OUTSTANDING</th><th style="text-align:right">PAID</th><th></th>'
          + '</tr></thead><tbody>'
          + clients.map(c => {
              const mine = inv.filter(i => i.clientId === c.id);
              const tot = f => mine.filter(f).reduce((m, i) => { m[i.token] = (m[i.token] || 0) + i.total; return m; }, {});
              const cell = m => Object.keys(m).length ? Object.keys(m).map(t => fmtAmt(m[t], t) + ' ' + t).join('<br>') : '<span class="gpinv-muted">·</span>';
              const open = i => ['SENT', 'PARTIAL', 'OVERDUE'].includes(invStatus(i, now));
              return '<tr><td><b>' + escHtml(c.name) + '</b>'
                + (c.vatNumber ? '<div class="gpinv-muted" style="font-size:10px">tax id: ' + escHtml(c.vatNumber) + '</div>' : '')
                + (c.notes ? '<div class="gpinv-muted" style="font-size:10px">' + escHtml(c.notes) + '</div>' : '')
                + '</td><td>' + (c.contact ? escHtml(c.contact) : '<span class="gpinv-muted">·</span>') + '</td>'
                + '<td style="text-align:right">' + cell(tot(open)) + '</td>'
                + '<td style="text-align:right">' + cell(tot(i => i.status === 'PAID')) + '</td>'
                + '<td style="width:1%"><button class="ghost gpinv-x" data-iact="del-client" data-id="' + escHtml(c.id) + '" title="delete customer">×</button></td></tr>';
            }).join('')
          + '</tbody></table></div>'
        : '<div class="gpinv-empty">no customers yet: add one above, then pick them when creating an invoice. outstanding and paid totals build up here as invoices move.</div>');
  }

  // ── tab: ITEMS (reusable line-item catalog) ──
  function renderItems() {
    const el = mounts.items;
    if (!el) return;
    const items = loadItems();
    el.innerHTML =
      '<h3>' + (itemEditId ? 'EDIT ITEM' : 'ADD ITEM') + '</h3>'
      + '<div class="gpinv-box">'
      + '<input id="gpinv-i-name" placeholder="item name (e.g. design retainer)" style="margin-top:0" value="' + escHtml(itemDraft.name) + '">'
      + '<input id="gpinv-i-desc" placeholder="description (prefills invoice lines)" value="' + escHtml(itemDraft.description) + '">'
      + '<div class="gpinv-grid" style="margin-top:8px">'
      + '<div><div class="gpinv-lbl">UNIT PRICE</div><input id="gpinv-i-price" type="number" min="0" step="any" style="margin-top:4px" value="' + escHtml(itemDraft.unitPrice) + '" placeholder="0.00"></div>'
      + '<div><div class="gpinv-lbl">TOKEN</div><select id="gpinv-i-token" style="margin-top:4px">'
      + ['USDC', 'ETH'].map(t => '<option' + (itemDraft.token === t ? ' selected' : '') + '>' + t + '</option>').join('')
      + '</select></div>'
      + '</div>'
      + '<div class="gpinv-grid" style="margin-top:8px">'
      + '<div><div class="gpinv-lbl">TAX % (OPTIONAL: PREFILLS THE ROW RATE)</div><input id="gpinv-i-tax" type="number" min="0" step="any" style="margin-top:4px" value="' + escHtml(itemDraft.taxPct) + '" placeholder="blank = profile rate"></div>'
      + '<div><div class="gpinv-lbl">DISCOUNT % (OPTIONAL)</div><input id="gpinv-i-disc" type="number" min="0" step="any" style="margin-top:4px" value="' + escHtml(itemDraft.discPct) + '" placeholder="0"></div>'
      + '</div>'
      + '<div class="gpinv-actions gpinv-sticky">'
      + '<button data-iact="save-item">' + (itemEditId ? 'SAVE ITEM' : 'ADD ITEM') + '</button>'
      + (itemEditId ? '<button class="ghost" data-iact="cancel-item">CANCEL</button>' : '')
      + '</div>'
      + '<div class="status" id="gpinv-i-st"></div>'
      + '</div>'
      + '<h3>CATALOG</h3>'
      + (items.length
        ? '<div class="gpinv-tablewrap"><table><thead><tr>'
          + '<th>NAME</th><th>DESCRIPTION</th><th>TAX</th><th style="text-align:right">UNIT PRICE</th><th></th>'
          + '</tr></thead><tbody>'
          + items.map(it =>
              '<tr><td><b>' + escHtml(it.name) + '</b></td>'
              + '<td>' + (it.description ? escHtml(it.description) : '<span class="gpinv-muted">·</span>') + '</td>'
              + '<td>' + (it.taxPct > 0 ? it.taxPct + '%' : '<span class="gpinv-muted">·</span>') + '</td>'
              + '<td style="text-align:right;white-space:nowrap">' + fmtAmt(it.unitPrice, it.token) + ' ' + it.token + '</td>'
              + '<td style="width:1%;white-space:nowrap">'
              + '<button class="ghost gpinv-x" data-iact="edit-item" data-id="' + escHtml(it.id) + '" title="edit item">✎</button> '
              + '<button class="ghost gpinv-x" data-iact="del-item" data-id="' + escHtml(it.id) + '" title="delete item">×</button>'
              + '</td></tr>'
            ).join('')
          + '</tbody></table></div>'
        : '<div class="gpinv-empty">the catalog is empty: add reusable line items above, then pick them from any invoice, estimate or recurring template row.</div>');
  }

  // ── tab: RECURRING ──
  function startRecForm(rec) {
    recFormOpen = true;
    recEditId = rec ? rec.id : null;
    recRows = rec
      ? rec.items.map(it => ({
          description: it.description, qty: it.qty, unitPrice: it.unitPrice,
          taxPct: it.taxPct > 0 ? String(it.taxPct) : '0',
          discPct: it.discountPct > 0 ? String(it.discountPct) : '',
        }))
      : [blankRow()];
    recDraft = {
      clientId: rec ? rec.clientId || '' : '',
      token: rec ? rec.token : loadProfile().token,
      note: rec ? rec.note : '',
      everyN: rec ? rec.everyN : 1,
      unit: rec ? rec.unit : 'months',
      next: rec ? dateInputVal(rec.nextDate) : dateInputVal(nextRecurrence(Date.now(), 1, 'months')),
      active: rec ? rec.active !== false : true,
    };
  }

  function recFormHtml() {
    const clients = loadClients();
    const catalog = loadItems();
    const d = recDraft;
    return '<h3>' + (recEditId ? 'EDIT TEMPLATE' : 'NEW RECURRING TEMPLATE') + '</h3>'
      + '<div class="gpinv-box">'
      + '<div class="gpinv-lbl">CLIENT</div>'
      + '<select id="gpinv-r-client" style="margin-top:4px"><option value="">no client</option>'
      + clients.map(c => '<option value="' + escHtml(c.id) + '"' + (d.clientId === c.id ? ' selected' : '') + '>' + escHtml(c.name) + '</option>').join('')
      + '</select>'
      + '<div class="gpinv-lbl" style="margin-top:14px">LINE ITEMS · TAX RATE PER ROW</div>'
      + rowsTableHtml(recRows, d.token, catalog, 'r')
      + totalsBlockHtml('r', computeTotals(recRows, null, null), d.token)
      + '<div class="gpinv-lbl" style="margin-top:14px">TOKEN</div>'
      + '<select id="gpinv-r-token" style="margin-top:4px">'
      + ['USDC', 'ETH'].map(t => '<option' + (d.token === t ? ' selected' : '') + '>' + t + '</option>').join('')
      + '</select>'
      + '<div class="gpinv-grid" style="margin-top:8px">'
      + '<div><div class="gpinv-lbl">REPEAT EVERY</div><input id="gpinv-r-everyn" style="margin-top:4px" type="number" min="1" step="1" value="' + escHtml(d.everyN) + '"></div>'
      + '<div><div class="gpinv-lbl">UNIT</div><select id="gpinv-r-unit" style="margin-top:4px">'
      + ['weeks', 'months'].map(u => '<option' + (d.unit === u ? ' selected' : '') + '>' + u + '</option>').join('')
      + '</select></div>'
      + '</div>'
      + '<div class="gpinv-lbl" style="margin-top:12px">NEXT RUN DATE</div>'
      + '<input id="gpinv-r-next" style="margin-top:4px" type="date" value="' + escHtml(d.next) + '">'
      + '<input id="gpinv-r-note" placeholder="note (optional: prefills the payer\'s encrypted memo)" value="' + escHtml(d.note) + '">'
      + '<label style="display:block;font-size:12px;margin-top:12px;cursor:pointer"><input type="checkbox" id="gpinv-r-active" style="width:auto;margin-right:6px"' + (d.active ? ' checked' : '') + '>active (inactive templates never come due)</label>'
      + '<div class="gpinv-actions gpinv-sticky">'
      + '<button data-iact="rec-save">' + (recEditId ? 'SAVE TEMPLATE' : 'CREATE TEMPLATE') + '</button>'
      + '<button class="ghost" data-iact="rec-new">CANCEL</button>'
      + '</div>'
      + '<div class="status" id="gpinv-r-st"></div>'
      + '</div>';
  }

  function syncRecFromDom() {
    const rows = readRows('r');
    if (rows) recRows = rows;
    const m = { 'gpinv-r-client': 'clientId', 'gpinv-r-token': 'token', 'gpinv-r-note': 'note', 'gpinv-r-everyn': 'everyN', 'gpinv-r-unit': 'unit', 'gpinv-r-next': 'next' };
    for (const [id, k] of Object.entries(m)) {
      const el = $(id);
      if (el) recDraft[k] = el.value;
    }
    const act = $('gpinv-r-active');
    if (act) recDraft.active = act.checked;
  }

  function recDetailHtml(r) {
    const t = computeTotals(r.items, r.taxPct, r.discountPct);
    const anyDisc = r.items.some(it => it.discountPct > 0);
    const itemRows = r.items.map(it => {
      // legacy templates carry the rate at template level: show the effective row rate
      const rate = Number.isFinite(+it.taxPct) && +it.taxPct >= 0 && it.taxPct != null && it.taxPct !== '' ? +it.taxPct : (r.taxPct > 0 ? r.taxPct : 0);
      return '<tr><td>' + escHtml(it.description || 'item') + '</td>'
        + '<td>' + escHtml(it.qty) + '</td>'
        + '<td>' + fmtAmt(it.unitPrice, r.token) + '</td>'
        + (anyDisc ? '<td>' + (it.discountPct > 0 ? it.discountPct + '%' : '<span class="gpinv-muted">·</span>') + '</td>' : '')
        + '<td>' + rate + '%</td>'
        + '<td style="text-align:right">' + fmtAmt((parseFloat(it.qty) || 0) * (parseFloat(it.unitPrice) || 0), r.token) + '</td></tr>';
    }).join('');
    const due = r.active && r.nextDate <= Date.now();
    return '<div class="gpinv-muted" style="font-size:12px">'
      + 'every ' + r.everyN + ' ' + r.unit + ' · next run ' + fmtDate(r.nextDate) + (due ? ' · due now' : '')
      + '</div>'
      + '<div class="gpinv-tablewrap" style="margin-top:12px"><table><thead><tr>'
      + '<th style="width:40%">DESCRIPTION</th><th>QTY</th><th>UNIT PRICE</th>' + (anyDisc ? '<th>DISC</th>' : '') + '<th>TAX</th><th style="text-align:right">AMOUNT</th>'
      + '</tr></thead><tbody>' + itemRows + '</tbody></table></div>'
      + '<div style="margin-top:10px;text-align:right;font-size:12px">'
      + (t.discountAmount > 0 ? '<div>discount · −' + fmtAmt(t.discountAmount, r.token) + ' ' + r.token + '</div>' : '')
      + t.taxLines.map(tl => '<div>tax ' + tl.rate + '% on ' + fmtAmt(tl.base, r.token) + ' · ' + fmtAmt(tl.amount, r.token) + ' ' + r.token + '</div>').join('')
      + '<div style="font-size:16px;margin-top:2px"><b>' + fmtAmt(t.total, r.token) + ' ' + r.token + '</b> per run</div>'
      + '</div>'
      + (r.note ? '<div class="status">note: ' + escHtml(r.note) + '</div>' : '')
      + '<div class="gpinv-actions">'
      + (due ? '<button data-iact="rec-gen" data-id="' + escHtml(r.id) + '">GENERATE NOW</button>' : '')
      + '<button class="ghost" data-iact="rec-edit" data-id="' + escHtml(r.id) + '">EDIT</button>'
      + '<button class="ghost" data-iact="rec-toggle" data-id="' + escHtml(r.id) + '">' + (r.active ? 'PAUSE' : 'RESUME') + '</button>'
      + '<button class="ghost" data-iact="rec-del" data-id="' + escHtml(r.id) + '">DELETE</button>'
      + '</div>';
  }

  function renderRecurring() {
    const el = mounts.recurring;
    if (!el) return;
    const list = loadRecurring();
    const now = Date.now();
    el.innerHTML =
      '<div class="gpinv-actions" style="margin-top:0">'
      + '<button data-iact="rec-new">' + (recFormOpen ? 'CANCEL' : 'NEW TEMPLATE') + '</button>'
      + '</div>'
      + (recFormOpen ? recFormHtml() : '')
      + '<h3>RECURRING TEMPLATES</h3>'
      + (list.length
        ? '<div class="gpinv-tablewrap"><table><thead><tr>'
          + '<th>CLIENT</th><th>FREQUENCY</th><th>NEXT RUN</th><th style="text-align:right">TOTAL / RUN</th><th style="text-align:right">STATUS</th>'
          + '</tr></thead><tbody>'
          + list.map(r => {
              const t = computeTotals(r.items, r.taxPct, r.discountPct);
              const due = r.active && r.nextDate <= now;
              return '<tr class="gpinv-rowbtn" data-iact="rec-open" data-id="' + escHtml(r.id) + '">'
                + '<td><b>' + (r.clientName ? escHtml(r.clientName) : '<span class="gpinv-muted">no client</span>') + '</b>'
                + '<div class="gpinv-muted" style="font-size:10px">' + r.items.length + ' line item' + (r.items.length === 1 ? '' : 's') + '</div></td>'
                + '<td style="white-space:nowrap">every ' + r.everyN + ' ' + r.unit + '</td>'
                + '<td style="white-space:nowrap">' + fmtDate(r.nextDate) + (due ? ' ' + pill('DUE') : '') + '</td>'
                + '<td style="text-align:right;white-space:nowrap">' + fmtAmt(t.total, r.token) + ' ' + r.token + '</td>'
                + '<td style="text-align:right">' + pill(r.active ? 'ACTIVE' : 'PAUSED') + '</td></tr>'
                + (recOpen === r.id ? '<tr class="gpinv-detail"><td colspan="5">' + recDetailHtml(r) + '</td></tr>' : '');
            }).join('')
          + '</tbody></table></div>'
        : '<div class="gpinv-empty">no recurring templates yet: press NEW TEMPLATE to bill a client on a schedule. when a run comes due, GENERATE NOW creates the invoice and moves the next date forward.</div>');
    afterRender(el);
  }

  // ── tab: SETTINGS (profile, numbering, ENS, CSV) ──
  function renderSettings() {
    const el = mounts.settings;
    if (!el) return;
    const p = loadProfile();
    const accent = p.accentColor || '#fff';
    el.innerHTML =
      '<div style="display:flex;gap:16px;align-items:center;margin-bottom:6px">'
      + '<div class="gpinv-mg" style="border-color:' + escHtml(accent) + '">' + escHtml(monogram(p.name)) + '</div>'
      + '<div><div style="font-weight:700">' + (p.name ? escHtml(p.name) : 'your business') + '</div>'
      + '<div class="gpinv-muted" style="font-size:11px">' + (p.contact ? escHtml(p.contact) : 'this profile stamps every invoice, estimate and receipt.') + '</div></div>'
      + '</div>'
      + '<h3>BUSINESS PROFILE</h3>'
      + '<div class="gpinv-box">'
      + '<div class="gpinv-lbl">BUSINESS NAME</div><input id="gpinv-p-name" style="margin-top:4px" value="' + escHtml(p.name) + '" placeholder="e.g. Ghost Studio">'
      + '<div class="gpinv-lbl" style="margin-top:12px">FROM / CONTACT LINE</div><input id="gpinv-p-contact" style="margin-top:4px" value="' + escHtml(p.contact) + '" placeholder="e.g. ben@ghoststudio.eth">'
      + '<div class="gpinv-lbl" style="margin-top:12px">ADDRESS LINES (ONE PER LINE: PRINTED ON DOCUMENTS)</div>'
      + '<textarea id="gpinv-p-addr" rows="3" style="margin-top:4px" placeholder="1 Ghost Lane&#10;Berlin">' + escHtml(p.addressLines.join('\n')) + '</textarea>'
      + '<div class="gpinv-lbl" style="margin-top:12px">VAT / TAX NUMBER (OPTIONAL: PRINTED UNDER YOUR ADDRESS)</div><input id="gpinv-p-vat" style="margin-top:4px" value="' + escHtml(p.taxNumber) + '" placeholder="e.g. NL123456789B01">'
      + '<div class="gpinv-lbl" style="margin-top:12px">DEFAULT TOKEN</div><select id="gpinv-p-token" style="margin-top:4px">'
      + ['USDC', 'ETH'].map(t => '<option' + (p.token === t ? ' selected' : '') + '>' + t + '</option>').join('') + '</select>'
      + '<div class="gpinv-lbl" style="margin-top:12px">DEFAULT PAYMENT TERMS</div><input id="gpinv-p-terms" style="margin-top:4px" value="' + escHtml(p.terms) + '" placeholder="payment due on receipt">'
      + '<div class="gpinv-lbl" style="margin-top:12px">DEFAULT TAX % (OPTIONAL: PREFILLS EVERY NEW ROW RATE)</div><input id="gpinv-p-tax" style="margin-top:4px" type="number" min="0" step="any" value="' + (p.taxPct ?? '') + '" placeholder="e.g. 21">'
      + '<div class="gpinv-lbl" style="margin-top:12px">ACCENT COLOR (OPTIONAL HEX: STAMPS PRINTED DOCUMENTS)</div><input id="gpinv-p-accent" style="margin-top:4px" value="' + escHtml(p.accentColor || '') + '" placeholder="#fff · blank = plain black and white">'
      + '<div class="gpinv-lbl" style="margin-top:12px">FOOTER NOTE (PRINTED AT THE BOTTOM OF EVERY DOCUMENT)</div><input id="gpinv-p-footer" style="margin-top:4px" value="' + escHtml(p.footerNote) + '" placeholder="e.g. thank you for your business">'
      + '<button data-iact="save-profile" style="margin-top:14px">SAVE PROFILE</button>'
      + '<div class="status" id="gpinv-p-st"></div>'
      + '</div>'
      + '<h3>NUMBERING</h3>'
      + '<div class="gpinv-box"><div class="gpinv-grid">'
      + '<div><div class="gpinv-lbl">NUMBER PREFIX</div><input id="gpinv-p-prefix" style="margin-top:4px" value="' + escHtml(p.prefix) + '" placeholder="GP-"></div>'
      + '<div><div class="gpinv-lbl">NEXT NUMBER</div><input id="gpinv-p-next" style="margin-top:4px" type="number" min="1" value="' + escHtml(p.next) + '"></div>'
      + '</div>'
      + '<div class="status">numbers allocate as prefix + zero-padded counter (GP-0001, GP-0002, …). invoices and estimates share the sequence.</div>'
      + '<button data-iact="save-profile" style="margin-top:14px">SAVE NUMBERING</button></div>'
      + '<h3>PUBLISH TO ENS</h3>'
      + '<div class="gpinv-box">'
      + '<div class="status" style="margin-top:0">writes a "stealth" text record on your ENS name so senders can resolve it to your stealth meta-address. the meta-address is public by design: anyone can derive fresh payment addresses from it, nobody can spend from it.</div>'
      + '<input id="gpinv-ensname" placeholder="yourname.eth">'
      + '<input id="gpinv-ensresolver" value="' + ENS_PUBLIC_RESOLVER + '" placeholder="resolver address">'
      + '<button class="ghost" data-iact="ens" style="margin-top:12px">PUBLISH TO ENS</button>'
      + '<div class="status" id="gpinv-ens-st"></div>'
      + '<div class="status">rather click through: <a id="gpinv-enslink" href="https://app.ens.domains" target="_blank" rel="noopener">open app.ens.domains</a> and set the "stealth" text record manually.</div>'
      + '</div>'
      + '<h3>EXPORT</h3>'
      + '<div class="gpinv-box">'
      + '<div class="status" style="margin-top:0">downloads every payment detected this session plus every invoice and estimate as one CSV: dates, amounts, usd values, statuses.</div>'
      + '<button class="ghost" data-iact="export-csv" style="margin-top:12px">EXPORT CSV</button>'
      + '</div>';
  }

  // ── render dispatch ──
  function renderAll() {
    renderInvoices();
    renderEstimates();
    renderCustomers();
    renderItems();
    renderRecurring();
    renderSettings();
  }

  // per-render tail: USD placeholders + any open QR canvas
  function afterRender(scope) {
    fillUsd(scope);
    if (qrFor) {
      const rec = findRec(qrFor);
      const cv = scope.querySelector('canvas[data-qr]');
      if (rec && cv) drawQr(cv, rec.url).catch(() => GP.toast('QR failed: content too long'));
    }
  }

  // fills every [data-usd] placeholder once a price is available
  function fillUsd(scope) {
    const els = [...scope.querySelectorAll('[data-usd]')];
    if (!els.length) return;
    const paint = px => els.forEach(el => {
      const u = fmtUsd(el.dataset.amt, el.dataset.token, px);
      if (u && el.isConnected) el.textContent = '≈ ' + u;
    });
    paint(GP.state.ethPriceUsd);
    ethUsd().then(paint);
  }

  // ── persistence ──
  // form rows → stored v4 line items: explicit per-line tax rate (0 allowed) and
  // optional per-line discount
  const rowsToItems = rows => rows.map(r => {
    const rate = parseFloat(r.taxPct);
    const dp = parseFloat(r.discPct);
    return {
      description: (r.description || '').trim() || 'item',
      qty: parseFloat(r.qty),
      unitPrice: parseFloat(r.unitPrice),
      taxPct: Number.isFinite(rate) && rate > 0 ? rate : 0,
      discountPct: Number.isFinite(dp) && dp > 0 ? dp : null,
    };
  });

  function saveForm() {
    const kind = formKind;
    const st = m => { const el = $('gpinv-f-st'); if (el) el.textContent = m; };
    if (!GP.state.unlocked || !GP.state.meta) { st('generate your stealth keys first (step 2).'); return; }
    syncFormFromDom();
    const rows = formRows.filter(r => (parseFloat(r.qty) || 0) > 0 && (parseFloat(r.unitPrice) || 0) > 0);
    if (!rows.length) { st('add at least one line item with qty and unit price.'); return; }
    const token = formDraft.token === 'ETH' ? 'ETH' : 'USDC';
    const note = (formDraft.note || '').trim();
    const days = parseFloat(formDraft.expDays);
    const clientId = formDraft.clientId || null;
    const client = clientId ? loadClients().find(c => c.id === clientId) : null;
    const items = rowsToItems(rows);
    const t = computeTotals(items, null, null);
    const expiry = Number.isFinite(days) && days > 0 ? Date.now() + Math.round(days * 86400000) : null;
    const reg = kind === 'estimate' ? loadEst() : loadInv();
    const save = kind === 'estimate' ? saveEst : saveInv;

    if (editId) {
      const rec = reg.find(x => x.id === editId);
      if (!rec) { st('record not found.'); return; }
      Object.assign(rec, {
        clientId, clientName: client ? client.name : '', items, token,
        subtotal: t.subtotal, taxPct: null, taxAmount: t.taxAmount, taxLines: t.taxLines,
        discountPct: null, discountAmount: t.discountAmount, total: t.total,
        note, expiry,
      });
      const pin = parsePinned(rec.url);
      if (pin.st && pin.eph && pin.vt !== null) {
        rec.url = buildUrl({ amount: fmtAmt(t.total, token), token, note, id: rec.id, number: rec.number, expiry, st: pin.st, eph: pin.eph, vt: pin.vt });
      }
      save(reg);
      GP.toast(kind + ' ' + rec.number + ' updated (same pinned stealth address)');
    } else {
      const profile = loadProfile();
      const a = allocateNumber(profile);
      profile.next = a.next;
      saveProfile(profile);
      const d = C.derive(GP.state.meta.slice(7));
      const id = (kind === 'estimate' ? 'est-' : 'inv-') + Date.now().toString(36) + '-' + Math.floor(Math.random() * 46656).toString(36);
      const url = buildUrl({ amount: fmtAmt(t.total, token), token, note, id, number: a.number, expiry, st: d.stealth, eph: d.ephPub, vt: d.viewTag });
      reg.push({
        v: 4, id, number: a.number,
        clientId, clientName: client ? client.name : '',
        items, token,
        subtotal: t.subtotal, taxPct: null, taxAmount: t.taxAmount, taxLines: t.taxLines,
        discountPct: null, discountAmount: t.discountAmount, total: t.total,
        note, stealthAddress: d.stealth, created: Date.now(), url, expiry,
        status: 'DRAFT', sentAt: null, paidAt: null, paidTx: null, paidAmount: null,
        estimateOf: null, kind,
      });
      save(reg);
      openId = id; qrFor = id;
      GP.toast(kind + ' ' + a.number + ' created: one fresh stealth address, link is self-contained');
    }
    showForm = false;
    editId = null;
    renderAll();
  }

  function duplicateRecord(rec) {
    if (!GP.state.unlocked || !GP.state.meta) { GP.toast('generate your stealth keys first (step 2)'); return; }
    const kind = rec.kind === 'estimate' ? 'estimate' : 'invoice';
    const profile = loadProfile();
    const a = allocateNumber(profile);
    profile.next = a.next;
    saveProfile(profile);
    const d = C.derive(GP.state.meta.slice(7));
    const id = (kind === 'estimate' ? 'est-' : 'inv-') + Date.now().toString(36) + '-' + Math.floor(Math.random() * 46656).toString(36);
    const url = buildUrl({
      amount: fmtAmt(rec.total, rec.token), token: rec.token, note: rec.note, id, number: a.number,
      expiry: rec.expiry && rec.expiry > Date.now() ? rec.expiry : null,
      st: d.stealth, eph: d.ephPub, vt: d.viewTag,
    });
    const reg = kind === 'estimate' ? loadEst() : loadInv();
    reg.push({
      ...rec, id, number: a.number,
      items: rec.items.map(it => ({ ...it })),
      stealthAddress: d.stealth, created: Date.now(), url,
      status: 'DRAFT', sentAt: null, paidAt: null, paidTx: null, paidAmount: null, estimateOf: null,
    });
    (kind === 'estimate' ? saveEst : saveInv)(reg);
    openId = id; qrFor = null;
    if (!mounts.estimates) invKind = kind;
    renderAll();
    GP.toast('duplicated as ' + a.number + ' (fresh stealth address)');
  }

  function convertEstimate(est) {
    if (!GP.state.unlocked || !GP.state.meta) { GP.toast('generate your stealth keys first (step 2)'); return; }
    const profile = loadProfile();
    const a = allocateNumber(profile);
    profile.next = a.next;
    saveProfile(profile);
    const d = C.derive(GP.state.meta.slice(7));
    const id = 'inv-' + Date.now().toString(36) + '-' + Math.floor(Math.random() * 46656).toString(36);
    const url = buildUrl({ amount: fmtAmt(est.total, est.token), token: est.token, note: est.note, id, number: a.number, expiry: null, st: d.stealth, eph: d.ephPub, vt: d.viewTag });
    const inv = loadInv();
    inv.push({
      v: 4, id, number: a.number,
      clientId: est.clientId, clientName: est.clientName,
      items: est.items.map(it => ({ ...it })),
      token: est.token,
      subtotal: est.subtotal, taxPct: null, taxAmount: est.taxAmount || 0,
      taxLines: taxLinesOf(est),
      discountPct: null, discountAmount: est.discountAmount || 0, total: est.total,
      note: est.note, stealthAddress: d.stealth, created: Date.now(), url, expiry: null,
      status: 'DRAFT', sentAt: null, paidAt: null, paidTx: null, paidAmount: null,
      estimateOf: est.id, kind: 'invoice',
    });
    saveInv(inv);
    const reg = loadEst();
    const src = reg.find(x => x.id === est.id);
    if (src && src.status !== 'ACCEPTED') { src.status = 'ACCEPTED'; saveEst(reg); }
    if (!mounts.estimates) invKind = 'invoice';
    openId = id; qrFor = null;
    renderAll();
    GP.toast('estimate ' + est.number + ' converted to invoice ' + a.number + ' (fresh stealth address)');
  }

  function saveRecurringTemplate() {
    const st = m => { const el = $('gpinv-r-st'); if (el) el.textContent = m; };
    syncRecFromDom();
    const rows = recRows.filter(r => (parseFloat(r.qty) || 0) > 0 && (parseFloat(r.unitPrice) || 0) > 0);
    if (!rows.length) { st('add at least one line item with qty and unit price.'); return; }
    const clientId = recDraft.clientId || null;
    const client = clientId ? loadClients().find(c => c.id === clientId) : null;
    const items = rowsToItems(rows);
    const everyN = Math.max(1, Math.floor(parseFloat(recDraft.everyN) || 1));
    const unit = recDraft.unit === 'months' ? 'months' : 'weeks';
    const nextDate = recDraft.next ? new Date(recDraft.next + 'T00:00:00').getTime() : Date.now();
    if (!Number.isFinite(nextDate)) { st('pick a valid next run date.'); return; }
    const list = loadRecurring();
    const fields = {
      clientId, clientName: client ? client.name : '',
      items, token: recDraft.token === 'ETH' ? 'ETH' : 'USDC',
      taxPct: null, discountPct: null,
      note: (recDraft.note || '').trim(),
      everyN, unit, nextDate,
      active: recDraft.active !== false,
    };
    if (recEditId) {
      const rec = list.find(x => x.id === recEditId);
      if (!rec) { st('template not found.'); return; }
      Object.assign(rec, fields);
      GP.toast('recurring template updated');
    } else {
      list.push({ id: 'rec-' + Date.now().toString(36) + '-' + Math.floor(Math.random() * 46656).toString(36), ...fields });
      GP.toast('recurring template created');
    }
    saveRecurring(list);
    recFormOpen = false;
    recEditId = null;
    renderAll();
  }

  // GENERATE NOW: one invoice from the template (fresh stealth address, next number),
  // then nextDate advances by exactly one period. Legacy templates carry the rate at
  // template level: fold it into the line items so the invoice is fully v4.
  function generateFromTemplate(rec) {
    if (!GP.state.unlocked || !GP.state.meta) { GP.toast('generate your stealth keys first (step 2)'); return; }
    const items = rec.items.map(it => ({
      ...it,
      taxPct: Number.isFinite(+it.taxPct) && +it.taxPct >= 0 && it.taxPct !== '' && it.taxPct != null ? +it.taxPct : (rec.taxPct > 0 ? rec.taxPct : 0),
      discountPct: Number.isFinite(+it.discountPct) && +it.discountPct > 0 ? +it.discountPct : (rec.discountPct > 0 ? rec.discountPct : null),
    }));
    const t = computeTotals(items, null, null);
    const profile = loadProfile();
    const a = allocateNumber(profile);
    profile.next = a.next;
    saveProfile(profile);
    const d = C.derive(GP.state.meta.slice(7));
    const id = 'inv-' + Date.now().toString(36) + '-' + Math.floor(Math.random() * 46656).toString(36);
    const url = buildUrl({ amount: fmtAmt(t.total, rec.token), token: rec.token, note: rec.note, id, number: a.number, expiry: null, st: d.stealth, eph: d.ephPub, vt: d.viewTag });
    const inv = loadInv();
    inv.push({
      v: 4, id, number: a.number,
      clientId: rec.clientId, clientName: rec.clientName,
      items, token: rec.token,
      subtotal: t.subtotal, taxPct: null, taxAmount: t.taxAmount, taxLines: t.taxLines,
      discountPct: null, discountAmount: t.discountAmount, total: t.total,
      note: rec.note || '', stealthAddress: d.stealth, created: Date.now(), url, expiry: null,
      status: 'DRAFT', sentAt: null, paidAt: null, paidTx: null, paidAmount: null,
      estimateOf: null, kind: 'invoice',
    });
    saveInv(inv);
    const list = loadRecurring();
    const tpl = list.find(x => x.id === rec.id);
    if (tpl) {
      tpl.nextDate = nextRecurrence(tpl.nextDate, tpl.everyN, tpl.unit);
      saveRecurring(list);
      recOpen = tpl.id;
    }
    renderAll();
    GP.toast('invoice ' + a.number + ' generated as a draft · next run ' + (tpl ? fmtDate(tpl.nextDate) : 'advanced'));
  }

  // ── actions (one delegated handler; data-iact is ours, the shell owns data-act) ──
  document.addEventListener('click', e => {
    const el = e.target.closest('[data-iact]');
    if (!el || !el.closest('#gp-invoices')) return;
    const act = el.dataset.iact, id = el.dataset.id;
    const invAll = id != null ? loadInv() : null;
    const estAll = id != null ? loadEst() : null;
    const rec = id != null ? (invAll.find(x => x.id === id) || estAll.find(x => x.id === id) || null) : null;
    const persistDocs = () => { saveInv(invAll); saveEst(estAll); };

    if (act === 'kind') { invKind = el.dataset.k === 'estimate' ? 'estimate' : 'invoice'; renderInvoices(); return; }
    if (act === 'filter') {
      if (el.dataset.k === 'estimate') estFilter = el.dataset.f; else invFilter = el.dataset.f;
      renderAll();
      return;
    }
    if (act === 'toggle-form') {
      const k = el.dataset.k || formKind;
      if (showForm && formKind === k) { showForm = false; editId = null; }
      else startForm(k, null);
      if (!mounts.estimates) invKind = formKind;
      renderAll();
      return;
    }
    if (act === 'save-form') { saveForm(); return; }
    if (act === 'f-add-row') { syncFormFromDom(); formRows.push(blankRow()); renderAll(); return; }
    if (act === 'f-del-row') {
      syncFormFromDom();
      formRows.splice(Number(el.dataset.row), 1);
      if (!formRows.length) formRows.push(blankRow());
      renderAll();
      return;
    }
    if (act === 'r-add-row') { syncRecFromDom(); recRows.push(blankRow()); renderAll(); return; }
    if (act === 'r-del-row') {
      syncRecFromDom();
      recRows.splice(Number(el.dataset.row), 1);
      if (!recRows.length) recRows.push(blankRow());
      renderAll();
      return;
    }
    if (act === 'open') { openId = openId === id ? null : id; if (qrFor !== openId) qrFor = null; renderAll(); return; }
    if (act === 'qr') { openId = id; qrFor = qrFor === id ? null : id; renderAll(); return; }
    if (act === 'copy' && rec) { copyBtn(rec.url, el, 'COPY LINK'); return; }
    if (act === 'remind' && rec) { copyBtn(reminderText(rec, loadProfile()), el, 'REMINDER'); return; }
    if (act === 'view' && rec) { window.open(rec.url, '_blank', 'noopener'); return; }
    if (act === 'print' && rec) { printInvoice(rec); return; }
    if (act === 'edit' && rec && invStatus(rec) === 'DRAFT') {
      startForm(rec.kind === 'estimate' ? 'estimate' : 'invoice', rec);
      if (!mounts.estimates) invKind = formKind;
      renderAll();
      return;
    }
    if (act === 'sent' && rec && invStatus(rec) === 'DRAFT') {
      rec.status = 'SENT'; rec.sentAt = Date.now();
      persistDocs(); renderAll();
      GP.toast(rec.number + ' marked sent');
      return;
    }
    if (act === 'accept' && rec && rec.kind === 'estimate' && invStatus(rec) === 'SENT') {
      rec.status = 'ACCEPTED';
      persistDocs(); renderAll();
      GP.toast('estimate ' + rec.number + ' accepted');
      return;
    }
    if (act === 'decline' && rec && rec.kind === 'estimate' && invStatus(rec) === 'SENT') {
      rec.status = 'DECLINED';
      persistDocs(); renderAll();
      GP.toast('estimate ' + rec.number + ' declined');
      return;
    }
    if (act === 'convert' && rec && rec.kind === 'estimate') { convertEstimate(rec); return; }
    if (act === 'dup' && rec) { duplicateRecord(rec); return; }
    if (act === 'del' && rec && invStatus(rec) === 'DRAFT') {
      saveInv(invAll.filter(x => x.id !== id));
      saveEst(estAll.filter(x => x.id !== id));
      if (openId === id) { openId = null; qrFor = null; }
      renderAll();
      GP.toast(rec.number + ' deleted');
      return;
    }
    if (act === 'add-client') {
      const name = $('gpinv-c-name').value.trim();
      if (!name) { $('gpinv-c-st').textContent = 'enter a name.'; return; }
      const clients = loadClients();
      clients.push({
        id: 'cl-' + Date.now().toString(36) + '-' + Math.floor(Math.random() * 46656).toString(36),
        name, contact: $('gpinv-c-contact').value.trim(),
        addressLines: $('gpinv-c-addr').value.split('\n').map(s => s.trim()).filter(Boolean),
        vatNumber: $('gpinv-c-vat').value.trim(),
        notes: $('gpinv-c-notes').value.trim(), created: Date.now(),
      });
      saveClients(clients); renderAll();
      GP.toast('customer added: ' + name);
      return;
    }
    if (act === 'del-client') {
      saveClients(loadClients().filter(c => c.id !== id));
      renderAll();
      return;
    }
    if (act === 'save-item') {
      const stEl = $('gpinv-i-st');
      const name = ($('gpinv-i-name').value || '').trim();
      const price = parseFloat($('gpinv-i-price').value);
      if (!name) { stEl.textContent = 'enter an item name.'; return; }
      if (!Number.isFinite(price) || price <= 0) { stEl.textContent = 'enter a unit price above zero.'; return; }
      const tax = parseFloat($('gpinv-i-tax').value);
      const disc = parseFloat($('gpinv-i-disc').value);
      const items = loadItems();
      const fields = {
        name, description: ($('gpinv-i-desc').value || '').trim(), unitPrice: price,
        token: $('gpinv-i-token').value === 'ETH' ? 'ETH' : 'USDC',
        taxPct: Number.isFinite(tax) && tax >= 0 && $('gpinv-i-tax').value.trim() !== '' ? tax : null,
        discountPct: Number.isFinite(disc) && disc > 0 ? disc : null,
      };
      if (itemEditId) {
        const it = items.find(x => x.id === itemEditId);
        if (it) Object.assign(it, fields);
        GP.toast('item updated: ' + name);
      } else {
        items.push({ id: 'it-' + Date.now().toString(36) + '-' + Math.floor(Math.random() * 46656).toString(36), ...fields });
        GP.toast('item added: ' + name);
      }
      saveItems(items);
      itemEditId = null;
      itemDraft = { name: '', description: '', unitPrice: '', token: loadProfile().token, taxPct: '', discPct: '' };
      renderAll();
      return;
    }
    if (act === 'edit-item') {
      const it = loadItems().find(x => x.id === id);
      if (it) {
        itemEditId = it.id;
        itemDraft = {
          name: it.name, description: it.description || '', unitPrice: it.unitPrice, token: it.token,
          taxPct: it.taxPct != null ? String(it.taxPct) : '',
          discPct: it.discountPct > 0 ? String(it.discountPct) : '',
        };
      }
      renderAll();
      return;
    }
    if (act === 'cancel-item') {
      itemEditId = null;
      itemDraft = { name: '', description: '', unitPrice: '', token: loadProfile().token, taxPct: '', discPct: '' };
      renderAll();
      return;
    }
    if (act === 'del-item') {
      saveItems(loadItems().filter(x => x.id !== id));
      if (itemEditId === id) { itemEditId = null; itemDraft = { name: '', description: '', unitPrice: '', token: loadProfile().token, taxPct: '', discPct: '' }; }
      renderAll();
      return;
    }
    if (act === 'rec-new') {
      if (recFormOpen) { recFormOpen = false; recEditId = null; }
      else startRecForm(null);
      renderAll();
      return;
    }
    if (act === 'rec-save') { saveRecurringTemplate(); return; }
    if (act === 'rec-open') { recOpen = recOpen === id ? null : id; renderAll(); return; }
    if (act === 'rec-edit') {
      const tpl = loadRecurring().find(x => x.id === id);
      if (tpl) startRecForm(tpl);
      renderAll();
      return;
    }
    if (act === 'rec-toggle') {
      const list = loadRecurring();
      const tpl = list.find(x => x.id === id);
      if (tpl) { tpl.active = !tpl.active; saveRecurring(list); GP.toast(tpl.active ? 'template resumed' : 'template paused'); }
      renderAll();
      return;
    }
    if (act === 'rec-del') {
      saveRecurring(loadRecurring().filter(x => x.id !== id));
      if (recOpen === id) recOpen = null;
      if (recEditId === id) { recFormOpen = false; recEditId = null; }
      renderAll();
      return;
    }
    if (act === 'rec-gen') {
      const tpl = loadRecurring().find(x => x.id === id);
      if (tpl) generateFromTemplate(tpl);
      return;
    }
    if (act === 'save-profile') {
      const stEl = $('gpinv-p-st');
      const p = loadProfile();
      p.name = $('gpinv-p-name').value.trim();
      p.contact = $('gpinv-p-contact').value.trim();
      p.addressLines = $('gpinv-p-addr').value.split('\n').map(s => s.trim()).filter(Boolean);
      p.taxNumber = $('gpinv-p-vat').value.trim();
      p.token = $('gpinv-p-token').value === 'ETH' ? 'ETH' : 'USDC';
      p.prefix = $('gpinv-p-prefix').value.trim() || 'GP-';
      p.next = Math.max(1, Math.floor(parseFloat($('gpinv-p-next').value) || 1));
      p.terms = $('gpinv-p-terms').value.trim() || DEFAULT_PROFILE.terms;
      const tax = parseFloat($('gpinv-p-tax').value);
      p.taxPct = Number.isFinite(tax) && tax > 0 ? tax : null;
      const accent = $('gpinv-p-accent').value.trim();
      if (accent && !/^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/.test(accent)) { stEl.textContent = 'accent color must be a hex value like #ffcc00 (or blank).'; return; }
      p.accentColor = accent || null;
      p.footerNote = $('gpinv-p-footer').value.trim();
      saveProfile(p); renderAll();
      GP.toast('profile saved');
      return;
    }
    if (act === 'export-csv') { exportCsv(); return; }
    if (act === 'ens') { publishEns(); return; }
  });

  // live totals + form drafts: typing syncs state so re-renders never lose input
  document.addEventListener('input', e => {
    const t = e.target;
    if (!t.closest || !t.closest('#gp-invoices')) return;
    if (t.closest('#gpinv-f-items') || ['gpinv-f-client', 'gpinv-f-token', 'gpinv-f-note', 'gpinv-f-exp'].includes(t.id)) {
      syncFormFromDom();
      paintTotals('f', formRows, formDraft.token);
    }
    if (t.closest('#gpinv-r-items') || ['gpinv-r-client', 'gpinv-r-token', 'gpinv-r-note', 'gpinv-r-everyn', 'gpinv-r-unit', 'gpinv-r-next'].includes(t.id)) {
      syncRecFromDom();
      paintTotals('r', recRows, recDraft.token);
    }
    if (['gpinv-i-name', 'gpinv-i-desc', 'gpinv-i-price', 'gpinv-i-token', 'gpinv-i-tax', 'gpinv-i-disc'].includes(t.id)) {
      itemDraft = { name: $('gpinv-i-name').value, description: $('gpinv-i-desc').value, unitPrice: $('gpinv-i-price').value, token: $('gpinv-i-token').value, taxPct: $('gpinv-i-tax').value, discPct: $('gpinv-i-disc').value };
    }
    if (t.id === 'gpinv-ensname') {
      const n = t.value.trim().toLowerCase();
      const link = $('gpinv-enslink');
      if (link) {
        touchSelf();
        link.href = n ? 'https://app.ens.domains/' + encodeURIComponent(n) : 'https://app.ens.domains';
        link.textContent = n ? 'open ' + n + ' in app.ens.domains' : 'open app.ens.domains';
      }
    }
  });

  // selects fire change, not input, in some browsers; catalog picks fill the row
  document.addEventListener('change', e => {
    const t = e.target;
    if (!t.closest || !t.closest('#gp-invoices')) return;
    if (t.dataset && t.dataset.f === 'pick') {
      const pref = t.dataset.pref === 'r' ? 'r' : 'f';
      if (pref === 'r') syncRecFromDom(); else syncFormFromDom();
      const rows = pref === 'r' ? recRows : formRows;
      const draft = pref === 'r' ? recDraft : formDraft;
      const row = rows[Number(t.dataset.row)];
      const cat = loadItems()[Number(t.value)];
      if (row) {
        row._pick = t.value;
        if (cat) {
          row.description = cat.description || cat.name;
          row.unitPrice = cat.unitPrice;
          if (cat.token && cat.token !== draft.token) draft.token = cat.token;
          // catalog defaults prefill the row rate; blank keeps the current (profile) rate
          if (cat.taxPct != null) { row.taxPct = String(cat.taxPct); row._taxpick = undefined; }
          if (cat.discountPct > 0) row.discPct = String(cat.discountPct);
        }
      }
      renderAll();
      return;
    }
    // tax rate picker: custom reveals a free-form % input, so the table re-renders
    if (t.dataset && t.dataset.f === 'taxpick') {
      if (t.dataset.pref === 'r') syncRecFromDom(); else syncFormFromDom();
      renderAll();
      return;
    }
    if (['gpinv-f-client', 'gpinv-f-token'].includes(t.id)) { syncFormFromDom(); paintTotals('f', formRows, formDraft.token); }
    if (['gpinv-r-client', 'gpinv-r-token', 'gpinv-r-unit', 'gpinv-r-next', 'gpinv-r-active'].includes(t.id)) { syncRecFromDom(); paintTotals('r', recRows, recDraft.token); }
    if (t.id === 'gpinv-i-token') itemDraft.token = t.value;
  });

  // ── print / pdf: the reports agent can take over by setting window.GPINVPrint ──
  function printInvoice(rec) {
    if (typeof window.GPINVPrint === 'function') {
      return window.GPINVPrint(rec, {
        profile: loadProfile(), escHtml, fmtAmt, fmtDate, fmtUsd, invStatus, monogram,
        qrDataUrl, ethUsd,
        memo: memos[(rec.stealthAddress || '').toLowerCase()] || '',
      });
    }
    return defaultPrint(rec);
  }

  // default print: a real document, monochrome (accent color when set), window.print()
  async function defaultPrint(i) {
    let qr;
    try { qr = await qrDataUrl(i.url); } catch { GP.toast('QR failed: content too long'); return; }
    const w = window.open('', '_blank', 'width=640,height=860');
    if (!w) { GP.toast('popup blocked: allow popups to print'); return; }
    const p = loadProfile();
    const kind = i.kind === 'estimate' ? 'estimate' : 'invoice';
    const st = invStatus(i);
    const memo = memos[(i.stealthAddress || '').toLowerCase()] || '';
    const accent = p.accentColor || '#000';
    const client = i.clientId ? loadClients().find(c => c.id === i.clientId) : null;
    const clientAddr = client && Array.isArray(client.addressLines) ? client.addressLines.filter(Boolean) : [];
    const anyDisc = i.items.some(it => it.discountPct > 0);
    const rows = i.items.map(it =>
      '<tr><td>' + escHtml(it.description || 'item') + '</td>'
      + '<td class="r">' + escHtml(it.qty) + '</td>'
      + '<td class="r">' + fmtAmt(it.unitPrice, i.token) + '</td>'
      + (anyDisc ? '<td class="r">' + (it.discountPct > 0 ? it.discountPct + '%' : '·') + '</td>' : '')
      + '<td class="r">' + (it.taxPct > 0 ? it.taxPct + '%' : '0%') + '</td>'
      + '<td class="r">' + fmtAmt((parseFloat(it.qty) || 0) * (parseFloat(it.unitPrice) || 0), i.token) + '</td></tr>'
    ).join('');
    const tls = taxLinesOf(i);
    w.document.write('<!DOCTYPE html><html><head><meta charset="utf-8"><title>' + kind + ' ' + escHtml(i.number) + '</title>'
      + '<style>body{font-family:\'IBM Plex Mono\',monospace;background:#fff;color:#000;padding:40px;font-size:12px;line-height:1.6;max-width:640px;margin:0 auto}'
      + '.top{display:flex;justify-content:space-between;align-items:flex-start;border-bottom:2px solid #000;padding-bottom:20px}'
      + '.mg{width:52px;height:52px;border:2px solid ' + escHtml(accent) + ';display:flex;align-items:center;justify-content:center;font-size:18px;font-weight:700;letter-spacing:.1em}'
      + '.biz{font-size:15px;font-weight:700;margin-top:10px}.muted{color:#555;font-size:10px;letter-spacing:.15em}'
      + 'h1{font-size:22px;letter-spacing:.15em;margin:0;text-align:right}.num{text-align:right;font-size:12px;margin-top:4px}'
      + 'table{width:100%;border-collapse:collapse;margin-top:22px}th{font-size:10px;letter-spacing:.2em;color:#555;text-align:left;font-weight:400;border-bottom:1px solid #000;padding:6px 0}'
      + 'td{padding:8px 0;border-bottom:1px solid #ccc;vertical-align:top}.r{text-align:right;white-space:nowrap}'
      + '.tot{margin-top:14px;text-align:right}.tot div{margin:2px 0}.grand{font-size:18px;font-weight:700;border-top:2px solid #000;padding-top:8px;margin-top:8px}'
      + '.pay{margin-top:26px;border:1px solid #000;padding:16px;display:flex;gap:18px;align-items:center}'
      + '.pay img{image-rendering:pixelated;width:150px;flex:none}.addr{word-break:break-all;font-size:11px;margin-top:6px}'
      + '.stamp{display:inline-block;border:3px solid #000;padding:4px 16px;font-size:16px;font-weight:700;letter-spacing:.3em;transform:rotate(-6deg);margin-top:16px}'
      + '.foot{margin-top:26px;border-top:1px solid #000;padding-top:12px;font-size:11px;color:#333}</style></head><body>'
      + '<div class="top"><div><div class="mg">' + escHtml(monogram(p.name)) + '</div>'
      + '<div class="biz">' + escHtml(p.name || 'GHOSTPAY') + '</div>'
      + (p.contact ? '<div class="muted">' + escHtml(p.contact) + '</div>' : '')
      + p.addressLines.map(l => '<div class="muted">' + escHtml(l) + '</div>').join('')
      + (p.taxNumber ? '<div class="muted">tax id: ' + escHtml(p.taxNumber) + '</div>' : '') + '</div>'
      + '<div><h1>' + kind.toUpperCase() + '</h1><div class="num"><b>' + escHtml(i.number) + '</b></div>'
      + '<div class="num">date: ' + fmtDate(i.created) + '</div>'
      + (i.expiry ? '<div class="num">' + (kind === 'invoice' ? 'due' : 'valid until') + ': ' + fmtDate(i.expiry) + '</div>' : '') + '</div></div>'
      + (i.clientName ? '<div style="margin-top:20px"><div class="muted">BILL TO</div><b>' + escHtml(i.clientName) + '</b>'
        + (client && client.contact ? '<div class="muted">' + escHtml(client.contact) + '</div>' : '')
        + clientAddr.map(l => '<div class="muted">' + escHtml(l) + '</div>').join('')
        + (client && client.vatNumber ? '<div class="muted">tax id: ' + escHtml(client.vatNumber) + '</div>' : '')
        + '</div>' : '')
      + '<table><thead><tr><th style="width:44%">DESCRIPTION</th><th class="r">QTY</th><th class="r">UNIT PRICE</th>' + (anyDisc ? '<th class="r">DISC</th>' : '') + '<th class="r">TAX</th><th class="r">AMOUNT</th></tr></thead>'
      + '<tbody>' + rows + '</tbody></table>'
      + '<div class="tot"><div>subtotal · ' + fmtAmt(i.subtotal, i.token) + ' ' + i.token + '</div>'
      + (i.discountAmount > 0 ? '<div>discount · −' + fmtAmt(i.discountAmount, i.token) + ' ' + i.token + '</div>' : '')
      + tls.map(tl => '<div>tax ' + tl.rate + '% on ' + fmtAmt(tl.base, i.token) + ' · ' + fmtAmt(tl.amount, i.token) + ' ' + i.token + '</div>').join('')
      + '<div class="grand">total · ' + fmtAmt(i.total, i.token) + ' ' + i.token + '</div></div>'
      + (st === 'PAID' ? '<div style="text-align:right"><span class="stamp">PAID</span></div>' : '')
      + '<div class="pay"><img src="' + qr + '" alt="payment QR"><div>'
      + '<div class="muted">PAY THIS ONE-TIME STEALTH ADDRESS</div>'
      + '<div class="addr"><b>' + escHtml(i.stealthAddress) + '</b></div>'
      + '<div class="addr" style="color:#555">' + escHtml(i.url) + '</div></div></div>'
      + (i.note ? '<div class="foot">note: ' + escHtml(i.note) + '</div>' : '')
      + (memo ? '<div class="foot">payment memo: ' + escHtml(memo) + '</div>' : '')
      + (p.terms ? '<div class="foot">terms: ' + escHtml(p.terms) + '</div>' : '')
      + (p.footerNote ? '<div class="foot">' + escHtml(p.footerNote) + '</div>' : '')
      + '</body></html>');
    w.document.close();
    w.focus();
    w.print();
  }

  // ── payment reconciliation: PAID arrives via GP events matching the pinned address.
  // The pinned address is unique to the invoice, so its ETH balance is the running sum
  // of everything paid to it; max() keeps the figure across sweeps. Sum below total is
  // PARTIAL, at/over total flips PAID.
  const partialToasted = new Set();
  async function syncPaid(p) {
    const all = loadInv();
    const hit = all.find(i => i.stealthAddress && i.stealthAddress.toLowerCase() === String(p.address).toLowerCase());
    if (!hit) return;
    let balEth = null;
    try {
      balEth = Number(GP.fmt.formatEth(BigInt(await GP.jrpc('eth_getBalance', [hit.stealthAddress, 'latest']))));
    } catch { /* balance best-effort: keep the previous figure */ }
    if (balEth != null && balEth > 0) {
      if (hit.token === 'ETH') {
        hit.paidAmount = Math.max(hit.paidAmount || 0, round6(balEth));
      } else {
        const px = await ethUsd();
        if (px) hit.paidAmount = Math.max(hit.paidAmount || 0, round2(balEth * px));
      }
    }
    const ps = paymentState(hit, hit.paidAmount);
    hit.paidTx = p.tx || hit.paidTx || null;
    if (ps === 'PAID' && hit.status !== 'PAID') {
      hit.status = 'PAID';
      hit.paidAt = Date.now();
      saveInv(all);
      renderAll();
      GP.toast('invoice paid: ' + hit.number + ' · ' + fmtAmt(hit.total, hit.token) + ' ' + hit.token);
    } else {
      saveInv(all);
      renderAll();
      if (ps === 'PARTIAL' && !partialToasted.has(hit.id)) {
        partialToasted.add(hit.id);
        GP.toast('partial payment on ' + hit.number + ': ' + fmtAmt(hit.paidAmount, hit.token) + ' of ' + fmtAmt(hit.total, hit.token) + ' ' + hit.token);
      }
    }
  }
  function reconcile() {
    if (!GP.state.unlocked) return;
    for (const p of GP.state.payments) syncPaid(p);
  }

  // encrypted memo pickup: the core scan emits payments without metadata, so we pull the
  // announcement receipt for the tx and try a viewing-key decrypt on any metadata > 1 byte.
  const memoInFlight = new Set();
  async function attachMemo(p) {
    if (!GP.state.unlocked) return;
    const key = p.address.toLowerCase();
    if (memos[key] || memoInFlight.has(key)) { if (memos[key]) p.memo = memos[key]; return; }
    memoInFlight.add(key);
    try {
      const receipt = await GP.jrpc('eth_getTransactionReceipt', [p.tx]);
      const log = (receipt.logs || []).find(l =>
        l.address.toLowerCase() === GP.const.ANNOUNCER.toLowerCase()
        && l.topics[2] && ('0x' + l.topics[2].slice(-40)).toLowerCase() === key);
      if (!log) return;
      const [, metadata] = GP.ethers.AbiCoder.defaultAbiCoder().decode(['bytes', 'bytes'], log.data);
      if (metadata.length <= 3) return; // 1-byte view tag: no memo (backward compatible)
      const viewPriv = GP.state.keys && GP.state.keys.viewPriv;
      if (!viewPriv) return;
      const memo = await unpackMemoMetadata({ viewPriv, metadata, crypto: C });
      if (memo) {
        memos[key] = memo;
        saveMemos(memos);
        p.memo = memo;
        renderAll();
        GP.toast('payment memo decrypted: ' + memo.slice(0, 60));
      }
    } catch { /* receipt unavailable or undecryptable: no memo */ } finally {
      memoInFlight.delete(key);
    }
  }

  async function publishEns() {
    const st = m => { $('gpinv-ens-st').textContent = m; };
    const name = $('gpinv-ensname').value.trim().toLowerCase();
    if (!name || !name.includes('.')) { st('enter an ENS name like yourname.eth'); return; }
    if (!GP.state.meta) { st('generate your stealth keys first (step 2).'); return; }
    const resolver = $('gpinv-ensresolver').value.trim() || ENS_PUBLIC_RESOLVER;
    if (!GP.ethers.isAddress(resolver)) { st('bad resolver address.'); return; }
    const node = namehash(name, C.keccak_256);
    const data = new GP.ethers.Interface(['function setText(bytes32,string,string)'])
      .encodeFunctionData('setText', [node, 'stealth', GP.state.meta]);
    st('confirm the setText transaction in your wallet…');
    try {
      const tx = { to: resolver, data };
      if (GP.state.address) tx.from = GP.state.address;
      const hash = await GP.state.walletRequest('eth_sendTransaction', [tx]);
      st('published: ' + hash + ' · ' + name + ' now advertises your stealth meta-address (public by design: anyone can pay it, nobody can spend from it).');
    } catch (e) {
      st('publish failed: ' + (e && e.message ? e.message : e));
    }
  }

  renderAll();
  reconcile();

  GP.on('payment', p => { syncPaid(p); attachMemo(p); });
  GP.on('session', () => reconcile());

  // the shell swaps tabs by toggling mount visibility: re-render any mount that
  // becomes visible so lists are always current
  let renderQueued = false;
  const queueRender = () => {
    if (renderQueued || Date.now() - selfTouch < 150) return;
    renderQueued = true;
    setTimeout(() => {
      renderQueued = false;
      for (const el of Object.values(mounts)) {
        if (el && el.offsetParent !== null) {
          if (el === mounts.invoices) renderInvoices();
          else if (el === mounts.estimates) renderEstimates();
          else if (el === mounts.customers) renderCustomers();
          else if (el === mounts.items) renderItems();
          else if (el === mounts.recurring) renderRecurring();
          else if (el === mounts.settings) renderSettings();
        }
      }
    }, 0);
  };
  const container = document.getElementById('gp-invoices');
  if (container) {
    new MutationObserver(queueRender).observe(container, { attributes: true, subtree: true, attributeFilter: ['style', 'class', 'hidden'] });
  }
}

// ── CSV export: payments + invoices + estimates ──
async function exportCsv() {
  const rows = [['date', 'type', 'number', 'client', 'address', 'amount', 'token', 'amount_usd', 'memo_or_note', 'status']];
  const price = await ethUsd();
  for (const p of GP.state.payments) {
    let date = '', amt = '';
    try {
      const [blk, bal] = await Promise.all([
        GP.jrpc('eth_getBlockByNumber', ['0x' + p.block.toString(16), false]),
        GP.jrpc('eth_getBalance', [p.address, 'latest']),
      ]);
      if (blk && blk.timestamp) date = new Date(parseInt(blk.timestamp, 16) * 1000).toISOString();
      amt = GP.fmt.formatEth(BigInt(bal));
    } catch { /* balance/date best-effort */ }
    const usd = amt && price ? (parseFloat(amt) * price).toFixed(2) : '';
    rows.push([date, 'payment', '', '', p.address, amt, 'ETH', usd, memos[p.address.toLowerCase()] || p.memo || '', p.swept ? 'SWEPT' : 'RECEIVED']);
  }
  for (const inv of loadInv()) {
    const usd = inv.token === 'USDC' ? inv.total.toFixed(2) : (price ? (inv.total * price).toFixed(2) : '');
    rows.push([new Date(inv.created).toISOString(), 'invoice', inv.number, inv.clientName || '', inv.stealthAddress, fmtAmt(inv.total, inv.token), inv.token, usd, inv.note || '', invStatus(inv)]);
  }
  for (const est of loadEst()) {
    const usd = est.token === 'USDC' ? est.total.toFixed(2) : (price ? (est.total * price).toFixed(2) : '');
    rows.push([new Date(est.created).toISOString(), 'estimate', est.number, est.clientName || '', est.stealthAddress, fmtAmt(est.total, est.token), est.token, usd, est.note || '', invStatus(est)]);
  }
  const csv = rows.map(r => r.map(c => '"' + String(c ?? '').replace(/"/g, '""') + '"').join(',')).join('\r\n');
  download('ghostpay-export-' + new Date().toISOString().slice(0, 10) + '.csv', csv, 'text/csv');
  GP.toast('csv exported');
}

// ── pay-a-ghost enhancement: pinned invoice addresses + encrypted memo field ──
// Runs only when the page was opened via a pay-me/invoice link. The core's pay-a-ghost
// block has already rendered; we add a memo input and take over the announce button.
// Invoice links (created above) pin a pre-derived stealth address so the payment lands
// exactly on the invoice's tracked address; plain links derive fresh, as the core does.
function enhancePayghost() {
  const pg = document.getElementById('payghost');
  if (!pg || getComputedStyle(pg).display === 'none') return;
  const metaMatch = location.hash.match(/st:eth:0x[0-9a-fA-F]{132}/);
  if (!metaMatch) return;
  const C = GP.crypto;
  const $ = id => document.getElementById(id);
  const metaHex = metaMatch[0].slice(7);
  const viewPub = C.buf(metaHex).slice(33, 66);
  const params = new URLSearchParams(location.hash.includes('?') ? location.hash.slice(location.hash.indexOf('?') + 1) : '');

  let target;
  const st = params.get('st'), eph = params.get('eph'), vt = params.get('vt');
  if (st && eph && vt !== null && GP.ethers.isAddress(st) && /^0x[0-9a-fA-F]{66}$/.test(eph)) {
    target = { stealth: st, ephPub: eph, viewTag: Number(vt) & 0xff };
  } else {
    target = C.derive(metaHex);
  }
  const addrEl = $('v-payaddr');
  if (addrEl) addrEl.textContent = target.stealth;
  const copyAddr = $('b-copyaddr');
  if (copyAddr) copyAddr.onclick = () => copyBtn(target.stealth, copyAddr, 'COPY');

  const invId = params.get('inv');
  const invNum = params.get('num');
  const exp = Number(params.get('exp'));
  const expired = Number.isFinite(exp) && exp > 0 && Date.now() > exp;
  const stInvoice = $('st-invoice');
  if (stInvoice && (invNum || invId)) stInvoice.textContent += ' · invoice ' + (invNum || invId);
  if (stInvoice && expired) stInvoice.textContent += ' · THIS INVOICE HAS EXPIRED';

  const btn = $('b-announce');
  if (!btn) return;
  const memoInput = document.createElement('input');
  memoInput.id = 'gpinv-memo';
  memoInput.maxLength = 280;
  memoInput.placeholder = 'memo (optional: encrypted, only the recipient can read it)';
  // the invoice note travels in the pay= param and prefills the payer's memo, so it
  // lands in the encrypted announcement memo on payment
  const payParts = (params.get('pay') || '').split(' · ');
  if (payParts.length > 1) memoInput.value = payParts.slice(1).join(' · ').slice(0, 280);
  btn.parentNode.insertBefore(memoInput, btn);
  if (expired) btn.disabled = true;

  btn.onclick = async () => {
    if (expired) { $('v-ann').textContent = 'invoice expired: ask for a fresh link.'; return; }
    const memo = memoInput.value.trim();
    let metadataHex = null;
    if (memo) {
      try {
        metadataHex = await packMemoMetadata({ viewPub, viewTag: target.viewTag, memo, crypto: C });
      } catch (e) {
        $('v-ann').textContent = e.message;
        return;
      }
    }
    // invoice amount (ETH only): "25 ETH · note" → the value of the payment call
    let value = 0n;
    const pm = (params.get('pay') || '').match(/^\s*([0-9]+(?:\.[0-9]+)?)\s*ETH/i);
    if (pm) { try { value = GP.ethers.parseEther(pm[1]); } catch { value = 0n; } }
    const PAA = GP.const && GP.const.PAY_AND_ANNOUNCE;
    if (PAA) {
      // one transaction: payment + announcement + (optional) encrypted memo via PayAndAnnounce
      try {
        $('v-ann').textContent = 'paying + announcing in one transaction…';
        const md = metadataHex ? C.buf(metadataHex) : Uint8Array.from([target.viewTag]);
        const payData = new GP.ethers.Interface(['function pay(address stealth, bytes ephPub, bytes metadata) payable'])
          .encodeFunctionData('pay', [target.stealth, target.ephPub, md]);
        const account = (await GP.state.walletRequest('eth_requestAccounts', []))[0];
        const hash = await GP.state.walletRequest('eth_sendTransaction', [{ from: account, to: PAA, value: '0x' + value.toString(16), data: payData }]);
        $('v-ann').textContent = 'paid + announced in one transaction · tx ' + hash + (memo ? ' · encrypted memo attached' : '');
        return;
      } catch (e) {
        $('v-ann').textContent = 'payment failed: ' + (e.shortMessage || e.message) + ' · nothing was sent, retry.';
        return;
      }
    }
    if (memo) {
      // relayer path: gasless for the payer, metadata passed through verbatim
      try {
        $('v-ann').textContent = 'announcing via relayer… (deliberate 2–15s privacy delay)';
        const r = await fetch('/announce', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ stealth: target.stealth, ephPub: target.ephPub, viewTag: target.viewTag, metadata: metadataHex }),
        });
        const j = await r.json().catch(() => ({}));
        if (!r.ok || j.error) throw new Error(j.error || 'http ' + r.status);
        $('v-ann').textContent = 'announced via relayer: ' + j.hash + ' · encrypted memo attached';
        return;
      } catch { /* relayer unreachable: fall back to the wallet below */ }
    }
    if (!window.ethereum) return alert('no wallet found');
    const signer = await new GP.ethers.BrowserProvider(window.ethereum).getSigner();
    const ann = new GP.ethers.Contract(GP.const.ANNOUNCER, ['function announce(uint256,address,bytes,bytes)'], signer);
    const md = metadataHex ? C.buf(metadataHex) : Uint8Array.from([target.viewTag]);
    const tx = await ann.announce(1, target.stealth, target.ephPub, md);
    $('v-ann').textContent = 'announced: ' + tx.hash + (memo ? ' · encrypted memo attached' : '');
  };
}

let booted = false;
function boot() {
  if (booted) return;
  GP = GP || (typeof window !== 'undefined' ? window.GP || null : null);
  if (!GP) return;
  booted = true;
  const SUITE_MOUNTS = ['tab-invoices', 'tab-estimates', 'tab-customers', 'tab-items', 'tab-recurring', 'tab-settings'];
  if (SUITE_MOUNTS.some(id => document.getElementById(id))) {
    initSuite().catch(e => console.error('gp-invoices: suite init failed', e));
  }
  enhancePayghost();
}
if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
  // window.GP may land a beat after this module evaluates: poll briefly, then stop
  let bootTries = 0;
  const bootTimer = setInterval(() => {
    if (booted || ++bootTries > 150) clearInterval(bootTimer);
    else boot();
  }, 100);
}
