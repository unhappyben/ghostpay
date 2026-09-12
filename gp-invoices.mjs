// gp-invoices.mjs · GHOSTPAY invoice suite module (docs/GP-API.md).
// Mounts into #gp-invoices on invoices.html (frag-invoices.html markup): four sub-tabs
// (OVERVIEW, INVOICES, CLIENTS, PROFILE) over three localStorage registries (gp-profile,
// gp-clients, gp-invoices). Invoices pin a pre-derived stealth address in a self-contained
// hash-param URL pointing at the homepage pay panel; payment status reconciles from GP
// payment events. On the homepage the same file runs without the suite mount and keeps
// only its pay-a-ghost enhancement (memo format unchanged). Pure helpers are exported so
// a node smoke test can exercise migration + totals math without a DOM.

const GP = typeof window !== 'undefined' ? window.GP || null : null;

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

export const DEFAULT_PROFILE = {
  name: '', contact: '', token: 'USDC', prefix: 'GP-', next: 1,
  terms: 'payment due on receipt', taxPct: null,
};

const round2 = n => Math.round((n + Number.EPSILON) * 100) / 100;

// Line items + optional tax % → subtotal/tax/total. Tax is its own line, never folded
// into the item prices.
export function computeTotals(items, taxPct) {
  const subtotal = round2((items || []).reduce((s, it) => s + (parseFloat(it.qty) || 0) * (parseFloat(it.unitPrice) || 0), 0));
  const pct = parseFloat(taxPct);
  const useTax = Number.isFinite(pct) && pct > 0;
  const taxAmount = useTax ? round2(subtotal * pct / 100) : 0;
  return { subtotal, taxPct: useTax ? pct : null, taxAmount, total: round2(subtotal + taxAmount) };
}

// Invoice numbers come from the profile counter: prefix + zero-padded counter.
export function allocateNumber(profile) {
  const p = profile || {};
  const prefix = typeof p.prefix === 'string' && p.prefix ? p.prefix : 'GP-';
  const n = Number.isFinite(+p.next) && +p.next > 0 ? Math.floor(+p.next) : 1;
  return { number: prefix + String(n).padStart(4, '0'), next: n + 1 };
}

// Effective status: PAID is terminal, EXPIRED is derived (past expiry, unpaid), the rest
// is the stored status. DRAFT → SENT is manual; PAID arrives via GP payment events.
export function invStatus(rec, now) {
  if (rec.status === 'PAID') return 'PAID';
  if (rec.expiry && (now ?? Date.now()) > rec.expiry) return 'EXPIRED';
  return rec.status || 'SENT';
}

// v1 → v2 record upgrade. v1 records were { id, amount, token, note, stealthAddress,
// created, url, status: 'UNPAID'|'PAID', expiry }: the amount becomes a single line
// item, UNPAID becomes SENT (the link was already handed out), a number is assigned.
export function migrateInvoice(rec, number) {
  if (rec && rec.v === 2) return rec;
  const amount = parseFloat(rec.amount) || 0;
  const t = computeTotals(
    Array.isArray(rec.items) && rec.items.length ? rec.items : [{ description: rec.note || 'invoice', qty: 1, unitPrice: amount }],
    rec.taxPct
  );
  return {
    v: 2,
    id: rec.id || 'inv-' + Date.now().toString(36),
    number: rec.number || number || rec.id,
    clientId: rec.clientId || null,
    clientName: rec.clientName || '',
    items: Array.isArray(rec.items) && rec.items.length ? rec.items : [{ description: rec.note || 'invoice', qty: 1, unitPrice: amount }],
    token: rec.token === 'ETH' ? 'ETH' : 'USDC',
    subtotal: Number.isFinite(rec.subtotal) ? rec.subtotal : t.subtotal,
    taxPct: rec.taxPct ?? t.taxPct,
    taxAmount: Number.isFinite(rec.taxAmount) ? rec.taxAmount : t.taxAmount,
    total: Number.isFinite(rec.total) ? rec.total : t.total,
    note: rec.note || '',
    stealthAddress: rec.stealthAddress || '',
    created: rec.created || Date.now(),
    url: rec.url || '',
    expiry: rec.expiry || null,
    status: rec.status === 'PAID' ? 'PAID' : (rec.status === 'DRAFT' ? 'DRAFT' : 'SENT'),
    sentAt: rec.sentAt || null,
    paidAt: rec.paidAt || null,
    paidTx: rec.paidTx || null,
  };
}

// Whole-registry migration: legacy records get numbers in creation order, the profile
// counter advances past them. Idempotent: v2 records pass through untouched.
export function migrateRegistry(records, profile) {
  const p = { ...DEFAULT_PROFILE, ...(profile || {}) };
  const out = (records || []).map(r => (r && r.v === 2 ? r : null));
  const legacy = (records || [])
    .map((r, i) => ({ r, i }))
    .filter(x => x.r && x.r.v !== 2)
    .sort((a, b) => (a.r.created || 0) - (b.r.created || 0));
  for (const { r, i } of legacy) {
    const a = allocateNumber(p);
    p.next = a.next;
    out[i] = migrateInvoice(r, a.number);
  }
  return { records: out.filter(Boolean), profile: p };
}

// ── everything below runs only in the browser with window.GP present ──

const INV_KEY = 'gp-invoices';
const MEMO_KEY = 'gp-invoice-memos';
const PROFILE_KEY = 'gp-profile';
const CLIENTS_KEY = 'gp-clients';
const ENS_PUBLIC_RESOLVER = '0x231b0Ee14048e9dCcD1d247744d114a4EB5E8E63';

const lsGet = (k, d) => { try { return JSON.parse(localStorage.getItem(k)) ?? d; } catch { return d; } };
const lsSet = (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* best-effort */ } };

const loadProfile = () => ({ ...DEFAULT_PROFILE, ...lsGet(PROFILE_KEY, {}) });
const saveProfile = p => lsSet(PROFILE_KEY, p);
const loadClients = () => lsGet(CLIENTS_KEY, []);
const saveClients = c => lsSet(CLIENTS_KEY, c);
const loadMemos = () => lsGet(MEMO_KEY, {});
const saveMemos = m => lsSet(MEMO_KEY, m);
const memos = typeof localStorage !== 'undefined' ? loadMemos() : {};

// Registry load migrates legacy records on the way out and persists the result once.
function loadInv() {
  const raw = lsGet(INV_KEY, []);
  if (!raw.some(r => r && r.v !== 2)) return raw;
  const { records, profile } = migrateRegistry(raw, loadProfile());
  lsSet(INV_KEY, records);
  saveProfile(profile);
  return records;
}
const saveInv = inv => lsSet(INV_KEY, inv);

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
const escHtml = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const monogram = name => {
  const w = (name || '').trim().split(/\s+/).filter(Boolean);
  return (w.length ? w.slice(0, 2).map(x => x[0]).join('') : 'GP').toUpperCase();
};

// ── qrcode-generator: same esm.sh import the core uses, loaded lazily so this file
// stays importable under plain node (no DOM, no network) for the smoke test.
let qrLib = null;
async function getQr() {
  qrLib ??= (await import('https://esm.sh/qrcode-generator@1.4.4')).default;
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
function initSuite() {
  const $ = id => document.getElementById(id);
  const root = $('gpinv-root');
  const view = $('gpinv-view');
  const C = GP.crypto;

  // view state (in-memory only)
  let tab = 'overview';
  let showForm = false;
  let formRows = [{ description: '', qty: 1, unitPrice: '' }];
  let openInv = null;
  let qrFor = null;

  const pill = st => '<span class="gpinv-pill' + (st === 'DRAFT' || st === 'EXPIRED' ? ' dim' : '') + '">' + st + '</span>';

  // ── tab: OVERVIEW ──
  function renderOverview() {
    const inv = loadInv();
    const now = Date.now();
    const month = new Date().toISOString().slice(0, 7);
    const sum = (fn) => inv.filter(fn).reduce((m, i) => { m[i.token] = (m[i.token] || 0) + i.total; return m; }, {});
    const outstanding = sum(i => invStatus(i, now) === 'SENT');
    const paidMonth = sum(i => i.status === 'PAID' && new Date(i.paidAt || i.created).toISOString().slice(0, 7) === month);
    const counts = { DRAFT: 0, SENT: 0, PAID: 0, EXPIRED: 0 };
    for (const i of inv) counts[invStatus(i, now)]++;
    const moneyLines = m => {
      const keys = Object.keys(m);
      if (!keys.length) return '<div class="gpinv-big">0</div>';
      return keys.map(t =>
        '<div class="gpinv-big">' + fmtAmt(m[t], t) + ' <span class="gpinv-unit">' + t + '</span></div>'
        + '<div class="status" style="margin-top:2px" data-usd data-amt="' + m[t] + '" data-token="' + t + '"></div>'
      ).join('');
    };
    const ev = [];
    for (const i of inv) {
      ev.push({ ts: i.created, text: i.number + ' created · ' + fmtAmt(i.total, i.token) + ' ' + i.token + (i.clientName ? ' · ' + i.clientName : '') });
      if (i.sentAt) ev.push({ ts: i.sentAt, text: i.number + ' marked sent' });
      if (i.paidAt) ev.push({ ts: i.paidAt, text: i.number + ' paid' });
    }
    ev.sort((a, b) => b.ts - a.ts);
    const recent = ev.slice(0, 8);
    const payments = GP.state.payments || [];
    const swept = payments.filter(p => p.swept).length;

    view.innerHTML =
      '<div class="gpinv-grid">'
      + '<div class="gpinv-box"><div class="gpinv-lbl">OUTSTANDING</div>' + moneyLines(outstanding) + '</div>'
      + '<div class="gpinv-box"><div class="gpinv-lbl">PAID THIS MONTH</div>' + moneyLines(paidMonth) + '</div>'
      + '</div>'
      + '<div class="gpinv-box" style="margin-top:14px"><div class="gpinv-lbl">INVOICES</div>'
      + '<div style="display:flex;gap:14px;flex-wrap:wrap;font-size:12px">'
      + ['DRAFT', 'SENT', 'PAID', 'EXPIRED'].map(s => '<span>' + pill(s) + ' <b>' + counts[s] + '</b></span>').join('')
      + '</div>'
      + '<div class="status">payments detected this session: ' + payments.length + (swept ? ' · swept: ' + swept : '') + '</div>'
      + '</div>'
      + '<h3>RECENT ACTIVITY</h3>'
      + (recent.length
        ? '<table><tbody>' + recent.map(e =>
            '<tr><td class="gpinv-muted" style="white-space:nowrap">' + fmtDate(e.ts) + '</td><td>' + escHtml(e.text) + '</td></tr>'
          ).join('') + '</tbody></table>'
        : '<div class="gpinv-empty">nothing yet: create an invoice in the INVOICES tab and it shows up here.</div>')
      + '<div class="gpinv-actions">'
      + '<button class="ghost" data-act="export-csv">EXPORT CSV</button>'
      + '<button class="ghost" data-act="recv-qr">RECEIVE QR</button>'
      + '</div>';
  }

  // ── tab: INVOICES ──
  function newFormHtml() {
    const p = loadProfile();
    const clients = loadClients();
    return '<h3>NEW INVOICE</h3>'
      + '<div class="gpinv-box">'
      + '<div class="gpinv-lbl">CLIENT</div>'
      + '<select id="gpinv-f-client" style="margin-top:4px"><option value="">no client</option>'
      + clients.map(c => '<option value="' + escHtml(c.id) + '">' + escHtml(c.name) + '</option>').join('')
      + '</select>'
      + '<div class="gpinv-lbl" style="margin-top:14px">LINE ITEMS</div>'
      + '<div class="gpinv-tablewrap"><table id="gpinv-f-items"><thead><tr>'
      + '<th style="width:46%">DESCRIPTION</th><th>QTY</th><th>UNIT PRICE</th><th style="text-align:right">AMOUNT</th><th></th>'
      + '</tr></thead><tbody>'
      + formRows.map((r, i) =>
          '<tr><td><input data-row="' + i + '" data-f="description" placeholder="description" value="' + escHtml(r.description) + '"></td>'
          + '<td><input data-row="' + i + '" data-f="qty" type="number" min="0" step="any" value="' + escHtml(r.qty) + '"></td>'
          + '<td><input data-row="' + i + '" data-f="unitPrice" type="number" min="0" step="any" placeholder="0.00" value="' + escHtml(r.unitPrice) + '"></td>'
          + '<td style="text-align:right;white-space:nowrap" data-rowamt="' + i + '">' + fmtAmt((parseFloat(r.qty) || 0) * (parseFloat(r.unitPrice) || 0), p.token) + '</td>'
          + '<td style="width:1%"><button class="ghost gpinv-x" data-act="del-row" data-row="' + i + '" title="remove row">×</button></td></tr>'
        ).join('')
      + '</tbody></table></div>'
      + '<button class="ghost" data-act="add-row" style="width:auto;padding:8px 14px;font-size:11px;margin-top:10px">+ ADD ROW</button>'
      + '<div style="margin-top:14px;text-align:right;font-size:12px">'
      + '<div>subtotal · <b id="gpinv-f-sub">0.00</b></div>'
      + '<div id="gpinv-f-taxrow" style="display:none">tax <span id="gpinv-f-taxpct"></span>% · <b id="gpinv-f-tax">0.00</b></div>'
      + '<div style="font-size:16px;margin-top:4px">total · <b id="gpinv-f-total">0.00</b> <span id="gpinv-f-tok2"></span></div>'
      + '<div class="status" style="margin-top:2px" id="gpinv-f-usd"></div>'
      + '</div>'
      + '<div class="gpinv-lbl" style="margin-top:14px">TOKEN</div>'
      + '<select id="gpinv-f-token" style="margin-top:4px">'
      + ['USDC', 'ETH'].map(t => '<option' + (p.token === t ? ' selected' : '') + '>' + t + '</option>').join('')
      + '</select>'
      + '<input id="gpinv-f-note" placeholder="note (optional: prefills the payer\'s encrypted memo)">'
      + '<input id="gpinv-f-exp" type="number" min="0" placeholder="expires in days (optional: blank = never)">'
      + '<button data-act="create" style="margin-top:14px">CREATE INVOICE</button>'
      + '<div class="status" id="gpinv-f-st"></div>'
      + '</div>';
  }

  function readForm() {
    const rows = [];
    view.querySelectorAll('#gpinv-f-items tbody tr').forEach(tr => {
      const get = f => { const el = tr.querySelector('[data-f="' + f + '"]'); return el ? el.value : ''; };
      rows.push({ description: get('description').trim(), qty: get('qty'), unitPrice: get('unitPrice') });
    });
    return rows;
  }

  function refreshFormTotals() {
    if (!$('gpinv-f-items')) return;
    formRows = readForm();
    const p = loadProfile();
    const token = $('gpinv-f-token').value;
    const t = computeTotals(formRows, p.taxPct);
    formRows.forEach((r, i) => {
      const cell = view.querySelector('[data-rowamt="' + i + '"]');
      if (cell) cell.textContent = fmtAmt((parseFloat(r.qty) || 0) * (parseFloat(r.unitPrice) || 0), token);
    });
    $('gpinv-f-sub').textContent = fmtAmt(t.subtotal, token);
    $('gpinv-f-taxrow').style.display = t.taxPct ? 'block' : 'none';
    if (t.taxPct) { $('gpinv-f-taxpct').textContent = t.taxPct; $('gpinv-f-tax').textContent = fmtAmt(t.taxAmount, token); }
    $('gpinv-f-total').textContent = fmtAmt(t.total, token);
    $('gpinv-f-tok2').textContent = token;
    const usdEl = $('gpinv-f-usd');
    const direct = fmtUsd(t.total, token, GP.state.ethPriceUsd);
    if (direct) usdEl.textContent = '≈ ' + direct + ' usd';
    else ethUsd().then(px => {
      const u = fmtUsd(t.total, token, px);
      if (usdEl.isConnected) usdEl.textContent = u ? '≈ ' + u + ' usd' : 'usd estimate unavailable (relayer price feed offline)';
    });
  }

  function invDetailHtml(i) {
    const st = invStatus(i);
    const memo = memos[(i.stealthAddress || '').toLowerCase()] || '';
    const itemRows = i.items.map(it =>
      '<tr><td>' + escHtml(it.description || 'item') + '</td>'
      + '<td>' + escHtml(it.qty) + '</td>'
      + '<td>' + fmtAmt(it.unitPrice, i.token) + '</td>'
      + '<td style="text-align:right">' + fmtAmt((parseFloat(it.qty) || 0) * (parseFloat(it.unitPrice) || 0), i.token) + '</td></tr>'
    ).join('');
    return '<div class="gpinv-lbl">INVOICE ' + escHtml(i.number) + '</div>'
      + '<div class="gpinv-muted" style="font-size:12px">'
      + 'created ' + fmtDate(i.created)
      + (i.clientName ? ' · client: ' + escHtml(i.clientName) : '')
      + (i.expiry ? ' · expires ' + fmtDate(i.expiry) : ' · no expiry')
      + (i.sentAt ? ' · sent ' + fmtDate(i.sentAt) : '')
      + (i.paidAt ? ' · paid ' + fmtDate(i.paidAt) : '')
      + '</div>'
      + '<div class="gpinv-tablewrap" style="margin-top:12px"><table><thead><tr>'
      + '<th style="width:46%">DESCRIPTION</th><th>QTY</th><th>UNIT PRICE</th><th style="text-align:right">AMOUNT</th>'
      + '</tr></thead><tbody>' + itemRows + '</tbody></table></div>'
      + '<div style="margin-top:10px;text-align:right;font-size:12px">'
      + '<div>subtotal · ' + fmtAmt(i.subtotal, i.token) + ' ' + i.token + '</div>'
      + (i.taxPct ? '<div>tax ' + i.taxPct + '% · ' + fmtAmt(i.taxAmount, i.token) + ' ' + i.token + '</div>' : '')
      + '<div style="font-size:16px;margin-top:2px"><b>' + fmtAmt(i.total, i.token) + ' ' + i.token + '</b></div>'
      + '<div class="status" style="margin-top:2px" data-usd data-amt="' + i.total + '" data-token="' + i.token + '"></div>'
      + '</div>'
      + (i.note ? '<div class="status">note: ' + escHtml(i.note) + '</div>' : '')
      + (memo ? '<div class="status" style="color:#fff">payment memo: ' + escHtml(memo) + '</div>' : '')
      + '<div class="gpinv-lbl" style="margin-top:12px">PINNED STEALTH ADDRESS</div>'
      + '<div class="gpinv-mono">' + escHtml(i.stealthAddress) + '</div>'
      + '<div class="gpinv-mono" style="margin-top:6px">' + escHtml(i.url) + '</div>'
      + (qrFor === i.id ? '<div style="margin-top:12px;text-align:center"><canvas data-qr style="background:#fff;padding:14px;image-rendering:pixelated;max-width:100%"></canvas></div>' : '')
      + '<div class="gpinv-actions">'
      + '<button class="ghost" data-act="view" data-id="' + escHtml(i.id) + '">VIEW LINK</button>'
      + '<button class="ghost" data-act="qr" data-id="' + escHtml(i.id) + '">QR</button>'
      + '<button class="ghost" data-act="copy" data-id="' + escHtml(i.id) + '">COPY LINK</button>'
      + '<button class="ghost" data-act="dup" data-id="' + escHtml(i.id) + '">DUPLICATE</button>'
      + (st === 'DRAFT' ? '<button class="ghost" data-act="sent" data-id="' + escHtml(i.id) + '">MARK SENT</button>' : '')
      + '<button class="ghost" data-act="print" data-id="' + escHtml(i.id) + '">PRINT / PDF</button>'
      + '<button class="ghost" data-act="del" data-id="' + escHtml(i.id) + '">DELETE</button>'
      + '</div>';
  }

  function renderInvoices() {
    const inv = loadInv();
    const rows = [...inv].sort((a, b) => b.created - a.created);
    view.innerHTML =
      '<div class="gpinv-actions" style="margin-top:0">'
      + '<button data-act="toggle-form">' + (showForm ? 'CANCEL' : 'NEW INVOICE') + '</button>'
      + '</div>'
      + (showForm ? newFormHtml() : '')
      + '<h3>INVOICES</h3>'
      + (rows.length
        ? '<div class="gpinv-tablewrap"><table><thead><tr>'
          + '<th>NUMBER</th><th>CLIENT</th><th style="text-align:right">TOTAL</th><th style="text-align:right">STATUS</th>'
          + '</tr></thead><tbody>'
          + rows.map(i =>
              '<tr class="gpinv-rowbtn" data-act="open" data-id="' + escHtml(i.id) + '">'
              + '<td><b>' + escHtml(i.number) + '</b><div class="gpinv-muted" style="font-size:10px">' + fmtDate(i.created) + '</div></td>'
              + '<td>' + (i.clientName ? escHtml(i.clientName) : '<span class="gpinv-muted">·</span>') + '</td>'
              + '<td style="text-align:right;white-space:nowrap">' + fmtAmt(i.total, i.token) + ' ' + i.token + '</td>'
              + '<td style="text-align:right">' + pill(invStatus(i)) + '</td></tr>'
              + (openInv === i.id ? '<tr class="gpinv-detail"><td colspan="4">' + invDetailHtml(i) + '</td></tr>' : '')
            ).join('')
          + '</tbody></table></div>'
        : '<div class="gpinv-empty">no invoices yet: press NEW INVOICE to create your first one.</div>');
    if (showForm) refreshFormTotals();
    if (openInv && qrFor === openInv) {
      const i = inv.find(x => x.id === openInv);
      const cv = view.querySelector('canvas[data-qr]');
      if (i && cv) drawQr(cv, i.url).catch(() => GP.toast('QR failed: content too long'));
    }
  }

  // ── tab: CLIENTS ──
  function renderClients() {
    const clients = loadClients();
    const inv = loadInv();
    const now = Date.now();
    view.innerHTML =
      '<h3>ADD CLIENT</h3>'
      + '<div class="gpinv-box">'
      + '<input id="gpinv-c-name" placeholder="name" style="margin-top:0">'
      + '<input id="gpinv-c-contact" placeholder="contact (email, telegram, …)">'
      + '<input id="gpinv-c-notes" placeholder="notes (optional)">'
      + '<button data-act="add-client" style="margin-top:14px">ADD CLIENT</button>'
      + '<div class="status" id="gpinv-c-st"></div>'
      + '</div>'
      + '<h3>CLIENTS</h3>'
      + (clients.length
        ? '<div class="gpinv-tablewrap"><table><thead><tr>'
          + '<th>NAME</th><th>CONTACT</th><th style="text-align:right">OUTSTANDING</th><th style="text-align:right">PAID</th><th></th>'
          + '</tr></thead><tbody>'
          + clients.map(c => {
              const mine = inv.filter(i => i.clientId === c.id);
              const tot = f => mine.filter(f).reduce((m, i) => { m[i.token] = (m[i.token] || 0) + i.total; return m; }, {});
              const cell = m => Object.keys(m).length ? Object.keys(m).map(t => fmtAmt(m[t], t) + ' ' + t).join('<br>') : '<span class="gpinv-muted">·</span>';
              return '<tr><td><b>' + escHtml(c.name) + '</b>'
                + (c.notes ? '<div class="gpinv-muted" style="font-size:10px">' + escHtml(c.notes) + '</div>' : '')
                + '</td><td>' + (c.contact ? escHtml(c.contact) : '<span class="gpinv-muted">·</span>') + '</td>'
                + '<td style="text-align:right">' + cell(tot(i => invStatus(i, now) === 'SENT')) + '</td>'
                + '<td style="text-align:right">' + cell(tot(i => i.status === 'PAID')) + '</td>'
                + '<td style="width:1%"><button class="ghost gpinv-x" data-act="del-client" data-id="' + escHtml(c.id) + '" title="delete client">×</button></td></tr>';
            }).join('')
          + '</tbody></table></div>'
        : '<div class="gpinv-empty">no clients yet: add one above, then pick them when creating an invoice.</div>');
  }

  // ── tab: PROFILE ──
  function renderProfile() {
    const p = loadProfile();
    view.innerHTML =
      '<div style="display:flex;gap:16px;align-items:center;margin-bottom:6px">'
      + '<div class="gpinv-mg">' + escHtml(monogram(p.name)) + '</div>'
      + '<div><div style="font-weight:700">' + (p.name ? escHtml(p.name) : 'your business') + '</div>'
      + '<div class="gpinv-muted" style="font-size:11px">' + (p.contact ? escHtml(p.contact) : 'this profile stamps every invoice and receipt.') + '</div></div>'
      + '</div>'
      + '<h3>BUSINESS PROFILE</h3>'
      + '<div class="gpinv-box">'
      + '<div class="gpinv-lbl">BUSINESS NAME</div><input id="gpinv-p-name" style="margin-top:4px" value="' + escHtml(p.name) + '" placeholder="e.g. Ghost Studio">'
      + '<div class="gpinv-lbl" style="margin-top:12px">FROM / CONTACT LINE</div><input id="gpinv-p-contact" style="margin-top:4px" value="' + escHtml(p.contact) + '" placeholder="e.g. ben@ghoststudio.eth">'
      + '<div class="gpinv-lbl" style="margin-top:12px">DEFAULT TOKEN</div><select id="gpinv-p-token" style="margin-top:4px">'
      + ['USDC', 'ETH'].map(t => '<option' + (p.token === t ? ' selected' : '') + '>' + t + '</option>').join('') + '</select>'
      + '<div class="gpinv-grid" style="margin-top:12px">'
      + '<div><div class="gpinv-lbl">NUMBER PREFIX</div><input id="gpinv-p-prefix" style="margin-top:4px" value="' + escHtml(p.prefix) + '" placeholder="GP-"></div>'
      + '<div><div class="gpinv-lbl">NEXT NUMBER</div><input id="gpinv-p-next" style="margin-top:4px" type="number" min="1" value="' + escHtml(p.next) + '"></div>'
      + '</div>'
      + '<div class="gpinv-lbl" style="margin-top:12px">DEFAULT PAYMENT TERMS</div><input id="gpinv-p-terms" style="margin-top:4px" value="' + escHtml(p.terms) + '" placeholder="payment due on receipt">'
      + '<div class="gpinv-lbl" style="margin-top:12px">TAX % (OPTIONAL: SHOWN AS ITS OWN LINE)</div><input id="gpinv-p-tax" style="margin-top:4px" type="number" min="0" step="any" value="' + (p.taxPct ?? '') + '" placeholder="e.g. 20">'
      + '<button data-act="save-profile" style="margin-top:14px">SAVE PROFILE</button>'
      + '<div class="status" id="gpinv-p-st"></div>'
      + '</div>'
      + '<h3>PUBLISH TO ENS</h3>'
      + '<div class="gpinv-box">'
      + '<div class="status" style="margin-top:0">writes a "stealth" text record on your ENS name so senders can resolve it to your stealth meta-address. the meta-address is public by design: anyone can derive fresh payment addresses from it, nobody can spend from it.</div>'
      + '<input id="gpinv-ensname" placeholder="yourname.eth">'
      + '<input id="gpinv-ensresolver" value="' + ENS_PUBLIC_RESOLVER + '" placeholder="resolver address">'
      + '<button class="ghost" data-act="ens" style="margin-top:12px">PUBLISH TO ENS</button>'
      + '<div class="status" id="gpinv-ens-st"></div>'
      + '<div class="status">rather click through: <a id="gpinv-enslink" href="https://app.ens.domains" target="_blank" rel="noopener">open app.ens.domains</a> and set the "stealth" text record manually.</div>'
      + '</div>';
  }

  function render() {
    root.querySelectorAll('.gpinv-tabs button').forEach(b => b.classList.toggle('on', b.dataset.tab === tab));
    if (tab === 'overview') renderOverview();
    else if (tab === 'invoices') renderInvoices();
    else if (tab === 'clients') renderClients();
    else renderProfile();
    fillUsd();
  }

  // fills every [data-usd] placeholder once a price is available
  function fillUsd() {
    const els = [...view.querySelectorAll('[data-usd]')];
    if (!els.length) return;
    const paint = px => els.forEach(el => {
      const u = fmtUsd(el.dataset.amt, el.dataset.token, px);
      if (u && el.isConnected) el.textContent = '≈ ' + u + ' usd';
    });
    paint(GP.state.ethPriceUsd);
    ethUsd().then(paint);
  }

  // ── actions (one delegated handler) ──
  root.addEventListener('click', e => {
    const el = e.target.closest('[data-act]');
    if (!el || !root.contains(el)) return;
    const act = el.dataset.act, id = el.dataset.id;
    const inv = id != null ? loadInv() : null;
    const rec = id != null ? inv.find(x => x.id === id) : null;

    if (act === 'tab') { tab = el.dataset.tab; render(); return; }
    if (act === 'toggle-form') { showForm = !showForm; render(); return; }
    if (act === 'add-row') { formRows = readForm(); formRows.push({ description: '', qty: 1, unitPrice: '' }); render(); return; }
    if (act === 'del-row') {
      formRows = readForm();
      formRows.splice(Number(el.dataset.row), 1);
      if (!formRows.length) formRows.push({ description: '', qty: 1, unitPrice: '' });
      render();
      return;
    }
    if (act === 'open') { openInv = openInv === id ? null : id; if (qrFor !== openInv) qrFor = null; render(); return; }
    if (act === 'qr') { openInv = id; qrFor = qrFor === id ? null : id; render(); return; }
    if (act === 'copy' && rec) { copyBtn(rec.url, el, 'COPY LINK'); return; }
    if (act === 'view' && rec) { window.open(rec.url, '_blank', 'noopener'); return; }
    if (act === 'print' && rec) { printInvoice(rec); return; }
    if (act === 'sent' && rec && invStatus(rec) === 'DRAFT') {
      rec.status = 'SENT'; rec.sentAt = Date.now();
      saveInv(inv); render();
      GP.toast(rec.number + ' marked sent');
      return;
    }
    if (act === 'dup' && rec) { duplicateInvoice(rec); return; }
    if (act === 'del' && rec) {
      saveInv(inv.filter(x => x.id !== id));
      if (openInv === id) { openInv = null; qrFor = null; }
      render();
      return;
    }
    if (act === 'create') { createInvoice(); return; }
    if (act === 'add-client') {
      const name = $('gpinv-c-name').value.trim();
      if (!name) { $('gpinv-c-st').textContent = 'enter a name.'; return; }
      const clients = loadClients();
      clients.push({ id: 'cl-' + Date.now().toString(36) + '-' + Math.floor(Math.random() * 46656).toString(36), name, contact: $('gpinv-c-contact').value.trim(), notes: $('gpinv-c-notes').value.trim(), created: Date.now() });
      saveClients(clients); render();
      GP.toast('client added: ' + name);
      return;
    }
    if (act === 'del-client') {
      saveClients(loadClients().filter(c => c.id !== id));
      render();
      return;
    }
    if (act === 'save-profile') {
      const p = loadProfile();
      p.name = $('gpinv-p-name').value.trim();
      p.contact = $('gpinv-p-contact').value.trim();
      p.token = $('gpinv-p-token').value === 'ETH' ? 'ETH' : 'USDC';
      p.prefix = $('gpinv-p-prefix').value.trim() || 'GP-';
      p.next = Math.max(1, Math.floor(parseFloat($('gpinv-p-next').value) || 1));
      p.terms = $('gpinv-p-terms').value.trim() || DEFAULT_PROFILE.terms;
      const tax = parseFloat($('gpinv-p-tax').value);
      p.taxPct = Number.isFinite(tax) && tax > 0 ? tax : null;
      saveProfile(p); render();
      GP.toast('profile saved');
      return;
    }
    if (act === 'export-csv') { exportCsv(); return; }
    if (act === 'recv-qr') {
      const recv = GP.state.recv;
      if (!recv) { GP.toast('generate your stealth keys first (step 2)'); return; }
      showQr(recv.stealth, 'your current one-time receiving address');
      return;
    }
    if (act === 'ens') { publishEns(); return; }
  });

  // live totals in the new-invoice form + ENS link preview
  root.addEventListener('input', e => {
    if (e.target.closest('#gpinv-f-items') || e.target.id === 'gpinv-f-token') refreshFormTotals();
    if (e.target.id === 'gpinv-ensname') {
      const n = e.target.value.trim().toLowerCase();
      const link = $('gpinv-enslink');
      if (link) {
        link.href = n ? 'https://app.ens.domains/' + encodeURIComponent(n) : 'https://app.ens.domains';
        link.textContent = n ? 'open ' + n + ' in app.ens.domains' : 'open app.ens.domains';
      }
    }
  });
  root.addEventListener('change', e => {
    if (e.target.id === 'gpinv-f-token') refreshFormTotals();
  });

  function showQr(text, caption) {
    drawQr($('gpinv-qr'), text).then(
      () => { $('gpinv-qr-cap').textContent = caption; $('gpinv-qrwrap').style.display = 'block'; },
      () => GP.toast('QR failed: content too long')
    );
  }

  // create: same link shape as before (self-contained hash params, pinned one-time
  // stealth address), now with number, client, itemized total and DRAFT status.
  function createInvoice() {
    const st = m => { $('gpinv-f-st').textContent = m; };
    if (!GP.state.unlocked || !GP.state.meta) { st('generate your stealth keys first (step 2).'); return; }
    const rows = readForm().filter(r => (parseFloat(r.qty) || 0) > 0 && (parseFloat(r.unitPrice) || 0) > 0);
    if (!rows.length) { st('add at least one line item with qty and unit price.'); return; }
    const token = $('gpinv-f-token').value;
    const note = $('gpinv-f-note').value.trim();
    const days = parseFloat($('gpinv-f-exp').value);
    const clientId = $('gpinv-f-client').value || null;
    const client = clientId ? loadClients().find(c => c.id === clientId) : null;
    const t = computeTotals(rows, loadProfile().taxPct);
    const profile = loadProfile();
    const a = allocateNumber(profile);
    profile.next = a.next;
    saveProfile(profile);
    const d = C.derive(GP.state.meta.slice(7));
    const id = 'inv-' + Date.now().toString(36) + '-' + Math.floor(Math.random() * 46656).toString(36);
    const expiry = Number.isFinite(days) && days > 0 ? Date.now() + Math.round(days * 86400000) : null;
    const items = rows.map(r => ({ description: r.description || 'item', qty: parseFloat(r.qty), unitPrice: parseFloat(r.unitPrice) }));
    const amount = fmtAmt(t.total, token);
    // links point at the homepage: the payer lands on the pay panel, not the app
    const url = location.origin + '/#' + GP.state.meta
      + '?pay=' + encodeURIComponent(amount + ' ' + token + (note ? ' · ' + note : ''))
      + '&inv=' + id + '&num=' + encodeURIComponent(a.number)
      + (expiry ? '&exp=' + expiry : '')
      + '&st=' + d.stealth + '&eph=' + d.ephPub + '&vt=' + d.viewTag;
    const all = loadInv();
    all.push({
      v: 2, id, number: a.number,
      clientId, clientName: client ? client.name : '',
      items, token, subtotal: t.subtotal, taxPct: t.taxPct, taxAmount: t.taxAmount, total: t.total,
      note, stealthAddress: d.stealth, created: Date.now(), url, expiry,
      status: 'DRAFT', sentAt: null, paidAt: null, paidTx: null,
    });
    saveInv(all);
    showForm = false;
    formRows = [{ description: '', qty: 1, unitPrice: '' }];
    openInv = id; qrFor = id;
    render();
    GP.toast('invoice ' + a.number + ' created: one fresh stealth address, link is self-contained');
  }

  function duplicateInvoice(rec) {
    if (!GP.state.unlocked || !GP.state.meta) { GP.toast('generate your stealth keys first (step 2)'); return; }
    const profile = loadProfile();
    const a = allocateNumber(profile);
    profile.next = a.next;
    saveProfile(profile);
    const d = C.derive(GP.state.meta.slice(7));
    const id = 'inv-' + Date.now().toString(36) + '-' + Math.floor(Math.random() * 46656).toString(36);
    const amount = fmtAmt(rec.total, rec.token);
    // links point at the homepage: the payer lands on the pay panel, not the app
    const url = location.origin + '/#' + GP.state.meta
      + '?pay=' + encodeURIComponent(amount + ' ' + rec.token + (rec.note ? ' · ' + rec.note : ''))
      + '&inv=' + id + '&num=' + encodeURIComponent(a.number)
      + (rec.expiry && rec.expiry > Date.now() ? '&exp=' + rec.expiry : '')
      + '&st=' + d.stealth + '&eph=' + d.ephPub + '&vt=' + d.viewTag;
    const all = loadInv();
    all.push({
      ...rec, id, number: a.number,
      items: rec.items.map(it => ({ ...it })),
      stealthAddress: d.stealth, created: Date.now(), url,
      status: 'DRAFT', sentAt: null, paidAt: null, paidTx: null,
    });
    saveInv(all);
    openInv = id; qrFor = null;
    render();
    GP.toast('duplicated as ' + a.number + ' (fresh stealth address)');
  }

  // ── print / pdf: a real invoice document, monochrome, window.print() ──
  async function printInvoice(i) {
    let qr;
    try { qr = await qrDataUrl(i.url); } catch { GP.toast('QR failed: content too long'); return; }
    const w = window.open('', '_blank', 'width=640,height=860');
    if (!w) { GP.toast('popup blocked: allow popups to print invoices'); return; }
    const p = loadProfile();
    const st = invStatus(i);
    const memo = memos[(i.stealthAddress || '').toLowerCase()] || '';
    const rows = i.items.map(it =>
      '<tr><td>' + escHtml(it.description || 'item') + '</td>'
      + '<td class="r">' + escHtml(it.qty) + '</td>'
      + '<td class="r">' + fmtAmt(it.unitPrice, i.token) + '</td>'
      + '<td class="r">' + fmtAmt((parseFloat(it.qty) || 0) * (parseFloat(it.unitPrice) || 0), i.token) + '</td></tr>'
    ).join('');
    w.document.write('<!DOCTYPE html><html><head><meta charset="utf-8"><title>invoice ' + escHtml(i.number) + '</title>'
      + '<style>body{font-family:\'IBM Plex Mono\',monospace;background:#fff;color:#000;padding:40px;font-size:12px;line-height:1.6;max-width:640px;margin:0 auto}'
      + '.top{display:flex;justify-content:space-between;align-items:flex-start;border-bottom:2px solid #000;padding-bottom:20px}'
      + '.mg{width:52px;height:52px;border:2px solid #000;display:flex;align-items:center;justify-content:center;font-size:18px;font-weight:700;letter-spacing:.1em}'
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
      + (p.contact ? '<div class="muted">' + escHtml(p.contact) + '</div>' : '') + '</div>'
      + '<div><h1>INVOICE</h1><div class="num"><b>' + escHtml(i.number) + '</b></div>'
      + '<div class="num">date: ' + fmtDate(i.created) + '</div>'
      + (i.expiry ? '<div class="num">due: ' + fmtDate(i.expiry) + '</div>' : '') + '</div></div>'
      + (i.clientName ? '<div style="margin-top:20px"><div class="muted">BILL TO</div><b>' + escHtml(i.clientName) + '</b></div>' : '')
      + '<table><thead><tr><th style="width:50%">DESCRIPTION</th><th class="r">QTY</th><th class="r">UNIT PRICE</th><th class="r">AMOUNT</th></tr></thead>'
      + '<tbody>' + rows + '</tbody></table>'
      + '<div class="tot"><div>subtotal · ' + fmtAmt(i.subtotal, i.token) + ' ' + i.token + '</div>'
      + (i.taxPct ? '<div>tax ' + i.taxPct + '% · ' + fmtAmt(i.taxAmount, i.token) + ' ' + i.token + '</div>' : '')
      + '<div class="grand">total · ' + fmtAmt(i.total, i.token) + ' ' + i.token + '</div></div>'
      + (st === 'PAID' ? '<div style="text-align:right"><span class="stamp">PAID</span></div>' : '')
      + '<div class="pay"><img src="' + qr + '" alt="payment QR"><div>'
      + '<div class="muted">PAY THIS ONE-TIME STEALTH ADDRESS</div>'
      + '<div class="addr"><b>' + escHtml(i.stealthAddress) + '</b></div>'
      + '<div class="addr" style="color:#555">' + escHtml(i.url) + '</div></div></div>'
      + (i.note ? '<div class="foot">note: ' + escHtml(i.note) + '</div>' : '')
      + (memo ? '<div class="foot">payment memo: ' + escHtml(memo) + '</div>' : '')
      + (p.terms ? '<div class="foot">terms: ' + escHtml(p.terms) + '</div>' : '')
      + '</body></html>');
    w.document.close();
    w.focus();
    w.print();
  }

  // ── payment reconciliation: PAID arrives via GP events matching the pinned address ──
  function markPaid(p) {
    const all = loadInv();
    const hit = all.find(i => i.stealthAddress && i.stealthAddress.toLowerCase() === p.address.toLowerCase());
    if (hit && hit.status !== 'PAID') {
      hit.status = 'PAID';
      hit.paidAt = Date.now();
      hit.paidTx = p.tx || null;
      saveInv(all);
      render();
      GP.toast('invoice paid: ' + hit.number + ' · ' + fmtAmt(hit.total, hit.token) + ' ' + hit.token);
    }
  }
  function reconcile() {
    if (!GP.state.unlocked) return;
    for (const p of GP.state.payments) markPaid(p);
    render();
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
        render();
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

  render();
  reconcile();

  GP.on('payment', p => { markPaid(p); attachMemo(p); });
  GP.on('session', () => reconcile());
}

// ── CSV export: payments + invoices ──
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

function boot() {
  if (!GP) return;
  if (document.getElementById('gpinv-root')) initSuite();
  enhancePayghost();
}
if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
}
