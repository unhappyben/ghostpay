// gp-reports.mjs · GHOSTPAY dashboard, reports and print documents (docs/GP-API.md).
// Renders into #tab-dashboard / #tab-reports on invoices.html (the shell's gp-tabpane
// mounts) over the schema v3 localStorage registries (gp-profile, gp-clients, gp-items,
// gp-invoices, gp-estimates). Storage is read-only here: status changes belong to
// gp-invoices.mjs, this module only derives them. Markup builds on the gp-ui.css
// primitives; the extra scoped styles live in frag-reports.html and are self-injected
// when that fragment was not pasted into the page. Also installs window.GPINVPrint,
// the print-document builder gp-invoices.mjs defers to when present. Pure helpers are
// exported so a node smoke test can exercise aging buckets, sales-by-month and
// PARTIAL/OVERDUE derivation without a DOM.

const GP = typeof window !== 'undefined' ? window.GP || null : null;

// ── schema v3 registries (read-only in this module) ──
const INV_KEY = 'gp-invoices';
const EST_KEY = 'gp-estimates';
const PROFILE_KEY = 'gp-profile';
const CLIENTS_KEY = 'gp-clients';

export const DEFAULT_PROFILE_V3 = {
  name: '', contact: '', addressLines: [], token: 'USDC', prefix: 'GP-', next: 1,
  terms: 'payment due on receipt', taxPct: null, accentColor: '', footerNote: '',
};

const lsGet = (k, d) => {
  if (typeof localStorage === 'undefined') return d;
  try { return JSON.parse(localStorage.getItem(k)) ?? d; } catch { return d; }
};
const loadProfile = () => ({ ...DEFAULT_PROFILE_V3, ...lsGet(PROFILE_KEY, {}) });
const loadClients = () => lsGet(CLIENTS_KEY, []);
const loadRecords = kind => (lsGet(kind === 'estimate' ? EST_KEY : INV_KEY, []) || []).filter(r => r && typeof r === 'object');

// ── formatting ──
export const fmtAmt = (n, token) => token === 'ETH'
  ? String(parseFloat(Number(n).toFixed(6)))
  : Number(n).toFixed(2);
const fmtUsd = (amount, token, ethPrice) => {
  const v = token === 'USDC' ? Number(amount) : (ethPrice == null ? null : Number(amount) * ethPrice);
  if (v == null || !Number.isFinite(v)) return null;
  return '$' + v.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
};
export const fmtDate = ts => new Date(ts).toISOString().slice(0, 10);
export const escHtml = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
export const monogram = name => {
  const w = (name || '').trim().split(/\s+/).filter(Boolean);
  return (w.length ? w.slice(0, 2).map(x => x[0]).join('') : 'GP').toUpperCase();
};
export const monthKey = ts => {
  const d = new Date(ts);
  return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0');
};

// ── derived statuses (schema v3 contract, compute identically everywhere) ──

// Amount paid towards a record. rec.paidAmount (maintained by gp-invoices.mjs off GP
// payment events) is authoritative; matched payment count is the fallback for records
// that predate the field. Payment records themselves carry no amount.
export function paidSum(rec, matched = []) {
  if (Number.isFinite(rec.paidAmount)) return rec.paidAmount;
  return matched.length;
}

// PAID (stored, terminal) → derived PAID (paid in full) → PARTIAL (some payment, not
// full) → OVERDUE (SENT past expiry) → stored status.
export function derivedStatus(rec, now = Date.now(), matched = []) {
  if (rec.status === 'PAID') return 'PAID';
  const total = Number(rec.total) || 0;
  const paid = paidSum(rec, matched);
  if (total > 0 && paid >= total) return 'PAID';
  if (paid > 0) return 'PARTIAL';
  if ((rec.status || 'SENT') === 'SENT' && rec.expiry && now > rec.expiry) return 'OVERDUE';
  return rec.status || 'SENT';
}

const isUnpaid = st => st === 'SENT' || st === 'OVERDUE' || st === 'PARTIAL';

// Whole days past expiry: 0 while current, at least 1 the moment expiry passes.
export function daysOverdue(rec, now = Date.now()) {
  if (!rec.expiry || now <= rec.expiry) return 0;
  return Math.max(1, Math.ceil((now - rec.expiry) / 86400000));
}

// Aging buckets for unpaid SENT invoices by days past expiry.
export function agingBuckets(records, now = Date.now(), matchedFor = () => []) {
  const buckets = { current: [], d1_7: [], d8_30: [], d30p: [] };
  for (const rec of records || []) {
    const st = derivedStatus(rec, now, matchedFor(rec));
    if (!isUnpaid(st)) continue;
    const d = daysOverdue(rec, now);
    if (d <= 0) buckets.current.push(rec);
    else if (d <= 7) buckets.d1_7.push(rec);
    else if (d <= 30) buckets.d8_30.push(rec);
    else buckets.d30p.push(rec);
  }
  return buckets;
}

// ── reports (pure: dates are ms timestamps, to is inclusive end-of-day) ──
export function inRange(ts, from, to) {
  if (!Number.isFinite(ts)) return false;
  if (Number.isFinite(from) && ts < from) return false;
  if (Number.isFinite(to) && ts > to) return false;
  return true;
}

const addMoney = (map, token, amt) => {
  const t = token === 'ETH' ? 'ETH' : 'USDC';
  map[t] = (map[t] || 0) + (Number(amt) || 0);
};
const addRec = (map, rec, amt) => addMoney(map, rec.token, amt == null ? rec.total : amt);

// (a) sales by client: invoiced (created in range, drafts excluded: not sales yet),
// paid (paid in range), outstanding (unpaid right now, created in range).
// PARTIAL outstanding counts the remainder only.
export function salesByClient(records, clients = [], from, to, now = Date.now(), matchedFor = () => []) {
  const rows = new Map();
  const nameOf = id => { const c = (clients || []).find(x => x.id === id); return c ? c.name : ''; };
  for (const rec of records || []) {
    const key = rec.clientId || '';
    if (!rows.has(key)) rows.set(key, { clientId: key, name: rec.clientName || nameOf(rec.clientId) || '', invoiced: {}, paid: {}, outstanding: {} });
    const row = rows.get(key);
    const st = derivedStatus(rec, now, matchedFor(rec));
    if (st !== 'DRAFT' && inRange(rec.created, from, to)) {
      addRec(row.invoiced, rec);
      if (isUnpaid(st)) {
        const remaining = Math.max(0, (Number(rec.total) || 0) - paidSum(rec, matchedFor(rec)));
        addRec(row.outstanding, rec, remaining);
      }
    }
    if (st === 'PAID' && inRange(rec.paidAt || rec.created, from, to)) addRec(row.paid, rec);
  }
  return [...rows.values()].filter(r => Object.keys(r.invoiced).length || Object.keys(r.paid).length || Object.keys(r.outstanding).length)
    .sort((a, b) => (a.name || '·').localeCompare(b.name || '·'));
}

// (b) sales by month: one row per month intersecting [from, to], latest 12 max.
// Invoiced by created month (drafts excluded), paid by paidAt month (created when
// paidAt is missing).
export function salesByMonth(records, from, to, now = Date.now(), matchedFor = () => []) {
  const start = new Date(from), end = new Date(to);
  const rows = [];
  let y = start.getFullYear(), m = start.getMonth();
  while (y < end.getFullYear() || (y === end.getFullYear() && m <= end.getMonth())) {
    rows.push({ month: y + '-' + String(m + 1).padStart(2, '0'), invoiced: {}, paid: {} });
    if (++m > 11) { m = 0; y++; }
  }
  const idx = new Map(rows.map((r, i) => [r.month, i]));
  for (const rec of records || []) {
    const st = derivedStatus(rec, now, matchedFor(rec));
    if (st !== 'DRAFT') { // drafts are not sales yet
      const ik = idx.get(monthKey(rec.created));
      if (ik != null && inRange(rec.created, from, to)) addRec(rows[ik].invoiced, rec);
    }
    if (derivedStatus(rec, now, matchedFor(rec)) === 'PAID') {
      const pts = rec.paidAt || rec.created;
      const pk = idx.get(monthKey(pts));
      if (pk != null && inRange(pts, from, to)) addRec(rows[pk].paid, rec);
    }
  }
  return rows.slice(-12);
}

// (c) aging detail: every unpaid SENT invoice with days overdue, worst first.
export function agingDetail(records, from, to, now = Date.now(), matchedFor = () => []) {
  return (records || [])
    .filter(rec => isUnpaid(derivedStatus(rec, now, matchedFor(rec))) && inRange(rec.created, from, to))
    .map(rec => ({ rec, status: derivedStatus(rec, now, matchedFor(rec)), days: daysOverdue(rec, now) }))
    .sort((a, b) => b.days - a.days || b.rec.created - a.rec.created);
}

// ── everything below runs only in the browser with window.GP present ──

// qrcode-generator: same lazy esm.sh import gp-invoices.mjs uses, so this file stays
// importable under plain node (no DOM, no network) for the smoke test.
let qrLib = null;
async function getQr() {
  qrLib ??= (await import('https://esm.sh/qrcode-generator@1.4.4')).default;
  return qrLib;
}
async function qrDataUrl(text) {
  const qrcode = await getQr();
  const qr = qrcode(0, 'M');
  qr.addData(text);
  qr.make();
  const n = qr.getModuleCount(), scale = 4;
  const cv = document.createElement('canvas');
  cv.width = cv.height = n * scale;
  const ctx = cv.getContext('2d');
  ctx.fillStyle = '#fff';
  ctx.fillRect(0, 0, cv.width, cv.height);
  ctx.fillStyle = '#000';
  for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) if (qr.isDark(r, c)) ctx.fillRect(c * scale, r * scale, scale, scale);
  return cv.toDataURL('image/png');
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

// payments grouped by lowercase stealth address, for status derivation
function paymentMap() {
  const m = new Map();
  for (const p of (GP && GP.state.payments) || []) {
    const k = (p.address || '').toLowerCase();
    if (!k) continue;
    if (!m.has(k)) m.set(k, []);
    m.get(k).push(p);
  }
  return m;
}

function accentOf(p) {
  const a = String(p.accentColor || '').trim();
  return /^#[0-9a-fA-F]{3}([0-9a-fA-F]{3})?$/.test(a) ? a : '#000';
}

// ── print document: invoice + estimate, Zoho-clean, monochrome with the profile
// accent only in the header bar. Installed as window.GPINVPrint; gp-invoices.mjs
// defers to it from its own printInvoice when present.
async function printDocument(rec) {
  const p = loadProfile();
  const kind = rec.kind === 'estimate' ? 'estimate' : 'invoice';
  const title = kind === 'estimate' ? 'ESTIMATE' : 'INVOICE';
  const accent = accentOf(p);
  const map = paymentMap();
  const matched = map.get((rec.stealthAddress || '').toLowerCase()) || [];
  const st = derivedStatus(rec, Date.now(), matched);
  const watermark = st === 'PAID' ? 'PAID' : (st === 'OVERDUE' ? 'OVERDUE' : '');
  const client = rec.clientId ? loadClients().find(c => c.id === rec.clientId) : null;

  let qr = null;
  if (kind === 'invoice' && rec.url) {
    try { qr = await qrDataUrl(rec.url); } catch { /* QR optional: print without it */ }
  }
  const px = await ethUsd();
  const totalUsd = fmtUsd(rec.total, rec.token, px);

  const w = window.open('', '_blank', 'width=680,height=900');
  if (!w) { GP.toast('popup blocked: allow popups to print'); return; }

  const addressLines = Array.isArray(p.addressLines) ? p.addressLines.filter(Boolean) : [];
  const rows = (rec.items || []).map(it =>
    '<tr><td>' + escHtml(it.description || 'item') + '</td>'
    + '<td class="r">' + escHtml(it.qty) + '</td>'
    + '<td class="r">' + fmtAmt(it.unitPrice, rec.token) + '</td>'
    + '<td class="r">' + fmtAmt((parseFloat(it.qty) || 0) * (parseFloat(it.unitPrice) || 0), rec.token) + '</td></tr>'
  ).join('');
  const discount = Number(rec.discountAmount) || 0;
  const tax = Number(rec.taxAmount) || 0;

  w.document.write('<!DOCTYPE html><html><head><meta charset="utf-8"><title>' + kind + ' ' + escHtml(rec.number || '') + '</title>'
    + '<style>'
    + 'body{font-family:\'IBM Plex Mono\',monospace;background:#fff;color:#000;padding:0 0 40px;font-size:12px;line-height:1.6;max-width:660px;margin:0 auto}'
    + '.bar{height:8px;background:' + accent + '}'
    + '.inner{padding:28px 40px 0}'
    + '.top{display:flex;justify-content:space-between;align-items:flex-start;border-bottom:2px solid #000;padding-bottom:20px}'
    + '.mg{width:52px;height:52px;border:2px solid #000;display:flex;align-items:center;justify-content:center;font-size:18px;font-weight:700;letter-spacing:.1em}'
    + '.biz{font-size:15px;font-weight:700;margin-top:10px}.muted{color:#555;font-size:10px;letter-spacing:.15em}'
    + '.addrline{color:#333;font-size:11px}'
    + 'h1{font-size:22px;letter-spacing:.15em;margin:0;text-align:right}.num{text-align:right;font-size:12px;margin-top:4px}'
    + 'table{width:100%;border-collapse:collapse;margin-top:22px}th{font-size:10px;letter-spacing:.2em;color:#555;text-align:left;font-weight:400;border-bottom:1px solid #000;padding:6px 0}'
    + 'td{padding:8px 0;border-bottom:1px solid #ccc;vertical-align:top}.r{text-align:right;white-space:nowrap}'
    + '.tot{margin-top:14px;text-align:right}.tot div{margin:2px 0}.grand{font-size:18px;font-weight:700;border-top:2px solid #000;padding-top:8px;margin-top:8px}'
    + '.pay{margin-top:26px;border:1px solid #000;padding:16px;display:flex;gap:18px;align-items:center}'
    + '.pay img{image-rendering:pixelated;width:150px;flex:none}.payaddr{word-break:break-all;font-size:11px;margin-top:6px}'
    + '.foot{margin-top:22px;border-top:1px solid #000;padding-top:12px;font-size:11px;color:#333}'
    + '.wm{position:fixed;top:42%;left:50%;transform:translate(-50%,-50%) rotate(-18deg);font-size:92px;font-weight:700;letter-spacing:.2em;color:rgba(0,0,0,.07);border:8px solid rgba(0,0,0,.09);padding:6px 34px;white-space:nowrap}'
    + '@media print{.bar{-webkit-print-color-adjust:exact;print-color-adjust:exact}}'
    + '</style></head><body>'
    + '<div class="bar"></div>'
    + (watermark ? '<div class="wm">' + watermark + '</div>' : '')
    + '<div class="inner">'
    + '<div class="top"><div><div class="mg">' + escHtml(monogram(p.name)) + '</div>'
    + '<div class="biz">' + escHtml(p.name || 'GHOSTPAY') + '</div>'
    + (p.contact ? '<div class="muted">' + escHtml(p.contact) + '</div>' : '')
    + addressLines.map(l => '<div class="addrline">' + escHtml(l) + '</div>').join('')
    + '</div>'
    + '<div><h1>' + title + '</h1><div class="num"><b>' + escHtml(rec.number || '') + '</b></div>'
    + '<div class="num">date: ' + fmtDate(rec.created) + '</div>'
    + (rec.expiry ? '<div class="num">' + (kind === 'estimate' ? 'valid until' : 'due') + ': ' + fmtDate(rec.expiry) + '</div>' : '')
    + '</div></div>'
    + (rec.clientName || client
      ? '<div style="margin-top:20px"><div class="muted">BILL TO</div><b>' + escHtml(rec.clientName || (client && client.name) || '') + '</b>'
        + (client && client.contact ? '<div class="addrline">' + escHtml(client.contact) + '</div>' : '')
        + '</div>'
      : '')
    + '<table><thead><tr><th style="width:50%">DESCRIPTION</th><th class="r">QTY</th><th class="r">UNIT PRICE</th><th class="r">AMOUNT</th></tr></thead>'
    + '<tbody>' + rows + '</tbody></table>'
    + '<div class="tot"><div>subtotal · ' + fmtAmt(rec.subtotal, rec.token) + ' ' + rec.token + '</div>'
    + (discount > 0 ? '<div>discount' + (rec.discountPct ? ' ' + rec.discountPct + '%' : '') + ' · -' + fmtAmt(discount, rec.token) + ' ' + rec.token + '</div>' : '')
    + (tax > 0 ? '<div>tax' + (rec.taxPct ? ' ' + rec.taxPct + '%' : '') + ' · ' + fmtAmt(tax, rec.token) + ' ' + rec.token + '</div>' : '')
    + '<div class="grand">total · ' + fmtAmt(rec.total, rec.token) + ' ' + rec.token + '</div>'
    + (totalUsd ? '<div class="muted" style="margin-top:2px">≈ ' + totalUsd + ' usd</div>' : '')
    + '</div>'
    + (kind === 'invoice' && rec.stealthAddress
      ? '<div class="pay">' + (qr ? '<img src="' + qr + '" alt="payment QR">' : '') + '<div>'
        + '<div class="muted">PAY THIS ONE-TIME STEALTH ADDRESS</div>'
        + '<div class="payaddr"><b>' + escHtml(rec.stealthAddress) + '</b></div>'
        + (rec.url ? '<div class="payaddr" style="color:#555">' + escHtml(rec.url) + '</div>' : '')
        + '</div></div>'
      : '')
    + (kind === 'estimate' ? '<div class="foot">this is an estimate, not a payment request.</div>' : '')
    + (rec.note ? '<div class="foot">note: ' + escHtml(rec.note) + '</div>' : '')
    + (p.terms ? '<div class="foot">terms: ' + escHtml(p.terms) + '</div>' : '')
    + (p.footerNote ? '<div class="foot">' + escHtml(p.footerNote) + '</div>' : '')
    + '</div></body></html>');
  w.document.close();
  w.focus();
  w.print();
}

// ── dashboard + reports UI ──
function init(dashMount, repsMount) {
  const root = document.getElementById('gp-invoices') || dashMount.parentNode;
  const dashView = dashMount ? (document.getElementById('gpr-dash-view') || dashMount) : null;
  const repsView = repsMount ? (document.getElementById('gpr-reports-view') || repsMount) : null;

  const pill = st => '<span class="gp-pill' + (st === 'DRAFT' || st === 'OVERDUE' ? ' dim' : '') + '">' + st + '</span>';
  const moneyLines = (m, big) => {
    const keys = Object.keys(m);
    if (!keys.length) return '<div class="' + (big ? 'gpr-big' : '') + '">0</div>';
    return keys.sort().map(t =>
      '<div class="' + (big ? 'gpr-big' : '') + '">' + fmtAmt(m[t], t) + ' <span class="gpr-unit">' + t + '</span></div>'
      + '<div class="status" style="margin-top:2px" data-usd data-amt="' + m[t] + '" data-token="' + t + '"></div>'
    ).join('');
  };
  const moneyCell = m => {
    const keys = Object.keys(m);
    return keys.length ? keys.sort().map(t => fmtAmt(m[t], t) + ' ' + t).join('<br>') : '<span class="gp-muted">·</span>';
  };

  // fills every [data-usd] placeholder once a price is available
  function fillUsd(view) {
    const els = [...view.querySelectorAll('[data-usd]')];
    if (!els.length) return;
    const paint = px => els.forEach(el => {
      const u = fmtUsd(el.dataset.amt, el.dataset.token, px);
      if (u && el.isConnected) el.textContent = '≈ ' + u + ' usd';
    });
    paint(GP.state.ethPriceUsd);
    ethUsd().then(paint);
  }

  // ── DASHBOARD ──
  function renderDashboard() {
    if (!dashView) return;
    const inv = loadRecords('invoice');
    const now = Date.now();
    const map = paymentMap();
    const mf = rec => map.get((rec.stealthAddress || '').toLowerCase()) || [];
    const month = monthKey(now);

    const outstanding = {}, overdue = {}, paidMonth = {};
    let drafts = 0;
    for (const rec of inv) {
      const st = derivedStatus(rec, now, mf(rec));
      if (st === 'DRAFT') { drafts++; continue; }
      if (st === 'OVERDUE') { addRec(overdue, rec); addRec(outstanding, rec); }
      else if (st === 'SENT' || st === 'PARTIAL') addRec(outstanding, rec);
      else if (st === 'PAID' && monthKey(rec.paidAt || rec.created) === month) addRec(paidMonth, rec);
    }

    const buckets = agingBuckets(inv, now, mf);
    const bucketDefs = [
      ['CURRENT', buckets.current], ['1-7 DAYS', buckets.d1_7], ['8-30 DAYS', buckets.d8_30], ['>30 DAYS', buckets.d30p],
    ];
    const maxCount = Math.max(1, ...bucketDefs.map(([, rs]) => rs.length));
    const bucketRows = bucketDefs.map(([lbl, rs], i) => {
      const m = {};
      for (const r of rs) addRec(m, r);
      const val = Object.keys(m).length ? Object.keys(m).sort().map(t => fmtAmt(m[t], t) + ' ' + t).join(' · ') : '·';
      return '<div class="gpr-barrow"><span class="gpr-barlbl">' + lbl + '</span>'
        + '<div class="gpr-bar"><div class="gpr-barfill' + (i ? ' dim' : '') + '" style="width:' + Math.round(rs.length / maxCount * 100) + '%"></div></div>'
        + '<span class="gpr-barval">' + rs.length + ' · ' + val + '</span></div>';
    }).join('');

    // recent activity: created / sent / paid events + payments seen onchain this session
    const ev = [];
    for (const rec of inv) {
      ev.push({ ts: rec.created, text: rec.number + ' created · ' + fmtAmt(rec.total, rec.token) + ' ' + rec.token + (rec.clientName ? ' · ' + rec.clientName : '') });
      if (rec.sentAt) ev.push({ ts: rec.sentAt, text: rec.number + ' marked sent' });
      if (rec.paidAt) ev.push({ ts: rec.paidAt, text: rec.number + ' paid' });
    }
    ev.sort((a, b) => b.ts - a.ts);
    const sessionEv = [];
    for (const rec of inv) {
      for (const p of mf(rec)) {
        sessionEv.push({ text: rec.number + ' payment seen onchain · block ' + p.block + (p.swept ? ' · swept' : '') });
      }
    }
    const recent = ev.slice(0, 8);
    const activityHtml = (recent.length || sessionEv.length)
      ? '<div class="gp-tablewrap"><table class="gp-table"><tbody>'
        + recent.map(e => '<tr><td class="gp-muted" style="white-space:nowrap">' + fmtDate(e.ts) + '</td><td>' + escHtml(e.text) + '</td></tr>').join('')
        + sessionEv.slice(0, 4).map(e => '<tr><td class="gp-muted" style="white-space:nowrap">session</td><td>' + escHtml(e.text) + '</td></tr>').join('')
        + '</tbody></table></div>'
      : '<div class="gpr-empty">nothing yet: create an invoice in the INVOICES tab and it shows up here.</div>';

    dashView.innerHTML =
      '<div class="gpr-cards">'
      + '<div class="gp-card gpr-stat"><div class="gp-label">TOTAL OUTSTANDING</div>' + moneyLines(outstanding, true) + '</div>'
      + '<div class="gp-card gpr-stat"><div class="gp-label">OVERDUE</div>' + moneyLines(overdue, true) + '</div>'
      + '<div class="gp-card gpr-stat"><div class="gp-label">PAID THIS MONTH</div>' + moneyLines(paidMonth, true) + '</div>'
      + '<div class="gp-card gpr-stat"><div class="gp-label">DRAFTS</div><div class="gpr-big">' + drafts + '</div></div>'
      + '</div>'
      + '<div class="gpr-section">AGING · UNPAID SENT INVOICES</div>'
      + '<div class="gp-card" style="margin-top:0">' + (bucketRows || '') + '</div>'
      + '<div class="gpr-split">'
      + '<div><div class="gpr-section" style="margin-top:0">RECENT ACTIVITY</div>' + activityHtml + '</div>'
      + '<div><div class="gpr-section" style="margin-top:0">TOP CLIENTS</div><div id="gpr-topclients"><div class="status">ranking by invoiced total…</div></div></div>'
      + '</div>';
    fillUsd(dashView);
    renderTopClients(inv);
  }

  // top clients by invoiced total, ranked in USD once the price resolves
  async function renderTopClients(inv) {
    const el = document.getElementById('gpr-topclients');
    if (!el) return;
    const px = await ethUsd();
    if (!el.isConnected) return;
    const now = Date.now();
    const map = paymentMap();
    const mf = rec => map.get((rec.stealthAddress || '').toLowerCase()) || [];
    const byClient = new Map();
    for (const rec of inv) {
      if (derivedStatus(rec, now, mf(rec)) === 'DRAFT') continue;
      const name = rec.clientName || '(no client)';
      if (!byClient.has(name)) byClient.set(name, { name, totals: {}, usd: 0 });
      const row = byClient.get(name);
      addRec(row.totals, rec);
      row.usd += rec.token === 'USDC' ? (Number(rec.total) || 0) : (px != null ? (Number(rec.total) || 0) * px : 0);
    }
    const rows = [...byClient.values()].sort((a, b) => b.usd - a.usd).slice(0, 5);
    el.innerHTML = rows.length
      ? '<div class="gp-tablewrap"><table class="gp-table"><tbody>' + rows.map((r, i) =>
          '<tr><td class="gp-muted" style="width:1%">' + (i + 1) + '</td><td><b>' + escHtml(r.name) + '</b></td>'
          + '<td style="text-align:right;white-space:nowrap">' + moneyCell(r.totals) + '</td></tr>'
        ).join('') + '</tbody></table></div>'
        + (px == null ? '<div class="status">usd ranking unavailable: relayer price feed offline, order is approximate.</div>' : '')
      : '<div class="gpr-empty">no invoiced clients yet.</div>';
  }

  // ── REPORTS ──
  const monthStart = () => {
    const d = new Date();
    return { from: new Date(d.getFullYear(), d.getMonth(), 1).getTime(), to: Date.now() };
  };
  const ranges = { client: monthStart(), month: monthStart(), aging: monthStart() };
  const dstr = ts => {
    const d = new Date(ts);
    return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
  };
  const parseDate = (v, end) => {
    const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(v || '');
    if (!m) return null;
    const d = new Date(+m[1], +m[2] - 1, +m[3], end ? 23 : 0, end ? 59 : 0, end ? 59 : 0, end ? 999 : 0);
    return d.getTime();
  };
  const REPORTS = [
    { key: 'client', title: 'SALES BY CLIENT' },
    { key: 'month', title: 'SALES BY MONTH' },
    { key: 'aging', title: 'AGING DETAIL' },
  ];

  const rangeHtml = key =>
    '<div class="gpr-range">'
    + '<input type="date" data-gpr-from="' + key + '" value="' + dstr(ranges[key].from) + '">'
    + '<input type="date" data-gpr-to="' + key + '" value="' + dstr(ranges[key].to) + '">'
    + '<button class="ghost" data-gpr="csv" data-report="' + key + '">CSV</button>'
    + '</div>';

  function reportTable(key) {
    const inv = loadRecords('invoice');
    const now = Date.now();
    const map = paymentMap();
    const mf = rec => map.get((rec.stealthAddress || '').toLowerCase()) || [];
    const { from, to } = ranges[key];
    const endOfTo = new Date(new Date(to).setHours(23, 59, 59, 999)).getTime();

    if (key === 'client') {
      const rows = salesByClient(inv, loadClients(), from, endOfTo, now, mf);
      return rows.length
        ? '<div class="gp-tablewrap"><table class="gp-table"><thead><tr>'
          + '<th>CLIENT</th><th style="text-align:right">INVOICED</th><th style="text-align:right">PAID</th><th style="text-align:right">OUTSTANDING</th>'
          + '</tr></thead><tbody>'
          + rows.map(r =>
              '<tr><td><b>' + (r.name ? escHtml(r.name) : '<span class="gp-muted">(no client)</span>') + '</b></td>'
              + '<td style="text-align:right">' + moneyCell(r.invoiced) + '</td>'
              + '<td style="text-align:right">' + moneyCell(r.paid) + '</td>'
              + '<td style="text-align:right">' + moneyCell(r.outstanding) + '</td></tr>'
            ).join('')
          + '</tbody></table></div>'
        : '<div class="gpr-empty">no invoices in this range.</div>';
    }
    if (key === 'month') {
      const rows = salesByMonth(inv, from, endOfTo, now, mf);
      return rows.length
        ? '<div class="gp-tablewrap"><table class="gp-table"><thead><tr>'
          + '<th>MONTH</th><th style="text-align:right">INVOICED</th><th style="text-align:right">PAID</th>'
          + '</tr></thead><tbody>'
          + rows.map(r =>
              '<tr><td><b>' + r.month + '</b></td>'
              + '<td style="text-align:right">' + moneyCell(r.invoiced) + '</td>'
              + '<td style="text-align:right">' + moneyCell(r.paid) + '</td></tr>'
            ).join('')
          + '</tbody></table></div>'
        : '<div class="gpr-empty">no months in this range.</div>';
    }
    const rows = agingDetail(inv, from, endOfTo, now, mf);
    return rows.length
      ? '<div class="gp-tablewrap"><table class="gp-table"><thead><tr>'
        + '<th>NUMBER</th><th>CLIENT</th><th>CREATED</th><th>DUE</th><th style="text-align:right">DAYS OVER</th><th style="text-align:right">TOTAL</th><th style="text-align:right">STATUS</th>'
        + '</tr></thead><tbody>'
        + rows.map(({ rec, status, days }) =>
            '<tr><td><b>' + escHtml(rec.number) + '</b></td>'
            + '<td>' + (rec.clientName ? escHtml(rec.clientName) : '<span class="gp-muted">·</span>') + '</td>'
            + '<td style="white-space:nowrap">' + fmtDate(rec.created) + '</td>'
            + '<td style="white-space:nowrap">' + (rec.expiry ? fmtDate(rec.expiry) : '<span class="gp-muted">never</span>') + '</td>'
            + '<td style="text-align:right">' + (days || '·') + '</td>'
            + '<td style="text-align:right;white-space:nowrap">' + fmtAmt(rec.total, rec.token) + ' ' + rec.token + '</td>'
            + '<td style="text-align:right">' + pill(status) + '</td></tr>'
          ).join('')
        + '</tbody></table></div>'
      : '<div class="gpr-empty">nothing unpaid in this range.</div>';
  }

  function renderReports() {
    if (!repsView) return;
    repsView.innerHTML = REPORTS.map(r =>
      '<div class="gpr-section">' + r.title + '</div>' + rangeHtml(r.key) + '<div data-gpr-table="' + r.key + '">' + reportTable(r.key) + '</div>'
    ).join('');
  }

  // ── CSV export (blob, no deps) ──
  const csvCell = c => '"' + String(c ?? '').replace(/"/g, '""') + '"';
  const toCsv = rows => rows.map(r => r.map(csvCell).join(',')).join('\r\n');
  function exportReport(key) {
    const inv = loadRecords('invoice');
    const now = Date.now();
    const map = paymentMap();
    const mf = rec => map.get((rec.stealthAddress || '').toLowerCase()) || [];
    const { from, to } = ranges[key];
    const endOfTo = new Date(new Date(to).setHours(23, 59, 59, 999)).getTime();
    const stamp = new Date().toISOString().slice(0, 10);
    let rows, name;
    if (key === 'client') {
      name = 'sales-by-client';
      rows = [['client', 'token', 'invoiced', 'paid', 'outstanding']];
      for (const r of salesByClient(inv, loadClients(), from, endOfTo, now, mf)) {
        const tokens = new Set([...Object.keys(r.invoiced), ...Object.keys(r.paid), ...Object.keys(r.outstanding)]);
        for (const t of [...tokens].sort()) {
          rows.push([r.name || '(no client)', t,
            r.invoiced[t] != null ? fmtAmt(r.invoiced[t], t) : '0',
            r.paid[t] != null ? fmtAmt(r.paid[t], t) : '0',
            r.outstanding[t] != null ? fmtAmt(r.outstanding[t], t) : '0']);
        }
      }
    } else if (key === 'month') {
      name = 'sales-by-month';
      rows = [['month', 'token', 'invoiced', 'paid']];
      for (const r of salesByMonth(inv, from, endOfTo, now, mf)) {
        const tokens = new Set([...Object.keys(r.invoiced), ...Object.keys(r.paid)]);
        for (const t of [...tokens].sort()) {
          rows.push([r.month, t,
            r.invoiced[t] != null ? fmtAmt(r.invoiced[t], t) : '0',
            r.paid[t] != null ? fmtAmt(r.paid[t], t) : '0']);
        }
      }
    } else {
      name = 'aging-detail';
      rows = [['number', 'client', 'created', 'due', 'days_overdue', 'status', 'total', 'token']];
      for (const { rec, status, days } of agingDetail(inv, from, endOfTo, now, mf)) {
        rows.push([rec.number, rec.clientName || '', fmtDate(rec.created), rec.expiry ? fmtDate(rec.expiry) : '', days, status, fmtAmt(rec.total, rec.token), rec.token]);
      }
    }
    download('ghostpay-' + name + '-' + stamp + '.csv', toCsv(rows), 'text/csv');
    GP.toast('csv exported: ' + name);
  }

  function renderAll() { renderDashboard(); renderReports(); }

  // one delegated handler on the shared root, namespaced away from gpinv's data-act
  root.addEventListener('click', e => {
    const el = e.target.closest('[data-gpr]');
    if (el && root.contains(el)) {
      if (el.dataset.gpr === 'csv') exportReport(el.dataset.report);
      return;
    }
    // the shell switches tabs by hiding/showing the tab containers: refresh our views
    // whenever a tab button fires so stale numbers never sit on screen
    const tabBtn = e.target.closest('[data-tab]');
    if (tabBtn && root.contains(tabBtn) && /(^|-)(dashboard|reports)$/.test(tabBtn.dataset.tab)) {
      setTimeout(renderAll, 0);
    }
  });
  root.addEventListener('change', e => {
    const f = e.target.closest('[data-gpr-from]'), t = e.target.closest('[data-gpr-to]');
    if (f) { const v = parseDate(f.value, false); if (v != null) ranges[f.dataset.gprFrom].from = v; renderReports(); }
    if (t) { const v = parseDate(t.value, true); if (v != null) ranges[t.dataset.gprTo].to = v; renderReports(); }
  });

  renderAll();

  // payments and session changes move statuses: re-derive everything
  GP.on('payment', renderAll);
  GP.on('swept', renderAll);
  GP.on('session', renderAll);
}

// Scoped styles live in frag-reports.html (single source of truth). When the fragment
// was not pasted into the page, pull the style block out of it and inject it here;
// if the fetch fails the gp-ui.css primitives still carry the layout.
async function ensureStyles() {
  if (document.getElementById('gpr-styles')) return;
  try {
    const r = await fetch('./frag-reports.html');
    if (!r.ok) return;
    const doc = new DOMParser().parseFromString(await r.text(), 'text/html');
    const st = doc.getElementById('gpr-styles');
    if (st) document.head.appendChild(document.importNode(st, true));
  } catch { /* fragment unreachable: gp-ui.css primitives still apply */ }
}

async function boot() {
  if (!GP) return;
  const dash = document.getElementById('tab-dashboard');
  const reps = document.getElementById('tab-reports');
  if (!dash && !reps) return; // no mounts on this page: stay out of the way
  window.GPINVPrint = rec => printDocument(rec);
  await ensureStyles();
  init(dash, reps);
}
if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
}
