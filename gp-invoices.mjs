// gp-invoices.mjs — GHOSTPAY invoice suite module (docs/GP-API.md).
// Mounts into #gp-invoices via frag-invoices.html, enhances the pay-a-ghost flow with
// encrypted memos, tracks invoice payment status, CSV export, print receipts, ENS publish.
// Pure helpers are exported so a node smoke test can exercise the memo crypto without a DOM.

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

// ── everything below runs only in the browser with window.GP present ──

const INV_KEY = 'gp-invoices';
const MEMO_KEY = 'gp-invoice-memos';
const ENS_PUBLIC_RESOLVER = '0x231b0Ee14048e9dCcD1d247744d114a4EB5E8E63';

const loadInv = () => { try { return JSON.parse(localStorage.getItem(INV_KEY) || '[]'); } catch { return []; } };
const saveInv = inv => { try { localStorage.setItem(INV_KEY, JSON.stringify(inv)); } catch { /* best-effort */ } };
const loadMemos = () => { try { return JSON.parse(localStorage.getItem(MEMO_KEY) || '{}'); } catch { return {}; } };
const saveMemos = m => { try { localStorage.setItem(MEMO_KEY, JSON.stringify(m)); } catch { /* best-effort */ } };
const memos = typeof localStorage !== 'undefined' ? loadMemos() : {};

const invStatus = inv => inv.status === 'PAID' ? 'PAID' : (inv.expiry && Date.now() > inv.expiry ? 'EXPIRED' : 'UNPAID');

// qrcode-generator: same esm.sh import the core uses, loaded lazily so this file stays
// importable under plain node (no DOM, no network) for the crypto smoke test.
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

const escHtml = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// ── invoice registry UI ──
function initSuite() {
  const $ = id => document.getElementById(id);
  const C = GP.crypto;
  const smallBtn = 'flex:1 1 auto;width:auto;padding:10px 14px;font-size:11px';

  function showQr(text, caption) {
    drawQr($('gpinv-qr'), text).then(
      () => { $('gpinv-qr-cap').textContent = caption; $('gpinv-qrwrap').style.display = 'block'; },
      () => GP.toast('QR failed: content too long')
    );
  }

  function renderList() {
    const list = $('gpinv-list');
    list.innerHTML = '';
    const inv = loadInv();
    if (!inv.length) {
      const d = document.createElement('div');
      d.className = 'status';
      d.textContent = 'no tracked invoices yet.';
      list.appendChild(d);
      return;
    }
    for (const item of [...inv].reverse()) {
      const div = document.createElement('div');
      div.style.cssText = 'border:1px solid #333;padding:16px;margin-top:12px';
      if (invStatus(item) === 'PAID') div.style.borderColor = '#fff';
      const head = document.createElement('div');
      head.style.cssText = 'font-weight:700';
      head.textContent = item.amount + ' ' + item.token + ' · ' + invStatus(item);
      const meta = document.createElement('div');
      meta.className = 'status';
      meta.style.marginTop = '4px';
      meta.textContent = item.id + ' · ' + new Date(item.created).toISOString().slice(0, 10)
        + (item.expiry ? ' · expires ' + new Date(item.expiry).toISOString().slice(0, 10) : ' · no expiry');
      const addr = document.createElement('div');
      addr.style.cssText = 'font-size:11px;color:#777;word-break:break-all;margin-top:4px';
      addr.textContent = item.stealthAddress;
      div.append(head, meta, addr);
      if (item.note) {
        const note = document.createElement('div');
        note.className = 'status';
        note.textContent = 'note: ' + item.note;
        div.appendChild(note);
      }
      const memo = memos[item.stealthAddress.toLowerCase()];
      if (memo) {
        const m = document.createElement('div');
        m.className = 'status';
        m.style.color = '#fff';
        m.textContent = 'payment memo: ' + memo;
        div.appendChild(m);
      }
      const row = document.createElement('div');
      row.style.cssText = 'display:flex;gap:8px;margin-top:12px;flex-wrap:wrap';
      const bCopy = document.createElement('button');
      bCopy.className = 'ghost'; bCopy.style.cssText = smallBtn; bCopy.textContent = 'COPY LINK';
      bCopy.onclick = () => copyBtn(item.url, bCopy, 'COPY LINK');
      const bQr = document.createElement('button');
      bQr.className = 'ghost'; bQr.style.cssText = smallBtn; bQr.textContent = 'QR';
      bQr.onclick = () => showQr(item.url, item.id + ' · ' + item.amount + ' ' + item.token);
      const bPrint = document.createElement('button');
      bPrint.className = 'ghost'; bPrint.style.cssText = smallBtn; bPrint.textContent = 'PRINT RECEIPT';
      bPrint.onclick = () => printReceipt(item);
      const bDel = document.createElement('button');
      bDel.className = 'ghost'; bDel.style.cssText = smallBtn; bDel.textContent = 'DELETE';
      bDel.onclick = () => { saveInv(loadInv().filter(x => x.id !== item.id)); renderList(); };
      row.append(bCopy, bQr, bPrint, bDel);
      div.appendChild(row);
      list.appendChild(div);
    }
  }

  // upgraded creation: same link shape as step 3, plus registry entry, pinned one-time
  // stealth address, expiry, and QR. one fresh stealth address per invoice.
  $('gpinv-create').onclick = () => {
    const st = m => { $('gpinv-create-st').textContent = m; };
    if (!GP.state.unlocked || !GP.state.meta) { st('generate your stealth keys first (step 2).'); return; }
    const amt = $('gpinv-amt').value.trim();
    const tok = $('gpinv-token').value;
    const note = $('gpinv-note').value.trim();
    const days = parseFloat($('gpinv-exp').value);
    if (!amt || !(parseFloat(amt) > 0)) { st('enter an amount.'); return; }
    const d = C.derive(GP.state.meta.slice(7));
    const id = 'inv-' + Date.now().toString(36) + '-' + Math.floor(Math.random() * 46656).toString(36);
    const expiry = Number.isFinite(days) && days > 0 ? Date.now() + Math.round(days * 86400000) : null;
    let url = location.origin + location.pathname + '#' + GP.state.meta
      + '?pay=' + encodeURIComponent(amt + ' ' + tok + (note ? ' · ' + note : ''))
      + '&inv=' + id
      + (expiry ? '&exp=' + expiry : '')
      + '&st=' + d.stealth + '&eph=' + d.ephPub + '&vt=' + d.viewTag;
    const inv = loadInv();
    inv.push({ id, amount: amt, token: tok, note, stealthAddress: d.stealth, created: Date.now(), url, status: 'UNPAID', expiry });
    saveInv(inv);
    st('invoice ' + id + ' created. one fresh stealth address, link is self-contained.');
    renderList();
    showQr(url, id + ' · ' + amt + ' ' + tok);
  };

  $('gpinv-recvqr').onclick = () => {
    const recv = GP.state.recv;
    if (!recv) { GP.toast('generate your stealth keys first (step 2)'); return; }
    showQr(recv.stealth, 'your current one-time receiving address');
  };

  $('gpinv-export').onclick = exportCsv;

  $('gpinv-ensname').oninput = e => {
    const n = e.target.value.trim().toLowerCase();
    $('gpinv-enslink').href = n ? 'https://app.ens.domains/' + encodeURIComponent(n) : 'https://app.ens.domains';
    $('gpinv-enslink').textContent = n ? 'open ' + n + ' in app.ens.domains' : 'open app.ens.domains';
  };
  $('gpinv-ens').onclick = publishEns;

  renderList();
  reconcile();

  GP.on('payment', p => { markPaid(p); attachMemo(p); });
  GP.on('session', () => reconcile());

  function markPaid(p) {
    const inv = loadInv();
    const hit = inv.find(i => i.stealthAddress.toLowerCase() === p.address.toLowerCase());
    if (hit && hit.status !== 'PAID') {
      hit.status = 'PAID';
      saveInv(inv);
      renderList();
      GP.toast('invoice paid: ' + hit.id + ' · ' + hit.amount + ' ' + hit.token);
    }
  }
  function reconcile() {
    if (!GP.state.unlocked) return;
    for (const p of GP.state.payments) markPaid(p);
    renderList();
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
        renderList();
        GP.toast('payment memo decrypted: ' + memo.slice(0, 60));
      }
    } catch { /* receipt unavailable or undecryptable: no memo */ } finally {
      memoInFlight.delete(key);
    }
  }

  async function printReceipt(inv) {
    let qr;
    try { qr = await qrDataUrl(inv.url); } catch { GP.toast('QR failed: content too long'); return; }
    const w = window.open('', '_blank', 'width=480,height=720');
    if (!w) { GP.toast('popup blocked: allow popups to print receipts'); return; }
    const memo = memos[inv.stealthAddress.toLowerCase()] || '';
    const row = (l, v) => '<div class="row"><div class="lbl">' + l + '</div>' + escHtml(v) + '</div>';
    w.document.write('<!DOCTYPE html><html><head><meta charset="utf-8"><title>GHOSTPAY receipt ' + escHtml(inv.id) + '</title>'
      + '<style>body{font-family:monospace;background:#fff;color:#000;padding:32px;font-size:13px;line-height:1.5}'
      + 'h1{font-size:15px;letter-spacing:.2em;margin:0 0 18px}.row{margin:10px 0;word-break:break-all}'
      + '.lbl{font-size:10px;letter-spacing:.2em;color:#555}img{image-rendering:pixelated;width:220px;margin:18px 0}</style></head><body>'
      + '<h1>GHOSTPAY · INVOICE RECEIPT</h1>'
      + row('INVOICE', inv.id)
      + row('AMOUNT', inv.amount + ' ' + inv.token)
      + row('STEALTH ADDRESS', inv.stealthAddress)
      + (inv.note ? row('NOTE', inv.note) : '')
      + (memo ? row('PAYMENT MEMO', memo) : '')
      + row('STATUS', invStatus(inv))
      + row('CREATED', new Date(inv.created).toISOString())
      + (inv.expiry ? row('EXPIRES', new Date(inv.expiry).toISOString()) : '')
      + '<img src="' + qr + '" alt="invoice QR">'
      + '<div class="row" style="font-size:10px;color:#555">' + escHtml(inv.url) + '</div>'
      + '</body></html>');
    w.document.close();
    w.focus();
    w.print();
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
}

// ── CSV export: payments + invoices ──
async function exportCsv() {
  const rows = [['date', 'type', 'address', 'amount_eth', 'amount_usd', 'memo_or_note', 'status']];
  const price = GP.state.ethPriceUsd;
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
    rows.push([date, 'payment', p.address, amt, usd, memos[p.address.toLowerCase()] || p.memo || '', p.swept ? 'SWEPT' : 'RECEIVED']);
  }
  for (const inv of loadInv()) {
    const eth = inv.token === 'ETH' ? String(inv.amount) : '';
    const usd = inv.token === 'USDC' ? String(inv.amount) : (eth && price ? (parseFloat(eth) * price).toFixed(2) : '');
    rows.push([new Date(inv.created).toISOString(), 'invoice', inv.stealthAddress, eth, usd, inv.note || '', invStatus(inv)]);
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
  const exp = Number(params.get('exp'));
  const expired = Number.isFinite(exp) && exp > 0 && Date.now() > exp;
  const stInvoice = $('st-invoice');
  if (stInvoice && invId) stInvoice.textContent += ' · invoice ' + invId;
  if (stInvoice && expired) stInvoice.textContent += ' · THIS INVOICE HAS EXPIRED';

  const btn = $('b-announce');
  if (!btn) return;
  const memoInput = document.createElement('input');
  memoInput.id = 'gpinv-memo';
  memoInput.maxLength = 280;
  memoInput.placeholder = 'memo (optional: encrypted, only the recipient can read it)';
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
