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

// ── ERC-20 payments: approve + payToken, batched (EIP-5792) or sequential ──
// PayAndAnnounce.payToken pulls the token via transferFrom, so the payer's wallet must
// approve the contract for the exact amount first. Wallets with EIP-5792 atomic batching
// take both calls in one confirmation; the rest take two transactions. The exact-amount
// approval (never infinite) is the privacy-preserving default: no standing allowance.

// USDC on mainnet, 6 decimals. The only ERC-20 the payer flow wires today; the invoice
// suite prices in it by default.
export const USDC_MAINNET = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48';
const TOKEN_DECIMALS = { ETH: 18, USDC: 6 };

// "25" / "25.50" → base units (USDC 6 decimals, ETH 18 wei). Null when the token is
// unknown, the string is not a plain positive decimal, or it carries more precision
// than the token has: a dead link is safer than a silently rounded payment.
export function parseTokenUnits(amountStr, token) {
  const dec = TOKEN_DECIMALS[String(token || '').toUpperCase()];
  if (dec == null) return null;
  const m = String(amountStr || '').trim().match(/^([0-9]+)(?:\.([0-9]+)?)?$/);
  if (!m || (m[2] || '').length > dec) return null;
  const units = BigInt(m[1]) * 10n ** BigInt(dec) + (m[2] ? BigInt(m[2].padEnd(dec, '0')) : 0n);
  return units > 0n ? units : null;
}

// The two wallet calls of a token payment: exact-amount approve on the token contract,
// then payToken on PayAndAnnounce (announces + transferFrom in one call). `ethers` is a
// parameter (GP.ethers in the browser, the vendored bundle in node tests) so this
// module stays importable without it.
export function buildTokenPayCalls({ ethers, tokenAddr, spender, stealth, amountUnits, ephPub, metadata }) {
  const approveData = new ethers.Interface(['function approve(address spender, uint256 amount) returns (bool)'])
    .encodeFunctionData('approve', [spender, amountUnits]);
  const payData = new ethers.Interface(['function payToken(address token, address stealth, uint256 amount, bytes ephPub, bytes metadata)'])
    .encodeFunctionData('payToken', [tokenAddr, stealth, amountUnits, ephPub, metadata]);
  return {
    approve: { to: tokenAddr, value: '0x0', data: approveData },
    payToken: { to: spender, value: '0x0', data: payData },
  };
}

// Wallet rejection, across the three shapes it arrives in: EIP-1193 code 4001, ethers
// ACTION_REJECTED, WalletConnect's message-only rejections.
export const isWalletReject = e => {
  const code = e && (e.code ?? (e.cause && e.cause.code));
  return code === 4001 || code === 'ACTION_REJECTED' || /user (rejected|denied)|rejected by (the )?user/i.test(String((e && e.message) || e));
};

// Status line for a failed token payment. The approve/pay split matters to the copy:
// before the approval nothing moved; after it, the approval is onchain but no payment left.
export function tokenPayErrorText(e) {
  const msg = (e && (e.shortMessage || e.message)) || String(e);
  if (e && e.stage === 'reject') return msg;
  if (e && e.stage === 'pay') return 'The approval mined, then the payment failed: ' + msg + ' · no payment was sent, retry.';
  if (e && e.stage === 'wait') return 'The approval was sent but its mining was never observed: ' + msg + ' · no payment was sent.';
  if (isWalletReject(e)) return 'Cancelled in your wallet · nothing was sent.';
  return 'Payment failed: ' + msg + ' · nothing was sent, retry.';
}

// The token-payment state machine. `calls` comes from buildTokenPayCalls, walletRequest
// is the provider-agnostic sender (GP.state.walletRequest), jrpc polls receipts.
// Returns { via: 'batch' | 'sequential', hash, confirmed }. Errors carry a .stage:
// 'batch' (the batch itself failed onchain), 'approve', 'wait' (approval mining never
// observed), 'pay' (approval is onchain but the payment failed), 'reject' (user said no).
export async function sendTokenPayment({ walletRequest, jrpc, account, calls, say = () => {}, pollMs = 3000, maxPolls = 40 }) {
  const sleep = ms => new Promise(x => setTimeout(x, ms));
  const fail = (stage, msg) => { const e = new Error(msg); e.stage = stage; throw e; };
  // EIP-5792 capability detection: an explicit "no atomic batching" skips straight to the
  // sequential flow; anything else (capabilities absent, API missing) still tries the batch.
  let caps = null;
  try { caps = await walletRequest('wallet_getCapabilities', [account]); } catch { /* no capabilities API: still try sendCalls */ }
  const cap1 = caps && (caps['0x1'] || caps['0x01'] || caps['eip155:1']);
  const atomic = cap1 && (cap1.atomicBatch || cap1.atomic);
  const capSaysNo = !!(caps && (!atomic || !(atomic.supported === true || atomic.status === 'supported' || atomic.status === 'ready')));
  if (!capSaysNo) {
    try {
      say('Confirm the approval + payment in your wallet: one confirmation does both (EIP-5792)…');
      const sendRes = await walletRequest('wallet_sendCalls', [{
        version: '2.0.0', chainId: '0x1', from: account,
        calls: [calls.approve, calls.payToken],
      }]);
      const bundleId = typeof sendRes === 'string' ? sendRes : (sendRes && sendRes.id) || null;
      // some wallets return the transaction hash straight from sendCalls
      let hash = bundleId && /^0x[0-9a-fA-F]{64}$/.test(bundleId) ? bundleId : null;
      let confirmed = false, polled = false;
      if (hash || bundleId) say('Batch sent · waiting for confirmation…');
      for (let i = 0; i < maxPolls && !confirmed; i++) {
        await sleep(pollMs);
        if (hash) {
          const rcpt = await jrpc('eth_getTransactionReceipt', [hash]).catch(() => null);
          if (rcpt) {
            if (rcpt.status !== '0x1') fail('batch', 'the batch transaction reverted');
            confirmed = true;
          }
        } else if (bundleId) {
          let cs = null;
          try { cs = await walletRequest('wallet_getCallsStatus', [bundleId]); } catch { break; } // no status API: report as submitted
          polled = true;
          const code = Number(cs && cs.status);
          if (code >= 200 && code < 300) {
            confirmed = true;
            const rc = cs.receipts && cs.receipts[0];
            hash = (rc && rc.transactionHash) || hash;
          } else if (code >= 400) fail('batch', 'the batch was rejected or reverted (wallet calls status ' + code + ')');
        } else break;
      }
      return { via: 'batch', hash, confirmed };
    } catch (e) {
      if (e && e.stage === 'batch') throw e;
      if (isWalletReject(e)) fail('reject', 'Cancelled in your wallet · nothing was sent.');
      say('EIP-5792 batch unavailable (' + ((e && e.message) || e) + ') · falling back to two transactions…');
    }
  }
  // sequential fallback: exact-amount approve, wait for it to mine, then payToken
  say('Confirm the exact-amount USDC approval in your wallet (transaction 1 of 2)…');
  let approveHash;
  try {
    approveHash = await walletRequest('eth_sendTransaction', [{ from: account, ...calls.approve }]);
  } catch (e) {
    if (isWalletReject(e)) fail('reject', 'Cancelled in your wallet · nothing was sent.');
    fail('approve', (e && e.message) || String(e));
  }
  say('Approval sent · waiting for it to mine…');
  for (let i = 0; ; i++) {
    const rcpt = await jrpc('eth_getTransactionReceipt', [approveHash]).catch(() => null);
    if (rcpt) {
      if (rcpt.status !== '0x1') fail('approve', 'the approval transaction reverted');
      break;
    }
    if (i >= maxPolls) fail('wait', 'the approval is still pending · check your wallet before retrying');
    await sleep(pollMs);
  }
  say('Approval mined · confirm the payment (transaction 2 of 2)…');
  let hash;
  try {
    hash = await walletRequest('eth_sendTransaction', [{ from: account, ...calls.payToken }]);
  } catch (e) {
    if (isWalletReject(e)) fail('reject', 'Cancelled in your wallet · the approval is already onchain, retrying reuses it.');
    fail('pay', (e && e.message) || String(e));
  }
  return { via: 'sequential', hash, approveHash, confirmed: false };
}

// paidAmount from the pinned address's balances. The token reading (USDC invoices paid
// via payToken) always wins; the ETH × price reading is only the legacy fallback for
// links paid before token payments existed, so one payment is never counted twice.
// Returns null when nothing readable arrived (the caller keeps its previous figure).
export function paidFromBalances(rec, { balEth = 0, tokenBal = null, ethPrice = null } = {}) {
  if (rec && rec.token === 'ETH') return balEth > 0 ? round6(balEth) : null;
  if (tokenBal != null && tokenBal > 0) return round6(tokenBal);
  if (balEth > 0 && ethPrice) return round2(balEth * ethPrice);
  return null;
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
    () => { btn.textContent = 'Copied ✓'; setTimeout(() => { btn.textContent = label; }, 1200); },
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

// offline fallback: identical copy of the <style> block in frag-invoices.html
const FRAG_FALLBACK = `<style id="gpinv-styles">
  /* pane headings + field labels (scoped to this module's five panes) */
  :is(#tab-invoices,#tab-customers,#tab-items,#tab-recurring,#tab-settings) .gp-h3 { margin: var(--gp-s6) 0 var(--gp-s3); }
  :is(#tab-invoices,#tab-customers,#tab-items,#tab-recurring,#tab-settings) > .gp-h3:first-child,
  :is(#tab-invoices,#tab-customers,#tab-items,#tab-recurring,#tab-settings) .gp-card > .gp-h3:first-child { margin-top: 0; }
  :is(#tab-invoices,#tab-customers,#tab-items,#tab-recurring,#tab-settings) .gp-eyebrow { display: block; margin-bottom: 6px; }
  :is(#tab-invoices,#tab-customers,#tab-items,#tab-recurring,#tab-settings) :is(.gp-input,.gp-select,.gp-textarea) { margin-top: 0; }

  /* field layout: two-column rows collapse on mobile, .gpinv-gap stacks fields */
  #gp-invoices .gpinv-grid { display: grid; grid-template-columns: 1fr 1fr; gap: var(--gp-s4); }
  #gp-invoices .gpinv-gap { margin-top: var(--gp-s4); }

  /* line-items editor: denser controls inside table cells */
  #gp-invoices .gpinv-items td :is(.gp-input,.gp-select) { padding: 8px 10px; font-size: var(--gp-fs-micro); }
  #gp-invoices .gpinv-items td .gp-select[data-f="pick"] { margin-bottom: 6px; }

  /* totals column: live editor totals, record detail, and the payer document.
     Right-aligned rows with hairlines, the grand total on a strong line */
  #gp-invoices .gpinv-totals, #payghost .gpinv-totals { margin: var(--gp-s4) 0 0 auto; width: min(320px,100%); font-size: var(--gp-fs-small); }
  #gp-invoices .gpinv-trow, #payghost .gpinv-trow { display: flex; justify-content: space-between; gap: 16px; padding: 6px 0; border-bottom: 1px solid var(--gp-line-soft); color: var(--gp-muted); }
  #gp-invoices .gpinv-trow > span:last-child, #payghost .gpinv-trow > span:last-child { color: var(--gp-fg); text-align: right; }
  #gp-invoices .gpinv-trow.gpinv-grand, #payghost .gpinv-trow.gpinv-grand { border-bottom: 0; border-top: 1px solid var(--gp-line-strong); margin-top: 4px; padding-top: 10px; font-weight: 700; }
  #gp-invoices .gpinv-trow.gpinv-grand > span, #payghost .gpinv-trow.gpinv-grand > span { color: var(--gp-fg); font-size: var(--gp-fs-body); }
  #gp-invoices .gpinv-trow.gpinv-tusd, #payghost .gpinv-trow.gpinv-tusd { border-bottom: 0; color: var(--gp-faint); font-size: var(--gp-fs-micro); justify-content: flex-end; }

  /* clickable list rows + the expansion row (an inset well) */
  #gp-invoices .gpinv-rowbtn { cursor: pointer; }
  #gp-invoices .gpinv-rowbtn:hover td { background: var(--gp-bg-raise); }
  #gp-invoices .gpinv-detail td { background: var(--gp-bg-inset); padding: var(--gp-s4); }
  #gp-invoices .gpinv-detailhead { display: flex; align-items: center; gap: 10px; }
  #gp-invoices .gpinv-detailhead .gp-eyebrow { margin-bottom: 0; }
  #gp-invoices .gpinv-meta { font-size: var(--gp-fs-small); margin-top: 6px; }
  #gp-invoices .gpinv-detailtable { margin-top: var(--gp-s3); }
  #gp-invoices .gpinv-sub { font-size: var(--gp-fs-micro); }

  /* address / url blocks + the decrypted memo line */
  #gp-invoices .gpinv-mono { font-size: var(--gp-fs-micro); color: var(--gp-muted); word-break: break-all; margin-top: 6px; }
  #gp-invoices .gpinv-memo-line { font-size: var(--gp-fs-small); margin-top: 10px; }
  #gp-invoices .gpinv-qr { margin-top: var(--gp-s3); text-align: center; }

  /* action rows + the editor's sticky save bar (stays reachable on long forms) */
  #gp-invoices .gpinv-actions { display: flex; gap: var(--gp-s2); margin-top: var(--gp-s4); flex-wrap: wrap; }
  #gp-invoices .gpinv-paneactions { margin-top: 0; }
  #gp-invoices .gpinv-sticky { position: sticky; bottom: 0; z-index: 5; background: var(--gp-bg-raise); border-top: 1px solid var(--gp-line); margin-top: var(--gp-s4); padding: var(--gp-s3) 0 var(--gp-s2); }

  /* status filter + the INVOICES/ESTIMATES sub-switch ride the .gp-tabs primitive */
  #gp-invoices .gp-tabs.gpinv-sub { margin-top: 0; }
  #gp-invoices .gp-tabs.gpinv-filter { margin: var(--gp-s4) 0 var(--gp-s3); }

  /* settings identity row (monogram + business name) */
  #gp-invoices .gpinv-idrow { display: flex; gap: var(--gp-s4); align-items: center; }
  #gp-invoices .gpinv-mg { width: 46px; height: 46px; border: 1px solid var(--gp-line-strong); border-radius: var(--gp-radius-sm); display: flex; flex: none; align-items: center; justify-content: center; font-family: var(--gp-font-display); font-weight: 700; letter-spacing: .1em; }

  /* checkbox row (recurring template active flag) */
  #gp-invoices .gpinv-check { display: flex; align-items: center; gap: 8px; font-size: var(--gp-fs-small); margin-top: var(--gp-s4); cursor: pointer; }
  #gp-invoices .gpinv-check input { width: auto; margin: 0; }

  /* ── payer invoice document (#payghost): the bill, above the address card ── */
  #payghost .gpinv-doc { background: var(--gp-bg-raise); border: 1px solid var(--gp-line); border-radius: var(--gp-radius); padding: var(--gp-s5); margin-top: var(--gp-s4); }
  #payghost .gpinv-doc-head { display: flex; align-items: center; gap: 10px; padding-bottom: var(--gp-s3); border-bottom: 1px solid var(--gp-line); }
  #payghost .gpinv-doc-num { font-weight: 700; }
  #payghost .gpinv-doc-head .gp-pill { margin-left: auto; }
  #payghost .gpinv-doc-items { margin-top: var(--gp-s3); }
  #payghost .gpinv-doc-kv { display: flex; justify-content: space-between; gap: 16px; padding: 8px 0; border-bottom: 1px solid var(--gp-line-soft); font-size: var(--gp-fs-small); }
  #payghost .gpinv-doc-k { color: var(--gp-muted); flex: none; }
  #payghost .gpinv-doc-duebox { margin-top: var(--gp-s4); }
  #payghost .gpinv-doc-duebox .gp-eyebrow { display: block; }
  #payghost .gpinv-doc-amount { font-size: 26px; font-weight: 700; letter-spacing: -.5px; margin-top: 6px; }
  #payghost .gpinv-doc-token { font-size: var(--gp-fs-small); font-weight: 400; color: var(--gp-muted); letter-spacing: .1em; }
  #payghost .gpinv-doc-eq { color: var(--gp-muted); font-size: var(--gp-fs-small); margin-top: 4px; min-height: 1.2em; }
  #payghost .gpinv-doc-settle { border: 1px solid var(--gp-line); border-radius: var(--gp-radius-sm); padding: 10px 12px; margin-top: var(--gp-s4); font-size: var(--gp-fs-small); color: var(--gp-muted); }
  #payghost .gpinv-doc-expired { border-color: rgba(205,111,94,.45); background: var(--gp-danger-bg); color: var(--gp-danger); }
  /* the memo field lives inside the shell's address card: inherit works on the
     inverted .card today and on a dark card if the shell retires .card later */
  #payghost .gpinv-memo { margin-top: var(--gp-s4); }
  #payghost .gpinv-memo .gp-eyebrow { display: block; margin-bottom: 6px; color: inherit; opacity: .8; }
  #payghost .gpinv-memo .gp-input { margin-top: 0; }

  @media (max-width: 700px) {
    #gp-invoices .gpinv-grid { grid-template-columns: 1fr; }
    #gp-invoices .gpinv-actions { flex-direction: column; }
    #gp-invoices .gpinv-actions .gp-btn { width: 100%; min-height: 44px; }
    #payghost .gpinv-doc { padding: var(--gp-s4); }
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

  // status pills ride the .gp-pill primitive: semantic tones for terminal and
  // attention states, dim for inactive, bare outline otherwise. Labels stay caps:
  // they are status tokens, not copy.
  const pill = st => {
    const tone =
      st === 'PAID' || st === 'ACCEPTED' || st === 'ACTIVE' ? ' ok'
      : st === 'OVERDUE' ? ' danger'
      : st === 'DRAFT' || st === 'DECLINED' || st === 'PAUSED' ? ' dim'
      : st === 'SENT' || st === 'PARTIAL' ? ' info'
      : '';
    return '<span class="gp-pill' + tone + '">' + st + '</span>';
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
    return '<select class="gp-select" data-row="' + i + '" data-f="taxpick" data-pref="' + pref + '">'
      + TAX_PRESETS.map(v => '<option value="' + v + '"' + (sel === v ? ' selected' : '') + '>' + v + '%</option>').join('')
      + '<option value="custom"' + (sel === 'custom' ? ' selected' : '') + '>custom…</option>'
      + '</select>'
      + (sel === 'custom'
        ? '<input class="gp-input" data-row="' + i + '" data-f="taxcustom" data-pref="' + pref + '" type="number" min="0" step="any" placeholder="%" value="' + escHtml(rateStr) + '" style="margin-top:6px">'
        : '');
  }

  function rowsTableHtml(rows, token, catalog, pref) {
    return '<div class="gp-tablewrap gpinv-items"><table class="gp-table" id="gpinv-' + pref + '-items"><thead><tr>'
      + '<th style="width:34%">Description</th><th>Qty</th><th>Unit price</th><th>Disc %</th><th>Tax</th><th style="text-align:right">Amount</th><th></th>'
      + '</tr></thead><tbody>'
      + rows.map((r, i) =>
          '<tr><td>'
          + '<select class="gp-select" data-row="' + i + '" data-f="pick" data-pref="' + pref + '">'
          + '<option value="">catalog item…</option>'
          + catalog.map((c, ci) =>
              '<option value="' + ci + '"' + (r._pick === String(ci) ? ' selected' : '') + '>'
              + escHtml(c.name) + ' · ' + fmtAmt(c.unitPrice, c.token) + ' ' + c.token + '</option>'
            ).join('')
          + '</select>'
          + '<input class="gp-input" data-row="' + i + '" data-f="description" data-pref="' + pref + '" placeholder="description" value="' + escHtml(r.description) + '"></td>'
          + '<td><input class="gp-input" data-row="' + i + '" data-f="qty" data-pref="' + pref + '" type="number" min="0" step="any" value="' + escHtml(r.qty) + '"></td>'
          + '<td><input class="gp-input" data-row="' + i + '" data-f="unitPrice" data-pref="' + pref + '" type="number" min="0" step="any" placeholder="0.00" value="' + escHtml(r.unitPrice) + '"></td>'
          + '<td><input class="gp-input" data-row="' + i + '" data-f="discPct" data-pref="' + pref + '" type="number" min="0" step="any" placeholder="0" value="' + escHtml(r.discPct ?? '') + '"></td>'
          + '<td style="white-space:nowrap">' + taxCellHtml(r, i, pref) + '</td>'
          + '<td style="text-align:right;white-space:nowrap" data-rowamt="' + i + '" data-pref="' + pref + '">' + fmtAmt((parseFloat(r.qty) || 0) * (parseFloat(r.unitPrice) || 0), token) + '</td>'
          + '<td style="width:1%"><button type="button" class="gp-btn small ghost gpinv-x" data-iact="' + pref + '-del-row" data-row="' + i + '" title="remove row">×</button></td></tr>'
        ).join('')
      + '</tbody></table></div>'
      + '<button type="button" class="gp-btn small ghost" data-iact="' + pref + '-add-row" style="margin-top:10px">Add row</button>';
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
    return '<div class="gpinv-trow"><span>Subtotal</span><span>' + fmtAmt(t.subtotal, token) + '</span></div>'
      + (t.discountAmount > 0 ? '<div class="gpinv-trow"><span>Discount</span><span>−' + fmtAmt(t.discountAmount, token) + '</span></div>' : '')
      + (t.taxLines || []).map(tl =>
          '<div class="gpinv-trow"><span>Tax ' + tl.rate + '% on ' + fmtAmt(tl.base, token) + '</span><span>' + fmtAmt(tl.amount, token) + '</span></div>'
        ).join('')
      + '<div class="gpinv-trow gpinv-grand"><span>Total</span><span>' + fmtAmt(t.total, token) + ' ' + token + '</span></div>'
      + '<div class="gpinv-trow gpinv-tusd" id="gpinv-' + pref + '-usd"></div>';
  }

  function totalsBlockHtml(pref, t, token) {
    return '<div class="gpinv-totals" id="gpinv-' + pref + '-totals">'
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
      if (direct) usdEl.textContent = '≈ ' + direct;
      else ethUsd().then(px => {
        const u = fmtUsd(t.total, token, px);
        if (usdEl.isConnected) usdEl.textContent = u ? '≈ ' + u : 'USD estimate unavailable (relayer price feed offline)';
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
    return '<div class="gp-card gpinv-editor">'
      + '<h3 class="gp-h3">' + (editId ? 'Edit ' : 'New ') + kind + '</h3>'
      + '<label class="gp-eyebrow" for="gpinv-f-client">Client</label>'
      + '<select class="gp-select" id="gpinv-f-client"><option value="">no client</option>'
      + clients.map(c => '<option value="' + escHtml(c.id) + '"' + (d.clientId === c.id ? ' selected' : '') + '>' + escHtml(c.name) + '</option>').join('')
      + '</select>'
      + '<div class="gp-eyebrow gpinv-gap">Line items · tax rate per row, default ' + escHtml(String(p.taxPct ?? 0)) + '% from your profile</div>'
      + rowsTableHtml(formRows, d.token, catalog, 'f')
      + totalsBlockHtml('f', computeTotals(formRows, null, null), d.token)
      + '<div class="gpinv-grid gpinv-gap">'
      + '<div><label class="gp-eyebrow" for="gpinv-f-token">Token</label>'
      + '<select class="gp-select" id="gpinv-f-token">'
      + ['USDC', 'ETH'].map(t => '<option' + (d.token === t ? ' selected' : '') + '>' + t + '</option>').join('')
      + '</select></div>'
      + '<div><label class="gp-eyebrow" for="gpinv-f-exp">Expires in days</label>'
      + '<input class="gp-input" id="gpinv-f-exp" type="number" min="0" placeholder="optional: blank = never" value="' + escHtml(d.expDays) + '"></div>'
      + '</div>'
      + '<div class="gpinv-gap"><label class="gp-eyebrow" for="gpinv-f-note">Note</label>'
      + '<input class="gp-input" id="gpinv-f-note" placeholder="optional: prefills the payer\'s encrypted memo" value="' + escHtml(d.note) + '"></div>'
      + '<div class="gpinv-actions gpinv-sticky">'
      + '<button type="button" class="gp-btn primary" data-iact="save-form">' + (editId ? 'Save changes' : 'Create ' + kind) + '</button>'
      + '<button type="button" class="gp-btn ghost" data-iact="toggle-form">Cancel</button>'
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
      + (anyDisc ? '<td>' + (it.discountPct > 0 ? it.discountPct + '%' : '<span class="gp-faint">·</span>') + '</td>' : '')
      + '<td>' + (it.taxPct > 0 ? it.taxPct + '%' : '0%') + '</td>'
      + '<td style="text-align:right">' + fmtAmt((parseFloat(it.qty) || 0) * (parseFloat(it.unitPrice) || 0), rec.token) + '</td></tr>'
    ).join('');
    const tls = taxLinesOf(rec);
    return '<div class="gpinv-detailhead"><span class="gp-eyebrow">' + kind + ' ' + escHtml(rec.number) + '</span>' + pill(st) + '</div>'
      + '<div class="gp-muted gpinv-meta">'
      + 'created ' + fmtDate(rec.created)
      + (rec.clientName ? ' · client: ' + escHtml(rec.clientName) : '')
      + (rec.expiry ? ' · ' + (kind === 'invoice' ? 'due ' : 'valid until ') + fmtDate(rec.expiry) : ' · no expiry')
      + (rec.sentAt ? ' · sent ' + fmtDate(rec.sentAt) : '')
      + (rec.paidAt ? ' · paid ' + fmtDate(rec.paidAt) : '')
      + (rec.estimateOf ? ' · converted from estimate' : '')
      + '</div>'
      + '<div class="gp-tablewrap gpinv-detailtable"><table class="gp-table"><thead><tr>'
      + '<th style="width:40%">Description</th><th>Qty</th><th>Unit price</th>' + (anyDisc ? '<th>Disc</th>' : '') + '<th>Tax</th><th style="text-align:right">Amount</th>'
      + '</tr></thead><tbody>' + itemRows + '</tbody></table></div>'
      + '<div class="gpinv-totals">'
      + '<div class="gpinv-trow"><span>Subtotal</span><span>' + fmtAmt(rec.subtotal, rec.token) + ' ' + rec.token + '</span></div>'
      + (rec.discountAmount > 0 ? '<div class="gpinv-trow"><span>Discount</span><span>−' + fmtAmt(rec.discountAmount, rec.token) + ' ' + rec.token + '</span></div>' : '')
      + tls.map(tl => '<div class="gpinv-trow"><span>Tax ' + tl.rate + '% on ' + fmtAmt(tl.base, rec.token) + '</span><span>' + fmtAmt(tl.amount, rec.token) + ' ' + rec.token + '</span></div>').join('')
      + '<div class="gpinv-trow gpinv-grand"><span>Total</span><span>' + fmtAmt(rec.total, rec.token) + ' ' + rec.token + '</span></div>'
      + '<div class="gpinv-trow gpinv-tusd" data-usd data-amt="' + rec.total + '" data-token="' + rec.token + '"></div>'
      + (st === 'PARTIAL' ? '<div class="gpinv-trow"><span>Paid so far</span><span>' + fmtAmt(rec.paidAmount, rec.token) + ' ' + rec.token + '</span></div>'
        + '<div class="gpinv-trow"><span>Remaining</span><span>' + fmtAmt(round2(rec.total - rec.paidAmount), rec.token) + ' ' + rec.token + '</span></div>' : '')
      + '</div>'
      + (rec.note ? '<div class="gp-muted gpinv-meta">note: ' + escHtml(rec.note) + '</div>' : '')
      + (memo ? '<div class="gpinv-memo-line">payment memo: ' + escHtml(memo) + '</div>' : '')
      + (rec.paidTx ? '<div class="gp-muted gpinv-meta">payment tx: <a href="https://etherscan.io/tx/' + escHtml(rec.paidTx) + '" target="_blank" rel="noopener">' + escHtml(rec.paidTx.slice(0, 18)) + '…</a></div>' : '')
      + '<div class="gp-eyebrow gpinv-gap">Pinned stealth address</div>'
      + '<div class="gpinv-mono">' + escHtml(rec.stealthAddress) + '</div>'
      + '<div class="gpinv-mono">' + escHtml(rec.url) + '</div>'
      + (qrFor === rec.id ? '<div class="gpinv-qr"><canvas data-qr style="background:#fff;padding:14px;image-rendering:pixelated;max-width:100%"></canvas></div>' : '')
      + '<div class="gpinv-actions">'
      + '<button type="button" class="gp-btn small ghost" data-iact="view" data-id="' + escHtml(rec.id) + '">View link</button>'
      + '<button type="button" class="gp-btn small ghost" data-iact="qr" data-id="' + escHtml(rec.id) + '">QR</button>'
      + '<button type="button" class="gp-btn small ghost" data-iact="copy" data-id="' + escHtml(rec.id) + '">Copy link</button>'
      + (kind === 'invoice' && st === 'OVERDUE' ? '<button type="button" class="gp-btn small ghost" data-iact="remind" data-id="' + escHtml(rec.id) + '">Reminder</button>' : '')
      + '<button type="button" class="gp-btn small ghost" data-iact="dup" data-id="' + escHtml(rec.id) + '">Duplicate</button>'
      + '<button type="button" class="gp-btn small ghost" data-iact="print" data-id="' + escHtml(rec.id) + '">Print / PDF</button>'
      + (st === 'DRAFT' ? '<button type="button" class="gp-btn small ghost" data-iact="edit" data-id="' + escHtml(rec.id) + '">Edit</button>' : '')
      + (st === 'DRAFT' ? '<button type="button" class="gp-btn small" data-iact="sent" data-id="' + escHtml(rec.id) + '">Mark sent</button>' : '')
      + (kind === 'estimate' && st === 'SENT' ? '<button type="button" class="gp-btn small" data-iact="accept" data-id="' + escHtml(rec.id) + '">Mark accepted</button>' : '')
      + (kind === 'estimate' && st === 'SENT' ? '<button type="button" class="gp-btn small ghost" data-iact="decline" data-id="' + escHtml(rec.id) + '">Mark declined</button>' : '')
      + (kind === 'estimate' && (st === 'SENT' || st === 'ACCEPTED') ? '<button type="button" class="gp-btn small primary" data-iact="convert" data-id="' + escHtml(rec.id) + '">Convert to invoice</button>' : '')
      + (st === 'DRAFT' ? '<button type="button" class="gp-btn small danger" data-iact="del" data-id="' + escHtml(rec.id) + '">Delete</button>' : '')
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
    return '<div class="gpinv-actions gpinv-paneactions">'
      + '<button type="button" class="gp-btn primary" data-iact="toggle-form" data-k="' + kind + '">' + (showForm && formKind === kind ? 'Cancel' : 'New ' + noun) + '</button>'
      + '</div>'
      + (showForm && formKind === kind ? editorHtml() : '')
      + '<div class="gp-tabs gpinv-filter">'
      + filters.map(f => '<button type="button" class="gp-tab' + (filter === f ? ' on' : '') + '" data-iact="filter" data-k="' + kind + '" data-f="' + f + '">' + f + '</button>').join('')
      + '</div>'
      + (rows.length === 0
        ? '<div class="gp-empty"><div class="gp-empty-title">No ' + noun + 's yet</div>'
          + (kind === 'invoice' ? 'Create one to get a private payment link. Add clients under Customers and reusable lines under Items first, then pick them here.' : 'Estimates share the client list and item catalog with invoices.') + '</div>'
        : shown.length === 0
          ? '<div class="gp-empty"><div class="gp-empty-title">Nothing with status ' + filter + '</div>Pick another filter above.</div>'
          : '<div class="gp-tablewrap"><table class="gp-table"><thead><tr>'
            + '<th>Number</th><th>Client</th><th>Date</th><th>' + (kind === 'invoice' ? 'Due' : 'Valid until') + '</th>'
            + '<th style="text-align:right">Total</th><th style="text-align:right">USD</th><th style="text-align:right">Status</th>'
            + '</tr></thead><tbody>'
            + shown.map(rec =>
                '<tr class="gpinv-rowbtn" data-iact="open" data-id="' + escHtml(rec.id) + '">'
                + '<td><b>' + escHtml(rec.number) + '</b></td>'
                + '<td>' + (rec.clientName ? escHtml(rec.clientName) : '<span class="gp-faint">·</span>') + '</td>'
                + '<td style="white-space:nowrap">' + fmtDate(rec.created) + '</td>'
                + '<td style="white-space:nowrap">' + (rec.expiry ? fmtDate(rec.expiry) : '<span class="gp-faint">·</span>') + '</td>'
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
      '<div class="gp-tabs gpinv-sub">'
      + '<button type="button" class="gp-tab' + (invKind === 'invoice' ? ' on' : '') + '" data-iact="kind" data-k="invoice">Invoices</button>'
      + '<button type="button" class="gp-tab' + (invKind === 'estimate' ? ' on' : '') + '" data-iact="kind" data-k="estimate">Estimates</button>'
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
      '<h3 class="gp-h3">Add customer</h3>'
      + '<div class="gp-card">'
      + '<label class="gp-eyebrow" for="gpinv-c-name">Name</label>'
      + '<input class="gp-input" id="gpinv-c-name" placeholder="e.g. Acme Ltd">'
      + '<div class="gpinv-gap"><label class="gp-eyebrow" for="gpinv-c-contact">Contact</label>'
      + '<input class="gp-input" id="gpinv-c-contact" placeholder="email, telegram, …"></div>'
      + '<div class="gpinv-gap"><label class="gp-eyebrow" for="gpinv-c-addr">Address lines</label>'
      + '<textarea class="gp-textarea" id="gpinv-c-addr" rows="2" placeholder="optional, one per line: printed on invoices"></textarea></div>'
      + '<div class="gpinv-gap"><label class="gp-eyebrow" for="gpinv-c-vat">VAT / tax number</label>'
      + '<input class="gp-input" id="gpinv-c-vat" placeholder="optional: printed under the bill-to block"></div>'
      + '<div class="gpinv-gap"><label class="gp-eyebrow" for="gpinv-c-notes">Notes</label>'
      + '<input class="gp-input" id="gpinv-c-notes" placeholder="optional"></div>'
      + '<div class="gpinv-actions"><button type="button" class="gp-btn primary" data-iact="add-client">Add customer</button></div>'
      + '<div class="status" id="gpinv-c-st"></div>'
      + '</div>'
      + '<h3 class="gp-h3">Customers</h3>'
      + (clients.length
        ? '<div class="gp-tablewrap"><table class="gp-table"><thead><tr>'
          + '<th>Name</th><th>Contact</th><th style="text-align:right">Outstanding</th><th style="text-align:right">Paid</th><th></th>'
          + '</tr></thead><tbody>'
          + clients.map(c => {
              const mine = inv.filter(i => i.clientId === c.id);
              const tot = f => mine.filter(f).reduce((m, i) => { m[i.token] = (m[i.token] || 0) + i.total; return m; }, {});
              const cell = m => Object.keys(m).length ? Object.keys(m).map(t => fmtAmt(m[t], t) + ' ' + t).join('<br>') : '<span class="gp-faint">·</span>';
              const open = i => ['SENT', 'PARTIAL', 'OVERDUE'].includes(invStatus(i, now));
              return '<tr><td><b>' + escHtml(c.name) + '</b>'
                + (c.vatNumber ? '<div class="gp-faint gpinv-sub">tax id: ' + escHtml(c.vatNumber) + '</div>' : '')
                + (c.notes ? '<div class="gp-faint gpinv-sub">' + escHtml(c.notes) + '</div>' : '')
                + '</td><td>' + (c.contact ? escHtml(c.contact) : '<span class="gp-faint">·</span>') + '</td>'
                + '<td style="text-align:right">' + cell(tot(open)) + '</td>'
                + '<td style="text-align:right">' + cell(tot(i => i.status === 'PAID')) + '</td>'
                + '<td style="width:1%"><button type="button" class="gp-btn small ghost gpinv-x" data-iact="del-client" data-id="' + escHtml(c.id) + '" title="delete customer">×</button></td></tr>';
            }).join('')
          + '</tbody></table></div>'
        : '<div class="gp-empty"><div class="gp-empty-title">No customers yet</div>Add one above, then pick them when creating an invoice. Outstanding and paid totals build up here as invoices move.</div>');
  }

  // ── tab: ITEMS (reusable line-item catalog) ──
  function renderItems() {
    const el = mounts.items;
    if (!el) return;
    const items = loadItems();
    el.innerHTML =
      '<h3 class="gp-h3">' + (itemEditId ? 'Edit item' : 'Add item') + '</h3>'
      + '<div class="gp-card">'
      + '<label class="gp-eyebrow" for="gpinv-i-name">Item name</label>'
      + '<input class="gp-input" id="gpinv-i-name" placeholder="e.g. design retainer" value="' + escHtml(itemDraft.name) + '">'
      + '<div class="gpinv-gap"><label class="gp-eyebrow" for="gpinv-i-desc">Description</label>'
      + '<input class="gp-input" id="gpinv-i-desc" placeholder="prefills invoice lines" value="' + escHtml(itemDraft.description) + '"></div>'
      + '<div class="gpinv-grid gpinv-gap">'
      + '<div><label class="gp-eyebrow" for="gpinv-i-price">Unit price</label><input class="gp-input" id="gpinv-i-price" type="number" min="0" step="any" value="' + escHtml(itemDraft.unitPrice) + '" placeholder="0.00"></div>'
      + '<div><label class="gp-eyebrow" for="gpinv-i-token">Token</label><select class="gp-select" id="gpinv-i-token">'
      + ['USDC', 'ETH'].map(t => '<option' + (itemDraft.token === t ? ' selected' : '') + '>' + t + '</option>').join('')
      + '</select></div>'
      + '</div>'
      + '<div class="gpinv-grid gpinv-gap">'
      + '<div><label class="gp-eyebrow" for="gpinv-i-tax">Tax % (optional: prefills the row rate)</label><input class="gp-input" id="gpinv-i-tax" type="number" min="0" step="any" value="' + escHtml(itemDraft.taxPct) + '" placeholder="blank = profile rate"></div>'
      + '<div><label class="gp-eyebrow" for="gpinv-i-disc">Discount % (optional)</label><input class="gp-input" id="gpinv-i-disc" type="number" min="0" step="any" value="' + escHtml(itemDraft.discPct) + '" placeholder="0"></div>'
      + '</div>'
      + '<div class="gpinv-actions gpinv-sticky">'
      + '<button type="button" class="gp-btn primary" data-iact="save-item">' + (itemEditId ? 'Save item' : 'Add item') + '</button>'
      + (itemEditId ? '<button type="button" class="gp-btn ghost" data-iact="cancel-item">Cancel</button>' : '')
      + '</div>'
      + '<div class="status" id="gpinv-i-st"></div>'
      + '</div>'
      + '<h3 class="gp-h3">Catalog</h3>'
      + (items.length
        ? '<div class="gp-tablewrap"><table class="gp-table"><thead><tr>'
          + '<th>Name</th><th>Description</th><th>Tax</th><th style="text-align:right">Unit price</th><th></th>'
          + '</tr></thead><tbody>'
          + items.map(it =>
              '<tr><td><b>' + escHtml(it.name) + '</b></td>'
              + '<td>' + (it.description ? escHtml(it.description) : '<span class="gp-faint">·</span>') + '</td>'
              + '<td>' + (it.taxPct > 0 ? it.taxPct + '%' : '<span class="gp-faint">·</span>') + '</td>'
              + '<td style="text-align:right;white-space:nowrap">' + fmtAmt(it.unitPrice, it.token) + ' ' + it.token + '</td>'
              + '<td style="width:1%;white-space:nowrap">'
              + '<button type="button" class="gp-btn small ghost gpinv-x" data-iact="edit-item" data-id="' + escHtml(it.id) + '" title="edit item">✎</button> '
              + '<button type="button" class="gp-btn small ghost gpinv-x" data-iact="del-item" data-id="' + escHtml(it.id) + '" title="delete item">×</button>'
              + '</td></tr>'
            ).join('')
          + '</tbody></table></div>'
        : '<div class="gp-empty"><div class="gp-empty-title">The catalog is empty</div>Add reusable line items above, then pick them from any invoice, estimate or recurring template row.</div>');
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
    return '<div class="gp-card gpinv-editor">'
      + '<h3 class="gp-h3">' + (recEditId ? 'Edit template' : 'New recurring template') + '</h3>'
      + '<label class="gp-eyebrow" for="gpinv-r-client">Client</label>'
      + '<select class="gp-select" id="gpinv-r-client"><option value="">no client</option>'
      + clients.map(c => '<option value="' + escHtml(c.id) + '"' + (d.clientId === c.id ? ' selected' : '') + '>' + escHtml(c.name) + '</option>').join('')
      + '</select>'
      + '<div class="gp-eyebrow gpinv-gap">Line items · tax rate per row</div>'
      + rowsTableHtml(recRows, d.token, catalog, 'r')
      + totalsBlockHtml('r', computeTotals(recRows, null, null), d.token)
      + '<div class="gpinv-grid gpinv-gap">'
      + '<div><label class="gp-eyebrow" for="gpinv-r-token">Token</label>'
      + '<select class="gp-select" id="gpinv-r-token">'
      + ['USDC', 'ETH'].map(t => '<option' + (d.token === t ? ' selected' : '') + '>' + t + '</option>').join('')
      + '</select></div>'
      + '<div><label class="gp-eyebrow" for="gpinv-r-note">Note</label>'
      + '<input class="gp-input" id="gpinv-r-note" placeholder="optional: prefills the payer\'s encrypted memo" value="' + escHtml(d.note) + '"></div>'
      + '</div>'
      + '<div class="gpinv-grid gpinv-gap">'
      + '<div><label class="gp-eyebrow" for="gpinv-r-everyn">Repeat every</label><input class="gp-input" id="gpinv-r-everyn" type="number" min="1" step="1" value="' + escHtml(d.everyN) + '"></div>'
      + '<div><label class="gp-eyebrow" for="gpinv-r-unit">Unit</label><select class="gp-select" id="gpinv-r-unit">'
      + ['weeks', 'months'].map(u => '<option' + (d.unit === u ? ' selected' : '') + '>' + u + '</option>').join('')
      + '</select></div>'
      + '</div>'
      + '<div class="gpinv-gap"><label class="gp-eyebrow" for="gpinv-r-next">Next run date</label>'
      + '<input class="gp-input" id="gpinv-r-next" type="date" value="' + escHtml(d.next) + '"></div>'
      + '<label class="gpinv-check" for="gpinv-r-active"><input type="checkbox" id="gpinv-r-active"' + (d.active ? ' checked' : '') + '>Active (paused templates never come due)</label>'
      + '<div class="gpinv-actions gpinv-sticky">'
      + '<button type="button" class="gp-btn primary" data-iact="rec-save">' + (recEditId ? 'Save template' : 'Create template') + '</button>'
      + '<button type="button" class="gp-btn ghost" data-iact="rec-new">Cancel</button>'
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
        + (anyDisc ? '<td>' + (it.discountPct > 0 ? it.discountPct + '%' : '<span class="gp-faint">·</span>') + '</td>' : '')
        + '<td>' + rate + '%</td>'
        + '<td style="text-align:right">' + fmtAmt((parseFloat(it.qty) || 0) * (parseFloat(it.unitPrice) || 0), r.token) + '</td></tr>';
    }).join('');
    const due = r.active && r.nextDate <= Date.now();
    return '<div class="gp-muted gpinv-meta">'
      + 'every ' + r.everyN + ' ' + r.unit + ' · next run ' + fmtDate(r.nextDate) + (due ? ' · due now' : '')
      + '</div>'
      + '<div class="gp-tablewrap gpinv-detailtable"><table class="gp-table"><thead><tr>'
      + '<th style="width:40%">Description</th><th>Qty</th><th>Unit price</th>' + (anyDisc ? '<th>Disc</th>' : '') + '<th>Tax</th><th style="text-align:right">Amount</th>'
      + '</tr></thead><tbody>' + itemRows + '</tbody></table></div>'
      + '<div class="gpinv-totals">'
      + (t.discountAmount > 0 ? '<div class="gpinv-trow"><span>Discount</span><span>−' + fmtAmt(t.discountAmount, r.token) + ' ' + r.token + '</span></div>' : '')
      + t.taxLines.map(tl => '<div class="gpinv-trow"><span>Tax ' + tl.rate + '% on ' + fmtAmt(tl.base, r.token) + '</span><span>' + fmtAmt(tl.amount, r.token) + ' ' + r.token + '</span></div>').join('')
      + '<div class="gpinv-trow gpinv-grand"><span>Total</span><span>' + fmtAmt(t.total, r.token) + ' ' + r.token + ' per run</span></div>'
      + '</div>'
      + (r.note ? '<div class="gp-muted gpinv-meta">note: ' + escHtml(r.note) + '</div>' : '')
      + '<div class="gpinv-actions">'
      + (due ? '<button type="button" class="gp-btn small primary" data-iact="rec-gen" data-id="' + escHtml(r.id) + '">Generate now</button>' : '')
      + '<button type="button" class="gp-btn small ghost" data-iact="rec-edit" data-id="' + escHtml(r.id) + '">Edit</button>'
      + '<button type="button" class="gp-btn small ghost" data-iact="rec-toggle" data-id="' + escHtml(r.id) + '">' + (r.active ? 'Pause' : 'Resume') + '</button>'
      + '<button type="button" class="gp-btn small danger" data-iact="rec-del" data-id="' + escHtml(r.id) + '">Delete</button>'
      + '</div>';
  }

  function renderRecurring() {
    const el = mounts.recurring;
    if (!el) return;
    const list = loadRecurring();
    const now = Date.now();
    el.innerHTML =
      '<div class="gpinv-actions gpinv-paneactions">'
      + '<button type="button" class="gp-btn primary" data-iact="rec-new">' + (recFormOpen ? 'Cancel' : 'New template') + '</button>'
      + '</div>'
      + (recFormOpen ? recFormHtml() : '')
      + '<h3 class="gp-h3">Recurring templates</h3>'
      + (list.length
        ? '<div class="gp-tablewrap"><table class="gp-table"><thead><tr>'
          + '<th>Client</th><th>Frequency</th><th>Next run</th><th style="text-align:right">Total / run</th><th style="text-align:right">Status</th>'
          + '</tr></thead><tbody>'
          + list.map(r => {
              const t = computeTotals(r.items, r.taxPct, r.discountPct);
              const due = r.active && r.nextDate <= now;
              return '<tr class="gpinv-rowbtn" data-iact="rec-open" data-id="' + escHtml(r.id) + '">'
                + '<td><b>' + (r.clientName ? escHtml(r.clientName) : '<span class="gp-faint">no client</span>') + '</b>'
                + '<div class="gp-faint gpinv-sub">' + r.items.length + ' line item' + (r.items.length === 1 ? '' : 's') + '</div></td>'
                + '<td style="white-space:nowrap">every ' + r.everyN + ' ' + r.unit + '</td>'
                + '<td style="white-space:nowrap">' + fmtDate(r.nextDate) + (due ? ' ' + pill('DUE') : '') + '</td>'
                + '<td style="text-align:right;white-space:nowrap">' + fmtAmt(t.total, r.token) + ' ' + r.token + '</td>'
                + '<td style="text-align:right">' + pill(r.active ? 'ACTIVE' : 'PAUSED') + '</td></tr>'
                + (recOpen === r.id ? '<tr class="gpinv-detail"><td colspan="5">' + recDetailHtml(r) + '</td></tr>' : '');
            }).join('')
          + '</tbody></table></div>'
        : '<div class="gp-empty"><div class="gp-empty-title">No recurring templates yet</div>Create one to bill a client on a schedule. When a run comes due, Generate now creates the invoice and moves the next date forward.</div>');
    afterRender(el);
  }

  // ── tab: SETTINGS (profile, numbering, ENS, CSV) ──
  function renderSettings() {
    const el = mounts.settings;
    if (!el) return;
    const p = loadProfile();
    const accent = p.accentColor || '#fff';
    el.innerHTML =
      '<div class="gpinv-idrow">'
      + '<div class="gpinv-mg" style="border-color:' + escHtml(accent) + '">' + escHtml(monogram(p.name)) + '</div>'
      + '<div><div style="font-weight:700">' + (p.name ? escHtml(p.name) : 'your business') + '</div>'
      + '<div class="gp-muted gpinv-sub">' + (p.contact ? escHtml(p.contact) : 'this profile stamps every invoice, estimate and receipt.') + '</div></div>'
      + '</div>'
      + '<h3 class="gp-h3">Business profile</h3>'
      + '<div class="gp-card">'
      + '<label class="gp-eyebrow" for="gpinv-p-name">Business name</label><input class="gp-input" id="gpinv-p-name" value="' + escHtml(p.name) + '" placeholder="e.g. Ghost Studio">'
      + '<div class="gpinv-gap"><label class="gp-eyebrow" for="gpinv-p-contact">From / contact line</label><input class="gp-input" id="gpinv-p-contact" value="' + escHtml(p.contact) + '" placeholder="e.g. ben@ghoststudio.eth"></div>'
      + '<div class="gpinv-gap"><label class="gp-eyebrow" for="gpinv-p-addr">Address lines (one per line: printed on documents)</label>'
      + '<textarea class="gp-textarea" id="gpinv-p-addr" rows="3" placeholder="1 Ghost Lane&#10;Berlin">' + escHtml(p.addressLines.join('\n')) + '</textarea></div>'
      + '<div class="gpinv-gap"><label class="gp-eyebrow" for="gpinv-p-vat">VAT / tax number (optional: printed under your address)</label><input class="gp-input" id="gpinv-p-vat" value="' + escHtml(p.taxNumber) + '" placeholder="e.g. NL123456789B01"></div>'
      + '<div class="gpinv-grid gpinv-gap">'
      + '<div><label class="gp-eyebrow" for="gpinv-p-token">Default token</label><select class="gp-select" id="gpinv-p-token">'
      + ['USDC', 'ETH'].map(t => '<option' + (p.token === t ? ' selected' : '') + '>' + t + '</option>').join('') + '</select></div>'
      + '<div><label class="gp-eyebrow" for="gpinv-p-tax">Default tax % (optional: prefills every new row rate)</label><input class="gp-input" id="gpinv-p-tax" type="number" min="0" step="any" value="' + (p.taxPct ?? '') + '" placeholder="e.g. 21"></div>'
      + '</div>'
      + '<div class="gpinv-gap"><label class="gp-eyebrow" for="gpinv-p-terms">Default payment terms</label><input class="gp-input" id="gpinv-p-terms" value="' + escHtml(p.terms) + '" placeholder="payment due on receipt"></div>'
      + '<div class="gpinv-gap"><label class="gp-eyebrow" for="gpinv-p-accent">Accent colour (optional hex: stamps printed documents)</label><input class="gp-input" id="gpinv-p-accent" value="' + escHtml(p.accentColor || '') + '" placeholder="#fff · blank = plain black and white"></div>'
      + '<div class="gpinv-gap"><label class="gp-eyebrow" for="gpinv-p-footer">Footer note (printed at the bottom of every document)</label><input class="gp-input" id="gpinv-p-footer" value="' + escHtml(p.footerNote) + '" placeholder="e.g. thank you for your business"></div>'
      + '<div class="gpinv-actions"><button type="button" class="gp-btn primary" data-iact="save-profile">Save profile</button></div>'
      + '<div class="status" id="gpinv-p-st"></div>'
      + '</div>'
      + '<h3 class="gp-h3">Numbering</h3>'
      + '<div class="gp-card"><div class="gpinv-grid">'
      + '<div><label class="gp-eyebrow" for="gpinv-p-prefix">Number prefix</label><input class="gp-input" id="gpinv-p-prefix" value="' + escHtml(p.prefix) + '" placeholder="GP-"></div>'
      + '<div><label class="gp-eyebrow" for="gpinv-p-next">Next number</label><input class="gp-input" id="gpinv-p-next" type="number" min="1" value="' + escHtml(p.next) + '"></div>'
      + '</div>'
      + '<div class="status">Numbers allocate as prefix + zero-padded counter (GP-0001, GP-0002, …). Invoices and estimates share the sequence.</div>'
      + '<div class="gpinv-actions"><button type="button" class="gp-btn primary" data-iact="save-profile">Save numbering</button></div></div>'
      + '<h3 class="gp-h3">Publish to ENS</h3>'
      + '<div class="gp-card">'
      + '<div class="status" style="margin-top:0">Writes a "stealth" text record on your ENS name so senders can resolve it to your stealth meta-address. The meta-address is public by design: anyone can derive fresh payment addresses from it, nobody can spend from it.</div>'
      + '<div class="gpinv-gap"><label class="gp-eyebrow" for="gpinv-ensname">ENS name</label><input class="gp-input" id="gpinv-ensname" placeholder="yourname.eth"></div>'
      + '<div class="gpinv-gap"><label class="gp-eyebrow" for="gpinv-ensresolver">Resolver address</label><input class="gp-input" id="gpinv-ensresolver" value="' + ENS_PUBLIC_RESOLVER + '" placeholder="resolver address"></div>'
      + '<div class="gpinv-actions"><button type="button" class="gp-btn primary" data-iact="ens">Publish to ENS</button></div>'
      + '<div class="status" id="gpinv-ens-st"></div>'
      + '<div class="status">Prefer the web flow: <a id="gpinv-enslink" href="https://app.ens.domains" target="_blank" rel="noopener">open app.ens.domains</a> and set the "stealth" text record yourself.</div>'
      + '</div>'
      + '<h3 class="gp-h3">Export</h3>'
      + '<div class="gp-card">'
      + '<div class="status" style="margin-top:0">Downloads every payment detected this session plus every invoice and estimate as one CSV: dates, amounts, USD values, statuses.</div>'
      + '<div class="gpinv-actions"><button type="button" class="gp-btn" data-iact="export-csv">Export CSV</button></div>'
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
    if (act === 'copy' && rec) { copyBtn(rec.url, el, 'Copy link'); return; }
    if (act === 'remind' && rec) { copyBtn(reminderText(rec, loadProfile()), el, 'Reminder'); return; }
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
      if (accent && !/^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/.test(accent)) { stEl.textContent = 'accent colour must be a hex value like #ffcc00 (or blank).'; return; }
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
      + (i.clientName ? '<div style="margin-top:20px"><div class="muted">Bill to</div><b>' + escHtml(i.clientName) + '</b>'
        + (client && client.contact ? '<div class="muted">' + escHtml(client.contact) + '</div>' : '')
        + clientAddr.map(l => '<div class="muted">' + escHtml(l) + '</div>').join('')
        + (client && client.vatNumber ? '<div class="muted">tax id: ' + escHtml(client.vatNumber) + '</div>' : '')
        + '</div>' : '')
      + '<table><thead><tr><th style="width:44%">Description</th><th class="r">Qty</th><th class="r">Unit price</th>' + (anyDisc ? '<th class="r">Disc</th>' : '') + '<th class="r">Tax</th><th class="r">Amount</th></tr></thead>'
      + '<tbody>' + rows + '</tbody></table>'
      + '<div class="tot"><div>subtotal · ' + fmtAmt(i.subtotal, i.token) + ' ' + i.token + '</div>'
      + (i.discountAmount > 0 ? '<div>discount · −' + fmtAmt(i.discountAmount, i.token) + ' ' + i.token + '</div>' : '')
      + tls.map(tl => '<div>tax ' + tl.rate + '% on ' + fmtAmt(tl.base, i.token) + ' · ' + fmtAmt(tl.amount, i.token) + ' ' + i.token + '</div>').join('')
      + '<div class="grand">total · ' + fmtAmt(i.total, i.token) + ' ' + i.token + '</div></div>'
      + (st === 'PAID' ? '<div style="text-align:right"><span class="stamp">PAID</span></div>' : '')
      + '<div class="pay"><img src="' + qr + '" alt="payment QR"><div>'
      + '<div class="muted">Pay this one-time stealth address</div>'
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
  // The pinned address is unique to the invoice, so its balance is the running sum of
  // everything paid to it: the USDC balance for token invoices (paid via payToken), the
  // ETH balance for ETH invoices, and ETH × price as the legacy fallback for USDC
  // invoices paid before token payments existed. max() keeps the figure across sweeps.
  // Sum below total is PARTIAL, at/over total flips PAID.
  const partialToasted = new Set();
  const usdcBalanceOf = new GP.ethers.Interface(['function balanceOf(address) view returns (uint256)']);
  async function syncPaid(p) {
    const all = loadInv();
    const hit = all.find(i => i.stealthAddress && i.stealthAddress.toLowerCase() === String(p.address).toLowerCase());
    if (!hit) return;
    // balances are best-effort: each reading settles on its own, a failed one stays null
    const settle = pr => pr.then(v => v, () => null);
    const usdc = hit.token !== 'ETH';
    const [balEth, tokenBal] = await Promise.all([
      settle(GP.jrpc('eth_getBalance', [hit.stealthAddress, 'latest']).then(b => Number(GP.fmt.formatEth(BigInt(b))))),
      usdc
        ? settle(GP.jrpc('eth_call', [{ to: USDC_MAINNET, data: usdcBalanceOf.encodeFunctionData('balanceOf', [hit.stealthAddress]) }, 'latest'])
          .then(r => Number(GP.ethers.formatUnits(BigInt(r), 6))))
        : Promise.resolve(null),
    ]);
    // the legacy ETH × price reading is only priced when the token reading is absent
    let px = null;
    if (usdc && !(tokenBal > 0) && balEth > 0) px = await ethUsd();
    const paid = paidFromBalances(hit, { balEth, tokenBal, ethPrice: px });
    if (paid != null) hit.paidAmount = Math.max(hit.paidAmount || 0, paid);
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
// On invoice links the payer also gets the bill itself above the address card: number,
// line items (when the record lives in this browser), totals, due date, expiry state.
// dead-link state for a meta-address that matches the st:eth:0x… shape but is not on
// the curve (deriving, or encrypting a memo against its view key, throws "Point is not
// on curve"). Same markup and copy as the shell's own showInvalidLink, which reasserts
// the state when the inline module's enterPayMode runs after this module's boot.
function showInvalidPayLink(pg) {
  const amt = pg.querySelector('.pg-amt'); if (amt) amt.style.display = 'none';
  pg.querySelectorAll('.cpfield, .pg-reassure, .gpinv-doc').forEach(el => el.style.display = 'none');
  const btn = pg.querySelector('#b-announce'); if (btn) { btn.disabled = true; btn.style.display = 'none'; }
  const ann = pg.querySelector('#v-ann'); if (ann) ann.textContent = '';
  const inv = pg.querySelector('#st-invoice'); if (inv) inv.textContent = '';
  if (pg.querySelector('[data-invalid-link]')) return;
  const d = document.createElement('div');
  d.className = 'gp-empty';
  d.dataset.invalidLink = '1';
  d.innerHTML = '<div class="gp-empty-title">This link is not valid</div>'
    + 'The payment details in it do not check out, so nothing here can be paid. Ask the person who sent it for a fresh link.';
  pg.appendChild(d);
}

function enhancePayghost() {
  const pg = document.getElementById('payghost');
  if (!pg || getComputedStyle(pg).display === 'none') return;
  const metaMatch = location.hash.match(/st:eth:0x[0-9a-fA-F]{132}/);
  if (!metaMatch) return;
  injectFrag(); // the payer document's styles ride in the suite frag (idempotent)
  const C = GP.crypto;
  const $ = id => document.getElementById(id);
  const metaHex = metaMatch[0].slice(7);
  // validate both compressed keys before anything derives from them: a malformed
  // meta-address is a dead link, not a thrown module
  try {
    C.secp256k1.ProjectivePoint.fromHex(C.buf(metaHex).slice(0, 33));
    C.secp256k1.ProjectivePoint.fromHex(C.buf(metaHex).slice(33, 66));
  } catch { showInvalidPayLink(pg); return; }
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
  if (copyAddr) copyAddr.onclick = () => copyBtn(target.stealth, copyAddr, 'Copy address');

  const invId = params.get('inv');
  const invNum = params.get('num');
  const exp = Number(params.get('exp'));
  const hasExp = Number.isFinite(exp) && exp > 0;
  const expired = hasExp && Date.now() > exp;

  // ── the invoice document: what the payer is being asked to pay ──
  // The link carries number/amount/note/expiry only; line items and the bill-to block
  // appear when the record lives in this browser's storage (the issuer opening their
  // own link, e.g. via VIEW LINK). Nothing here changes what the buttons below do.
  const payRaw = params.get('pay') || '';
  const payParts = payRaw.split(' · ');
  const payM = payRaw.match(/^\s*([0-9]+(?:\.[0-9]+)?)\s*([A-Za-z]+)/);
  const amount = payM ? payM[1] : '';
  const token = payM ? payM[2].toUpperCase() : '';
  const note = payParts.length > 1 ? payParts.slice(1).join(' · ') : '';
  const rec = invId ? (loadInv().find(x => x.id === invId) || loadEst().find(x => x.id === invId) || null) : null;
  if (invNum || invId || amount || note || hasExp) {
    let doc = '<div class="gpinv-doc-head">'
      + '<span class="gp-eyebrow">' + (rec && rec.kind === 'estimate' ? 'estimate' : (invNum || invId ? 'invoice' : 'payment request')) + '</span>'
      + (invNum ? '<span class="gpinv-doc-num">' + escHtml(invNum) + '</span>' : '')
      + (expired ? '<span class="gp-pill danger">Expired</span>' : '')
      + '</div>';
    if (rec && rec.clientName) doc += '<div class="gpinv-doc-kv"><span class="gpinv-doc-k">Billed to</span><span>' + escHtml(rec.clientName) + '</span></div>';
    if (rec) {
      doc += '<div class="gp-tablewrap gpinv-doc-items"><table class="gp-table"><thead><tr>'
        + '<th>Description</th><th>Qty</th><th style="text-align:right">Amount</th></tr></thead><tbody>'
        + rec.items.map(it => '<tr><td>' + escHtml(it.description || 'item') + '</td><td>' + escHtml(it.qty) + '</td>'
          + '<td style="text-align:right">' + fmtAmt((parseFloat(it.qty) || 0) * (parseFloat(it.unitPrice) || 0), rec.token) + '</td></tr>').join('')
        + '</tbody></table></div>'
        + '<div class="gpinv-totals gpinv-doc-totals">'
        + '<div class="gpinv-trow"><span>Subtotal</span><span>' + fmtAmt(rec.subtotal, rec.token) + '</span></div>'
        + (rec.discountAmount > 0 ? '<div class="gpinv-trow"><span>Discount</span><span>−' + fmtAmt(rec.discountAmount, rec.token) + '</span></div>' : '')
        + taxLinesOf(rec).map(tl => '<div class="gpinv-trow"><span>Tax ' + tl.rate + '% on ' + fmtAmt(tl.base, rec.token) + '</span><span>' + fmtAmt(tl.amount, rec.token) + '</span></div>').join('')
        + '</div>';
    }
    const amountDisp = token === 'USDC'
      ? Number(amount).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })
      : amount;
    // the shell shows its own amount hero for ETH and USDC links (enterPayMode's
    // .pg-amt), so the document only builds its amount block for other tokens
    if (amount && token !== 'ETH' && token !== 'USDC') {
      doc += '<div class="gpinv-doc-duebox">'
        + '<div class="gp-eyebrow">' + (expired ? 'amount due · invoice expired' : 'amount due') + '</div>'
        + '<div class="gpinv-doc-amount">' + escHtml(amountDisp) + ' <span class="gpinv-doc-token">' + escHtml(token) + '</span></div>'
        + '</div>';
    }
    if (note) doc += '<div class="gpinv-doc-kv"><span class="gpinv-doc-k">Note</span><span>' + escHtml(note) + '</span></div>';
    if (hasExp) doc += '<div class="gpinv-doc-kv"><span class="gpinv-doc-k">' + (expired ? 'Expired' : 'Due') + '</span><span>' + fmtDate(exp) + '</span></div>';
    if (expired) doc += '<div class="gpinv-doc-settle gpinv-doc-expired">This invoice has expired. Do not pay it: ask the issuer for a fresh link.</div>';
    else if (amount && token === 'USDC') doc += '<div class="gpinv-doc-settle">Priced in USDC: paying approves the exact amount and sends it, batched into one confirmation where your wallet supports it, two transactions otherwise. The announcement rides the same call, so the recipient\'s scanner finds the payment.</div>';
    const docEl = document.createElement('div');
    docEl.className = 'gpinv-doc';
    docEl.innerHTML = doc;
    // the bill sits between the shell's invoice line and the payment mechanics
    const anchor = pg.querySelector('.cpfield') || pg.querySelector('.card, .gp-card');
    if (anchor) pg.insertBefore(docEl, anchor); else pg.appendChild(docEl);
  }

  const btn = $('b-announce');
  if (!btn) return;
  const memoInput = document.createElement('input');
  memoInput.id = 'gpinv-memo';
  memoInput.className = 'gp-input';
  memoInput.maxLength = 280;
  memoInput.placeholder = 'optional · encrypted: only the recipient can read it';
  // the invoice note travels in the pay= param and prefills the payer's memo, so it
  // lands in the encrypted announcement memo on payment
  if (payParts.length > 1) memoInput.value = payParts.slice(1).join(' · ').slice(0, 280);
  const memoLbl = document.createElement('label');
  memoLbl.className = 'gp-eyebrow';
  memoLbl.htmlFor = 'gpinv-memo';
  memoLbl.textContent = 'Memo for the recipient';
  const memoWrap = document.createElement('div');
  memoWrap.className = 'gpinv-memo';
  memoWrap.appendChild(memoLbl);
  memoWrap.appendChild(memoInput);
  btn.parentNode.insertBefore(memoWrap, btn);
  if (expired) btn.disabled = true;
  // the label says what the click does: an ETH amount pays and announces in one
  // transaction; a USDC amount approves + pays real USDC (one confirmation where the
  // wallet batches, two transactions otherwise); anything else announces only
  let payValue = 0n;
  const ethM = payRaw.match(/^\s*([0-9]+(?:\.[0-9]+)?)\s*ETH/i);
  if (ethM) { try { payValue = GP.ethers.parseEther(ethM[1]); } catch { payValue = 0n; } }
  const usdcUnits = token === 'USDC' ? parseTokenUnits(amount, 'USDC') : null;
  btn.textContent = payValue > 0n ? 'Pay and announce with my wallet'
    : usdcUnits ? 'Pay ' + amount + ' USDC and announce with my wallet'
    : 'Announce the payment with my wallet';
  // a USDC amount the token cannot carry (over 6 decimals) is a dead link, not an announce
  if (token === 'USDC' && amount && !usdcUnits) {
    btn.disabled = true;
    $('v-ann').textContent = 'Bad USDC amount in this link · ask the issuer for a fresh one.';
  }

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
    // invoice amount: "25 ETH · note" pays via pay(); "25 USDC · note" approves + pays real USDC
    let value = 0n;
    const pm = (params.get('pay') || '').match(/^\s*([0-9]+(?:\.[0-9]+)?)\s*ETH/i);
    if (pm) { try { value = GP.ethers.parseEther(pm[1]); } catch { value = 0n; } }
    const PAA = GP.const && GP.const.PAY_AND_ANNOUNCE;
    const md = metadataHex ? C.buf(metadataHex) : Uint8Array.from([target.viewTag]);
    if (usdcUnits && PAA) {
      // approve + payToken: one confirmation where the wallet batches (EIP-5792), two
      // transactions otherwise. The encrypted memo rides the payToken call's metadata.
      btn.disabled = true;
      const setSt = m => { $('v-ann').textContent = m; };
      try {
        const account = (await GP.state.walletRequest('eth_requestAccounts', []))[0];
        const calls = buildTokenPayCalls({
          ethers: GP.ethers, tokenAddr: USDC_MAINNET, spender: PAA, stealth: target.stealth,
          amountUnits: usdcUnits, ephPub: target.ephPub, metadata: md,
        });
        const res = await sendTokenPayment({
          walletRequest: (m2, p2) => GP.state.walletRequest(m2, p2),
          jrpc: (m2, p2) => GP.jrpc(m2, p2),
          account, calls, say: setSt,
          pollMs: Number(window.GP_PAY_POLL_MS) || 3000,
        });
        setSt('Paid ' + amount + ' USDC and announced' + (res.via === 'batch' ? ' in one confirmation (EIP-5792)' : '')
          + (res.hash ? ' · tx ' + res.hash : (res.confirmed ? '' : ' · submitted, still pending'))
          + (memo ? ' · encrypted memo attached' : ''));
      } catch (e) {
        btn.disabled = false;
        setSt(tokenPayErrorText(e));
      }
      return;
    }
    if (PAA) {
      // one transaction: payment + announcement + (optional) encrypted memo via PayAndAnnounce
      try {
        $('v-ann').textContent = 'paying + announcing in one transaction…';
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
