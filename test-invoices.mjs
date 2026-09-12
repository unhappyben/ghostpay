// test-invoices.mjs — node smoke test for the invoice suite pure helpers in
// gp-invoices.mjs (no DOM, no network). Covers: v1/v2 → v3 migration (idempotent),
// totals with tax + discount, PARTIAL/OVERDUE derivation, recurring nextDate advance.
//
//   node test-invoices.mjs
import {
  DEFAULT_PROFILE, computeTotals, allocateNumber, invStatus, paymentState,
  migrateProfile, migrateInvoice, migrateRegistry, nextRecurrence,
} from './gp-invoices.mjs';

let pass = 0, fail = 0;
const check = (name, cond) => {
  if (cond) { pass++; console.log('  ok  ' + name); }
  else { fail++; console.log(' FAIL ' + name); }
};

// ─── totals: discount comes off first, tax applies to the discounted amount ───
const items = [
  { description: 'design', qty: 2, unitPrice: 100 },
  { description: 'hosting', qty: 1, unitPrice: 50 },
];
const t1 = computeTotals(items, 20, 10);
check('subtotal sums qty × unitPrice', t1.subtotal === 250);
check('discount 10% of subtotal', t1.discountAmount === 25 && t1.discountPct === 10);
check('tax 20% on discounted 225', t1.taxAmount === 45 && t1.taxPct === 20);
check('total = 250 − 25 + 45', t1.total === 270);
const t2 = computeTotals(items, null, null);
check('no tax/discount: null pct, zero amounts, total = subtotal',
  t2.taxPct === null && t2.discountPct === null && t2.taxAmount === 0 && t2.discountAmount === 0 && t2.total === 250);
const t3 = computeTotals(items, 0, 0);
check('zero pct behaves like blank', t3.taxPct === null && t3.discountPct === null && t3.total === 250);
const t4 = computeTotals([{ description: 'x', qty: 3, unitPrice: 0.1 }], null, null);
check('float dust rounds to cents', t4.subtotal === 0.3 && t4.total === 0.3);

// ─── v1 → v3 migration ───
const v1 = { id: 'inv-old', amount: 42.5, token: 'USDC', note: 'old link', stealthAddress: '0xabc', created: 1000, url: 'https://x/#y', status: 'UNPAID', expiry: null };
const m1 = migrateInvoice(v1, 'GP-0001', 'invoice');
check('v1: v flag is 3', m1.v === 3);
check('v1: amount becomes a single line item', m1.items.length === 1 && m1.items[0].unitPrice === 42.5 && m1.items[0].qty === 1);
check('v1: UNPAID becomes SENT', m1.status === 'SENT');
check('v1: number assigned', m1.number === 'GP-0001');
check('v1: v3 fields defaulted',
  m1.discountPct === null && m1.discountAmount === 0 && m1.paidAmount === null && m1.estimateOf === null && m1.kind === 'invoice');
check('v1: totals recomputed', m1.subtotal === 42.5 && m1.total === 42.5);

// ─── v2 → v3 migration: fields carry over, additions defaulted ───
const v2 = {
  v: 2, id: 'inv-2', number: 'GP-0007', clientId: 'cl-1', clientName: 'Ada',
  items: [{ description: 'audit', qty: 1, unitPrice: 900 }], token: 'ETH',
  subtotal: 900, taxPct: 20, taxAmount: 180, total: 1080,
  note: 'n', stealthAddress: '0xdef', created: 2000, url: 'https://x/#z', expiry: 3000,
  status: 'PAID', sentAt: 2100, paidAt: 2200, paidTx: '0xtx',
};
const m2 = migrateInvoice(v2, null, 'invoice');
check('v2: fields carry over', m2.number === 'GP-0007' && m2.total === 1080 && m2.taxPct === 20 && m2.status === 'PAID' && m2.paidTx === '0xtx');
check('v2: v3 additions defaulted', m2.v === 3 && m2.discountPct === null && m2.discountAmount === 0 && m2.paidAmount === null && m2.estimateOf === null && m2.kind === 'invoice');
const est = migrateInvoice({ ...v2, status: 'UNPAID' }, null, 'estimate');
check('estimate kind: status vocabulary + kind', est.kind === 'estimate' && est.status === 'SENT');

// ─── idempotency: v3 records pass through untouched ───
const once = migrateRegistry([v1, v2], { ...DEFAULT_PROFILE, next: 10 }, 'invoice');
check('registry: two records migrated', once.records.length === 2 && once.records.every(r => r.v === 3));
check('registry: numbers in creation order', once.records[0].number === 'GP-0010' && once.records[1].number === 'GP-0007');
check('registry: counter advanced past every legacy record (v2 keeps its number but still burns one)', once.profile.next === 12);
const twice = migrateRegistry(once.records, once.profile, 'invoice');
check('idempotent: second pass changes nothing and does not burn numbers',
  twice.records.every((r, i) => r === once.records[i]) && twice.profile.next === 12);
check('idempotent: profile migration stable', JSON.stringify(migrateProfile(once.profile)) === JSON.stringify(once.profile));
const p3 = migrateProfile({ name: 'X', token: 'ETH' });
check('profile: v3 fields defaulted', Array.isArray(p3.addressLines) && p3.addressLines.length === 0 && p3.accentColor === null && p3.footerNote === '' && p3.token === 'ETH');

// ─── status derivation: PARTIAL / OVERDUE / PAID ───
const now = 1_000_000;
const sent = { kind: 'invoice', status: 'SENT', total: 100, paidAmount: null, expiry: null };
check('plain SENT stays SENT', invStatus(sent, now) === 'SENT');
check('PARTIAL: payments below total', invStatus({ ...sent, paidAmount: 40 }, now) === 'PARTIAL');
check('PAID derived: payments reach total', invStatus({ ...sent, paidAmount: 100 }, now) === 'PAID');
check('PAID derived: overpayment counts', invStatus({ ...sent, paidAmount: 120 }, now) === 'PAID');
check('stored PAID is terminal', invStatus({ ...sent, status: 'PAID', paidAmount: null, expiry: now - 1 }, now) === 'PAID');
check('OVERDUE: SENT past expiry, unpaid', invStatus({ ...sent, expiry: now - 1 }, now) === 'OVERDUE');
check('PARTIAL beats OVERDUE: money in hand shows first', invStatus({ ...sent, paidAmount: 10, expiry: now - 1 }, now) === 'PARTIAL');
check('DRAFT past expiry stays DRAFT', invStatus({ kind: 'invoice', status: 'DRAFT', total: 100, paidAmount: null, expiry: now - 1 }, now) === 'DRAFT');
check('explicit paidSum argument wins', invStatus(sent, now, 55) === 'PARTIAL' && paymentState(sent, 100) === 'PAID');
check('estimate: ACCEPTED/DECLINED terminal, SENT past expiry OVERDUE',
  invStatus({ kind: 'estimate', status: 'ACCEPTED', expiry: now - 1 }, now) === 'ACCEPTED'
  && invStatus({ kind: 'estimate', status: 'DECLINED' }, now) === 'DECLINED'
  && invStatus({ kind: 'estimate', status: 'SENT', expiry: now - 1 }, now) === 'OVERDUE');

// ─── recurring: nextDate advance, weeks + months ───
const d0 = new Date('2026-09-12T12:00:00Z').getTime();
const w2 = nextRecurrence(d0, 2, 'weeks');
check('weeks: +14 days', w2 - d0 === 14 * 86400000);
const m1n = nextRecurrence(d0, 1, 'months');
check('months: +1 calendar month', new Date(m1n).toISOString().slice(0, 10) === '2026-10-12');
const jan31 = new Date('2026-01-31T12:00:00Z').getTime();
check('months: jan 31 clamps into feb (no skip to march)', new Date(nextRecurrence(jan31, 1, 'months')).getMonth() === 1);
check('garbage interval falls back to one unit', nextRecurrence(d0, 0, 'weeks') - d0 === 7 * 86400000);
// GENERATE NOW advances exactly one period, so a backlog catches up one run at a time
let nd = new Date('2026-06-01T00:00:00Z').getTime();
nd = nextRecurrence(nd, 1, 'months');
check('advance after generate is exactly one period', new Date(nd).toISOString().slice(0, 10) === '2026-07-01');

// ─── numbering ───
const a = allocateNumber({ prefix: 'GS-', next: 9 });
check('number = prefix + zero-padded counter', a.number === 'GS-0009' && a.next === 10);
check('bad profile falls back to GP-0001', allocateNumber({}).number === 'GP-0001');

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
