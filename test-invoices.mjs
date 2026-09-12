// test-invoices.mjs · node smoke test for the invoice suite pure helpers in
// gp-invoices.mjs and gp-reports.mjs (no DOM, no network). Covers: v1/v2/v3 → v4
// migration (idempotent), v4 totals math (per-line tax grouping, per-line discount,
// exact rounding rules), PARTIAL/OVERDUE derivation, recurring nextDate advance,
// tax report aggregation, reminder text.
//
//   node test-invoices.mjs
import {
  DEFAULT_PROFILE, computeTotals, taxLinesOf, allocateNumber, invStatus, paymentState,
  migrateProfile, migrateInvoice, migrateRegistry, nextRecurrence, reminderText,
} from './gp-invoices.mjs';
import { taxReport } from './gp-reports.mjs';

let pass = 0, fail = 0;
const check = (name, cond) => {
  if (cond) { pass++; console.log('  ok  ' + name); }
  else { fail++; console.log(' FAIL ' + name); }
};

// ─── totals v4: legacy callers (uniform default rates) get the v3 numbers ───
const items = [
  { description: 'design', qty: 2, unitPrice: 100 },
  { description: 'hosting', qty: 1, unitPrice: 50 },
];
const t1 = computeTotals(items, 20, 10);
check('subtotal sums qty × unitPrice', t1.subtotal === 250);
check('discount 10% of subtotal', t1.discountAmount === 25 && t1.discountPct === 10);
check('tax 20% on discounted 225', t1.taxAmount === 45 && t1.taxPct === 20);
check('total = 250 − 25 + 45', t1.total === 270);
check('uniform default rate yields one tax line', t1.taxLines.length === 1 && t1.taxLines[0].rate === 20 && t1.taxLines[0].base === 225 && t1.taxLines[0].amount === 45);
const t2 = computeTotals(items, null, null);
check('no tax/discount: null pct, zero amounts, total = subtotal, no tax lines',
  t2.taxPct === null && t2.discountPct === null && t2.taxAmount === 0 && t2.discountAmount === 0 && t2.total === 250 && t2.taxLines.length === 0);
const t3 = computeTotals(items, 0, 0);
check('zero pct behaves like blank', t3.taxPct === null && t3.discountPct === null && t3.total === 250 && t3.taxLines.length === 0);
const t4 = computeTotals([{ description: 'x', qty: 3, unitPrice: 0.1 }], null, null);
check('float dust rounds to cents', t4.subtotal === 0.3 && t4.total === 0.3);

// ─── totals v4: two tax rates on one invoice ───
const two = computeTotals([
  { description: 'books', qty: 1, unitPrice: 100, taxPct: 9 },
  { description: 'design', qty: 1, unitPrice: 200, taxPct: 21 },
], null, null);
check('two rates: tax lines sorted by rate with own bases',
  two.taxLines.length === 2
  && two.taxLines[0].rate === 9 && two.taxLines[0].base === 100 && two.taxLines[0].amount === 9
  && two.taxLines[1].rate === 21 && two.taxLines[1].base === 200 && two.taxLines[1].amount === 42);
check('two rates: taxAmount and total aggregate the groups', two.taxAmount === 51 && two.subtotal === 300 && two.total === 351);
check('two rates: invoice-level taxPct stays null (per-line only)', two.taxPct === null);

// ─── totals v4: per-line discount comes off before the rate group base ───
const disc = computeTotals([{ description: 'hosting', qty: 2, unitPrice: 50, taxPct: 21, discountPct: 10 }], null, null);
check('per-line discount: base is the discounted net', disc.subtotal === 100 && disc.discountAmount === 10
  && disc.taxLines.length === 1 && disc.taxLines[0].base === 90 && disc.taxLines[0].amount === 18.9 && disc.total === 108.9);

// ─── totals v4: exact rounding (round each line, then sum; tax per rate group) ───
const cents = computeTotals([
  { description: 'a', qty: 1, unitPrice: 0.33, taxPct: 20, discountPct: 10 },
  { description: 'b', qty: 1, unitPrice: 0.33, taxPct: 20, discountPct: 10 },
  { description: 'c', qty: 1, unitPrice: 0.33, taxPct: 20, discountPct: 10 },
], null, null);
check('rounding: each line discount rounds on its own (0.03 × 3, not 0.10 once)',
  cents.discountAmount === 0.09 && cents.subtotal === 0.99);
check('rounding: group base sums rounded nets, tax rounds once per group',
  cents.taxLines[0].base === 0.9 && cents.taxLines[0].amount === 0.18 && cents.total === 1.08);

// ─── totals v4: default rates apply only to lines without an own rate ───
const mixed = computeTotals([
  { description: 'own', qty: 1, unitPrice: 100, taxPct: 9 },
  { description: 'inherits', qty: 1, unitPrice: 100 },
], 21, null);
check('default rate fills only the lines without one',
  mixed.taxLines.length === 2 && mixed.taxLines[0].rate === 9 && mixed.taxLines[1].rate === 21 && mixed.taxAmount === 30);
const zeroRated = computeTotals([{ description: 'free', qty: 1, unitPrice: 100, taxPct: 0 }], 21, null);
check('explicit 0% line stays untaxed even with a default rate', zeroRated.taxLines.length === 0 && zeroRated.total === 100);

// ─── v1 → v4 migration ───
const v1 = { id: 'inv-old', amount: 42.5, token: 'USDC', note: 'old link', stealthAddress: '0xabc', created: 1000, url: 'https://x/#y', status: 'UNPAID', expiry: null };
const m1 = migrateInvoice(v1, 'GP-0001', 'invoice');
check('v1: v flag is 4', m1.v === 4);
check('v1: amount becomes a single line item', m1.items.length === 1 && m1.items[0].unitPrice === 42.5 && m1.items[0].qty === 1);
check('v1: line gains explicit 0% rate and null discount', m1.items[0].taxPct === 0 && m1.items[0].discountPct === null);
check('v1: UNPAID becomes SENT', m1.status === 'SENT');
check('v1: number assigned', m1.number === 'GP-0001');
check('v1: v3/v4 fields defaulted',
  m1.discountPct === null && m1.discountAmount === 0 && m1.paidAmount === null && m1.estimateOf === null && m1.kind === 'invoice' && Array.isArray(m1.taxLines) && m1.taxLines.length === 0);
check('v1: totals recomputed', m1.subtotal === 42.5 && m1.total === 42.5);

// ─── v2 → v4 migration: fields carry over, additions defaulted ───
const v2 = {
  v: 2, id: 'inv-2', number: 'GP-0007', clientId: 'cl-1', clientName: 'Ada',
  items: [{ description: 'audit', qty: 1, unitPrice: 900 }], token: 'ETH',
  subtotal: 900, taxPct: 20, taxAmount: 180, total: 1080,
  note: 'n', stealthAddress: '0xdef', created: 2000, url: 'https://x/#z', expiry: 3000,
  status: 'PAID', sentAt: 2100, paidAt: 2200, paidTx: '0xtx',
};
const m2 = migrateInvoice(v2, null, 'invoice');
check('v2: fields carry over', m2.number === 'GP-0007' && m2.total === 1080 && m2.taxPct === 20 && m2.status === 'PAID' && m2.paidTx === '0xtx');
check('v2: v4 additions defaulted', m2.v === 4 && m2.discountPct === null && m2.discountAmount === 0 && m2.paidAmount === null && m2.estimateOf === null && m2.kind === 'invoice');
check('v2: tax line synthesized from the stored totals (issued numbers never shift)',
  m2.taxLines.length === 1 && m2.taxLines[0].rate === 20 && m2.taxLines[0].base === 900 && m2.taxLines[0].amount === 180);
check('v2: line items inherit the legacy invoice-level rate', m2.items[0].taxPct === 20);
const est = migrateInvoice({ ...v2, status: 'UNPAID' }, null, 'estimate');
check('estimate kind: status vocabulary + kind', est.kind === 'estimate' && est.status === 'SENT');

// ─── v3 → v4 migration: totals preserved, lines seeded, idempotent ───
const v3rec = {
  v: 3, id: 'inv-3', number: 'GP-0009', clientId: null, clientName: '',
  items: [{ description: 'audit', qty: 1, unitPrice: 500 }, { description: 'fix', qty: 1, unitPrice: 100 }],
  token: 'USDC', subtotal: 600, taxPct: 21, taxAmount: 126,
  discountPct: null, discountAmount: 0, total: 726,
  note: '', stealthAddress: '0x123', created: 5000, url: 'https://x/#q', expiry: null,
  status: 'SENT', sentAt: 5100, paidAt: null, paidTx: null, paidAmount: null,
  estimateOf: null, kind: 'invoice',
};
const m3 = migrateInvoice(v3rec, null, 'invoice');
check('v3: v flag is 4, stored totals untouched', m3.v === 4 && m3.subtotal === 600 && m3.taxAmount === 126 && m3.total === 726);
check('v3: every line seeded with the invoice-level rate', m3.items.every(it => it.taxPct === 21 && it.discountPct === null));
check('v3: one synthesized tax line matching the issued document',
  m3.taxLines.length === 1 && m3.taxLines[0].rate === 21 && m3.taxLines[0].base === 600 && m3.taxLines[0].amount === 126);
check('v3 → v4 idempotent: second pass returns the same object', migrateInvoice(m3, null, 'invoice') === m3);

// ─── taxLinesOf: stored lines win, legacy fallback, junk dropped ───
check('taxLinesOf: v4 stored lines pass through', taxLinesOf(m3)[0].amount === 126);
check('taxLinesOf: legacy record falls back to its invoice-level rate', taxLinesOf({ items: [], taxPct: 20, discountPct: null, subtotal: 50, discountAmount: 0 })[0].rate === 20);
check('taxLinesOf: nonpositive rates and junk lines drop out',
  taxLinesOf({ taxLines: [{ rate: 0, base: 10, amount: 0 }, { rate: 'x', base: 1, amount: 1 }, { rate: 9, base: 100, amount: 9 }] }).length === 1);
check('taxLinesOf: no rates anywhere means no lines', taxLinesOf({ items: [{ qty: 1, unitPrice: 10 }] }).length === 0);

// ─── idempotency: v4 records pass through untouched ───
const once = migrateRegistry([v1, v2], { ...DEFAULT_PROFILE, next: 10 }, 'invoice');
check('registry: two records migrated', once.records.length === 2 && once.records.every(r => r.v === 4));
check('registry: numbers in creation order', once.records[0].number === 'GP-0010' && once.records[1].number === 'GP-0007');
check('registry: counter advances only for records that needed a number (v2 keeps its own, burns nothing)', once.profile.next === 11);
const twice = migrateRegistry(once.records, once.profile, 'invoice');
check('idempotent: second pass changes nothing and does not burn numbers',
  twice.records.every((r, i) => r === once.records[i]) && twice.profile.next === 11);
check('idempotent: profile migration stable', JSON.stringify(migrateProfile(once.profile)) === JSON.stringify(once.profile));
const p3 = migrateProfile({ name: 'X', token: 'ETH' });
check('profile: v4 fields defaulted', Array.isArray(p3.addressLines) && p3.addressLines.length === 0 && p3.accentColor === null && p3.footerNote === '' && p3.token === 'ETH' && p3.taxNumber === '');
check('profile: VAT/tax number kept when present', migrateProfile({ taxNumber: 'NL123456789B01' }).taxNumber === 'NL123456789B01');

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

// ─── tax report: per-rate aggregation over PAID + SENT invoices in range ───
const day = 86400000;
const t0 = new Date('2026-09-01T00:00:00').getTime();
const mkInv = (over) => ({
  kind: 'invoice', status: 'SENT', token: 'USDC', created: t0 + day,
  total: 0, paidAmount: null, expiry: null, ...over,
});
const repRecs = [
  mkInv({ number: 'A', taxLines: [{ rate: 9, base: 100, amount: 9 }, { rate: 21, base: 200, amount: 42 }] }),
  mkInv({ number: 'B', status: 'PAID', taxLines: [{ rate: 21, base: 50, amount: 10.5 }] }),
  mkInv({ number: 'C', status: 'DRAFT', taxLines: [{ rate: 21, base: 999, amount: 209.79 }] }),        // excluded: draft
  mkInv({ number: 'D', created: t0 - 40 * day, taxLines: [{ rate: 21, base: 999, amount: 209.79 }] }), // excluded: out of range
  mkInv({ number: 'E', kind: 'estimate', taxLines: [{ rate: 21, base: 999, amount: 209.79 }] }),       // excluded: estimate
  mkInv({ number: 'F', expiry: t0 - day, taxLines: [{ rate: 9, base: 10, amount: 0.9 }] }),            // OVERDUE counts
  mkInv({ number: 'G', taxLines: [] }),                                                                // untaxed: no row
  mkInv({ number: 'H', token: 'ETH', taxLines: [{ rate: 21, base: 1, amount: 0.21 }] }),               // per-token sums
];
const rep = taxReport(repRecs, t0, t0 + 10 * day, t0 + 5 * day);
check('tax report: one row per rate, sorted', rep.length === 2 && rep[0].rate === 9 && rep[1].rate === 21);
check('tax report: 9% base/tax aggregate SENT + OVERDUE', rep[0].base.USDC === 110 && rep[0].tax.USDC === 9.9);
check('tax report: 21% base/tax aggregate SENT + PAID, drafts/estimates/out-of-range excluded',
  rep[1].base.USDC === 250 && rep[1].tax.USDC === 52.5);
check('tax report: tokens stay separate', rep[1].base.ETH === 1 && rep[1].tax.ETH === 0.21);
check('tax report: empty range yields no rows', taxReport(repRecs, t0 + 20 * day, t0 + 30 * day, t0 + 25 * day).length === 0);
check('tax report: legacy invoice-level rate aggregates via fallback',
  taxReport([{ kind: 'invoice', status: 'PAID', token: 'USDC', created: t0, total: 60, subtotal: 50, discountAmount: 0, taxPct: 20, taxAmount: 10 }], t0 - day, t0 + day, t0)[0].base.USDC === 50);

// ─── reminder text: short, polite, payment link, no em dashes ───
const remRec = { number: 'GP-0007', clientName: 'Ada', total: 351, token: 'USDC', expiry: t0, url: 'https://x/#y?pay=351' };
const rem = reminderText(remRec, { name: 'Ghost Studio' });
check('reminder: names the client, invoice, amount and due date',
  rem.includes('Ada') && rem.includes('GP-0007') && rem.includes('351.00 USDC') && rem.includes(new Date(t0).toISOString().slice(0, 10)));
check('reminder: carries the payment link and signs off with the profile name',
  rem.includes('pay here: https://x/#y?pay=351') && rem.trimEnd().endsWith('Ghost Studio'));
check('reminder: no expiry means no due clause', reminderText({ ...remRec, expiry: null }, {}).includes('is still open.') && !reminderText({ ...remRec, expiry: null }, {}).includes('due on'));
check('reminder: no em dashes anywhere', !rem.includes('—'));

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
