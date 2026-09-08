// test-commitment.mjs — proves the browser code path (vendor/*.mjs, the exact files
// index.html imports) reproduces commitments the real withdrawal flows accept.
//
//   node test-commitment.mjs
//
// 1. Privacy Pools: poseidon2(nullifier, secret) from the vendored module must
//    reproduce the precommitment in the known-good pp-secret.json, and match the
//    original poseidon-lite install in ept-privacy-pools.
// 2. Tornado Cash: the vendored pedersen implementation must match canonical
//    circomlibjs (what tornado-cli/circomlib use) on fixed and random notes,
//    and the note-string round-trip (parse -> recompute) must hold.
import { readFileSync } from 'fs';
import { randomBytes } from 'crypto';
import { poseidon2 } from './vendor/poseidon2.mjs';
import { pedersenCommitmentX } from './vendor/tc-pedersen.mjs';

let pass = 0, fail = 0;
const check = (name, cond) => {
  if (cond) { pass++; console.log('  ok  ' + name); }
  else { fail++; console.log(' FAIL ' + name); }
};

// ─── Privacy Pools: pp-secret.json known-good vector ───
const secret = JSON.parse(readFileSync(new URL('./pp-secret.json', import.meta.url), 'utf8'));
const n = BigInt(secret.nullifier);
const s = BigInt(secret.secret);
check('nullifier is 31 bytes', secret.nullifier.length === 2 + 62);
check('secret is 31 bytes', secret.secret.length === 2 + 62);
const pre = poseidon2([n, s]);
const preHex = '0x' + pre.toString(16).padStart(64, '0');
check('pp-secret.json precommitment reproduced: ' + preHex, preHex === secret.precommitment.toLowerCase());

// cross-check against the original poseidon-lite in ept-privacy-pools (skipped if that
// project is not on disk; the pp-secret.json vector above is the authoritative check)
try {
  const { poseidon2: refPoseidon2 } = await import('/Users/benrenshaw/ept-privacy-pools/node_modules/poseidon-lite/poseidon2.js');
  check('vendored poseidon2 === poseidon-lite (pp-secret vector)', refPoseidon2([n, s]) === pre);
  const r1 = BigInt('0x' + randomBytes(31).toString('hex'));
  const r2 = BigInt('0x' + randomBytes(31).toString('hex'));
  check('vendored poseidon2 === poseidon-lite (random)', refPoseidon2([r1, r2]) === poseidon2([r1, r2]));
} catch {
  console.log('  ..  ept-privacy-pools not found: skipping poseidon-lite cross-check');
}

// ─── Tornado Cash: vendored pedersen === circomlibjs ───
// circomlibjs is the canonical reference (tornado-cli uses circomlib, same algorithm).
// Installed locally with `npm install --no-save circomlibjs@0.1.7`; if it is missing the
// reference cross-checks are skipped (the note-format self-checks below still run).
let refCommitment = null;
try {
  const { buildPedersenHash, buildBabyjub } = await import('circomlibjs');
  const babyJub = await buildBabyjub();
  const ped = await buildPedersenHash();
  refCommitment = (buf) => babyJub.F.toObject(babyJub.unpackPoint(ped.hash(buf))[0]);
} catch {
  console.log('  ..  circomlibjs not installed: skipping pedersen reference cross-check');
}

if (refCommitment) {
  // fixed vector: nullifier = 0x01.., secret = 0x02.. (LE byte layout as in the note string)
  const fixed = Buffer.concat([Buffer.alloc(31, 1), Buffer.alloc(31, 2)]);
  check('pedersen fixed vector === circomlibjs', pedersenCommitmentX(new Uint8Array(fixed)) === refCommitment(fixed));

  let allOk = true;
  for (let i = 0; i < 20; i++) {
    const buf = new Uint8Array(randomBytes(62));
    if (pedersenCommitmentX(buf) !== refCommitment(Buffer.from(buf))) allOk = false;
  }
  check('pedersen 20 random notes === circomlibjs', allOk);
}

// note-string round trip: build `tornado-eth-0.1-1-0x<124hex>`, parse it back the way
// parseNote in tornado-cli does (LE interpretation), recompute the commitment.
const bufHex = (b) => [...b].map(x => x.toString(16).padStart(2, '0')).join('');
const noteBytes = new Uint8Array(randomBytes(62));
const noteString = 'tornado-eth-0.1-1-0x' + bufHex(noteBytes);
const m = /tornado-(?<currency>\w+)-(?<amount>[\d.]+)-(?<netId>\d+)-0x(?<note>[0-9a-fA-F]{124})/.exec(noteString);
check('note string matches tornado-cli regex', !!m && m.groups.currency === 'eth' && m.groups.amount === '0.1' && m.groups.netId === '1');
const parsed = Uint8Array.from(m.groups.note.match(/../g).map(h => parseInt(h, 16)));
check('note round trip: parsed commitment === deposited commitment', pedersenCommitmentX(parsed) === pedersenCommitmentX(noteBytes));
const commitHex = '0x' + pedersenCommitmentX(noteBytes).toString(16).padStart(64, '0');
check('commitment is bytes32', commitHex.length === 66);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
