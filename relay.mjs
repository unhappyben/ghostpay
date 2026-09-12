#!/usr/bin/env node
// relay.mjs — broadcast a signed sweep artifact from ghostpay's sweep tab.
// The relayer (you, running this) pays the gas. The stealth EOA never needs funding.
// Fees are tracked server-side: serve.mjs logs every fee-bearing broadcast to fees.jsonl
// (see fees.mjs). This CLI stays a dumb broadcaster and writes no ledger entries itself.
//
//   RUNNER_PK=0x… node relay.mjs artifact.json [--rpc https://eth.drpc.org]
//
// artifact kinds:
//   eip3009        — executes USDC transferWithAuthorization (gasless for the EOA)
//   eip7702-sweep  — type-4 tx: stealth EOA delegates to Sweeper.sol, sweeper moves the funds
//   eip7702-intent — type-4 tx: executeSweep(intent, sig) on the stealth EOA delegated to
//                    SweeperV2. Needs SWEEPER_V2 set; the EIP-712 intent is verified first.
//   eip7702-intent-batch — one type-4 tx to BatchRelayer.relay sweeping up to 20 stealth
//                    EOAs. Needs BATCH_RELAYER set; a single batch tx links the swept
//                    addresses onchain.
import { readFileSync } from 'fs';
import { ethers } from 'ethers';

// type-4 (EIP-7702) txs and authorizationList only exist in ethers >= 6.14.
// On 6.13.x, Transaction.from({type:4}) throws "unsupported transaction type", and
// worse: without an explicit type the authorizationList is SILENTLY dropped, so the
// sweep executes against an undelegated EOA and moves nothing.
{
  const [maj, min] = ethers.version.split('.').map(Number);
  if (maj < 6 || (maj === 6 && min < 14)) {
    console.error('relay.mjs needs ethers >= 6.14 for EIP-7702 (type-4) txs; found', ethers.version, '. Fix: npm install ethers@^6.14');
    process.exit(1);
  }
}

if (!process.argv[2] || process.argv[2].startsWith('--')) {
  console.error('usage: RUNNER_PK=0x… node relay.mjs artifact.json [--rpc URL]');
  process.exit(1);
}
const artifact = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const rpcIdx = process.argv.indexOf('--rpc');
const RPC = rpcIdx > -1 ? process.argv[rpcIdx + 1] : 'https://eth.drpc.org';
const pk = process.env.RUNNER_PK;
if (!pk) { console.error('set RUNNER_PK'); process.exit(1); }

const provider = new ethers.JsonRpcProvider(RPC, artifact.chainId);
const runner = new ethers.Wallet(pk, provider);
console.log('relayer:', runner.address, '| chain:', artifact.chainId);

// ── SweeperV2 intents: EIP-712 SweepIntent signed by the stealth key (mirrors serve.mjs) ──
const MIN_FEE_BPS = Number.isFinite(parseInt(process.env.MIN_FEE_BPS, 10)) ? parseInt(process.env.MIN_FEE_BPS, 10) : 30;
const INTENT_TYPES = { SweepIntent: [
  { name: 'action', type: 'uint8' },
  { name: 'token', type: 'address' },
  { name: 'destination', type: 'address' },
  { name: 'precommitment', type: 'uint256' },
  { name: 'feeBps', type: 'uint256' },
  { name: 'deadline', type: 'uint256' },
] };
// tuple components are named so encodeFunctionData accepts an intent object; the selector
// (0x89cb3125) is identical to the unnamed-components ABI since names never enter the canonical type.
const SWEEPER_IFACE = new ethers.Interface(['function executeSweep((uint8 action,address token,address destination,uint256 precommitment,uint256 feeBps,uint256 deadline) intent, bytes sig)']);
const BATCH_IFACE = new ethers.Interface(['function relay(address[] targets, bytes[] datas)']);

// ethers does not treat a bare {chainId,address,nonce,yParity,r,s} object as
// carrying the signature — it serializes r/s as ZERO. Wrap it explicitly.
function wrapAuthorization(a) {
  return {
    chainId: a.chainId,
    address: a.address,
    nonce: a.nonce,
    signature: ethers.Signature.from({ r: a.r, s: a.s, yParity: a.yParity }),
  };
}

// preflight: the intent must be signed by the stealth key itself, unexpired, and pay the fee floor.
function verifyIntent(sweep) {
  const fail = msg => { console.error('intent verification failed:', msg); process.exit(1); };
  if (!sweep || !ethers.isAddress(sweep.stealthAddress)) fail('bad stealthAddress');
  if (!sweep.intent || typeof sweep.intent !== 'object') fail('missing intent');
  let digest;
  try {
    digest = ethers.TypedDataEncoder.hash(
      { name: 'GhostpaySweeper', version: '1', chainId: 1, verifyingContract: sweep.stealthAddress },
      INTENT_TYPES, sweep.intent);
  } catch (e) { fail('bad intent: ' + e.message); }
  let recovered;
  try { recovered = ethers.recoverAddress(digest, sweep.signature); }
  catch { fail('bad intent signature'); }
  if (recovered.toLowerCase() !== sweep.stealthAddress.toLowerCase()) {
    fail(`signer ${recovered} does not match stealthAddress ${sweep.stealthAddress}`);
  }
  if (BigInt(sweep.intent.deadline) <= BigInt(Math.floor(Date.now() / 1000))) fail('deadline has passed — sign a fresh sweep in the app');
  if (BigInt(sweep.intent.feeBps) < BigInt(MIN_FEE_BPS)) fail(`feeBps ${sweep.intent.feeBps} is below the relayer minimum of ${MIN_FEE_BPS}`);
}

if (artifact.kind === 'eip3009') {
  const usdc = new ethers.Contract(artifact.token, [
    'function transferWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, uint8 v, bytes32 r, bytes32 s)'],
    runner);
  const sig = ethers.Signature.from(artifact.signature);
  const tx = await usdc.transferWithAuthorization(
    artifact.from, artifact.to, artifact.value, artifact.validAfter, artifact.validBefore, artifact.nonce,
    sig.v, sig.r, sig.s);
  console.log('sent:', tx.hash);
  await tx.wait();
  console.log('confirmed. swept', ethers.formatUnits(artifact.value, 6), 'USDC →', artifact.to);
} else if (artifact.kind === 'eip7702-sweep') {
  const authorization = wrapAuthorization(artifact.authorization);
  const fee = await provider.getFeeData();
  const tx = await runner.sendTransaction({
    type: 4,
    chainId: artifact.chainId,
    to: artifact.stealthAddress,
    data: artifact.data,
    authorizationList: [authorization],
    maxFeePerGas: fee.maxFeePerGas * 2n,
    maxPriorityFeePerGas: fee.maxPriorityFeePerGas * 2n,
  });
  console.log('sent:', tx.hash);
  await tx.wait();
  console.log('confirmed. swept', artifact.stealthAddress, 'via sweeper', artifact.sweeper);
  if (artifact.precommitment) console.log('REMINDER for the owner — Privacy Pools precommitment:', artifact.precommitment);
} else if (artifact.kind === 'eip7702-intent') {
  if (!process.env.SWEEPER_V2) { console.error('set SWEEPER_V2 to relay eip7702-intent artifacts'); process.exit(1); }
  verifyIntent(artifact);
  const data = SWEEPER_IFACE.encodeFunctionData('executeSweep', [artifact.intent, artifact.signature]);
  const fee = await provider.getFeeData();
  const tx = await runner.sendTransaction({
    type: 4,
    chainId: artifact.chainId,
    to: artifact.stealthAddress,
    data,
    authorizationList: [wrapAuthorization(artifact.authorization)],
    maxFeePerGas: fee.maxFeePerGas * 2n,
    maxPriorityFeePerGas: fee.maxPriorityFeePerGas * 2n,
  });
  console.log('sent:', tx.hash);
  await tx.wait();
  console.log('confirmed. swept', artifact.stealthAddress, 'via SweeperV2 intent (fee', artifact.intent.feeBps, 'bps)');
  if (artifact.intent.precommitment && BigInt(artifact.intent.precommitment)) console.log('REMINDER for the owner — Privacy Pools precommitment:', artifact.intent.precommitment);
} else if (artifact.kind === 'eip7702-intent-batch') {
  // one tx sweeps many stealth EOAs: cheaper per sweep, but the batch links them onchain.
  if (!process.env.BATCH_RELAYER) { console.error('set BATCH_RELAYER to relay eip7702-intent-batch artifacts'); process.exit(1); }
  const sweeps = artifact.sweeps;
  if (!Array.isArray(sweeps) || sweeps.length < 1 || sweeps.length > 20) { console.error('bad sweeps: expected 1-20 entries'); process.exit(1); }
  const targets = [], datas = [], authorizationList = [];
  for (const s of sweeps) {
    verifyIntent(s);
    targets.push(s.stealthAddress);
    datas.push(SWEEPER_IFACE.encodeFunctionData('executeSweep', [s.intent, s.signature]));
    authorizationList.push(wrapAuthorization(s.authorization));
  }
  const data = BATCH_IFACE.encodeFunctionData('relay', [targets, datas]);
  const fee = await provider.getFeeData();
  const tx = await runner.sendTransaction({
    type: 4,
    chainId: artifact.chainId,
    to: process.env.BATCH_RELAYER,
    data,
    authorizationList,
    maxFeePerGas: fee.maxFeePerGas * 2n,
    maxPriorityFeePerGas: fee.maxPriorityFeePerGas * 2n,
  });
  console.log('sent:', tx.hash);
  await tx.wait();
  console.log('confirmed. batch-swept', sweeps.length, 'stealth addresses via BatchRelayer (note: one tx links them onchain)');
} else {
  console.error('unknown artifact kind:', artifact.kind);
  process.exit(1);
}
