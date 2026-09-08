#!/usr/bin/env node
// relay.mjs — broadcast a signed sweep artifact from ghostpay's sweep tab.
// The relayer (you, running this) pays the gas. The stealth EOA never needs funding.
//
//   RUNNER_PK=0x… node relay.mjs artifact.json [--rpc https://eth.drpc.org]
//
// artifact kinds:
//   eip3009        — executes USDC transferWithAuthorization (gasless for the EOA)
//   eip7702-sweep  — type-4 tx: stealth EOA delegates to Sweeper.sol, sweeper moves the funds
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
  // ethers does not treat a bare {chainId,address,nonce,yParity,r,s} object as
  // carrying the signature — it serializes r/s as ZERO. Wrap it explicitly.
  const a = artifact.authorization;
  const authorization = {
    chainId: a.chainId,
    address: a.address,
    nonce: a.nonce,
    signature: ethers.Signature.from({ r: a.r, s: a.s, yParity: a.yParity }),
  };
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
} else {
  console.error('unknown artifact kind:', artifact.kind);
  process.exit(1);
}
