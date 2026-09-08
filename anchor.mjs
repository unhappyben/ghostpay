#!/usr/bin/env node
// anchor.mjs — publish stealth meta-addresses in an EIP-4844 blob (the "ephemeral registry").
// Consensus nodes serve the blob for ~4096 epochs (~18 days), then prune it.
// The permanent chain record keeps only the KZG commitment — the meta-address is
// recoverable only from whoever archived the blob during the window.
//
//   RUNNER_PK=0x… node anchor.mjs "st:eth:0x<spendPub><viewPub>" ["st:eth:0x…" ...] [--rpc URL]
//
// Batching many meta-addresses into one blob gives publication a crowd to hide in.
import { ethers } from 'ethers';
import { KZG } from 'micro-eth-signer/kzg.js';
import { trustedSetup } from '@paulmillr/trusted-setups/small-kzg.js';

const kzg = new KZG(trustedSetup);

const rpcIdx = process.argv.indexOf('--rpc');
const RPC = rpcIdx > -1 ? process.argv[rpcIdx + 1] : 'https://eth.drpc.org';
const metas = process.argv.slice(2).filter(a => !a.startsWith('--') && a !== process.argv[rpcIdx + 1]);
const pk = process.env.RUNNER_PK;
if (!pk || !metas.length) { console.error('usage: RUNNER_PK=0x… node anchor.mjs "st:eth:0x…" [--rpc URL]'); process.exit(1); }

for (const m of metas) {
  if (!/^st:eth:0x[0-9a-fA-F]{132}$/.test(m)) { console.error('bad meta-address:', m); process.exit(1); }
}

const provider = new ethers.JsonRpcProvider(RPC);
const runner = new ethers.Wallet(pk, provider);
const { chainId } = await provider.getNetwork();

// blob payload: newline-separated meta-addresses, packed into 32-byte field elements
// (31 bytes of data per element, 0x00 prefix — keeps every element below the BLS field modulus)
const payload = new TextEncoder().encode(metas.join('\n'));
const blobData = new Uint8Array(131072); // 4096 x 32B field elements
for (let off = 0, i = 0; off < payload.length; off += 31, i++) {
  blobData[i * 32] = 0;
  blobData.set(payload.slice(off, off + 31), i * 32 + 1);
}
const blobHex = ethers.hexlify(blobData);
const commitment = kzg.blobToKzgCommitment(blobHex);
// EIP-4844: versioned_hash = 0x01 || sha256(commitment)[1:]
const versionedHash = '0x01' + ethers.sha256(commitment).slice(4);
const proof = kzg.computeBlobProof(blobHex, commitment);

console.log('anchoring', metas.length, 'meta-address(es) in one blob');
console.log('versioned hash:', versionedHash);

const fee = await provider.getFeeData();
const tx = await runner.sendTransaction({
  type: 3,
  to: '0x000000000000000000000000000000000000dEaD', // anchor inbox — nothing executes
  value: 0,
  data: '0x',
  maxFeePerBlobGas: ethers.parseUnits('2', 'gwei'),
  blobs: [{ data: blobData, commitment, proof }],
  maxFeePerGas: fee.maxFeePerGas,
  maxPriorityFeePerGas: fee.maxPriorityFeePerGas,
});
console.log('blob tx sent:', tx.hash);
await tx.wait();
console.log('anchored. discoverable via beacon API for ~18 days, then pruned by the protocol.');
