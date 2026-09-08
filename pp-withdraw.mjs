#!/usr/bin/env node
// Privacy Pools gasless withdrawal CLI (mainnet, 0xbow).
//
//   node pp-withdraw.mjs <secret-file.json> <recipient-address> [amount-eth] [--broadcast|--dry-run]
//
// Default is --dry-run: everything up to and including groth16 proof generation,
// prints the relay payload it WOULD submit, but never POSTs to /relayer/request.
// Only --broadcast submits.
//
// Flow (ported from ept-privacy-pools/src/adapters/privacy-pools-withdraw.ts):
//   locate deposit onchain by precommitmentHash -> spent-nullifier guard ->
//   fetch ASP approved set + state leaves from 0xbow -> LeanIMT inclusion proofs
//   -> relayer fee commitment -> groth16 proof (local artifacts) -> relay.

import fs from "node:fs";
import path from "node:path";
import url from "node:url";
import { ethers } from "ethers";
import {
  SNARK_FIELD,
  PP_ETH_ASSET,
  precommitment,
  commitment as ppCommitment,
  leanIMTBuild,
  leanIMTProof,
  computeContext,
  deriveChangeKeys,
  spentNullifierHash,
} from "./pp-crypto.mjs";

// ---- Fixed mainnet parameters (verified onchain) ----
const CHAIN_ID = 1;
const POOL = "0xf241d57c6debae225c0f2e6ea1529373c9a9c9fb";
const ENTRYPOINT = "0x6818809EefCe719E480a7526D76bD3e561526b46";
const SCOPE = 4916574638117198869413701114161172350986437430914933850166949084132905299523n;
const DEPOSIT_BLOCK = 25931460; // known deposit block; seeds the event search window
const SEARCH_WINDOW = 50_000; // scan DEPOSIT_BLOCK +/- this many blocks
const LOG_CHUNK = 5_000; // drpc eth_getLogs fails over ~10k ranges

const RPC_URL = process.env.RPC_URL || "https://eth.drpc.org"; // set RPC_URL to your own endpoint (paid keys stay out of the repo)
const ASP_BASE = "https://api.0xbow.io/1/public";
const RELAYER = "https://fastrelay.xyz/relayer";
const ARTIFACTS_DIR = path.join(path.dirname(url.fileURLToPath(import.meta.url)), "artifacts");
const WASM_LOCAL = path.join(ARTIFACTS_DIR, "withdraw.wasm");
const ZKEY_LOCAL = path.join(ARTIFACTS_DIR, "withdraw.zkey");
const WASM_URL = "https://privacypools.com/artifacts/withdraw.wasm";
const ZKEY_URL = "https://privacypools.com/artifacts/withdraw.zkey";

const POOL_ABI = [
  "event Deposited(address indexed _depositor, uint256 _commitment, uint256 _label, uint256 _value, uint256 _precommitmentHash)",
  "function nullifierHashes(uint256) view returns (bool)",
];

const say = (msg) => console.log(`[pp-withdraw] ${msg}`);
const fail = (msg) => {
  console.error(`[pp-withdraw] ERROR: ${msg}`);
  process.exit(1);
};

// ---- Arg parsing ----
function parseArgs(argv) {
  const positional = [];
  let broadcast = false;
  for (const a of argv) {
    if (a === "--broadcast") broadcast = true;
    else if (a === "--dry-run") broadcast = false;
    else if (a.startsWith("--")) fail(`unknown flag: ${a}`);
    else positional.push(a);
  }
  if (positional.length < 2 || positional.length > 3)
    fail("usage: node pp-withdraw.mjs <secret-file.json> <recipient-address> [amount-eth] [--broadcast|--dry-run]");
  return { secretFile: positional[0], recipient: positional[1], amountEth: positional[2] ?? null, broadcast };
}

// ---- Deposit lookup: Deposited events, newest-first, narrow chunks ----
async function findDeposit(provider, precommitmentHash) {
  const iface = new ethers.Interface(POOL_ABI);
  const topic = iface.getEvent("Deposited").topicHash;
  const latest = await provider.getBlockNumber();
  const windowEnd = Math.min(latest, DEPOSIT_BLOCK + SEARCH_WINDOW);
  const windowStart = Math.max(0, DEPOSIT_BLOCK - SEARCH_WINDOW);
  let scanned = 0;
  for (let end = windowEnd; end >= windowStart; end -= LOG_CHUNK) {
    const start = Math.max(end - LOG_CHUNK + 1, windowStart);
    const logs = await provider.getLogs({ address: POOL, fromBlock: start, toBlock: end, topics: [topic] });
    for (const log of logs) {
      const p = iface.parseLog(log);
      if (BigInt(p.args._precommitmentHash) === precommitmentHash) {
        return {
          label: BigInt(p.args._label),
          commitment: BigInt(p.args._commitment),
          value: BigInt(p.args._value),
          blockNumber: log.blockNumber,
        };
      }
    }
    scanned += logs.length;
    say(`  scanned blocks ${start}-${end} (${logs.length} Deposited events), no match yet`);
  }
  throw new Error(`No matching deposit found in blocks ${windowStart}-${windowEnd} (${scanned} events scanned).`);
}

async function main() {
  const { secretFile, recipient, amountEth, broadcast } = parseArgs(process.argv.slice(2));

  if (!ethers.isAddress(recipient)) fail(`recipient is not a valid address: ${recipient}`);
  const recipientCk = ethers.getAddress(recipient);

  // ---- Secret file + corruption guard ----
  if (!fs.existsSync(secretFile)) fail(`secret file not found: ${secretFile}`);
  const note = JSON.parse(fs.readFileSync(secretFile, "utf8"));
  if (!note.nullifier || !note.secret || !note.precommitment)
    fail("secret file must contain nullifier, secret and precommitment.");
  const nullifier = BigInt(note.nullifier);
  const secret = BigInt(note.secret);
  const precomFile = BigInt(note.precommitment);
  const precomCalc = precommitment(nullifier, secret);
  if (precomCalc !== precomFile)
    fail(
      "precommitment mismatch: poseidon2(nullifier, secret) =\n" +
        `  ${precomCalc}\nbut the file says\n  ${precomFile}\n` +
        "The secret file is corrupt or mistyped. Refusing to continue.",
    );
  say("Secret file OK: precommitment matches poseidon2(nullifier, secret).");

  const provider = new ethers.JsonRpcProvider(RPC_URL, CHAIN_ID, { staticNetwork: true });

  // 1. Locate the deposit onchain.
  say("Locating deposit onchain…");
  const { label, commitment: com, value: onchainValue, blockNumber } = await findDeposit(provider, precomFile);
  say(
    `Deposit found in block ${blockNumber}: label=${label} commitment=${com} value=${ethers.formatEther(onchainValue)} ETH`,
  );
  if (ppCommitment(onchainValue, label, precomFile) !== com)
    console.warn("[pp-withdraw] WARN: commitment mismatch (non-fatal)");

  const poolC = new ethers.Contract(POOL, POOL_ABI, provider);
  if (await poolC.nullifierHashes(spentNullifierHash(nullifier))) fail("This note has already been withdrawn.");
  say("Spent-nullifier check: not withdrawn.");

  // 2. ASP approved set + state leaves; confirm membership.
  say("Fetching approved set from ASP…");
  const res = await fetch(`${ASP_BASE}/mt-leaves`, { headers: { "X-Pool-Scope": SCOPE.toString() } });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    fail(`ASP leaves fetch failed (${res.status}): ${text.slice(0, 300)}`);
  }
  const { aspLeaves: aspRaw, stateTreeLeaves: stateRaw } = await res.json();
  const aspLeaves = aspRaw.map((x) => BigInt(x));
  const stateLeaves = stateRaw.map((x) => BigInt(x));
  say(`ASP snapshot: ${aspLeaves.length} asp leaves, ${stateLeaves.length} state leaves.`);

  const aspIndex = aspLeaves.indexOf(label);
  if (aspIndex < 0)
    fail("Deposit label is not in the approved ASP set (still screening, or rejected). Cannot withdraw via ASP.");
  const stateIndex = stateLeaves.indexOf(com);
  if (stateIndex < 0) fail("Deposit commitment not in the state-tree snapshot yet. Retry shortly.");
  say(`Membership confirmed: ASP index ${aspIndex}, state index ${stateIndex}.`);

  say("Building LeanIMT inclusion proofs…");
  const stateTree = leanIMTBuild(stateLeaves);
  const aspTree = leanIMTBuild(aspLeaves);
  const stateSiblings = leanIMTProof(stateTree.levels, stateIndex);
  const aspSiblings = leanIMTProof(aspTree.levels, aspIndex);

  // Withdraw amount: default = full escrowed (net) value, change = 0.
  const amountWei = amountEth == null ? onchainValue : ethers.parseEther(amountEth);
  if (amountWei <= 0n) fail("withdrawal amount must be positive.");
  const withdrawnValue = amountWei >= onchainValue ? onchainValue : amountWei;
  const changeValue = onchainValue - withdrawnValue;
  say(
    `Amount: withdrawing ${ethers.formatEther(withdrawnValue)} ETH` +
      (changeValue > 0n ? ` (change ${ethers.formatEther(changeValue)} ETH stays in the pool).` : " (full balance, no change)."),
  );

  // 3. Relayer fee commitment.
  say("Getting relayer quote…");
  const quoteRes = await fetch(`${RELAYER}/quote`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      chainId: CHAIN_ID,
      amount: withdrawnValue.toString(),
      asset: PP_ETH_ASSET,
      recipient: recipientCk,
      extraGas: false,
    }),
  });
  if (!quoteRes.ok) {
    const text = await quoteRes.text().catch(() => "");
    fail(`Relayer quote failed (${quoteRes.status}): ${text.slice(0, 300)}`);
  }
  const quote = await quoteRes.json();
  const feeCommitment = quote.feeCommitment ?? quote;
  const withdrawalData = feeCommitment.withdrawalData;
  if (!withdrawalData) fail("Relayer did not return withdrawalData in the fee commitment.");
  say(`Relayer quote: ${JSON.stringify(quote, null, 2)}`);

  // 4. Circuit inputs (existingValue = NET onchain value).
  const { newNullifier, newSecret } = deriveChangeKeys(nullifier, secret);
  const context = computeContext(ENTRYPOINT, withdrawalData, SCOPE);
  const input = {
    withdrawnValue: withdrawnValue.toString(),
    stateRoot: stateTree.root.toString(),
    stateTreeDepth: "32",
    ASPRoot: aspTree.root.toString(),
    ASPTreeDepth: "32",
    context: context.toString(),
    label: label.toString(),
    existingValue: onchainValue.toString(),
    existingNullifier: nullifier.toString(),
    existingSecret: secret.toString(),
    newNullifier: newNullifier.toString(),
    newSecret: newSecret.toString(),
    stateSiblings: stateSiblings.map((s) => s.toString()),
    stateIndex: stateIndex.toString(),
    ASPSiblings: aspSiblings.map((s) => s.toString()),
    ASPIndex: aspIndex.toString(),
  };

  // 5. Groth16 proof with local artifacts (URL fallback).
  const wasmPath = fs.existsSync(WASM_LOCAL) ? WASM_LOCAL : WASM_URL;
  const zkeyPath = fs.existsSync(ZKEY_LOCAL) ? ZKEY_LOCAL : ZKEY_URL;
  say(`Proving (groth16, ~10-30s) with ${wasmPath === WASM_LOCAL ? "local" : "remote"} artifacts…`);
  const snarkjs = await import("snarkjs");
  const t0 = Date.now();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasmPath, zkeyPath);
  say(`Proof generated in ${((Date.now() - t0) / 1000).toFixed(1)}s.`);

  if (BigInt(publicSignals[7]) % SNARK_FIELD !== context % SNARK_FIELD)
    console.warn("[pp-withdraw] WARN: context public signal mismatch (non-fatal)", publicSignals[7], context.toString());

  const SIGNAL_NAMES = [
    "newCommitmentHash",
    "existingNullifierHash",
    "withdrawnValue",
    "stateRoot",
    "stateTreeDepth",
    "ASPRoot",
    "ASPTreeDepth",
    "context",
  ];
  say("Public signals:");
  publicSignals.forEach((s, i) => console.log(`  [${i}] ${SIGNAL_NAMES[i] ?? "?"} = ${s}`));

  const payload = {
    chainId: CHAIN_ID,
    scope: SCOPE.toString(),
    withdrawal: { processooor: ENTRYPOINT, data: withdrawalData },
    proof: { pi_a: proof.pi_a, pi_b: proof.pi_b, pi_c: proof.pi_c, protocol: proof.protocol, curve: proof.curve },
    publicSignals,
    feeCommitment,
  };

  if (!broadcast) {
    say("DRY RUN (default). Proof is ready; NOT submitting. Payload that WOULD be POSTed to /relayer/request:");
    console.log(JSON.stringify(payload, null, 2));
    say("Re-run with --broadcast to submit for real.");
    return;
  }

  // 6. Submit (only with --broadcast).
  say("Submitting to relayer…");
  const relayRes = await fetch(`${RELAYER}/request`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!relayRes.ok) {
    const text = await relayRes.text().catch(() => "");
    fail(`Relayer rejected the withdrawal (${relayRes.status}): ${text.slice(0, 300)}`);
  }
  const out = await relayRes.json();
  const hash = out.txHash ?? out.hash ?? out.transactionHash ?? out.tx;
  if (!hash) fail("Relayer accepted the withdrawal but returned no tx hash: " + JSON.stringify(out).slice(0, 300));
  say(`Submitted. tx hash: ${hash}`);
  console.log(hash);
}

// snarkjs/ffjavascript leaves worker threads alive; exit explicitly or the
// process lingers after the work is done.
main()
  .then(() => process.exit(0))
  .catch((err) => fail(err?.message ?? String(err)));
