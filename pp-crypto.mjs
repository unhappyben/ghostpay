// Privacy Pools (0xbow) cryptography: local ESM port of
// ept-privacy-pools/src/adapters/pp-crypto.ts, kept dependency-local so this
// CLI is standalone. poseidon2 comes from vendor/poseidon2.mjs (byte-verified
// against ept's poseidon-lite); poseidon1/poseidon3 come from the locally
// installed poseidon-lite@0.3.0 (same version ept uses).
//
//   precommitment = poseidon2([nullifier, secret])
//   commitment    = poseidon3([value, label, precommitment])
//   spentNullHash = poseidon1([nullifier])
//   context = keccak256(abi.encode(Withdrawal{processooor,data}, scope)) % FIELD
//   trees are LeanIMT: poseidon2 hash, odd node promoted, empty root 0n, siblings padded to 32.

import { poseidon1, poseidon3 } from "poseidon-lite";
import { poseidon2 } from "./vendor/poseidon2.mjs";
import { AbiCoder, keccak256 } from "ethers";

export const SNARK_FIELD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export const PP_MAX_TREE_DEPTH = 32;
export const PP_ETH_ASSET = "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE";

export function precommitment(nullifier, secret) {
  return poseidon2([nullifier, secret]);
}
export function commitment(value, label, precom) {
  return poseidon3([value, label, precom]);
}
export function spentNullifierHash(nullifier) {
  return poseidon1([nullifier]);
}

// context = keccak256(abi.encode(Withdrawal{processooor,data}, scope)) % FIELD.
export function computeContext(processooor, data, scope) {
  const encoded = AbiCoder.defaultAbiCoder().encode(
    ["tuple(address,bytes)", "uint256"],
    [[processooor, data], scope],
  );
  return BigInt(keccak256(encoded)) % SNARK_FIELD;
}

// LeanIMT build: poseidon2 hash; odd node promoted (carried up, not zero-hashed);
// empty tree root = 0n.
export function leanIMTBuild(leaves) {
  if (leaves.length === 0) return { levels: [[]], depth: 0, root: 0n };
  const levels = [leaves.slice()];
  while (levels[levels.length - 1].length > 1) {
    const cur = levels[levels.length - 1];
    const next = [];
    for (let i = 0; i < cur.length; i += 2) {
      if (i + 1 < cur.length) next.push(poseidon2([cur[i], cur[i + 1]]));
      else next.push(cur[i]); // odd node promoted
    }
    levels.push(next);
  }
  return { levels, depth: levels.length - 1, root: levels[levels.length - 1][0] };
}

// Inclusion proof: siblings bottom-up, missing sibling => 0n, padded to depth 32.
export function leanIMTProof(levels, leafIndex) {
  const siblings = [];
  let idx = leafIndex;
  for (let d = 0; d < levels.length - 1; d++) {
    const sib = idx ^ 1;
    siblings.push(sib < levels[d].length ? levels[d][sib] : 0n);
    idx = idx >> 1;
  }
  while (siblings.length < PP_MAX_TREE_DEPTH) siblings.push(0n);
  return siblings;
}

// Deterministic change (new) keys from the note secrets.
export function deriveChangeKeys(nullifier, secret) {
  return {
    newNullifier: poseidon2([nullifier, 1n]),
    newSecret: poseidon2([secret, 1n]),
  };
}
