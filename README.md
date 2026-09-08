# GHOSTPAY

Receive to a one-time stealth address, sweep into Privacy Pools in a single transaction, withdraw to an unlinked wallet. The stealth EOA never holds gas and never sends a transaction itself.

Built as the companion prototype to the essay *How Much Stealth Does a Stealth Address Get You?* The essay shows that stealth addresses leak at spend time; this is the fix: a spend path where the recipient's wallet never appears onchain at all.

## How it works

1. **Connect + generate.** Stealth keys derive from one wallet signature (ERC-5564 scheme 1, keccak256 shared secret, ScopeLift/Rust-reference compatible). Same signature regenerates the same keys on any device.
2. **Receive.** The app derives a fresh one-time address. Share the `0x` address. The Announcement (what your scanner needs to find the payment) is broadcast by the relayer, so your wallet never touches the announcer.
3. **Sweep.** Payments are found by scanning Announcement logs with the viewing key. Sweeping signs an EIP-7702 authorization delegating the stealth EOA to `Sweeper.sol`, which deposits the full balance into Privacy Pools (0xbow entrypoint) under a `poseidon2(nullifier, secret)` precommitment. The relayer broadcasts the type-4 transaction and pays the gas. The withdrawal secret downloads as a JSON file: lose it and the deposit is gone.
4. **Withdraw.** After ASP approval, withdraw gaslessly from the app (groth16 proof in the browser, fastrelay.xyz submits) to any fresh address.

Every step after payment is relayed: the recipient's wallet appears nowhere onchain.

## Run it

```sh
npm install          # ethers, snarkjs, poseidon-lite
node serve.mjs       # http://localhost:8791/
```

Relayer endpoints (`/announce`, `/sweep`) need a funded runner wallet:

```sh
RUNNER_PK=0x… RPC_URL=https://your-rpc node serve.mjs
```

Without `RUNNER_PK` the app still serves and the announce falls back to the connected wallet. `RPC_URL` defaults to a public endpoint; for a private one in the browser, create `config.local.js` (gitignored):

```js
window.GHOSTPAY_RPC = 'https://your-rpc';
```

The withdrawal also works as a CLI: `node pp-withdraw.mjs <pp-secret.json> <recipient> [--broadcast]`. Circuit artifacts (`artifacts/withdraw.wasm`, `withdraw.zkey`) are gitignored; download from `https://privacypools.com/artifacts/` or let pp-withdraw fetch them.

## Files

- `index.html` — the whole app (connect, generate, receive, scan, sweep, withdraw)
- `serve.mjs` — static server + announce/sweep relayer
- `Sweeper.sol` — 7702 sweep target (Privacy Pools, Tornado, direct; deployed on mainnet, the UI uses the Privacy Pools path only)
- `pp-withdraw.mjs` / `pp-crypto.mjs` — standalone Privacy Pools withdrawal CLI + crypto
- `vendor/` — vendored poseidon (byte-verified against poseidon-lite / circomlib)
- `test-commitment.mjs` — secret/commitment verification suite

## Honest caveats

- Prototype. Sweeper.sol is unaudited; the stealth crypto follows the ERC-5564 reference but is hand-rolled.
- MetaMask strips `authorizationList` from wallet-sent transactions, which is why the relayer exists. Any 7702-capable broadcaster can carry the signed artifact; the relayer learns your IP and timing, nothing else.
- Legacy checkbox: announcements made before 2026-09-08 used a sha256 shared secret (pre-migration); tick "legacy scheme" to find and sweep them.
