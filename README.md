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

## Relayer privacy

The relayer is the one party that sees your IP, your timing, and your runner address. Three knobs shrink that footprint.

**Fund the runner from Privacy Pools.** Create one fresh EOA, withdraw to it from the app (step 5), and use its key as `RUNNER_PK`. One 0.01 ETH withdrawal funds dozens of sweeps (a sweep costs roughly 0.0005 ETH at 2x fee bump). Rotate any time: withdraw again to a new address, swap the key, restart. The runner then has no funding link to you onchain.

**Tor + endpoint rotation for all RPC.** Every JSON-RPC call (nonce, balance, fees, broadcast) goes through a random endpoint per call from `RPC_URLS` (comma-separated, defaults to flashbots/drpc/merkle). With `TOR_PROXY` set, all of it routes over Tor, so no single RPC provider sees both your IP and the broadcasts:

```sh
brew install tor && tor &
TOR_PROXY=socks5://127.0.0.1:9050 RPC_URLS=https://rpc.flashbots.net,https://eth.drpc.org node serve.mjs
```

Broadcasts also wait a random jitter before sending (announce 2-15s, sweep 5-45s) so the browser request and the onchain transaction are not trivially time-correlated.

**Serve the app itself as an onion service** so the browser-to-relayer hop is Tor too. In your torrc:

```
HiddenServiceDir /var/lib/tor/ghostpay/
HiddenServicePort 80 127.0.0.1:8791
```

Restart tor, read the hostname from `/var/lib/tor/ghostpay/hostname`, and open that .onion address in Tor Browser. The relayer then never sees your IP at all.

For a pool of runners instead of one, drop `runners.local.json` (gitignored) next to serve.mjs: `[{"address":"0x…","key":"0x…"}, …]`. Each request picks a runner at random, preferring a different one than the previous request.


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
