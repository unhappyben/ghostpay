# GHOSTPAY

Receive to a one-time stealth address, sweep into Privacy Pools in a single transaction, withdraw to an unlinked wallet. The stealth EOA never holds gas and never sends a transaction itself.

Built as the companion prototype to the essay *How Much Stealth Does a Stealth Address Get You?* The essay shows that stealth addresses leak at spend time; this is the fix: a spend path where the recipient's wallet never appears onchain at all.

## How it works

1. **Connect + generate.** Stealth keys derive from one wallet signature (ERC-5564 scheme 1, keccak256 shared secret, ScopeLift/Rust-reference compatible). Same signature regenerates the same keys on any device.
2. **Receive.** The app derives a fresh one-time address. Share the `0x` address. The Announcement (what your scanner needs to find the payment) is broadcast by the relayer, so your wallet never touches the announcer.
3. **Sweep.** Payments are found by scanning Announcement logs with the viewing key. The moment a payment is found (and the session holds the spend key), the app silently arms a signed intent: it generates the Privacy Pools secret + `poseidon2(nullifier, secret)` precommitment (the secret file downloads right then: lose it and the deposit is gone), signs an EIP-712 `SweepIntent` with the stealth key, and signs an EIP-7702 authorization delegating the stealth EOA to `SweeperV2.sol`. SIGN SWEEP just broadcasts the pre-armed artifact through the relayer, which executes `executeSweep` and pays the gas. Relayers without SweeperV2 (`GET /health` shows `sweeperV2: null`) get the legacy `eip7702-sweep` flow instead, unchanged.
4. **Withdraw.** After ASP approval, withdraw gaslessly from the app (groth16 proof in the browser) to any fresh address. The app first checks the same-origin relayer (`GET ./health`): if it advertises `ppRelay`, the withdrawal is built and submitted locally (`POST ./pp-withdraw`, fee from `ppFeeBps`). Otherwise it falls back to the fastrelay.xyz public relayer, unchanged.

Every step after payment is relayed: the recipient's wallet appears nowhere onchain.

## Dashboard and sessions

The app is a five-step wizard that collapses into a dashboard on return visits. Opting into "remember" stores a `gp-session` entry in localStorage containing only the viewing key and the stealth meta-address: a watch-only session. The spend key is never stored, so sweeping always asks for a fresh wallet signature. With a stored session, steps 1-2 collapse into the `#gp-dash` header (session mode, active address, rescan, forget), scanning runs in the background on load and on a timer, and new payments raise toast notifications plus events on the `GP.on`/`GP.emit` module bus. A status strip (`#gp-status`) shows relayer health, the relayer fee floor, and the ETH price, refreshed every 60s. The module contract between the core page and the feature modules below is documented in `docs/GP-API.md`.

The app is also a PWA: `manifest.json`, `sw.js` (cache-first static shell, relayer endpoints always network-only), and `icon.svg`.

## Invoice suite (`gp-invoices.mjs`)

Mounted inside step 3. On top of the basic invoice link it adds:

- **Tracked invoices.** Create an invoice with amount, token, note, and optional expiry; the suite stores it locally and watches the derived stealth address, marking it paid when the scanner sees the payment.
- **Encrypted memos.** The payer's note travels inside the announcement metadata, encrypted to the recipient's viewing key. Metadata format v2: `[viewTag(1)][R(33)][nonce(12)][AES-GCM ciphertext]`. R is a compressed ephemeral memo key; the AES key is `keccak256(ECDH(r, viewPub) ‖ "memo")`, so decryption needs only the viewing key. A 1-byte metadata stays a bare view tag, so old payers and scanners keep working.
- **QR + CSV + receipts.** Receive QR for the meta-address, CSV export of the invoice ledger, and printable receipts for paid invoices.
- **ENS publish.** Writes a `stealth` text record on your ENS name so senders can resolve it to your stealth meta-address. The meta-address is public by design: anyone can derive fresh payment addresses from it, nobody can spend from it.

The suite also enhances the pay-a-ghost flow (`#payghost`) with the memo field, so a payer can attach an encrypted note when announcing. Where the payer's wallet supports EIP-5792 (`wallet_sendCalls`), the ETH payment and the announcement go out in a single batched confirmation; other wallets keep the sequential announce-only flow. The status line says which path executed.

## Inbox (`gp-inbox.mjs`)

Mounted inside step 4. Turns the raw payment list into a per-payment inbox:

- **Status pills.** Each payment carries a pill on the ladder `DETECTED → SWEEPING → IN POOL → ASP PENDING → WITHDRAWABLE → WITHDRAWN`, plus a terminal `SWEPT DIRECT` state for sweeps that skip the pool.
- **Labels.** Free-text labels per stealth address, stored locally.
- **Token detection.** Checks each detected stealth address for USDC, USDT, DAI, and WETH balances, not just ETH.
- **USDC eip3009 sweep.** USDC can move gaslessly with a signed `transferWithAuthorization` (EIP-3009); the inbox builds and submits that artifact through the relayer.
- **Dust direct-sweep.** Amounts below the Privacy Pools minimum (0.01 ETH) cannot enter the pool; the inbox offers a direct sweep to a destination instead (a signed `SweepIntent` with `action: 0` on sweeperV2 relayers, the legacy `sweepETH` artifact otherwise).

## Money safety (`gp-money.mjs`)

Mounted into steps 4 and 5. A guard layer over the existing buttons; the core handlers are never edited:

- **Sweep preview.** SIGN SWEEP is gated behind an interstitial showing from address, balance, destination, fee floor, and sweeper contract before anything is signed.
- **Cost preview + relay progress.** Broadcast clicks open a progress view that polls `GET ./status/<hash>` until the relayed transaction confirms or fails.
- **Backup gate.** Once a withdrawal secret has been generated, further sweeps are blocked until you confirm the secret file is saved (or pass a file re-upload check).
- **Encrypted backup/restore.** Export the full local state (session, invoices, labels, scan cursors) as a passcode-encrypted file (PBKDF2, 600k iterations, AES-GCM) and restore it on another device.
- **Fresh-address check.** WITHDRAW is gated behind an onchain check of the recipient (transaction count + balance). A used address raises a loud warning and needs an explicit override.

## Watch-only notifier (`notify.mjs`)

A standalone daemon that watches the announcer and pings you on new payments, without the app open. Read-only: it needs the viewing key, never the spend key.

```sh
node notify.mjs                     # reads ./notify.local.json
node notify.mjs /path/to/conf.json
```

`notify.local.json` (gitignored, treat it like a key file):

```json
{
  "viewingKey": "0x…64 hex…",
  "spendPub":   "0x…66 hex…",
  "telegram": { "botToken": "…", "chatId": "…" },
  "webhook": "https://example.org/ghostpay",
  "pollSeconds": 60,
  "fromBlock": 23000000,
  "legacy": false
}
```

`telegram` or `webhook`, one of the two. `pollSeconds` defaults to 60 (minimum 5). `fromBlock` defaults to the current block (no backfill). `legacy: true` also scans pre-2026-09-08 sha256 announcements. State lives in `notify-state.json` (gitignored) so restarts never re-notify. `RPC_URLS` rotation and `TOR_PROXY` work the same as in serve.mjs.

## SweeperV2 signed intents + BatchRelayer

`SweeperV2.sol` is a strict superset of `Sweeper.sol`. V1 signs a 7702 authorization but the relayer picks the calldata, so a malicious relayer could call `sweepETH(itsOwnAddress)` and take the whole balance. V2 adds `executeSweep(intent, sig)`: the destination, fee, deadline, and action all come from an EIP-712 `SweepIntent` signed by the stealth key itself, so third-party relaying is trustless. A relayer that tampers with anything invalidates the signature.

- **EIP-712 domain:** `EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)` with name `GhostpaySweeper`, version `1`. Under 7702 the code executes as the stealth EOA, so `verifyingContract = address(this)` is the stealth account itself: every intent is pinned to exactly one stealth address, and the domain separator is rebuilt fresh in memory on every call (never cached, never immutable).
- **Struct:** `SweepIntent(uint8 action,address token,address destination,uint256 precommitment,uint256 feeBps,uint256 deadline)`. Actions: 0 = ETH to destination, 1 = Privacy Pools ETH deposit, 2 = Privacy Pools token deposit, 3 = token to destination.
- **Fee:** `feeBps` is paid to `tx.origin`, the runner EOA that broadcast the transaction. That is what makes third-party relaying safe to open up: any runner can carry the intent, the fee goes to whoever actually pays the gas, and the fee is capped onchain at `MAX_FEE_BPS` (1000, i.e. 10%).

`BatchRelayer.sol` fans out one type-4 transaction across up to 20 stealth EOAs: the authorization list delegates every EOA to SweeperV2, then one call to `relay()` (all-or-nothing) or `relaySkipFailures()` (best-effort, `RelayFailed` events) runs each `executeSweep`. One gas payment for N sweeps. Fees still land on `tx.origin`, not on the BatchRelayer contract. Caveat: a batch shares one transaction, so the swept addresses are linked onchain.

`test/` covers both contracts with 11 mainnet fork tests (`forge test`, see `foundry.toml`; needs `MAINNET_RPC`). SweeperV2 is deployed on mainnet at `0xCC29c7723116155ccF20C7c0b8924F4747331903` (bytecode verified against the fork-tested artifact); the app arms intents against it by default. BatchRelayer is not deployed yet: see the deployment checklist.

## Relayer endpoints

`serve.mjs` is the static server plus relayer:

| Endpoint | Purpose |
| --- | --- |
| `POST /announce` | `{stealth, ephPub, viewTag, metadata?}` → announce on the ERC-5564 announcer from a runner wallet. `metadata` is optional 0x-hex, 1-1024 bytes (view tag + encrypted memo); default is the 1-byte view tag. |
| `POST /sweep` | Relay a signed sweep artifact: `eip3009`, `eip7702-sweep`, `eip7702-intent`, or `eip7702-intent-batch`. |
| `POST /pp-withdraw` | Privacy Pools withdrawal relay (`PP_RELAY=1` only, else 503). Same payload shape the app sends fastrelay.xyz. The groth16 context signal binds the fee terms into the proof: the fee recipient must be one of this server's runners and `relayFeeBPS` must not exceed `PP_FEE_BPS`. The runner pays gas; the fee accrues to the runner inside the withdrawal itself. |
| `GET /health` | Relayer status JSON: runners (addresses only, never keys), sweeperV2, batchRelayer, feeOwner, tor, endpoints. With `PP_RELAY=1` also `ppRelay: true` and `ppFeeBps`, so the app can discover the relay and price proofs. |
| `GET /fee` | `{minFeeBps}`: the relayer fee floor for intent sweeps. |
| `GET /price` | ETH + USDC USD prices, CoinGecko proxied with a 60s cache so the price fetch stays out of the browser. |
| `GET /status/:hash` | Transaction receipt status: `confirmed`, `failed`, or `pending`. |

Environment variables:

| Var | Default | Purpose |
| --- | --- | --- |
| `PORT` | `8791` | Listen port. |
| `RUNNER_PK` | unset | Single runner key. Alternative: `runners.local.json` (gitignored) for a pool, random per request. |
| `RPC_URLS` | flashbots/drpc/merkle | Comma-separated read endpoints, random per call. |
| `BROADCAST_URLS` | `https://rpc.flashbots.net` | Comma-separated endpoints used only for `eth_sendRawTransaction`; every read stays on the `RPC_URLS` rotation. |
| `TOR_PROXY` | unset | Route all JSON-RPC over Tor (`socks5://127.0.0.1:9050`). |
| `MIN_FEE_BPS` | `30` | Fee floor for intent sweeps, advertised at `GET /fee`. |
| `SWEEPER_V2` | unset | Deployed SweeperV2 address: gates `eip7702-intent` sweeps. |
| `BATCH_RELAYER` | unset | Deployed BatchRelayer address: gates `eip7702-intent-batch` sweeps. |
| `PP_RELAY` | unset | Set to `1` to enable `POST /pp-withdraw`. |
| `PP_FEE_BPS` | `25` | Max relay fee the withdrawal relay accepts, advertised at `GET /health`. |
| `FEE_OWNER` | unset | Owner address for the fee auto-forwarder; unset disables it. |
| `FEE_RESERVE_ETH` | `0.005` | Gas reserve kept on each runner when fees are forwarded. |
| `FEE_SWEEP_MINUTES` | `60` | Minutes between fee-forward sweeps (first sweep 5 min after boot). |

Broadcasts wait a random jitter (announce 2-15s, sweep 5-45s) so the browser request and the onchain transaction are not trivially time-correlated.

**Collecting fees.** Relayer fees accrue onchain to the runner: `tx.origin` on intent sweeps, `feeRecipient` inside Privacy Pools withdrawals. With `FEE_OWNER` set, a forwarder runs every `FEE_SWEEP_MINUTES` (default hourly): each runner keeps `FEE_RESERVE_ETH` for gas and sweeps the rest to `FEE_OWNER` as a plain type-2 transfer. Sweeps ride the same broadcast machinery as user transactions (endpoint rotation, fee bump, `BROADCAST_URLS`) but skip the jitter. Every forward is logged to `fees.jsonl` as `kind: "fee-forward"` so the ledger sees the outflow. `GET /health` shows the configured `feeOwner` (an address is public onchain anyway).

## Fee ledger (`fees.mjs`)

Every successful fee-bearing broadcast appends one JSON line to `fees.jsonl` (gitignored): `{ts, kind, feeBps, estFeeWei, txHash, runner}` where kind is `sweep-intent`, `sweep-intent-batch`, or `pp-withdraw`. Sweep fees are estimated at preflight from the stealth balance; withdrawal fees are exact, computed from the withdrawnValue public signal. Announce requests carry no fee and are never logged. The auto-forwarder appends `{ts, kind: "fee-forward", estFeeWei, txHash, runner}` lines for each sweep to `FEE_OWNER`. Run the revenue report with:

```sh
node fees.mjs          # FEES_FILE=/path/to.jsonl to override
```

The report totals per kind and converts to USD at the current price (same CoinGecko source as `GET /price`, fail soft). Fee-forward lines are reported separately (total forwarded, last forward time, and runner holdings as earned minus forwarded); the ARR run-rate counts fees earned, not fees held.

## Run it

```sh
npm install          # ethers, snarkjs, poseidon-lite
node serve.mjs       # http://localhost:8791/
```

Relayer endpoints (`/announce`, `/sweep`, `/pp-withdraw`) need a funded runner wallet:

```sh
RUNNER_PK=0x… RPC_URLS=https://your-rpc node serve.mjs
```

Without a runner the app still serves and the announce falls back to the connected wallet. For a private RPC in the browser, create `config.local.js` (gitignored):

```js
window.GHOSTPAY_RPC = 'https://your-rpc';
```

The withdrawal also works as a CLI: `node pp-withdraw.mjs <pp-secret.json> <recipient> [--relay <url>] [--broadcast]`. Default is `--dry-run`. Default relayer is fastrelay.xyz; `--relay http://localhost:8791` switches to your own serve.mjs instance (fee terms from its `GET /health`, submitted to `/pp-withdraw`). Circuit artifacts (`artifacts/withdraw.wasm`, `withdraw.zkey`) are gitignored; download from `https://privacypools.com/artifacts/` or let pp-withdraw fetch them.

`relay.mjs` remains a standalone dumb broadcaster for saved sweep artifacts: `RUNNER_PK=0x… node relay.mjs artifact.json`.

## Deployment checklist

SweeperV2 is deployed on mainnet (`0xCC29c7723116155ccF20C7c0b8924F4747331903`). To take the relayer fully self-hosted:

1. **Set `SWEEPER_V2=0xCC29c7723116155ccF20C7c0b8924F4747331903`** and restart serve.mjs: intent sweeps come online (`GET /health` confirms, the app switches to auto-armed intents automatically).
2. **Deploy BatchRelayer.** `forge create BatchRelayer.sol:BatchRelayer`. No constructor args. Set `BATCH_RELAYER=<address>` to enable batch sweeps.
3. **Set `PP_RELAY=1`** (optionally `PP_FEE_BPS`, `MIN_FEE_BPS`, `BROADCAST_URLS`) to enable local Privacy Pools withdrawals via `POST /pp-withdraw`.
4. **Fund runners from Privacy Pools.** Withdraw from the app (step 5) to one or more fresh EOAs and use their keys in `runners.local.json`. One 0.01 ETH withdrawal funds dozens of sweeps. Rotate any time: withdraw again to a new address, swap the key, restart. The runners then have no funding link to you onchain.

## Relayer privacy

The relayer is the one party that sees your IP, your timing, and your runner address. Three knobs shrink that footprint.

**Fund the runner from Privacy Pools** (see the deployment checklist). The runner then has no funding link to you onchain.

**Tor + endpoint rotation for all RPC.** Every JSON-RPC call (nonce, balance, fees, broadcast) goes through a random endpoint per call from `RPC_URLS`. With `TOR_PROXY` set, all of it routes over Tor, so no single RPC provider sees both your IP and the broadcasts:

```sh
brew install tor && tor &
TOR_PROXY=socks5://127.0.0.1:9050 RPC_URLS=https://rpc.flashbots.net,https://eth.drpc.org node serve.mjs
```

**Serve the app itself as an onion service** so the browser-to-relayer hop is Tor too. In your torrc:

```
HiddenServiceDir /var/lib/tor/ghostpay/
HiddenServicePort 80 127.0.0.1:8791
```

Restart tor, read the hostname from `/var/lib/tor/ghostpay/hostname`, and open that .onion address in Tor Browser. The relayer then never sees your IP at all.

### Relayer privacy roadmap

A note on what can and cannot be fixed. ZK cannot hide a computed output from the machine computing it: the relayer would hold the witness, so server-side stealth-address generation can never be private from the server. The correct construction is the one this repo already has: client-side generation, plus payer-side announce (the pay-a-ghost flow, where the sender's wallet posts the announcement instead of the recipient's), plus anonymous transport (Tor or Waku) on the remaining relayer hops, plus blind-signature metering (Privacy Pass / Anonymous Rate-Limited Credentials) if request counts ever need hiding from the relayer. For private scanning and metering respectively, see ePrint 2021/1256 (Oblivious Message Retrieval) and RFC 9576 (Privacy Pass).

## Files

- `index.html`: the app core (connect, generate, receive, scan, sweep, withdraw), PWA shell
- `gp-invoices.mjs` / `gp-inbox.mjs` / `gp-money.mjs`: invoice suite, payment inbox, money-safety layer (`frag-*.html` are their markup)
- `serve.mjs`: static server + announce/sweep/withdraw relayer
- `notify.mjs`: watch-only payment notifier (Telegram/webhook)
- `fees.mjs`: relayer fee ledger + revenue report
- `Sweeper.sol`: legacy 7702 sweep target (deployed on mainnet; the fallback path when a relayer has no SweeperV2)
- `SweeperV2.sol` / `BatchRelayer.sol`: signed-intent sweeper (deployed on mainnet) + batch fan-out (not deployed)
- `relay.mjs`: standalone sweep-artifact broadcaster
- `pp-withdraw.mjs` / `pp-crypto.mjs`: standalone Privacy Pools withdrawal CLI + crypto
- `sw.js` / `manifest.json` / `icon.svg`: PWA
- `vendor/`: vendored poseidon (byte-verified against poseidon-lite / circomlib)
- `test/`: mainnet fork tests for SweeperV2 + BatchRelayer
- `test-commitment.mjs`: secret/commitment verification suite
- `docs/GP-API.md`: the window.GP module contract

## Honest caveats

- Prototype. The sweepers are unaudited; the stealth crypto follows the ERC-5564 reference but is hand-rolled.
- MetaMask strips `authorizationList` from wallet-sent transactions, which is why the relayer exists. Any 7702-capable broadcaster can carry the signed artifact; the relayer learns your IP and timing, nothing else.
- Legacy checkbox: announcements made before 2026-09-08 used a sha256 shared secret (pre-migration); tick "legacy scheme" to find and sweep them.
