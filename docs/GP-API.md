# GHOSTPAY module API (window.GP)

`index.html` exposes a single global, `window.GP`, so feature modules ship as separate
`<script type="module">` files without ever editing `index.html`. This document is the
contract: if it is not written here, modules must not rely on it.

Version: `GP.version === '1.0-ui-core'`.

## How a module wires in

Add one script tag to `index.html`, immediately AFTER the main inline
`<script type="module">` block (the one that ends just before `</body>`) and before
`</body>`:

```html
<script type="module" src="./gp-yourmodule.mjs"></script>
```

Script order is the only guarantee needed: `window.GP` is fully assembled before any
module file executes. Modules must not import ethers or crypto from a CDN themselves;
use `GP.ethers` and `GP.crypto`.

A module renders its UI into exactly one of the mount points listed under "DOM
contract" below. It must not touch any other element, and it must not redefine `window.GP`.

## GP.state

Live getters over the app's internal wallet object. All getters are cheap and may be
read at any time; they reflect the current session.

| Member | Type | Meaning |
|---|---|---|
| `GP.state.connected` | `boolean` | A wallet is connected this session (injected provider or WalletConnect). |
| `GP.state.unlocked` | `boolean` | Stealth keys are available (at minimum the viewing key). Scanning works when true. |
| `GP.state.watchOnly` | `boolean` | Keys are restored from a stored `gp-session`: viewing key only, `spendPriv` is null. Sweeping is NOT possible in this state. |
| `GP.state.address` | `string \| null` | Checksummed connected wallet address. Null for a restored watch-only session (the wallet address is never persisted). |
| `GP.state.keys` | `object \| null` | `{ viewPriv, viewPub, spendPub, spendPriv, meta }`, all `0x`-hex strings except `meta` which is the `st:eth:0x…` ERC-5564 meta-address. `spendPriv` is `null` in watch-only sessions. Null when locked. |
| `GP.state.meta` | `string \| null` | The user's stealth meta-address (`st:eth:0x` + 128 hex chars). |
| `GP.state.recv` | `object \| null` | Current one-time receiving address: `{ stealth, ephPub, viewTag, sh }` as produced by `GP.crypto.derive`. |
| `GP.state.ethPriceUsd` | `number \| null` | Last ETH price seen by the status strip (`GET /price`). Null until a price poll succeeds. |
| `GP.state.payments` | `Array<Payment>` | Live array of every payment card rendered this session (see Payment below). Mutated in place by scans; do not replace the array. |

`Payment`: `{ address: string, ephPub: string, block: number, tx: string, swept: boolean, fresh: boolean }`.
`fresh` is true only when the payment was discovered by an incremental background scan
(false on full rescans). `swept` flips to true when a sweep for that address confirms
via the relayer.

### Signing

- `GP.state.signer(): Promise<ethers.Signer>` : resolves an ethers signer from the
  injected provider. Throws if the session is WalletConnect or watch-only.
- `GP.state.walletRequest(method: string, params: any[]): Promise<any>` : provider
  agnostic request. Uses the WalletConnect session (`eip155:1`) when present, else the
  connected EIP-1193 provider, else `window.ethereum`. Throws when no wallet is connected.

Rules: never persist `keys.spendPriv` anywhere. Sweeping always requires a fresh
wallet signature in the current session.

## Actions

- `GP.scan(fromBlock?: number): Promise<Payment[]>` : full rescan. Wipes and re-renders
  `#payments`, resets `GP.state.payments`, respects the stored scan cursor unless
  `fromBlock` is given. Resolves the (live) payments array.
- `GP.scanIncremental(): Promise<Payment[]>` : append-only scan from the stored cursor.
  Existing cards are kept; only newly discovered payments are appended and emitted.
  Safe to call on a timer (the core already does, every 60s).
- `GP.announce(): Promise<{ hash: string, via: 'relayer' | 'wallet' } | null>` :
  announces the current receiving address (`GP.state.recv`) on the ERC-5564 announcer.
  Tries the local relayer first (`POST /announce`), falls back to the user's wallet.
  Resolves null on failure (the status line already shows the error).
- `GP.relaySweep(artifact: object): Promise<void>` : broadcasts a signed sweep artifact
  via `POST /sweep` and updates the broadcast status line through confirmation. Emits
  `swept` on success.

## Formatting

- `GP.fmt.formatEth(wei: bigint | string | number): string` : wei to a trimmed ETH
  decimal string (`'0.5'`, not `'0.500000'`).
- `GP.fmt.formatUsd(eth: number | string, usdPrice?: number): string | null` : ETH
  amount to a display string like `'$1,234.56'`. Uses `GP.state.ethPriceUsd` when
  `usdPrice` is omitted; returns null when no price is available.

## UI primitives

- `GP.toast(msg: string): void` : transient bottom toast, auto-dismisses after 4s.

## Events

- `GP.on(event: string, cb: (data: any) => void): void`
- `GP.emit(event: string, data: any): void`

Listener exceptions are caught and logged, they never break the emitter. Core events:

| Event | Payload | Fired when |
|---|---|---|
| `"payment"` | `Payment` | A payment matching the user's keys is found by any scan. `payload.fresh === true` means it arrived via the incremental background poll. |
| `"swept"` | `{ hash, block, artifact, payment }` | A relayer-broadcast sweep confirms onchain. `payment` is the matching `Payment` record or null. |
| `"session"` | `{ type, watchOnly?, address? }` | `type` is one of `"unlocked"` (fresh key derivation), `"saved"` (user opted into device persistence), `"restored"` (watch-only session loaded at boot), `"forgotten"` (session wiped). |

The core's own notification listener is a reference consumer: it fires a
`Notification` only for `payment` events with `fresh === true` and only after the
user pressed ENABLE NOTIFICATIONS.

## Crypto (GP.crypto)

Vendored, no network. BigInt in, BigInt out for poseidon.

- `secp256k1`, `keccak_256`, `sha256` : the @noble primitives.
- `hex(bytes: Uint8Array): string` / `buf(hexStr: string): Uint8Array` : `0x` hex codecs.
- `N: bigint`, `mod(x: bigint): bigint` : secp256k1 group order and reduction.
- `derive(metaHex: string): { stealth, ephPub, viewTag, sh }` : sender side. Generates a
  fresh ephemeral key and the one-time stealth address for a meta-address (without the
  `st:eth:` prefix).
- `check(viewPriv, spendPub, ephPub, addr): { match: boolean, viewTag: number, sh: string }` :
  scanner side. Honors the active scheme (keccak, or sha256 when legacy is on).
- `stealthKey(spendPriv: string, sh: string): string` : spend private key of a stealth
  address. Never store the result.
- `sign7702(priv, chainId, sweeper, nonce): { chainId, address, nonce, yParity, r, s }` :
  EIP-7702 authorization signature.
- `poseidon1`, `poseidon2`, `poseidon3` : `(bigint[]) => bigint`, vendored.
- `ppCommitment(value, label, precommitment): bigint`
- `spentNullifierHash(nullifier: bigint): bigint`
- `deriveChangeKeys(nullifier, secret): { newNullifier: bigint, newSecret: bigint }`
- `computeContext(processooor: string, data: string, scope: bigint): bigint`
- `leanIMTBuild(leaves: bigint[]): { levels: bigint[][], root: bigint }`
- `leanIMTProof(levels: bigint[][], leafIndex: number): bigint[]` (32 siblings)
- `getLegacy(): boolean` / `setLegacy(b: boolean): void` : the sha256 legacy scheme flag
  (pre 2026-09-08 announcements). Reflects the legacy checkbox.

## Privacy Pools (GP.pp)

Constants and helpers for the withdrawal flow:

`PP_POOL`, `PP_ENTRYPOINT`, `PP_ETH_ASSET`, `PP_ASP`, `PP_RELAYER` (strings),
`SNARK_FIELD` (bigint), `PP_IFACE` and `SWEEPER_IFACE` (ethers Interface),
`ppCall(data: string): Promise<string>` (eth_call against the pool),
`ppFindDeposit(precommitmentHash: bigint, timestamp?: string, say: (msg: string) => void): Promise<{ label, commitment, value, blockNumber }>`.

## Misc

- `GP.jrpc(method: string, params: any[]): Promise<any>` : browser-side JSON-RPC with
  endpoint rotation and 15s timeout per endpoint.
- `GP.ethers` : the ethers v6 module namespace.
- `GP.const` : `{ ANNOUNCER, CHAIN_ID, SWEEPER, RPC }` (chainId 1, mainnet only).

## DOM contract

Mount points a module may render into (append only, never replace other children):

| Id | Location | Intended use |
|---|---|---|
| `gp-status` | Top of the page, above the logo | The core owns the text content of this strip. Modules must NOT write here; it is listed so modules can read relayer state from the DOM if needed. |
| `gp-dash` | Below the logo, visible when a session exists | Returning-user dashboard. Contains RE-CONNECT, ENABLE NOTIFICATIONS, FORGET THIS DEVICE. |
| `gp-inbox` | Inside step 4 (SWEEP), after the sweeper UI | Module mount point: anything about detected payments. Core payment cards render in the sibling `#payments`. |
| `gp-sweep` | Inside step 4, after `#gp-inbox` | Module mount point: sweep-side features. |
| `gp-withdraw` | Inside step 5 (WITHDRAW), at the end | Module mount point: withdrawal-side features. |
| `gp-invoices` | Inside step 3 (INVOICE), at the end | Module mount point: invoice-side features. |
| `gp-toast` | Fixed bottom overlay | Owned by `GP.toast`. Do not write here directly. |

Styling: the app is monospace on black (`#000` bg, `#fff` fg, `#333` borders,
`.status` for muted lines, `.card` for inverted boxes, `button.ghost` for secondary
actions). Match it. Buttons are full width by default; on screens under 700px
everything stacks and buttons are at least 44px tall.

Session storage keys modules may read (never write): `gp-session` (JSON
`{ v, viewPriv, meta, ts }`, viewing key only) and `ghostpay:lastScanned:<viewPub>`
(scan cursor). The spend key is deliberately absent from storage.

## Relayer endpoints consumed by the status strip

The strip polls `GET ./health`, `GET ./fee`, `GET ./price` every 60s and degrades
gracefully on any non-200. Field names are probed defensively; the shapes serve.mjs
currently returns (all handled):

- `/health` → `{ ok: true, chainId: 1, runners: string[], runnerCount: number, sweeperV2: string | null, tor: boolean, … }`
- `/fee` → `{ minFeeBps: number }` (rendered as a percentage; `minFeeGwei` also handled)
- `/price` → `{ ethereum: { usd: number }, … }` (CoinGecko shape; flat `usd` also handled)
