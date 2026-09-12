# GHOSTPAY module API (window.GP)

`app-core.mjs` exposes a single global, `window.GP`, so feature modules ship as separate
`<script type="module">` files without ever editing the page. This document is the
contract: if it is not written here, modules must not rely on it.

Version: `GP.version === '1.0-ui-core'`.

## The app shell

ghostpay is one single-page app: `index.html` with four hash routes, switched by
display toggling only (never innerHTML), so modules can render into hidden tabs at
any time.

| Route | Tab | Contents |
|---|---|---|
| `#/get-paid` | GET PAID | The receive journey: a four-step stepper (connect, generate, amount, share) owned by the homepage inline module. Default route. |
| `#/pay` | PAY | The payer flow: paste a payment link or land here directly from a `#st:eth:0x…` hash. |
| `#/funds` | FUNDS | The app-core wizard: connect, generate, sweep, withdraw, plus the returning-user dashboard. |
| `#/invoices` | INVOICES | The invoice suite: `#gp-invoices` with its own seven-pane tab shell. |

`app.html` and `invoices.html` are redirects into `#/funds` and `#/invoices`. A
payment-link hash (`#st:eth:0x…`, no `#/` prefix) is not a route: it forces the PAY
tab and reveals the payer flow before any module evaluates, because gp-invoices.mjs
enhances `#payghost` only if it is visible at its boot.

## Script load order on index.html

1. `config.local.js` (optional, classic script, removed on error)
2. `app-core.mjs` (owns `window.GP`)
3. `gp-inbox.mjs`
4. `gp-money.mjs`
5. `gp-invoices.mjs`
6. `gp-reports.mjs`
7. the homepage inline `<script type="module">` (GET PAID journey + PAY tab + the GP merge)

Script order is the only guarantee needed: `window.GP` is fully assembled before any
feature module executes. Modules must not import ethers or crypto from a CDN
themselves; use `GP.ethers` and `GP.crypto`.

## The GP merge

Two scripts on the page can produce a `window.GP`: app-core.mjs (the full module
API) and the homepage inline module (the old payer shim, version `1.0-homepay`).
The inline module loads last and reconciles instead of replacing, because the
feature modules already captured app-core's object:

- `GP.const.PAY_AND_ANNOUNCE` is added by the inline module: the one-transaction
  pay + announce contract the PAY tab (and gp-invoices' `enhancePayghost`) needs.
  app-core does not define it.
- `GP.state.walletRequest` is wrapped: app-core's wallet session is tried first,
  the inline module's own wallet state (the PAY tab's wallet) is the fallback. The
  two sessions stay separate by design: the same wallet signature regenerates the
  same keys in both, and nothing attempts to unify them.

If app-core never landed (its script tag failed), the inline module installs the
standalone `1.0-homepay` shim instead, enough of the API for the PAY tab.

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
| `GP.state.armedIntent(addr)` | `artifact \| null` | The auto-armed `eip7702-intent` artifact for a stealth address (secret downloaded, SweepIntent + 7702 authorization signed at detection time). Null when nothing is armed: watch-only session, a relayer without `sweeperV2`, or a balance below the 0.01 ETH pool minimum. |

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
  On index.html the homepage merge wraps this to also try the PAY tab's wallet as a
  fallback (see "The GP merge").

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
- `GP.relaySweep(artifact: object, onHash?: (hash: string) => void): Promise<void>` :
  broadcasts a signed sweep artifact via `POST /sweep` and updates the broadcast
  status line through confirmation. Emits `swept` on success.
- `GP.relayerCaps(): Promise<{ sweeperV2: boolean, sweeperV2Addr: string | null, minFeeBps: number }>` :
  the relayer's capabilities, fetched once per session from `GET ./health` + `GET ./fee`
  and cached. `sweeperV2` true means the relayer accepts `eip7702-intent` artifacts;
  `minFeeBps` is the fee floor intents must pay (default 30 when the relayer is offline).

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
- `intentDomain(stealthAddress: string): object` : the EIP-712 domain for SweeperV2 sweep
  intents (`{ name: 'GhostpaySweeper', version: '1', chainId: 1, verifyingContract: stealthAddress }`;
  the verifying contract is the stealth EOA itself, since SweeperV2 executes as the EOA
  under 7702). Pair with `signTypedData` from an ethers Wallet over `INTENT_TYPES`.
- `INTENT_TYPES` : the EIP-712 types object for
  `SweepIntent(uint8 action,address token,address destination,uint256 precommitment,uint256 feeBps,uint256 deadline)`.
  Actions: 0 = ETH to destination, 1 = Privacy Pools ETH deposit, 2 = PP token deposit,
  3 = token to destination.
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
- `GP.const` : `{ ANNOUNCER, CHAIN_ID, SWEEPER, SWEEPER_V2, RPC, PAY_AND_ANNOUNCE }`
  (chainId 1, mainnet only). `SWEEPER` is the legacy v1 sweeper; `SWEEPER_V2` is the
  deployed signed-intent sweeper (use it when `GP.relayerCaps().sweeperV2` is true,
  fall back to `SWEEPER` otherwise). `PAY_AND_ANNOUNCE` is added by the homepage
  merge (see above): the one-transaction pay + announce contract.

## DOM contract

Mount points a module may render into (append only, never replace other children).
All ids live on `index.html`; sections toggle by display only, so hidden mounts are
safe to render into at any time.

| Id | Route / location | Intended use |
|---|---|---|
| `gp-status` | Top of the page, above the routes | The core owns the text content of this strip (relayer health, fee floor, ETH price, 60s refresh). Modules must NOT write here; it is listed so modules can read relayer state from the DOM if needed. |
| `getpaid` | GET PAID | The receive journey stepper (`r-p0`…`r-p3`, `r-*` ids), owned by the homepage inline module. Not a module mount. |
| `r-recovery` | GET PAID, below the stepper | RECOVERY banner for un-announced receive records (`gp-recv-records`). Owned by the inline module. |
| `doors` / `payflow` / `payghost` | PAY | The payer flow, owned by the inline module. gp-invoices enhances `#payghost` (memo field `#gpinv-memo`, invoice-pinned address) when it is visible at boot. |
| `gp-dash` | FUNDS, visible when a session exists | Returning-user dashboard. Contains RE-CONNECT, ENABLE NOTIFICATIONS, FORGET THIS DEVICE. |
| `s1` … `s4` | FUNDS | The app-core wizard steps: connect, generate, sweep, withdraw. Owned by app-core. |
| `payments` | FUNDS, inside `s3` | Core payment cards. |
| `gp-inbox` | FUNDS, inside `s3`, after the sweeper UI | Module mount point: anything about detected payments (gp-inbox). |
| `gp-sweep` | FUNDS, inside `s3`, after `#gp-inbox` | Module mount point: sweep-side features (gp-money). |
| `gp-withdraw` | FUNDS, inside `s4`, at the end | Module mount point: withdrawal-side features (gp-money). |
| `gp-invoices` | INVOICES | The invoice suite mount (gp-invoices + gp-reports). Contains the `#gp-tabs` bar and seven panes: `tab-dashboard`, `tab-invoices`, `tab-customers`, `tab-items`, `tab-recurring`, `tab-reports`, `tab-settings`. gp-invoices fills invoices/customers/items/recurring/settings; gp-reports fills dashboard/reports. Renderers tolerate any pane being absent. |
| `gp-toast` | Fixed bottom overlay | Owned by `GP.toast`. Do not write here directly. |

Styling: the app is monospace on black (`#000` bg, `#fff` fg, `#333` borders,
`.status` for muted lines, `.card` for inverted boxes, `button.ghost` for secondary
actions); the shared design system lives in `gp-ui.css` (fixed nav, `.gp-card`,
`.gp-table`, `.gp-pill`, `.gp-tabs`, warm off-black + bone palette). Match it.
Buttons are full width by default; on screens under 700px everything stacks and
buttons are at least 44px tall.

Session storage keys modules may read (never write): `gp-session` (JSON
`{ v, viewPriv, meta, ts }`, viewing key only), `gp-recv-records` (un-announced
receive addresses, the RECOVERY banner source), and `ghostpay:lastScanned:<viewPub>`
(scan cursor). The spend key is deliberately absent from storage.

## Invoice storage: schema v4

The invoice suite persists under `gp-profile` (profile) and per-invoice records.
Current schema is v4:

- **Per-line rates.** Each line item carries its own `taxPct` and `discountPct`.
  Per-line values win; the invoice-level `taxPct` / `discountPct` are only defaults
  for lines that leave them blank.
- **`taxLines`.** The grouped tax block stored on the record:
  `[{ rate, base, amount }]` sorted by rate. `computeTotals(items, taxPct, discountPct)`
  returns `{ subtotal, discountPct, discountAmount, taxPct, taxAmount, taxLines, total }`.
  `taxLinesOf(rec)` reads a v4 record's stored block and synthesizes one for older
  records, so issued documents never shift by a rounding cent.
- **`taxNumber`.** Profile field: VAT / tax id printed on documents.
- **Upgrade.** v3 → v4 is additive and idempotent: each line gains
  `taxPct`/`discountPct` seeded from the legacy invoice-level rates, and the record
  gains `taxLines` synthesized from the stored v3 totals.

## Relayer endpoints consumed by the status strip

The strip polls `GET ./health`, `GET ./fee`, `GET ./price` every 60s and degrades
gracefully on any non-200. Field names are probed defensively; the shapes serve.mjs
currently returns (all handled):

- `/health` → `{ ok: true, chainId: 1, runners: string[], runnerCount: number, runnerBalances: object, sweeperV2: string | null, batchRelayer: string | null, minFeeBps: number, ppRelay: boolean, ppFeeBps?: number, feeOwner: string | null, rateLimited: true, authRequired?: true, tor: boolean, endpoints: string[] }`
- `/fee` → `{ minFeeBps: number }` (rendered as a percentage; `minFeeGwei` also handled)
- `/price` → `{ ethereum: { usd: number }, … }` (CoinGecko shape; flat `usd` also handled)

The full relayer API contract lives in `api.html` (browsable under `docs/`).
