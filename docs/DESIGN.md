# GHOSTPAY design system · wave-2 contract

`gp-ui.css` is the single source of truth: tokens + primitives, dark only. Every
surface (index.html routes, `frag-*.html`, module-rendered HTML) consumes it. If a
style is not here, add it here first, do not improvise it locally.

Palette in one line: bone (`#ece7db`) on warm off-black (`#14120f`), hairline
borders, one restrained amber accent, muted semantic colours. Never pure `#000`/`#fff`.
Typography: Space Grotesk for display/headings/wordmark/nav, IBM Plex Mono for body,
data, labels, buttons. Fonts are vendored woff2 in `vendor/fonts/` (latin subsets,
`font-display: swap`, precached by `sw.js`): never load fonts from a CDN.

## 1 · Tokens

Colour:

| Token | Value | Use |
|---|---|---|
| `--gp-bg` | `#14120f` | page background |
| `--gp-bg-raise` | `#1b1814` | raised surfaces: cards, steps, stats |
| `--gp-bg-inset` | `#0e0c0a` | inset wells: inputs, tab tracks, bar tracks |
| `--gp-sheen` | `#292318` | skeleton shimmer highlight |
| `--gp-fg` | `#ece7db` | bone foreground |
| `--gp-muted` | `#a39e92` | secondary text |
| `--gp-faint` | `#6b665b` | placeholders, least-important text |
| `--gp-line` | `rgba(236,231,219,.13)` | hairline borders |
| `--gp-line-soft` | `rgba(236,231,219,.07)` | table row separators |
| `--gp-line-strong` | `rgba(236,231,219,.26)` | active/hover hairline |
| `--gp-accent` | `#d9a441` | the one accent (warm amber) |
| `--gp-accent-hi` | `#e9b95c` | accent hover |
| `--gp-accent-ink` | `#14120f` | text on the accent |
| `--gp-ok` / `--gp-ok-bg` | `#86ac6c` / rgba | paid, success |
| `--gp-danger` / `--gp-danger-bg` | `#cd6f5e` / rgba | overdue, destructive |
| `--gp-info` / `--gp-info-bg` | `#a39e92` / rgba | pending, neutral |

The accent is user-customisable: `gp-profile.accentColor` in localStorage is applied
to `--gp-accent` on `<html>` by the inline script at `index.html:11`. Never hardcode
the amber; always `var(--gp-accent)`. Never set `--gp-accent` yourself. Semantic
colours are for status only (pills, status text, borders on armed/danger states),
never for decoration.

Typography:

| Token | Value | Use |
|---|---|---|
| `--gp-font-display` | Space Grotesk stack | display, headings, wordmark, nav |
| `--gp-font-mono` | IBM Plex Mono stack | body, data, labels, buttons, tables |
| `--gp-fs-display` | `clamp(2.5rem,4.5vw,3.5rem)` (40–56px) | the route wordmark only |
| `--gp-fs-h2` | 26px | section headings |
| `--gp-fs-h3` | 18px | card headings, step titles |
| `--gp-fs-body` | 14px | body copy |
| `--gp-fs-small` | 12.5px | dense body, status lines, buttons |
| `--gp-fs-micro` | 11px | eyebrows, pills, table headers, meta |

Space, radius, motion:

| Token | Value |
|---|---|
| `--gp-s1`…`--gp-s8` | 4 · 8 · 12 · 16 · 24 · 32 · 48 · 64px |
| `--gp-radius` | 10px (cards) |
| `--gp-radius-sm` | 6px (controls) |
| `--gp-t` | `160ms ease` (interactive transitions) |
| `--gp-shadow` | `0 8px 24px rgba(0,0,0,.4)` (toast only; surfaces stay flat) |
| `--gp-nav-h` | 48px |

## 2 · Primitives

Minimal snippets. All classes live in `gp-ui.css`; do not restyle them per surface.

### Buttons · `.gp-btn`
Variants: `.primary` (accent fill, the one strong action per view), `.ghost`,
`.danger`, `.small`, `.block` (full width). Base is the neutral secondary action.
```html
<button class="gp-btn primary block">Sign · generate stealth keys</button>
<button class="gp-btn ghost">Skip</button>
<button class="gp-btn danger small">Delete</button>
```
Bare `<button>` elements (no class) keep the legacy full-width accent look from
index.html until wave 2 converts them; convert to `.gp-btn` as you touch each surface.

### Card · `.gp-card`
```html
<div class="gp-card">…</div>
```
`.gp-card.on` marks the active/highlighted card. The inverted bone `.card` (light
surface, dark text) still exists for copyable secrets/addresses in the old flows:
prefer `.gp-card` for new work and let wave 2 retire `.card` surface by surface.

### Inputs · `.gp-input` `.gp-select` `.gp-textarea`
```html
<label class="gp-eyebrow" for="x">Amount</label>
<input class="gp-input" id="x" type="number" min="0" step="any" placeholder="0.0">
```

### Pills · `.gp-pill`
Tones: `.ok` (paid), `.danger` (overdue), `.info` (pending/neutral), `.dim`
(archived/draft). Bare `.gp-pill` is the outline idiom.
```html
<span class="gp-pill ok">Paid</span> <span class="gp-pill danger">Overdue</span>
```

### Tables · `.gp-tablewrap` + `.gp-table`
```html
<div class="gp-tablewrap"><table class="gp-table">
  <thead><tr><th>Invoice</th><th>Client</th><th>Total</th></tr></thead>
  <tbody><tr><td>…</td><td>…</td><td>…</td></tr></tbody>
</table></div>
```

### Tabs · `.gp-tabs` + `.gp-tab` + `.gp-tabpane`
Segmented control, scrolls horizontally on overflow. `.on` is the active tab.
```html
<div class="gp-tabs">
  <button type="button" class="gp-tab on" data-tab="pane-a">Overview</button>
  <button type="button" class="gp-tab" data-tab="pane-b">History</button>
</div>
<div class="gp-tabpane" id="pane-a">…</div>
```

### Stat · `.gp-stat`
```html
<div class="gp-stat">
  <div class="gp-stat-label">Received</div>
  <div class="gp-stat-num">1.25 <span class="gp-stat-unit">ETH</span></div>
</div>
```

### Bar · `.gp-bar`
```html
<div class="gp-bar"><span class="gp-bar-label">ETH</span>
  <span class="gp-bar-track"><span class="gp-bar-fill" style="width:62%"></span></span>
  <span class="gp-bar-val">$4,120</span></div>
```

### Stepper · `.gp-step` (vertical) and `.gp-steps` + `.gp-step-i` (progress row)
```html
<ol class="gp-steps">
  <li class="gp-step-i done">1 · Connect</li>
  <li class="gp-step-i on">2 · Generate</li>
  <li class="gp-step-i">3 · Share</li>
</ol>
<div class="gp-step on">
  <div class="gp-step-head"><span class="gp-step-num">2</span>
    <span class="gp-step-title">Generate address</span></div>
  …
</div>
```

### Skeleton · `.gp-skeleton`
Shimmer block for loading states. Size it inline to echo the content it replaces:
```html
<span class="gp-skeleton" style="height:52px;width:60%"></span>
```
The boot skeleton lives in `#bootline` (FUNDS route) and is cleared by app-core's
400ms wallet-check write, not by anything you must call.

### Empty state · `.gp-empty`
```html
<div class="gp-empty"><div class="gp-empty-title">No invoices yet</div>
  Create your first invoice to get a private payment link.</div>
```

### Key/value rows · `.gp-kv`
```html
<div class="gp-kv"><span class="gp-k">Fee floor</span><span class="gp-v">0.30%</span></div>
```

### Toast · `.gp-toast`
Class form of `#gp-toast`. In app code call `GP.toast(msg)`; never write to
`#gp-toast` directly.

### Layout + text utilities
`.gp-container` (960px app shell) · `.gp-measure` (640px reading measure for prose
flows) · `.gp-section` · `.gp-label` · `.gp-eyebrow` · `.gp-h2` · `.gp-h3` ·
`.gp-muted` · `.gp-faint`.

## 3 · Existing shell classes you must keep working

JS and the frag fallback strings bind these. Add classes, never rename or remove:
`.gp-nav` `.gp-nav-logo` `.gp-nav-link` (+`.on`) · `#gp-status` · `#gp-toast` ·
`.gp-route` · `.wrap` `.logo` `.sub` · `.step` (+`.on`) · `.card` `.lbl` `.status`
`.ok` · `.door` `.door-t` `.door-d` · `.r-tabs` `.r-tab` `.r-panel` ·
`#gp-dash` `.dashaddr` `.dashmode` `.dashbtns` · `.gp-tabs` `.gp-tab` `.gp-tabpane`.
Retired with the old duplicate lists (kept here so old branches read clearly): the
`.pay` cards and the `.r-row`/`.r-pill`/`.r-spanel`/`.r-secret`/`.gp-pulse` GET PAID
rows. All payment rows are the inbox's (`.gp-inbox-root` scope in `frag-inbox.html`);
gp-inbox injects its own `.gp-pulse` when a broadcast is live.
The full mount/id contract is `docs/GP-API.md`; it wins over this file.

## 4 · Copy rules

- British English: finalised, cancelled, anonymised, labelled.
- Never "on-chain"/"off-chain": always onchain/offchain.
- No em dashes in UI copy: use colons, full stops, or ·.
- Sentence case everywhere. Letter-spaced ALL-CAPS is allowed only for small
  overlines/eyebrows (`.gp-eyebrow`, `.gp-label`), never for body copy or buttons.
- Facts, no throat-clearing.
- Verbatim exceptions (never touch): the key-derivation sign message
  `GHOSTPAY v1 — derive stealth keys. This signature spends nothing.` (load-bearing:
  changing it changes every derived key), contract names, ERC/EIP numbers.

## 5 · Do not

- Do not rename or remove any id/class/mount in `docs/GP-API.md` or polled by the
  `.mjs` modules. New id hooks: document them in `docs/GP-API.md` AND this file in
  the same commit.
- No inline hardcoded colours (`style="color:#…"`, `background:#fff` etc.). Use
  `var(--gp-*)`. Existing legacy inline styles are being retired surface by surface;
  never add new ones. Inline width/height for sizing (skeletons, bar fills, QR
  canvases) is fine.
- No new `@font-face`, no font CDNs, no other typefaces, no light theme.
- Do not set `--gp-accent` (the profile hook owns it) and do not introduce a second
  accent colour.
- No em dashes, no "on-chain"/"off-chain" (see copy rules).
- If you edit a `frag-*.html`, update its byte-identical fallback string in the
  owning `.mjs` in the same commit; `npm run check` must pass.
- Never touch stealth crypto, key derivation, sweep/withdraw logic, `serve.mjs`,
  `config.local.js`.
- Keep the 700px mobile breakpoint, 44px touch targets, and 16px inputs on mobile.
- Honour `prefers-reduced-motion` (the system already does; do not add animation
  that bypasses it) and keep `:focus-visible` rings visible.
- No framework, no build step, no new runtime dependencies.

## 6 · Known seams (wave-2 heads-up)

- `frag-inbox.html` (and its fallback in `gp-inbox.mjs`) injects UNSCOPED
  `.gp-pill` / `.gp-label` / `.gp-row` / `.gp-actions` / `.gp-panel` rules that
  override the system classes at runtime. Tokenise and scope them to `#gp-inbox-root`
  when you own that surface; do not leave new globals.
- `frag-invoices.html` / `frag-reports.html` / `frag-money.html` carry their own
  scoped styles with hardcoded `#333`/`#888`/`#fff`: replace with tokens as you
  rework each suite surface.
- The invoice/estimate switcher buttons use a bare `.on` class styled only by the
  invoice frag; convert to `.gp-tabs` or `.gp-btn` with an explicit state class.
- `#bootline` belongs to app-core (wallet detection + gentest write to it). Keep
  the skeleton children as the only pre-boot content.
