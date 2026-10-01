// gp-inbox.mjs · GHOSTPAY payment inbox + token detection. Module contract: docs/GP-API.md.
// The ONE payment list: rendered by this module into both inbox mounts, FUNDS step 3
// (#gp-inbox, canonical ids) and GET PAID's payments section (#r-rows). All payment
// data comes from app-core's scanner: GP.state.payments plus the payment/swept events.
// Load AFTER app-core.mjs: <script type="module" src="./gp-inbox.mjs"></script>
// Markup comes from frag-inbox.html (fetched and injected by this module, with an
// embedded copy as the offline fallback). The frag's rules are scoped to the
// .gp-inbox-root class so every mounted instance shares them.
// app-core's module graph can delay window.GP assembly past this module's
// evaluation (the same race gp-invoices/gp-reports handle): wait for it instead of dying.
const GP = await (async () => {
  for (let i = 0; i < 60; i++) {
    if (window.GP && window.GP.version) return window.GP;
    await new Promise(r => setTimeout(r, 500));
  }
  return null;
})();
if (!GP) throw new Error('gp-inbox: window.GP never appeared · load this module after the core inline script');
// the homepage's standalone shim (app-core failed to load) is not enough: no events,
// no scan, no pp helpers. Stay out rather than mount a dead list.
const FULL_CORE = typeof GP.on === 'function' && typeof GP.jrpc === 'function' && !!(GP.pp && GP.crypto && GP.state);
if (!FULL_CORE) console.warn('gp-inbox: app-core API incomplete (shim GP) · inbox disabled');
const ethers = GP.ethers;

const TOKENS = [
  { sym: 'USDC', addr: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', dec: 6 },
  { sym: 'USDT', addr: '0xdAC17F958D2ee523a2206206994597C13D831ec7', dec: 6 },
  { sym: 'DAI',  addr: '0x6B175474E89094C44Da98b954EedeAC495271d0f', dec: 18 },
  { sym: 'WETH', addr: '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2', dec: 18 },
];
const USDC = TOKENS[0];
const BALANCE_OF = '0x70a08231';
const PP_MIN = 10000000000000000n; // 0.01 ETH: below this a deposit cannot enter Privacy Pools
const PP_LOG_CHUNK = 5000;         // drpc eth_getLogs caps out around 10k blocks
const SWEEPETH_IFACE = new ethers.Interface(['function sweepETH(address to)']);
const USDC_712_DOMAIN = { name: 'USD Coin', version: '2', chainId: 1, verifyingContract: USDC.addr };
const USDC_712_TYPES = { TransferWithAuthorization: [
  { name: 'from', type: 'address' }, { name: 'to', type: 'address' }, { name: 'value', type: 'uint256' },
  { name: 'validAfter', type: 'uint256' }, { name: 'validBefore', type: 'uint256' }, { name: 'nonce', type: 'bytes32' },
] };
const BATCH_MAX = 20;                          // serve.mjs accepts 1-20 sweeps per eip7702-intent-batch
const GATE_KEY = 'gp-money:backup-gate';       // gp-money's secret-backup gate (read-only here)

// pill ladder; 'direct' is a terminal off-ladder state for sweeps that skip the pool
const STAGES = ['detected', 'sweeping', 'in_pool', 'asp_pending', 'withdrawable', 'withdrawn'];
const PILL_TEXT = {
  detected: 'DETECTED', sweeping: 'SWEEPING', in_pool: 'IN POOL', asp_pending: 'ASP PENDING',
  withdrawable: 'WITHDRAWABLE', withdrawn: 'WITHDRAWN', direct: 'SWEPT DIRECT',
};
// display tone per stage: pending states dim/info, terminal states ok
const PILL_TONE = {
  detected: 'dim', sweeping: 'info', in_pool: 'info', asp_pending: 'dim',
  withdrawable: 'ok', withdrawn: 'ok', direct: 'ok',
};
const stageRank = s => s === 'direct' ? 99 : STAGES.indexOf(s);

// ── storage (labels + pill state, both keyed by lowercase stealth address) ──
const lsGet = (k, d) => { try { const v = JSON.parse(localStorage.getItem(k)); return v ?? d; } catch { return d; } };
const lsSet = (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* storage blocked: inbox state is best-effort */ } };
const getLabel = a => (lsGet('gp-labels', {})[a.toLowerCase()] || '');
const setLabel = (a, t) => { const m = lsGet('gp-labels', {}); const k = a.toLowerCase(); if (t) m[k] = t; else delete m[k]; lsSet('gp-labels', m); };
const getPill = a => lsGet('gp-inbox-pills', {})[a.toLowerCase()] || null;
const putPill = (a, patch) => {
  const m = lsGet('gp-inbox-pills', {}); const k = a.toLowerCase();
  m[k] = { ...(m[k] || {}), ...patch };
  lsSet('gp-inbox-pills', m);
};

// ── caches: /price (60s), block timestamps, ASP snapshot (120s) ──
let priceCache = { ts: 0, eth: null, usdc: null };
async function getPrices() {
  if (priceCache.eth && Date.now() - priceCache.ts < 60000) return priceCache;
  try {
    const r = await fetch('./price');
    if (r.ok) {
      const j = await r.json();
      priceCache = { ts: Date.now(), eth: j?.ethereum?.usd ?? GP.state.ethPriceUsd, usdc: j?.['usd-coin']?.usd ?? 1 };
      return priceCache;
    }
  } catch { /* relayer down: fall back to whatever the status strip last saw */ }
  priceCache = { ts: Date.now(), eth: priceCache.eth ?? GP.state.ethPriceUsd, usdc: priceCache.usdc ?? 1 };
  return priceCache;
}
const timeCache = new Map();
async function blockTime(b) {
  if (timeCache.has(b)) return timeCache.get(b);
  const blk = await GP.jrpc('eth_getBlockByNumber', ['0x' + b.toString(16), false]);
  const s = new Date(parseInt(blk.timestamp, 16) * 1000).toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
  timeCache.set(b, s);
  return s;
}
let aspCache = new Map(); // pool address (lowercase) -> { ts, promise }
function getAsp(pool) {
  const poolAddr = pool || GP.pp.PP_POOL;
  const key = poolAddr.toLowerCase();
  const cur = aspCache.get(key);
  if (cur && cur.promise && Date.now() - cur.ts < 120000) return cur.promise;
  const promise = (async () => {
    const scope = BigInt(await GP.pp.ppCallPool(poolAddr, GP.pp.PP_IFACE.encodeFunctionData('SCOPE', [])));
    const res = await fetch(GP.pp.PP_ASP + '/mt-leaves', { headers: { 'X-Pool-Scope': scope.toString() } });
    if (!res.ok) throw new Error('ASP leaves fetch failed (' + res.status + ')');
    const { aspLeaves } = await res.json();
    return new Set(aspLeaves.map(x => BigInt(x)));
  })();
  aspCache.set(key, { ts: Date.now(), promise });
  return promise;
}
const fetchJson = async u => { const r = await fetch(u); if (!r.ok) throw new Error('http ' + r.status); return r.json(); };

// the tracking record written at arm time (app-core): fields beyond nullifier/
// precommitment/amount/ts exist only for token pool notes; missing fields mean ETH.
const noteFor = addr => lsGet('ghostpay:ppnote:' + addr.toLowerCase(), null);
const notePool = note => (note && typeof note.pool === 'string' && ethers.isAddress(note.pool)) ? note.pool : GP.pp.PP_POOL;
const noteSym = note => (note && typeof note.asset === 'string' && note.asset) || 'ETH';
const noteDec = note => (note && Number.isFinite(note.decimals)) ? note.decimals : 18;
const fmtNote = (note, v) => trim(ethers.formatUnits(v, noteDec(note))) + ' ' + noteSym(note);

// ── deposit + withdrawal trace (the pool/ASP lifecycle tracing lives in this module) ──
async function findDeposit(addr, fromBlock, pool) {
  const topic = GP.pp.PP_IFACE.getEvent('Deposited').topicHash;
  const depTopic = ethers.zeroPadValue(addr, 32);
  const end = Math.min(fromBlock + 100000, parseInt(await GP.jrpc('eth_blockNumber', []), 16));
  for (let e = end; e >= fromBlock; e -= PP_LOG_CHUNK) {
    const s = Math.max(e - PP_LOG_CHUNK + 1, fromBlock);
    const logs = await GP.jrpc('eth_getLogs', [{ address: pool || GP.pp.PP_POOL, topics: [topic, depTopic], fromBlock: '0x' + s.toString(16), toBlock: '0x' + e.toString(16) }]);
    if (logs.length) {
      const p = GP.pp.PP_IFACE.parseLog(logs[logs.length - 1]);
      return { label: BigInt(p.args._label), value: BigInt(p.args._value), block: parseInt(logs[logs.length - 1].blockNumber, 16) };
    }
  }
  return null;
}
async function isWithdrawn(addr) {
  const rec = noteFor(addr);
  if (!rec || !rec.nullifier) return null; // no tracking record on this device: state unknown
  const spent = BigInt(await GP.pp.ppCallPool(notePool(rec), GP.pp.PP_IFACE.encodeFunctionData('nullifierHashes', [GP.crypto.spentNullifierHash(BigInt(rec.nullifier))])));
  return spent !== 0n;
}

// ── status machine: ground truth from chain + ASP, persisted pill as the floor ──
async function computeStage(row) {
  const addr = row.rec.address;
  const p = getPill(addr);
  const funded = (row.ethBal !== null && row.ethBal > 0n) || Object.keys(row.tokens).length > 0;
  if (funded) {
    if (p && p.stage === 'sweeping') {
      if (p.sweepTx) {
        try {
          const st = await fetchJson('./status/' + p.sweepTx);
          if (st.status === 'failed') { putPill(addr, { stage: 'detected', sweepTx: null, direct: false }); return 'detected'; }
          if (st.status === 'confirmed') return p.direct ? 'direct' : 'in_pool';
        } catch { /* relayer status unreachable: keep SWEEPING */ }
      }
      return 'sweeping';
    }
    return 'detected';
  }
  // address is empty: swept (or a zero-value announcement)
  if (p && p.stage === 'direct') return 'direct';
  // the note's pool drives the whole trace: USDC notes query the USDC pool (deposit
  // logs, nullifier, ASP scope), old notes with no asset fields stay on the ETH pool.
  const note = noteFor(addr);
  const pool = notePool(note);
  let dep = null;
  try { dep = await findDeposit(addr, row.rec.block, pool); } catch { /* RPC hiccup: fall through to persisted state */ }
  if (!dep) {
    if (p && p.sweepTx && (p.stage === 'sweeping' || p.stage === 'detected')) {
      try {
        const st = await fetchJson('./status/' + p.sweepTx);
        if (st.status === 'confirmed') return p.direct ? 'direct' : 'in_pool';
        if (st.status === 'failed') { putPill(addr, { stage: 'detected', sweepTx: null, direct: false }); return 'detected'; }
        return 'sweeping';
      } catch { return p.stage; }
    }
    return p && stageRank(p.stage) > 0 ? p.stage : 'detected';
  }
  row.deposit = dep;
  try { if (await isWithdrawn(addr)) return 'withdrawn'; } catch { /* nullifier check failed: keep tracing */ }
  try {
    const asp = await getAsp(pool);
    return asp.has(dep.label) ? 'withdrawable' : 'asp_pending';
  } catch { return 'in_pool'; }
}

// ── formatting ──
const trim = s => (s.includes('.') ? s.replace(/\.?0+$/, '') : s);
const usdStr = n => '$' + n.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
const fmtToken = (sym, bal) => { const t = TOKENS.find(x => x.sym === sym); return trim(ethers.formatUnits(bal, t.dec)); };
const short = a => a.slice(0, 10) + '…' + a.slice(-6);

// ── instances + rows ──
// One logical row set rendered into every mounted inbox instance (FUNDS #gp-inbox and
// GET PAID #r-rows). insts: { root, rowsEl, statusEl, emptyEl, batchEl }. A row's views
// map each instance root to that instance's DOM ({ el, refs }).
const insts = [];
const rows = new Map(); // addrLower → { rec, views: Map(root → { el, refs }), ethBal, tokens, deposit, busy }

// batch selection (pool-sized ETH payments, swept together as one eip7702-intent-batch):
// one shared selection across instances. Everything renders only while the relayer
// advertises a BatchRelayer (GET /health batchRelayer non-null); otherwise zero UI trace.
const batch = { allowed: false, sel: new Set(), busy: false, broadcasting: false, artifact: null };

function ensureRow(rec) {
  const key = rec.address.toLowerCase();
  if (rows.has(key)) return rows.get(key);
  const row = { rec, views: new Map(), ethBal: null, tokens: {}, deposit: null, busy: false };
  rows.set(key, row);
  for (const inst of insts) {
    const el = document.createElement('div');
    el.className = 'gp-row';
    const head = document.createElement('div'); head.className = 'gp-rowhead';
    const addrEl = document.createElement('div'); addrEl.className = 'gp-addr'; addrEl.textContent = short(rec.address);
    addrEl.title = rec.address;
    const pill = document.createElement('span'); pill.className = 'gp-pill dim'; pill.textContent = '…';
    head.append(addrEl, pill);
    const meta = document.createElement('div'); meta.className = 'gp-meta';
    const labelEl = document.createElement('span'); labelEl.className = 'gp-label';
    const tokensEl = document.createElement('div'); tokensEl.className = 'gp-tokens'; tokensEl.style.display = 'none';
    const note = document.createElement('div'); note.className = 'gp-note'; note.style.display = 'none';
    const actions = document.createElement('div'); actions.className = 'gp-actions';
    const panel = document.createElement('div'); panel.className = 'gp-panel'; panel.style.display = 'none';
    el.append(head, meta, labelEl, tokensEl, note, actions, panel);
    inst.rowsEl.appendChild(el);
    const view = { el, refs: { addrEl, meta, labelEl, tokensEl, pill, note, actions, panel, check: null } };
    row.views.set(inst.root, view);
    wireLabel(row, view);
    syncRowCheckbox(row);
  }
  return row;
}

function wireLabel(row, view) {
  const { labelEl } = view.refs;
  const paint = v => {
    const l = getLabel(row.rec.address);
    v.refs.labelEl.textContent = 'label: ' + (l || 'add +');
    v.refs.labelEl.classList.toggle('set', !!l);
  };
  paint(view);
  labelEl.onclick = () => {
    const cur = getLabel(row.rec.address);
    const inp = document.createElement('input');
    inp.type = 'text'; inp.value = cur; inp.placeholder = 'local label (this device only)';
    inp.className = 'gp-input gp-label-edit';
    labelEl.replaceWith(inp);
    inp.focus();
    const commit = () => {
      setLabel(row.rec.address, inp.value.trim());
      inp.replaceWith(labelEl);
      for (const v of row.views.values()) paint(v); // the label shows in every instance
      GP.toast(inp.value.trim() ? 'label saved' : 'label cleared');
    };
    inp.onkeydown = e => { if (e.key === 'Enter') inp.blur(); if (e.key === 'Escape') { inp.value = cur; inp.blur(); } };
    inp.onblur = commit;
  };
}

// ── batch sweep UI (dark-shipped: renders only when the relayer advertises a BatchRelayer) ──
function batchEligible(row) {
  const p = getPill(row.rec.address);
  const stageKnown = p && stageRank(p.stage) >= stageRank('in_pool');
  return !row.rec.swept && !stageKnown && row.ethBal !== null && row.ethBal >= PP_MIN;
}

async function refreshBatchGate() {
  try {
    const caps = GP.relayerCaps ? await GP.relayerCaps() : null;
    batch.allowed = !!(caps && caps.batchRelayer);
  } catch { batch.allowed = false; }
  if (!batch.allowed) { batch.sel.clear(); batch.artifact = null; }
  for (const row of rows.values()) syncRowCheckbox(row);
  renderBatchBar();
}

// the row checkbox comes and goes with eligibility + the relayer gate: never a dead control
function syncRowCheckbox(row) {
  const want = batch.allowed && batchEligible(row);
  let removed = false;
  for (const view of row.views.values()) {
    let cb = view.refs.check;
    if (want && !cb) {
      cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.className = 'gp-rowcheck';
      cb.title = 'Select for a batch sweep';
      cb.setAttribute('aria-label', 'Select ' + short(row.rec.address) + ' for a batch sweep');
      cb.checked = batch.sel.has(row.rec.address.toLowerCase());
      cb.onchange = () => {
        const k = row.rec.address.toLowerCase();
        if (cb.checked) {
          if (batch.sel.size >= BATCH_MAX) {
            cb.checked = false;
            GP.toast('A batch carries at most ' + BATCH_MAX + ' sweeps');
            return;
          }
          batch.sel.add(k);
        } else batch.sel.delete(k);
        for (const v of row.views.values()) if (v.refs.check && v.refs.check !== cb) v.refs.check.checked = cb.checked;
        renderBatchBar();
      };
      view.refs.check = cb;
      view.refs.addrEl.insertAdjacentElement('beforebegin', cb);
      view.el.classList.add('has-check');
    } else if (!want && cb) {
      cb.remove();
      view.refs.check = null;
      view.el.classList.remove('has-check');
      removed = true;
    } else if (cb) {
      cb.checked = batch.sel.has(row.rec.address.toLowerCase());
    }
  }
  if (removed) {
    batch.sel.delete(row.rec.address.toLowerCase());
    renderBatchBar();
  }
}

// each instance's batch container keeps a stable skeleton: a status line the arming and
// broadcast flows write into, and a body that holds the selection bar or the preview.
function ensureBatchSkeleton(el) {
  if (el._st) return;
  el._st = document.createElement('div');
  el._st.className = 'gp-note';
  el._st.style.display = 'none';
  el._body = document.createElement('div');
  el.append(el._st, el._body);
}
function batchSay(html) {
  for (const inst of insts) {
    const el = inst.batchEl;
    if (!el) continue;
    ensureBatchSkeleton(el);
    el.style.display = 'block';
    el._st.style.display = html ? 'block' : 'none';
    el._st.innerHTML = html || '';
  }
}

function renderBatchBar() {
  for (const inst of insts) {
    const el = inst.batchEl;
    if (!el) continue;
    ensureBatchSkeleton(el);
    if (!batch.allowed) { el.style.display = 'none'; el._st.textContent = ''; el._body.textContent = ''; continue; }
    if (batch.artifact) continue; // the preview owns the body until the broadcast resolves
    el._body.textContent = '';
    const n = batch.sel.size;
    if (!n) { el.style.display = el._st.textContent ? 'block' : 'none'; continue; }
    el.style.display = 'block';
    const line = document.createElement('div');
    line.className = 'gp-batch-line';
    const cnt = document.createElement('span');
    cnt.textContent = n + ' selected';
    line.appendChild(cnt);
    const btn = document.createElement('button');
    btn.className = 'gp-btn small primary';
    btn.textContent = 'Sweep together';
    btn.disabled = n < 2 || batch.busy;
    btn.onclick = armBatch;
    line.appendChild(btn);
    const clr = document.createElement('button');
    clr.className = 'gp-btn small ghost';
    clr.textContent = 'Clear';
    clr.onclick = () => { batch.sel.clear(); for (const row of rows.values()) syncRowCheckbox(row); renderBatchBar(); };
    line.appendChild(clr);
    el._body.appendChild(line);
    const warn = document.createElement('div');
    warn.className = 'gp-note';
    warn.style.display = 'block';
    warn.textContent = 'A batch sweep moves the selected addresses in one transaction: it links them onchain. Sweep individually when the linkage matters.';
    el._body.appendChild(warn);
    if (n < 2) {
      const hint = document.createElement('div');
      hint.className = 'gp-note';
      hint.style.display = 'block';
      hint.textContent = 'Select at least two payments for a batch sweep.';
      el._body.appendChild(hint);
    }
  }
}

// one click: force a fresh arm for every selected payment (each generates and downloads
// its pp-secret NOW, serialized behind app-core's arm queue), then assemble one batch
// artifact. The backup gate applies per secret: a pending gate blocks arming, and the
// secrets this click downloads re-arm it, so the broadcast refuses until the backup is
// confirmed in the gp-money gate on the FUNDS tab.
async function armBatch() {
  if (batch.busy || batch.artifact) return;
  if (lsGet(GATE_KEY, null)) {
    batchSay('A withdrawal-secret backup is still unconfirmed. Confirm it in the backup gate on the FUNDS tab before arming more sweeps.');
    return;
  }
  batch.busy = true;
  renderBatchBar();
  try {
    if (!GP.state.keys || !GP.state.keys.spendPriv)
      throw new Error('watch-only session: your spend key is never stored on this device. Reconnect, generate your stealth keys again (same wallet, same keys), then retry.');
    const addrs = [...batch.sel];
    const sweeps = [];
    let i = 0;
    for (const a of addrs) {
      i++;
      batchSay('Arming ' + i + ' of ' + addrs.length + ' · the pp-secret-' + a.slice(2, 10) + '.json file downloads now. Keep every file: each one withdraws its own deposit.');
      const armed = await GP.armPayment(a);
      if (!armed || !armed.artifact)
        throw new Error('could not arm ' + short(a) + ' (relayer without sweeperV2, or the balance dropped below the pool minimum). Nothing was broadcast: rescan and retry.');
      sweeps.push(armed.artifact);
    }
    batch.artifact = { kind: 'eip7702-intent-batch', chainId: GP.const.CHAIN_ID, sweeps };
    batchSay('');
    renderBatchPreview();
  } catch (e) {
    batchSay('Error: ' + e.message);
  } finally {
    batch.busy = false;
    renderBatchBar();
  }
}

function renderBatchPreview() {
  for (const inst of insts) {
    const el = inst.batchEl;
    if (!el || !batch.artifact) continue;
    ensureBatchSkeleton(el);
    el.style.display = 'block';
    el._body.textContent = '';
    const n = batch.artifact.sweeps.length;
    const prev = document.createElement('div');
    prev.className = 'gp-note gp-prev';
    prev.textContent = 'signed · ' + n + ' sweeps in one transaction · valid 24h · one pp-secret file per payment downloaded: keep every file, each withdraws its own deposit';
    const warn = document.createElement('div');
    warn.className = 'gp-note';
    warn.style.display = 'block';
    warn.textContent = 'This batch links the ' + n + ' swept addresses onchain.';
    const bBc = document.createElement('button');
    bBc.className = 'gp-btn primary block';
    bBc.textContent = 'BROADCAST VIA RELAYER';
    const bCp = document.createElement('button');
    bCp.className = 'gp-btn ghost block';
    bCp.textContent = 'Copy artifact';
    bCp.onclick = () => { navigator.clipboard.writeText(JSON.stringify(batch.artifact, null, 2)); GP.toast('artifact copied'); };
    el._body.append(prev, warn, bBc, bCp);
    bBc.onclick = () => broadcastBatch();
  }
}

async function broadcastBatch() {
  if (batch.broadcasting || !batch.artifact) return;
  if (lsGet(GATE_KEY, null)) {
    batchSay('Confirm the downloaded secret files in the backup gate on the FUNDS tab first: no broadcast without a confirmed backup.');
    return;
  }
  batch.broadcasting = true;
  for (const inst of insts) {
    const b = inst.batchEl && inst.batchEl._body && inst.batchEl._body.querySelector('.gp-btn.primary');
    if (b) b.disabled = true;
  }
  const artifact = batch.artifact;
  const addrs = artifact.sweeps.map(s => s.stealthAddress);
  for (const a of addrs) putPill(a, { stage: 'sweeping', sweepTx: null, direct: false });
  if (!document.getElementById('gp-pulse-style')) {
    const s = document.createElement('style');
    s.id = 'gp-pulse-style';
    s.textContent = '.gp-pulse{display:inline-block;animation:gpPulse 1.2s ease-in-out infinite}@keyframes gpPulse{0%,100%{opacity:.25}50%{opacity:1}}';
    document.head.appendChild(s);
  }
  const t0 = Date.now();
  let phase = 'broadcasting via relayer', extra = '5-45s privacy delay';
  const tick = setInterval(() => {
    const s = Math.floor((Date.now() - t0) / 1000);
    batchSay('<span class="gp-pulse">&#9679;</span> ' + phase + ' · ' + Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0') + (extra ? ' · ' + extra : ''));
  }, 1000);
  const out = await GP.relaySweep(artifact, h => {
    phase = 'pending'; extra = 'tx ' + h.slice(0, 14) + '… · explorers show it only once mined';
    for (const a of addrs) putPill(a, { sweepTx: h });
  });
  clearInterval(tick);
  if (out && out.hash) {
    const link = ' · <a href="https://etherscan.io/tx/' + out.hash + '" target="_blank" rel="noopener">etherscan</a>';
    if (out.status === 'confirmed') {
      // the core fans the confirmation out as one 'swept' event per address: the rows
      // advance their own pills. Here only the selection + preview reset.
      batchSay('&#10003; confirmed' + (out.block ? ' in block ' + out.block.toLocaleString() : '') + ' · ' + addrs.length + ' sweeps in one tx ' + out.hash.slice(0, 14) + '…' + link);
      batch.artifact = null;
      batch.sel.clear();
      for (const a of addrs) { const r = rows.get(a.toLowerCase()); if (r) syncRowCheckbox(r); }
      renderBatchBar();
      return;
    }
    if (out.status === 'reverted') {
      batchSay('tx reverted onchain · ' + out.hash + ' · the artifacts stay valid: Copy artifact and retry, or sweep individually.');
    } else {
      batchSay('still pending after 10 minutes · tx ' + out.hash.slice(0, 14) + '…' + link + ' · it is in the private mempool, it usually lands within a few more minutes.');
    }
  } else {
    batchSay('relayer broadcast failed: ' + ((out && out.error) || 'unknown') + ' · the artifacts stay valid: Copy artifact and retry via relay.mjs.');
  }
  batch.broadcasting = false;
  for (const inst of insts) {
    const b = inst.batchEl && inst.batchEl._body && inst.batchEl._body.querySelector('.gp-btn.primary');
    if (b) b.disabled = false;
  }
}

async function refreshRow(row) {
  if (row.busy) return;
  row.busy = true;
  const addr = row.rec.address;
  try {
    try { row.ethBal = BigInt(await GP.jrpc('eth_getBalance', [addr, 'latest'])); } catch { row.ethBal = null; }
    // token balances: only while the address is unswept (nothing to find once it is empty)
    row.tokens = {};
    const p = getPill(addr);
    const swept = row.rec.swept === true || (p && stageRank(p.stage) >= stageRank('in_pool'));
    if (!swept) {
      const bals = await Promise.all(TOKENS.map(t =>
        GP.jrpc('eth_call', [{ to: t.addr, data: BALANCE_OF + ethers.zeroPadValue(addr, 32).slice(2) }, 'latest'])
          .then(r => BigInt(r)).catch(() => 0n)));
      TOKENS.forEach((t, i) => { if (bals[i] > 0n) row.tokens[t.sym] = bals[i]; });
    }
    const stage = await computeStage(row);
    if (!p || stageRank(stage) > stageRank(p.stage)) putPill(addr, { stage });
    renderRow(row, stage);
    syncRowCheckbox(row);
  } catch { /* leave last rendered state */ }
  finally { row.busy = false; }
}

async function renderRow(row, stage) {
  const addr = row.rec.address;
  const prices = await getPrices();
  const syms = Object.keys(row.tokens);
  const pillTok = (getPill(addr) || {}).tokenSwept || {};
  const tokUsd = s => {
    const px = s === 'WETH' ? prices.eth : prices.usdc;
    return px ? ' ≈ ' + usdStr(Number(ethers.formatUnits(row.tokens[s], TOKENS.find(x => x.sym === s).dec)) * px) : '';
  };
  // USDC pool sweep eligibility: the deposited amount (balance minus the relayer fee)
  // must clear the pool's minimum, the session must hold the spend key, and the relayer
  // must take signed intents. The pool config resolves live via the entrypoint's
  // assetConfig (session-cached, constants as fallback), so new token pools light up here
  // without an app update.
  let usdcPool = null, usdcPoolOk = false, usdcPoolWhy = null;
  if (row.tokens.USDC) {
    try { usdcPool = await GP.pp.ppPoolForAsset(USDC.addr); } catch { usdcPool = null; }
    const caps = GP.relayerCaps ? await GP.relayerCaps().catch(() => null) : null;
    const hasSpend = !!(GP.state.keys && GP.state.keys.spendPriv);
    if (usdcPool && usdcPool.pool && usdcPool.minimumDepositAmount != null) {
      const feeBps = BigInt((caps && caps.minFeeBps) ?? 30);
      const deposited = row.tokens.USDC - row.tokens.USDC * feeBps / 10000n;
      if (!caps || !caps.sweeperV2) usdcPoolWhy = 'this relayer does not take signed intents, so the pool path is unavailable';
      else if (!hasSpend) usdcPoolWhy = 'watch-only session: reconnect and generate your keys to sweep into the pool';
      else if (deposited < BigInt(usdcPool.minimumDepositAmount)) {
        const minStr = trim(ethers.formatUnits(BigInt(usdcPool.minimumDepositAmount), 6));
        usdcPoolWhy = 'below the ' + minStr + ' USDC Privacy Pools minimum after the relayer fee (' + fmtToken('USDC', deposited) + ' USDC would land)';
      }
      usdcPoolOk = !usdcPoolWhy;
    }
  }
  // line 1: balance + detected time. A token-paid address holds tokens, not ETH: lead
  // with the token balance instead of a misleading 0 ETH.
  let balTxt = 'balance unknown';
  if (row.ethBal !== null) {
    if (row.ethBal === 0n && syms.length) {
      balTxt = syms.map(s => fmtToken(s, row.tokens[s]) + ' ' + s + tokUsd(s)).join(' · ');
    } else {
      balTxt = GP.fmt.formatEth(row.ethBal) + ' ETH';
      const usd = GP.fmt.formatUsd(GP.fmt.formatEth(row.ethBal), prices.eth);
      if (usd && row.ethBal > 0n) balTxt += ' · ' + usd;
    }
  }
  let timeTxt = 'block ' + row.rec.block.toLocaleString();
  try { timeTxt = await blockTime(row.rec.block); } catch { /* keep block number */ }
  // token line (skipped when the balance line already leads with those same tokens:
  // a token-only address shows its balance once)
  const leadWithTokens = row.ethBal !== null && row.ethBal === 0n && syms.length > 0;
  let tokensTxt = null;
  {
    const parts = [];
    if (!leadWithTokens) for (const s of syms) parts.push(fmtToken(s, row.tokens[s]) + ' ' + s + tokUsd(s));
    for (const s of Object.keys(pillTok)) if (!syms.includes(s)) parts.push(s + ' swept ✓');
    if (parts.length) tokensTxt = parts.join(' · ');
  }
  // note line
  let noteTxt = '';
  if (stage === 'asp_pending') noteTxt = 'deposits wait for the association-set provider to approve them. usually hours. funds are safe.';
  else if (stage === 'withdrawable') noteTxt = 'ASP approved: withdraw in step 4 with your pp-secret file.';
  else if (stage === 'in_pool' && row.deposit) noteTxt = 'pool deposit ' + fmtNote(noteFor(addr), row.deposit.value) + ' · block ' + row.deposit.block.toLocaleString() + '. tracing ASP…';
  else if (stage === 'sweeping') noteTxt = 'sweep broadcast. this line advances when the tx confirms.';
  else if (stage === 'detected' && row.ethBal !== null && row.ethBal > 0n && row.ethBal >= PP_MIN) noteTxt = 'pool-ready: sweep this address into Privacy Pools from this row.';
  else if (stage === 'detected' && (row.ethBal === null || row.ethBal === 0n) && syms.length) {
    noteTxt = usdcPoolOk
      ? 'token balance, no ETH: sweep the USDC into the Privacy Pool from this row (the deposit is public, your withdrawal address stays unlinked), or sweep direct to an address you choose.'
      : ('token balance, no ETH: sweep the token from this row.' + (row.tokens.USDC && usdcPoolWhy ? ' pool unavailable: ' + usdcPoolWhy + '.' : ''));
  }
  for (const view of row.views.values()) {
    const { meta, tokensEl, pill, note, actions } = view.refs;
    const balEl = document.createElement('span'); balEl.className = 'gp-bal'; balEl.textContent = balTxt;
    const whenEl = document.createElement('span'); whenEl.className = 'gp-when'; whenEl.textContent = 'detected ' + timeTxt;
    meta.replaceChildren(balEl, document.createTextNode(' · '), whenEl);
    if (tokensTxt) { tokensEl.style.display = 'block'; tokensEl.textContent = tokensTxt; }
    else tokensEl.style.display = 'none';
    pill.textContent = PILL_TEXT[stage] || stage.toUpperCase();
    pill.className = 'gp-pill ' + (PILL_TONE[stage] || 'dim');
    note.style.display = noteTxt ? 'block' : 'none';
    note.textContent = noteTxt;
    // actions
    actions.textContent = '';
    const live = stage === 'detected' || stage === 'sweeping';
    if (live && row.tokens.USDC && usdcPoolOk) {
      // the pool path is primary: it breaks the public link between this one-time
      // address and wherever the funds go next. The direct sweep stays as the
      // secondary option with the linkage spelled out in its panel.
      const b = document.createElement('button');
      b.className = 'gp-btn small primary';
      b.textContent = 'Sweep USDC to pool';
      b.onclick = () => openTokenPoolSweep(row, view);
      actions.appendChild(b);
    }
    if (live && row.tokens.USDC) {
      const b = document.createElement('button');
      b.className = usdcPoolOk ? 'gp-btn small ghost' : 'gp-btn small';
      b.textContent = usdcPoolOk ? 'Sweep USDC direct' : 'Sweep USDC';
      b.onclick = () => openUsdcSweep(row, view);
      actions.appendChild(b);
    }
    // pool-sized ETH: the app-core sweep surface (arm → secret → SIGN SWEEP → broadcast
    // on the FUNDS tab, gp-money interceptions intact). GP.sweepPayment routes there.
    if (live && row.ethBal !== null && row.ethBal >= PP_MIN && GP.sweepPayment) {
      const b = document.createElement('button');
      b.className = 'gp-btn small';
      b.textContent = 'Sweep to pool';
      b.onclick = () => GP.sweepPayment(addr);
      actions.appendChild(b);
    }
    if (live && row.ethBal !== null && row.ethBal > 0n && row.ethBal < PP_MIN) {
      const b = document.createElement('button');
      b.className = 'gp-btn small ghost';
      b.textContent = 'Sweep direct';
      b.onclick = () => openDirectSweep(row, view);
      actions.appendChild(b);
    }
  }
}

// ── stealth key (transient, never stored, never logged) ──
function stealthWallet(rec) {
  const keys = GP.state.keys;
  if (!keys || !keys.spendPriv) {
    throw new Error('watch-only session: your spend key is never stored on this device. Re-connect, Generate my stealth keys, then retry.');
  }
  const { sh } = GP.crypto.check(keys.viewPriv, keys.spendPub, rec.ephPub, rec.address);
  const w = new ethers.Wallet(GP.crypto.stealthKey(keys.spendPriv, sh));
  if (w.address.toLowerCase() !== rec.address.toLowerCase()) throw new Error('derived key mismatch');
  return w;
}

function panelBase(view, noteTxt) {
  const { panel } = view.refs;
  panel.textContent = '';
  panel.style.display = 'block';
  const note = document.createElement('div'); note.className = 'gp-note'; note.textContent = noteTxt;
  const amt = document.createElement('div'); amt.className = 'gp-tokens';
  const dest = document.createElement('input'); dest.type = 'text'; dest.placeholder = 'destination address (0x…)';
  dest.className = 'gp-input';
  if (GP.state.address) dest.value = GP.state.address;
  const st = document.createElement('div'); st.className = 'gp-note';
  panel.append(note, amt, dest, st);
  panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  return { panel, amt, dest, st };
}

// the pool-deposit variant (opts.gate) is backup-gated like the batch flow: the arm
// already downloaded a fresh pp-secret, so gp-money's gate (armed by the #v-secret
// observer) must be confirmed on the FUNDS tab before this broadcast may leave.
function previewAndBroadcast(row, panel, st, artifact, summary, onRelayed, opts = {}) {
  const prev = document.createElement('div'); prev.className = 'gp-note gp-prev';
  prev.textContent = 'signed · ' + summary;
  const bBc = document.createElement('button'); bBc.className = 'gp-btn primary block'; bBc.textContent = 'BROADCAST VIA RELAYER';
  const bCp = document.createElement('button'); bCp.className = 'gp-btn ghost block'; bCp.textContent = 'Copy artifact';
  bCp.onclick = () => { navigator.clipboard.writeText(JSON.stringify(artifact, null, 2)); GP.toast('artifact copied'); };
  panel.append(prev, bBc, bCp);
  bBc.onclick = async () => {
    if (opts.gate && lsGet(GATE_KEY, null)) {
      st.textContent = 'Confirm the downloaded pp-secret file in the backup gate on the FUNDS tab first: no broadcast without a confirmed backup.';
      return;
    }
    bBc.disabled = true;
    onRelayed();
    row._pendingArt = artifact;
    // live broadcast lifecycle: a static line reads as dead during the minutes this takes.
    // pulsing dot + elapsed timer while the relayer works, then the hash once broadcast, then the outcome.
    if (!document.getElementById('gp-pulse-style')) {
      const s = document.createElement('style');
      s.id = 'gp-pulse-style';
      s.textContent = '.gp-pulse{display:inline-block;animation:gpPulse 1.2s ease-in-out infinite}@keyframes gpPulse{0%,100%{opacity:.25}50%{opacity:1}}';
      document.head.appendChild(s);
    }
    const t0 = Date.now();
    let phase = 'broadcasting via relayer', extra = '5-45s privacy delay';
    const tick = setInterval(() => {
      const s = Math.floor((Date.now() - t0) / 1000);
      st.innerHTML = '<span class="gp-pulse">&#9679;</span> ' + phase + ' · ' + Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0') + (extra ? ' · ' + extra : '');
    }, 1000);
    const out = await GP.relaySweep(artifact, h => {
      phase = 'pending'; extra = 'tx ' + h.slice(0, 14) + '… · explorers show it only once mined';
    });
    clearInterval(tick);
    if (out && out.hash) {
      const link = ' · <a href="https://etherscan.io/tx/' + out.hash + '" target="_blank" rel="noopener">etherscan</a>';
      if (out.status === 'confirmed') {
        st.innerHTML = '&#10003; confirmed' + (out.block ? ' in block ' + out.block.toLocaleString() : '') + ' · tx ' + out.hash.slice(0, 14) + '…' + link;
        return;
      }
      if (out.status === 'reverted') {
        st.textContent = 'tx reverted onchain · ' + out.hash + ' · the artifact stays valid: Copy artifact and retry.';
      } else {
        st.innerHTML = 'still pending after 10 minutes · tx ' + out.hash.slice(0, 14) + '…' + link + ' · it is in the private mempool, it usually lands within a few more minutes.';
      }
    } else {
      st.textContent = 'relayer broadcast failed: ' + ((out && out.error) || 'unknown') + ' · the artifact stays valid: Copy artifact and retry via relay.mjs.';
    }
    bBc.disabled = false;
  };
}

// USDC: gasless EIP-3009 transferWithAuthorization, signed by the stealth key. Direct
// transfer, not a pool deposit: it stays the fallback for sub-minimum balances and for
// relayers without sweeperV2, and the secondary option when the pool path is available
// (the pool breaks the link; a direct transfer does not).
function openUsdcSweep(row, view) {
  const rec = row.rec;
  const { panel, amt, dest, st } = panelBase(view,
    'USDC sweep is an EIP-3009 transferWithAuthorization: gasless for this address, signed by the stealth key. it moves USDC straight to your destination without entering Privacy Pools: the transfer is public, so this one-time address and your destination stay linked onchain. the pool sweep breaks that link.');
  amt.textContent = 'amount: ' + fmtToken('USDC', row.tokens.USDC) + ' USDC (full balance)';
  const b = document.createElement('button'); b.className = 'gp-btn primary block'; b.textContent = 'Sign USDC sweep';
  panel.appendChild(b);
  b.onclick = async () => {
    try {
      if (!ethers.isAddress(dest.value.trim())) throw new Error('bad destination address');
      const to = ethers.getAddress(dest.value.trim());
      const w = stealthWallet(rec);
      const value = row.tokens.USDC;
      const validAfter = 0;
      const validBefore = Math.floor(Date.now() / 1000) + 3600;
      const nonce = ethers.hexlify(crypto.getRandomValues(new Uint8Array(32)));
      const signature = await w.signTypedData(USDC_712_DOMAIN, USDC_712_TYPES,
        { from: rec.address, to, value, validAfter, validBefore, nonce });
      const artifact = {
        kind: 'eip3009', from: rec.address, to, value: value.toString(),
        validAfter, validBefore, nonce, signature, token: USDC.addr,
        chainId: GP.const.CHAIN_ID, stealthAddress: rec.address,
      };
      b.remove();
      previewAndBroadcast(row, panel, st, artifact,
        fmtToken('USDC', value) + ' USDC → ' + short(to) + ' · valid 1h',
        () => putPill(rec.address, { stage: 'sweeping', sweepTx: null }));
    } catch (e) { st.textContent = 'error: ' + e.message; }
  };
}

// USDC → Privacy Pools (SweeperV2 intent action 2). Mirrors the ETH pool sweep: arming
// generates the pp-secret (downloaded immediately, gp-money's backup gate arms off the
// #v-secret observer), the preview states the terms, and the broadcast refuses while a
// secret backup is unconfirmed. The pill then climbs the pool ladder per computeStage.
async function openTokenPoolSweep(row, view) {
  const rec = row.rec;
  let pool = null;
  try { pool = await GP.pp.ppPoolForAsset(USDC.addr); } catch { /* fallthrough copy covers it */ }
  const vetTxt = pool && Number.isFinite(pool.vettingFeeBPS) ? ' · pool vetting fee ' + (pool.vettingFeeBPS / 100) + '%' : ' · the pool takes a vetting fee';
  const { panel, amt, dest, st } = panelBase(view,
    'the full USDC balance (minus the relayer fee) deposits into the mainnet USDC Privacy Pool. the deposit is public but your withdrawal address stays unlinked'
    + vetTxt + ' · the deposit waits for ASP screening (usually hours) before you can withdraw in step 4 with the pp-secret file. keep that file: it is the only way to withdraw.');
  dest.remove(); // pool deposits have no destination: the withdrawal picks it later
  amt.textContent = 'amount: ' + fmtToken('USDC', row.tokens.USDC) + ' USDC (full balance minus the relayer fee)';
  if (lsGet(GATE_KEY, null)) {
    st.textContent = 'A withdrawal-secret backup is still unconfirmed. Confirm it in the backup gate on the FUNDS tab before arming another pool sweep.';
    return;
  }
  st.textContent = 'arming: generating the Privacy Pools secret (the pp-secret file downloads now) and signing the sweep intent…';
  let armed;
  try {
    armed = await GP.armTokenPoolPayment(rec.address, USDC.addr);
  } catch (e) {
    st.textContent = 'arm failed: ' + e.message;
    return;
  }
  if (!armed || !armed.artifact) {
    st.textContent = 'could not arm (relayer without sweeperV2, or the balance dropped below the pool minimum after the fee). nothing was broadcast: rescan and retry.';
    return;
  }
  const artifact = armed.artifact;
  st.textContent = '';
  previewAndBroadcast(row, panel, st, artifact,
    fmtToken('USDC', row.tokens.USDC) + ' USDC → USDC Privacy Pool · valid 24h · fee ' + artifact.intent.feeBps + ' bps · pp-secret downloaded: keep it, it is the only way to withdraw',
    () => putPill(rec.address, { stage: 'sweeping', sweepTx: null, direct: false }),
    { gate: true });
}

// dust ETH (< 0.01): cannot enter Privacy Pools, so offer a direct sweep to a destination.
// With a sweeperV2 relayer this is a signed intent (action 0); older relayers get the
// legacy eip7702-sweep artifact (sweepETH calldata picked by the app, carried by the relayer).
function openDirectSweep(row, view) {
  const rec = row.rec;
  const { panel, amt, dest, st } = panelBase(view,
    'privacy note: direct sweeps skip the pool, so the destination sees this address.');
  amt.textContent = 'amount: ' + GP.fmt.formatEth(row.ethBal) + ' ETH (full balance, below the 0.01 pool minimum)';
  const b = document.createElement('button'); b.className = 'gp-btn primary block'; b.textContent = 'Sign direct sweep';
  panel.appendChild(b);
  b.onclick = async () => {
    try {
      if (!ethers.isAddress(dest.value.trim())) throw new Error('bad destination address');
      const to = ethers.getAddress(dest.value.trim());
      const w = stealthWallet(rec);
      const nonce = parseInt(await GP.jrpc('eth_getTransactionCount', [rec.address, 'latest']), 16);
      const caps = GP.relayerCaps ? await GP.relayerCaps() : { sweeperV2: false, minFeeBps: 30 };
      let artifact, summary;
      if (caps.sweeperV2 && GP.const.SWEEPER_V2 && GP.crypto.intentDomain) {
        const intent = {
          action: 0, token: ethers.ZeroAddress, destination: to, precommitment: 0,
          feeBps: caps.minFeeBps, deadline: Math.floor(Date.now() / 1000) + 86400,
        };
        const signature = await w.signTypedData(GP.crypto.intentDomain(rec.address), GP.crypto.INTENT_TYPES, intent);
        artifact = {
          kind: 'eip7702-intent', chainId: GP.const.CHAIN_ID, stealthAddress: rec.address,
          sweeper: GP.const.SWEEPER_V2,
          authorization: GP.crypto.sign7702(w.privateKey, GP.const.CHAIN_ID, GP.const.SWEEPER_V2, nonce),
          intent, signature,
        };
        summary = GP.fmt.formatEth(row.ethBal) + ' ETH → ' + short(to) + ' · direct intent (no pool) · fee ' + caps.minFeeBps + ' bps';
      } else {
        const data = SWEEPETH_IFACE.encodeFunctionData('sweepETH', [to]);
        artifact = {
          kind: 'eip7702-sweep', chainId: GP.const.CHAIN_ID, stealthAddress: rec.address,
          sweeper: GP.const.SWEEPER, data,
          authorization: GP.crypto.sign7702(w.privateKey, GP.const.CHAIN_ID, GP.const.SWEEPER, nonce),
        };
        summary = GP.fmt.formatEth(row.ethBal) + ' ETH → ' + short(to) + ' · direct (no pool)';
      }
      b.remove();
      previewAndBroadcast(row, panel, st, artifact, summary,
        () => putPill(rec.address, { stage: 'sweeping', sweepTx: null, direct: true }));
    } catch (e) { st.textContent = 'error: ' + e.message; }
  };
}

// ── sync + poll ──
function syncRows() {
  for (const rec of GP.state.payments) ensureRow(rec);
  const n = rows.size;
  for (const inst of insts) {
    // visible while unlocked even when empty: the empty state explains what lands here
    inst.root.style.display = (n || GP.state.unlocked) ? 'block' : 'none';
    if (inst.emptyEl) inst.emptyEl.style.display = n ? 'none' : 'block';
    if (inst.statusEl) inst.statusEl.textContent = n
      ? n + ' payment' + (n === 1 ? '' : 's') + ' tracked · labels and pill state stay on this device'
      : '';
  }
}

let refreshing = false;
async function refreshAll() {
  if (refreshing || !GP.state.unlocked) return;
  refreshing = true;
  try {
    syncRows();
    for (const row of rows.values()) await refreshRow(row);
  } finally { refreshing = false; }
}

// inject the frag into one mount. The <style> block mounts once (into <head>); every
// instance gets a deep copy of the root markup with the ids stripped (they are re-homed
// onto the canonical FUNDS instance afterwards, one copy each, per docs/GP-API.md).
async function mountInto(mountEl, { heading }) {
  let html = null;
  try { const r = await fetch('./frag-inbox.html'); if (r.ok) html = await r.text(); } catch { /* static open: use the embedded copy */ }
  html = html || FRAG_FALLBACK;
  // parsed, not regexed: the frag's own comment block may mention the style tag
  const doc = new DOMParser().parseFromString(html, 'text/html');
  if (!document.getElementById('gp-inbox-style')) {
    const style = doc.querySelector('style');
    if (style) {
      const styleEl = document.createElement('style');
      styleEl.id = 'gp-inbox-style';
      styleEl.textContent = style.textContent;
      document.head.appendChild(styleEl);
    }
  }
  const src = doc.querySelector('.gp-inbox-root');
  if (!src) return;
  const root = document.importNode(src, true);
  root.removeAttribute('id');
  root.querySelectorAll('[id]').forEach(el => el.removeAttribute('id'));
  if (!heading) { const h = root.querySelector('.gp-inbox-h'); if (h) h.remove(); }
  mountEl.appendChild(root);
  insts.push({
    root,
    rowsEl: root.querySelector('.gp-inbox-rows'),
    statusEl: root.querySelector('.gp-inbox-status'),
    emptyEl: root.querySelector('.gp-empty'),
    batchEl: root.querySelector('.gp-inbox-batch'),
  });
}

async function mount() {
  const m = document.getElementById('gp-inbox');
  if (m) await mountInto(m, { heading: true });
  const rr = document.getElementById('r-rows');
  if (rr) await mountInto(rr, { heading: false });
  if (!insts.length) return;
  // re-home the canonical ids onto the FUNDS instance (the frag carries them, but only
  // one copy of each id may exist in the document)
  const canon = insts[0];
  canon.root.id = 'gp-inbox-root';
  if (canon.statusEl) canon.statusEl.id = 'gp-inbox-status';
  if (canon.batchEl) canon.batchEl.id = 'gp-inbox-batch';
  if (canon.rowsEl) canon.rowsEl.id = 'gp-inbox-rows';
}

// offline fallback: identical copy of frag-inbox.html
const FRAG_FALLBACK = `<style>
  .gp-inbox-root .gp-inbox-h { font-family:var(--gp-font-display); font-size:var(--gp-fs-h3); font-weight:500;
    color:var(--gp-fg); margin:32px 0 4px; }
  .gp-inbox-status { color:var(--gp-muted); font-size:var(--gp-fs-small); }
  .gp-inbox-root .gp-empty { margin-top:12px; }
  .gp-inbox-root .gp-row { background:var(--gp-bg-raise); border:1px solid var(--gp-line);
    border-radius:var(--gp-radius); padding:18px 20px; margin-top:12px; }
  .gp-inbox-root .gp-rowhead { display:flex; align-items:center; justify-content:space-between; gap:12px; }
  .gp-inbox-root .gp-row.has-check .gp-rowhead { display:grid; grid-template-columns:auto 1fr auto; }
  .gp-inbox-root .gp-rowcheck { width:18px; height:18px; margin:2px 0 0; accent-color:var(--gp-accent); flex:none; }
  .gp-inbox-root .gp-addr { font-weight:700; font-size:var(--gp-fs-small); word-break:break-all; }
  .gp-inbox-root .gp-rowhead .gp-pill { flex:none; }
  .gp-inbox-root .gp-meta { font-size:var(--gp-fs-small); margin:8px 0 0; }
  .gp-inbox-root .gp-bal { color:var(--gp-fg); font-weight:500; }
  .gp-inbox-root .gp-when { color:var(--gp-faint); }
  .gp-inbox-root .gp-label { display:inline-block; margin-top:6px; cursor:text; color:var(--gp-faint);
    border-bottom:1px dashed var(--gp-line-strong); }
  .gp-inbox-root .gp-label.set { color:var(--gp-muted); }
  .gp-inbox-root .gp-label:hover { color:var(--gp-fg); border-bottom-color:var(--gp-fg); }
  .gp-inbox-root .gp-label-edit { margin-top:8px; max-width:360px; }
  .gp-inbox-root .gp-tokens { font-size:var(--gp-fs-small); color:var(--gp-fg); margin-top:8px; }
  .gp-inbox-root .gp-note { color:var(--gp-muted); font-size:var(--gp-fs-small); margin-top:8px; }
  .gp-inbox-root .gp-prev { color:var(--gp-fg); margin-top:10px; }
  .gp-inbox-root .gp-actions { display:flex; gap:8px; margin-top:14px; flex-wrap:wrap; }
  .gp-inbox-root .gp-actions .gp-btn { flex:1 1 auto; }
  .gp-inbox-root .gp-panel { background:var(--gp-bg-inset); border:1px solid var(--gp-line);
    border-radius:var(--gp-radius-sm); padding:16px; margin-top:12px; }
  .gp-inbox-root .gp-panel .gp-note:first-child { margin-top:0; }
  .gp-inbox-root .gp-panel .gp-tokens { margin:8px 0; }
  .gp-inbox-root .gp-panel .gp-btn { margin-top:10px; }
  .gp-inbox-root .gp-panel a { color:var(--gp-accent); }
  .gp-inbox-root .gp-inbox-batch { background:var(--gp-bg-raise); border:1px solid var(--gp-accent);
    border-radius:var(--gp-radius); padding:14px 16px; margin-top:14px; }
  .gp-inbox-root .gp-batch-line { display:flex; align-items:center; gap:10px; flex-wrap:wrap;
    font-size:var(--gp-fs-small); color:var(--gp-fg); }
  @media (max-width:700px) {
    .gp-inbox-root .gp-row { padding:16px; }
    .gp-inbox-root .gp-actions { flex-direction:column; }
    .gp-inbox-root .gp-actions .gp-btn { width:100%; }
  }
</style>
<div id="gp-inbox-root" class="gp-inbox-root" style="display:none">
  <h2 class="gp-inbox-h">Payment inbox</h2>
  <div class="status gp-inbox-status" id="gp-inbox-status" style="margin-top:0"></div>
  <div class="gp-inbox-batch" id="gp-inbox-batch" style="display:none"></div>
  <div id="gp-inbox-rows" class="gp-inbox-rows"></div>
  <div class="gp-empty" style="display:none"><div class="gp-empty-title">No payments tracked yet</div>
    When the scanner finds a payment to one of your stealth addresses it lands here, with its balance and sweep state. Labels and pill state stay on this device.</div>
</div>`;

await mount();
if (insts.length && FULL_CORE) {
  syncRows();
  refreshAll();
  refreshBatchGate(); // batch UI renders only if the relayer advertises a BatchRelayer

  GP.on('payment', rec => { ensureRow(rec); syncRows(); refreshRow(rows.get(rec.address.toLowerCase())); });
  GP.on('swept', d => {
    const a = d && d.artifact && (d.artifact.stealthAddress || d.artifact.from);
    const addr = (a || (d.payment && d.payment.address) || '').toLowerCase();
    const row = rows.get(addr);
    if (!row) return;
    if (row._pendingArt === d.artifact) row._pendingArt = null;
    if (d.artifact.kind === 'eip3009') {
      // token sweep: direct transfer, the pool/ASP ladder does not apply. 'direct' is terminal
      // only once the address is fully empty; while ETH remains the row shows DETECTED. A row
      // already on the pool ladder keeps its stage (the USDC left beside the pool deposit).
      const p = getPill(addr) || {};
      const patch = { sweepTx: d.hash, tokenSwept: { ...(p.tokenSwept || {}), USDC: d.hash } };
      if (stageRank(p.stage || 'detected') < stageRank('in_pool')) patch.stage = 'direct';
      putPill(addr, patch);
    } else if (d.artifact.precommitment) {
      putPill(addr, { stage: 'in_pool', sweepTx: d.hash, direct: false });
    } else {
      putPill(addr, { stage: 'direct', sweepTx: d.hash });
    }
    refreshRow(row);
  });
  GP.on('session', ({ type }) => {
    if (type === 'forgotten') {
      rows.clear();
      batch.sel.clear(); batch.artifact = null;
      for (const inst of insts) { inst.rowsEl.textContent = ''; inst.root.style.display = 'none'; }
      return;
    }
    syncRows();
    refreshAll();
  });

  setInterval(() => {
    if (document.visibilityState === 'hidden') return;
    refreshAll();
  }, 60000);
}
