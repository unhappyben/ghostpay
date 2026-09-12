// gp-inbox.mjs · GHOSTPAY payment inbox + token detection. Module contract: docs/GP-API.md.
// Renders into the #gp-inbox mount (step 4). Load AFTER the core inline script:
//   <script type="module" src="./gp-inbox.mjs"></script>
// Markup comes from frag-inbox.html (pasted into #gp-inbox by the integrator, or fetched
// and injected by this module, with an embedded copy as the offline fallback).
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
const PP_LOG_CHUNK = 5000;         // mirrors the core cardState deposit search (drpc caps ~10k)
const SWEEPETH_IFACE = new ethers.Interface(['function sweepETH(address to)']);
const USDC_712_DOMAIN = { name: 'USD Coin', version: '2', chainId: 1, verifyingContract: USDC.addr };
const USDC_712_TYPES = { TransferWithAuthorization: [
  { name: 'from', type: 'address' }, { name: 'to', type: 'address' }, { name: 'value', type: 'uint256' },
  { name: 'validAfter', type: 'uint256' }, { name: 'validBefore', type: 'uint256' }, { name: 'nonce', type: 'bytes32' },
] };

// pill ladder; 'direct' is a terminal off-ladder state for sweeps that skip the pool
const STAGES = ['detected', 'sweeping', 'in_pool', 'asp_pending', 'withdrawable', 'withdrawn'];
const PILL_TEXT = {
  detected: 'DETECTED', sweeping: 'SWEEPING', in_pool: 'IN POOL', asp_pending: 'ASP PENDING',
  withdrawable: 'WITHDRAWABLE', withdrawn: 'WITHDRAWN', direct: 'SWEPT DIRECT',
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
let aspCache = { ts: 0, promise: null };
function getAsp() {
  if (aspCache.promise && Date.now() - aspCache.ts < 120000) return aspCache.promise;
  aspCache = { ts: Date.now(), promise: (async () => {
    const scope = BigInt(await GP.pp.ppCall(GP.pp.PP_IFACE.encodeFunctionData('SCOPE', [])));
    const res = await fetch(GP.pp.PP_ASP + '/mt-leaves', { headers: { 'X-Pool-Scope': scope.toString() } });
    if (!res.ok) throw new Error('ASP leaves fetch failed (' + res.status + ')');
    const { aspLeaves } = await res.json();
    return new Set(aspLeaves.map(x => BigInt(x)));
  })() };
  return aspCache.promise;
}
const fetchJson = async u => { const r = await fetch(u); if (!r.ok) throw new Error('http ' + r.status); return r.json(); };

// ── deposit + withdrawal trace (mirrors the core cardState logic) ──
async function findDeposit(addr, fromBlock) {
  const topic = GP.pp.PP_IFACE.getEvent('Deposited').topicHash;
  const depTopic = ethers.zeroPadValue(addr, 32);
  const end = Math.min(fromBlock + 100000, parseInt(await GP.jrpc('eth_blockNumber', []), 16));
  for (let e = end; e >= fromBlock; e -= PP_LOG_CHUNK) {
    const s = Math.max(e - PP_LOG_CHUNK + 1, fromBlock);
    const logs = await GP.jrpc('eth_getLogs', [{ address: GP.pp.PP_POOL, topics: [topic, depTopic], fromBlock: '0x' + s.toString(16), toBlock: '0x' + e.toString(16) }]);
    if (logs.length) {
      const p = GP.pp.PP_IFACE.parseLog(logs[logs.length - 1]);
      return { label: BigInt(p.args._label), value: BigInt(p.args._value), block: parseInt(logs[logs.length - 1].blockNumber, 16) };
    }
  }
  return null;
}
async function isWithdrawn(addr) {
  const rec = lsGet('ghostpay:ppnote:' + addr.toLowerCase(), null);
  if (!rec || !rec.nullifier) return null; // no tracking record on this device: state unknown
  const spent = BigInt(await GP.pp.ppCall(GP.pp.PP_IFACE.encodeFunctionData('nullifierHashes', [GP.crypto.spentNullifierHash(BigInt(rec.nullifier))])));
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
  let dep = null;
  try { dep = await findDeposit(addr, row.rec.block); } catch { /* RPC hiccup: fall through to persisted state */ }
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
    const asp = await getAsp();
    return asp.has(dep.label) ? 'withdrawable' : 'asp_pending';
  } catch { return 'in_pool'; }
}

// ── formatting ──
const trim = s => (s.includes('.') ? s.replace(/\.?0+$/, '') : s);
const usdStr = n => '$' + n.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
const fmtToken = (sym, bal) => { const t = TOKENS.find(x => x.sym === sym); return trim(ethers.formatUnits(bal, t.dec)); };
const short = a => a.slice(0, 10) + '…' + a.slice(-6);

// ── rows ──
const rows = new Map(); // addrLower → { rec, el, refs, ethBal, tokens, deposit, busy }
let rowsEl = null, statusEl = null, rootEl = null;

function ensureRow(rec) {
  const key = rec.address.toLowerCase();
  if (rows.has(key)) return rows.get(key);
  const el = document.createElement('div');
  el.className = 'gp-row';
  const addrEl = document.createElement('div'); addrEl.className = 'gp-addr'; addrEl.textContent = short(rec.address);
  addrEl.title = rec.address;
  const meta = document.createElement('div'); meta.className = 'gp-meta';
  const labelEl = document.createElement('span'); labelEl.className = 'gp-label';
  const tokensEl = document.createElement('div'); tokensEl.className = 'gp-tokens'; tokensEl.style.display = 'none';
  const pill = document.createElement('span'); pill.className = 'gp-pill dim'; pill.textContent = '…';
  const note = document.createElement('div'); note.className = 'gp-note'; note.style.display = 'none';
  const actions = document.createElement('div'); actions.className = 'gp-actions';
  const panel = document.createElement('div'); panel.className = 'gp-panel'; panel.style.display = 'none';
  el.append(addrEl, meta, labelEl, tokensEl, pill, note, actions, panel);
  rowsEl.appendChild(el);
  const row = { rec, el, refs: { addrEl, meta, labelEl, tokensEl, pill, note, actions, panel }, ethBal: null, tokens: {}, deposit: null, busy: false };
  rows.set(key, row);
  wireLabel(row);
  return row;
}

function wireLabel(row) {
  const { labelEl } = row.refs;
  const paint = () => {
    const l = getLabel(row.rec.address);
    labelEl.textContent = 'label: ' + (l || 'add +');
    labelEl.style.color = l ? '#fff' : '#555';
  };
  paint();
  labelEl.onclick = () => {
    const cur = getLabel(row.rec.address);
    const inp = document.createElement('input');
    inp.type = 'text'; inp.value = cur; inp.placeholder = 'local label (this device only)';
    inp.style.marginTop = '4px';
    labelEl.replaceWith(inp);
    inp.focus();
    const commit = () => {
      setLabel(row.rec.address, inp.value.trim());
      inp.replaceWith(labelEl);
      paint();
      GP.toast(inp.value.trim() ? 'label saved' : 'label cleared');
    };
    inp.onkeydown = e => { if (e.key === 'Enter') inp.blur(); if (e.key === 'Escape') { inp.value = cur; inp.blur(); } };
    inp.onblur = commit;
  };
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
  } catch { /* leave last rendered state */ }
  finally { row.busy = false; }
}

async function renderRow(row, stage) {
  const { meta, tokensEl, pill, note, actions } = row.refs;
  const addr = row.rec.address;
  const prices = await getPrices();
  // line 1: balance + detected time
  let balTxt = 'balance unknown';
  if (row.ethBal !== null) {
    balTxt = GP.fmt.formatEth(row.ethBal) + ' ETH';
    const usd = GP.fmt.formatUsd(GP.fmt.formatEth(row.ethBal), prices.eth);
    if (usd) balTxt += ' · ' + usd;
  }
  let timeTxt = 'block ' + row.rec.block.toLocaleString();
  try { timeTxt = await blockTime(row.rec.block); } catch { /* keep block number */ }
  meta.textContent = balTxt + ' · detected ' + timeTxt;
  // token line
  const syms = Object.keys(row.tokens);
  const pillTok = (getPill(addr) || {}).tokenSwept || {};
  if (syms.length || Object.keys(pillTok).length) {
    tokensEl.style.display = 'block';
    tokensEl.textContent = '';
    const parts = [];
    for (const s of syms) {
      let t = fmtToken(s, row.tokens[s]) + ' ' + s;
      const px = s === 'WETH' ? prices.eth : prices.usdc;
      if (px) t += ' ≈ ' + usdStr(Number(ethers.formatUnits(row.tokens[s], TOKENS.find(x => x.sym === s).dec)) * px);
      parts.push(t);
    }
    for (const s of Object.keys(pillTok)) if (!syms.includes(s)) parts.push(s + ' swept ✓');
    tokensEl.textContent = parts.join(' · ');
  } else {
    tokensEl.style.display = 'none';
  }
  // pill
  pill.textContent = PILL_TEXT[stage] || stage.toUpperCase();
  pill.classList.toggle('dim', stage === 'detected' || stage === 'asp_pending');
  // note line
  let noteTxt = '';
  if (stage === 'asp_pending') noteTxt = 'deposits wait for the association-set provider to approve them. usually hours. funds are safe.';
  else if (stage === 'withdrawable') noteTxt = 'ASP approved: withdraw in step 5 with your pp-secret file.';
  else if (stage === 'in_pool' && row.deposit) noteTxt = 'pool deposit ' + GP.fmt.formatEth(row.deposit.value) + ' ETH @ block ' + row.deposit.block.toLocaleString() + '. tracing ASP…';
  else if (stage === 'sweeping') noteTxt = 'sweep broadcast. this line advances when the tx confirms.';
  else if (stage === 'detected' && row.ethBal !== null && row.ethBal > 0n && row.ethBal >= PP_MIN) noteTxt = 'pool-ready: use SWEEP THIS on the payment card above to enter Privacy Pools.';
  note.style.display = noteTxt ? 'block' : 'none';
  note.textContent = noteTxt;
  // actions
  actions.textContent = '';
  const live = stage === 'detected' || stage === 'sweeping';
  if (live && row.tokens.USDC) {
    const b = document.createElement('button');
    b.textContent = 'SWEEP USDC';
    b.onclick = () => openUsdcSweep(row);
    actions.appendChild(b);
  }
  if (live && row.ethBal !== null && row.ethBal > 0n && row.ethBal < PP_MIN) {
    const b = document.createElement('button');
    b.className = 'ghost';
    b.textContent = 'SWEEP DIRECT';
    b.onclick = () => openDirectSweep(row);
    actions.appendChild(b);
  }
}

// ── stealth key (transient, never stored, never logged) ──
function stealthWallet(rec) {
  const keys = GP.state.keys;
  if (!keys || !keys.spendPriv) {
    throw new Error('watch-only session: your spend key is never stored on this device. RE-CONNECT, GENERATE MY STEALTH KEYS, then retry.');
  }
  const { sh } = GP.crypto.check(keys.viewPriv, keys.spendPub, rec.ephPub, rec.address);
  const w = new ethers.Wallet(GP.crypto.stealthKey(keys.spendPriv, sh));
  if (w.address.toLowerCase() !== rec.address.toLowerCase()) throw new Error('derived key mismatch');
  return w;
}

function panelBase(row, noteTxt) {
  const { panel } = row.refs;
  panel.textContent = '';
  panel.style.display = 'block';
  const note = document.createElement('div'); note.className = 'gp-note'; note.textContent = noteTxt;
  const amt = document.createElement('div'); amt.className = 'gp-tokens';
  const dest = document.createElement('input'); dest.type = 'text'; dest.placeholder = 'destination address (0x…)';
  if (GP.state.address) dest.value = GP.state.address;
  const st = document.createElement('div'); st.className = 'gp-note';
  panel.append(note, amt, dest, st);
  panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  return { panel, amt, dest, st };
}

function previewAndBroadcast(row, panel, st, artifact, summary, onRelayed) {
  const prev = document.createElement('div'); prev.className = 'gp-note'; prev.style.color = '#fff';
  prev.textContent = 'signed · ' + summary;
  const bBc = document.createElement('button'); bBc.textContent = 'BROADCAST VIA RELAYER';
  const bCp = document.createElement('button'); bCp.className = 'ghost'; bCp.textContent = 'COPY ARTIFACT';
  bCp.onclick = () => { navigator.clipboard.writeText(JSON.stringify(artifact, null, 2)); GP.toast('artifact copied'); };
  panel.append(prev, bBc, bCp);
  bBc.onclick = async () => {
    bBc.disabled = true;
    onRelayed();
    row._pendingArt = artifact;
    // live broadcast lifecycle: a static line reads as dead during the minutes this takes.
    // pulsing dot + elapsed timer while the relayer works, then the hash, then the outcome.
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
        st.textContent = 'tx REVERTED onchain · ' + out.hash + ' · the artifact stays valid: COPY ARTIFACT and retry.';
      } else {
        st.innerHTML = 'still pending after 10 minutes · tx ' + out.hash.slice(0, 14) + '…' + link + ' · it is in the private mempool, it usually lands within a few more minutes.';
      }
    } else {
      st.textContent = 'relayer broadcast failed: ' + ((out && out.error) || 'unknown') + ' · the artifact stays valid: COPY ARTIFACT and retry via relay.mjs.';
    }
    bBc.disabled = false;
  };
}

// USDC: gasless EIP-3009 transferWithAuthorization, signed by the stealth key. Direct transfer,
// not a pool deposit (the pool path is ETH-only in the current sweeper).
function openUsdcSweep(row) {
  const rec = row.rec;
  const { panel, amt, dest, st } = panelBase(row,
    'USDC sweep is an EIP-3009 transferWithAuthorization: gasless for this address, signed by the stealth key. it moves USDC straight to your destination, it does NOT enter Privacy Pools.');
  amt.textContent = 'amount: ' + fmtToken('USDC', row.tokens.USDC) + ' USDC (full balance)';
  const b = document.createElement('button'); b.textContent = 'SIGN USDC SWEEP';
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

// dust ETH (< 0.01): cannot enter Privacy Pools, so offer a direct sweep to a destination.
// With a sweeperV2 relayer this is a signed intent (action 0); older relayers get the
// legacy eip7702-sweep artifact (sweepETH calldata picked by the app, carried by the relayer).
function openDirectSweep(row) {
  const rec = row.rec;
  const { panel, amt, dest, st } = panelBase(row,
    'privacy note: direct sweeps skip the pool, so the destination sees this address.');
  amt.textContent = 'amount: ' + GP.fmt.formatEth(row.ethBal) + ' ETH (full balance, below the 0.01 pool minimum)';
  const b = document.createElement('button'); b.textContent = 'SIGN DIRECT SWEEP';
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
  rootEl.style.display = n ? 'block' : 'none';
  if (statusEl) statusEl.textContent = n
    ? n + ' payment' + (n === 1 ? '' : 's') + ' tracked · labels and pill state stay on this device'
    : '';
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

async function mount() {
  const m = document.getElementById('gp-inbox');
  if (!m) return;
  if (!document.getElementById('gp-inbox-root')) {
    let html = null;
    try { const r = await fetch('./frag-inbox.html'); if (r.ok) html = await r.text(); } catch { /* static open: use the embedded copy */ }
    m.insertAdjacentHTML('beforeend', html || FRAG_FALLBACK);
  }
  rootEl = document.getElementById('gp-inbox-root');
  rowsEl = document.getElementById('gp-inbox-rows');
  statusEl = document.getElementById('gp-inbox-status');
}

// offline fallback: identical copy of frag-inbox.html
const FRAG_FALLBACK = `<style>
  #gp-inbox-root h2 { font-size:11px; letter-spacing:.25em; color:#888; font-weight:400; margin:28px 0 6px; }
  .gp-row { border:1px solid #333; padding:16px; margin-top:12px; }
  .gp-row .gp-addr { font-weight:700; font-size:12px; word-break:break-all; }
  .gp-row .gp-meta { color:#777; font-size:11px; margin:6px 0 4px; }
  .gp-row .gp-tokens { font-size:12px; margin-top:6px; }
  .gp-row .gp-note { color:#666; font-size:11px; margin-top:6px; }
  .gp-pill { display:inline-block; border:1px solid #fff; padding:2px 8px; font-size:10px; letter-spacing:.15em; margin-top:8px; }
  .gp-pill.dim { border-color:#444; color:#888; }
  .gp-label { border-bottom:1px dashed #444; cursor:text; }
  .gp-label:hover { color:#fff; }
  .gp-actions { display:flex; gap:8px; margin-top:12px; flex-wrap:wrap; }
  .gp-actions button { width:auto; flex:1 1 auto; padding:10px 14px; font-size:11px; }
  .gp-panel { border:1px solid #444; padding:12px; margin-top:10px; }
  .gp-panel .gp-note:first-child { margin-top:0; }
  .gp-panel button { margin-top:8px; }
  @media (max-width:700px) { .gp-actions { flex-direction:column; } .gp-actions button { width:100%; } }
</style>
<div id="gp-inbox-root" style="display:none">
  <h2>PAYMENT INBOX</h2>
  <div class="status" id="gp-inbox-status" style="margin-top:0"></div>
  <div id="gp-inbox-rows"></div>
</div>`;

await mount();
if (rootEl) {
  syncRows();
  refreshAll();

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
  GP.on('withdrawn', d => {
    const addr = ((d && (d.stealthAddress || d.address)) || '').toLowerCase();
    if (rows.has(addr)) { putPill(addr, { stage: 'withdrawn' }); refreshRow(rows.get(addr)); }
  });
  GP.on('session', ({ type }) => {
    if (type === 'forgotten') { rows.clear(); rowsEl.textContent = ''; rootEl.style.display = 'none'; return; }
    syncRows();
    refreshAll();
  });

  setInterval(() => {
    if (document.visibilityState === 'hidden') return;
    refreshAll();
  }, 60000);
}
