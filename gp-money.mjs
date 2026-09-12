// gp-money.mjs · GHOSTPAY money-safety + relay-progress module.
// Mounts into #gp-sweep and #gp-withdraw via ./frag-money.html. Requires window.GP
// (docs/GP-API.md); loaded as <script type="module" src="./gp-money.mjs"></script>
// after the main inline script.
//
// ── INTERCEPTIONS (documented for the integrator) ─────────────────────────────
// All click interception uses ONE capture-phase listener on `document`, matched by
// target id. Capture on an ancestor fires strictly before the target's own onclick
// (registration order cannot race it). Gating = preventDefault + stopPropagation,
// then a one-shot bypass flag and a programmatic re-click runs the core handler
// untouched. The core handlers themselves are never edited.
//
// 1. #b-sweep, label "SIGN SWEEP": GATED. Backup-gate check first, then the sweep
//    preview interstitial (from/balance/destination/fee floor/sweeper). CONFIRM sets
//    the one-shot bypass and re-clicks; CANCEL leaves the core handler unfired.
// 2. #b-sweep, label "BROADCAST VIA RELAYER": DECORATED, never blocked. Starts the
//    relay progress view. NOTE: index.html's broadcast button calls the internal
//    relaySweep() directly, not GP.relaySweep, so this click hook (plus the
//    #st-broadcast observer below) is what covers the UI path.
// 3. #b-withdraw: GATED. Fresh-address check via GP.jrpc (eth_getTransactionCount +
//    eth_getBalance). Clean address: one-shot bypass scoped to that exact recipient
//    string, then re-click. History or unreachable RPC: loud warning, explicit
//    override re-clicks. The bypass is scoped so editing the recipient re-arms it.
// 4. #v-secret MutationObserver: the core writes the pp-secret JSON into #v-secret
//    when the auto-download fires. That arms the secret-backup gate
//    (localStorage "gp-money:backup-gate"): further SIGN SWEEP clicks are blocked
//    until CONFIRM BACKUP SAVED or a successful file re-upload check.
// 5. #st-broadcast MutationObserver: picks the tx hash out of the core's broadcast
//    status line, then polls GET ./status/<hash> every 5s for the progress view.
// 6. GP.relaySweep: WRAPPED (property reassigned, window.GP itself untouched) so
//    programmatic/module callers also get the progress view. The UI button path is
//    covered by hooks 2 + 5, not by this wrap.
//
// STORAGE: reads/writes only "gp-money:backup-gate". IMPORT BACKUP writes back the
// keys an export contains (gp-session, gp-invoice*, gp-label*, ghostpay:lastScanned:*,
// ghostpay:ppnote:*, gp-money:*). docs/GP-API.md marks gp-session + cursors as
// read-only for modules; the restore flow is the deliberate, documented exception.

const GP = (typeof window !== 'undefined' && window.GP) || null;

// ── backup crypto: pure WebCrypto, exported so it can be roundtrip-tested in node ──
const te = new TextEncoder();
const td = new TextDecoder();
const toHex = u8 => [...u8].map(x => x.toString(16).padStart(2, '0')).join('');
const fromHex = h => { const u = new Uint8Array(h.length / 2); for (let i = 0; i < u.length; i++) u[i] = parseInt(h.slice(2 * i, 2 * i + 2), 16); return u; };
const PBKDF2_ITERATIONS = 600000;

async function backupKey(passcode, salt, iterations) {
  const km = await crypto.subtle.importKey('raw', te.encode(passcode), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    km, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

export async function backupEncrypt(plainText, passcode) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await backupKey(passcode, salt, PBKDF2_ITERATIONS);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, te.encode(plainText)));
  return JSON.stringify({
    v: 1, app: 'ghostpay-backup',
    kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations: PBKDF2_ITERATIONS, salt: toHex(salt) },
    cipher: { name: 'AES-GCM', iv: toHex(iv) },
    data: toHex(ct),
  });
}

export async function backupDecrypt(fileText, passcode) {
  const f = JSON.parse(fileText);
  if (!f || f.v !== 1 || !f.kdf || !f.cipher || typeof f.data !== 'string')
    throw new Error('not a ghostpay backup file');
  const key = await backupKey(passcode, fromHex(f.kdf.salt), f.kdf.iterations | 0);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromHex(f.cipher.iv) }, key, fromHex(f.data));
  return td.decode(pt);
}

// ── everything below is browser-only ──
if (typeof window !== 'undefined' && typeof document !== 'undefined') {
  if (GP) boot().catch(e => console.error('gp-money boot failed:', e));
  else console.error('gp-money: window.GP missing. load gp-money.mjs after the main inline script.');
}

const GATE_KEY = 'gp-money:backup-gate';
const EST_SWEEP_GAS = 300000n;      // rough: 7702 auth + delegated PP deposit. estimate only, never used for signing.
const PP_MIN_WEI = 10n ** 16n;      // 0.01 ETH: serve.mjs rejects PP sweeps below this
const HASH_RE = /0x[0-9a-fA-F]{64}/;
const ADDR_RE = /0x[0-9a-fA-F]{40}/;
const BACKUP_EXACT = ['gp-session'];
const BACKUP_PREFIXES = ['gp-invoice', 'gp-label', 'ghostpay:lastScanned:', 'ghostpay:ppnote:', 'gp-money:'];

let signBypass = false;          // one-shot, consumed by the next capture pass
let withdrawBypassFor = null;    // recipient string the check already cleared
let previewOpen = false;
let armedAddr = null;            // last address seen in #st-armed
let progress = { active: false, hash: null, polls: 0, timer: null };

async function boot() {
  await mountFragments();
  wireSweepCapture();
  wireWithdrawCapture();
  wireSecretObserver();
  wireBroadcastObserver();
  wireProgressEvents();
  wireGate();
  wireBackup();
  wrapRelaySweep();
  const g = readGate();
  if (g) showGate(g);
  new MutationObserver(() => updateCost()).observe(document.getElementById('st-armed'), { childList: true, characterData: true, subtree: true });
  updateCost();
  setInterval(updateCost, 60000);
}

const $ = id => document.getElementById(id);
const short = s => s.length > 18 ? s.slice(0, 10) + '…' + s.slice(-6) : s;
const usdOf = eth => { try { const u = GP.fmt.formatUsd(eth); return u ? ' (' + u + ')' : ''; } catch { return ''; } };

async function mountFragments() {
  const res = await fetch('./frag-money.html');
  if (!res.ok) throw new Error('frag-money.html: http ' + res.status);
  const doc = new DOMParser().parseFromString(await res.text(), 'text/html');
  const style = doc.querySelector('style[data-gm-style]');
  if (style) document.head.appendChild(style);
  for (const [block, mountId] of [['sweep', 'gp-sweep'], ['withdraw', 'gp-withdraw']]) {
    const fragRoot = doc.querySelector('[data-gm-block="' + block + '"]');
    const mount = $(mountId);
    if (!fragRoot || !mount) { console.error('gp-money: missing fragment block or mount point', block, mountId); continue; }
    for (const node of [...fragRoot.childNodes]) mount.appendChild(node); // appendChild adopts across documents
  }
}

// address currently armed for sweeping, parsed from the core's own status line
// ("sweeping 0x… into Privacy Pools"). Null when nothing is armed.
function armedAddress() {
  const m = (($('st-armed') || {}).textContent || '').match(ADDR_RE);
  return m ? m[0] : null;
}

// ── 1 + 2 · sweep preview gate + broadcast decoration ──
function wireSweepCapture() {
  document.addEventListener('click', e => {
    if (e.target !== $('b-sweep')) return;
    const label = ($('b-sweep').textContent || '').trim().toUpperCase();
    if (label.startsWith('BROADCAST')) { beginRelayProgress(); return; } // decoration only, event continues
    if (!label.startsWith('SIGN')) return;                               // unknown stage: never interfere
    if (signBypass) { signBypass = false; return; }                      // our own re-click: let it through once
    e.preventDefault();
    e.stopPropagation();
    onSignSweepGated();
  }, true);
}

async function onSignSweepGated() {
  const gate = readGate();
  if (gate) {
    showGate(gate);
    $('gm-gate').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    GP.toast('confirm your withdrawal-secret backup before sweeping another payment');
    return;
  }
  const ok = await runPreview();
  if (ok) { signBypass = true; $('b-sweep').click(); }
}

function row(parent, k, v) {
  const d = document.createElement('div');
  d.className = 'gm-row';
  const a = document.createElement('span');
  a.className = 'gm-k';
  a.textContent = k;
  const b = document.createElement('b');
  b.textContent = v;
  d.append(a, b);
  parent.appendChild(d);
}

async function runPreview() {
  const addr = armedAddress();
  if (!addr) return true; // nothing armed: let the core handler say so itself
  if (previewOpen) return false;
  let bal = null, feeBps = null;
  try { bal = BigInt(await GP.jrpc('eth_getBalance', [addr, 'latest'])); } catch { /* shown as unknown */ }
  try {
    const r = await fetch('./fee');
    if (r.ok) { const j = await r.json(); if (j.minFeeBps != null) feeBps = Number(j.minFeeBps); }
  } catch { /* fee floor optional */ }

  const body = $('gm-preview-body');
  body.textContent = '';
  row(body, 'FROM (STEALTH)', addr);
  const eth = bal != null ? GP.fmt.formatEth(bal) : null;
  row(body, 'BALANCE', eth != null ? eth + ' ETH' + usdOf(eth) : 'unknown (RPC unreachable)');
  row(body, 'DESTINATION', 'Privacy Pools ETH deposit · 0xbow entrypoint ' + short(GP.pp.PP_ENTRYPOINT));
  let pre = null, sweeper = GP.const.SWEEPER, isIntent = false;
  const armedArt = GP.state.armedIntent ? GP.state.armedIntent(addr) : null;
  if (armedArt) {
    if (armedArt.sweeper) sweeper = armedArt.sweeper;
    isIntent = armedArt.kind === 'eip7702-intent';
    if (armedArt.precommitment) pre = armedArt.precommitment;
  }
  if (!pre) try {
    const a = JSON.parse($('v-artifact').textContent);
    if (a && a.precommitment && String(a.stealthAddress || '').toLowerCase() === addr.toLowerCase()) pre = a.precommitment;
  } catch { /* no live artifact */ }
  row(body, 'PRECOMMITMENT', pre
    ? short(pre) + ' · from the signed artifact on this card'
    : 'generated fresh at signing (random nullifier) · shown in the secret file + artifact right after');
  row(body, 'RELAYER FEE FLOOR', feeBps != null
    ? feeBps + ' bps (' + (feeBps / 100).toFixed(2) + '%)'
      + (bal != null ? ' = ' + GP.fmt.formatEth(bal * BigInt(feeBps) / 10000n) + ' ETH' : '')
    : 'unknown (relayer offline)');
  row(body, 'SWEEPER CONTRACT', sweeper + ' · etherscan.io/address/' + sweeper);
  const note = document.createElement('div');
  note.className = 'gm-note';
  note.style.color = '#444';
  note.textContent = isIntent
    ? 'signed intent sweep (SweeperV2): destination, fee and deadline come from your signature, the relayer cannot change them. '
      + 'gas is paid by the relayer. the pp-secret file already downloaded when this payment was armed: it is the only way to withdraw later.'
    : 'the v1 sweep deposits the full balance; the fee floor applies to intent sweeps. '
      + 'gas is paid by the relayer. the pp-secret file downloads the moment you sign: it is the only way to withdraw later.';
  body.appendChild(note);

  return new Promise(res => {
    previewOpen = true;
    $('gm-preview').style.display = 'block';
    $('gm-preview').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    const done = ok => {
      previewOpen = false;
      $('gm-preview').style.display = 'none';
      $('gm-preview-confirm').onclick = $('gm-preview-cancel').onclick = null;
      res(ok);
    };
    $('gm-preview-confirm').onclick = () => done(true);
    $('gm-preview-cancel').onclick = () => done(false);
  });
}

// ── 2 · cost preview line (refreshed every 60s and on re-arming) ──
let costBusy = false;
async function updateCost() {
  const box = $('gm-cost');
  if (!box || costBusy) return;
  const addr = armedAddress();
  if (!addr) { box.style.display = 'none'; armedAddr = null; return; }
  costBusy = true;
  try {
    let bal = null, gas = null, feeBps = null;
    try { bal = BigInt(await GP.jrpc('eth_getBalance', [addr, 'latest'])); } catch { /* RPC down */ }
    try { gas = BigInt(await GP.jrpc('eth_gasPrice', [])); } catch { /* RPC down */ }
    try {
      const r = await fetch('./fee');
      if (r.ok) { const j = await r.json(); if (j.minFeeBps != null) feeBps = Number(j.minFeeBps); }
    } catch { /* fee floor optional */ }

    const body = $('gm-cost-body');
    body.textContent = '';
    const eth = bal != null ? GP.fmt.formatEth(bal) : null;
    row(body, 'ARMED', short(addr) + (eth != null ? ' · ' + eth + ' ETH' + usdOf(eth) : ' · balance unknown'));
    row(body, 'RELAYER FEE FLOOR', feeBps != null ? feeBps + ' bps (' + (feeBps / 100).toFixed(2) + '%)' : 'unknown (relayer offline)');
    const gwei = gas != null ? (Number(gas) / 1e9).toFixed(2) + ' gwei' : 'unknown';
    let costTxt = 'unknown';
    if (gas != null) {
      const costEth = GP.fmt.formatEth(gas * EST_SWEEP_GAS);
      costTxt = '~' + costEth + ' ETH' + usdOf(costEth) + ' at ' + gwei + ' · paid by the relayer';
    }
    row(body, 'EST. NETWORK COST', costTxt);
    row(body, 'NET INTO THE POOL', eth != null
      ? eth + ' ETH' + usdOf(eth) + ' · v1 sweeps deposit the full balance'
      : 'unknown');
    $('gm-cost-min').style.display = (bal != null && bal < PP_MIN_WEI) ? 'block' : 'none';
    box.style.display = 'block';
    armedAddr = addr;
  } finally { costBusy = false; }
}

// ── 3 · relay progress view ──
function beginRelayProgress() {
  progress.active = true;
  progress.hash = null;
  progress.polls = 0;
  if (progress.timer) { clearInterval(progress.timer); progress.timer = null; }
  $('gm-progress').style.display = 'block';
  setProgressLine1('<span class="gm-pulse"></span>signed · relaying (the relayer adds a random delay to protect your timing)');
  setProgressLine2('waiting for the relayer to hand back a tx hash…');
  $('gm-progress').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function setProgressLine1(html) { $('gm-progress-line1').innerHTML = html; }
function setProgressLine2(html) { $('gm-progress-line2').innerHTML = html; }

// the core's broadcast status line is the only place the tx hash is observable without
// editing index.html; a persistent observer catches every broadcast path.
function wireBroadcastObserver() {
  new MutationObserver(() => {
    if (progress.hash) return;
    const m = (($('st-broadcast') || {}).textContent || '').match(HASH_RE);
    if (m) trackHash(m[0]);
  }).observe($('st-broadcast'), { childList: true, characterData: true, subtree: true });
}

async function trackHash(hash) {
  progress.hash = hash;
  progress.polls = 0;
  setProgressLine1('<span class="gm-pulse"></span>broadcast · pending ' + short(hash)
    + ' · <a href="https://etherscan.io/tx/' + hash + '" target="_blank" rel="noopener">etherscan</a>');
  setProgressLine2('polling the relayer every 5s for confirmation…');
  progress.timer = setInterval(() => pollStatus(hash), 5000);
  pollStatus(hash);
}

async function pollStatus(hash) {
  if (progress.hash !== hash) return;
  progress.polls++;
  try {
    const r = await fetch('./status/' + hash);
    if (!r.ok) throw new Error('http ' + r.status);
    const j = await r.json();
    if (j.status === 'confirmed') return setConfirmed(hash, j.blockNumber);
    if (j.status === 'failed') return setFailed(hash);
    setProgressLine2('pending · poll ' + progress.polls + ' · still waiting for a block…');
  } catch (e) {
    setProgressLine2('status poll failed (' + e.message + ') · retrying…');
  }
  if (progress.polls >= 120) {
    stopPolling();
    setProgressLine2('still pending after 10 minutes · check <a href="https://etherscan.io/tx/' + hash + '" target="_blank" rel="noopener">etherscan</a>.');
  }
}

function stopPolling() { if (progress.timer) { clearInterval(progress.timer); progress.timer = null; } }

function setConfirmed(hash, blockNumber) {
  stopPolling();
  progress.active = false;
  setProgressLine1('<span class="gm-ok">CONFIRMED'
    + (blockNumber != null ? ' in block ' + Number(blockNumber).toLocaleString() : '')
    + ' · ' + short(hash) + '</span>');
  setProgressLine2('<a href="https://etherscan.io/tx/' + hash + '" target="_blank" rel="noopener">view on etherscan: ' + hash + '</a>');
}

function setFailed(hash) {
  stopPolling();
  progress.active = false;
  setProgressLine1('<span class="gm-bad">FAILED · ' + short(hash) + ' · the sweep reverted onchain or was dropped</span>');
  setProgressLine2('hit RESCAN above, re-arm the payment, and SIGN SWEEP again. the signed artifact is single-use (the nonce moves on).');
}

// the core emits "swept" when its own receipt poll confirms; reconcile in case ./status lags.
function wireProgressEvents() {
  GP.on('swept', d => { if (d && d.hash && HASH_RE.test(d.hash)) setConfirmed(d.hash, d.block); });
}

function wrapRelaySweep() {
  const orig = GP.relaySweep;
  GP.relaySweep = artifact => { beginRelayProgress(); return orig(artifact); };
}

// ── 4 · secret-backup gate ──
function readGate() { try { return JSON.parse(localStorage.getItem(GATE_KEY) || 'null'); } catch { return null; } }
function clearGate() { try { localStorage.removeItem(GATE_KEY); } catch { /* storage blocked */ } $('gm-gate').style.display = 'none'; }

function wireSecretObserver() {
  new MutationObserver(() => {
    let j = null;
    try { j = JSON.parse($('v-secret').textContent); } catch { return; }
    if (!j || !j.nullifier || !j.precommitment) return;
    const g = { nullifier: j.nullifier, precommitment: j.precommitment, stealthAddress: j.stealthAddress || null, ts: Date.now() };
    try { localStorage.setItem(GATE_KEY, JSON.stringify(g)); } catch { /* the visible gate still works this session */ }
    showGate(g);
  }).observe($('v-secret'), { childList: true, characterData: true, subtree: true });
}

function showGate(g) {
  const body = $('gm-gate-body');
  body.textContent = '';
  row(body, 'NEW SECRET', g.stealthAddress ? 'pp-secret for ' + short(g.stealthAddress) : 'pp-secret downloaded');
  row(body, 'PRECOMMITMENT', short(g.precommitment));
  $('gm-gate-status').textContent = '';
  $('gm-gate-file').value = '';
  $('gm-gate').style.display = 'block';
}

function wireGate() {
  $('gm-gate-confirm').onclick = () => { clearGate(); GP.toast('backup confirmed · sweeping re-enabled'); };
  $('gm-gate-file').onchange = async e => {
    const f = e.target.files && e.target.files[0];
    if (!f) return;
    const st = $('gm-gate-status');
    const g = readGate();
    if (!g) { st.textContent = ''; return; }
    try {
      const j = JSON.parse(await f.text());
      if (!j.nullifier || !j.secret || !j.precommitment) throw new Error('file is missing nullifier, secret, or precommitment');
      if (String(j.nullifier).toLowerCase() !== String(g.nullifier).toLowerCase())
        throw new Error('nullifier mismatch: this file is for a different deposit');
      if (GP.crypto.poseidon2([BigInt(j.nullifier), BigInt(j.secret)]) !== BigInt(g.precommitment))
        throw new Error('poseidon2(nullifier, secret) does not match the precommitment: file corrupt or edited');
      clearGate();
      GP.toast('backup verified · sweeping re-enabled');
    } catch (err) {
      st.textContent = 'check failed: ' + err.message;
    }
  };
}

// ── 6 · fresh-address withdrawal check ──
function wireWithdrawCapture() {
  document.addEventListener('click', e => {
    if (e.target !== $('b-withdraw')) return;
    const rcpt = (($('i-recipient') || {}).value || '').trim();
    if (!GP.ethers.isAddress(rcpt)) return; // bad input: the core handler reports it
    if (withdrawBypassFor && withdrawBypassFor.toLowerCase() === rcpt.toLowerCase()) { withdrawBypassFor = null; return; }
    e.preventDefault();
    e.stopPropagation();
    checkRecipient(rcpt);
  }, true);
}

async function checkRecipient(rcpt) {
  let nonce = null, bal = null;
  try {
    nonce = parseInt(await GP.jrpc('eth_getTransactionCount', [rcpt, 'latest']), 16);
    bal = BigInt(await GP.jrpc('eth_getBalance', [rcpt, 'latest']));
    if (!Number.isFinite(nonce)) throw new Error('bad nonce response');
  } catch {
    return showFreshWarning(rcpt, null); // check unreachable: warn, do not silently skip
  }
  if (nonce === 0 && bal === 0n) { withdrawBypassFor = rcpt; $('b-withdraw').click(); return; }
  showFreshWarning(rcpt, { nonce, bal });
}

function showFreshWarning(rcpt, info) {
  const body = $('gm-fresh-body');
  body.textContent = '';
  row(body, 'RECIPIENT', rcpt);
  if (info) {
    row(body, 'NONCE', String(info.nonce) + (info.nonce > 0 ? ' · this address has sent transactions' : ''));
    row(body, 'ETH BALANCE', GP.fmt.formatEth(info.bal) + ' ETH' + usdOf(GP.fmt.formatEth(info.bal)));
  } else {
    row(body, 'HISTORY CHECK', 'FAILED · RPC unreachable, history unknown');
  }
  $('gm-fresh').style.display = 'block';
  $('gm-fresh').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  $('gm-fresh-new').onclick = () => {
    $('gm-fresh').style.display = 'none';
    const inp = $('i-recipient');
    inp.focus();
    inp.select();
  };
  $('gm-fresh-override').onclick = () => {
    $('gm-fresh').style.display = 'none';
    withdrawBypassFor = rcpt;
    $('b-withdraw').click();
  };
}

// ── 5 · encrypted backup export / import ──
function collectBackup() {
  const items = {};
  for (let i = 0; i < localStorage.length; i++) {
    const k = localStorage.key(i);
    if (BACKUP_EXACT.includes(k) || BACKUP_PREFIXES.some(p => k.startsWith(p))) items[k] = localStorage.getItem(k);
  }
  return { v: 1, app: 'ghostpay', ts: new Date().toISOString(), items };
}

function downloadFile(name, text) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
}

function wireBackup() {
  const st = $('gm-backup-status');
  $('gm-backup-export').onclick = async () => {
    const p1 = $('gm-backup-pass').value, p2 = $('gm-backup-pass2').value;
    if (!p1) { st.textContent = 'set a passcode first.'; return; }
    if (p1 !== p2) { st.textContent = 'passcodes do not match.'; return; }
    if (p1.length < 8) { st.textContent = 'passcode too short: use 12+ characters.'; return; }
    try {
      st.textContent = 'encrypting (PBKDF2 x600,000)…';
      const payload = collectBackup();
      const n = Object.keys(payload.items).length;
      const enc = await backupEncrypt(JSON.stringify(payload), p1);
      downloadFile('ghostpay-backup-' + new Date().toISOString().slice(0, 10) + '.json', enc);
      st.textContent = 'exported ' + n + ' key(s), encrypted. store the file like a key: it holds your watch-only session'
        + (n ? ' and everything else restorable on this device.' : '.');
    } catch (e) { st.textContent = 'export failed: ' + e.message; }
  };
  $('gm-backup-import').onclick = async () => {
    const f = $('gm-backup-file').files && $('gm-backup-file').files[0];
    const pass = $('gm-backup-pass').value;
    if (!f) { st.textContent = 'pick a backup file first.'; return; }
    if (!pass) { st.textContent = 'enter the backup passcode in the first passcode field.'; return; }
    try {
      st.textContent = 'decrypting (PBKDF2 x600,000)…';
      const payload = JSON.parse(await backupDecrypt(await f.text(), pass));
      if (!payload || payload.v !== 1 || payload.app !== 'ghostpay' || !payload.items || typeof payload.items !== 'object')
        throw new Error('decrypted payload is not a ghostpay backup');
      const keys = Object.keys(payload.items);
      for (const k of keys) localStorage.setItem(k, String(payload.items[k]));
      st.textContent = 'imported ' + keys.length + ' key(s). importing overwrote same-named keys on this device. reload to apply.';
      $('gm-backup-reload').style.display = 'block';
    } catch (e) {
      st.textContent = 'import failed: ' + (e && e.name === 'OperationError' ? 'wrong passcode or corrupt file' : e.message);
    }
  };
  $('gm-backup-reload').onclick = () => location.reload();
}
