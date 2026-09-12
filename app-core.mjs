// app-core.mjs — GHOSTPAY shared core: connect, generate, receive, scan, sweep, withdraw,
// the window.GP module API (docs/GP-API.md). Imported as a module by app.html (full app)
// and invoices.html (invoice suite needs the same connect/generate/scan machinery).
// The homepage (index.html) is self-contained: doors + the payer flow.
// Sweep/withdraw-only controls exist on app.html alone, so those bindings are guarded.
import { secp256k1 } from 'https://esm.sh/@noble/curves@1.6.0/secp256k1.js';
import { sha256 } from 'https://esm.sh/@noble/hashes@1.5.0/sha256.js';
import { keccak_256 } from 'https://esm.sh/@noble/hashes@1.5.0/sha3.js';
import * as ethers from 'https://esm.sh/ethers@6.13.4';
import { IrnClient } from 'https://esm.sh/@hazae41/latrine/out/mods/irn/mod.js';
import { WalletConnect, WcPairing } from 'https://esm.sh/@hazae41/latrine/out/mods/wc/mod.js';
import { Jwt } from 'https://esm.sh/@hazae41/latrine/out/libs/jwt/mod.js';
import qrcode from 'https://esm.sh/qrcode-generator@1.4.4';
import { poseidon2 } from './vendor/poseidon2.mjs';
import { poseidon1, poseidon3 } from './vendor/poseidon13.mjs';

const $ = id => document.getElementById(id);
const hex = b => '0x' + [...b].map(x => x.toString(16).padStart(2, '0')).join('');
function buf(h){ h = h.replace(/^0x/, ''); const u = new Uint8Array(h.length/2); for (let i=0;i<u.length;i++) u[i]=parseInt(h.slice(2*i,2*i+2),16); return u; }
const N = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
const mod = x => ((x % N) + N) % N;
const bint = b => BigInt(hex(b));

// ERC-5564 scheme 1. Shared-secret hash: keccak256 (spec/ScopeLift/Rust reference).
// GHOSTPAY used sha256 before the 2026-09-08 migration; LEGACY enables scanning and
// sweeping announcements made under the old scheme (their addresses differ).
let LEGACY = false;
const schemeHash = u => LEGACY ? sha256(u) : keccak_256(u);
const addrOf = P => '0x' + [...keccak_256(P.toRawBytes(false).slice(1)).slice(-20)].map(x=>x.toString(16).padStart(2,'0')).join('');
function derive(metaHex) {
  const m = buf(metaHex);
  const ephPriv = mod(bint(secp256k1.utils.randomPrivateKey()));
  const ephPub = secp256k1.getPublicKey(ephPriv, true);
  const sh = keccak_256(secp256k1.getSharedSecret(ephPriv, m.slice(33,66), true));
  const stealthPub = secp256k1.ProjectivePoint.fromHex(m.slice(0,33)).add(secp256k1.ProjectivePoint.BASE.multiply(mod(bint(sh))));
  return { stealth: addrOf(stealthPub), ephPub: hex(ephPub), viewTag: sh[0], sh: hex(sh) };
}
function check(viewPriv, spendPub, ephPub, addr) {
  const sh = schemeHash(secp256k1.getSharedSecret(buf(viewPriv), buf(ephPub), true));
  const stealthPub = secp256k1.ProjectivePoint.fromHex(buf(spendPub)).add(secp256k1.ProjectivePoint.BASE.multiply(mod(bint(sh))));
  return { match: addrOf(stealthPub).toLowerCase() === addr.toLowerCase(), viewTag: sh[0], sh: hex(sh) };
}
const stealthKey = (spendPriv, sh) => '0x' + mod(bint(buf(spendPriv)) + bint(buf(sh))).toString(16).padStart(64,'0');

// minimal RLP + 7702 auth
const cat = (...as) => { const u = new Uint8Array(as.reduce((s,a)=>s+a.length,0)); let o=0; for (const a of as){u.set(a,o);o+=a.length;} return u; };
const big2b = n => { const h = n.toString(16); return buf(h.length%2?'0'+h:h); };
function rlp(x){
  if (Array.isArray(x)) { const p = cat(...x.map(rlp)); return cat(rlplen(p,0xc0), p); }
  let b = typeof x === 'bigint' ? (x===0n ? new Uint8Array(0) : big2b(x)) : buf(x);
  if (b.length===1 && b[0]<0x80) return b;
  return cat(rlplen(b,0x80), b);
}
const rlplen = (p,off) => p.length<56 ? Uint8Array.from([off+p.length]) : cat(Uint8Array.from([off+55+nb(p.length)]), nbarr(p.length));
const nb = n => { let c=0; while(n){c++;n>>=8;} return c; };
const nbarr = n => { const a=new Uint8Array(nb(n)); for(let i=a.length-1;i>=0;i--){a[i]=n&255;n>>=8;} return a; };
function sign7702(priv, chainId, sweeper, nonce) {
  const msg = keccak_256(cat(Uint8Array.from([0x05]), rlp([BigInt(chainId), sweeper, BigInt(nonce)])));
  const sig = secp256k1.sign(msg, buf(priv));
  return { chainId, address: sweeper, nonce, yParity: sig.recovery, r: '0x'+sig.r.toString(16).padStart(64,'0'), s: '0x'+sig.s.toString(16).padStart(64,'0') };
}

// state
let W = null; // { account, viewPriv, spendPriv, spendPub, viewPub, meta }
const RPC = window.GHOSTPAY_RPC || 'https://eth.drpc.org'; // paid/private RPC goes in config.local.js (gitignored)
const ANNOUNCER = '0x55649E01B5Df198D18D95b5cc5051630cfD45564';
const CHAIN_ID = 1;
const SWEEPER = '0x749d2c0e9Ffb57102Aa9f5424e94216791f6467B'; // StealthSweeper, mainnet, tx 0xb0630930
const SWEEPER_V2 = '0xCC29c7723116155ccF20C7c0b8924F4747331903'; // StealthSweeperV2 (signed intents), mainnet
const ZERO_ADDR = '0x0000000000000000000000000000000000000000';
const PP_MIN_SWEEP = 10000000000000000n; // 0.01 ETH: below this a deposit cannot enter Privacy Pools
const INTENT_TYPES = { SweepIntent: [
  { name: 'action', type: 'uint8' }, { name: 'token', type: 'address' }, { name: 'destination', type: 'address' },
  { name: 'precommitment', type: 'uint256' }, { name: 'feeBps', type: 'uint256' }, { name: 'deadline', type: 'uint256' },
] };
// EIP-712 domain: verifyingContract is the stealth EOA itself (SweeperV2 executes AS the EOA under 7702)
const intentDomain = stealth => ({ name: 'GhostpaySweeper', version: '1', chainId: CHAIN_ID, verifyingContract: stealth });
const SWEEPER_IFACE = new ethers.Interface([
  'function sweepToPrivacyPoolsETH(uint256 precommitment)'
]);
const copy = (txt, btn) => { navigator.clipboard.writeText(txt); btn.textContent = 'COPIED ✓'; setTimeout(()=>btn.textContent=btn.dataset.t, 1200); };
document.querySelectorAll('button').forEach(b => b.dataset.t = b.textContent);

// ── ui-core: event hub, toast, session persistence ──
// GP.on/GP.emit are the module bus (see docs/GP-API.md). Events: "payment", "swept", "session".
const GP_EVENTS = {};
const gpOn = (ev, cb) => { (GP_EVENTS[ev] ??= []).push(cb); };
const gpEmit = (ev, data) => { (GP_EVENTS[ev] || []).forEach(cb => { try { cb(data); } catch (e) { console.error('GP listener failed (' + ev + '):', e); } }); };
let toastTimer = null;
function toast(msg) {
  const t = $('gp-toast');
  t.textContent = msg;
  t.style.display = 'block';
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.style.display = 'none'; }, 4000);
}
// gp-session: ONLY the viewing key + stealth meta-address (watch-only). The spend key is
// never stored, so sweeping always needs a fresh wallet signature.
const SESSION_KEY = 'gp-session';
const loadGpSession = () => { try { return JSON.parse(localStorage.getItem(SESSION_KEY) || 'null'); } catch { return null; } };

// ── ephemeral receive records: the safety net ──
// A generated receive address is recoverable only while its ephemeral record exists, and
// derive() rolls a fresh random ephemeral key every time (previously the record lived in
// the live tab's memory only: a closed tab stranded any unannounced payment forever).
// Persist every generated address until it is announced (scanner can find payments from
// the onchain announcement alone) or swept (funds moved). Records carry exactly what an
// announcement publishes, never spend-key material.
const RECV_KEY = 'gp-recv-records';
const loadRecvRecords = () => { try { const r = JSON.parse(localStorage.getItem(RECV_KEY) || '[]'); return Array.isArray(r) ? r : []; } catch { return []; } };
const saveRecvRecords = rs => { try { localStorage.setItem(RECV_KEY, JSON.stringify(rs.slice(-10))); } catch { /* storage full: recovery banner just shows fewer */ } };
function recordRecv(rec) {
  const rs = loadRecvRecords().filter(x => x.stealth.toLowerCase() !== rec.stealth.toLowerCase());
  rs.push({ stealth: rec.stealth, ephPub: rec.ephPub, viewTag: rec.viewTag, created: Date.now() });
  saveRecvRecords(rs);
  renderRecvRecovery();
}
function dropRecvRecord(stealth) {
  saveRecvRecords(loadRecvRecords().filter(x => x.stealth.toLowerCase() !== stealth.toLowerCase()));
  renderRecvRecovery();
}
function renderRecvRecovery() {
  const host = $('s2'); if (!host) return;
  let el = $('recv-recovery');
  const cur = W && W.recv && W.recv.stealth.toLowerCase();
  const pending = loadRecvRecords().filter(x => x.stealth.toLowerCase() !== cur);
  if (!pending.length) { if (el) el.remove(); return; }
  if (!el) {
    el = document.createElement('div');
    el.id = 'recv-recovery';
    el.style.cssText = 'border:1px solid #fff;padding:14px;margin:12px 0;font-size:12px;line-height:1.7';
    host.insertBefore(el, host.children[1] || null);
  }
  el.innerHTML = '';
  const r = pending[pending.length - 1];
  const txt = document.createElement('div');
  txt.textContent = 'RECOVERY · ' + pending.length + ' unannounced address' + (pending.length > 1 ? 'es' : '') + ' · latest: ' + r.stealth
    + ' · any payment to it is invisible to your scanner until you announce it:';
  el.appendChild(txt);
  const row = document.createElement('div');
  row.style.cssText = 'margin-top:10px;display:flex;gap:10px';
  const bAnn = document.createElement('button');
  bAnn.textContent = 'ANNOUNCE NOW';
  bAnn.style.cssText = 'width:auto;padding:8px 16px;font-size:11px';
  bAnn.onclick = async () => { bAnn.disabled = true; await announceRecv(r); bAnn.disabled = false; };
  const bDrop = document.createElement('button');
  bDrop.textContent = 'FORGET IT';
  bDrop.className = 'ghost';
  bDrop.style.cssText = 'width:auto;padding:8px 16px;font-size:11px';
  bDrop.onclick = () => dropRecvRecord(r.stealth);
  row.appendChild(bAnn); row.appendChild(bDrop);
  el.appendChild(row);
}
function saveGpSession() {
  try {
    localStorage.setItem(SESSION_KEY, JSON.stringify({ v: 1, viewPriv: W.viewPriv, meta: W.meta, ts: Date.now() }));
  } catch { /* storage blocked/full: persistence is best-effort, the session still works */ }
}
// wizard collapse/expand: a stored session hides steps 1-2 into the #gp-dash header.
// the receive card (c-recv) and meta details (d-meta) inside s2 stay visible either way.
function collapseWizard() {
  $('s1').style.display = 'none';
  $('s2').querySelector('h2').style.display = 'none';
  $('b-gen').style.display = 'none';
  $('st-gen').style.display = 'none';
  $('remember-row').style.display = 'none';
  $('s2').classList.add('on');
}
function expandWizard() {
  $('s1').style.display = 'block';
  $('s2').querySelector('h2').style.display = '';
  $('b-gen').style.display = '';
  $('st-gen').style.display = '';
}
function refreshDash() {
  const sess = loadGpSession();
  if (!sess || !W || !W.viewPriv) { $('gp-dash').style.display = 'none'; return; }
  $('gp-dash').style.display = 'block';
  $('gp-dash-addr').textContent = W.account ? 'wallet: ' + W.account : 'meta: ' + (W.meta || sess.meta);
  $('gp-dash-mode').textContent = W.spendPriv ? 'FULL SESSION · SWEEP ENABLED' : 'WATCH-ONLY SESSION';
}

// withdrawal-secret download: auto-saves once, button re-saves. The secret is generated and
// displayed BEFORE the signed artifact is shown, so a sweep can never exist without its secret.
function download(filename, text) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], { type: 'application/octet-stream' }));
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
}
function showSecret(label, display, filename, fileText) {
  $('c-secret').style.display = 'block';
  $('v-secret-lbl').textContent = label;
  $('v-secret').textContent = display;
  $('b-dlsecret').onclick = () => download(filename, fileText);
  download(filename, fileText);
}

// ── loud failure mode: any error, anywhere, lands in the status line ──
window.addEventListener('error', e => { const s = $('st-connect'); if (s) s.textContent = 'error: ' + (e.message || 'script failed to load · check network (esm.sh CDN) and reload'); });
window.addEventListener('unhandledrejection', e => { const s = $('st-connect'); if (s) s.textContent = 'error: ' + ((e.reason && e.reason.message) || e.reason || 'unknown'); });

// ── EIP-6963 wallet discovery: finds every installed wallet even when extensions fight over window.ethereum ──
const PROVIDERS = []; // {info, provider}
window.addEventListener('eip6963:announceProvider', e => {
  if (!PROVIDERS.some(p => p.info.uuid === e.detail.info.uuid)) PROVIDERS.push(e.detail);
});
window.dispatchEvent(new Event('eip6963:requestProvider'));
setTimeout(() => {
  const names = PROVIDERS.map(p => p.info.name);
  const boot = $('bootline');
  if (!boot) return;
  if (names.length) boot.textContent = 'wallets detected: ' + names.join(' · ');
  else if (window.ethereum) boot.textContent = 'wallets detected: an injected provider (unnamed)';
  else boot.textContent = 'no injected wallet detected · CONNECT will use WalletConnect (latrine): QR / link / paste.';
}, 400);

async function connectInjected() {
  // prefer a 6963 provider (Ambire if present), fall back to window.ethereum
  let provider = null, name = 'injected wallet';
  if (PROVIDERS.length) {
    const amb = PROVIDERS.find(p => /ambire/i.test(p.info.name)) || PROVIDERS[0];
    provider = amb.provider; name = amb.info.name;
  } else if (window.ethereum) {
    provider = window.ethereum;
  }
  if (!provider) { $('st-connect').textContent = 'no injected wallet found · use the WalletConnect path below.'; return; }
  const prov = new ethers.BrowserProvider(provider);
  const accounts = await prov.send('eth_requestAccounts', []);
  W = { account: accounts[0], prov, eip1193: provider };
  $('qrwrap').style.display = 'none';
  $('st-connect').innerHTML = 'connected via ' + name + ': <span class="ok">' + W.account + '</span>';
  $('b-gen').disabled = false;
  $('s2').classList.add('on');
}

// ── 1 · connect (latrine = privacy-hardened WalletConnect client) ──
function showQr(text) {
  const qr = qrcode(0, 'M'); qr.addData(text); qr.make();
  const cv = $('qr'), ctx = cv.getContext('2d');
  const n = qr.getModuleCount(), scale = 4;
  cv.width = cv.height = n * scale;
  ctx.fillStyle = '#fff'; ctx.fillRect(0, 0, cv.width, cv.height);
  ctx.fillStyle = '#000';
  for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) if (qr.isDark(r, c)) ctx.fillRect(c * scale, r * scale, scale, scale);
  $('qrwrap').style.display = 'block';
}
async function connectLatrine() {
  const st = m => $('st-connect').textContent = m;
  const pid = $('i-wcpid').value.trim();
  st('signing relay identity…');
  const jwk = crypto.getRandomValues(new Uint8Array(32));
  const jwt = await Jwt.sign(jwk, WalletConnect.RELAY);
  st('creating pairing…');
  const socket = new WebSocket(`${WalletConnect.RELAY}/?auth=${jwt}&projectId=${pid}`);
  const client = new IrnClient(socket);
  const pairing = await WcPairing.generate(client);
  const url = pairing.url;
  // show everything FIRST so nothing can vanish the evidence
  showQr(url);
  $('wc-link').href = url;
  $('wc-raw').textContent = url;
  st('pairing ready · open your wallet and approve. (on mobile your wallet opens by itself)');
  // mobile: auto-open wallet app via the wc: uri (WalletConnect-recommended); desktop: user clicks OPEN WALLET
  if (/Android|iPhone|iPad/i.test(navigator.userAgent)) window.location.href = url;
  // relay handshake in the background, with real error surfacing (IrnClient.open can't do this)
  st('relay connecting… approve in your wallet when it pops');
  await Promise.race([
    new Promise((res, rej) => {
      socket.addEventListener('open', res);
      socket.addEventListener('error', () => rej(new Error('relay rejected the connection')));
      socket.addEventListener('close', e => rej(new Error('relay closed the handshake (' + e.code + ')')));
    }),
    new Promise((_, rej) => setTimeout(() => rej(new Error('relay handshake timed out · try again')), 25000))
  ]);
  st('relay connected · waiting for wallet approval…');
  const upgraded = new Promise((res, rej) => {
    pairing.addEventListener('upgrade', e => res(e.data));
    pairing.addEventListener('close', () => rej(new Error('pairing closed')));
  });
  await pairing.open();
  await pairing.propose({
    self: { name: 'GHOSTPAY', description: 'receive-only stealth payments', url: location.origin, icons: [] },
    requiredNamespaces: { eip155: { chains: ['eip155:1'], methods: ['personal_sign', 'eth_sendTransaction'], events: [] } }
  });
  const session = await upgraded;
  st('session upgrading…');
  const settled = new Promise((res, rej) => {
    session.addEventListener('settle', e => res(e.data));
    session.addEventListener('close', () => rej(new Error('session closed')));
  });
  await session.open();
  const stl = await settled;
  const account = stl.namespaces.eip155.accounts[0].split(':')[2];
  return { session, account };
}
async function ghostSign(message) {
  if (W.session) {
    const hexMsg = ethers.hexlify(new TextEncoder().encode(message));
    return await W.session.request({ chainId: 'eip155:1', request: { method: 'personal_sign', params: [hexMsg, W.account] } });
  }
  return await (await W.prov.getSigner()).signMessage(message);
}
$('b-connect').onclick = async () => {
  // 6963/injected wallet (Ambire extension, …) pops instantly; latrine/WC when nothing is injected.
  if (PROVIDERS.length || window.ethereum) return connectInjected();
  try {
    const { session, account } = await connectLatrine();
    W = { session, account };
    $('qrwrap').style.display = 'none';
    $('st-connect').innerHTML = 'connected: <span class="ok">' + account + '</span>';
    $('b-gen').disabled = false;
    $('s2').classList.add('on');
  } catch (e) {
    $('st-connect').textContent = 'pairing failed: ' + e.message;
    $('b-injected').style.display = 'block';
  }
};
$('b-injected').onclick = connectInjected;
$('b-forcelatrine').onclick = async e => {
  e.preventDefault();
  try {
    const { session, account } = await connectLatrine();
    W = { session, account };
    $('qrwrap').style.display = 'none';
    $('st-connect').innerHTML = 'connected: <span class="ok">' + account + '</span>';
    $('b-gen').disabled = false;
    $('s2').classList.add('on');
  } catch (err) {
    $('st-connect').textContent = 'pairing failed: ' + err.message;
  }
};

// ── 2 · generate (keys from one wallet signature) ──
$('b-gen').onclick = async () => {
  const sig = await ghostSign('GHOSTPAY v1 — derive stealth keys. This signature spends nothing.');
  const spendPriv = '0x' + hex(keccak_256(cat(buf(sig), new TextEncoder().encode('|spend')))).slice(2);
  const viewPriv  = '0x' + hex(keccak_256(cat(buf(sig), new TextEncoder().encode('|view')))).slice(2);
  W.spendPriv = spendPriv; W.viewPriv = viewPriv;
  W.spendPub = hex(secp256k1.getPublicKey(buf(spendPriv), true));
  W.viewPub = hex(secp256k1.getPublicKey(buf(viewPriv), true));
  W.meta = 'st:eth:0x' + (W.spendPub + W.viewPub).replace(/0x/g, '');
  // fresh one-time receiving address off our own meta-address (same derive() as pay-a-ghost mode).
  // share the 0x address; the announcement is what lets the scanner below find the payment.
  W.recv = derive(W.meta.slice(7));
  recordRecv(W.recv);
  $('c-recv').style.display = 'block';
  $('v-recv').textContent = W.recv.stealth;
  $('st-announce').textContent = 'share this 0x address to get paid. payment links announce automatically when the payer pays; ANNOUNCE IT is only needed for raw-address payments.';
  $('d-meta').style.display = 'block';
  $('v-meta').textContent = W.meta;
  $('st-gen').textContent = 'done. your keys regenerate from the same signature any time, any device.';
  // s3/s4 exist on app.html (sweep/withdraw); invoices.html has neither
  ['s3', 's4'].forEach(id => { const el = $(id); if (el) el.classList.add('on'); });
  // watch-only persistence offer: storing the viewing key + meta-address only, never the spend key
  $('remember-row').style.display = 'block';
  $('i-remember').checked = !!loadGpSession();
  if ($('i-remember').checked) { saveGpSession(); collapseWizard(); }
  refreshDash();
  gpEmit('session', { type: 'unlocked', watchOnly: false, address: W.account || null });
  scan();
};
$('i-remember').onchange = e => {
  if (e.target.checked) {
    if (W && W.viewPriv && W.meta) {
      saveGpSession();
      collapseWizard();
      toast('session saved on this device (watch-only)');
      gpEmit('session', { type: 'saved', watchOnly: !W.spendPriv, address: W.account || null });
    }
  } else {
    localStorage.removeItem(SESSION_KEY);
    expandWizard();
    toast('session removed from this device');
    gpEmit('session', { type: 'forgotten' });
  }
  refreshDash();
};
$('b-copyrecv').onclick = e => copy(W.recv.stealth, e.target);
$('b-copymeta').onclick = e => copy(W.meta, e.target);
// pay-me links point at the homepage: the payer flow (pay-a-ghost) lives there
$('b-copylink').onclick = e => copy(location.origin + '/#' + W.meta, e.target);
async function announceRecv(rec) {
  const st = m => $('st-announce').textContent = m;
  const src = rec || (W && W.recv);
  if (!src) { st('generate your stealth keys first (or restore a session).'); return null; }
  const { stealth, ephPub, viewTag } = src;
  // primary path: the local relayer announces (runner wallet pays gas).
  try {
    st('announcing via relayer… (deliberate 2–15s privacy delay before broadcast · hold on)');
    const r = await fetch('/announce', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ stealth, ephPub, viewTag }) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok || j.error) throw new Error(j.error || ('http ' + r.status));
    st('broadcast via relayer: ' + j.hash + ' · waiting for confirmation (private mempool: explorers will not show it until it is mined)…');
    (async () => {
      for (let i = 0; i < 120; i++) {
        await new Promise(x => setTimeout(x, 5000));
        try {
          const s = await fetch('/status/' + j.hash).then(r => r.json());
          if (s.status === 'confirmed') {
            st('announced: ' + j.hash + ' · your scanner will now find payments to this address. share it and get paid.');
            dropRecvRecord(stealth); // confirmed onchain: the scanner covers recovery from here
            return;
          }
          if (s.status === 'failed') { st('announce tx REVERTED onchain · ' + j.hash + ' · hit ANNOUNCE IT to retry.'); return; }
        } catch { /* keep polling */ }
      }
      st('still pending after 10 minutes · ' + j.hash + ' · it is in the private mempool, it usually lands within a few more minutes.');
    })();
    return { hash: j.hash, via: 'relayer' };
  } catch (e) {
    st('relayer unreachable (' + e.message + ') · falling back to announcing from your wallet…');
  }
  // fallback: wallet-self-announce (same contract call pattern as pay-a-ghost mode).
  try {
    const eip1193 = (W && W.eip1193) || window.ethereum;
    if (!eip1193) throw new Error('no injected wallet available for the fallback');
    const signer = await new ethers.BrowserProvider(eip1193).getSigner();
    const ann = new ethers.Contract(ANNOUNCER, ['function announce(uint256,address,bytes,bytes)'], signer);
    const tx = await ann.announce(1, stealth, ephPub, Uint8Array.from([viewTag]));
    st('announced from your wallet: ' + tx.hash + ' · your scanner will now find payments to this address.');
    dropRecvRecord(stealth);
    return { hash: tx.hash, via: 'wallet' };
  } catch (e) {
    st('announce failed: ' + (e.shortMessage || e.message) + ' · retry. without an announcement your scanner cannot find payments to this address.');
    return null;
  }
}
$('b-annrecv').onclick = () => announceRecv();

// invoices: the quick-link form is gone with the old step 3. The full invoice suite
// (tracked invoices, clients, memos) is its own page now: invoices.html + gp-invoices.mjs.

// ── 3 · scan + sweep ──
const RPCS = [...(window.GHOSTPAY_RPC ? [window.GHOSTPAY_RPC] : []), 'https://rpc.flashbots.net', 'https://eth.drpc.org', 'https://eth.merkle.io'];
async function jrpc(method, params) {
  let lastErr;
  for (const url of RPCS) {
    try {
      const ac = new AbortController(); const to = setTimeout(() => ac.abort(), 15000);
      const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }), signal: ac.signal });
      clearTimeout(to);
      const j = await r.json();
      if (j.error) throw new Error(j.error.message || 'rpc error');
      return j.result;
    } catch (e) { lastErr = e; }
  }
  throw lastErr;
}
let scanSeq = 0;
let scanBusy = false;
const payments = [];      // GP.state.payments: one record per rendered payment card
const seenPays = new Set(); // dedupe tx:addr across incremental scans; cleared on full scans
// per-card lifecycle state, best-effort and async: balance → swept → PP deposit →
// ASP → withdrawn. Any RPC/ASP failure leaves the balance-only state; the mySeq
// guard stops a superseded scan from writing into freshly rendered cards.
async function cardState(div, btn, addr, payBlock, mySeq, getAsp) {
  const state = document.createElement('div');
  state.className = 'meta';
  const setState = t => { if (mySeq === scanSeq) state.textContent = t; };
  try {
    const bal = BigInt(await jrpc('eth_getBalance', [addr, 'latest']));
    const nonce = BigInt(await jrpc('eth_getTransactionCount', [addr, 'latest']));
    if (mySeq !== scanSeq) return;
    div.insertBefore(state, btn);
    if (bal > 0n) {
      setState('LIVE · ' + ethers.formatEther(bal) + ' ETH · sweepable');
      return;
    }
    // swept: dim, kill the button, then trace the deposit lifecycle
    div.classList.add('swept');
    div.classList.remove('armed');
    btn.disabled = true;
    btn.textContent = 'ALREADY SWEPT';
    let txt = 'SWEPT · 0 balance' + (nonce > 0n ? ' · nonce ' + nonce : '');
    setState(txt);
    // PP deposit from this stealth address. The deposit always lands AFTER the payment
    // block (usually within minutes); the search is capped at payment block + 100k to
    // bound RPC time, newest first, <=5k-block chunks.
    let dep = null;
    try {
      const topic = PP_IFACE.getEvent('Deposited').topicHash;
      const depTopic = ethers.zeroPadValue(addr, 32);
      const end = Math.min(payBlock + 100000, parseInt(await jrpc('eth_blockNumber', []), 16));
      for (let e2 = end; e2 >= payBlock && !dep; e2 -= PP_LOG_CHUNK) {
        const s2 = Math.max(e2 - PP_LOG_CHUNK + 1, payBlock);
        const logs = await jrpc('eth_getLogs', [{ address: PP_POOL, topics: [topic, depTopic], fromBlock: '0x' + s2.toString(16), toBlock: '0x' + e2.toString(16) }]);
        if (logs.length) {
          const p = PP_IFACE.parseLog(logs[logs.length - 1]);
          dep = { label: BigInt(p.args._label), value: BigInt(p.args._value), block: parseInt(logs[logs.length - 1].blockNumber, 16) };
        }
      }
    } catch { /* deposit search failed: keep the balance-only state */ }
    if (mySeq !== scanSeq) return;
    if (dep) {
      txt += ' → PP deposit ' + ethers.formatEther(dep.value) + ' ETH @ block ' + dep.block.toLocaleString();
      setState(txt);
      try {
        const asp = await getAsp();
        txt += asp.has(dep.label) ? ' · ASP approved' : ' · ASP screening';
        setState(txt);
      } catch { /* ASP unreachable: leave the state without ASP status */ }
    }
    // withdrawal state from the local tracking record (nullifier only, written at sweep time)
    try {
      const rec = JSON.parse(localStorage.getItem('ghostpay:ppnote:' + addr.toLowerCase()) || 'null');
      if (rec && rec.nullifier) {
        const spent = BigInt(await ppCall(PP_IFACE.encodeFunctionData('nullifierHashes', [spentNullifierHash(BigInt(rec.nullifier))])));
        txt += spent !== 0n ? ' · WITHDRAWN' : ' · in pool (withdrawable)';
        setState(txt);
      }
    } catch { /* no tracking record or RPC failed: skip */ }
  } catch { /* balance check failed: leave the card enabled, no state line */ }
}
// scan(opts): full rescan by default (wipes + re-renders #payments). {append:true} keeps the
// existing cards and only appends newly discovered payments (the 60s background poll uses
// this, resuming from the stored cursor). {quiet:true} leaves the status line alone unless
// something new was found or the scan failed. {from:N} overrides the from-block.
async function scan(opts = {}) {
  const append = !!opts.append, quiet = !!opts.quiet;
  if (scanBusy && append) return payments; // a scan is in flight: skip this background tick
  scanBusy = true;
  const mySeq = ++scanSeq;
  if (!append) { $('payments').innerHTML = ''; seenPays.clear(); payments.length = 0; }
  if (!quiet) $('st-scan').textContent = 'scanning announcements…';
  try {
    const topic0 = ethers.id('Announcement(uint256,address,address,bytes,bytes)');
    const t1 = ethers.zeroPadValue('0x01', 32);
    const latest = parseInt(await jrpc('eth_blockNumber', []), 16);
    const ov = Number.isFinite(opts.from) ? opts.from : parseInt($('i-fromblock').value, 10);
    // scan cursor: after a clean scan we remember `latest` per wallet and resume from there.
    // an explicit from-block in the input always wins; clearing localStorage forces a full rescan.
    const cursorKey = 'ghostpay:lastScanned:' + (W.viewPub || W.account || '');
    const stored = parseInt(localStorage.getItem(cursorKey) || '', 10);
    const fromBlock = Number.isFinite(ov) && ov >= 0 ? ov
      : (Number.isFinite(stored) && stored >= 0 ? Math.min(stored, latest) : Math.max(0, latest - 50000));
    const ranges = [];
    for (let f = fromBlock; f <= latest; f += 100000) ranges.push([f, Math.min(f + 99999, latest), 0]);
    const logs = []; let done = 0, failed = 0;
    async function worker() {
      while (ranges.length) {
        if (mySeq !== scanSeq) return;
        const r = ranges.shift(); const [f, t] = [r[0], r[1]];
        try {
          const res = await jrpc('eth_getLogs', [{ address: ANNOUNCER, topics: [topic0, t1], fromBlock: '0x' + f.toString(16), toBlock: '0x' + t.toString(16) }]);
          logs.push(...res); done++;
          if (!quiet) $('st-scan').textContent = 'scanning blocks ' + fromBlock.toLocaleString() + ' → ' + latest.toLocaleString() + ' · ' + logs.length + ' announcements found so far…';
        } catch (e) {
          if (t - f + 1 > 10000) { for (let g = f; g <= t; g += 10000) ranges.push([g, Math.min(g + 9999, t), 0]); }
          else if (r[2] < 3) { r[2]++; ranges.push(r); await new Promise(x => setTimeout(x, 600)); }
          else { failed++; }
        }
      }
    }
    await Promise.all(Array.from({ length: 6 }, worker));
    if (mySeq !== scanSeq) return payments;
    if (!quiet) $('st-scan').textContent = logs.length + ' announcements. filtering…';
    // ASP snapshot: fetched at most once per scan (live SCOPE() call + mt-leaves),
    // shared by every card that finds a PP deposit.
    let aspPromise = null;
    const getAsp = () => aspPromise ??= (async () => {
      const scope = BigInt(await ppCall(PP_IFACE.encodeFunctionData('SCOPE', [])));
      const res = await fetch(PP_ASP + '/mt-leaves', { headers: { 'X-Pool-Scope': scope.toString() } });
      if (!res.ok) throw new Error('ASP leaves fetch failed (' + res.status + ')');
      const { aspLeaves } = await res.json();
      return new Set(aspLeaves.map(x => BigInt(x)));
    })();
    let found = 0;
    for (const l of logs) {
      const [ephPub, metadata] = ethers.AbiCoder.defaultAbiCoder().decode(['bytes','bytes'], l.data);
      const addr = '0x' + l.topics[2].slice(-40);
      const r = check(W.viewPriv, W.spendPub, ephPub, addr);
      if (metadata.length >= 3 && parseInt(metadata.slice(2,4),16) !== r.viewTag) continue;
      if (!r.match) continue;
      const dedupeKey = l.transactionHash + ':' + addr.toLowerCase();
      if (seenPays.has(dedupeKey)) continue;
      seenPays.add(dedupeKey);
      found++;
      const div = document.createElement('div');
      div.className = 'pay';
      div.innerHTML = '<div class="addr">' + addr + '</div><div class="meta">block ' + parseInt(l.blockNumber,16) + ' · tx ' + l.transactionHash.slice(0,16) + '…</div>';
      const b = document.createElement('button');
      b.textContent = 'SWEEP THIS';
      b.onclick = () => sweepUI(addr, ephPub, div);
      div.appendChild(b);
      $('payments').appendChild(div);
      const rec = { address: addr, ephPub, block: parseInt(l.blockNumber, 16), tx: l.transactionHash, swept: false, fresh: append };
      payments.push(rec);
      gpEmit('payment', rec);
      queueArm(rec); // silent auto-arm: intent signed + secret downloaded the moment a payment is found
      // lifecycle state line: LIVE / SWEPT / PP deposit / ASP / WITHDRAWN (async, best-effort)
      cardState(div, b, addr, parseInt(l.blockNumber, 16), mySeq, getAsp);
    }
    // advance the cursor only on a fully clean scan, so unreachable ranges are never skipped for good
    if (!failed) localStorage.setItem(cursorKey, String(latest));
    if (!quiet || found) {
      $('st-scan').textContent = (found ? found + (append ? ' new ' : ' ') + 'payment(s) found. sweep when ready.' : 'nothing yet. share your address, get paid, come back.')
        + ' (blocks ' + fromBlock.toLocaleString() + ' → ' + latest.toLocaleString() + ')'
        + (failed ? ' (' + failed + ' block range(s) unreachable · rescan to retry)' : '')
        + (failed ? '' : ' · cursor saved · next scan resumes from block ' + latest.toLocaleString() + '. type a from-block above to rescan earlier.');
    }
    return payments;
  } catch (e) { $('st-scan').textContent = 'scan failed: ' + e.message; return payments; }
  finally { scanBusy = false; }
}

// sweep controls exist on app.html only (invoices.html imports this core for connect/generate/scan)
if ($('b-rescan')) $('b-rescan').onclick = () => { if (W && W.viewPriv) scan(); };
if ($('i-legacy')) $('i-legacy').onchange = e => { LEGACY = e.target.checked; if (W && W.viewPriv) scan(); };

// broadcast a signed artifact via the local relayer (serve.mjs POST /sweep). The runner wallet
// pays gas; the stealth EOA stays unfunded. MetaMask strips authorizationList from type-4 txs,
// so in-page wallet broadcast is dead · the relayer is the only broadcast path.
async function relaySweep(artifact) {
  const st = m => $('st-broadcast').textContent = m;
  // hash-bearing lines get a clickable etherscan link; the regex guard keeps innerHTML safe
  const txLink = h => /^0x[0-9a-fA-F]{64}$/.test(h) ? ' · <a href="https://etherscan.io/tx/' + h + '" target="_blank" rel="noopener">etherscan</a>' : '';
  const stHtml = m => $('st-broadcast').innerHTML = m;
  try {
    st('sending to relayer… (deliberate 5–45s privacy delay before broadcast · hold on)');
    const r = await fetch('/sweep', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(artifact) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok || j.error) throw new Error(j.error || ('http ' + r.status));
    stHtml('pending: ' + j.hash + txLink(j.hash) + ' · waiting for confirmation…');
    for (let i = 0; i < 120; i++) {
      await new Promise(x => setTimeout(x, 5000));
      const rcpt = await jrpc('eth_getTransactionReceipt', [j.hash]);
      if (rcpt) {
        if (rcpt.status === '0x1') {
          stHtml('CONFIRMED in block ' + parseInt(rcpt.blockNumber, 16) + ' · ' + j.hash + txLink(j.hash)
            + (artifact.precommitment ? ' · PP deposit sent · withdrawal after ASP review, using your downloaded secret file.' : ''));
          const rec = payments.find(p => p.address.toLowerCase() === String(artifact.stealthAddress || '').toLowerCase());
          if (rec) rec.swept = true;
          gpEmit('swept', { hash: j.hash, block: parseInt(rcpt.blockNumber, 16), artifact, payment: rec || null });
        } else {
          stHtml('tx REVERTED onchain · ' + j.hash + txLink(j.hash) + ' · copy the artifact and retry via relay.mjs if the failure was transient.');
        }
        return;
      }
    }
    stHtml('still pending after 10 minutes · ' + j.hash + txLink(j.hash) + ' · check a block explorer.');
  } catch (e) {
    st('relayer broadcast failed: ' + e.message + ' · artifact is still valid, COPY ARTIFACT and use relay.mjs.');
  }
}

// ── SweeperV2 signed intents + auto-arm ──
// When the relayer advertises sweeperV2 (GET ./health), every detected payment with a
// pool-sized balance is armed the moment it is found: PP secret + precommitment generated
// (and downloaded, same as the legacy arm did at click time), the EIP-712 SweepIntent
// signed by the stealth key, and the 7702 authorization delegating the stealth EOA to
// SweeperV2. SIGN SWEEP then only re-validates and broadcasts the pre-armed artifact.
// Relayers with sweeperV2 null keep the legacy eip7702-sweep flow below, untouched.

// relayer capabilities: fetched once per session, then cached.
let capsPromise = null;
function relayerCaps() {
  capsPromise ??= (async () => {
    let health = null, minFeeBps = 30;
    try { const r = await fetch('./health'); if (r.ok) health = await r.json(); } catch { /* relayer offline: legacy flow */ }
    try { const r = await fetch('./fee'); if (r.ok) { const j = await r.json(); if (Number.isFinite(j.minFeeBps)) minFeeBps = j.minFeeBps; } } catch { /* keep the 30 bps default */ }
    return { sweeperV2: !!(health && health.sweeperV2), sweeperV2Addr: (health && health.sweeperV2) || null, minFeeBps };
  })();
  return capsPromise;
}

// armed intent artifacts by lowercase stealth address: { artifact, nonce, deadline }
const armedIntents = new Map();

async function armIntent(rec) {
  if (!W || !W.spendPriv || !W.viewPriv || !rec || !rec.ephPub) return null;
  const key = rec.address.toLowerCase();
  const prev = armedIntents.get(key);
  if (prev && prev.deadline > Math.floor(Date.now() / 1000) + 300) return prev; // still valid: arm once per payment
  const caps = await relayerCaps();
  if (!caps.sweeperV2) return null; // old relayer: the legacy arm flow runs at SIGN SWEEP time
  const addr = rec.address;
  const bal = BigInt(await jrpc('eth_getBalance', [addr, 'latest']));
  if (bal < PP_MIN_SWEEP) return null; // below the pool minimum: the inbox dust path handles those
  const { sh } = check(W.viewPriv, W.spendPub, rec.ephPub, addr);
  const sPriv = stealthKey(W.spendPriv, sh);
  const wallet = new ethers.Wallet(sPriv);
  if (wallet.address.toLowerCase() !== addr.toLowerCase()) return null;
  // same secret construction as the legacy arm (poseidon2 precommitment, 31-byte values);
  // the downloaded file works in the standard withdrawal flow (v2.privacypools.com).
  const nullifier = crypto.getRandomValues(new Uint8Array(31));
  const ppsecret = crypto.getRandomValues(new Uint8Array(31));
  const pre = poseidon2([BigInt(hex(nullifier)), BigInt(hex(ppsecret))]);
  const preHex = '0x' + pre.toString(16).padStart(64, '0');
  const secretFile = {
    note: 'GHOSTPAY Privacy Pools withdrawal secret. KEEP SAFE. Anyone with this file can withdraw the deposit.',
    nullifier: hex(nullifier),
    secret: hex(ppsecret),
    precommitment: preHex,
    amount: bal.toString(),
    chainId: CHAIN_ID,
    sweeper: SWEEPER_V2,
    stealthAddress: addr,
    timestamp: new Date().toISOString(),
    pool: 'ETH mainnet Privacy Pools (0xbow entrypoint 0x6818809EefCe719E480a7526D76bD3e561526b46)'
  };
  // non-secret tracking record so the scanner can show this deposit's lifecycle
  // (PP deposit / ASP / WITHDRAWN) on the payment card. The secret itself is NEVER
  // stored anywhere: the downloaded file remains the only place it exists.
  try {
    localStorage.setItem('ghostpay:ppnote:' + key, JSON.stringify({
      nullifier: hex(nullifier), precommitment: preHex, amount: bal.toString(), ts: Date.now()
    }));
  } catch { /* storage blocked/full: tracking is best-effort, the sweep is unaffected */ }
  showSecret(
    'PRIVACY POOLS WITHDRAWAL SECRET · KEEP this file: it is your withdrawal secret. lose it and the deposit is gone forever.'
      + ' the app keeps a local tracking key (nullifier only · it cannot withdraw) so the scanner can show this deposit\'s state.',
    JSON.stringify(secretFile, null, 2),
    'pp-secret-' + addr.slice(2, 10) + '.json',
    JSON.stringify(secretFile, null, 2)
  );
  const deadline = Math.floor(Date.now() / 1000) + 86400;
  const intent = { action: 1, token: ZERO_ADDR, destination: ZERO_ADDR, precommitment: preHex, feeBps: caps.minFeeBps, deadline };
  const signature = await wallet.signTypedData(intentDomain(addr), INTENT_TYPES, intent);
  const nonce = parseInt(await jrpc('eth_getTransactionCount', [addr, 'latest']), 16);
  const artifact = {
    kind: 'eip7702-intent', chainId: CHAIN_ID, stealthAddress: addr, sweeper: SWEEPER_V2,
    authorization: sign7702(sPriv, CHAIN_ID, SWEEPER_V2, nonce),
    intent, signature,
    precommitment: preHex,
    warning: 'KEEP the downloaded secret file: it is your withdrawal secret',
  };
  const armed = { artifact, nonce, deadline };
  armedIntents.set(key, armed);
  return armed;
}

// arms are serialized: several payments found in one scan must not race downloads or RPC.
let armChain = Promise.resolve();
function queueArm(rec) {
  armChain = armChain.then(() => armIntent(rec)).catch(e => console.warn('auto-arm failed for ' + (rec && rec.address) + ': ' + e.message));
  return armChain;
}

function sweepUI(addr, ephPub, card) {
  // (re)arm: clicking SWEEP THIS on another card moves the arming to that address.
  document.querySelectorAll('.pay.armed').forEach(d => d.classList.remove('armed'));
  if (card) card.classList.add('armed');
  $('st-armed').textContent = 'sweeping ' + addr + ' into Privacy Pools';
  $('sweeper-ui').style.display = 'block';
  $('sweeper-ui').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  $('b-sweep').textContent = 'SIGN SWEEP';
  $('b-sweep').onclick = async () => {
    try {
      $('c-secret').style.display = 'none';
      if (!W.spendPriv) throw new Error('watch-only session: your spend key is never stored on this device, so sweeping needs a fresh wallet signature. hit RE-CONNECT above, connect, GENERATE MY STEALTH KEYS (same wallet, same keys), then retry.');
      // intent path: use the artifact auto-armed at detection time, re-arming silently if
      // the deadline passed or the stealth nonce moved. Falls through to the legacy arm
      // below when nothing is armed (old relayer, or a below-minimum balance).
      let armed = armedIntents.get(addr.toLowerCase()) || null;
      if (armed) {
        let stale = armed.deadline <= Math.floor(Date.now() / 1000) + 60;
        if (!stale) {
          const nonceNow = parseInt(await jrpc('eth_getTransactionCount', [addr, 'latest']), 16);
          stale = nonceNow !== armed.nonce;
        }
        if (stale) {
          armedIntents.delete(addr.toLowerCase());
          armed = await armIntent({ address: addr, ephPub });
          if (!armed) throw new Error('the pre-signed intent expired and re-arming failed (relayer unreachable, or the balance dropped below the 0.01 ETH pool minimum). rescan and retry.');
        }
        const artifact = armed.artifact;
        $('c-artifact').style.display = 'block';
        $('v-artifact').textContent = JSON.stringify(artifact);
        $('st-broadcast').textContent = '';
        $('b-copyart').onclick = e => copy(JSON.stringify(artifact, null, 2), e.target);
        // the sign button becomes the broadcast button: one primary action per stage
        $('b-sweep').textContent = 'BROADCAST VIA RELAYER';
        $('b-sweep').onclick = () => relaySweep(artifact);
        $('b-sweep').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        return;
      }
      const { sh } = check(W.viewPriv, W.spendPub, ephPub, addr);
      const sPriv = stealthKey(W.spendPriv, sh);
      const wallet = new ethers.Wallet(sPriv);
      if (wallet.address.toLowerCase() !== addr.toLowerCase()) throw new Error('derived key mismatch');
      // Privacy Pools (0xbow), the only door: the whole balance goes into the pool, no destination
      // needed. precommitment = poseidon2(nullifier, secret), 31-byte values, identical to
      // ept-privacy-pools / the zFi client, so the downloaded file works in the real withdrawal
      // flow (v2.privacypools.com).
      const nullifier = crypto.getRandomValues(new Uint8Array(31));
      const ppsecret = crypto.getRandomValues(new Uint8Array(31));
      const pre = poseidon2([BigInt(hex(nullifier)), BigInt(hex(ppsecret))]);
      const preHex = '0x' + pre.toString(16).padStart(64, '0');
      const bal = await jrpc('eth_getBalance', [addr, 'latest']);
      const secretFile = {
        note: 'GHOSTPAY Privacy Pools withdrawal secret. KEEP SAFE. Anyone with this file can withdraw the deposit.',
        nullifier: hex(nullifier),
        secret: hex(ppsecret),
        precommitment: preHex,
        amount: BigInt(bal).toString(),
        chainId: CHAIN_ID,
        sweeper: SWEEPER,
        stealthAddress: addr,
        timestamp: new Date().toISOString(),
        pool: 'ETH mainnet Privacy Pools (0xbow entrypoint 0x6818809EefCe719E480a7526D76bD3e561526b46)'
      };
      const data = SWEEPER_IFACE.encodeFunctionData('sweepToPrivacyPoolsETH', [pre]);
      // non-secret tracking record so the scanner can show this deposit's lifecycle
      // (PP deposit / ASP / WITHDRAWN) on the payment card. The secret itself is NEVER
      // stored anywhere: the downloaded file remains the only place it exists.
      try {
        localStorage.setItem('ghostpay:ppnote:' + addr.toLowerCase(), JSON.stringify({
          nullifier: hex(nullifier), precommitment: preHex, amount: BigInt(bal).toString(), ts: Date.now()
        }));
      } catch { /* storage blocked/full: tracking is best-effort, the sweep is unaffected */ }
      showSecret(
        'PRIVACY POOLS WITHDRAWAL SECRET · KEEP this file: it is your withdrawal secret. lose it and the deposit is gone forever.'
          + ' the app keeps a local tracking key (nullifier only · it cannot withdraw) so the scanner can show this deposit\'s state.',
        JSON.stringify(secretFile, null, 2),
        'pp-secret-' + addr.slice(2, 10) + '.json',
        JSON.stringify(secretFile, null, 2)
      );
      const nonce = await new ethers.JsonRpcProvider(RPC).getTransactionCount(addr);
      const artifact = { precommitment: preHex, warning: 'KEEP the downloaded secret file: it is your withdrawal secret', kind: 'eip7702-sweep', chainId: CHAIN_ID, stealthAddress: addr, sweeper: SWEEPER, data, authorization: sign7702(sPriv, CHAIN_ID, SWEEPER, nonce) };
      $('c-artifact').style.display = 'block';
      $('v-artifact').textContent = JSON.stringify(artifact);
      $('st-broadcast').textContent = '';
      $('b-copyart').onclick = e => copy(JSON.stringify(artifact, null, 2), e.target);
      // the sign button becomes the broadcast button: one primary action per stage
      $('b-sweep').textContent = 'BROADCAST VIA RELAYER';
      $('b-sweep').onclick = () => relaySweep(artifact);
      $('b-sweep').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    } catch (e) {
      $('c-artifact').style.display = 'block';
      $('v-artifact').textContent = 'error: ' + e.message;
    }
  };
}

// ── 4 · withdraw from Privacy Pools (in-browser port of pp-withdraw.mjs · same flow,
// same constructions, no wallet needed: the relayer pays gas) ──
const PP_POOL = '0xf241d57c6debae225c0f2e6ea1529373c9a9c9fb'; // ETH mainnet Privacy Pools pool
const PP_ENTRYPOINT = '0x6818809EefCe719E480a7526D76bD3e561526b46';
const PP_ETH_ASSET = '0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE';
const PP_ASP = 'https://api.0xbow.io/1/public';
const PP_RELAYER = 'https://fastrelay.xyz/relayer';
const PP_DEPOSIT_BLOCK = 25931460; // known deposit block; seeds the event search window
const PP_LOG_CHUNK = 5000; // drpc eth_getLogs fails over ~10k ranges
const SNARK_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const PP_IFACE = new ethers.Interface([
  'event Deposited(address indexed _depositor, uint256 _commitment, uint256 _label, uint256 _value, uint256 _precommitmentHash)',
  'function nullifierHashes(uint256) view returns (bool)',
  'function SCOPE() view returns (uint256)'
]);
const ppCall = data => jrpc('eth_call', [{ to: PP_POOL, data }, 'latest']);
// pp-crypto.mjs primitives, browser edition (same constructions, vendored poseidon 1/2/3)
const ppCommitment = (value, label, precom) => poseidon3([value, label, precom]);
const spentNullifierHash = nullifier => poseidon1([nullifier]);
const deriveChangeKeys = (nullifier, secret) => ({ newNullifier: poseidon2([nullifier, 1n]), newSecret: poseidon2([secret, 1n]) });
function computeContext(processooor, data, scope) {
  const encoded = ethers.AbiCoder.defaultAbiCoder().encode(['tuple(address,bytes)', 'uint256'], [[processooor, data], scope]);
  return BigInt(ethers.keccak256(encoded)) % SNARK_FIELD;
}
// LeanIMT: poseidon2 hash, odd node promoted (carried up), empty root 0n, siblings padded to 32.
function leanIMTBuild(leaves) {
  if (leaves.length === 0) return { levels: [[]], root: 0n };
  const levels = [leaves.slice()];
  while (levels[levels.length - 1].length > 1) {
    const cur = levels[levels.length - 1]; const next = [];
    for (let i = 0; i < cur.length; i += 2) next.push(i + 1 < cur.length ? poseidon2([cur[i], cur[i + 1]]) : cur[i]);
    levels.push(next);
  }
  return { levels, root: levels[levels.length - 1][0] };
}
function leanIMTProof(levels, leafIndex) {
  const siblings = []; let idx = leafIndex;
  for (let d = 0; d < levels.length - 1; d++) {
    const sib = idx ^ 1;
    siblings.push(sib < levels[d].length ? levels[d][sib] : 0n);
    idx = idx >> 1;
  }
  while (siblings.length < 32) siblings.push(0n);
  return siblings;
}
// Deposited-event search: newest first, chunks of <=5k blocks. The window seeds near the
// secret file's timestamp (estimated off the known deposit block's timestamp) when the
// file carries one, else scans back up to ~200k blocks.
async function ppFindDeposit(precommitmentHash, timestamp, say) {
  const topic = PP_IFACE.getEvent('Deposited').topicHash;
  const latest = parseInt(await jrpc('eth_blockNumber', []), 16);
  let windowStart, windowEnd;
  if (timestamp && Number.isFinite(Date.parse(timestamp))) {
    const refBlock = await jrpc('eth_getBlockByNumber', ['0x' + PP_DEPOSIT_BLOCK.toString(16), false]);
    const refTime = parseInt(refBlock.timestamp, 16);
    const seed = PP_DEPOSIT_BLOCK + Math.round((Date.parse(timestamp) / 1000 - refTime) / 12);
    windowStart = Math.max(0, seed - 50000);
    windowEnd = Math.min(latest, seed + 50000);
  } else {
    windowStart = Math.max(0, latest - 200000);
    windowEnd = latest;
  }
  for (let end = windowEnd; end >= windowStart; end -= PP_LOG_CHUNK) {
    const start = Math.max(end - PP_LOG_CHUNK + 1, windowStart);
    const logs = await jrpc('eth_getLogs', [{ address: PP_POOL, topics: [topic], fromBlock: '0x' + start.toString(16), toBlock: '0x' + end.toString(16) }]);
    for (const log of logs) {
      const p = PP_IFACE.parseLog(log);
      if (BigInt(p.args._precommitmentHash) === precommitmentHash)
        return { label: BigInt(p.args._label), commitment: BigInt(p.args._commitment), value: BigInt(p.args._value), blockNumber: parseInt(log.blockNumber, 16) };
    }
    say('locating deposit… scanned blocks ' + start.toLocaleString() + '–' + end.toLocaleString() + ' (' + logs.length + ' Deposited events), no match yet');
  }
  throw new Error('no matching deposit found in blocks ' + windowStart.toLocaleString() + '–' + windowEnd.toLocaleString() + ' · the sweep may not have confirmed yet, or the secret file is for a different deposit.');
}

// withdraw controls exist on app.html only
if ($('i-secretfile')) $('i-secretfile').onchange = async e => {
  const f = e.target.files && e.target.files[0];
  if (!f) return;
  $('i-secretjson').value = await f.text();
};

if ($('b-withdraw')) $('b-withdraw').onclick = async () => {
  const btn = $('b-withdraw');
  const lines = [];
  const el = $('st-withdraw');
  el.style.whiteSpace = 'pre-line';
  const say = m => { lines.push(m); el.textContent = lines.join('\n'); };
  btn.disabled = true;
  lines.length = 0; el.textContent = '';
  try {
    let note;
    try { note = JSON.parse($('i-secretjson').value); }
    catch { throw new Error('no valid secret JSON · pick the pp-secret file or paste its contents above'); }
    if (!note.nullifier || !note.secret || !note.precommitment)
      throw new Error('secret file must contain nullifier, secret and precommitment.');
    const recipient = $('i-recipient').value.trim();
    if (!ethers.isAddress(recipient)) throw new Error('recipient is not a valid address: ' + (recipient || '(empty)'));
    const recipientCk = ethers.getAddress(recipient);
    const nullifier = BigInt(note.nullifier);
    const secret = BigInt(note.secret);
    const precomFile = BigInt(note.precommitment);
    if (poseidon2([nullifier, secret]) !== precomFile)
      throw new Error("precommitment mismatch: poseidon2(nullifier, secret) does not equal the file's precommitment. the secret file is corrupt or mistyped · refusing to continue.");
    say('secret file OK: precommitment matches poseidon2(nullifier, secret).');

    // 1. locate the deposit onchain
    say('locating deposit onchain…');
    const dep = await ppFindDeposit(precomFile, note.timestamp, say);
    say('deposit found in block ' + dep.blockNumber.toLocaleString() + ': label=' + dep.label + ' value=' + ethers.formatEther(dep.value) + ' ETH');
    if (ppCommitment(dep.value, dep.label, precomFile) !== dep.commitment)
      say('WARN: commitment mismatch (non-fatal)');
    const spent = await ppCall(PP_IFACE.encodeFunctionData('nullifierHashes', [spentNullifierHash(nullifier)]));
    if (BigInt(spent) !== 0n) throw new Error('this note has already been withdrawn.');
    say('spent-nullifier check: not withdrawn.');

    // 2. ASP approved set + state leaves; confirm membership
    say('fetching pool scope (live SCOPE() call) + approved set from ASP…');
    const scope = BigInt(await ppCall(PP_IFACE.encodeFunctionData('SCOPE', [])));
    const res = await fetch(PP_ASP + '/mt-leaves', { headers: { 'X-Pool-Scope': scope.toString() } });
    if (!res.ok) throw new Error('ASP leaves fetch failed (' + res.status + '): ' + (await res.text().catch(() => '')).slice(0, 300));
    const { aspLeaves: aspRaw, stateTreeLeaves: stateRaw } = await res.json();
    const aspLeaves = aspRaw.map(BigInt), stateLeaves = stateRaw.map(BigInt);
    say('ASP snapshot: ' + aspLeaves.length + ' asp leaves, ' + stateLeaves.length + ' state leaves.');
    const aspIndex = aspLeaves.indexOf(dep.label);
    if (aspIndex < 0) throw new Error('deposit label is not in the approved ASP set yet (still screening, or rejected). cannot withdraw via ASP · retry later.');
    const stateIndex = stateLeaves.indexOf(dep.commitment);
    if (stateIndex < 0) throw new Error('deposit commitment not in the state-tree snapshot yet. retry shortly.');
    say('membership confirmed: ASP index ' + aspIndex + ', state index ' + stateIndex + '.');
    say('building LeanIMT inclusion proofs…');
    const stateTree = leanIMTBuild(stateLeaves);
    const aspTree = leanIMTBuild(aspLeaves);
    const stateSiblings = leanIMTProof(stateTree.levels, stateIndex);
    const aspSiblings = leanIMTProof(aspTree.levels, aspIndex);

    // withdraw amount: default = full escrowed (net) value, change = 0
    const amtStr = $('i-wamount').value.trim();
    const amountWei = amtStr ? ethers.parseEther(amtStr) : dep.value;
    if (amountWei <= 0n) throw new Error('withdrawal amount must be positive.');
    const withdrawnValue = amountWei >= dep.value ? dep.value : amountWei;
    const changeValue = dep.value - withdrawnValue;
    say('amount: withdrawing ' + ethers.formatEther(withdrawnValue) + ' ETH' + (changeValue > 0n ? ' (change ' + ethers.formatEther(changeValue) + ' ETH stays in the pool).' : ' (full balance, no change).'));

    // 3. relayer fee terms: prefer the local self-hosted relay (serve.mjs with PP_RELAY=1,
    // advertised via GET ./health). Otherwise the fastrelay.xyz path is exactly as before.
    let withdrawalData, feeCommitment = null, localRelay = false;
    let health = null;
    try {
      const hr = await fetch('./health');
      if (hr.ok) health = await hr.json();
    } catch { /* no same-origin relayer reachable: fall back to the public relayer below */ }
    if (health && health.ppRelay === true && Array.isArray(health.runners) && health.runners.length && Number.isFinite(health.ppFeeBps)) {
      localRelay = true;
      withdrawalData = ethers.AbiCoder.defaultAbiCoder().encode(['address', 'address', 'uint256'], [recipientCk, health.runners[0], health.ppFeeBps]);
      say('relay: local self-hosted relayer (./pp-withdraw), fee ' + health.ppFeeBps + ' bps.');
    } else {
      say('relay: fastrelay.xyz public relayer, fee per quote.');
      say('getting relayer quote…');
      const quoteRes = await fetch(PP_RELAYER + '/quote', {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ chainId: CHAIN_ID, amount: withdrawnValue.toString(), asset: PP_ETH_ASSET, recipient: recipientCk, extraGas: false })
      });
      if (!quoteRes.ok) throw new Error('relayer quote failed (' + quoteRes.status + '): ' + (await quoteRes.text().catch(() => '')).slice(0, 300));
      const quote = await quoteRes.json();
      feeCommitment = quote.feeCommitment ?? quote;
      withdrawalData = feeCommitment.withdrawalData;
      if (!withdrawalData) throw new Error('relayer did not return withdrawalData in the fee commitment.');
      say('relayer quote received.');
    }

    // 4. circuit inputs (existingValue = NET onchain value)
    const { newNullifier, newSecret } = deriveChangeKeys(nullifier, secret);
    const context = computeContext(PP_ENTRYPOINT, withdrawalData, scope);
    const input = {
      withdrawnValue: withdrawnValue.toString(),
      stateRoot: stateTree.root.toString(),
      stateTreeDepth: '32',
      ASPRoot: aspTree.root.toString(),
      ASPTreeDepth: '32',
      context: context.toString(),
      label: dep.label.toString(),
      existingValue: dep.value.toString(),
      existingNullifier: nullifier.toString(),
      existingSecret: secret.toString(),
      newNullifier: newNullifier.toString(),
      newSecret: newSecret.toString(),
      stateSiblings: stateSiblings.map(s => s.toString()),
      stateIndex: stateIndex.toString(),
      ASPSiblings: aspSiblings.map(s => s.toString()),
      ASPIndex: aspIndex.toString(),
    };

    // 5. groth16 proof with same-origin artifacts, snarkjs from esm.sh (as ept-privacy-pools does)
    say('loading snarkjs from esm.sh…');
    const ns = await import('https://esm.sh/snarkjs@0.7.5');
    const snarkjs = ns.groth16 ? ns : (ns.default || ns);
    say('proving (groth16, ~10-30s) with local artifacts ./artifacts/withdraw.wasm + withdraw.zkey…');
    const t0 = Date.now();
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, './artifacts/withdraw.wasm', './artifacts/withdraw.zkey');
    say('proof generated in ' + ((Date.now() - t0) / 1000).toFixed(1) + 's.');
    if (BigInt(publicSignals[7]) % SNARK_FIELD !== context % SNARK_FIELD)
      say('WARN: context public signal mismatch (non-fatal)');

    // 6. submit
    const payload = {
      chainId: CHAIN_ID,
      scope: scope.toString(),
      withdrawal: { processooor: PP_ENTRYPOINT, data: withdrawalData },
      proof: { pi_a: proof.pi_a, pi_b: proof.pi_b, pi_c: proof.pi_c, protocol: proof.protocol, curve: proof.curve },
      publicSignals,
      ...(localRelay ? {} : { feeCommitment }),
    };
    const relayUrl = localRelay ? './pp-withdraw' : PP_RELAYER + '/request';
    say('submitting to ' + (localRelay ? 'local relayer ./pp-withdraw…' : 'fastrelay.xyz…'));
    const relayRes = await fetch(relayUrl, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload) });
    if (!relayRes.ok) throw new Error('relayer rejected the withdrawal (' + relayRes.status + '): ' + (await relayRes.text().catch(() => '')).slice(0, 300));
    const out = await relayRes.json();
    const hash = out.txHash ?? out.hash ?? out.transactionHash ?? out.tx;
    if (!hash) throw new Error('relayer accepted the withdrawal but returned no tx hash: ' + JSON.stringify(out).slice(0, 300));
    say('SUBMITTED. tx hash: ' + hash + ' · the relayer broadcasts it; watch it land at the recipient.');
    if (/^0x[0-9a-fA-F]{64}$/.test(hash)) {
      const a = document.createElement('a');
      a.href = 'https://etherscan.io/tx/' + hash;
      a.textContent = 'view on etherscan: ' + hash;
      a.target = '_blank'; a.rel = 'noopener';
      a.style.display = 'block';
      el.appendChild(a);
    }
  } catch (e) {
    say('ERROR: ' + (e.message || e));
  } finally {
    btn.disabled = false;
  }
};

// ── ui-core: formatting helpers, status strip, dashboard, notifications, GP namespace ──
const formatEth = wei => { const s = ethers.formatEther(BigInt(wei)); return s.includes('.') ? s.replace(/0+$/, '').replace(/\.$/, '') : s; };
let ethPriceUsd = null;
const formatUsd = (eth, usd) => {
  const p = usd ?? ethPriceUsd;
  return p == null ? null : '$' + (Number(eth) * p).toLocaleString(undefined, { maximumFractionDigits: 2 });
};

// status strip (#gp-status): relayer health + min fee + ETH price, refreshed every 60s.
// every endpoint is optional: static-only serving shows "relayer: offline", a failed
// /price simply hides the price.
async function pollStatus() {
  const el = $('gp-status'); if (!el) return;
  const parts = [];
  try {
    const r = await fetch('./health');
    if (!r.ok) throw new Error('http ' + r.status);
    const h = await r.json();
    const runners = h.runnerCount ?? (Array.isArray(h.runners) ? h.runners.length
      : (typeof h.runners === 'number' ? h.runners : null));
    parts.push('relayer: online'
      + (runners != null ? ' · ' + runners + ' runner' + (runners === 1 ? '' : 's') : '')
      + ' · sweeperV2 ' + (h.sweeperV2 ? 'configured' : 'NOT configured')
      + ' · tor ' + (h.tor ? 'on' : 'off'));
  } catch { parts.push('relayer: offline (static serving only)'); }
  try {
    const r = await fetch('./fee');
    if (r.ok) {
      const f = await r.json();
      if (f.minFeeBps != null) parts.push('min fee ' + (f.minFeeBps / 100) + '%');
      else {
        const g = f.minFeeGwei ?? f.gwei ?? f.minFee;
        if (g != null) parts.push('min fee ' + g + ' gwei');
      }
    }
  } catch { /* fee endpoint optional */ }
  try {
    const r = await fetch('./price');
    if (r.ok) {
      const p = await r.json();
      const usd = p.usd ?? p.ethUsd ?? p.price ?? (p.ethereum && p.ethereum.usd);
      if (usd != null && isFinite(Number(usd))) { ethPriceUsd = Number(usd); parts.push('ETH $' + ethPriceUsd.toLocaleString()); }
    }
  } catch { /* price hidden on failure, by design */ }
  el.textContent = parts.join(' · ');
}
pollStatus();
setInterval(pollStatus, 60000);

// returning-user dashboard: restore a watch-only session from gp-session (viewing key +
// meta-address only). Steps 1-2 collapse into the #gp-dash header; scanning works
// immediately, sweeping waits for a fresh signature.
function enterDashboard(sess) {
  try {
    const m = buf(sess.meta.slice(7));
    W = {
      account: null, watchOnly: true,
      viewPriv: sess.viewPriv,
      viewPub: hex(secp256k1.getPublicKey(buf(sess.viewPriv), true)),
      spendPriv: null,
      spendPub: hex(m.slice(0, 33)),
      meta: sess.meta,
    };
    if (W.viewPub.toLowerCase() !== hex(m.slice(33, 66)).toLowerCase()) throw new Error('stored session is inconsistent');
  } catch (e) {
    localStorage.removeItem(SESSION_KEY);
    return;
  }
  // reuse the persisted un-announced record as the receive address: that is exactly the
  // address a previous session may have shared, so restoring keeps it alive (and visible).
  const pendingRecv = loadRecvRecords();
  W.recv = pendingRecv.length ? pendingRecv[pendingRecv.length - 1] : derive(W.meta.slice(7));
  if (!pendingRecv.length) recordRecv(W.recv);
  $('c-recv').style.display = 'block';
  $('v-recv').textContent = W.recv.stealth;
  $('st-announce').textContent = 'share this 0x address to get paid. payment links announce automatically when the payer pays; ANNOUNCE IT is only needed for raw-address payments.';
  $('d-meta').style.display = 'block';
  $('v-meta').textContent = W.meta;
  // s3/s4 exist on app.html (sweep/withdraw); invoices.html has neither
  ['s3', 's4'].forEach(id => { const el = $(id); if (el) el.classList.add('on'); });
  collapseWizard();
  $('i-remember').checked = true;
  refreshDash();
  gpEmit('session', { type: 'restored', watchOnly: true, address: null });
  scan();
}
$('b-reconnect').onclick = () => {
  expandWizard();
  $('s1').scrollIntoView({ behavior: 'smooth', block: 'start' });
};
$('b-forget').onclick = () => {
  localStorage.removeItem(SESSION_KEY);
  gpEmit('session', { type: 'forgotten' });
  toast('session wiped from this device');
  setTimeout(() => location.reload(), 600);
};
// browser notifications: opt-in only, from this button. denied/unsupported degrades silently.
$('b-notify').onclick = async () => {
  if (!('Notification' in window)) { toast('notifications are not supported in this browser'); return; }
  if (Notification.permission === 'granted') { toast('notifications already enabled'); return; }
  if (Notification.permission === 'denied') { toast('notifications are blocked in your browser settings'); return; }
  try { await Notification.requestPermission(); } catch { /* user dismissed or unsupported: stay silent */ }
};
// one Notification per newly detected payment (fresh = found by the background poll, so a
// full rescan of old history never spam-notifies).
// swept payments prune their ephemeral receive record (funds moved: nothing left to recover)
gpOn('swept', e => { const a = e && e.artifact && e.artifact.stealthAddress; if (a) dropRecvRecord(a); });
renderRecvRecovery();
gpOn('payment', async p => {
  if (p.fresh !== true) return;
  if (!('Notification' in window) || Notification.permission !== 'granted') return;
  let amt = '';
  try { amt = formatEth(await jrpc('eth_getBalance', [p.address, 'latest'])) + ' ETH · '; } catch { /* balance unknown: notify with the address only */ }
  try { new Notification('GHOSTPAY payment received', { body: amt + p.address.slice(0, 10) + '…' + p.address.slice(-6) }); } catch { /* some browsers require a service worker for notifications */ }
});

// background scanning: incremental poll every 60s while unlocked, resuming from the
// stored cursor and appending new payments (never a full rescan). RESCAN stays manual.
setInterval(() => {
  if (!W || !W.viewPriv) return;
  if (document.visibilityState === 'hidden') return;
  scan({ append: true, quiet: true });
}, 60000);

// ── window.GP: the module API. Everything a follow-up module needs, documented in
// docs/GP-API.md. Modules load as separate <script type="module"> files after this one. ──
window.GP = {
  version: '1.0-ui-core',
  state: {
    get connected() { return !!(W && (W.prov || W.session)); },
    get unlocked() { return !!(W && W.viewPriv); },
    get watchOnly() { return !!(W && W.viewPriv && !W.spendPriv); },
    get address() { return (W && W.account) || null; },
    get keys() {
      return W && W.viewPriv
        ? { viewPriv: W.viewPriv, viewPub: W.viewPub, spendPub: W.spendPub, spendPriv: W.spendPriv || null, meta: W.meta }
        : null;
    },
    get meta() { return (W && W.meta) || null; },
    get recv() { return (W && W.recv) || null; },
    get ethPriceUsd() { return ethPriceUsd; },
    armedIntent(addr) {
      const a = armedIntents.get(String(addr || '').toLowerCase());
      return a ? a.artifact : null;
    },
    payments,
    signer() {
      if (W && W.prov) return W.prov.getSigner();
      throw new Error('no injected-wallet signer (WalletConnect session or watch-only): use GP.state.walletRequest instead');
    },
    walletRequest(method, params) {
      if (W && W.session) return W.session.request({ chainId: 'eip155:1', request: { method, params } });
      if (W && W.eip1193) return W.eip1193.request({ method, params });
      if (window.ethereum) return window.ethereum.request({ method, params });
      throw new Error('no wallet connected');
    },
  },
  scan: fromBlock => scan(Number.isFinite(fromBlock) ? { from: fromBlock } : {}),
  scanIncremental: () => scan({ append: true, quiet: true }),
  announce: () => announceRecv(),
  relaySweep: artifact => relaySweep(artifact),
  relayerCaps,
  fmt: { formatEth, formatUsd },
  toast,
  on: gpOn,
  emit: gpEmit,
  jrpc,
  ethers,
  const: { ANNOUNCER, CHAIN_ID, SWEEPER, SWEEPER_V2, RPC },
  crypto: {
    secp256k1, keccak_256, sha256, hex, buf, mod, N,
    derive, check, stealthKey, sign7702,
    intentDomain, INTENT_TYPES,
    poseidon1, poseidon2, poseidon3,
    ppCommitment, spentNullifierHash, deriveChangeKeys, computeContext,
    leanIMTBuild, leanIMTProof,
    getLegacy: () => LEGACY,
    setLegacy: b => { LEGACY = !!b; },
  },
  pp: { PP_POOL, PP_ENTRYPOINT, PP_ETH_ASSET, PP_ASP, PP_RELAYER, SNARK_FIELD, PP_IFACE, SWEEPER_IFACE, ppCall, ppFindDeposit },
};

// PWA: cache-first offline shell. http(s) only: file:// and weird schemes skip registration.
if ('serviceWorker' in navigator && /^https?:$/.test(location.protocol)) {
  navigator.serviceWorker.register('./sw.js').catch(() => { /* offline shell unavailable: the app still works */ });
}

// pay-a-ghost mode lives on the homepage (index.html): a meta-address in the URL hash
// is the payer flow, not the app. app.html / invoices.html keep their own boot here.

if (location.search.includes('connect')) setTimeout(() => $('b-connect').click(), 300);
if (location.search.includes('gentest')) setTimeout(() => {
  // wallet-free test of the generate path: fake 65-byte sig in place of personal_sign output
  try {
    const sig = hex(keccak_256(new TextEncoder().encode('fake-signature-for-test'))) + 'ab'.repeat(32) + '1b';
    const spendPriv = '0x' + hex(keccak_256(cat(buf(sig), new TextEncoder().encode('|spend')))).slice(2);
    const viewPriv = '0x' + hex(keccak_256(cat(buf(sig), new TextEncoder().encode('|view')))).slice(2);
    const spendPub = hex(secp256k1.getPublicKey(buf(spendPriv), true));
    const viewPub = hex(secp256k1.getPublicKey(buf(viewPriv), true));
    const meta = 'st:eth:0x' + (spendPub + viewPub).replace(/0x/g, '');
    $('bootline').textContent = 'GENTEST OK · meta-address derived: ' + meta.slice(0, 30) + '…';
  } catch (e) { $('bootline').textContent = 'GENTEST FAIL: ' + e.message; }
}, 700);
// returning user: a stored gp-session collapses the wizard into the dashboard header.
const sess = loadGpSession();
if (sess) enterDashboard(sess);
