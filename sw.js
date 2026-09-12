// sw.js · GHOSTPAY service worker: cache-first static shell.
// Relayer endpoints and all non-GET traffic always go to the network.
const CACHE = 'ghostpay-v6';
// single-page reality: index.html is the whole tabbed app (GET PAID · PAY · FUNDS ·
// INVOICES); app.html / invoices.html are tiny redirect stubs, precached so they still
// redirect offline. All gp-*.mjs modules, frags, and vendor files stay as before.
const PRECACHE = [
  './',
  './index.html',
  './app.html',
  './invoices.html',
  './app-core.mjs',
  './gp-ui.css',
  './manifest.json',
  './icon.svg',
  './gp-inbox.mjs',
  './gp-money.mjs',
  './gp-invoices.mjs',
  './gp-reports.mjs',
  './frag-inbox.html',
  './frag-money.html',
  './frag-invoices.html',
  './frag-reports.html',
  './vendor/poseidon2.mjs',
  './vendor/poseidon13.mjs',
  './vendor/tc-pedersen.mjs',
  './vendor/noble-curves-secp256k1.mjs',
  './vendor/noble-hashes-sha256.mjs',
  './vendor/noble-hashes-sha3.mjs',
  './vendor/ethers.mjs',
  './vendor/qrcode-generator.mjs',
  './vendor/latrine-irn.mjs',
  './vendor/latrine-wc.mjs',
  './vendor/latrine-jwt.mjs',
  './vendor/snarkjs.mjs',
  './vendor/esm-node/process.mjs',
  './vendor/esm-node/events.mjs',
  './vendor/esm-node/tty.mjs',
  './vendor/esm-node/async_hooks.mjs',
];
const NETWORK_ONLY = /^\/(announce|sweep|health|fee|price)$/;

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(PRECACHE)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET' || url.origin !== location.origin) return;
  if (NETWORK_ONLY.test(url.pathname)) return; // relayer calls: never cached
  e.respondWith(
    caches.match(e.request, { ignoreSearch: true }).then(hit => hit || fetch(e.request).then(res => {
      // cache-first, but backfill good responses (artifacts/wasm, config) for offline reuse
      if (res.ok) {
        const copy = res.clone();
        caches.open(CACHE).then(c => c.put(e.request, copy));
      }
      return res;
    }))
  );
});
