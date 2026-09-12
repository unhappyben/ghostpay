// sw.js — GHOSTPAY service worker: cache-first static shell.
// Relayer endpoints and all non-GET traffic always go to the network.
const CACHE = 'ghostpay-v3';
const PRECACHE = [
  './',
  './index.html',
  './app.html',
  './invoices.html',
  './app-core.mjs',
  './manifest.json',
  './icon.svg',
  './gp-inbox.mjs',
  './gp-money.mjs',
  './gp-invoices.mjs',
  './frag-inbox.html',
  './frag-money.html',
  './frag-invoices.html',
  './vendor/poseidon2.mjs',
  './vendor/poseidon13.mjs',
  './vendor/tc-pedersen.mjs',
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
