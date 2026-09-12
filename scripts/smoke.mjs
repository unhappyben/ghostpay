// Boot smoke: start serve.mjs with no runner configured, assert the public
// endpoints respond as expected, then kill the server. Exits 1 on any failure.
import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { join } from 'path';

const PORT = parseInt(process.env.PORT || '8791', 10);
const BASE = `http://127.0.0.1:${PORT}`;
const ROOT = fileURLToPath(new URL('..', import.meta.url));

const env = { ...process.env, PORT: String(PORT) };
delete env.RUNNER_PK; // guarantee the no-runner path

const srv = spawn(process.execPath, [join(ROOT, 'serve.mjs')], { env, stdio: ['ignore', 'pipe', 'pipe'] });
srv.stderr.on('data', d => process.stderr.write(`[serve] ${d}`));
srv.on('error', e => { console.error('failed to start serve.mjs:', e.message); process.exit(1); });

const bail = code => { srv.kill('SIGTERM'); process.exit(code); };
setTimeout(() => { console.error('smoke timed out'); bail(1); }, 30000).unref();

async function waitUp() {
  for (let i = 0; i < 100; i++) {
    try { if ((await fetch(`${BASE}/health`)).ok) return; } catch { /* not up yet */ }
    await new Promise(r => setTimeout(r, 150));
  }
  throw new Error('serve.mjs did not come up');
}

let failures = 0;
async function expect(name, fn) {
  try { await fn(); console.log('ok  ', name); }
  catch (e) { failures++; console.error('FAIL', name, ':', e.message); }
}
const statusIs = (res, want, what) => { if (res.status !== want) throw new Error(`${what}: got ${res.status}, want ${want}`); };

await waitUp();

await expect('GET /health 200, runnerCount 0', async () => {
  const res = await fetch(`${BASE}/health`);
  statusIs(res, 200, '/health');
  const j = await res.json();
  if (j.runnerCount !== 0) throw new Error(`runnerCount ${j.runnerCount}, want 0`);
});
await expect('GET /fee 200, minFeeBps 30', async () => {
  const res = await fetch(`${BASE}/fee`);
  statusIs(res, 200, '/fee');
  const j = await res.json();
  if (j.minFeeBps !== 30) throw new Error(`minFeeBps ${j.minFeeBps}, want 30`);
});
await expect('GET /status/0xbad 400', async () => {
  statusIs(await fetch(`${BASE}/status/0xbad`), 400, '/status/0xbad');
});
for (const p of ['/', '/app.html', '/invoices.html']) {
  await expect(`GET ${p} 200`, async () => statusIs(await fetch(BASE + p), 200, p));
}
await expect('POST /announce 503 (no runner)', async () => {
  const res = await fetch(`${BASE}/announce`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ stealth: '0x' + '11'.repeat(20), ephPub: '0x' + '02' + '22'.repeat(32), viewTag: 1 }),
  });
  statusIs(res, 503, 'POST /announce');
});

console.log(failures ? `smoke failed: ${failures} assertion(s)` : 'smoke passed');
bail(failures ? 1 : 0);
