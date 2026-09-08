// CDP end-to-end smoke of the in-browser WITHDRAW flow (error path):
// loads the app, pastes the stale pp-secret.json (no onchain deposit) + a recipient,
// clicks WITHDRAW, and watches st-withdraw. Expects: precommitment check passes
// (browser poseidon2 verified), deposit search runs, ends with "no matching deposit".
//   node cdp-withdraw-test.mjs <url> <timeout-ms>
import { spawn } from 'child_process';
import { readFileSync } from 'fs';

const [, , url, timeoutArg] = process.argv;
const TIMEOUT = parseInt(timeoutArg || '150000', 10);
const PORT = 9334;
const secretJson = readFileSync(new URL('./pp-secret.json', import.meta.url), 'utf8');

const chrome = spawn('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', [
  '--headless=new', '--disable-gpu', '--no-first-run', '--disable-extensions',
  '--user-data-dir=/tmp/ghostpay-cdp-profile2',
  `--remote-debugging-port=${PORT}`, 'about:blank',
], { stdio: 'ignore' });
process.on('exit', () => { try { chrome.kill('SIGKILL'); } catch {} });
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function getWsUrl() {
  for (let i = 0; i < 40; i++) {
    try {
      const r = await fetch(`http://localhost:${PORT}/json/version`);
      if (r.ok) return (await r.json()).webSocketDebuggerUrl;
    } catch {}
    await sleep(500);
  }
  throw new Error('chrome devtools endpoint never came up');
}

const ws = new WebSocket(await getWsUrl());
await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
let msgId = 0;
const pending = new Map();
const events = [];
ws.onmessage = e => {
  const m = JSON.parse(e.data);
  if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); }
  else if (m.method) events.push(m);
};
const send = (method, params = {}, sessionId) => new Promise(res => {
  const id = ++msgId;
  pending.set(id, res);
  ws.send(JSON.stringify({ id, method, params, sessionId }));
});
const evalJs = async (expr, sessionId) => {
  const r = await send('Runtime.evaluate', { expression: expr, returnByValue: true, awaitPromise: true }, sessionId);
  if (r.result && r.result.exceptionDetails) throw new Error('page eval failed: ' + JSON.stringify(r.result.exceptionDetails).slice(0, 300));
  return r.result && r.result.result && r.result.result.value;
};

const { result: { targetId } } = await send('Target.createTarget', { url: 'about:blank' });
const { result: { sessionId } } = await send('Target.attachToTarget', { targetId, flatten: true });
await send('Runtime.enable', {}, sessionId);
await send('Page.enable', {}, sessionId);
await send('Page.navigate', { url }, sessionId);
await sleep(4000); // let the module + esm.sh imports finish

// fill the form and click WITHDRAW
await evalJs(`document.getElementById('i-secretjson').value = ${JSON.stringify(secretJson)}`, sessionId);
await evalJs(`document.getElementById('i-recipient').value = '0x000000000000000000000000000000000000dEaD'`, sessionId);
await evalJs(`document.getElementById('b-withdraw').click()`, sessionId);

let status = '';
const t0 = Date.now();
while (Date.now() - t0 < TIMEOUT) {
  status = await evalJs(`document.getElementById('st-withdraw').textContent`, sessionId) || '';
  if (/ERROR|SUBMITTED/.test(status)) break;
  await sleep(2000);
}
console.log('--- st-withdraw final state ---');
console.log(status);
const lines = status.split('\n');
const preOk = lines.some(l => /precommitment matches poseidon2/.test(l));
const searched = lines.some(l => /scanned blocks/.test(l));
const refused = /no matching deposit found/.test(status);
const exceptions = events.filter(e => e.method === 'Runtime.exceptionThrown');
console.log('---');
console.log('browser poseidon2 precommitment check passed:', preOk);
console.log('deposit search ran in-browser:', searched);
console.log('correctly refused (stale fixture has no onchain deposit):', refused);
console.log('uncaught exceptions:', exceptions.length);
const pass = preOk && searched && refused && exceptions.length === 0;
console.log(pass ? 'RESULT: PASS' : 'RESULT: FAIL');
chrome.kill('SIGKILL');
process.exit(pass ? 0 : 1);
