// CDP driver: loads a URL in headless Chrome, waits for a bootline marker,
// and reports all console messages / exceptions. Usage:
//   node cdp-check.mjs <url> <timeout-ms>
import { spawn } from 'child_process';

const [, , url, timeoutArg] = process.argv;
const TIMEOUT = parseInt(timeoutArg || '45000', 10);
const PORT = 9333;

const chrome = spawn('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', [
  '--headless=new', '--disable-gpu', '--no-first-run', '--disable-extensions',
  '--user-data-dir=/tmp/ghostpay-cdp-profile',
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

const wsUrl = await getWsUrl();
const ws = new WebSocket(wsUrl);
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

const { result: { targetId } } = await send('Target.createTarget', { url: 'about:blank' });
const { result: { sessionId } } = await send('Target.attachToTarget', { targetId, flatten: true });
await send('Runtime.enable', {}, sessionId);
await send('Log.enable', {}, sessionId);
await send('Page.enable', {}, sessionId);
await send('Page.navigate', { url }, sessionId);

let bootline = null;
const t0 = Date.now();
while (Date.now() - t0 < TIMEOUT) {
  const r = await send('Runtime.evaluate', {
    expression: `(document.getElementById('bootline')||{}).textContent || ''`,
    returnByValue: true,
  }, sessionId);
  bootline = r.result && r.result.result && r.result.result.value;
  if (bootline && /GENTEST|error/i.test(bootline)) break;
  await sleep(500);
}

const consoleMsgs = [];
const exceptions = [];
for (const e of events) {
  if (e.method === 'Runtime.consoleAPICalled') {
    const p = e.params;
    consoleMsgs.push(`[${p.type}] ` + p.args.map(a => a.value ?? a.description ?? a.unserializableValue ?? '').join(' '));
  } else if (e.method === 'Runtime.exceptionThrown') {
    const d = e.params.exceptionDetails;
    exceptions.push(d.text + ' ' + (d.exception && d.exception.description || ''));
  } else if (e.method === 'Log.entryAdded' && e.params.entry.level === 'error') {
    if (/favicon\.ico/.test(e.params.entry.url || '')) continue; // benign: no favicon in the prototype
    consoleMsgs.push('[log:error] ' + e.params.entry.text + ' ' + (e.params.entry.url || ''));
  }
}

console.log('BOOTLINE: ' + bootline);
console.log('CONSOLE MESSAGES (' + consoleMsgs.length + '):');
consoleMsgs.forEach(m => console.log('  ' + m.slice(0, 300)));
console.log('EXCEPTIONS (' + exceptions.length + '):');
exceptions.forEach(m => console.log('  ' + m.slice(0, 300)));
const ok = /GENTEST OK/.test(bootline || '') && exceptions.length === 0 && !consoleMsgs.some(m => /^\[(error|log:error)\]/.test(m));
console.log(ok ? 'RESULT: PASS' : 'RESULT: FAIL');
chrome.kill('SIGKILL');
process.exit(ok ? 0 : 1);
