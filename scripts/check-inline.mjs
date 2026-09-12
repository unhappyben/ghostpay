// Syntax gate: node --check on every root *.mjs, plus the inline
// <script type="module"> bodies extracted from the HTML entry points.
import { readdirSync, readFileSync, writeFileSync, mkdtempSync, rmSync } from 'fs';
import { execFileSync } from 'child_process';
import { fileURLToPath } from 'url';
import { join } from 'path';
import { tmpdir } from 'os';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const HTML = ['index.html', 'app.html', 'invoices.html'];

const targets = readdirSync(ROOT)
  .filter(f => f.endsWith('.mjs'))
  .map(f => join(ROOT, f));

const tmp = mkdtempSync(join(tmpdir(), 'ghostpay-inline-'));
try {
  for (const name of HTML) {
    const html = readFileSync(join(ROOT, name), 'utf8');
    const re = /<script\s+type="module"\s*>([\s\S]*?)<\/script>/g;
    let m, i = 0;
    while ((m = re.exec(html))) {
      const f = join(tmp, `${name.replace('.html', '')}-inline-${i++}.mjs`);
      writeFileSync(f, m[1]);
      targets.push(f);
    }
  }
  for (const f of targets) {
    try {
      execFileSync(process.execPath, ['--check', f], { stdio: 'pipe' });
    } catch (e) {
      console.error(`FAIL ${f}\n${e.stderr ? e.stderr.toString() : e.message}`);
      process.exit(1);
    }
    console.log('ok', f.replace(ROOT, '').replace(tmp, '<inline>'));
  }
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
console.log(`syntax check passed: ${targets.length} files`);
