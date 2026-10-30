import assert from 'node:assert/strict';
import {readFileSync,readdirSync,lstatSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../docs');
const allowed=['.nojekyll','app.js','execution-reader.js','index.html','robots.txt','styles.css'].sort();
assert.deepEqual(readdirSync(root).sort(),allowed,'Only six reviewed static files may be published');
const forbidden=/\/Users\/[A-Za-z][^/]+\/|\.private-import-data|BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY|gh[pousr]_[a-zA-Z0-9]{20,}|github_pat_[a-zA-Z0-9_]{30,}|sk-[a-zA-Z0-9]{20,}/;
for(const file of allowed){
  assert.ok(lstatSync(path.join(root,file)).isFile(),`Not a regular file: ${file}`);
  assert.ok(!forbidden.test(readFileSync(path.join(root,file),'utf8')),`Private content: ${file}`);
  if(file.endsWith('.js'))execFileSync(process.execPath,['--check',path.join(root,file)]);
}
const html=readFileSync(path.join(root,'index.html'),'utf8');
const app=readFileSync(path.join(root,'app.js'),'utf8');
assert.ok(html.includes("connect-src 'none'"));
assert.ok(html.includes('noindex,nofollow'));
assert.ok(app.includes('架空サンプル'));
assert.ok(!/\bfetch\s*\(|XMLHttpRequest|WebSocket|sendBeacon\s*\(/.test(app));
console.log('PASS: six static assets, synthetic data, no network submission, valid JavaScript');
