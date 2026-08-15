// smoke.mjs — run a BUILT xap-verify.wasm and check it actually verifies.
//
//   node smoke.mjs ./xap-verify.wasm
//   node smoke.mjs https://vidimuslabs.com/xap-verify.wasm
//
// Exit 0 on pass, non-zero on failure, so it can gate a deploy.
//
// Why this exists, given the Go tests next to it already cover the same
// behaviour: those test the SOURCE. This tests an ARTIFACT — a specific file,
// including one fetched from the live site — through Go's real loader shim.
//
// On 2026-08-15 a build went to production that was byte-identical to a clean
// reproducible build, passed a full 85-file deploy hash comparison, and could
// not start: its embedded trust anchors declared no signer roles, so main()
// panicked before installing the exports and the page loaded and did nothing.
// Every automated signal was green over a dead binary. A digest confirms
// provenance; it says nothing about whether the thing runs. This is the check
// that says whether it runs.
//
// Deliberately dependency-free and outside the Go build: it must be able to
// check a binary whose source you do not have.

import { readFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import path from 'node:path';

const target = process.argv[2];
if (!target) {
  console.error('usage: node smoke.mjs <path-or-url-to-xap-verify.wasm>');
  process.exit(2);
}

// Go's loader shim, from the toolchain rather than a checked-in copy — a stale
// copy of wasm_exec.js is its own way to fail, and the recipe already says the
// shipped shim is GOROOT's verbatim.
const goroot = execFileSync('go', ['env', 'GOROOT'], { encoding: 'utf8' }).trim();
await import(path.join(goroot, 'lib/wasm/wasm_exec.js')); // defines globalThis.Go

const bytes = /^https?:\/\//.test(target)
  ? Buffer.from(await (await fetch(target)).arrayBuffer())
  : await readFile(target);

console.log(`artifact: ${target} (${bytes.length} bytes)`);

const go = new Go();
const { instance } = await WebAssembly.instantiate(bytes, go.importObject);

// go.run() never resolves: main() parks on select{} so the exports stay
// callable. A panic during startup surfaces as an unhandled rejection, so watch
// for it rather than awaiting a promise that will not settle.
let startupError = null;
go.run(instance).catch((e) => { startupError = e; });
await new Promise((r) => setImmediate(r));

if (startupError) fail(`the module panicked during startup: ${startupError.message ?? startupError}`);

for (const name of ['xapDemoReceiptHex', 'xapVerify']) {
  if (typeof globalThis[name] !== 'function') {
    fail(`export ${name} is missing — the page calls this name and would do nothing`);
  }
}

const receipt = globalThis.xapDemoReceiptHex();
if (typeof receipt !== 'string' || receipt.length === 0) fail('xapDemoReceiptHex returned no receipt');

const good = globalThis.xapVerify(receipt);
if (good?.valid !== true) fail(`the demo receipt did not verify: ${good?.message}`);
console.log(`  untampered -> valid   ${good.message}`);

// One flipped character. A verifier that accepts everything passes the check
// above, and the page's whole claim is that tampering is detectable.
const i = Math.floor(receipt.length / 2);
const tampered = receipt.slice(0, i) + (receipt[i] === 'a' ? 'b' : 'a') + receipt.slice(i + 1);
const bad = globalThis.xapVerify(tampered);
if (bad?.valid !== false) fail('a tampered receipt verified');
console.log(`  tampered   -> invalid ${bad.message}`);

// Bad input must return a result, not kill the instance: a panic here leaves
// every later click on the page doing nothing until the visitor reloads.
for (const junk of [undefined, '', 'zzzz', 'abc', 'deadbeef']) {
  const res = globalThis.xapVerify(junk);
  if (typeof res?.valid !== 'boolean') fail(`bad input ${JSON.stringify(junk)} returned no usable result`);
  if (res.valid) fail(`bad input ${JSON.stringify(junk)} reported as valid`);
}
console.log('  malformed  -> refused, instance still alive');

console.log('SMOKE PASS');
process.exit(0);

function fail(msg) {
  console.error(`SMOKE FAIL: ${msg}`);
  process.exit(1);
}
