// smoke.mjs — run a BUILT xap-verify.wasm, report which one it is, and check it
// actually verifies.
//
//   node smoke.mjs ./xap-verify.wasm
//   node smoke.mjs https://vidimuslabs.com/xap-verify.wasm
//   node smoke.mjs https://vidimuslabs.com/xap-verify.wasm --expect <sha256>
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
// The digest half was added on 2026-08-17, when the converse bit: production was
// serving e194d78a while this module's tip built 4482a437, and this harness ran
// green against the live URL without ever saying which binary it had just
// approved. So the digest is now printed unconditionally — one line that makes
// every run of this script answer "which artifact?" as well as "does it work?" —
// and --expect turns that into an assertion. CI compares its own fresh build
// against the README's published claim; only this can be pointed at a deployed
// URL, which is where the drift actually lived.
//
// Deliberately dependency-free and outside the Go build: it must be able to
// check a binary whose source you do not have.

import { readFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import path from 'node:path';

function usage(msg) {
  if (msg) console.error(msg);
  console.error('usage: node smoke.mjs <path-or-url-to-xap-verify.wasm> [--expect <sha256>]');
  process.exit(2);
}

const argv = process.argv.slice(2);
let target = null;
let expected = null;
for (let i = 0; i < argv.length; i++) {
  if (argv[i] === '--expect') {
    expected = (argv[++i] ?? '').toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(expected)) usage('--expect wants a 64-character hex sha256');
  } else if (target === null) {
    target = argv[i];
  } else {
    usage(`unexpected argument: ${argv[i]}`);
  }
}
if (!target) usage();

// Go's loader shim, from the toolchain rather than a checked-in copy — a stale
// copy of wasm_exec.js is its own way to fail, and the recipe already says the
// shipped shim is GOROOT's verbatim.
const goroot = execFileSync('go', ['env', 'GOROOT'], { encoding: 'utf8' }).trim();
await import(path.join(goroot, 'lib/wasm/wasm_exec.js')); // defines globalThis.Go

const bytes = /^https?:\/\//.test(target)
  ? Buffer.from(await (await fetch(target)).arrayBuffer())
  : await readFile(target);

// Printed before the module is instantiated on purpose: a binary that panics on
// startup should still tell you which binary it was. That is the one fact the
// 2026-08-15 rollback had to establish by hand.
const digest = createHash('sha256').update(bytes).digest('hex');
console.log(`artifact: ${target} (${bytes.length} bytes)`);
console.log(`  sha256     ${digest}`);

// Checked before the behavioural tests rather than alongside them: if this is not
// the artifact you meant, everything below is a green result about the wrong file,
// which is more misleading than a failure.
if (expected && digest !== expected) {
  fail(
    `digest mismatch\n` +
    `  expected   ${expected}\n` +
    `  got        ${digest}\n` +
    `  Against a URL this means the site serves a different build from the one that\n` +
    `  digest names. Against a local file it means it was not built from the source\n` +
    `  you think it was. Either way the checks below would describe the wrong binary.`,
  );
}

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
