// Lab: libsodium.js (libsodium-wrappers, wasm) over the corpus: the candidate TS verifier for ENV-210/211.
// Usage: node verify-sodium.mjs CORPUS OUT
import { readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
const sodium = createRequire(import.meta.url)("libsodium-wrappers"); // the 0.7.16 ESM build is broken
await sodium.ready;
const [, , inp, out] = process.argv;
const cases = JSON.parse(readFileSync(inp, "utf8"));
const hex = (s) => Uint8Array.from(Buffer.from(s, "hex"));
const name = `js:libsodium-wrappers 0.7.16 [libsodium ${sodium.sodium_version_string()}]`;
const res = {};
const t0 = performance.now();
for (const c of cases) {
  let ok = false;
  try { ok = sodium.crypto_sign_verify_detached(hex(c.sig), hex(c.msg), hex(c.pk)); } catch { ok = false; }
  res[c.id] = { [name]: ok };
}
console.error(`${name}: ${cases.length} cases in ${((performance.now() - t0) / 1000).toFixed(1)} s`);
writeFileSync(out, JSON.stringify(res));
