// Lab: run JS/TS Ed25519 verifiers over the corpus. Usage: node|bun verify.mjs CORPUS OUT
// Under node, node:crypto and WebCrypto are OpenSSL; under bun they are BoringSSL (as in Chrome).
import { readFileSync, writeFileSync } from "node:fs";
import * as nc from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519.js";
import * as ed from "@noble/ed25519";
import nacl from "tweetnacl";

ed.hashes.sha512 = (m) => new Uint8Array(nc.createHash("sha512").update(m).digest());

const rt = typeof Bun !== "undefined" ? `bun ${Bun.version} (BoringSSL)` : `node ${process.versions.node} (OpenSSL ${process.versions.openssl})`;
const [, , inp, out] = process.argv;
const cases = JSON.parse(readFileSync(inp, "utf8"));
const hex = (s) => Uint8Array.from(Buffer.from(s, "hex"));
const b64u = (u) => Buffer.from(u).toString("base64url");

const tryb = (f) => {
  try {
    return !!f();
  } catch {
    return false;
  }
};

const res = {};
const t0 = performance.now();
for (const c of cases) {
  const pk = hex(c.pk), sig = hex(c.sig), msg = hex(c.msg);
  const r = {};
  r[`js:node:crypto.verify [${rt}]`] = tryb(() => {
    const key = nc.createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: b64u(pk) }, format: "jwk" });
    return nc.verify(null, msg, key, sig);
  });
  r["js:@noble/curves 2.4 ed25519 (default zip215:true)"] = tryb(() => ed25519.verify(sig, msg, pk));
  r["js:@noble/curves 2.4 ed25519 {zip215:false}"] = tryb(() => ed25519.verify(sig, msg, pk, { zip215: false }));
  r["js:@noble/ed25519 3.2 (default)"] = tryb(() => ed.verify(sig, msg, pk));
  r["js:@noble/ed25519 3.2 {zip215:false}"] = tryb(() => ed.verify(sig, msg, pk, { zip215: false }));
  r["js:tweetnacl 1.0.3"] = tryb(() => nacl.sign.detached.verify(msg, sig, pk));
  res[c.id] = r;
}
// WebCrypto is async; do it in a second pass
for (const c of cases) {
  const pk = hex(c.pk), sig = hex(c.sig), msg = hex(c.msg);
  let ok = false;
  try {
    const key = await crypto.subtle.importKey("raw", pk, { name: "Ed25519" }, false, ["verify"]);
    ok = await crypto.subtle.verify({ name: "Ed25519" }, key, sig, msg);
  } catch {
    ok = false;
  }
  res[c.id][`js:WebCrypto subtle [${rt}]`] = ok;
}
console.error(`${rt}: ${cases.length} cases in ${((performance.now() - t0) / 1000).toFixed(1)} s`);
writeFileSync(out, JSON.stringify(res));
