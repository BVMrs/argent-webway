// Lab: does "pre-check + permissive stdlib verifier" reproduce ENV-210/211?
// Pre-check: A and R decode canonically (RFC 8032 strict decoding), neither is of small order, S < L.
// Usage: node verify-precheck.mjs CORPUS OUT
import { readFileSync, writeFileSync } from "node:fs";
import * as nc from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519.js";

const L = 2n ** 252n + 27742317777372353535851937790883648493n;
const P = ed25519.Point;
const hex = (s) => Uint8Array.from(Buffer.from(s, "hex"));
const le = (u) => BigInt("0x" + Buffer.from(u).reverse().toString("hex"));
function precheck(pk, sig) {
  try {
    for (const enc of [pk, sig.subarray(0, 32)]) {
      const pt = P.fromBytes(enc, false); // zip215=false: rejects y >= p and x = 0 with the sign bit set
      if (!Buffer.from(pt.toBytes()).equals(Buffer.from(enc))) return false;
      if (pt.isSmallOrder()) return false;
    }
    return le(sig.subarray(32)) < L;
  } catch {
    return false;
  }
}
const [, , inp, out] = process.argv;
const cases = JSON.parse(readFileSync(inp, "utf8"));
const res = {};
for (const c of cases) {
  const pk = hex(c.pk), sig = hex(c.sig), msg = hex(c.msg);
  const pre = precheck(pk, sig);
  let o = false, n = false;
  try {
    const key = nc.createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(pk).toString("base64url") }, format: "jwk" });
    o = nc.verify(null, msg, key, sig);
  } catch {}
  try { n = ed25519.verify(sig, msg, pk, { zip215: false }); } catch {}
  res[c.id] = {
    "js:pre-check + node:crypto (OpenSSL)": pre && o,
    "js:pre-check + @noble/curves {zip215:false}": pre && n,
  };
}
writeFileSync(out, JSON.stringify(res));
