// Lab: turn the signature-bearing audit/v0 checkpoint and receipt vectors into corpus cases. Usage: node extract-audit.mjs VECTORDIR OUT
import { readFileSync, writeFileSync } from "node:fs";
const [, , dir, out] = process.argv;
const b32 = (s) => { // RFC 4648 base32, lowercase, unpadded
  const A = "abcdefghijklmnopqrstuvwxyz234567"; let bits = 0, v = 0; const o = [];
  for (const ch of s) { v = (v << 5) | A.indexOf(ch); bits += 5; if (bits >= 8) { o.push((v >>> (bits - 8)) & 255); bits -= 8; } }
  return Buffer.from(o);
};
const jcs = (x) => Array.isArray(x) ? `[${x.map(jcs).join(",")}]`
  : x && typeof x === "object" ? `{${Object.keys(x).sort().map((k) => JSON.stringify(k) + ":" + jcs(x[k])).join(",")}}`
  : JSON.stringify(x);
const cases = [];
for (const [file, field] of [["checkpoint.json", "checkpoint"], ["receipt.json", "receipt"]]) {
  for (const c of JSON.parse(readFileSync(`${dir}/${file}`, "utf8")).cases) {
    const o = c.input?.[field];
    if (!o || typeof o.sig !== "string" || typeof o.log !== "string") continue;
    const sig = Buffer.from(o.sig, "base64url");
    const pk = b32(o.log.slice(4));
    if (sig.length !== 64 || pk.length !== 32) continue;
    const { sig: _, ...rest } = o;
    const msg = Buffer.concat([Buffer.from(o.v), Buffer.from([0]), Buffer.from(jcs(rest))]);
    cases.push({ id: `${field}|${c.id}`, class: `audit-${field}`, expect: c.expected ?? c.expect ?? c.output,
      pk: pk.toString("hex"), msg: msg.toString("hex"), sig: sig.toString("hex"), f: {} });
  }
}
console.error(`${cases.length} signature cases`);
writeFileSync(out, JSON.stringify(cases));
