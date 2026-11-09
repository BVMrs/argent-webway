// ECMAScript oracle for RFC 8785: JSON.parse + the reference canonicaliser (RFC 8785 Appendix / cyberphone
// canonicalize.js), plus the I-JSON checks envelope/v0 requires (duplicate keys, lone surrogates, finite numbers).
// Run: node oracle.ts <cases.jsonl> <oracle.jsonl>   (Node >= 22.18 strips the types)
import { createReadStream, createWriteStream } from "node:fs";
import { createInterface } from "node:readline";

function canon(o: unknown): string {
  if (typeof o === "number" && !Number.isFinite(o)) throw new Error("non-finite number");
  if (o === null || typeof o !== "object") return JSON.stringify(o);
  if (Array.isArray(o)) return "[" + o.map(canon).join(",") + "]";
  const rec = o as Record<string, unknown>;
  // default Array.prototype.sort compares UTF-16 code units, which is what RFC 8785 §3.2.3 requires
  return "{" + Object.keys(rec).sort().map((k) => JSON.stringify(k) + ":" + canon(rec[k])).join(",") + "}";
}

function loneSurrogate(o: unknown): boolean {
  if (typeof o === "string") return !o.isWellFormed();
  if (o === null || typeof o !== "object") return false;
  if (Array.isArray(o)) return o.some(loneSurrogate);
  return Object.entries(o).some(([k, v]) => !k.isWellFormed() || loneSurrogate(v));
}

// Duplicate keys are invisible after JSON.parse, so scan the text (already known to be valid JSON).
function duplicateKey(t: string): boolean {
  const stack: (Set<string> | null)[] = [];
  let expectKey = false;
  for (let i = 0; i < t.length; i++) {
    const c = t[i];
    if (c === '"') {
      let j = i + 1;
      while (t[j] !== '"') j += t[j] === "\\" ? 2 : 1;
      if (expectKey) {
        const k: string = JSON.parse(t.slice(i, j + 1));
        const s = stack[stack.length - 1]!;
        if (s.has(k)) return true;
        s.add(k);
        expectKey = false;
      }
      i = j;
    } else if (c === "{") { stack.push(new Set()); expectKey = true; }
    else if (c === "[") { stack.push(null); }
    else if (c === "}" || c === "]") { stack.pop(); expectKey = false; }
    else if (c === ",") { expectKey = stack[stack.length - 1] instanceof Set; }
  }
  return false;
}

const out = createWriteStream(process.argv[3]);
for await (const line of createInterface({ input: createReadStream(process.argv[2]) })) {
  const c = JSON.parse(line);
  let r: { id: number; out?: string; err?: string };
  try {
    const v = JSON.parse(c.text);
    if (loneSurrogate(v)) throw new Error("lone surrogate");
    if (duplicateKey(c.text)) throw new Error("duplicate key");
    r = { id: c.id, out: canon(v) };
  } catch (e) {
    r = { id: c.id, err: String((e as Error).message) };
  }
  if (!out.write(JSON.stringify(r) + "\n")) await new Promise((res) => out.once("drain", res));
}
out.end();
