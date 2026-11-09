// TS side of lab/2026-11-09-proto-json-signer-form.md. Run with bun (resolves a2a-js's `.js` imports to `.ts`).
//   bun serialize.ts <dir> <a2a-js checkout>
// Reads <dir>/a2a.binpb, cases.jsonl, mutants.jsonl. Writes, per library, <lib>.jsonl (binary -> JSON) and
// <lib>.parse.jsonl (mutant JSON -> binary), in the row formats the Rust `check` command reads.
import { readFileSync, writeFileSync } from "node:fs";
import { createFileRegistry, fromBinary, fromJsonString, toBinary, toJsonString } from "@bufbuild/protobuf";
import type { DescMessage } from "@bufbuild/protobuf";
import { FileDescriptorSetSchema } from "@bufbuild/protobuf/wkt";
import protobuf from "protobufjs";
import "protobufjs/ext/descriptor/index.js";

const [dir, a2ajs] = process.argv.slice(2);
const fdsBytes = readFileSync(`${dir}/a2a.binpb`);
const reg = createFileRegistry(fromBinary(FileDescriptorSetSchema, fdsBytes));
// protobufjs/ext/descriptor adds Root.fromDescriptor
const pbjsRoot = (protobuf.Root as any).fromDescriptor(new Uint8Array(fdsBytes));
const grpcPb: any = await import(`${a2ajs}/src/grpc/pb/a2a.ts`);
const protojson: any = await import(`${a2ajs}/src/types/protojson.ts`);

const lines = (f: string) =>
  readFileSync(f, "utf8").split("\n").filter((l) => l.length > 0).map((l) => JSON.parse(l));
const cases = lines(`${dir}/cases.jsonl`);
const mutants = lines(`${dir}/mutants.jsonl`);
const b64 = (u: Uint8Array) => Buffer.from(u).toString("base64");
const msg = (e: unknown) => String((e as Error)?.message ?? e).slice(0, 200);

function row(i: number, f: () => string) {
  try {
    const json = f();
    if (json === undefined) return JSON.stringify({ i, err: "undefined" });
    return JSON.stringify({ i, json });
  } catch (e) {
    return JSON.stringify({ i, err: msg(e) });
  }
}

const out: Record<string, string[]> = { bufbuild: [], protobufjs: [], "a2a-js": [] };
for (const c of cases) {
  const bin = new Uint8Array(Buffer.from(c.bin, "base64"));
  const desc = reg.getMessage(`lf.a2a.v1.${c.type}`) as DescMessage;
  out.bufbuild.push(row(c.i, () => toJsonString(desc, fromBinary(desc, bin))));
  const T = pbjsRoot.lookupType(`lf.a2a.v1.${c.type}`);
  out.protobufjs.push(
    row(c.i, () =>
      JSON.stringify(T.toObject(T.decode(bin), { longs: String, enums: String, bytes: String, json: true })),
    ),
  );
  out["a2a-js"].push(row(c.i, () => JSON.stringify(protojson[c.type].toJSON(grpcPb[c.type].decode(bin)))));
}
for (const [k, v] of Object.entries(out)) writeFileSync(`${dir}/${k}.jsonl`, v.join("\n") + "\n");

function prow(f: () => Uint8Array) {
  try {
    return JSON.stringify({ ok: true, bin: b64(f()) });
  } catch (e) {
    return JSON.stringify({ ok: false, err: msg(e) });
  }
}
const pout: Record<string, string[]> = { bufbuild: [], "a2a-js": [] };
for (const m of mutants) {
  const desc = reg.getMessage(`lf.a2a.v1.${m.type}`) as DescMessage;
  pout.bufbuild.push(prow(() => toBinary(desc, fromJsonString(desc, m.json))));
  pout["a2a-js"].push(prow(() => grpcPb[m.type].encode(protojson[m.type].fromJSON(JSON.parse(m.json))).finish()));
}
// typed JSON -> JSON round trip of the unmutated pinned JSON, as a JS gateway that decodes and re-encodes would do
const rt: Record<string, string[]> = { bufbuild: [], "a2a-js": [] };
for (const m of mutants) {
  if (m.kind !== "identity (control)") continue;
  const desc = reg.getMessage(`lf.a2a.v1.${m.type}`) as DescMessage;
  rt.bufbuild.push(row(m.i, () => toJsonString(desc, fromJsonString(desc, m.json))));
  rt["a2a-js"].push(row(m.i, () => JSON.stringify(protojson[m.type].toJSON(protojson[m.type].fromJSON(JSON.parse(m.json))))));
}
for (const [k, v] of Object.entries(rt)) writeFileSync(`${dir}/${k}.rt.jsonl`, v.join("\n") + "\n");
// A2A §8.4.1 card canonicalisation as implemented by a2a-js (typed round trip + cleanEmpty + JCS), on pinned
// AgentCard JSON and on its mutants. Rust compares these with JCS(pinned card minus `signatures`).
const sig: any = await import(`${a2ajs}/src/signature.ts`);
const cardRows: string[] = [];
for (const m of mutants) {
  if (m.type !== "AgentCard") continue;
  let canon: string | null = null;
  let err: string | null = null;
  try {
    canon = sig.canonicalizeAgentCard(JSON.parse(m.json));
  } catch (e) {
    err = msg(e);
  }
  cardRows.push(JSON.stringify({ i: m.i, kind: m.kind, canon, err }));
}
writeFileSync(`${dir}/a2a-js.cardcanon.jsonl`, cardRows.join("\n") + "\n");
for (const [k, v] of Object.entries(pout)) writeFileSync(`${dir}/${k}.parse.jsonl`, v.join("\n") + "\n");
console.error(`ts: ${cases.length} cases, ${mutants.length} mutants`);
