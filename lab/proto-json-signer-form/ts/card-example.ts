// A2A v1.0.1 §8.4.1 worked example through a2a-js canonicalizeAgentCard.  bun card-example.ts <a2a-js checkout>
const sig: any = await import(`${process.argv[2]}/src/signature.ts`);
const example = {
  name: "Example Agent",
  description: "",
  capabilities: { streaming: false, pushNotifications: false, extensions: [] },
  skills: [],
};
const expected = '{"capabilities":{"pushNotifications":false,"streaming":false},"description":"","name":"Example Agent","skills":[]}';
const got = sig.canonicalizeAgentCard(example);
console.log(JSON.stringify({ spec: expected, a2a_js: got, equal: got === expected }));
const extra = { ...example, name: "X", webwayFutureField: { x: 1 }, capabilities: { streaming: true } };
console.log(JSON.stringify({ with_unknown: sig.canonicalizeAgentCard(extra), without: sig.canonicalizeAgentCard({ ...extra, webwayFutureField: undefined }) }));

// Realistic cards: generic JCS (what a2a-go signs: raw JSON minus `signatures`, nothing dropped) vs a2a-js.
const jcs = (v: unknown): string =>
  v === null || typeof v !== "object"
    ? JSON.stringify(v)
    : Array.isArray(v)
      ? `[${v.map(jcs).join(",")}]`
      : `{${Object.keys(v as object)
          .sort()
          .map((k) => `${JSON.stringify(k)}:${jcs((v as any)[k])}`)
          .join(",")}}`;
const base = {
  name: "tester",
  description: "Runs the test suite of a repository",
  version: "1.2.0",
  supportedInterfaces: [{ url: "webway://wwn:abc/wwa:def", protocolBinding: "webway-quic/v0", protocolVersion: "1.0" }],
  capabilities: { streaming: true },
  defaultInputModes: ["text/plain"],
  defaultOutputModes: ["text/plain", "application/json"],
  skills: [{ id: "run-tests", name: "Run tests", description: "Runs cargo test", tags: ["ci"] }],
};
const variants: Record<string, object> = {
  "typical card": base,
  "no optional capabilities (`capabilities: {}`)": { ...base, capabilities: {} },
  "capability explicitly false": { ...base, capabilities: { streaming: false, pushNotifications: false } },
  "extension with params {mode: \"\"}": {
    ...base,
    capabilities: { streaming: true, extensions: [{ uri: "https://github.com/BVMrs/argent-webway/ext/envelope/v0", required: true, params: { mode: "" } }] },
  },
  "REQUIRED description empty": { ...base, description: "" },
  "webway field from a newer card schema": { ...base, webwayRelay: "wwn:evil" },
};
for (const [k, card] of Object.entries(variants)) {
  const generic = jcs(card);
  const js = sig.canonicalizeAgentCard(card);
  console.log(JSON.stringify({ card: k, equal: generic === js, generic_len: generic.length, a2a_js_len: js.length }));
}
