# The envelope/v0 "pinned signer form" against real proto3-JSON libraries, and A2A card signing

Track: T2 `envelope/v0` (critical path T0 → T2 → T5 → M1) and the signed Agent Card of §4.2 / M1 step 2.
Kind: harder tests (d), with a small prior-art read of the official A2A SDKs.

## Question

Due diligence §4.4 pins one proto3-JSON form for signed bodies: lowerCamelCase names, enums as names, standard
padded base64, RFC 3339 `Z` timestamps, implicit-presence defaults omitted, explicit-presence defaults kept.
Signers MUST emit that form and receivers MUST reject known fields that deviate from it. Two practical questions:

1. **Signer side.** Does any real proto3-JSON serializer we could use (Rust core, TS UI) emit exactly that form
   for A2A 1.0 messages? If two such libraries serialize the same message, do they give the same JCS bytes?
2. **Receiver side.** Can a library's JSON parser serve as the "reject non-pinned forms" check? If not, what has
   to be written?

While answering (1) I found that Agent Card signing (A2A §8.4.1), which §4.2 says webway reuses, follows a
different rule in each official SDK. That is reported as part 3.

## Method

Code is in [`lab/proto-json-signer-form/`](proto-json-signer-form/). Run it with `run.sh`; the output is in
`results.txt`. Rust and TypeScript only, no GPU.

- **Schema**: `a2a.proto` from A2A tag **v1.0.1** (sha256 `e195bf96…`), compiled with `protox` 0.10 (no
  `protoc`). The same descriptor set feeds every library.
- **Generator** (`gen`, seed 1): **120 000 random messages**, spread evenly over the 9 top-level types that travel
  as bodies or get signed (`SendMessageRequest`, `SendMessageResponse`, `StreamResponse`, `Task`, `AgentCard`,
  `ListTasksRequest`/`Response`, `TaskPushNotificationConfig`, `GetTaskRequest`). The generator favours the hard
  cases on purpose:
  - fields set to their default, `optional` fields and `oneof` members set to default (`historyLength: 0`,
    `Part{text: ""}`);
  - timestamps at 0, 3, 6 and 9 significant fractional digits, at the 0001/9999 bounds, and about 1 % out of range;
  - odd doubles in `Struct`/`Value` (−0, 2^53+1, 5e-324, about 1 % NaN/∞);
  - unknown enum number 77 (5 % of enum fields), standing in for a peer on a newer schema.

  Each message is encoded to binary, and each library turns the binary into JSON.
- **Serializers under test**:
  - `prost-reflect` 0.16.5 (`SerializeOptions` default);
  - `pbjson` 0.9.0 + `pbjson-types` (the usual prost/tonic JSON stack);
  - `@bufbuild/protobuf` 2.17.0 `toJsonString`;
  - `protobufjs` 8.8.1 `toObject({enums: String, longs: String, bytes: String, json: true})`;
  - **a2a-js**, the official A2A JS SDK at `3d3ca829` (2026-11-05): its ts-proto decoder plus its hand-written
    `src/types/protojson.ts`.
- **Pinned-form checker**: `pinned_violations` in `src/main.rs`, about 150 lines. I wrote it from §4.4 and the
  proto3 JSON mapping, independently of all five libraries. It walks the generic JSON with the descriptor. For
  Timestamps I read "the canonical form the mapping defines" as `Z`, years 0001–9999, and the *shortest* of 0, 3,
  6 or 9 fractional digits. That is what protobuf-go, protobuf-java, bufbuild and prost-reflect emit.
- **Mutants** (receiver side): from each pinned-form output I derive one mutant per class, picked at random, plus
  an unmodified control. **239 236 mutants** in total. The classes are: enum as number, snake_case name, an
  implicit-presence field emitted at its default, `null` for an absent field, a timestamp with non-minimal digits,
  a timestamp with a `+00:00` offset, url-safe unpadded base64, int32 as a string, and an unknown field. Each Rust
  and TS parser parses each mutant. I record whether it **accepts** the mutant and whether the result decodes to
  the **same** message as the original.
- **Typed round trip**: on the 118 357 pinned-form controls, each library parses the JSON into its typed form and
  emits it again. I compare JCS(input) with JCS(output); if they are equal, a signature over the input survives
  that library.
- **Cards**: each of the 13 301 generated AgentCards goes through a2a-js `canonicalizeAgentCard` (A2A §8.4.1) and
  through JCS(pinned card minus `signatures`). The latter is what a2a-go signs (see the prior art below). I also
  ran the spec's own §8.4.1 example and six hand-written realistic cards (`ts/card-example.ts`).

## Results

### 1. Signer side: two libraries emit the pinned form; three do not

| Library | Refused to emit | Pass pinned form (of emitted) | JCS = prost-reflect | Violations |
|---|---|---|---|---|
| prost-reflect 0.16.5 | 644 (402 NaN/∞, 242 bad Timestamp) | **99.16 %** | n/a | only unknown enum → number (0.83 %); 3 out-of-range timestamps emitted as year `+10000` |
| @bufbuild/protobuf 2.17.0 | 891 (401 NaN/∞, 490 bad Timestamp) | **99.17 %** | **119 109 / 119 109** | only unknown enum → number (0.83 %) |
| pbjson 0.9.0 | 1 635 (1 002 unknown enum, 398 NaN/∞, 235 bad Timestamp) | 89.91 % | 106 424 / 118 130 | **every Timestamp written `+00:00`** (9.98 % of messages), year `+10000` |
| protobufjs 8.8.1 | 0 | 88.96 % | 79 378 / 119 356 | Timestamp as `{seconds, nanos}`, Struct as `{fields: …}`: not a proto3-JSON mapper for WKTs |
| a2a-js (`3d3ca829`) | 0 | 94.96 % | 108 780 / 119 356 | Timestamps go through JS `Date`: always 3 digits (`.000Z`, 4.18 %), **sub-ms nanos truncated**; unknown enum → `"UNRECOGNIZED"`; out-of-range years emitted (`+010000-…`) |

- **prost-reflect and bufbuild agree byte for byte after JCS on every message both emit (119 109).** Apart from
  unknown enums, every message they emit is in the pinned form. So a Rust signer built on prost-reflect and a TS
  tool built on bufbuild interoperate.
- **Unknown enum values have no pinned form.** For a value the signer's schema does not know:
  - prost-reflect, bufbuild and protobufjs emit the number, which §4.4 says receivers reject;
  - pbjson refuses to serialize;
  - a2a-js silently writes the string `"UNRECOGNIZED"`, so the value is lost.

  This only matters when a node *originates* JSON from typed data, for example data decoded from a binary/gRPC
  edge. Forwarded bodies stay generic JSON.
- **Invalid Timestamps are not handled the same way.** bufbuild refuses `nanos` outside [0, 1e9). prost-reflect
  quietly normalises it (`nanos = 1e9` becomes the next second): those are the ~238 controls that do not decode
  back to the identical message. It also emits `+10000-01-01T00:00:00Z` for one second past the maximum.
- **`Value{}` with no kind set** (no JSON form in the mapping): both prost-reflect and pbjson emit `null` (probe),
  so `Value{}` and `Value{null_value}` sign the same.
- **pbjson's `+00:00`** also breaks A2A v1.0.1 §5.6.1 ("MUST NOT include timezone offsets other than 'Z'"), not
  just the webway pin. Of the 118 357 pinned inputs, it changes **12 365 (10.4 %)** in a typed round trip.

### 2. Receiver side: no parser rejects any non-pinned form

Accepted / decoded to the same message, out of `n` mutants. The checker column shows how many the checker
rejected. Only the control row shows the "same" count (full counts are in `results.txt`), because control losses
confound "same" in the mutant rows: pbjson's Struct-`null` and a2a-js's ms truncation.

| Mutation | n | checker rejects | prost-reflect | pbjson | bufbuild | a2a-js |
|---|---|---|---|---|---|---|
| control (unmodified) | 118 357 | **0** | 118 354 / 118 116 | 118 357 / 103 860 | 118 354 / 118 116 | 118 357 / 112 126 |
| enum as number | 1 772 | 1 772 | **100 % accepted** | 100 % | 100 % | 100 % |
| snake_case name | 19 973 | 19 973 | 100 % | 100 % | 100 % | 100 % |
| implicit default emitted | 27 751 | 27 751 | 100 % | 100 % | 100 % | 100 % |
| `null` for absent | 28 624 | 28 624 | 100 % | 24 % | 100 % | 100 % |
| int32 as string | 7 320 | 7 320 | 100 % | 100 % | 100 % | 100 % |
| timestamp not minimal | 2 181 | 2 181 | 100 % | 100 % | 100 % | 100 % (then truncated) |
| timestamp `+00:00` | 3 106 | 3 106 | 100 % | 100 % | 100 % | 100 % (53 % same) |
| base64 url-safe unpadded | 501 | 501 | 100 % | 100 % | 100 % | 100 % |
| unknown field | 29 651 | flagged as unknown, kept (§4.8) | **0 %** (rejected) | 0 % | 0 % | 100 %, field dropped |

- Every parser accepts every non-pinned class (pbjson rejects `null` 76 % of the time, by accident). So
  "parse it with the library" cannot enforce §4.4's MUST-reject. The receiver needs its own descriptor-driven
  check over the generic JSON. The 150-line checker here rejected **all 91 228 non-pinned mutants** (8 classes) and flagged
  **0 of 118 357** pinned controls.
- In their default settings, the typed parsers reject unknown fields. §4.4/§4.8 require unknown fields to be kept.
  This confirms the "verify on generic JSON, never on typed values" rule from the parse side as well.
- Typed round trips that are safe: prost-reflect and bufbuild return JCS-identical JSON on 100 % of pinned inputs
  (3 errors are the `+10000` years). a2a-js changes **535 (0.45 %)**: its `fromJSON` uses `isSet()`, which treats
  `null` as unset, so it drops `Part{data: null}` (an explicit-presence oneof member). pbjson changes 10.4 % (the
  `+00:00` timestamps). It also parses `null` inside `Struct` into a kind-less `Value`, which is not equal in
  binary to `null_value`.

### 3. Agent Card signatures: the A2A ecosystem has three rules

Read from source (Python and Go are outside the owner's language rules, so I read their code but did not run it):

| Who | Rule |
|---|---|
| A2A v1.0.1 spec §8.4.1 | Presence-aware JSON. **REQUIRED fields are included even at default** (`"description": ""`, `"skills": []`), then JCS. |
| a2a-js `src/signature.ts` (ran), a2a-python `utils/signing.py` @`2cc1dd50` (read) | Typed round trip (`fromJSON`/`toJSON`, or `MessageToDict`), which **drops unknown fields**. Then `cleanEmpty`/`_clean_empty` removes **every** `""`, `[]`, `{}` and `null`, including REQUIRED and explicit-presence fields and values inside `Struct`. Then JCS. |
| a2a-go `a2acrypto/canonical.go` @`ea739de3` (read) | JCS of the raw JSON minus `signatures`. Keeps everything. This is the same rule as webway §4.4. |

- On the spec's own worked example, a2a-js gives `{"capabilities":{…},"name":"Example Agent"}`, not the
  expected `…,"description":"","name":"Example Agent","skills":[]}`. **a2a-js does not reproduce §8.4.1's example.**
- Pinned card vs a2a-js canonical form: equal for only **728 of 13 301 (5.5 %)** random cards. The generator
  favours empties, so that rate is a floor, not a forecast. The realistic cards are more telling:
  - equal: a typical card, and one with `streaming: false` set explicitly;
  - **different**: no optional capabilities (`"capabilities": {}`), an extension with `params: {"mode": ""}`, an
    empty REQUIRED `description`, and a card with one extra field.
- **What an a2a-js/a2a-python signature does not cover**: for 100 % of mutated cards the canonical form stays the
  same. That is 3 359 with an unknown field added, 3 322 renamed to snake_case, 3 359 with defaults added and
  3 351 with nulls added. So a relay, registry or owner directory can **add fields to a signed card and it still
  verifies** in those SDKs. A webway-specific card field (for example a relay or mailbox address in a future card
  extension) is unauthenticated for those verifiers.
- **A direct contradiction with §4.4.** If a webway node applies its envelope receiver rule to cards, it rejects
  `"description": ""`, an implicit-presence default. §8.4.1 says that field MUST be included.

## What this means for the design

- **Signer**: build the Rust signer on **prost-reflect** (or prost types + a prost-reflect emitter), not on
  pbjson. pbjson's `+00:00` breaks both the webway pin and A2A §5.6.1. TS tooling that signs or checks (inspector,
  test tools) should use **@bufbuild/protobuf**. a2a-js types are not suitable, because they lose sub-ms precision,
  turn unknown enums into `UNRECOGNIZED`, and drop `data: null`.
- **Receiver**: T2/T5 needs a **descriptor-driven pinned-form validator over `serde_json::Value`**.
  `pinned_violations` here is a working sketch. It must not be a typed parser.
- **Spec gaps in §4.4 to close in T2**:
  1. Timestamps: state "`Z`, years 0001–9999, shortest of 0/3/6/9 fractional digits". "The canonical form the
     mapping defines" leaves the digit count to the reader.
  2. Unknown enum values: signers MUST refuse to emit (never a number, never `UNRECOGNIZED`). Receivers need a
     rule for an enum *name* their schema does not know: reject, or accept as forward-compatible. This is not
     decided yet.
  3. `Value` with no kind and non-finite numbers: signers MUST refuse.
- **Cards**: decide which card rule webway uses before T3/T17. One option to evaluate is a "clean card" profile,
  in which webway cards are fixed points of all three rules:
  - no `""`, `[]`, `{}` or `null` anywhere, including inside `Struct` params;
  - REQUIRED strings and lists non-empty (A2A §5.7 already requires non-empty REQUIRED arrays);
  - `capabilities` always carries at least one explicit boolean, so it is never `{}`;
  - no unknown fields.

  For such a card, all three rules give identical bytes. Webway nodes then verify with generic JCS (which covers
  every field) and still interoperate with vanilla a2a-js/python/go verifiers.

## What the planner should do next

1. **T2 vectors**: add the 9 mutation classes as `EnvelopeInvalid` vectors. Add positive vectors for
   `historyLength: 0`, `Part{text: ""}`, `Part{data: null}` (must verify and stay distinct from absent), and
   timestamps with 0, 3, 6 and 9 digits. Add negatives for `.000Z`, `+00:00`, year `+10000`, an enum number, and
   `UNRECOGNIZED`.
2. **T2 spec text**: close gaps 1–3 above. Add a SHOULD naming prost-reflect as the reference emitter, and a note
   that pbjson is non-conforming.
3. **T5**: port `pinned_violations` into the envelope crate as the receiver check. Fuzz it against prost-reflect
   round trips (a round trip that changes JCS ⇒ the checker must reject).
4. **T3/T17 decision (owner question candidate)**: choose the card canonicalisation, either the "clean card"
   profile above or a separate webway signature next to the A2A JWS. Record that unknown card fields are unsigned
   for a2a-js/a2a-python verifiers.
5. **Upstream (T20, owner's call, nothing posted)**: the §8.4.1 text and a2a-js/a2a-python disagree on the spec's
   own example, and a2a-go follows a third rule. That is worth an A2A issue once the owner decides.

## Sources

- A2A specification v1.0.1, §5.6.1, §5.7 and §8.4.1, and `specification/a2a.proto` at tag v1.0.1:
  <https://github.com/a2aproject/A2A/tree/v1.0.1>
- Protobuf proto3 JSON mapping (Timestamp output uses 0, 3, 6 or 9 fractional digits; `Z`):
  <https://protobuf.dev/programming-guides/json/>
- a2a-js `src/types/protojson.ts`, `src/signature.ts`, `src/types/buf.gen.yaml` (ts-proto 2.11, `useDate=string`)
  at `3d3ca8291e1f6b1f53293f61c12ba46c36670000`: <https://github.com/a2aproject/a2a-js>
- a2a-python `src/a2a/utils/signing.py` at `2cc1dd5020874376ed293ef87089e5df9d205571`:
  <https://github.com/a2aproject/a2a-python>
- a2a-go `a2acrypto/canonical.go`, `sign.go`, `verify.go` at `ea739de3859f0574175bc9876eda39b7120da8e3`:
  <https://github.com/a2aproject/a2a-go>
- Crates: prost-reflect 0.16.5, pbjson/pbjson-types/pbjson-build 0.9.0, protox 0.10.0, prost 0.14.4,
  serde_json_canonicalizer 0.3 (checked against RFC 8785 in
  [jcs-differential](2026-11-09-jcs-differential.md)). npm: @bufbuild/protobuf 2.17.0, protobufjs 8.8.1,
  jose 6.2.3.
- RFC 8785 (JCS): <https://www.rfc-editor.org/rfc/rfc8785>
