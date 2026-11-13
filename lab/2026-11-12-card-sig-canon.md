# Lab 2026-11-12: do signed A2A Agent Cards verify across the upstream SDKs and a strict Rust verifier, and what can be changed without the key?

## Question

M1 step 2 says `alpha` verifies beta's signed Agent Card against B's pinned key and **rejects a tampered card**.
§4.2 says the card is signed by the owner key as "JWS over JCS, the same format as A2A card signatures". Scenario 9
and T11 need cards that upstream A2A SDKs can also verify. A2A 1.0 §8.4 defines the signing input as the card
with `signatures` removed and default values removed under proto presence rules (§8.4.1), then JCS. The
shipping SDKs do something else: they parse the card into the v1.0 proto, which drops unknown fields, then
**recursively delete every empty string, empty list, empty object and null** (`_clean_empty` in a2a-python,
`cleanEmpty` in a2a-js), then apply JCS.

1. Which signer/verifier pairs agree, on what kinds of card?
2. Which **keyless** edits of a validly signed card does each verifier still accept? These are edits anyone on
   the path can make: a registry, a mirror, a relay serving the owner directory, a compromised CDN.
3. What rule should webway's signer and verifier follow?

## Method

`lab/card-sig-canon/`: `run.sh N SEED OUT` (needs a venv with `a2a-sdk[signing]` 1.3.0 and a `node_modules`
with `@a2a-js/sdk` 1.3.0, jose 6.2.17). It takes 4 min for N = 3000.

- `gen.py` generates random v1.0 cards in ProtoJSON. The base card is plain (interface, capabilities, one
  skill). Edge features are added independently: `pushNotifications:false` (30 %), `documentationUrl:""` (10 %),
  a bearer scheme plus a requirement with no scopes `{"schemes":{"bearer":{"list":[]}}}` (30 %), an mTLS scheme
  with no description (15 %), an OAuth scope with an empty description (15 %), an extension with random `params`
  that include `""`, `null`, `[]`, `{}`, ints, `1e21`, `2^53+1`, non-ASCII and non-BMP keys (50 %), an unknown
  top-level field (20 %), non-BMP text (20 %), and an empty string in `skills[0].examples` (10 %).
- **Signers** use one Ed25519 key (RFC 8032 test 1), `alg: EdDSA`.
  - `py`: the SDK signer. The served card is what the SDK's well-known route emits (`agent_card_to_dict`).
  - `js`: the SDK signer. The served card is `JSON.stringify` of the signed object.
  - `rs`: JWS over JCS of exactly the served JSON minus `signatures` (serde_json_canonicalizer 0.4,
    ed25519-dalek `verify_strict`). This is §4.2 read literally.
- **Verifiers**
  - `py_sdk`: the SDK client path (`parse_agent_card`, then `create_signature_verifier`).
  - `js_sdk`: `verifyAgentCardSignature`.
  - `py_spec`: §8.4.1 as written (proto presence via `MessageToDict`, no empty cleaning).
  - `rs_raw`: JCS of the received JSON minus `signatures`.
  - `rs_clean`: the SDK cleaning done on raw JSON, without a schema.
- `mutate.py` makes 17 edits of each served card, none of which needs the key. Two are benign (`none`, and
  `reserialize`, which re-sorts keys, adds whitespace and ASCII-escapes). The other 15 change what some reader of
  the card sees. For each verifier, a mutation counts only on cards whose unmutated form that verifier accepted.
- 3000 cards × 3 signers give 104 460 candidates (seed 20261112). The full tables are in
  `card-sig-canon/results.md`.

## Results

### 1. Interop: the two SDKs agree with each other, not with the spec text or a raw-JCS verifier

Acceptance of the card as served (n = 3000 per signer):

| signer | py_sdk | js_sdk | py_spec (§8.4.1 literal) | rs_raw | rs_clean |
|---|---|---|---|---|---|
| py SDK | 100 % | 100 % | 23.0 % | 23.0 % | 100 % |
| js SDK | 100 % | 100 % | 23.0 % | 18.9 % | 80.0 % |
| rs raw-JCS | 18.9 % | 18.9 % | 55.8 % | 100 % | 23.0 % |

- **Plain cards**, and cards whose only edge features are an explicit `false` or non-BMP text, verify under all
  five verifiers from all three signers: 100 %. Explicit `false` on an `optional` field is kept by everyone.
  UTF-16 key order and ES number formatting agree everywhere, including `1e21`. A big int becomes the same double
  everywhere.
- **Any empty value** splits the SDKs from both literal readings. Under `py_spec`/`rs_raw`, SDK-signed cards
  verify at 0 % when they contain a bearer requirement with no scopes, an mTLS scheme with no description, an
  OAuth scope with an empty description, `documentationUrl:""` or an empty `examples` item, and at 6 % with
  extension params. The reverse direction is also 0 % for these features.
- **Unknown fields**: the JS signer serves them without signing them (`rs_raw` 0/599 on those cards). The rs signer
  covers them, so both SDKs reject (0/599).
- `py_spec` rejects rs-signed cards that carry `"list": []`, because ProtoJSON omits empty repeated fields. A
  raw-JCS signer must therefore serve **ProtoJSON normal form** (camelCase, implicit defaults omitted) to be
  readable by a spec-literal verifier.
- **Portable cards** are 566 of 3000 rs-signed cards: raw JCS = SDK-cleaned JCS = ProtoJSON-roundtrip JCS, which
  means no empty value anywhere, no unknown field, and normal form. On these cards all five verifiers accept:
  566/566 for each verifier, and 566/566 after `reserialize`.

### 2. Keyless edits accepted (all signers pooled; percentages over cards the verifier accepted unmutated)

| edit | what a reader then sees | py_sdk | js_sdk | py_spec | rs_raw |
|---|---|---|---|---|---|
| add `securityRequirements:[{"schemes":{"mtls":{"list":[]}}}]` | a new auth requirement | **100 %** | **100 %** | 0 % | 0 % |
| drop a no-scope requirement (e.g. bearer) | auth requirement removed | **100 %** | **100 %** | n/a¹ | 0 % |
| add / drop `securitySchemes.mtls = {"mtlsSecurityScheme":{}}` | a scheme appears / disappears | **100 %** | **100 %** | 0 % | 0 % |
| add / drop an OAuth scope with `""` description | scope list changed | **100 %** | **100 %** | 0 % | 0 % |
| params: add key `""` / `[]` / `null` | extension config key appears | **100 %** | **100 %** | 0 % | 0 % |
| params: insert `""` at the head of a list | every positional index shifts | **100 %** | **100 %** | 0 % | 0 % |
| `skills[0].examples` insert `""` | example list changed | **100 %** | **100 %** | 0 % | 0 % |
| set an unknown top-level field (`webwayNode`) | anything outside v1.0 schema | **100 %** | **100 %** | **100 %** | 0 % |
| add legacy v0.3 `url` / `preferredTransport` | a v0.3 reader dials elsewhere | **100 %** | **100 %** | **100 %** | 0 % |
| duplicate key, evil value first (`{"name":"evil","name":…}`) | first-wins parsers read `evil` | 100 % | 100 % | 100 % | 100 % |
| add `supported_interfaces` (snake case) next to `supportedInterfaces` | proto-name readers dial evil | 0 % (parse error) | **100 %** | 0 % | 0 % |
| drop an explicit `pushNotifications:false` | — | 0 % | 0 % | 0 % | 0 % |

¹ No card that `py_spec` accepted had a requirement to drop.

These rates hold for **portable cards too** (566/566 accepted by both SDKs for add-requirement, add-mTLS,
unknown field and examples, and 69/69 for params). A careful signer cannot protect a card from SDK verifiers. The
weakness is in the verification rule, not in the signed bytes. The JS SDK documents that fields outside the
v1.0 schema are uncovered. The empty-value collapse of semantically meaningful elements is not documented. The
`dup_key` row holds because every verifier tested is last-wins. It only matters if some consumer parses
first-wins, and none tested here does.

### 3. Prior art and upstream status

- A2A#2122 (open, 48 comments) and a2a-js#627/#663 (open) track the **byte divergence**: SDK cleaning versus §8.4.1
  REQUIRED-field handling, the "field-level prune" versus "element collapse" question for
  `securityRequirements:[{}]`, and unknown-field scope. The working consensus (2026-10-07 comment) is that the SDKs
  "disagree only when a card has an empty value or an unknown field". Our 566/566 portable result reproduces
  this with 1.3.0 SDKs and an independent Rust verifier. Proposed TCK vectors: a2a-tck#245/#246.
- A keyword scan of the threads (attacker, keyless, integrity, inject, tamper, malleab) found no discussion of the
  **verifier-side** consequence measured here: under the pruning reading, a third party can add or remove
  no-scope security requirements, empty mTLS schemes, empty-description scopes and empty-valued extension params
  without invalidating the signature. The interim proposal there ("signers SHOULD avoid empty values") does not
  close it (section 2). Only a portion of the 48 comments was read in full.
- A2A#2249: the §8.4.2 example signature cannot be checked, because no key is published. We cannot use it as a vector.
- RFC 7515 (JWS), RFC 8785 (JCS), RFC 7493 (I-JSON: no duplicate member names), RFC 9864 (fully specified
  `Ed25519` alg). PyJWT 2.15.1 knows only `EdDSA` and jose 6 accepts both, so `alg: EdDSA` is required for SDK
  interop today.

## What applies to webway / recommendation

1. **Verifier (M1 step 2, T3/T6): raw JCS over the received JSON minus `signatures`**, `alg` pinned to `EdDSA`,
   key from the pinned owner key (never from `jku`), parsed with duplicate keys rejected (I-JSON). It rejected
   every semantic edit in this run (0 %) and accepted every benign reserialisation (100 %). Treat the card's
   protected content as the whole served object. Do **not** use the SDK rule, because a node would then accept a
   relay-altered `securityRequirements`, extension params or unknown fields.
2. **Signer: emit only portable cards.** That means ProtoJSON normal form, no `""`/`[]`/`{}`/`null` anywhere
   (including extension params), and no fields outside the v1.0 schema. Before signing, check that JCS(raw) =
   JCS(clean(raw)) = JCS(ProtoJSON roundtrip). Refuse to sign a card that fails the check. Such cards then verify
   under py/js SDKs, a §8.4.1-literal verifier and our raw verifier alike (566/566). Put webway data (node id,
   relay, supported ext versions) inside `capabilities.extensions[].params` or `supportedInterfaces`, never as
   top-level fields.
3. **Extension params semantics (all webway `ext/*/v0`):** absent, `""`, `[]`, `{}` and `null` MUST mean the same
   thing, and no list with positional meaning, because an SDK client that verified the card cannot tell them apart.
4. **Do not rely on third-party SDK verification for anything security-relevant.** At the HTTP edge (T11),
   document that an SDK client's "verified" card does not authenticate security requirements, scheme
   declarations or extension params. Webway clients must verify with rule 1.
5. Add conformance vectors (T4): one portable card that must verify, plus each section-2 edit of it, which must
   be rejected. Also add a duplicate-key card and a snake-case-shadow card, both of which must be rejected.

## What the planner should do next

- Put rules 1–3 into the identity/capability spec (T3) next to the card-signing text. Add the vectors (rule 5)
  under `conformance/vectors/card-sig/`. `lab/card-sig-canon` can generate them.
- Optional and outward-facing (owner's call): post the keyless-edit table to A2A#2122. The verifier-side angle
  seems to be missing there.
- Not tested: a2a-go and the Java SDK, the v0.3 compat signing path, and ES256 keys.
