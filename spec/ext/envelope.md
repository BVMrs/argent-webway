# `envelope/v0`: signed envelopes

| | |
|---|---|
| Status | **Draft** (v0, unstable until M1) |
| Extension URI | `https://github.com/BVMrs/argent-webway/spec/ext/envelope/v0` ([Q6](../../docs/due-diligence.md#q6-namespace-and-governance) option b) |
| Envelope version string | `webway-envelope/0` |
| Requirement prefix | `ENV-` |
| Test vectors | [`conformance/vectors/envelope/v0/`](../../conformance/vectors/envelope/v0/) |
| Depends on | A2A 1.0 (`a2a.proto` at tag `v1.0.1`, package `lf.a2a.v1`), RFC 8785 (JCS), RFC 7493 (I-JSON), RFC 8032 (Ed25519), BLAKE3, RFC 9562 (UUIDv7) |
| Referenced by | `profile.md`, `binding-webway-quic.md`, `capability.md`, `mailbox.md`, `provenance.md`, `audit.md` (all planned) |

## 1. Purpose and scope

Every A2A request, response and event that leaves a webway node travels inside a **signed envelope**. The
envelope proves which agent key produced it, which agent it is for, until when it may be acted on, and that
nobody on the path (relay, mailbox host, gateway, forwarder) changed it. Integrity is end to end between agent
keys, independent of how many hops or transports the envelope crosses.

This document specifies:

- the envelope's JSON structure and field formats ([§3](#3-envelope-structure)),
- the canonical form that is signed and hashed ([§4](#4-canonicalisation)),
- the signature and body binding ([§5](#5-signature-and-body-binding)),
- freshness ([§6](#6-freshness)), recipient binding ([§7](#7-recipient-and-operation-binding)) and replay handling
  ([§8](#8-replay-and-duplicates)),
- the receiver's verification procedure ([§9](#9-verification-procedure)) and the error model ([§10](#10-error-model)),
- rules for intermediaries ([§11](#11-intermediaries)) and versioning ([§12](#12-versioning)).

Out of scope, specified elsewhere:

- **Whether the sender may do what it asks.** Capability tokens travel in the envelope (`cap`), and this document
  makes them tamper-proof, but their format and evaluation belong to `capability/v0`. So does the check that the
  `from` key is certified by an owner the receiver trusts.
- **What provenance labels mean.** `prov` is carried and signed here, and its well-formedness is checked here
  ([§3.6](#36-prov)), but the trust computation belongs to `provenance/v0`.
- **Framing, stream mapping and transport authentication**: `binding-webway-quic.md`.
- **Store-and-forward and outbox behaviour** beyond the replay rules here: `mailbox/v0`.
- **Confidentiality.** Envelopes are signed, not encrypted. Sealed envelopes (HPKE) are a later extension (T15).

The design follows [due diligence §4.4 and §4.7.3](../../docs/due-diligence.md#44-message-and-task-model) and
decision [Q5](../../docs/due-diligence.md#q5-wire-encoding) (JSON + JCS + Ed25519). Where this document refines
the sketch there, [Appendix C](#appendix-c-changes-from-the-due-diligence-sketch) lists the change and why.

## 2. Conventions

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**,
**RECOMMENDED**, **MAY** and **OPTIONAL** are to be interpreted as described in BCP 14 ([RFC 2119], [RFC 8174])
when, and only when, they appear in all capitals.

Every normative statement has a stable ID, `ENV-nnn`, written as **ENV-nnn** (LEVEL) before the statement. IDs are
never reused or renumbered. A removed requirement keeps its ID with the note *withdrawn*. IDs are grouped by
section in blocks of 100 so sections can grow. [Appendix A](#appendix-a-requirement-index) lists every ID, its
level and what tests it.

Terms:

- **Node**: a process that holds keys and speaks the protocol on behalf of the agents it hosts.
- **Agent key**: the Ed25519 key of an agent. Agents do not hold their keys; their node does and signs for them.
- **Sender** / **receiver**: the nodes hosting the `from` and `to` agents.
- **Intermediary**: anything that carries an envelope without being its sender or receiver: relays, mailbox
  hosts, gateways, forwarders, audit stores.
- **Signed header**: the envelope object without its `sig` and `body` members ([§5.1](#51-signing-input)).
- **`now`**: the receiver's current time. **`SKEW`**, **`MAX_TTL`** and the other constants are in
  [§13](#13-constants).
- `JCS(x)`: the RFC 8785 canonical UTF-8 serialisation of JSON value `x`.
- `BLAKE3(b)`: the 32-byte BLAKE3 hash (default, unkeyed mode) of bytes `b`.

## 3. Envelope structure

An envelope is one JSON object. Example (line breaks added, `…` shortens values):

```json
{
  "v": "webway-envelope/0",
  "typ": "request",
  "op": "SendMessage",
  "from": "wwa:4f3w…",
  "to": "wwa:q2ya…",
  "id": "019a5d2e-7b40-7c3a-9d1e-0a1b2c3d4e5f",
  "ts": "2026-11-07T12:00:00Z",
  "exp": "2026-11-07T13:00:00Z",
  "ctx": { "contextId": "ctx-42" },
  "cap": { "access": "En0KEwoE…" },
  "prov": { "parts": { "/message/parts/0": { "taint": { "owners": ["did:key:z6Mk…"], "unverified": false } } } },
  "body_hash": "blake3:6a1f…",
  "body": { "message": { "messageId": "019a5d2e-…", "role": "ROLE_USER", "parts": [ { "text": "run the tests" } ] } },
  "sig": "Qm9…"
}
```

### 3.1 Members

| Member | JSON type | Presence | Meaning |
|---|---|---|---|
| `v` | string | REQUIRED | Envelope version. Exactly `webway-envelope/0` for this spec. |
| `typ` | string | REQUIRED | Envelope type: `request`, `response`, `event`, `error` or `ack` ([§3.3](#33-typ-and-op)). |
| `op` | string | REQUIRED | The operation the body belongs to ([§3.3](#33-typ-and-op)). |
| `from` | string | REQUIRED | Sender agent ID ([§3.2](#32-field-formats)). The signature is verified with this key. |
| `to` | string | REQUIRED | Recipient agent ID. |
| `id` | string | REQUIRED | Envelope ID, a UUIDv7. For a `request` whose body carries an A2A `Message`, equal to its `messageId`. |
| `ts` | string | REQUIRED | Creation time. A sanity check and ordering hint only, never the basis of freshness. |
| `exp` | string | REQUIRED | Sender-set expiry, the delivery TTL. After `exp + SKEW` nobody may act on the envelope. |
| `ctx` | object | OPTIONAL | Task context: `taskId`, `contextId`, `seq`, `inReplyTo` ([§3.4](#34-ctx)). |
| `cap` | object | OPTIONAL | Capability proofs: `access`, `mandate` ([§3.5](#35-cap)). |
| `prov` | object | CONDITIONAL | Per-Part provenance, REQUIRED when the body contains A2A Parts ([§3.6](#36-prov)). |
| `body_hash` | string | REQUIRED | `blake3:` + lowercase hex of `BLAKE3(JCS(body))`. |
| `body` | any JSON value | REQUIRED | The operation payload, in the pinned signer form ([§4.3](#43-pinned-signer-form-of-the-body)). |
| `sig` | string | REQUIRED | Ed25519 signature over the signing input ([§5.1](#51-signing-input)). |

**ENV-001** (MUST) An envelope MUST be a JSON object containing every REQUIRED member of [§3.1](#31-members), each
with the JSON type and format given in this section. A receiver MUST reject an envelope that does not as
`EnvelopeInvalid` (reason `missing-field` or `malformed-field`).

**ENV-002** (MUST) A receiver MUST treat members it does not know, at the top level and inside `ctx`, `cap` and
`prov`, as part of the signed header: it MUST include them when computing the signing input and MUST otherwise
ignore them. It MUST NOT reject an envelope because of them.

ENV-002 is what lets a minor revision add header members ([§12](#12-versioning)). A member whose meaning a receiver
must understand to process the envelope safely can only be added with a new major version.

### 3.2 Field formats

| Format | Rule | Example |
|---|---|---|
| Agent ID | `wwa:` followed by the 32-byte Ed25519 public key in RFC 4648 base32, **lowercase**, no padding (52 characters). | `wwa:aiaq…` |
| UUIDv7 | RFC 9562 UUID, version 7, variant `10`, in the lowercase hyphenated 8-4-4-4-12 form. | `019a5d2e-7b40-7c3a-9d1e-0a1b2c3d4e5f` |
| Timestamp | RFC 3339 in UTC with the `Z` suffix and 0, 3, 6 or 9 fractional digits: `YYYY-MM-DDTHH:MM:SS[.f{3,6,9}]Z`. Seconds are `00`–`59` (no leap second). This is the proto3 JSON form of `google.protobuf.Timestamp`. | `2026-11-07T12:00:00Z`, `2026-11-07T12:00:00.250Z` |
| Hash | `blake3:` followed by 64 lowercase hex digits. | `blake3:af13…` |
| Signature | The 64-byte Ed25519 signature in RFC 4648 §5 base64url, no padding (86 characters). | |

**ENV-010** (MUST) Agent IDs, UUIDs, timestamps, hashes and signatures MUST use exactly the formats in the table
above. A receiver MUST reject any other form, including uppercase letters where lowercase is required, padding, and
base32 or base64url strings whose unused trailing bits are not zero, as `EnvelopeInvalid` (reason
`malformed-field`). For `sig` the reason is `malformed-signature`.

Each value has exactly one valid string form, so string comparison and comparison of decoded values agree.

**ENV-011** (MUST) `exp` MUST be later than `ts`, and `exp − ts` MUST NOT exceed `MAX_TTL`. A receiver MUST reject
a violation as `EnvelopeInvalid` (reason `exp-not-after-ts` or `ttl-too-long`).

**ENV-012** (SHOULD) A sender SHOULD set `ts` to its current time and SHOULD choose `exp` per operation: short
(minutes) for interactive requests, longer (up to `MAX_TTL`) for work that may wait in a mailbox while the
recipient is offline. Answers that may be stored for duplicates are bound by ENV-522 instead.

### 3.3 `typ` and `op`

`typ` says what role the envelope plays:

| `typ` | Sent by | Body |
|---|---|---|
| `request` | the caller | An A2A request message (`SendMessageRequest`, `GetTaskRequest`, …) or an extension request. |
| `response` | the callee | The response to one request. `ctx.inReplyTo` is the request's `id`. |
| `event` | the callee | One streamed event (`StreamResponse`), or a task update delivered to a mailbox. `ctx.inReplyTo` is the originating request's `id` when there is one. |
| `error` | either side | An error object ([§10](#10-error-model)) answering one envelope. `ctx.inReplyTo` is that envelope's `id`. |
| `ack` | the callee | An acknowledgement without a result, e.g. the duplicate ack of [§8.4](#84-answering-duplicates). |

`op` names the operation: an A2A 1.0 method name (`SendMessage`, `SendStreamingMessage`, `GetTask`, `ListTasks`,
`CancelTask`, `SubscribeToTask`, the push-notification-config methods, `GetExtendedAgentCard`) or an operation
defined by a webway extension, written as `<extension URI>#<name>`. A `response`, `event`, `error` or `ack` carries
the `op` of the request it answers.

**ENV-020** (MUST) `typ` MUST be one of the five values above. A receiver MUST reject any other value as
`EnvelopeInvalid` (reason `malformed-field`).

**ENV-021** (MUST) A receiver MUST select the operation, and the schema it interprets `body` with, from the
signed `typ` and `op` only. It MUST NOT take them from transport framing, URL paths, headers or any other unsigned
source. If unsigned framing also names an operation and it differs, the receiver MUST reject the envelope as
`EnvelopeInvalid` (reason `op-mismatch`).

Several A2A request bodies have the same shape (`GetTaskRequest` and `CancelTaskRequest` both reduce to a task
name), so an unsigned operation name would let an intermediary turn a read into a cancel. ENV-021 closes that.

**ENV-022** (MUST) A receiver MUST reject an envelope whose `op` it does not implement in step 7 of
[§9](#9-verification-procedure), before the signer-form check (which needs the schema), with
`UnsupportedOperationError` (−32004, reason `unsupported-op`). For a `request`, the signature has been verified by
then, so the error is answered as a signed `error` envelope (ENV-620). An envelope of any other `typ` with an
unknown `op` is discarded without an answer (ENV-402) and the rejection is recorded (ENV-623).

"Implements" is a property of the receiver: the A2A operations it serves, plus the extension operations
(`<extension URI>#<name>`) of the extensions it declares in its Agent Card. An extension `op` is not implemented
just because it is well-formed.

### 3.4 `ctx`

| Member | Type | Meaning |
|---|---|---|
| `taskId` | string | The A2A task this envelope concerns. |
| `contextId` | string | The A2A context. |
| `seq` | integer | Per-task event sequence number (`event` envelopes), `0` ≤ `seq` ≤ 2^53 − 1. |
| `inReplyTo` | UUIDv7 | The `id` of the envelope this one answers (REQUIRED for `response`, `error` and `ack`). |

`ctx` lets audit logs, mailboxes and stream cursors index envelopes from the signed header alone, without the body.

**ENV-030** (MUST) When `body` carries a task ID or context ID at a location listed for the envelope's `op` in
[Appendix B](#appendix-b-body-locations-provisional), and `ctx` carries the corresponding member, the two MUST be
equal. A receiver MUST reject a mismatch as `EnvelopeInvalid` (reason `ctx-mismatch`).

**ENV-031** (MUST) A `response`, `error` or `ack` envelope MUST carry `ctx.inReplyTo`. A receiver MUST reject one
without it as `EnvelopeInvalid` (reason `missing-field`).

### 3.5 `cap`

| Member | Type | Meaning |
|---|---|---|
| `access` | string | The capability token authorising this request at the recipient (rooted in the resource owner's key). |
| `mandate` | string | OPTIONAL. The on-behalf-of mandate for delegated requests (S4). |

Both values are opaque to this document. `capability/v0` defines their encoding (Biscuit, base64url) and
evaluation, including binding the token's presenter to the verified `from` key.

**ENV-040** (MUST) A receiver MUST evaluate only capability tokens taken from the `cap` member of an envelope whose
signature it has verified, and MUST pass the verified `from` key to the capability evaluator as the presenter.
Tokens found anywhere else, including inside `body`, MUST NOT authorise anything.

**ENV-041** (MUST NOT) A sender MUST NOT place capability tokens or other credentials in `body`.

Because `cap` is inside the signed header, an intermediary cannot strip, swap or add tokens, and a token captured
from one envelope cannot be attached to an envelope signed by another key without failing the presenter check.

### 3.6 `prov`

```json
"prov": {
  "parts": {
    "<JSON Pointer to a Part in body>": {
      "taint": { "owners": ["did:key:z6Mk…", …], "unverified": false },
      "derivedFrom": ["blake3:…", …],
      "contentKind": "…"
    }
  }
}
```

`parts` maps an RFC 6901 JSON Pointer, evaluated against `body`, to that Part's provenance. `taint.owners` is a
non-empty array of owner identifiers (`did:key:` strings); `taint.unverified` is a boolean. `derivedFrom` and
`contentKind` are OPTIONAL and advisory. What they mean, and how a receiver computes trust from them, is
`provenance/v0`'s business. This section only fixes the container, so that taint is signed and cannot be stripped.

**ENV-050** (MUST) When `body` contains A2A Parts at the locations listed for the envelope's `op` in
[Appendix B](#appendix-b-body-locations-provisional), `prov.parts` MUST contain exactly one entry for each such
Part, and each entry MUST contain a well-formed `taint`. A receiver MUST reject an envelope with a Part that has no
entry, or an entry without `taint`, as `EnvelopeInvalid` (reason `missing-taint`).

**ENV-051** (MUST) Every key of `prov.parts` MUST be a JSON Pointer that resolves to a Part in `body`. A receiver
MUST reject a pointer that does not resolve, or resolves to something other than a Part, and a malformed `taint`,
as `EnvelopeInvalid` (reason `bad-prov`).

**ENV-052** (MUST NOT) A receiver MUST NOT use any member of `prov` to raise the trust it assigns to content. A
member named `trust`, or any other trust-like assertion, is ignored by trust computation (ENV-002 still applies).

## 4. Canonicalisation

### 4.1 Input rules

**ENV-100** (MUST) A receiver MUST parse an envelope as I-JSON ([RFC 7493]) and MUST reject, as `EnvelopeInvalid`
with the reason given, input that:

- is not well-formed JSON text in UTF-8 (`not-json`),
- contains invalid UTF-8, or a string escape that denotes a lone surrogate (`invalid-unicode`),
- contains an object with two members of the same name after unescaping, at any depth (`duplicate-key`),
- contains a number that, parsed as an IEEE 754 double, overflows to infinity (`number-out-of-range`),
- contains a number whose parsed double value is an integer of magnitude greater than 2^53 − 1, however it is
  spelled (`9007199254740992`, `1e16` and `9007199254740993.0` are all rejected) (`unsafe-integer`).

Values that can carry larger integers (proto `int64`, `uint64` and the fixed variants) are JSON strings, as the
proto3 JSON mapping already requires. `ctx.seq` is capped at 2^53 − 1, so it stays a number.

The `unsafe-integer` rule is on the value, not the spelling, so it is preserved by canonicalisation: every double
of magnitude 2^53 or more is an integer, so any accepted number is below 2^53 in magnitude, and its JCS form parses
again to the same value. `parse(JCS(parse(x)))` therefore succeeds whenever `parse(x)` does. That is what lets an
intermediary re-serialise an envelope (ENV-700), and a binary binding carry JCS bytes (ENV-111), without turning a
valid envelope into an invalid one.

**ENV-101** (MUST) A receiver MUST reject an envelope whose JCS serialisation is longer than `MAX_ENVELOPE_BYTES`
(`too-large`) or whose JSON nesting depth exceeds `MAX_DEPTH` (`too-deep`). It MAY reject received input longer
than twice `MAX_ENVELOPE_BYTES` before parsing it.

### 4.2 Canonical form

`JCS(x)` is defined by [RFC 8785]: object members sorted by the UTF-16 code units of their names, no insignificant
whitespace, strings escaped minimally (only `"`, `\`, and control characters U+0000–U+001F, using `\b \t \n \f \r`
where they exist and `\u00xx` with lowercase hex otherwise), non-ASCII characters emitted as UTF-8, and numbers
serialised as ECMAScript `Number.prototype.toString` does (so `1.0` → `1`, `-0` → `0`, `9.007199254740991e15` →
`9007199254740991`, `0.0000001` → `1e-7`).

**ENV-110** (MUST) Signers and verifiers MUST compute the signing input ([§5.1](#51-signing-input)) and `body_hash`
over `JCS` of the **parsed generic JSON value**, never over the bytes as received. A verifier MUST NOT decode
signed data into typed structures (such as `a2a.proto` messages) before verification, and MUST keep every member,
known or unknown, in the value it canonicalises.

As a consequence, whitespace, member order and escape spelling on the wire do not affect verification, and an
intermediary that re-serialises generic JSON does not break signatures.

**ENV-111** (MUST) A node MUST NOT emit or accept a canonicalisation other than RFC 8785 for envelope v0. Binary
encodings (Protobuf, CBOR) of signed data are never signed or hashed. A future binary binding MUST carry the JCS
bytes of the signed header and of the body as opaque byte strings.

### 4.3 Pinned signer form of the body

The proto3 JSON mapping allows several spellings of one message (field names, enum spelling, defaults). JCS cannot
reconcile these, because it canonicalises JSON, not protobuf. So v0 pins one spelling, the **signer form**:

- field names in `lowerCamelCase` (the proto3 `json_name`),
- enums as their string names (`"ROLE_USER"`, not `1`),
- singular scalar, string, `bytes` and enum fields **without explicit presence** omitted when equal to their
  default (`""`, `0`, `false`, the `*_UNSPECIFIED` enum value), and repeated and map fields omitted when empty.
  Fields with explicit presence (`optional` fields, members of a `oneof`, message-typed fields) are emitted when
  set, even to a default value: `{"text": ""}` is a valid Part, and `"historyLength": 0` is a meaningful setting,
- at most one member of each `oneof` (a Part is text, raw, url *or* data; a `SendMessageResponse` is a task *or* a
  message). Typed decoders disagree on a body with two (some reject it, others keep the last), so it is rejected
  before any of them sees it,
- `bytes` as standard base64 (RFC 4648 §4) with padding,
- `int64`, `uint64`, `fixed64` and their signed variants as JSON strings in decimal,
- `google.protobuf.Timestamp` in the timestamp format of [§3.2](#32-field-formats), and the canonical proto3 JSON
  forms for the other well-known types.

`google.protobuf.Struct` and `Value` fields (such as `metadata` and `Part.data`) are free JSON; their contents are
not subject to the signer form, only to [§4.1](#41-input-rules).

**ENV-120** (MUST) A signer MUST emit `body` in the signer form for the schema selected by `typ` and `op`.

**ENV-121** (MUST) A receiver MUST reject a body in which a field known to the schema is not in the signer form
(an enum as a number, a field under its proto name instead of its `json_name`, an explicit default value, a
wrongly encoded `bytes` or 64-bit integer, a number outside the field's range such as an `int32` beyond
±2^31, more than one member of a `oneof`) as `EnvelopeInvalid` (reason `signer-form`). Members the schema does not
know are kept and ignored (ENV-002, ENV-110).

The check is about rejecting ambiguity, not about schema validation in general: a receiver still validates the
body's semantics after verification, as the operation requires.

## 5. Signature and body binding

### 5.1 Signing input

The **signed header** is the envelope object with the members `sig` and `body` removed and every other member,
known or unknown, kept. The **signing input** is the byte string

```text
signing_input = ASCII("webway-envelope/0") || 0x00 || JCS(signed header)
```

The prefix separates envelope signatures from every other signature the same key may make (shared-document
changes, receipts, future versions). A JSON text never contains a raw `0x00` byte, so the split is unambiguous.

**ENV-200** (MUST) A sender MUST set `body_hash` to `blake3:` followed by the lowercase hex of `BLAKE3(JCS(body))`,
and `sig` to the base64url (no padding) Ed25519 signature ([RFC 8032], pure Ed25519, not Ed25519ph or Ed25519ctx)
of the signing input, made with the private key of the `from` agent.

**ENV-201** (MUST NOT) A node MUST NOT sign an envelope whose `from` is not an agent it hosts. A gateway that
brings unsigned content into the overlay signs as its own agent and marks the content's taint (`provenance/v0`); it
never signs as the original author.

### 5.2 Verification

Ed25519 implementations disagree on edge cases (non-canonical encodings, small-order points, cofactored or
cofactorless equations, see [Chalkias et al. 2020][ed25519-edge]). Envelope v0 pins the strict variant so that
every conforming verifier accepts exactly the same set of signatures.

**ENV-210** (MUST) A verifier MUST decode the `from` key and reject it, as `SignatureInvalid` (reason `weak-key`),
if its 32 bytes are not the canonical encoding of a point on the curve (decoding then re-encoding the point must
reproduce them) or if the point has small order (order dividing 8).

**ENV-211** (MUST) A verifier MUST verify `sig` over the signing input with the decoded `from` key using the
cofactorless equation `[S]B = R + [k]A`, and MUST reject, as `SignatureInvalid`:

- a signature whose scalar `S` is not less than the group order L (reason `non-canonical-signature`),
- a signature whose `R` is not a canonical point encoding or is of small order (reason `non-canonical-signature`),
- a signature for which the equation does not hold (reason `verification-failed`).

This matches `verify_strict` in `ed25519-dalek` 2.x.

**ENV-212** (MUST) A verifier MUST check that `body_hash` equals `blake3:` followed by the lowercase hex of
`BLAKE3(JCS(body))` and MUST reject a mismatch as `EnvelopeInvalid` (reason `body-hash-mismatch`).

Signature plus `body_hash` is equivalent to signing the body, but an audit log, receipt or mailbox index can keep
only the signed header (the body redacted) and still verify the signature, and refer to the body by a hash that is
known to match.

**ENV-213** (MUST) A store that keeps a signed header without its body (audit log, mailbox index, receipt) MUST
keep every member of the signed header, including unknown ones, so that the signature stays verifiable.

## 6. Freshness

Freshness comes from the sender's signed `exp`, not from `ts` and not from a global window. An envelope can wait in
a mailbox for hours and still be accepted, and a captured envelope becomes useless as soon as its own `exp` passes.
`SKEW` absorbs clock differences between owners and is small.

**ENV-300** (MUST) A receiver MUST reject an envelope when `now > exp + SKEW`, as `EnvelopeExpired`
(`retryable: false`).

**ENV-301** (MUST) A receiver MUST reject an envelope when `ts > now + SKEW`, as `EnvelopeNotYetValid`
(`retryable: true`, `retryAfter` = the whole seconds until `ts − SKEW`, rounded up).

**ENV-302** (MUST NOT) A receiver MUST NOT reject an envelope because `now − ts` is large. Age is limited only by
`exp` (ENV-300) and `MAX_TTL` (ENV-011).

**ENV-303** (MUST) Comparisons in this section MUST use the full precision of the timestamps. Both bounds are
inclusive: an envelope with `now = exp + SKEW` or `ts = now + SKEW` is fresh.

**ENV-304** (MUST) A sender, and any outbox or mailbox host acting for it, MUST stop delivery attempts once
`now > exp`, and the sender MUST report the message to the originating agent as expired. Retries MUST resend the
original signed envelope (ENV-500); a sender MUST NOT extend a message's life by re-signing it with a later `exp`.

**ENV-305** (SHOULD) A mailbox host SHOULD discard envelopes whose `exp + SKEW` has passed instead of delivering
them.

## 7. Recipient and operation binding

**ENV-400** (MUST) A receiver MUST reject an envelope whose `to` is not an agent it hosts, as `EnvelopeInvalid`
(reason `wrong-recipient`). It MUST NOT process or forward it on behalf of that agent.

Because `to` is signed, an intermediary cannot redirect an envelope to a different agent, even one on the same
node.

**ENV-401** (MUST) A node that receives a `response`, `error` or `ack` MUST discard it, without answering, unless
its `from` equals the `to` of an envelope the node sent, its `to` equals that envelope's `from`, and its
`ctx.inReplyTo` equals that envelope's `id`. An `event` with `ctx.inReplyTo` is subject to the same check. The
discard is recorded with reason `unsolicited`.

**ENV-402** (MUST NOT) A node MUST NOT answer a `response`, `event`, `error` or `ack` envelope with an `error`
envelope. This prevents error loops between nodes.

## 8. Replay and duplicates

A lost acknowledgement makes the sender resend a byte-identical envelope, and a receiver cannot tell that apart
from a replay by an attacker. v0 treats both the same way: a duplicate is never processed twice and gets the
original answer. There is no separate "replayed" error. A replay after the acceptance horizon is
`EnvelopeExpired`.

### 8.1 Dedupe key and entries

The **dedupe key** of an envelope is the pair (decoded 32-byte `from` key, `id`). A **dedupe entry** records the
dedupe key, `BLAKE3(signing input)` (the **header digest**), `exp`, and the response the receiver sent.

**ENV-500** (MUST) A sender MUST NOT use the same `id` for two envelopes with different signed headers under the
same `from` key. A retry MUST resend the identical envelope (same signed header and `sig`; re-serialised generic
JSON is acceptable).

**ENV-501** (MUST) A receiver MUST create a dedupe entry for every `request` envelope it accepts for processing,
unless processing ends in a retryable error (ENV-521), and MUST NOT create one for an envelope that failed any of verification steps 1–7 ([§9](#9-verification-procedure)).

**ENV-502** (MUST) A receiver MUST keep each dedupe entry at least until `now > exp + SKEW` for that entry.

**ENV-503** (MUST) Dedupe entries MUST be durable and MUST be written in the same atomic transaction as the task
state or event that processing the envelope creates, before the response or acknowledgement is sent. After a
crash and restart, a retry of an envelope whose effects were persisted MUST be treated as a duplicate.

**ENV-504** (MUST) A receiver MUST keep a **purge watermark** `W`: the largest `exp + SKEW` of any dedupe entry it
has removed, initially the time it first started. `W` MUST be durable and MUST never decrease. A receiver MUST
reject an envelope with `exp + SKEW ≤ W` as `EnvelopeExpired`, whatever `now` says.

The watermark keeps ENV-502 sound when the receiver's clock steps backwards: an envelope whose entry has been
purged can never become fresh again.

**ENV-505** (MUST) A receiver MUST process at most one envelope per dedupe key at a time. A duplicate that arrives
while the original is still being processed MUST either wait for the original's response and get it (as in
[§8.4](#84-answering-duplicates)) or be dropped without a response.

### 8.2 Classifying an envelope

After verification steps 1–7 succeed, the receiver looks up the dedupe key:

| Lookup result | Classification | Action |
|---|---|---|
| no entry | **new** | Continue to authorisation and processing (step 9). |
| entry with the same header digest | **duplicate** | Do not process. Answer as in [§8.4](#84-answering-duplicates). |
| entry with a different header digest | **id reuse** | Do not process. Reject as `EnvelopeInvalid` (reason `id-reuse`) and record an anomaly. |

**ENV-510** (MUST) A receiver MUST classify every verified `request` envelope as in the table above and MUST NOT
process a duplicate or an id reuse.

**ENV-511** (MUST) The header digest comparison MUST be over the signing input (canonical form), so a duplicate
that an intermediary re-serialised is still recognised as a duplicate.

**ENV-512** (MUST) A node MUST deduplicate received `response`, `event`, `error` and `ack` envelopes by dedupe key
as well, delivering each to the local agent at most once, and MUST NOT answer duplicates of them.

### 8.3 Responses that may be stored

**ENV-520** (MUST) A receiver MUST store, in the dedupe entry, the signed envelope it sent in answer to the
request: the `response`, or a signed `error` for a non-retryable failure in authorisation or processing.

**ENV-521** (MUST NOT) A receiver MUST NOT create a dedupe entry for a request that failed with a retryable error
(for example `MailboxFull` or a transient storage failure), so that the sender's retry is processed as new.

**ENV-522** (MUST) The `exp` of an answer that may be stored under ENV-520 MUST be at least the `exp` of the request
it answers. If that would make the answer's `exp − ts` exceed `MAX_TTL` (the receiver's clock is behind the
sender's), the receiver MUST set the answer's `ts` to its `exp − MAX_TTL`. That `ts` is no later than the
request's `ts`, so the sender accepts it (ENV-301).

A stored answer is replayed byte for byte (ENV-530) to every retry until the request's `exp + SKEW`, and the sender
retries until the request's `exp` (ENV-304). ENV-522 keeps the stored answer fresh for as long as a retry can
arrive. Without it, a lost response to a long-lived request would be replaced by an expired copy on every retry,
and the result of work that did run would never be delivered.

### 8.4 Answering duplicates

**ENV-530** (MUST) A receiver MUST answer a duplicate with the stored envelope byte for byte (same `id`, same
`sig`), not with a newly signed one.

**ENV-531** (MUST) If the duplicate arrived over a connection that the binding did not authenticate as the
`from` agent's node or as a mailbox host delivering for the receiver's owner, the receiver MUST NOT send the
stored envelope. It MUST instead send a signed `ack` envelope whose body is
`{"duplicateOf": "<id of the duplicate>", "responseBodyHash": "<body_hash of the stored envelope>"}`.

For a `SendStreamingMessage` duplicate, the stored envelope is the first response of the stream (the `Task`). The
caller resumes the stream with `SubscribeToTask` and `fromSeq` (`mailbox/v0`).

## 9. Verification procedure

A receiver handles an incoming envelope in the following steps. Steps 1–7 depend only on the envelope, the
receiver's hosted agents, `now` and the watermark `W`. Steps 8–9 use the dedupe store.

1. **Parse** as I-JSON within the size and depth limits (ENV-100, ENV-101).
2. **Version**: if `v` is present and is a string other than `webway-envelope/0`, A2A `VersionNotSupportedError`
   (ENV-800). A missing `v`, or one that is not a string, is a structure error (ENV-001, `missing-field` or
   `malformed-field`).
3. **Structure**: required members, types and formats (ENV-001, ENV-010, ENV-011, ENV-020, ENV-031).
4. **Signature** over the signing input with the `from` key (ENV-210, ENV-211).
5. **Body binding**: `body_hash` (ENV-212).
6. **Recipient and freshness**: `to` (ENV-400), `exp`, `ts` and the watermark (ENV-300, ENV-301, ENV-504).
7. **Operation, body form and header consistency**: known `op` and framing agreement (ENV-022, ENV-021), signer
   form (ENV-121), `ctx` consistency (ENV-030) and `prov` (ENV-050, ENV-051).
8. **Dedupe** (ENV-510).
9. **Hand-off** to capability evaluation (`capability/v0`), provenance computation (`provenance/v0`) and the
   operation.

**ENV-600** (MUST) A receiver MUST complete steps 1–7 successfully before step 8, and step 8 before step 9. It
MUST NOT process, store as a dedupe entry, forward to an agent or acknowledge as accepted an envelope that failed
any of steps 1–8.

**ENV-601** (MAY) A receiver MAY perform steps 1–7 in any order (for example checking `to` and `exp` before the
signature to save work). When an envelope has several defects, it MAY report the error of any failing step.

Every test vector has exactly one defect, so its expected error does not depend on the order. In particular, an
invalid case that does not expect `SignatureInvalid` carries a valid signature wherever one can be checked.

**ENV-602** (MUST) A receiver MUST NOT use any member of an envelope (for authorisation, routing to an agent,
storage, or display) before the envelope has passed steps 1–7, except to perform those steps and to log the
rejection.

## 10. Error model

### 10.1 Errors

Errors reuse the A2A error object (`code`, `message`, `data`) in the JSON-RPC style. The profile registers webway's
own codes; the codes below are **provisional** until `profile.md` allocates the range
([open question 3](#open-questions)).

| Name | Code | `retryable` | When |
|---|---|---|---|
| `EnvelopeInvalid` | −33001 | false | Parsing, structure, format, body binding, recipient, body form, `prov`, `ctx`, id reuse. |
| `SignatureInvalid` | −33002 | false | Weak key, non-canonical signature, verification failure. |
| `EnvelopeExpired` | −33003 | false | `now > exp + SKEW`, or `exp + SKEW ≤ W`. |
| `EnvelopeNotYetValid` | −33004 | true | `ts > now + SKEW`. |
| A2A `VersionNotSupportedError` | −32009 | false | Unknown `v`. `data.supported` lists the versions the receiver accepts. |
| A2A `UnsupportedOperationError` | −32004 | false | Unknown `op` (ENV-022). |

The error object:

```json
{
  "code": -33001,
  "message": "envelope invalid: body-hash-mismatch",
  "data": { "type": "EnvelopeInvalid", "reason": "body-hash-mismatch", "retryable": false }
}
```

`data.type` is the name from the table, `data.reason` one of the reasons in [§10.2](#102-reasons), `data.retryable`
a boolean, and `data.retryAfter` (OPTIONAL) a non-negative integer number of seconds. `message` is for humans and
MUST NOT be parsed.

**ENV-610** (MUST) Every error a receiver returns for an envelope MUST carry `data.type`, `data.reason` and
`data.retryable` as in [§10.1](#101-errors) and [§10.2](#102-reasons).

**ENV-611** (MUST) Errors MUST NOT echo the rejected envelope's `body`, `cap` or `prov`, nor contain a newly
computed signature over any part of it.

### 10.2 Reasons

| Error | Reasons |
|---|---|
| `EnvelopeInvalid` | `not-json`, `invalid-unicode`, `duplicate-key`, `number-out-of-range`, `unsafe-integer`, `too-large`, `too-deep`, `missing-field`, `malformed-field`, `malformed-signature`, `exp-not-after-ts`, `ttl-too-long`, `body-hash-mismatch`, `wrong-recipient`, `op-mismatch`, `signer-form`, `ctx-mismatch`, `missing-taint`, `bad-prov`, `id-reuse` |
| `SignatureInvalid` | `weak-key`, `non-canonical-signature`, `verification-failed` |
| `EnvelopeExpired` | `expired`, `below-watermark` |
| `EnvelopeNotYetValid` | `ts-in-future` |
| `VersionNotSupportedError` | `unsupported-version` |
| `UnsupportedOperationError` | `unsupported-op` |

New reasons can be added in minor versions. A receiver that gets an unknown reason MUST treat it by its `data.type`
and `data.retryable` alone.

### 10.3 How errors travel

**ENV-620** (MUST) An error for an envelope that passed step 4 (signature) and whose `to` is an agent the receiver
hosts MUST be sent as an `error` envelope, signed by that agent, with `to` = the failed envelope's `from` and
`ctx.inReplyTo` = its `id`. A `wrong-recipient` rejection (ENV-400) cannot be signed, because the node hosts no
agent it could sign as (ENV-201). It is reported unsigned at the binding level, as in ENV-621.

**ENV-621** (SHOULD NOT) An error for an envelope that failed before or at step 4 SHOULD NOT be sent as a signed
envelope, because its `from` is unauthenticated. The receiver SHOULD report it as an unsigned error at the binding
level and MUST NOT send it to any address other than the connection it came from.

**ENV-622** (MUST NOT) A sender MUST NOT treat an unsigned error, or a signed one that fails verification, as
final, unless the binding authenticated the connection it arrived on as the recipient's node. It MAY back off, and
it MAY keep retrying the original envelope until `exp`.

ENV-622 stops a relay or mailbox host from forging `EnvelopeExpired` or `SignatureInvalid` to make a sender give up.

**ENV-623** (SHOULD) Every rejection SHOULD be recorded in the receiver's audit log with the error type, reason,
the header digest if it could be computed, and the transport peer (`audit/v0`).

## 11. Intermediaries

**ENV-700** (MUST) An intermediary MUST forward an envelope as received, or as a re-serialisation of the same
generic JSON value. It MUST NOT add, remove or change any member, including unknown ones, and MUST NOT decode the
envelope or its body into typed structures and re-encode them.

**ENV-701** (MUST NOT) An intermediary MUST NOT re-sign, counter-sign in place or "repair" an envelope. Metadata it
needs to add (routing, mailbox sequence numbers) goes in the binding's framing, outside the envelope.

**ENV-702** (SHOULD) An intermediary that can parse envelopes SHOULD drop those that fail steps 1–5, or whose
`exp + SKEW` has passed, rather than store or forward them, and SHOULD NOT rely on its own check: the receiver
always verifies.

## 12. Versioning

The envelope version is `v`. This document defines `webway-envelope/0`. The extension URI ends in `/v0`.

- **Minor revisions** of v0 may add OPTIONAL header members that a receiver can safely ignore, new `op` values
  that receivers reject cleanly (ENV-022), new error reasons and new test vectors. New `typ` values are not minor:
  a v0 receiver rejects an unknown `typ` as `malformed-field` (ENV-020), and answers it (unsigned, ENV-621) rather
  than ignoring it as ENV-402 does for the known answer types. So a new `typ` needs a major version. They never change the
  signing input rules or the meaning of existing members.
- **A major revision** (`webway-envelope/1`) is needed for any change a v0 receiver could not safely ignore. A new
  major gets a new signing-input prefix, so a signature can never be valid under two versions.

**ENV-800** (MUST) A receiver MUST reject an envelope whose `v` it does not support as A2A
`VersionNotSupportedError` (−32009) with `data.supported` listing the envelope versions it accepts. It MUST NOT
try to verify such an envelope under another version's rules.

**ENV-801** (MUST) A node that supports `envelope/v0` MUST declare the extension URI in its Agent Card. Peers in the
overlay MUST treat it as required (A2A §4.6): there is no unsigned fallback inside the overlay.

## 13. Constants

| Name | Value | Notes |
|---|---|---|
| `SKEW` | 300 s | Clock tolerance, applied on both sides of `now`. |
| `MAX_TTL` | 604 800 s (7 days) | Upper bound on `exp − ts`. Bounds dedupe storage. |
| `MAX_ENVELOPE_BYTES` | 1 048 576 (1 MiB) | Length of `JCS(envelope)`. Parts over 64 KiB go by blob reference (`blob/v0`). |
| `MAX_DEPTH` | 64 | Nesting depth of arrays and objects, the envelope object itself being depth 1. |

**ENV-900** (MUST) Nodes MUST use the constants above. A deployment MAY lower `MAX_TTL` for envelopes it sends,
but receivers MUST accept any `exp − ts` up to the value above.

## 14. Security considerations

- **What a signature proves.** A valid envelope proves that the holder of the `from` key produced exactly this
  header and body for this `to`, op and lifetime. It does not prove that the key belongs to anyone in particular
  (that is the owner binding in `capability/v0`), that the sender may do what it asks (capabilities), or that the
  content is true or safe to follow (provenance and the prompt-injection rules).
- **Relays and mailbox hosts** can drop, delay (up to `exp`), reorder and duplicate envelopes, and observe
  metadata and, until sealed envelopes exist, bodies. They cannot forge, alter, redirect, re-type or extend the
  life of an envelope, and cannot make a receiver process one twice.
- **Replay** inside the acceptance horizon returns the stored answer, which is `to`-bound to the original sender
  and was already visible on the wire, or a bodiless `ack` to unauthenticated connections (ENV-531). Outside the
  horizon it is `EnvelopeExpired`. Clock rollback on the receiver is covered by the watermark (ENV-504).
- **Clock skew.** A receiver whose clock runs ahead by more than `SKEW` rejects fresh envelopes near their `exp`;
  one that runs behind accepts envelopes up to its own error past `exp + SKEW`. Nodes SHOULD keep clocks
  synchronised (NTP). The watermark keeps a rollback from reopening the replay window.
- **Equivocation.** A sender that signs two different envelopes with one `id` gets `id-reuse` on the second; the
  anomaly is logged and can be used as evidence against that key.
- **Signature malleability** is ruled out by the strict verification of ENV-211, so a third party cannot produce a
  second valid `sig` for the same header. Dedupe does not depend on it anyway: it keys on `(from, id)` and compares
  the canonical header, not `sig`.
- **Type confusion** between operations is prevented by signing `typ` and `op` (ENV-021), and cross-protocol use of
  a signature by the signing-input prefix ([§5.1](#51-signing-input)).
- **Parser differentials** (duplicate keys, lone surrogates, huge numbers, deep nesting) are classic ways to make a
  verifier and an application see different documents. ENV-100 and ENV-101 reject them up front, and ENV-110
  ensures the verified value is the value the application uses.
- **Denial of service.** Signature verification is cheap but not free. Receivers can check `to`, `exp` and size
  before the signature (ENV-601) and rate-limit per transport peer.
- **Privacy.** Signed headers are kept in audit logs and mailbox indexes; they reveal who talks to whom and when.
  Bodies can be redacted (ENV-213) without breaking verification.

## Open questions

1. **Signing-input prefix.** The prefix ([§5.1](#51-signing-input)) is not in the due-diligence sketch. It costs
   nothing and blocks cross-protocol signature reuse, but it makes the envelope signature differ from a plain
   "Ed25519 over JCS" that generic JWS/JCS tooling would produce. Keep it, or drop it and rely on `v` alone?
2. **Encodings of identifiers and hashes.** `wwa:` uses lowercase RFC 4648 base32 and `body_hash` uses hex. iroh
   displays `NodeId`s in its own base32 variant, and `blob/v0` has not chosen its hash encoding. One encoding for all
   keys and all hashes across the spec should be settled in the profile before M1.
3. **Error code range.** −33001…−33004 are placeholders. `profile.md` should allocate one block for all webway
   errors and define the mapping to HTTP status and gRPC codes for the edge.
4. **Signer-form checking needs the schema.** ENV-121 requires the receiver to know the A2A schema for every `op`.
   That ties envelope verification to the pinned `a2a.proto` revision. Should a receiver that does not know a
   message type (e.g. an extension `op`) skip the check, or reject?
5. **Body locations.** [Appendix B](#appendix-b-body-locations-provisional) lists where Parts, task IDs and context
   IDs live per `op`. It belongs in `profile.md`, and `provenance/v0` may prefer taint inside `Part.metadata`
   (simpler for A2A-native tools, but not visible in a body-redacted header).
6. **`MAX_ENVELOPE_BYTES` and `MAX_TTL`.** 1 MiB and 7 days are first guesses. Long-offline peers (S5) may want
   longer TTLs; dedupe storage grows with `MAX_TTL` × request rate.
7. **Response caching for streams.** ENV-530 stores only the first response of a streaming request. Is replaying
   the stream from `seq` 0 on a duplicate more useful than requiring `SubscribeToTask`?
8. **Key rotation and revocation of agent keys.** An envelope signed by a key revoked after `ts` but before
   receipt: accept (it was valid when signed) or reject? This depends on `capability/v0` and is left to it.
9. **Multiple recipients.** v0 has one `to`. Group delivery (shared docs, fan-out) would need either one envelope
   per recipient or a recipient set, which interacts with sealed envelopes and MLS.
10. **Sealed envelopes (T15).** Whether sealing wraps the whole signed envelope (sign-then-encrypt, hides `from` from
    the mailbox host) or only the body (keeps headers routable) is open and affects ENV-531 and audit.

## Appendix A. Requirement index

"Vectors" names the file in `conformance/vectors/envelope/v0/` with at least one case for the requirement.
"Harness" means the requirement involves time, state across restarts, transports or more than one node and is
tested by the black-box harness (T4), not by a pure vector.

| ID | Level | Topic | Tested by |
|---|---|---|---|
| ENV-001 | MUST | required members | `envelopes.json` |
| ENV-002 | MUST | unknown members kept and signed | `envelopes.json` |
| ENV-010 | MUST | field formats | `envelopes.json` |
| ENV-011 | MUST | `exp` after `ts`, `MAX_TTL` | `freshness.json`, `envelopes.json` |
| ENV-012 | SHOULD | choice of `ts`, `exp` | n/a |
| ENV-020 | MUST | `typ` values | `envelopes.json` |
| ENV-021 | MUST | operation from signed `typ`/`op` | `envelopes.json`, harness |
| ENV-022 | MUST | unknown `op` | `envelopes.json`, `replay.json` |
| ENV-030 | MUST | `ctx` matches body | `envelopes.json` |
| ENV-031 | MUST | `inReplyTo` on answers | `envelopes.json` |
| ENV-040 | MUST | tokens only from signed `cap` | `envelopes.json`, harness |
| ENV-041 | MUST NOT | no credentials in body | harness |
| ENV-050 | MUST | taint for every Part | `envelopes.json` |
| ENV-051 | MUST | `prov` pointers resolve | `envelopes.json` |
| ENV-052 | MUST NOT | `prov` never raises trust | `envelopes.json` (kept, ignored), provenance vectors (T13) |
| ENV-100 | MUST | I-JSON input | `jcs.json`, `envelopes.json` |
| ENV-101 | MUST | size and depth limits | `jcs.json`, `envelopes.json` (depth), harness (size) |
| ENV-110 | MUST | canonicalise the generic value | `jcs.json`, `envelopes.json` |
| ENV-111 | MUST | JCS only | `jcs.json` |
| ENV-120 | MUST | signer emits signer form | `envelopes.json` (valid cases) |
| ENV-121 | MUST | reject non-signer form | `envelopes.json` |
| ENV-200 | MUST | `body_hash` and `sig` | `envelopes.json` |
| ENV-201 | MUST NOT | sign only for hosted agents | harness |
| ENV-210 | MUST | weak keys | `envelopes.json` |
| ENV-211 | MUST | strict verification | `envelopes.json` |
| ENV-212 | MUST | `body_hash` check | `envelopes.json` |
| ENV-213 | MUST | keep full signed header | `header-only.json` |
| ENV-300 | MUST | expiry | `freshness.json`, `envelopes.json`, `replay.json` |
| ENV-301 | MUST | future `ts` | `freshness.json`, `envelopes.json` |
| ENV-302 | MUST NOT | no age limit from `ts` | `freshness.json`, `envelopes.json` |
| ENV-303 | MUST | inclusive, full precision | `freshness.json`, `envelopes.json` |
| ENV-304 | MUST | sender stops at `exp` | harness |
| ENV-305 | SHOULD | mailbox discards expired | harness |
| ENV-400 | MUST | recipient binding | `envelopes.json` |
| ENV-401 | MUST | unsolicited answers | `replay.json` |
| ENV-402 | MUST NOT | no errors for answers | `replay.json` |
| ENV-500 | MUST | one header per id | `replay.json` |
| ENV-501 | MUST | when entries are created | `replay.json` |
| ENV-502 | MUST | entry lifetime | `replay.json` |
| ENV-503 | MUST | durable, atomic entries | harness |
| ENV-504 | MUST | purge watermark | `replay.json`, `freshness.json`, `envelopes.json` |
| ENV-505 | MUST | one at a time per key | harness |
| ENV-510 | MUST | classification | `replay.json` |
| ENV-511 | MUST | canonical header digest | `replay.json` |
| ENV-512 | MUST | dedupe answers | `replay.json` |
| ENV-520 | MUST | stored response | `replay.json` |
| ENV-521 | MUST NOT | no entry on retryable error | `replay.json` |
| ENV-522 | MUST | stored answer outlives the request | `replay.json` |
| ENV-530 | MUST | byte-identical answer | `replay.json` |
| ENV-531 | MUST | duplicate ack for unauthenticated peers | `replay.json` |
| ENV-600 | MUST | step order | `replay.json` |
| ENV-601 | MAY | order within steps 1–7 | n/a |
| ENV-602 | MUST | no use before verification | harness |
| ENV-610 | MUST | error `data` | all vector files (expected errors) |
| ENV-611 | MUST | errors do not echo | harness |
| ENV-620 | MUST | signed errors after step 4 | harness |
| ENV-621 | SHOULD NOT | unsigned errors before step 4 | harness |
| ENV-622 | MUST NOT | unsigned errors not final | harness |
| ENV-623 | SHOULD | audit rejections | harness |
| ENV-700 | MUST | forward unchanged | `envelopes.json` (re-serialised cases), harness |
| ENV-701 | MUST NOT | no re-signing | harness |
| ENV-702 | SHOULD | intermediaries drop bad envelopes | harness |
| ENV-800 | MUST | unknown version | `envelopes.json` |
| ENV-801 | MUST | declared, required in overlay | harness |
| ENV-900 | MUST | constants | `freshness.json` |

## Appendix B. Body locations (provisional)

Locations are JSON Pointer patterns, `*` matching any array index. They follow `a2a.proto` at tag `v1.0.1` (package `lf.a2a.v1`).
`profile.md` will take this table over ([open question 5](#open-questions)).

| `typ` / `op` | Parts at | `taskId` at | `contextId` at |
|---|---|---|---|
| `request` `SendMessage`, `SendStreamingMessage` | `/message/parts/*` | `/message/taskId` | `/message/contextId` |
| `response` `SendMessage`, `SendStreamingMessage`, `SubscribeToTask` (body is `SendMessageResponse` / `StreamResponse`) | `/message/parts/*`, `/task/status/message/parts/*`, `/task/artifacts/*/parts/*`, `/task/history/*/parts/*` | `/message/taskId`, `/task/id` | `/message/contextId`, `/task/contextId` |
| `event` (body is `StreamResponse`) | as for the response, plus `/statusUpdate/status/message/parts/*`, `/artifactUpdate/artifact/parts/*` | as for the response, plus `/statusUpdate/taskId`, `/artifactUpdate/taskId` | as for the response, plus `/statusUpdate/contextId`, `/artifactUpdate/contextId` |
| `response` `GetTask`, `CancelTask` (body is `Task`) | `/status/message/parts/*`, `/artifacts/*/parts/*`, `/history/*/parts/*` | `/id` | `/contextId` |
| `request` `GetTask`, `CancelTask`, `SubscribeToTask` | none | `/id` | none |
| `response` `ListTasks` (body is `ListTasksResponse`) | `/tasks/*/status/message/parts/*`, `/tasks/*/artifacts/*/parts/*`, `/tasks/*/history/*/parts/*` | none (many tasks) | none |
| other operations | none | none | none |

In `a2a.proto` v1.0.1 the only bodies that carry Parts are `SendMessageRequest`, `Message`, `Task` (and therefore
`ListTasksResponse`), `SendMessageResponse`, `StreamResponse` and the two update events. The table covers every
operation whose request or answer contains one of them.

## Appendix C. Changes from the due-diligence sketch

| Change | Why |
|---|---|
| Added signed `typ` and `op`. | Without them the operation comes from unsigned framing, and same-shaped bodies (`GetTask`/`CancelTask`) could be re-typed by an intermediary ([§3.3](#33-typ-and-op)). |
| Signing input has a `webway-envelope/0` + `0x00` prefix. | Domain separation from other signatures by the same key ([§5.1](#51-signing-input), [open question 1](#open-questions)). |
| Ed25519 verification pinned to the strict variant. | Implementations otherwise disagree on which signatures are valid ([§5.2](#52-verification)). |
| Purge watermark. | Keeps the dedupe horizon sound if the receiver's clock steps back ([§8.1](#81-dedupe-key-and-entries)). |
| `id-reuse` handling for the same `(from, id)` with a different header. | The sketch only covered byte-identical duplicates ([§8.2](#82-classifying-an-envelope)). |
| A stored answer's `exp` is at least the request's `exp` (ENV-522). | The sketch replays stored answers byte for byte but did not bound their lifetime, so a lost response to a long-lived request could only ever be replayed expired ([§8.3](#83-responses-that-may-be-stored)). |
| `EnvelopeNotYetValid` (retryable) for `ts` in the future. | It is a clock problem that resolves by waiting, unlike `EnvelopeInvalid`. |
| Duplicate ack is a signed `ack` envelope with a body. | Keeps "every envelope has a body and a signature" without a special bodiless form ([§8.4](#84-answering-duplicates)). |
| `prov` is keyed by JSON Pointer into `body`. | Frame-independent addressing of Parts, so taint stays in the signed header ([§3.6](#36-prov)). |

[RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119
[RFC 8174]: https://www.rfc-editor.org/rfc/rfc8174
[RFC 7493]: https://www.rfc-editor.org/rfc/rfc7493
[RFC 8785]: https://www.rfc-editor.org/rfc/rfc8785
[RFC 8032]: https://www.rfc-editor.org/rfc/rfc8032
[ed25519-edge]: https://eprint.iacr.org/2020/1244
