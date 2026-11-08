# `audit/v0`: hash-chained audit log, checkpoints, receipts

| | |
|---|---|
| Status | **Draft** (v0, unstable until M1). Roadmap track T9. |
| Extension URI | `https://github.com/BVMrs/argent-webway/spec/ext/audit/v0` |
| Object versions | `webway-audit-entry/0`, `webway-checkpoint/0`, `webway-receipt/0`, `webway-audit-evidence/0` |
| Requirement prefix | `AUD-` ([conventions](../conventions.md)) |
| Test vectors | [`conformance/vectors/audit/`](../../conformance/vectors/audit/) |
| Depends on | `envelope/v0` (JCS, signing rules, header digest), `capability/v0` (identifiers, node certificates), `profile.md` (error range, extension activation), RFC 9162 §2.1 (Merkle tree algorithms), RFC 8785 (JCS), RFC 8032 (Ed25519), BLAKE3 |
| Requirement R9 | Due diligence [§1.2](../../docs/due-diligence.md#12-requirements-these-imply) and [§4.7.5](../../docs/due-diligence.md#475-audit-log) |
| Threats closed | Threat model AUD-1…AUD-9, gaps G6 (fork detection between counterparties), G7 (receipts commit to contents), and the AUD-5 and AUD-8 items of §7.1 |

## Contents

1. [Purpose and scope](#1-purpose-and-scope)
2. [Conventions and terms](#2-conventions-and-terms)
3. [Log model](#3-log-model)
4. [Entries](#4-entries)
5. [Hash chain and Merkle tree](#5-hash-chain-and-merkle-tree)
6. [Signed objects: checkpoints and receipts](#6-signed-objects-checkpoints-and-receipts)
7. [What a node logs](#7-what-a-node-logs)
8. [Durability, epochs and retention](#8-durability-epochs-and-retention)
9. [Operations](#9-operations)
10. [Cross-node consistency](#10-cross-node-consistency)
11. [Evidence bundles](#11-evidence-bundles)
12. [Error model](#12-error-model)
13. [Versioning](#13-versioning)
14. [Constants](#14-constants)
15. [Security and privacy considerations](#15-security-and-privacy-considerations)
16. [Relation to other work](#16-relation-to-other-work)
17. [Conformance](#17-conformance)
18. [Changes to other documents](#18-changes-to-other-documents)
19. [Open questions](#19-open-questions)

Appendix A. [Requirement index](#appendix-a-requirement-index)

## 1. Purpose and scope

S2 (two owners negotiate) needs "a non-repudiable record of what was offered and accepted, meaning signed messages
and an audit log that a third party can check". Signed envelopes (`envelope/v0`) give the first half: a receiver
can prove what a sender signed. This extension gives the second half:

- each node keeps an **append-only log** of security-relevant events, where every entry commits to all earlier
  entries ([§4](#4-entries), [§5](#5-hash-chain-and-merkle-tree)),
- the node signs **checkpoints** (tree heads), so a node cannot later rewrite history it has shown to anyone
  ([§6.2](#62-checkpoints)),
- a receiver returns signed **receipts** that commit to the log *contents* at the point where it logged an envelope,
  so the sender can prove delivery and the receiver cannot quietly drop the record later
  ([§6.3](#63-receipts)),
- peers **exchange checkpoints** and check consistency proofs, so forks and rollbacks are detected by the
  counterparty rather than trusted away ([§10](#10-cross-node-consistency)),
- disputes are settled with **evidence bundles**: selected entries with inclusion proofs against a signed
  checkpoint, never a log dump ([§11](#11-evidence-bundles)).

What the log proves, stated plainly (threat model AUD-5): **the log proves what was logged, in which order, and
that the node has not changed it since it committed to it.** It does not prove that the node logged everything.
Completeness can only be checked against counterparties: their receipts, their own logs, and the signed envelopes
they hold. Times in the log are claims by the node (AUD-7). Order comes from the tree.

Out of scope: witness co-signing of checkpoints by third parties (planned, [§19](#19-open-questions)), the inspector
UI that browses logs (T16), legal admissibility (threat model §8), and the meaning of events defined by other
extensions (they define their own entry types, [§4.3](#43-entry-types)).

## 2. Conventions and terms

The key words `MUST`, `MUST NOT`, `SHOULD`, `SHOULD NOT` and `MAY` are to be interpreted as described in BCP 14
(RFC 2119, RFC 8174) when, and only when, they appear in all capitals. Requirement IDs follow
[conventions.md](../conventions.md): every requirement block with a `MUST` begins with its tag, such as
`[AUD-101]`. IDs are grouped by section in blocks of 100.

Terms and notation:

- **Log**: the sequence of entries of one node in one epoch. It is identified by the pair (**log ID**, **epoch**).
  The log ID is the node identifier (`wwn:…`, `capability/v0` §3) of the node that keeps it.
- **Epoch**: a non-negative integer. A node starts a new epoch only when it can no longer extend the old one
  ([§8.2](#82-epochs)).
- **Size**: the number of entries in a log. Entries are numbered by **index** from 0. A log has size ≥ 1 from its
  creation, because entry 0 is the genesis entry.
- **Entry hash**: `blake3:` + lowercase hex of `BLAKE3(0x00 ‖ JCS(entry))`. It is also the Merkle leaf hash.
- **Root** at size n: the Merkle tree hash over the entry hashes of indices 0…n−1 ([§5.2](#52-merkle-tree)).
- **Commitment**: a signed statement by the node that its log (log ID, epoch) had root r at size n. Checkpoints and
  receipts are commitments.
- **Holder**: a node that keeps commitments of another node's log. **Monitor**: the role of a holder that checks
  new commitments against the ones it holds ([§10](#10-cross-node-consistency)).
- **Stub** of an envelope: the envelope JSON object with the `body` member removed and every other member, `sig`
  and unknown members included. A stub keeps the signature verifiable (`envelope/v0` ENV-213).
- **Header digest**: `blake3:` + lowercase hex of `BLAKE3(signing input)` of an envelope, as defined in
  `envelope/v0` §8.1. It identifies one exact signed header.
- `JCS(x)`, `BLAKE3(b)`, the hash, signature, timestamp, UUID and agent ID formats: as in `envelope/v0` §2 and
  §3.2. `‖` is byte concatenation.
- **Safe integer**: a JSON integer `n` with 0 ≤ `n` ≤ 2^53 − 1.

## 3. Log model

```text
   entries (append-only)         Merkle tree (RFC 9162 §2.1, BLAKE3)     signed by the node key
 ┌──────────┐  prev  ┌──────────┐  prev  ┌──────────┐
 │ #0       │◄───────│ #1       │◄───────│ #2       │ ...      root(n) ──► checkpoint {log, epoch, size n, root}
 │ genesis  │        │ env.recv │        │ authz    │                    receipt    {..., index i, root(i+1), env digest}
 └──────────┘        └──────────┘        └──────────┘
        entry hash = leaf hash = BLAKE3(0x00 ‖ JCS(entry))
```

Two structures, one set of hashes:

- a **hash chain**: every entry names the entry hash of its predecessor (`prev`). A complete export can be checked
  front to back with no other data, and an entry cannot be moved, dropped or inserted without changing every later
  hash. This is the "hash-chained" property of R9.
- a **Merkle tree** over the same entry hashes, with the algorithms of Certificate Transparency (RFC 9162 §2.1).
  It gives logarithmic **inclusion proofs** (this entry is at index i of the log with root r) and **consistency
  proofs** (the log with root r′ at size m extends the log with root r at size n). Third parties use these.
  A pure chain would need every entry hash between two commitments, which grows linearly.

The chain costs one hash per entry and makes a log export self-checking. The tree is what makes commitments cheap to
compare. Both are over the same leaf hashes, so they cannot disagree about an entry.

**Who signs.** The log ID is the node key, and the node key signs the log's checkpoints and receipts. The node
certificate (`capability/v0` §4.4) binds that key to the owner, so a verifier who pins the owner can attribute
every commitment, with no extra key type. This needs a change to CAP-003 ([§18](#18-changes-to-other-documents)).

## 4. Entries

### 4.1 Format

An entry is a JSON object:

```json
{
  "v": "webway-audit-entry/0",
  "log": "wwn:ab3k…",
  "epoch": 0,
  "index": 41,
  "prev": "blake3:6f0c…",
  "time": "2026-11-07T12:00:01.250Z",
  "type": "envelope.received",
  "parties": ["wwa:4f3w…", "wwa:q2ya…"],
  "data": { "hd": "blake3:91d2…", "via": "wwn:r3la…", "outcome": "accepted", "stub": { "v": "webway-envelope/0", "…": "…" } }
}
```

| Member | Type | Presence | Meaning |
|---|---|---|---|
| `v` | string | required | `webway-audit-entry/0`. |
| `log` | string | required | Log ID: the node identifier `wwn:…`. |
| `epoch` | integer | required | Epoch, a safe integer. |
| `index` | integer | required | Position in the log, a safe integer. |
| `prev` | string | required if `index` > 0, absent if `index` = 0 | Entry hash of the entry at `index − 1`. |
| `time` | string | required | When the node appended the entry, in the timestamp format of `envelope/v0` §3.2. A claim, not a proof. |
| `type` | string | required | Entry type ([§4.3](#43-entry-types)): lowercase `area.name`, matching `^[a-z][a-z0-9-]*\.[a-z][a-z0-9-]*$`. |
| `parties` | array of strings | optional | Agent or owner identifiers the entry concerns. Governs disclosure ([§9.6](#96-disclosure)). |
| `data` | object | required | Type-specific members. |

- [AUD-001] An entry MUST be a JSON object with every required member of the table above, of the given type and
  format, and no `prev` at index 0. A verifier MUST reject an entry that is not, or that contains a value that is
  not I-JSON as `envelope/v0` ENV-100 defines it, as `EntryInvalid`.
- [AUD-002] A verifier MUST reject as `EntryInvalid` an entry whose `v` is not `webway-audit-entry/0`, or whose
  `JCS` serialisation is longer than `MAX_ENTRY_BYTES`.
- [AUD-003] A verifier MUST keep unknown members of an entry, at the top level and inside `data`, when it hashes
  the entry, and MUST NOT reject an entry because of them or because its `type` is unknown to it.

Unknown members and types are what let minor versions and other extensions add data ([§13](#13-versioning)).

### 4.2 Bodies and redaction

Entries never contain envelope bodies or other bulky payloads. An envelope entry keeps the stub, whose signed
`body_hash` already commits to the body. The node stores the body, if its policy keeps it, in a separate **body
store** keyed by that hash.

- [AUD-010] A node MUST NOT put an envelope `body` into an entry. Where an entry type refers to a payload, it
  MUST refer to it by hash.

So redaction is deletion from the body store. It changes no entry hash, every proof stays valid, and a body that
is produced later can still be checked against the signed `body_hash`. The same pattern is available to other
extensions: keep a hash in `data` and the payload outside the log.

### 4.3 Entry types

v0 registers the types below. Other extensions register theirs in their own document, with their own area
(`blob.read`, `doc.change`, `mailbox.custody`, …). The `data` members listed are required unless marked optional.

| `type` | `data` members | `parties` |
|---|---|---|
| `log.genesis` | `node`: the log ID again. `reason`: `new`, `data-loss` or `rotation` ([§8.2](#82-epochs)). `predecessor` (optional): `{"epoch", "size", "root"}` of the previous epoch, as far as the node knows it. `profile`: the profile version (`webway-profile/0.1`). | none |
| `envelope.sent` | `hd`: header digest. `stub`: the stub. | `[from, to]` |
| `envelope.received` | `via`: who handed the envelope over: a `wwn:` node identifier (the authenticated transport peer, possibly a mailbox host), `edge` (A2A HTTP edge, `profile.md` §12.2) or `local` (a hosted agent). `outcome`: `accepted`, `duplicate` or `rejected`. `stub` and `hd`: when the input parsed into a JSON object (optional otherwise). `error` (with `rejected`): `{"type", "reason"}` as in `envelope/v0` §10. `trust` (optional): the trust level the receiver computed per Part (`provenance/v0`), keyed like `prov.parts`. | `[from, to]` when the stub is present |
| `authz.decision` | `hd`: the envelope decided on. `decision`: `allow` or `deny`. `error` (with `deny`): the error name. The other members of CAP-190 (`reason`, `presenter`, `capability`, `operation`, `access`, `mandate`, `principal`, `revocationLists`) as `capability/v0` §10.1 lists them. | `[presenter]` |
| `statement.issued` | `id`: the statement or token ID. `typ`: its type. `subject` (optional): the key or agent it is about. | none |
| `task.transition` | `taskId`, `from` (absent for creation), `to`: A2A task states. `seq`: the event sequence number. `cause` (optional): the header digest of the envelope that caused it. | the task's requester and responder agents |
| `bridge.crossing` | `bridge`: `a2a-http-in`, `a2a-http-out`, `mcp-facade`, `mcp-in` or `mcp-out` (`profile.md` §12). `hd` (optional): the envelope on the overlay side. `principal` (optional): the edge client or MCP principal. | as known |
| `checkpoint.peer` | `checkpoint`: a checkpoint of another node's log, verbatim. `result`: `consistent`, `first` (no earlier one held) or `inconsistent`. | none |
| `anomaly` | `name`: a kebab-case anomaly name ([§7.2](#72-anomalies)). `hd` (optional). `detail` (optional): an object. | as known |
| `node.event` | `event`: `start`, `stop`, `clock-step` or `restore-detected`. `detail` (optional). | none |
| `log.retention` | `entriesBefore` (optional): entries with a lower index had their contents deleted. `bodiesBefore` (optional): a time; bodies of envelopes logged before it were deleted. | none |

`trust` and `stub.prov` together record both the taint the sender claimed and the trust the receiver computed, so
taint laundering by a compromised node of the same owner (DD §4.7.4, INJ-12) is visible after the fact.

- [AUD-020] An `envelope.sent` or `envelope.received` entry that has a stub MUST have `data.hd` equal to the header
  digest of that stub, and MUST have `parties` equal to `[stub.from, stub.to]`. A verifier MUST reject a
  violation as `EntryInvalid`.

## 5. Hash chain and Merkle tree

### 5.1 Chain rules

- [AUD-100] In a log, the entry at index 0 MUST have type `log.genesis`, and every entry MUST have the log's `log`
  and `epoch` and the index of its position. A verifier of a sequence of entries MUST reject a violation as
  `ChainBroken`.
- [AUD-101] The entry at index i > 0 MUST have `prev` equal to the entry hash of the entry at index i − 1. A
  verifier MUST reject a mismatch as `ChainBroken`.
- [AUD-102] Entry `time` values MUST NOT decrease along the log. A verifier MUST reject a decrease as
  `ChainBroken`. Equal times are allowed.
- [AUD-103] A node MUST append entries only at the end of its current log and MUST NOT change, reorder or remove
  an entry it has appended. Deleting the contents of an entry under retention ([§8.3](#83-retention)) keeps its
  entry hash.

When a node's clock steps backwards, it keeps writing the last `time` it used until its clock passes it, and logs
a `node.event` `clock-step`.

### 5.2 Merkle tree

The tree is RFC 9162 §2.1.1 with BLAKE3 as the hash function. For the list of entry hashes `D[n]` = `d0 … d(n−1)`
(32-byte values):

```text
MTH(D[1]) = d0                                       (a leaf hash is already BLAKE3(0x00 ‖ JCS(entry)))
MTH(D[n]) = BLAKE3(0x01 ‖ MTH(D[0:k]) ‖ MTH(D[k:n]))   for n > 1, k the largest power of two < n
```

The prefixes `0x00` (leaf) and `0x01` (interior node) are those of RFC 9162 and stop a leaf from being passed off
as an interior node. There is no empty tree, because size ≥ 1.

- [AUD-110] The root at size n MUST be computed as `MTH` above over the entry hashes of indices 0…n−1, and written
  as `blake3:` + lowercase hex.

### 5.3 Proofs

An **inclusion proof** for index i in a log of size n is the list `PATH(i, D[n])` of RFC 9162 §2.1.3.1. A
**consistency proof** from size n to size m (1 ≤ n ≤ m) is `PROOF(n, D[m])` of RFC 9162 §2.1.4.1. Both are JSON
arrays of hashes in the `blake3:` format, in the order RFC 9162 defines. The proof between equal sizes is the empty
array.

- [AUD-120] A verifier MUST verify an inclusion proof with the algorithm of RFC 9162 §2.1.3.2 and a consistency
  proof with the algorithm of RFC 9162 §2.1.4.2, each with BLAKE3 and the prefixes of [§5.2](#52-merkle-tree), and
  MUST reject a proof that does not verify, that has more than `MAX_PROOF_HASHES` elements or extra elements left
  over, or whose sizes and index are out of range (i ≥ n, n < 1 or n > m), as `ProofInvalid`.
- [AUD-121] For a consistency proof from size n to size m with n = m, a verifier MUST accept only the empty proof,
  and only if the two roots are equal.

RFC 9162 omits the old root from consistency proofs when n is a power of two. That is unchanged here: the verifier
always knows the old root from a commitment.

## 6. Signed objects: checkpoints and receipts

### 6.1 Signing rules

Checkpoints and receipts are JSON objects with a `v` member naming their type and a `sig` member. The **signing
input** is

```text
signing_input = ASCII(v) ‖ 0x00 ‖ JCS(object without its sig member)
```

The prefix separates these signatures from envelope signatures (`webway-envelope/0`), JWS statements (start with
`eyJ`), Biscuit blocks (binary protobuf, whose first byte cannot be `w`), and TLS 1.3 `CertificateVerify` content
(starts with 64 spaces). It is the domain separation threat-model G2 asks for.

- [AUD-200] A node MUST sign a checkpoint or receipt with the private key of the node named in its `log` member,
  as pure Ed25519 over the signing input above, and MUST encode `sig` as in `envelope/v0` §3.2.
- [AUD-201] A verifier MUST verify `sig` with the key decoded from `log`, using the strict rules of `envelope/v0`
  ENV-210 and ENV-211 (equivalently `capability/v0` CAP-002), and MUST reject a failure as `CheckpointInvalid` or
  `ReceiptInvalid` respectively. It MUST compute the signing input over the parsed JSON value, keeping unknown
  members.
- [AUD-202] A verifier MUST reject a checkpoint or receipt that lacks a required member, has a member of the wrong
  type or format, or whose `v` is not the value this section gives, as `CheckpointInvalid` or `ReceiptInvalid`
  respectively. Unknown members MUST be kept and otherwise ignored.

Attributing a commitment to an owner is a separate step: the verifier checks a node certificate of the `log` node
under a pinned owner (`capability/v0` §4.4). A checkpoint whose signature verifies but whose node is not certified by
an owner the verifier trusts proves nothing about that owner.

### 6.2 Checkpoints

```json
{
  "v": "webway-checkpoint/0",
  "log": "wwn:ab3k…",
  "epoch": 0,
  "size": 1024,
  "root": "blake3:0d5e…",
  "time": "2026-11-07T12:05:00Z",
  "sig": "kq7Y…"
}
```

| Member | Meaning |
|---|---|
| `log`, `epoch` | The log. |
| `size` | Tree size, a safe integer ≥ 1. |
| `root` | The root at `size`. |
| `time` | When the node signed it, not earlier than the `time` of entry `size − 1`. A claim. |

- [AUD-210] A node MUST sign a new checkpoint for its current log whenever `CP_MAX_ENTRIES` entries have been
  appended since the last one, or `CP_MAX_AGE` has passed since the last one and at least one entry has been
  appended since. It MUST sign a checkpoint only over entries that are durable ([§8.1](#81-durability)).
- [AUD-211] All commitments (checkpoints and receipts) a node signs for one log MUST be commitments to prefixes of
  one sequence of entries: for any two of them, the one with the larger size MUST be consistent with the other,
  and two of equal size MUST have equal roots.
- [AUD-212] Checkpoint `size` and `time` MUST NOT decrease from one checkpoint to the next of the same log.

AUD-211 is the property everything else checks. Two signed commitments of one log with the same size and different
roots are, on their own, a transferable proof that the node forked its log ([§10.3](#103-fork-and-rollback-evidence)).

### 6.3 Receipts

A **receipt** is the node's signed statement "I logged the envelope with this header digest at index i, and my log
then had root r". Because it commits to the root after the entry, not just to a position, the node cannot rewrite
that entry or anything before it without contradicting its own signature (G7).

```json
{
  "v": "webway-receipt/0",
  "log": "wwn:ab3k…",
  "epoch": 0,
  "index": 41,
  "entry": "blake3:5b11…",
  "root": "blake3:a3c9…",
  "time": "2026-11-07T12:00:01.250Z",
  "env": "blake3:91d2…",
  "id": "019a5d2e-7b40-7c3a-9d1e-0a1b2c3d4e5f",
  "from": "wwa:4f3w…",
  "to": "wwa:q2ya…",
  "sig": "Xr0e…"
}
```

| Member | Meaning |
|---|---|
| `log`, `epoch` | The receiver's log. |
| `index` | The index of the `envelope.received` entry. |
| `entry` | That entry's hash. |
| `root` | The root at size `index + 1`. |
| `time` | The entry's `time`. |
| `env` | The header digest of the envelope. |
| `id`, `from`, `to` | The envelope's `id`, `from` and `to`, so a holder can match the receipt without the envelope. |

A receipt is a commitment to size `index + 1`.

- [AUD-300] A node MUST issue a receipt only for an `envelope.received` entry that has a stub whose signature
  verified (`envelope/v0` steps 1–5), only after that entry is durable, and with `entry`, `root`, `time`, `env`,
  `id`, `from` and `to` taken from that entry. For an envelope logged more than once (duplicates), the receipt
  MUST be for the first entry.
- [AUD-301] A verifier that holds the envelope a receipt is for MUST check that `env` is its header digest and
  that `id`, `from` and `to` are its members, and MUST reject a mismatch as `ReceiptInvalid`.
- [AUD-302] A verifier that is given the entry a receipt names MUST check that its entry hash equals `entry`,
  that it is an `envelope.received` entry with `data.hd` equal to `env`, with the receipt's `log`, `epoch`,
  `index` and `time`, and that `entry` is included at `index` under `root` at size `index + 1` (an inclusion
  proof), and MUST reject a mismatch as `ReceiptInvalid` (or `ProofInvalid` for the proof).

A receipt says the node logged the envelope. Whether it accepted it is in the entry's `outcome` and, for a request,
in the signed response. A receipt is about delivery to the node that hosts `to`, which holds the agent's key and
speaks for it.

## 7. What a node logs

### 7.1 Required entries

These rules implement `profile.md` PROF-049, `capability/v0` CAP-190 and `envelope/v0` ENV-623 in this log.

- [AUD-400] A node MUST append an `envelope.sent` entry for every envelope it signs and releases for delivery,
  durably and before the first transmission. A retry or a mailbox redelivery of the same envelope is not a new
  entry.
- [AUD-401] A node MUST append an `envelope.received` entry for every envelope that reaches its verification
  procedure and parses into a JSON object, whatever the outcome. For a `request` processed as new, the entry MUST
  be written in the same atomic transaction as the dedupe entry and task effects of `envelope/v0` ENV-503, before
  any response or acknowledgement is sent.
- [AUD-402] A node MUST append an `authz.decision` entry for every authorisation decision, a `task.transition`
  entry for every task state change it records, a `statement.issued` entry for every token, mandate, invite,
  certificate or revocation list it signs, a `bridge.crossing` entry for every request that crosses one of its
  bridges, and an `anomaly` entry for every anomaly named in [§7.2](#72-anomalies) or in another webway document.
- [AUD-403] A node MUST append a `node.event` `start` entry each time it starts, before it processes any
  envelope.

Rate limiting the log itself (AUD-9): a node MAY coalesce `envelope.received` entries with outcome `duplicate` for
the same `hd` into one entry per `CP_MAX_AGE`, with `detail.count`, and MAY coalesce rejections that failed before a
stub could be parsed (no `stub`) per transport peer the same way. Other entries are never coalesced (AUD-401 and
AUD-402 say "every").

### 7.2 Anomalies

| Name | Logged when |
|---|---|
| `id-reuse` | `envelope/v0` reason `id-reuse`: same `(from, id)`, different header digest. |
| `receipt-invalid` | A receipt from a peer fails verification (AUD-301, AUD-302) or a requested receipt is missing. |
| `checkpoint-invalid` | A peer's checkpoint or proof fails verification. |
| `log-inconsistent` | Two commitments of one peer log conflict, or a consistency proof fails ([§10.3](#103-fork-and-rollback-evidence)). |
| `log-epoch-change` | A peer log moved to a higher epoch. |
| `log-rollback` | A peer log shows a lower epoch than one already held, or a commitment beyond the log's current size. |
| `trust-claim-ignored` | A sender put a trust-like field in `prov` (`provenance/v0`). |

Other documents name further anomalies (`profile.md` PROF-016, PROF-017, PROF-034, …). Their names are recorded as
given there.

## 8. Durability, epochs and retention

### 8.1 Durability

- [AUD-500] A node MUST make an entry durable before it signs any commitment that covers it, and before it sends
  anything that depends on the entry (a response, an acknowledgement, a receipt, or the envelope of an
  `envelope.sent` entry).
- [AUD-501] A node MUST keep, outside the data that a backup restore replaces (the separate store of threat-model
  G5 (a)), its current epoch and the largest size it has signed a commitment for in that epoch. On start, if its
  durable log is shorter than that size, it MUST NOT extend the log and MUST start a new epoch ([§8.2](#82-epochs)).

Without AUD-501 a node restored from backup would reuse indices it had already committed to with other entries, and
look exactly like a node that forks on purpose.

### 8.2 Epochs

A new epoch is a new log with the same log ID. Its genesis entry says why it exists:

- `data-loss`: the node lost entries it may have committed to (AUD-501). `predecessor` is the last commitment it
  still knows of, which may be older than what peers hold.
- `rotation`: the node closes a log on purpose, for example to bound the leaf hashes it keeps (AUD-511).
  `predecessor` is the final state of the old epoch, and the node keeps serving proofs for the old epoch up to that
  state for at least `EPOCH_OVERLAP`.

A new node key always starts a new log ID, not a new epoch.

- [AUD-510] A node MUST start epochs at 0 and number them in increasing order, MUST NOT sign a commitment for an
  epoch after it has signed one for a later epoch, and MUST set `predecessor` in the genesis entry of every epoch
  after 0. With reason `rotation`, `predecessor` MUST be its final checkpoint of the old epoch, and that
  checkpoint MUST be signed before the new genesis entry is written.

Peers see an epoch change as an anomaly ([§10.2](#102-monitoring-a-peer-log)). An honest node pays for data loss
with a visible, logged admission. A dishonest node gains nothing over that: the old epoch's commitments that peers
hold remain evidence of everything it committed to.

### 8.3 Retention

- [AUD-511] A node MAY delete the contents of entries and bodies under its retention policy, but MUST keep the entry
  hash of every entry of an epoch for as long as it serves commitments, proofs or receipts for that epoch, and
  MUST log each deletion of entry contents as a `log.retention` entry.
- Owners SHOULD keep entry contents for at least `RETENTION_MIN`, and bodies as long as their dispute horizon
  requires. A request for a deleted entry gets `AuditPruned`.

Leaf hashes cost 32 bytes per entry. A node that must bound them closes the epoch with reason `rotation`.

## 9. Operations

### 9.1 Transport and activation

Audit operations are webway extension operations. A request is an envelope with `typ` `request` and `op`
`https://github.com/BVMrs/argent-webway/spec/ext/audit/v0#<Name>`, addressed to any agent hosted by the node whose
log is asked about. The answer is a signed `response` (or `error`) envelope from that agent. So every answer,
including a proof that does not verify or a refusal, is signed by the answering node's owner and can serve as
evidence ([§10.3](#103-fork-and-rollback-evidence)).

The extension is active for a request when the requester lists its URI in `a2a-extensions` and the responder
confirms it (`profile.md` PROF-056).

- [AUD-600] A node that declares `audit/v0` in its Agent Card MUST implement `GetCheckpoint`, `GetConsistency`,
  `GetInclusion` and `GetReceipts`, and MUST attach receipts to responses as [§9.2](#92-receipts-on-responses)
  requires.
- [AUD-601] Bodies of audit requests and responses MUST be JSON objects with the members given below, safe
  integers for sizes, indices and epochs, and the formats of [§2](#2-conventions-and-terms). A responder MUST
  answer a request whose body is not as given with A2A `InvalidParamsError`.

`ExchangeCheckpoints` is optional in v0 ([§10.4](#104-exchanging-third-party-checkpoints)).

### 9.2 Receipts on responses

When `audit/v0` is active for a request, the response carries the receipt for that request in a header member:

```json
{ "v": "webway-envelope/0", "typ": "response", "op": "SendMessage", "…": "…",
  "ctx": { "inReplyTo": "019a5d2e-…" },
  "rcpt": { "v": "webway-receipt/0", "log": "wwn:ab3k…", "…": "…", "sig": "Xr0e…" } }
```

`rcpt` is part of the signed header (`envelope/v0` ENV-002), so it is also kept in the stored response and replayed
byte for byte to duplicates. It carries its own `sig`, so it can be taken out and shown without the response.

- [AUD-610] When `audit/v0` is active for a request, a responder MUST include in every `response` envelope, and in
  every signed `error` envelope sent after the request's entry was logged, a header member `rcpt` with the receipt
  for that request.
- [AUD-611] A requester that receives a response with `rcpt` MUST verify the receipt (AUD-201, AUD-202, AUD-301),
  check that its `id` is the response's `ctx.inReplyTo`, and keep it with the request. On failure it MUST log the
  anomaly `receipt-invalid`, and MUST NOT reject the response for that reason.

### 9.3 `GetCheckpoint`

Request body: `{"epoch": e, "have": [n1, n2, …]}`, both members optional. `have` lists the sizes of commitments the
requester holds for epoch `e`, at most `MAX_HAVE`.

Response body: `{"checkpoint": C, "proofs": [{"size": n, "proof": [...]}, …]}`.

- [AUD-620] A responder MUST return a checkpoint of its current epoch that is no older than `CP_MAX_AGE` and whose
  size is at least every `n` in `have` (signing a new one if needed). When `e` equals the current epoch, it MUST
  return one consistency proof from each `n` in `have` to `C.size`, in the order of `have`.
- [AUD-621] When `e` is the current epoch and some `n` in `have` exceeds the current log size, the responder MUST
  answer `AuditRangeInvalid` with reason `beyond-size`.

AUD-621's answer is a signed admission that the requester holds a commitment the log no longer has: a rollback
([§10.3](#103-fork-and-rollback-evidence)).

### 9.4 `GetConsistency` and `GetInclusion`

`GetConsistency` request: `{"epoch": e, "from": n, "to": m}`. Response: `{"proof": [...]}`.

`GetInclusion` request: `{"epoch": e, "index": i, "size": n, "entry": true|false}`. Response:
`{"leaf": "blake3:…", "proof": [...], "entry": {…}}`, with `entry` only when asked for and disclosed
([§9.6](#96-disclosure)).

- [AUD-630] A responder MUST answer `GetConsistency` for any 1 ≤ n ≤ m ≤ the size of epoch `e`, and
  `GetInclusion` for any i < n ≤ the size of epoch `e`, for its current epoch and for any epoch it still keeps
  (AUD-511). Otherwise it MUST answer `AuditRangeInvalid`.
- [AUD-631] A responder MUST return in `GetInclusion` the entry contents only if [§9.6](#96-disclosure) allows it,
  and MUST otherwise answer `AuditNotFound` when `entry` is `true`; it MUST answer `AuditPruned` when the contents
  were deleted (AUD-511) and the requester could otherwise see them.

### 9.5 `GetReceipts`

Request: `{"ids": [uuid, …]}`, at most `MAX_RECEIPT_IDS`. Response: `{"receipts": [R, …], "missing": [uuid, …]}`.

- [AUD-640] A responder MUST return, for each `id` in the request, the receipt of the first `envelope.received`
  entry with a verified stub whose `from` is the requesting envelope's `from` and whose `id` is that `id`, or list
  the `id` in `missing`. It MUST NOT reveal whether an envelope with that `id` from another sender exists.

This is how a node gets receipts for envelopes that are not requests: responses, events and acknowledgements it
sent, including those delivered through a mailbox while it was offline.

### 9.6 Disclosure

Audit data about other conversations is sensitive (AUD-8). The rules:

- Checkpoints, proofs and leaf hashes reveal sizes and hashes only. Any requester whose identity verifies
  (`profile.md` PROF-040) may get them.
- Receipts are for the sender of the envelope (AUD-640).
- Entry contents are for the agents and owners in the entry's `parties`, for the genesis entry of each epoch
  (anyone), and otherwise only for a requester whose access token grants the capability `audit:read` on this node.

- [AUD-650] A responder MUST disclose entry contents only as the rules above allow.

Owners MAY restrict everything further by local policy (for example refuse audit operations to peers they have
never exchanged a task with), and SHOULD rate-limit audit operations per peer.

## 10. Cross-node consistency

### 10.1 What a holder keeps

A holder keeps, per peer log (log ID): the latest checkpoint it has verified, per epoch it has seen, and every
receipt from that log it still needs, with its envelope. A receipt is **pending** until it has been checked against
a checkpoint of the same epoch that covers it.

### 10.2 Monitoring a peer log

- [AUD-700] A node MUST, while it exchanges envelopes with a peer node, get that node's checkpoint with
  `GetCheckpoint` at least every `GOSSIP_INTERVAL`, and within `CP_MAX_AGE` of holding a pending receipt from it,
  listing in `have` the size of its held checkpoint of the current epoch and of every pending receipt (at most
  `MAX_HAVE` per request).
- [AUD-701] A node MUST verify each checkpoint it receives (AUD-201, AUD-202), check that its `log` is the node it
  asked, and verify each returned consistency proof against its held commitment. A checkpoint of the held epoch
  with a smaller size than the held one MUST be accepted only if consistent with it, and does not replace it.
- [AUD-702] When a new checkpoint verifies and is consistent with the held checkpoint and with every pending
  receipt it covers, the node MUST replace its held checkpoint, mark those receipts checked, and append a
  `checkpoint.peer` entry with the new checkpoint and `result` `consistent` (or `first` when it held none).
- [AUD-703] When any check of AUD-701 or AUD-702 fails, or two commitments of one epoch have equal size and
  different roots, the node MUST NOT replace its held checkpoint, MUST append an anomaly `log-inconsistent` with the
  conflicting commitments and the signed response envelope's header digest, and MUST keep that response envelope
  and both commitments as evidence.
- [AUD-704] When a peer's checkpoint has a higher epoch than the held one, the node MUST keep the held checkpoint
  of the old epoch as evidence, MUST append an anomaly `log-epoch-change`, and SHOULD fetch the new genesis entry
  (`GetInclusion` index 0) and compare its `predecessor` with what it holds. A `predecessor` with a smaller size
  than, or the same size and a different root from, the held checkpoint is a rollback: the node MUST then append
  an anomaly `log-rollback`.
- [AUD-705] A checkpoint with a lower epoch than one already held, and an `AuditRangeInvalid` `beyond-size` answer
  to AUD-700, MUST be treated as rollback: anomaly `log-rollback`, with the evidence kept as in AUD-703.

What a node does after an anomaly (alert the owner, stop accepting work from the peer, stop sending to it) is owner
policy. The spec only requires that the evidence is kept and logged.

**Offline peers.** Nothing here blocks delivery. A pending receipt stays pending while the peer is unreachable, and
is checked at the next contact. The receipt itself is already evidence of delivery.

### 10.3 Fork and rollback evidence

Transferable evidence a third party can check with the owner's pinned key alone:

1. **Equal-size fork**: two commitments (checkpoints or receipts) with the same `log`, `epoch` and size, and
   different roots. Self-contained.
2. **Refused or bad proof**: a commitment C1 held by the holder, a later commitment C2, and the signed response
   envelope in which the node returned a consistency proof from C1 to C2 that does not verify, or answered
   `AuditRangeInvalid` `beyond-size` for C1's size. The node signed both the commitments and the answer.
3. **Rollback across epochs**: a commitment of epoch e, and a genesis entry of epoch e′ > e (with its inclusion
   proof and a checkpoint of e′) whose `predecessor` is inconsistent with it. This is not by itself proof of
   malice. It proves the node lost or discarded what it had committed to, which it has to explain.

- [AUD-710] A verifier comparing two commitments of the same `log` and `epoch` MUST report them as conflicting
  (`LogInconsistent`) when they have equal size and different roots, and MUST otherwise require a valid consistency
  proof from the smaller to the larger before treating them as consistent.

### 10.4 Exchanging third-party checkpoints

A node that shows one history to peer P and another to peer Q is caught only if P and Q compare (AUD-3). In v0 any
two nodes may compare their held checkpoints of third logs.

`ExchangeCheckpoints` request: `{"checkpoints": [C, …]}`, at most `MAX_HAVE`, at most one per log. Response:
`{"checkpoints": [C′, …]}`: the responder's held checkpoint for each log in the request that it holds one for, plus
its own latest checkpoint.

- Nodes SHOULD exchange checkpoints of logs they both hold with every peer they monitor, at each `GetCheckpoint`
  contact. For each log both hold, each side compares as in AUD-710 and gets any missing consistency proof from the
  log's node with `GetConsistency`.
- [AUD-720] A node that implements `ExchangeCheckpoints` MUST verify every received checkpoint (AUD-201) before
  using it, and MUST NOT replace its own held checkpoint of a third log with one received this way unless it has
  checked consistency with the log's node itself.

Co-signing witnesses (threat-model G6, later) build on the same exchange: a witness is a holder that also signs
the checkpoints it has checked.

## 11. Evidence bundles

A dispute (S2) is settled by showing selected entries, not the log (AUD-8). An evidence bundle is a JSON object,
not itself signed: every piece in it is signed or hash-bound to something signed.

```json
{
  "v": "webway-audit-evidence/0",
  "checkpoint": { "v": "webway-checkpoint/0", "…": "…" },
  "entries": [ { "entry": { "v": "webway-audit-entry/0", "…": "…" }, "proof": ["blake3:…"] } ],
  "receipts": [ { "receipt": { "v": "webway-receipt/0", "…": "…" }, "proof": ["blake3:…"] } ],
  "bodies": { "blake3:…": { "message": { "…": "…" } } },
  "statements": [ "…JWS statements: owner-key events and the node-cert of the log's node…" ]
}
```

| Member | Presence | Meaning |
|---|---|---|
| `checkpoint` | required | A checkpoint of the log the entries come from. |
| `entries` | required | At least one. Each `proof` is the inclusion proof of `entry` at `entry.index` under `checkpoint`. |
| `receipts` | optional | Receipts of the same log. Each `proof` is the consistency proof from the receipt's size to `checkpoint.size`. |
| `bodies` | optional | Envelope bodies, keyed by the `body_hash` of a stub in `entries`. |
| `statements` | optional | The `capability/v0` statements that attribute the log's node to an owner. |

- [AUD-800] A verifier of an evidence bundle MUST reject it as `EvidenceInvalid` when `v` is not
  `webway-audit-evidence/0`, a required member is missing, or an entry, receipt or body key does not belong to the
  bundle's checkpoint (different `log` or `epoch`, `index` ≥ `size`, or a body whose key is not the `body_hash`
  of a stub in `entries`).
- [AUD-801] A verifier MUST verify the checkpoint (AUD-201), each entry (AUD-001, AUD-002, AUD-020) and its
  inclusion proof (AUD-120), each receipt (AUD-201) and its consistency proof, and for each stub in an entry the
  envelope signature with the rules of `envelope/v0` §5.2; for each body, that `blake3:` + hex of
  `BLAKE3(JCS(body))` equals its key. It MUST reject the bundle with the error of the first failing check.

Owner attribution (the `statements`) is verified with `capability/v0`, as of the checkpoint's `time`
([open question 4](#19-open-questions)).

## 12. Error model

### 12.1 Errors on the wire

Answers to audit operations. Codes are proposed for the profile's range (`profile.md` §10.3), to be registered by
change proposal. Errors carry `ErrorInfo` as PROF-051 requires.

| Name | Code | `REASON` | Retryable | When |
|---|---|---|---|---|
| `AuditNotFound` | −30050 | `AUDIT_NOT_FOUND` | no | The entry does not exist or may not be disclosed to the requester. The two cases are not distinguished. |
| `AuditPruned` | −30051 | `AUDIT_PRUNED` | no | The entry's contents were deleted under retention. Its hash and proofs are still available. |
| `AuditRangeInvalid` | −30052 | `AUDIT_RANGE_INVALID` | no | An epoch, size or index outside what the log has or keeps, or too many items. Detail reason: `beyond-size`, `bad-range`, `epoch-unavailable`, `too-many`. |

A2A `InvalidParamsError` for malformed bodies (AUD-601), and the profile's `RateLimited` for rate limits.

### 12.2 Verification results

Names a verifier uses for its local results: in test vectors, in evidence verification, and in the `detail` of
anomaly entries. They are not sent to the node being verified.

| Name | Meaning | Reasons |
|---|---|---|
| `EntryInvalid` | An entry is malformed. | `missing-field`, `malformed-field`, `bad-version`, `too-large`, `not-ijson`, `hd-mismatch`, `parties-mismatch` |
| `ChainBroken` | A sequence of entries is not a valid chain. | `no-genesis`, `index-gap`, `prev-mismatch`, `log-mismatch`, `epoch-mismatch`, `time-decreased` |
| `ProofInvalid` | An inclusion or consistency proof fails. | `bad-range`, `wrong-length`, `root-mismatch`, `malformed-proof` |
| `CheckpointInvalid` | A checkpoint is malformed or its signature fails. | `missing-field`, `malformed-field`, `bad-version`, `bad-signature`, `weak-key` |
| `ReceiptInvalid` | A receipt is malformed, its signature fails, or it does not match its envelope or entry. | as `CheckpointInvalid`, plus `envelope-mismatch`, `entry-mismatch` |
| `LogInconsistent` | Two commitments of one log conflict (AUD-710). | `fork` |
| `EvidenceInvalid` | A bundle is malformed or mixes logs. | `missing-field`, `bad-version`, `foreign-item`, `body-mismatch` |

- [AUD-900] A verifier reporting a verification result MUST use the names of the table above, so that results
  agree across implementations and the conformance vectors can test them.

## 13. Versioning

- The extension URI ends in `/v0`. Each object carries its own version string in `v`.
- **Minor revisions** of v0 may add entry types, optional members of entries, `data`, checkpoints and receipts,
  anomaly names, error reasons, and operations. v0 verifiers keep and hash unknown members (AUD-003, AUD-202) and
  ignore unknown types.
- **A major revision** is needed to change hashing, the tree, the signing input, or the meaning of an existing
  member. A new major gets new `v` strings, and so new signing-input prefixes. A node switching its log to a new
  major starts a new epoch with reason `rotation`, so one epoch never mixes versions.

- [AUD-910] A verifier MUST reject an entry, checkpoint, receipt or evidence bundle whose `v` it does not support,
  with the error of that object type and reason `bad-version`, and MUST NOT verify it under another version's
  rules.

## 14. Constants

| Name | Value | Notes |
|---|---|---|
| `CP_MAX_ENTRIES` | 1024 | Entries between checkpoints at most. |
| `CP_MAX_AGE` | 300 s | Age of the latest checkpoint at most, when there are new entries. Also the response bound of AUD-620. |
| `GOSSIP_INTERVAL` | 3600 s | How often a node fetches a peer's checkpoint while in contact. |
| `MAX_HAVE` | 64 | Sizes in `have`; checkpoints in `ExchangeCheckpoints`. |
| `MAX_RECEIPT_IDS` | 64 | IDs per `GetReceipts`. |
| `MAX_PROOF_HASHES` | 128 | Hashes in one proof. Inclusion proofs need at most 53 and consistency proofs at most 54 for safe-integer sizes. |
| `MAX_ENTRY_BYTES` | 1 179 648 | `JCS(entry)`: the largest stub (`envelope/v0` `MAX_ENVELOPE_BYTES`) plus 128 KiB. |
| `EPOCH_OVERLAP` | 30 days | Proofs for a rotated-out epoch stay available at least this long. |
| `RETENTION_MIN` | 400 days | Recommended minimum for entry contents. Matches the longest certificate validity (`capability/v0` `MAX_CERT_TTL`). |

- [AUD-920] Nodes MUST use the constants above. An owner MAY choose shorter checkpoint intervals and longer
  retention.

## 15. Security and privacy considerations

- **What is detected, and by whom.** Edits or deletions of committed entries (AUD-1) are detected by any holder of a
  later commitment. Tail rewrites (AUD-2) are detected by holders of receipts, because receipts commit to the root
  after each received envelope. Forks (AUD-3) are detected when two holders compare (§10.4), and rollbacks (AUD-4)
  by the next `GetCheckpoint`. An insider with the node key (AUD-6) can sign anything, but cannot make it
  consistent with commitments already held by others. **Nothing is prevented, only made detectable**, and only to
  the extent that someone outside the node holds commitments. A node nobody talks to has an unchecked log.
- **Omission** (AUD-5). A node can fail to log an event. Its counterparty then holds a signed envelope and, for
  requests, a response without a matching receipt, or a `missing` answer from `GetReceipts`. Both are signed by the
  node. That is the only completeness check v0 offers.
- **Time** (AUD-7). Entry and checkpoint times are claims. Order comes from indices. In disputes, the counterparty's
  signed `ts` and `exp` bound when an envelope can have been received.
- **Data in the log** (AUD-8). Entries hold signed headers, which include capability tokens and taint owner sets.
  Export only by evidence bundle of selected entries. Bodies are outside the log and can be deleted without breaking
  anything. Envelope `body_hash` is an unkeyed hash, so a guessable body can be confirmed from a stub. A disclosed
  entry shows its counterparty the same header it already has.
- **Sizes leak activity** (META-9, G13). Checkpoints and receipts reveal how many entries a node logs over time.
  Accepted for v0.
- **Log flooding** (AUD-9). Coalescing (§7.1), the rate limits of `profile.md`, and per-peer limits on audit
  operations (§9.6) bound it. Retention deletes contents but keeps hashes, so it never breaks proofs.
- **Prompt injection through the log.** Entries contain strings chosen by peers: error messages, IDs, metadata,
  anomaly details. A tool that gives audit records to a model (a summariser, a triage agent) SHOULD pass them as
  data with `foreign` trust (`provenance/v0`), never as instructions, like any other remote content.
- **Transferable records** (PEER-10, G18). Receipts and checkpoints are signed and can be shown to anyone. That is
  their purpose here. Owners who want deniability cannot have it with this extension active.
- **Key compromise.** A stolen node key can sign false commitments for that node's log. Holders' earlier
  commitments still constrain the past. Revoking the node certificate (`capability/v0` §9) ends attribution of new
  commitments to the owner.

## 16. Relation to other work

- **A2A 1.0** asks implementations to "maintain audit trails" (§13.4) and defines no format, so audit/v0 is an A2A
  extension: stock A2A peers ignore it, and lose nothing but the receipts. Traffic from stock peers through the HTTP
  edge is still logged, with `via: "edge"`.
- **MCP** has no audit concept. Calls through the MCP facade and bridges are logged as `bridge.crossing`.
- **Certificate Transparency** (RFC 9162): the tree, the proof algorithms and the signed tree head are taken from it,
  with BLAKE3 instead of SHA-256 to match `envelope/v0`. The submission and SCT machinery is not: a webway log is
  per node and private, and receipts play the part of SCTs.
- **C2SP `tlog-checkpoint`** and **`tlog-cosignature`** (the signed-note format used by the Go checksum database and
  Sigstore witnesses): the same idea in a text format. v0 uses JSON and JCS like every other webway signature, and
  leaves a bridge that re-signs webway checkpoints as signed notes, so public witness networks can co-sign them, as
  an option for later ([open question 2](#19-open-questions)).
- **IETF SCITT** (signed statements registered in a transparency service, with COSE receipts): close in purpose to
  receipts here, but centred on a shared registry and on CBOR/COSE. A per-node log fits the no-central-server
  requirement better. An export of evidence bundles as SCITT statements is possible later.

## 17. Conformance

### 17.1 Vector kinds

All vectors are in `conformance/vectors/audit/`, in the format `webway-vectors/v0`. Binary values are in the string
formats of this document. Keys and seeds used to build them are in that directory's README.

| Kind | Input | Output on `accept` |
|---|---|---|
| `audit/entry-hash` | `{"entry": E}` | `{"hash": "blake3:…"}` |
| `audit/chain` | `{"entries": [E, …]}` (a whole log from index 0) | `{"log", "epoch", "size", "root", "head"}` where `head` is the last entry hash |
| `audit/inclusion` | `{"index", "size", "leaf", "root", "proof"}` | none |
| `audit/consistency` | `{"size1", "root1", "size2", "root2", "proof"}` | none |
| `audit/checkpoint` | `{"checkpoint": C}` | `{"log", "epoch", "size", "root"}` |
| `audit/receipt` | `{"receipt": R, "envelope": X}` (`envelope` optional) | `{"log", "epoch", "size", "root"}` |
| `audit/compare` | `{"a": C1, "b": C2, "proof": [...]}`: two commitments, already verified, with the consistency proof from the smaller to the larger | `{"relation": "equal" \| "consistent" \| "unrelated"}` (`unrelated`: different log or epoch) |
| `audit/evidence` | `{"bundle": B}` | `{"entries": n}`, the number of verified entries |

`expect.error` is a name from [§12.2](#122-verification-results).

### 17.2 Harness

Requirements on node behaviour (what is logged and when, durability, epochs after a crash, monitoring, the
operations) are tested by the black-box harness against running nodes, as M1 scenario step 8 describes: both nodes'
logs verify as chains, `alpha` holds a verified receipt from `beta` for each envelope it sent, and the checkpoints
they exchanged are consistent. Planned harness scenarios:

- crash `beta` after it logs and before it responds, then retry: one `envelope.received` entry with outcome
  `accepted`, and the receipt in the replayed response is identical,
- restore `beta` from a backup older than its last receipt: `beta` starts epoch 1 with reason `data-loss`, and
  `alpha` logs `log-epoch-change` and `log-rollback`,
- a modified `beta` signs two checkpoints of equal size and different roots: `alpha` logs `log-inconsistent` and
  keeps both,
- `beta` offline while `alpha` holds a pending receipt: no error, and the receipt is checked on reconnect.

## 18. Changes to other documents

- **`capability/v0` CAP-003** says the node key "signs no statement and no token". This document needs it to sign
  `webway-checkpoint/0` and `webway-receipt/0` objects, and nothing else. The prefixes make these signatures
  impossible to confuse with TLS `CertificateVerify` content, JWS statements, envelopes or Biscuit blocks
  ([§6.1](#61-signing-rules)). Proposed text: "the node key signs the TLS handshake and the audit/v0 objects
  `webway-checkpoint/0` and `webway-receipt/0`, nothing else".
- **`profile.md` §10.3**: register `AuditNotFound`, `AuditPruned` and `AuditRangeInvalid` (−30050…−30052).
- **`profile.md` §5 or capability names**: the capability `audit:read` ([§9.6](#96-disclosure)).
- **`envelope/v0`**: `rcpt` is a header member defined by an extension. ENV-002 already makes receivers keep and
  sign it. Nothing to change, but §3.1 could list it as reserved.

## 19. Open questions

1. **Node key or a separate log key.** Signing with the node key avoids a new key role and a new certificate. A
   separate log key, certified like an issuing key, would let the node key stay a pure TLS identity, at the cost of
   one more certificate to rotate and verify. This draft picks the node key.
2. **Witnesses.** Co-signing by a second node of the same owner, or by a counterparty, is the stronger fix for
   G6. A C2SP-compatible signed-note export would let public witnesses co-sign. After M1.
3. **Default authorisation of audit operations.** §9.6 lets any authenticated peer get checkpoints and proofs, and
   the parties of an entry get its contents, without a capability token. That is the minimum for receipts and
   monitoring to work between counterparties, but it is a built-in grant. The alternative is an `audit:checkpoint`
   capability in every invite.
4. **Evidence after key rotation.** `capability/v0` CAP-021 rejects statements signed by an owner's retired root
   key whatever their `iat`. A dispute years later needs to verify a node certificate as of the checkpoint's time.
   Evidence verification needs an "as of" mode with the key events in the bundle, which `capability/v0` should
   define.
5. **Hash encoding.** This document uses `blake3:` + hex, as `envelope/v0` does. `capability/v0` uses `b3:` +
   base64url for statement IDs. One encoding should be chosen across the spec (`envelope/v0` open question 2).
6. **Receipts on events.** Events have no response, so their receipts need `GetReceipts`. An `ack` envelope carrying
   receipts for a batch of events would save round trips on long streams.

## Appendix A. Requirement index

"Vectors" names the kinds in `conformance/vectors/audit/` with cases for the requirement. "Harness" means the
requirement is about node behaviour and is tested by the black-box harness (T4). Every requirement listed is a
`MUST`; `SHOULD`s are not indexed.

| ID | Topic | Tested by |
|---|---|---|
| AUD-001 | entry structure | `entry-hash`, `chain` |
| AUD-002 | entry version and size | `entry-hash` |
| AUD-003 | unknown members and types kept | `entry-hash`, `chain` |
| AUD-010 | no bodies in entries | harness |
| AUD-020 | envelope entry `hd` and `parties` | `entry-hash`, `evidence` |
| AUD-100 | genesis, log, epoch, index | `chain` |
| AUD-101 | `prev` chain | `chain` |
| AUD-102 | non-decreasing time | `chain` |
| AUD-103 | append only | harness |
| AUD-110 | Merkle root | `chain` |
| AUD-120 | proof verification | `inclusion`, `consistency` |
| AUD-121 | equal-size consistency | `consistency` |
| AUD-200 | signing commitments | `checkpoint`, `receipt` |
| AUD-201 | verifying commitments | `checkpoint`, `receipt` |
| AUD-202 | commitment structure | `checkpoint`, `receipt` |
| AUD-210 | checkpoint cadence | harness |
| AUD-211 | one history per log | `compare`, harness |
| AUD-212 | checkpoint monotonic | harness |
| AUD-300 | issuing receipts | harness |
| AUD-301 | receipt matches envelope | `receipt` |
| AUD-302 | receipt matches entry | `evidence` |
| AUD-400 | log sent envelopes | harness |
| AUD-401 | log received envelopes atomically | harness |
| AUD-402 | log decisions, transitions, statements, bridges, anomalies | harness |
| AUD-403 | log start | harness |
| AUD-500 | durability before commitments | harness |
| AUD-501 | epoch and committed size outside backups | harness |
| AUD-510 | epoch numbering and predecessor | harness |
| AUD-511 | retention keeps hashes | harness |
| AUD-600 | operations implemented | harness |
| AUD-601 | operation bodies | harness |
| AUD-610 | `rcpt` on responses | harness |
| AUD-611 | requester verifies `rcpt` | `receipt`, harness |
| AUD-620 | `GetCheckpoint` | harness |
| AUD-621 | `beyond-size` | harness |
| AUD-630 | `GetConsistency`, `GetInclusion` ranges | harness |
| AUD-631 | `GetInclusion` disclosure | harness |
| AUD-640 | `GetReceipts` | harness |
| AUD-650 | disclosure rules | harness |
| AUD-700 | monitoring cadence | harness |
| AUD-701 | checkpoint and proof checks | `checkpoint`, `consistency`, harness |
| AUD-702 | replacing the held checkpoint | harness |
| AUD-703 | inconsistency evidence | `compare`, harness |
| AUD-704 | epoch change | harness |
| AUD-705 | rollback | harness |
| AUD-710 | comparing commitments | `compare` |
| AUD-720 | third-party checkpoints | harness |
| AUD-800 | bundle structure | `evidence` |
| AUD-801 | bundle verification | `evidence` |
| AUD-900 | verification result names | all kinds |
| AUD-910 | unknown versions | `entry-hash`, `checkpoint`, `receipt`, `evidence` |
| AUD-920 | constants | harness |
