# argent-webway: threat model

Status: draft v0, for owner review. Date: 2026-11-07.
Input to: the spec drafts (T1–T3, T7–T9, T13–T15, T17), the implementation tracks that gaps are assigned to
(T5, T6, T11, T12, T16, T18), and the security review (T19).
Based on: [`due-diligence.md`](due-diligence.md), mainly [§4.7](due-diligence.md#47-security-model). Section
numbers like "DD §4.4" refer to that document.

**Summary.** The design already handles the threats it was built around: forged or altered messages in transit,
stolen capability tokens, simple replay, trust claims from the wire, and the S4 confused deputy *when C requires a
mandate* (DLG-4 covers the case where it does not). This document lists what the drafts still have to specify, and
**19 gaps** (§7) where the due diligence has no mitigation or only part of one. The gaps marked "Before M1" are:

- the local agent ↔ node boundary has no authentication (G1),
- signatures have no domain separation and no common Ed25519 verification rules (G2),
- `delivered` status can come from the mailbox host instead of the recipient (G3),
- anyone can fill a mailbox (G4),
- replay protection breaks if a node restores its dedupe store from a backup (G5),
- an audit log can be forked or have its tail rewritten without anyone noticing (G6, G7),
- no resource limits are set: message size, JSON depth, token size, Datalog evaluation (G15),
- revocation has no freshness rule (G11 (a)), if M1 tests revocation.

One more must be settled when T3 starts: the online key that actually signs capabilities is missing from the
design (G19).

The largest *design* gap is that taint only tracks where content came from. Nothing tracks what content may
leave, so a prompt-injected agent can still send private data to a foreign peer (G9). The enforceable fix is
coarse: in a foreign-tainted task, *any* send to a foreign owner other than the one that started the task needs a
grant or a human confirmation.

---

## Contents

1. [Scope and method](#1-scope-and-method)
2. [Assets](#2-assets)
3. [Actors](#3-actors)
4. [Trust boundaries](#4-trust-boundaries)
5. [Assumptions](#5-assumptions)
6. [Threats and mitigations](#6-threats-and-mitigations)
7. [Gaps](#7-gaps)
8. [Out of scope](#8-out-of-scope)
9. [Using this document](#9-using-this-document)

---

## 1. Scope and method

**In scope**: the protocol (profile, binding `webway-quic/v0` and the seven extensions), and the reference node,
relay, mailbox host and HTTP edge gateway, as sketched in the due diligence. Also the boundary where content
from other agents reaches an LLM.

**Method**: we list assets, actors and trust boundaries, then go through each boundary with STRIDE (spoofing,
tampering, repudiation, information disclosure, denial of service, elevation of privilege). Threats are grouped
by the areas the issue asks for (relays, malicious peers, cross-owner delegation, replay, metadata leakage,
prompt injection, audit-log tampering), plus identity, the local boundary, artefacts and shared docs, the
edge, and resource exhaustion.

Every threat has:

- an **ID** (`REL-1`, `INJ-3`, …), which spec sections and conformance tests can refer to,
- a **mitigation**, short, with the DD section it comes from,
- a **spec home**: the extension or document that has to state the rule normatively,
- a **status** from a closed vocabulary. The cell starts with exactly one of:
  - **Designed**: the DD specifies a mitigation, and the spec has to write it down and test it,
  - **Partial**: a mitigation exists but leaves a named hole,
  - **Gap G*n***: no mitigation yet, see §7.

  It may be followed by **, accepted**, meaning we keep the remaining risk on purpose for v0. Anything after the
  first full stop is a note. "Folded into G*n*" in a note means the remaining work is tracked in that gap.

Nothing here is normative. Normative text goes in `spec/`, with requirement IDs (e.g. `ENV-012`).

---

## 2. Assets

| ID | Asset | Why it matters | Where it lives |
|---|---|---|---|
| A1 | **Owner root keys** | Root of all trust for an owner. Certifies the owner's nodes, agents and issuing keys (A14), and signs successor statements. It should not sign day-to-day objects (assumption 2). If compromised, the attacker *is* the owner. | Offline or hardware-backed (DD §4.2) |
| A2 | **Node keys** | QUIC endpoint identity (NodeId). Compromise lets an attacker impersonate the node and receive its traffic. | Node |
| A3 | **Agent keys** | Sign every envelope. Compromise gives the attacker non-repudiable speech as that agent. | Node (agents never hold them, DD §4.1) |
| A4 | **Capability tokens and mandates** | Grant access. Holder-bound, but they reveal the authorisation structure. | Envelopes, node stores, invites |
| A5 | **Message and task content** | Prompts, data, negotiation positions (S2), results. Confidential and integrity-critical. | In transit, mailbox, task store |
| A6 | **Artefacts (blobs)** | Possibly large and sensitive (datasets, traces, checkpoints). | Blob stores of several providers |
| A7 | **Shared documents / memory** | Long-lived. Decisions persist and later steer agents (S3). | Every node with read access |
| A8 | **Provenance state** (taint, computed trust) | The prompt-injection boundary depends on it being correct. | Envelopes, node-local metadata |
| A9 | **Audit logs, checkpoints, receipts** | Evidence for cross-owner disputes (S2) and incident response. | Each node, plus counterparties |
| A10 | **Dedupe and task store** | Gives effectively-once delivery. If lost, replays succeed. | Node durable store |
| A11 | **Metadata**: who talks to whom, when, how much, from which IP, about which task | Sensitive across owners even when content is encrypted (DD Q7). | Relays, mailboxes, discovery records, peers |
| A12 | **Availability** of nodes, relays and mailboxes | Offline must degrade gracefully, not become a DoS vector (R2). | Everywhere |
| A13 | **Local resources behind skills** | Shell, files, browser sessions, GPUs, hardware keys (S1). The reason capabilities exist. | Owner's machines |
| A14 | **Owner issuing keys** (online) | Capabilities are short-lived and minted by node code (DD §4.7.2), so a node needs an online key that speaks for the owner. The DD does not name one. G19 proposes it: certified by A1 with a scope and expiry, and used as the Biscuit root, to sign cards and directories, and to sign encryption-key statements. If compromised, the attacker can grant anything inside its scope until it expires or is revoked (ID-7). | Node (one per node, or per owner per machine) |

---

## 3. Actors

Each actor is a potential adversary, with what it can do *by position*. "Honest-but-curious" means it follows the
protocol and records what it sees.

| ID | Actor | Position and capabilities | Trust given by the design |
|---|---|---|---|
| X1 | **Network attacker** (on path) | Reads, drops, delays, reorders and injects packets between any two parties. | None. |
| X2 | **Relay operator** | Sees ciphertext, source and destination NodeIds, client IPs, timing and volume. Can drop and delay. Own or third-party. | Availability only (DD §4.3). |
| X3 | **Mailbox host operator** | Is a QUIC endpoint. Sees full envelopes (headers, and bodies until T15). Can drop, delay, reorder and replay, up to `exp`. | Content and availability before T15; availability only after T15 (DD §4.5). |
| X4 | **Malicious peer** (foreign owner) | Holds valid keys of its own owner. Sends well-formed but hostile envelopes, lies in every unsigned-by-others field, injects text, misuses granted capabilities, does not cooperate. | Exactly what its capabilities grant. |
| X5 | **Malicious delegate** (B in A → B → C) | Holds a mandate and/or access token. Tries to exceed scope, reuse it for other tasks, or launder results. | The mandate's scope. |
| X6 | **Compromised own node** | Has the owner's certification for its node and agent keys. | Inside the owner's trust boundary (DD §4.7.4). |
| X7 | **Malicious or compromised local agent / local process** | Can reach the node's MCP facade or local A2A port on the same machine. May be an LLM agent already under prompt injection. | Not specified yet (G1). |
| X8 | **Content author** (indirect injection) | Never talks to us. Writes web pages, files, emails or tool output that some agent later reads and passes on. | None. Their content arrives under the forwarder's identity. |
| X9 | **Vanilla A2A client** at the HTTP edge | Authenticated with OAuth or mTLS, or not at all. No webway signatures. | `unverified-origin` (DD §3.2). |
| X10 | **Discovery infrastructure** | DNS, the web host for `did:web`, owner directory host, pkarr/DNS discovery, future registries. Can withhold, serve stale data, or (if compromised) serve wrong key bindings. | Integrity of the binding only if not pinned (DD Q3). |
| X11 | **Insider at the owner** with access to the node host | Can read disks, edit the audit log, restore backups, change the clock. | Full control of that node. The audit design aims to make their edits *detectable by others*. |

---

## 4. Trust boundaries

```
   owner A                                  │ B8 │                              owner B
                                            │    │
   [LLM context]                            │    │
        │ B7                                │    │
   agent ──B1── node A1 ──B2── node A2      │    │
                  │                         │    │
                  ├──B3── relay (sees ciphertext + NodeIds) ─────── node B1 ──B1── agent
                  ├──B4── mailbox host (sees envelopes) ─────────── node B1
                  ├──B5── HTTP edge ◄── vanilla A2A clients
                  └──B6── discovery (DNS, did:web, pkarr, owner directories, registry)
```

| ID | Boundary | What crosses | Controls at the boundary |
|---|---|---|---|
| B1 | **Agent ↔ its own node** (same machine) | Unsigned requests (MCP, local A2A). The node signs on the agent's behalf. | DD: "localhost only". **No agent authentication** (G1). |
| B2 | **Node ↔ node, same owner** | Signed envelopes over QUIC. | Mutual node-key TLS, envelope signatures, capabilities. Same-owner is *not* ambient trust (DD §3.2). |
| B3 | **Node ↔ relay** | QUIC datagrams addressed by NodeId. | QUIC end to end between nodes. The relay sees only routing metadata. |
| B4 | **Node ↔ mailbox host** | Whole envelopes, stored for up to `exp`. | Signatures (integrity). Sealing (confidentiality, T15). |
| B5 | **HTTP edge ↔ vanilla A2A** | Unsigned A2A requests, push webhooks out. | A2A auth schemes, `unverified-origin` taint. |
| B6 | **Node ↔ discovery** | Key bindings, cards, address records. | Signed cards and directories, pinning. |
| B7 | **Node ↔ LLM context** | Remote text, artefacts, memory, card text, tool descriptions. | Provenance labels, labelled containers, policy hooks (DD §4.7.4). |
| B8 | **Owner ↔ owner** | Everything above, across owners. | Capabilities rooted in the resource owner, mandates, audit receipts. |

B7 is the boundary the protocol cannot fully enforce: the node controls what goes into the model's context and
what the agent may do afterwards, but not what the model concludes from it.

---

## 5. Assumptions

If one of these fails, the listed mitigations fail with it.

1. **Cryptography**: Ed25519, BLAKE3, TLS 1.3 and HPKE are secure, and the implementations (`ed25519-dalek`,
   `rustls`, `quinn`/iroh, `biscuit-rust`) are correct. That Ed25519 *verification rules* are the same in every
   implementation is **not** assumed. It is a requirement (RPL-10).
2. **Owner root keys** stay offline or hardware-backed, and are used rarely: to certify nodes, agents and
   issuing keys, and to rotate. Everything signed often (capabilities, cards, encryption-key statements) is
   signed by an issuing key (A14) or an agent key.
3. **Each owner's nodes run honest code**, unless stated (X6 is treated as detectable, not preventable, DD §4.7.4).
4. **Clocks** are within `skew` of real time, or the node notices it is not (see RPL-5).
5. **Durable storage** does what it says: a write committed before an ack survives a crash (DD §4.4).
6. **Pinning is done correctly** out of band: the key someone pins for owner B really is B's.
7. **LLMs are not a security boundary.** Any model that reads attacker text may do what that text says. All
   mitigations in §6.7 limit what a model can *cause*, not what it *believes*.

---

## 6. Threats and mitigations

### 6.1 Relays and transport (B3, X1, X2)

| ID | Threat | Mitigation | Spec home | Status |
|---|---|---|---|---|
| REL-1 | Network attacker or relay reads or alters traffic. | QUIC TLS 1.3 end to end between nodes, with raw public keys. Relays forward ciphertext (DD §4.3). Envelope signatures on top (DD §4.4). | binding | Designed |
| REL-2 | Relay impersonates a node, or connects a node to the wrong peer. | Connections are addressed and authenticated by NodeId. The node checks that the peer's TLS key is the NodeId it dialled, and that the NodeId is certified for the agent in `to` / `from`. | binding, capability (identity) | Designed. The binding spec must state the NodeId ↔ agent-binding check. |
| REL-3 | Relay drops, delays or throttles traffic for chosen peers (selective DoS or censorship). | Several relays per node, direct paths after hole punching, mailbox fallback, `PeerUnreachable` is retryable (DD §4.4). The relay cannot tell envelopes apart by content. | binding, mailbox | Partial: a relay can still target a NodeId pair. Mitigated by choosing your own relay (DD Q7). |
| REL-4 | Relay learns the communication graph, timing, volume and client IPs. | None in the protocol. Self-hosted relays move this to the owner (DD Q7). | n/a | Gap G13, accepted. See §6.6. |
| REL-5 | Downgrade: attacker strips ALPN or forces an older binding version. | ALPN `webway/<major>` fails closed. Version and required extensions are in the *signed* Agent Card, so a peer can check what the other side should support (DD §4.8). | binding, profile | Designed |
| REL-6 | Using n0's public relays exposes metadata to a third party. | Development only (DD Q7). | profile (deployment note) | Designed |

### 6.2 Mailbox hosts (B4, X3)

| ID | Threat | Mitigation | Spec home | Status |
|---|---|---|---|---|
| MBX-1 | Mailbox host alters or forges envelopes. | Signatures and `body_hash` (DD §4.4). | envelope | Designed |
| MBX-2 | Mailbox host reads bodies. | Before T15: only use a mailbox host the sender's owner trusts with the content. After T15: sealed envelopes (HPKE) (DD §4.5). | mailbox, envelope (sealing) | Partial: a sender cannot see *which* mailbox host the recipient uses unless the card or address record says so. The sender's node must check it before sending an unsealed envelope. The spec must say where the mailbox host is declared and that this check is a MUST. |
| MBX-3 | Mailbox host reads headers even after sealing: `from`, `to`, `ctx` (task and context IDs), `cap` (tokens), `prov` (taint owners), `exp`. | None yet. T15 as described seals only the body. | envelope (sealing) | Gap G12 |
| MBX-4 | Mailbox host drops envelopes and tells the sender they were `delivered`. | None. DD §4.5 does not say who reports `delivered`. | mailbox | Gap G3 |
| MBX-5 | Mailbox host replays an envelope to the recipient. | Dedupe on `(from, id)` until `exp + skew`, durable (DD §4.4). | envelope | Designed |
| MBX-6 | Mailbox host reorders or withholds some events of a task. | Per-task `seq` (signed in `ctx`), gaps are visible, `SubscribeToTask fromSeq` recovers (DD §4.5). | mailbox | Designed. The spec must say what a receiver does on a `seq` gap (wait, then resubscribe). |
| MBX-7 | Strangers fill a mailbox so real envelopes get `MailboxFull` (DoS), or use it as free storage. | None. | mailbox | Gap G4. Must keep working once headers are sealed (see G12). |
| MBX-8 | Long-term recipient key compromise decrypts every stored sealed envelope that an attacker recorded. HPKE to a static key has no forward secrecy. | Not addressed. | envelope (sealing) | Gap G12. Forward-secrecy part. |

### 6.3 Malicious peers (B2, B8, X4)

| ID | Threat | Mitigation | Spec home | Status |
|---|---|---|---|---|
| PEER-1 | Peer impersonates another agent or owner. | Envelope signature by an agent key certified by an owner key the receiver pins (DD §4.7.1). | envelope, capability (identity) | Designed |
| PEER-2 | Peer uses a skill it was not granted, or a broader form of one. | Capability token rooted in the *resource owner's* key, checked by node code, deny by default (DD §4.7.2). | capability, profile | Designed |
| PEER-3 | Peer presents a token stolen from another holder. | Holder chain plus presenter = verified envelope key (DD §4.7.2). | capability | Designed |
| PEER-4 | Peer claims higher trust for its content (`trust: self`, `taint.owners = [receiver's owner]`). | Trust is computed by the receiver and clamped to the verified sender. Wire labels can only lower it (DD §4.7.4). | provenance | Designed |
| PEER-5 | Peer sends malformed input to crash or exploit the parser: deep JSON, huge numbers, duplicate keys, non-UTF-8, giant Biscuit tokens, Datalog that takes long to evaluate. | I-JSON rules and signer form (DD §4.4). Fuzzing (T19). | envelope, capability, profile | Partial. Folded into G15: no size, depth or evaluation limits are set yet. |
| PEER-6 | Peer sends the same `(from, id)` twice with *different* bodies (equivocation), to get two different results recorded, or to confuse dedupe. | Dedupe returns the stored response (DD §4.4). Nothing says the second body is an anomaly. | envelope, audit | Partial: the spec should require that a duplicate `id` with a different `body_hash` is rejected as `EnvelopeInvalid` and logged as an anomaly. Folded into G5. |
| PEER-7 | Peer abuses a granted capability: too many calls, huge inputs, long-running tasks. | Caveats (TTL, `max_calls`, argument constraints) and local quotas (DD §4.7.2). | capability, profile | Designed. `max_calls` needs state at the verifier, and the spec must say it is counted by the resource owner's node. |
| PEER-8 | Peer learns the receiver's IP address and so its location, because hole punching makes a direct connection. | None. | binding, profile | Gap G14 |
| PEER-9 | Peer denies having sent something (repudiation). | Signed envelopes, receipts, audit (DD §4.7.5). | envelope, audit | Designed |
| PEER-10 | The opposite problem: everything an agent sends is signed and transferable, so the recipient can prove to anyone what was said. In S2, a negotiation position can be shown to a competitor. | Not discussed in the DD. | profile (security considerations) | Gap G18. Design note, not a defect. |

### 6.4 Cross-owner delegation (S4, X5)

| ID | Threat | Mitigation | Spec home | Status |
|---|---|---|---|---|
| DLG-1 | B asks C for more than A allowed. | Mandate rooted in A, attenuated to the sub-task. C checks it covers the request (DD §4.7.2). | capability | Designed |
| DLG-2 | B reuses A's mandate for another task or after A is done. | Task-ID and TTL caveats on the mandate (DD §4.7.2). | capability | Designed |
| DLG-3 | A previous holder of the mandate presents it again. | Holder chain: only the last holder can present (DD §4.7.2). | capability | Designed |
| DLG-4 | Confused deputy at B: B handles a request from A and calls C with *B's own* access token and no mandate, so C cannot see that A is the real principal. | C's policy *can* require a mandate (DD §4.7.2), but C cannot tell that B is acting for someone. | capability, profile | Partial: the profile should require B's node to attach the mandate when an outbound request is caused by an inbound task from another owner. B's node knows this from taint and `ctx`. Folded into G10. |
| DLG-5 | A revokes, but C still accepts the mandate, because C checks A's revocation list rarely or cannot reach it. | Short TTL by default, revocation IDs (DD §4.7.2). | capability | Gap G11 |
| DLG-6 | B launders C's result: it forwards it to A without C in `taint.owners`. A's policy "never accept content from owner C" does not fire. | Trust is still clamped to `foreign` because B is foreign to A, so A's trust level is right. Only the *owner set* is wrong. | provenance | Gap G10 |
| DLG-7 | C learns about A: the mandate chain names A's agents and owner. | Inherent: C must know the principal to check it. | capability (privacy note) | Designed, accepted. |
| DLG-8 | B and C collude to act beyond A's intent while staying within the literal mandate. | Narrow mandates (argument constraints, `max_calls`). Audit at A and receipts make it attributable. | capability, audit | Partial, accepted. |

### 6.5 Replay and freshness (X1, X3, X4)

| ID | Threat | Mitigation | Spec home | Status |
|---|---|---|---|---|
| RPL-1 | Replay inside the acceptance window. | Durable dedupe on `(from, id)` until `exp + skew`, and the duplicate gets the stored response (DD §4.4). | envelope | Designed |
| RPL-2 | Replay after expiry. | Reject when `now > exp + skew` (DD §4.7.3). | envelope | Designed |
| RPL-3 | Redirect a captured envelope to another recipient. | `to` is signed (DD §4.4). | envelope | Designed |
| RPL-4 | Replay into another task, stream position or request. | `ctx` (task, context, `seq`, `inReplyTo`) is signed. | envelope | Designed |
| RPL-5 | The receiver's clock is set back (NTP attack, insider X11) so expired envelopes are accepted again, after their dedupe entries were deleted. | None. Assumption 4 only. | envelope, profile | Gap G5. Clock part. |
| RPL-6 | The node restores its store from a backup, or loses it. Dedupe entries since the backup are gone, so envelopes processed since then are processed again. | None. | envelope, profile | Gap G5 |
| RPL-7 | A signature made for one purpose is accepted as another: an agent's envelope signature reused as a doc-change signature, receipt, or Biscuit third-party block, or an owner's binding statement accepted as a card. | Envelopes contain `v: "webway-envelope/0"`. No general rule. | envelope, all extensions | Gap G2 |
| RPL-8 | A third party replays a captured duplicate to read the stored response. | Response is `to`-bound. Bodiless `duplicate` ack over a connection not authenticated as the sender's node or its mailbox host (DD §4.4). | envelope | Designed |
| RPL-10 | Two verifiers disagree on whether a signature is valid: non-canonical `S`, non-canonical or small-order public key `A` or point `R`, batch vs single verification. One node dedupes, logs or forwards an envelope another rejects, and audit verification differs across nodes. | None. The DD names Ed25519 but no verification rules. | envelope (T2), all signed objects | Gap G2. Needs negative vectors: non-canonical `S`, small-order `A`, small-order `R`, non-canonical `A` encoding. |
| RPL-9 | An old, validly signed Agent Card or owner directory is served again, after the owner changed keys, interfaces or skills. | Binding statements have `valid until` (DD §4.2). Cards have no stated version or expiry. | capability (identity), discovery | Gap G16 |

### 6.6 Metadata leakage (A11)

Content is protected by TLS, sealing and capabilities. Metadata mostly is not. This table lists who learns what.

| ID | Who learns | What | Mitigation | Spec home | Status |
|---|---|---|---|---|---|
| META-1 | Relay (X2) | NodeId pairs, client IPs, timing, sizes. | Self-hosted relays (DD Q7). | binding (security considerations) | Gap G13, accepted. See §8. |
| META-2 | Mailbox host (X3) | Before G12: all header fields, including capability tokens and taint owner lists, and bodies until T15. With G12 and G4: only `to`, `exp`, size, and the deposit token ID, which is a stable pseudonym per sender, so the host still learns how much each (unnamed) sender deposits. | T15 for bodies, G12 for headers. | envelope (sealing), mailbox | Gap G12 |
| META-3 | Anyone resolving a NodeId | Home relay and possibly direct IP addresses, if published in public DNS/pkarr records. | Local or private discovery for tests (DD §4.2). | discovery (T17) | Gap G14 |
| META-4 | Direct peer (X4) | The other node's IP address. | None. | binding, profile | Gap G14 |
| META-5 | Every later receiver of a Part | `taint.owners`: the set of owners whose content went into it. A learns that B works with D. | None. Taint has to be complete to be safe (DD §4.7.4), so it cannot just be dropped. | provenance | Gap G17 |
| META-6 | Every later holder of a token | The holder chain and all caveats: who delegated to whom, task IDs, argument constraints. | Inherent in Biscuit. | capability | Partial: the spec should say tokens are readable by every holder and must not contain secrets. |
| META-7 | Blob providers, and whoever reads a `webway-blob:` URL | Who fetches which hash. Which nodes hold a blob (the `providers` list). | Capability needed to *read*, not to learn the hash (DD §4.5). | blob | Partial: `providers` should list only nodes the recipient is meant to contact. |
| META-8 | Anyone with a guess | `derived-from` hashes let someone confirm a guessed input (a known file, a short string). | None. | provenance | Partial: the spec should use keyed hashes or allow `derived-from` to be omitted across owners. Folded into G17. |
| META-9 | Counterparties holding checkpoints | Tree size shows activity volume over time. | None. | audit | Gap G13, accepted. Low impact. |
| META-10 | Anyone fetching cards or directories | Which agents and skills an owner runs. | Authenticated extended cards (A2A §8), owner directories may be private. | capability (identity), discovery | Designed |
| META-11 | Error responses | `CapabilityDenied` details can reveal policy and token structure. | None stated. | profile (error model) | Partial: errors to foreign peers should say *that* it was denied, not *why*. The reason goes in the local audit log. Folded into G15. |

### 6.7 Prompt injection through agent content (B7, X4, X8)

The DD's position (§2.5, §4.7.4): we cannot detect injection reliably, so the protocol labels content, keeps data
apart from instructions, and lets policy limit what tainted tasks may do.

| ID | Threat | Mitigation | Spec home | Status |
|---|---|---|---|---|
| INJ-1 | Remote message text tells the local agent to do something ("ignore previous instructions…"). | Content is delivered as data in a labelled container. The MCP facade returns it as a tool *result*, never as system or user text (DD §4.7.4 (2)). | provenance (MCP facade rules) | Designed. Limits impact, does not prevent. |
| INJ-2 | Injected text makes the agent call a side-effecting capability (deploy, pay, send mail). | Policy hooks: foreign-tainted tasks need human confirmation for capabilities with external side effects. Dual-LLM / quarantined reader (DD §4.7.4 (3)). | provenance, profile (policy) | Designed |
| INJ-3 | Injected text makes the agent *send private data* to a foreign peer (the exfiltration leg of the lethal trifecta). Inbound taint marks the *task* as foreign, but nothing stops the agent from putting private data into an outbound message to that peer or to another foreign owner. The data may never have passed through the node (the agent read it from its own files, shell or browser, A13), so the node cannot recognise it. | Only partly, by INJ-2 if "send to foreign" counts as a side effect. | provenance, profile (policy) | Gap G9 |
| INJ-4 | Injected text makes the agent ask for broader capabilities, or pass tokens around in text. | Only node code mints (with the issuing key, A14) and attenuates tokens. Tokens never appear in text (DD §4.7.2, §4.7.4 (4)). | capability, provenance | Designed |
| INJ-5 | Taint is lost on the way: through same-owner hops, relays, storage, blobs, bridges, the HTTP edge. | Taint is per Part, signed, lower-only, MUST be set and forwarded. Receiver takes the minimum (DD §4.7.4 (1)). Conformance tests (DD §4.7.4 (5)). | provenance | Designed |
| INJ-6 | Taint is lost inside the agent: it stores foreign text in its own files or memory outside the node, and uses it later in an untainted session. | The node taints derived content by what *it* gave the agent (DD §4.7.4). It cannot see the agent's own storage. | provenance (stated limitation) | Partial: the spec must state this limit. Agents that keep their own state should keep it in shared docs or node storage, where taint is kept. |
| INJ-7 | **Agent Card text** (name, description, skill descriptions, examples) is attacker-controlled and ends up in the planner's context during discovery. | Not covered: §4.7.4 labels Parts, not cards. | provenance, capability (identity) | Gap G8 |
| INJ-8 | **Tool descriptions** that the MCP facade generates from remote skills carry injected text into the local agent's tool list (MCP "tool poisoning"). Tool lists are often treated as more trusted than tool results. | Not covered. | provenance (MCP facade rules) | Gap G8 |
| INJ-9 | Injected text in *metadata fields* that reach the model: task status messages, error messages, artefact names, file names, MIME types. | Not covered explicitly. | provenance | Gap G8 |
| INJ-10 | **Shared memory** poisoning: a foreign agent writes a "decision" that later steers same-owner agents, long after the conversation (S3). | Entries keep their `foreign` label forever (DD §4.6). Each change is signed and capability-checked. | shared-doc, provenance | Partial: an edit by a *same-owner* agent that read foreign entries must carry foreign taint too. The DD says this for messages, not doc changes. Folded into G8. |
| INJ-11 | An HTTP-edge client injects through the gateway, and the content then looks like it came from the gateway's own owner. | `taint.unverified`, `unverified-origin` survives hops (DD §3.2, §4.3). | provenance | Designed |
| INJ-12 | A compromised own node (X6) launders taint. | Out of reach by design. Detectable by audit of taint in and out (DD §4.7.4). | audit | Designed, accepted. Detects, does not prevent. |

### 6.8 Audit-log tampering (A9, X6, X11)

The audit log is a hash chain with signed checkpoints that peers can hold (DD §4.7.5). What it protects
against depends on whether anyone outside the node has seen a checkpoint.

| ID | Threat | Mitigation | Spec home | Status |
|---|---|---|---|---|
| AUD-1 | Edit or delete an entry that is already covered by a checkpoint that another party holds. | Consistency proofs against the held checkpoint (DD §4.7.5). | audit | Designed |
| AUD-2 | Rewrite or drop the *tail*: entries written after the last checkpoint that anyone else holds. | Checkpoints every N entries or T seconds. Receipts give `audit position`. | audit | Gap G7: a receipt with only a position does not commit to the log's contents. The node can rewrite the entry at that position. |
| AUD-3 | **Fork** (equivocation): show checkpoint X to peer P and a different checkpoint X′ to peer Q. Each peer sees a consistent log. | None. Detection needs P and Q (or a witness) to compare. | audit | Gap G6 |
| AUD-4 | Roll the whole log back to a backup, or delete it. | Peers holding later checkpoints detect it, if they ever ask. | audit | Partial: detection needs a protocol to ask for consistency with a held checkpoint. Folded into G6. |
| AUD-5 | Never log an event at all (omission). | Counterparty receipts and their own logs show the event happened. | audit | Partial, accepted. The log proves what was logged. Completeness can only be checked against counterparties. The spec must state this. |
| AUD-6 | Insider with the node key re-signs a fully rewritten log. | Only checkpoints held by others reveal it. Key events are logged. | audit, capability (identity) | Partial. As AUD-3 and AUD-4. Folded into G6. |
| AUD-7 | Lie about time: `received_at` in receipts and log entries is self-asserted. | None. | audit | Partial, accepted. Times are claims. Order comes from the chain. Cross-owner disputes can use the counterparty's `ts` and `exp`. |
| AUD-8 | The audit log leaks data: full signed headers (and bodies, by policy) of other conversations, when exported for a dispute or shown in the inspector. | Body redaction by policy (DD §4.7.5). Inclusion proofs can show one entry without the rest. | audit, inspector (T16) | Partial: export must be by inclusion proof of selected entries, not a log dump. The inspector needs its own access control. |
| AUD-9 | Flood the log (causing many logged events) to fill disk or push real events out of rotation. | Rate limits (DD §4.7.2). | audit, profile | Partial: retention and rotation need rules that keep the chain verifiable. Folded into G15. |

### 6.9 Identity and discovery (B6, X10, A1–A3)

| ID | Threat | Mitigation | Spec home | Status |
|---|---|---|---|---|
| ID-1 | DNS or web host compromise binds the wrong key to a name (`did:web`, DNS TXT). | Pinning is the default for M1. Once pinned, a key change needs a successor statement signed by the old key (DD §4.2, Q3). | capability (identity), discovery (T17) | Partial: first contact by name is trust on first use. The spec must say that a binding never overrides a pin. |
| ID-2 | Owner root key compromised. The attacker can also sign a "successor" statement and take over the identity for good. | Rotation by successor statement (DD §4.2). | capability (identity) | Gap G11. No recovery path for a compromised root key. |
| ID-3 | Node compromised. All agent keys on it are exposed, and its issuing key (A14) too. | Per-node certification with expiry. | capability (identity) | Partial. Certificate revocation needs the same distribution as capability revocation. Folded into G11. The issuing key is ID-7, folded into G19. |
| ID-4 | Invite token intercepted on the way (chat, mail). | Capability in the invite is bound to a named key (DD §6 step 1). | capability (invites) | Partial: the DD also mentions a "one-time capability" in invites. If it is a bearer token, an interceptor can redeem it first. The spec must make invites holder-bound or single-use with confirmation. Folded into G16. |
| ID-5 | Registry or directory withholds or censors cards. | Signed cards make registries untrusted for integrity (DD §4.2). Several discovery paths. | discovery | Designed, accepted. Availability is not protected. |
| ID-7 | Issuing key (A14) compromised, through a compromised node (X6) or insider (X11). The attacker can mint capabilities for anything in the key's scope, re-sign cards and directories, and publish its own encryption keys (so it can read new sealed mail). | None: the DD has no such key. | capability (identity) | Gap G19 |
| ID-6 | Key confusion across roles: the node key is both the TLS identity and (possibly) a signing key, and the owner key signs cards, bindings and Biscuit roots. | None stated. | all | Gap G2 |

### 6.10 The local boundary: agent ↔ node (B1, X7)

| ID | Threat | Mitigation | Spec home | Status |
|---|---|---|---|---|
| LOC-1 | Any local process (another user's process, a browser exploit calling `localhost`, a sandboxed tool) talks to the MCP facade or local A2A port and gets the node to sign envelopes as one of its agents. | "localhost only" (DD §4.1). That is not authentication: on a shared machine (like a VPS running many agents) every process can reach localhost. | profile, MCP facade (T12) | Gap G1 |
| LOC-2 | Agent X on a node uses agent Y's identity or capabilities on the same node. | Not specified. The node holds all agent keys. | profile, capability | Gap G1 |
| LOC-3 | DNS rebinding from a browser to the node's local HTTP ports. | Not specified. | profile | Gap G1 |

### 6.11 Artefacts and shared documents (A6, A7)

| ID | Threat | Mitigation | Spec home | Status |
|---|---|---|---|---|
| ART-1 | Provider serves wrong or corrupted blob bytes. | BLAKE3 verified streaming, chunk by chunk (DD §4.5). | blob | Designed |
| ART-2 | Someone who learns the hash fetches the blob. | Read needs a capability scoped to the hash (DD §4.5). | blob, capability | Partial: when several providers (other owners) serve one blob, the spec must say whose key roots the capability and how a provider checks it. |
| ART-3 | Taint is lost when a blob is fetched from a different provider than the one that referenced it. | Taint is on the referencing Part, not the blob (DD §4.7.4). | blob, provenance | Designed. The spec must say the receiver takes taint from the referencing Part, never from the provider. |
| ART-4 | Huge declared `size`, slow-drip providers, many parallel fetches. | Verified streaming detects bad data, not bad sizes. | blob | Partial. Folded into G15. |
| ART-5 | `providers` list makes the receiver connect to arbitrary NodeIds chosen by the sender (reveals IP, used as a probe). | None. | blob | Gap G14 |
| DOC-1 | Unauthorised change to a shared doc. | Every change signed, checked against a capability when syncing and applying (DD §4.6). | shared-doc | Designed |
| DOC-2 | Readers can see deleted content: CRDT history keeps everything, and revoking read access does not un-share history already synced. Read access cannot be scoped to a path: every reader of an Automerge document syncs all of it. | Not addressed. | shared-doc | Gap G18. Design note: one doc = one read audience. |
| DOC-3 | A writer floods a doc with changes (history growth). | Snapshots and compaction (DD §4.6). | shared-doc | Partial. Compaction is specified in T14. |

### 6.12 HTTP edge gateway and bridges (B5, X9)

| ID | Threat | Mitigation | Spec home | Status |
|---|---|---|---|---|
| EDGE-1 | Vanilla client content is treated as trusted. | `unverified-origin` and `taint.unverified` (DD §3.2). | provenance, profile | Designed |
| EDGE-2 | Confused deputy at the gateway: the gateway holds overlay capabilities and any edge client can make it use them. | OAuth tokens at the edge are mapped to internal capabilities by the gateway (DD Q4 (d)). | profile (gateway) | Partial: the mapping must be per edge client, never "the gateway's own token for everyone". Folded into G10. |
| EDGE-3 | Push webhooks at the edge used for SSRF. | A2A §13.2 guidance applies. | profile (gateway) | Designed. Inherited from A2A. |
| EDGE-4 | A webway peer reached via the edge loses its guarantees without noticing. | The edge labels everything `unverified-origin`. | profile | Designed |
| EDGE-5 | Bridges (SLIM, NATS, MCP tool exposure) drop taint or signatures. | Bridges are edge adapters and must set `taint.unverified` like the HTTP edge (DD §3.2). | provenance, bridges (T18) | Designed. Conformance must cover each bridge. |

### 6.13 Resource exhaustion (A12)

| ID | Threat | Mitigation | Spec home | Status |
|---|---|---|---|---|
| DOS-1 | Unauthenticated connection floods. | QUIC handshake costs, retry tokens. iroh relays authenticate clients by key. | binding | Partial |
| DOS-2 | Authenticated peer with no capability sends many envelopes, each needing signature checks, JSON parsing and Biscuit evaluation. | Rate limits and quotas (DD §4.7.2). | profile | Partial. Folded into G15: the spec must order checks cheapest first (size, then signature, then capability) and set limits. |
| DOS-3 | Dedupe storage exhaustion: many envelopes with long `exp`. | `exp − ts` cap, e.g. 7 days (DD §4.7.3). | envelope | Partial. Bounded only *per envelope*. Needs a per-sender quota. Folded into G15. |
| DOS-4 | Mailbox flooding. | See MBX-7. | mailbox | Gap G4 |
| DOS-5 | Expensive tasks or streams kept open forever. | Caveats, quotas, task timeouts. | profile | Partial |

---

## 7. Gaps

Each gap is something the due diligence does not yet mitigate, or mitigates only in part. "Before M1" means the
gap affects something that is in M1 (DD §6), so the M1 drafts should close it or say explicitly that they do not.

| Gap | Threats | Problem | Proposed direction | Track | When |
|---|---|---|---|---|---|
| **G1** | LOC-1, LOC-2, LOC-3 | The agent ↔ node boundary has no authentication. "localhost only" is not access control on a shared machine. | Each local agent authenticates to its node: Unix domain socket with file permissions or peer credentials, or a per-agent secret given at agent launch. Each local session is bound to one agent identity. Local HTTP checks `Host` and `Origin`. | T5, T12, profile | Before M1 |
| **G2** | RPL-7, RPL-10, ID-6 | No general signature rules: no domain separation between signature purposes or key roles, and no Ed25519 verification rules. | (a) Every signed object carries a type string in the signed bytes (`webway-envelope/0`, `webway-receipt/0`, `webway-checkpoint/0`, `webway-doc-change/0`, `webway-binding/0`, …). Verifiers check the type matches what they expect. Root, issuing, node and agent keys each sign only their own list of types. (b) Strict verification, the same everywhere: reject non-canonical `S` (≥ L), non-canonical point encodings, and small-order `A` and `R`. Use cofactorless single verification, never batch. Negative vectors for each case. | T2 (general rule), every extension | Before M1 |
| **G3** | MBX-4 | It is unclear who reports `delivered`. A mailbox host could report it falsely. | Only a recipient-signed ack or receipt moves a task to `delivered`. A mailbox host may report `stored`, which is a separate state and promises nothing. | T7 | Before M1 |
| **G4** | MBX-7, DOS-4 | Anyone can put envelopes in a mailbox. | Mailbox admission by a **deposit token** that the host can read even when the rest of the header is sealed (G12). The recipient's node issues each sender a deposit capability (`mailbox:<recipient>#deposit`, with quota caveats), held by a per-token key, not the sender's identity key. The sender wraps each deposit with that token and a signature by the token key. The host checks both, and counts quotas and scopes `MailboxFull` per token. Before T15 the host also sees `from`, but admission must not depend on it, so T15 does not break T7. The token ID is the only sender-linked field left in clear (META-2). | T7, T15 | Before M1 |
| **G5** | RPL-5, RPL-6, PEER-6 | Replay protection depends on the dedupe store and the clock, and neither may go backwards. (a) The node keeps a *store epoch* and a *clock high-water mark* **outside the backup set**: a separate file that backups exclude, an OS or TPM monotonic counter, or an operator flag at restore. If they live in the store, they roll back with it and the node cannot tell a restore happened. Restoring without advancing the epoch is outside the guarantee, and the spec says so. (b) When the node detects a restore or data loss at time `R`, it starts a new epoch and rejects every envelope with `ts ≤ R + skew`, because receivers accept `ts` up to `now + skew` (DD §4.7.3). A cutoff at `R` alone would let in an envelope from a fast-clocked sender that was processed just before the loss. The rejection is retryable, with `retryAfter`. Honest senders resend with a new `id` and a fresh `ts`, after up to 2 × `skew`. The node also announces the epoch change to peers. Work done in the lost period may then run twice. That cannot be avoided once the state is gone, but the sender now knows it can happen. (c) Never accept a `now` earlier than the high-water mark. (d) Same `(from, id)` with a different `body_hash` is `EnvelopeInvalid` and an audit anomaly. Conformance case: restore within `skew` of the last processed envelope, sender clock at `+skew`, and the replay is rejected. | T2, T5 | Before M1 |
| **G6** | AUD-3, AUD-4, AUD-6 | An audit log can fork (show different histories to different peers) or be rolled back, and nobody compares. | Checkpoint gossip: peers that hold checkpoints exchange them on contact and ask for consistency proofs. Optional *witnesses* (another node of the owner, or a counterparty) that co-sign checkpoints, as in CT witness co-signing. | T9 | Before M1 (gossip between the two M1 owners), witnesses later |
| **G7** | AUD-2 | Receipts commit to a position, not to the log contents, so the tail before the next checkpoint can be rewritten. | Receipts include the chain hash after the entry is appended. A later checkpoint must be consistent with it. | T9 | Before M1 |
| **G8** | INJ-7, INJ-8, INJ-9, INJ-10 | Provenance covers Parts, but not other attacker-controlled text that reaches the model: card and skill descriptions, generated MCP tool descriptions, status and error messages, file names, and same-owner doc edits made after reading foreign entries. | Extend `provenance/v0`: every string from a peer that may reach a model is treated as a tainted Part. The MCP facade puts remote descriptions only in labelled results, or replaces them with descriptions the owner approved. Doc changes carry the author session's taint. | T13, T14, T12 | With T13 |
| **G9** | INJ-3 | Taint tracks where content came from, not where it may go. A prompt-injected agent can send same-owner private data to a foreign peer. | An outbound rule the node can actually check, because it looks only at the task's taint and the destination, not the data. In a foreign-tainted task or session, **any** outbound send to a foreign owner *other than the task's originator* needs an explicit grant or human confirmation. Replies to the originator are allowed only within the inbound task's capability (results of the requested skill, on that task). Optional refinement for data that passes through the node: confidentiality labels on Parts (`share-with: [owners]`). Stated limit, as in INJ-6: the node cannot see agent-local data, so the labels never replace the coarse rule. This is the exfiltration leg of the lethal trifecta. | T13, T6 | With T13. Decision for the owner: is this in `provenance/v0` or a separate extension? |
| **G10** | DLG-4, DLG-6, EDGE-2 | Owner sets in taint are only as honest as the last foreign forwarder. Mandates are optional. Gateways may share their own capabilities with all edge clients. | (a) The profile requires a mandate on any outbound request caused by an inbound task from another owner. (b) Optionally the forwarder includes the *signed* upstream envelope headers as evidence for `taint.owners`, so a receiver can verify part of the owner set. (c) Gateway capability mapping is per edge client. | T3, T13, T11 | (a) with T3, rest later |
| **G11** | DLG-5, ID-2, ID-3 | Revocation has no freshness rule and no distribution channel. A compromised root key cannot be recovered. | (a) Revocation lists are signed with a sequence number and `valid until`. A verifier that cannot get a fresh list *fails closed* for capabilities longer than a spec constant, and short-lived tokens (≤ that constant) need no check. (b) Pre-rotation: the owner key commits to the hash of its next key (as in KERI or `did:plc` rotation keys), so a thief cannot also issue a successor. | T3 | (a) before M1 if M1 tests revocation, (b) with T3 |
| **G12** | MBX-3, MBX-8, META-2 | Sealing as planned hides bodies but not headers, and has no forward secrecy. | Seal everything except what the mailbox host needs for routing and expiry (`to`, `exp`, a size). `from`, `ctx`, `cap` and `prov` go inside, under the signature. Admission uses the deposit token (G4), the only sender-linked field left in clear. Use a separate X25519 encryption key per agent, published in a short-lived statement signed by the issuing key (A14) or the agent key, not in the root-signed card, and rotated often. Forward secrecy needs the old private keys to be *deleted* after rotation (plus the envelope's `exp`), not just retired. | T15 | With T15 |
| **G13** | REL-4, META-1, META-9 | Relays learn the communication graph. Checkpoint tree sizes show activity volume. | Accepted for v0 (§8). Document it. Owners self-host. Later options: padding, mixing, onion routing. | T1 (security considerations) | Document now |
| **G14** | PEER-8, META-3, META-4, ART-5 | Direct connections and public address records reveal IP addresses. Blob `providers` lists make receivers contact NodeIds the sender chose. | Policy option "relay-only for foreign peers". Discovery records for foreign-facing nodes publish only the relay. Receivers contact `providers` only if each is certified by an owner the receiver already accepts for this task. | T1, T8, T17 | With T1 (option), T8 |
| **G15** | PEER-5, META-11, AUD-9, DOS-2, DOS-3, ART-4 | No resource limits: message size, JSON depth, token size, Datalog run limits, per-sender dedupe quota, log retention. Errors to foreign peers may reveal too much. | A limits table in the profile, with spec constants and conformance vectors (just under and just over each limit). Order checks cheapest first. Denial reasons go to the local audit log, not to the peer. | T1, T2, T3, T19 | Before M1 |
| **G16** | RPL-9, ID-4 | Agent Cards and owner directories have no version or expiry, so old ones can be served again. Invites may contain bearer capabilities. | Cards and directories carry a monotonic version and `valid until`. Receivers keep the highest version seen per owner. Invites are holder-bound, or single-use with redemption confirmed by the issuer. | T3, T17 | With T3 |
| **G17** | META-5, META-8 | `taint.owners` and `derived-from` reveal who worked with whom, and can confirm guessed inputs. | Owner decision. Options: (a) accept and document, (b) replace owner keys with per-receiver blinded identifiers (the receiver can still tell "mine" from "not mine" but not which foreigner), losing owner-specific deny rules, (c) keyed hashes for `derived-from`. | T13 | Decision before T13 |
| **G18** | PEER-10, DOC-2 | Design notes rather than defects: signed messages are transferable proof (no deniability), and shared docs cannot hide history from readers. | Document both in the profile's security considerations. Shared docs: one document per read audience. Say clearly that revocation does not un-share. | T1, T14 | Document now |
| **G19** | ID-7, ID-3 | Capabilities are minted online by node code and rooted in the owner's key (DD §4.7.2), but the root key stays offline (assumption 2). The online key that does the signing is not named, scoped or analysed. G12 and G16 also need frequent signatures on cards and key statements. | An **issuing key** per node (A14). The root key certifies it with: the node, a *scope* (only resources and skills hosted on that node, unless the owner says otherwise), and a short expiry (e.g. 30 days, renewed). Verifiers accept a Biscuit root, card or key statement only through a chain issuing key → root key they pin. Compromise analysis: an attacker on the node (X6, X11) can mint capabilities within the scope until expiry or revocation. With the scope rule, that is no more than the node can already do with its own resources, but anything outside the scope (other nodes' skills, shared docs the owner roots) is protected. Every issuance is logged (audit). Revocation of the certificate uses G11. Note: this changes DD §4.2, where the owner key signs Agent Cards. | T3 | With T3 |

**Owner decisions** raised by this document (not blocking the drafts): G9 (where the outbound rule lives) and
G17 (how much owner metadata taint may carry). G19 changes who signs Agent Cards (DD §4.2), which T3 should
confirm. Both are noted here and do not need an answer before T1 or T2.

---

## 8. Out of scope

These are not handled, by choice, for v0. Each could become in scope later.

- **Traffic analysis resistance** against relays or a global network observer (G13). No padding, mixing or
  cover traffic.
- **Compromise of the owner's own machine** beyond detection by audit (X6, X11). An attacker with root on a node
  host can do what that node can do.
- **Prompt-injection detection.** Classifiers may be used as a policy *signal* (DD §5), never as a boundary.
- **The behaviour of the LLM itself** once content is in its context (assumption 7).
- **Side channels** in cryptographic implementations (timing, power).
- **Dependency and build integrity** (reproducible builds, signed releases). Handled by T19 and release process,
  not by the protocol.
- **Economic abuse** (payments, reputation, Sybil resistance in open registries). DD §9: "Out of scope until
  after M1 and T11–T14".
- **Legal non-repudiation.** Signatures and receipts give technical evidence. Whether they hold in a given
  jurisdiction is not a protocol question.

---

## 9. Using this document

- **Spec authors**: each spec document gets a *Security considerations* section that lists the threat IDs it
  handles (e.g. "`envelope/v0` handles RPL-1 to RPL-4, RPL-7, MBX-1, MBX-5") and the requirement IDs that do it.
  A threat with status *Designed* that no spec section claims is a review finding.
- **Conformance**: every *Designed* threat with a wire-observable mitigation gets at least one negative vector or
  harness scenario. Most M1 ones are already listed in DD §6. New ones from this document: duplicate `id` with a
  different body (PEER-6), restore from backup within `skew` with a fast sender clock (RPL-6, G5), Ed25519
  malleability and small-order keys (RPL-10), signature of one type presented as another (RPL-7),
  mailbox reporting `delivered` (MBX-4), mailbox admission by deposit token with a sealed header (MBX-7, G4), capability rooted in an
  issuing key outside its scope (ID-7), forked checkpoints (AUD-3), receipt then tail
  rewrite (AUD-2), injected card text reaching the MCP facade unlabelled (INJ-7), and each limit in G15.
- **Security review (T19)**: fuzz targets follow PEER-5 (envelope JSON, Biscuit tokens and Datalog, blob
  framing, Automerge sync messages). The review checks every *Partial* row and every gap in §7 again.
- **Updates**: each change proposal in `spec/changes/` that touches security says which threat rows it changes.
  A gap is closed by changing its status here and naming the spec requirement that closes it.
