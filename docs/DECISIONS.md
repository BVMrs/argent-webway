# Decision register

This page records the owner's decisions: what was chosen, when, and why. It starts with the seven questions in
[`docs/due-diligence.md` §8](due-diligence.md#8-decisions-needed) (DD). Answering them is roadmap item T0
([DD §7](due-diligence.md#7-roadmap)), and T1–T3 depend on it.

Other documents cite an entry by its ID (`D-Q1` … `D-Q7`). An item that depends on an entry with status `open` is
marked `(proposed)` where it appears, for example in `docs/CHARTER.md`. When the entry becomes `accepted`, the
PR that records it also removes those marks.

## How an entry changes

- **Status** is `open`, `accepted` or `rejected`. Only the owner moves an entry out of `open`. An agent records the
  owner's answer and cites where it was given (an issue or PR comment, or the owner's own commit).
- **accepted**: the owner chose the option in **Choice**. Rationale says why, in a sentence or two. If the owner
  accepted the DD recommendation as it stands, the rationale points to it instead of copying it.
- **rejected**: the owner turned the DD recommendation down. Choice records what replaces it, or `open` again with
  a new question.
- A decision is changed by a new entry (`D-Q1.1`, …) that supersedes the old one. Old entries stay, with
  `Status: superseded by D-Q1.1`, so the history can be read top to bottom.
- Every entry keeps the date of its last status change (YYYY-MM-DD).

## Summary

| ID | Question | DD recommendation | Status | Decided |
|---|---|---|---|---|
| [D-Q1](#d-q1-core-language) | Core language | Rust | open | — |
| [D-Q2](#d-q2-overlay-transport) | Overlay transport | iroh behind a transport trait, rust-libp2p as fallback | open | — |
| [D-Q3](#d-q3-human-readable-identity-binding) | Human-readable identity binding | pinned keys + petnames for M1, `did:web` / DNS next | open | — |
| [D-Q4](#d-q4-capability-token-format) | Capability token format | Biscuit (OAuth at the HTTP edge only) | open | — |
| [D-Q5](#d-q5-wire-encoding) | Wire encoding | JSON + JCS + Ed25519 for v0 | open | — |
| [D-Q6](#d-q6-namespace-and-governance) | Namespace and governance | GitHub URIs for v0, upstream to A2A after M1 | open | — |
| [D-Q7](#d-q7-relay-and-mailbox-operation) | Relay and mailbox operation | owners self-host; n0 public relays for development only | open | — |

The owner can accept all seven at once with a comment such as "Accept DD §8 Q1–Q7 as recommended". That
comment, with its link, is enough for an agent to fill in every entry below.

---

## D-Q1. Core language

- **DD**: [§8 Q1](due-diligence.md#q1-core-language), justified in
  [§5](due-diligence.md#5-language-choice-for-the-core-rust).
- **Options**: (a) Rust; (b) OCaml; (c) an OCaml executable spec model plus a Rust node.
- **DD recommendation**: (a) Rust.
- **Context**: the owner directive allows Rust or OCaml for the core and asks the DD to choose and justify.
- **Status**: open
- **Decided**: —
- **Choice**: —
- **Rationale**: —
- **Depends on it**: the language rule in `CONTRIBUTING.md` ("Rust or OCaml … the due diligence makes that
  choice"), crate layout under `crates/`, every command in the charter's demo and M1 acceptance criteria.

## D-Q2. Overlay transport

- **DD**: [§8 Q2](due-diligence.md#q2-overlay-transport), background in
  [§4.3](due-diligence.md#43-transports-and-nat-traversal).
- **Options**: (a) iroh; (b) rust-libp2p; (c) plain QUIC (quinn) plus our own relay; (d) SLIM.
- **DD recommendation**: (a) iroh behind a transport trait, (b) as the fallback backend, (d) bridged (T18).
- **Status**: open
- **Decided**: —
- **Choice**: —
- **Rationale**: —
- **Depends on it**: the `webway-quic/v0` binding (T1), the relay in the M1 devnet topology, NAT tests.

## D-Q3. Human-readable identity binding

- **DD**: [§8 Q3](due-diligence.md#q3-human-readable-identity-binding), background in
  [§4.2](due-diligence.md#42-identity-and-discovery).
- **Options**: (a) pinned keys and petnames only; (b) plus `did:web` / DNS TXT; (c) plus ANP `did:wba`;
  (d) plus SPIFFE federation.
- **DD recommendation**: (a) for M1, (b) next (T17); (c) and (d) only on demand. Keys stay the identity.
- **Status**: open
- **Decided**: —
- **Choice**: —
- **Rationale**: —
- **Depends on it**: identity and `capability/v0` (T3), invites in M1, discovery (T17).

## D-Q4. Capability token format

- **DD**: [§8 Q4](due-diligence.md#q4-capability-token-format), background in
  [§4.7.2](due-diligence.md#472-authorisation-per-capability).
- **Options**: (a) Biscuit; (b) UCAN; (c) Macaroons; (d) OAuth 2.0 with Token Exchange and DPoP.
- **DD recommendation**: (a) Biscuit with a holder chain of third-party blocks, plus an access token and a mandate
  for S4; (d) only at the HTTP edge, mapped to internal capabilities by the gateway. UCAN is the strongest
  alternative, especially for the mandate.
- **Status**: open
- **Decided**: —
- **Choice**: —
- **Rationale**: —
- **Depends on it**: `capability/v0` (T3) and its vectors, re-delegation in M1, the HTTP edge (T11).

## D-Q5. Wire encoding

- **DD**: [§8 Q5](due-diligence.md#q5-wire-encoding), background in
  [§4.4](due-diligence.md#44-message-and-task-model).
- **Options**: (a) a Protobuf frame carrying signed JCS bytes, JSON at the HTTP edge; (b) JSON (pinned proto3 JSON
  form of `a2a.proto`) + JCS everywhere; (c) CBOR/COSE everywhere.
- **DD recommendation**: (b) JSON + JCS + Ed25519 for v0; revisit (a) after M1 only if profiling asks for it.
- **Status**: open
- **Decided**: —
- **Choice**: —
- **Rationale**: —
- **Depends on it**: `envelope/v0` (T2) and every signed test vector, the `webway-quic/v0` framing (T1).

## D-Q6. Namespace and governance

- **DD**: [§8 Q6](due-diligence.md#q6-namespace-and-governance), background in
  [§4.8](due-diligence.md#48-versioning).
- **Options**: (a) a registered domain for extension URIs; (b) `https://github.com/BVMrs/argent-webway/...` URIs;
  (c) upstream into the A2A project from the start.
- **DD recommendation**: (b) for v0; (c) for envelope, provenance and blob after M1 (T20).
- **Status**: open
- **Decided**: —
- **Choice**: —
- **Rationale**: —
- **Depends on it**: every extension URI in `spec/ext/` and in the Agent Card examples.

## D-Q7. Relay and mailbox operation

- **DD**: [§8 Q7](due-diligence.md#q7-relay-and-mailbox-operation), background in
  [§4.5](due-diligence.md#45-delivery-offline-peers-streaming-and-artefacts).
- **Options**: (a) each owner self-hosts a relay and mailbox; (b) a shared community relay run by the project;
  (c) n0's public relays during development.
- **DD recommendation**: (a) as the model, (c) only for development. Relays see metadata (who talks to whom,
  when), which is sensitive across owners.
- **Status**: open
- **Decided**: —
- **Choice**: —
- **Rationale**: —
- **Depends on it**: `mailbox/v0` (T7), the charter's non-goal "a project-run production relay", the devnet relay.
