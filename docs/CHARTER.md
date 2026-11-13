# argent-webway charter

Status: **draft for owner approval** (2026-11-12). The owner edits and approves this page. The planner proposes only
work that moves the current milestone. Sources: owner directives, [`docs/due-diligence.md`](due-diligence.md) (DD),
[`docs/research/a2a-mcp-interop.md`](research/a2a-mcp-interop.md), `spec/`, `conformance/`. There is no decision
register yet: DD §8 Q1–Q7 are still open, so anything that depends on them is marked `(proposed)`.

## 1. Objective

Build an architecture for agent-to-agent communication and sharing between remote agents across machines and owners.
It covers discovery, identity, messaging, task delegation, streaming, and sharing of context, artefacts and results.
The protocol is specified first with a conformance suite, interoperates with A2A and MCP, and builds in security.

## 2. Demo `(proposed)`

```sh
cargo run -p webway-cli -- devnet demo m1 --nodes 3 --nat --dataset agentdojo   # (proposed) nothing exists yet
```

- **Topology** (DD §6): `relay`, `alpha` (owner A, agent `planner`), and `beta` (owner B, agent `tester`, skill
  `run-tests`). Direct alpha ↔ beta dialing is forbidden, so all traffic takes the relay path.
- **Dataset**: the AgentDojo prompt-injection suite (Debenedetti et al., *AgentDojo: A Dynamic Environment to
  Evaluate Prompt Injection Attacks and Defenses for LLM Agents*, NeurIPS 2024 Datasets & Benchmarks,
  arXiv:2406.13352, MIT licence; 97 user tasks, 629 security cases). CaMeL (arXiv:2503.18813, DD §2.5) uses it.
  A script fetches it at a pinned commit and checksum. The demo does not run an LLM. `beta` returns the injection
  payloads as artefact and message content, which is exactly the untrusted cross-owner content of DD scenario S2.
- **What the owner sees**: a table with one row per M1 step (DD §6, steps 1–9) and PASS/FAIL. Under it are counts:
  tasks sent, delivered exactly once, lost, duplicated; forged, expired, replayed and out-of-capability envelopes
  rejected; payloads labelled `foreign` or `unverified-origin` (target 100 %); injected requests that got a
  capability granted (target 0); audit chains and receipts verified. At the end it prints the path to each node's
  audit log, and `webway audit verify <path>` re-checks that log.

## 3. Success criteria

1. **Conformance**: every spec `MUST` has a requirement ID and at least one test, and the reference node passes them
   all. `cargo run -p webway-conformance -- report` prints 0 untested and 0 failing `MUST`s. `(proposed command)`
2. **Injection boundary**: over all AgentDojo payloads, 100 % reach `planner` labelled `foreign` or
   `unverified-origin`, and 0 cause an authorisation beyond the presented capability (demo above, 3 seeds).
3. **Offline and NAT**: with direct dialing forbidden and `beta` down for longer than the skew window, 0 lost and
   0 duplicated tasks and stream events over 100 seeded fault-injection runs (`devnet test m1 --seeds 100`).
   A task is **lost** if it is neither delivered nor reported `expired` to its sender. A task whose `exp` passes
   while `beta` is down is expected to expire (DD §6 step 6); it counts as lost only if `planner` is never told.
4. **Interop**: a vanilla A2A 1.0 client built with the official SDK completes a task through `beta`'s HTTP edge.
   That client's input reaches `alpha` labelled `unverified-origin` (DD §6 step 9).
5. **Audit**: both nodes' logs, checkpoints and receipts verify offline with the audit/v0 vectors' reference
   verifier and with the node's own verifier.

## 4. Current milestone: M1, delegated task across owners on one machine (DD §6)

**Why first**: M1 exercises every directive at once: protocol first, relay-only NAT path, offline peer, signed
envelopes, capabilities, provenance labels and the audit log. It needs no public IP, DNS or cloud account. Every
later track (T11–T20) builds on the node and the spec it produces.

Acceptance criteria. Command names other than the audit-vectors ones are `(proposed)`:
1. The v0 spec drafts are merged: `ls spec/profile.md spec/binding-webway-quic.md spec/ext/{envelope,capability,mailbox,blob,audit}.md`.
2. The vectors regenerate byte for byte from the generators. Today:
   `cargo run --manifest-path conformance/tools/audit-vectors/Cargo.toml -- --check`. M1 adds one such check per module.
3. No untested `MUST`: `cargo run -p webway-conformance -- report --fail-on-untested` exits 0.
4. Scenario steps 1–8 pass against the reference node on loopback with `--nat`:
   `cargo run -p webway-cli -- devnet test m1 --nodes 3 --nat` exits 0.
5. Step 9 passes against an upstream A2A SDK: `cargo run -p webway-conformance -- interop a2a-sdk` exits 0.
6. The workspace builds and its tests pass: `cargo test --workspace`, plus CI green on the PR.

**Next**: M2 `(proposed)`, edges and boundaries: the A2A HTTP edge, the MCP facade and `provenance/v0` (T11–T13).
M3 `(proposed)`, sharing and visibility: `shared-doc/v0`, the inspector UI and discovery (T14, T16, T17).

## 5. Non-goals

- A new task model, discovery or streaming protocol. We reuse A2A 1.0 and add a profile, extensions and a binding.
- A claim that prompt injection cannot succeed. Labels and capabilities limit its impact. An ML classifier, if one
  is ever added, is a policy signal and never a security boundary (DD §5, §9).
- In M1: shared docs, sealed envelopes, registries, the inspector UI, and an MCP facade beyond a stub (DD §6).
- Registries, payments and reputation until after M1 and T11–T14. SLIM and NATS bridges only on demand (T18).
- A project-run production relay. Owners self-host. n0's public relays are for development only (Q7, `(proposed)`).

## 6. Constraints

- **Languages** (directive): the core in Rust or OCaml. The DD recommends Rust (Q1, awaiting confirmation). Any UI
  in React + TypeScript (bun). Python only for ML pieces. Nothing else.
- **Protocol first, security in the design** (directives): each feature's spec, with its capability, signing,
  provenance and audit rules and its conformance vectors, lands before or with the code that implements it.
- **Platform**: Linux (`cogitator-primum`), several nodes on one machine, with no root, public IP, DNS or cloud
  account (DD R12, S6). **GPU**: none needed `(proposed)`. **Budget**: not stated by the owner.
- **Process** (CONTRIBUTING): one concern and about 400 lines per PR, an owner approval on every merge, and agents
  never push or merge.

## 7. Open questions for the owner

1. **Approve the DD §8 recommendations (Q1–Q7) as a block?** Rust, iroh behind a transport trait, pinned keys,
   Biscuit, JSON + JCS + Ed25519, GitHub URIs, self-hosted relays. *Recommendation: yes. Record the answers in a
   decision register so that the `(proposed)` marks above can be removed.*
2. **Is AgentDojo the right demo dataset?** *Recommendation: yes. It is the standard benchmark for the threat our
   provenance and capability design targets, and CaMeL uses it. InjecAgent (arXiv:2403.02691) is the fallback.*
3. **Which upstream A2A SDK runs the step 9 interop test?** *Both options need a test-tooling exception to the
   language rule: TypeScript is allowed only for UI, and Python only for ML pieces, so neither a2a-js (via bun) nor
   a2a-python (as a test client) is covered. Recommendation: grant the exception for a2a-js via bun, because the lab
   already compared it with a2a-python and the repo already has bun for the UI. The exception covers the test client
   only, never the core.*
