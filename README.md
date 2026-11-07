# argent-webway

An architecture for agent-to-agent communication: how remote agents discover each other, talk, delegate work,
and share context, artefacts and results, safely, across machines and owners.

Status: **due diligence**. Read [`docs/due-diligence.md`](docs/due-diligence.md). It has no protocol code yet.

## Approach (proposed)

- An **A2A 1.0 profile + extensions** (signed envelopes, capabilities, mailbox, blobs, provenance, audit,
  shared docs), plus an A2A **transport binding over an authenticated QUIC overlay** with relays for NAT traversal.
- Standard A2A HTTP bindings at the edge for interop. MCP between a node and its local agents.
- Protocol first: the written spec in `spec/` and the conformance suite in `conformance/` come before the node.

## Layout

| Path | What | Language |
|---|---|---|
| `docs/` | Due diligence, design notes, threat model | Markdown |
| `spec/` | The normative protocol spec: profile, binding, extensions, error model, versioning | Markdown |
| `conformance/` | Language-neutral test vectors and the black-box conformance harness | JSON + Rust |
| `crates/` | Core: overlay, router, reference node, relay, CLI/devnet | Rust |
| `ui/` | Inspector and dashboards | React + TypeScript |

Owner rules: the core is in Rust, any UI in React + TypeScript, Python only for ML pieces (if any), nothing else.
Security is part of the design (see §4.7 of the due diligence).
