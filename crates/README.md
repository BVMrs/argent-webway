# crates/

The Rust core. No code yet: it starts after the spec drafts (roadmap track T5).

Planned crates:

| Crate | Role |
|---|---|
| `webway-proto` | Wire types (A2A 1.0 + extension messages), canonicalisation |
| `webway-envelope` | Envelope signing and verification, replay protection |
| `webway-cap` | Identities, owner bindings, capability tokens, policy engine |
| `webway-overlay` | Transport trait, iroh backend, in-memory test backend |
| `webway-node` | Reference node: router, task engine, mailbox, blobs, audit, A2A HTTP edge, MCP facade |
| `webway-relay` | Relay and mailbox host |
| `webway-cli` | CLI and `devnet` multi-node local runner |
