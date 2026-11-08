# spec/

The normative argent-webway specification. Drafts so far: [`profile.md`](profile.md) (Profile of A2A 1.0,
v0.1) and [`binding-webway-quic.md`](binding-webway-quic.md) (binding `webway-quic/v0`, v0.1). They follow the
recommendations in [`docs/due-diligence.md` §8](../docs/due-diligence.md#8-decisions-needed) (Rust, iroh, JSON +
JCS) pending the owner's decisions.

Planned documents (see roadmap tracks T1–T3, T7–T9, T13–T14):

| File | Content |
|---|---|
| `profile.md` | argent-webway Profile of A2A 1.0: mandatory features, extra rules, error model, versioning |
| `binding-webway-quic.md` | A2A custom binding over the QUIC overlay (ALPN, framing, stream mapping) |
| `ext/envelope.md` | Signed envelopes, canonicalisation, replay protection |
| `ext/capability.md` | Identities, owner bindings, invites, capability tokens, revocation |
| `ext/mailbox.md` | Store-and-forward, delivery semantics, resumable streams |
| `ext/blob.md` | Content-addressed artefacts |
| `ext/provenance.md` | Trust and provenance labels, prompt-injection boundary rules |
| `ext/audit.md` | Hash-chained audit log, checkpoints, receipts |
| `ext/shared-doc.md` | Shared CRDT documents with signed, capability-checked changes |
| `changes/` | Numbered change proposals |

Conventions: RFC 2119 keywords. Every `MUST` gets a stable requirement ID (e.g. `ENV-012`) that the
conformance suite references. Every normative change comes with test vectors.
