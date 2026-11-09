# `mailbox/v0` vectors

Vectors for [`spec/ext/mailbox.md`](../../../spec/ext/mailbox.md), in the format `webway-vectors/v0` (vector format
and stdio adapter protocol: `conformance/vectors/README.md`, issue #7). The kinds and their input and output shapes
are defined in spec §14.

| File | Kind | Source |
|---|---|---|
| `outbox-step.json` | `mailbox/outbox-step` | Generated from the two tables of spec §9.2 |
| `host-step.json` | `mailbox/host-step` | Generated from the table of spec §8 |
| `deposit-sig.json` | `mailbox/deposit-sig` | Generated with fixed test keys (BLAKE3 of a label, see `gen.rs`) |
| `admit.json`, `token.json`, `card.json`, `register.json`, `path.json`, `backoff.json`, `order.json`, `timing.json`, `reconnect.json` | as named | Written by hand from the spec text |

Identifiers in the hand-written files (`wwa:recipientaaa…`, `wwi:issueraaa…`) are well-formed placeholders, not
real keys. Signatures and Biscuit verification other than the deposit signature are given as their results,
because their own vectors belong to `ext/envelope.md` and `ext/capability.md`.

The reference model in [`conformance/tools/mailbox-model`](../../tools/mailbox-model) implements every kind
independently of the vectors (the state tables are read from the spec, the model is a separate `match`):

```sh
cd conformance/tools/mailbox-model
cargo run -- gen   ../../../spec/ext/mailbox.md ../../vectors/mailbox   # rewrite the three generated files
cargo run -- check ../../../spec/ext/mailbox.md ../../vectors/mailbox   # run all vectors against the model
cargo run -- adapter                                                    # stdio adapter for webway-conformance run
```
