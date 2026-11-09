# `audit/v0` test vectors

Vectors for [`spec/ext/audit.md`](../../../spec/ext/audit.md), in the format `webway-vectors/v0`. The kinds and
their input and output shapes are defined in §17.1 of the spec.

| File | Kind | Tests |
|---|---|---|
| `entry-hash.json` | `audit/entry-hash` | Entry form, entry hash `BLAKE3(0x00 ‖ JCS(entry))`, `hd` and `parties` of envelope entries |
| `chain.json` | `audit/chain` | Whole logs: genesis, `prev` chain, log and epoch, time order, Merkle root |
| `inclusion.json` | `audit/inclusion` | RFC 9162 inclusion proofs with BLAKE3 |
| `consistency.json` | `audit/consistency` | RFC 9162 consistency proofs with BLAKE3, equal sizes |
| `checkpoint.json` | `audit/checkpoint` | Checkpoint form and strict Ed25519 signature by the node key |
| `receipt.json` | `audit/receipt` | Receipt form, signature, match with its envelope, domain separation from checkpoints |
| `compare.json` | `audit/compare` | Two commitments: equal, consistent, unrelated, fork |
| `evidence.json` | `audit/evidence` | Evidence bundles: entries with inclusion proofs, receipts, bodies, check order |

## Scenario

The vectors come from one M1-like scenario. `planner` (on node `alpha-node`) sends `SendMessage` and `GetTask`
to `tester` (on node `beta-node`). beta's log (epoch 0, 12 entries) holds: genesis, start, the received request,
the authorisation decision, two task transitions, the sent response, the second request, an anomaly, a forged
envelope (signed by `mallory` with `from` = `planner`) logged as rejected, alpha's checkpoint, and an entry of an
unknown type with an unknown member. Further logs: alpha's (3 entries), a fork of beta's log that differs from
index 7, beta's epoch 1 after data loss, and a log that claims to have accepted an envelope whose signature fails.

## Keys

Test-only Ed25519 keys. The seed of key `name` is `BLAKE3("argent-webway audit/v0 test key: " + name)`. Never
trust them anywhere else.

| Name | Seed (hex) | Public key (hex) |
|---|---|---|
| `beta-node` | `2fcd6305dbb56b1713b30b657dd1e14a0d938b6b72c05ef6ce20f9704b44cea8` | `3da4d5b6f42760ce1c582bcc2d4ffc6cfbc8ccb880e3c84a393328c31a39740c` |
| `alpha-node` | `6d601cb0c27f238bc02cce7e844587795ff2d2de9ac00a789f403193e64f73d5` | `9108b6b3a6b8bfa06e94783a0ba78d24bfdc2aacf5607aba026318d17e1b3e5a` |
| `planner` | `d995dad6886da5409d547ff4a32dda56c9e065201cdaa8f3861647c4ad81c737` | `42168d5e225e058798a89d427c2326a87dab0dc9c70fbb1ba72b6ddb86265018` |
| `tester` | `6b1ef129c7445807567a3e67bc35609655e3014d86dbda2277ef385faa54aba1` | `81d66c8508102ca93ae75b3fe5dd38500f3e4780c6b282c59894696fea2a19b9` |
| `alpha-owner` | `c93aab7913171620cdeb9b37910bd7bb69bed63476a8346ee9b2aa6b00d9d069` | `f6c56655fe60e667abfa3687b54fd41b2fed21477fa6089590080ac1f1584b91` |
| `mallory` | `356cd4d36337e55e528a2deb85a1164aed54ce36c2a2d9cbd70ce9a957bf1bf3` | `7fb68c263e2d2a85e21b672a89611c7adeb09307b00cddf947e294c915290961` |

## Regenerating

The files are generated, and every case is checked against a reference verifier, by
[`conformance/tools/audit-vectors`](../../tools/audit-vectors):

```sh
cargo run --manifest-path conformance/tools/audit-vectors/Cargo.toml            # write the files
cargo run --manifest-path conformance/tools/audit-vectors/Cargo.toml -- --check # fail if they differ
cargo test --manifest-path conformance/tools/audit-vectors/Cargo.toml           # Merkle code against the CT reference roots
```

Do not edit the JSON by hand: change the generator and regenerate.
