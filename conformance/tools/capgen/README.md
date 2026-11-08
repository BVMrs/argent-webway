# webway-capgen

Reference model and vector generator for [`spec/ext/capability.md`](../../../spec/ext/capability.md)
(`capability/v0`). It is a prototype that checks the spec is implementable with `biscuit-auth` 6.0, and the source
of the `identity/*` and `capability/*` vectors. It is not the node: the capability engine is track T6
(`crates/webway-cap`).

```sh
cargo build
target/debug/webway-capgen gen   ../../vectors   # write the vector files (deterministic)
target/debug/webway-capgen check ../../vectors   # run them through the model
target/debug/webway-capgen adapter               # stdio adapter for webway-conformance run
```

- Test keys are derived from names: `seed = BLAKE3-derive_key("argent-webway capgen test key v0", name)`
  (`src/keys.rs`). They are public and test-only.
- Every case states its expected verdict in `src/gen.rs`. `gen` refuses to write a file if the model disagrees,
  so a wrong expectation or a model bug stops the build of the vectors.
- `src/cap.rs` follows spec §6.2 and §7.3 step by step; `src/stmt.rs` follows §4; `src/model.rs` has invites (§8)
  and the outbound mandate rule (CAP-186).
- `biscuit-auth` has no public accessor for one block's facts. The model prints each block's source and re-parses
  it to walk the holder chain (spec §13, Q-CAP-2).
