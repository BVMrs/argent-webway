# conformance/

The conformance suite for the argent-webway spec (roadmap track T4). So far: the `envelope/v0` vectors and
their generator. The harness is not written yet.

- `vectors/`: language-neutral JSON test vectors: canonicalisation, envelope signatures (valid and invalid),
  capability chains (allow and deny), task state transitions (legal and illegal), error mapping.
  Each spec has its own directory, e.g. [`vectors/envelope/v0/`](vectors/envelope/v0/), whose README documents
  the file formats.
- `tools/`: Rust generators that produce the vectors and check each case against a reference implementation
  of the spec (e.g. [`tools/envelope-vectors`](tools/envelope-vectors)). `cargo test` in a tool fails when its
  vectors are stale or do not cover the requirements the spec says they cover.
- `harness/`: a Rust black-box harness that drives nodes only through their wire interface and a small control
  API (start, stop, partition), runs scenarios (e.g. the M1 delegated-task scenario), and reports results per
  requirement ID.

Rule: every `MUST` in `spec/` has at least one test here. CI fails on untested requirements.
