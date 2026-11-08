# conformance/

The conformance suite for the argent-webway spec. Nothing here yet (roadmap track T4).

- `vectors/`: language-neutral JSON test vectors: canonicalisation, envelope signatures (valid and invalid),
  capability chains (allow and deny), task state transitions (legal and illegal), error mapping.
- `harness/`: a Rust black-box harness that drives nodes only through their wire interface and a small control
  API (start, stop, partition), runs scenarios (e.g. the M1 delegated-task scenario), and reports results per
  requirement ID.
- `tools/capgen/`: the reference model and generator of the `identity/*` and `capability/*` vectors
  ([`spec/ext/capability.md`](../spec/ext/capability.md) §12).

Rule: every `MUST` in `spec/` has at least one test here. CI fails on untested requirements.
