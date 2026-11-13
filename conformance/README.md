# conformance/

The conformance suite for the argent-webway spec. Nothing here yet (roadmap track T4).

- `vectors/`: language-neutral JSON test vectors: canonicalisation, envelope signatures (valid and invalid),
  capability chains (allow and deny), task state transitions (legal and illegal), error mapping.
- `harness/`: a Rust black-box harness that drives nodes only through their wire interface and a small control
  API (start, stop, partition), runs scenarios (e.g. the M1 delegated-task scenario), and reports results per
  requirement ID.

Rule: every `MUST` in `spec/` has at least one test here. CI fails on untested requirements.

## Prompt-injection payloads (AgentDojo)

The injection-boundary vectors (provenance and taint, due-diligence §4.7.4) need realistic attack strings.
[AgentDojo](https://github.com/ethz-spylab/agentdojo) (Debenedetti et al., NeurIPS 2024 Datasets and Benchmarks,
arXiv 2406.13352) renders them from Python attack classes. Python is not allowed in the core, so no node, harness or
CI step runs AgentDojo. Instead:

1. **Render once, commit the result.** A named attack (for example `important_instructions`) is rendered against a
   pinned AgentDojo commit and benchmark version into `conformance/vectors/injection/<attack>.json`. Tests read only
   that JSON, using the same language-neutral format as the other vectors.
2. **Provenance travels with the file.** The vector file's header records: the AgentDojo repository URL, the full
   commit SHA, the benchmark version, the attack name, the exact generation command, the date, and the SHA-256 of
   the payload list. A `conformance/vectors/injection/SHA256SUMS` file pins each vector file. The harness fails if a
   checksum does not match, so a payload cannot change unnoticed.
3. **Regeneration is manual and rare.** It happens only when bumping the pinned commit, in a throwaway checkout and
   virtualenv, never in CI. The diff of the committed JSON is reviewed like any spec change.
4. **Licence.** The AgentDojo licence and attribution are checked and quoted in the vector header before the first
   commit of generated payloads. If it does not allow redistribution, the vectors keep only the generation command
   and checksums, and a fetch script (checksum pinned) downloads them.

**Open question for the owner.** The generation step is a one-off Python script, which sits outside "Python only for
ML pieces". Options: (a) allow it as a documented dev-time exception, kept in `conformance/tools/` and not built or run
by CI (proposed); (b) re-implement the templates in Rust and diff against AgentDojo output, which costs more and can
drift from upstream; (c) hand-write the payloads and drop AgentDojo as a source. Until decided, no generated vectors
are committed and the hand-written taint vectors are the only injection tests.
