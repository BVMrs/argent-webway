#!/usr/bin/env bash
# Reproduce lab/2026-11-09-jcs-differential.md. Needs cargo and Node >= 22.18. Writes scratch files to $W.
# Optional: CYBERPHONE=<checkout of github.com/cyberphone/json-canonicalization> for the RFC 8785 reference data.
set -euo pipefail
cd "$(dirname "$0")"
W=${W:-../../.agent-work/jcs}; mkdir -p "$W"
cargo build --release -q
cargo build --release -q --features arbitrary_precision --target-dir target/ap
(cd parse-default && cargo build --release -q)
./target/release/jcs-differential gen "$W/cases.jsonl" 1 1          # seed 1, 2 600 039 cases
node oracle.ts "$W/cases.jsonl" "$W/oracle.jsonl"
{
  echo "### cmp (default features; float_roundtrip on via the canonicaliser crates)"
  ./target/release/jcs-differential cmp "$W/cases.jsonl" "$W/oracle.jsonl" | grep -v '^  \[depth'
  echo; echo "### cmp (serde_json arbitrary_precision on)"
  ./target/ap/release/jcs-differential cmp "$W/cases.jsonl" "$W/oracle.jsonl" | grep -v '^  \[\|^examples'
  echo; echo "### serde_json default float parser vs std (no float_roundtrip)"
  ./parse-default/target/release/parse-default "$W/cases.jsonl"
  echo; echo "### probes"; ./target/release/jcs-differential probe
  echo; ./target/ap/release/jcs-differential probe | head -1
  if [ -n "${CYBERPHONE:-}" ]; then echo; echo "### RFC 8785 reference data (cyberphone testdata)"; ./target/release/jcs-differential rfc "$CYBERPHONE/testdata"; fi
} > results.txt
echo "wrote results.txt"
