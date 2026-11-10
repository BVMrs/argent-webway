#!/usr/bin/env bash
# Lab: reproduce lab/2026-11-09-ed25519-verifier-diff.md. Needs cargo, node 22, (optional) bun, python3 venv
# with pynacl + cryptography at $PY, Go toolchain at $GO. Outputs go to out/ (not committed except tables).
set -euo pipefail
cd "$(dirname "$0")"
PY=${PY:-../../.agent-work/pyenv/bin/python}
GO=$(realpath "${GO:-../../.agent-work/go-dl/go/bin/go}")
(cd rs && cargo build --release -q)
(cd ts && npm ci --no-audit --no-fund -s)
B=rs/target/release/ed25519-verifier-diff
mkdir -p out/audit out/proposed
$B gen out/corpus.json
node ts/extract-audit.mjs ../../conformance/vectors/audit out/audit/corpus.json
$B propose ../../conformance/vectors/audit/checkpoint.json proposed-checkpoint-vectors.json out/proposed/corpus.json
for d in out out/audit out/proposed; do
  $B verify $d/corpus.json $d/rs.json
  node ts/verify.mjs $d/corpus.json $d/node.json          # ~10 min on the full corpus (pure-JS libraries)
  node ts/verify-sodium.mjs $d/corpus.json $d/sodium.json
  $PY -I py/verify.py $d/corpus.json $d/py.json
  (cd go && GOTOOLCHAIN=local "$GO" run . "../$d/corpus.json" "../$d/go.json")
done
node ts/verify-precheck.mjs out/corpus.json out/precheck.json
command -v bun >/dev/null && bun ts/verify.mjs out/corpus.json out/bun.json
node ts/analyse.mjs out
node ts/matrix.mjs out/audit > out/audit/matrix.md
node ts/matrix.mjs out/proposed > out/proposed/matrix.md
