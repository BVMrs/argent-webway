#!/usr/bin/env bash
# Reproduce lab/2026-11-09-proto-json-signer-form.md. Needs cargo, bun >= 1.3, git, network (crates, npm, GitHub).
# N cases (default 120000), seed 1. Scratch files go to $W.
set -euo pipefail
cd "$(dirname "$0")"
W=${W:-../../.agent-work/pjsf}; N=${N:-120000}
EXT=${EXT:-../../.agent-work/ext}; A2AJS_REV=3d3ca8291e1f6b1f53293f61c12ba46c36670000
mkdir -p "$W" "$EXT"; W=$(realpath "$W"); EXT=$(realpath "$EXT")
[ -d "$EXT/a2a-js" ] || git clone -q https://github.com/a2aproject/a2a-js "$EXT/a2a-js"
git -C "$EXT/a2a-js" fetch -q --depth 1 origin "$A2AJS_REV" 2>/dev/null || true
git -C "$EXT/a2a-js" checkout -q "$A2AJS_REV"
(cd ts && bun install --frozen-lockfile >/dev/null)
ln -sfn "$PWD/ts/node_modules" "$EXT/a2a-js/node_modules"   # a2a-js sources resolve our pinned deps
cargo build --release -q
B=./target/release/proto-json-signer-form
$B gen "$W" "$N" 1
(cd ts && bun serialize.ts "$W" "$EXT/a2a-js")
{
  echo "### probe"; $B probe
  echo; echo "### A2A §8.4.1 example and realistic cards through a2a-js canonicalizeAgentCard"
  (cd ts && bun card-example.ts "$EXT/a2a-js")
  echo; echo "### differential (N=$N, seed 1)"; $B check "$W" prost-reflect pbjson bufbuild protobufjs a2a-js
} > results.txt
echo "wrote results.txt"
