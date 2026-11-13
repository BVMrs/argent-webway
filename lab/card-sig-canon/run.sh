#!/usr/bin/env bash
# usage: PY=<venv python with a2a-sdk[signing] 1.3.0> NODE_PATH=<node_modules with @a2a-js/sdk 1.3.0> ./run.sh N SEED OUTDIR
set -euo pipefail
N=$1; SEED=$2; O=$3; mkdir -p "$O"
cargo build --release -q
B=./target/release/card-sig-canon
$PY gen.py "$N" "$SEED" > "$O/cards.jsonl"
$PY py_card.py sign < "$O/cards.jsonl" > "$O/signed_py.jsonl"
node js_card.mjs sign < "$O/cards.jsonl" > "$O/signed_js.jsonl"
$B sign < "$O/cards.jsonl" > "$O/signed_rs.jsonl"
$PY mutate.py "$O/signed_py.jsonl" "$O/signed_js.jsonl" "$O/signed_rs.jsonl" > "$O/candidates.jsonl"
$PY py_card.py verify < "$O/candidates.jsonl" > "$O/verdict_py.jsonl"
node js_card.mjs verify < "$O/candidates.jsonl" > "$O/verdict_js.jsonl"
$B verify < "$O/candidates.jsonl" > "$O/verdict_rs.jsonl"
$PY report.py "$O"
