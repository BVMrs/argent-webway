#!/usr/bin/env bash
# Reproduce lab/2026-11-10-inline-threshold.md. About 35 min on 3 cores (the 5 Mbit/s path dominates).
set -euo pipefail
cd "$(dirname "$0")"
cargo build --release --bins
mkdir -p out
./target/release/cpu 31 > out/cpu.tsv
./target/release/net 10 > out/net.tsv
