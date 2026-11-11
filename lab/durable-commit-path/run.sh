#!/usr/bin/env bash
# Usage: lab/durable-commit-path/run.sh  (from the repo root). Writes results under lab/durable-commit-path/out/.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
export CARGO_TARGET_DIR="$root/.agent-work/dcp-target"
(cd "$here" && cargo build --release -q)
B="$CARGO_TARGET_DIR/release/durable-commit-path"
W="$root/.agent-work/dcp"; mkdir -p "$W" "$here/out"
$B fsync "$W" | tee "$here/out/fsync.csv"
echo "backend,mode,conc,acks_per_s,p50_ms,p99_ms,p999_ms,entries_per_commit,disk_bytes_per_entry" > "$here/out/cap.csv"
for b in redb sqlite sqlite-normal fjall rawlog; do
  $B cap "$W" $b serial 1 5 | tee -a "$here/out/cap.csv"
  $B cap "$W" $b serial 16 5 | tee -a "$here/out/cap.csv"
  for c in 1 4 16 64 256; do $B cap "$W" $b group $c 5 | tee -a "$here/out/cap.csv"; done
done
echo "backend,policy,stub,bw_mbit,peers,adv_per_s,adv_logged_per_s,adv_coalesced_per_s,h_sent,h_acked,h_p50_ms,h_p99_ms,h_max_ms,entries_per_commit,disk_MB_per_s,backlog_at_end" > "$here/out/flood.csv"
for b in redb sqlite fjall; do
  for p in S G GP GC; do
    $B flood "$W" $b $p 1536 0 8 10 | tee -a "$here/out/flood.csv"
    for s in 1536 65536 1048576; do
      for bw in 20 100 1000; do
        $B flood "$W" $b $p $s $bw 8 10 | tee -a "$here/out/flood.csv"
      done
    done
  done
  $B flood "$W" $b GC 1536 100 1000 10 | tee -a "$here/out/flood.csv"
  $B flood "$W" $b GC 1536 1000 1000 10 | tee -a "$here/out/flood.csv"
done
