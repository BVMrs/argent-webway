# Lab 2026-11-10: the durable commit path, and logging every rejected envelope under a flood

## Question

M1 needs a reference node (T5, critical path) whose task engine meets three durability rules at once:

- due diligence §4.4 / `envelope/v0` ENV-503: the dedupe entry with its stored response is written in the
  **same atomic transaction** as the task, **before the ack**;
- `audit/v0` AUD-401: an `envelope.received` entry for **every** envelope that reaches verification, *whatever
  the outcome*. Only duplicates and rejections that failed before a stub could be parsed may be coalesced (§7.1:
  "Other entries are never coalesced"). AUD-300 adds a signed receipt for every entry whose stub signature verified,
  stored in the same transaction;
- AUD-500: an entry is durable before anything that depends on it is sent. That includes a reject response.

So every rejected envelope with a parseable stub costs a durable write of up to `MAX_ENTRY_BYTES` (1 MiB stub +
128 KiB) plus an Ed25519 signature, before the node may answer. Any peer that can open a connection can produce
such rejections: no token, a fresh self-generated `wwa:` key, a wrong `to`. This lab asks:

**What does the durable acceptance commit cost on the candidate embedded stores, with one transaction per envelope
and with group commit? And can a flood of rejected envelopes, logged as AUD-401 requires, starve honest acks or
fill the disk? If so, which logging policy prevents it?**

This is not in `lab/INDEX.md`. The outbox lab modelled a mailbox host's admission. The metering lab modelled what
the transaction must contain, not what it costs or what rejected traffic does to it.

## Method

`lab/durable-commit-path/` is a Rust crate (redb 4.5, rusqlite 0.42 with bundled SQLite, fjall 3.1, ed25519-dalek,
blake3). `run.sh` runs everything (about 75 min) and writes `out/fsync.csv`, `out/cap.csv` and `out/flood.csv`.

- **Committer.** One thread owns the store and the audit log head. For each request it:
  - builds an `envelope.received` entry (§4.1 shape, with the stub inline);
  - computes the entry hash and the RFC 9162 leaf hash (BLAKE3) and appends the leaf to a Merkle frontier;
  - computes the root at `index + 1` and signs a `webway-receipt/0` (AUD-300).

  For an accepted request it also reads the dedupe table and writes the dedupe entry (stored response + receipt,
  about 600 B), the task (800 B), the first event (300 B) and the `max_calls` counter. For a rejected request it
  writes only the entry, leaf and receipt. Each request's ack goes out only after its commit returns.
- **Backends.**
  - `redb`: `Durability::Immediate`.
  - `sqlite`: WAL, `synchronous=FULL`.
  - `sqlite-normal`: WAL, `NORMAL`. **Not** power-loss durable, so it breaks AUD-500/ENV-503; listed for reference.
  - `fjall`: write batch with `PersistMode::SyncAll`.
  - `rawlog`: append file + `fdatasync`, with no index. This is a lower bound.
- **Modes.** `serial`: one transaction per request. `group`: the committer drains whatever is queued, up to 1024
  requests or 8 MiB, into one transaction. This is PostgreSQL-style leader group commit with `commit_delay = 0`.
- **Capacity (`cap`).** c ∈ {1, 4, 16, 64, 256} closed-loop clients send accepted 1.5 KiB-stub requests for 5 s.
- **Flood (`flood`).** Honest load is open-loop Poisson at 200 accepted envelopes/s with 1.5 KiB stubs (well above
  M1). The adversary sends open-loop rejected envelopes with verified stubs (outcome `rejected`,
  `Unauthorized/no-capability`). Its rate is ingress bandwidth / stub size, for bandwidth ∈ {20, 100, 1000} Mbit/s
  (20 Mbit/s is the relay path of the earlier QUIC labs) and stub ∈ {1.5 KiB, 64 KiB, 1 MiB}, spread over 8
  transport peers, or 1000 for the Sybil cells. Each cell runs 10 s. Honest acks get up to 20 s more to arrive;
  later ones count as unacked. Policies:
  - **S**: spec as written, serial commit, FIFO.
  - **G**: spec as written, group commit, FIFO.
  - **GP**: group commit, accepted class first, reject backlog bounded at 256. Overflow is coalesced: an
    in-memory count per peer becomes one entry per peer per second, and the response goes out immediately with no
    receipt.
  - **GC**: group commit, per-peer token bucket of 10 individually logged rejects/s (burst 20). The rest is
    coalesced as in GP.

  GP and GC each need a spec change (see below).
- **Machine.** 3 vCPU VM, 7 GB RAM, virtual disk. `fdatasync` p50/p99: 512 B 0.78/4.7 ms, 64 KiB 0.97/18 ms,
  1 MiB 2.8/28 ms. Committer CPU: 52 µs per 1.5 KiB entry (≈19 k entries/s ceiling, mostly receipt signing and
  formatting) and 1.04 ms per 1 MiB entry. `verify_strict`: 85 µs.

**What the model leaves out:**

- The node's own verification CPU and the transport. The 1 Gbit/s small-stub cells (81 k env/s) would need about
  7 cores just to verify the signatures, so on this box they mean "the flood exceeds what the node can verify".
- Crash testing. Earlier labs settled the atomicity requirements; this lab only measures what they cost.
- Disk figures are directory growth, not device bytes written.

## Results

### 1. Capacity with no attacker (acks/s, ack latency in ms)

| backend | serial c=1: acks/s, p50 / p99 | serial c=16: acks/s | group c=16: acks/s, p99 | group c=64: acks/s, p50 / p99 | group c=256: acks/s, p99 |
|---|---|---|---|---|---|
| redb | 424, 1.5 / 26 | 389 | 1 464, 42 | 2 445, 16 / 58 | 3 434, 151 |
| sqlite FULL | 540, 0.9 / 25 | 573 | 1 224, 55 | 2 141, 27 / 68 | 2 143, 266 |
| sqlite NORMAL (not durable) | 1 660, 0.1 / 19 | 1 572 | 1 957, 57 | 2 130, 29 / 69 | 2 291, 203 |
| fjall | 935, 0.8 / 2.3 | 802 | 3 741, 35 | 7 393, 4.2 / 41 | 9 440, 63 |
| rawlog (bound) | 752, 1.0 / 19 | 844 | 3 920, 34 | 8 033, 4.1 / 40 | 11 020, 60 |

- With one transaction per envelope, a node acks only 400–950 envelopes/s, whatever the concurrency. Group commit
  gives 4–10× at c = 64, with 33–35 entries per commit.
- fjall stays within 10 % of the raw append-log bound. redb and SQLite FULL level off at 2–3.4 k/s, limited by
  B-tree/WAL work per commit rather than by fsync.
- On this disk the p99 (≈ 25 ms even at c = 1) is set by fsync stalls and is the same for every backend.
- SQLite `NORMAL` buys little once commits are grouped, so the durability break is not worth it.
- Disk footprint per accepted envelope: 4.3 KB in the raw log, 7–11 KB in redb and SQLite.

### 2. Reject flood, spec as written

Honest ack latency (p50 / p99 ms), or the fraction of honest acks at all when the node fell behind. 8 attacker peers.

| policy | backend | 1.5 KiB @ 20 Mbit/s (1.6 k rej/s) | 1.5 KiB @ 100 (8.1 k/s) | 1.5 KiB @ 1000 (81 k/s) | 64 KiB @ 1000 (1.9 k/s) | 1 MiB @ 1000 (119/s) |
|---|---|---|---|---|---|---|
| S | redb | **9 226 / 18 444** | **21 % acked** | **2.5 % acked** | **55 % acked** | 2 644 / 4 369 |
| S | sqlite | **5 053 / 10 767** | **33 % acked** | **4 % acked** | **88 % acked** | 876 / 2 590 |
| S | fjall | **1 934 / 3 788** | **43 % acked** | **5 % acked** | 9 695 / 18 627 | 5.2 / 49 |
| G | redb | 4.4 / 41 | 24 / 76 | **43 % acked** | 13 / 142 | 7.4 / 32 |
| G | sqlite | 1.5 / 28 | 3.0 / 26 | **63 % acked** | 6.3 / 98 | 9.3 / 83 |
| G | fjall | 1.7 / 3.5 | 3.7 / 19 | **86 % acked** | 3.8 / 30 | 2.2 / 33 |
| none | redb / sqlite / fjall | 3.6 / 33 · 1.6 / 26 · 1.2 / 3.9 (serial, no flood) | | | | |

- **The spec as written, with one transaction per envelope, is a denial of service at 20 Mbit/s.** A single
  relay-path's worth of 1.5 KiB rejected envelopes (≈ 1 600/s) exceeds the serial commit rate of every backend.
  The FIFO backlog then grows without bound: 4.7 k–11.5 k requests after 10 s. Honest acks wait 2–18 s, and at
  100 Mbit/s 57–79 % of honest envelopes get no ack within 30 s. The sender's retries then add load. This is the
  same metastable shape as the outbox lab.
- **Group commit is necessary and holds up to about 100 Mbit/s of small rejects**, with honest p99 of 19–76 ms.
  Past the commit capacity it collapses the same way: at 81 k rej/s the backlog was 0.58–0.70 M and 14–57 % of
  honest acks were lost.
- **Disk growth is the larger problem, even where latency holds.** Every logged reject stores its stub, so log
  growth tracks attacker ingress: 13.5 MB/s at 20 Mbit/s and 35–54 MB/s at 100 Mbit/s (G), up to 216 MB/s for
  64 KiB stubs at 1 Gbit/s. That is **1.2 TB/day per 20 Mbit/s** of attacker bandwidth. AUD-401 forbids
  coalescing these entries. §15 says retention "deletes contents but keeps hashes", so the node must keep each
  stub for its whole retention period.

### 3. Reject flood, with a logging budget (group commit)

| policy | backend | 1.5 KiB @ 100 | 1.5 KiB @ 1000 | 64 KiB @ 1000 | 1 MiB @ 1000 | rejects individually logged @ 1.5 KiB/1000 |
|---|---|---|---|---|---|---|
| GP (global backlog bound) | redb | 17 / 55 | 38 / 84 | 26 / 91 | 30 / 98 | 10 060/s (54 MB/s) |
| GP | sqlite | 2.3 / 19 | 25 / 54 | 6.0 / 71 | 3.7 / 19 | 15 383/s (65 MB/s) |
| GP | fjall | 3.4 / 14 | 18 / 48 | 5.4 / 41 | 3.6 / 45 | 21 049/s (103 MB/s) |
| GC (per peer 10/s), 8 peers | redb | 2.2 / 28 | 2.4 / 32 | 2.7 / 34 | 20 / 101 | 95/s (1.7 MB/s) |
| GC, 8 peers | sqlite | 1.5 / 14 | 1.3 / 14 | 1.4 / 16 | 2.4 / 27 | 95/s (2.1 MB/s) |
| GC, 8 peers | fjall | 1.7 / 3.9 | 1.7 / 3.8 | 1.2 / 4.2 | 2.1 / 24 | 95/s (6.7 MB/s) |
| GC, **1000 Sybil peers** | redb | 20 / 59 | **654 / 1 468** | | | 11 900/s |
| GC, 1000 Sybil peers | sqlite | 2.3 / 17 | 27 / **726** | | | 11 900/s |
| GC, 1000 Sybil peers | fjall | 4.5 / 12 | 9.9 / **262** | | | 11 900/s |

- **GP** (a global bound on the reject backlog, accepted class first) keeps every honest ack within 98 ms p99 in
  all 36 cells, with all of them acked. But it still logs rejects as fast as the disk allows, so disk growth stays
  at 54–103 MB/s.
- **GC** (a per-peer count budget) is the best case against a few peers: honest p99 is equal to no flood, and log
  growth is ≤ 2 MB/s for small stubs. It fails in two ways:
  - Sybil peers (transport keys are free) multiply the budget. At 1000 peers it degrades to G, with honest p99
    0.26–1.5 s.
  - A **count** budget does not bound **bytes**: 95 rejects/s × 1 MiB is still 100 MB/s of log (redb p99 101 ms).
- What the results imply is a **global byte-and-count budget** for individually logged rejects, plus per-peer fair
  sharing inside it, with coalescing beyond. The run did not test that combination as one policy. Its parts
  correspond to the GP (global) and GC (per-peer) rows.

## What applies from prior art

- **Group commit** is standard. PostgreSQL's WAL leader flushes every queued commit record with one sync
  (`commit_delay`/`commit_siblings`, <https://www.postgresql.org/docs/current/wal-configuration.html>). The
  committer here is the same idea with `commit_delay = 0`, and it was enough. A delay would only add latency at M1
  loads.
- **SQLite** documents that WAL + `synchronous=NORMAL` "might roll back following a power loss", while FULL syncs the
  WAL "after each transaction commit" (<https://www.sqlite.org/pragma.html#pragma_synchronous>). NORMAL therefore
  does not meet AUD-500/ENV-503.
- **Transparency logs batch, and dedupe on a best-effort basis.** Tessera sequences in batches (default 256 entries
  or 250 ms). `Add` returns a future that resolves once the index is durably assigned. Its antispam is explicitly
  best effort (<https://pkg.go.dev/github.com/transparency-dev/tessera>). Those logs also accept only entries
  worth keeping. None of them logs every rejected submission with its full payload, which is what AUD-401 asks
  for.
- The same entry-rate limit applies to audit open question 6 (batch receipts on streams). A per-entry receipt
  signature is part of the 52 µs of serial committer CPU per entry (not measured separately), so batching receipts would also raise the
  committer ceiling.

## What the planner should do next

1. **T5 (reference node): make a single committer with group commit the design, not an optimisation.**
   - Write the ack-gating rule as: release an ack after the transaction that contains its entry commits.
   - Do not use SQLite `NORMAL` or `Durability::None`-style modes for the task, dedupe and audit stores.
   - fjall, redb and SQLite FULL all meet M1 by a wide margin. fjall had the best tails here (honest p99 3–4 ms
     under 100 Mbit/s floods with GC), but the store choice can wait for T5.
2. **Spec change to `audit/v0` §7.1 / AUD-401 / AUD-500** (and the matching `profile.md` rate-limit text):
   - A node MUST log individually every `accepted` envelope, every `duplicate` (already coalescable) and every
     `rejected` envelope within a reject-logging budget. The budget is a global bytes/s and entries/s limit, shared
     fairly per authenticated transport peer.
   - Beyond the budget, it MAY coalesce rejections per (peer, error reason, window) into one entry with
     `detail.count`, and optionally the `hd` of the first and last envelope.
   - A coalesced rejection gets no receipt. Its response (`RateLimited` or the error) MAY be sent before the
     coalesced entry is durable (an explicit exemption from AUD-500).
   - Also consider capping the logged stub of a rejected envelope: keep `hd` and the signed header fields
     (`from`, `to`, `id`, `exp`, `body_hash`, `sig`), drop `cap` and `prov` above e.g. 4 KiB. The stub is what makes
     1 MiB rejects cost 1 MiB of log.
   - Accepted envelopes are bounded by capabilities. Rejects are bounded by nothing else.
3. **Conformance (T4/T10)**: add a harness scenario "reject flood". The node gets a flood of signature-valid,
   capability-less envelopes at the devnet relay bandwidth from ≥ 100 transport keys, while an authorised client
   sends at a low rate. Assert that the client's acks stay below a latency bound and that log growth stays below
   the configured budget.
4. **Follow-up lab:** run the combined global + per-peer byte budget policy, and repeat the capacity table on a
   real NVMe disk (this VM's fsync p99 is 4–28 ms). That shows how much of the 25 ms ack p99 is the disk. Also
   measure verify CPU as the real limit on small-stub floods.

## Files

- `lab/durable-commit-path/src/main.rs`: the bench (backends, committer, flood generator).
- `lab/durable-commit-path/run.sh`: the full run.
- `lab/durable-commit-path/out/{fsync,cap,flood}.csv`: raw results. Flood columns: honest sent/acked, p50/p99/max
  over acked samples after a 1 s warm-up, entries per commit, directory growth MB/s, queue backlog at the end of
  the attack.
