# Lab 2026-11-10: is 64 KiB the right inline / by-reference threshold for artefacts?

## Question

§4.5 (`blob/v0`, T8) says: "Parts under 64 KiB are inline, larger ones are by reference (tunable, a spec
constant)". M1 step 5 tests one artefact above that size. No number in the due diligence supports 64 KiB.
For an artefact of S bytes, this lab asks:

1. What does inline cost? In the pinned signer form, `Part.raw` is standard base64 inside a JSON body that is
   parsed generically, re-canonicalised with JCS and hashed with BLAKE3 (§4.4). That is a 4/3 wire expansion
   plus CPU on both ends.
2. What does by-reference cost? It needs an extra request/response for the fetch, possibly a new QUIC connection
   (the quic-control-latency lab recommends a separate blob connection), and bao verification.
3. Where is the latency crossover on realistic paths, and what does each mode do to concurrent control RPCs (R13)?

## Method

Code: `lab/inline-threshold/` (Rust: quinn 0.11.12 / quinn-proto 0.11.19, serde_json_canonicalizer 0.4,
blake3 1.8, ed25519-dalek 2.2, bao-tree 0.17). Run it with `run.sh` (about 35 min on 3 cores). Raw TSVs are in
`out/`.

- **`cpu`** (single thread, median of 31 reps, 7 for ≥ 4 MiB). It builds one `TaskArtifactUpdateEvent`
  envelope with a realistic header: a 420 B capability token and the `prov` block.
  - Inline. Sender: base64, JSON value, JCS(body), BLAKE3, JCS(header), Ed25519, serialise. Receiver: generic
    parse, JCS(body), BLAKE3 compare, JCS(header), verify, base64 decode.
  - By reference. Sender: bao outboard with 16 KiB groups (as pinned by the blob-bao-size-auth lab) plus the same
    small envelope. Provider: encode. Receiver: small envelope plus bao decode/verify of the whole blob.
- **`net`**. It reuses the bottleneck emulator of the quic-control-latency lab: a userspace UDP proxy with a
  byte-bounded drop-tail FIFO, both directions. Four paths:
  - `100M-20ms`: 100 Mbit/s, RTT 20 ms, 1 BDP buffer.
  - `20M-60ms`: 20 Mbit/s, RTT 60 ms, 1 BDP buffer.
  - `20M-60ms-relay1MB`: the same with a 1 MiB relay-like FIFO.
  - `5M-200ms`: 5 Mbit/s, RTT 200 ms, 1 BDP buffer.

  The time is measured from the receiver's request to the last artefact byte received. There are five modes:

  | Mode | What happens |
  |---|---|
  | `inline` | One response of 1.7 kB envelope + base64(S) on the long-lived control connection. Trials run in increasing size, so that connection has carried earlier inline payloads. |
  | `inline-fresh` | Inline on a new connection that has done only 3 small RPCs, so cwnd is the initial window. |
  | `ref-open` | Small envelope, then a fetch (700 B capability in the request, S·(1 + 1/256) + 8 B response) on an already-open blob connection that has only carried small RPCs. |
  | `ref-hot` | The same, but the blob connection first carried an 8 MiB blob. |
  | `ref-new` | Small envelope, then a new QUIC connection (1-RTT handshake, no 0-RTT) and the fetch. |

  Sizes: 4 KiB to 4 MiB, 10 trials each, spaced so queues drain. Throughout the run, a 512 B / 2 KiB control RPC
  every 50 ms runs on the control connection. Its latency is recorded while a transfer is in flight ("during")
  and while the link is idle.

## Results

### 1. CPU and bytes (out/cpu.tsv)

| S | inline wire | inline send / recv µs | ref wire (envelope + bao) | ref send / provider / recv µs |
|---|---|---|---|---|
| 4 KiB | 7.0 kB (+72 %) | 63 / 75 | 5.8 kB | 52 / 3 / 66 |
| 64 KiB | 89.0 kB (+35.7 %) | 266 / 247 | 67.5 kB (+2.9 %) | 68 / 20 / 85 |
| 256 KiB | 351 kB (+33.9 %) | 916 / 763 | 265 kB | 123 / 78 / 145 |
| 1 MiB | 1.40 MB (+33.5 %) | 3 657 / 2 924 | 1.05 MB (+0.6 %) | 349 / 316 / 402 |
| 16 MiB | 22.4 MB | 116 229 / 92 489 | 16.8 MB (+0.4 %) | 5 385 / 6 609 / 6 793 |

- Inline runs at about **270–360 MB/s per side**, roughly 4 µs per KiB on each end. By-reference runs at
  2.5–3.3 GB/s (bao), and its envelope has a fixed cost of about 50–85 µs.
- At 64 KiB, inline adds **about 0.5 ms of CPU** in total. CPU only matters on a LAN or the same machine.
- Model: inline loses (0.33·S/bw + about 6 µs/KiB) against by-reference's one extra RTT. With that model, the
  crossover is about 60 KiB at 1 Gbit/s / 0.5 ms and about 15 KiB on loopback. These are sub-millisecond
  differences either way.

### 2. Delivery latency (out/net.tsv, p50 ms, n = 10; the 1 MiB relay path is in the TSV and within 3 % of `20M-60ms` for every cell except `ref-open` at 16–64 KiB (−6 to +13 %))

**100 Mbit/s, RTT 20 ms**

| mode | 4 KiB | 16 KiB | 64 KiB | 256 KiB | 1 MiB | 4 MiB |
|---|---|---|---|---|---|---|
| inline | 23.1 | 32.2 | **44.7** | **52.4** | 141.7 | 496.8 |
| inline-fresh | 23.3 | 46.8 | 91.1 | 142.9 | 247.3 | 588.9 |
| ref-hot | 45.5 | 46.9 | 51.7 | 68.2 | 139.6 | 404.5 |
| ref-open | 45.9 | 47.9 | 64.3 | 71.2 | 138.6 | 405.6 |
| ref-new | 69.9 | 94.1 | 131.0 | 178.8 | 275.9 | 518.6 |

**20 Mbit/s, RTT 60 ms (M1's relay path)**

| mode | 4 KiB | 16 KiB | 64 KiB | 256 KiB | 1 MiB | 4 MiB |
|---|---|---|---|---|---|---|
| inline | 65.9 | 88.9 | **111.4** | **212.0** | 657.7 | 2440.8 |
| inline-fresh | 65.7 | 131.3 | 255.4 | 392.8 | 841.8 | 2624.3 |
| ref-hot | 128.1 | 133.5 | 154.3 | 237.0 | 574.3 | 1917.4 |
| ref-open | 127.7 | 135.2 | 190.2 | 238.0 | 575.9 | 1917.5 |
| ref-new | 194.6 | 258.2 | 349.2 | 491.1 | 824.4 | 2169.0 |

**5 Mbit/s, RTT 200 ms**

| mode | 4 KiB | 16 KiB | 64 KiB | 256 KiB | 1 MiB | 4 MiB |
|---|---|---|---|---|---|---|
| inline | 215.0 | 244.1 | **359.4** | **825.3** | 2703.1 | 10242.4 |
| inline-fresh | 215.1 | 429.5 | 831.7 | 1341.9 | 3213.1 | 10739.0 |
| ref-hot | 416.9 | 437.4 | 524.3 | 870.4 | 2289.5 | 7958.1 |
| ref-open | 417.3 | 440.5 | 576.7 | 870.0 | 2288.3 | 7956.6 |
| ref-new | 627.9 | 838.8 | 1125.0 | 1627.8 | 3035.3 | 8697.1 |

What the tables show:

- **At 64 KiB, inline is clearly faster on every WAN path.**
  - Against the best by-reference case (`ref-hot`), it is 1.16–1.46× faster.
  - Against a blob connection dialled on demand (`ref-new`), it is **2.9–3.1×** faster: +86 ms at 20 ms RTT,
    +238 ms on M1's relay path, +766 ms at 200 ms RTT.
- **The latency crossover is between 256 KiB and 1 MiB** for inline against `ref-hot`/`ref-open`, on all three
  rates (about 1 MiB at 100 Mbit/s). For inline against `ref-new`, it is **between 1 MiB and 4 MiB**, and above
  4 MiB at 100 Mbit/s.
  - Above the crossover, by-reference wins only because base64 inflates the bytes by 33 %. 4 MiB is 19–22 %
    faster by reference (`ref-hot`).
- **A by-reference fetch costs a fixed amount, and connection setup dominates it.**
  - `ref-hot`/`ref-open` cost about +1 RTT over inline, because the fetch is a second request.
  - `ref-new` costs **+3 to +4 RTT** at ≤ 64 KiB. Its gap to `ref-open` is the QUIC/TLS handshake (no 0-RTT here)
    plus a second slow start: +24 to +758 ms, or 1.1–5.4 RTT, at 4 KiB–256 KiB. It never beats `inline` at any
    size ≤ 1 MiB on any path.
- **cwnd, not the threshold, decides small inline transfers.** quinn's Cubic does not grow cwnd while app-limited
  (`quinn-proto 0.11.19 congestion/cubic.rs:102`) and does not reset it after idle. So a control connection that
  only ever carried small RPCs keeps the 14 720 B initial window:
  - `inline-fresh` 16 KiB already takes 2 RTT. The base64 body is 23 kB, so only about 9.7 KiB of raw bytes fit
    in one flight.
  - `inline-fresh` 64 KiB takes 4.2–4.6 RTT.
  - Once the connection has carried one larger inline payload, the window stays open. That is why the
    `inline` p50 is lower: 64 KiB in 1.9–2.2 RTT.
  - In `ref-hot`, the blob connection's window was opened by the earlier 8 MiB blob. Measured against `ref-hot`,
    `ref-open` costs up to 1.2× more (+12.6 ms at 100 Mbit/s, +36 ms on M1's path, +52 ms at 5 Mbit/s, all at
    64 KiB). It is identical from 256 KiB up.

### 3. Effect on concurrent control RPCs (R13)

Control RPC latency that started while a transfer was in flight, in ms. Format: p50 / max. The idle p50 is
22.7 / 63.7 / 207.0 ms on the three rates.

| path | size | inline | ref-hot | ref-new |
|---|---|---|---|---|
| 20M-60ms | 64 KiB | 64.4 / 89.5 | 63.9 / 73.4 | 64.0 / 69.6 |
| 20M-60ms | 256 KiB | **80.6 / 119.9** | 64.0 / 100.4 | 64.0 / 69.5 |
| 20M-60ms-relay1MB | 64 KiB | 65.2 / 95.2 | 64.0 / 80.3 | 63.7 / 68.4 |
| 20M-60ms-relay1MB | 256 KiB | **89.8 / 147.6** | 64.5 / 133.3 | 63.8 / 71.1 |
| 20M-60ms-relay1MB | 1 MiB | **244.2 / 483.4** | 153.7 / 395.7 | 66.2 / 218.4 |
| 5M-200ms | 64 KiB | 207.7 / 265.6 | 207.0 / 260.1 | 207.2 / 226.7 |
| 5M-200ms | 256 KiB | **297.2 / 619.0** | 207.9 / 394.9 | 207.3 / 261.0 |
| 100M-20ms | 256 KiB | 23.9 / 31.9 | 23.2 / 28.5 | 23.1 / 24.4 |

- **Up to 64 KiB, inline is harmless to control traffic.** It adds +0.6–1.5 ms at p50 and at most +59 ms (about
  0.3–1 RTT) on any path.
- **At 256 KiB, inline starts to cost control traffic.**
  - On the M1 relay path, the p50 of concurrent control RPCs rises by +17 to +26 ms. At 5 Mbit/s it rises by
    +90 ms, with a max of 619 ms.
  - The same bytes sent by reference on the separate blob connection add < 1 ms at p50.
  - The cause is that inline bytes share the control connection's send path and cwnd. A control response is
    queued behind them in quinn, not only in the network queue.
- From 1 MiB up, every mode fills the shared bottleneck. The R13 remedy then is the quic-control-latency lab's:
  a separate connection plus a receive-window cap. The ref modes here run without that cap.

### Summary of the trade-off

| Threshold | Latency vs by-ref (WAN) | Control-RPC impact (R13) | Other |
|---|---|---|---|
| 64 KiB (current) | Inline wins at every size below it, by 1.2–1.5× against a warm blob connection and 3× against a new one | Negligible | ≤ 89 kB envelopes |
| 256 KiB | Inline still wins up to it by 5–30 % against a warm blob connection, and 2.0–3.4× against a new one | p50 +17–90 ms on slow paths | Mailboxes, the task store and `SubscribeToTask` replay carry 1.33× the bytes |
| ≥ 1 MiB | By-reference wins | Inline is worse than a blob connection | 5 MB+ peak memory per envelope parse (estimated from copies: wire + `Value` + JCS body + decoded) |

## Conclusion

**Keep 64 KiB as the default.** The data now gives a reason for it: it is the largest power of two that is
harmless to concurrent control traffic on slow and deep-buffered paths. The latency optimum for the artefact
itself is higher (256 KiB–1 MiB). Raising the threshold to 256 KiB would buy 25 ms per 256 KiB artefact on M1's path
against a warm blob connection, but would cost every concurrent control RPC +17–26 ms.

The size of the threshold is the smaller issue. The bigger lever is **how by-reference fetches are dialled**. A
blob connection dialled on demand adds 1–5 RTT per artefact (`ref-new` against `ref-open`: +24 to +758 ms at
4 KiB–256 KiB on the three rates). On M1's path that is +159 ms at 64 KiB and +253 ms at 256 KiB, which is
1.4–1.6× the whole inline delivery time.

## Caveats

- quinn, not noq or iroh. Emulated drop-tail paths with no random loss and no reordering. No 0-RTT. One machine
  with 3 cores.
- `inline` trials share a connection whose cwnd grew during earlier trials. `inline-fresh` and `ref-open` bound
  that effect from the other side.
- The `net` binary adds no CPU. Section 1 shows CPU is ≤ 0.5 ms below 64 KiB and about 7 ms at 1 MiB, which
  changes no crossover on these WAN paths.
- The memory figure in the summary is an estimate from counting copies, not a measurement.
- Not measured: offline delivery (below) and storage costs.

## What the planner should do next

1. **T8 (`blob/v0`)**: keep the spec constant `INLINE_MAX = 64 KiB` **of raw Part bytes**. Say it is measured on
   raw bytes (the envelope carries about 1.36×). Give the reason as "control-RPC latency on shared connections",
   not throughput.
   - Add a receiver rule: "a receiver MUST accept inline Parts up to `INLINE_MAX` and MAY reject an envelope
     larger than `ENVELOPE_MAX`". Suggest `ENVELOPE_MAX = 128 KiB` for the overlay. That gives parsers a bound
     (§4.7 / T19) and keeps senders from inlining 1 MiB.
2. **T1/T8, the bigger win**: a node that sends a `webway-blob:` reference SHOULD expect a fetch. The receiver
   SHOULD dial the blob connection **when the task enters `working`** (or keep it open for the life of an active
   task), not when it parses the reference.
   - This lab measures that this saves 1–5 RTT per artefact (+159 ms at 64 KiB on M1's path).
   - Allowing 0-RTT on the blob ALPN is the other half, but needs a replay analysis first. A fetch is read-only and
     capability-scoped, so it is probably safe. That analysis is a follow-up lab.
3. **Open design gap (not decided here; possible owner question)**: by-reference artefacts sent while the receiver
   is offline (M1 step 6 plus step 5) need a provider that is online when the receiver comes back. Today only the
   sender is listed in `providers=`.
   - Option (a): the mailbox host also caches blobs referenced by queued envelopes.
   - Option (b): the sender inlines up to `ENVELOPE_MAX` when the peer is offline.
   - Option (c): delivery is reported as `delivered` but the fetch can fail with `BlobNotFound`.

   The current M1 scenario does not exercise this.
4. **T10 devnet**: assert in M1 step 5 that control RPCs issued while the > 64 KiB artefact is fetched stay within
   base + 1 RTT at p50. That fits the quic-control-latency recommendation and these numbers.

## Sources

- argent-webway due diligence §4.3, §4.4 (pinned signer form: `bytes` as base64), §4.5 (inline threshold),
  §6 step 5.
- lab/2026-11-10-quic-control-latency.md (emulator, separate blob connection, R13 numbers).
- lab/2026-11-09-blob-bao-size-auth.md (16 KiB chunk groups, bao overhead 0.39 %).
- quinn-proto 0.11.19 `src/congestion/cubic.rs` (initial window 14 720 B, line 266; no growth while app-limited,
  line 102).
- RFC 9002 §7.2 (initial window), §7.8 (underutilising the congestion window).
- RFC 4648 §4 (base64 expansion 4/3); RFC 8785 (JCS).
