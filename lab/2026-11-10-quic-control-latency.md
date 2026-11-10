# Lab 2026-11-10: does a blob transfer delay control messages on the `webway-quic/v0` path?

## Question

R13 (due diligence §1.2) says "bulk transfer must not block control messages", and §4.3 answers it with "blob
transfers get their own streams, so bulk data never blocks control messages" and "backpressure comes from QUIC flow
control". M1 forces the relay path (alpha ↔ beta direct dialling is forbidden). Step 5 then sends status updates
and a > 64 KiB artefact by blob reference over that path.

Separate QUIC streams remove *loss* head-of-line blocking between streams. They do nothing about the **shared
bottleneck queue**. An iroh relay is a deep FIFO: a per-client queue of `PER_CLIENT_SEND_QUEUE_DEPTH = 512`
datagrams (`iroh-relay 1.4.1`, `protos/relay.rs:40`), each up to 64 KiB with GSO, plus a TCP/TLS send buffer. This
lab asks:

1. How much latency does a concurrent blob add to a small A2A request/response on the same peer pair, with a
   shallow router buffer and with relay-like deep buffers?
2. Which knobs available in quinn/noq (the stack iroh 1.4 uses) fix it: stream priority (`SendStream::set_priority`),
   congestion controller, receive-window caps, or a separate QUIC connection for blobs?

## Method

`lab/quic-control-latency/` is a Rust crate (quinn 0.11.12, rustls/ring, tokio). Run it with
`cargo run --release -- 20` for the main matrix and `MATRIX=mitig cargo run --release -- 20` for the mitigations.
Each scenario takes 20 s wall clock. The full matrix takes about 15 min on 3 cores. Raw TSVs are in `out/`.

- **Path.** A userspace UDP proxy emulates a 20 Mbit/s bottleneck in each direction, with a 30 ms one-way delay
  (RTT 60 ms, BDP 150 kB). Its FIFO is byte-bounded, with drop-tail and 28 B UDP/IP overhead counted. Buffers:
  - `router-1bdp`: 150 kB, a typical shallow access buffer.
  - `relay-1MB`: about 512 × 1.2 kB datagrams plus a small TCP buffer.
  - `relay-4MB`: GSO batches and/or an auto-tuned TCP send buffer on the relay → client leg.

  The relay leg is modelled as a FIFO with no reordering; the TCP leg's own loss is not modelled.
- **Traffic.**
  - **Control.** `alpha` (client) opens a new bidi stream every 50 ms: a 512 B request and a 2 KiB response. This
    is one A2A request per stream, as in §4.3. Latency runs from `open_bi` to the full response.
  - **Blob.** From t = 3 s, `beta` (server) streams 0, 1 or 4 unbounded blob streams to `alpha`.
  - **Windows.** "Startup" is t = 3–6 s and covers slow-start overshoot; "steady" is t = 6–19 s. RPCs still open
    at t = 20 s count as *unfinished*.
- **Axes (main).**
  - Buffer: 3 values.
  - CC: Cubic (quinn and noq default), NewReno, BBR (quinn's experimental one; noq ships BBRv3 instead, not
    tested).
  - Blob streams: 0, 1, 4.
  - Stream priority: off, or on (control 10 > blob 0, set on the server's send streams).
  - Each scenario was run twice, and both values are reported where they differ.
- **Axes (mitigation).** Blob streams on a **separate QUIC connection** (as iroh-blobs does with its own ALPN
  `/iroh-bytes/4`), a receiver `receive_window` and `stream_receive_window` cap of 2×BDP (300 kB) or 4×BDP
  (600 kB), and combinations. Quinn and noq default to a 1.25 MB stream window, an unlimited connection window
  and a 10 MB send window.

## Results

Without a blob, the control RPC takes **63.5–64.1 ms p50** (one RTT plus about 4 ms) in every configuration.

### 1. One shared connection with defaults (main matrix, steady-state ms, run1/run2)

| Buffer | CC | Blobs | p50 | p99 | Startup p99 | Unfinished | Goodput Mbit/s |
|---|---|---|---|---|---|---|---|
| router-1bdp | Cubic | 1 | 100 / 108 | 124 | 226 / 245 | 0 | 17.7–18.6 |
| router-1bdp | Cubic | 4 | 113 | 128 | 229 | 0 | 18.6 |
| router-1bdp | NewReno | 4 | 101 | 128 | 130 / 208 | 0 | 18.5 |
| router-1bdp | BBR | 4 | **371** | **1352** | 1107 / 1481 | 0 | 18.1 |
| relay-1MB | Cubic | 1 | 427–447 | 476–480 | 477–896 | 0 | 18.0–18.4 |
| relay-1MB | Cubic | 4 | 424 | 451 | 967 / 1347 | 0 | 18.6 |
| relay-4MB | Cubic | 1 | **494** | 522 | 502–509 | 0 | 18.6 |
| relay-4MB | Cubic | 4 | **1600** | **1746** | **3446 / 3424** | **15 / 15** | 18.6 |
| relay-4MB | NewReno | 4 | 1357 | 1696 | 3347 | 8 / 8 | 18.6 |
| relay-4MB | BBR | 4 | 376 / 1011 | 386 / 3415 | 387 / 3399 | 0 / 10 | 18.6 |

- **The added latency is the standing queue.** One blob stream is capped by the 1.25 MB default stream window.
  That allows about 1.16 MB of queue, which is 463 ms at 20 Mbit/s and matches the measured 494 ms p50. Four
  streams fill the 4 MB buffer (≈ 1.7 s). The interactive target in R13, "low hundreds of ms", is missed by 4–25×
  on the relay path.
- **Stream priority does not change steady state.** For example, relay-4MB Cubic 4 blobs gives 1600 → 1608 ms
  p50, and router Cubic 1 blob gives 100–108 → 107 ms. Priority only orders bytes inside quinn's send buffer. The
  delay is in the network queue, which priority cannot reach. Priority does halve the startup p99 under heavy
  overshoot (relay-4MB Cubic 4: 3446 → 1763 ms; router Cubic 4: 229 → 124 ms on run 2), so it is worth setting,
  but it is not the fix.
- **quinn's BBR is not a fix.** It drops 28 k–51 k packets per 17 s on the shallow buffer (Cubic drops about 330),
  gives 370 ms p50 with 4 blobs, and varies a lot between runs on the deep buffers.

### 2. Mitigations (steady-state ms; `sep` = blobs on their own connection; one run)

| Buffer | CC | Blobs | sep, default window | shared, rwnd 300 kB | shared, rwnd 600 kB | **sep, rwnd 300 kB** |
|---|---|---|---|---|---|---|
| router-1bdp | Cubic | 1 | p50 107, p99 122 | 120 / 635 | 115 / 410 | **114 / 121** |
| router-1bdp | Cubic | 4 | 107 / 122 | 335 / 1558 | 373 / 2193 | **111 / 121** |
| router-1bdp | BBR | 4 | 123 / 594 | 343 / 1663 | 455 / 2198 | **99 / 123** |
| relay-1MB | Cubic | 1 | 430 / 478 | 123 / 471 | 239 / 412 | **121 / 127** |
| relay-1MB | Cubic | 4 | 428 / 1828 | 286 / 1432 | 565 / 2893 | **121 / 128** |
| relay-4MB | Cubic | 1 | 493 / 522 | 124 / 430 | 239 / 394 | **120 / 128** |
| relay-4MB | Cubic | 4 | 1788 / 3749 (15 unfinished) | 317 / 1575 | 501 / 2534 | **120 / 127** |
| relay-4MB | BBR | 4 | 397 / 1573 (12 unfinished) | 282 / 1008 | 512 / 1505 | **120 / 128** |

Goodput with `sep` + 300 kB: 18.3–18.7 Mbit/s with Cubic (93–94 % of link, the same as the defaults); 15.3–16.9
Mbit/s with BBR on the shallow buffer.

- **A separate connection alone does nothing.** Two connections share the same bottleneck FIFO.
- **A window cap alone, on the shared connection, makes the tail worse.** p99 rises to 0.4–2.9 s, even though the
  queue is now ≤ 160 kB (max queue column in `out/mitig.tsv`). The connection-level `receive_window` (MAX_DATA)
  is shared by all streams. Blob streams use up the credit, so a new control response waits for credit, not for
  the queue. This is flow-control head-of-line blocking that the QUIC stream design does not remove. The
  mechanism is inferred from the max-queue/latency mismatch, not traced.
- **Only both together work.** A blob-only connection with a receive window of ≈ 2×BDP bounds the standing queue
  to about 1 BDP. Control stays on an uncapped connection. Steady p99 is **121–128 ms** (base + ≈ 1 BDP of queue)
  in all 3 buffers × 2 CCs × 1–4 blobs, with 0 unfinished RPCs and an unchanged Cubic goodput. Startup p99 is
  ≤ 128 ms as well.

**Does stream priority rescue the shared, capped connection?** No (`out/mitig-prio.tsv`: control 10 > blob 0,
rwnd 300 kB, one connection). With 4 blobs, steady p50 is 250–346 ms and p99 991–1617 ms across all 6
buffer × CC cells, against 282–343 ms and 1008–1663 ms without priority. With 1 blob, p99 is 201–489 ms. This fits
the credit explanation: priority decides which stream sends once credit exists, but a 2 KiB response still waits
for MAX_DATA. So the separation has to happen at the connection level.

### Caveats

- One link profile was tested: 20 Mbit/s, 60 ms. A fixed 300 kB window caps one blob connection at about
  300 kB / RTT. That is 40 Mbit/s at 60 ms but only 12 Mbit/s at 200 ms, so the cap must follow measured
  RTT × delivery rate rather than be a constant (see next steps).
- The emulator is a userspace tokio proxy with about 1 ms timer granularity. It does not model the relay's TCP
  leg reacting to loss, iroh path switching, GSO batching, or the receiver's application read rate.
- quinn 0.11 was tested, not noq 1.4 via iroh. noq has the same defaults (Cubic, `STREAM_RWND` 1.25 MB,
  `send_window` 8×) and the same `set_priority` and window knobs (`noq-proto 1.4.0 config/transport.rs`). Its
  BBRv3 was not tested.

## Sources

- RFC 9000 §2.3 (stream prioritisation is left to implementations) and §4 (connection-level flow control is
  shared by all streams): https://www.rfc-editor.org/rfc/rfc9000
- RFC 9218, Extensible Prioritization Scheme for HTTP (priority orders the sender's buffer; it cannot drain a
  network queue): https://www.rfc-editor.org/rfc/rfc9218
- RFC 8289, CoDel; RFC 7567, AQM recommendations (standing-queue / bufferbloat framing):
  https://www.rfc-editor.org/rfc/rfc8289, https://www.rfc-editor.org/rfc/rfc7567
- RFC 6817, LEDBAT (scavenger CC for background bulk transfer, the textbook fix for exactly this; not available
  in quinn/noq): https://www.rfc-editor.org/rfc/rfc6817
- iroh-relay 1.4.1 `PER_CLIENT_SEND_QUEUE_DEPTH = 512`, `MAX_PACKET_SIZE = 64 KiB`, `try_send` drops when full:
  https://docs.rs/crate/iroh-relay/1.4.1/source/src/protos/relay.rs
- iroh 1.4.1 uses noq 1.4 and exposes `congestion_controller_factory`, `stream_receive_window`, `receive_window`,
  `send_fairness`: https://docs.rs/crate/iroh/1.4.1/source/src/endpoint/quic.rs
- iroh-blobs 0.104.1 serves on its own ALPN `/iroh-bytes/4`, so a separate connection is the default when the
  blob layer is used as is: https://docs.rs/crate/iroh-blobs/0.104.1/source/src/protocol.rs
- quinn-proto 0.11.19 transport defaults (`EXPECTED_RTT` 100 ms, `MAX_STREAM_BANDWIDTH` 12.5 MB/s, unlimited
  `receive_window`): https://docs.rs/crate/quinn-proto/0.11.19/source/src/config/transport.rs

## What the planner should do next

1. **T1 (binding `webway-quic/v0`).** Replace "blob transfers get their own streams, so bulk data never blocks
   control messages" with something like this. Blob transfers MUST use a separate QUIC connection (the blob ALPN),
   not streams on the `webway/0` connection. The receiver SHOULD bound that connection's flow-control window to
   about 2× the path's BDP estimate. Control streams SHOULD have a higher send priority than any bulk stream. The
   `webway/0` connection MUST NOT have a connection receive window smaller than its streams need. Fix R13's
   "Mitigation" column the same way (streams avoid loss head-of-line blocking, not queueing delay).
2. **T8 (`blob/v0`) / T5.** A small task: auto-tune the blob connection's receive window from noq's RTT and
   delivery-rate estimates (for example `max(2 × min_rtt × rate, 64 kB)`). Re-run this harness at 100 Mbit/s /
   20 ms and 5 Mbit/s / 200 ms to check that a dynamic cap keeps throughput while holding control p99 under
   base + 1 BDP. Also try noq BBRv3 on the blob connection.
3. **T10 (devnet).** Make this a conformance/devnet check for M1 step 5: with a blob in flight over the relay
   path, the status-update latency p99 must stay under a stated bound (for example base RTT + 150 ms). Otherwise
   the "two status updates" arrive seconds late, which is not caught by any assertion today.
4. **Relay ops (Q7).** The relay's per-client queue (512 datagrams of up to 64 KiB) is the deep buffer. Ask
   upstream, or set in our relay binary, a byte bound on it instead of a datagram count.
