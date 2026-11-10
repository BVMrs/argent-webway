# Lab 2026-11-10: outbox retry policy vs a mailbox host coming back from an outage

## Question

`mailbox/v0` (due diligence §4.5, roadmap T7, on the M1 critical path) says only: "Each node has an **outbox**: a
durable queue per destination, retried with exponential backoff and jitter." It does not say whether the timer is
per envelope or per queue, what the cap is, which jitter, or how the mailbox host behaves when overloaded.
Relays are a first-class path (§4.3), and each owner's relay is also its mailbox host (Q7). So when a relay or
mailbox host restarts after an outage, every outbox that targets it retries at once. The earlier freshness lab
assumed "1 s doubling to 10 min, ±50 % jitter, per envelope". This lab asks:

**Which outbox retry policy, combined with which mailbox-host admission behaviour, makes a mailbox host recover
from an outage, and at what cost in delivery delay and `expired` envelopes?** In particular, can a
reasonable-looking policy push the host into a *metastable* overload that persists after the cause is gone?

## Method

`lab/outbox-retry-herd/` is a dependency-free Rust crate: a discrete-event model (header of `src/main.rs` has the
full model). Run it with `cargo run --release -- main` (192 cells, 6.5 min on 3 cores) and `-- sens` (108 cells,
55 s). Raw per-cell TSVs: `results-main.tsv` (seed 1, handshake cost 1.0) and `results-sens.tsv` (seed 2,
handshake cost 0.3 / 1 / 3).

- **Load.** K = 1000 sender nodes, each creating envelopes for this mailbox host as a Poisson process at
  1/min (16.7 env/s in total). TTL (`exp − ts`) is log-uniform over 5 min to 24 h, as in the freshness lab. Senders
  stop retrying at `exp`; an envelope never acked by `exp` is reported `expired`.
- **Mailbox host.** One FIFO at C = 100 work units/s. A request carrying n envelopes costs `hs + 0.1·n` (connection
  + auth + one fsync per request, plus a per-envelope verify/store), with hs = 1 by default. Steady load is about
  18 % of capacity. The client times out after 10 s. The host is down from t = 30 min for D ∈ {1 min, 10 min, 1 h,
  6 h}. While it is down, attempts fail after 5 s at no cost to it. The model then runs for 3 h after recovery.
- **Host variants.**
  - `Fifo`: naive. It finishes (and stores) requests whose client already gave up, which is wasted work.
  - `Cancel`: skips requests whose client gave up before service started (deadline propagation).
  - `Shed`: `Cancel`, plus a cheap reject (0.02 units, e.g. QUIC `CONNECTION_REFUSED` before the handshake
    crypto) when queue delay > 2 s.
  - `Hint`: `Shed`, plus the reject carries a Retry-After ~ U(0, queue + 2·rejected demand in the last 10 s / C).
- **Outbox variants.**
  - Grain:
    - `E`: one timer per envelope, and each attempt carries one envelope.
    - `Q`: one timer per (sender, mailbox host) queue. An attempt carries everything queued, and new envelopes
      join the queue and wait for its timer.
  - Shape, with base 1 s, doubling:
    - `Pm50`: ±50 % jitter (the earlier lab's assumption).
    - `None`: no jitter.
    - `Full`: U(0, d), "full jitter".
    - `Decor`: min(cap, U(1, 3·prev)), "decorrelated jitter".
  - Cap: 600 s or 60 s.
- **Metrics.** "Backlog" means envelopes created in [T0 − 10 min, T_up) and not acked before the outage.
  - `bl p99`: delay after recovery to ack the backlog, over the envelopes that were delivered.
  - `avoidable exp`: backlog envelopes whose `exp` was more than 2 min after recovery and still expired.
  - `new p99`: latency of envelopes created in the first hour after recovery.
  - `recovered`: no client timeout or reject in the last 30 min of the 3 h horizon.
  - `wasted`: fraction of host work spent on requests whose client had already given up.

## Results

### 1. Per-envelope timers drive a naive mailbox host into metastable collapse

On `Fifo`, the earlier lab's default policy (E, ±50 %, cap 600 s) recovers from a 10 min outage. After a **1 h
outage it never recovers**:

- the 60 k-envelope backlog arrives as a 3.9× capacity herd, the queue passes the 10 s client timeout, and the
  host keeps serving abandoned requests (99.0 % of its work wasted);
- every new envelope then also fails and joins the herd, so offered load stays above capacity for the whole 3 h
  horizon;
- 41 107 of 59 774 backlog envelopes (69 %) and about 36 k new ones expire.

The tail-latency columns for these collapsed cells only describe the few envelopes that got through.

| `Fifo` host, policy | 1 min | 10 min | 1 h | 6 h |
|---|---|---|---|---|
| E ±50 % cap 600 | ok | ok (p99 655 s) | **collapse** | **collapse** |
| E none / full cap 600 | ok | ok | **collapse** | **collapse** |
| E decorrelated cap 600 | ok | **collapse** | **collapse** | **collapse** |
| E ±50 % / full cap 60 | ok | **collapse** | **collapse** | **collapse** |
| Q ±50 % / full / decor cap 600 | ok | ok | ok | ok |
| Q none cap 600 | ok | ok | ok | ok after 43 min (21 % wasted) |
| Q ±50 % / full cap 60 | ok | ok | ok | **collapse** |

Across the main matrix, collapses ("not recovered after 3 h") occur in:

- E on `Fifo`: 15 of 24 cells;
- E on `Cancel`: 11 of 24. Deadline propagation alone does not save per-envelope timers at ≥ 1 h;
- E on `Shed`: 1 of 24 (6 h outage, cap 60, full jitter, still at 70× capacity offered);
- Q on `Fifo`: 2 of 24 (6 h, cap 60);
- Q on `Cancel` / `Shed` / `Hint`: 0 of 72.

Why: with per-envelope timers the herd size is the **backlog** (up to 360 k envelopes), and each envelope's
retries continue for its whole TTL. With per-queue timers the herd size is the number of **senders** (1 000), and
one request drains a whole queue at 0.1 units per envelope. Decorrelated jitter is the worst shape for per-envelope
timers because U(1, 3·prev) keeps falling back to a few seconds.

### 2. Per-queue timers are safe, but a 600 s cap delays new traffic and causes avoidable expiries

Q with cap 600 s never collapses, on any host, at any outage length, at any handshake cost. But the timer is still
up to 10–15 min out when the host comes back. Every new envelope joins that queue and waits:

- new-envelope p99 is 170–510 s after a 10 min to 6 h outage;
- 6–198 short-TTL new envelopes expire;
- 141–2 825 backlog envelopes expire avoidably;
- backlog p99 is 530–830 s.

This is the cost of SMTP-style "keep a list of hosts you cannot reach, not per-message retries" (RFC 5321
§4.5.4.1) with a long cap.

### 3. Recommended: per-queue timer, 60 s cap, jitter, and admission shedding at the mailbox host

Q + cap 60 s (±50 % or full jitter) + `Shed`. Results over 4 outages × seed 1 plus 3 outages × 3 handshake costs
× seed 2, 13 cells per jitter shape (26 in total):

- **recovered in all 26 cells**; 0 wasted work;
- backlog p50 8–103 s, p99 46–262 s;
- avoidable expiries ≤ 3 for outages ≤ 1 h; for 6 h, 65–327 of about 360 k (≤ 0.09 %);
- new-envelope p99 ≤ 102 s, 0 new envelopes expired.

The same Q / 60 s outbox **without** shedding (`Fifo`) collapses after a 6 h outage at every handshake cost: each
queue then holds about 360 envelopes, so the 1 000 drain requests together need about 370 s of host time, far over
the 10 s client timeout. With hs = 3, full jitter also collapses after 1 h, and ±50 % survives with 4.3 % wasted work. So the outbox policy and the host's admission
rule must be specified together.

`Hint` (Retry-After) adds little on top of `Shed` with per-queue timers (6 h p99 172 s vs 194 s). With
per-envelope timers it hurts new traffic: the hinted delays are applied to fresh envelopes too, and
2.9 k–17.9 k new envelopes expire after a 6 h outage. It is optional, not a fix.

### Sensitivity

- Handshake cost hs = 0.3 makes everything easier. E ±50 % / 600 then recovers from 1 h but still collapses at
  6 h on `Fifo`. With hs = 3, E ±50 % / 600 collapses after just 10 min on `Fifo`.
- Seed 2 at hs = 1 reproduces seed 1 to within a few percent on every metric shown.
- Not modelled: ack loss (covered by the freshness lab), several mailbox hosts, a TCP-leg relay, host restart
  losing its queue, reachability signals that iroh could give for a sender's *own* home relay, and a batch-size cap
  (the next thing to try for hosts that cannot shed).

## Sources

- AWS Architecture Blog, "Exponential Backoff and Jitter" (2015):
  <https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/>. It defines full, equal and
  decorrelated jitter and measures them on contention, not on recovery from overload. That is why decorrelated
  jitter looks good there and bad here.
- M. Brooker, "Timeouts, retries, and backoff with jitter", Amazon Builders' Library:
  <https://aws.amazon.com/builders-library/timeouts-retries-and-backoff-with-jitter/>. It covers retry
  amplification and load shedding.
- N. Bronson et al., "Metastable Failures in Distributed Systems", HotOS 2021:
  <https://sigops.org/s/conferences/hotos/2021/papers/hotos21-s11-bronson.pdf>. Collapse sustained by retries
  after the trigger is gone is exactly result 1.
- L. Huang et al., "Metastable Failures in the Wild", OSDI 2022:
  <https://www.usenix.org/conference/osdi22/presentation/huang-lexiang>.
- gRPC connection backoff: <https://github.com/grpc/grpc/blob/master/doc/connection-backoff.md>. It is one
  timer per *connection* (not per RPC): initial 1 s, ×1.6, ±20 % jitter, max 120 s, min connect timeout 20 s.
  This matches the per-queue grain and a short cap.
- RFC 5321 §4.5.4.1 (SMTP sending strategy): "A client SHOULD keep a list of hosts it cannot reach and
  corresponding connection timeouts, rather than just retrying queued mail items". It suggests a ≥ 30 min retry
  interval, because SMTP has days of TTL, while ours can be 5 min.
- RFC 9110 §10.2.3 (Retry-After): <https://www.rfc-editor.org/rfc/rfc9110#section-10.2.3>.

## What the planner should do next

1. In `mailbox/v0` (T7), make the outbox **retry timer per (sender node, next hop / mailbox host)**, not per
   envelope. A successful attempt drains the queue. New envelopes for a host in backoff wait for its timer.
   Suggested constants: base 1 s, ×2, **cap 60 s**, ±50 % or full jitter. Retries stop per envelope at `exp`,
   as now. Fix the freshness lab's assumption (per envelope, cap 10 min) wherever it is copied into the spec.
2. Add a **mailbox-host admission rule** to the same spec. The host MUST reject cheaply (before the handshake
   crypto where the transport allows, else with a `Busy`/`Unavailable` error mapped in the error model) when its
   queue delay exceeds a bound well under the client timeout. It SHOULD drop work for requests whose client has
   gone. Retry-After is optional (MAY).
3. Add a T10 devnet scenario: mailbox host down for ≥ 1 h with ≥ 100 senders, then assert recovery within a
   bound and zero avoidable expiries. M1 step 6 only checks one task's dedupe, not recovery.
4. Follow-up lab: a per-request batch cap (bytes or envelopes) as an alternative to shedding for hosts that cannot
   reject early, and the effect of a host restart that loses its in-memory queue.
