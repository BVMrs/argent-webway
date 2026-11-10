# Lab 2026-11-10: what must `SubscribeToTask fromSeq` pin so a resumed stream loses and duplicates nothing?

## Question

M1 step 6 (`docs/due-diligence.md` §6) asserts: "Kill `alpha` mid-stream, restart, `SubscribeToTask fromSeq=k`,
and no events are lost or duplicated." §4.4/§4.5 give only three facts: each task event gets a per-task monotonic
`seq`, the node "persists tasks and their event log before acknowledging", and on reconnect "the node replays from
its durable event log". The interop report (`docs/research/a2a-mcp-interop.md` §3.4, R-E2, R-E5) found that no
A2A SDK replays events, Java has a snapshot/tap race, and JS can duplicate. So argent-webway has to define resume
itself.

Several choices are still open, and each one alone can break the M1 assertion: when an event is persisted
relative to being published, how the replay hands off to the live tail, whether `fromSeq=k` is inclusive, what the
client does with stale or gapped `seq`, and how the client makes its cursor durable. **Which combinations give
exactly-once, in-order delivery under disconnects, client crashes and server crashes, and what does each wrong
choice cost?**

## Method

`lab/stream-resume-model/` is a dependency-free Rust crate (rules in the header of `src/main.rs`). In the model,
one task on beta produces N events and alpha consumes them over an ordered stream (one QUIC stream, FIFO). The
stream starts attached live, like `SendStreamingMessage`. After any fault the client must resume through
`SubscribeToTask`. The design axes are:

| Axis | Options |
|---|---|
| Producer, per event | **P1** persist → publish (2 steps) · **P2** publish → persist · **P3** persist+publish atomic under a per-task lock |
| Replay → live handoff | **H1** read log, then attach · **H2** attach (buffer live), read log, flush buffer · **H3** as H2, but the flush drops `seq ≤ last replayed` · **H4** read+attach atomically (a full lock only together with P3) |
| `fromSeq` meaning | **Fok** client and server agree · **Fdup** client sends last seen, server treats it as inclusive · **Fskip** client sends next wanted, server treats it as exclusive |
| Client receive rule | **C1** drop `seq ≤ cursor`, resubscribe on a gap (`seq > cursor+1`), else apply · **C2** apply whatever arrives |
| Client durability | **K1** effect + cursor in one transaction · **K2** effect, then cursor · **K3** cursor, then effect |

These give 3 × 4 × 3 × 2 × 3 = **216 configurations**.

When the server crashes, it loses everything that is not durable, and the agent re-executes from the last
persisted event. A regenerated event has **different content** (LLM agents are not deterministic) and takes the
next free `seq`.

**Exhaustive part.** For each configuration and each fault budget (none; ≤2 disconnects; 1 client crash; 1 server
crash; all of these together), a BFS visits every interleaving of producer steps, handoff steps, client steps and
faults, and judges every *quiescent* state (producer done, client attached live, nothing in flight) against the
ground truth, which is beta's durable log. A quiescent state is the outcome if no further fault occurs. The
failure classes are:

- **tail loss**: the last events are missing. The client waits forever for the terminal event.
- **mid loss**: an event is missing but later ones were applied. The loss is *silent*: a gap check cannot see it.
- **dup**: an event was applied twice.
- **phantom**: the client applied an event that is not in the durable log.
- **reorder**: events were applied out of `seq` order.
- **livelock**: the client resubscribes more than 6 times because of gaps.

With N = 4 the run covers 12.46 M states and judges 337 k quiescent states, in about 28 s. With N = 3 it covers
3.56 M states. Both sizes give the same set of correct configurations.

**Monte Carlo part.** This part runs 2,000 tasks × 40 events for the recommended configuration and each one-axis
deviation from it. The scheduler picks a random enabled action at each step. Faults fire per scheduler step with
p(disconnect) = 1 %, p(client crash) = 0.1 % and p(server crash) = 0.1 %, with no budget. These rates are
deliberately harsh. They are there to rank the failure modes, not to predict field rates.

Reproduce with `cargo run --release -- 4 2000` (output in `results.txt`: the table, every shortest
counterexample, and the MC table).

## Results

### Exhaustive (N = 4)

| Fault budget | Configurations that fail (of 216) |
|---|---|
| none | **0** |
| ≤ 2 disconnects | 174 |
| 1 client crash | 202 |
| 1 server crash | 174 |
| all of these together | **202** (138 of them with *silent* mid loss or phantoms) |

The tests pass with no faults for every configuration. M1 step 6 only catches a bug if the devnet actually
injects these faults at the right points.

**Exactly 14 configurations are correct under every budget**, and they have the following shape:

- the producer is **P1 or P3**: an event is durable before anyone can see it. **All 72 P2 configurations** fail
  under a single server crash, with mid loss + phantom.
- the handoff is **H2, H3 or H4**. **H1 never works**: events produced between the read and the attach are lost.
  This is the Java SDK race from the interop report.
- `fromSeq` is **Fok or Fdup**. **Fskip never works**: with a gap-detecting client it livelocks (it always asks
  one past what it needs, sees a gap and resubscribes), and without one it loses an event at every resume.
- client durability is **K1** (effect and cursor atomic). K2 duplicates and K3 silently loses an event on a crash
  that falls between the two writes.
- the client rule is **C1** (dedupe by `seq` plus gap → resubscribe). There is one exception: with P3 + (H3 or H4)
  + Fok the server alone delivers exactly once, so even C2 is correct. Under Fdup, P1 or H2, C2 duplicates.

### Shortest counterexamples (verbatim from `results.txt`)

- **P2, publish before persist, server crash → phantom + silent loss.** The shortest trace in `results.txt` for
  this budget is a tail loss:
  `… publish(4:3) > F:server-crash > publish(4:19) > c:subscribe > ho:read > persist > ho:flush` gives log
  `[1:0 2:1 3:2 4:19]` and client `[1:0 2:1 3:2]`. The phantom variant was traced by hand from the same rules:
  the client receives `(3, X)`, beta crashes before persisting it, and the re-executed agent writes a different
  `(3, Y)`. The client's cursor is already 3, so it resumes after 3, never sees `(3, Y)`, keeps `X`, which the
  server no longer has, and the next event `(4, …)` passes the gap check. **Using `seq` as the dedupe key is only
  safe if a `seq` is never shown to anyone before it is durable.**
- **H1, read then attach, one disconnect → everything lost.**
  `F:disconnect > c:subscribe > ho:read > persist+publish ×4 > ho:attach` gives the client `[]` and the log
  `[1..4]`, and the client hangs waiting for a terminal event.
- **P1 + H4 + C2, persist/publish not under the same lock → duplicate.** Event 4 is persisted, replayed by the
  atomic read+attach, and then published live, so the client gets `4:3 4:3`. A lock around the handoff alone is
  not enough. The lock must also cover persist+publish (P3), as .NET's per-task lock does, or the client must
  dedupe.
- **K3, cursor saved before the effect, client crash → silent loss**: client `[1:0 2:1 3:2]` vs log `[1..4]`.

### Monte Carlo (2,000 tasks × 40 events; % of tasks with a wrong final view)

| Configuration | bad | loss | of which silent | dup | phantom | livelock |
|---|---|---|---|---|---|---|
| **P3-H3-Fok-C1-K1** (recommended) | **0.00** | 0 | 0 | 0 | 0 | 0 |
| P1-H3-Fok-C1-K1, P1-H4-Fok-C1-K1, P3-H2/H4-Fok-C1-K1, P3-H3-Fdup-C1-K1, P3-H3-Fok-C2-K1 | 0.00 | 0 | 0 | 0 | 0 | 0 |
| P2-H3-Fok-C1-K1 (publish before persist) | 2.30 | 2.30 | 1.35 | 0 | 1.35 | 0 |
| P3-H1-Fok-C1-K1 (read then attach) | 3.15 | 3.15 | 0 | 0 | 0 | 0 |
| P3-H3-Fskip-C1-K1 (off by one) | 64.50 | 0.65 | 0 | 0 | 0 | 63.85 |
| P1-H3-Fok-C2-K1 (no client dedupe) | 24.35 | 0 | 0 | 24.35 | 0 | 0 |
| P1-H2-Fok-C2-K1 (no filter, no dedupe) | 61.00 | 0 | 0 | 61.00 | 0 | 0 |
| P3-H3-Fok-C1-K2 (effect, then cursor) | 7.00 | 0 | 0 | 7.00 | 0 | 0 |
| P3-H3-Fok-C1-K3 (cursor, then effect) | 6.30 | 6.30 | 6.30 | 0 | 0 | 0 |

The Monte Carlo agrees with the exhaustive check: every configuration the exhaustive check marks correct scores
0 % here, and every one-axis deviation fails.

## Sources and prior art

- A2A v1.0.1 streaming and SubscribeToTask (snapshot first, no replay, "Messages MUST NOT be considered a reliable
  delivery mechanism"), and the v1.1.0-rc `generation` / `last_seen_generation`: quoted with line numbers in
  `docs/research/a2a-mcp-interop.md` §2 and §3.4. The v1.1 name means "last seen", i.e. exclusive.
- WHATWG HTML, Server-sent events, `Last-Event-ID`: <https://html.spec.whatwg.org/multipage/server-sent-events.html>.
  The client reports the *last id it received*, so resumption is exclusive.
- Kafka consumer offsets: the committed offset is the *next* record to read (`KafkaConsumer` javadoc,
  <https://kafka.apache.org/documentation/#consumerconfigs>). That is the inclusive convention, so Kafka and SSE
  disagree. This is exactly the Fdup/Fskip mismatch that bites bridges.
- Redis `XREAD`: returns entries with an ID *greater than* the given one (<https://redis.io/docs/latest/commands/xread/>).
  NATS JetStream `DeliverByStartSequence` / `opt_start_seq` starts *at* the sequence
  (<https://docs.nats.io/nats-concepts/jetstream/consumers>). EventStoreDB/KurrentDB clients removed the ambiguity
  from the name with `FromStream.After(revision)`.
- Transactional outbox / "publish only what is committed" (persist then publish): the standard fix for P2. See
  <https://microservices.io/patterns/data/transactional-outbox.html>.

What does not apply: Kafka and JetStream redeliver at-least-once and leave idempotence to the consumer. Here the
consumer *can* be exact because `seq` is dense and per task, which is why gap → resubscribe (C1) works. That is
only true while `seq` is never reused (no P2).

## What the planner should do next

When writing `mailbox/v0` "resumable streams" and the binding (T1/T7), pin the following, each with a requirement
ID and a vector:

1. **A `seq` is assigned and persisted before the event is sent to anyone** (P1 or P3). It MUST NOT be reused after
   a crash. This is the only rule whose violation causes silent loss and phantoms.
2. **The handoff MUST NOT read before attaching**. Attach and buffer live events, replay, then flush only
   `seq > last replayed` (H3), or do everything under the same per-task lock as the producer (P3 + H4).
3. **Rename `fromSeq` to `afterSeq`**: exclusive, equal to the last applied `seq`, aligned with A2A 1.1
   `last_seen_generation` and SSE `Last-Event-ID`. Add a vector with `afterSeq = k` that expects first `seq = k+1`.
   Fskip livelocks a correct client in 64 % of tasks.
4. **The client MUST drop `seq ≤ cursor`, and MUST treat `seq > cursor+1` as a disconnect and resubscribe.** It
   MUST commit its cursor in the same transaction as the event's effect. That transaction is the client-side
   equivalent of §4.4's durable dedupe rule.
5. **The devnet must inject the faults at these interleaving points.** With no faults, all 216 configurations
   pass. The devnet needs a server crash between publish and persist, a disconnect between replay-read and attach,
   and a client crash between effect and cursor. Otherwise M1 step 6 passes for the wrong reasons.
   `results.txt` lists ready-made shortest traces to turn into harness scenarios.

Not modelled, possible follow-ups: the A2A snapshot-first `Task` on SubscribeToTask (the snapshot must carry the
`seq` it reflects, or C1 cannot reconcile it), several concurrent subscribers, bounded subscriber buffers (R-E6),
and log compaction after a terminal state (`afterSeq` below the retained range needs an explicit error, not an
empty replay).
