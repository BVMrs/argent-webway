# Lab 2026-11-09: does "effectively once" hold under clock offsets and clock steps?

## Question

M1 (`docs/due-diligence.md` §6, steps 4 and 6) depends on the `envelope/v0` freshness and dedupe rules in §4.4,
§4.5 and §4.7.3. A receiver accepts while `now ≤ exp + skew` and rejects `ts > now + skew`. It keeps dedupe
entries until `exp + skew`. A duplicate gets the stored response, whose `exp` is at least `req.exp + skew`.
Senders stop retrying at `exp` and tell the caller the message is `delivered` or `expired`. The text claims this
gives at-least-once plus idempotent receivers, so effectively once.

There is no `spec/envelope.md` on master yet. The rules exist only in the due diligence, so this is the right
time to test them. This lab asks one question: **with real clocks (offsets, steps), lost acks, mailbox dwell and
replays, can an envelope be processed twice, or can the caller be told `expired` for a task that ran?** If so,
which small rule change fixes it, and what does the fix cost?

## Method

`lab/delivery-freshness-sim/` is a dependency-free Rust crate: a per-envelope discrete-event Monte Carlo. Each
trial is one envelope from sender S to receiver R. It may also pass through R's mailbox host M. Every node reads
`true time + its own offset`. The rules are modelled as written (see the header of `src/main.rs`):

- S retries directly with exponential backoff (1 s doubling up to 10 min, ±50 % jitter) while `now_s ≤ exp`.
  When R is unreachable, S also gives one copy to M. M delivers whenever R is up, retries until R acks, and drops
  the copy once `now_m > exp`.
- R applies the `Future` and `Expired` checks, then the dedupe lookup. A pruner runs every 60 s and deletes
  entries once `now_r > exp + skew`. R stores and replays the response with `exp = req.exp + skew`.
- S accepts a response while `now_s ≤ resp.exp + skew` and `resp.ts ≤ now_s + skew`. In V0, S reports `expired`
  when `now_s = exp` and it has no response.
- Fixed parameters: `skew` = 5 min (the doc's example). Each response and each mailbox ack is lost with
  probability 5 %. R's uptime is ~Exp(2 h) and its downtime ~Exp(30 min). TTL is log-uniform over 5 min–24 h.
  Latency is 20–300 ms.

Scenarios: A0 exact clocks. A: each node's offset uniform in ±skew/2, so pairwise offsets stay within `skew`
(the case the design assumes). A′: A with TTL 1–10 min. B and B′: offsets ±skew and ±2·skew (pairwise up to 2·skew
and 4·skew, out of spec). R: a party holding a copy (the mailbox host, which can read bodies until T15) replays it
3 times at random within `[0, ttl + 3·skew]`. C1–C6: R's clock runs fast by d, then is stepped back by d at a
random time (NTP correction, VM resume, manual fix). d is 1 s, 1 min, 10 min or 1 h, with and without replays.

Variants:

| Variant | Change |
|---|---|
| V0 | as written |
| V1 | S reports `expired` at `now_s = exp + 2·skew` instead of `exp`. It still stops retrying at `exp` and keeps accepting responses until then. `exp + 2·skew` equals `resp.exp + skew`, the last moment S would accept a response anyway |
| V2 | R persists a **prune watermark** W, the largest `exp + skew` it has pruned, and rejects as `Expired` any envelope with `exp + skew ≤ W`. The model takes the worst case for liveness: dense traffic, so W tracks the high-water mark of `now_r` |
| V3 | V1 + V2 |
| V4 | V3, and R looks up an unpruned dedupe entry *before* the freshness checks |

Each cell has 200 000 trials. All variants use the same seeds, so within a scenario they see the same world. The
full run takes 7 s:

```sh
cargo run --release --offline --manifest-path lab/delivery-freshness-sim/Cargo.toml   # N=… to change trials
```

The full table is in `lab/delivery-freshness-sim/results.txt`. A first run reported doubles with exact clocks.
That was a model bug, an `i64::MAX` overflow in the prune-time computation, and it was fixed before the numbers
below. A0, A and R give 0 doubles, which is the sanity check that the model implements the stated invariant.

## Results

Rates are **per million envelopes**. "Told expired, ran" means R processed the envelope but S's caller got
`expired` (or S received `EnvelopeExpired`). It is split into: (a) a valid response arrived *after* the report,
(b) R answered a retry with `EnvelopeExpired` after processing an earlier copy, (c) every response was lost.

| Scenario | Variant | Double processed | Told expired, ran (a / b / c) | Spurious reject |
|---|---|---|---|---|
| A0 exact clocks | V0 | 0 | 355 (5 / 0 / 350) | 0 |
| A ±skew/2 | V0 | 0 | 1670 (**1300** / 0 / 370) | 0 |
| A ±skew/2 | V1 | 0 | 370 (**0** / 0 / 370) | 0 |
| A′ TTL 1–10 min | V0 | 0 | 4985 (**4445** / 0 / 540) | 0 |
| A′ TTL 1–10 min | V1 | 0 | 540 (**0** / 0 / 540) | 0 |
| R replays | V0 | **0** | 3240 (1120 / 0 / 2120) | 0 |
| B ±skew | V0 | 0 | 7195 (2155 / 2795 / 2245) | 1065 |
| B′ ±2·skew | V0 | 0 | 32 955 (3165 / 22 635 / 7155) | 29 360 |
| C1 step 1 s + replays | V0 | 0 | 3660 | 0 |
| C2 step 1 min + replays | V0 | **200** | 3330 | 0 |
| C2 step 1 min + replays | V2 | **0** | 3330 | 0 |
| C3 step 10 min + replays | V0 | **31 315** | 106 365 | 20 950 |
| C3 step 10 min + replays | V2 | **0** | 106 430 | 24 795 |
| C4 step 1 h + replays | V0 | **48 570** | 164 415 | 298 630 |
| C4 step 1 h + replays | V2 | **0** | 97 575 | 384 805 |
| C5 step 10 min, no attacker | V0 | **4250** | 102 095 | 24 455 |
| C5 step 10 min, no attacker | V2 | **0** | 105 920 | 25 040 |
| C6 step 1 h, no attacker | V0 | **8650** | 90 365 | 371 985 |
| C6 step 1 h, no attacker | V2 | **0** | 98 050 | 383 420 |

V4 (dedupe first) on top of V3 lowers category (b) by 0.6–21 % in B and C (B 2795 → 2205, C5 81 920 → 75 155, C4
90 990 → 90 480). It changes nothing in A0, A or R.

Deterministic cases (exact clocks, skew 5 min, TTL 1 h), printed by the run:

- **E1**: M sends at `exp − 100 ms`, which the rules allow. R processes it, and the response reaches S at
  `exp + 200 ms`. Under V0, S has already told the caller `expired`.
- **E2**: a copy delivered at `exp + 4 min` is accepted by R (`now_r ≤ exp + skew`).
- **E3**: R prunes the entry, its clock steps back 10 min, and a replay at true `exp + skew + 2 min` is accepted
  again: **double processing**.

### What this means

1. **With monotone clocks, the dedupe invariant holds.** No doubles in A0, A, A′, B or B′, and none with 600 000
   replays (R). That includes out-of-spec offsets: R uses its own clock for both acceptance and pruning, so the
   offset to other nodes does not matter. Only a clock that goes *backwards* breaks it.
2. **A backward step on the receiver's clock breaks at-most-once, even with no attacker.** This happens when R's
   clock steps back past an already pruned `exp + skew`. A 10 min correction double-processes 0.4 % of envelopes
   in flight (C5) with only honest retries. If the mailbox host replays, that rises to 3.1 % (C3). With the 60 s
   pruner, steps under a minute were mostly absorbed (C1: 0, C2: 200 per million). A node that prunes eagerly
   would have no such margin. **V2 (the prune watermark) removes every double in every scenario.** It costs one
   persisted integer. In A, B and R it changes nothing: with a monotone clock W never exceeds `now_r`, so the check is already
   implied by `now_r ≤ exp + skew`. Only after a
   backward step does it add spurious rejects, up to +29 % in C4. That is the right trade for a node whose clock
   just went backwards. The same idea is old: Kerberos requires a server that lost its replay cache to reject
   everything for one skew window (RFC 4120 §3.2.3).
3. **V0's `expired` report is wrong even with good clocks.** The mailbox may deliver until `now_m = exp`. R
   accepts until `now_r = exp + skew`. Yet S tells the caller `expired` at `now_s = exp`. With in-spec offsets,
   0.13 % of envelopes (0.44 % at short TTLs) are reported `expired` and then complete (category a). Moving the
   report to `exp + 2·skew` (V1) makes category (a) zero in A, A′ and R.
4. **`expired` can never mean "did not run".** Category (c), where R ran the task and every response was lost, is
   350–540 per million at 5 % loss in every in-spec scenario, and no variant changes it. The two generals problem
   rules it out. The caller-facing state must be defined as "no confirmation received, may have run". M1 step 6
   and the error docs should not call it a negative outcome.
5. **Out-of-spec skew degrades liveness, not safety.** In B, R is ahead of S by more than `skew`. S then refuses
   11.8 % of responses on `resp.ts ≤ now_s + skew` until its clock catches up. R also answers 0.28 % of S's late
   retries with `EnvelopeExpired` for a task it already ran (b). Detecting this needs the error to carry R's
   `now`, so S can log the clock anomaly. That is not modelled.

### Limits

- One envelope per trial. The dedupe store is not shared, so W is modelled with a dense-traffic upper bound,
  which is the worst case for V2's liveness and has no effect on its safety.
- The sender is always online. Responses that wait in the *sender's* mailbox past `resp.exp + skew` are not
  modelled. The `≥ req.exp + skew` rule would lose them, which is an argument for letting R pick a longer response
  `exp`.
- The loss rate (5 %) and the outage shape are illustrative. Category (c) grows with the loss rate.

## Sources

- `docs/due-diligence.md` §4.4 (idempotency, duplicates, stored response), §4.5 (mailbox, `delivered`/`expired`),
  §4.7.3 (freshness), §6 steps 4 and 6, §9 (clock skew risk), on master at 10d10ad.
- RFC 4120 (Kerberos V5) §3.2.3, replay cache and the post-restart rejection window:
  https://www.rfc-editor.org/rfc/rfc4120#section-3.2.3
- RFC 8446 (TLS 1.3) §8, anti-replay for 0-RTT with a time window and a recorded set (same horizon logic):
  https://www.rfc-editor.org/rfc/rfc8446#section-8
- ntpd step threshold (default 128 ms, `tinker step`): https://www.ntp.org/documentation/4.2.8-series/miscopt/
- chrony `makestep`, which steps the clock on large offsets: https://chrony-project.org/doc/4.5/chrony.conf.html

## What the planner should do next

1. **Write the `envelope/v0` freshness section (T2) with a prune watermark** (V2): "A receiver MUST persist the
   largest `exp + skew` it has pruned, as part of the same durable store, and MUST reject an envelope with
   `exp + skew ≤` that value as `EnvelopeExpired`." It also helps to say that the dedupe lookup comes before the
   freshness checks (V4). Add vectors for both: E3 with a fake clock that steps back, and a duplicate just after
   `exp + skew` while the entry still exists.
2. **Change the sender rule** (§4.5, V1): stop retrying at `exp`, but report the terminal state only at
   `exp + 2·skew`. Name or document that state as **unconfirmed**, not "not delivered" (finding 4). Whether the
   caller then needs a way to reconcile (for example, look up a task by `messageId`) is a design question for the
   owner, not decided here.
3. **Tighten M1 step 6**: "the mailbox delivers it anyway" is only rejected if it arrives after `exp + skew` in
   beta's clock. The harness should pin both edges: delivery at `exp + skew` is accepted (and planner must not have
   been told `expired` yet), and delivery at `exp + skew + 1 ms` is rejected. Add a devnet case where beta's fake
   clock steps back 10 min after pruning, with a replayed copy. It must not create a second task.
4. Optional: carry the receiver's `now` in `EnvelopeExpired` and `Future` errors so senders can log clock
   anomalies (finding 5).
