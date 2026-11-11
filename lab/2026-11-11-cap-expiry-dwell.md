# Which clock checks capability expiry for a mailbox-delayed envelope?

Date: 2026-11-11. Track: `capability/v0` × `mailbox/v0` (T3, T5, M1 steps 4 and 6). Code: [`cap-expiry-dwell/`](cap-expiry-dwell/).

## Question

`envelope/v0` makes freshness independent of mailbox dwell: an envelope is accepted while `now ≤ exp + skew`, so
it can wait in a mailbox for hours (§4.7.3). The capability token inside it has its own expiry, a Biscuit
`check if time($t), $t <= <exp>` caveat (M1 issues `ttl=1h`). The spec does not say **which time the node injects
as `time()`** when it authorizes an envelope that waited in a mailbox. Possible choices:

| rule | time checked against `tok_exp` |
|---|---|
| R1 | receiver `now`, strict |
| R1s | receiver `now`, `+ skew` grace |
| R2 | envelope `ts` (sender-claimed), `+ skew` |
| R3 | **postmark**: arrival time signed by the receiver owner's own mailbox host (receiver `now` if delivered directly), `+ skew` |
| R5 | receiver `now` with a long grace (1 h, 24 h) |
| clamp+R1s | sender sets `exp = min(ts + E, tok_exp)`, receiver uses R1s |

How many honest envelopes does each rule reject, and how long does each let a holder whose token has expired keep
using it? Also: does biscuit-auth 6 make any choice unsafe?

M1 runs straight into this. Step 1 issues a 1 h token. Step 4 requires "expired token" to be rejected. Step 6 keeps
`beta` down "longer than the skew window" and requires the queued task to be accepted. Under R1/R1s, step 6 passes
only if the fake-clock outage is shorter than the token's remaining life. The scenario never states that limit.

## Method

1. **Monte Carlo** (`src/bin/sim.rs`, 60 runs × 8 weeks per cell, about 0.97 M envelopes per cell, 60 cells, 3.7 s).
   One honest sender sends Poisson traffic, one per 5 min. Receiver availability follows one of three profiles:
   - *server*: up for an exponential mean of 7 d, then down for a mean of 15 min;
   - *flaky*: 2 h up, 30 min down;
   - *office*: weekdays 08:30–18:30 with jitter, 15 % of weekdays absent, weekends off.

   The mailbox host itself is down 10 min per 30 d. Clock offsets for the sender, receiver, host and issuer are drawn
   from U(±60 s), with skew = 5 min.

   The token TTL ranges over 5 min to 7 d. The envelope TTL `E` is 1 d or 7 d (cap 7 d). Token refresh is either
   *lazy* (refresh when the sender's clock says the token has expired) or *per-send* (the issuer is always reachable
   and mints a fresh token for every send).

   An envelope that passes envelope freshness and fails only the token check counts as an honest token rejection.
   The *lost* columns add envelope expiry to that, so they give the total share of messages that are not processed.
2. **Attacker window**: a direct search for the latest time after `tok_exp` at which a holder whose token has expired,
   but who still has its agent key, gets a new envelope accepted. The holder picks `ts` freely within freshness. The
   mailbox host is either honest or colluding (backdates the postmark).
3. **biscuit-auth 6.0.0 behaviour** (`src/bin/biscuit_time.rs`, 9 cases): how the injected `time` facts and check
   scopes interact with a TTL check.

Run: `cargo run --release --bin sim` and `cargo run --release --bin biscuit_time`. Outputs are in
`results.txt` and `biscuit_time.txt`.

## Results

### Honest loss: % of sent envelopes not processed (envelope expiry + token rejection)

Selected cells. Full table, including R1, R2 and R5, in `results.txt`.

| profile (share via mailbox, dwell p50/p99) | refresh | token TTL | E | env expired | lost R1s | lost clamp+R1s | lost R3 |
|---|---|---|---|---|---|---|---|
| server (0.15 %, 10 min / 1.4 h) | lazy | 1 h | 7 d | 0 | 0.04 | 0.04 | **0** |
| flaky (20 %, 21 min / 2.3 h) | lazy | 5 min | 7 d | 0 | 14.99 | 14.99 | **0.0002** |
| flaky | lazy | 1 h | 7 d | 0 | 6.91 | 6.91 | **0.0007** |
| flaky | per-send | 1 h | 7 d | 0 | 2.22 | 2.22 | **0** |
| flaky | per-send | 8 h | 7 d | 0 | 0 | 0 | 0 |
| office (75 %, 16 h / 4 d) | lazy | 1 h | 7 d | 0 | 73.81 | 73.81 | **0.0011** |
| office | per-send | 1 h | 7 d | 0 | 72.69 | 72.69 | **0** |
| office | per-send | 1 d | 7 d | 0 | 31.35 | 31.35 | **0** |
| office | per-send | 7 d | 7 d | 0 | 0 | 0 | 0 |
| office | per-send | 1 h | 1 d | 31.02 | 71.91 | 71.91 | 31.02 |

- Under R1s, **any receiver that is ever offline longer than the token's remaining life loses that traffic**. With
  M1's 1 h TTL, the loss is 2–7 % for a flaky laptop and 73 % for an office-hours receiver. Per-send refresh only
  helps when the TTL exceeds the dwell. Strict R1 is worse still: 20 % (flaky, lazy, 5 min TTL).
- **clamp+R1s loses exactly as much as R1s in all 60 cells** (by construction, a token rejection becomes envelope
  expiry). Its only benefit is the signal: the sender's own clock tells it the message died (`expired`, §4.5),
  instead of a `CapabilityDenied` arriving hours later.
- **R3 (postmark) reduces token-induced loss to ≤ 0.007 % in every cell.** What remains is the sender presenting a
  token that is already expired by the issuer's clock (lazy refresh plus issuer–sender offset). What R3 still loses
  is envelope expiry, which the sender chose and is told about.
- R2 (sender `ts`) and R5-1d lose almost nothing (R5-1d: up to 32 % with office receivers and 7 d envelopes), but
  see the attacker window.

### Attacker window: how long after `tok_exp` an expired holder is still accepted

| rule | honest mailbox host | colluding mailbox host |
|---|---|---|
| R1 | 0 s | 0 s |
| R1s | 299 s (= skew) | 299 s |
| R2 (`ts`) | **7 d** (= `exp − ts` cap) | 7 d |
| R3 (postmark) | 299 s | **7 d** |
| R5 1 h / 1 d | 1 h / 24 h | 1 h / 24 h |

R2 is unacceptable: `ts` is chosen by the sender, so every token gets an extra week. R5 trades honest loss for a
fixed extension of every TTL, which makes short TTLs meaningless. R3 matches R1s unless the receiver's **own**
designated mailbox host lies. The receiver already depends on that host for availability. R3 additionally trusts it
for one timestamp, bounded by the 7 d `exp − ts` cap and by `ts − skew` from below.

### biscuit-auth 6 pitfalls (3 of 9 cases unsafe)

| case | result |
|---|---|
| B1/B2/B3: node injects one explicit `time` fact; no fact means the check fails closed | correct |
| **B4**: `AuthorizerBuilder::time()` reads `SystemTime::now()`. With the fake clock set 1 d past `exp` (wall clock earlier), the token is **accepted** | unsafe for the R12 fake clock, and any node that calls it ignores the injected clock |
| **B5**: injecting two `time` facts ("check at postmark *and* now") is an **OR**: the token is accepted if either one passes | unsafe |
| **B6**: a delegator's TTL check written `trusting authority, ed25519/<next holder>` lets that next holder assert its own `time(<before exp>)` in its third-party holder block, and the expired token is **accepted** | unsafe; this is the shape a §4.7.2 holder chain invites |
| B7/B8: the same forged `time` fact against a default-scope (authority) check, from a third-party or an ephemeral block | correctly rejected |

## Sources

- biscuit-auth 6.0.0 (crates.io), `AuthorizerBuilder::time`, scopes and `trusting` in the Biscuit specification:
  <https://github.com/eclipse-biscuit/biscuit/blob/main/SPECIFICATION.md>. Results above were measured, not read
  from the docs.
- Prior art for checking validity at a trusted arrival time rather than at verification time:
  - RFC 3161 (Time-Stamp Protocol), <https://www.rfc-editor.org/rfc/rfc3161>;
  - RFC 5126 (CAdES): long-term validation checks the signer's certificate at the time given by a trusted
    timestamp, <https://www.rfc-editor.org/rfc/rfc5126>.

  In both, the time is trusted only because a designated authority signs it. Here, that authority is the receiver
  owner's own mailbox host, never the sender.
- Matrix homeserver-as-mailbox pattern (cited in due-diligence §3): the receiving side's server stamps arrival.
- Earlier lab: [delivery-freshness-sim](2026-11-09-delivery-freshness-sim.md) (receiver clock steps),
  [biscuit-authz-limits](2026-11-11-biscuit-authz-limits.md) (pre-Datalog block-shape gate).

## What the planner should do next

1. **Decide the rule in `capability/v0` (T3).** Recommendation: **R3**. Token expiry is evaluated at
   `t_check = postmark.at` if the envelope carries a valid postmark from the receiver owner's designated mailbox
   host, and at the receiver's `now` otherwise, with `t_check ≤ tok_exp + skew`. A valid postmark requires:
   - a key bound by an owner-signed designation;
   - covering `(to, from, id, body_hash)`;
   - `ts − skew ≤ at ≤ now + skew`.

   This needs a new signed `postmark` field in `mailbox/v0` (T5): a single Ed25519 signature per stored envelope.
   If the planner prefers no postmark in M1, use **clamp+R1s**: the sender MUST NOT set `exp` past the earliest
   `time` caveat it can read in its tokens. Then state in the spec that offline delivery is bounded by token
   lifetime, which with 1 h tokens makes the mailbox nearly useless for office-hours receivers (73 % loss).
2. **Revocation stays at the receiver's `now`**, not at `t_check`. Otherwise a token revoked while the envelope sits in
   the mailbox still runs. `max_calls` metering is unaffected.
3. **Pin how the time is injected (T3):**
   - the node injects **exactly one** `time` fact from its (fake-able) node clock;
   - it never calls `AuthorizerBuilder::time()`;
   - the block-shape gate from biscuit-authz-limits rejects any token block that defines a `time` fact. That closes
     B6 regardless of check scopes.

   Add conformance vectors for B4, B5 and B6. Each must reject.
4. **Fix M1 step 6:** state that the fake-clock outage is longer than skew **and** longer than the token's remaining
   TTL (e.g. 2 h with `ttl=1h`), and that the task is accepted. That only holds under R3, so the step tests the
   chosen rule. Also add a vector: a postmark from a host that is not designated is ignored, and the token is
   checked at `now` and rejected.

Limits: one sender, independent clocks with no drift (a receiver clock step is covered by delivery-freshness-sim),
and profile parameters that are assumptions rather than measurements. The office profile dominates the losses. The
attacker search assumes exact clocks.
