# Lab 2026-11-11: mailbox-host storage admission vs flooding senders

## Question

`mailbox/v0` (due diligence §4.5, roadmap T7, M1 step 6) says the owner's mailbox host "accepts envelopes for
their offline nodes and holds them until they reconnect". The error model lists `MailboxFull`. Nothing says
**who may store envelopes at a mailbox host, how much each may store, or what happens when it is full**. Earlier
labs covered the host's *CPU* admission after an outage (outbox-retry-herd) and its clock (cap-expiry-dwell). None
covered its *storage*. Envelopes may pin storage for up to the 7-day `exp − ts` cap (§4.7.3).

**While receiver R is offline, can one sender (a capability holder or anyone with fresh keys) fill R's mailbox and
deny honest senders? Which admission rule prevents that? And does evicting stored envelopes break the
delivered/expired promise the outbox gives `planner`?**

## Method

`lab/mailbox-quota-flood/` is a dependency-free Rust crate. The full model is in the header of `src/main.rs`. Run it
with `cargo run --release -- main 200` (192 cells × 200 trials, about 2 min on 3 cores) and `-- sens 200`. Raw
results are in `results-main.tsv` and `results-sens.tsv`. Each cell uses common random numbers across policies and
attacks.

- **Setup.** R (owner B) is offline for D ∈ {8 h, 24 h, 72 h}. Its mailbox host M (B's relay, Q7 (a)) holds
  Q = 64 MiB for R and frees envelopes at `exp`.
- **Honest senders.** 20 senders, each with its own key and its own capability root from B. Daily demand is
  0.3·Q (≈19 MiB, ≈1 100 envelopes), split uniformly or Zipf(1) (the top sender has 28 %). Senders are online
  8 h/day at a random phase ("office") or always. Sizes are log-uniform from 512 B to 90 KiB (the 64 KiB inline cap
  after base64). `exp − ts` is log-uniform from 1 h to 7 d.
- **Outbox.** The outbox offers each envelope to M at once. On `MailboxFull` it retries every 60 s, in order, while
  the sender is online. After R returns, the sender delivers directly when it is next online, if that is before
  `exp`. Otherwise the envelope is reported `expired`.
- **Attacker.** It sends 20 Mbit/s of 90 KiB envelopes with `exp = ts + 7 d` (the profile cap), starting at
  U(0, D/2). There are three variants:
  - `insider`: one key with a valid capability from B.
  - `sybil`: a fresh key and fresh owner per envelope, with no capability from B.
  - `fanout`: the insider re-delegates its token through the §4.7.2 holder chain to a fresh key per envelope. That
    gives many keys under one root.
- **Policies at M.**

  | policy | keyed by | when full |
  |---|---|---|
  | `tail` | nothing | reject (`MailboxFull`) |
  | `oldest` | nothing | evict the oldest stored envelope |
  | `keyq` | sender key, cap Q/16 | reject |
  | `keylqd` | sender key | longest-queue-drop: evict from the key that stores most bytes |
  | `g-tail` | **gate**: admit only if the envelope's capability chain roots in B (or the sender is a pinned contact); principal = that root | reject |
  | `g-lqd` | gate + principal | longest-queue-drop per principal |
  | `g-resv` | gate + principal: reservation Q/(2N), N = 21 known principals (≈1.5 MiB each), plus a shared pool Q/2 with a per-principal pool cap Q/8 | reject, never evict |
  | `g-resv4` | as `g-resv`, pool cap Q/4 | reject, never evict |

- **Metrics.** They are computed over honest envelopes created during the outage with `exp > D`, which an infinite
  mailbox would deliver in full: 56 k–245 k envelopes per cell.

  | metric | meaning |
  |---|---|
  | `ret` | delivered from M at return |
  | `late` | delivered directly later; the mean delay is reported |
  | `vexp` | reported `expired` to the sender |
  | `silent` | M acked it and later evicted it, so it is lost and the sender never learns |
  | `fill` | the attacker's share of Q at return |

## Results

### 1. Main grid (load 0.3, office-hours senders; ranges over D ∈ {8, 24, 72} h × {uniform, Zipf})

| policy | no attack | insider | sybil | fanout |
|---|---|---|---|---|
| `tail` | 100 % ret | ret 37–42 %, vexp **8.0–11.1 %**, late 3.2–5.6 h | same as insider | same |
| `oldest` | 100 % | **silent 14–22 %** | silent 14–22 % | silent 14–22 % |
| `keyq` | ret 90–100 % (Zipf: vexp ≤ 1.7 %) | as no attack, fill 6.2 % | = `tail` | = `tail` |
| `keylqd` | 100 % | 100 % | **silent 51–77 %**, ret 7–22 % | silent 51–78 % |
| `g-tail` | 100 % | = `tail` (ret 37–42 %, vexp 8–11 %) | 100 % | = `tail` |
| `g-lqd` | 100 % | 100 % | 100 % | 100 % |
| `g-resv` | 100 % | **100 %**, fill 14.8 % | **100 %** | **100 %**, fill 14.8 % |
| `g-resv4` | 100 % | 100 %, fill 27.3 % | 100 % | 100 %, fill 27.3 % |

Notes on the grid:

- **Without a rule, one insider at 20 Mbit/s fills 64 MiB in about 27 s.** After that, 73–83 % of honest envelopes
  are refused. Office-hours senders lose 8–11 % of them as visibly `expired`. The rest reach R 3–6 h after it
  returns, when their sender is next online.
- **Always-on senders lose nothing to rejection** (sens, load 0.3, `g-tail` insider: ret 39–44 %, the rest `late` with zero
  delay). Rejection only defeats the mailbox when sender and receiver are rarely online together, and that is the
  case the mailbox exists for.
- **Keying by sender key fails to Sybils.** Fresh keys and owners cost nothing, so `keyq` behaves like `tail`. Under
  `keylqd` it is worse than no rule: every Sybil key holds one envelope, so the honest senders become the "longest
  queues". Then 51–77 % of honest envelopes are silently evicted.
- **The holder chain turns one capability into unlimited keys** (`fanout`). Under any per-key rule one valid token
  is a Sybil army. The gate must key by the *root* (authority-block revocation ID), as `max_calls` already does
  (max-calls-metering lab).
- **The gate alone is not enough.** `g-tail` stops strangers but not one capability holder, who still takes 88–98 %
  of Q.
- **Eviction converts denial into silent loss.** `oldest` looks better on `ret` (78–86 % vs 37–42 %), but its loss
  is invisible. The sender got an ack, so its outbox stopped retrying and `planner` is never told `expired`. This
  breaks the §4.5 promise ("callers are told when it becomes `delivered` or `expired`"). It also breaks the reasoning
  behind "effectively once", which assumes a stored envelope is either delivered or expires.

### 2. Honest overload (sens: load 1.0·Q/day, Zipf)

With no attacker, 72 h of honest demand exceeds Q. Each policy fails differently:

| D = 72 h, load 1.0, Zipf, office | ret | late | vexp | silent |
|---|---|---|---|---|
| `g-tail`, no attack | 92.2 % | 6.3 % | 1.5 % | 0 |
| `g-lqd`, no attack | 90.4 % | 0.9 % | 0.2 % | **8.5 %** |
| `g-lqd`, insider | 79.1 % | 1.7 % | 0.4 % | **18.8 %** |
| `g-resv`, no attack | 81.4 % | 15.8 % | 2.9 % | 0 |
| `g-resv`, insider | 71.2 % | 24.3 % | 4.5 % | 0 |
| `g-resv4`, insider | 60.4 % | 33.5 % | 6.1 % | 0 |

Longest-queue-drop evicts the heaviest *honest* principal: 8.5 % silent loss with no attacker, and 18.8 % with an
insider, who pushes everyone down to its own level. Reservation never loses silently. Under honest overload it
refuses more, but visibly.

The pool cap is a real knob:

- **Shorter outages (8–24 h, load 1.0).** `g-resv` refuses the Zipf top sender (rej 4.8–9.8 %, vexp 0.9–1.3 % for
  office senders). `g-resv4` refuses nobody without an attacker, but hands an insider 27 % of Q instead of 15 %.
- **Load 0.3.** Both caps give 100 % in every cell.

### 3. What the gate needs from the protocol (design consequences, not simulated)

- **Responses and events need a credential too.** §4.4 routes a response to the *requester's* mailbox host, and
  §4.5 replaces push with `TaskStatusUpdateEvent` envelopes to the requester's mailbox. B's node holds no
  capability rooted in A's owner. Options:
  - **(i)** The request carries a short reply token: a Biscuit rooted in A's owner, `mailbox:deposit to=<A agent>
    ctx=<taskId>`, holder = B, `exp` ≥ the task's horizon. The principal is that token's root.
  - **(ii)** M holds A's owner's pinned-contact list and keys by verified sender owner. This is cheaper, but it
    leaks the contact list to M (fine for an own relay, Q7 (a)) and offers nothing for first contact.

  Option (i) fits the existing capability machinery and also bounds a counterparty's event flood to one task.
- **Sealed envelopes (T15) must leave the gate inputs in the clear**: `from`, `to`, `exp`, `cap` (or a hash plus
  the root revocation ID), and `sig`. If the token moves inside the HPKE payload, M can only fall back to
  `tail`/`keyq`, which this lab shows fail to Sybils.
- **Gate cost under a Sybil flood** (an estimate from earlier labs, not measured here):
  - Per envelope: one Ed25519 verify for the envelope, plus about 0.13 ms per holder-chain hop (biscuit-holder-chain
    lab).
  - At 20 Mbit/s of 1 KiB junk (≈2 400/s) that is about 0.3–0.4 core.
  - Checking `to` ∈ M's served agents and the token's root key == B's owner key before any Datalog rejects most junk
    after one signature. The biscuit-authz-limits block-shape gate and size cap apply here too.
- **M does not evaluate stateful caveats.** It cannot meter `max_calls` (that is the resource owner's node). So
  the gate admits any unexpired token with a valid chain and an unrevoked root. Revocation lists must therefore
  reach M, or a revoked insider keeps its share until the token expires.

## Prior art

- **SMTP has the same split.** RFC 5321 §4.2.5/§6.1: once a server returns 250 it "accepts responsibility" and
  must deliver or send a non-delivery notification. Silently dropping an accepted message is forbidden. Mailbox
  full is a *transient* reply (452, RFC 3463 `4.2.2`) that makes the sender keep and retry. The `g-resv` behaviour
  is SMTP's. `oldest`/`lqd` are what SMTP forbids.
  <https://www.rfc-editor.org/rfc/rfc5321#section-6.1>, <https://www.rfc-editor.org/rfc/rfc3463>
- **Longest-queue-drop** (Suter et al., "Design considerations for supporting TCP with per-flow queueing",
  INFOCOM 1998) is max-min fair across flows. That only holds if flows cannot be split, which Douceur's Sybil
  argument says needs an identity cost ("The Sybil Attack", IPTPS 2002,
  <https://www.microsoft.com/en-us/research/publication/the-sybil-attack/>). Here the capability root supplies that
  cost; agent keys do not.
- **Matrix and ActivityPub inbox hosts** accept anything signed by any server and depend on server-level rate limits
  and blocklists. That is the `keyq` class and inherits its Sybil problem. Webway has something they lack: a
  receiver-rooted capability to gate on.

What does not apply: router AQM (RED, CoDel) manages delay of transient queues. Here the storage is held for
hours to days, and an accepted envelope is a promise, not a packet.

## What the planner should do next

1. **mailbox/v0 (T7): admission and quota are normative.**
   - The host MUST admit an envelope for R only if the envelope signature verifies, `to` is an agent it serves, and
     `cap` carries a chain rooted in R's owner with a valid holder chain and an unrevoked root (or a reply token,
     item 2).
   - It accounts storage **per root revocation ID**, never per sender key.
   - It uses a per-principal reservation plus a shared pool with a per-principal cap. The defaults are Q/(2N) and
     Q/2, and the cap is a spec constant between Q/8 and Q/4. This lab suggests Q/8 for M1.
2. **Add a reply/event deposit token to `capability/v0` (T3)**, or explicitly choose the pinned-contact alternative.
   Otherwise responses and push events to an offline requester have no admissible principal.
3. **Forbid eviction of acknowledged envelopes before `exp`.** If an operator must drop one (disk loss), the host
   MUST send the sender a signed `dropped` notice so the outbox re-queues it or reports `expired`. `MailboxFull` MUST
   be `retryable: true` with a `retryAfter` derived from the principal's earliest `exp`. The outbox then keeps the
   envelope, in SMTP 452 style.
4. **T15 (sealed envelopes)** must keep `from`, `to`, `exp`, the root revocation ID and `sig` outside the sealed
   payload.
5. **Conformance and M1 vectors.** Add the following to step 6, using a fake clock and a small Q:
   - a non-capability sender flood is rejected;
   - one capability holder (or its re-delegated keys) cannot take more than its reservation plus its pool cap;
   - an honest second principal's envelope is still stored;
   - no acked envelope is ever missing at reconnect.
6. **Open, not decided here.** Whether revocation lists propagate to the mailbox host (needed so a revoked insider
   loses its share). The quota size Q and N are operator settings, not protocol constants.
