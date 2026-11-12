# Lab 2026-11-11: can a requester cancel a task whose create envelope is still queued?

## Question

`mailbox/v0` (due diligence §4.5) makes "send to an offline peer" normal. `SendMessage` returns a local `Task` in
`submitted` with `delivery: queued`, and the create envelope C waits in alpha's outbox and at beta's mailbox host
until beta reconnects, possibly for hours. Users and planners change their minds, so the next question is how to
cancel that task. The profile says nothing about it, and A2A 1.0 rules out the obvious answer:

- §3.4.2: "Client-provided `taskId` values for creating new tasks is NOT supported". Task IDs are server-generated,
  and an unknown `taskId` gets `TaskNotFoundError`.
- §3.1.5 `CancelTask`: "The server will attempt to cancel the task, but success is not guaranteed". An unknown ID
  gets `TaskNotFoundError`, and a terminal task gets `TaskNotCancelableError`.
- §3.3.1: cancels are idempotent, and a duplicate cancel "MAY return TaskNotFoundError" after a purge.
- Due diligence §4.7.2 lists `task:<id>#cancel` as a capability. It is scoped to an ID the requester cannot know
  while the task is queued.

So a requester has nothing to cancel until beta has processed C and replied, and by then the agent has started.
Any by-reference alternative runs into reordering, because the cancel envelope X can overtake C. C and X travel
over two paths (direct outbox retries and the mailbox host), each A2A request runs on its own QUIC stream (§4.3),
and the receiver commits concurrently (group commit, durable-commit-path lab). **Which cancel semantics make "the
requester cancelled while the task was queued" reliably mean "the agent never runs it", under reordering,
duplicates, a receiver crash and a requester that goes offline, and what does each alternative cost?**

## Method

`lab/queued-cancel/` is a dependency-free Rust crate. `cargo run --release -- 20000` writes `results.txt` (about
2 min), and `./summarize.sh results.txt` writes `summary.txt`.

Designs:

| ID | Cancel addressing and unknown-target handling |
|---|---|
| **D0** | A2A as written: `CancelTask{taskId}`. R holds the intent until C's response gives it the taskId, then sends. |
| **D1** | Cancel names C by `(from, messageId)`. If beta has no such task: `TaskNotFound`, final, stored in dedupe. |
| **D2** | As D1, but `NotFound` is retryable and *not* stored in dedupe, so R's outbox keeps retrying while it is online. |
| **D3s** | As D1, but an unknown reference stores a **tombstone** until `X.exp + skew`, and X has its own short TTL (5 min). When C arrives while the tombstone is live, beta creates the task already `canceled` and stores that as C's response. |
| **D3r** | As D3s, with **`X.exp ≥ C.exp`**, so the tombstone outlives every acceptable copy of C. |

**Part A, exhaustive.** A DFS covers every interleaving of S coming up, the cancel intent, deliveries of C and X
copies (one direct and one mailbox copy each), agent start and finish, C expiry, X expiry, R receiving C's
response, R going offline for good, one S crash (task store and dedupe durable, tombstone durable or volatile), and
C's hand-off to the mailbox failing. It uses two orderings: **O1** (any copy in any order) and **O2** (mailbox FIFO
per sender, outbox head-of-line, so a direct X goes only after C is acked). It explores 8 fault combinations per
design × ordering × tombstone-durability, 112 configurations in all, with up to 9.4 k states each. It judges every
terminal state:

- **lost**: an X reached beta before the task finished, but the task completed.
- **run-after-cancel**: the agent started after an X reached beta.
- **unsent**: the intent never left R, and the task completed.
- **misled**: R was told canceled or cancel-pending, but the task completed.
- **uncertain**: R's last answer is `NotFound`.
- **spurious**: canceled without an intent.

**Part B, Monte Carlo timing.** Each cell runs 20 000 trials, with the cancel intent at `t_i ~ U(0, D)`, so the
task is always still queued.

- **Offline profiles for beta** (duration D, mailbox backlog of other senders): restart, U(5, 60) s, ≤10;
  flaky, 5 s + Exp(10 min), ≤50; overnight, U(8, 16) h, ≤500.
- **Outbox**: 1 s × 2ⁿ backoff, capped at 60 s, with equal jitter. Timers are per envelope or per destination
  (the outbox-retry-herd recommendation). The first failed attempt hands the envelope to the mailbox host, and that
  hand-off fails with p = 0 or 2 %.
- **Mailbox drain** after a 0.1–1 s reconnect: **pipelined** (5 ms apart, concurrent processing) or
  **stop-and-wait** (the next envelope goes after beta acks the previous one, 2 × 30 ms + processing).
- **Beta processing**: U(2, 20) ms of verify + commit per envelope. The agent starts U(10, 500) ms after the
  create commits and finishes after lognormal(median 120 s, σ = 1).
- **R offline variant**: R goes offline U(0, 10) min after the intent and stays away U(1, 12) h. Replies wait in
  R's mailbox.
- **TTLs**: C.exp = 24 h, skew = 5 min.

The grid is 6 designs × 2 timers × 3 profiles × 2 R-states × 2 drain modes × 2 hand-off failure rates =
288 cells.

## Results

### A. Which designs can ever go wrong

Faults are written as `(hand-off fails, R offline, S crash)`.

| Design | lost / run-after-cancel | misled | unsent | uncertain |
|---|---|---|---|---|
| D0 | 0 | 0 | **yes, with R offline**: R never learns the taskId, the deferred cancel is never sent, the task completes | 0 |
| D1 | O1: **yes, with no fault**. O2: yes as soon as C's hand-off fails (X is first in the mailbox FIFO) | 0 | 0 | yes (R gets `NotFound`, the task runs anyway) |
| D2 | O1: yes with no fault (R's retries are finite, or R goes offline). O2: yes when the hand-off fails | 0 | 0 | yes |
| D3s | O1: yes with no fault (tombstone expires before C arrives). O2: yes when the hand-off fails | **yes** (R was told "pending cancel") | 0 | 0 |
| **D3r, durable tombstone** | **0 in all 16 fault combinations, O1 and O2** | **0** | 0 | 0 |
| D3r, volatile tombstone | yes, with only a crash | yes | 0 | 0 |

No design ever produced a spurious cancel. The ordering discipline does not fix D1 or D2: even with FIFO mailboxes
and a head-of-line outbox, one failed (retryable) hand-off of C to the mailbox host is enough for the cancel to
arrive first. D3r's remaining "agent started" states are runs where X genuinely arrives after C. That is cancel
latency, and the cancel then wins as an ordinary `CancelTask`.

### B. How often, with realistic timing

These are the worst values over both timer modes and both hand-off failure rates (`summary.txt`). "completed" means
the agent ran the cancelled task to the end, so all its side effects happened.

| Design | beta profile | R stays online: completed | R goes offline: completed | Mechanism |
|---|---|---|---|---|
| D0 (A2A) | restart / flaky / overnight | 0 / 0 / 0 % | **2.9 / 40 / 55 %** | taskId only reaches R after beta is back. If R is away by then, the task runs to completion (76–110 s of agent work per trial). Even with R online, 12–13 % of agents have started before the cancel lands. |
| D1, X TTL 5 min | restart / flaky / overnight | 33 / 40 / **99 %** | 33 / 39 / 99 % | X overtakes C (lost) or X expires in the mailbox (15 % flaky, 98.7 % overnight) |
| D1, X.exp = C.exp | restart / flaky / overnight | **33 / 28 / 28 %** pipelined; 16 / 10 / 30 % stop-and-wait | 33 / 28 / 27 %; 15 / 8 / 14 % | `NotFound` is final, so the later copies are deduped to the same answer |
| D2 | restart / flaky / overnight | 1.1 / 1.4 / 1.6 % pipelined; ≤0.47 % stop-and-wait | 2.3 / **12 / 15 %** pipelined; ≤0.28 % stop-and-wait | the task completes before the next retry, or R is offline and stops retrying |
| D3s, X TTL 5 min | restart / flaky / overnight | 0.02 / **15 / 99 %** | 0.05 / 15 / 99 % | X expires in the mailbox before beta returns |
| **D3r** | restart / flaky / overnight | **≤0.02 / ≤0.02 / ≤0.42 %**, lost 0 | **≤0.04 / ≤0.07 / ≤0.20 %**, lost 0 | the residue is cancel latency: C overtook X by a direct retry while X waited behind the backlog of a stop-and-wait mailbox |

Further points:

- **Pipelined mailbox drains reorder a lot.** Two envelopes pushed 5 ms apart, each on its own stream, are committed
  in the wrong order 26–33 % of the time with a 2–20 ms commit jitter. That alone gives D1 its ~33 % loss. A
  stop-and-wait drain halves it, but the outbox's own direct retries of C and X still race while the mailbox works
  through other senders' backlog: D1 loses 30 % in the overnight, R-online, stop-and-wait cell. In-order delivery
  cannot be the fix. Making the receiver tolerate an early cancel is.
- **A short cancel TTL is a separate trap.** A control message with a "fresh" 5 min `exp`, queued for an offline
  peer, expires in the mailbox before beta returns: 15 % (flaky) and 98.7 % (overnight). It does not matter how
  beta handles it. The cancel's `exp` must be at least the `exp` of what it cancels.
- **D2 works only while R stays online** and spends a retry stream per attempt. It also asks beta not to dedupe one
  error class, which contradicts the §4.4 "a duplicate gets the stored response" rule.
- **D3r's cost is small.** It costs one durable tombstone per early cancel, living at most `C.exp + skew`
  (≤ 7 d + skew under the §4.7.3 cap). It is written in the same transaction as X's dedupe entry, and the create
  path makes one extra index lookup. In the stop-and-wait cells 14–34 % of agents were dispatched before the
  cancel arrived, but were canceled 0–3 s later (mean work ≤ 2.9 s per trial).

## What applies, what doesn't (prior art)

- The tombstone is Time Warp's **anti-message** (Jefferson, "Virtual Time", ACM TOPLAS 7(3), 1985): a cancel that
  arrives before its positive message waits and annihilates it on arrival. The same rule here is "create it
  `canceled`".
- Workflow engines that let a cancel precede a start use **client-chosen IDs**, as in Temporal, where workflow IDs
  are supplied by the caller. A2A 1.0 forbids client task IDs (§3.4.2), so a reference to the client's `messageId`
  (or a server ID *derived* from it) is the closest fit.
- Withdrawing the envelope at the mailbox host is only an optimisation. The host is trusted for availability only
  (§4.5), may already have delivered, and the outbox also holds a copy.

## Recommendation (for T2/T7 spec text and M1)

1. **Define cancel-by-reference for queued tasks.** A cancel names the create by `(from, messageId)`. One encoding is
   a profile field in `ctx` with `CancelTask.id` empty. The other is for the profile to derive the server taskId
   deterministically from `(to, from, messageId)` (e.g. BLAKE3, formatted as a UUID), so that the plain A2A
   `CancelTask{id}` works before delivery. Both are equivalent in the model. The second needs no new field and
   keeps `GetTask` usable too. T1/T7 decide the encoding.
2. **An early cancel creates a durable tombstone** in the same transaction as its dedupe entry. A create that
   matches a live tombstone is stored as a task in `canceled`, and that is its stored response for every duplicate.
   The agent is never dispatched. A volatile tombstone is wrong: it loses the cancel after one crash.
3. **`X.exp ≥ referenced C.exp`** (MUST for the sender), and the tombstone lives until `C.exp + skew`. A receiver
   can enforce this by rejecting a reference cancel whose `exp` is earlier than the latest `exp` it would accept
   for that create, i.e. `X.ts + cap`. More simply, the tombstone's lifetime is set to `X.ts + max(exp − ts) + skew`,
   independent of X's own TTL.
4. **Authorisation**: only the original `from` may cancel by reference. The key includes `from` and X is signed by
   it, so a third party cannot pre-cancel someone else's message. `task:<id>#cancel` cannot be issued for a task
   that does not exist yet, so §4.7.2 should say that the creator may always cancel its own task. Tombstones count
   against the sender's root revocation-ID storage budget (mailbox-quota-flood lab), so they cannot be used to fill
   beta's store.
5. **Do not answer an early cancel with `TaskNotFound`**, retryable or final. Answer with a cancel-pending
   acknowledgement, and on alpha make the local task `canceled` only once beta's stored response for C says so.
6. **M1/conformance**: add to step 6 "cancel the queued second task while beta is down; beta's restart must not
   dispatch it". Add vectors for: cancel before create → create stored `canceled`; duplicate create after that →
   same stored response; cancel after completion → `TaskNotCancelable`; tombstone survives a crash; cancel with
   `exp` < create's `exp` → rejected (or tombstone clamped up); cancel from another `from` → no effect.

## Limits

- One task and one cancel per trial, with no multi-turn follow-ups. Reordering of `input-required` replies is the
  same problem and is not modelled here.
- The agent-start delay U(10, 500) ms and the 2–20 ms commit jitter drive D0's 12–13 % "started" and D1's 26–33 %
  with pipelined drains. The ordering of the designs does not depend on them, but the exact percentages do.
- Part A's D2 runs cap retries at 2 because the scheduler is adversarial. In practice D2 fails only when R goes
  away or the task finishes first, as Part B shows.

## Sources

- A2A specification 1.0, §3.1.1, §3.1.5, §3.3.1, §3.3.3, §3.4.2: https://a2a-protocol.org/latest/specification/
- D. R. Jefferson, "Virtual Time", ACM TOPLAS 7(3), 1985 (anti-messages).
- Earlier labs: outbox-retry-herd (timer design), durable-commit-path (group-commit jitter), mailbox-quota-flood
  (per-root budget), cap-expiry-dwell (token TTL vs dwell; a cancel token needs the same treatment).

## What the planner should do next

- Put recommendation items 1–5 into the T2 (`envelope/v0`: `exp` rule for control messages) and T7 (`mailbox/v0`:
  cancel of queued tasks) drafts. Open a small T1 decision on the encoding (ctx reference vs derived taskId).
- Add the step 6 cancel assertion and the six vectors to the M1 conformance list.
- A follow-up lab can apply the same model to **multi-turn follow-ups** (two `input-required` replies, or a reply
  overtaking the create), where the fix is likely a per-(from, contextId) requester sequence rather than a tombstone.
