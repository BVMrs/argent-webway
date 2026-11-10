# Lab 2026-11-10: how must a node meter a stateful `max_calls` caveat?

## Question

Due diligence §4.7.2 says: "Stateful caveats are counted at the verifier, per root token. A caveat such as
`max_calls=5` is enforced by the resource owner's node counting uses per *authority-block revocation ID*, summed
over all chains derived from it." M1 step 1 makes beta count `max_calls=5` per root revocation ID. Steps 4 and 6
also require that a retried, replayed or redelivered envelope is processed once and returns the original result.
They also require that a crash after persist but before ack does not create a second task.

The spec does not yet say *where* in the receive pipeline the counter is checked and incremented, or how that
interacts with dedupe, retries, crashes and stale envelopes. `capability/v0` is not written yet; this lab is input
for it. There are two sub-questions:

- **A.** Which ordering of envelope verification, dedupe, count check and counter update keeps three properties
  under at-least-once delivery? (1) never more than L tasks, (2) never budget lost to calls that did not run,
  (3) never a final `CapabilityDenied` for a call whose task exists.
- **B.** Is "one counter per authority-block revocation ID" right when a later holder adds its *own* `max_calls`
  in an attenuation block?

## Method

`lab/max-calls-metering/` is a dependency-free Rust crate. Its rules are in the header of `src/main.rs`. Run it
with `cargo run --release`: 197 s on 3 cores, about 1 GB of memory. Output is in `results.txt`.

**Part A (exhaustive BFS).** One holder has a remaining budget of **L = 2** and makes **3 distinct calls**. The
receiver runs **2 concurrent workers**. Each envelope runs the stages of the design under test:

| Axis | Options |
|---|---|
| Stage order | **O1** Env → Dedupe → Authz · **O2** Env → Authz → Dedupe · **O3** Authz → Env → Dedupe · **O4** Env → one serialisable txn {dedupe lookup; count check; insert task + counter++} |
| Counter update (O1–O3) | **Atx** in the commit txn with the dedupe entry/task · **Pre** durable, at authz · **Post** durable, after commit · **Mem** in RAM |
| Concurrency (O1–O3) | **Lock**: per-root lock from authz to counter update · **NoLock** |
| What is counted | **Adm** admitted tasks · **Cmp** completed tasks |

Commit is always a conditional insert on the dedupe key, so a racing duplicate gets the stored response. That
gives 31 designs. Fault budgets: none; one lost response; one server crash (drops RAM, inbox and in-flight work);
one early client retry (the first copy is still in flight); one mailbox replay inside the horizon; one stale
envelope (past `exp + skew`, rejected at Env); and all five together. Clients retry freely once nothing of a call
is in flight. Every quiescent state is judged:

- **over**: more than L tasks;
- **burn**: fewer than L tasks although 3 calls were made;
- **mismatch**: the client's first answer for a call was `CapabilityDenied` but the task exists.

The run explored **207 M states** in total.

**Part B (Monte Carlo).** The model draws 200 k random delegation trees with 2–7 blocks. The authority block has
`max_calls` 3–10, and each other block has a 50 % chance of its own `max_calls` 1–5. Each tree gets 40 random
calls, each through a random chain, for **8 M decisions per scheme**. Each counter-keying scheme decides each call
on its own accepted history. The decision is compared with the reference rule: *a caveat in block j bounds the
calls made through chains that contain block j*. The schemes are:

- **Root**: all caveats against one counter per authority-block revocation ID; the literal reading of §4.7.2.
- **Tail**: per presented token, i.e. last block.
- **RootTail**: root caveat on the root counter, all other caveats on the tail counter.
- **AuthorityOnly**: only the root caveat is enforced.
- **Depth**: per block depth.
- **Block**: one counter per block revocation ID, checked for every block in the chain. This is the reference,
  so its 0 is by construction.

## Results

### A. Pipeline ordering (L = 2, 3 calls, 2 workers)

| Fault budget | Designs failing (of 31) | over | burn | mismatch |
|---|---|---|---|---|
| none | 18 | 18 | 0 | 0 |
| 1 lost response | 26 | 18 | 8 | 20 |
| 1 crash | 29 | 24 | 6 | 20 |
| 1 early retry | 30 | 18 | 12 | 30 |
| 1 replay | 30 | 18 | 12 | 30 |
| 1 stale envelope | 20 | 18 | 4 | 0 |
| all five | 30 | 24 | 12 | 30 |

**Only O4 (dedupe lookup + count check + task insert + counter++ in one serialisable transaction) passes every
budget.** With all five faults it had 1.05 M states and 96 quiescent states, with 0 over, 0 burn and 0 mismatch.
The best non-transactional design is O1-Atx-Lock: dedupe first, per-root lock, counter in the commit txn. It
passes no faults, lost response, crash and stale. It fails only when two copies of the same call are in flight
together (early retry or replay), which M1's outbox + mailbox path makes routine.

What each wrong choice costs, with a minimal trace from `results.txt` for each:

1. **No lock / check-then-act (every NoLock design, every Cmp design): over, even with no faults.** Two workers
   both read 1 < 2 and both commit, giving 3 tasks against L = 2.
2. **Counting completions (Cmp): over, with no faults, even with a lock.** Admitted tasks that have not completed
   yet are invisible to the check. A completion-counted `max_calls` is a different and weaker caveat.
3. **Authz before dedupe (O2, O3): mismatch after one lost response.** In the O2-Atx-Lock trace, call 2 commits
   and its ack is lost. The retry reaches authz before dedupe, sees the counter at 2, and gets `CapabilityDenied`.
   Its task exists and runs. This is *exactly* M1 step 4 (the devnet drops beta's first ack) on the last call of
   the budget.
4. **Racing duplicates denied (O1 with any counter): mismatch after an early retry or a replay.** Two copies pass
   dedupe before either commits. One commits, a different call uses the last slot, and the second copy is denied
   at authz. The client may see the denial first. A denial needs the same atomic view as dedupe; a lock around
   authz alone is not enough.
5. **Counter updated outside the commit txn: burn or over after one crash.** With Pre, a crash between `IncPre`
   and `Commit` spends a slot with no task (1 task of 2). With Post, a crash between `Commit` and `IncPost` gives
   a task with no count (3 tasks). Mem resets on restart and over-admits.
6. **Authz before envelope verification (O3-Pre, O3-Mem): burn from one stale envelope.** An attacker who holds
   an old, expired envelope of the holder's (for example from a mailbox) can spend the holder's budget without a
   valid envelope.

### B. Counter keying across delegation (8 M decisions per scheme)

| Keying | over-admit | under-admit |
|---|---|---|
| Root (literal §4.7.2: every caveat on the authority-block counter) | 0 % | **8.41 %** |
| Tail (per presented token) | **32.05 %** | 0 % |
| RootTail | 1.12 % | 0 % |
| AuthorityOnly | 2.18 % | 0 % |
| Depth | 0 % | 3.32 % |
| Block (per block revocation ID, every block in the chain) | 0 % (reference) | 0 % (reference) |

The literal rule is right for the *authority* caveat: B and C together get 5, as §4.7.2 wants. But if C attenuates
to `max_calls=2` in its own block, a root-keyed counter charges B's calls against C's 2. So it denies 8.4 % of calls
that should pass. Keying per presented token lets copies multiply the budget (32 % over), which is the attack
§4.7.2 rules out. Only per-block keying is exact. Biscuit already gives one revocation ID per block
(`revocation_identifiers()`), so this is cheap: for each block j that carries `max_calls(n)`, key the counter by
`rev_id[j]`. In the same transaction, check `count < n` and increment every counter on the presented chain.

## Recommendation for `capability/v0`

- **CAP (pipeline):** a stateful caveat is checked and charged in **the same serialisable transaction** that does
  the dedupe lookup, writes the dedupe entry and creates the task (the transaction of ENV-503 / AUD-401). Envelope
  signature, freshness and `to` are verified before it. The stateless Datalog checks may run before it. A
  duplicate found in that transaction gets the stored response, never a fresh authz decision. SQLite
  `BEGIN IMMEDIATE` is enough for one node.
- **CAP (unit):** `max_calls` counts **admitted** requests (tasks created), not completions. Rejected and
  duplicate requests are not counted.
- **CAP (keying):** one counter per **block revocation ID** that carries a `max_calls` fact. A call is admitted
  only if every such block on the presented chain is under its limit, and it is charged to all of them. Replace
  "per authority-block revocation ID" in §4.7.2 and in M1 step 1 with this; the authority block is the special
  case.
- **Vectors to add to T3 / M1:**
  - the last call of the budget has its ack dropped and is retried, and must get the original `Accepted`, not
    `CapabilityDenied`;
  - two copies of one call arrive concurrently when one slot is left;
  - a crash between commit and ack;
  - a stale envelope when one slot is left, and the budget must be intact afterwards;
  - B (`max_calls=5`) delegates to C with `max_calls=2`: C's 3rd call is denied, B can still make 3 more, and
    C's 3rd call does not consume B's budget.

## What the planner should do next

1. Put the three CAP rules above into the `capability/v0` draft, change the wording of §4.7.2 and M1 step 1, and
   add the 5 vectors.
2. Open question for the spec author: does the counter persist after the token expires? It only needs to live
   until the token's own expiry plus `skew`, like dedupe entries. Is a denied call ever retried with a fresh
   envelope ID, making it a new call? The model assumes yes.
3. Not covered here: multi-node verifiers (one resource owner behind several nodes) would need a shared counter
   or partitioned budgets. This is out of scope for M1.

## Sources

- `docs/due-diligence.md` §4.4 (idempotency), §4.7.2 (stateful caveats), §4.7.3 (dedupe horizon), §6 M1 steps 1, 4, 6.
- `spec/ext/audit.md` AUD-401 (dedupe entry and task effects in one atomic transaction).
- Biscuit specification, revocation identifiers (one per block): https://github.com/eclipse-biscuit/biscuit/blob/main/SPECIFICATIONS.md
- IETF draft "The Idempotency-Key HTTP Header Field": https://datatracker.ietf.org/doc/draft-ietf-httpapi-idempotency-key-header/
- AWS Builders' Library, "Making retries safe with idempotent APIs": https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/
- Earlier labs: `2026-11-09-delivery-freshness-sim.md` (dedupe horizon), `2026-11-09-biscuit-holder-chain.md`
  (per-block scoping of the holder walk), `2026-11-10-stream-resume-model.md` (persist-then-publish).
