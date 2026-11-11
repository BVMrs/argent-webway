# How much can one capability block cost the verifier? biscuit-auth 6 run limits vs adversarial Datalog

Date: 2026-11-11. Track: T3 / T6 (capability/v0, policy engine), T19 (fuzzing/DoS). Code: [`biscuit-authz-limits/`](biscuit-authz-limits/).

## Question

M1 step 4 has `beta` verify a Biscuit capability on **every** envelope. Biscuit is append-only, and anyone
holding a token can add an ordinary attenuation block with arbitrary Datalog, without any key. That includes the
legitimate cross-owner holder (`planner`) and anyone who copied the token. biscuit-auth 6.0.0 protects the
authorizer with `AuthorizerLimits` (default: 1 000 facts, 100 iterations, **1 ms**). Two questions:

1. Do those limits bound the CPU and memory that one attacker-appended block can make `beta` spend?
2. Does the wall-clock limit make the verdict for an *honest* token depend on machine load? That would make
   verdicts non-reproducible, and conformance vectors could not pin them.

If the limits fail, what must capability/v0 pin instead?

## Method

- The code reads biscuit-auth 6.0.0 `datalog/mod.rs::run_with_limits` and `token/authorizer.rs::authorize*`.
- A Rust bench (`src/main.rs`) builds the M1-like honest token: an authority block with `right`, `holder(B,0)`,
  presenter/holder, `call_count` and time checks, then a B→C third-party holder hop, then an attenuation block
  with a time and a task check. It is 920 bytes. Optionally one attacker block is appended with `Biscuit::append`.
  Each token is serialised and then parsed with `Biscuit::from(root)`, which verifies every signature. The
  authorizer injects `presenter`, `current_holder`, `call_count`, `operation`, `task` and `time`, then runs
  `authorize()`.
- Each case runs in a fresh child process with `ulimit -v 3 GiB` and a 120 s cap. It reports token bytes, parse
  time, authorize time, verdict and ΔmaxRSS. Each case runs under two limit sets: `default` (as shipped) and
  `unbounded` (10⁹ facts, 600 s), which shows the true cost.
- Attack blocks, each a single ordinary block:
  - `rule_join n k` is `f(0..n); g($x0) <- f($x0),…,f($xk-1), $x0 < 0;`. It makes nᵏ bindings, produces no
    facts, and reaches fixpoint after one iteration.
  - `check_join n k` is the same join in a `reject if` query, so the token is still **accepted**.
  - `fact_join n k` is `g($x0..$xk-1) <- f($x0),…`. It produces nᵏ facts in one iteration.
  - `closure n d` nests `[0..n].any($c -> …)` d deep inside one `reject if`. That is nᵈ evaluations in one
    expression.
  - `regex n k` is the join plus `"x".matches("[a-z]{1000}{1000}")`. `regexmed` uses a pattern that compiles in
    0.15 ms.
  - `blocks n` appends n blocks of `check if true`.
- A **static gate**, run after parsing and before any Datalog (`gate()` in the code):
  - token ≤ 8 KiB and ≤ 16 blocks;
  - non-authority blocks have **no rules**, and no facts except one `holder` fact in a third-party block;
  - at most 8 checks per block, at most 2 body predicates per query, predicates from an allowlist (`time`,
    `operation`, `resource`, `task`, `arg`, `call_count`, `presenter`, `current_holder`, `right`);
  - expressions use only comparison, equality, `contains`/`prefix`/`suffix`, boolean operators and `-`. Lazy
    `&&`/`||` (encoded as zero-parameter closures) are allowed. Parameterised closures (`.any`/`.all`), regex,
    FFI, and sets of more than 64 elements are rejected.

  `gatemax` is the costliest token we could build that the gate still admits.
- Load test (`load T 8 s`): T threads loop parse + authorize on the honest token, on a **3-vCPU VM**. The test
  counts `Timeout` verdicts under `default` limits and under a 100 ms `backstop` that keeps the same counts.

## Results

### 1. The limits are checked only between fixpoint iterations

In `run_with_limits`, one iteration applies every rule to every binding (`CombineIt`). The facts, iteration and
time limits are tested only **after** the iteration completes. `authorize_inner` tests the time only after each
whole check query. Nothing interrupts a single join, a single expression, or a single closure. `Regex::new` runs
**for every binding** (`expression.rs:372`), with no cache.

Biscuit Datalog cannot create new terms: rule heads take only variables and constants. So the "exponential
string" attack is impossible. The parser rejects `s($s + $s) <- s($s)`, and the number of facts is bounded by
(number of terms)^arity. The danger is therefore the size of a single join or expression, not runaway recursion.

### 2. One small block, measured cost (default limits; the unbounded run is within ±15 %)

| case | token bytes | authorize time | verdict (default) | ΔRSS |
|---|---|---|---|---|
| honest (no attack) | 920 | 0.08 ms | Allow | 0 |
| rule_join 10⁴ | 1 239 | 8.1 ms | Timeout | 0 |
| check_join 30⁴ | 1 454 | 740 ms | Timeout | 0 |
| rule_join 40⁴ | 1 569 | 2.4 s | Timeout | 0 |
| rule_join 300³ | 4 587 | 15.4 s | Timeout | 0 |
| rule_join 16⁶ | 1 333 | 18.2 s | Timeout | 0 |
| **rule_join 20⁶** | **1 377** | **70.5 s** | Timeout | 0 |
| check_join 20⁶ | 1 372 | 72.9 s | Timeout | 0 |
| fact_join 20⁴ | 1 343 | 324 ms | TooManyFacts | 42 MiB |
| **fact_join 30⁴** | 1 453 | 1.7 s | TooManyFacts (fact count 810 039) | **193 MiB** |
| fact_join 30⁴, unbounded | 1 453 | 99 s | Allow | 354 MiB |
| closure 100³ | 2 376 | 330 ms | Timeout | 0 |
| closure 30⁵ | 1 843 | 11.3 s | Timeout | 0 |
| regex, 1 binding | 1 115 | 12.8 ms | Timeout | 14 MiB |
| regex 10³ bindings | 1 243 | 9.6 s | Timeout | 21 MiB |
| regexmed 20² | 1 349 | 43 ms | Timeout | 1 MiB |
| blocks 400 (parse only) | 52 120 | parse 22–26 ms, authorize 1.3–1.9 ms | Allow | 0 |

A legitimate holder, or anyone holding a copy of the token, can hold one core for **over 70 s** with a 1.4 KB
block that passes every signature check. That is about 50 000× the honest cost. The 1 ms limit turns the
verdict into `Timeout` only **after** the work is done, so it caps nothing. `max_facts = 1000` lets 810 k facts
(193 MiB) be materialised before it trips. The regex crate spends 9.6 ms on each compile before it reports
"exceeds size limit", and biscuit-auth repeats that compile for every binding.

There is also an unbounded cost before any Datalog: `Biscuit::from` verifies one signature per block. 400 cheap
blocks (52 KB, which fits in the 64 KiB inline/envelope budget of the
[inline-threshold](2026-11-10-inline-threshold.md) lab) cost 22–26 ms of parse time, and no `AuthorizerLimits`
covers it. A thief can mount this too, because appending blocks needs no key. The holder walk rejects the thief
only after parsing.

### 3. The gate

Every attack block above is rejected by the gate in **40–550 µs** (lab code reprints and reparses the block
source; walking the decoded protobuf would be cheaper). The honest token passes. Reasons reported: rule in an
attenuation block, fact `f`, `closure`, block count or byte cap.

The costliest admitted tokens are `gatemax`:
- 1 extra block with 8 checks over two 64-int sets: 5.9 KB, 0.23 ms;
- 5 blocks × 8 checks: 7.7 KB, 0.83–0.85 ms authorize plus 1.3 ms parse.

With the predicate allowlist, the world holds only owner and authorizer facts (9 here). So each admitted query
has at most 9² bindings, and the cost is bounded by the byte cap.

### 4. Honest tokens under load: the 1 ms limit is not deterministic

| threads on 3 vCPU | rate | Timeout with `default` (1 ms) | Timeout with 100 ms `backstop` | p99 latency |
|---|---|---|---|---|
| 1 | 3.4 k/s | 0 / 27 289 | 0 | 0.41 ms |
| 3 | 8.2 k/s | 10 / 65 484 (0.015 %) | 0 | 0.46 ms |
| 6 | 8.2 k/s | 157 / 65 721 (0.24 %) | 0 | 3.4 ms |
| 12 | 8.3 k/s | 260 / 66 722 (0.39 %) | 0 | 41 ms |
| 24 | 8.2 k/s | 151 / 65 744 (0.23 %) | 0 | 82 ms |
| 48 | 8.3 k/s | 286 / 66 536 (0.43 %) | 0 | 74 ms |

The Datalog part of an honest check takes about 80 µs, but a thread preempted mid-run exceeds 1 ms. With the
default limit, **0.015–0.43 % of honest, valid requests are denied**, depending only on load. In M1 a Timeout
would surface as a capability rejection of a valid call, and its interaction with the dedupe/metering
transaction of the [max-calls-metering](2026-11-10-max-calls-metering.md) lab was not tested here. The 100 ms backstop never fired
on an honest token. The `gatemax` token (0.85 ms end to end, unloaded) leaves almost no headroom under the
default, so a richer but legitimate token would hit the same load-dependent timeouts more often (not measured
under load).

## What applies from prior art

- The Biscuit specification (<https://doc.biscuitsec.org/reference/specifications>) says only that
  implementations should limit execution (facts, iterations, time). It defines no cost model and no
  deterministic budget. So two implementations (Rust node, a future TS verifier) can disagree on any
  `Timeout` verdict. Our measurements show biscuit-auth's limits are coarse-grained in practice.
- Datalog has polynomial *data* complexity only for a **fixed** program. If the attacker writes the program, a
  k-way join costs nᵏ (Dantsin, Eiter, Gottlob, Voronkov, "Complexity and expressive power of logic
  programming", ACM Computing Surveys 33(3), 2001). Restricting attenuation blocks to checks with ≤ 2 body
  predicates over a closed predicate allowlist is the usual way to restore a bound.
- Cedar (Cutler et al., "Cedar: A New Language for Expressive, Fast, Safe, and Analyzable Authorization",
  OOPSLA 2024, <https://arxiv.org/abs/2403.04651>) deliberately has no loops, no recursion and no user regex,
  so evaluation is bounded by policy size. That is the property our gate imposes on the Biscuit blocks we accept.
  Macaroons and UCAN have only caveat matching or `aud`/`att` checks, so they have no equivalent issue. This is
  one point in UCAN's favour for Q4's fallback.
- regex crate: `RegexBuilder::size_limit` defaults to 10 MiB
  (<https://docs.rs/regex/latest/regex/struct.RegexBuilder.html#method.size_limit>). Exceeding it is an error,
  but only after compilation work. biscuit-auth calls `Regex::new` uncached on every evaluation.

## Recommendation (for capability/v0 and T6)

1. **Pin a block-shape profile in capability/v0, enforced before Datalog** (a MUST with vectors). Non-authority
   blocks:
   - have no rules;
   - contain only the single `holder` fact, and only in third-party blocks;
   - have ≤ 8 checks, ≤ 2 body predicates per query, and predicates from a fixed allowlist;
   - use an operator allowlist: no `.matches`, no parameterised closures (`.any`/`.all`), no FFI, sets ≤ 64.

   Authority blocks are written by the resource owner, so they may be richer, but the node should lint them at
   minting time. Violations are a capability rejection with a distinct error code, so they are deterministic and
   testable.
2. **Cap the token before signature verification**: ≤ 8 KiB serialised and ≤ 16 blocks, read from the protobuf
   framing before `Biscuit::from`. The 400-block case shows that parse cost is otherwise unbounded and payable by
   a thief.
3. **Do not use the 1 ms default.** Set `max_time` to a generous backstop (100 ms measured; 0 honest timeouts at
   any load), and treat a `Timeout` as a node fault to log and alert on, not a normal verdict. Determinism comes
   from rules 1–2 plus `max_facts`/`max_iterations`, which are load-independent. Conformance vectors must never
   expect `Timeout`.
4. **Run authorization on a bounded worker pool** and order it after the cheap checks: envelope signature,
   freshness, dedupe and holder walk. Then a misbehaving holder costs at most one gated evaluation (< 1 ms)
   per envelope, and the per-peer rate limits of §4.7.2 apply.
5. Add capability/v0 vectors: one rejected token per attack class above, the `gatemax` token accepted, and
   a 17-block token and an 8 KiB + 1 token rejected before parsing.
6. Optional upstream issue for biscuit-auth: check the limits inside `CombineIt` (per-binding counter), and
   cache compiled regexes per evaluation.

## Caveats

- Timings come from one 3-vCPU VM. The ratios and verdicts are robust; the absolute ms are not.
- The gate reprints and reparses the block source via `biscuit-parser` (lab shortcut). A production gate walks
  the decoded protobuf. Its cost (40 µs–1.2 ms here) is an upper bound.
- The predicate allowlist is a sketch. T3 decides the real one; arguments (`arg`) may need richer operators
  such as `prefix` on paths, which the gate already allows.
- The first full matrix run hit the 600 s tool limit after the closure cases. The remaining cases were re-run
  separately (`results-cases-part1.tsv` and `results-cases-part2.tsv`; `none` and the first closure rows appear
  in both and agree).

## Reproduce

```
cd lab/biscuit-authz-limits && cargo build --release
target/release/biscuit-authz-limits                       # full matrix (~15 min); CASES=closure,regex,... to filter
target/release/biscuit-authz-limits load 12 8 default     # honest load test
target/release/biscuit-authz-limits regex                 # regex compile costs
```

## Next for the planner

- T3: write the block-shape profile (rules 1–3) into capability/v0 with requirement IDs, and turn this lab's
  attack tokens into rejection vectors.
- T6: make the authorizer wrapper implement the pre-parse cap, the gate and the 100 ms backstop. Fuzz the gate
  (T19) against a differential "run it with unbounded limits and a fuel counter" oracle.
- Q4 context (no decision): the gate gives Biscuit Cedar-like bounded evaluation. Without the gate, Biscuit
  attenuation is a remotely triggerable CPU sink, a cost UCAN does not have.
