# Can biscuit-auth 6 carry the capability/v0 holder chain? (T3 prototype)

Date: 2026-11-09 · Track: T3 (`capability/v0`), feeds Q4 · Code: [`biscuit-holder-chain/`](biscuit-holder-chain/) ·
Raw output: [`biscuit-holder-chain/results.md`](biscuit-holder-chain/results.md)

## Question

Due diligence §4.7.2 says the holder of a capability token is bound through a *holder chain*. The authority block
names `holder(<B>, 0)`. Each re-delegation appends a **third-party block signed by the current holder** asserting
`holder(<next>, n+1)`. Node code walks the chain and injects `current_holder` and `presenter`. `max_calls` is
counted per authority revocation ID. It also says: "T3 prototypes the holder chain in `biscuit-rust` first. If it
turns out awkward, mandates use UCAN-style chained delegation." This note does that prototype. Two questions:

1. Can biscuit-auth 6.0.0 express it, and does it pass the six vectors listed in §4.7.2?
2. What exactly must the "walk" do? How easily can an implementation get it wrong?

## Method

A Rust program (biscuit-auth 6.0.0, Ed25519, seeded RNG) builds the token shape from §4.7.2:

```
authority (owner root R):  right("skill:run-tests"); holder(hex:<B>, 0);
                           check if presenter($k), current_holder($k);
                           check if call_count($c), $c < 5;
B -> C:  third-party block signed by B:  holder(hex:<C>, 1);   (+ optional attenuating checks)
attenuation: ordinary ephemeral-key block, checks only
```

The verifying node first parses the token from bytes against R. Then it checks revocation IDs and walks the chain.
It injects `presenter(<envelope signer>)`, `current_holder(<walk result>)` and `call_count(<uses of revocation ID 0>)`,
and finally authorises with `allow if operation($op), right($op)`. The call count is incremented only on success.

Four walker implementations are compared:

| Walker | Algorithm | Public API only? |
|---|---|---|
| **Scoped** | `holder($k,0) trusting authority`, then for n = 0, 1, …: `holder($k, n+1) trusting ed25519/<holder n>` (exactly one result, or stop; more than one = fork) | yes |
| **Naive** | `query_all("holder($k,$n)")`, take the max depth | yes |
| **Strict** | per block: `print_block_source(i)` and reparse with `biscuit-parser`. The authority has exactly one `holder(_,0)`. A block with holder facts must be third-party, have exactly one, at depth = previous + 1, signed by the previous holder. No holder facts in first-party blocks. | needs reparse |
| **ScopedSeq** | Scoped, then require that the external signers of the third-party blocks, in block order, equal `[holder_0 … holder_{m-1}]` exactly (one third-party block per hop, nothing else) | yes |

There are 20 vectors: the six from §4.7.2 (V1–V6) and 14 adversarial or edge cases (A1–A14). The cost is measured
for 0–16 hops (release build, 200 iterations, one core).

## Results

### 1. Biscuit can express it. The §4.7.2 vectors pass, with any careful walker.

| # | Case | Expected | Scoped | Naive | Strict | ScopedSeq |
|---|---|---|---|---|---|---|
| V1 | valid chain B→C→D, D presents | accept | ✓ | ✓ | ✓ | ✓ |
| V2 | holder block for C signed by X instead of B | reject | ✓ | **accept** | ✓ | ✓ |
| V3 | ephemeral-key block asserts `holder(X,1)` | reject | ✓ | **accept** | ✓ | ✓ |
| V4 | D's token presented by C | reject | ✓ | ✓ | ✓ | ✓ |
| V5 | B keeps using its shorter token after delegating | accept | ✓ | ✓ | ✓ | ✓ |
| V6 | B 3 calls + C 2 calls, 6th call | reject | ✓ | ✓ | ✓ | ✓ |
| A1 | thief X presents D's token | reject | ✓ | ✓ | ✓ | ✓ |
| A2 | node skips the walk (no `current_holder` injected) | reject | ✓ | ✓ | ✓ | ✓ |
| A3 | attenuation block injects `presenter(X)`, `current_holder(X)` | reject | ✓ | ✓ | ✓ | ✓ |
| A4 | B's holder block cut from one token, pasted on another | reject | ✓ (library refuses) | ✓ | ✓ | ✓ |
| A5 | C signs `holder(X,1)` (wrong depth) | reject | ✓ | **flaky** | ✓ | ✓ |
| A6 | B's block names two depth-1 holders (fork) | reject | ✓ | **flaky** | ✓ | ✓ |
| A7 | **pre-plant**: B's block has `(C,1)` and `(X,3)`; C hands back to B at depth 2; X presents | reject | **accept** | **accept** | ✓ | ✓ |
| A8 | holder block adds `right("skill:deploy")` | reject | ✓ | ✓ | ✓ | ✓ |
| A9 | same, but the node's allow policy says `trusting authority, ed25519/<holder>` | reject | **accept** | **accept** | **accept** | **accept** |
| A10 | revoke block 1's revocation ID: the C and D chains die | reject | ✓ | ✓ | ✓ | ✓ |
| A11 | …and B's shorter token still works | accept | ✓ | ✓ | ✓ | ✓ |
| A12 | holder block adds `check if call_count($c), $c < 2` for C | reject 3rd | ✓ | ✓ | ✓ | ✓ |
| A13 | round trip B→C→B, B presents the long token | accept | ✓ | ✓ | ✓ | ✓ |
| A14 | sealed token, try to re-delegate | reject | ✓ (library refuses) | ✓ | ✓ | ✓ |

Wrong verdicts out of 20: **Scoped 2, Naive 4–6, Strict 1, ScopedSeq 1**. The one remaining wrong verdict for Strict
and ScopedSeq is A9, which is a policy-writing error, not a walker error (point 4 below). Over 30 runs, Naive
returned 4, 5 or 6 wrong verdicts. `query_all` returns facts in hash order, so ties at the max depth (A5, A6) are
broken differently from run to run.

What works out of the box:

- **Scoping does most of the work.** Facts in ephemeral blocks (V3) and in third-party blocks (A8) are invisible to
  authority checks and to default-scope authorizer policies. Injected or forged `presenter`/`current_holder` facts in
  token blocks (A3) cannot satisfy the authority's presenter check. A node that forgets the walk fails closed (A2).
- **Third-party signatures are bound to the previous block's signature**, so a holder block cannot be spliced onto
  another token (A4: `append_third_party` fails to verify).
- **Counting per authority revocation ID** (`revocation_identifiers()[0]`) gives the shared budget (V6). Attenuating
  checks in a holder block can lower it further (A12). Revoking block 1's ID cuts every chain derived from it and
  leaves the shorter token alone (A10, A11). These match §4.7.2 exactly.

### 2. Biscuit cannot do the walk in Datalog. It must be node code, as §4.7.2 assumes.

`trusting` takes only literal keys or build-time parameters (`Scope::{Authority, Previous, PublicKey, Parameter}`).
You cannot write `holder($k2, $n+1) trusting $k1`. So the walk is node code, and it is a place where independent
implementations can diverge.

### 3. The obvious walkers are wrong in different ways

- **Naive (`query_all`)** is the worst. `query_all` ignores scopes and sees every block, including ephemeral ones.
  Anyone can then name themselves holder (V2, V3), and ties make the result non-deterministic (A5, A6). The name
  makes it look like the right call.
- **Scoped** passes all six §4.7.2 vectors but fails **A7 (pre-planting)**. A holder can put facts for *future*
  depths in its own block (`holder(X,3)`). If the chain ever comes back to that holder (B→C→B), the depth-3 query
  trusting B finds the pre-planted fact. X becomes last holder although the newest block (C's) named B. Severity is
  moderate: B could have delegated to X legitimately after getting the token back. But the token's block order no
  longer matches the delegation history, so the "every hop is identified, in order" claim of §4.7.2 does not hold.
  Implementations will also disagree on the verdict, which is the conformance problem.
- **Strict** and **ScopedSeq** both reject everything except A9. Strict needs per-block facts. biscuit-auth 6 has no
  public accessor for them (`Biscuit::block()` is `pub(crate)`), so it uses `print_block_source` and a reparse with
  `biscuit-parser`. That works, but it depends on a round trip through the printed text. **ScopedSeq** uses only the
  public API: the scoped walk plus "the third-party block signers, in order, are exactly holder_0 … holder_{m-1}".
  The price is that **every** third-party block in a capability token must be a holder block.

### 4. Policy footgun (A9)

If the node's allow policy trusts holder keys (`allow if right($op) trusting authority, ed25519/<C>`), any holder
can mint rights (here `skill:deploy`) in its holder block. No walker can prevent that. The spec must say that
authorizer policies and rules MUST use the default scope (authority + authorizer). The only queries that trust
holder keys are the holder-walk queries.

### 5. Cost is small

| hops | token bytes | walk Scoped µs | walk Strict µs | walk ScopedSeq µs | full verify + authorize µs |
|---|---|---|---|---|---|
| 0 | 343 | 23 | 11 | 23 | 133 |
| 1 | 617 | 37 | 15 | 39 | 268 |
| 2 | 891 | 49 | 18 | 49 | 392 |
| 3 | 1165 | 64 | 22 | 64 | 520 |
| 4 | 1439 | 79 | 25 | 79 | 649 |
| 8 | 2535 | 134 | 40 | 134 | 1163 |
| 16 | 4727 | 256 | 70 | 256 | 2340 |

Each hop adds **274 bytes** (Ed25519 third-party signature + next key + block) and about **130–140 µs** of full
verification (mostly signature checks on parse). M1's S4 chain (2–3 hops) costs about 1 KB and about 0.5 ms per
request. Envelopes carry the token on every request, so with a 64 KiB inline limit this is not a concern. Timings
come from one machine and are only indicative.

## What applies and what doesn't (prior art)

- Biscuit specification, third-party blocks and scopes: <https://doc.biscuitsec.org/reference/specifications>.
  The scoping rules are what make V3, A3 and A8 safe. The spec has no "holder" concept, so the walk is ours.
- biscuit-auth 6.0.0 API (`third_party_request`, `append_third_party`, `block_external_key`, `query` vs
  `query_all`): <https://docs.rs/biscuit-auth/6.0.0>.
- UCAN 1.0 delegation (`iss`/`aud` chain, each delegation signed by the previous audience):
  <https://github.com/ucan-wg/spec>. In UCAN, rebinding is positional by construction (each link proves the previous
  `aud`), so pre-planting (A7) cannot happen. Our ScopedSeq rule makes the Biscuit chain behave like that.

## Recommendation, and what the planner should do next

1. **Keep Biscuit for Q4.** The holder chain is not awkward. It is about 40 lines of node code, and the library's
   scoping and signature binding do the hard parts. Nothing here argues for switching to UCAN.
2. **Pin the walk algorithm normatively in `spec/ext/capability.md` (T3).** Use the ScopedSeq or Strict semantics:
   - exactly one `holder(_, 0)` in the authority;
   - every third-party block is a holder block with exactly one `holder(k, n+1)`, signed by holder n, in block order;
   - holder facts in first-party blocks are rejected;
   - never use `query_all` (or an equivalent that ignores scopes) for holder facts;
   - authorizer policies MUST use the default scope.
3. **Add vectors V2, V3, A5, A6, A7 and A9 to the T3 conformance set** alongside the six in §4.7.2. A5–A7 are the
   cases where plausible implementations disagree. Language-neutral vectors need the token bytes. The program is
   seeded, so it can emit them (next step: a `--emit-vectors` mode writing `conformance/vectors/capability/`).
4. **Open question for T3:** banning non-holder third-party blocks also rules out third-party *attestations* in
   capability tokens, such as a revocation-service "not revoked" block. If those are wanted later, use Strict, or
   tag holder blocks (for example a `hop(n)` fact) so that ScopedSeq can skip the other third-party blocks.
5. **Nice-to-have upstream:** a public per-block facts accessor in biscuit-auth would remove the print/reparse step.
