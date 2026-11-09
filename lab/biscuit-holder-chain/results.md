# Holder-chain vectors

| case | expected | Scoped | Naive | Strict | ScopedSeq |
|---|---|---|---|---|---|
| V1 valid chain B->C->D (3 holders), presented by D | accept | accept | accept | accept | accept |
| V2 holder block for C signed by X (not B) | reject | reject (Datalog check failed) | accept **WRONG** | reject (block 1: holder block not signed by current holder) | reject (third-party signer order does not match holder chain (1 blocks, 0 hops) |
| V3 ephemeral-key block sets holder(X,1), presented by X | reject | reject (Datalog check failed) | accept **WRONG** | reject (block 1: holder fact in a first-party (ephemeral) block) | reject (Datalog check failed) |
| V4 D's token presented by C (not last holder) | reject | reject (Datalog check failed) | reject (Datalog check failed) | reject (Datalog check failed) | reject (Datalog check failed) |
| V5 B keeps using its shorter token after delegating | accept | accept | accept | accept | accept |
| V6 B 3 calls + C 2 calls ok, then C's 6th call rejected | reject | reject (Datalog check failed) | reject (Datalog check failed) | reject (Datalog check failed) | reject (Datalog check failed) |
| A1 thief X presents D's token | reject | reject (Datalog check failed) | reject (Datalog check failed) | reject (Datalog check failed) | reject (Datalog check failed) |
| A2 node forgets the walk (no current_holder): fail closed | reject | reject (Datalog check failed) | reject (Datalog check failed) | reject (Datalog check failed) | reject (Datalog check failed) |
| A3 attenuation block injects presenter(X), current_holder(X) | reject | reject (Datalog check failed) | reject (Datalog check failed) | reject (Datalog check failed) | reject (Datalog check failed) |
| A4 holder block of T1 cut-and-pasted onto another B token | reject | reject (append: error deserializing or verifying the token) | reject (append: error deserializing or verifying the token) | reject (append: error deserializing or verifying the token) | reject (append: error deserializing or verifying the token) |
| A5 C signs holder(X,1) (depth replay at wrong depth) | reject | reject (Datalog check failed) | accept **WRONG** | reject (block 2: depth 1 != 2) | reject (third-party signer order does not match holder chain (2 blocks, 1 hops) |
| A6 B's holder block names two holders (C,1),(X,1): fork | reject | reject (fork at depth 1) | reject (Datalog check failed) | reject (block 1: 2 holder facts) | reject (fork at depth 1) |
| A7 pre-plant: B signs (C,1)+(X,3); C->B at 2; X presents | reject | accept **WRONG** | accept **WRONG** | reject (block 1: 2 holder facts) | reject (chain longer than token) |
| A8 3p holder block adds right("skill:deploy"); D asks deploy | reject | reject (no matching policy) | reject (no matching policy) | reject (no matching policy) | reject (no matching policy) |
| A9 same, but node policy trusts holder keys (footgun) | reject | accept **WRONG** | accept **WRONG** | accept **WRONG** | accept **WRONG** |
| A10 revoke block-1 id: C and D chains die | reject | reject (revoked) | reject (revoked) | reject (revoked) | reject (revoked) |
| A11 revoke block-1 id: B's shorter token still works | accept | accept | accept | accept | accept |
| A12 holder block adds attenuating check (max 2 calls) on C | reject | reject (Datalog check failed) | reject (Datalog check failed) | reject (Datalog check failed) | reject (Datalog check failed) |
| A13 round trip B->C->B: B presents the long token | accept | accept | accept | accept | accept |
| A14 sealed token cannot be re-delegated | reject | reject (3p request: tried to append a block to a sealed token) | reject (3p request: tried to append a block to a sealed token) | reject (3p request: tried to append a block to a sealed token) | reject (3p request: tried to append a block to a sealed token) |

wrong verdicts per walker: Scoped=2, Naive=5, Strict=1, ScopedSeq=1  (of 20 cases; Naive varies 4-6 run to run: query_all tie order is hash-dependent)

# Cost vs hops (release build recommended)

| hops | token bytes | walk Scoped µs | walk Strict µs | walk ScopedSeq µs | full authorize (ScopedSeq) µs |
|---|---|---|---|---|---|
| 0 | 343 | 23 | 11 | 23 | 135 |
| 1 | 617 | 37 | 14 | 37 | 268 |
| 2 | 891 | 50 | 18 | 50 | 393 |
| 3 | 1165 | 65 | 21 | 64 | 525 |
| 4 | 1439 | 79 | 25 | 79 | 667 |
| 8 | 2535 | 147 | 39 | 137 | 1172 |
| 16 | 4727 | 250 | 67 | 256 | 2206 |
