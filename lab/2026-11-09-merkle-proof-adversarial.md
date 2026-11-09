# Lab 2026-11-09: adversarial and differential tests of the audit/v0 Merkle proof verifiers

## Question

`spec/ext/audit.md` §5.2–§5.3 (AUD-110, AUD-120, AUD-121) is the only part of the project with running code:
`conformance/tools/audit-vectors/src/merkle.rs` builds and verifies RFC 9162 proofs with BLAKE3. Its own tests use
fixed mutations on trees up to n = 70, and they check the tool against itself. This lab asks whether that verifier
accepts anything false. Three things are checked:

1. Does an independent implementation agree with the verifier and with the committed vectors?
2. Which false statements does the RFC 9162 algorithm accept? §5.3 says only that "for some index and size pairs,
   a proof for size n also verifies for a different size". How often does that happen, and is it the only gap?
3. Are the §14 bounds right (inclusion ≤ 53 and consistency ≤ 54 hashes for safe-integer sizes), and does the
   u64 bit arithmetic hold up near 2^53 and beyond?

## Method

`lab/merkle-proof-adversarial/` is a Rust crate (the core language, no GPU). It includes master's `merkle.rs`
verbatim (`#[path]`) as `reference`. It also has `model.rs`, an independent model written from the recursive
definitions of RFC 9162 §2.1: MTH, PATH and SUBPROOF. Its verifiers walk the MTH split recursively and consume the
proof from the end. They need no tree and no bit tricks, so they work for any u64 size.

| Test | What it does |
|---|---|
| T1 | All 38 `inclusion.json`/`consistency.json` vectors judged by the model, with its own wire parsing: `blake3:` + 64 lowercase hex, safe integers, `MAX_PROOF_HASHES` = 128 |
| T2 | Model roots, PATH and PROOF compared byte for byte with `ct-merkle` for every n ≤ 300 |
| T3 | Exhaustive replay: every genuine inclusion proof (n ≤ 64) against every (index, size) with size ≤ 128, and every genuine consistency proof against every (size1, size2) with size2 ≤ 128, using the same leaf and roots. Reference and model must agree, and every acceptance is classified |
| T3b | Every interior node of every tree with n ≤ 128, offered as an "entry hash" with its honest sibling path at every index of the committed size. This matters because audit/v0 verifies from the entry *hash* (AUD-302), so the 0x00/0x01 prefixes alone do not stop it |
| T4 | 200 000 random shapes up to 2^53 − 1 (10 % up to 2^63 − 1): random path hashes, root implied by the model, the reference must accept, then 3.17 M mutations (index ±1, size ±1/+2, drop or add a hash, swap) where reference and model must agree |
| T4b | Exact maximum proof lengths for every n ≤ 4096, and the worst cases at n = 2^53 − 1 |
| T5 | 1 M random multi-step mutations of inclusion claims on trees with n ≤ 300 (bit flips, removed, inserted or swapped hashes, other leaves or roots, index or size ±2), each acceptance judged against the true tree |

Run from the repo root (about 130 s with `--release`; `QUICK=1` runs only T1, T4b and T5):

```sh
cargo run --release --offline --manifest-path lab/merkle-proof-adversarial/Cargo.toml
```

## Results

The run prints 0 failures. The reference verifier and the model agreed on every one of about 37 M verifications.

| Test | Result |
|---|---|
| T1 | 38/38 vectors give the expected result in the independent model |
| T2 | roots, PATH and PROOF identical to `ct-merkle` for all n ≤ 300 (90 300 proofs) |
| T3 inclusion | **0** acceptances at the committed size with another index. At another size: 41 664 acceptances with the same index and **11 858 with another index**. **2078 of 2080 (99.9 %)** genuine proofs verify for at least one other (index, size), e.g. PATH(1, D[2]) verifies as (2, 3), (4, 5), (8, 9), …, and PATH(3, D[4]) as (5, 6), (6, 7), (9, 10), … |
| T3 consistency | 202 146 acceptances for other size pairs. **All 2016** genuine proofs alias. 41 664 change only size2 and 160 482 change both sizes. **None** changes only size1 |
| T3b | 690 753 interior-node-as-entry attempts at the committed size: all rejected |
| T4 | reference == model on 200 000 genuine and 3 167 066 mutated proofs up to 2^63 − 1. No overflow or panic in the `fn`/`sn` shifts |
| T4b | max \|PATH\| = ⌈log2 n⌉ and max \|PROOF\| ≤ ⌈log2 n⌉ + 1 for every n ≤ 4096. At n = 2^53 − 1 they reach **53** and **54**, as §14 says. `MAX_PROOF_HASHES` = 128 leaves room |
| T5 | 1 M claims: 942 441 rejected, 24 632 accepted and true, 32 915 accepted with the true index and the root of another size, 12 accepted with another index and the root of another size, **0** other false acceptances |

### What this means

- **No bug in the verifier.** It accepts exactly what RFC 9162 §2.1.3.2 and §2.1.4.2 accept, with no extra false
  acceptances. AUD-121 (equal sizes) and the range checks hold. An interior node offered as an entry hash is never
  accepted at the true size, because each tree position has a unique direction path.
- **Aliasing is the norm, not "some pairs".** Almost every inclusion proof and every consistency proof also verifies
  for other sizes. For inclusion, a fifth of the aliases also change the **index**, which the §5.3 wording does not
  make clear. With the size fixed, nothing aliases. So everything rests on the rule that §5.3 already states:
  sizes, roots *and indices* come from signed or hash-bound data.
- **The spec follows that rule.** Every use I found takes the index and size from signed or hash-bound data:
  - evidence bundles use `entry.index` (hash-bound) and `checkpoint.size` (AUD-801);
  - receipts use `index` and `index + 1` (AUD-302, AUD-702);
  - `GetInclusion` lets the requester choose `index` and `size`, and the response does not echo them (§9.4).

  I found no exploitable path. The risk is in implementations. A node or harness that reads `index` or `size`
  from a proof response, or from an unsigned bundle field, would accept forged positions, and no current vector
  catches that.

Side note, not a bug: `audit-vectors --check` run from a directory other than the repo root reports every file as
"differs from generated output" instead of "missing", which at first looked like stale vectors. From the repo root
it passes (exit 0, no diff).

## Sources

- RFC 9162, Certificate Transparency 2.0, §2.1.1 (MTH), §2.1.3 (inclusion), §2.1.4 (consistency):
  https://www.rfc-editor.org/rfc/rfc9162#section-2.1
- RFC 6962 §2.1, which uses the same tree, and the CT reference roots used in `merkle.rs` tests:
  https://www.rfc-editor.org/rfc/rfc6962#section-2.1
- `ct-merkle` 0.3: https://docs.rs/ct-merkle/0.3
- `spec/ext/audit.md` §5.2–§5.3, §9.4, §11 (AUD-801), §14 on master (10d10ad)

## What the planner should do next

1. **Clarify the §5.3 text** (small spec edit): "a proof for (index i, size n) also verifies for other index and
   size pairs, for almost every i and n. A verifier MUST take the index, the size and the root from a commitment or
   a hash-bound entry, never from the party that supplies the proof." It could also say that equal-size aliasing
   is impossible, which T3 confirms exhaustively for n ≤ 64.
2. **Add vectors** to `audit/inclusion` and `audit/consistency`: accept cases that document aliasing, e.g. the
   size-2 index-1 proof verifying as (2, 3), so implementers do not add non-RFC "fixes" that break interop.
   Add an `audit/evidence` reject case where an entry's proof is valid only for an aliased index.
   (Current evidence vectors take the index from `entry.index`, so that case needs a bundle whose entry is at
   the wrong position.)
3. **Harness scenario for AUD-702**: a modified responder returns a `GetInclusion` proof that verifies at an
   aliased (index, size). `alpha` must log `receipt-invalid` and not mark the receipt checked.
4. Optionally move T3/T3b/T4 into `audit-vectors` as `#[test]`s. They take about 100 s in release mode, so cap
   them at n ≤ 32 for CI.
