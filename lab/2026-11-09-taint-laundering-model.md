# Lab 2026-11-09: can a foreign node launder provenance taint through the receiver's own nodes?

## Question

`provenance/v0` (`docs/due-diligence.md` §4.7.4) computes trust at the receiver as
`trust = min(level(verified sender owner), min over o in taint.owners of level(o), unverified ? unverified-origin : top)`.
The first term clamps a lying foreign sender to `foreign`. The rule for storing content says: "Receivers MUST keep
the computed trust and the full taint attached when storing content, and MUST emit that taint when forwarding or
deriving. This is the same data the next receiver recomputes from." Trust is never sent on the wire.

The clamp comes from the sender's identity, and that identity is **not** written into the stored taint. So read
literally, a foreign node B can send content to A1 with `taint.owners = []` or `[A]`. A1 computes `foreign`, which
is correct, but stores and later emits taint `[A]`. A2 (also owner A) then gets it from a same-owner sender with
same-owner taint and computes `same-owner`. The one-hop vector in §6 step 7 cannot see this. The question:
**does the rule as written let foreign content gain trust after crossing the receiver's own nodes, and which
minimal rule closes it without over-tainting honest traffic?**

## Method

`lab/taint-laundering-model/` is a dependency-free Rust crate that does an exhaustive bounded model check (the
rules are in the header of `src/main.rs`). The world has owners A, B and C, and nodes A1, A2, A3, B1, B2 and C1.
Content starts at a node, from its agent or from its HTTP edge (`unverified`). An honest node forwards it, or
derives a new Part from two inputs (union of taint, min of trust). A *liar* node emits any wire taint. Each liar
keeps one lie for the whole scenario.

- **Family 1, chains**: every path of 2–5 nodes (4,680 paths) × 2 origins × every liar assignment with at most 2
  liars, each with all 16 possible `{owners ⊆ {A,B,C}, unverified}` lies. That gives 9.9 M scenarios and
  12.2 M judged receipts per policy.
- **Family 2, derivation**: two inputs of 1–3 nodes each reach an honest node X, X derives one Part from them,
  and the Part is forwarded along 2–3 nodes. Liars are limited to the four lies that drop owners (`{}`, `{A}`,
  `{B}`, `{C}`, `unverified=false`). That gives 125 M scenarios and 109 M judged receipts per policy.

Ground truth for each copy: the owners of every node that produced, held or merged it, and whether any input
came from an HTTP edge. At each **honest** receiver of owner r, the model counts:

- **RAISE**: computed trust is above the truth. If a foreign liar touched the content, the best possible answer
  is `foreign`, so any `same-owner` result counts as a RAISE.
- **over-taint**: computed trust is below the truth, with no liar involved.
- **inconsistent**: stored trust ≠ f(stored taint). This breaks "the same data the next receiver recomputes
  from".
- **inherent**: truly unverified content that a foreign liar relabelled as `foreign`. No rule can catch this,
  and it does no harm: a liar's relayed content cannot be told apart from content the liar wrote itself, and
  that content is `foreign`.
- **out of scope**: a liar *of the receiver's own owner* is in the history. The doc accepts this case and
  mitigates it by audit.

Receiver policies:

| Policy | Receiver rule |
|---|---|
| P0 | As written: store the wire taint; `trust = min(level(sender owner), f(wire taint))` |
| P1 | **Normalise**: store `owners = wire owners ∪ {verified sender owner}`; `trust = f(stored taint)` |
| P2 | Reject (`EnvelopeInvalid`) if the wire owners lack the verified sender's owner; otherwise as P0 |

Each policy runs with two honest-sender behaviours. E1: emit the stored taint ∪ own owner (the doc says owners
include "the sender's own owner"). E0: forward the stored taint unchanged, an easy implementation slip.

```sh
cargo run --release --offline --manifest-path lab/taint-laundering-model/Cargo.toml   # 3 min; MAXLEN=4 for a quick run
```

The full output is in `lab/taint-laundering-model/results.md`.

## Results

Family 1, chains (9,946,320 scenarios, 12,227,800 judged receipts per policy):

| Policy | RAISE | over-taint | inconsistent | inherent | honest envelopes rejected |
|---|---|---|---|---|---|
| P0/E1 (as written) | **99,904** | 0 | 1,025,136 | 2,700,608 | 0 |
| P0/E0 | **110,088** | 0 | 1,282,944 | 2,695,928 | 0 |
| P1/E1 normalise | 0 | 0 | 0 | 2,750,560 | 0 |
| P1/E0 normalise | 0 | 0 | 0 | 2,750,560 | 0 |
| P2/E1 reject | 0 | 0 | 0 | 978,480 | 0 |
| P2/E0 reject | 0 | 0 | 0 | 784,700 | **2,217,540** |

Family 2, derivation (125,237,520 scenarios, 109,105,160 judged receipts per policy for P0 and P1):

| Policy | RAISE | over-taint | inconsistent | honest envelopes rejected |
|---|---|---|---|---|
| P0/E1 (as written) | **2,296,192** | 0 | 9,939,824 | 0 |
| P0/E0 | **4,959,746** | 0 | 19,545,270 | 0 |
| P1 (E0 or E1) | 0 | 0 | 0 | 0 |
| P2/E1 | 0 | 0 | 0 | 0 |
| P2/E0 | 0 | 0 | 0 | **9,502,840** |

Shortest counterexamples under the rule as written:

- Chain: `B1*[] → A1 → A2`. B1 sends `taint.owners = []`. A1 computes `foreign` and stores `[]`. A1 forwards
  `[A]`, so A2 computes **same-owner**. The same happens with `owners = [A]`, the exact lie in §6 step 7, and
  with any number of further A hops.
- Derivation: `(A1's own Part + B1*[] → A1) derive@A1 → A3`. A1's agent merges its own Part with the laundered
  input. The union of taints is `[A]`, so A3 computes **same-owner** for a Part built from foreign text. This is
  the CaMeL-style case §4.7.4 is meant to stop: an agent reads foreign text and its output goes to a sibling node.

Directed vectors (trust at the last node):

| Vector | As written (P0) | Normalise (P1) | Correct |
|---|---|---|---|
| B1 claims `owners=[A]` to A1 (§6 step 7, one hop) | foreign | foreign | foreign |
| B1 claims `owners=[A]` to A1, A1 → A2 | **same-owner** | foreign | foreign |
| B1 sends `owners=[]` to A1, A1 → A2 | **same-owner** | foreign | foreign |
| B1 claims `owners=[A]`, A1 → A2 → A3 | **same-owner** | foreign | foreign |
| A1 edge content → honest B1 → A2 | unverified-origin | unverified-origin | unverified-origin |
| A1 edge content → B1 drops `unverified` → A2 | foreign | foreign | foreign (inherent) |
| honest B1 → A1 → A2 | foreign | foreign | foreign |
| honest A1 → A2 → A3 | same-owner | same-owner | same-owner |

What the numbers say:

1. **The rule as written is unsound across two hops.** It holds for a single receipt, which is all the §6
   vectors test. Every RAISE comes from a foreign liar plus one or more hops through the receiver's own honest
   nodes. That is the "hops through same-owner nodes" case §4.7.4 item 5 says the tests must cover. The trust
   assumption in §4.7.4 says "a foreign node lying is harmless (clamped to `foreign`)". That holds only at the
   first receiver.
2. **The cause is the inconsistency.** Every RAISE is downstream of a receipt where stored trust ≠ f(stored
   taint). P0 has 1.0 M such receipts in chains and 9.9 M in derivation. P1 and P2 have none.
3. **Normalising (P1) closes it at no cost.** It gives 0 RAISE, 0 over-taint and 0 rejections of honest traffic.
   The results are identical whether honest senders add their own owner or not, so P1 also covers the E0
   implementation slip. With P1 the sender clamp term in the formula is implied, and trust becomes a pure
   function of the stored taint.
4. **Rejecting (P2) is also sound, but brittle.** It rejects 2.2 M honest chain envelopes and 9.5 M honest
   derivation envelopes as soon as one honest implementation forwards taint without adding its own owner. It
   also contradicts §6 step 7, which says to compute `foreign` and log, not to reject.
5. The `unverified` flag cannot be protected against a foreign liar. It affects 22 % (chains) and 38 % (derivation)
   of all judged receipts, but the result is `foreign`, which is the correct clamp for anything a liar relays. No
   rule change is needed for it.

Limits: there are 3 owners, 6 nodes, at most 2 liars, paths of at most 5 nodes, and derivation from 2 inputs. In
the derivation family, liars only drop owners, never add them; adding owners only lowers trust. The model takes
taint per Part and does not model `derived-from` or `content-kind`, which are advisory. It does not model owner
key rotation. Under any rule, a Part tainted with an owner's old root key would read as `foreign` after a
rotation unless taint compares owners through the successor chain. That is a separate follow-up.

## Sources

- `docs/due-diligence.md` §4.7.4 (trust formula, storage rule, trust assumption), §4.4 (envelope `prov`), §6
  steps 7 and 9 and the provenance vector list.
- CaMeL, Debenedetti et al., "Defeating Prompt Injections by Design", arXiv:2503.18813: capabilities attached to
  values propagate through every data-flow step. The analogue here is that the *sender* is a source of taint and
  must be in the stored label.
- Denning, "A Lattice Model of Secure Information Flow", CACM 19(5), 1976: the label of a value must be the join
  of the labels of everything that influenced it. That includes the channel it arrived on, which is the sender
  term here.

## What the planner should do next

1. When `spec/ext/provenance.md` is drafted (T13), replace the storage rule with: *"On receipt, the receiver MUST
   set the stored taint to `owners = taint.owners ∪ {verified sender owner}`, `unverified = taint.unverified`,
   and compute trust as f(stored taint). If the received owners lacked the sender's owner, it MUST log an
   anomaly. Stored trust MUST equal f(stored taint)."* Keep the sender clamp in the prose as the reason, not as a
   separate formula term. Fix the "Trust assumption" bullet to say the clamp holds because the sender owner is
   added to the stored taint.
2. Add to the §6 provenance vectors: (a) B claims `owners=[A]` to A1, A1 forwards to A2, so A2 computes
   `foreign`; (b) the same with `owners=[]`; (c) B → A1, A1 derives a Part with its own content and sends it to
   A2, so A2 computes `foreign`. Extend M1 scenario step 7 with one more same-owner hop. With three nodes, alpha
   can forward to a second agent on alpha, or the devnet adds an `alpha2`.
3. Do not adopt "reject if the sender owner is missing". It breaks honest implementations that forward taint
   unchanged, and normalising is sound for every case the model covers.
4. Follow-up for T3/T13: decide how `taint.owners` is compared across an owner root-key rotation.
