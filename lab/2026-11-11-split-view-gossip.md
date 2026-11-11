# Does audit/v0 checkpoint exchange catch a node that shows different histories to different peers?

Date: 2026-11-11. Track: `audit/v0` §10.2–§10.4 (T9, threat AUD-3 / gap G6, M1 step 8). Code: [`split-view-gossip/`](split-view-gossip/).

## Question

audit/v0 §15 says: "Forks (AUD-3) are detected when two holders compare (§10.4)". The comparison happens in
`ExchangeCheckpoints` (AUD-721), and it is deliberately **one hop**:

- A node calls it only on peers it is already exchanging envelopes with (AUD-700/721). It sends up to `MAX_HAVE` = 64
  held checkpoints of third-party logs, most recently used first.
- AUD-720 forbids replacing a held checkpoint with one received this way, so a checkpoint never travels further than
  one hop from the node that fetched it from the log.

A node X that equivocates shows branch F to a victim set V and branch M to everyone else. Two questions:

1. How often is that detected, and how fast, on realistic who-talks-to-whom graphs?
2. Every counterparty v of X calls `ExchangeCheckpoints` on X and lists the logs it holds, and a log ID is a node.
   So X learns who v talks to (the leak §15 accepts as "the price of fork detection"). Can X use that leak to pick
   victims that no comparison can reach?

## Method

`split-view-gossip/src/main.rs` (Rust, no dependencies) is a discrete-event model. Each cell runs 200 trials. Each
trial builds a fresh graph, then runs a 7 d warm-up, a fork at t0 and a 30 d horizon. The full grid of 60 cells
took 5 min 14 s on 3 cores.

**Contact graph.** Each edge carries Poisson sessions at a lognormal rate (σ = 1). Every session triggers
`GetCheckpoint` on the peer (AUD-700) and one `ExchangeCheckpoints` call in each direction (AUD-721), with
MRU/`MAX_HAVE` gating.

**Detection.** A fork counts as detected when one comparison brings together a post-fork M commitment and a post-fork
F commitment. This counts detection by **anyone**, which is an upper bound on what the victim learns.

**Topologies:**

- *market(c)*: the S1/S2 shape. 400 client owners each run 5 nodes, all talking to each other (median 4/d).
  There are 20 service nodes with Zipf popularity. Each owner uses 1+Poisson(1) services, and each of its nodes
  uses each chosen service with p = 0.6 (median 2/d). Owners also have cross-owner partner ties, c per owner on
  average (c = 0, 0.5, 2; median 0.5/d). X is a random service, with about 120 counterparties.
- *fleets(d)*: the S3 shape. 200 owners × 10 nodes, complete graph inside each owner. Cross-owner edges are random,
  with mean cross-degree d per node (d = 1, 3). X is a random node, with 10–12 counterparties.

**Protocol variants:**

| variant | rule |
|---|---|
| `spec` | as written: one hop, only checkpoints fetched from X itself are held and sent |
| `relay` | nodes also keep and forward X-signed checkpoints received from others (still MRU-gated); two inconsistent X-signed commitments anywhere are a detection |
| `spec+W3` | spec plus 3 shared witnesses. Every node runs ExchangeCheckpoints with its (random) witness at 1/d (24/d in the sensitivity run). Witnesses keep everything submitted and exchange among themselves hourly |
| `relay+W3` | both |

**Attackers:**

- *One*: forks one random counterparty.
- *Half*: forks a random half of the counterparties.
- *Adaptive*: uses only what the exchange leaks. It takes each counterparty's MRU-64 held-log list as seen at t0
  and builds the co-holder graph among its counterparties. It knows witnesses gossip, so everyone listing a witness
  log is merged into one node. If that graph has ≥ 2 components, it forks the smallest one not tied to a witness:
  no one-hop comparison can then cross the cut. Otherwise it forks the counterparty with the fewest co-holders.

Only trials in which a victim actually fetched a fork checkpoint are counted ("effective", 198–200 per cell).

## Results

Each cell gives the share of effective attacks detected within 1 d / 7 d / 30 d, and then the median latency from
t0 (`inf` = under 50 % detected). Latency includes the time until the victim next fetches from X.

| topology | attacker | spec | relay | spec+W3 | relay+W3 |
|---|---|---|---|---|---|
| market c=0 | One | .64/.97/.98, 0.7 d | .79/.99/1.00, 0.4 d | .68/.98/1.00, 0.6 d | .78/.99/1.00, 0.4 d |
| market c=0 | Half | 1/1/1, 0.11 d | 1/1/1, 0.06 d | 1/1/1, 0.10 d | 1/1/1, 0.06 d |
| market c=0 | **Adaptive** | **.02/.06/.08**, inf | .61/.82/.83, 0.6 d | .42/.99/**1.00**, 1.2 d | .79/.98/**1.00**, 0.4 d |
| market c=0.5 | **Adaptive** | **.01/.06/.07** | .73/.93/.95 | .48/1.00/1.00 | .79/1.00/1.00 |
| market c=2 | **Adaptive** | **.01/.08/.08** | .77/.96/.97 | .46/1.00/1.00 | .79/.99/1.00 |
| fleets d=1 | One | .83/.91/.91 | .83/1.00/1.00 | .85/.99/1.00 | .87/1.00/1.00 |
| fleets d=1 | **Adaptive** | **.33/.40/.40** | .53/.93/1.00 | .53/.94/1.00 | .72/.95/1.00 |
| fleets d=3 | One | .76/.81/.81 | .79/.97/1.00 | .73/.97/1.00 | .79/.98/1.00 |
| fleets d=3 | **Adaptive** | **.07/.09/.09** | .55/.93/1.00 | .23/.91/1.00 | .50/.96/1.00 |

The full table, with p90 latency and attacker beliefs, is in `split-view-gossip/results-200.tsv`.

1. **As written, a targeted split view is almost never caught.** Using only the ExchangeCheckpoints leak, the
   adaptive attacker found a component it could fork in 200/200 trials when X was a service in the market graph,
   and its fork went undetected for 30 d in 92–93 % of trials. In fleet graphs it found one for 60 % (d = 1) and
   92 % (d = 3) of nodes, and none of the attacks it believed safe was ever detected (120/120 and 181/182 survived
   30 d). The few market detections come from edges that were silent in the 7 d warm-up, so the leaked view missed
   them. More cross-owner ties make the attack *easier* in the fleet graph: X's cross-owner counterparties belong
   to different owners and rarely know each other.
2. **Untargeted forks are caught, but not always.** Forking half the counterparties is detected within 0.3 d in
   every cell. Forking one random counterparty is caught in 97–98 % of market trials (its own fleet usually uses the
   same service), but only in 81–91 % of fleet trials: a lone cross-owner counterparty has nobody to compare with.
3. **Relaying X-signed checkpoints (dropping one-hop) closes most of it.** The adaptive attacker is caught in
   94–100 % of trials, except in market with c = 0, where 17.5 % survive: clients whose fleet uses only X have no
   path to anyone else. Other services that relay act as accidental witnesses. This model is optimistic for relay,
   because relayed logs do not compete for the 64 MRU slots.
4. **Shared witnesses give 100 % within 30 d in every cell, for every attacker.** With daily submission, p90
   latency is ≤ 3.4 d (market) and ≤ 6.6 d (fleets). With hourly submission (`results-w24.tsv`) the adaptive
   attacker is caught in 94–100 % of trials within 7 d (median 0.3–0.8 d). Latency is then dominated by the
   victim's next contact with X. Witnesses also remove the leak's value: the attacker never found a safe set
   (0–1 of 200).
5. **`MAX_HAVE` = 64 never mattered here.** Client degrees are 5–15. Only services and witnesses exceed 64, and
   witnesses are exempt from the limit. It would matter for a client node with more than 64 active peers.
6. **M1 cannot exercise AUD-3.** In the devnet, beta's only audited counterparty is alpha (the relay hosts the
   mailbox and is not an audit peer), so there is no second holder. Step 8's "exchanged checkpoints are
   consistent" covers only the honest path.

**Limits of the model:**

- Sessions are Poisson, and every session triggers an exchange. AUD-700 actually rate-limits fetches to
  `GOSSIP_INTERVAL` unless a receipt is pending, so these numbers are optimistic for spec.
- The graphs are synthetic.
- Detection means "some node logs `log-inconsistent`". The victim learns of it only if the detector tells it, and
  v0 has no message for that.
- With unequal sizes, transferable evidence needs X to answer `GetConsistency` (§10.3 item 2). If X stays silent,
  the result is `audit-unanswered`, which is not transferable. Equal-size forks are self-contained evidence.
- Pre-acceptance witness cosigning (C2SP `tlog-witness`) prevents a split view rather than detecting it. It is not
  simulated, because it holds by construction unless a quorum of witnesses colludes.

## Prior art

- Mazières & Shasha, SUNDR, "Building secure file systems out of Byzantine storage" (PODC 2002): fork consistency.
  Once forked, the two groups never see each other's updates again, and only out-of-band communication detects the
  fork. That is exactly the cut the adaptive attacker picks.
- Chuat, Szalachowski, Perrig, Laurie, Messeri, "Efficient Gossip Protocols for Verifying the Consistency of
  Certificate Logs" (IEEE CNS 2015), <https://arxiv.org/abs/1511.01514>: client-to-client STH pooling. Detection
  depends on how well clients mix, which matches our finding 2.
- Nordberg, Gillmor, Ritter, "Gossiping in CT", draft-ietf-trans-gossip (expired). It abandoned STH pollination
  among peers largely because of the privacy leak, the same leak the adaptive attacker uses here.
- Dahlberg et al., "Aggregation-Based Gossip for Certificate Transparency" (2019), <https://arxiv.org/abs/1806.08817>:
  third-party aggregation, a witness by another name.
- Meiklejohn et al., "Think Global, Act Local: Gossip and Client Audits in Verifiable Data Structures" (2020),
  <https://arxiv.org/abs/2011.04551>: argues that peer gossip is hard to deploy and moves to witness-style
  verification.
- Syta et al., "Keeping Authorities 'Honest or Bust' with Decentralized Witness Cosigning" (IEEE S&P 2016), and
  C2SP `tlog-witness` / `tlog-cosignature` (Go sumdb, Sigstore): cosigning before acceptance.

What applies here: the per-node, private-log setting is the hardest case for peer gossip. Each log has few holders,
and they cluster by owner. What does not apply: CT's argument that the population of browsers is too large to target
does not hold, because a webway node knows each of its counterparties by key.

## What the planner should do next

1. **Correct the claim in audit/v0 §15.** State the bound: under one-hop exchange a split view is detected only if
   some victim and some non-victim are direct counterparties that both hold the log. ExchangeCheckpoints shows the
   log's node exactly which sets meet that condition. Here 60–100 % of attacker positions had an undetectable victim
   set.
2. **Allow relay in AUD-720/721.** Keep the rule "never *replace* the held checkpoint", but let a node keep and
   forward X-signed checkpoints received from others (as evidence candidates), and compare them. This is a small
   spec change that raises adaptive detection to 83–100 %.
3. **Move witnesses (open question 2) from "after M1" to a design note before T9 freezes.** A small set of shared
   witnesses that every node submits to daily gave 100 % detection within 30 d in all 60 cells. Also define how a
   witness reports a conflict back to the submitting victim. Weigh cosign-before-accept (prevention, needs witness
   availability) against submit-and-compare (detection only).
4. **M1:** do not claim AUD-3 coverage. Add a conformance scenario in which the harness plays two holders of
   beta's log that are given inconsistent checkpoints, with the expected `log-inconsistent` evidence, or add a
   fourth devnet node.
5. **Follow-up lab:** measure `MAX_HAVE`/MRU on a busy-client graph (more than 64 peers), and measure how often
   X can refuse to answer `GetConsistency` and leave only non-transferable `audit-unanswered` evidence.
