# Lab 2026-11-12: how long does a revoked S4 mandate stay usable at the other owner's verifier?

## Question

`capability/v0` (draft on `claude/issue-4-spec-identity-and-capability-v0-owner-bi`, d07f078, not on master)
specifies revocation in §9. For most tokens, the verifier and the revoker are the same node. CAP-110 makes an
access token valid only on the node whose issuing key minted it, so that node revokes its own tokens locally and
at once. The one cross-owner case is the **S4 mandate** (§7). A, of owner OA, grants B a mandate. B presents it at
C, of owner OC. When A finds that B misbehaves (B is compromised, prompt-injected or rogue) and revokes the
mandate, C has to learn about it from OA's revocation list. The draft's mechanisms are:

- CAP-172: a mandate with `expires − issued > REVOCATION_EXEMPT_TTL` (1 h) needs a **fresh** list from A's
  issuing key, meaning `now ≤ validUntil`, with `validUntil − iat ≤ MAX_LIST_VALIDITY` = 24 h. Mandates of 1 h
  or less need no list.
- §9.4 / CAP-173: **stapling**. The sender, which here is B (the party being revoked), puts lists in
  `cap.revocations`, "so C can check a long-lived mandate while A is offline". C fetches lists from A's nodes.
- CAP-170: keep the highest `seq`, with no rollback. CAP-171: a stale list still revokes.
- §9.3 claims: "revoking a long-lived token takes effect at a verifier within `MAX_LIST_VALIDITY`".

`MAX_MANDATE_TTL` is also 24 h, so that claim allows a revoked mandate to stay usable for its whole lifetime. **How
long does C keep honouring a revoked mandate when A's node is a server, an office machine or a laptop? Which
distribution rule shortens that window without rejecting honest calls while A is offline (the case S4 stapling
exists for)?**

## Method

`lab/mandate-revocation/` is a dependency-free Rust crate. `cargo run --release -- 20000` writes `results.tsv`
in about 70 s (102 cells × 20 000 attack trials + 20 000 honest trials).

- **A's node availability** over 10 days:
  - `server`: always on.
  - `office`: weekdays about 9–18 on 92 % of days, plus an evening session on 10 % of days.
  - `laptop`: on for Exp(2 h), off for Exp(4 h).

  A's node holds the issuing key. It signs mandates and lists only while it is online, and it bumps `seq` on
  every signing (validity 24 h). C is always on. OA's relay or owner directory is always on.
- **Mandate**: minted at a uniformly random moment when A is online. TTL is 1 h, 4 h or 24 h.
- **B** calls C as Poisson traffic with a 5 min mean gap for the mandate's lifetime. It fetches A's list at mint
  and then hourly while A is reachable.
- **Attack trial**: A revokes at a uniformly random online moment `r` inside the lifetime. A's node must be
  online to revoke, because it holds the issuing key. From `r` on, B keeps calling and staples the newest list it
  fetched before `r`, the best choice for B.
- **Honest trial**: the same run without a revocation. It measures how many of B's calls are rejected with
  `RevocationStatusUnavailable` (or for lack of a mandate under `renew1h`).
- **k** other honest holders of A mandates also call C (30 min mean gap) and staple their newest hourly list. With
  k = 5, the new list can reach C through them.
- **Policies at C (and A)**:

| ID | Rule |
|---|---|
| `spec` | §9 as written: accept staples (newest `seq`), freshness = `now ≤ validUntil`; fetch from A's node only when C holds no fresh list and A is reachable. |
| `pull15m` | `spec`, plus C re-pulls from A's node at most every 15 min on use, if A is reachable. Soft: an unreachable A falls back to `spec`. |
| `hard1h` | A list is fresh only while `now − iat ≤ 1 h`, whether stapled or fetched. Fail closed. |
| `dir5m` | A's node uploads its list to OA's always-on host (relay/mailbox host/owner directory) hourly, and at once on a revocation. On use, C pulls it from there at most every 5 min. Validity stays 24 h, so the rule is soft if A is down. |
| `push` | `spec`, plus on revocation A's node sends the new list to the target owner named in the revoked mandate's `grant(OC, …)` (C), arriving 2 s later. |
| `renew1h` | Mandates are always 1 h (exempt). B renews at A every 50 min while A is reachable, for a job of 4 h or 24 h. |

Metrics:

- **window**: the time from `r` to the last accepted call by B (0 if there is none).
- **all-ok**: the share of attack trials in which every call by B after `r` was accepted, so the revocation had no
  effect.
- **bad calls**: accepted calls after `r`.
- **honest reject**: the share of honest calls rejected.
- **fetches/call**: C's pulls per call (load).

## Results

k = 0 (no other A-mandate traffic at C). Window in hours (mean / p90 / p99):

| A node | TTL | policy | window mean / p90 / p99 | all-ok | bad calls | honest reject | fetches/call |
|---|---|---|---|---|---|---|---|
| server | 24 h | **spec** | **12.0 / 21.6 / 23.7** | **100 %** | 145 | 0 % | 0 |
| office | 24 h | **spec** | **14.5 / 23.4 / 23.9** | **100 %** | 175 | 0 % | 0 |
| laptop | 24 h | **spec** | **13.3 / 23.0 / 23.9** | **100 %** | 160 | 0 % | 0 |
| any | 4 h | spec | 1.9–2.6 / 3.5–3.8 / 3.9–4.0 | 100 % | 24–32 | 0 % | 0 |
| any | 1 h (exempt) | spec | 0.42–0.52 / 0.83–0.89 / 0.96–0.98 | 100 % | 6–7 | 0 % | 0 |
| server | 24 h | pull15m | 0.05 / 0.16 / 0.23 | 0.4 % | 1.1 | 0 % | 0.25 |
| office | 24 h | pull15m | 0.80 / 0.18 / **23.5** | 3.3 % | 10.2 | 0 % | 0.08 |
| laptop | 24 h | pull15m | 0.50 / 0.23 / **10.5** | 2.4 % | 6.5 | 0 % | 0.10 |
| office | 4 h / 24 h | hard1h | 0.46–0.48 / 0.85–0.87 / 0.96 | 4–8 % | 6.4–6.7 | **17 % / 65 %** | 0.01 |
| laptop | 4 h / 24 h | hard1h | 0.48–0.52 / 0.86–0.88 / 0.96–0.97 | 2–8 % | 6.6–7.2 | **32 % / 55 %** | 0.01 |
| office | 4 h / 24 h | renew1h | 0.51 / 0.86 / 0.96 | 4–9 % | 7.1 | **17 % / 64 %** | 0 |
| laptop | 4 h / 24 h | renew1h | 0.52–0.53 / 0.86–0.88 / 0.97 | 3–8 % | 7.1–7.4 | **32 % / 55 %** | 0 |
| any | any | **dir5m** | **0.005 / 0.024 / 0.067** | 0.1–2.4 % | 0.24–0.25 | **0 %** | 0.50 |
| any | any | **push** | **0 / 0 / 0** | ≤ 0.07 % | 0.01 | **0 %** | 0 |

With k = 5 (other holders staple newer lists), `spec` improves only when A is online after `r`. Office/24 h: window
2.4 / 11.2 / 23.8 h, all-ok 11 %, 29.5 bad calls. Laptop/24 h: 1.8 / 5.7 / 17.8 h, 9 %. Exempt 1 h mandates are
still all-ok in 62–69 % of trials. `dir5m` is unchanged (window p99 0.068 h, ≤ 3 % all-ok, 0.32 bad calls). Full
table: `lab/mandate-revocation/results.tsv`.

What the numbers say:

1. **As written, mandate revocation does nothing against the holder it targets.** B staples a list signed before
   `r`, and that list stays fresh until 24 h after its `iat`, which is at least the mandate's expiry when B fetched
   it at mint. C has a fresh list, so it never fetches. In every k = 0 cell, all of B's calls after revocation are
   accepted (100 % all-ok, window = the remaining lifetime). The §9.3 bound "within `MAX_LIST_VALIDITY`" holds,
   but `MAX_LIST_VALIDITY` equals `MAX_MANDATE_TTL`, so the bound never bites. Exempt 1 h mandates are never
   checked against a new list. Incidental gossip from other holders helps only while A stays online.
2. **Pulling from A's own node leaves an overnight tail.** A revokes while online, and then the office machine
   or laptop often goes offline. C cannot reach A, the stapled list is still fresh, and B runs until morning
   (office p99 23.5 h).
3. **Short freshness or short mandates bound the window to about 1 h, but break S4.** `hard1h` and `renew1h`
   reject 17–65 % of honest calls whenever A's node is an office machine or a laptop, the exact "A is offline"
   case that stapling was added for. They also only bound the window to 1 h (p99 0.96 h), not close it.
4. **Publishing at an always-on owner host, or pushing to the target, closes the window at no availability
   cost.** `dir5m` gives a window p99 of 4 min in every cell and 0 honest rejects, because the 24 h validity
   stays soft. Its cost is ≤ 12 pulls/h per (verifier, issuing key) pair, 0.35–0.51 per call at these rates.
   `push` gives about 0 as long as C is reachable. The two complement each other: push is immediate,
   and the directory covers a lost push, a C that was offline, and any verifier A does not know about (a
   re-delegated mandate's later hop).

Side finding (spec text): CAP-170 says a list with an *equal* `seq` must not replace the held one. §9.2 requires
re-signing at least daily, even when nothing changed. If an implementation re-signs an unchanged list under the
same `seq`, verifiers can never refresh it and long tokens fail with `RevocationStatusUnavailable` after 24 h. The
model assumes every signing bumps `seq`. The spec should say so explicitly.

## Limits

- C is always on and fetches take no time. With an intermittent C, a pushed list and B's request both wait in C's
  mailbox. C must apply queued revocation lists before it authorises queued requests. The cap-expiry-dwell lab
  already pins revocation to the receiver's `now`.
- OA's status host is assumed available and not colluding with B. It cannot forge lists, only withhold them, and
  it is A's own relay.
- The OA root-signed list, which must also be fresh under CAP-172, is not modelled. Its 30-day validity with a
  monthly ceremony leaves no slack: a late ceremony makes every long mandate from OA fail everywhere.
- Single-use mandates (`check if calls($n), $n < 1`, the §7.1 example) bound the damage to one call whatever the
  revocation rule. The window matters for multi-call mandates and standing (S1-style) mandates.
- B's call rate (5 min) sets the "bad calls" count. The window figures do not depend on it much.

## Prior art

- **OCSP stapling** (RFC 6066 §8, RFC 6960; must-staple RFC 7633). The presenter chooses which signed status to
  staple, and a response stays acceptable until its `nextUpdate`. A revoked certificate holder can therefore keep
  stapling a pre-revocation "good" response for the rest of its validity. This is the same failure as point 1.
  The usual mitigations are short validity, which is costly here (point 3), and a relying party that also checks
  the source. <https://www.rfc-editor.org/rfc/rfc6066#section-8>, <https://www.rfc-editor.org/rfc/rfc6960>,
  <https://www.rfc-editor.org/rfc/rfc7633>
- **CRL distribution points** (RFC 5280 §4.2.1.13): the certificate names where its status lives. The issuer-cert
  could carry a status location the same way, so a verifier of another owner knows where to pull (`dir5m`).
  <https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.13>
- **Let's Encrypt ending OCSP** (2024–25) in favour of CRLs and short-lived certificates. Short lifetimes work
  when the issuer is always online, which A's node is not (point 3). <https://letsencrypt.org/2024/12/05/ending-ocsp/>
- **UCAN revocation** (ucan-wg/revocation): a revocation is signed by an issuer in the chain and is meant to be
  sent to the parties that validate, which is the `push` direction here. <https://github.com/ucan-wg/revocation>
- **Biscuit**: per-block revocation IDs, and distribution is left to the application.
  <https://github.com/eclipse-biscuit/biscuit/blob/main/SPECIFICATIONS.md>

## What the planner should do next

1. **capability/v0 §9.3/§9.4 (T3)**: state that stapling proves only what a list *lists*, never that nothing
   newer exists. For mandates, the verifier MUST also consult the principal owner's status source:
   - (a) Define a `status` location in the issuer-cert (or the owner directory, T17) where the issuing node
     publishes its current list at once on every revocation and at least hourly. Serve it from OA's always-on host
     (relay/mailbox host), as §9.4 already does for root lists.
   - (b) A verifier of a mandate (exempt or not) refreshes from it at most every 5 min on use. An unreachable
     status source falls back to the held or stapled list (soft), so honest S4 calls while A is offline keep
     working.
2. **capability/v0 / profile (T1/T3)**: on revoking a mandate, the issuing node SHOULD push the new list to every
   resource owner named in its `grant` facts, and a receiver MUST apply queued revocation lists before queued
   requests.
3. Fix the §9.3 sentence. With stapling as written, a revoked mandate is honoured until it expires (≤ 24 h, the
   whole lifetime). The bound becomes "≤ the status refresh interval" only with item 1.
4. CAP-170/§9.2: every signing of a list, including the daily re-signing, MUST use a higher `seq`.
5. Do **not** shorten `MAX_LIST_VALIDITY` or force 1 h mandates to fix this. That rejects 17–65 % of honest calls
   for office or laptop principals.
6. Conformance (T4 harness, when mandates are in M1+): A revokes a multi-call mandate and goes offline. B keeps
   stapling its pre-revocation list. C must deny within the refresh interval, and an honest holder's call
   in the same period must still pass.
