# Lab index

| Date | Slug | Finding |
|---|---|---|
| 2026-11-09 | [merkle-proof-adversarial](2026-11-09-merkle-proof-adversarial.md) | audit/v0 Merkle verifier agrees with an independent RFC 9162 model on ~37 M checks, 0 false accepts at the committed size; but 99.9 % of inclusion and 100 % of consistency proofs alias to other (index,size) pairs, so §5.3 should say index too |
| 2026-11-09 | [delivery-freshness-sim](2026-11-09-delivery-freshness-sim.md) | Monte Carlo of envelope/v0 freshness+dedupe: 0 doubles with monotone clocks (even 600 k replays), but a 10 min backward step on the receiver clock double-processes 0.4 % (honest) to 3.1 % (replays) of in-flight envelopes; a persisted prune watermark removes all doubles; reporting `expired` at `exp` is wrong for 0.13–0.44 % with good clocks, `exp + 2·skew` fixes it |
