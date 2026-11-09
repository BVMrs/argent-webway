//! Lab 2026-11-09: Monte Carlo model of the envelope/v0 freshness, dedupe and mailbox rules
//! (docs/due-diligence.md §4.4, §4.5, §4.7.3) under clock offsets, clock steps, lost acks and
//! receiver outages.
//!
//! One trial = one envelope from sender S to receiver R, possibly via the receiver's mailbox host M.
//! All times are true time in ms. Each node reads `true + offset`.
//!
//! Rules modelled (as written in the due diligence):
//! - S stamps `ts = now_s`, `exp = ts + ttl`, retries direct with exponential backoff while `now_s <= exp`,
//!   and hands one copy to M when R is unreachable.
//! - M delivers when R is up, retries until it gets R's ack, and drops the copy once `now_m > exp`.
//! - R rejects `ts > now_r + skew` (Future) and `now_r > exp + skew` (Expired); dedupes on (from, id);
//!   a pruner (every 60 s) deletes entries once `now_r > exp + skew`.
//! - R's response has `exp = req.exp + skew`; S accepts it while `now_s <= resp.exp + skew` and
//!   `resp.ts <= now_s + skew`.
//! - S reports `expired` to the caller at `now_s = exp` (V0) when it has no response.
//!
//! Variants:
//! - `report2`: S reports `expired` at `now_s = exp + 2*skew` instead of `exp` (still stops retrying at exp).
//! - `watermark`: R persists W = the largest `exp + skew` it has pruned and rejects any envelope with
//!   `exp + skew <= W` as Expired (worst case: dense traffic, W = high-water of now_r at pruner ticks).
//! - `dedupe_first`: R looks up an unpruned dedupe entry before the freshness checks and answers a
//!   duplicate with the stored response even if it would now fail them.

use std::cmp::Reverse;
use std::collections::BinaryHeap;

const S: i64 = 1000;
const MIN: i64 = 60 * S;
const HOUR: i64 = 60 * MIN;
const PRUNE_TICK: i64 = MIN;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn f(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
    fn uni(&mut self, lo: i64, hi: i64) -> i64 {
        if hi <= lo {
            return lo;
        }
        lo + (self.f() * (hi - lo) as f64) as i64
    }
    fn exp(&mut self, mean: i64) -> i64 {
        (-(1.0 - self.f()).ln() * mean as f64) as i64
    }
    fn chance(&mut self, p: f64) -> bool {
        self.f() < p
    }
}

#[derive(Clone)]
struct Scenario {
    name: &'static str,
    skew: i64,
    ttl: (i64, i64),      // log-uniform range
    off: i64,             // each node offset uniform in [-off, off]
    step: Option<i64>,    // R runs fast by d, then steps back by d at a random time
    replay: bool,         // a party holding a copy (mailbox host, relay with plaintext) replays it
    p_loss: f64,          // loss probability of each response and each mailbox ack
    mean_up: i64,
    mean_down: i64,
}

#[derive(Clone, Copy)]
struct Variant {
    name: &'static str,
    report2: bool,
    watermark: bool,
    dedupe_first: bool,
}

#[derive(Clone, Copy, PartialEq)]
enum Via {
    Direct,
    Mailbox,
    Replay,
}

#[derive(Clone, Copy)]
enum Resp {
    Ok { ts: i64, exp: i64 },
    Expired,
    Future,
}

#[derive(Clone, Copy)]
enum Ev {
    SenderAttempt(u32),
    SenderReport,
    SenderGets(Resp),
    MailboxRecv,
    MailboxTry(u32),
    MailboxAck,
    Arrive(Via, u32),
}

#[derive(Default, Clone)]
struct Tally {
    n: u64,
    processed: u64,
    double: u64,
    confirmed: u64,
    told_expired_and_processed: u64,
    // split of the above
    tep_late_confirm: u64,  // S later accepted a response for it
    tep_err_expired: u64,   // R answered a retry with EnvelopeExpired after processing an earlier copy
    tep_all_lost: u64,      // every response lost
    processed_never_confirmed: u64,
    refused_response: u64,
    spurious_reject: u64,
}

struct Trial<'a> {
    sc: &'a Scenario,
    v: Variant,
    rng: Rng,
    ttl: i64,
    o_s: i64,
    o_m: i64,
    o_r: i64,
    step_at: i64,
    step_d: i64,
    ts: i64,
    exp: i64,
    up: Vec<(i64, i64)>,
    horizon: i64,
    heap: BinaryHeap<Reverse<(i64, u64, usize)>>,
    evs: Vec<Ev>,
    seq: u64,
    // receiver
    processed: u32,
    entry: Option<(i64, i64)>, // stored response (ts, exp)
    pruned_at: i64,
    ideal_ok_copy: bool,
    // sender
    done: bool,
    reported: bool,
    err_expired: bool,
    late_confirm: bool,
    refused: bool,
    sent_mailbox: bool,
    // mailbox
    mb_holds: bool,
}

impl<'a> Trial<'a> {
    fn new(sc: &'a Scenario, v: Variant, seed: u64) -> Self {
        let mut rng = Rng(seed);
        let (lo, hi) = sc.ttl;
        let ttl = ((lo as f64).ln() + rng.f() * ((hi as f64).ln() - (lo as f64).ln())).exp() as i64;
        let o_s = rng.uni(-sc.off, sc.off);
        let o_m = rng.uni(-sc.off, sc.off);
        let o_r = rng.uni(-sc.off, sc.off);
        let step_d = sc.step.unwrap_or(0);
        let step_at = if sc.step.is_some() { rng.uni(0, ttl + 3 * sc.skew) } else { i64::MAX };
        let horizon = ttl + 6 * sc.skew + step_d + 4 * HOUR;
        // receiver up/down schedule
        let mut up = Vec::new();
        let mut t = 0;
        let mut is_up = rng.chance(sc.mean_up as f64 / (sc.mean_up + sc.mean_down) as f64);
        while t < horizon {
            let d = if is_up { rng.exp(sc.mean_up) } else { rng.exp(sc.mean_down) }.max(S);
            if is_up {
                up.push((t, t + d));
            }
            t += d;
            is_up = !is_up;
        }
        let ts = o_s;
        Trial {
            sc,
            v,
            rng,
            ttl,
            o_s,
            o_m,
            o_r,
            step_at,
            step_d,
            ts,
            exp: ts + ttl,
            up,
            horizon,
            heap: BinaryHeap::new(),
            evs: Vec::new(),
            seq: 0,
            processed: 0,
            entry: None,
            pruned_at: i64::MAX,
            ideal_ok_copy: false,
            done: false,
            reported: false,
            err_expired: false,
            late_confirm: false,
            refused: false,
            sent_mailbox: false,
            mb_holds: false,
        }
    }

    fn at(&mut self, t: i64, e: Ev) {
        self.seq += 1;
        self.evs.push(e);
        self.heap.push(Reverse((t, self.seq, self.evs.len() - 1)));
    }
    fn lat(&mut self) -> i64 {
        self.rng.uni(20, 300)
    }
    fn backoff(&mut self, k: u32) -> i64 {
        let base = (S << k.min(20)).min(10 * MIN);
        (base as f64 * (0.5 + self.rng.f())) as i64
    }
    fn is_up(&self, t: i64) -> bool {
        let i = self.up.partition_point(|&(s, _)| s <= t);
        i > 0 && t < self.up[i - 1].1
    }
    fn next_up(&self, t: i64) -> Option<i64> {
        if self.is_up(t) {
            return Some(t);
        }
        let i = self.up.partition_point(|&(s, _)| s <= t);
        self.up.get(i).map(|&(s, _)| s)
    }
    fn off_r(&self, t: i64) -> i64 {
        if t < self.step_at { self.o_r + self.step_d } else { self.o_r }
    }
    fn now_r(&self, t: i64) -> i64 {
        t + self.off_r(t)
    }
    /// First pruner tick strictly after `t` at which now_r > x.
    fn first_prune(&self, t: i64, x: i64) -> i64 {
        let ceil_tick = |a: i64| (a.max(t + 1) + PRUNE_TICK - 1).div_euclid(PRUNE_TICK) * PRUNE_TICK;
        let mut best = i64::MAX;
        // segment before the step: offset o_r + d
        let c1 = ceil_tick(x - (self.o_r + self.step_d) + 1);
        if c1 < self.step_at {
            best = c1;
        }
        // segment after the step: offset o_r
        if self.step_at == i64::MAX {
            return best;
        }
        let c2 = ceil_tick((x - self.o_r + 1).max(self.step_at));
        best.min(c2)
    }
    /// Pruned watermark W(t) under dense traffic: high-water of now_r over pruner ticks <= t, minus 1.
    fn watermark(&self, t: i64) -> i64 {
        let lt = t.div_euclid(PRUNE_TICK) * PRUNE_TICK;
        let mut w = lt + self.off_r(lt);
        if lt >= self.step_at && self.step_at != i64::MAX {
            let before = (self.step_at - 1).div_euclid(PRUNE_TICK) * PRUNE_TICK;
            if before >= 0 {
                w = w.max(before + self.o_r + self.step_d);
            }
        }
        w - 1
    }

    fn receiver(&mut self, t: i64) -> Option<Resp> {
        if !self.is_up(t) {
            return None;
        }
        if t <= self.ttl {
            self.ideal_ok_copy = true;
        }
        let skew = self.sc.skew;
        let now = self.now_r(t);
        if self.v.dedupe_first {
            if let Some((rts, rexp)) = self.entry {
                if t < self.pruned_at {
                    return Some(Resp::Ok { ts: rts, exp: rexp });
                }
            }
        }
        if self.ts > now + skew {
            return Some(Resp::Future);
        }
        if now > self.exp + skew {
            return Some(Resp::Expired);
        }
        if self.v.watermark && self.exp + skew <= self.watermark(t) {
            return Some(Resp::Expired);
        }
        if let Some((rts, rexp)) = self.entry {
            if t < self.pruned_at {
                return Some(Resp::Ok { ts: rts, exp: rexp });
            }
        }
        self.processed += 1;
        let r = (now, self.exp + skew);
        self.entry = Some(r);
        self.pruned_at = self.first_prune(t, self.exp + skew);
        Some(Resp::Ok { ts: r.0, exp: r.1 })
    }

    fn run(mut self) -> Tally {
        let skew = self.sc.skew;
        self.at(0, Ev::SenderAttempt(0));
        let report_sender_time = if self.v.report2 { self.exp + 2 * skew } else { self.exp };
        self.at(report_sender_time - self.o_s, Ev::SenderReport);
        if self.sc.replay {
            for _ in 0..3 {
                let t = self.rng.uni(0, self.ttl + 3 * skew + self.step_d);
                self.at(t, Ev::Arrive(Via::Replay, 0));
            }
        }
        while let Some(Reverse((t, _, i))) = self.heap.pop() {
            if t > self.horizon {
                break;
            }
            match self.evs[i] {
                Ev::SenderAttempt(k) => {
                    if self.done || self.err_expired || t + self.o_s > self.exp {
                        continue;
                    }
                    let l = self.lat();
                    if self.is_up(t) {
                        self.at(t + l, Ev::Arrive(Via::Direct, 0));
                    } else if !self.sent_mailbox {
                        self.sent_mailbox = true;
                        self.at(t + l, Ev::MailboxRecv);
                    }
                    let b = self.backoff(k);
                    self.at(t + b, Ev::SenderAttempt(k + 1));
                }
                Ev::SenderReport => {
                    if !self.done && !self.err_expired {
                        self.reported = true;
                    }
                }
                Ev::SenderGets(r) => match r {
                    Resp::Ok { ts, exp } => {
                        let now = t + self.o_s;
                        if now <= exp + skew && ts <= now + skew {
                            if !self.done && (self.reported || self.err_expired) {
                                self.late_confirm = true;
                            }
                            self.done = true;
                        } else {
                            self.refused = true;
                        }
                    }
                    Resp::Expired => {
                        if !self.done {
                            self.err_expired = true;
                        }
                    }
                    Resp::Future => {}
                },
                Ev::MailboxRecv => {
                    self.mb_holds = true;
                    self.at(t, Ev::MailboxTry(0));
                }
                Ev::MailboxTry(k) => {
                    if !self.mb_holds {
                        continue;
                    }
                    if t + self.o_m > self.exp {
                        self.mb_holds = false;
                        continue;
                    }
                    match self.next_up(t) {
                        Some(u) if u == t => {
                            let l = self.lat();
                            self.at(t + l, Ev::Arrive(Via::Mailbox, k));
                        }
                        Some(u) => self.at(u, Ev::MailboxTry(k)),
                        None => {}
                    }
                }
                Ev::MailboxAck => self.mb_holds = false,
                Ev::Arrive(via, k) => {
                    let r = self.receiver(t);
                    match (via, r) {
                        (Via::Replay, _) => {}
                        (Via::Direct, None) => {}
                        (Via::Mailbox, None) => self.at(t, Ev::MailboxTry(k)),
                        (Via::Direct, Some(r)) => {
                            if !self.rng.chance(self.sc.p_loss) {
                                let l = self.lat();
                                self.at(t + l, Ev::SenderGets(r));
                            }
                        }
                        (Via::Mailbox, Some(r)) => {
                            if !self.rng.chance(self.sc.p_loss) {
                                let l = self.lat();
                                self.at(t + l, Ev::SenderGets(r));
                            }
                            if !self.rng.chance(self.sc.p_loss) {
                                let l = self.lat();
                                self.at(t + l, Ev::MailboxAck);
                            }
                            let b = 30 * S + self.backoff(k + 5);
                            self.at(t + b, Ev::MailboxTry(k + 1));
                        }
                    }
                }
            }
        }
        let mut y = Tally { n: 1, ..Default::default() };
        let p = self.processed > 0;
        y.processed = p as u64;
        y.double = (self.processed > 1) as u64;
        y.confirmed = self.done as u64;
        y.refused_response = self.refused as u64;
        y.processed_never_confirmed = (p && !self.done) as u64;
        y.spurious_reject = (!p && self.ideal_ok_copy) as u64;
        if p && (self.reported || self.err_expired) {
            y.told_expired_and_processed = 1;
            if self.late_confirm {
                y.tep_late_confirm = 1;
            } else if self.err_expired {
                y.tep_err_expired = 1;
            } else {
                y.tep_all_lost = 1;
            }
        }
        y
    }
}

fn add(a: &mut Tally, b: &Tally) {
    a.n += b.n;
    a.processed += b.processed;
    a.double += b.double;
    a.confirmed += b.confirmed;
    a.told_expired_and_processed += b.told_expired_and_processed;
    a.tep_late_confirm += b.tep_late_confirm;
    a.tep_err_expired += b.tep_err_expired;
    a.tep_all_lost += b.tep_all_lost;
    a.processed_never_confirmed += b.processed_never_confirmed;
    a.refused_response += b.refused_response;
    a.spurious_reject += b.spurious_reject;
}

fn per_m(x: u64, n: u64) -> String {
    let v = x as f64 * 1e6 / n as f64;
    if x == 0 { "0".into() } else if v >= 100.0 { format!("{:.0}", v) } else { format!("{:.1}", v) }
}

/// Deterministic edge cases, all clocks exact, skew = 5 min, ttl = 1 h.
fn deterministic() -> u32 {
    let mut fails = 0;
    let skew = 5 * MIN;
    let exp = HOUR;
    // E1: M1 scenario 6, third task: mailbox sends at exp - 100 ms (allowed: now_m <= exp), 150 ms to R,
    // R processes, 150 ms back to S. V0 has already reported `expired` at exp.
    let deliver = exp - 100;
    let resp_arrive = deliver + 150 + 150;
    let v0_reported = resp_arrive > exp;
    println!("E1 mailbox sends at exp-100ms, response arrives at exp+{} ms: V0 told caller `expired` first: {}",
        resp_arrive - exp, v0_reported);
    // E2: mailbox host (or a relay that sees plaintext) delivers at exp + 4 min. R accepts (<= exp + skew).
    let late = exp + 4 * MIN;
    println!("E2 copy delivered at exp+4min: R accepts = {} (rule: now_r <= exp + skew)", late <= exp + skew);
    // E3: R clock steps back by 10 min after pruning; replay at true exp + skew + 1 min.
    let d = 10 * MIN;
    let pruned_tick = exp + skew + MIN; // first tick with now_r > exp + skew while still accurate
    let replay_true = pruned_tick + MIN;
    let now_after_step = replay_true - d;
    let accepted_again = now_after_step <= exp + skew;
    println!("E3 step back {} min after prune, replay at true exp+skew+2min: re-accepted (double) = {}",
        d / MIN, accepted_again);
    if !v0_reported || !accepted_again {
        fails += 1;
    }
    fails
}

fn main() {
    let n: u64 = std::env::var("N").ok().and_then(|s| s.parse().ok()).unwrap_or(200_000);
    let skew = 5 * MIN;
    let base = Scenario {
        name: "",
        skew,
        ttl: (5 * MIN, 24 * HOUR),
        off: skew / 2,
        step: None,
        replay: false,
        p_loss: 0.05,
        mean_up: 2 * HOUR,
        mean_down: 30 * MIN,
    };
    let sc = |name, f: &dyn Fn(&mut Scenario)| {
        let mut s = base.clone();
        s.name = name;
        f(&mut s);
        s
    };
    let scenarios = vec![
        sc("A0 exact clocks", &|s| s.off = 0),
        sc("A  offsets ±skew/2", &|_| {}),
        sc("A' short ttl 1-10min", &|s| s.ttl = (MIN, 10 * MIN)),
        sc("B  offsets ±skew", &|s| s.off = skew),
        sc("B' offsets ±2skew", &|s| s.off = 2 * skew),
        sc("R  replays", &|s| s.replay = true),
        sc("C1 step 1s + replays", &|s| { s.step = Some(S); s.replay = true }),
        sc("C2 step 1min + replays", &|s| { s.step = Some(MIN); s.replay = true }),
        sc("C3 step 10min + replays", &|s| { s.step = Some(10 * MIN); s.replay = true }),
        sc("C4 step 1h + replays", &|s| { s.step = Some(HOUR); s.replay = true }),
        sc("C5 step 10min, honest", &|s| s.step = Some(10 * MIN)),
        sc("C6 step 1h, honest", &|s| s.step = Some(HOUR)),
    ];
    let variants = [
        Variant { name: "V0 as written", report2: false, watermark: false, dedupe_first: false },
        Variant { name: "V1 report@exp+2skew", report2: true, watermark: false, dedupe_first: false },
        Variant { name: "V2 prune watermark", report2: false, watermark: true, dedupe_first: false },
        Variant { name: "V3 both", report2: true, watermark: true, dedupe_first: false },
        Variant { name: "V4 V3 + dedupe first", report2: true, watermark: true, dedupe_first: true },
    ];
    println!("Deterministic cases:");
    let det_fail = deterministic();
    println!();
    println!("N = {} trials per cell; rates per million trials. skew = 5 min, ack/response loss 5 %,", n);
    println!("receiver up ~Exp(2 h) / down ~Exp(30 min), ttl log-uniform (5 min..24 h unless noted).");
    println!();
    println!("| scenario | variant | processed | double | told expired but processed (late confirm / EnvelopeExpired / all lost) | processed, never confirmed | response refused | spurious reject |");
    println!("|---|---|---|---|---|---|---|---|");
    for (si, s) in scenarios.iter().enumerate() {
        for v in variants.iter() {
            let mut t = Tally::default();
            for i in 0..n {
                // same seed across variants, so each variant sees the same world
                let seed = (i + 1).wrapping_mul(0x2545_F491_4F6C_DD1D) ^ ((si as u64 + 1) << 48);
                add(&mut t, &Trial::new(s, *v, seed).run());
            }
            println!(
                "| {} | {} | {} | {} | {} ({} / {} / {}) | {} | {} | {} |",
                s.name, v.name,
                per_m(t.processed, t.n), per_m(t.double, t.n),
                per_m(t.told_expired_and_processed, t.n), per_m(t.tep_late_confirm, t.n),
                per_m(t.tep_err_expired, t.n), per_m(t.tep_all_lost, t.n),
                per_m(t.processed_never_confirmed, t.n), per_m(t.refused_response, t.n),
                per_m(t.spurious_reject, t.n)
            );
        }
    }
    if det_fail > 0 {
        println!("deterministic expectation mismatch: {}", det_fail);
        std::process::exit(1);
    }
}
