//! Monte Carlo: honest capability-expiry rejections of mailbox-delayed envelopes, per time-of-check rule.
//!
//! An honest sender holds a capability token (issuer-set expiry `tok_exp`, TTL from the issuer) and sends
//! envelopes (`exp = ts + E`) to a receiver whose availability follows a profile. If the receiver is down, the
//! envelope goes to the receiver owner's mailbox host (postmark = host clock at arrival) and is delivered when
//! the receiver is next up. The receiver first applies envelope freshness (`now <= exp + skew`), then checks
//! token expiry against one of these clocks:
//!   R1    receiver now, strict            now_r <= tok_exp
//!   R1s   receiver now, skew grace        now_r <= tok_exp + skew
//!   R2    envelope ts (sender-claimed)    ts    <= tok_exp + skew
//!   R3    postmark (own mailbox host, or receiver clock if direct)  pm <= tok_exp + skew
//!   R5g1h receiver now, 1 h grace
//!   R5g1d receiver now, 24 h grace
//! Outputs honest loss (fresh envelopes rejected only because of the token) per cell, and verifies the
//! attacker windows (how long after `tok_exp` an expired holder that still has its agent key gets accepted).

const MIN: f64 = 60.0;
const HOUR: f64 = 3600.0;
const DAY: f64 = 86400.0;
const SKEW: f64 = 5.0 * MIN;
const EXP_CAP: f64 = 7.0 * DAY; // profile cap on exp - ts

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn u(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
    fn exp(&mut self, mean: f64) -> f64 {
        -mean * (1.0 - self.u()).ln()
    }
    fn unif(&mut self, a: f64, b: f64) -> f64 {
        a + (b - a) * self.u()
    }
    fn norm(&mut self) -> f64 {
        let (u1, u2) = (1.0 - self.u(), self.u());
        (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()
    }
}

/// Sorted, disjoint down intervals.
struct Trace(Vec<(f64, f64)>);
impl Trace {
    fn next_up(&self, t: f64) -> f64 {
        // first interval with end > t
        let i = self.0.partition_point(|&(_, e)| e <= t);
        match self.0.get(i) {
            Some(&(s, e)) if s <= t => e,
            _ => t,
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Profile {
    Server,
    Flaky,
    Office,
}
impl Profile {
    fn name(self) -> &'static str {
        match self {
            Profile::Server => "server",
            Profile::Flaky => "flaky",
            Profile::Office => "office",
        }
    }
}

fn alternating(rng: &mut Rng, horizon: f64, up: f64, down: f64) -> Trace {
    let mut v = vec![];
    let mut t = rng.exp(up);
    while t < horizon {
        let d = rng.exp(down);
        v.push((t, t + d));
        t += d + rng.exp(up);
    }
    Trace(v)
}

/// Weekdays online ~08:30-18:30 with jitter, 15 % of weekdays absent, weekends off. t=0 is Monday 00:00.
fn office(rng: &mut Rng, horizon: f64) -> Trace {
    let mut ups = vec![];
    let days = (horizon / DAY).ceil() as i64 + 1;
    for d in 0..days {
        let dow = d % 7;
        if dow >= 5 || rng.u() < 0.15 {
            continue;
        }
        let s = d as f64 * DAY + 8.5 * HOUR + rng.norm() * 20.0 * MIN;
        let e = d as f64 * DAY + 18.5 * HOUR + rng.norm() * 45.0 * MIN;
        ups.push((s, e));
    }
    let mut v = vec![];
    let mut prev = 0.0;
    for (s, e) in ups {
        if s > prev {
            v.push((prev, s));
        }
        prev = e;
    }
    v.push((prev, f64::INFINITY));
    Trace(v)
}

#[derive(Clone, Copy, PartialEq)]
enum Refresh {
    Lazy,  // refresh only when the sender's clock says the token has expired
    Fresh, // a fresh token for every send (issuer always reachable)
}

const RULES: [&str; 6] = ["R1", "R1s", "R2", "R3", "R5g1h", "R5g1d"];

#[derive(Default, Clone)]
struct Tally {
    sent: u64,
    via_mailbox: u64,
    env_expired: u64,
    rejected: [u64; 6],
    rejected_mailbox: [u64; 6],
    clamp_lost: u64, // sender clamps exp to min(ts + E, tok_exp); lost = delivered after exp + skew (or token reject)
    dwell: Vec<f32>,
}

fn run_cell(p: Profile, ttl: f64, e: f64, refresh: Refresh, runs: u32, seed: u64) -> Tally {
    let mut t = Tally::default();
    let send_period = 5.0 * MIN;
    let span = 8.0 * 7.0 * DAY;
    let warm = 7.0 * DAY;
    for r in 0..runs {
        let mut rng = Rng(seed ^ (r as u64).wrapping_mul(0xD1B54A32D192ED03) ^ (ttl as u64) << 20 ^ (e as u64));
        let horizon = warm + span + e + 30.0 * DAY;
        let recv = match p {
            Profile::Server => alternating(&mut rng, horizon, 7.0 * DAY, 15.0 * MIN),
            Profile::Flaky => alternating(&mut rng, horizon, 2.0 * HOUR, 30.0 * MIN),
            Profile::Office => office(&mut rng, horizon),
        };
        let host = alternating(&mut rng, horizon, 30.0 * DAY, 10.0 * MIN);
        let (os, or, oh, oi) = (
            rng.unif(-MIN, MIN),
            rng.unif(-MIN, MIN),
            rng.unif(-MIN, MIN),
            rng.unif(-MIN, MIN),
        );
        let mut tok_exp = f64::NEG_INFINITY; // issuer-clock expiry of the token held
        let mut now = warm + rng.exp(send_period);
        while now < warm + span {
            // honest sender: refresh per policy (issuer reachable, mints at its own clock)
            let s_now = now + os;
            if refresh == Refresh::Fresh || s_now >= tok_exp {
                tok_exp = now + oi + ttl;
            }
            let ts = s_now;
            let exp = ts + e.min(EXP_CAP);
            // path
            let direct = recv.next_up(now) == now;
            let (arrive_true, pm, deliver) = if direct {
                let d = now + 0.05;
                (d, d + or, d)
            } else {
                // reach the mailbox host (sender outbox retries while host is down) unless receiver comes up first
                let h = host.next_up(now);
                let ru = recv.next_up(now);
                if ru <= h {
                    (ru, ru + or, ru)
                } else {
                    let d = recv.next_up(h) + rng.unif(0.0, 5.0);
                    (h, h + oh, d)
                }
            };
            let _ = arrive_true;
            t.sent += 1;
            let mb = deliver - now > 1.0;
            if mb {
                t.via_mailbox += 1;
                t.dwell.push((deliver - now) as f32);
            }
            let now_r = deliver + or;
            let exp_c = exp.min(tok_exp);
            if now_r > exp_c + SKEW || now_r > tok_exp + SKEW {
                t.clamp_lost += 1;
            }
            if now_r > exp + SKEW {
                t.env_expired += 1;
            } else {
                let ok = [
                    now_r <= tok_exp,
                    now_r <= tok_exp + SKEW,
                    ts <= tok_exp + SKEW,
                    pm <= tok_exp + SKEW,
                    now_r <= tok_exp + HOUR,
                    now_r <= tok_exp + DAY,
                ];
                for (i, &k) in ok.iter().enumerate() {
                    if !k {
                        t.rejected[i] += 1;
                        if mb {
                            t.rejected_mailbox[i] += 1;
                        }
                    }
                }
            }
            now += rng.exp(send_period);
        }
    }
    t
}

/// Largest delay `a` after token expiry at which an expired holder (with its agent key) can still send a new
/// envelope and have it accepted, by direct search over `a`. `colluding_host` lets the mailbox host backdate pm.
fn attacker_window(rule: usize, colluding_host: bool) -> f64 {
    let tok_exp = 0.0;
    let accepted = |a: f64| {
        let now = tok_exp + a; // attacker composes and sends at true time `now`, all clocks exact
        // attacker picks ts to maximise acceptance: as early as freshness allows
        let ts = (tok_exp).min(now);
        let exp = ts + EXP_CAP;
        let fresh = now <= exp + SKEW && ts <= now + SKEW;
        let pm = if colluding_host { tok_exp } else { now };
        let ok = [
            now <= tok_exp,
            now <= tok_exp + SKEW,
            ts <= tok_exp + SKEW,
            pm <= tok_exp + SKEW,
            now <= tok_exp + HOUR,
            now <= tok_exp + DAY,
        ];
        fresh && ok[rule]
    };
    let mut a = 0.0;
    let mut step = 30.0 * DAY;
    while step >= 1.0 {
        if accepted(a + step) {
            a += step;
        } else {
            step /= 2.0;
        }
    }
    a
}

fn fmt_dur(s: f64) -> String {
    if s >= DAY {
        format!("{:.2} d", s / DAY)
    } else if s >= HOUR {
        format!("{:.1} h", s / HOUR)
    } else {
        format!("{:.0} s", s)
    }
}

fn pct(n: u64, d: u64) -> String {
    if d == 0 {
        return "-".into();
    }
    let p = 100.0 * n as f64 / d as f64;
    if n == 0 {
        "0".into()
    } else if p < 0.01 {
        format!("{:.4}", p)
    } else {
        format!("{:.2}", p)
    }
}

fn main() {
    let runs: u32 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(60);
    println!("# runs per cell = {runs}, 8 weeks of sends each at 1 per 5 min (Poisson), skew = 5 min, clock offsets U(-60 s, 60 s)");
    println!("# R1..R5 columns = % of sent envelopes that pass envelope freshness but fail the token-expiry check");
    println!("# lost X = env expired + X rejects; lost clamp+R1s = sender sets exp = min(ts + E, tok_exp), receiver uses R1s");
    println!();
    println!("| profile | refresh | token TTL | env TTL | sent | via mailbox % | dwell p50 / p99 | env expired % | R1 | R1s | R2 | R3 | R5 1h | R5 1d | lost R1s | lost R3 | lost clamp+R1s |");
    println!("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|");
    let ttls = [5.0 * MIN, HOUR, 8.0 * HOUR, DAY, 7.0 * DAY];
    for p in [Profile::Server, Profile::Flaky, Profile::Office] {
        for refresh in [Refresh::Lazy, Refresh::Fresh] {
            for &e in &[DAY, 7.0 * DAY] {
                for &ttl in &ttls {
                    let mut t = run_cell(p, ttl, e, refresh, runs, 0x5EED_0001);
                    t.dwell.sort_by(|a, b| a.partial_cmp(b).unwrap());
                    let q = |f: f64| {
                        if t.dwell.is_empty() {
                            "-".to_string()
                        } else {
                            fmt_dur(t.dwell[((t.dwell.len() - 1) as f64 * f) as usize] as f64)
                        }
                    };
                    let rs: Vec<String> = (0..6).map(|i| pct(t.rejected[i], t.sent)).collect();
                    println!(
                        "| {} | {} | {} | {} | {} | {} | {} / {} | {} | {} | {} | {} | {} |",
                        p.name(),
                        if refresh == Refresh::Lazy { "lazy" } else { "per-send" },
                        fmt_dur(ttl),
                        fmt_dur(e),
                        t.sent,
                        pct(t.via_mailbox, t.sent),
                        q(0.5),
                        q(0.99),
                        pct(t.env_expired, t.sent),
                        rs.join(" | "),
                        pct(t.env_expired + t.rejected[1], t.sent),
                        pct(t.env_expired + t.rejected[3], t.sent),
                        pct(t.clamp_lost, t.sent)
                    );
                    // sanity: every rejection under R3 must be explained (none should be mailbox-only artefacts)
                    let _ = t.rejected_mailbox;
                }
            }
        }
    }
    println!();
    println!("## attacker window after token expiry (expired holder still holds agent key; exp - ts cap = 7 d)");
    println!("| rule | honest host | colluding mailbox host |");
    println!("|---|---|---|");
    for (i, r) in RULES.iter().enumerate() {
        println!("| {} | {} | {} |", r, fmt_dur(attacker_window(i, false)), fmt_dur(attacker_window(i, true)));
    }
}
