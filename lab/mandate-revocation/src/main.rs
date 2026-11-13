//! Lab 2026-11-12: how long does a revoked S4 mandate stay usable at the cross-owner verifier C,
//! under capability/v0 §9 (draft on claude/issue-4-…, d07f078), and what does each fix cost honest traffic?
//!
//! Actors: A (principal, owner OA) runs the issuing node that signs mandates and OA's issuing-key revocation
//! lists. B holds a mandate from A and calls C (owner OC) under it. C is always on. A revokes B's mandate at
//! time r (A's node must be online: it holds the issuing key). From r on B is adversarial: it keeps calling C
//! every ~5 min and staples the newest list it fetched *before* r. k other honest holders of A mandates also
//! call C and staple their newest list.
//!
//! Lists are modelled by their signing time `iat` (a node bumps `seq` on every signing, so newer iat = higher
//! seq), `vu = iat + validity`, and `revoked = iat >= r`.
//!
//! Usage: mandate-revocation [trials]   (prints a TSV to stdout)

use std::fmt::Write as _;

const MIN: f64 = 60.0;
const H: f64 = 3600.0;
const D: f64 = 86400.0;
const HORIZON: f64 = 10.0 * D;
const EXEMPT_TTL: f64 = H; // REVOCATION_EXEMPT_TTL
const LIST_VALIDITY: f64 = 24.0 * H; // MAX_LIST_VALIDITY, what the issuing node uses
const B_CALL_MEAN: f64 = 5.0 * MIN;
const OTHER_CALL_MEAN: f64 = 30.0 * MIN;
const B_REFETCH: f64 = H; // holders refetch A's list hourly while A is reachable

// ---------------------------------------------------------------- rng
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn f(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
    fn u(&mut self, a: f64, b: f64) -> f64 {
        a + (b - a) * self.f()
    }
    fn exp(&mut self, mean: f64) -> f64 {
        -mean * (1.0 - self.f()).ln()
    }
}

// ---------------------------------------------------------------- availability of A's node
#[derive(Clone, Copy, Debug)]
enum Profile {
    Server, // always on
    Office, // weekdays ~9-18 (92 % of days), sometimes an evening session
    Laptop, // on Exp(2 h), off Exp(4 h)
}
impl Profile {
    fn name(self) -> &'static str {
        match self {
            Profile::Server => "server",
            Profile::Office => "office",
            Profile::Laptop => "laptop",
        }
    }
}

struct Avail {
    iv: Vec<(f64, f64)>, // sorted, disjoint
}
impl Avail {
    fn gen(p: Profile, rng: &mut Rng) -> Avail {
        let mut iv = Vec::new();
        match p {
            Profile::Server => iv.push((0.0, HORIZON + D)),
            Profile::Office => {
                for d in 0..11 {
                    let base = d as f64 * D;
                    if d % 7 < 5 && rng.f() < 0.92 {
                        let s = base + 9.0 * H + rng.u(-0.5 * H, 1.0 * H);
                        let e = base + 18.0 * H + rng.u(-1.0 * H, 1.5 * H);
                        iv.push((s, e));
                    }
                    if rng.f() < 0.10 {
                        iv.push((base + 20.0 * H, base + 22.0 * H));
                    }
                }
            }
            Profile::Laptop => {
                let mut t = -rng.exp(4.0 * H);
                let mut on = rng.f() < 1.0 / 3.0;
                while t < HORIZON + D {
                    let len = if on { rng.exp(2.0 * H) } else { rng.exp(4.0 * H) };
                    if on {
                        iv.push((t.max(0.0), t + len));
                    }
                    t += len;
                    on = !on;
                }
            }
        }
        iv.retain(|&(s, e)| e > s);
        Avail { iv }
    }
    fn online(&self, t: f64) -> bool {
        let i = self.iv.partition_point(|&(s, _)| s <= t);
        i > 0 && t < self.iv[i - 1].1
    }
    /// Uniform sample of an online instant in [a, b); None if A is never online there.
    fn sample_online(&self, a: f64, b: f64, rng: &mut Rng) -> Option<f64> {
        let mut segs = Vec::new();
        let mut tot = 0.0;
        for &(s, e) in &self.iv {
            let (s2, e2) = (s.max(a), e.min(b));
            if e2 > s2 {
                segs.push((s2, e2));
                tot += e2 - s2;
            }
        }
        if tot <= 0.0 {
            return None;
        }
        let mut x = rng.f() * tot;
        for (s, e) in segs {
            if x < e - s {
                return Some(s + x);
            }
            x -= e - s;
        }
        None
    }
    /// Latest hourly tick <= t at which A was online (holders' and directory's periodic refresh).
    fn last_tick(&self, t: f64, step: f64) -> Option<f64> {
        let mut k = (t / step).floor();
        while k >= 0.0 {
            let x = k * step;
            if self.online(x) {
                return Some(x);
            }
            k -= 1.0;
        }
        None
    }
}

// ---------------------------------------------------------------- lists
#[derive(Clone, Copy, Debug)]
struct List {
    iat: f64,
    vu: f64,
    revoked: bool,
}
fn sign(t: f64, r: f64, validity: f64) -> List {
    List { iat: t, vu: t + validity, revoked: t >= r }
}
fn newer(a: Option<List>, b: Option<List>) -> Option<List> {
    match (a, b) {
        (Some(x), Some(y)) => Some(if y.iat > x.iat { y } else { x }),
        (x, None) => x,
        (None, y) => y,
    }
}

// ---------------------------------------------------------------- policies at C (and A)
#[derive(Clone, Copy, Debug, PartialEq)]
enum Policy {
    /// capability/v0 §9 as written: stapled lists accepted (CAP-173), freshness = now <= validUntil (24 h),
    /// C fetches from A's node only when it holds no fresh list (and A is reachable).
    Spec,
    /// Spec + C re-pulls from A's node at most every 15 min on use, if A is reachable (soft).
    Pull15,
    /// Spec, but a list counts as fresh only while now - iat <= 1 h (stapled or fetched; fail closed).
    Hard1h,
    /// A's node uploads its list to OA's always-on host (relay / owner directory) hourly and at once on a
    /// revocation; C pulls it from there at most every 5 min on use. Validity stays 24 h (soft if A is down).
    Dir5,
    /// Spec + A's node pushes the new list to C (the grant's target owner) at revocation time.
    Push,
    /// Mandates only ever 1 h (exempt, no list needed), B renews at A every 50 min while A is reachable.
    Renew1h,
}
impl Policy {
    fn name(self) -> &'static str {
        match self {
            Policy::Spec => "spec",
            Policy::Pull15 => "pull15m",
            Policy::Hard1h => "hard1h",
            Policy::Dir5 => "dir5m",
            Policy::Push => "push",
            Policy::Renew1h => "renew1h",
        }
    }
}

struct C {
    held: Option<List>,
    last_pull: f64,
    fetches: u64,
}

enum Verdict {
    Accept,
    Revoked,
    Unavailable, // RevocationStatusUnavailable
}

struct Trial<'a> {
    pol: Policy,
    av: &'a Avail,
    r: f64,
    long: bool, // mandate TTL > REVOCATION_EXEMPT_TTL
}
impl<'a> Trial<'a> {
    fn fresh(&self, l: &List, t: f64) -> bool {
        match self.pol {
            Policy::Hard1h => t - l.iat <= H && t <= l.vu,
            _ => t <= l.vu,
        }
    }
    fn directory(&self, t: f64) -> Option<List> {
        let tick = self.av.last_tick(t, H).map(|x| sign(x, self.r, LIST_VALIDITY));
        let rev = if self.r <= t { Some(sign(self.r, self.r, LIST_VALIDITY)) } else { None };
        newer(tick, rev)
    }
    fn call(&self, c: &mut C, t: f64, staple: Option<List>) -> Verdict {
        c.held = newer(c.held, staple); // CAP-170/173: keep the highest seq
        let reachable = self.av.online(t);
        match self.pol {
            Policy::Pull15 if t - c.last_pull >= 15.0 * MIN && reachable => {
                c.held = newer(c.held, Some(sign(t, self.r, LIST_VALIDITY)));
                c.last_pull = t;
                c.fetches += 1;
            }
            Policy::Dir5 if t - c.last_pull >= 5.0 * MIN => {
                c.held = newer(c.held, self.directory(t));
                c.last_pull = t;
                c.fetches += 1;
            }
            _ => {}
        }
        if self.long && !c.held.map_or(false, |l| self.fresh(&l, t)) && reachable {
            let validity = LIST_VALIDITY;
            c.held = newer(c.held, Some(sign(t, self.r, validity)));
            c.fetches += 1;
        }
        if c.held.map_or(false, |l| l.revoked) {
            return Verdict::Revoked; // CAP-171: a stale list still proves what it lists
        }
        if self.long && !c.held.map_or(false, |l| self.fresh(&l, t)) {
            return Verdict::Unavailable;
        }
        Verdict::Accept
    }
}

#[derive(Default)]
struct Stats {
    trials: u64,
    window: Vec<f64>, // hours from r to the last accepted call by B (0 if none)
    remaining: f64,   // sum of (job end - r), hours
    with_calls: u64,  // trials in which B called at least once after r
    any_ok: u64,      // ... and at least one of those calls was accepted
    all_ok: u64,      // ... and every one was accepted (revocation had no effect)
    bad_accepted: u64,
    honest_calls: u64,
    honest_rejects: u64,
    honest_trials_hit: u64,
    fetches: u64,
    calls_total: u64,
}

#[derive(PartialEq, Clone, Copy)]
enum Ev {
    B,
    Other(usize),
    Push,
}

/// One trial. `malicious`: A revokes at r and B turns. Returns (B outcomes after r or all honest outcomes).
fn run(p: Profile, pol: Policy, ttl: f64, k: usize, malicious: bool, rng: &mut Rng, st: &mut Stats) {
    let av = Avail::gen(p, rng);
    // mint at a moment A is online during the first 7 days
    let m = match av.sample_online(0.0, 7.0 * D, rng) {
        Some(x) => x,
        None => return,
    };
    let job_end = m + ttl;
    // per-mandate TTL: Renew1h always uses 1 h mandates for a job of length `ttl`
    let mand_ttl = if pol == Policy::Renew1h { ttl.min(H) } else { ttl };
    let r = if malicious {
        match av.sample_online(m, job_end, rng) {
            Some(x) => x,
            None => return,
        }
    } else {
        f64::INFINITY
    };
    let tr = Trial { pol, av: &av, r, long: mand_ttl > EXEMPT_TTL };
    st.trials += 1;

    // events
    let mut evs: Vec<(f64, Ev)> = Vec::new();
    let mut t = m;
    loop {
        t += rng.exp(B_CALL_MEAN);
        if t >= job_end {
            break;
        }
        evs.push((t, Ev::B));
    }
    for i in 0..k {
        let mut t = m - rng.exp(OTHER_CALL_MEAN);
        loop {
            t += rng.exp(OTHER_CALL_MEAN);
            if t >= job_end {
                break;
            }
            if t >= m {
                evs.push((t, Ev::Other(i)));
            }
        }
    }
    if pol == Policy::Push && malicious {
        evs.push((r + 2.0, Ev::Push));
    }
    evs.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());

    // C has whatever the other holders stapled before m (their newest hourly list), else nothing
    let mut c = C { held: None, last_pull: f64::NEG_INFINITY, fetches: 0 };
    if k > 0 {
        c.held = av.last_tick(m, B_REFETCH).map(|x| sign(x, r, LIST_VALIDITY));
    }
    // B: list fetched at mint, then hourly refetch while A reachable, never at or after r
    let b_list = |t: f64| -> Option<List> {
        let lim = t.min(r - 1e-6);
        let tick = av.last_tick(lim, B_REFETCH).filter(|&x| x >= m).map(|x| sign(x, r, LIST_VALIDITY));
        newer(Some(sign(m, r, LIST_VALIDITY)), tick)
    };
    // Renew1h: B's current mandate expiry
    let mut b_exp = m + mand_ttl;
    let (mut n_after, mut n_ok, mut last_ok) = (0u64, 0u64, None::<f64>);
    let mut honest_hit = false;
    for (t, ev) in evs {
        match ev {
            Ev::Push => {
                c.held = newer(c.held, Some(sign(r, r, LIST_VALIDITY)));
            }
            Ev::Other(_) => {
                let s = av.last_tick(t, B_REFETCH).map(|x| sign(x, r, LIST_VALIDITY));
                let _ = tr.call(&mut c, t, s);
                st.calls_total += 1;
            }
            Ev::B => {
                if pol == Policy::Renew1h {
                    // renewal attempts every 5 min from 10 min before expiry, while A reachable and t < r
                    let mut x = b_exp - 10.0 * MIN;
                    while x <= t {
                        if x < r && av.online(x) {
                            b_exp = x + H;
                            x = b_exp - 10.0 * MIN;
                        } else {
                            x += 5.0 * MIN;
                        }
                    }
                }
                st.calls_total += 1;
                let v = if t > b_exp { Verdict::Unavailable } else { tr.call(&mut c, t, b_list(t)) };
                let ok = matches!(v, Verdict::Accept);
                if malicious {
                    if t >= r {
                        n_after += 1;
                        if ok {
                            n_ok += 1;
                            last_ok = Some(t);
                            st.bad_accepted += 1;
                        }
                    }
                } else {
                    st.honest_calls += 1;
                    if !ok {
                        st.honest_rejects += 1;
                        honest_hit = true;
                    }
                }
            }
        }
    }
    st.fetches += c.fetches;
    if malicious {
        st.remaining += (job_end - r) / H;
        st.window.push(last_ok.map_or(0.0, |x| (x - r) / H));
        if n_after > 0 {
            st.with_calls += 1;
            st.any_ok += (n_ok > 0) as u64;
            st.all_ok += (n_ok == n_after) as u64;
        }
    } else if honest_hit {
        st.honest_trials_hit += 1;
    }
}

fn pct(v: &mut [f64], q: f64) -> f64 {
    if v.is_empty() {
        return f64::NAN;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((v.len() as f64 - 1.0) * q).round() as usize]
}

fn main() {
    let n: u64 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(20000);
    let mut out = String::new();
    writeln!(
        out,
        "profile\tttl_h\tk\tpolicy\tbad_trials\twin_mean_h\twin_p50_h\twin_p90_h\twin_p99_h\tremaining_mean_h\twin_over_remaining\tany_ok_pct\tall_ok_pct\tbad_calls_accepted_mean\thonest_trials\thonest_reject_pct\thonest_trials_hit_pct\tfetches_per_call"
    )
    .unwrap();
    let mut seed = 1u64;
    for p in [Profile::Server, Profile::Office, Profile::Laptop] {
        for ttl_h in [1.0, 4.0, 24.0] {
            for k in [0usize, 5] {
                for pol in [Policy::Spec, Policy::Pull15, Policy::Hard1h, Policy::Dir5, Policy::Push, Policy::Renew1h] {
                    if pol == Policy::Renew1h && ttl_h <= 1.0 {
                        continue;
                    }
                    seed += 1;
                    let mut rng = Rng(seed.wrapping_mul(0x2545F4914F6CDD1D));
                    let mut bad = Stats::default();
                    let mut good = Stats::default();
                    for _ in 0..n {
                        run(p, pol, ttl_h * H, k, true, &mut rng, &mut bad);
                        run(p, pol, ttl_h * H, k, false, &mut rng, &mut good);
                    }
                    let ex_mean = bad.window.iter().sum::<f64>() / bad.window.len() as f64;
                    let ratio = bad.window.iter().sum::<f64>() / bad.remaining;
                    let p50 = pct(&mut bad.window, 0.5);
                    let p90 = pct(&mut bad.window, 0.9);
                    let p99 = pct(&mut bad.window, 0.99);
                    writeln!(
                        out,
                        "{}\t{}\t{}\t{}\t{}\t{:.3}\t{:.3}\t{:.3}\t{:.3}\t{:.3}\t{:.3}\t{:.2}\t{:.2}\t{:.2}\t{}\t{:.3}\t{:.2}\t{:.3}",
                        p.name(),
                        ttl_h,
                        k,
                        pol.name(),
                        bad.trials,
                        ex_mean,
                        p50,
                        p90,
                        p99,
                        bad.remaining / bad.trials as f64,
                        ratio,
                        100.0 * bad.any_ok as f64 / bad.with_calls.max(1) as f64,
                        100.0 * bad.all_ok as f64 / bad.with_calls.max(1) as f64,
                        bad.bad_accepted as f64 / bad.trials as f64,
                        good.trials,
                        100.0 * good.honest_rejects as f64 / good.honest_calls.max(1) as f64,
                        100.0 * good.honest_trials_hit as f64 / good.trials.max(1) as f64,
                        (bad.fetches + good.fetches) as f64 / (bad.calls_total + good.calls_total).max(1) as f64,
                    )
                    .unwrap();
                }
            }
        }
    }
    print!("{out}");
}
