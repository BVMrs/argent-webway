//! Lab 2026-11-11: mailbox/v0 host storage admission vs flooding senders.
//!
//! Model (one receiver R of owner B, its mailbox host M = B's relay, Q7 (a)):
//! - R is offline for D hours (t in [0, D)). M stores envelopes for R in a per-receiver budget of Q bytes and
//!   hands everything still stored (and unexpired) to R at t = D. Expired envelopes are freed at `exp`.
//! - H = 20 honest senders, one agent key and one capability root (principal) each. Daily honest demand is
//!   `load * Q` bytes, split uniformly or Zipf(1) over senders. Senders are online 8 h/day with a random phase
//!   ("office") or always ("always"), and only create envelopes while online. Size is log-uniform 512 B..90 KiB
//!   (64 KiB inline cap after base64, plus header); TTL (`exp - ts`) is log-uniform 1 h..7 d.
//! - Outbox: a new envelope is offered to M at once. On `MailboxFull` it stays in the per-destination outbox,
//!   which retries in order every 60 s while the sender is online, stopping at the first reject, until `exp`.
//!   After R returns, a still-pending envelope goes direct at the sender's next online instant if before `exp`
//!   ("late"), else it is reported `expired` to the sender ("visible expiry"). An envelope M accepted and later
//!   evicted is lost without any signal: the sender already got the ack ("silent loss").
//! - Attacker floods M for R at 20 Mbit/s with 90 KiB envelopes, `exp = ts + 7 d` (the profile cap), starting at
//!   U(0, D/2). Variants: `insider` (one key, one valid capability root from B), `sybil` (a fresh key and fresh
//!   owner per envelope, no capability from B), `fanout` (the insider re-delegates its root through the holder
//!   chain to a fresh key per envelope: many keys, one principal).
//!   The attacker stops its burst for a 10 s tick at the first reject, or when admitting would only evict its own
//!   envelopes (state-equivalent), which keeps event counts small without changing outcomes.
//! - Host policies:
//!   tail    global byte cap, reject (MailboxFull) when full
//!   oldest  global byte cap, evict oldest stored envelope (silent)
//!   keyq    per-sender-key cap Q/16 plus global cap, reject
//!   keylqd  per-sender-key longest-queue-drop: evict oldest of the key using most bytes (silent), reject if
//!           that is the incoming key
//!   g-*     gate first: admit only envelopes whose capability chain verifies to a root B issued (or a pinned
//!           contact); principal = that root. Then:
//!   g-tail  global cap, reject
//!   g-lqd   longest-queue-drop per principal (silent)
//!   g-resv  per-principal reservation Q/(2N) (N = principals B knows = 21) plus a shared pool Q/2 with a
//!           per-principal pool cap Q/8; reject, never evict
//!   g-resv4 as g-resv with a per-principal pool cap Q/4
//!
//! Metrics over honest envelopes created during the outage whose `exp` > D (an infinite mailbox delivers all):
//!   ret    delivered from the mailbox at t = D
//!   late   delivered directly after D (mean delay reported)
//!   vexp   reported expired to the sender
//!   silent accepted by M, then evicted: lost with no signal
//!   rej    fraction not stored on first offer (answered MailboxFull, or queued behind such an envelope)

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, VecDeque};

const H: usize = 20;
const NPRIN: usize = H + 1;
const DAY: f64 = 86400.0;
const HOUR: f64 = 3600.0;
const DT: f64 = 10.0;
const RETRY: f64 = 60.0;
const SMIN: f64 = 512.0;
const SMAX: f64 = 92160.0;
const ATK_SIZE: u64 = 92160;
const ATK_RATE: f64 = 2.5e6;
const Q: u64 = 64 << 20;

#[derive(Clone, Copy, PartialEq, Debug)]
enum Policy {
    Tail,
    Oldest,
    KeyQ,
    KeyLqd,
    GTail,
    GLqd,
    GResv,
    GResv4,
}
const POLICIES: [Policy; 8] = [
    Policy::Tail,
    Policy::Oldest,
    Policy::KeyQ,
    Policy::KeyLqd,
    Policy::GTail,
    Policy::GLqd,
    Policy::GResv,
    Policy::GResv4,
];
impl Policy {
    fn name(self) -> &'static str {
        match self {
            Policy::Tail => "tail",
            Policy::Oldest => "oldest",
            Policy::KeyQ => "keyq",
            Policy::KeyLqd => "keylqd",
            Policy::GTail => "g-tail",
            Policy::GLqd => "g-lqd",
            Policy::GResv => "g-resv",
            Policy::GResv4 => "g-resv4",
        }
    }
    fn gated(self) -> bool {
        matches!(self, Policy::GTail | Policy::GLqd | Policy::GResv | Policy::GResv4)
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Attack {
    None,
    Insider,
    Sybil,
    Fanout,
}
const ATTACKS: [Attack; 4] = [Attack::None, Attack::Insider, Attack::Sybil, Attack::Fanout];
impl Attack {
    fn name(self) -> &'static str {
        match self {
            Attack::None => "none",
            Attack::Insider => "insider",
            Attack::Sybil => "sybil",
            Attack::Fanout => "fanout",
        }
    }
}

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
    fn logu(&mut self, a: f64, b: f64) -> f64 {
        (a.ln() + self.f() * (b.ln() - a.ln())).exp()
    }
    fn poisson(&mut self, l: f64) -> u32 {
        let e = (-l).exp();
        let mut k = 0;
        let mut p = self.f();
        while p > e {
            k += 1;
            p *= self.f();
        }
        k
    }
}

struct Item {
    alive: bool,
    key: u64,
    principal: Option<usize>,
    size: u64,
    atk: bool,
    henv: usize,
    pool: u64,
}

enum Admit {
    Ok(usize),
    Reject,
    Futile,
}

struct Host {
    policy: Policy,
    items: Vec<Item>,
    used: u64,
    by_key: HashMap<u64, u64>,
    by_prin: [u64; NPRIN],
    pool_used: u64,
    pool_by_prin: [u64; NPRIN],
    heap: BinaryHeap<Reverse<(u64, usize)>>,
    fifo: VecDeque<usize>,
    flows: HashMap<u64, VecDeque<usize>>,
    evicted: Vec<usize>,
}

impl Host {
    fn new(policy: Policy) -> Self {
        Host {
            policy,
            items: Vec::new(),
            used: 0,
            by_key: HashMap::new(),
            by_prin: [0; NPRIN],
            pool_used: 0,
            pool_by_prin: [0; NPRIN],
            heap: BinaryHeap::new(),
            fifo: VecDeque::new(),
            flows: HashMap::new(),
            evicted: Vec::new(),
        }
    }

    fn flow_of(&self, key: u64, principal: Option<usize>) -> u64 {
        match self.policy {
            Policy::GLqd => principal.unwrap() as u64,
            _ => key,
        }
    }

    fn free(&mut self, slot: usize) {
        let it = &mut self.items[slot];
        it.alive = false;
        self.used -= it.size;
        let k = self.by_key.get_mut(&it.key).unwrap();
        *k -= it.size;
        if *k == 0 {
            self.by_key.remove(&it.key);
        }
        if let Some(p) = it.principal {
            self.by_prin[p] -= it.size;
            self.pool_by_prin[p] -= it.pool;
            self.pool_used -= it.pool;
        }
    }

    fn evict(&mut self, slot: usize) {
        self.free(slot);
        if !self.items[slot].atk {
            self.evicted.push(self.items[slot].henv);
        }
    }

    fn gc(&mut self, now: f64) {
        while let Some(&Reverse((eb, slot))) = self.heap.peek() {
            if f64::from_bits(eb) > now {
                break;
            }
            self.heap.pop();
            if self.items[slot].alive {
                self.free(slot);
            }
        }
    }

    fn front_alive(dq: &mut VecDeque<usize>, items: &[Item]) -> Option<usize> {
        while let Some(&s) = dq.front() {
            if items[s].alive {
                return Some(s);
            }
            dq.pop_front();
        }
        None
    }

    fn admit(&mut self, key: u64, principal: Option<usize>, size: u64, exp: f64, atk: bool, henv: usize) -> Admit {
        if self.policy.gated() && principal.is_none() {
            return Admit::Reject;
        }
        let mut pool = 0;
        match self.policy {
            Policy::Tail | Policy::GTail => {
                if self.used + size > Q {
                    return Admit::Reject;
                }
            }
            Policy::KeyQ => {
                let k = *self.by_key.get(&key).unwrap_or(&0);
                if k + size > Q / 16 || self.used + size > Q {
                    return Admit::Reject;
                }
            }
            Policy::Oldest => {
                while self.used + size > Q {
                    let v = Self::front_alive(&mut self.fifo, &self.items).unwrap();
                    if self.items[v].atk && atk {
                        return Admit::Futile;
                    }
                    self.evict(v);
                }
            }
            Policy::KeyLqd | Policy::GLqd => {
                let f = self.flow_of(key, principal);
                while self.used + size > Q {
                    // usage per flow, the incoming flow counted with the new envelope
                    let (mut best, mut bu) = (f, self.flow_usage(f) + size);
                    let cands: Vec<(u64, u64)> = match self.policy {
                        Policy::GLqd => (0..NPRIN).map(|p| (p as u64, self.by_prin[p])).collect(),
                        _ => self.by_key.iter().map(|(&k, &u)| (k, u)).collect(),
                    };
                    for (g, u) in cands {
                        if g != f && u > bu {
                            best = g;
                            bu = u;
                        }
                    }
                    if best == f {
                        return Admit::Reject;
                    }
                    let dq = self.flows.get_mut(&best).unwrap();
                    let v = Self::front_alive(dq, &self.items).unwrap();
                    if self.items[v].atk && atk {
                        return Admit::Futile;
                    }
                    self.evict(v);
                }
            }
            Policy::GResv | Policy::GResv4 => {
                let pcap = if self.policy == Policy::GResv { Q / 8 } else { Q / 4 };
                let p = principal.unwrap();
                let g = Q / (2 * NPRIN as u64);
                let reserved_use = self.by_prin[p] - self.pool_by_prin[p];
                if reserved_use + size <= g {
                    pool = 0;
                } else if self.pool_used + size <= Q / 2 && self.pool_by_prin[p] + size <= pcap {
                    pool = size;
                } else {
                    return Admit::Reject;
                }
            }
        }
        let slot = self.items.len();
        self.items.push(Item { alive: true, key, principal, size, atk, henv, pool });
        self.used += size;
        *self.by_key.entry(key).or_insert(0) += size;
        if let Some(p) = principal {
            self.by_prin[p] += size;
            self.pool_by_prin[p] += pool;
            self.pool_used += pool;
        }
        self.heap.push(Reverse((exp.to_bits(), slot)));
        match self.policy {
            Policy::Oldest => self.fifo.push_back(slot),
            Policy::KeyLqd | Policy::GLqd => {
                let f = self.flow_of(key, principal);
                self.flows.entry(f).or_default().push_back(slot)
            }
            _ => {}
        }
        Admit::Ok(slot)
    }

    fn flow_usage(&self, f: u64) -> u64 {
        match self.policy {
            Policy::GLqd => self.by_prin[f as usize],
            _ => *self.by_key.get(&f).unwrap_or(&0),
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum St {
    Pending,
    Stored(usize),
    Evicted,
    Dropped,
}

struct HEnv {
    sender: usize,
    size: u64,
    exp: f64,
    st: St,
    rejected: bool,
}

#[derive(Default, Clone)]
struct Stats {
    deliverable: u64,
    ret: u64,
    late: u64,
    late_delay: f64,
    vexp: u64,
    silent: u64,
    rej: u64,
    trials: u64,
    atk_share_end: f64,
}

#[derive(Clone, Copy)]
struct Cell {
    policy: Policy,
    attack: Attack,
    d_hours: f64,
    zipf: bool,
    load: f64,
    office: bool,
}

fn online(office: bool, phase: f64, t: f64) -> bool {
    !office || (t + phase).rem_euclid(DAY) < 8.0 * HOUR
}

fn next_online(office: bool, phase: f64, t: f64) -> f64 {
    if online(office, phase, t) {
        t
    } else {
        t + DAY - (t + phase).rem_euclid(DAY)
    }
}

fn trial(c: Cell, seed: u64, s: &mut Stats) {
    let mut rng = Rng(seed);
    let d = c.d_hours * HOUR;
    let phases: Vec<f64> = (0..H).map(|_| rng.f() * DAY).collect();
    let w: Vec<f64> = (0..H).map(|i| if c.zipf { 1.0 / (i as f64 + 1.0) } else { 1.0 }).collect();
    let ws: f64 = w.iter().sum();
    let mean_size = (SMAX - SMIN) / (SMAX / SMIN).ln();
    let frac = if c.office { 8.0 / 24.0 } else { 1.0 };
    let rate: Vec<f64> =
        w.iter().map(|wi| c.load * Q as f64 * wi / ws / mean_size / (frac * DAY)).collect();

    let mut host = Host::new(c.policy);
    let mut henvs: Vec<HEnv> = Vec::new();
    let mut pending: Vec<VecDeque<usize>> = vec![VecDeque::new(); H];
    let mut next_retry = vec![0.0f64; H];
    let atk_start = rng.f() * d / 2.0;
    let mut budget = 0.0f64;
    let mut fresh: u64 = 1 << 40;

    let mut t = 0.0;
    while t < d {
        host.gc(t);
        for i in 0..H {
            if !online(c.office, phases[i], t) {
                continue;
            }
            // retries, in outbox order, stop at the first reject
            if t >= next_retry[i] && !pending[i].is_empty() {
                next_retry[i] = t + RETRY;
                while let Some(&e) = pending[i].front() {
                    if henvs[e].exp <= t {
                        henvs[e].st = St::Dropped;
                        pending[i].pop_front();
                        continue;
                    }
                    match host.admit(i as u64, Some(i), henvs[e].size, henvs[e].exp, false, e) {
                        Admit::Ok(slot) => {
                            henvs[e].st = St::Stored(slot);
                            pending[i].pop_front();
                        }
                        _ => {
                            henvs[e].rejected = true;
                            break;
                        }
                    }
                }
            }
            for _ in 0..rng.poisson(rate[i] * DT) {
                let size = rng.logu(SMIN, SMAX) as u64;
                let exp = t + rng.logu(HOUR, 7.0 * DAY);
                let e = henvs.len();
                henvs.push(HEnv { sender: i, size, exp, st: St::Pending, rejected: false });
                if !pending[i].is_empty() {
                    henvs[e].rejected = true; // queued behind a rejected envelope: not stored on first offer
                    pending[i].push_back(e);
                    continue;
                }
                match host.admit(i as u64, Some(i), size, exp, false, e) {
                    Admit::Ok(slot) => henvs[e].st = St::Stored(slot),
                    _ => {
                        henvs[e].rejected = true;
                        pending[i].push_back(e);
                        next_retry[i] = t + RETRY;
                    }
                }
            }
        }
        for e in host.evicted.drain(..) {
            henvs[e].st = St::Evicted;
        }
        if c.attack != Attack::None && t >= atk_start {
            budget = (budget + ATK_RATE * DT).min(2.0 * ATK_RATE * DT);
            while budget >= ATK_SIZE as f64 {
                let (key, prin) = match c.attack {
                    Attack::Insider => (1u64 << 39, Some(H)),
                    Attack::Sybil => {
                        fresh += 1;
                        (fresh, None)
                    }
                    Attack::Fanout => {
                        fresh += 1;
                        (fresh, Some(H))
                    }
                    Attack::None => unreachable!(),
                };
                match host.admit(key, prin, ATK_SIZE, t + 7.0 * DAY, true, usize::MAX) {
                    Admit::Ok(_) => budget -= ATK_SIZE as f64,
                    _ => {
                        budget = 0.0;
                        break;
                    }
                }
            }
            for e in host.evicted.drain(..) {
                henvs[e].st = St::Evicted;
            }
        }
        t += DT;
    }

    let atk_bytes: u64 = host.items.iter().filter(|it| it.alive && it.atk).map(|it| it.size).sum();
    s.atk_share_end += atk_bytes as f64 / Q as f64;
    s.trials += 1;
    for h in &henvs {
        if h.exp <= d {
            continue;
        }
        s.deliverable += 1;
        if h.rejected {
            s.rej += 1;
        }
        match h.st {
            St::Stored(slot) => {
                assert!(host.items[slot].alive);
                s.ret += 1
            }
            St::Evicted => s.silent += 1,
            St::Pending => {
                let td = next_online(c.office, phases[h.sender], d);
                if td < h.exp {
                    s.late += 1;
                    s.late_delay += td - d;
                } else {
                    s.vexp += 1;
                }
            }
            St::Dropped => unreachable!(),
        }
    }
}

fn run(cells: &[Cell], trials: u64, seed: u64) -> Vec<Stats> {
    let n = std::thread::available_parallelism().map(|x| x.get()).unwrap_or(1);
    let mut out = vec![Stats::default(); cells.len()];
    std::thread::scope(|sc| {
        let chunks: Vec<_> = out.chunks_mut(cells.len().div_ceil(n)).enumerate().collect();
        let step = cells.len().div_ceil(n);
        for (ci, chunk) in chunks {
            sc.spawn(move || {
                for (j, st) in chunk.iter_mut().enumerate() {
                    let idx = ci * step + j;
                    for k in 0..trials {
                        // common random numbers across policies/attacks for the same (D, skew, trial)
                        let c = cells[idx];
                        let base = seed
                            ^ ((c.d_hours as u64) << 32)
                            ^ ((c.zipf as u64) << 48)
                            ^ ((c.office as u64) << 50)
                            ^ ((c.load * 10.0) as u64) << 52;
                        trial(c, base.wrapping_mul(1_000_003).wrapping_add(k), st);
                    }
                }
            });
        }
    });
    out
}

fn pct(a: u64, b: u64) -> f64 {
    if b == 0 {
        0.0
    } else {
        100.0 * a as f64 / b as f64
    }
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "main".into());
    let trials: u64 = std::env::args().nth(2).and_then(|x| x.parse().ok()).unwrap_or(200);
    let mut cells = Vec::new();
    let (seed, attacks, loads, offices): (u64, Vec<Attack>, Vec<f64>, Vec<bool>) = match mode.as_str() {
        "main" => (1, ATTACKS.to_vec(), vec![0.3], vec![true]),
        "sens" => (2, vec![Attack::None, Attack::Insider], vec![0.3, 1.0], vec![true, false]),
        _ => panic!("mode: main | sens"),
    };
    for &load in &loads {
        for &office in &offices {
            if mode == "sens" && load == 0.3 && office {
                continue;
            }
            for &d_hours in &[8.0, 24.0, 72.0] {
                for &zipf in &[false, true] {
                    for &attack in &attacks {
                        for &policy in &POLICIES {
                            cells.push(Cell { policy, attack, d_hours, zipf, load, office });
                        }
                    }
                }
            }
        }
    }
    let res = run(&cells, trials, seed);
    println!("load\tsenders\tD_h\tskew\tattack\tpolicy\tdeliverable\tret%\tlate%\tlate_mean_h\tvexp%\tsilent%\trej%\tatk_fill%");
    for (c, s) in cells.iter().zip(res.iter()) {
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:.2}\t{:.2}\t{:.2}\t{:.3}\t{:.3}\t{:.2}\t{:.1}",
            c.load,
            if c.office { "office" } else { "always" },
            c.d_hours,
            if c.zipf { "zipf" } else { "uniform" },
            c.attack.name(),
            c.policy.name(),
            s.deliverable,
            pct(s.ret, s.deliverable),
            pct(s.late, s.deliverable),
            if s.late > 0 { s.late_delay / s.late as f64 / HOUR } else { 0.0 },
            pct(s.vexp, s.deliverable),
            pct(s.silent, s.deliverable),
            pct(s.rej, s.deliverable),
            100.0 * s.atk_share_end / s.trials as f64,
        );
    }
}
