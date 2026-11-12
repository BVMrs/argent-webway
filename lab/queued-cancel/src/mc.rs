//! Monte Carlo timing model: requester R sends create C at t = 0 to receiver S, which is offline
//! for D seconds. R decides to cancel at t_i ~ U(0, D) (the task is still queued).
//!
//! R's outbox tries S directly; while S is offline an attempt fails and the envelope is handed to
//! S's mailbox host M (hand-off fails with p_hf, retried at the next attempt). The outbox keeps
//! retrying until R holds a reply (mailbox/v0, M1 step 6). Timers: per-envelope "equal jitter"
//! backoff (1 s base, x2, cap 60 s) or one per-destination timer that sends every pending envelope
//! at each firing (the outbox-retry-herd recommendation). M drains its queue to S after S reconnects
//! (0.1-1 s reconnect, then 5 ms per queued envelope behind a backlog of other senders). Each
//! envelope reaching S finishes processing after U(2, 20) ms (verify + group commit), so envelopes
//! that arrive together may be processed in either order.
//!
//! A created task starts work 100 ms later and completes after a lognormal time (median 120 s).
//! Replies to R go direct while R is online; if R is offline they wait in R's mailbox until R is back.

use std::cmp::Ordering;
use std::collections::BinaryHeap;

use crate::rng::Rng;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Design { D0, D1, D2, D3 }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Timer { PerEnv, PerDest }

#[derive(Clone, Copy, Debug)]
pub struct Profile {
    pub name: &'static str,
    pub d_lo: f64,
    pub d_hi: f64,
    pub d_exp_mean: f64, // > 0: exponential instead of uniform
    pub backlog_hi: f64,
}

#[derive(Clone, Copy, Debug)]
pub struct Cell {
    pub design: Design,
    pub timer: Timer,
    pub profile: Profile,
    pub r_goes_offline: bool,
    pub x_ttl_short: bool, // X.exp = send + 5 min; otherwise X.exp = C.exp
    pub p_hf: f64,
    pub m_serial: bool, // M drains stop-and-wait (next envelope after S acks the previous)
}

const C_TTL: f64 = 24.0 * 3600.0;
const X_TTL_SHORT: f64 = 300.0;
const SKEW: f64 = 300.0;
const OWD: f64 = 0.030;

#[derive(Clone, Copy, PartialEq, Debug)]
enum Ev {
    Attempt(usize),      // per-envelope timer firing for envelope i
    DestTimer,           // per-destination timer firing
    MStart,              // M starts draining after S reconnects
    MDeliver(usize),     // M pushes envelope i to S
    SArrive(usize, bool),
    SProc(usize, bool),  // bool: delivered by M
    Work,
    Finish,
    RRecv(usize, Reply), // R receives the reply to envelope i
    Intent,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Reply { Created, CreatedCanceled, Canceled, NotCancelable, NotFound, NotFoundRetry, Pending }

struct Item { t: f64, seq: u64, ev: Ev }
impl PartialEq for Item { fn eq(&self, o: &Self) -> bool { self.t == o.t && self.seq == o.seq } }
impl Eq for Item {}
impl PartialOrd for Item { fn partial_cmp(&self, o: &Self) -> Option<Ordering> { Some(self.cmp(o)) } }
impl Ord for Item {
    fn cmp(&self, o: &Self) -> Ordering {
        o.t.partial_cmp(&self.t).unwrap().then(o.seq.cmp(&self.seq))
    }
}

#[derive(Clone)]
struct Envl {
    is_c: bool,

    exp: f64,
    acked: bool,
    handed: bool,
    k: u32,
    processed: bool, // dedupe entry with a stored final answer
}

#[derive(Default, Clone, Debug)]
pub struct Out {
    pub n: u64,
    pub work_started: u64,
    pub completed: u64,
    pub canceled: u64,
    pub lost: u64,
    pub x_expired: u64,
    pub misled: u64,
    pub uncertain: u64,
    pub work_secs: f64,
    pub r_sends: u64,
}

struct Sim<'a> {
    cell: Cell,
    rng: &'a mut Rng,
    q: BinaryHeap<Item>,
    seq: u64,
    d: f64,
    r_off_at: f64,
    r_back: f64,

    envs: Vec<Envl>,
    task: u8, // 0 none, 1 sub, 2 work, 3 done, 4 canc
    tomb_until: f64,
    deferred: bool,
    dest_k: u32,
    dest_armed: bool,
    work_start: f64,
    x_live_arrival: bool,
    x_ever_sent: bool,
    belief: Option<Reply>,
    work_secs: f64,
    sends: u64,
    finish_at: f64,

    m_queue: Vec<usize>,
    m_next: usize,
}

impl<'a> Sim<'a> {
    fn push(&mut self, t: f64, ev: Ev) { self.seq += 1; self.q.push(Item { t, seq: self.seq, ev }); }
    fn r_online(&self, t: f64) -> bool { !(t >= self.r_off_at && t < self.r_back) }
    fn s_online(&self, t: f64) -> bool { t >= self.d }
    fn backoff(&mut self, k: u32) -> f64 {
        let b = (2f64.powi(k as i32)).min(60.0);
        b * self.rng.range(0.5, 1.0)
    }
    fn new_env(&mut self, t: f64, is_c: bool) -> usize {
        let exp = if is_c { C_TTL } else if self.cell.x_ttl_short { t + X_TTL_SHORT } else { C_TTL };
        self.envs.push(Envl { is_c, exp, acked: false, handed: false, k: 0, processed: false });
        let i = self.envs.len() - 1;
        if !is_c { self.x_ever_sent = true; }
        // first attempt right away
        self.try_send(t, i);
        match self.cell.timer {
            Timer::PerEnv => { let b = self.backoff(0); self.push(t + b, Ev::Attempt(i)); }
            Timer::PerDest => {
                if !self.dest_armed { self.dest_armed = true; let b = self.backoff(self.dest_k); self.push(t + b, Ev::DestTimer); }
            }
        }
        i
    }
    fn live(&self, i: usize, t: f64) -> bool { !self.envs[i].acked && t <= self.envs[i].exp }
    fn try_send(&mut self, t: f64, i: usize) {
        self.sends += 1;
        if self.s_online(t) {
            self.push(t + OWD, Ev::SArrive(i, false));
        } else if !self.envs[i].handed {
            if self.rng.f() >= self.cell.p_hf {
                self.envs[i].handed = true;
                let h = t + 0.05;
                // M: queued until S reconnects
                if h < self.d {
                    self.m_queue.push(i);
                } else {
                    self.push(h + OWD, Ev::MDeliver(i));
                }
            }
        }
    }
    fn reply(&mut self, t: f64, i: usize, r: Reply) {
        let at = if self.r_online(t + OWD) { t + OWD } else { self.r_back };
        self.push(at, Ev::RRecv(i, r));
    }
}

pub fn trial(cell: Cell, rng: &mut Rng, out: &mut Out) {
    let p = cell.profile;
    let d = if p.d_exp_mean > 0.0 { p.d_lo + rng.exp(p.d_exp_mean) } else { rng.range(p.d_lo, p.d_hi) };
    let t_i = rng.range(0.0, d);
    let (r_off_at, r_back) = if cell.r_goes_offline {
        let o = t_i + rng.range(0.0, 600.0);
        (o, o + rng.range(3600.0, 12.0 * 3600.0))
    } else { (f64::INFINITY, f64::INFINITY) };
    let backlog = rng.range(0.0, p.backlog_hi);
    let reconnect = rng.range(0.1, 1.0);
    let mut s = Sim {
        cell, rng, q: BinaryHeap::new(), seq: 0, d, r_off_at, r_back,
        envs: vec![], task: 0, tomb_until: f64::NEG_INFINITY, deferred: false, dest_k: 0, dest_armed: false,
        work_start: 0.0, x_live_arrival: false, x_ever_sent: false, belief: None, work_secs: 0.0, sends: 0,
        finish_at: 0.0, m_queue: vec![], m_next: 0,
    };
    // other senders' envelopes ahead of R's in M's queue
    let per_other = if cell.m_serial { 2.0 * OWD + 0.011 } else { 0.005 };
    s.push(d + reconnect + backlog * per_other, Ev::MStart);
    s.new_env(0.0, true);
    s.push(t_i, Ev::Intent);
    let horizon = 3.0 * 86400.0;
    while let Some(Item { t, ev, .. }) = s.q.pop() {
        if t > horizon { break; }
        match ev {
            Ev::Intent => {
                if s.cell.design == Design::D0 { s.deferred = true; } else { s.new_env(t, false); }
            }
            Ev::Attempt(i) => {
                if !s.live(i, t) { continue; }
                if !s.r_online(t) { let b = s.r_back; s.push(b, Ev::Attempt(i)); continue; }
                s.try_send(t, i);
                s.envs[i].k += 1;
                let b = s.backoff(s.envs[i].k);
                s.push(t + b, Ev::Attempt(i));
            }
            Ev::DestTimer => {
                let pend: Vec<usize> = (0..s.envs.len()).filter(|&i| s.live(i, t)).collect();
                if pend.is_empty() { s.dest_armed = false; continue; }
                if !s.r_online(t) { let b = s.r_back; s.push(b, Ev::DestTimer); continue; }
                for i in pend { s.try_send(t, i); }
                s.dest_k += 1;
                let b = s.backoff(s.dest_k);
                s.push(t + b, Ev::DestTimer);
            }
            Ev::MStart => {
                if s.cell.m_serial {
                    if let Some(&i) = s.m_queue.first() { s.m_next = 1; s.push(t, Ev::MDeliver(i)); }
                } else {
                    let q = s.m_queue.clone();
                    for (k, i) in q.into_iter().enumerate() { s.push(t + k as f64 * 0.005, Ev::MDeliver(i)); }
                }
            }
            Ev::MDeliver(i) => s.push(t + OWD, Ev::SArrive(i, true)),
            Ev::SArrive(i, m) => { let j = s.rng.range(0.002, 0.020); s.push(t + j, Ev::SProc(i, m)); }
            Ev::SProc(i, via_m) => {
                if via_m && s.cell.m_serial && s.m_next < s.m_queue.len() {
                    let nx = s.m_queue[s.m_next]; s.m_next += 1;
                    s.push(t + OWD, Ev::MDeliver(nx)); // ack to M, M sends the next
                }
                let e = s.envs[i].clone();
                if t > e.exp + SKEW { continue; } // expired
                if e.is_c {
                    if s.task != 0 { continue; } // duplicate: stored response
                    if t <= s.tomb_until {
                        s.task = 4;
                        s.reply(t, i, Reply::CreatedCanceled);
                    } else {
                        s.task = 1;
                        let w = s.rng.range(0.01, 0.5); s.push(t + w, Ev::Work);
                        s.reply(t, i, Reply::Created);
                    }
                } else {
                    if e.processed { continue; }
                    if s.task != 3 { s.x_live_arrival = true; }
                    let r = match s.task {
                        1 | 2 => {
                            if s.task == 2 { s.work_secs += t - s.work_start; }
                            s.task = 4; Reply::Canceled
                        }
                        4 => Reply::Canceled,
                        3 => Reply::NotCancelable,
                        _ => match s.cell.design {
                            Design::D0 | Design::D1 => Reply::NotFound,
                            Design::D2 => Reply::NotFoundRetry,
                            Design::D3 => { s.tomb_until = e.exp + SKEW; Reply::Pending }
                        },
                    };
                    if r != Reply::NotFoundRetry { s.envs[i].processed = true; }
                    s.reply(t, i, r);
                }
            }
            Ev::Work => {
                if s.task == 1 {
                    s.task = 2; s.work_start = t;
                    let l = 120.0 * (s.rng.normal()).exp();
                    s.finish_at = t + l;
                    s.push(t + l, Ev::Finish);
                }
            }
            Ev::Finish => {
                if s.task == 2 && (t - s.finish_at).abs() < 1e-9 { s.task = 3; s.work_secs += t - s.work_start; }
            }
            Ev::RRecv(i, r) => {
                if r != Reply::NotFoundRetry { s.envs[i].acked = true; }
                if s.envs[i].is_c {
                    if r == Reply::CreatedCanceled { s.belief = Some(Reply::Canceled); }
                    if s.deferred { s.deferred = false; s.new_env(t, false); }
                } else {
                    s.belief = Some(r);
                }
            }
        }
    }
    out.n += 1;
    let started = s.work_secs > 0.0 || s.task == 2 || s.task == 3;
    if started { out.work_started += 1; }
    if s.task == 3 { out.completed += 1; }
    if s.task == 4 { out.canceled += 1; }
    if s.task == 3 && s.x_live_arrival { out.lost += 1; }
    let x_exp = s.x_ever_sent && s.envs.iter().filter(|e| !e.is_c).all(|e| !e.processed && !e.acked) && !s.x_live_arrival;
    if x_exp && s.envs.iter().any(|e| !e.is_c && e.exp + SKEW < horizon) { out.x_expired += 1; }
    if s.task == 3 && matches!(s.belief, Some(Reply::Canceled) | Some(Reply::Pending)) { out.misled += 1; }
    if matches!(s.belief, Some(Reply::NotFound) | Some(Reply::NotFoundRetry)) { out.uncertain += 1; }
    out.work_secs += s.work_secs;
    out.r_sends += s.sends;
}
