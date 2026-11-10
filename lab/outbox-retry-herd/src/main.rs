//! Lab 2026-11-10: outbox retry policy vs a mailbox host recovering from an outage.
//!
//! Discrete-event model. K sender nodes each create envelopes (Poisson, rate LAMBDA) addressed to offline
//! nodes whose mailbox host is one relay M. Each sender's outbox retries until the envelope's `exp`.
//! M is down during [T0, T_UP). Afterwards every outbox retries at once, and the question is whether the
//! retry policy lets M drain the backlog quickly, or herds it into overload (or metastable collapse).
//!
//! Server model (M): one FIFO with capacity C work units per second (fluid, deterministic service).
//!   * a request carrying n envelopes costs `HS + PER_ENV * n` units (connection + auth + one fsync
//!     per request, plus per-envelope verify/store); a cheap reject costs REJECT units.
//!   * the client gives up after T_TO seconds; the server still finishes (and stores) a request it already
//!     queued unless the server variant says otherwise. Work done for a client that gave up is "wasted".
//!   * while M is down, every attempt fails after DOWN_FAIL seconds and costs M nothing.
//! Server variants:
//!   Fifo   - unbounded FIFO, serves abandoned requests (naive)
//!   Cancel - FIFO, skips a request whose client gave up before service started (deadline propagation)
//!   Shed   - Cancel + reject at admission when queue delay > SHED_Q seconds
//!   Hint   - Shed + the reject carries Retry-After ~ U(0, H), H = queue + 2 * (rejected demand in last 10 s)/C
//! Client variants:
//!   grain  E = one timer per envelope, each attempt carries one envelope
//!          Q = one timer per (sender, mailbox host) queue, an attempt carries every queued envelope
//!   shape  Pm50  = min(cap, 2^(n-1)) * U(0.5, 1.5)   (what the earlier freshness lab assumed)
//!          None  = min(cap, 2^(n-1))
//!          Full  = U(0, min(cap, 2^(n-1)))           ("full jitter")
//!          Decor = min(cap, U(1, 3 * prev))           ("decorrelated jitter")
//!   cap    seconds
//! The sender stops retrying at `exp`; an envelope never acked by `exp` is reported expired.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, VecDeque};

const K: usize = 1000; // senders using this mailbox host
const LAMBDA: f64 = 1.0 / 60.0; // envelopes per sender per second
const C: f64 = 100.0; // mailbox host capacity, work units / s
const HS: f64 = 1.0;
const PER_ENV: f64 = 0.1;
const REJECT: f64 = 0.02;
const T_TO: f64 = 10.0;
const DOWN_FAIL: f64 = 5.0;
const RTT: f64 = 0.05;
const SHED_Q: f64 = 2.0;
const T0: f64 = 1800.0;
const POST: f64 = 3.0 * 3600.0;
const TTL_MIN: f64 = 300.0;
const TTL_MAX: f64 = 86400.0;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Server {
    Fifo,
    Cancel,
    Shed,
    Hint,
}
#[derive(Clone, Copy, Debug, PartialEq)]
enum Grain {
    E,
    Q,
}
#[derive(Clone, Copy, Debug, PartialEq)]
enum Shape {
    Pm50,
    None,
    Full,
    Decor,
}

#[derive(Clone, Copy, Debug)]
struct Cfg {
    server: Server,
    grain: Grain,
    shape: Shape,
    cap: f64,
    down: f64,
    seed: u64,
    hs: f64,
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        // splitmix64
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn u(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
    fn exp(&mut self, rate: f64) -> f64 {
        -(1.0 - self.u()).ln() / rate
    }
}

#[derive(Clone, Copy)]
enum Ev {
    Create(u32),
    Attempt(u32), // sender (Q) or envelope (E)
    Result { owner: u32, ok: bool, hint: f64 },
}

struct Env {
    created: f64,
    exp: f64,
    acked: f64, // NaN = never
    stored: f64,
    stores: u32,
    attempts: u32,
}

#[derive(Default)]
struct Sender {
    pending: VecDeque<u32>,
    inflight: Vec<u32>,
    busy: bool,
    backing_off: bool,
    n: u32,
    prev: f64,
}

struct Sim {
    cfg: Cfg,
    rng: Rng,
    heap: BinaryHeap<Reverse<(u64, u64, u8, u32, u64)>>,
    seq: u64,
    envs: Vec<Env>,
    senders: Vec<Sender>,
    env_n: Vec<(u32, f64)>, // E-mode per-envelope backoff state
    busy_until: f64,
    rejected: VecDeque<(f64, f64)>,
    t_up: f64,
    end: f64,
    // metrics, 1 s bins from t_up
    offered: Vec<f64>,
    fails: Vec<u32>,
    wasted: f64,
    total_work: f64,
    attempts: u64,
}

fn key(t: f64) -> u64 {
    t.to_bits()
}

impl Sim {
    fn new(cfg: Cfg) -> Sim {
        let t_up = T0 + cfg.down;
        let end = t_up + POST;
        let bins = POST as usize + 1;
        Sim {
            cfg,
            rng: Rng(cfg.seed),
            heap: BinaryHeap::new(),
            seq: 0,
            envs: Vec::new(),
            senders: (0..K).map(|_| Sender::default()).collect(),
            env_n: Vec::new(),
            busy_until: 0.0,
            rejected: VecDeque::new(),
            t_up,
            end,
            offered: vec![0.0; bins],
            fails: vec![0; bins],
            wasted: 0.0,
            total_work: 0.0,
            attempts: 0,
        }
    }
    fn push(&mut self, t: f64, ev: Ev) {
        self.seq += 1;
        let item = match ev {
            Ev::Create(s) => (0u8, s, 0u64),
            Ev::Attempt(o) => (1, o, 0),
            Ev::Result { owner, ok, hint } => (if ok { 2 } else { 3 }, owner, hint.to_bits()),
        };
        self.heap.push(Reverse((key(t), self.seq, item.0, item.1, item.2)));
    }
    fn backoff(&mut self, n: u32, prev: f64) -> f64 {
        let cap = self.cfg.cap;
        let e = (2f64.powi(n as i32 - 1)).min(cap);
        match self.cfg.shape {
            Shape::Pm50 => e * (0.5 + self.rng.u()),
            Shape::None => e,
            Shape::Full => e * self.rng.u(),
            Shape::Decor => {
                let hi = (3.0 * prev).max(1.0);
                (1.0 + self.rng.u() * (hi - 1.0)).min(cap)
            }
        }
    }
    fn bin(&self, t: f64) -> Option<usize> {
        if t >= self.t_up && t < self.end {
            Some((t - self.t_up) as usize)
        } else {
            None
        }
    }
    /// Submit an attempt with `ids` at time t. Returns (result time, ok, hint).
    fn submit(&mut self, t: f64, ids: &[u32]) -> (f64, bool, f64) {
        self.attempts += 1;
        for &i in ids {
            self.envs[i as usize].attempts += 1;
        }
        let work = self.cfg.hs + PER_ENV * ids.len() as f64;
        if let Some(b) = self.bin(t) {
            self.offered[b] += work;
        }
        if t >= T0 && t < self.t_up {
            return (t + DOWN_FAIL, false, f64::NAN);
        }
        let srv = self.cfg.server;
        if (srv == Server::Shed || srv == Server::Hint) && self.busy_until - t > SHED_Q {
            self.busy_until = self.busy_until.max(t) + REJECT / C;
            self.total_work += REJECT;
            if let Some(b) = self.bin(t) {
                self.fails[b] += 1;
            }
            let mut hint = f64::NAN;
            if srv == Server::Hint {
                self.rejected.push_back((t, work));
                while let Some(&(t0, _)) = self.rejected.front() {
                    if t0 < t - 10.0 {
                        self.rejected.pop_front();
                    } else {
                        break;
                    }
                }
                let dem: f64 = self.rejected.iter().map(|x| x.1).sum();
                let h = ((self.busy_until - t) + 2.0 * dem / C).max(1.0);
                hint = h * self.rng.u();
            }
            return (t + RTT, false, hint);
        }
        let start = self.busy_until.max(t);
        if srv != Server::Fifo && start - t >= T_TO {
            if let Some(b) = self.bin(t) {
                self.fails[b] += 1;
            }
            return (t + T_TO, false, f64::NAN);
        }
        let done = start + work / C;
        self.busy_until = done;
        self.total_work += work;
        for &i in ids {
            let e = &mut self.envs[i as usize];
            e.stores += 1;
            if e.stored.is_nan() {
                e.stored = done;
            }
        }
        if done - t <= T_TO {
            (done + RTT, true, f64::NAN)
        } else {
            self.wasted += work;
            if let Some(b) = self.bin(t) {
                self.fails[b] += 1;
            }
            (t + T_TO, false, f64::NAN)
        }
    }

    fn new_env(&mut self, t: f64) -> u32 {
        let ttl = (TTL_MIN.ln() + self.rng.u() * (TTL_MAX.ln() - TTL_MIN.ln())).exp();
        self.envs.push(Env { created: t, exp: t + ttl, acked: f64::NAN, stored: f64::NAN, stores: 0, attempts: 0 });
        self.env_n.push((0, 1.0));
        (self.envs.len() - 1) as u32
    }

    fn attempt_q(&mut self, s: u32, t: f64) {
        let mut pend = std::mem::take(&mut self.senders[s as usize].pending);
        pend.retain(|&i| self.envs[i as usize].exp >= t);
        let st = &mut self.senders[s as usize];
        st.backing_off = false;
        if pend.is_empty() {
            st.n = 0;
            st.prev = 1.0;
            return;
        }
        let batch: Vec<u32> = pend.into_iter().collect();
        let (tr, ok, hint) = self.submit(t, &batch);
        let st = &mut self.senders[s as usize];
        st.inflight = batch;
        st.busy = true;
        self.push(tr, Ev::Result { owner: s, ok, hint });
    }

    fn attempt_e(&mut self, i: u32, t: f64) {
        if self.envs[i as usize].exp < t {
            return;
        }
        let (tr, ok, hint) = self.submit(t, &[i]);
        self.push(tr, Ev::Result { owner: i, ok, hint });
    }

    fn run(&mut self) {
        for s in 0..K as u32 {
            let t = self.rng.exp(LAMBDA);
            self.push(t, Ev::Create(s));
        }
        while let Some(Reverse((k, _, kind, o, h))) = self.heap.pop() {
            let t = f64::from_bits(k);
            if t > self.end {
                break;
            }
            let ev = match kind {
                0 => Ev::Create(o),
                1 => Ev::Attempt(o),
                _ => Ev::Result { owner: o, ok: kind == 2, hint: f64::from_bits(h) },
            };
            match ev {
                Ev::Create(s) => {
                    let nt = t + self.rng.exp(LAMBDA);
                    self.push(nt, Ev::Create(s));
                    let i = self.new_env(t);
                    match self.cfg.grain {
                        Grain::E => self.attempt_e(i, t),
                        Grain::Q => {
                            let st = &mut self.senders[s as usize];
                            st.pending.push_back(i);
                            if !st.busy && !st.backing_off {
                                self.attempt_q(s, t);
                            }
                        }
                    }
                }
                Ev::Attempt(o) => match self.cfg.grain {
                    Grain::E => self.attempt_e(o, t),
                    Grain::Q => self.attempt_q(o, t),
                },
                Ev::Result { owner, ok, hint } => match self.cfg.grain {
                    Grain::E => {
                        if ok {
                            let e = &mut self.envs[owner as usize];
                            if e.acked.is_nan() {
                                e.acked = t;
                            }
                        } else {
                            let (n, prev) = self.env_n[owner as usize];
                            let n = n + 1;
                            let d = if hint.is_nan() { self.backoff(n, prev) } else { hint };
                            self.env_n[owner as usize] = (n, d.max(1.0));
                            let nt = t + d;
                            if nt <= self.envs[owner as usize].exp {
                                self.push(nt, Ev::Attempt(owner));
                            }
                        }
                    }
                    Grain::Q => {
                        let batch = std::mem::take(&mut self.senders[owner as usize].inflight);
                        self.senders[owner as usize].busy = false;
                        if ok {
                            for &i in &batch {
                                let e = &mut self.envs[i as usize];
                                if e.acked.is_nan() {
                                    e.acked = t;
                                }
                            }
                            let st = &mut self.senders[owner as usize];
                            st.n = 0;
                            st.prev = 1.0;
                            if !st.pending.is_empty() {
                                self.attempt_q(owner, t);
                            }
                        } else {
                            let (n, prev) = {
                                let st = &mut self.senders[owner as usize];
                                for &i in batch.iter().rev() {
                                    st.pending.push_front(i);
                                }
                                st.n += 1;
                                (st.n, st.prev)
                            };
                            let d = if hint.is_nan() { self.backoff(n, prev) } else { hint };
                            let st = &mut self.senders[owner as usize];
                            st.prev = d.max(1.0);
                            st.backing_off = true;
                            self.push(t + d, Ev::Attempt(owner));
                        }
                    }
                },
            }
        }
    }
}

fn pct(v: &mut [f64], p: f64) -> f64 {
    if v.is_empty() {
        return f64::NAN;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let i = ((v.len() as f64 - 1.0) * p).round() as usize;
    v[i]
}

fn run_cell(cfg: Cfg) -> String {
    let mut sim = Sim::new(cfg);
    sim.run();
    let t_up = sim.t_up;
    // backlog: created before t_up, not acked before T0
    let (mut bl, mut bl_exp_unavoid, mut bl_exp_near, mut bl_exp_avoid, mut stored_but_expired) = (0u64, 0u64, 0u64, 0u64, 0u64);
    let mut bl_delay = Vec::new();
    let mut new_lat = Vec::new();
    let (mut new_n, mut new_exp) = (0u64, 0u64);
    let mut dup_stores = 0u64;
    for e in &sim.envs {
        if e.stores > 1 {
            dup_stores += (e.stores - 1) as u64;
        }
        if e.created < t_up && !(e.acked < T0) && e.created > T0 - 600.0 {
            // backlog: envelopes created in [T0-600, t_up) and not delivered before the outage
            bl += 1;
            if e.acked.is_nan() {
                if !e.stored.is_nan() {
                    stored_but_expired += 1;
                }
                if e.exp < t_up {
                    bl_exp_unavoid += 1;
                } else if e.exp < t_up + 120.0 {
                    bl_exp_near += 1;
                } else {
                    bl_exp_avoid += 1;
                }
            } else {
                bl_delay.push((e.acked - t_up).max(0.0));
            }
        } else if e.created >= t_up && e.created < t_up + 3600.0 {
            new_n += 1;
            if e.acked.is_nan() {
                if e.exp <= sim.end {
                    new_exp += 1;
                }
                new_lat.push(f64::INFINITY);
            } else {
                new_lat.push(e.acked - e.created);
            }
        }
    }
    // offered load peak (1 s and 10 s windows)
    let peak1 = sim.offered.iter().cloned().fold(0.0, f64::max) / C;
    let mut peak10 = 0.0f64;
    for w in sim.offered.windows(10) {
        peak10 = peak10.max(w.iter().sum::<f64>() / 10.0 / C);
    }
    let last_fail = sim.fails.iter().rposition(|&f| f > 0).map(|i| i as f64).unwrap_or(0.0);
    let recovered = last_fail < POST - 1800.0;
    let total_fails: u64 = sim.fails.iter().map(|&x| x as u64).sum();
    let bl_n = bl;
    let d50 = pct(&mut bl_delay, 0.5);
    let d99 = pct(&mut bl_delay, 0.99);
    let dmax = pct(&mut bl_delay, 1.0);
    let l50 = pct(&mut new_lat, 0.5);
    let l99 = pct(&mut new_lat, 0.99);
    format!(
        "{:?}\t{:?}\t{:?}\t{}\t{}\t{}\t{}\t{}\t{:.2}\t{:.2}\t{}\t{}\t{:.1}\t{:.1}\t{:.1}\t{}\t{}\t{}\t{}\t{:.3}\t{:.2}\t{}\t{}\t{}\t{:.0}\t{:.3}\t{}\t{}",
        cfg.server,
        cfg.grain,
        cfg.shape,
        cfg.cap,
        cfg.down,
        cfg.hs,
        cfg.seed,
        bl_n,
        peak1,
        peak10,
        if recovered { "yes" } else { "NO" },
        last_fail,
        d50,
        d99,
        dmax,
        bl_exp_unavoid,
        bl_exp_near,
        bl_exp_avoid,
        stored_but_expired,
        l50,
        l99,
        new_n,
        new_exp,
        total_fails,
        sim.wasted,
        sim.wasted / sim.total_work.max(1e-9),
        sim.attempts,
        dup_stores,
    )
}

fn header() -> &'static str {
    "server\tgrain\tshape\tcap\tdown_s\ths\tseed\tbacklog\tpeak1s_xC\tpeak10s_xC\trecovered\tlast_fail_s\tbl_p50_s\tbl_p99_s\tbl_max_s\tbl_exp_unavoid\tbl_exp_near\tbl_exp_avoid\tstored_but_expired\tnew_p50_s\tnew_p99_s\tnew_n\tnew_exp\tfails_post\twasted_work\twasted_frac\tattempts\tdup_stores"
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("main");
    let seeds: u64 = std::env::var("SEEDS").ok().and_then(|s| s.parse().ok()).unwrap_or(1);
    let threads: usize = std::env::var("THREADS").ok().and_then(|s| s.parse().ok()).unwrap_or(3);
    let mut cells = Vec::new();
    let shapes: Vec<(Shape, f64)> = vec![
        (Shape::Pm50, 600.0),
        (Shape::None, 600.0),
        (Shape::Full, 600.0),
        (Shape::Decor, 600.0),
        (Shape::Pm50, 60.0),
        (Shape::Full, 60.0),
    ];
    if mode == "sens" {
        let combos = [
            (Grain::E, Shape::Pm50, 600.0),
            (Grain::Q, Shape::Full, 600.0),
            (Grain::Q, Shape::Pm50, 60.0),
            (Grain::Q, Shape::Full, 60.0),
        ];
        for hs in [0.3, 1.0, 3.0] {
            for down in [600.0, 3600.0, 21600.0] {
                for server in [Server::Fifo, Server::Shed, Server::Hint] {
                    for &(grain, shape, cap) in &combos {
                        cells.push(Cfg { server, grain, shape, cap, down, seed: 2, hs });
                    }
                }
            }
        }
    }
    let downs: Vec<f64> = match mode {
        "smoke" => vec![600.0],
        _ => vec![60.0, 600.0, 3600.0, 6.0 * 3600.0],
    };
    let servers: Vec<Server> = match mode {
        "smoke" => vec![Server::Fifo],
        _ => vec![Server::Fifo, Server::Cancel, Server::Shed, Server::Hint],
    };
    let hss: Vec<f64> = match mode {
        "hs" => vec![0.3, 1.0, 3.0],
        _ => vec![HS],
    };
    for &hs in if mode == "sens" { &[][..] } else { &hss[..] } {
        for &down in &downs {
            for &server in &servers {
                for grain in [Grain::E, Grain::Q] {
                    for &(shape, cap) in &shapes {
                        for seed in 1..=seeds {
                            cells.push(Cfg { server, grain, shape, cap, down, seed, hs });
                        }
                    }
                }
            }
        }
    }
    println!("{}", header());
    let cells = std::sync::Arc::new(cells);
    let next = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let out = std::sync::Arc::new(std::sync::Mutex::new(vec![String::new(); cells.len()]));
    let mut hs = Vec::new();
    for _ in 0..threads {
        let (cells, next, out) = (cells.clone(), next.clone(), out.clone());
        hs.push(std::thread::spawn(move || loop {
            let i = next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if i >= cells.len() {
                break;
            }
            let line = run_cell(cells[i]);
            eprintln!("{}", line);
            out.lock().unwrap()[i] = line;
        }));
    }
    for h in hs {
        h.join().unwrap();
    }
    for l in out.lock().unwrap().iter() {
        println!("{}", l);
    }
}
