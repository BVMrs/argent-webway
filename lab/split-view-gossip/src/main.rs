//! Lab model: does audit/v0 §10.4 checkpoint exchange catch a node that shows different
//! histories to different peers (split view, threat AUD-3)?
//!
//! Nodes talk over a contact graph (Poisson sessions per edge). At each session both sides
//! fetch the peer's checkpoint (AUD-700) and, if neither is the attacker X, each side calls
//! ExchangeCheckpoints (AUD-721) with its held third-party checkpoints (MRU, at most MAX_HAVE).
//! From t0 the attacker X shows branch F to a victim set and branch M to everyone else.
//! A fork is detected when two inconsistent post-fork commitments meet in one comparison.
//!
//! Protocol variants:
//!   spec    : as written. Only checkpoints a node fetched from X itself are held and sent
//!             (AUD-720: a received checkpoint never replaces the held one), so evidence
//!             travels exactly one hop.
//!   relay   : nodes also keep and forward X-signed checkpoints received from others (any
//!             X-signed pair that is inconsistent is evidence), still MRU/MAX_HAVE gated.
//!   spec+W  : spec, plus W shared witnesses: every node exchanges with its witness at
//!             WITNESS_RATE, witnesses keep everything submitted and exchange among themselves.
//!   relay+W : both.
//!
//! Attackers: one (one random counterparty), half (random half), adaptive (uses what
//! ExchangeCheckpoints leaks: each counterparty's held-log list tells X who it talks to;
//! X forks a whole connected component of its counterparties' co-holder graph, or, if
//! there is only one, the counterparty with fewest co-holders).

use std::env;

// ---------- rng (xoshiro256**) ----------
struct Rng([u64; 4]);
impl Rng {
    fn new(seed: u64) -> Self {
        let mut z = seed;
        let mut s = [0u64; 4];
        for x in s.iter_mut() {
            z = z.wrapping_add(0x9e3779b97f4a7c15);
            let mut y = z;
            y = (y ^ (y >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
            y = (y ^ (y >> 27)).wrapping_mul(0x94d049bb133111eb);
            *x = y ^ (y >> 31);
        }
        Rng(s)
    }
    fn next(&mut self) -> u64 {
        let s = &mut self.0;
        let r = s[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = s[1] << 17;
        s[2] ^= s[0];
        s[3] ^= s[1];
        s[1] ^= s[2];
        s[0] ^= s[3];
        s[2] ^= t;
        s[3] = s[3].rotate_left(45);
        r
    }
    fn f(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
    fn below(&mut self, n: usize) -> usize {
        (self.f() * n as f64) as usize % n.max(1)
    }
    fn exp(&mut self, rate: f64) -> f64 {
        -(1.0 - self.f()).ln() / rate
    }
    fn normal(&mut self) -> f64 {
        let u1 = 1.0 - self.f();
        let u2 = self.f();
        (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()
    }
    fn lognormal(&mut self, median: f64, sigma: f64) -> f64 {
        median * (sigma * self.normal()).exp()
    }
    fn poisson(&mut self, mean: f64) -> usize {
        let l = (-mean).exp();
        let mut k = 0;
        let mut p = 1.0;
        loop {
            p *= self.f();
            if p <= l {
                return k;
            }
            k += 1;
        }
    }
}

// ---------- graph ----------
#[derive(Clone)]
struct Edge {
    u: usize,
    w: usize,
    rate: f64,
    iu: usize,
    iw: usize,
}
struct Graph {
    n: usize,
    adj: Vec<Vec<usize>>,
    edges: Vec<Edge>,
    cum: Vec<f64>,
    witness: Vec<bool>,
    candidates: Vec<usize>, // nodes that may be the attacker X
}
const SIGMA: f64 = 1.0; // lognormal spread of per-edge session rates

impl Graph {
    fn new(n: usize) -> Self {
        Graph { n, adj: vec![vec![]; n], edges: vec![], cum: vec![], witness: vec![false; n], candidates: vec![] }
    }
    fn has(&self, u: usize, w: usize) -> bool {
        self.adj[u].contains(&w)
    }
    fn add(&mut self, u: usize, w: usize, rate: f64) {
        if u == w || self.has(u, w) {
            return;
        }
        let iu = self.adj[u].len();
        let iw = self.adj[w].len();
        self.adj[u].push(w);
        self.adj[w].push(u);
        self.edges.push(Edge { u, w, rate, iu, iw });
    }
    fn finish(&mut self) {
        let mut c = 0.0;
        self.cum = self.edges.iter().map(|e| { c += e.rate; c }).collect();
    }
    fn total_rate(&self) -> f64 {
        *self.cum.last().unwrap()
    }
    fn pick_edge(&self, r: f64) -> usize {
        let x = r * self.total_rate();
        self.cum.partition_point(|&c| c < x).min(self.edges.len() - 1)
    }
    fn add_witnesses(&mut self, w: usize, rate: f64, rng: &mut Rng) {
        let base = self.n;
        self.n += w;
        for _ in 0..w {
            self.adj.push(vec![]);
            self.witness.push(true);
        }
        for i in 0..base {
            let wi = base + rng.below(w);
            self.add(i, wi, rate);
        }
        for a in 0..w {
            for b in a + 1..w {
                self.add(base + a, base + b, 24.0);
            }
        }
    }
}

/// Market: client owners with small fleets use a few shared service nodes (S1/S2 shape).
/// `c` = mean number of partner owners per client owner (cross-owner client-client ties).
fn market(c: f64, rng: &mut Rng) -> Graph {
    let owners = 400;
    let per = 5;
    let services = 20;
    let nc = owners * per;
    let mut g = Graph::new(nc + services);
    for o in 0..owners {
        for a in 0..per {
            for b in a + 1..per {
                g.add(o * per + a, o * per + b, rng.lognormal(4.0, SIGMA));
            }
        }
    }
    let pop: Vec<f64> = (0..services).map(|s| 1.0 / (s as f64 + 1.0)).collect();
    let tot: f64 = pop.iter().sum();
    for o in 0..owners {
        let k = (1 + rng.poisson(1.0)).min(services);
        let mut chosen: Vec<usize> = vec![];
        while chosen.len() < k {
            let mut r = rng.f() * tot;
            let mut s = 0;
            while r > pop[s] {
                r -= pop[s];
                s += 1;
            }
            if !chosen.contains(&s) {
                chosen.push(s);
            }
        }
        for &s in &chosen {
            let mut any = false;
            for a in 0..per {
                if rng.f() < 0.6 {
                    g.add(o * per + a, nc + s, rng.lognormal(2.0, SIGMA));
                    any = true;
                }
            }
            if !any {
                g.add(o * per + rng.below(per), nc + s, rng.lognormal(2.0, SIGMA));
            }
        }
    }
    let ties = (owners as f64 * c / 2.0).round() as usize;
    for _ in 0..ties {
        let a = rng.below(owners);
        let mut b = rng.below(owners);
        while b == a {
            b = rng.below(owners);
        }
        g.add(a * per + rng.below(per), b * per + rng.below(per), rng.lognormal(0.5, SIGMA));
    }
    g.candidates = (nc..nc + services).filter(|&s| g.adj[s].len() >= 2).collect();
    g
}

/// Fleets: owners with 10 nodes each (complete inside), sparse random cross-owner edges
/// with mean cross-degree `d` per node (S3 consortium shape). X is any node.
fn fleets(d: f64, rng: &mut Rng) -> Graph {
    let owners = 200;
    let per = 10;
    let n = owners * per;
    let mut g = Graph::new(n);
    for o in 0..owners {
        for a in 0..per {
            for b in a + 1..per {
                g.add(o * per + a, o * per + b, rng.lognormal(4.0, SIGMA));
            }
        }
    }
    let m = (n as f64 * d / 2.0).round() as usize;
    let mut k = 0;
    while k < m {
        let a = rng.below(n);
        let b = rng.below(n);
        if a / per == b / per || g.has(a, b) {
            continue;
        }
        g.add(a, b, rng.lognormal(0.5, SIGMA));
        k += 1;
    }
    g.candidates = (0..n).collect();
    g
}

// ---------- simulation ----------
const MAX_HAVE: usize = 64;
const DAY: f64 = 1.0; // time unit: days
const WARMUP: f64 = 7.0 * DAY;
const HORIZON: f64 = 30.0 * DAY;

#[derive(Clone, Copy, PartialEq)]
enum Variant {
    Spec,
    Relay,
}
#[derive(Clone, Copy, PartialEq, Debug)]
enum Attacker {
    One,
    Half,
    Adaptive,
}

struct Outcome {
    effective: bool,      // some victim actually received a fork checkpoint
    detected: Option<f64>, // days after t0
    believed_safe: bool,  // adaptive attacker saw >= 2 components
    victims: usize,
    nbrs: usize,
}

fn bit(own: u8) -> u8 {
    match own {
        2 => 1,
        3 => 2,
        _ => 0,
    }
}

/// rank of X among `u`'s held logs by recency, excluding `resp`; returns true if X is in the
/// first MAX_HAVE. Witnesses send everything.
fn x_in_list(g: &Graph, last: &[Vec<f64>], u: usize, resp: usize, xuse: f64) -> bool {
    if g.witness[u] || g.adj[u].len() <= MAX_HAVE {
        return true;
    }
    let mut more = 0;
    for (j, &y) in g.adj[u].iter().enumerate() {
        if y != resp && last[u][j] > xuse {
            more += 1;
            if more >= MAX_HAVE {
                return false;
            }
        }
    }
    true
}

fn choose_victims(g: &Graph, x: usize, last: &[Vec<f64>], att: Attacker, rng: &mut Rng) -> (Vec<bool>, bool) {
    let nb: Vec<usize> = g.adj[x]
        .iter()
        .enumerate()
        .filter(|&(j, &v)| !g.witness[v] && last[x][j] > f64::NEG_INFINITY)
        .map(|(_, &v)| v)
        .collect();
    let mut fork = vec![false; g.n];
    if nb.is_empty() {
        return (fork, false);
    }
    match att {
        Attacker::One => {
            fork[nb[rng.below(nb.len())]] = true;
            (fork, false)
        }
        Attacker::Half => {
            for &v in &nb {
                if rng.f() < 0.5 {
                    fork[v] = true;
                }
            }
            (fork, false)
        }
        Attacker::Adaptive => {
            // What X learns: each counterparty v lists its MAX_HAVE most recently used held logs
            // (log ID = node) in ExchangeCheckpoints. Logs X also holds = co-holders reachable
            // in one comparison. Witness logs count too (a witness is a co-holder of everything).
            let all: Vec<usize> = g.adj[x].iter().copied().filter(|&v| last[x][g.adj[x].iter().position(|&y| y == v).unwrap()] > f64::NEG_INFINITY).collect();
            let idx = |v: usize| all.iter().position(|&y| y == v);
            let k = all.len();
            let mut parent: Vec<usize> = (0..k).collect();
            fn find(p: &mut Vec<usize>, a: usize) -> usize {
                let mut a = a;
                while p[a] != a {
                    p[a] = p[p[a]];
                    a = p[a];
                }
                a
            }
            let mut deg = vec![0usize; k];
            for (a, &v) in all.iter().enumerate() {
                // v's leaked list: its MRU logs excluding X
                let mut held: Vec<(f64, usize)> = g.adj[v]
                    .iter()
                    .enumerate()
                    .filter(|&(j, &y)| y != x && last[v][j] > f64::NEG_INFINITY)
                    .map(|(j, &y)| (last[v][j], y))
                    .collect();
                if !g.witness[v] && held.len() > MAX_HAVE {
                    held.sort_by(|p, q| q.0.partial_cmp(&p.0).unwrap());
                    held.truncate(MAX_HAVE);
                }
                for &(_, y) in &held {
                    if let Some(b) = idx(y) {
                        deg[a] += 1;
                        deg[b] += 1;
                        let (ra, rb) = (find(&mut parent, a), find(&mut parent, b));
                        parent[ra] = rb;
                    }
                }
            }
            // The attacker knows witnesses gossip with each other: every counterparty that
            // lists a witness log (or is a witness) is linked to one virtual "witness net" node.
            let vnet = k;
            parent.push(vnet);
            for (a, &v) in all.iter().enumerate() {
                let linked = g.witness[v] || g.adj[v].iter().enumerate().any(|(j, &y)| g.witness[y] && last[v][j] > f64::NEG_INFINITY);
                if linked {
                    let (ra, rb) = (find(&mut parent, a), find(&mut parent, vnet));
                    parent[ra] = rb;
                }
            }
            let netroot = find(&mut parent, vnet);
            let mut comp: std::collections::HashMap<usize, Vec<usize>> = Default::default();
            for a in 0..k {
                let r = find(&mut parent, a);
                comp.entry(r).or_default().push(a);
            }
            let ncomp = comp.len();
            let mut targets: Vec<Vec<usize>> = comp
                .into_iter()
                .filter(|(r, c)| *r != netroot && c.iter().all(|&a| !g.witness[all[a]]))
                .map(|(_, c)| c)
                .collect();
            targets.sort_by_key(|c| (c.len(), c[0]));
            if ncomp >= 2 && !targets.is_empty() {
                // >= 2 components among X's counterparties: fork the smallest one not tied to
                // the witness network; no comparison can ever cross the cut.
                for &a in &targets[0] {
                    fork[all[a]] = true;
                }
                (fork, true)
            } else {
                // one component: the counterparty with the fewest co-holders
                let mut best = usize::MAX;
                let mut pick = vec![];
                for (a, &v) in all.iter().enumerate() {
                    if g.witness[v] {
                        continue;
                    }
                    if deg[a] < best {
                        best = deg[a];
                        pick.clear();
                    }
                    if deg[a] == best {
                        pick.push(v);
                    }
                }
                if !pick.is_empty() {
                    fork[pick[rng.below(pick.len())]] = true;
                }
                (fork, false)
            }
        }
    }
}

fn trial(g: &Graph, x: usize, variant: Variant, att: Attacker, rng: &mut Rng) -> Outcome {
    let n = g.n;
    let mut last: Vec<Vec<f64>> = g.adj.iter().map(|a| vec![f64::NEG_INFINITY; a.len()]).collect();
    let mut own = vec![0u8; n]; // 0 none, 1 pre-fork, 2 main, 3 fork (fetched from X directly)
    let mut seen = vec![0u8; n]; // bits of post-fork branches known (relay-capable nodes)
    let mut xuse = vec![f64::NEG_INFINITY; n];
    let relay_all = variant == Variant::Relay;
    let mut fork = vec![false; n];
    let mut forked = false;
    let mut believed = false;
    let mut victims = 0;
    let mut effective = false;
    let mut t = 0.0;
    let total = g.total_rate();
    loop {
        t += rng.exp(total);
        if !forked && t >= WARMUP {
            let (f, b) = choose_victims(g, x, &last, att, rng);
            fork = f;
            believed = b;
            victims = fork.iter().filter(|&&v| v).count();
            forked = true;
        }
        if t >= WARMUP + HORIZON {
            break;
        }
        let e = &g.edges[g.pick_edge(rng.f())];
        last[e.u][e.iu] = t;
        last[e.w][e.iw] = t;
        if e.u == x || e.w == x {
            let p = if e.u == x { e.w } else { e.u };
            own[p] = if !forked { 1 } else if fork[p] { 3 } else { 2 };
            xuse[p] = t;
            if own[p] == 3 {
                effective = true;
            }
            if relay_all || g.witness[p] {
                seen[p] |= bit(own[p]);
                if seen[p] == 3 {
                    return Outcome { effective, detected: Some(t - WARMUP), believed_safe: believed, victims, nbrs: g.adj[x].len() };
                }
            }
            continue;
        }
        if !forked {
            continue;
        }
        // two ExchangeCheckpoints calls, one per direction
        for (req, resp) in [(e.u, e.w), (e.w, e.u)] {
            let rq_relay = relay_all || g.witness[req];
            let rs_relay = relay_all || g.witness[resp];
            let rq_k = if rq_relay { seen[req] | bit(own[req]) } else { bit(own[req]) };
            let rs_k = if rs_relay { seen[resp] | bit(own[resp]) } else { bit(own[resp]) };
            let rq_holds = own[req] > 0 || (rq_relay && seen[req] > 0);
            let rs_holds = own[resp] > 0 || (rs_relay && seen[resp] > 0);
            if !rq_holds || !x_in_list(g, &last, req, resp, xuse[req]) {
                continue;
            }
            if !rs_holds {
                // responder holds no checkpoint of X: nothing to compare; a relay-capable
                // responder (or witness) keeps the submitted one.
                if rs_relay && rq_k != 0 {
                    seen[resp] |= rq_k;
                    xuse[resp] = t;
                }
                continue;
            }
            if rq_k | rs_k == 3 {
                return Outcome { effective, detected: Some(t - WARMUP), believed_safe: believed, victims, nbrs: g.adj[x].len() };
            }
            if rq_relay && rs_k != 0 {
                seen[req] |= rs_k;
                xuse[req] = t;
            }
            if rs_relay && rq_k != 0 {
                seen[resp] |= rq_k;
                xuse[resp] = t;
            }
        }
    }
    Outcome { effective, detected: None, believed_safe: believed, victims, nbrs: g.adj[x].len() }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let trials: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(200);
    let wrate: f64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1.0);
    let topos: Vec<(&str, f64)> = vec![("market", 0.0), ("market", 0.5), ("market", 2.0), ("fleets", 1.0), ("fleets", 3.0)];
    let variants = [("spec", Variant::Spec, 0usize), ("relay", Variant::Relay, 0), ("spec+W3", Variant::Spec, 3), ("relay+W3", Variant::Relay, 3)];
    let attackers = [Attacker::One, Attacker::Half, Attacker::Adaptive];
    println!("# trials per cell {trials}, warmup {WARMUP} d, horizon {HORIZON} d, witness submit rate {wrate}/d, MAX_HAVE {MAX_HAVE}");
    println!("topology\tparam\tvariant\tattacker\teffective\tdet_1d\tdet_7d\tdet_30d\tmedian_d\tp90_d\tbelieved_safe\tbelieved_safe_undetected\tmean_victims\tmean_deg_x");
    let mut jobs = vec![];
    for (ti, &(tn, tp)) in topos.iter().enumerate() {
        for (vi, &(vn, v, w)) in variants.iter().enumerate() {
            for (ai, &a) in attackers.iter().enumerate() {
                jobs.push((ti, tn, tp, vi, vn, v, w, ai, a));
            }
        }
    }
    let results = std::sync::Mutex::new(vec![String::new(); jobs.len()]);
    let next = std::sync::atomic::AtomicUsize::new(0);
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| loop {
                let j = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if j >= jobs.len() {
                    break;
                }
                let (ti, tn, tp, vi, vn, v, w, ai, a) = jobs[j];
                let mut eff = 0;
                let mut lat: Vec<f64> = vec![];
                let mut believed = 0;
                let mut believed_und = 0;
                let mut vict = 0usize;
                let mut degx = 0usize;
                for k in 0..trials {
                    // same graph + X for the same (topology, trial) across variants/attackers
                    let mut grng = Rng::new(0x5eed_0000 + (ti as u64) * 1_000_003 + k as u64);
                    let mut g = if tn == "market" { market(tp, &mut grng) } else { fleets(tp, &mut grng) };
                    if w > 0 {
                        g.add_witnesses(w, wrate, &mut grng);
                    }
                    g.finish();
                    let x = g.candidates[grng.below(g.candidates.len())];
                    let mut rng = Rng::new(0xabcd_0000 + (ti as u64) * 7919 + (vi as u64) * 104_729 + (ai as u64) * 15_485_863 + k as u64 * 31);
                    let o = trial(&g, x, v, a, &mut rng);
                    if !o.effective {
                        continue;
                    }
                    eff += 1;
                    vict += o.victims;
                    degx += o.nbrs;
                    if o.believed_safe {
                        believed += 1;
                        if o.detected.is_none() {
                            believed_und += 1;
                        }
                    }
                    if let Some(d) = o.detected {
                        lat.push(d);
                    }
                }
                lat.sort_by(|p, q| p.partial_cmp(q).unwrap());
                let frac = |lim: f64| lat.iter().filter(|&&d| d <= lim).count() as f64 / eff.max(1) as f64;
                let q = |p: f64| {
                    let k = (p * eff as f64).ceil() as usize;
                    if k == 0 || k > lat.len() { "inf".to_string() } else { format!("{:.2}", lat[k - 1]) }
                };
                let line = format!(
                    "{tn}\t{tp}\t{vn}\t{:?}\t{eff}\t{:.3}\t{:.3}\t{:.3}\t{}\t{}\t{believed}\t{believed_und}\t{:.1}\t{:.1}",
                    a,
                    frac(1.0),
                    frac(7.0),
                    frac(30.0),
                    q(0.5),
                    q(0.9),
                    vict as f64 / eff.max(1) as f64,
                    degx as f64 / eff.max(1) as f64
                );
                results.lock().unwrap()[j] = line;
            });
        }
    });
    for l in results.into_inner().unwrap() {
        println!("{l}");
    }
}
