//! Lab 2026-11-10: bounded model of `SubscribeToTask fromSeq` resume (due diligence §4.4, §4.5, M1 step 6).
//!
//! One task on a server node (beta) produces N events. One client (alpha) consumes them over a stream that can
//! be disconnected, and resumes with `SubscribeToTask(fromSeq)`. Both sides can crash. The model explores every
//! interleaving (BFS, hashed states) under a fault budget, and checks each *quiescent* state (producer done,
//! client attached live, nothing in flight) against the ground truth: the server's durable event log.
//!
//! Design axes (each a choice the spec has not pinned yet):
//!
//! * Producer (server, per event):
//!   - `P1` persist, then publish (two steps; a crash can fall between them)
//!   - `P2` publish, then persist (publish-before-durable)
//!   - `P3` persist+publish atomically under a per-task lock
//!   `seq` is the next free log slot (log length + 1). After a server crash the agent re-executes from the last
//!   persisted event, and a regenerated event gets *different content* (LLM agents are not deterministic).
//! * Handoff (server, on SubscribeToTask from start s):
//!   - `H1` read log >= s, then attach to live publishes
//!   - `H2` attach (buffer live), read log >= s, flush buffer (no filter)
//!   - `H3` as H2, but the flush drops buffered events with seq <= last replayed seq
//!   - `H4` read + attach as one atomic step (per-task lock); only a full lock if the producer is `P3`
//! * fromSeq meaning (client sends, server reads):
//!   - `Fok` both agree (client asks for "after cursor" and server serves seq > cursor)
//!   - `Fdup` client sends last seen, server treats it as inclusive (serves seq >= cursor)
//!   - `Fskip` client sends next wanted (cursor + 1), server treats it as exclusive (serves seq > cursor + 1)
//! * Client receive rule:
//!   - `C1` drop seq <= cursor, resubscribe on a gap (seq > cursor + 1), else apply
//!   - `C2` apply whatever arrives, cursor = seq
//! * Client durability (effect = appending the event to the client's durable task view):
//!   - `K1` effect and cursor in one transaction
//!   - `K2` effect, then cursor (crash between = replay after restart)
//!   - `K3` cursor, then effect (crash between = skipped after restart)

use std::collections::{HashMap, VecDeque};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum P { P1, P2, P3 }
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum H { H1, H2, H3, H4 }
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum F { Fok, Fdup, Fskip }
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum C { C1, C2 }
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum K { K1, K2, K3 }

#[derive(Clone, Copy, Debug)]
struct Cfg { p: P, h: H, f: F, c: C, k: K }

impl Cfg {
    fn name(&self) -> String { format!("{:?}-{:?}-{:?}-{:?}-{:?}", self.p, self.h, self.f, self.c, self.k) }
}

#[derive(Clone, Copy, Debug)]
struct Budget { name: &'static str, srv: u8, cli: u8, disc: u8 }

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
struct St {
    // server, durable
    log: Vec<u8>, // log[i] = content of seq i+1; content = gen*16 + logical index
    // server, volatile
    gen: u8,
    pending: Option<(u8, u8)>, // event whose first producer step is done: (seq, content)
    attached: u8,              // 0 none, 1 buffering, 2 live
    livebuf: Vec<(u8, u8)>,
    handoff: Option<(u8, u8, u8)>, // (start, stage, replay_max)
    chan: VecDeque<(u8, u8)>,
    // client
    connected: bool,
    cur_mem: u8,
    cur_dur: u8,
    applied: Vec<(u8, u8)>, // durable effect
    cproc: Option<u8>,      // second half of a K2/K3 apply still to do (seq)
    k3c: u8,                // K3: content still to apply in the second half
    // fault and protocol counters
    srv: u8,
    cli: u8,
    disc: u8,
    gapresub: u8,
}

#[derive(Default, Clone, Copy)]
struct Outcome { loss: bool, midloss: bool, dup: bool, phantom: bool, reorder: bool }
impl Outcome {
    fn bad(&self) -> bool { self.loss || self.dup || self.phantom || self.reorder }
}

fn judge(s: &St) -> Outcome {
    let truth: Vec<(u8, u8)> = s.log.iter().enumerate().map(|(i, &c)| (i as u8 + 1, c)).collect();
    let mut o = Outcome::default();
    for t in &truth {
        if !s.applied.contains(t) {
            o.loss = true;
            // silent mid-stream loss: the client applied something later in the true log, so it cannot stall-detect
            if truth.iter().any(|u| u.0 > t.0 && s.applied.contains(u)) { o.midloss = true; }
        }
    }
    for (i, a) in s.applied.iter().enumerate() {
        if !truth.contains(a) { o.phantom = true; }
        if s.applied[..i].contains(a) { o.dup = true; }
    }
    // reorder: first occurrences not in increasing seq order
    let mut seen: Vec<(u8, u8)> = Vec::new();
    for a in &s.applied { if !seen.contains(a) { seen.push(*a); } }
    if seen.windows(2).any(|w| w[0].0 >= w[1].0) { o.reorder = true; }
    o
}

fn publish(s: &mut St, ev: (u8, u8)) {
    match s.attached { 1 => s.livebuf.push(ev), 2 => s.chan.push_back(ev), _ => {} }
}

fn drop_conn(s: &mut St) {
    s.connected = false;
    s.attached = 0;
    s.livebuf.clear();
    s.handoff = None;
    s.chan.clear();
}

fn replay(s: &mut St, start: u8) -> u8 {
    let mut m = start.saturating_sub(1);
    for (i, &c) in s.log.iter().enumerate() {
        let seq = i as u8 + 1;
        if seq >= start { s.chan.push_back((seq, c)); m = seq; }
    }
    m
}

fn apply(s: &mut St, cfg: &Cfg, seq: u8, c: u8) {
    match cfg.k {
        K::K1 => { s.applied.push((seq, c)); s.cur_mem = seq; s.cur_dur = seq; }
        K::K2 => { s.applied.push((seq, c)); s.cur_mem = seq; s.cproc = Some(seq); }
        K::K3 => { s.cur_dur = seq; s.cur_mem = seq; s.cproc = Some(seq); s.k3c = c; }
    }
}

const GAP_LIMIT: u8 = 6;

enum Next { State(St), Livelock }

fn successors(s: &St, cfg: &Cfg, n: u8, b: &Budget) -> Vec<(&'static str, Next)> {
    let mut out: Vec<(&'static str, Next)> = Vec::new();
    // producer
    if s.pending.is_none() && (s.log.len() as u8) < n {
        let seq = s.log.len() as u8 + 1;
        let content = s.gen * 16 + (seq - 1);
        let mut t = s.clone();
        match cfg.p {
            P::P1 => { t.log.push(content); t.pending = Some((seq, content)); out.push(("persist", Next::State(t))); }
            P::P2 => { publish(&mut t, (seq, content)); t.pending = Some((seq, content)); out.push(("publish", Next::State(t))); }
            P::P3 => { t.log.push(content); publish(&mut t, (seq, content)); out.push(("persist+publish", Next::State(t))); }
        }
    }
    if let Some((seq, content)) = s.pending {
        let mut t = s.clone();
        t.pending = None;
        match cfg.p {
            P::P1 => { publish(&mut t, (seq, content)); out.push(("publish", Next::State(t))); }
            P::P2 => { t.log.push(content); out.push(("persist", Next::State(t))); }
            P::P3 => unreachable!(),
        }
    }
    // handoff
    if let Some((start, stage, rmax)) = s.handoff {
        let mut t = s.clone();
        match (cfg.h, stage) {
            (H::H1, 0) => { let m = replay(&mut t, start); t.handoff = Some((start, 1, m)); out.push(("ho:read", Next::State(t))); }
            (H::H1, _) => { t.attached = 2; t.handoff = None; out.push(("ho:attach", Next::State(t))); }
            (H::H2 | H::H3, 0) => { t.attached = 1; t.handoff = Some((start, 1, rmax)); out.push(("ho:attach-buf", Next::State(t))); }
            (H::H2 | H::H3, 1) => { let m = replay(&mut t, start); t.handoff = Some((start, 2, m)); out.push(("ho:read", Next::State(t))); }
            (H::H2 | H::H3, _) => {
                let buf = std::mem::take(&mut t.livebuf);
                for ev in buf { if cfg.h == H::H2 || ev.0 > rmax { t.chan.push_back(ev); } }
                t.attached = 2; t.handoff = None; out.push(("ho:flush", Next::State(t)));
            }
            (H::H4, _) => { replay(&mut t, start); t.attached = 2; t.handoff = None; out.push(("ho:read+attach", Next::State(t))); }
        }
    }
    // client second half
    if let Some(seq) = s.cproc {
        let mut t = s.clone();
        t.cproc = None;
        match cfg.k {
            K::K2 => { t.cur_dur = seq; out.push(("c:save-cursor", Next::State(t))); }
            K::K3 => { let c = t.k3c; t.applied.push((seq, c)); t.k3c = 0; out.push(("c:apply", Next::State(t))); }
            K::K1 => unreachable!(),
        }
    }
    // client receive
    if s.connected && s.cproc.is_none() {
        if let Some(&(seq, c)) = s.chan.front() {
            let mut t = s.clone();
            t.chan.pop_front();
            match cfg.c {
                C::C1 if seq <= t.cur_mem => out.push(("c:drop-old", Next::State(t))),
                C::C1 if seq > t.cur_mem + 1 => {
                    drop_conn(&mut t);
                    t.gapresub += 1;
                    if t.gapresub > GAP_LIMIT { out.push(("c:gap", Next::Livelock)); } else { out.push(("c:gap-resub", Next::State(t))); }
                }
                _ => { apply(&mut t, cfg, seq, c); out.push(("c:recv", Next::State(t))); }
            }
        }
    }
    // client subscribe
    if !s.connected {
        let mut t = s.clone();
        let start = match cfg.f { F::Fok => s.cur_mem + 1, F::Fdup => s.cur_mem.max(1), F::Fskip => s.cur_mem + 2 };
        t.connected = true;
        t.handoff = Some((start, 0, start - 1));
        out.push(("c:subscribe", Next::State(t)));
    }
    // faults
    if s.connected && s.disc < b.disc {
        let mut t = s.clone(); drop_conn(&mut t); t.disc += 1; out.push(("F:disconnect", Next::State(t)));
    }
    if s.cli < b.cli {
        let mut t = s.clone(); drop_conn(&mut t); t.cli += 1; t.cproc = None; t.k3c = 0; t.cur_mem = t.cur_dur;
        out.push(("F:client-crash", Next::State(t)));
    }
    if s.srv < b.srv {
        let mut t = s.clone(); drop_conn(&mut t); t.srv += 1; t.pending = None; t.gen += 1;
        out.push(("F:server-crash", Next::State(t)));
    }
    out
}

fn quiescent(s: &St, n: u8) -> bool {
    s.log.len() as u8 == n && s.pending.is_none() && s.connected && s.handoff.is_none() && s.chan.is_empty()
        && s.cproc.is_none()
}

#[derive(Default, Clone)]
struct Report {
    states: usize,
    quiescent: usize,
    loss: usize,
    midloss: usize,
    dup: usize,
    phantom: usize,
    reorder: usize,
    livelock: usize,
    example: Option<String>,
}
impl Report {
    fn bad(&self) -> bool { self.loss + self.dup + self.phantom + self.reorder + self.livelock > 0 }
    fn kinds(&self) -> String {
        let mut v = Vec::new();
        if self.midloss > 0 { v.push("midloss"); } else if self.loss > 0 { v.push("tailloss"); }
        if self.dup > 0 { v.push("dup"); }
        if self.phantom > 0 { v.push("phantom"); }
        if self.reorder > 0 { v.push("reorder"); }
        if self.livelock > 0 { v.push("livelock"); }
        if v.is_empty() { "ok".into() } else { v.join("+") }
    }
}

fn explore(cfg: &Cfg, n: u8, b: &Budget) -> Report {
    let init = St {
        log: vec![], gen: 0, pending: None, attached: 2, livebuf: vec![], handoff: None, chan: VecDeque::new(),
        connected: true, cur_mem: 0, cur_dur: 0, applied: vec![], cproc: None, k3c: 0, srv: 0, cli: 0, disc: 0,
        gapresub: 0,
    };
    let mut idx: HashMap<St, usize> = HashMap::new();
    let mut states: Vec<St> = vec![init.clone()];
    let mut parent: Vec<(usize, &'static str)> = vec![(usize::MAX, "init")];
    idx.insert(init, 0);
    let mut q = VecDeque::from([0usize]);
    let mut r = Report::default();
    let trace = |parent: &Vec<(usize, &'static str)>, mut i: usize, last: &str| -> String {
        let mut v = vec![last.to_string()];
        while parent[i].0 != usize::MAX { v.push(parent[i].1.to_string()); i = parent[i].0; }
        v.reverse();
        v.join(" > ")
    };
    while let Some(i) = q.pop_front() {
        let s = states[i].clone();
        if quiescent(&s, n) {
            r.quiescent += 1;
            let o = judge(&s);
            if o.loss { r.loss += 1; }
            if o.midloss { r.midloss += 1; }
            if o.dup { r.dup += 1; }
            if o.phantom { r.phantom += 1; }
            if o.reorder { r.reorder += 1; }
            if o.bad() && r.example.is_none() {
                let truth: Vec<String> = s.log.iter().enumerate().map(|(k, c)| format!("{}:{}", k + 1, c)).collect();
                let got: Vec<String> = s.applied.iter().map(|(a, c)| format!("{}:{}", a, c)).collect();
                r.example = Some(format!("{}  => log [{}] client [{}]", trace(&parent, i, "quiescent"),
                    truth.join(" "), got.join(" ")));
            }
        }
        for (label, nx) in successors(&s, cfg, n, b) {
            match nx {
                Next::Livelock => {
                    r.livelock += 1;
                    if r.example.is_none() { r.example = Some(format!("{} (gap-resubscribe loop)", trace(&parent, i, label))); }
                }
                Next::State(t) => {
                    if !idx.contains_key(&t) {
                        let j = states.len();
                        idx.insert(t.clone(), j);
                        states.push(t);
                        parent.push((i, label));
                        q.push_back(j);
                    }
                }
            }
        }
    }
    r.states = states.len();
    r
}

// ---------------- Monte Carlo ----------------

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 { self.0 ^= self.0 << 13; self.0 ^= self.0 >> 7; self.0 ^= self.0 << 17; self.0 }
    fn f(&mut self) -> f64 { (self.next() >> 11) as f64 / (1u64 << 53) as f64 }
    fn pick(&mut self, n: usize) -> usize { (self.next() % n as u64) as usize }
}

/// One task with `n` events. Each scheduler step picks a uniformly random enabled protocol action; before it, a
/// disconnect / client crash / server crash happens with the given per-step probabilities (no budget).
fn mc_task(cfg: &Cfg, n: u8, rng: &mut Rng, pd: f64, pc: f64, ps: f64) -> (Outcome, bool) {
    let inf = Budget { name: "mc", srv: u8::MAX, cli: u8::MAX, disc: u8::MAX };
    let mut s = St {
        log: vec![], gen: 0, pending: None, attached: 2, livebuf: vec![], handoff: None, chan: VecDeque::new(),
        connected: true, cur_mem: 0, cur_dur: 0, applied: vec![], cproc: None, k3c: 0, srv: 0, cli: 0, disc: 0,
        gapresub: 0,
    };
    for _ in 0..20_000 {
        if quiescent(&s, n) { return (judge(&s), false); }
        let succ = successors(&s, cfg, n, &inf);
        let (faults, normal): (Vec<_>, Vec<_>) = succ.into_iter().partition(|(l, _)| l.starts_with("F:"));
        let x = rng.f();
        let want = if x < ps { Some("F:server-crash") } else if x < ps + pc { Some("F:client-crash") }
            else if x < ps + pc + pd { Some("F:disconnect") } else { None };
        let mut chosen = None;
        if let Some(w) = want { chosen = faults.into_iter().find(|(l, _)| *l == w).map(|(_, nx)| nx); }
        let nx = match chosen { Some(nx) => nx, None => {
            if normal.is_empty() { return (judge(&s), true); }
            let k = rng.pick(normal.len());
            normal.into_iter().nth(k).unwrap().1
        }};
        match nx { Next::State(t) => { s = t; s.srv = 0; s.cli = 0; s.disc = 0; s.gapresub = 0; } Next::Livelock => return (judge(&s), true) }
        if s.gen > 200 { s.gen = 1; }
    }
    (judge(&s), true)
}

fn all_cfgs() -> Vec<Cfg> {
    let mut v = Vec::new();
    for p in [P::P1, P::P2, P::P3] { for h in [H::H1, H::H2, H::H3, H::H4] { for f in [F::Fok, F::Fdup, F::Fskip] {
        for c in [C::C1, C::C2] { for k in [K::K1, K::K2, K::K3] { v.push(Cfg { p, h, f, c, k }); } } } } }
    v
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let n: u8 = args.get(1).and_then(|x| x.parse().ok()).unwrap_or(4);
    let budgets = [
        Budget { name: "none", srv: 0, cli: 0, disc: 0 },
        Budget { name: "disc2", srv: 0, cli: 0, disc: 2 },
        Budget { name: "cli1", srv: 0, cli: 1, disc: 0 },
        Budget { name: "srv1", srv: 1, cli: 0, disc: 0 },
        Budget { name: "all", srv: 1, cli: 1, disc: 2 },
    ];
    println!("# exhaustive, N = {n} events per task");
    println!("config\t{}\tstates(all)\tquiescent(all)", budgets.iter().map(|b| b.name).collect::<Vec<_>>().join("\t"));
    let mut tot_states = 0usize;
    let mut tot_q = 0usize;
    let mut ok_all = Vec::new();
    let mut examples: Vec<(String, String, String)> = Vec::new();
    for cfg in all_cfgs() {
        let mut cols = Vec::new();
        let mut last = Report::default();
        for b in &budgets {
            let r = explore(&cfg, n, b);
            tot_states += r.states;
            tot_q += r.quiescent;
            cols.push(r.kinds());
            if let Some(e) = &r.example { examples.push((cfg.name(), b.name.to_string(), e.clone())); }
            last = r;
        }
        if !last.bad() { ok_all.push(cfg.name()); }
        println!("{}\t{}\t{}\t{}", cfg.name(), cols.join("\t"), last.states, last.quiescent);
    }
    println!("\n# total states explored {tot_states}, quiescent states judged {tot_q}");
    println!("# configs correct under budget 'all': {}", ok_all.len());
    for c in &ok_all { println!("OK\t{c}"); }
    println!("\n# shortest counterexample per (config, budget), first bad state found by BFS");
    for (c, b, e) in &examples { println!("CEX\t{c}\t{b}\t{e}"); }

    if args.get(2).map(|x| x == "0").unwrap_or(false) { return; }
    // Monte Carlo
    let tasks: usize = args.get(2).and_then(|x| x.parse().ok()).unwrap_or(2000);
    let mn: u8 = 40;
    let (pd, pc, ps) = (0.01, 0.001, 0.001);
    println!("\n# Monte Carlo: {tasks} tasks x {mn} events, per-step p(disconnect)={pd} p(client crash)={pc} p(server crash)={ps}");
    println!("config\tbad%\tloss%\tmidloss%\tdup%\tphantom%\treorder%\tlivelock%");
    let mut rng = Rng(0x9E3779B97F4A7C15);
    let base = Cfg { p: P::P3, h: H::H3, f: F::Fok, c: C::C1, k: K::K1 };
    let mut sel = vec![base, Cfg { p: P::P1, h: H::H4, f: F::Fok, c: C::C1, k: K::K1 }];
    for p in [P::P1, P::P2] { sel.push(Cfg { p, ..base }); }
    for h in [H::H1, H::H2, H::H4] { sel.push(Cfg { h, ..base }); }
    for f in [F::Fdup, F::Fskip] { sel.push(Cfg { f, ..base }); }
    sel.push(Cfg { c: C::C2, ..base });
    sel.push(Cfg { p: P::P1, c: C::C2, ..base });
    sel.push(Cfg { p: P::P1, h: H::H2, c: C::C2, ..base });
    for k in [K::K2, K::K3] { sel.push(Cfg { k, ..base }); }
    for cfg in sel {
        let (mut bad, mut loss, mut mid, mut dup, mut ph, mut ro, mut ll) = (0, 0, 0, 0, 0, 0, 0);
        for _ in 0..tasks {
            let (o, live) = mc_task(&cfg, mn, &mut rng, pd, pc, ps);
            if live { ll += 1; bad += 1; continue; }
            if o.bad() { bad += 1; }
            if o.loss { loss += 1; } if o.midloss { mid += 1; } if o.dup { dup += 1; } if o.phantom { ph += 1; } if o.reorder { ro += 1; }
        }
        let pct = |x: usize| 100.0 * x as f64 / tasks as f64;
        println!("{}\t{:.2}\t{:.2}\t{:.2}\t{:.2}\t{:.2}\t{:.2}\t{:.2}", cfg.name(), pct(bad), pct(loss), pct(mid), pct(dup), pct(ph), pct(ro), pct(ll));
    }
}
