//! Lab: how must a node meter a stateful `max_calls` caveat (due diligence §4.7.2, M1 step 1)?
//!
//! PART A (exhaustive). One holder has a remaining budget of L = 2 calls on one root token and issues
//! NCALL = 3 distinct calls (distinct envelope ids). Beta runs 2 concurrent workers. Each envelope goes through
//! the stages of the design under test:
//!
//!   Env     envelope freshness/sig/to (only the adversary's stale envelope fails here)
//!   Dedupe  durable (from,id) index lookup; a hit answers with the stored response
//!   Authz   Datalog check, reads the counter v and denies (CapabilityDenied, final) if v >= L
//!   IncPre  increments the counter now (P=Pre durable, P=Mem in memory)
//!   Commit  conditional insert of (dedupe entry, task); if the id already exists it is a duplicate and gets
//!           the stored response (unique key); with P=Atx the counter is incremented in this transaction
//!   IncPost increments the durable counter after the commit (P=Post)
//!   Ack     sends Accepted
//!
//! Design axes:
//!   O  stage order   O1 Env>Dedupe>Authz   O2 Env>Authz>Dedupe   O3 Authz>Env>Dedupe
//!                    O4 Env>Txn, where Txn is one serialisable transaction {dedupe lookup; count check;
//!                       insert task + counter++} (P and R do not apply)
//!   P  counter       Atx (in commit txn) | Pre (durable, at authz) | Post (durable, after commit) | Mem (RAM)
//!   R  concurrency   Lock (per-root lock from Authz to the counter/commit step) | NoLock (read, write later)
//!   C  what counts   Adm (admitted tasks) | Cmp (completed tasks; P is n/a, counted in the completion txn)
//!
//! Faults (budgeted): lost response, server crash (drops RAM, inbox and in-progress work), early client retry
//! (timeout while the first copy is still being processed), mailbox replay of an honest envelope inside the
//! horizon, an adversary delivering a stale (expired, past exp+skew) envelope of the same holder.
//! Clients retry freely once nothing of a call is in flight. Every quiescent state is judged:
//!   over      more than L tasks created (budget exceeded)
//!   burn      fewer than L tasks created although NCALL > L calls were made (budget lost)
//!   mismatch  a client was told CapabilityDenied but its task exists (it ran, and it was counted)
//!
//! PART B (Monte Carlo). Random delegation trees with optional max_calls caveats in any block; random use
//! sequences. Each counter-keying scheme decides each call; the decision is compared against the ideal
//! per-block rule (a caveat in block j bounds the calls made through chains that contain block j).

use std::collections::{HashMap, VecDeque};

const L: u8 = 2;
const NCALL: usize = 3;
const NW: usize = 2;
const STALE: u8 = NCALL as u8;
const NTHREADS: usize = 3;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum O { O1, O2, O3, O4 }
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum P { Atx, Pre, Post, Mem }
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum R { Lock, NoLock }
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum C { Adm, Cmp }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum St { Env, Dedupe, Authz, IncPre, Commit, IncPost, Ack, Txn }

#[derive(Clone, Copy, Debug)]
struct Design { o: O, p: P, r: R, c: C }

impl Design {
    fn name(&self) -> String {
        if self.o == O::O4 { return "O4-Txn".into(); }
        match self.c {
            C::Adm => format!("{:?}-{:?}-{:?}-Adm", self.o, self.p, self.r),
            C::Cmp => format!("{:?}-Cmp-{:?}", self.o, self.r),
        }
    }
    fn program(&self) -> Vec<St> {
        if self.o == O::O4 { return vec![St::Env, St::Txn, St::Ack]; }
        let pre = self.c == C::Adm && matches!(self.p, P::Pre | P::Mem);
        let post = self.c == C::Adm && self.p == P::Post;
        let mut v = vec![];
        let authz: Vec<St> = if pre { vec![St::Authz, St::IncPre] } else { vec![St::Authz] };
        match self.o {
            O::O1 => { v.push(St::Env); v.push(St::Dedupe); v.extend(authz); }
            O::O2 => { v.push(St::Env); v.extend(authz); v.push(St::Dedupe); }
            O::O3 => { v.extend(authz); v.push(St::Env); v.push(St::Dedupe); }
            O::O4 => unreachable!(),
        }
        v.push(St::Commit);
        if post { v.push(St::IncPost); }
        v.push(St::Ack);
        v
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct Worker { msg: u8, pc: u8, lock: bool }

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct S {
    // durable
    tasks: u8,     // bitmask of calls with a task
    done: u8,      // bitmask of completed tasks (C=Cmp)
    ctr: u8,       // durable counter
    // volatile
    mem: u8,
    lock: bool,
    inbox: [u8; 4], // multiset of msg codes (counts; code 3 = stale)
    w: [Option<Worker>; NW],
    // network back to client: multiset (counts) of (call<<1 | accepted)
    resp: [u8; 6],
    // client: 0 not sent, 1 waiting, 2 accepted, 3 denied
    cl: [u8; NCALL],
    // remaining fault budget: lost, crash, early, replay, stale
    b: [u8; 5],
}

#[derive(Clone, Copy)]
struct Budget { lost: u8, crash: u8, early: u8, replay: u8, stale: u8 }

fn ins<const N: usize>(v: &mut [u8; N], x: u8) { v[x as usize] += 1; }
fn rm<const N: usize>(v: &mut [u8; N], x: u8) { assert!(v[x as usize] > 0); v[x as usize] -= 1; }
fn has<const N: usize>(v: &[u8; N], x: u8) -> bool { v[x as usize] > 0 }
fn items<const N: usize>(v: &[u8; N]) -> impl Iterator<Item = u8> + '_ { (0..N as u8).filter(move |&i| v[i as usize] > 0) }

fn read_count(d: &Design, s: &S) -> u8 {
    match d.c {
        C::Cmp => s.done.count_ones() as u8,
        C::Adm => if d.p == P::Mem { s.mem } else { s.ctr },
    }
}

/// all successors with an action label
fn succ(d: &Design, prog: &[St], s: &S) -> Vec<(String, S)> {
    let mut out = vec![];
    // client sends / retries
    for i in 0..NCALL {
        let ci = i as u8;
        if s.cl[i] == 0 {
            let mut t = s.clone(); t.cl[i] = 1; ins(&mut t.inbox, ci);
            out.push((format!("send{}", i), t));
        } else if s.cl[i] == 1 {
            let in_flight = has(&s.inbox, ci)
                || s.w.iter().any(|w| matches!(w, Some(x) if x.msg == ci))
                || has(&s.resp, ci << 1) || has(&s.resp, (ci << 1) | 1);
            if !in_flight {
                let mut t = s.clone(); ins(&mut t.inbox, ci);
                out.push((format!("retry{}", i), t));
            } else if s.b[2] > 0 {
                let mut t = s.clone(); t.b[2] -= 1; ins(&mut t.inbox, ci);
                out.push((format!("F:early-retry{}", i), t));
            }
        }
        // mailbox replay of a sent envelope
        if s.cl[i] != 0 && s.b[3] > 0 {
            let mut t = s.clone(); t.b[3] -= 1; ins(&mut t.inbox, ci);
            out.push((format!("F:replay{}", i), t));
        }
    }
    if s.b[4] > 0 {
        let mut t = s.clone(); t.b[4] -= 1; ins(&mut t.inbox, STALE);
        out.push(("F:stale".into(), t));
    }
    // responses
    for r in items(&s.resp) {
        let ci = (r >> 1) as usize;
        let mut t = s.clone(); rm(&mut t.resp, r);
        if t.cl[ci] == 1 { t.cl[ci] = if r & 1 == 1 { 2 } else { 3 }; }
        out.push((format!("c:recv{}{}", ci, if r & 1 == 1 { "ok" } else { "denied" }), t));
        if s.b[0] > 0 {
            let mut t = s.clone(); rm(&mut t.resp, r); t.b[0] -= 1;
            out.push((format!("F:lose-resp{}", ci), t));
        }
    }
    // crash
    if s.b[1] > 0 {
        let mut t = s.clone(); t.b[1] -= 1;
        t.mem = 0; t.lock = false; t.inbox = [0; 4]; t.w = [None; NW];
        out.push(("F:crash".into(), t));
    }
    // completion (C=Cmp)
    if d.c == C::Cmp {
        for i in 0..NCALL {
            if s.tasks & (1 << i) != 0 && s.done & (1 << i) == 0 {
                let mut t = s.clone(); t.done |= 1 << i;
                out.push((format!("complete{}", i), t));
            }
        }
    }
    // workers pick up
    for wi in 0..NW {
        if s.w[wi].is_none() {
            for m in items(&s.inbox) {
                let mut t = s.clone(); rm(&mut t.inbox, m);
                t.w[wi] = Some(Worker { msg: m, pc: 0, lock: false });
                out.push((format!("w{}:take{}", wi, m), t));
            }
        }
    }
    // worker steps
    for wi in 0..NW {
        let Some(wk) = s.w[wi] else { continue };
        let st = prog[wk.pc as usize];
        let m = wk.msg;
        let mut t = s.clone();
        let finish = |t: &mut S, rel: bool| { if rel { t.lock = false; } t.w[wi] = None; };
        let label = format!("w{}:{:?}{}", wi, st, m);
        match st {
            St::Env => {
                if m == STALE { finish(&mut t, wk.lock); }
                else { t.w[wi].as_mut().unwrap().pc += 1; }
            }
            St::Dedupe => {
                if m != STALE && t.tasks & (1 << m) != 0 {
                    ins(&mut t.resp, (m << 1) | 1); finish(&mut t, wk.lock);
                } else { t.w[wi].as_mut().unwrap().pc += 1; }
            }
            St::Authz => {
                let mut lk = false;
                if d.r == R::Lock { if s.lock { continue; } lk = true; t.lock = true; }
                let v = read_count(d, &t);
                if v >= L {
                    if m != STALE { ins(&mut t.resp, m << 1); }
                    finish(&mut t, lk);
                } else { let w = t.w[wi].as_mut().unwrap(); w.pc += 1; w.lock = lk; }
            }
            St::IncPre => {
                if d.p == P::Mem { t.mem += 1; } else { t.ctr += 1; }
                t.w[wi].as_mut().unwrap().pc += 1;
            }
            St::Commit => {
                if t.tasks & (1 << m) != 0 {
                    ins(&mut t.resp, (m << 1) | 1); finish(&mut t, wk.lock);
                } else {
                    t.tasks |= 1 << m;
                    if d.c == C::Adm && d.p == P::Atx { t.ctr += 1; }
                    let post = prog[wk.pc as usize + 1] == St::IncPost;
                    let w = t.w[wi].as_mut().unwrap(); w.pc += 1;
                    if !post && w.lock { w.lock = false; t.lock = false; }
                }
            }
            St::IncPost => {
                t.ctr += 1;
                let w = t.w[wi].as_mut().unwrap(); w.pc += 1;
                if w.lock { w.lock = false; t.lock = false; }
            }
            St::Txn => {
                // one serialisable transaction: dedupe lookup, count check, insert task + counter++
                if t.tasks & (1 << m) != 0 { ins(&mut t.resp, (m << 1) | 1); finish(&mut t, false); }
                else if t.ctr >= L { ins(&mut t.resp, m << 1); finish(&mut t, false); }
                else { t.tasks |= 1 << m; t.ctr += 1; t.w[wi].as_mut().unwrap().pc += 1; }
            }
            St::Ack => { ins(&mut t.resp, (m << 1) | 1); finish(&mut t, wk.lock); }
        }
        out.push((label, t));
    }
    out
}

fn quiescent(d: &Design, s: &S) -> bool {
    s.cl.iter().all(|&c| c >= 2) && s.inbox == [0; 4] && s.w.iter().all(|w| w.is_none()) && s.resp == [0; 6]
        && (d.c == C::Adm || s.done == s.tasks)
}

#[derive(Default, Clone)]
struct Res { states: usize, quiescent: usize, over: usize, burn: usize, mismatch: usize,
             cex: [Option<String>; 3] }

fn explore(d: &Design, b: Budget) -> Res {
    let prog = d.program();
    let init = S { tasks: 0, done: 0, ctr: 0, mem: 0, lock: false, inbox: [0; 4], w: [None; NW], resp: [0; 6],
                   cl: [0; NCALL], b: [b.lost, b.crash, b.early, b.replay, b.stale] };
    let mut idx: HashMap<S, u32> = HashMap::new();
    let mut nodes: Vec<(S, u32)> = vec![];
    idx.insert(init, 0); nodes.push((init, u32::MAX));
    let mut q = VecDeque::from([0u32]);
    let mut res = Res::default();
    // labels are recomputed from the parent's successors, so they are not stored per state
    let trace = |nodes: &Vec<(S, u32)>, mut i: u32| {
        let mut v = vec![];
        while nodes[i as usize].1 != u32::MAX {
            let (s, p) = nodes[i as usize];
            let lab = succ(d, &prog, &nodes[p as usize].0).into_iter().find(|(_, t)| *t == s).unwrap().0;
            v.push(lab); i = p;
        }
        v.reverse(); v.join(" > ")
    };
    while let Some(i) = q.pop_front() {
        let s = nodes[i as usize].0;
        if quiescent(d, &s) {
            res.quiescent += 1;
            let n = s.tasks.count_ones() as u8;
            let mism = (0..NCALL).any(|c| s.cl[c] == 3 && s.tasks & (1 << c) != 0);
            let flags = [n > L, n < L, mism];
            for k in 0..3 {
                if flags[k] {
                    match k { 0 => res.over += 1, 1 => res.burn += 1, _ => res.mismatch += 1 }
                    if res.cex[k].is_none() {
                        res.cex[k] = Some(format!("{}  => tasks={} client={:?}", trace(&nodes, i), n, s.cl));
                    }
                }
            }
        }
        for (_, t) in succ(d, &prog, &s) {
            if !idx.contains_key(&t) {
                let j = nodes.len() as u32;
                idx.insert(t, j); nodes.push((t, i)); q.push_back(j);
            }
        }
    }
    res.states = nodes.len();
    res
}

// ------------------------------------------------------------------------------------------------ Part B
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 { self.0 ^= self.0 << 13; self.0 ^= self.0 >> 7; self.0 ^= self.0 << 17; self.0 }
    fn below(&mut self, n: u64) -> u64 { self.next() % n }
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum K { Root, Tail, RootTail, AuthorityOnly, Depth, Block }

fn part_b(trees: usize, calls: usize) -> Vec<(K, u64, u64, u64)> {
    let schemes = [K::Root, K::Tail, K::RootTail, K::AuthorityOnly, K::Depth, K::Block];
    let mut agg: Vec<(K, u64, u64, u64)> = schemes.iter().map(|&k| (k, 0, 0, 0)).collect();
    let mut rng = Rng(0x9e3779b97f4a7c15);
    for _ in 0..trees {
        // block 0 = authority (holder B). Each further block has a parent, a depth, an optional caveat.
        let nb = 2 + rng.below(6) as usize; // 2..7 blocks
        let mut parent = vec![usize::MAX]; let mut depth = vec![0usize];
        let mut cav: Vec<Option<u32>> = vec![Some(3 + rng.below(8) as u32)]; // root max_calls 3..10
        for _ in 1..nb {
            let p = rng.below(parent.len() as u64) as usize;
            parent.push(p); depth.push(depth[p] + 1);
            cav.push(if rng.below(2) == 0 { Some(1 + rng.below(5) as u32) } else { None });
        }
        let chain = |b: usize| { let mut v = vec![]; let mut x = b; while x != usize::MAX { v.push(x); x = parent[x]; } v.reverse(); v };
        let seq: Vec<usize> = (0..calls).map(|_| rng.below(nb as u64) as usize).collect();
        for a in agg.iter_mut() {
            let k = a.0;
            let mut per_block = vec![0u32; nb]; // ideal accounting of this scheme's own accepted history
            let mut per_tail = vec![0u32; nb];
            let mut per_depth = vec![0u32; 8];
            let mut root = 0u32;
            for &b in &seq {
                let ch = chain(b);
                let ideal = ch.iter().all(|&j| cav[j].map_or(true, |m| per_block[j] < m));
                let dec = match k {
                    K::Block => ideal,
                    K::Root => ch.iter().all(|&j| cav[j].map_or(true, |m| root < m)),
                    K::Tail => ch.iter().all(|&j| cav[j].map_or(true, |m| per_tail[b] < m)),
                    K::RootTail => ch.iter().all(|&j| cav[j].map_or(true, |m| if j == 0 { root < m } else { per_tail[b] < m })),
                    K::AuthorityOnly => cav[0].map_or(true, |m| root < m),
                    K::Depth => ch.iter().all(|&j| cav[j].map_or(true, |m| per_depth[depth[j]] < m)),
                };
                a.3 += 1;
                if dec && !ideal { a.1 += 1; }
                if !dec && ideal { a.2 += 1; }
                if dec {
                    root += 1; per_tail[b] += 1;
                    for &j in &ch { per_block[j] += 1; per_depth[depth[j]] += 1; }
                }
            }
        }
    }
    agg
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let trees: usize = args.get(1).and_then(|x| x.parse().ok()).unwrap_or(200_000);
    let mut designs = vec![];
    for o in [O::O1, O::O2, O::O3] { for p in [P::Atx, P::Pre, P::Post, P::Mem] { for r in [R::Lock, R::NoLock] {
        designs.push(Design { o, p, r, c: C::Adm });
    }}}
    for o in [O::O1, O::O2, O::O3] { for r in [R::Lock, R::NoLock] { designs.push(Design { o, p: P::Atx, r, c: C::Cmp }); } }
    designs.push(Design { o: O::O4, p: P::Atx, r: R::Lock, c: C::Adm });

    let z = Budget { lost: 0, crash: 0, early: 0, replay: 0, stale: 0 };
    let budgets: Vec<(&str, Budget)> = vec![
        ("none", z),
        ("1 lost resp", Budget { lost: 1, ..z }),
        ("1 crash", Budget { crash: 1, ..z }),
        ("1 early retry", Budget { early: 1, ..z }),
        ("1 replay", Budget { replay: 1, ..z }),
        ("1 stale", Budget { stale: 1, ..z }),
        ("all", Budget { lost: 1, crash: 1, early: 1, replay: 1, stale: 1 }),
    ];
    println!("PART A: L={} NCALL={} workers={}", L, NCALL, NW);
    let mut total_states = 0usize;
    let mut summary: Vec<(String, Vec<String>)> = vec![];
    for (bn, b) in &budgets {
        let mut fail = 0; let (mut o_, mut bu, mut mi) = (0, 0, 0);
        println!("\n=== budget: {} ===", bn);
        println!("{:<22} {:>9} {:>8} {:>8} {:>8} {:>8}", "design", "states", "quiesc", "over", "burn", "mismatch");
        // explore the designs on NTHREADS threads, print in order
        let next = std::sync::atomic::AtomicUsize::new(0);
        let slots: Vec<std::sync::Mutex<Option<Res>>> = designs.iter().map(|_| std::sync::Mutex::new(None)).collect();
        std::thread::scope(|sc| {
            for _ in 0..NTHREADS {
                sc.spawn(|| loop {
                    let k = next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if k >= designs.len() { break; }
                    let r = explore(&designs[k], *b);
                    *slots[k].lock().unwrap() = Some(r);
                });
            }
        });
        for (di, d) in designs.iter().enumerate() {
            let r = slots[di].lock().unwrap().take().unwrap();
            total_states += r.states;
            let bad = r.over + r.burn + r.mismatch > 0;
            if bad { fail += 1; }
            if r.over > 0 { o_ += 1; } if r.burn > 0 { bu += 1; } if r.mismatch > 0 { mi += 1; }
            println!("{:<22} {:>9} {:>8} {:>8} {:>8} {:>8}{}", d.name(), r.states, r.quiescent, r.over, r.burn,
                     r.mismatch, if bad { "  FAIL" } else { "" });
            if summary.len() <= di { summary.push((d.name(), vec![])); }
            let mut tags = vec![];
            if r.over > 0 { tags.push("over"); } if r.burn > 0 { tags.push("burn"); } if r.mismatch > 0 { tags.push("mismatch"); }
            summary[di].1.push(if tags.is_empty() { "ok".into() } else { tags.join("+") });
            for (k, nm) in ["over", "burn", "mismatch"].iter().enumerate() {
                if let Some(c) = &r.cex[k] { println!("    cex {}: {}", nm, c); }
            }
        }
        println!("-- {}: {} of {} designs fail (over {}, burn {}, mismatch {})", bn, fail, designs.len(), o_, bu, mi);
    }
    println!("\nSUMMARY (columns: {})", budgets.iter().map(|b| b.0).collect::<Vec<_>>().join(" | "));
    for (n, v) in &summary { println!("{:<22} {}", n, v.join(" | ")); }
    println!("total states explored: {}", total_states);

    println!("\nPART B: {} random delegation trees x 40 calls", trees);
    println!("{:<14} {:>10} {:>10} {:>10} {:>9} {:>9}", "keying", "decisions", "over", "under", "over%", "under%");
    for (k, o, u, n) in part_b(trees, 40) {
        println!("{:<14} {:>10} {:>10} {:>10} {:>8.3}% {:>8.3}%", format!("{:?}", k), n, o, u,
                 100.0 * o as f64 / n as f64, 100.0 * u as f64 / n as f64);
    }
}
