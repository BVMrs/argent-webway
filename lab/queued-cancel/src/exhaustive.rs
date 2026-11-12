//! Exhaustive interleaving model: one create envelope C (SendMessage, new task) and one cancel
//! intent from requester R to receiver S, which is offline when C is sent.
//!
//! Copies: C and every cancel envelope X have a direct (outbox) copy and a mailbox copy. A copy can
//! be delivered at any time after S is up (O1), or the paths are FIFO (O2: mailbox FIFO per sender,
//! outbox head-of-line, so a direct X is only sent once R holds C's response).
//! Faults: C's hand-off to the mailbox may fail (C only goes direct), R may go offline for good
//! after the intent, S may crash once (task store and dedupe are durable; a volatile tombstone is lost).
//! Time: `Ce` = now > C.exp + skew (C copies rejected afterwards). `Xe` = now > X.exp + skew
//! (X copies rejected afterwards, tombstone dropped). For D3r, X.exp >= C.exp so `Xe` only after `Ce`.
//!
//! A run is judged in every terminal state (no event enabled).

use std::collections::HashSet;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Design {
    /// A2A as written: CancelTask{taskId}; R must wait for the response that carries the taskId.
    D0,
    /// Cancel by reference to C's (from, messageId); unknown -> TaskNotFound, final, deduped.
    D1,
    /// As D1 but NotFound is retryable and not stored in dedupe; R keeps retrying while online.
    D2,
    /// As D1 but an unknown reference stores a tombstone until X.exp + skew; X has its own TTL.
    D3s,
    /// As D3s with X.exp >= referenced C.exp (tombstone outlives every acceptable C copy).
    D3r,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Task { None, Sub, Work, Done, Canc }

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Env { C, X }

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Path { Direct, Mbox }

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Belief { Nothing, Canceled, Pending, NotCancelable, NotFound }

#[derive(Clone, PartialEq, Eq, Hash)]
struct St {
    s_up: bool,
    pend: Vec<(Env, Path)>, // in hand-off order
    task: Task,
    c_seen: bool,     // dedupe entry for C
    x_deduped: bool,  // dedupe entry for X (a stored final answer)
    tomb: u8,         // 0 none, 1 live
    crashed: bool,
    ce: bool,
    xe: bool,
    // requester
    intent: bool,
    deferred: bool,
    x_sent: bool,
    r_off: bool,
    resp_pending: bool,
    r_resp: bool,
    belief: Belief,
    retries: u8,
    // trace
    intent_before_create: bool,
    work_after_intent: bool,
    x_arrived_live: bool, // an X copy reached S while the task was not Done (or did not exist)
    work_after_x: bool,
}

#[derive(Clone, Copy)]
pub struct Cfg {
    pub design: Design,
    pub fifo: bool,
    pub tomb_volatile: bool,
    pub hfail: bool,
    pub roff: bool,
    pub crash: bool,
}

#[derive(Default, Debug, Clone)]
pub struct Tally {
    pub terminals: u64,
    pub with_intent: u64,
    pub queued_intent: u64,
    pub queued_work_started: u64,   // intent before C processed, yet the agent started work
    pub lost: u64,                  // an X reached S before completion, task still completed
    pub unsent: u64,                // intent before completion, no X ever sent, task completed
    pub run_after_cancel: u64,      // agent started work after an X reached S
    pub misled: u64,                // R believes canceled/pending, task completed
    pub uncertain: u64,             // R's last answer is NotFound
    pub spurious: u64,              // canceled without intent
    pub states: u64,
}

fn send_x(s: &mut St, cfg: &Cfg) {
    s.x_sent = true;
    s.x_deduped = false;
    s.pend.push((Env::X, Path::Direct));
    if !(cfg.design == Design::D0) {
        s.pend.push((Env::X, Path::Mbox));
    }
}

fn enabled(s: &St, cfg: &Cfg) -> Vec<u8> {
    // event codes: 0 SUp, 1 Intent, 2 RespArrive, 3 ROff, 4 Work, 5 Finish, 6 Ce, 7 Xe, 8 Crash, 100+i deliver i
    let mut v = Vec::new();
    if !s.s_up { v.push(0); }
    if !s.intent && !s.r_off { v.push(1); }
    if s.resp_pending && !s.r_off { v.push(2); }
    if cfg.roff && s.intent && !s.r_off { v.push(3); }
    if s.task == Task::Sub { v.push(4); }
    if s.task == Task::Work { v.push(5); }
    if !s.ce { v.push(6); }
    if s.x_sent && !s.xe && (cfg.design != Design::D3r || s.ce) { v.push(7); }
    if cfg.crash && s.s_up && !s.crashed { v.push(8); }
    if s.s_up {
        let mut first_mbox = true;
        for (i, &(e, p)) in s.pend.iter().enumerate() {
            let ok = if !cfg.fifo {
                true
            } else {
                match p {
                    Path::Mbox => {
                        let f = first_mbox;
                        first_mbox = false;
                        f
                    }
                    Path::Direct => e == Env::C || s.r_resp,
                }
            };
            if ok { v.push(100 + i as u8); }
        }
    }
    v
}

fn step(s: &St, ev: u8, cfg: &Cfg) -> St {
    let mut n = s.clone();
    match ev {
        0 => n.s_up = true,
        1 => {
            n.intent = true;
            if n.task == Task::None && !n.c_seen { n.intent_before_create = true; }
            if cfg.design == Design::D0 {
                if n.r_resp { send_x(&mut n, cfg) } else { n.deferred = true }
            } else {
                send_x(&mut n, cfg);
            }
        }
        2 => {
            n.resp_pending = false;
            n.r_resp = true;
            if n.deferred { n.deferred = false; send_x(&mut n, cfg); }
            // stop direct retries of C once its response is in
            n.pend.retain(|&(e, p)| !(e == Env::C && p == Path::Direct));
        }
        3 => n.r_off = true,
        4 => {
            n.task = Task::Work;
            if n.intent { n.work_after_intent = true; }
            if n.x_arrived_live { n.work_after_x = true; }
        }
        5 => n.task = Task::Done,
        6 => n.ce = true,
        7 => { n.xe = true; n.tomb = 0; }
        8 => { n.crashed = true; if cfg.tomb_volatile { n.tomb = 0; } }
        _ => {
            let i = (ev - 100) as usize;
            let (e, _p) = n.pend.remove(i);
            match e {
                Env::C => {
                    if n.ce || n.c_seen {
                        // expired or duplicate: no effect (duplicate gets the stored response)
                    } else {
                        n.c_seen = true;
                        n.task = if n.tomb == 1 { Task::Canc } else { Task::Sub };
                        n.resp_pending = true;
                        if n.task == Task::Canc && !n.r_off { n.belief = Belief::Canceled; }
                    }
                }
                Env::X => {
                    if n.xe || n.x_deduped {
                        // expired, or a duplicate of an X already answered: stored answer, no effect
                    } else {
                        if n.task != Task::Done { n.x_arrived_live = true; }
                        let b = match n.task {
                            Task::Sub | Task::Work => { n.task = Task::Canc; n.x_deduped = true; Belief::Canceled }
                            Task::Canc => { n.x_deduped = true; Belief::Canceled }
                            Task::Done => { n.x_deduped = true; Belief::NotCancelable }
                            Task::None => match cfg.design {
                                Design::D0 | Design::D1 => { n.x_deduped = true; Belief::NotFound }
                                Design::D2 => {
                                    if !n.r_off && !n.ce && n.retries < 2 {
                                        n.retries += 1;
                                        n.pend.push((Env::X, Path::Direct));
                                    }
                                    Belief::NotFound
                                }
                                Design::D3s | Design::D3r => { n.tomb = 1; n.x_deduped = true; Belief::Pending }
                            },
                        };
                        if !n.r_off { n.belief = b; }
                    }
                }
            }
        }
    }
    n
}

fn judge(s: &St, t: &mut Tally) {
    t.terminals += 1;
    if !s.intent {
        if s.task == Task::Canc { t.spurious += 1; }
        return;
    }
    t.with_intent += 1;
    if s.intent_before_create {
        t.queued_intent += 1;
        if s.work_after_intent { t.queued_work_started += 1; }
    }
    if s.task == Task::Done {
        if s.x_arrived_live { t.lost += 1; }
        if !s.x_sent { t.unsent += 1; }
        if matches!(s.belief, Belief::Canceled | Belief::Pending) { t.misled += 1; }
    }
    if s.work_after_x { t.run_after_cancel += 1; }
    if s.belief == Belief::NotFound { t.uncertain += 1; }
}

pub fn run(cfg: Cfg) -> Tally {
    let init = St {
        s_up: false,
        pend: if cfg.hfail { vec![(Env::C, Path::Direct)] } else { vec![(Env::C, Path::Mbox), (Env::C, Path::Direct)] },
        task: Task::None,
        c_seen: false,
        x_deduped: false,
        tomb: 0,
        crashed: false,
        ce: false,
        xe: false,
        intent: false,
        deferred: false,
        x_sent: false,
        r_off: false,
        resp_pending: false,
        r_resp: false,
        belief: Belief::Nothing,
        retries: 0,
        intent_before_create: false,
        work_after_intent: false,
        x_arrived_live: false,
        work_after_x: false,
    };
    let mut seen: HashSet<St> = HashSet::new();
    let mut stack = vec![init];
    let mut t = Tally::default();
    while let Some(s) = stack.pop() {
        if !seen.insert(s.clone()) { continue; }
        let evs = enabled(&s, &cfg);
        if evs.is_empty() { judge(&s, &mut t); continue; }
        for ev in evs { stack.push(step(&s, ev, &cfg)); }
    }
    t.states = seen.len() as u64;
    t
}
