//! Exhaustive bounded model of provenance/v0 taint propagation (docs/due-diligence.md §4.7.4).
//!
//! World: owners A, B, C; nodes A1 A2 A3 (owner A), B1 B2 (owner B), C1 (owner C). Content starts at a node,
//! either from that node's agent (`agent`) or from the node's HTTP edge (`edge`, unverified). It travels along a
//! path of nodes. Each send emits a wire taint `{owners, unverified}`. An honest sender emits its stored taint
//! (optionally adding its own owner, see E0/E1). A malicious ("liar") node emits any taint it likes. The liar's
//! choice is fixed per scenario and enumerated.
//!
//! Receiver rules (policies):
//!   P0  as written:  stored taint = wire taint;  trust = min(level(sender owner), f(wire taint))
//!   P1  normalise:   stored taint = wire taint ∪ {sender owner};  trust = f(stored taint)
//!   P2  reject:      reject the envelope if wire owners lack the verified sender owner; else as P0
//! Honest sender emission:
//!   E0  emit the stored taint unchanged;   E1  emit stored taint ∪ {own owner}  ("including the sender's own owner")
//!
//! f(owners, unverified, r) = unverified-origin if unverified, foreign if owners ⊄ {r}, else same-owner.
//!
//! Ground truth for each copy of the content: owners = owners of every node that held or produced it
//! (including inputs merged in), unverified = some input came from an HTTP edge, liars = owners of liar nodes
//! that sent it or any of its inputs. At each honest receiver of owner r:
//!   - out of scope if a liar of owner r is in the history (the doc accepts same-owner laundering, mitigated by audit);
//!   - with a foreign liar in the history: RAISE if computed trust is same-owner (the liar is foreign, so the
//!     content can be at best foreign); `inherent` if truly unverified but computed foreign (a liar can drop the
//!     flag, and its content is indistinguishable from its own);
//!   - without liars: RAISE if computed > ideal, OVERTAINT if computed < ideal;
//!   - INCONSISTENT if stored trust != f(stored taint): the next hop recomputes from the stored taint, so the
//!     stored taint must carry everything the trust was based on ("the same data the next receiver recomputes from").
//!   - false reject (P2 only): an envelope from an honest sender rejected.

use std::fmt::Write as _;

const A: u8 = 1;
const B: u8 = 2;
const C: u8 = 4;
const OWNER: [u8; 6] = [A, A, A, B, B, C];
const NAME: [&str; 6] = ["A1", "A2", "A3", "B1", "B2", "C1"];
const N: usize = 6;

const UNV: u8 = 0;
const FOREIGN: u8 = 1;
const SAME: u8 = 2;
const SELF: u8 = 3;

#[derive(Clone, Copy)]
struct Stored {
    owners: u8,
    unv: bool,
    trust: u8,
}
#[derive(Clone, Copy)]
struct Truth {
    owners: u8,
    unv: bool,
    liars: u8,
}
#[derive(Clone, Copy, PartialEq)]
enum Recv {
    Literal,
    Normalise,
    Reject,
}
#[derive(Clone, Copy)]
struct Policy {
    name: &'static str,
    recv: Recv,
    add_own: bool,
}
const POLICIES: [Policy; 6] = [
    Policy { name: "P0/E1 as written, senders add own owner", recv: Recv::Literal, add_own: true },
    Policy { name: "P0/E0 as written, senders forward taint", recv: Recv::Literal, add_own: false },
    Policy { name: "P1/E1 normalise", recv: Recv::Normalise, add_own: true },
    Policy { name: "P1/E0 normalise", recv: Recv::Normalise, add_own: false },
    Policy { name: "P2/E1 reject if sender owner missing", recv: Recv::Reject, add_own: true },
    Policy { name: "P2/E0 reject if sender owner missing", recv: Recv::Reject, add_own: false },
];

fn f(owners: u8, unv: bool, r: u8) -> u8 {
    if unv {
        UNV
    } else if owners & !r != 0 {
        FOREIGN
    } else {
        SAME
    }
}
fn level(o: u8, r: u8) -> u8 {
    if o == r {
        SAME
    } else {
        FOREIGN
    }
}

#[derive(Default, Clone)]
struct Stats {
    scenarios: u64,
    checks: u64,
    raise: u64,
    overtaint: u64,
    inconsistent: u64,
    inherent: u64,
    out_of_scope: u64,
    false_reject: u64,
    liar_reject: u64,
    raise_example: Option<(usize, String)>,
    over_example: Option<(usize, String)>,
    fr_example: Option<(usize, String)>,
}

/// Liar strategy: Some((owners, unverified)) for liar nodes, None for honest ones.
type Lies = [Option<(u8, bool)>; N];

/// One send from `s` to `d`. Returns None if rejected.
fn send(p: Policy, lies: &Lies, st: Stored, s: usize, d: usize, stats: &mut Stats, trace: &str) -> Option<Stored> {
    let (wo, wu) = match lies[s] {
        Some(l) => l,
        None => (st.owners | if p.add_own { OWNER[s] } else { 0 }, st.unv),
    };
    let r = OWNER[d];
    match p.recv {
        Recv::Normalise => {
            let o = wo | OWNER[s];
            Some(Stored { owners: o, unv: wu, trust: f(o, wu, r) })
        }
        Recv::Literal | Recv::Reject => {
            if p.recv == Recv::Reject && wo & OWNER[s] == 0 {
                if lies[s].is_none() {
                    stats.false_reject += 1;
                    let ex = format!("{trace} -> {} rejected: honest {} omitted its own owner", NAME[d], NAME[s]);
                    keep_shortest(&mut stats.fr_example, ex);
                } else {
                    stats.liar_reject += 1;
                }
                return None;
            }
            Some(Stored { owners: wo, unv: wu, trust: level(OWNER[s], r).min(f(wo, wu, r)) })
        }
    }
}

fn keep_shortest(slot: &mut Option<(usize, String)>, ex: String) {
    if slot.as_ref().map_or(true, |(l, _)| ex.len() < *l) {
        *slot = Some((ex.len(), ex));
    }
}

fn check(lies: &Lies, st: Stored, t: Truth, d: usize, stats: &mut Stats, trace: &str) {
    if lies[d].is_some() {
        return; // only honest receivers are judged
    }
    let r = OWNER[d];
    if t.liars & r != 0 {
        stats.out_of_scope += 1;
        return;
    }
    stats.checks += 1;
    let ideal = f(t.owners, t.unv, r);
    let got = st.trust.min(SAME); // SELF only at the origin, never from the wire
    if st.trust != SELF && st.trust != f(st.owners, st.unv, r) {
        stats.inconsistent += 1;
    }
    let tn = ["unverified-origin", "foreign", "same-owner", "self"];
    if t.liars != 0 {
        if got == SAME {
            stats.raise += 1;
            let ex = format!("{trace}: {} computes same-owner, truth {}", NAME[d], tn[ideal as usize]);
            keep_shortest(&mut stats.raise_example, ex);
        } else if ideal == UNV && got == FOREIGN {
            stats.inherent += 1;
        }
    } else if got > ideal {
        stats.raise += 1;
        let ex = format!("{trace}: {} computes {}, truth {}", NAME[d], tn[got as usize], tn[ideal as usize]);
        keep_shortest(&mut stats.raise_example, ex);
    } else if got < ideal {
        stats.overtaint += 1;
        let ex = format!("{trace}: {} computes {}, truth {}", NAME[d], tn[got as usize], tn[ideal as usize]);
        keep_shortest(&mut stats.over_example, ex);
    }
}

fn origin(node: usize, edge: bool) -> (Stored, Truth) {
    let o = OWNER[node];
    (
        Stored { owners: o, unv: edge, trust: if edge { UNV } else { SELF } },
        Truth { owners: o, unv: edge, liars: 0 },
    )
}

fn node_label(lies: &Lies, n: usize) -> String {
    match lies[n] {
        None => NAME[n].to_string(),
        Some((o, u)) => {
            let mut s = format!("{}*[", NAME[n]);
            for (bit, c) in [(A, 'A'), (B, 'B'), (C, 'C')] {
                if o & bit != 0 {
                    s.push(c);
                }
            }
            if u {
                s.push_str(",unv");
            }
            s.push(']');
            s
        }
    }
}

/// Walk `path` (path[0] holds `st`/`t`), checking every honest receiver. Returns the final state, or None if rejected.
fn walk(
    p: Policy,
    lies: &Lies,
    mut st: Stored,
    mut t: Truth,
    path: &[usize],
    stats: &mut Stats,
    trace: &mut String,
    judge: bool,
) -> Option<(Stored, Truth)> {
    for w in path.windows(2) {
        let (s, d) = (w[0], w[1]);
        st = send(p, lies, st, s, d, stats, trace)?;
        t.owners |= OWNER[s];
        if lies[s].is_some() {
            t.liars |= OWNER[s];
        }
        let _ = write!(trace, " -> {}", node_label(lies, d));
        if judge {
            check(lies, st, t, d, stats, trace);
        }
    }
    Some((st, t))
}

/// All paths of `len` nodes with distinct consecutive nodes, optionally pinned at the start or end.
fn paths(len: usize, start: Option<usize>, end: Option<usize>) -> Vec<Vec<usize>> {
    let mut out = vec![];
    let mut cur = vec![];
    fn rec(len: usize, start: Option<usize>, end: Option<usize>, cur: &mut Vec<usize>, out: &mut Vec<Vec<usize>>) {
        if cur.len() == len {
            if end.map_or(true, |e| *cur.last().unwrap() == e) {
                out.push(cur.clone());
            }
            return;
        }
        for n in 0..N {
            if cur.is_empty() && start.map_or(false, |s| s != n) {
                continue;
            }
            if cur.last() == Some(&n) {
                continue;
            }
            cur.push(n);
            rec(len, start, end, cur, out);
            cur.pop();
        }
    }
    rec(len, start, end, &mut cur, &mut out);
    out
}

/// Liar sets of size <= 2 with every strategy in `menu`.
fn lie_sets(menu: &[(u8, bool)]) -> Vec<Lies> {
    let mut v = vec![[None; N]];
    for a in 0..N {
        for &la in menu {
            let mut l = [None; N];
            l[a] = Some(la);
            v.push(l);
            for b in a + 1..N {
                for &lb in menu {
                    let mut l2 = l;
                    l2[b] = Some(lb);
                    v.push(l2);
                }
            }
        }
    }
    v
}

fn main() {
    let max_len: usize = std::env::var("MAXLEN").ok().and_then(|s| s.parse().ok()).unwrap_or(5);
    let full_menu: Vec<(u8, bool)> = (0..8u8).flat_map(|o| [(o, false), (o, true)]).collect();
    let drop_menu: Vec<(u8, bool)> = vec![(0, false), (A, false), (B, false), (C, false)];
    let lies_full = lie_sets(&full_menu);
    let lies_drop = lie_sets(&drop_menu);

    let mut out = String::new();
    let _ = writeln!(out, "# taint-laundering-model results (MAXLEN={max_len})\n");

    // Family 1: chains.
    let mut chain_paths = vec![];
    for len in 2..=max_len {
        chain_paths.extend(paths(len, None, None));
    }
    let _ = writeln!(
        out,
        "## Family 1: chains, {} paths of 2..={max_len} nodes x 2 origins x {} liar assignments (<= 2 liars, 16 lies each)\n",
        chain_paths.len(),
        lies_full.len()
    );
    let mut fam1 = vec![];
    for p in POLICIES {
        let mut stats = Stats::default();
        for path in &chain_paths {
            for edge in [false, true] {
                for lies in &lies_full {
                    // only count liar assignments where every liar is on the path as a sender (others are redundant)
                    if (0..N).any(|n| lies[n].is_some() && !path[..path.len() - 1].contains(&n)) {
                        continue;
                    }
                    stats.scenarios += 1;
                    let (st, t) = origin(path[0], edge);
                    let mut trace = format!("{}{}", if edge { "edge@" } else { "" }, node_label(lies, path[0]));
                    if lies[path[0]].is_some() && edge {
                        // a liar's own edge input: the liar may drop the flag; truth still unverified
                    }
                    walk(p, lies, st, t, path, &mut stats, &mut trace, true);
                }
            }
        }
        fam1.push((p, stats));
    }
    table(&mut out, &fam1);

    // Family 2: derivation. Two inputs reach honest node X (paths of 1..=3 nodes ending at X), X's agent derives
    // one Part from both (union of taint, min of trust), then it is forwarded along a path of 2..=3 nodes from X.
    let dlen = 3.min(max_len);
    let mut ins: Vec<Vec<Vec<usize>>> = vec![vec![]; N];
    let mut outs: Vec<Vec<Vec<usize>>> = vec![vec![]; N];
    for x in 0..N {
        for len in 1..=dlen {
            ins[x].extend(paths(len, None, Some(x)));
        }
        for len in 2..=dlen {
            outs[x].extend(paths(len, Some(x), None));
        }
    }
    let _ = writeln!(
        out,
        "\n## Family 2: derivation at an honest node, inputs 1..={dlen} nodes, output 2..={dlen} nodes, {} liar assignments (<= 2 liars, lies: owners in {{}},{{A}},{{B}},{{C}}, unverified=false)\n",
        lies_drop.len()
    );
    let mut fam2 = vec![];
    for p in POLICIES {
        let mut stats = Stats::default();
        for x in 0..N {
            for lies in &lies_drop {
                if lies[x].is_some() {
                    continue;
                }
                for i1 in &ins[x] {
                    for i2 in &ins[x] {
                        for e1 in [false, true] {
                            for e2 in [false, true] {
                                let mut tr1 = format!("{}{}", if e1 { "edge@" } else { "" }, node_label(lies, i1[0]));
                                let (s1, t1) = origin(i1[0], e1);
                                let Some((s1, t1)) = walk(p, lies, s1, t1, i1, &mut stats, &mut tr1, false) else { continue };
                                let mut tr2 = format!("{}{}", if e2 { "edge@" } else { "" }, node_label(lies, i2[0]));
                                let (s2, t2) = origin(i2[0], e2);
                                let Some((s2, t2)) = walk(p, lies, s2, t2, i2, &mut stats, &mut tr2, false) else { continue };
                                let st = Stored { owners: s1.owners | s2.owners, unv: s1.unv || s2.unv, trust: s1.trust.min(s2.trust) };
                                let t = Truth { owners: t1.owners | t2.owners, unv: t1.unv || t2.unv, liars: t1.liars | t2.liars };
                                for o in &outs[x] {
                                    stats.scenarios += 1;
                                    let mut tr = format!("({tr1} + {tr2}) derive@{}", NAME[x]);
                                    walk(p, lies, st, t, o, &mut stats, &mut tr, true);
                                }
                            }
                        }
                    }
                }
            }
        }
        fam2.push((p, stats));
    }
    table(&mut out, &fam2);

    // Directed vectors for the conformance suite (§6 list), evaluated under P0 and P1.
    let _ = writeln!(out, "\n## Directed vectors (trust computed at the last node)\n");
    let _ = writeln!(out, "| vector | P0/E1 | P1/E1 | expected |\n|---|---|---|---|");
    let vectors: Vec<(&str, Vec<usize>, Vec<(usize, (u8, bool))>, bool, &str)> = vec![
        ("B1 claims owners=[A] to A1 (§6 step 7)", vec![3, 0], vec![(3, (A, false))], false, "foreign"),
        ("B1 claims owners=[A] to A1, A1 forwards to A2", vec![3, 0, 1], vec![(3, (A, false))], false, "foreign"),
        ("B1 sends owners=[] to A1, A1 forwards to A2", vec![3, 0, 1], vec![(3, (0, false))], false, "foreign"),
        ("B1 claims owners=[A] to A1, A1 -> A2 -> A3", vec![3, 0, 1, 2], vec![(3, (A, false))], false, "foreign"),
        ("A1 edge content -> B1 (honest) -> A2", vec![0, 3, 1], vec![], true, "unverified-origin"),
        ("A1 edge content -> B1 drops unverified -> A2", vec![0, 3, 1], vec![(3, (A | B, false))], true, "foreign (inherent)"),
        ("honest B1 -> A1 -> A2", vec![3, 0, 1], vec![], false, "foreign"),
        ("honest A1 -> A2 -> A3", vec![0, 1, 2], vec![], false, "same-owner"),
    ];
    let tn = ["unverified-origin", "foreign", "same-owner", "self"];
    for (label, path, lv, edge, exp) in vectors {
        let mut row = format!("| {label} |");
        for p in [POLICIES[0], POLICIES[2]] {
            let mut lies: Lies = [None; N];
            for (n, l) in &lv {
                lies[*n] = Some(*l);
            }
            let mut stats = Stats::default();
            let (st, t) = origin(path[0], edge);
            let mut trace = String::new();
            let r = walk(p, &lies, st, t, &path, &mut stats, &mut trace, false);
            let _ = write!(row, " {} |", r.map_or("rejected", |(s, _)| tn[s.trust as usize]));
        }
        let _ = writeln!(row, " {exp} |");
        out.push_str(&row);
    }

    print!("{out}");
}

fn table(out: &mut String, rows: &[(Policy, Stats)]) {
    let _ = writeln!(
        out,
        "| policy | scenarios | judged receipts | RAISE | over-taint | inconsistent | inherent | out of scope | liar rejected | honest rejected |"
    );
    let _ = writeln!(out, "|---|---|---|---|---|---|---|---|---|---|");
    for (p, s) in rows {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
            p.name, s.scenarios, s.checks, s.raise, s.overtaint, s.inconsistent, s.inherent, s.out_of_scope, s.liar_reject, s.false_reject
        );
    }
    for (p, s) in rows {
        if let Some((_, e)) = &s.raise_example {
            let _ = writeln!(out, "\n- {}: shortest RAISE: `{e}`", p.name);
        }
        if let Some((_, e)) = &s.over_example {
            let _ = writeln!(out, "- {}: shortest over-taint: `{e}`", p.name);
        }
        if let Some((_, e)) = &s.fr_example {
            let _ = writeln!(out, "- {}: shortest honest reject: `{e}`", p.name);
        }
    }
}
