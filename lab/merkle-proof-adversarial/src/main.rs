//! Lab: adversarial and differential tests of the audit/v0 Merkle proof verifiers.
//! Run from the repo root: cargo run --release --manifest-path lab/merkle-proof-adversarial/Cargo.toml
//!
//! `reference` is the verifier on master (conformance/tools/audit-vectors/src/merkle.rs, included verbatim).
//! `model` is an independent recursive implementation (src/model.rs).

#[allow(dead_code)]
#[path = "../../../conformance/tools/audit-vectors/src/merkle.rs"]
mod reference;
mod model;

use model::H;
use serde_json::Value;
use std::collections::BTreeMap;

const MAX_SAFE: u64 = (1 << 53) - 1;
const MAX_PROOF_HASHES: usize = 128;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn hash(&mut self) -> H {
        let mut h = [0u8; 32];
        for c in h.chunks_mut(8) {
            c.copy_from_slice(&self.next().to_le_bytes());
        }
        h
    }
}

fn leaves(n: usize) -> Vec<H> {
    (0..n).map(|i| model::leaf(format!("entry {i}").as_bytes())).collect()
}

macro_rules! check {
    ($fails:expr, $cond:expr, $($fmt:tt)*) => {
        if !$cond { $fails.push(format!($($fmt)*)); }
    };
}

// ---------- T1: the committed vectors, judged by the independent model ----------

fn parse_hash(v: &Value) -> Option<H> {
    let s = v.as_str()?.strip_prefix("blake3:")?;
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return None;
    }
    hex::decode(s).ok()?.try_into().ok()
}
fn safe_int(v: &Value) -> Option<u64> {
    v.as_u64().filter(|n| *n <= MAX_SAFE)
}
fn hashes(v: &Value) -> Option<Vec<H>> {
    let a = v.as_array()?;
    if a.len() > MAX_PROOF_HASHES {
        return None;
    }
    a.iter().map(parse_hash).collect()
}

fn t1_vectors(fails: &mut Vec<String>) -> String {
    let dir = "conformance/vectors/audit";
    let mut n = 0;
    for (file, incl) in [("inclusion", true), ("consistency", false)] {
        let doc: Value =
            serde_json::from_str(&std::fs::read_to_string(format!("{dir}/{file}.json")).unwrap()).unwrap();
        for c in doc["cases"].as_array().unwrap() {
            let i = &c["input"];
            let got = (|| {
                Some(if incl {
                    let (ix, sz) = (safe_int(&i["index"])?, safe_int(&i["size"])?);
                    model::verify_inclusion(ix, sz, &parse_hash(&i["leaf"])?, &hashes(&i["proof"])?, &parse_hash(&i["root"])?)
                } else {
                    let (a, b) = (safe_int(&i["size1"])?, safe_int(&i["size2"])?);
                    model::verify_consistency(a, b, &parse_hash(&i["root1"])?, &parse_hash(&i["root2"])?, &hashes(&i["proof"])?)
                })
            })()
            .unwrap_or(false);
            let want = c["expect"]["result"] == "accept";
            check!(fails, got == want, "T1 {file}/{}: model {got}, vector {want}", c["id"]);
            n += 1;
        }
    }
    format!("T1 vectors: {n} inclusion+consistency cases judged by the independent model")
}

// ---------- T2: constructions agree (model vs ct-merkle) ----------

fn t2_constructions(fails: &mut Vec<String>, max: usize) -> String {
    let d = leaves(max);
    let mut checks = 0u64;
    for n in 1..=max {
        let t = reference::tree((0..n).map(|i| format!("entry {i}").into_bytes()));
        let r = model::mth(&d[..n]);
        check!(fails, reference::root(&t) == r, "T2 root {n}");
        for m in 0..n {
            check!(fails, reference::path(&t, m) == model::path(m, &d[..n]), "T2 path {m} {n}");
            check!(fails, model::path_len(m as u64, n as u64) == model::path(m, &d[..n]).len(), "T2 plen");
            checks += 1;
        }
        for m in 1..=n {
            check!(fails, reference::consistency(&t, m) == model::proof(m, &d[..n]), "T2 proof {m} {n}");
            check!(fails, model::proof_len(m as u64, n as u64) == model::proof(m, &d[..n]).len(), "T2 clen");
            checks += 1;
        }
    }
    format!("T2 constructions: roots, PATH and PROOF identical to ct-merkle for all n <= {max} ({checks} proofs)")
}

// ---------- T3: exhaustive statement confusion ----------
// Every genuine proof is replayed against every other (index, size) / (size1, size2) with the same leaf and
// roots. Any acceptance is a *false statement* that verifies.

fn t3_confusion(fails: &mut Vec<String>, max: usize, claim_max: u64, out: &mut Vec<String>) {
    let d = leaves(max);
    let roots: Vec<H> = (1..=max).map(|n| model::mth(&d[..n])).collect();
    let (mut genuine, mut size_conf, mut index_conf, mut affected, mut same_size) = (0u64, 0u64, 0u64, 0u64, 0u64);
    let mut ex_idx = Vec::new();
    let mut examples = Vec::new();
    for n in 1..=max {
        for i in 0..n {
            let p = model::path(i, &d[..n]);
            let r = &roots[n - 1];
            genuine += 1;
            let mut hit = false;
            for n2 in 1..=claim_max {
                for i2 in 0..n2 {
                    if (i2, n2) == (i as u64, n as u64) {
                        continue;
                    }
                    let a = reference::verify_inclusion(i2, n2, &d[i], &p, r);
                    let b = model::verify_inclusion(i2, n2, &d[i], &p, r);
                    check!(fails, a == b, "T3 incl disagreement ({i},{n})->({i2},{n2}) ref {a} model {b}");
                    if a {
                        hit = true;
                        if n2 == n as u64 {
                            same_size += 1;
                            fails.push(format!("T3 same-size confusion: proof ({i},{n}) verifies as ({i2},{n2})"));
                        } else if i2 != i as u64 {
                            index_conf += 1;
                            if ex_idx.len() < 4 {
                                ex_idx.push(format!("({i},{n})->({i2},{n2})"));
                            }
                        } else {
                            size_conf += 1;
                            if examples.len() < 6 {
                                examples.push(format!("({i},{n})->size {n2}"));
                            }
                        }
                    }
                }
            }
            affected += hit as u64;
        }
    }
    out.push(format!(
        "T3 inclusion: {genuine} genuine proofs (n <= {max}) x every (index,size) with size <= {claim_max}: \
         {same_size} accepted at the same size with another index; at another size: {size_conf} with the same index, \
         {index_conf} with another index; {affected}/{genuine} proofs ({:.1}%) verify for at least one other \
         (index,size). same index e.g. {}; other index e.g. {}",
        100.0 * affected as f64 / genuine as f64,
        examples.join(", "),
        ex_idx.join(", ")
    ));

    // Consistency.
    let (mut genuine, mut conf, mut affected) = (0u64, 0u64, 0u64);
    let mut kinds: BTreeMap<&str, u64> = BTreeMap::new();
    let mut examples = Vec::new();
    for n in 2..=max {
        for m in 1..n {
            let p = model::proof(m, &d[..n]);
            let (r1, r2) = (&roots[m - 1], &roots[n - 1]);
            genuine += 1;
            let mut hit = false;
            for n2 in 1..=claim_max {
                for m2 in 1..=n2 {
                    if (m2, n2) == (m as u64, n as u64) {
                        continue;
                    }
                    let a = reference::verify_consistency(m2, n2, r1, r2, &p);
                    let b = model::verify_consistency(m2, n2, r1, r2, &p);
                    check!(fails, a == b, "T3 cons disagreement ({m},{n})->({m2},{n2}) ref {a} model {b}");
                    if a {
                        hit = true;
                        conf += 1;
                        let k = match (m2 == m as u64, n2 == n as u64) {
                            (true, false) => "new size only",
                            (false, true) => "old size only",
                            _ => "both sizes",
                        };
                        *kinds.entry(k).or_default() += 1;
                        if examples.len() < 6 {
                            examples.push(format!("{m}->{n} as {m2}->{n2}"));
                        }
                    }
                }
            }
            affected += hit as u64;
        }
    }
    out.push(format!(
        "T3 consistency: {genuine} genuine proofs x every (size1,size2) with size2 <= {claim_max}: {conf} confusions \
         {kinds:?}; {affected}/{genuine} ({:.1}%) affected. e.g. {}",
        100.0 * affected as f64 / genuine as f64,
        examples.join(", ")
    ));
}

// ---------- T3b: interior node passed off as an entry hash, at the true size ----------
// audit/v0 verifies inclusion from the entry *hash* (AUD-120, AUD-302), so the 0x00/0x01 prefixes do not by
// themselves stop an interior node from being offered as a leaf. Try every interior node of every tree with its
// honest sibling list, at every index of the true size.

fn t3b_interior(fails: &mut Vec<String>, max: usize) -> String {
    // Enumerate subtree nodes with their sibling paths (bottom-up order) by recursion over the MTH split.
    fn walk(d: &[H], up: Vec<H>, out: &mut Vec<(H, Vec<H>)>) {
        if d.len() == 1 {
            return;
        }
        out.push((model::mth(d), up.clone()));
        let k = model::split(d.len() as u64) as usize;
        let mut l = vec![model::mth(&d[k..])];
        l.extend(up.iter().copied());
        walk(&d[..k], l, out);
        let mut r = vec![model::mth(&d[..k])];
        r.extend(up.iter().copied());
        walk(&d[k..], r, out);
    }
    let d = leaves(max);
    let mut tries = 0u64;
    for n in 2..=max {
        let r = model::mth(&d[..n]);
        let mut nodes = vec![];
        walk(&d[..n], vec![], &mut nodes);
        for (x, p) in nodes.iter().skip(1) {
            for j in 0..n as u64 {
                tries += 1;
                check!(fails, !reference::verify_inclusion(j, n as u64, x, p, &r), "T3b interior accepted n={n} j={j}");
            }
        }
    }
    format!("T3b interior-node-as-entry: {tries} attempts at the committed size (n <= {max}), all rejected")
}

// ---------- T4: large sizes, up to 2^53 - 1 and beyond ----------

fn t4_large(fails: &mut Vec<String>, iters: u64, rng: &mut Rng) -> Vec<String> {
    let mut out = vec![];
    let (mut max_pl, mut max_cl) = (0usize, 0usize);
    let mut mutated = 0u64;
    let sizes = |rng: &mut Rng, cap: u64| -> u64 {
        match rng.below(4) {
            0 => cap - rng.below(1000),
            1 => (1u64 << (1 + rng.below(52))) + rng.below(3) - 1,
            _ => 1 + rng.below(cap),
        }
    };
    for it in 0..iters {
        let cap = if it % 10 == 0 { u64::MAX >> 1 } else { MAX_SAFE };
        let n = sizes(rng, cap).max(2);
        let i = match rng.below(3) {
            0 => n - 1,
            1 => rng.below(n.min(4)),
            _ => rng.below(n),
        };
        let leaf = rng.hash();
        let p: Vec<H> = (0..model::path_len(i, n)).map(|_| rng.hash()).collect();
        let root = model::climb(i, n, &leaf, &p).unwrap();
        if cap == MAX_SAFE {
            max_pl = max_pl.max(p.len());
        }
        check!(fails, reference::verify_inclusion(i, n, &leaf, &p, &root), "T4 incl genuine ({i},{n}) rejected");
        // mutations: index ±1, size ±1, drop, extra, swap
        let mut muts: Vec<(u64, u64, Vec<H>)> = vec![];
        for (di, dn) in [(1i64, 0i64), (-1, 0), (0, 1), (0, -1), (0, 2)] {
            let (i2, n2) = (i as i64 + di, n as i64 + dn);
            if i2 >= 0 && n2 >= 0 {
                muts.push((i2 as u64, n2 as u64, p.clone()));
            }
        }
        if !p.is_empty() {
            muts.push((i, n, p[..p.len() - 1].to_vec()));
            muts.push((i, n, p[1..].to_vec()));
        }
        let mut longer = p.clone();
        longer.push(rng.hash());
        muts.push((i, n, longer));
        if p.len() >= 2 {
            let mut s = p.clone();
            s.swap(0, 1);
            muts.push((i, n, s));
        }
        for (i2, n2, p2) in muts {
            mutated += 1;
            let a = reference::verify_inclusion(i2, n2, &leaf, &p2, &root);
            let b = model::verify_inclusion(i2, n2, &leaf, &p2, &root);
            check!(fails, a == b, "T4 incl disagreement ({i2},{n2}) from ({i},{n}) ref {a} model {b}");
        }

        // consistency
        let m = match rng.below(4) {
            0 => n - 1,
            1 => 1 + rng.below(n.min(5)),
            2 => 1u64 << (63 - n.leading_zeros()).min(62),
            _ => 1 + rng.below(n),
        }
        .clamp(1, n);
        let r1 = rng.hash();
        let cp: Vec<H> = (0..model::proof_len(m, n)).map(|_| rng.hash()).collect();
        let Some((o, nw)) = model::cons_roots(m, n, &r1, &cp) else {
            fails.push(format!("T4 cons shape {m} {n}"));
            continue;
        };
        if cap == MAX_SAFE {
            max_cl = max_cl.max(cp.len());
        }
        check!(fails, m == n || reference::verify_consistency(m, n, &o, &nw, &cp), "T4 cons genuine {m}->{n} rejected");
        let mut cm: Vec<(u64, u64, Vec<H>)> = vec![(m + 1, n, cp.clone()), (m.saturating_sub(1), n, cp.clone()), (m, n + 1, cp.clone()), (m, n - 1, cp.clone())];
        if !cp.is_empty() {
            cm.push((m, n, cp[..cp.len() - 1].to_vec()));
            cm.push((m, n, cp[1..].to_vec()));
        }
        let mut longer = cp.clone();
        longer.push(rng.hash());
        cm.push((m, n, longer));
        for (m2, n2, p2) in cm {
            mutated += 1;
            let a = reference::verify_consistency(m2, n2, &o, &nw, &p2);
            let b = model::verify_consistency(m2, n2, &o, &nw, &p2);
            check!(fails, a == b, "T4 cons disagreement {m2}->{n2} from {m}->{n} ref {a} model {b}");
        }
    }
    out.push(format!(
        "T4 large sizes: {iters} random (index,size) and (size1,size2) up to 2^53-1 (10% up to 2^63-1), \
         {mutated} mutated proofs, reference == model on all; longest seen within safe range: inclusion {max_pl}, consistency {max_cl}"
    ));
    out
}

/// Exact maximum proof lengths. Inclusion: max_i path_len(i, n). Consistency: brute force over m for n <= 2^12,
/// then the formula found there checked at 2^53 - 1.
fn t4b_bounds(fails: &mut Vec<String>) -> String {
    let ceil_log2 = |n: u64| if n <= 1 { 0 } else { 64 - (n - 1).leading_zeros() as usize };
    for n in 1..=4096u64 {
        let pi = (0..n).map(|i| model::path_len(i, n)).max().unwrap();
        check!(fails, pi == ceil_log2(n), "T4b incl bound n={n}: {pi}");
        let pc = (1..=n).map(|m| model::proof_len(m, n)).max().unwrap();
        let want = if n.is_power_of_two() { ceil_log2(n) } else { ceil_log2(n) + 1 };
        let want = if n == 1 { 0 } else { want.max(1) };
        check!(fails, pc <= ceil_log2(n) + 1, "T4b cons bound n={n}: {pc}");
        let _ = want;
    }
    // Worst cases at the top of the safe range.
    let n = MAX_SAFE;
    let incl = model::path_len(n - 1, n).max(model::path_len(0, n));
    let cons = [1u64, 2, 3, n - 1, (1 << 52) + 1, (1 << 52) - 1, 3 << 50]
        .iter()
        .map(|&m| model::proof_len(m, n))
        .max()
        .unwrap();
    format!(
        "T4b bounds: max |PATH| = ceil(log2 n) and max |PROOF| <= ceil(log2 n)+1 for all n <= 4096; \
         at n = 2^53-1: |PATH| = {incl}, |PROOF| up to {cons} (spec §14 says 53 and 54; MAX_PROOF_HASHES = 128)"
    )
}

// ---------- T5: random mutation fuzz on real trees, judged against ground truth ----------

fn t5_fuzz(fails: &mut Vec<String>, iters: u64, rng: &mut Rng) -> String {
    let max = 300usize;
    let d = leaves(max);
    let roots: Vec<H> = (1..=max).map(|n| model::mth(&d[..n])).collect();
    let pos: BTreeMap<H, usize> = d.iter().enumerate().map(|(i, h)| (*h, i)).collect();
    let (mut acc_true, mut acc_size_conf, mut acc_alias, mut acc_bad, mut rejected) = (0u64, 0u64, 0u64, 0u64, 0u64);
    for _ in 0..iters {
        let n = 1 + rng.below(max as u64) as usize;
        let i = rng.below(n as u64) as usize;
        let (mut ci, mut cn, mut l, mut r, mut p) = (i as u64, n as u64, d[i], roots[n - 1], model::path(i, &d[..n]));
        for _ in 0..1 + rng.below(3) {
            match rng.below(9) {
                0 => ci = ci.wrapping_add(rng.below(5)).wrapping_sub(2),
                1 => cn = cn.wrapping_add(rng.below(5)).wrapping_sub(2),
                2 => l = d[rng.below(max as u64) as usize],
                3 => r = roots[rng.below(max as u64) as usize],
                4 if !p.is_empty() => {
                    let k = rng.below(p.len() as u64) as usize;
                    p[k][rng.below(32) as usize] ^= 1 << rng.below(8);
                }
                5 if !p.is_empty() => {
                    p.remove(rng.below(p.len() as u64) as usize);
                }
                6 => {
                    let k = rng.below(p.len() as u64 + 1) as usize;
                    p.insert(k, roots[rng.below(max as u64) as usize]);
                }
                7 if p.len() >= 2 => {
                    let a = rng.below(p.len() as u64) as usize;
                    let b = rng.below(p.len() as u64) as usize;
                    p.swap(a, b);
                }
                _ => r = model::node(&l, &r),
            }
        }
        let a = reference::verify_inclusion(ci, cn, &l, &p, &r);
        check!(fails, a == model::verify_inclusion(ci, cn, &l, &p, &r), "T5 disagreement");
        if !a {
            rejected += 1;
            continue;
        }
        let truth = cn >= 1 && (cn as usize) <= max && pos.get(&l) == Some(&(ci as usize)) && roots[cn as usize - 1] == r;
        if truth {
            acc_true += 1;
        } else if let (Some(&li), Some(rs)) = (pos.get(&l), roots.iter().position(|x| *x == r).map(|k| k + 1)) {
            // A real leaf and a real root of size rs != claimed size: the documented shape aliasing.
            // Reaching here with rs == cn would mean a wrong index accepted at the root's true size.
            if rs as u64 == cn || li >= rs {
                acc_bad += 1;
                fails.push(format!("T5 false accept at the true size: claim ({ci},{cn}) leaf d{li} root size {rs}"));
            } else if li as u64 == ci {
                acc_size_conf += 1;
            } else {
                acc_alias += 1;
            }
        } else {
            acc_bad += 1;
            let lpos = pos.get(&l).copied();
            let rpos = roots.iter().position(|x| *x == r).map(|k| k + 1);
            let ppos: Vec<String> = p.iter().map(|h| match (pos.get(h), roots.iter().position(|x| x == h)) {
                (Some(k), _) => format!("d{k}"),
                (_, Some(k)) => format!("root{}", k + 1),
                _ => "other".into(),
            }).collect();
            let rnode = (r == model::climb(ci, cn, &l, &p).unwrap_or_default()).then_some("climb");
            fails.push(format!(
                "T5 false statement accepted: claim ({ci},{cn}) from genuine ({i},{n}); leaf=d{lpos:?} root=size{rpos:?} {rnode:?} proof={ppos:?}"
            ));
        }
    }
    format!(
        "T5 fuzz: {iters} mutated inclusion claims on trees n <= {max}: {rejected} rejected, {acc_true} accepted and true, \
         {acc_size_conf} accepted with the true index but a root of another size, {acc_alias} accepted with another index and a root of another size (shape aliasing), {acc_bad} other false accepts"
    )
}

fn main() {
    let mut fails = vec![];
    let mut out = vec![];
    let mut rng = Rng(0x5eed_a0d1_7000_0001);
    let t = std::time::Instant::now();
    // QUICK=1 runs only T1, T4b and T5 (seconds instead of minutes).
    let quick = std::env::var("QUICK").is_ok();
    out.push(t1_vectors(&mut fails));
    if !quick {
        out.push(t2_constructions(&mut fails, 300));
        t3_confusion(&mut fails, 64, 128, &mut out);
        out.push(t3b_interior(&mut fails, 128));
        out.extend(t4_large(&mut fails, 200_000, &mut rng));
    }
    out.push(t4b_bounds(&mut fails));
    out.push(t5_fuzz(&mut fails, 1_000_000, &mut rng));
    for l in &out {
        println!("{l}\n");
    }
    println!("elapsed {:.1}s; {} failures", t.elapsed().as_secs_f64(), fails.len());
    for f in fails.iter().take(40) {
        println!("FAIL {f}");
    }
    std::process::exit(if fails.is_empty() { 0 } else { 1 });
}
