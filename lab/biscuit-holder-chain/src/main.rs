//! Lab: does biscuit-auth 6.0 carry the capability/v0 holder chain of due-diligence §4.7.2?
//!
//! Token shape (as proposed):
//!   authority (signed by owner root key R):
//!       right("skill:run-tests"); holder(<B>, 0);
//!       check if presenter($k), current_holder($k);
//!       check if call_count($c), $c < 5;
//!   re-delegation B -> C: third-party block signed by B's key: holder(<C>, 1); (+ optional checks)
//!   attenuation: ordinary (ephemeral-key) block with checks only.
//!
//! The node (not Datalog) walks the holder blocks, then injects
//!   current_holder(<last holder>), presenter(<verified envelope signer>), call_count(<uses of root rev id>).
//!
//! Three walkers are compared:
//!   Scoped : per depth n, `holder($k, n+1) trusting ed25519/<holder n>` via Authorizer::query (public API).
//!   Naive  : Authorizer::query_all over all blocks, take the max depth (a plausible but wrong implementation).
//!   Strict : per block, print_block_source + parse_block_source, require 1 holder fact per holder block,
//!            depth == previous+1, signer == previous holder, no holder facts in first-party blocks.

use biscuit_auth::{
    builder::{Algorithm, AuthorizerBuilder, BlockBuilder},
    Biscuit, KeyPair, PublicKey,
};
use rand::{rngs::StdRng, SeedableRng};
use std::collections::HashMap;
use std::time::Instant;

fn hexk(k: &PublicKey) -> String {
    k.to_bytes_hex()
}
fn kp(rng: &mut StdRng) -> KeyPair {
    KeyPair::new_with_rng(Algorithm::Ed25519, rng)
}

fn mint(root: &KeyPair, first: &PublicKey, rng: &mut StdRng) -> Biscuit {
    Biscuit::builder()
        .fact("right(\"skill:run-tests\")").unwrap()
        .fact(format!("holder(hex:{}, 0)", hexk(first)).as_str()).unwrap()
        .check("check if presenter($k), current_holder($k)").unwrap()
        .check("check if call_count($c), $c < 5").unwrap()
        .build_with_rng(root, Default::default(), rng)
        .unwrap()
}

/// Holder `signer` appends a third-party block naming `next` at `depth`, plus extra datalog.
fn delegate(t: &Biscuit, signer: &KeyPair, next: &PublicKey, depth: i64, extra: &[&str]) -> Biscuit {
    let mut bb = BlockBuilder::new()
        .fact(format!("holder(hex:{}, {depth})", hexk(next)).as_str())
        .unwrap();
    for e in extra {
        bb = add(bb, e);
    }
    let req = t.third_party_request().unwrap();
    let blk = req.create_block(&signer.private(), bb).unwrap();
    t.append_third_party(signer.public(), blk).unwrap()
}

fn add(bb: BlockBuilder, src: &str) -> BlockBuilder {
    if src.starts_with("check") {
        bb.check(src).unwrap()
    } else {
        bb.fact(src).unwrap()
    }
}

fn attenuate(t: &Biscuit, src: &[&str]) -> Biscuit {
    let mut bb = BlockBuilder::new();
    for s in src {
        bb = add(bb, s);
    }
    t.append(bb).unwrap()
}

/// Round-trip through bytes, as on the wire (verifies all signatures against root).
fn wire(t: &Biscuit, root: &PublicKey) -> Result<Biscuit, String> {
    Biscuit::from(t.to_vec().map_err(|e| e.to_string())?, *root).map_err(|e| e.to_string())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Walker {
    Scoped,
    Naive,
    Strict,
    ScopedSeq,
}

use biscuit_parser::builder::Term as PTerm;
fn term_bytes(t: &PTerm) -> Option<Vec<u8>> {
    if let PTerm::Bytes(b) = t { Some(b.clone()) } else { None }
}
fn term_int(t: &PTerm) -> Option<i64> {
    if let PTerm::Integer(i) = t { Some(*i) } else { None }
}

/// Returns the last holder's key bytes, or an error string.
fn walk(t: &Biscuit, w: Walker) -> Result<Vec<u8>, String> {
    match w {
        Walker::ScopedSeq => {
            // Scoped walk, recording the holder sequence, then require that the third-party blocks,
            // in block order, are signed by exactly holder_0, holder_1, ..., holder_{m-1}: one per hop.
            let mut a = t.authorizer().map_err(|e| e.to_string())?;
            let h0: Vec<(Vec<u8>, i64)> = a
                .query("h($k, $n) <- holder($k, $n) trusting authority")
                .map_err(|e| e.to_string())?;
            if h0.len() != 1 || h0[0].1 != 0 {
                return Err("authority must name exactly one holder at depth 0".into());
            }
            let mut seq = vec![h0[0].0.clone()];
            loop {
                let q = format!("h($k) <- holder($k, {}) trusting ed25519/{}", seq.len(), hex_encode(seq.last().unwrap()));
                let r: Vec<(Vec<u8>,)> = a.query(q.as_str()).map_err(|e| e.to_string())?;
                match r.len() {
                    0 => break,
                    1 => seq.push(r[0].0.clone()),
                    _ => return Err(format!("fork at depth {}", seq.len())),
                }
                if seq.len() > t.block_count() { return Err("chain longer than token".into()); }
            }
            let signers: Vec<Vec<u8>> = (1..t.block_count())
                .filter_map(|i| t.block_external_key(i).ok().flatten().map(|k| k.to_bytes()))
                .collect();
            if signers[..] != seq[..seq.len() - 1] {
                return Err(format!("third-party signer order does not match holder chain ({} blocks, {} hops)", signers.len(), seq.len() - 1));
            }
            Ok(seq.pop().unwrap())
        }
        Walker::Scoped => {
            let mut a = t.authorizer().map_err(|e| e.to_string())?;
            let h0: Vec<(Vec<u8>, i64)> = a
                .query("h($k, $n) <- holder($k, $n) trusting authority")
                .map_err(|e| e.to_string())?;
            if h0.len() != 1 || h0[0].1 != 0 {
                return Err(format!("authority must name exactly one holder at depth 0, got {h0:?}"));
            }
            let mut cur = h0[0].0.clone();
            let mut n = 0i64;
            loop {
                let pk = hex_encode(&cur);
                let q = format!("h($k) <- holder($k, {}) trusting ed25519/{pk}", n + 1);
                let r: Vec<(Vec<u8>,)> = a.query(q.as_str()).map_err(|e| e.to_string())?;
                match r.len() {
                    0 => return Ok(cur),
                    1 => {
                        cur = r[0].0.clone();
                        n += 1;
                    }
                    _ => return Err(format!("fork at depth {}", n + 1)),
                }
            }
        }
        Walker::Naive => {
            let mut a = t.authorizer().map_err(|e| e.to_string())?;
            let all: Vec<(Vec<u8>, i64)> =
                a.query_all("h($k, $n) <- holder($k, $n)").map_err(|e| e.to_string())?;
            all.into_iter().max_by_key(|x| x.1).map(|x| x.0).ok_or("no holder".into())
        }
        Walker::Strict => {
            let mut cur: Option<Vec<u8>> = None;
            let mut n = -1i64;
            for i in 0..t.block_count() {
                let src = t.print_block_source(i).map_err(|e| e.to_string())?;
                let parsed = biscuit_auth::parser::parse_block_source(&src)
                    .map_err(|e| format!("reparse block {i}: {e:?}"))?;
                let hs: Vec<(Vec<u8>, i64)> = parsed
                    .facts
                    .iter()
                    .filter(|(_, f)| f.predicate.name == "holder")
                    .map(|(_, f)| {
                        let ts = &f.predicate.terms;
                        (term_bytes(&ts[0]).unwrap_or_default(), term_int(&ts[1]).unwrap_or(-99))
                    })
                    .collect();
                let ext = t.block_external_key(i).map_err(|e| e.to_string())?;
                if i == 0 {
                    if hs.len() != 1 || hs[0].1 != 0 {
                        return Err("authority must name exactly one holder at depth 0".into());
                    }
                    cur = Some(hs[0].0.clone());
                    n = 0;
                    continue;
                }
                if hs.is_empty() {
                    continue; // attenuation block or non-holder third-party block
                }
                let Some(ext) = ext else {
                    return Err(format!("block {i}: holder fact in a first-party (ephemeral) block"));
                };
                if hs.len() != 1 {
                    return Err(format!("block {i}: {} holder facts", hs.len()));
                }
                if hs[0].1 != n + 1 {
                    return Err(format!("block {i}: depth {} != {}", hs[0].1, n + 1));
                }
                if Some(ext.to_bytes()) != cur {
                    return Err(format!("block {i}: holder block not signed by current holder"));
                }
                cur = Some(hs[0].0.clone());
                n += 1;
            }
            cur.ok_or("no holder".into())
        }
    }
}

fn short(e: &str) -> String {
    if e.contains("FailedLogic(Unauthorized") { return "Datalog check failed".into(); }
    if e.contains("NoMatchingPolicy") { return "no matching policy".into(); }
    e.replace('|', "/").chars().take(70).collect()
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Node-side verifier state: per root revocation id call counts, revoked ids.
#[derive(Default)]
struct Node {
    calls: HashMap<Vec<u8>, i64>,
    revoked: Vec<Vec<u8>>,
}

impl Node {
    /// Full check as the resource owner's node would run it. `inject_holder=false` simulates
    /// a node that forgets the walk (must fail closed).
    fn authorize(
        &mut self,
        t: &Biscuit,
        root: &PublicKey,
        presenter: &PublicKey,
        w: Walker,
        inject_holder: bool,
        extra_policy: Option<&str>,
        skill: &str,
    ) -> Result<(), String> {
        let t = wire(t, root)?;
        let ids = t.revocation_identifiers();
        if ids.iter().any(|id| self.revoked.contains(id)) {
            return Err("revoked".into());
        }
        let root_id = ids[0].clone();
        let used = *self.calls.get(&root_id).unwrap_or(&0);
        let mut ab = AuthorizerBuilder::new()
            .fact(format!("presenter(hex:{})", hexk(presenter)).as_str()).unwrap()
            .fact(format!("call_count({used})").as_str()).unwrap()
            .fact(format!("operation(\"{skill}\")").as_str()).unwrap();
        if inject_holder {
            let h = walk(&t, w)?;
            ab = ab.fact(format!("current_holder(hex:{})", hex_encode(&h)).as_str()).unwrap();
        }
        let pol = extra_policy.unwrap_or("allow if operation($op), right($op)");
        ab = ab.policy(pol).map_err(|e| e.to_string())?;
        let mut a = ab.build(&t).map_err(|e| e.to_string())?;
        a.authorize().map_err(|e| format!("{e:?}").chars().take(90).collect::<String>())?;
        *self.calls.entry(root_id).or_insert(0) += 1;
        Ok(())
    }
}

struct Case {
    name: &'static str,
    expect_ok: bool,
    results: Vec<(Walker, Result<(), String>)>,
}

fn main() {
    let mut rng = StdRng::seed_from_u64(42);
    let (r, b, c, d, x) = (kp(&mut rng), kp(&mut rng), kp(&mut rng), kp(&mut rng), kp(&mut rng));
    let root = r.public();
    let walkers = [Walker::Scoped, Walker::Naive, Walker::Strict, Walker::ScopedSeq];
    let mut cases: Vec<Case> = Vec::new();

    let t0 = mint(&r, &b.public(), &mut rng);
    let t1 = delegate(&t0, &b, &c.public(), 1, &[]);
    let t2 = delegate(&t1, &c, &d.public(), 2, &[]);
    let t3 = attenuate(&t2, &["check if operation(\"skill:run-tests\")"]);

    // helper to run one case on all walkers with fresh node state
    let mut run = |name: &'static str, expect_ok: bool, f: &dyn Fn(Walker, &mut Node) -> Result<(), String>| {
        let results = walkers.iter().map(|&w| (w, f(w, &mut Node::default()))).collect();
        cases.push(Case { name, expect_ok, results });
    };

    let s = "skill:run-tests";
    // --- the six vectors listed in §4.7.2 ---
    run("V1 valid chain B->C->D (3 holders), presented by D", true, &|w, n| n.authorize(&t3, &root, &d.public(), w, true, None, s));
    run("V2 holder block for C signed by X (not B)", false, &|w, n| {
        let bad = delegate(&t0, &x, &c.public(), 1, &[]);
        n.authorize(&bad, &root, &c.public(), w, true, None, s)
    });
    run("V3 ephemeral-key block sets holder(X,1), presented by X", false, &|w, n| {
        let bad = attenuate(&t0, &[&format!("holder(hex:{}, 1)", hexk(&x.public()))]);
        n.authorize(&bad, &root, &x.public(), w, true, None, s)
    });
    run("V4 D's token presented by C (not last holder)", false, &|w, n| n.authorize(&t2, &root, &c.public(), w, true, None, s));
    run("V5 B keeps using its shorter token after delegating", true, &|w, n| n.authorize(&t0, &root, &b.public(), w, true, None, s));
    run("V6 B 3 calls + C 2 calls ok, then C's 6th call rejected", false, &|w, n| {
        for _ in 0..3 { n.authorize(&t0, &root, &b.public(), w, true, None, s)?; }
        for _ in 0..2 { n.authorize(&t1, &root, &c.public(), w, true, None, s)?; }
        n.authorize(&t1, &root, &c.public(), w, true, None, s)
    });
    // --- extra adversarial vectors ---
    run("A1 thief X presents D's token", false, &|w, n| n.authorize(&t3, &root, &x.public(), w, true, None, s));
    run("A2 node forgets the walk (no current_holder): fail closed", false, &|w, n| n.authorize(&t3, &root, &d.public(), w, false, None, s));
    run("A3 attenuation block injects presenter(X), current_holder(X)", false, &|w, n| {
        let bad = attenuate(&t2, &[&format!("presenter(hex:{})", hexk(&x.public())), &format!("current_holder(hex:{})", hexk(&x.public()))]);
        n.authorize(&bad, &root, &x.public(), w, true, None, s)
    });
    run("A4 holder block of T1 cut-and-pasted onto another B token", false, &|w, n| {
        let other = mint(&r, &b.public(), &mut StdRng::seed_from_u64(7));
        let req = t0.third_party_request().unwrap(); // request bound to t0's last signature
        let blk = req.create_block(&b.private(), BlockBuilder::new().fact(format!("holder(hex:{}, 1)", hexk(&c.public())).as_str()).unwrap()).unwrap();
        let spliced = other.append_third_party(b.public(), blk).map_err(|e| format!("append: {e}"))?;
        n.authorize(&spliced, &root, &c.public(), w, true, None, s)
    });
    run("A5 C signs holder(X,1) (depth replay at wrong depth)", false, &|w, n| {
        let bad = delegate(&t1, &c, &x.public(), 1, &[]);
        n.authorize(&bad, &root, &x.public(), w, true, None, s)
    });
    run("A6 B's holder block names two holders (C,1),(X,1): fork", false, &|w, n| {
        let bad = delegate(&t0, &b, &c.public(), 1, &[&format!("holder(hex:{}, 1)", hexk(&x.public()))]);
        n.authorize(&bad, &root, &x.public(), w, true, None, s)
    });
    run("A7 pre-plant: B signs (C,1)+(X,3); C->B at 2; X presents", false, &|w, n| {
        let p1 = delegate(&t0, &b, &c.public(), 1, &[&format!("holder(hex:{}, 3)", hexk(&x.public()))]);
        let p2 = delegate(&p1, &c, &b.public(), 2, &[]);
        n.authorize(&p2, &root, &x.public(), w, true, None, s)
    });
    run("A8 3p holder block adds right(\"skill:deploy\"); D asks deploy", false, &|w, n| {
        let bad = delegate(&t1, &c, &d.public(), 2, &["right(\"skill:deploy\")"]);
        n.authorize(&bad, &root, &d.public(), w, true, None, "skill:deploy")
    });
    run("A9 same, but node policy trusts holder keys (footgun)", false, &|w, n| {
        let bad = delegate(&t1, &c, &d.public(), 2, &["right(\"skill:deploy\")"]);
        let pol = format!("allow if operation($op), right($op) trusting authority, ed25519/{}", hexk(&c.public()));
        n.authorize(&bad, &root, &d.public(), w, true, Some(&pol), "skill:deploy")
    });
    run("A10 revoke block-1 id: C and D chains die", false, &|w, n| {
        n.revoked.push(t1.revocation_identifiers()[1].clone());
        n.authorize(&t3, &root, &d.public(), w, true, None, s)
    });
    run("A11 revoke block-1 id: B's shorter token still works", true, &|w, n| {
        n.revoked.push(t1.revocation_identifiers()[1].clone());
        n.authorize(&t0, &root, &b.public(), w, true, None, s)
    });
    run("A12 holder block adds attenuating check (max 2 calls) on C", false, &|w, n| {
        let t = delegate(&t0, &b, &c.public(), 1, &["check if call_count($c), $c < 2"]);
        for _ in 0..2 { n.authorize(&t, &root, &c.public(), w, true, None, s)?; }
        n.authorize(&t, &root, &c.public(), w, true, None, s)
    });
    run("A13 round trip B->C->B: B presents the long token", true, &|w, n| {
        let t = delegate(&t1, &c, &b.public(), 2, &[]);
        n.authorize(&t, &root, &b.public(), w, true, None, s)
    });
    run("A14 sealed token cannot be re-delegated", false, &|w, n| {
        let sealed = t1.seal().map_err(|e| e.to_string())?;
        let req = sealed.third_party_request().map_err(|e| format!("3p request: {e}"))?;
        let blk = req.create_block(&c.private(), BlockBuilder::new().fact(format!("holder(hex:{}, 2)", hexk(&d.public())).as_str()).unwrap()).unwrap();
        let t = sealed.append_third_party(c.public(), blk).map_err(|e| format!("append: {e}"))?;
        n.authorize(&t, &root, &d.public(), w, true, None, s)
    });

    println!("# Holder-chain vectors\n\n| case | expected | Scoped | Naive | Strict | ScopedSeq |\n|---|---|---|---|---|---|");
    let mut mism = HashMap::<Walker, usize>::new();
    for c in &cases {
        let mark = |r: &Result<(), String>| {
            let ok = r.is_ok();
            let tag = if ok == c.expect_ok { "" } else { " **WRONG**" };
            match r {
                Ok(()) => format!("accept{tag}"),
                Err(e) => format!("reject{tag} ({})", short(e)),
            }
        };
        for (w, r) in &c.results {
            if r.is_ok() != c.expect_ok {
                *mism.entry(*w).or_default() += 1;
            }
        }
        println!(
            "| {} | {} | {} | {} | {} | {} |",
            c.name,
            if c.expect_ok { "accept" } else { "reject" },
            mark(&c.results[0].1),
            mark(&c.results[1].1),
            mark(&c.results[2].1),
            mark(&c.results[3].1)
        );
    }
    let summary: Vec<String> = walkers.iter().map(|w| format!("{w:?}={}", mism.get(w).unwrap_or(&0))).collect();
    println!("\nwrong verdicts per walker: {}  (of {} cases; Naive varies 4-6 run to run: query_all tie order is hash-dependent)\n", summary.join(", "), cases.len());

    // --- cost: size and verify time vs number of holder hops ---
    println!("# Cost vs hops (release build recommended)\n");
    println!("| hops | token bytes | walk Scoped µs | walk Strict µs | walk ScopedSeq µs | full authorize (ScopedSeq) µs |\n|---|---|---|---|---|---|");
    let iters = 200;
    for hops in [0usize, 1, 2, 3, 4, 8, 16] {
        let mut keys = vec![kp(&mut rng)];
        let mut t = mint(&r, &keys[0].public(), &mut rng);
        for h in 0..hops {
            let next = kp(&mut rng);
            t = delegate(&t, &keys[h], &next.public(), h as i64 + 1, &[]);
            keys.push(next);
        }
        let last = keys.last().unwrap().public();
        let bytes = t.to_vec().unwrap().len();
        let tw = wire(&t, &root).unwrap();
        let time = |f: &dyn Fn()| {
            let st = Instant::now();
            for _ in 0..iters { f(); }
            st.elapsed().as_secs_f64() * 1e6 / iters as f64
        };
        let ws = time(&|| { assert_eq!(walk(&tw, Walker::Scoped).unwrap(), last.to_bytes()); });
        let wst = time(&|| { assert_eq!(walk(&tw, Walker::Strict).unwrap(), last.to_bytes()); });
        let wsq = time(&|| { assert_eq!(walk(&tw, Walker::ScopedSeq).unwrap(), last.to_bytes()); });
        let full = time(&|| { Node::default().authorize(&t, &root, &last, Walker::ScopedSeq, true, None, s).unwrap(); });
        println!("| {hops} | {bytes} | {ws:.0} | {wst:.0} | {wsq:.0} | {full:.0} |");
    }
}
