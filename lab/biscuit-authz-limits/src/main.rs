//! Lab: how much CPU/memory can one attenuation block make a capability/v0 verifier spend, given
//! biscuit-auth 6.0.0 `AuthorizerLimits` (default: 1000 facts, 100 iterations, 1 ms)? Are the limits
//! deterministic for honest tokens under load? Does a static pre-Datalog gate bound the cost?
//!
//! Modes:
//!   (no args)                 driver: runs every case in a child process (RLIMIT_AS 3 GiB, 120 s wall cap)
//!   child <case> <a> <b> <limits>   one measurement, prints one TSV line
//!   load <threads> <secs> <limits>  honest-token throughput/verdicts with N threads
//!   regex                     compile cost of candidate regex patterns

use biscuit_auth::{
    builder::{Algorithm, AuthorizerBuilder, BlockBuilder},
    AuthorizerLimits, Biscuit, KeyPair,
};
use biscuit_parser::builder as pb;
use rand::{rngs::StdRng, SeedableRng};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn kp(rng: &mut StdRng) -> KeyPair {
    KeyPair::new_with_rng(Algorithm::Ed25519, rng)
}

struct Keys {
    root: KeyPair,
    b: KeyPair,
    c: KeyPair,
}

fn keys() -> Keys {
    let mut rng = StdRng::seed_from_u64(7);
    Keys { root: kp(&mut rng), b: kp(&mut rng), c: kp(&mut rng) }
}

/// Honest M1-like token: authority (owner B's root) -> third-party holder hop B->C -> attenuation.
fn honest(k: &Keys) -> Biscuit {
    let mut rng = StdRng::seed_from_u64(9);
    let t = Biscuit::builder()
        .fact("right(\"skill:run-tests\")").unwrap()
        .fact(format!("holder(hex:{}, 0)", k.b.public().to_bytes_hex()).as_str()).unwrap()
        .check("check if presenter($k), current_holder($k)").unwrap()
        .check("check if call_count($c), $c < 5").unwrap()
        .check("check if time($t), $t <= 2100-01-01T00:00:00Z").unwrap()
        .build_with_rng(&k.root, Default::default(), &mut rng)
        .unwrap();
    let bb = BlockBuilder::new()
        .fact(format!("holder(hex:{}, 1)", k.c.public().to_bytes_hex()).as_str()).unwrap()
        .check("check if operation(\"skill:run-tests\")").unwrap();
    let req = t.third_party_request().unwrap();
    let blk = req.create_block(&k.b.private(), bb).unwrap();
    let t = t.append_third_party(k.b.public(), blk).unwrap();
    t.append(
        BlockBuilder::new()
            .check("check if time($t), $t <= 2099-01-01T00:00:00Z").unwrap()
            .check("check if task($id), [\"t-1\", \"t-2\"].contains($id)").unwrap(),
    )
    .unwrap()
}

fn vars(k: usize) -> Vec<String> {
    (0..k).map(|i| format!("$x{i}")).collect()
}
fn body(k: usize) -> String {
    vars(k).iter().map(|v| format!("f({v})")).collect::<Vec<_>>().join(", ")
}
fn ffacts(n: usize) -> String {
    (0..n).map(|i| format!("f({i});\n")).collect()
}

/// Datalog source of the attacker's ordinary attenuation block for each case.
fn adv_block(case: &str, a: usize, b: usize) -> Option<String> {
    Some(match case {
        "none" => String::new(),
        // n^k bindings in one rule, no output: fixpoint after one iteration
        "rule_join" => format!("{}g($x0) <- {}, $x0 < 0;\n", ffacts(a), body(b)),
        // n^k bindings in a `reject if` query (passes after a full scan)
        "check_join" => format!("{}reject if {}, $x0 < 0;\n", ffacts(a), body(b)),
        // n^k derived facts in one iteration
        "fact_join" => format!("{}g({}) <- {};\n", ffacts(a), vars(b).join(", "), body(b)),
        // nested closures over a set literal of a ints, depth b: a^b evaluations in one expression
        "closure" => {
            let set = format!("[{}]", (0..a).map(|i| i.to_string()).collect::<Vec<_>>().join(", "));
            let mut e = format!("{} < 0", (0..b).map(|i| format!("$c{i}")).collect::<Vec<_>>().join(" + "));
            for i in (0..b).rev() {
                e = format!("{set}.any($c{i} -> {e})");
            }
            format!("reject if {e};\n")
        }
        // regex recompiled for every binding: a facts joined b ways
        "regex" => format!("{}reject if {}, \"x\".matches(\"{}\");\n", ffacts(a), body(b), REGEX_HEAVY),
        // same, with a pattern that compiles (≈0.3 ms) instead of the heavy one
        "regexmed" => format!("{}reject if {}, \"x\".matches(\"{}\");\n", ffacts(a), body(b), REGEX_MED),
        // many cheap blocks: handled in build()
        "blocks" | "gatemax" => String::new(),
        _ => return None,
    })
}

/// Heaviest pattern from `regex` mode that still compiles under the regex crate's default size limit.
const REGEX_HEAVY: &str = "[a-z]{1000}{1000}";
const REGEX_MED: &str = "[a-z]{60}[0-9]{60}[a-z]{60}";

fn build(k: &Keys, case: &str, a: usize, b: usize) -> Biscuit {
    let mut t = honest(k);
    if case == "gatemax" {
        // worst token the gate admits: `a` extra blocks, each GATE_MAX_CHECKS checks with 2 allowlisted
        // predicates and two sets of `b` ints
        let set = format!("[{}]", (0..b).map(|i| i.to_string()).collect::<Vec<_>>().join(","));
        for _ in 0..a {
            let mut bb = BlockBuilder::new();
            for _ in 0..GATE_MAX_CHECKS {
                bb = bb
                    .check(format!("check if call_count($c), time($t), {set}.contains($c) || {set}.contains($c - 1)").as_str())
                    .unwrap();
            }
            t = t.append(bb).unwrap();
        }
        return t;
    }
    if case == "blocks" {
        for _ in 0..a {
            t = t.append(BlockBuilder::new().check("check if true").unwrap()).unwrap();
        }
        return t;
    }
    let src = adv_block(case, a, b).expect("case");
    if !src.is_empty() {
        let bb = BlockBuilder::new().code(&src).expect("block parse");
        t = t.append(bb).unwrap();
    }
    t
}

fn limits(name: &str) -> AuthorizerLimits {
    match name {
        "default" => AuthorizerLimits::default(),
        // generous backstop: same counts, 100 ms
        "backstop" => AuthorizerLimits { max_time: Duration::from_millis(100), ..Default::default() },
        // measure true cost
        "unbounded" => AuthorizerLimits {
            max_facts: 1_000_000_000,
            max_iterations: 100,
            max_time: Duration::from_secs(600),
        },
        _ => panic!("limits"),
    }
}

fn authorizer(k: &Keys, t: &Biscuit, l: AuthorizerLimits) -> Result<biscuit_auth::Authorizer, String> {
    AuthorizerBuilder::new()
        .fact(format!("presenter(hex:{})", k.c.public().to_bytes_hex()).as_str()).unwrap()
        .fact(format!("current_holder(hex:{})", k.c.public().to_bytes_hex()).as_str()).unwrap()
        .fact("call_count(0)").unwrap()
        .fact("operation(\"skill:run-tests\")").unwrap()
        .fact("task(\"t-1\")").unwrap()
        .time()
        .policy("allow if right($r), operation($r)").unwrap()
        .set_limits(l)
        .build(t)
        .map_err(|e| format!("{e:?}"))
}

// ---------------------------------------------------------------------------------------------
// Static gate (proposed capability/v0 profile rule), run on the parsed token before any Datalog.

const GATE_MAX_BLOCKS: usize = 16;
const GATE_MAX_BYTES: usize = 8 * 1024;
const GATE_MAX_CHECKS: usize = 8;
const GATE_MAX_BODY: usize = 2;
const GATE_MAX_SET: usize = 64;
const GATE_PREDICATES: &[&str] =
    &["time", "operation", "resource", "task", "arg", "call_count", "presenter", "current_holder", "right"];

fn gate_term(t: &pb::Term) -> Result<(), String> {
    match t {
        pb::Term::Set(s) if s.len() > GATE_MAX_SET => Err(format!("set of {}", s.len())),
        pb::Term::Parameter(_) => Err("parameter".into()),
        _ => Ok(()),
    }
}

/// Allowlisted operators. Zero-parameter closures are how biscuit 6 encodes lazy `&&`/`||`: allowed and
/// checked recursively. Closures with parameters (`.any`/`.all`) are rejected.
fn gate_ops(ops: &[pb::Op]) -> Result<(), String> {
    for op in ops {
        match op {
            pb::Op::Value(t) => gate_term(t)?,
            pb::Op::Unary(pb::Unary::Ffi(_)) => return Err("ffi".into()),
            pb::Op::Unary(_) => {}
            pb::Op::Closure(params, inner) if params.is_empty() => gate_ops(inner)?,
            pb::Op::Closure(..) => return Err("closure".into()),
            pb::Op::Binary(bin) => {
                use pb::Binary::*;
                match bin {
                    LessThan | GreaterThan | LessOrEqual | GreaterOrEqual | Equal | NotEqual
                    | HeterogeneousEqual | HeterogeneousNotEqual | Contains | Prefix | Suffix | And | Or
                    | LazyAnd | LazyOr | Sub => {}
                    other => return Err(format!("operator {other:?}")),
                }
            }
        }
    }
    Ok(())
}

fn gate_rule(r: &pb::Rule) -> Result<(), String> {
    if r.body.len() > GATE_MAX_BODY {
        return Err(format!("{} body predicates", r.body.len()));
    }
    if !r.scopes.is_empty() {
        return Err("explicit scope".into());
    }
    for p in &r.body {
        if !GATE_PREDICATES.contains(&p.name.as_str()) {
            return Err(format!("predicate {}", p.name));
        }
        for t in &p.terms {
            gate_term(t)?;
        }
    }
    for e in &r.expressions {
        gate_ops(&e.ops)?;
    }
    Ok(())
}

/// Returns Ok(()) if every non-authority block fits the profile. `bytes` = serialized token length.
fn gate(t: &Biscuit, bytes: usize) -> Result<(), String> {
    if bytes > GATE_MAX_BYTES {
        return Err(format!("{bytes} bytes"));
    }
    if t.block_count() > GATE_MAX_BLOCKS {
        return Err(format!("{} blocks", t.block_count()));
    }
    for i in 1..t.block_count() {
        let src = t.print_block_source(i).map_err(|e| format!("{e:?}"))?;
        let parsed = biscuit_parser::parser::parse_block_source(&src).map_err(|_| "reparse".to_string())?;
        if !parsed.rules.is_empty() {
            return Err("rule in attenuation block".into());
        }
        let third_party = t.block_external_key(i).ok().flatten().is_some();
        for (_, f) in &parsed.facts {
            if !(third_party && f.predicate.name == "holder" && parsed.facts.len() == 1) {
                return Err(format!("fact {}", f.predicate.name));
            }
        }
        if parsed.checks.len() > GATE_MAX_CHECKS {
            return Err(format!("{} checks", parsed.checks.len()));
        }
        for (_, c) in &parsed.checks {
            for q in &c.queries {
                gate_rule(q)?;
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------

fn maxrss_kb() -> i64 {
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
    ru.ru_maxrss
}

fn short(e: &str) -> String {
    if e.contains("Timeout") {
        "Timeout".into()
    } else if e.contains("TooManyFacts") {
        "TooManyFacts".into()
    } else if e.contains("TooManyIterations") {
        "TooManyIter".into()
    } else if e.contains("FailedLogic") {
        "Denied".into()
    } else {
        e.chars().take(40).collect()
    }
}

fn child(case: &str, a: usize, b: usize, lim: &str) {
    let k = keys();
    let t = build(&k, case, a, b);
    let bytes = t.to_vec().unwrap();
    let rss0 = maxrss_kb();
    let g0 = Instant::now();
    let parsed = Biscuit::from(&bytes, k.root.public()).unwrap();
    let parse_us = g0.elapsed().as_secs_f64() * 1e6;
    let g1 = Instant::now();
    let gv = gate(&parsed, bytes.len());
    let gate_us = g1.elapsed().as_secs_f64() * 1e6;
    let t0 = Instant::now();
    let (res, iters, facts) = match authorizer(&k, &parsed, limits(lim)) {
        Err(e) => (short(&e), 0, 0),
        Ok(mut az) => {
            let r = az.authorize();
            let r = match r {
                Ok(_) => "Allow".to_string(),
                Err(e) => short(&format!("{e:?}")),
            };
            (r, az.iterations(), az.fact_count())
        }
    };
    let authz_ms = t0.elapsed().as_secs_f64() * 1e3;
    println!(
        "{case}\t{a}\t{b}\t{lim}\t{}\t{parse_us:.0}\t{authz_ms:.3}\t{res}\t{iters}\t{facts}\t{}\t{}\t{gate_us:.0}",
        bytes.len(),
        (maxrss_kb() - rss0) / 1024,
        match gv {
            Ok(()) => "pass".to_string(),
            Err(e) => format!("reject:{e}"),
        }
    );
}

fn driver() {
    let exe = std::env::current_exe().unwrap();
    let mut cases: Vec<(&str, usize, usize)> = vec![("none", 0, 0)];
    for &(n, k) in &[(10, 2), (10, 4), (20, 4), (30, 4), (40, 4), (10, 6), (16, 6), (20, 6), (100, 3), (200, 3), (300, 3)] {
        cases.push(("rule_join", n, k));
        cases.push(("check_join", n, k));
    }
    for &(n, k) in &[(10, 3), (20, 3), (10, 4), (30, 3), (20, 4), (25, 4), (30, 4)] {
        cases.push(("fact_join", n, k));
    }
    for &(n, d) in &[(10, 3), (30, 3), (100, 3), (30, 4), (60, 4), (20, 5), (30, 5)] {
        cases.push(("closure", n, d));
    }
    for &(n, k) in &[(1, 1), (10, 1), (10, 2), (20, 2), (30, 2), (10, 3)] {
        cases.push(("regex", n, k));
    }
    for &(n, k) in &[(1, 1), (10, 1), (10, 2), (20, 2)] {
        cases.push(("regexmed", n, k));
    }
    for &n in &[10, 50, 100, 200, 400] {
        cases.push(("blocks", n, 0));
    }
    println!("case\ta\tb\tlimits\ttoken_B\tparse_us\tauthz_ms\tresult\titers\tfacts\tdrss_MiB\tgate\tgate_us");
    for &(n, b) in &[(1, 64), (5, 8), (12, 1), (13, 1), (14, 64)] {
        cases.push(("gatemax", n, b));
    }
    let only: Vec<String> = std::env::var("CASES").map(|v| v.split(',').map(String::from).collect()).unwrap_or_default();
    if !only.is_empty() {
        cases.retain(|(c, _, _)| only.iter().any(|o| o == c));
    }
    for (case, a, b) in cases {
        for lim in ["default", "unbounded"] {
            let out = Command::new("bash")
                .arg("-c")
                .arg(format!(
                    "ulimit -v 3145728; timeout 120 '{}' child {case} {a} {b} {lim}",
                    exe.display()
                ))
                .output()
                .unwrap();
            let s = String::from_utf8_lossy(&out.stdout);
            if s.trim().is_empty() {
                let code = out.status.code().map(|c| c.to_string()).unwrap_or("signal".into());
                let why = if code == "124" { "KILLED>120s" } else { "KILLED(oom/abort)" };
                println!("{case}\t{a}\t{b}\t{lim}\t-\t-\t-\t{why} exit={code}\t-\t-\t-\t-\t-");
            } else {
                print!("{s}");
            }
        }
    }
}

fn load(threads: usize, secs: u64, lim: &str) {
    let k = Arc::new(keys());
    let bytes = Arc::new(honest(&k).to_vec().unwrap());
    let stop = Arc::new(AtomicBool::new(false));
    let mut hs = vec![];
    for _ in 0..threads {
        let (k, bytes, stop) = (k.clone(), bytes.clone(), stop.clone());
        let lim = lim.to_string();
        hs.push(std::thread::spawn(move || {
            let (mut ok, mut timeout, mut other) = (0u64, 0u64, 0u64);
            let mut lat = vec![];
            while !stop.load(Ordering::Relaxed) {
                let t0 = Instant::now();
                let t = Biscuit::from(&*bytes, k.root.public()).unwrap();
                let mut az = authorizer(&k, &t, limits(&lim)).unwrap();
                match az.authorize() {
                    Ok(_) => ok += 1,
                    Err(e) if format!("{e:?}").contains("Timeout") => timeout += 1,
                    Err(_) => other += 1,
                }
                lat.push(t0.elapsed().as_secs_f64() * 1e6);
            }
            (ok, timeout, other, lat)
        }));
    }
    std::thread::sleep(Duration::from_secs(secs));
    stop.store(true, Ordering::Relaxed);
    let (mut ok, mut to, mut ot, mut lat) = (0, 0, 0, vec![]);
    for h in hs {
        let (a, b, c, l) = h.join().unwrap();
        ok += a;
        to += b;
        ot += c;
        lat.extend(l);
    }
    lat.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p = |q: f64| lat[((lat.len() as f64 - 1.0) * q) as usize];
    let n = ok + to + ot;
    println!(
        "{threads}\t{lim}\t{n}\t{:.0}/s\t{ok}\t{to}\t{:.4}%\t{ot}\t{:.0}\t{:.0}\t{:.0}\t{:.0}",
        n as f64 / secs as f64,
        100.0 * to as f64 / n as f64,
        p(0.5),
        p(0.99),
        p(0.999),
        lat[lat.len() - 1]
    );
}

fn regex_mode() {
    for pat in [
        "a",
        "[a-z]{10}",
        "[a-z]{60}[0-9]{60}[a-z]{60}",
        "(a|b|c|d|e|f|g|h|i|j){50}",
        "[a-z]{200}[0-9]{200}",
        "[a-z]{1000}{1000}",
        "((a{10}){10}){10}",
    ] {
        let ok = regex::Regex::new(pat)
            .map(|_| "ok".to_string())
            .unwrap_or_else(|e| format!("{e}").replace('\n', " ").chars().take(40).collect());
        let t0 = Instant::now();
        for _ in 0..20 {
            let _ = regex::Regex::new(pat);
        }
        println!("{pat}\t{ok}\t{:.1} us", t0.elapsed().as_secs_f64() * 1e6 / 20.0);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        None => driver(),
        Some("child") => child(&args[2], args[3].parse().unwrap(), args[4].parse().unwrap(), &args[5]),
        Some("load") => load(args[2].parse().unwrap(), args[3].parse().unwrap(), &args[4]),
        Some("regex") => regex_mode(),
        _ => panic!("mode"),
    }
}
