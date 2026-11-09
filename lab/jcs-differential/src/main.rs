//! Differential test of Rust RFC 8785 (JCS) canonicalisers against an ECMAScript oracle.
//!
//!   jcs-differential gen <cases.jsonl> [seed] [scale]   write test inputs (JSON texts)
//!   jcs-differential cmp <cases.jsonl> <oracle.jsonl>   run each crate, compare with oracle
//!   jcs-differential rfc <testdata dir>                 cyberphone input/ vs output/ pairs
//!
//! The oracle (oracle.ts, run by Node) is JSON.parse + the RFC 8785 reference algorithm,
//! which defines numbers and strings by ECMAScript JSON.stringify, so V8 is the spec's own model.

use rand::{seq::SliceRandom, Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, BufWriter, Write};

mod bigdec;
mod strict;

type Canon = fn(&Value) -> Result<String, String>;

fn crates() -> Vec<(&'static str, Canon)> {
    vec![
        ("sjc-0.3", |v| sjc03::to_string(v).map_err(|e| e.to_string())),
        ("sjc-0.4", |v| sjc04::to_string(v).map_err(|e| e.to_string())),
        ("serde_jcs-0.2", |v| serde_jcs::to_string(v).map_err(|e| e.to_string())),
    ]
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("gen") => gen(&a[2], a.get(3).map_or(1, |s| s.parse().unwrap()), a.get(4).map_or(1.0, |s| s.parse().unwrap())),
        Some("cmp") => cmp(&a[2], &a[3]),
        Some("rfc") => rfc(&a[2]),
        Some("probe") => probe(),
        _ => eprintln!("usage: gen|cmp|rfc"),
    }
}

// ---------------------------------------------------------------- generation

struct Out(BufWriter<fs::File>, u64);
impl Out {
    fn case(&mut self, cat: &str, text: String) {
        let line = json!({"id": self.1, "cat": cat, "text": text});
        writeln!(self.0, "{}", line).unwrap();
        self.1 += 1;
    }
}

fn gen(path: &str, seed: u64, scale: f64) {
    let mut r = ChaCha20Rng::seed_from_u64(seed);
    let mut o = Out(BufWriter::new(fs::File::create(path).unwrap()), 0);
    let n = |k: usize| ((k as f64) * scale) as usize;

    // 1. random finite doubles, written in Rust's shortest round-trip form: tests serialisation
    for _ in 0..n(1_000_000) {
        let f = loop {
            let f = f64::from_bits(r.gen());
            if f.is_finite() { break f; }
        };
        o.case("num-bits", format!("[{:e}]", f));
    }
    // 1b. "nice" doubles in the ranges where ES switches notation (1e-7, 1e21) and short decimals
    for _ in 0..n(300_000) {
        let digits = r.gen_range(1..=17);
        let m: u64 = r.gen_range(1..10u64.pow(digits));
        let e: i32 = r.gen_range(-30..=30);
        o.case("num-short", format!("[{}e{}]", m, e));
    }
    // 2. random decimal strings, up to 40 significant digits: tests correctly-rounded parsing
    for _ in 0..n(300_000) {
        let len = r.gen_range(1..=40);
        let mut s: String = (0..len).map(|i| char::from(b'0' + if i == 0 { r.gen_range(1..10) } else { r.gen_range(0..10) })).collect();
        let e: i32 = r.gen_range(-345..=310);
        if r.gen_bool(0.5) { s.insert(1, '.'); if s.ends_with('.') { s.push('0'); } }
        let sign = if r.gen_bool(0.3) { "-" } else { "" };
        o.case("num-dec", format!("[{}{}e{}]", sign, s, e));
    }
    // 3. exact midpoints between adjacent doubles, and a hair above/below: hardest parse cases
    for _ in 0..n(200_000) {
        let f = loop {
            let f = f64::from_bits(r.gen::<u64>() >> 1);
            if f.is_finite() && f != f64::MAX && f > 0.0 { break f; }
        };
        let mid = bigdec::midpoint_above(f);
        let v = match r.gen_range(0..3) { 0 => mid, 1 => bigdec::nudge(&mid, true), _ => bigdec::nudge(&mid, false) };
        o.case("num-mid", format!("[{}]", v));
    }
    // 4. integers written as integers, by range
    for _ in 0..n(100_000) {
        o.case("int-le2^53", format!("[{}]", r.gen_range(0..=(1u64 << 53)) as i64 * if r.gen_bool(0.5) { 1 } else { -1 }));
        o.case("int-2^53..2^63", format!("[{}]", r.gen_range((1i64 << 53) + 1..=i64::MAX) * if r.gen_bool(0.5) { 1 } else { -1 }));
        o.case("int-2^63..2^64", format!("[{}]", r.gen_range((1u64 << 63)..=u64::MAX)));
        o.case("int->2^64", format!("[{}{:019}]", r.gen_range(2..1_000_000u64), r.gen_range(0..10u64.pow(19))));
    }
    for t in ["[-0]", "[-0.0]", "[0e5]", "[-0e-5]", "[1E2]", "[1e21]", "[1e20]", "[999999999999999999999]", "[1e-7]", "[1e-6]",
              "[9007199254740993]", "[9007199254740992.5]", "[18446744073709551615]", "[18446744073709551616]", "[-9223372036854775808]",
              "[5e-324]", "[2.4703282292062328e-324]", "[2.4703282292062327e-324]", "[1.7976931348623157e308]", "[1.7976931348623158e308]",
              "[1.7976931348623159e308]", "[1e309]", "[-1e400]", "[1e-400]"] {
        o.case("num-edge", t.to_string());
    }

    // 5. strings: random code points, each written raw or \u-escaped
    let pool: Vec<std::ops::RangeInclusive<u32>> = vec![0x00..=0x1f, 0x20..=0x7f, 0x80..=0x7ff, 0x2028..=0x2029, 0xd7f0..=0xd7ff,
        0xe000..=0xe0ff, 0xfff0..=0xffff, 0x10000..=0x100ff, 0x10ff00..=0x10ffff, 0x1f600..=0x1f64f];
    let rand_char = |r: &mut ChaCha20Rng| -> char {
        let rg = pool.choose(r).unwrap().clone();
        char::from_u32(r.gen_range(rg)).unwrap()
    };
    let write_str = |r: &mut ChaCha20Rng, s: &str| -> String {
        let mut t = String::from("\"");
        for c in s.chars() {
            let esc = r.gen_bool(0.3) || c == '"' || c == '\\' || (c as u32) < 0x20;
            if !esc { t.push(c); continue; }
            match (c, r.gen_bool(0.5)) {
                ('"', true) => t.push_str("\\\""), ('\\', true) => t.push_str("\\\\"), ('/', true) => t.push_str("\\/"),
                ('\n', true) => t.push_str("\\n"), ('\t', true) => t.push_str("\\t"), ('\u{8}', true) => t.push_str("\\b"),
                _ => { let mut b = [0u16; 2]; let up = r.gen_bool(0.5); for u in c.encode_utf16(&mut b) { t.push_str(&if up { format!("\\u{:04X}", u) } else { format!("\\u{:04x}", u) }); } }
            }
        }
        t.push('"');
        t
    };
    for _ in 0..n(200_000) {
        let len = r.gen_range(0..12);
        let s: String = (0..len).map(|_| rand_char(&mut r)).collect();
        let t = write_str(&mut r, &s);
        o.case("str", format!("[{}]", t));
    }
    // 6. object key ordering: keys from the ranges where UTF-8/code-point order and UTF-16 order differ
    for _ in 0..n(200_000) {
        let k = r.gen_range(2..7);
        let mut keys = std::collections::BTreeSet::new();
        while keys.len() < k {
            let len = r.gen_range(1..4);
            keys.insert((0..len).map(|_| rand_char(&mut r)).collect::<String>());
        }
        let mut keys: Vec<_> = keys.into_iter().collect();
        keys.shuffle(&mut r);
        let body: Vec<String> = keys.iter().enumerate().map(|(i, k)| format!("{}:{}", write_str(&mut r, k), i)).collect();
        o.case("keys", format!("{{{}}}", body.join(",")));
    }
    // 7. I-JSON violations: every one of these MUST be rejected by an envelope/v0 verifier
    for t in [r#"{"a":1,"a":2}"#, r#"{"a":1,"a":2}"#, r#"{"x":{"b":1,"b":1}}"#, r#"["\ud800"]"#, r#"["\udc00"]"#,
              r#"["\ud800A"]"#, r#"["\udbff\udbff"]"#, r#"{"\ud800":1}"#] {
        o.case("ijson", t.to_string());
    }
    // 8. nesting depth
    for d in [64usize, 127, 128, 129, 200, 1000, 5000] {
        o.case(&format!("depth-{}", d), format!("{}{}", "[".repeat(d), "]".repeat(d)));
    }
}

// ---------------------------------------------------------------- comparison

#[derive(Default, Debug)]
struct Tally { n: u64, agree: u64, differ: u64, err_where_oracle_ok: u64, ok_where_oracle_err: u64, both_err: u64, not_idem: u64 }

fn cmp(cases: &str, oracle: &str) {
    let cs = BufReader::new(fs::File::open(cases).unwrap()).lines();
    let os = BufReader::new(fs::File::open(oracle).unwrap()).lines();
    let cr = crates();
    let mut t: BTreeMap<(String, String), Tally> = BTreeMap::new();
    let mut examples: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
    for (c, ol) in cs.zip(os) {
        let c: Value = serde_json::from_str(&c.unwrap()).unwrap();
        let ol: Value = serde_json::from_str(&ol.unwrap()).unwrap();
        assert_eq!(c["id"], ol["id"]);
        let cat = c["cat"].as_str().unwrap().to_string();
        let text = c["text"].as_str().unwrap();
        let want = ol["out"].as_str();
        let lax: Result<Value, String> = serde_json::from_str(text).map_err(|e| e.to_string());
        let strict = strict::parse(text);
        for (pname, parsed) in [("lax", &lax), ("strict", &strict)] {
        for (cname, f) in &cr {
            let name = format!("{}+{}", pname, cname);
            let got = parsed.clone().and_then(|v| f(&v));
            let e = t.entry((cat.clone(), name.to_string())).or_default();
            e.n += 1;
            let ex = examples.entry((cat.clone(), name.to_string())).or_default();
            match (&got, want) {
                (Ok(g), Some(w)) if g == w => {
                    e.agree += 1;
                    // idempotence: canon(parse(canon(x))) == canon(x)
                    let again = serde_json::from_str::<Value>(g).map_err(|e| e.to_string()).and_then(|v| f(&v));
                    if again.as_deref() != Ok(g.as_str()) { e.not_idem += 1; }
                }
                (Ok(g), Some(w)) => { e.differ += 1; if ex.len() < 4 { ex.push(format!("in {}  rust {}  oracle {}", short(text), short(g), short(w))); } }
                (Err(er), Some(w)) => { e.err_where_oracle_ok += 1; if ex.len() < 4 { ex.push(format!("in {}  rust ERR {}  oracle {}", short(text), short(er), short(w))); } }
                (Ok(g), None) => { e.ok_where_oracle_err += 1; if ex.len() < 4 { ex.push(format!("in {}  rust {}  oracle ERR {}", short(text), short(g), ol["err"])); } }
                (Err(_), None) => e.both_err += 1,
            }
        }
        }
    }
    println!("{:<16} {:<22} {:>9} {:>9} {:>7} {:>8} {:>8} {:>6} {:>6}", "category", "crate", "n", "agree", "differ", "rustErr", "oraclErr", "both", "!idem");
    for ((cat, name), x) in &t {
        println!("{:<16} {:<22} {:>9} {:>9} {:>7} {:>8} {:>8} {:>6} {:>6}", cat, name, x.n, x.agree, x.differ, x.err_where_oracle_ok, x.ok_where_oracle_err, x.both_err, x.not_idem);
    }
    println!("\nexamples of disagreement:");
    for ((cat, name), ex) in &examples {
        for e in ex { println!("  [{} / {}] {}", cat, name, e); }
    }
}

fn short(s: &str) -> String {
    let s: String = s.chars().flat_map(|c| if (c as u32) < 0x20 || (0x7f..0xa0).contains(&(c as u32)) { format!("<{:02x}>", c as u32).chars().collect::<Vec<_>>() } else { vec![c] }).collect();
    if s.chars().count() > 90 { format!("{}…", s.chars().take(90).collect::<String>()) } else { s }
}

// ---------------------------------------------------------------- RFC 8785 reference data

fn rfc(dir: &str) {
    let mut names: Vec<_> = fs::read_dir(format!("{}/input", dir)).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
    names.sort();
    for (cname, f) in crates() {
        let mut pass = 0;
        let mut fail = vec![];
        for n in &names {
            let input = fs::read_to_string(format!("{}/input/{}", dir, n)).unwrap();
            let want = fs::read(format!("{}/output/{}", dir, n)).unwrap();
            let want = String::from_utf8(want).unwrap();
            let want = want.trim_end_matches('\n');
            let got = serde_json::from_str::<Value>(&input).map_err(|e| e.to_string()).and_then(|v| f(&v));
            if got.as_deref() == Ok(want) { pass += 1 } else { fail.push(format!("{}: {:?}", n, got.map(|g| short(&g)))) }
        }
        println!("{:<14} {}/{} pass {:?}", cname, pass, names.len(), fail);
    }
}

// ---------------------------------------------------------------- probes

/// Copy of `numbers_ok` from conformance/tools/audit-vectors/src/audit.rs (master 10d10ad), AUD-001.
fn audit_numbers_ok(v: &Value) -> bool {
    const MAX_SAFE: u64 = (1 << 53) - 1;
    match v {
        Value::Number(n) => n.as_u64().is_some_and(|x| x <= MAX_SAFE) || n.as_i64().is_some_and(|x| x.unsigned_abs() <= MAX_SAFE),
        Value::Array(a) => a.iter().all(audit_numbers_ok),
        Value::Object(m) => m.values().all(audit_numbers_ok),
        _ => true,
    }
}

fn probe() {
    let v: Value = serde_json::from_str("[1e2,100.0]").unwrap();
    println!("serde_json build: Value [1e2,100.0] re-serialises as {} (arbitrary_precision keeps the spelling)\n", serde_json::to_string(&v).unwrap());
    println!("## AUD-001 'integer of magnitude at most 2^53-1 (no fractions or exponents that denote non-integers)'");
    println!("{:<26} {:>14} {:>22}", "token", "JCS", "audit-vectors accepts");
    for t in ["100", "1e2", "1E+2", "100.0", "1.00e2", "0", "-0", "0.0", "9007199254740991", "9.007199254740991e15",
              "9007199254740992", "-9007199254740991", "1.5", "1e-400"] {
        let v: Value = serde_json::from_str(t).unwrap();
        println!("{:<26} {:>14} {:>22}", t, sjc04::to_string(&v).unwrap(), audit_numbers_ok(&v));
    }
    println!("\n## spellings that canonicalise to the same bytes (so the same signature / body_hash)");
    for group in [vec!["0", "-0", "0.0", "0e9", "1e-400", "-1e-400"], vec!["100", "1e2", "100.000", "1000e-1"],
                  vec!["9007199254740992", "9007199254740993", "9.007199254740993e15"],
                  vec!["0.1", "0.1000000000000000055511151231257827", "0.10000000000000001"]] {
        let outs: Vec<String> = group.iter().map(|t| sjc04::to_string(&serde_json::from_str::<Value>(t).unwrap()).unwrap()).collect();
        println!("{:?} -> {:?}", group, outs);
    }
    println!("\n## duplicate keys in a signed header");
    let hdr = r#"{"v":"webway-envelope/0","to":"wwa:alice","to":"wwa:mallory","id":"x"}"#;
    println!("input           {}", hdr);
    println!("lax  + sjc-0.4  {:?}", serde_json::from_str::<Value>(hdr).map_err(|e| e.to_string()).and_then(|v| sjc04::to_string(&v).map_err(|e| e.to_string())));
    println!("strict          {:?}", strict::parse(hdr));
}
