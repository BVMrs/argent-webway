//! serde_json without `float_roundtrip` vs Rust's correctly rounded `str::parse::<f64>`, on the
//! num-dec and num-mid cases of ../cases.jsonl. Built in its own package so that no other dependency
//! can switch `float_roundtrip` on through feature unification (serde_json_canonicalizer and serde_jcs do).
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};

fn main() {
    let path = std::env::args().nth(1).expect("cases.jsonl");
    let mut t: BTreeMap<String, (u64, u64, Vec<String>)> = BTreeMap::new();
    for l in BufReader::new(std::fs::File::open(path).unwrap()).lines() {
        let c: Value = serde_json::from_str(&l.unwrap()).unwrap();
        let cat = c["cat"].as_str().unwrap();
        if !cat.starts_with("num-") { continue; }
        let text = c["text"].as_str().unwrap();
        let inner = &text[1..text.len() - 1];
        let Ok(want) = inner.parse::<f64>() else { continue };
        if !want.is_finite() { continue; }
        let got = serde_json::from_str::<f64>(inner);
        let e = t.entry(cat.to_string()).or_default();
        e.0 += 1;
        match got {
            Ok(g) if g.to_bits() == want.to_bits() => {}
            Ok(g) => { e.1 += 1; if e.2.len() < 3 { e.2.push(format!("{} -> serde {:e} std {:e} ({} ulp)", if inner.len() > 60 { &inner[..60] } else { inner }, g, want, (g.to_bits() as i64 - want.to_bits() as i64).abs())); } }
            Err(er) => { e.1 += 1; if e.2.len() < 3 { e.2.push(format!("{} -> serde ERR {}", inner, er)); } }
        }
    }
    for (cat, (n, bad, ex)) in t {
        println!("{:<10} n={:>8} misrounded={:>6} ({:.3} %)", cat, n, bad, 100.0 * bad as f64 / n as f64);
        for e in ex { println!("    {}", e); }
    }
}
