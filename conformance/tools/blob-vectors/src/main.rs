//! Reference model, vector generator and stdio adapter for `blob/v0` (spec/ext/blob.md).
//!
//!   cargo run -- generate   # rewrite conformance/vectors/blob/*.json
//!   cargo run -- check      # fail if the files on disk differ from what the generator produces
//!   cargo run -- adapter    # serve the model over the stdio adapter protocol
//!
//! `cargo test` runs `check`, checks that every `MUST` requirement of the spec is covered by a
//! vector or marked pending, and compares the tree model with bao-tree (tests/bao_compat.rs).

mod gen;
mod model;
mod tree;

use std::io::{BufRead, Write};
use std::path::PathBuf;

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/blob")
}

fn render(v: &serde_json::Value) -> String {
    serde_json::to_string_pretty(v).unwrap() + "\n"
}

fn check() -> Result<(), String> {
    let dir = vectors_dir();
    let mut stale = vec![];
    for (name, content) in gen::all() {
        let on_disk = std::fs::read_to_string(dir.join(name)).unwrap_or_default();
        if on_disk != render(&content) {
            stale.push(name);
        }
    }
    if stale.is_empty() {
        Ok(())
    } else {
        Err(format!("stale vector files (run `cargo run -- generate`): {stale:?}"))
    }
}

/// The stdio adapter protocol of conformance/vectors/README.md (CONV-006).
fn adapter() {
    let stdin = std::io::stdin();
    let mut out = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line.unwrap();
        if line.trim().is_empty() {
            continue;
        }
        let req: serde_json::Value = serde_json::from_str(&line).unwrap();
        let kind = req["kind"].as_str().unwrap_or("");
        let resp = match model::run(kind, &req["input"]) {
            None => serde_json::json!({ "result": "unsupported" }),
            Some(Ok(o)) => serde_json::json!({ "result": "accept", "output": o }),
            Some(Err(e)) => serde_json::json!({ "result": "reject", "error": e }),
        };
        writeln!(out, "{resp}").unwrap();
        out.flush().unwrap();
    }
}

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("generate") => {
            let dir = vectors_dir();
            std::fs::create_dir_all(&dir).unwrap();
            for (name, content) in gen::all() {
                let n = content["cases"].as_array().map_or(0, |c| c.len());
                std::fs::write(dir.join(name), render(&content)).unwrap();
                println!("wrote {name} ({n} cases)");
            }
        }
        Some("check") => match check() {
            Ok(()) => println!("vectors up to date"),
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        },
        Some("adapter") => adapter(),
        _ => {
            eprintln!("usage: blob-vectors generate|check|adapter");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    #[test]
    fn vectors_are_current() {
        super::check().unwrap();
    }

    /// Requirement blocks of spec/ext/blob.md: (id, is MUST, is pending).
    fn spec_requirements() -> Vec<(String, bool, bool)> {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../spec/ext/blob.md");
        let text = std::fs::read_to_string(path).unwrap();
        // Blocks are paragraphs or list items; drop fenced code first.
        let mut clean = String::new();
        let mut fenced = false;
        for l in text.lines() {
            if l.trim_start().starts_with("```") {
                fenced = !fenced;
                continue;
            }
            if !fenced {
                clean.push_str(l);
                clean.push('\n');
            }
        }
        let mut blocks: Vec<String> = vec![];
        for l in clean.lines() {
            let t = l.trim_start();
            let starts = t.is_empty() || t.starts_with("- ") || t.starts_with('|') || t.starts_with('#');
            if starts || blocks.is_empty() {
                blocks.push(String::new());
            }
            blocks.last_mut().unwrap().push_str(l);
            blocks.last_mut().unwrap().push(' ');
        }
        let strip_code = |s: &str| {
            let mut out = String::new();
            let mut code = false;
            for c in s.chars() {
                if c == '`' {
                    code = !code;
                } else if !code {
                    out.push(c);
                }
            }
            out
        };
        let mut reqs = vec![];
        for b in blocks {
            let t = b.trim_start().trim_start_matches("- ").trim_start_matches("| ").trim_start_matches("**");
            if let Some(rest) = t.strip_prefix("[BLOB-") {
                let id = format!("BLOB-{}", &rest[..3]);
                let body = strip_code(&b);
                let must = body.contains("MUST") || body.contains("SHALL") || body.contains("REQUIRED");
                reqs.push((id, must, b.contains("*Pending:")));
            } else {
                let body = strip_code(&b);
                assert!(!body.contains("MUST"), "MUST block without a requirement ID: {}", b.trim());
            }
        }
        reqs
    }

    #[test]
    fn every_must_is_covered_or_pending() {
        let reqs = spec_requirements();
        assert!(reqs.len() > 20, "too few requirements found: {}", reqs.len());
        let mut ids = BTreeSet::new();
        for (id, _, _) in &reqs {
            assert!(ids.insert(id.clone()), "{id} defined twice");
        }
        let mut covered = BTreeSet::new();
        for (_, file) in super::gen::all() {
            for c in file["cases"].as_array().unwrap() {
                for r in c["requirements"].as_array().unwrap() {
                    let r = r.as_str().unwrap().to_string();
                    assert!(ids.contains(&r), "vector references undefined {r}");
                    covered.insert(r);
                }
            }
        }
        for (id, must, pending) in &reqs {
            if *must && !*pending {
                assert!(covered.contains(id), "{id} is a MUST with no vector and no Pending marker");
            }
            if *pending {
                assert!(!covered.contains(id), "{id} is marked pending but has vectors: remove the marker");
            }
        }
    }
}
