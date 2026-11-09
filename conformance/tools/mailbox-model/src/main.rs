//! mailbox-model: reference model for the `mailbox/v0` vectors (spec/ext/mailbox.md §14).
//!
//! ```text
//! mailbox-model gen     <spec/ext/mailbox.md> <vectors/mailbox>   write the table-derived and signature vectors
//! mailbox-model check   <spec/ext/mailbox.md> <vectors/mailbox>   run every vector against the model
//! mailbox-model adapter                                           stdio adapter (conformance/vectors/README.md)
//! ```

mod gen;
mod model;
mod time;

use model::Outcome;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::io::{BufRead, Write};
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let res = match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["gen", spec, out] => gen::generate(Path::new(spec), Path::new(out)),
        ["check", spec, dir] => check(Path::new(spec), Path::new(dir)),
        ["adapter"] => adapter(),
        _ => Err("usage: mailbox-model gen|check <spec> <dir> | adapter".into()),
    };
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn outcome_json(o: &Outcome) -> Value {
    match o {
        Outcome::Accept(Some(v)) => json!({ "result": "accept", "output": v }),
        Outcome::Accept(None) => json!({ "result": "accept" }),
        Outcome::Reject(Some(e)) => json!({ "result": "reject", "error": e }),
        Outcome::Reject(None) => json!({ "result": "reject" }),
        Outcome::Unsupported => json!({ "result": "unsupported" }),
    }
}

fn adapter() -> Result<(), String> {
    let stdin = std::io::stdin();
    let mut out = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line.map_err(|e| e.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        let resp = match serde_json::from_str::<Value>(&line) {
            Ok(req) => {
                let kind = req.get("kind").and_then(Value::as_str).unwrap_or("");
                outcome_json(&model::run(kind, req.get("input").unwrap_or(&Value::Null)))
            }
            Err(_) => json!({ "result": "unsupported" }),
        };
        writeln!(out, "{resp}").map_err(|e| e.to_string())?;
        out.flush().map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Requirement IDs defined (`[MBX-nnn]` tags) in the spec.
pub fn defined_ids(spec: &str) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    for (pos, _) in spec.match_indices("[MBX-") {
        let tail = &spec[pos + 1..];
        if let Some(end) = tail.find(']') {
            ids.insert(tail[..end].to_string());
        }
    }
    ids
}

fn check(spec_path: &Path, dir: &Path) -> Result<(), String> {
    let spec = std::fs::read_to_string(spec_path).map_err(|e| format!("{}: {e}", spec_path.display()))?;
    let defined = defined_ids(&spec);
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    let (mut pass, mut fail) = (0, 0);
    let mut covered = BTreeSet::new();
    for f in &files {
        let text = std::fs::read_to_string(f).map_err(|e| e.to_string())?;
        let v: Value = serde_json::from_str(&text).map_err(|e| format!("{}: {e}", f.display()))?;
        let kind = v["kind"].as_str().ok_or("missing kind")?;
        if v["format"] != "webway-vectors/v0" {
            return Err(format!("{}: wrong format", f.display()));
        }
        let mut seen = BTreeSet::new();
        for c in v["cases"].as_array().ok_or("missing cases")? {
            let id = c["id"].as_str().unwrap_or("?");
            let name = format!("{}#{id}", f.file_name().unwrap().to_string_lossy());
            if !seen.insert(id.to_string()) {
                return Err(format!("{name}: duplicate case id"));
            }
            for r in c["requirements"].as_array().ok_or("missing requirements")? {
                let r = r.as_str().unwrap_or("");
                if r.starts_with("MBX-") && !defined.contains(r) {
                    return Err(format!("{name}: requirement {r} is not defined in the spec"));
                }
                covered.insert(r.to_string());
            }
            let got = model::run(kind, &c["input"]);
            let exp = &c["expect"];
            let good = match (exp["result"].as_str(), &got) {
                (Some("accept"), Outcome::Accept(out)) => {
                    exp.get("output").is_none() || out.as_ref() == exp.get("output")
                }
                (Some("reject"), Outcome::Reject(err)) => match exp.get("error") {
                    None => true,
                    Some(e) => err.as_deref() == e.as_str(),
                },
                _ => false,
            };
            if good {
                pass += 1;
            } else {
                fail += 1;
                println!("FAIL {name}: expected {exp}, model gave {}", outcome_json(&got));
            }
        }
    }
    let untested: Vec<_> = defined.difference(&covered).cloned().collect();
    println!("{pass} passed, {fail} failed, {} files", files.len());
    println!("MBX requirements without a vector (harness-only): {}", untested.join(", "));
    if fail > 0 {
        return Err(format!("{fail} cases failed"));
    }
    Ok(())
}
