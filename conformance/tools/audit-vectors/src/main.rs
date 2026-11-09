//! `audit-vectors [DIR]` writes the audit/v0 vector files into DIR (default `conformance/vectors/audit`).
//! `audit-vectors --check [DIR]` regenerates them in memory and fails if the files on disk differ.

mod audit;
mod merkle;
mod scenario;

use serde_json::{json, Value};
use std::process::ExitCode;

fn render(f: &scenario::File) -> String {
    let doc = json!({
        "$schema": "../vector.schema.json",
        "format": "webway-vectors/v0",
        "kind": f.kind,
        "description": f.description,
        "spec": f.spec,
        "cases": f.cases,
    });
    lint(&doc);
    serde_json::to_string_pretty(&doc).unwrap() + "\n"
}

/// The structural rules of conformance/vectors/vector.schema.json that this tool can break.
fn lint(doc: &Value) {
    let mut ids = std::collections::BTreeSet::new();
    for c in doc["cases"].as_array().unwrap() {
        let id = c["id"].as_str().unwrap();
        assert!(
            id.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
            "case id {id}"
        );
        assert!(ids.insert(id.to_string()), "duplicate case id {id}");
        let reqs = c["requirements"].as_array().unwrap();
        assert!(!reqs.is_empty());
        for r in reqs {
            let r = r.as_str().unwrap();
            assert!(r.starts_with("AUD-") && r.len() == 7, "requirement {r}");
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let check = args.iter().any(|a| a == "--check");
    let dir = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .cloned()
        .unwrap_or("conformance/vectors/audit".into());
    if args.iter().any(|a| a == "--keys") {
        for n in scenario::KEY_NAMES {
            let k = scenario::key(n);
            println!(
                "| `{n}` | `{}` | `{}` |",
                hex::encode(k.to_bytes()),
                hex::encode(k.verifying_key().as_bytes())
            );
        }
        return ExitCode::SUCCESS;
    }
    let mut ok = true;
    for f in scenario::files() {
        let path = format!("{dir}/{}.json", f.name);
        let text = render(&f);
        if check {
            if std::fs::read_to_string(&path).ok().as_deref() != Some(text.as_str()) {
                eprintln!("{path}: differs from generated output");
                ok = false;
            }
        } else {
            std::fs::write(&path, text).unwrap_or_else(|e| panic!("{path}: {e}"));
            eprintln!("wrote {path} ({} cases)", f.cases.len());
        }
    }
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
