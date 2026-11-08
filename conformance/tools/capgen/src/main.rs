//! webway-capgen: reference model and vector generator for spec/ext/capability.md.
//!
//!   webway-capgen gen <vectors-dir>     write identity/*.json and capability/*.json
//!   webway-capgen check <vectors-dir>   run those files through the model, compare verdicts
//!   webway-capgen adapter               stdio adapter (conformance/vectors/README.md)

// The operation table in cap.rs reads better as a match; the generator's token builders take many fields.
#![allow(clippy::match_like_matches_macro, clippy::too_many_arguments)]

mod cap;
mod err;
mod gen;
mod ids;
mod jcs;
mod keys;
mod model;
mod stmt;
mod time;

use serde_json::{json, Value};
use std::io::{BufRead, Write};
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match (args.get(1).map(String::as_str), args.get(2)) {
        (Some("gen"), Some(dir)) => gen_all(Path::new(dir)),
        (Some("check"), Some(dir)) => check_all(Path::new(dir)),
        (Some("adapter"), None) => adapter(),
        _ => {
            eprintln!("usage: webway-capgen gen <dir> | check <dir> | adapter");
            ExitCode::from(2)
        }
    }
}

fn gen_all(dir: &Path) -> ExitCode {
    for f in gen::files() {
        let path = dir.join(f.path);
        match gen::render(f) {
            Ok(v) => {
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                let mut s = serde_json::to_string_pretty(&v).unwrap();
                s.push('\n');
                std::fs::write(&path, s).unwrap();
                println!("wrote {} ({} cases)", path.display(), v["cases"].as_array().unwrap().len());
            }
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::FAILURE;
            }
        }
    }
    ExitCode::SUCCESS
}

fn answer(kind: &str, input: &Value) -> Value {
    match model::run(kind, input) {
        None => json!({"result": "unsupported"}),
        Some(Ok(out)) => json!({"result": "accept", "output": out}),
        Some(Err(e)) => json!({"result": "reject", "error": e.name()}),
    }
}

fn check_all(dir: &Path) -> ExitCode {
    let (mut pass, mut fail) = (0, 0);
    for f in gen::files() {
        let path = dir.join(f.path);
        let v: Value = match std::fs::read(&path).ok().and_then(|b| serde_json::from_slice(&b).ok()) {
            Some(v) => v,
            None => {
                eprintln!("missing or unreadable: {}", path.display());
                fail += 1;
                continue;
            }
        };
        let kind = v["kind"].as_str().unwrap_or("");
        for c in v["cases"].as_array().into_iter().flatten() {
            let got = answer(kind, &c["input"]);
            let want = &c["expect"];
            let ok = got["result"] == want["result"]
                && (want.get("error").is_none() || got.get("error") == want.get("error"))
                && (want.get("output").is_none() || got.get("output") == want.get("output"));
            if ok {
                pass += 1;
            } else {
                fail += 1;
                eprintln!("FAIL {}#{}: want {want}, got {got}", f.path, c["id"].as_str().unwrap_or("?"));
            }
        }
    }
    println!("{pass} passed, {fail} failed");
    if fail == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn adapter() -> ExitCode {
    let stdin = std::io::stdin();
    let mut out = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let resp = match serde_json::from_str::<Value>(&line) {
            Ok(req) => answer(req["kind"].as_str().unwrap_or(""), &req["input"]),
            Err(_) => json!({"result": "unsupported"}),
        };
        writeln!(out, "{resp}").unwrap();
        out.flush().unwrap();
    }
    ExitCode::SUCCESS
}
