//! Generates the envelope/v0 conformance vectors (`conformance/vectors/envelope/v0/`).
//!
//!   cargo run -- generate   # rewrite the vector files
//!   cargo run -- check      # fail if the files on disk differ from what the generator produces
//!
//! `cargo test` also runs `check`, and checks that every requirement the spec's Appendix A says
//! is tested by a vector file has at least one case in that file.

mod encoding;
mod gen;
mod json;
mod schema;
mod verify;

use std::path::PathBuf;

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/envelope/v0")
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

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("generate") => {
            let dir = vectors_dir();
            std::fs::create_dir_all(&dir).unwrap();
            for (name, content) in gen::all() {
                let cases = content["cases"].as_array().map_or(0, |c| c.len());
                std::fs::write(dir.join(name), render(&content)).unwrap();
                println!("wrote {name} ({cases} cases)");
            }
        }
        Some("check") => {
            if let Err(e) = check() {
                eprintln!("{e}");
                std::process::exit(1);
            }
            println!("vectors up to date");
        }
        _ => {
            eprintln!("usage: envelope-vectors generate|check");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    #[test]
    fn vectors_are_up_to_date() {
        super::check().unwrap();
    }

    /// Appendix A of the spec ↔ requirement IDs in the vector files.
    #[test]
    fn requirement_coverage() {
        let spec = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../spec/ext/envelope.md"),
        )
        .unwrap();
        // IDs defined in the body: "**ENV-nnn** (LEVEL)".
        let mut defined = BTreeMap::new();
        for part in spec.split("**ENV-").skip(1) {
            if !part.as_bytes()[..3].iter().all(u8::is_ascii_digit) {
                continue; // e.g. "**ENV-nnn**" in the conventions section
            }
            let id = format!("ENV-{}", &part[..3]);
            let level = part[3..].trim_start_matches("**").trim().trim_start_matches('(');
            let level = &level[..level.find(')').unwrap()];
            defined.insert(id, level.to_string());
        }
        // Appendix A rows: "| ENV-nnn | LEVEL | topic | tested by |".
        let appendix = &spec[spec.find("## Appendix A").unwrap()..spec.find("## Appendix B").unwrap()];
        let mut index = BTreeMap::new();
        for line in appendix.lines().filter(|l| l.starts_with("| ENV-")) {
            let cols: Vec<&str> = line.split('|').map(str::trim).collect();
            index.insert(cols[1].to_string(), (cols[2].to_string(), cols[4].to_string()));
        }
        assert_eq!(defined.keys().collect::<Vec<_>>(), index.keys().collect::<Vec<_>>(), "Appendix A must list exactly the defined IDs");
        for (id, level) in &defined {
            assert_eq!(&index[id].0, level, "{id}: level in Appendix A differs from the body");
        }
        let files = super::gen::all();
        let mut used: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
        for (name, content) in &files {
            for c in content["cases"].as_array().into_iter().flatten() {
                for r in c["requirements"].as_array().unwrap() {
                    let r = r.as_str().unwrap().to_string();
                    assert!(defined.contains_key(&r), "{name}: {r} is not defined in the spec");
                    used.entry(name).or_default().insert(r);
                }
            }
        }
        let mut problems = vec![];
        for (id, (level, tested_by)) in &index {
            for (name, _) in &files {
                if tested_by.contains(&format!("`{name}`")) && !used.get(name).is_some_and(|s| s.contains(id)) {
                    problems.push(format!("{id}: Appendix A names {name}, which has no case for it"));
                }
            }
            for (name, ids) in &used {
                if ids.contains(id) && !tested_by.contains(&format!("`{name}`")) && !tested_by.contains("all vector files") {
                    problems.push(format!("{id}: {name} has cases for it, but Appendix A does not name the file"));
                }
            }
            let named = tested_by.contains(".json") || tested_by.contains("all vector files") || tested_by.contains("harness") || tested_by.contains("vectors (T13)");
            if level.starts_with("MUST") && !named {
                problems.push(format!("{id}: a {level} needs a vector or a harness test"));
            }
        }
        assert!(problems.is_empty(), "requirement coverage:\n{}", problems.join("\n"));
    }
}
