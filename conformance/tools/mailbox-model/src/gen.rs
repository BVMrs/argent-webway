//! Generates the vectors that are mechanical: the two outbox tables and the host table, read straight from the
//! markdown of spec/ext/mailbox.md (so the vectors are the spec, and the model is checked against them), and the
//! deposit-signature cases, which need real keys.

use crate::model::deposit_signing_input;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use std::path::Path;

/// One markdown table: header cells and body rows, located by the start of its header line.
fn table(spec: &str, header_start: &str) -> Result<(Vec<String>, Vec<Vec<String>>), String> {
    let mut lines = spec.lines().skip_while(|l| !l.starts_with(header_start));
    let cells =
        |l: &str| -> Vec<String> { l.trim().trim_matches('|').split('|').map(|c| c.trim().to_string()).collect() };
    let header = cells(lines.next().ok_or(format!("table not found: {header_start}"))?);
    lines.next(); // separator
    let rows = lines.take_while(|l| l.starts_with('|')).map(cells).collect();
    Ok((header, rows))
}

/// Backticked names in a cell: "`delivered`, `refused`" -> ["delivered", "refused"].
fn ticked(cell: &str) -> Vec<String> {
    cell.split('`').skip(1).step_by(2).map(str::to_string).collect()
}

/// A transition cell: Some(next state) or None for "illegal".
fn cell_next(cell: &str, from: &str) -> Option<String> {
    if cell.starts_with("illegal") {
        None
    } else if cell.starts_with("unchanged") {
        Some(from.to_string())
    } else {
        Some(ticked(cell).into_iter().next().expect("transition cell names a state"))
    }
}

fn expect(next: &Option<String>) -> Value {
    match next {
        Some(s) => json!({ "result": "accept", "output": { "state": s } }),
        None => json!({ "result": "reject" }),
    }
}

fn write(out: &Path, file: &str, kind: &str, description: &str, spec: &str, cases: &[Value]) -> Result<(), String> {
    let mut text = format!(
        "{{\n  \"$schema\": \"../vector.schema.json\",\n  \"format\": \"webway-vectors/v0\",\n  \"kind\": {},\n  \"description\": {},\n  \"spec\": {},\n  \"cases\": [\n",
        json!(kind),
        json!(description),
        json!(spec)
    );
    for (n, c) in cases.iter().enumerate() {
        text.push_str("    ");
        text.push_str(&serde_json::to_string(c).unwrap());
        text.push_str(if n + 1 < cases.len() { ",\n" } else { "\n" });
    }
    text.push_str("  ]\n}\n");
    std::fs::write(out.join(file), text).map_err(|e| e.to_string())
}

fn outbox(spec: &str) -> Result<Vec<Value>, String> {
    let mut cases = vec![];
    let all_events = [
        "transmit",
        "host-custody",
        "recipient-custody",
        "response",
        "recipient-refusal",
        "retryable-error",
        "expiry",
        "local-cancel",
    ];
    let request_states = ["queued", "pending", "stored", "received", "delivered", "refused", "expired", "withdrawn"];
    for (request, header_start) in [
        (true, "| from \\ event | transmit | host-custody | recipient-custody | response"),
        (false, "| from \\ event | transmit | host-custody | recipient-custody | recipient-refusal"),
    ] {
        let (header, rows) = table(spec, header_start)?;
        let events: Vec<String> = header[1..].to_vec();
        let mut listed = vec![];
        for row in rows {
            for state in ticked(&row[0]) {
                listed.push(state.clone());
                for event in all_events {
                    let next = match events.iter().position(|e| e == event) {
                        Some(col) => cell_next(&row[col + 1], &state),
                        None => None, // event without a column: illegal for this kind of entry
                    };
                    cases.push(outbox_case(request, &state, event, &next));
                }
            }
        }
        // States the table does not have are impossible for that kind of entry.
        for state in request_states.iter().filter(|s| !listed.iter().any(|l| l == *s)) {
            for event in all_events {
                cases.push(outbox_case(request, state, event, &None));
            }
        }
    }
    Ok(cases)
}

fn outbox_case(request: bool, state: &str, event: &str, next: &Option<String>) -> Value {
    let who = if request { "request" } else { "answer" };
    let mut reqs = vec!["MBX-061"];
    if event == "expiry" {
        reqs.push("MBX-062");
    }
    if event == "host-custody" || event == "retryable-error" {
        reqs.push("MBX-070");
    }
    let desc = match next {
        Some(n) => format!("{who} entry: {state} --{event}--> {n}"),
        None => format!("{who} entry: {event} is illegal in {state}"),
    };
    json!({
        "id": format!("{who}-{state}-{event}"),
        "description": desc,
        "requirements": reqs,
        "input": { "request": request, "state": state, "event": event },
        "expect": expect(next),
    })
}

fn host(spec: &str) -> Result<Vec<Value>, String> {
    let (header, rows) = table(spec, "| from \\ event | recipient accepted")?;
    let names = |h: &str| -> &'static str {
        match h {
            "recipient accepted" => "recipient-accepted",
            "recipient duplicate" => "recipient-duplicate",
            "recipient refusal" => "recipient-refusal",
            "retryable error" => "retryable-error",
            "`now > exp`" => "exp-passed",
            "re-deposit" => "re-deposit",
            other => panic!("unknown host table column {other}"),
        }
    };
    let mut cases = vec![];
    for row in rows {
        for state in ticked(&row[0]) {
            for (col, h) in header[1..].iter().enumerate() {
                let event = names(h);
                let next = cell_next(&row[col + 1], &state);
                let mut reqs = vec!["MBX-050"];
                if event == "exp-passed" {
                    reqs.push("MBX-053");
                }
                let desc = match &next {
                    Some(n) => format!("held record: {state} --{event}--> {n}"),
                    None => format!("held record: {event} is illegal in {state}"),
                };
                cases.push(json!({
                    "id": format!("{state}-{event}"),
                    "description": desc,
                    "requirements": reqs,
                    "input": { "state": state, "event": event },
                    "expect": expect(&next),
                }));
            }
        }
    }
    Ok(cases)
}

fn key(label: &str) -> SigningKey {
    SigningKey::from_bytes(blake3::hash(label.as_bytes()).as_bytes())
}

fn deposit_sig() -> Vec<Value> {
    let k1 = key("mailbox-model test deposit key 1");
    let k2 = key("mailbox-model test deposit key 2");
    let pk1 = B64.encode(k1.verifying_key().as_bytes());
    let pk2 = B64.encode(k2.verifying_key().as_bytes());
    let d1 = *blake3::hash(b"mailbox-model example signing input 1").as_bytes();
    let d2 = *blake3::hash(b"mailbox-model example signing input 2").as_bytes();
    let sign = |k: &SigningKey, m: &[u8]| B64.encode(k.sign(m).to_bytes());
    let good = sign(&k1, &deposit_signing_input(&d1));
    // S + L: same signature, non-canonical scalar (rejected by verify_strict).
    let mut malleable = k1.sign(&deposit_signing_input(&d1)).to_bytes();
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let mut carry = 0u16;
    for n in 0..32 {
        let sum = malleable[32 + n] as u16 + L[n] as u16 + carry;
        malleable[32 + n] = sum as u8;
        carry = sum >> 8;
    }
    let mut identity = [0u8; 32];
    identity[0] = 1; // small-order point (the identity)
    let mut prefixed_other = b"webway-mailbox-deposit/1\0".to_vec();
    prefixed_other.extend_from_slice(&d1);
    let accept = |m: &[u8]| json!({ "result": "accept", "output": { "signingInput": hex::encode(m) } });
    let deny = json!({ "result": "reject", "error": "CapabilityDenied" });
    let case = |id: &str, desc: &str, key: &str, digest: &[u8; 32], sig: String, expect: Value| {
        json!({
            "id": id, "description": desc, "requirements": ["MBX-021"],
            "input": { "depositKey": key, "headerDigest": hex::encode(digest), "sig": sig },
            "expect": expect,
        })
    };
    vec![
        case(
            "valid",
            "Signature by the token's deposit key over prefix and header digest",
            &pk1,
            &d1,
            good.clone(),
            accept(&deposit_signing_input(&d1)),
        ),
        case(
            "valid-second-key",
            "Another key, another digest",
            &pk2,
            &d2,
            sign(&k2, &deposit_signing_input(&d2)),
            accept(&deposit_signing_input(&d2)),
        ),
        case("wrong-key", "Signed by a key other than deposit_key", &pk2, &d1, good.clone(), deny.clone()),
        case(
            "other-envelope",
            "Signature for another envelope's digest (moved authorisation)",
            &pk1,
            &d2,
            good.clone(),
            deny.clone(),
        ),
        case(
            "no-prefix",
            "Signature over the bare digest, without the domain prefix",
            &pk1,
            &d1,
            sign(&k1, &d1),
            deny.clone(),
        ),
        case(
            "wrong-prefix-version",
            "Signature under a different prefix (webway-mailbox-deposit/1)",
            &pk1,
            &d1,
            sign(&k1, &prefixed_other),
            deny.clone(),
        ),
        case(
            "non-canonical-s",
            "S + L, accepted by lax verifiers, rejected by strict verification",
            &pk1,
            &d1,
            B64.encode(malleable),
            deny.clone(),
        ),
        case(
            "small-order-key",
            "Deposit key is a small-order point",
            &B64.encode(identity),
            &d1,
            good.clone(),
            deny.clone(),
        ),
        case(
            "short-key",
            "Deposit key of 31 bytes",
            &B64.encode(&k1.verifying_key().as_bytes()[..31]),
            &d1,
            good.clone(),
            deny.clone(),
        ),
        case("padded-sig", "Signature in padded base64url", &pk1, &d1, format!("{good}=="), deny.clone()),
        case("truncated-sig", "Signature of 63 bytes", &pk1, &d1, B64.encode(&B64.decode(&good).unwrap()[..63]), deny),
    ]
}

pub fn generate(spec_path: &Path, out: &Path) -> Result<(), String> {
    let spec = std::fs::read_to_string(spec_path).map_err(|e| e.to_string())?;
    write(
        out,
        "outbox-step.json",
        "mailbox/outbox-step",
        "Outbox entry state machine. Input {\"request\": bool, \"state\", \"event\"}. Accept with {\"state\": next}, or reject an illegal event. Generated from the tables of spec §9.2 by conformance/tools/mailbox-model.",
        "ext/mailbox.md#92-entry-state-machine",
        &outbox(&spec)?,
    )?;
    write(
        out,
        "host-step.json",
        "mailbox/host-step",
        "Mailbox host held-record state machine. Input {\"state\", \"event\"}. Accept with {\"state\": next}, or reject an illegal event. Generated from the table of spec §8 by conformance/tools/mailbox-model.",
        "ext/mailbox.md#8-mailbox-host-held-envelopes",
        &host(&spec)?,
    )?;
    write(
        out,
        "deposit-sig.json",
        "mailbox/deposit-sig",
        "Deposit signature (spec §5.1). Input {\"depositKey\": base64url, \"headerDigest\": hex, \"sig\": base64url}. Accept with {\"signingInput\": hex of the signed bytes}; reject as CapabilityDenied. Test keys are BLAKE3 of their labels in conformance/tools/mailbox-model/src/gen.rs and are test-only.",
        "ext/mailbox.md#51-deposit-signature",
        &deposit_sig(),
    )?;
    Ok(())
}
