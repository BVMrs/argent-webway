//! Rust side of the card-signature cross-check.
//!
//!   card-sig-canon sign   < cards.jsonl      > signed_rs.jsonl
//!   card-sig-canon verify < candidates.jsonl > verdict_rs.jsonl
//!
//! sign  : JWS (EdDSA) whose payload is JCS(card as served, minus `signatures`): every
//!         served byte is covered. The card is served exactly as generated.
//! verify: rs_raw   = JCS(wire minus `signatures`), the webway §4.2 reading
//!         rs_clean = SDK-style recursive empty removal ("" / null / [] / {}) on the
//!                    raw JSON, no schema, no unknown-field drop, then JCS
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::{json, Map, Value};
use std::io::{self, BufRead, Write};

const SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const PUB: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

fn hex32(s: &str) -> [u8; 32] {
    let mut o = [0u8; 32];
    for i in 0..32 {
        o[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    o
}

fn clean(v: &Value) -> Option<Value> {
    match v {
        Value::Null => None,
        Value::String(s) if s.is_empty() => None,
        Value::Array(a) => {
            let c: Vec<Value> = a.iter().filter_map(clean).collect();
            (!c.is_empty()).then(|| Value::Array(c))
        }
        Value::Object(m) => {
            let c: Map<String, Value> =
                m.iter().filter_map(|(k, v)| clean(v).map(|v| (k.clone(), v))).collect();
            (!c.is_empty()).then(|| Value::Object(c))
        }
        x => Some(x.clone()),
    }
}

fn payload(card: &Value, cleaned: bool) -> Option<String> {
    let mut c = card.clone();
    c.as_object_mut()?.remove("signatures");
    let c = if cleaned { clean(&c).unwrap_or(json!({})) } else { c };
    let bytes = serde_json_canonicalizer::to_vec(&c).ok()?;
    Some(B64.encode(bytes))
}

fn verify(card: &Value, cleaned: bool, vk: &VerifyingKey) -> bool {
    let Some(p) = payload(card, cleaned) else { return false };
    let Some(sigs) = card.get("signatures").and_then(|s| s.as_array()) else { return false };
    sigs.iter().any(|s| {
        let (Some(prot), Some(sig)) = (s["protected"].as_str(), s["signature"].as_str()) else {
            return false;
        };
        let Ok(h) = B64.decode(prot) else { return false };
        let Ok(h): Result<Value, _> = serde_json::from_slice(&h) else { return false };
        if h["alg"] != "EdDSA" {
            return false;
        }
        let Ok(sb) = B64.decode(sig) else { return false };
        let Ok(sig) = Signature::from_slice(&sb) else { return false };
        vk.verify_strict(format!("{prot}.{p}").as_bytes(), &sig).is_ok()
    })
}

fn main() {
    let mode = std::env::args().nth(1).expect("sign|verify");
    let sk = SigningKey::from_bytes(&hex32(SEED));
    let vk = VerifyingKey::from_bytes(&hex32(PUB)).unwrap();
    let out = io::stdout();
    let mut out = io::BufWriter::new(out.lock());
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        if line.is_empty() {
            continue;
        }
        let rec: Value = serde_json::from_str(&line).unwrap();
        if mode == "sign" {
            let mut card = rec["card"].clone();
            let prot = B64.encode(br#"{"alg":"EdDSA","kid":"owner-b","typ":"JOSE"}"#);
            let p = payload(&card, false).unwrap();
            let sig = sk.sign(format!("{prot}.{p}").as_bytes());
            card["signatures"] = json!([{"protected": prot, "signature": B64.encode(sig.to_bytes())}]);
            let r = json!({"id": rec["id"], "signer": "rs", "features": rec["features"],
                           "wire": serde_json::to_string(&card).unwrap()});
            writeln!(out, "{r}").unwrap();
        } else {
            let wire = rec["wire"].as_str().unwrap();
            let (raw, cl) = match serde_json::from_str::<Value>(wire) {
                Ok(card) => (verify(&card, false, &vk), verify(&card, true, &vk)),
                Err(_) => (false, false),
            };
            writeln!(out, "{}", json!({"cid": rec["cid"], "rs_raw": raw, "rs_clean": cl})).unwrap();
        }
    }
}
