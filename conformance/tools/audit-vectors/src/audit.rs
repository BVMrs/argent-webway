//! A reference verifier for audit/v0 (spec/ext/audit.md), plus the signing helpers the generator needs.
//! Every function returns the vector output on success, or the error name and reason of §12.2.

use crate::merkle::{self, H};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde_json::{json, Map, Value};

pub const ENTRY_V: &str = "webway-audit-entry/0";
pub const CHECKPOINT_V: &str = "webway-checkpoint/0";
pub const RECEIPT_V: &str = "webway-receipt/0";
pub const EVIDENCE_V: &str = "webway-audit-evidence/0";
pub const ENVELOPE_V: &str = "webway-envelope/0";
pub const MAX_ENTRY_BYTES: usize = 1_179_648;
pub const MAX_PROOF_HASHES: usize = 128;
pub const MAX_SAFE: u64 = (1u64 << 53) - 1;

#[derive(Debug, Clone, PartialEq)]
pub struct Fail {
    pub name: &'static str,
    pub reason: &'static str,
}
pub type R<T> = Result<T, Fail>;
fn fail<T>(name: &'static str, reason: &'static str) -> R<T> {
    Err(Fail { name, reason })
}

// ---------- encodings ----------

/// RFC 8785 JCS, via `serde_json_canonicalizer`.
pub fn jcs(v: &Value) -> Vec<u8> {
    serde_json_canonicalizer::to_vec(v).expect("JCS of a serde_json value")
}

/// Lowercase, unpadded RFC 4648 base32 (`data-encoding`). Decoding is strict: wrong case, padding or
/// non-zero trailing bits are errors.
static B32: std::sync::LazyLock<data_encoding::Encoding> = std::sync::LazyLock::new(|| {
    let mut s = data_encoding::Specification::new();
    s.symbols.push_str("abcdefghijklmnopqrstuvwxyz234567");
    s.encoding().unwrap()
});

pub fn base32(b: &[u8]) -> String {
    B32.encode(b)
}

/// A 32-byte key in base32 (52 characters, zero trailing bits).
fn base32_key(s: &str) -> Option<[u8; 32]> {
    if s.len() != 52 {
        return None;
    }
    B32.decode(s.as_bytes()).ok()?.try_into().ok()
}

pub fn node_id(k: &VerifyingKey) -> String {
    format!("wwn:{}", base32(k.as_bytes()))
}
pub fn agent_id(k: &VerifyingKey) -> String {
    format!("wwa:{}", base32(k.as_bytes()))
}
pub fn hash_str(h: &H) -> String {
    format!("blake3:{}", hex::encode(h))
}

fn parse_hash(v: &Value) -> Option<H> {
    let s = v.as_str()?.strip_prefix("blake3:")?;
    if s.len() != 64
        || !s
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return None;
    }
    hex::decode(s).ok()?.try_into().ok()
}

fn parse_id(v: &Value, prefix: &str) -> Option<[u8; 32]> {
    base32_key(v.as_str()?.strip_prefix(prefix)?)
}

fn is_agent_or_owner(s: &str) -> bool {
    // did:key forms are checked by capability/v0; here only the shape is checked.
    parse_id(&json!(s), "wwa:").is_some() || (s.starts_with("did:key:z") && s.len() > 9)
}

fn safe_int(v: &Value) -> Option<u64> {
    let n = v.as_u64()?;
    (n <= MAX_SAFE).then_some(n)
}

/// envelope/v0 §3.2 timestamp: YYYY-MM-DDTHH:MM:SS[.f{3,6,9}]Z, with no leap second. That profile is checked
/// here. Calendar validity and the instant come from `time`'s RFC 3339 parser. Returns Unix nanoseconds.
pub fn parse_time(v: &Value) -> Option<i128> {
    let s = v.as_str()?;
    let b = s.as_bytes();
    let shape = |i: usize, c: u8| {
        if c == b'#' {
            b[i].is_ascii_digit()
        } else {
            b[i] == c
        }
    };
    let frac = b.len().checked_sub(20)?;
    if !b"####-##-##T##:##:##"
        .iter()
        .enumerate()
        .all(|(i, &c)| shape(i, c))
        || *b.last()? != b'Z'
        || ![0, 4, 7, 10].contains(&frac)
        || (frac > 0 && (b[19] != b'.' || !b[20..b.len() - 1].iter().all(u8::is_ascii_digit)))
        || &b[17..19] == b"60"
    {
        return None;
    }
    let t = time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()?;
    Some(t.unix_timestamp_nanos())
}

/// A lowercase, hyphenated RFC 9562 UUID of version 7 (`uuid`).
fn is_uuid7(v: &Value) -> bool {
    let Some(s) = v.as_str() else { return false };
    let Ok(u) = uuid::Uuid::try_parse(s) else {
        return false;
    };
    u.hyphenated().to_string() == s
        && u.get_version_num() == 7
        && u.get_variant() == uuid::Variant::RFC4122
}

fn hashes(v: &Value) -> Option<Vec<H>> {
    v.as_array()?.iter().map(parse_hash).collect()
}

// ---------- signatures ----------

pub fn signing_input(v: &str, obj: &Map<String, Value>) -> Vec<u8> {
    let mut o = obj.clone();
    o.remove("sig");
    let mut out = v.as_bytes().to_vec();
    out.push(0);
    out.extend(jcs(&Value::Object(o)));
    out
}

pub fn sign_obj(key: &SigningKey, v: &str, obj: &mut Map<String, Value>) {
    let sig = key.sign(&signing_input(v, obj));
    obj.insert("sig".into(), json!(URL_SAFE_NO_PAD.encode(sig.to_bytes())));
}

/// Strict Ed25519 (envelope/v0 ENV-210, ENV-211). Err(reason).
fn verify_strict(key: &[u8; 32], msg: &[u8], sig: &Value) -> Result<(), &'static str> {
    let sig_s = sig.as_str().ok_or("malformed-field")?;
    if sig_s.len() != 86 {
        return Err("malformed-field");
    }
    let sig_b = URL_SAFE_NO_PAD
        .decode(sig_s)
        .map_err(|_| "malformed-field")?;
    let sig_b: [u8; 64] = sig_b.try_into().map_err(|_| "malformed-field")?;
    // canonical encoding of a point that is not of small order (ENV-210)
    let point = curve25519_dalek::edwards::CompressedEdwardsY(*key)
        .decompress()
        .ok_or("weak-key")?;
    if point.compress().to_bytes() != *key || point.is_small_order() {
        return Err("weak-key");
    }
    let vk = VerifyingKey::from_bytes(key).map_err(|_| "weak-key")?;
    let sig = Signature::from_bytes(&sig_b);
    vk.verify_strict(msg, &sig).map_err(|_| "bad-signature")
}

/// The envelope signing input and header digest of a stub (envelope without body).
pub fn envelope_signing_input(stub: &Map<String, Value>) -> Vec<u8> {
    let mut o = stub.clone();
    o.remove("body");
    signing_input(ENVELOPE_V, &o)
}
pub fn header_digest(stub: &Map<String, Value>) -> String {
    hash_str(blake3::hash(&envelope_signing_input(stub)).as_bytes())
}

fn verify_stub_sig(stub: &Map<String, Value>) -> bool {
    let Some(from) = stub.get("from").and_then(|f| parse_id(f, "wwa:")) else {
        return false;
    };
    let Some(sig) = stub.get("sig") else {
        return false;
    };
    verify_strict(&from, &envelope_signing_input(stub), sig).is_ok()
}

// ---------- entries ----------

pub fn entry_hash(e: &Value) -> H {
    merkle::leaf(&jcs(e))
}

/// AUD-001, AUD-002, AUD-003, AUD-020, AUD-910. Returns the entry hash.
pub fn check_entry(e: &Value) -> R<H> {
    const N: &str = "EntryInvalid";
    let Some(o) = e.as_object() else {
        return fail(N, "malformed-field");
    };
    if !numbers_ok(e) {
        return fail(N, "not-ijson");
    }
    for k in ["v", "log", "epoch", "index", "time", "type", "data"] {
        if !o.contains_key(k) {
            return fail(N, "missing-field");
        }
    }
    if o["v"] != json!(ENTRY_V) {
        return fail(N, "bad-version");
    }
    if parse_id(&o["log"], "wwn:").is_none()
        || safe_int(&o["epoch"]).is_none()
        || parse_time(&o["time"]).is_none()
    {
        return fail(N, "malformed-field");
    }
    let Some(index) = safe_int(&o["index"]) else {
        return fail(N, "malformed-field");
    };
    match (index, o.get("prev")) {
        (0, Some(_)) => return fail(N, "malformed-field"),
        (0, None) => {}
        (_, None) => return fail(N, "missing-field"),
        (_, Some(p)) => {
            if parse_hash(p).is_none() {
                return fail(N, "malformed-field");
            }
        }
    }
    let ty = o["type"].as_str().unwrap_or("");
    if !valid_type(ty) || !o["data"].is_object() {
        return fail(N, "malformed-field");
    }
    if let Some(p) = o.get("parties") {
        let ok = p
            .as_array()
            .is_some_and(|a| a.iter().all(|x| x.as_str().is_some_and(is_agent_or_owner)));
        if !ok {
            return fail(N, "malformed-field");
        }
    }
    if jcs(e).len() > MAX_ENTRY_BYTES {
        return fail(N, "too-large");
    }
    if ty == "envelope.sent" || ty == "envelope.received" {
        if let Some(stub) = o["data"].get("stub") {
            let Some(stub) = stub.as_object() else {
                return fail(N, "malformed-field");
            };
            if o["data"].get("hd") != Some(&json!(header_digest(stub))) {
                return fail(N, "hd-mismatch");
            }
            let want = json!([stub.get("from"), stub.get("to")]);
            if o.get("parties") != Some(&want) {
                return fail(N, "parties-mismatch");
            }
        }
    }
    Ok(entry_hash(e))
}

/// AUD-001: every number is an integer of magnitude at most 2^53 - 1.
fn numbers_ok(v: &Value) -> bool {
    match v {
        Value::Number(n) => {
            n.as_u64().is_some_and(|x| x <= MAX_SAFE)
                || n.as_i64().is_some_and(|x| x.unsigned_abs() <= MAX_SAFE)
        }
        Value::Array(a) => a.iter().all(numbers_ok),
        Value::Object(m) => m.values().all(numbers_ok),
        _ => true,
    }
}

fn valid_type(t: &str) -> bool {
    let mut parts = t.split('.');
    let ok = |s: Option<&str>| {
        s.is_some_and(|s| {
            let b = s.as_bytes();
            !b.is_empty()
                && b[0].is_ascii_lowercase()
                && b.iter()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        })
    };
    ok(parts.next()) && ok(parts.next()) && parts.next().is_none()
}

/// audit/chain: AUD-100, AUD-101, AUD-102, AUD-110.
pub fn verify_chain(entries: &[Value]) -> R<Value> {
    const N: &str = "ChainBroken";
    if entries.is_empty() {
        return fail(N, "no-genesis");
    }
    let mut leaves = vec![];
    let mut last_time = None;
    for (i, e) in entries.iter().enumerate() {
        let h = check_entry(e)?;
        if i == 0 && e["type"] != json!("log.genesis") {
            return fail(N, "no-genesis");
        }
        if e["index"].as_u64() != Some(i as u64) {
            return fail(N, "index-gap");
        }
        if e["log"] != entries[0]["log"] {
            return fail(N, "log-mismatch");
        }
        if e["epoch"] != entries[0]["epoch"] {
            return fail(N, "epoch-mismatch");
        }
        if i > 0 && parse_hash(&e["prev"]) != Some(leaves[i - 1]) {
            return fail(N, "prev-mismatch");
        }
        let t = parse_time(&e["time"]);
        if last_time.is_some_and(|lt| t < Some(lt)) {
            return fail(N, "time-decreased");
        }
        last_time = t;
        leaves.push(h);
    }
    Ok(json!({
        "log": entries[0]["log"], "epoch": entries[0]["epoch"], "size": entries.len(),
        "root": hash_str(&merkle::root(&merkle::tree(entries.iter().map(jcs)))), "head": hash_str(leaves.last().unwrap()),
    }))
}

// ---------- proofs ----------

fn proof_list(v: &Value) -> R<Vec<H>> {
    let p = hashes(v).ok_or(Fail {
        name: "ProofInvalid",
        reason: "malformed-proof",
    })?;
    if p.len() > MAX_PROOF_HASHES {
        return fail("ProofInvalid", "wrong-length");
    }
    Ok(p)
}

/// audit/inclusion: AUD-120.
pub fn verify_inclusion(
    index: &Value,
    size: &Value,
    leaf: &Value,
    root: &Value,
    proof: &Value,
) -> R<()> {
    let (Some(i), Some(n)) = (safe_int(index), safe_int(size)) else {
        return fail("ProofInvalid", "bad-range");
    };
    if n < 1 || i >= n {
        return fail("ProofInvalid", "bad-range");
    }
    let (Some(l), Some(r)) = (parse_hash(leaf), parse_hash(root)) else {
        return fail("ProofInvalid", "malformed-proof");
    };
    let p = proof_list(proof)?;
    if merkle::verify_inclusion(i, n, &l, &p, &r) {
        Ok(())
    } else {
        fail("ProofInvalid", "root-mismatch")
    }
}

/// audit/consistency: AUD-120, AUD-121.
pub fn verify_consistency(n1: &Value, r1: &Value, n2: &Value, r2: &Value, proof: &Value) -> R<()> {
    let (Some(a), Some(b)) = (safe_int(n1), safe_int(n2)) else {
        return fail("ProofInvalid", "bad-range");
    };
    if a < 1 || a > b {
        return fail("ProofInvalid", "bad-range");
    }
    let (Some(x), Some(y)) = (parse_hash(r1), parse_hash(r2)) else {
        return fail("ProofInvalid", "malformed-proof");
    };
    let p = proof_list(proof)?;
    if merkle::verify_consistency(a, b, &x, &y, &p) {
        Ok(())
    } else {
        fail("ProofInvalid", "root-mismatch")
    }
}

// ---------- commitments ----------

pub struct Commitment {
    pub log: Value,
    pub epoch: u64,
    pub size: u64,
    pub root: H,
}

impl Commitment {
    pub fn out(&self) -> Value {
        json!({"log": self.log, "epoch": self.epoch, "size": self.size, "root": hash_str(&self.root)})
    }
}

fn check_signed(c: &Value, v: &str, name: &'static str, required: &[&str]) -> R<()> {
    let Some(o) = c.as_object() else {
        return fail(name, "malformed-field");
    };
    for k in required
        .iter()
        .chain(&["v", "log", "epoch", "root", "time", "sig"])
    {
        if !o.contains_key(*k) {
            return fail(name, "missing-field");
        }
    }
    if o["v"] != json!(v) {
        return fail(name, "bad-version");
    }
    let Some(key) = parse_id(&o["log"], "wwn:") else {
        return fail(name, "malformed-field");
    };
    if safe_int(&o["epoch"]).is_none()
        || parse_hash(&o["root"]).is_none()
        || parse_time(&o["time"]).is_none()
    {
        return fail(name, "malformed-field");
    }
    verify_strict(&key, &signing_input(v, o), &o["sig"]).map_err(|r| Fail { name, reason: r })
}

/// audit/checkpoint: AUD-200, AUD-201, AUD-202, AUD-910.
pub fn verify_checkpoint(c: &Value) -> R<Commitment> {
    const N: &str = "CheckpointInvalid";
    check_signed(c, CHECKPOINT_V, N, &["size"])?;
    match safe_int(&c["size"]) {
        Some(s) if s >= 1 => Ok(Commitment {
            log: c["log"].clone(),
            epoch: c["epoch"].as_u64().unwrap(),
            size: s,
            root: parse_hash(&c["root"]).unwrap(),
        }),
        _ => fail(N, "malformed-field"),
    }
}

/// audit/receipt: AUD-200, AUD-201, AUD-202, AUD-301, AUD-910.
pub fn verify_receipt(r: &Value, envelope: Option<&Value>) -> R<Commitment> {
    const N: &str = "ReceiptInvalid";
    check_signed(
        r,
        RECEIPT_V,
        N,
        &["index", "entry", "env", "id", "from", "to"],
    )?;
    let Some(index) = safe_int(&r["index"]).filter(|i| *i < MAX_SAFE) else {
        return fail(N, "malformed-field");
    };
    if parse_hash(&r["entry"]).is_none()
        || parse_hash(&r["env"]).is_none()
        || !is_uuid7(&r["id"])
        || parse_id(&r["from"], "wwa:").is_none()
        || parse_id(&r["to"], "wwa:").is_none()
    {
        return fail(N, "malformed-field");
    }
    if let Some(env) = envelope {
        let Some(eo) = env.as_object() else {
            return fail(N, "envelope-mismatch");
        };
        if r["env"] != json!(header_digest(eo))
            || Some(&r["id"]) != eo.get("id")
            || Some(&r["from"]) != eo.get("from")
            || Some(&r["to"]) != eo.get("to")
        {
            return fail(N, "envelope-mismatch");
        }
    }
    Ok(Commitment {
        log: r["log"].clone(),
        epoch: r["epoch"].as_u64().unwrap(),
        size: index + 1,
        root: parse_hash(&r["root"]).unwrap(),
    })
}

fn commitment_unverified(c: &Value) -> Option<Commitment> {
    let size = if c["v"] == json!(RECEIPT_V) {
        safe_int(&c["index"])? + 1
    } else {
        safe_int(&c["size"])?
    };
    Some(Commitment {
        log: c["log"].clone(),
        epoch: safe_int(&c["epoch"])?,
        size,
        root: parse_hash(&c["root"])?,
    })
}

/// audit/compare: AUD-211, AUD-703, AUD-710.
pub fn compare(a: &Value, b: &Value, proof: &Value) -> R<Value> {
    let (Some(x), Some(y)) = (commitment_unverified(a), commitment_unverified(b)) else {
        return fail("ProofInvalid", "malformed-proof");
    };
    if x.log != y.log || x.epoch != y.epoch {
        return Ok(json!({"relation": "unrelated"}));
    }
    if x.size == y.size {
        return if x.root == y.root {
            Ok(json!({"relation": "equal"}))
        } else {
            fail("LogInconsistent", "fork")
        };
    }
    let (s, l) = if x.size < y.size { (&x, &y) } else { (&y, &x) };
    verify_consistency(
        &json!(s.size),
        &json!(hash_str(&s.root)),
        &json!(l.size),
        &json!(hash_str(&l.root)),
        proof,
    )?;
    Ok(json!({"relation": "consistent"}))
}

// ---------- evidence ----------

/// audit/evidence: AUD-020, AUD-302, AUD-800, AUD-801, AUD-802, AUD-910.
pub fn verify_evidence(b: &Value) -> R<Value> {
    const N: &str = "EvidenceInvalid";
    let Some(o) = b.as_object() else {
        return fail(N, "missing-field");
    };
    if !o.contains_key("v") || !o.contains_key("checkpoint") || !o.contains_key("entries") {
        return fail(N, "missing-field");
    }
    if o["v"] != json!(EVIDENCE_V) {
        return fail(N, "bad-version");
    }
    let Some(entries) = o["entries"].as_array().filter(|a| !a.is_empty()) else {
        return fail(N, "missing-field");
    };
    let cp = verify_checkpoint(&o["checkpoint"])?;
    let mut by_index = std::collections::BTreeMap::new();
    let mut body_hashes = std::collections::BTreeSet::new();
    for item in entries {
        let (Some(e), Some(p)) = (item.get("entry"), item.get("proof")) else {
            return fail(N, "missing-field");
        };
        let h = check_entry(e)?;
        let idx = e["index"].as_u64().unwrap();
        if e["log"] != cp.log || e["epoch"].as_u64() != Some(cp.epoch) || idx >= cp.size {
            return fail(N, "foreign-item");
        }
        verify_inclusion(
            &json!(idx),
            &json!(cp.size),
            &json!(hash_str(&h)),
            &json!(hash_str(&cp.root)),
            p,
        )?;
        let ty = e["type"].as_str().unwrap();
        let accepted = ty == "envelope.sent"
            || (ty == "envelope.received"
                && matches!(
                    e["data"]["outcome"].as_str(),
                    Some("accepted" | "duplicate")
                ));
        let stub = e["data"].get("stub").and_then(Value::as_object);
        if accepted && stub.is_none() {
            return fail(N, "missing-stub");
        }
        if let Some(stub) = stub {
            if accepted && !verify_stub_sig(stub) {
                return fail(N, "stub-signature");
            }
            if let Some(bh) = stub.get("body_hash").and_then(Value::as_str) {
                body_hashes.insert(bh.to_string());
            }
        }
        by_index.insert(idx, (e.clone(), h));
    }
    if let Some(rs) = o.get("receipts") {
        let Some(rs) = rs.as_array() else {
            return fail(N, "missing-field");
        };
        for item in rs {
            let (Some(r), Some(p)) = (item.get("receipt"), item.get("proof")) else {
                return fail(N, "missing-field");
            };
            let c = verify_receipt(r, None)?;
            if c.log != cp.log || c.epoch != cp.epoch || c.size > cp.size {
                return fail(N, "foreign-item");
            }
            verify_consistency(
                &json!(c.size),
                &json!(hash_str(&c.root)),
                &json!(cp.size),
                &json!(hash_str(&cp.root)),
                p,
            )?;
            if let Some((e, h)) = by_index.get(&(c.size - 1)) {
                // AUD-302
                if r["entry"] != json!(hash_str(h))
                    || e["type"] != json!("envelope.received")
                    || e["data"]["hd"] != r["env"]
                    || e["data"]["stub"]["id"] != r["id"]
                    || e["data"]["stub"]["from"] != r["from"]
                    || e["data"]["stub"]["to"] != r["to"]
                    || e["time"] != r["time"]
                {
                    return fail("ReceiptInvalid", "entry-mismatch");
                }
            }
        }
    }
    if let Some(bodies) = o.get("bodies") {
        let Some(bodies) = bodies.as_object() else {
            return fail(N, "missing-field");
        };
        for (k, body) in bodies {
            if !body_hashes.contains(k) {
                return fail(N, "foreign-item");
            }
            if *k != hash_str(blake3::hash(&jcs(body)).as_bytes()) {
                return fail(N, "body-mismatch");
            }
        }
    }
    Ok(json!({"entries": entries.len()}))
}

/// Pin the library behaviour audit/v0 depends on, so a dependency update that changes it fails here.
#[cfg(test)]
mod encoding_tests {
    use super::*;

    #[test]
    fn jcs_sorts_and_escapes() {
        let v = json!({"b": 1, "a": [true, null, "x\n\u{1}é"], "\u{e9}": 0, "A": -3});
        assert_eq!(
            String::from_utf8(jcs(&v)).unwrap(),
            "{\"A\":-3,\"a\":[true,null,\"x\\n\\u0001é\"],\"b\":1,\"é\":0}"
        );
    }

    #[test]
    fn jcs_utf16_order() {
        // U+1F600 (surrogates D83D DE00) sorts before U+FF61 in UTF-16, after it in UTF-8/code points.
        let v = json!({"\u{ff61}": 1, "\u{1f600}": 2});
        assert_eq!(
            String::from_utf8(jcs(&v)).unwrap(),
            "{\"\u{1f600}\":2,\"\u{ff61}\":1}"
        );
    }

    #[test]
    fn base32_strict() {
        let k = [0xffu8; 32];
        let s = base32(&k);
        assert_eq!(s.len(), 52);
        assert_eq!(base32_key(&s), Some(k));
        assert_eq!(base32_key(&s.to_uppercase()), None);
        // last character carries 2 data bits; '7' sets the 3 trailing bits too
        assert_eq!(base32_key(&format!("{}7", &s[..51])), None);
    }

    #[test]
    fn time_profile() {
        for ok in [
            "2026-11-07T10:00:00Z",
            "2024-02-29T23:59:59.123Z",
            "2026-11-07T10:00:00.123456789Z",
        ] {
            assert!(parse_time(&json!(ok)).is_some(), "{ok}");
        }
        for bad in [
            "2026-11-07T10:00:00+00:00",
            "2026-11-07t10:00:00Z",
            "2026-11-07T10:00:00.12Z",
            "2026-11-07T23:59:60Z",
            "2025-02-29T10:00:00Z",
            "2026-13-01T10:00:00Z",
            "2026-11-07T24:00:00Z",
        ] {
            assert!(parse_time(&json!(bad)).is_none(), "{bad}");
        }
        assert!(
            parse_time(&json!("2026-11-07T10:00:00Z"))
                < parse_time(&json!("2026-11-07T10:00:00.001Z"))
        );
    }

    #[test]
    fn uuid7_shape() {
        assert!(is_uuid7(&json!("0190b5a6-7e4c-7abc-8def-0123456789ab")));
        assert!(!is_uuid7(&json!("0190B5A6-7E4C-7ABC-8DEF-0123456789AB")));
        assert!(!is_uuid7(&json!("0190b5a67e4c7abc8def0123456789ab")));
        assert!(!is_uuid7(&json!("0190b5a6-7e4c-4abc-8def-0123456789ab")));
        assert!(!is_uuid7(&json!("0190b5a6-7e4c-7abc-cdef-0123456789ab")));
    }
}
