//! The mailbox/v0 decision functions, one per vector kind (spec/ext/mailbox.md §14).
//! Written from the spec text, independently of the vectors.

use crate::time::{self, MS, SECOND};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use serde_json::{json, Map, Value};

pub const SKEW: i128 = 300 * SECOND;
pub const MAX_TTL: i128 = 7 * 86_400 * SECOND;
pub const RETRY_BASE_MS: i128 = 1_000;
pub const RETRY_MAX_MS: i128 = 300_000;
pub const MAX_HOSTS: usize = 4;
pub const LEASE_MAX: i128 = 30 * 86_400 * SECOND;
pub const MAX_DEPOSIT_TTL: i128 = 30 * 86_400 * SECOND;
pub const DEPOSIT_SIG_PREFIX: &[u8] = b"webway-mailbox-deposit/0\0";

#[derive(Debug, PartialEq)]
pub enum Outcome {
    Accept(Option<Value>),
    /// A rejection with the spec's error name, or `None` where the kind fixes no name (illegal transitions).
    Reject(Option<String>),
    Unsupported,
}

fn rej(e: &str) -> Outcome {
    Outcome::Reject(Some(e.to_string()))
}

fn ok(v: Value) -> Outcome {
    Outcome::Accept(Some(v))
}

/// Malformed vector input: a bug in the vector, reported as an unnamed rejection so that it fails any accept case.
fn bad() -> Outcome {
    Outcome::Reject(Some("MalformedVectorInput".into()))
}

pub fn run(kind: &str, input: &Value) -> Outcome {
    let r = match kind {
        "mailbox/card" => card(input),
        "mailbox/token" => token(input),
        "mailbox/deposit-sig" => deposit_sig(input),
        "mailbox/admit" => admit(input),
        "mailbox/register" => register(input),
        "mailbox/host-step" => host_step(input),
        "mailbox/outbox-step" => outbox_step(input),
        "mailbox/path" => path(input),
        "mailbox/backoff" => backoff(input),
        "mailbox/order" => order(input),
        "mailbox/timing" => timing(input),
        "mailbox/reconnect" => reconnect(input),
        _ => return Outcome::Unsupported,
    };
    r.unwrap_or_else(bad)
}

fn ts(v: &Value, k: &str) -> Option<i128> {
    time::parse(v.get(k)?.as_str()?)
}
fn s<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k)?.as_str()
}
fn b(v: &Value, k: &str) -> Option<bool> {
    v.get(k)?.as_bool()
}
fn i(v: &Value, k: &str) -> Option<i64> {
    v.get(k)?.as_i64()
}

// ---------- identifiers (ext/capability.md §3) ----------

/// `prefix` + 52 lowercase base32 characters encoding 32 bytes, trailing 4 bits zero.
fn is_b32_key_id(id: &str, prefix: &str) -> bool {
    let Some(rest) = id.strip_prefix(prefix) else { return false };
    if rest.len() != 52 || !rest.bytes().all(|c| c.is_ascii_lowercase() || (b'2'..=b'7').contains(&c)) {
        return false;
    }
    let last = rest.as_bytes()[51];
    let v = if last.is_ascii_lowercase() { last - b'a' } else { last - b'2' + 26 };
    v & 0x0f == 0
}

fn base58_decode(s: &str) -> Option<Vec<u8>> {
    const ALPHA: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut out: Vec<u8> = Vec::new();
    for c in s.bytes() {
        let mut carry = ALPHA.iter().position(|&a| a == c)? as u32;
        for byte in out.iter_mut().rev() {
            carry += (*byte as u32) * 58;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            out.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let zeros = s.bytes().take_while(|&c| c == b'1').count();
    let mut v = vec![0u8; zeros];
    v.extend(out);
    Some(v)
}

fn is_did_key(id: &str) -> bool {
    let Some(rest) = id.strip_prefix("did:key:z") else { return false };
    matches!(base58_decode(rest), Some(v) if v.len() == 34 && v[0] == 0xed && v[1] == 0x01)
}

/// base64url without padding, canonical (re-encodes to the same string), `len` bytes.
fn b64_exact(s: &str, len: usize) -> Option<Vec<u8>> {
    let v = B64.decode(s).ok()?;
    (v.len() == len && B64.encode(&v) == s).then_some(v)
}

// ---------- §3.1 card ----------

fn card(input: &Value) -> Option<Outcome> {
    // MBX-001 fixes no error name: the node just does not use the agent's hosts.
    let invalid = || Some(Outcome::Reject(None));
    let Some(params) = input.get("params").and_then(Value::as_object) else { return invalid() };
    match params.get("depositKey").and_then(Value::as_str) {
        Some(k) if b64_exact(k, 32).is_some() => {}
        _ => return invalid(),
    }
    let Some(hosts) = params.get("hosts").and_then(Value::as_array) else { return invalid() };
    if hosts.len() > MAX_HOSTS {
        return invalid();
    }
    for h in hosts {
        let okh = h.is_object()
            && s(h, "agent").is_some_and(|a| is_b32_key_id(a, "wwa:"))
            && s(h, "node").is_some_and(|n| is_b32_key_id(n, "wwn:"))
            && s(h, "owner").is_some_and(is_did_key);
        if !okh {
            return invalid();
        }
    }
    Some(ok(json!({ "hosts": hosts.len() })))
}

// ---------- §4.2 token ----------

fn scope_covers(pattern: &str, right: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => right.starts_with(prefix),
        None => pattern == right,
    }
}

fn token(input: &Value) -> Option<Outcome> {
    let facts: &Map<String, Value> = input.get("facts")?.as_object()?;
    let invalid = || Some(rej("CapabilityInvalid"));
    if i(input, "blocks")? != 1 {
        return invalid();
    }
    // Returns the single term tuple of a fact that must occur exactly once.
    let one = |name: &str| -> Option<&Vec<Value>> {
        let occ = facts.get(name)?.as_array()?;
        if occ.len() != 1 {
            return None;
        }
        occ[0].as_array()
    };
    let strs = |name: &str, arity: usize| -> Option<Vec<String>> {
        let t = one(name)?;
        if t.len() != arity {
            return None;
        }
        t.iter().map(|x| x.as_str().map(str::to_string)).collect()
    };
    let Some(webway) = strs("webway", 2) else { return invalid() };
    if webway != ["mailbox/v0", "deposit"] {
        return invalid();
    }
    let (Some(issuer), Some(owner), Some(right), Some(dkey)) =
        (strs("issuer", 1), strs("owner", 1), strs("right", 1), strs("deposit_key", 1))
    else {
        return invalid();
    };
    let (Some(issued), Some(expires)) = (strs("issued", 1), strs("expires", 1)) else { return invalid() };
    let (Some(issued), Some(expires)) = (time::parse(&issued[0]), time::parse(&expires[0])) else {
        return invalid();
    };
    let mut quota = Map::new();
    for (fact, key) in [("quota_envelopes", "envelopes"), ("quota_bytes", "bytes")] {
        match one(fact).map(|t| t.as_slice()) {
            Some([n]) if n.as_i64().is_some_and(|n| n >= 1) => {
                quota.insert(key.into(), n.clone());
            }
            _ => return invalid(),
        }
    }
    let now = ts(input, "now")?;
    if expires - issued > MAX_DEPOSIT_TTL || issued > now + SKEW || issuer[0] != s(input, "signedBy")? {
        return invalid();
    }
    if b(input, "revoked")? {
        return Some(rej("CapabilityRevoked"));
    }
    let denied = || Some(rej("CapabilityDenied"));
    let reg_owner = s(input, "registrationOwner")?;
    if owner[0] != reg_owner || s(input, "issuerChainOwner")? != reg_owner {
        return denied();
    }
    if !b(input, "issuerRegistered")? || s(input, "issuerNode")? != s(input, "registrationNode")? {
        return denied();
    }
    let scope = input.get("issuerScope")?.as_array()?;
    if !scope.iter().filter_map(Value::as_str).any(|p| scope_covers(p, &right[0])) {
        return denied();
    }
    if right[0] != format!("mailbox:{}#deposit", s(input, "recipient")?) {
        return denied();
    }
    if now > expires {
        return denied();
    }
    if dkey[0] != s(input, "depositSigner")? {
        return denied();
    }
    Some(ok(json!({ "quota": quota })))
}

// ---------- §5.1 deposit signature ----------

pub fn deposit_signing_input(digest: &[u8]) -> Vec<u8> {
    let mut m = DEPOSIT_SIG_PREFIX.to_vec();
    m.extend_from_slice(digest);
    m
}

fn deposit_sig(input: &Value) -> Option<Outcome> {
    let denied = || Some(rej("CapabilityDenied"));
    let Some(key) = b64_exact(s(input, "depositKey")?, 32) else { return denied() };
    let digest = match hex::decode(s(input, "headerDigest")?) {
        Ok(d) if d.len() == 32 => d,
        _ => return bad().into(),
    };
    let Some(sig) = b64_exact(s(input, "sig")?, 64) else { return denied() };
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&key.try_into().ok()?) else { return denied() };
    let sig = ed25519_dalek::Signature::from_bytes(&sig.try_into().ok()?);
    let msg = deposit_signing_input(&digest);
    if vk.is_weak() || vk.verify_strict(&msg, &sig).is_err() {
        return denied();
    }
    Some(ok(json!({ "signingInput": hex::encode(msg) })))
}

// ---------- §7 admission ----------

fn admit(input: &Value) -> Option<Outcome> {
    let now = ts(input, "now")?;
    let env = input.get("envelope")?;
    // 1
    if !b(env, "parsed")? {
        return Some(rej("EnvelopeInvalid"));
    }
    // 2
    let reg = input.get("registration")?;
    let to = s(env, "to")?;
    if reg.is_null() || s(reg, "agent")? != to || now > ts(reg, "leaseUntil")? {
        return Some(rej("RecipientUnknown"));
    }
    // 3
    let deposit = input.get("deposit")?;
    if deposit.is_null() {
        return Some(rej("CapabilityMissing"));
    }
    // 4, 5, 6
    let (t, exp) = (ts(env, "ts")?, ts(env, "exp")?);
    if now > exp {
        return Some(rej("EnvelopeExpired"));
    }
    if t > now + SKEW {
        return Some(rej("EnvelopeNotYetValid"));
    }
    if t >= exp || exp - t > MAX_TTL + SKEW {
        return Some(rej("EnvelopeInvalid"));
    }
    // 7, 8
    match s(deposit, "token")? {
        "ok" => {}
        "invalid" => return Some(rej("CapabilityInvalid")),
        "denied" => return Some(rej("CapabilityDenied")),
        "revoked" => return Some(rej("CapabilityRevoked")),
        _ => return None,
    }
    // 9
    if !b(deposit, "sigValid")? {
        return Some(rej("CapabilityDenied"));
    }
    // 10
    match s(env, "verify")? {
        "ok" => {}
        "signature" => return Some(rej("SignatureInvalid")),
        "body-hash" | "format" => return Some(rej("EnvelopeInvalid")),
        _ => return None,
    }
    // 11
    let (from, id, digest) = (s(env, "from")?, s(env, "id")?, s(env, "digest")?);
    for h in input.get("held")?.as_array()? {
        if s(h, "from")? == from && s(h, "id")? == id {
            return Some(if s(h, "digest")? == digest {
                ok(json!({ "custody": "duplicate" }))
            } else {
                rej("EnvelopeInvalid")
            });
        }
    }
    // 12
    let (usage, quota) = (input.get("usage")?, input.get("quota")?);
    for scope in ["token", "registration"] {
        let (u, q) = (usage.get(scope)?, quota.get(scope)?);
        if i(u, "envelopes")? + 1 > i(q, "envelopes")? || i(u, "bytes")? + i(env, "bytes")? > i(q, "bytes")? {
            return Some(rej("MailboxFull"));
        }
    }
    // 13
    Some(ok(json!({ "custody": "accepted" })))
}

// ---------- §6 registration ----------

fn register(input: &Value) -> Option<Outcome> {
    let now = ts(input, "now")?;
    match s(input, "capability")? {
        "ok" => {}
        "missing" => return Some(rej("CapabilityMissing")),
        "denied" => return Some(rej("CapabilityDenied")),
        "revoked" => return Some(rej("CapabilityRevoked")),
        _ => return None,
    }
    if !b(input, "certifiesFrom")? {
        return Some(rej("IdentityUntrusted"));
    }
    let req = ts(input, "leaseUntil")?;
    if req <= now {
        return Some(rej("InvalidParamsError"));
    }
    Some(ok(json!({ "leaseUntil": time::format(req.min(now + LEASE_MAX)) })))
}

// ---------- §8 host record ----------

fn host_step(input: &Value) -> Option<Outcome> {
    let state = s(input, "state")?;
    let event = s(input, "event")?;
    if !["held", "delivered", "dropped", "expired"].contains(&state) {
        return Some(Outcome::Reject(None));
    }
    let next = match (state, event) {
        ("held", "recipient-accepted" | "recipient-duplicate") => "delivered",
        ("held", "recipient-refusal") => "dropped",
        ("held", "retryable-error" | "re-deposit") => "held",
        ("held", "exp-passed") => "expired",
        (_, "exp-passed" | "re-deposit") => state,
        (_, "recipient-accepted" | "recipient-duplicate" | "recipient-refusal" | "retryable-error") => {
            return Some(Outcome::Reject(None))
        }
        _ => return None,
    };
    Some(ok(json!({ "state": next })))
}

// ---------- §9.2 outbox entry ----------

const FINAL: [&str; 4] = ["delivered", "refused", "expired", "withdrawn"];

fn outbox_step(input: &Value) -> Option<Outcome> {
    let request = b(input, "request")?;
    let state = s(input, "state")?;
    let event = s(input, "event")?;
    const EVENTS: [&str; 8] = [
        "transmit",
        "host-custody",
        "recipient-custody",
        "response",
        "recipient-refusal",
        "retryable-error",
        "expiry",
        "local-cancel",
    ];
    if !EVENTS.contains(&event) {
        return None;
    }
    let illegal = || Some(Outcome::Reject(None));
    let states: &[&str] = if request {
        &["queued", "pending", "stored", "received", "delivered", "refused", "expired", "withdrawn"]
    } else {
        &["queued", "pending", "stored", "delivered", "refused", "expired"]
    };
    if !states.contains(&state) {
        return illegal();
    }
    if !request && (event == "response" || event == "local-cancel") {
        return illegal();
    }
    let next = match state {
        "queued" => match event {
            "transmit" => "pending",
            "expiry" => "expired",
            "local-cancel" => "withdrawn",
            _ => return illegal(),
        },
        "withdrawn" => match event {
            "expiry" | "local-cancel" => state,
            _ => return illegal(),
        },
        "delivered" | "refused" | "expired" => state,
        // pending, stored, received
        _ => match event {
            "host-custody" if state == "pending" => "stored",
            "recipient-custody" if request => "received",
            "recipient-custody" => "delivered",
            "response" => "delivered",
            "recipient-refusal" => "refused",
            "expiry" => "expired",
            _ => state,
        },
    };
    Some(ok(json!({ "state": next })))
}

// ---------- §9.3 paths ----------

fn path(input: &Value) -> Option<Outcome> {
    let state = s(input, "state")?;
    let mut paths = vec![];
    if FINAL.contains(&state) {
        return Some(ok(json!({ "paths": paths })));
    }
    if b(input, "direct")? {
        paths.push("direct".to_string());
    }
    let stored_fallback = state == "stored" && b(input, "fallback")?;
    if state == "queued" || state == "pending" || stored_fallback {
        for (n, h) in input.get("hosts")?.as_array()?.iter().enumerate() {
            if stored_fallback && b(h, "custody")? {
                continue;
            }
            let operator_ok = matches!(s(h, "operator")?, "sender-owner" | "recipient-owner") || b(h, "allowListed")?;
            let trusted = b(h, "chainValid")? && operator_ok;
            if trusted && b(h, "token")? && !b(h, "failed")? {
                paths.push(format!("host:{n}"));
            }
        }
    }
    Some(ok(json!({ "paths": paths })))
}

// ---------- §9.4 retry schedule ----------

fn backoff(input: &Value) -> Option<Outcome> {
    let n = i(input, "attempt")?;
    let r = input.get("r")?.as_f64()?;
    if n < 1 || !(0.0..1.0).contains(&r) {
        return None;
    }
    let d: i128 = if n > 20 { RETRY_MAX_MS } else { (RETRY_BASE_MS << (n - 1)).min(RETRY_MAX_MS) };
    let mut delay = (d as f64 / 2.0 + r * d as f64 / 2.0).floor() as i128;
    if let Some(ra) = input.get("retryAfterMs") {
        delay = delay.max(ra.as_i64()? as i128);
    }
    let next = ts(input, "now")? + delay * MS;
    let out = if next > ts(input, "exp")? { Value::Null } else { Value::String(time::format(next)) };
    Some(ok(json!({ "next": out })))
}

// ---------- §9.5 order ----------

fn order(input: &Value) -> Option<Outcome> {
    let entries = input.get("entries")?.as_array()?;
    let mut eligible = vec![];
    for (n, e) in entries.iter().enumerate() {
        let state = s(e, "state")?;
        if FINAL.contains(&state) {
            continue;
        }
        let key = e.get("key")?;
        let blocked = !key.is_null()
            && entries[..n].iter().any(|p| {
                p.get("key") == Some(key)
                    && match s(p, "state") {
                        Some("queued" | "pending") => true,
                        Some("stored") => b(p, "request") == Some(true),
                        _ => false,
                    }
            });
        if !blocked {
            eligible.push(n);
        }
    }
    Some(ok(json!({ "eligible": eligible })))
}

// ---------- timing (§8, §9.2, §10) ----------

fn timing(input: &Value) -> Option<Outcome> {
    let (now, t, exp) = (ts(input, "now")?, ts(input, "ts")?, ts(input, "exp")?);
    let action = match s(input, "role")? {
        "outbox" if now <= exp => "attempt",
        "outbox" if now <= exp + SKEW => "await",
        "outbox" => "expire",
        "host" if now <= exp => "deliver",
        "host" => "stop",
        "recipient" if now > exp + SKEW => return Some(rej("EnvelopeExpired")),
        "recipient" if t > now + SKEW => return Some(rej("EnvelopeNotYetValid")),
        "recipient" => "accept",
        _ => return None,
    };
    Some(ok(json!({ "action": action })))
}

// ---------- §11 reconnect ----------

fn reconnect(input: &Value) -> Option<Outcome> {
    let v = if s(input, "delivery")? != "acknowledged" || b(input, "remoteTerminal")? {
        json!({ "action": "none" })
    } else if !b(input, "responderReachable")? {
        json!({ "action": "wait" })
    } else {
        json!({ "action": "subscribe", "fromSeq": i(input, "applied")? + 1 })
    };
    Some(ok(v))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_ids() {
        let id = format!("wwa:{}", "a".repeat(52));
        assert!(is_b32_key_id(&id, "wwa:"));
        assert!(!is_b32_key_id(&format!("wwa:{}b", "a".repeat(51)), "wwa:"));
        assert!(is_b32_key_id(&format!("wwa:{}q", "a".repeat(51)), "wwa:"));
    }

    #[test]
    fn did_key() {
        assert!(is_did_key("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"));
        assert!(!is_did_key("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2do"));
    }
}
