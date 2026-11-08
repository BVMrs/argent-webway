//! Reference implementation of the envelope/v0 receive procedure (spec §9), used only to
//! self-check the generated vectors. It is not the node's envelope layer (that is
//! `crates/webway-envelope`, track T5).

use std::collections::HashMap;

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, VerifyingKey};

use crate::encoding::*;
use crate::json::{self, jcs, Value};
use crate::schema;

pub const VERSION: &str = "webway-envelope/0";
pub const SKEW: Nanos = 300 * SEC;
pub const MAX_TTL: Nanos = 604_800 * SEC;
pub const MAX_ENVELOPE_BYTES: usize = 1_048_576;
pub const TYPS: &[&str] = &["request", "response", "event", "error", "ack"];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reject {
    pub typ: &'static str,
    pub reason: &'static str,
}

impl Reject {
    pub fn code(&self) -> i64 {
        match self.typ {
            "EnvelopeInvalid" => -33001,
            "SignatureInvalid" => -33002,
            "EnvelopeExpired" => -33003,
            "EnvelopeNotYetValid" => -33004,
            "VersionNotSupportedError" => -32009,
            "UnsupportedOperationError" => -32004,
            _ => unreachable!(),
        }
    }
    pub fn retryable(&self) -> bool {
        self.typ == "EnvelopeNotYetValid"
    }
}

fn inv(reason: &'static str) -> Reject {
    Reject { typ: "EnvelopeInvalid", reason }
}
fn sig_inv(reason: &'static str) -> Reject {
    Reject { typ: "SignatureInvalid", reason }
}

/// What the receiver knows: hosted agents, clock, watermark, and any operation named by framing.
pub struct Ctx<'a> {
    pub hosts: &'a [[u8; 32]],
    pub now: Nanos,
    pub watermark: Option<Nanos>,
    pub framing_op: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct Verified {
    pub from: [u8; 32],
    pub to: [u8; 32],
    pub id: String,
    pub typ: String,
    pub in_reply_to: Option<String>,
    pub exp: Nanos,
    pub signing_input: Vec<u8>,
    pub header_digest: [u8; 32],
    pub body_hash: String,
}

pub fn signing_input(signed_header: &Value) -> Vec<u8> {
    let mut b = VERSION.as_bytes().to_vec();
    b.push(0);
    b.extend_from_slice(jcs(signed_header).as_bytes());
    b
}

pub fn body_hash(body: &Value) -> String {
    hash_str(blake3::hash(jcs(body).as_bytes()).as_bytes())
}

fn req_str<'v>(env: &'v Value, k: &str) -> Result<&'v str, Reject> {
    match env.get(k) {
        None => Err(inv("missing-field")),
        Some(Value::String(s)) => Ok(s),
        Some(_) => Err(inv("malformed-field")),
    }
}

/// Signature checks of ENV-210 / ENV-211 over an already-built signing input.
pub fn check_signature(from: &[u8; 32], sig: &[u8], input: &[u8]) -> Result<(), Reject> {
    let a = CompressedEdwardsY(*from).decompress().ok_or(sig_inv("weak-key"))?;
    if a.compress().to_bytes() != *from || a.is_small_order() {
        return Err(sig_inv("weak-key"));
    }
    let r: [u8; 32] = sig[..32].try_into().unwrap();
    let s: [u8; 32] = sig[32..].try_into().unwrap();
    if Option::<Scalar>::from(Scalar::from_canonical_bytes(s)).is_none() {
        return Err(sig_inv("non-canonical-signature"));
    }
    match CompressedEdwardsY(r).decompress() {
        Some(p) if p.compress().to_bytes() == r && !p.is_small_order() => {}
        _ => return Err(sig_inv("non-canonical-signature")),
    }
    let vk = VerifyingKey::from_bytes(from).map_err(|_| sig_inv("weak-key"))?;
    let sig = Signature::from_bytes(&sig.try_into().unwrap());
    vk.verify_strict(input, &sig).map_err(|_| sig_inv("verification-failed"))
}

/// Verification steps 1–7.
pub fn verify(input: &[u8], cx: &Ctx) -> Result<Verified, Reject> {
    // 1. parse
    let env = json::parse(input).map_err(|e| inv(e.reason()))?;
    if jcs(&env).len() > MAX_ENVELOPE_BYTES {
        return Err(inv("too-large"));
    }
    if env.as_object().is_none() {
        return Err(inv("malformed-field"));
    }
    // 2. version
    if req_str(&env, "v")? != VERSION {
        return Err(Reject { typ: "VersionNotSupportedError", reason: "unsupported-version" });
    }
    // 3. structure
    for k in ["typ", "op", "from", "to", "id", "ts", "exp", "body_hash", "body", "sig"] {
        if env.get(k).is_none() {
            return Err(inv("missing-field"));
        }
    }
    let typ = req_str(&env, "typ")?;
    if !TYPS.contains(&typ) {
        return Err(inv("malformed-field"));
    }
    let op = req_str(&env, "op")?;
    if op.is_empty() {
        return Err(inv("malformed-field"));
    }
    let from = parse_agent_id(req_str(&env, "from")?).ok_or(inv("malformed-field"))?;
    let to = parse_agent_id(req_str(&env, "to")?).ok_or(inv("malformed-field"))?;
    let id = req_str(&env, "id")?;
    if !is_uuid_v7(id) {
        return Err(inv("malformed-field"));
    }
    let ts = parse_ts(req_str(&env, "ts")?).ok_or(inv("malformed-field"))?;
    let exp = parse_ts(req_str(&env, "exp")?).ok_or(inv("malformed-field"))?;
    let bh = req_str(&env, "body_hash")?;
    if !is_hash_str(bh) {
        return Err(inv("malformed-field"));
    }
    let sig = parse_b64url(req_str(&env, "sig").map_err(|_| inv("malformed-signature"))?)
        .filter(|b| b.len() == 64)
        .ok_or(inv("malformed-signature"))?;
    let mut in_reply_to = None;
    if let Some(ctx) = env.get("ctx") {
        let m = ctx.as_object().ok_or(inv("malformed-field"))?;
        for (k, v) in m {
            let ok = match (k.as_str(), v) {
                ("taskId" | "contextId", Value::String(_)) => true,
                ("seq", Value::Number(n)) => n.fract() == 0.0 && *n >= 0.0 && *n <= 9007199254740991.0,
                ("inReplyTo", Value::String(s)) => is_uuid_v7(s),
                ("taskId" | "contextId" | "seq" | "inReplyTo", _) => false,
                _ => true, // unknown ctx members are kept (ENV-002)
            };
            if !ok {
                return Err(inv("malformed-field"));
            }
        }
        in_reply_to = ctx.get("inReplyTo").and_then(|v| v.as_str()).map(String::from);
    }
    if matches!(typ, "response" | "error" | "ack") && in_reply_to.is_none() {
        return Err(inv("missing-field"));
    }
    if let Some(cap) = env.get("cap") {
        let m = cap.as_object().ok_or(inv("malformed-field"))?;
        for (k, v) in m {
            if matches!(k.as_str(), "access" | "mandate") && v.as_str().is_none() {
                return Err(inv("malformed-field"));
            }
        }
    }
    if let Some(p) = env.get("prov") {
        if p.as_object().is_none() {
            return Err(inv("malformed-field"));
        }
    }
    if exp <= ts {
        return Err(inv("exp-not-after-ts"));
    }
    if exp - ts > MAX_TTL {
        return Err(inv("ttl-too-long"));
    }
    // 4. signature
    let header = env.without(&["sig", "body"]);
    let si = signing_input(&header);
    check_signature(&from, &sig, &si)?;
    // 5. body binding
    let body = env.get("body").unwrap();
    if body_hash(body) != bh {
        return Err(inv("body-hash-mismatch"));
    }
    // 6. recipient and freshness
    if !cx.hosts.contains(&to) {
        return Err(inv("wrong-recipient"));
    }
    check_freshness(cx.now, ts, exp, cx.watermark)?;
    // 7. operation, body form, header consistency
    let known = schema::A2A_OPS.contains(&op) || op.contains('#');
    if !known {
        return Err(Reject { typ: "UnsupportedOperationError", reason: "unsupported-op" });
    }
    if let Some(fop) = cx.framing_op {
        if fop != op {
            return Err(inv("op-mismatch"));
        }
    }
    if let Some(msg) = schema::body_schema(typ, op) {
        if !schema::signer_form_ok(body, msg) {
            return Err(inv("signer-form"));
        }
    }
    let (part_pats, task_ptrs, ctx_ptrs) = schema::locations(typ, op);
    for (ptrs, key) in [(task_ptrs, "taskId"), (ctx_ptrs, "contextId")] {
        if let Some(Value::String(c)) = env.get("ctx").and_then(|c| c.get(key)) {
            for p in ptrs {
                if let Some(Value::String(b)) = body.pointer(p) {
                    if b != c {
                        return Err(inv("ctx-mismatch"));
                    }
                }
            }
        }
    }
    check_prov(&env, body, &part_pats)?;

    Ok(Verified {
        from,
        to,
        id: id.to_string(),
        typ: typ.to_string(),
        in_reply_to,
        exp,
        header_digest: *blake3::hash(&si).as_bytes(),
        signing_input: si,
        body_hash: bh.to_string(),
    })
}

pub fn check_freshness(now: Nanos, ts: Nanos, exp: Nanos, watermark: Option<Nanos>) -> Result<(), Reject> {
    if exp <= ts {
        return Err(inv("exp-not-after-ts"));
    }
    if exp - ts > MAX_TTL {
        return Err(inv("ttl-too-long"));
    }
    if now > exp + SKEW {
        return Err(Reject { typ: "EnvelopeExpired", reason: "expired" });
    }
    if let Some(w) = watermark {
        if exp + SKEW <= w {
            return Err(Reject { typ: "EnvelopeExpired", reason: "below-watermark" });
        }
    }
    if ts > now + SKEW {
        return Err(Reject { typ: "EnvelopeNotYetValid", reason: "ts-in-future" });
    }
    Ok(())
}

fn check_prov(env: &Value, body: &Value, part_pats: &[&str]) -> Result<(), Reject> {
    let parts: Vec<String> = part_pats.iter().flat_map(|p| schema::expand(body, p)).collect();
    let entries = match env.get("prov").map(|p| p.get("parts")) {
        None => {
            return if parts.is_empty() { Ok(()) } else { Err(inv("missing-taint")) };
        }
        Some(None) => return Err(inv("bad-prov")),
        Some(Some(Value::Object(m))) => m,
        Some(Some(_)) => return Err(inv("bad-prov")),
    };
    for (ptr, _) in entries {
        if !parts.contains(ptr) {
            return Err(inv("bad-prov"));
        }
    }
    for p in &parts {
        let Some((_, entry)) = entries.iter().find(|(k, _)| k == p) else {
            return Err(inv("missing-taint"));
        };
        let Some(taint) = entry.get("taint") else { return Err(inv("missing-taint")) };
        let owners_ok = matches!(taint.get("owners"), Some(Value::Array(a)) if !a.is_empty()
            && a.iter().all(|o| o.as_str().is_some_and(|s| s.starts_with("did:key:z"))));
        let unverified_ok = matches!(taint.get("unverified"), Some(Value::Bool(_)));
        if !owners_ok || !unverified_ok {
            return Err(inv("bad-prov"));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Dedupe state machine (spec §8), for replay scenarios.

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// New request, processed. `entry` says whether a dedupe entry was created.
    Process { entry: bool },
    /// Answer received and delivered to the local agent.
    Deliver,
    /// Duplicate request: answered with the stored envelope or a duplicate ack.
    Duplicate { answer: &'static str },
    /// Duplicate answer (response/event/error/ack): dropped silently.
    DropDuplicate,
    /// Unsolicited answer: discarded, not answered.
    Discard,
    Reject(Reject),
}

pub struct Entry {
    digest: [u8; 32],
    exp: Nanos,
}

pub struct Node {
    pub hosts: Vec<[u8; 32]>,
    pub entries: HashMap<([u8; 32], String), Entry>,
    pub seen_answers: HashMap<([u8; 32], String), ()>,
    /// (from, to, id) of envelopes this node sent.
    pub sent: Vec<([u8; 32], [u8; 32], String)>,
    pub watermark: Nanos,
}

impl Node {
    pub fn new(hosts: Vec<[u8; 32]>, start: Nanos) -> Self {
        Node { hosts, entries: HashMap::new(), seen_answers: HashMap::new(), sent: vec![], watermark: start }
    }

    pub fn purge(&mut self, now: Nanos) {
        let mut w = self.watermark;
        self.entries.retain(|_, e| {
            if now > e.exp + SKEW {
                w = w.max(e.exp + SKEW);
                false
            } else {
                true
            }
        });
        self.watermark = w;
    }

    pub fn record_sent(&mut self, from: [u8; 32], to: [u8; 32], id: &str) {
        self.sent.push((from, to, id.to_string()));
    }

    /// `app`: "ok" | "fatal-error" | "retryable-error"; `authenticated`: the binding authenticated
    /// the transport peer as the sender's node or our mailbox host.
    pub fn receive(&mut self, input: &[u8], now: Nanos, app: &str, authenticated: bool) -> Outcome {
        let hosts = self.hosts.clone();
        let cx = Ctx { hosts: &hosts, now, watermark: Some(self.watermark), framing_op: None };
        let v = match verify(input, &cx) {
            Ok(v) => v,
            Err(r) => return Outcome::Reject(r),
        };
        let key = (v.from, v.id.clone());
        if v.typ != "request" {
            if let Some(irt) = &v.in_reply_to {
                let solicited =
                    self.sent.iter().any(|(f, t, id)| *t == v.from && *f == v.to && id == irt);
                if !solicited {
                    return Outcome::Discard;
                }
            } else if v.typ != "event" {
                return Outcome::Discard;
            }
            if self.seen_answers.insert(key, ()).is_some() {
                return Outcome::DropDuplicate;
            }
            return Outcome::Deliver;
        }
        if let Some(e) = self.entries.get(&key) {
            if e.digest == v.header_digest {
                return Outcome::Duplicate { answer: if authenticated { "stored" } else { "ack" } };
            }
            return Outcome::Reject(inv("id-reuse"));
        }
        let entry = app != "retryable-error";
        if entry {
            self.entries.insert(key, Entry { digest: v.header_digest, exp: v.exp });
        }
        Outcome::Process { entry }
    }
}
