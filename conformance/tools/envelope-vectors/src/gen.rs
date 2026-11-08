//! Builds the envelope/v0 vector files. Every case is checked against the reference verifier
//! (`verify.rs`) as it is built: a case whose verifier result differs from its expectation
//! aborts generation.

use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Map, Value as J};

use crate::encoding::*;
use crate::json::{self, jcs, to_text, Value};
use crate::verify::{self, Ctx, Outcome, Reject, MAX_TTL, SKEW, VERSION};

// ---------------------------------------------------------------------------------------------
// Keys and fixtures

pub struct Key {
    pub name: &'static str,
    pub seed: [u8; 32],
    pub sk: SigningKey,
    pub pk: [u8; 32],
}

impl Key {
    fn new(name: &'static str) -> Key {
        let seed = *blake3::hash(format!("argent-webway/test-vectors/envelope/v0/{name}").as_bytes()).as_bytes();
        let sk = SigningKey::from_bytes(&seed);
        let pk = sk.verifying_key().to_bytes();
        Key { name, seed, sk, pk }
    }
    pub fn id(&self) -> String {
        agent_id(&self.pk)
    }
}

pub struct Fx {
    pub alice: Key,
    pub bob: Key,
    pub carol: Key,
    pub mallory: Key,
    pub owner_a: Key,
    pub owner_b: Key,
    pub t0: Nanos,
}

impl Fx {
    pub fn new() -> Fx {
        Fx {
            alice: Key::new("alice"),
            bob: Key::new("bob"),
            carol: Key::new("carol"),
            mallory: Key::new("mallory"),
            owner_a: Key::new("owner-a"),
            owner_b: Key::new("owner-b"),
            t0: parse_ts("2026-11-07T12:00:00Z").unwrap(),
        }
    }
    fn keys(&self) -> [&Key; 6] {
        [&self.alice, &self.bob, &self.carol, &self.mallory, &self.owner_a, &self.owner_b]
    }
    fn agent(&self, name: &str) -> &Key {
        self.keys().into_iter().find(|k| k.name == name).unwrap()
    }
}

pub fn from_serde(v: &J) -> Value {
    match v {
        J::Null => Value::Null,
        J::Bool(b) => Value::Bool(*b),
        J::Number(n) => Value::Number(n.as_f64().unwrap()),
        J::String(s) => Value::String(s.clone()),
        J::Array(a) => Value::Array(a.iter().map(from_serde).collect()),
        J::Object(m) => Value::Object(m.iter().map(|(k, v)| (k.clone(), from_serde(v))).collect()),
    }
}

fn uuid_for(label: &str, t: Nanos) -> String {
    let h = blake3::hash(label.as_bytes());
    uuid_v7((t / 1_000_000) as u64, h.as_bytes()[..10].try_into().unwrap())
}

/// Unsigned envelope description.
#[derive(Clone)]
pub struct Env {
    pub typ: &'static str,
    pub op: &'static str,
    pub from: &'static str,
    pub to: &'static str,
    pub id: String,
    pub ts: Nanos,
    pub exp: Nanos,
    pub ctx: Option<J>,
    pub cap: Option<J>,
    pub prov: Option<J>,
    pub extra: Vec<(&'static str, J)>,
    pub body: J,
}

const ACCESS_TOKEN: &str = "dGVzdC1hY2Nlc3MtdG9rZW4tbm90LWEtYmlzY3VpdA"; // placeholder, not a Biscuit

impl Fx {
    fn taint_a(&self) -> J {
        json!({"taint": {"owners": [did_key(&self.owner_a.pk)], "unverified": false}})
    }

    /// The baseline: alice asks bob to run tests.
    pub fn send_message(&self, label: &str) -> Env {
        let id = uuid_for(label, self.t0);
        Env {
            typ: "request",
            op: "SendMessage",
            from: "alice",
            to: "bob",
            id: id.clone(),
            ts: self.t0,
            exp: self.t0 + 3600 * SEC,
            ctx: Some(json!({"contextId": "ctx-0001"})),
            cap: Some(json!({"access": ACCESS_TOKEN})),
            prov: Some(json!({"parts": {"/message/parts/0": self.taint_a()}})),
            extra: vec![],
            body: json!({"message": {
                "messageId": id,
                "contextId": "ctx-0001",
                "role": "ROLE_USER",
                "parts": [{"text": "Run the test suite on branch main."}]
            }}),
        }
    }

    fn get_task(&self, label: &str, op: &'static str) -> Env {
        Env {
            typ: "request",
            op,
            from: "alice",
            to: "bob",
            id: uuid_for(label, self.t0),
            ts: self.t0,
            exp: self.t0 + 600 * SEC,
            ctx: Some(json!({"taskId": "task-0001"})),
            cap: Some(json!({"access": ACCESS_TOKEN})),
            prov: None,
            extra: vec![],
            body: json!({"id": "task-0001"}),
        }
    }

    /// bob's response to a request envelope `req`.
    fn response_to(&self, req: &Env, label: &str) -> Env {
        let t = req.ts + 2 * SEC;
        Env {
            typ: "response",
            op: req.op,
            from: req.to,
            to: req.from,
            id: uuid_for(label, t),
            ts: t,
            exp: t + 3600 * SEC,
            ctx: Some(json!({"taskId": "task-0001", "contextId": "ctx-0001", "inReplyTo": req.id})),
            cap: None,
            prov: None,
            extra: vec![],
            body: json!({"task": {"id": "task-0001", "contextId": "ctx-0001", "status": {"state": "TASK_STATE_SUBMITTED"}}}),
        }
    }

    pub fn header_value(&self, e: &Env) -> Value {
        let mut m = Map::new();
        m.insert("v".into(), json!(VERSION));
        m.insert("typ".into(), json!(e.typ));
        m.insert("op".into(), json!(e.op));
        m.insert("from".into(), json!(self.agent(e.from).id()));
        m.insert("to".into(), json!(self.agent(e.to).id()));
        m.insert("id".into(), json!(e.id));
        m.insert("ts".into(), json!(fmt_ts(e.ts)));
        m.insert("exp".into(), json!(fmt_ts(e.exp)));
        for (k, v) in [("ctx", &e.ctx), ("cap", &e.cap), ("prov", &e.prov)] {
            if let Some(v) = v {
                m.insert(k.into(), v.clone());
            }
        }
        for (k, v) in &e.extra {
            m.insert((*k).into(), v.clone());
        }
        m.insert("body_hash".into(), json!(verify::body_hash(&from_serde(&e.body))));
        from_serde(&J::Object(m))
    }

    /// Signs with the `from` key: header + body + sig.
    pub fn sign(&self, e: &Env) -> Value {
        self.sign_with(e, &self.agent(e.from).sk)
    }

    pub fn sign_with(&self, e: &Env, sk: &SigningKey) -> Value {
        let header = self.header_value(e);
        let sig = sk.sign(&verify::signing_input(&header)).to_bytes();
        assemble(header, from_serde(&e.body), &sig)
    }
}

fn assemble(header: Value, body: Value, sig: &[u8]) -> Value {
    let Value::Object(mut m) = header else { unreachable!() };
    m.push(("body".into(), body));
    m.push(("sig".into(), Value::String(b64url(sig))));
    Value::Object(m)
}

fn set(v: &mut Value, path: &[&str], new: Value) {
    let mut cur = v;
    for (i, k) in path.iter().enumerate() {
        let last = i == path.len() - 1;
        cur = match cur {
            Value::Object(m) => {
                if last {
                    if let Some(slot) = m.iter_mut().find(|(mk, _)| mk == k) {
                        slot.1 = new;
                    } else {
                        m.push(((*k).into(), new));
                    }
                    return;
                }
                &mut m.iter_mut().find(|(mk, _)| mk == k).unwrap().1
            }
            Value::Array(a) => {
                let idx: usize = k.parse().unwrap();
                if last {
                    a[idx] = new;
                    return;
                }
                &mut a[idx]
            }
            _ => panic!("bad path"),
        };
    }
}

fn remove(v: &mut Value, key: &str) {
    v.as_object_mut().unwrap().retain(|(k, _)| k != key);
}

fn s(x: &str) -> Value {
    Value::String(x.into())
}

fn compact(v: &Value) -> String {
    to_text(v, false)
}

fn sig_bytes(env: &Value) -> Vec<u8> {
    parse_b64url(env.get("sig").unwrap().as_str().unwrap()).unwrap()
}

// ---------------------------------------------------------------------------------------------
// Case builders

fn err_json(r: &Reject, retry_after: Option<i64>) -> J {
    let mut m = Map::new();
    m.insert("type".into(), json!(r.typ));
    m.insert("code".into(), json!(r.code()));
    m.insert("reason".into(), json!(r.reason));
    m.insert("retryable".into(), json!(r.retryable()));
    if let Some(ra) = retry_after {
        m.insert("retryAfter".into(), json!(ra));
    }
    J::Object(m)
}

fn rj(typ: &'static str, reason: &'static str) -> Reject {
    Reject { typ, reason }
}
fn inv(reason: &'static str) -> Reject {
    rj("EnvelopeInvalid", reason)
}
fn sinv(reason: &'static str) -> Reject {
    rj("SignatureInvalid", reason)
}

struct Recv<'a> {
    hosts: Vec<&'a Key>,
    now: Nanos,
    watermark: Option<Nanos>,
    framing_op: Option<&'static str>,
}

struct Cases {
    out: Vec<J>,
}

fn dr(fx: &Fx) -> Recv<'_> {
    Recv { hosts: vec![&fx.bob], now: fx.t0 + 10 * SEC, watermark: None, framing_op: None }
}

impl Cases {

    /// Adds an envelope-verify case. `expect`: Ok(()) for accept, Err for the expected rejection.
    fn add(&mut self, id: &str, reqs: &[&str], desc: &str, rx: Recv, input: Input, expect: Result<(), Reject>) {
        let bytes = input.bytes();
        let hosts: Vec<[u8; 32]> = rx.hosts.iter().map(|k| k.pk).collect();
        let cx = Ctx { hosts: &hosts, now: rx.now, watermark: rx.watermark, framing_op: rx.framing_op };
        let got = verify::verify(&bytes, &cx);
        let mut c = Map::new();
        c.insert("id".into(), json!(id));
        c.insert("requirements".into(), json!(reqs));
        c.insert("description".into(), json!(desc));
        let mut r = Map::new();
        r.insert("hosts".into(), json!(rx.hosts.iter().map(|k| k.id()).collect::<Vec<_>>()));
        r.insert("now".into(), json!(fmt_ts(rx.now)));
        if let Some(w) = rx.watermark {
            r.insert("watermark".into(), json!(fmt_ts(w)));
        }
        if let Some(f) = rx.framing_op {
            r.insert("framing_op".into(), json!(f));
        }
        c.insert("receiver".into(), J::Object(r));
        input.write(&mut c);
        match (&expect, &got) {
            (Ok(()), Ok(v)) => {
                let header = json::parse(&v.signing_input[VERSION.len() + 1..]).unwrap();
                c.insert(
                    "expect".into(),
                    json!({
                        "result": "accept",
                        "from": agent_id(&v.from),
                        "id": v.id,
                        "body_hash": v.body_hash,
                        "signed_header_jcs": jcs(&header),
                        "signing_input_hex": hex::encode(&v.signing_input),
                        "header_digest": hash_str(&v.header_digest),
                    }),
                );
            }
            (Err(e), Err(g)) if e == g => {
                let retry_after = (e.typ == "EnvelopeNotYetValid").then(|| {
                    let env = json::parse(&bytes).unwrap();
                    let ts = parse_ts(env.get("ts").unwrap().as_str().unwrap()).unwrap();
                    let d = ts - SKEW - rx.now;
                    ((d + SEC - 1) / SEC) as i64
                });
                c.insert("expect".into(), json!({"result": "reject", "error": err_json(e, retry_after)}));
            }
            _ => panic!("case {id}: expected {expect:?}, reference verifier gave {got:?}"),
        }
        self.out.push(J::Object(c));
    }
}

enum Input {
    Text(String),
    Hex(Vec<u8>),
}

impl Input {
    fn bytes(&self) -> Vec<u8> {
        match self {
            Input::Text(t) => t.as_bytes().to_vec(),
            Input::Hex(b) => b.clone(),
        }
    }
    fn write(&self, c: &mut Map<String, J>) {
        match self {
            Input::Text(t) => c.insert("input".into(), json!(t)),
            Input::Hex(b) => c.insert("input_hex".into(), json!(hex::encode(b))),
        };
    }
}

fn txt(v: &Value) -> Input {
    Input::Text(compact(v))
}

// ---------------------------------------------------------------------------------------------
// envelopes.json

pub fn envelopes(fx: &Fx) -> J {
    let mut cs = Cases { out: vec![] };
    let base = fx.send_message("base");
    let good = fx.sign(&base);

    // --- valid
    cs.add("valid-minimal-send-message", &["ENV-001", "ENV-120", "ENV-200", "ENV-610"],
        "A well-formed SendMessage request from alice to bob.", dr(fx), txt(&good), Ok(()));

    {
        // Re-serialised: pretty-printed, members reversed, escapes spelled differently.
        let mut v = good.clone();
        fn reverse(v: &mut Value) {
            match v {
                Value::Object(m) => {
                    m.reverse();
                    m.iter_mut().for_each(|(_, x)| reverse(x));
                }
                Value::Array(a) => a.iter_mut().for_each(reverse),
                _ => {}
            }
        }
        reverse(&mut v);
        let t = to_text(&v, true).replace("Run the test suite", "Run the test\\u0020suite").replace("ctx-0001", "ctx\\u002d0001");
        cs.add("valid-reserialised", &["ENV-110", "ENV-700"],
            "The valid envelope with whitespace, reversed member order and unnecessary escapes. Verification uses the parsed value, so it still verifies.",
            dr(fx), Input::Text(t), Ok(()));
    }
    {
        let mut e = fx.send_message("unknown-members");
        e.extra.push(("x-future", json!({"hint": 1})));
        e.ctx = Some(json!({"contextId": "ctx-0001", "priority": "low"}));
        e.body["message"]["x-unknown-field"] = json!("kept");
        cs.add("valid-unknown-members-signed", &["ENV-002", "ENV-121"],
            "Unknown members at the top level, in ctx and in the body are covered by the signature and ignored.",
            dr(fx), txt(&fx.sign(&e)), Ok(()));
    }
    {
        let mut e = fx.send_message("numbers");
        e.body["metadata"] = json!({"ratio": 0.1, "big": 9007199254740991.0, "small": 1e-7, "neg": -1.5, "int": 42, "u64": "18446744073709551615"});
        let signed = fx.sign(&e);
        let t = compact(&signed)
            .replace("\"ratio\":0.1", "\"ratio\":1.0E-1")
            .replace("\"big\":9007199254740991", "\"big\":9.007199254740991E15")
            .replace("\"small\":1e-7", "\"small\":0.00000010")
            .replace("\"int\":42", "\"int\":4.2e1");
        assert!(t.contains("1.0E-1") && t.contains("0.00000010") && t.contains("4.2e1") && t.contains("E15"));
        cs.add("valid-number-spellings", &["ENV-110", "ENV-100"],
            "Body numbers spelled differently from their JCS form (1.0E-1, 0.00000010, 4.2e1, and 9.007199254740991E15 = 2^53 − 1) canonicalise to what was signed. A 64-bit value travels as a string.",
            dr(fx), Input::Text(t), Ok(()));
    }
    {
        let mut e = fx.send_message("non-ascii");
        e.body["message"]["parts"][0]["text"] = json!("Prüfe café 🚀 \u{fb33} \"quoted\" \\ tab\t end");
        e.body["metadata"] = json!({"€": 1, "\u{1f600}": 2, "\u{fb33}": 3, "\r": 4});
        let signed = fx.sign(&e);
        let t = compact(&signed).replace("🚀", "\\ud83d\\ude80").replace("é", "\\u00e9");
        cs.add("valid-non-ascii-and-utf16-key-order", &["ENV-110"],
            "Non-ASCII text, surrogate-pair escapes and metadata keys whose UTF-16 order differs from code point order (U+1F600 sorts before U+FB33).",
            dr(fx), Input::Text(t), Ok(()));
    }
    {
        let mut e = fx.send_message("presence");
        e.body["message"]["parts"][0] = json!({"text": ""});
        e.body["configuration"] = json!({"historyLength": 0});
        cs.add("valid-explicit-presence-defaults", &["ENV-120", "ENV-121"],
            "A oneof member (Part.text) and an optional field (historyLength) set to their default values are emitted, as the signer form requires.",
            dr(fx), txt(&fx.sign(&e)), Ok(()));
    }
    {
        let mut e = fx.send_message("ttl-max");
        e.exp = e.ts + MAX_TTL;
        cs.add("valid-ttl-exactly-max", &["ENV-011"], "exp − ts equals MAX_TTL (7 days).", dr(fx), txt(&fx.sign(&e)), Ok(()));
    }
    {
        let e = fx.send_message("dwell");
        let mut rx = dr(fx);
        rx.now = e.ts + 3000 * SEC;
        cs.add("valid-mailbox-dwell-beyond-skew", &["ENV-302"],
            "Delivered 50 minutes after ts (far more than SKEW) but before exp: accepted.", rx, txt(&fx.sign(&e)), Ok(()));
    }
    {
        let e = fx.send_message("boundary-exp");
        let mut rx = dr(fx);
        rx.now = e.exp + SKEW;
        cs.add("valid-now-equals-exp-plus-skew", &["ENV-300", "ENV-303"], "now = exp + SKEW exactly: still fresh.", rx, txt(&fx.sign(&e)), Ok(()));
    }
    {
        let e = fx.send_message("boundary-ts");
        let mut rx = dr(fx);
        rx.now = e.ts - SKEW;
        cs.add("valid-ts-equals-now-plus-skew", &["ENV-301", "ENV-303"], "ts = now + SKEW exactly: accepted.", rx, txt(&fx.sign(&e)), Ok(()));
    }
    {
        let req = fx.send_message("base");
        let resp = fx.response_to(&req, "resp");
        let mut rx = dr(fx);
        rx.hosts = vec![&fx.alice];
        rx.now = resp.ts + SEC;
        cs.add("valid-response", &["ENV-031", "ENV-030"], "bob's response to the baseline request, received by alice's node.", rx, txt(&fx.sign(&resp)), Ok(()));
    }
    {
        let mut e = fx.send_message("prov-trust");
        e.prov = Some(json!({"parts": {"/message/parts/0": {
            "taint": {"owners": [did_key(&fx.owner_a.pk)], "unverified": false}, "trust": "self"}}}));
        cs.add("valid-prov-with-ignored-trust-member", &["ENV-002", "ENV-052"],
            "A sender-declared trust member is signed and kept but has no effect (provenance/v0 ignores it).", dr(fx), txt(&fx.sign(&e)), Ok(()));
    }
    {
        let mut e = fx.send_message("ext-op");
        e.op = "https://github.com/BVMrs/argent-webway/spec/ext/blob/v0#GetBlob";
        e.prov = None;
        e.ctx = None;
        e.body = json!({"hash": "blake3:00", "anything": [1, 2, 3]});
        cs.add("valid-extension-op", &["ENV-021"], "An extension operation (URI#name). Its body is not an A2A schema, so only the generic rules apply.",
            dr(fx), txt(&fx.sign(&e)), Ok(()));
    }

    // --- tampering by an intermediary
    let tamper = |cs: &mut Cases, id: &str, reqs: &[&str], desc: &str, path: &[&str], val: Value, rx: Recv, why: Reject| {
        let mut v = good.clone();
        set(&mut v, path, val);
        cs.add(id, reqs, desc, rx, txt(&v), Err(why));
    };
    {
        let mut rx = dr(fx);
        rx.hosts = vec![&fx.bob, &fx.carol];
        tamper(&mut cs, "tampered-to-redirect", &["ENV-211", "ENV-400"],
            "A relay changes `to` from bob to carol, both hosted on the receiving node.", &["to"], s(&fx.carol.id()), rx, sinv("verification-failed"));
    }
    tamper(&mut cs, "tampered-exp-extended", &["ENV-211"], "A mailbox host extends `exp` by a day.",
        &["exp"], s(&fmt_ts(fx.t0 + 86400 * SEC)), dr(fx), sinv("verification-failed"));
    tamper(&mut cs, "tampered-cap-swapped", &["ENV-211", "ENV-040"], "An intermediary swaps the capability token.",
        &["cap", "access"], s("c3dhcHBlZC10b2tlbg"), dr(fx), sinv("verification-failed"));
    tamper(&mut cs, "tampered-taint-laundered", &["ENV-211"], "An intermediary replaces the taint owners (laundering provenance).",
        &["prov", "parts", "/message/parts/0", "taint", "owners"], Value::Array(vec![s(&did_key(&fx.owner_b.pk))]), dr(fx), sinv("verification-failed"));
    tamper(&mut cs, "tampered-body-text", &["ENV-212"], "The body text is changed, body_hash left as signed.",
        &["body", "message", "parts", "0", "text"], s("Delete branch main."), dr(fx), inv("body-hash-mismatch"));
    {
        let mut v = good.clone();
        set(&mut v, &["body", "message", "parts", "0", "text"], s("Delete branch main."));
        let bh = verify::body_hash(v.get("body").unwrap());
        set(&mut v, &["body_hash"], s(&bh));
        cs.add("tampered-body-and-body-hash", &["ENV-211", "ENV-212"],
            "The body is changed and body_hash recomputed to match: the signature over the header fails.", dr(fx), txt(&v), Err(sinv("verification-failed")));
    }
    {
        let mut v = good.clone();
        set(&mut v, &["x-added"], s("by relay"));
        cs.add("unknown-member-added-after-signing", &["ENV-002", "ENV-700"],
            "An intermediary adds an unknown top-level member. Unknown members are signed, so this breaks the signature.", dr(fx), txt(&v), Err(sinv("verification-failed")));
    }
    {
        let mut v = good.clone();
        remove(&mut v, "cap");
        cs.add("cap-stripped", &["ENV-211", "ENV-040"], "An intermediary removes `cap`.", dr(fx), txt(&v), Err(sinv("verification-failed")));
    }
    {
        let g = fx.get_task("op-confusion", "GetTask");
        let mut v = fx.sign(&g);
        set(&mut v, &["op"], s("CancelTask"));
        cs.add("tampered-op-get-to-cancel", &["ENV-021", "ENV-211"],
            "GetTask and CancelTask bodies have the same shape. Changing the signed `op` breaks the signature.", dr(fx), txt(&v), Err(sinv("verification-failed")));
        let mut rx = dr(fx);
        rx.framing_op = Some("CancelTask");
        cs.add("framing-op-mismatch", &["ENV-021"],
            "A valid GetTask envelope delivered in a frame that names CancelTask: the signed op wins and the mismatch is rejected.",
            rx, txt(&fx.sign(&g)), Err(inv("op-mismatch")));
    }

    // --- signatures
    cs.add("signed-by-other-key", &["ENV-200", "ENV-211"], "from = alice, but signed with mallory's key.",
        dr(fx), txt(&fx.sign_with(&base, &fx.mallory.sk)), Err(sinv("verification-failed")));
    {
        let header = fx.header_value(&base);
        let sig = fx.alice.sk.sign(jcs(&header).as_bytes()).to_bytes();
        cs.add("signature-without-domain-prefix", &["ENV-200"],
            "Signed over JCS(signed header) without the `webway-envelope/0` 0x00 prefix.", dr(fx),
            txt(&assemble(header.clone(), from_serde(&base.body), &sig)), Err(sinv("verification-failed")));
        let mut with_body = header.clone();
        with_body.as_object_mut().unwrap().push(("body".into(), from_serde(&base.body)));
        let sig = fx.alice.sk.sign(&verify::signing_input(&with_body)).to_bytes();
        cs.add("signature-over-header-and-body", &["ENV-200"],
            "Signed over the envelope minus sig (body included) instead of the signed header.", dr(fx),
            txt(&assemble(header, from_serde(&base.body), &sig)), Err(sinv("verification-failed")));
    }
    {
        // S + L: same signature for lax verifiers that reduce S mod L.
        let mut sig = sig_bytes(&good);
        const L: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ];
        let mut carry = 0u16;
        for i in 0..32 {
            let t = sig[32 + i] as u16 + L[i] as u16 + carry;
            sig[32 + i] = t as u8;
            carry = t >> 8;
        }
        assert_eq!(carry, 0);
        let mut v = good.clone();
        set(&mut v, &["sig"], s(&b64url(&sig)));
        cs.add("signature-s-not-reduced", &["ENV-211"],
            "The valid signature with S replaced by S + L. Verifiers that reduce S mod L would accept it (malleability).", dr(fx), txt(&v), Err(sinv("non-canonical-signature")));
    }
    {
        // Small-order public key (identity) with R = identity, S = 0: passes the cofactorless
        // equation for any message unless the key is rejected.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let mut header = fx.header_value(&base);
        set(&mut header, &["from"], s(&agent_id(&identity)));
        let mut sig = [0u8; 64];
        sig[0] = 1;
        cs.add("weak-key-identity-point", &["ENV-210"],
            "from is the identity point (small order) and the signature is (R = identity, S = 0), which satisfies the verification equation for every message.",
            dr(fx), txt(&assemble(header, from_serde(&base.body), &sig)), Err(sinv("weak-key")));
    }
    {
        // Non-canonical encoding of a valid point: y = p + d.
        let mut found = None;
        for d in 2u8..19 {
            let mut y = [0xffu8; 32];
            y[0] = 0xed + d;
            y[31] = 0x7f;
            if curve25519_dalek::edwards::CompressedEdwardsY(y).decompress().is_some() {
                found = Some(y);
                break;
            }
        }
        let y = found.expect("a non-canonical point encoding");
        let mut header = fx.header_value(&base);
        set(&mut header, &["from"], s(&agent_id(&y)));
        cs.add("weak-key-non-canonical-encoding", &["ENV-210"],
            "from encodes a curve point with y ≥ p (a non-canonical encoding of a valid point).",
            dr(fx), txt(&assemble(header, from_serde(&base.body), &sig_bytes(&good))), Err(sinv("weak-key")));
    }
    {
        let mut sig = sig_bytes(&good);
        sig[..32].copy_from_slice(&{
            let mut r = [0u8; 32];
            r[0] = 1;
            r
        });
        let mut v = good.clone();
        set(&mut v, &["sig"], s(&b64url(&sig)));
        cs.add("signature-r-small-order", &["ENV-211"], "The signature's R is the identity point.", dr(fx), txt(&v), Err(sinv("non-canonical-signature")));
    }

    // --- structure and formats
    let mutate = |cs: &mut Cases, id: &str, reqs: &[&str], desc: &str, f: &dyn Fn(&mut Value), why: Result<(), Reject>| {
        let mut v = good.clone();
        f(&mut v);
        let rx = dr(fx);
        cs.add(id, reqs, desc, rx, txt(&v), why);
    };
    for m in ["v", "typ", "op", "from", "to", "id", "ts", "exp", "body_hash", "body", "sig"] {
        mutate(&mut cs, &format!("missing-{}", m.replace('_', "-")), &["ENV-001"], &format!("The `{m}` member is absent."),
            &|v: &mut Value| remove(v, m), Err(inv("missing-field")));
    }
    mutate(&mut cs, "version-unsupported", &["ENV-800"], "v = webway-envelope/1.",
        &|v: &mut Value| set(v, &["v"], s("webway-envelope/1")), Err(rj("VersionNotSupportedError", "unsupported-version")));
    mutate(&mut cs, "typ-unknown", &["ENV-020"], "typ = notify.", &|v: &mut Value| set(v, &["typ"], s("notify")), Err(inv("malformed-field")));
    let alice_upper = format!("wwa:{}", fx.alice.id()[4..].to_uppercase());
    mutate(&mut cs, "from-uppercase", &["ENV-010"], "from in uppercase base32.", &|v: &mut Value| set(v, &["from"], s(&alice_upper)), Err(inv("malformed-field")));
    {
        let id = fx.alice.id();
        let last = id.chars().last().unwrap();
        // flip the lowest unused bit of the final character: the decoded key would be unchanged
        let pos = b"abcdefghijklmnopqrstuvwxyz234567".iter().position(|&c| c as char == last).unwrap();
        assert_eq!(pos & 0b1111, 0, "last char carries 1 data bit and 4 zero bits");
        let alt = b"abcdefghijklmnopqrstuvwxyz234567"[pos | 1] as char;
        let bad = format!("{}{}", &id[..id.len() - 1], alt);
        mutate(&mut cs, "from-non-canonical-base32", &["ENV-010"],
            "from with non-zero unused trailing bits: decodes to alice's key under a lax decoder.", &|v: &mut Value| set(v, &["from"], s(&bad)), Err(inv("malformed-field")));
    }
    mutate(&mut cs, "id-uuid-v4", &["ENV-010"], "id is a version 4 UUID.", &|v: &mut Value| set(v, &["id"], s("550e8400-e29b-41d4-a716-446655440000")), Err(inv("malformed-field")));
    mutate(&mut cs, "ts-with-offset", &["ENV-010"], "ts uses +00:00 instead of Z.", &|v: &mut Value| set(v, &["ts"], s("2026-11-07T12:00:00+00:00")), Err(inv("malformed-field")));
    mutate(&mut cs, "ts-two-fraction-digits", &["ENV-010"], "ts has 2 fractional digits (only 0, 3, 6 or 9 are allowed).",
        &|v: &mut Value| set(v, &["ts"], s("2026-11-07T12:00:00.25Z")), Err(inv("malformed-field")));
    mutate(&mut cs, "body-hash-uppercase-hex", &["ENV-010"], "body_hash in uppercase hex.",
        &|v: &mut Value| {
            let up = format!("blake3:{}", v.get("body_hash").unwrap().as_str().unwrap()[7..].to_uppercase());
            set(v, &["body_hash"], s(&up))
        }, Err(inv("malformed-field")));
    mutate(&mut cs, "sig-padded", &["ENV-010"], "sig with base64 padding.",
        &|v: &mut Value| {
            let p = format!("{}==", v.get("sig").unwrap().as_str().unwrap());
            set(v, &["sig"], s(&p))
        }, Err(inv("malformed-signature")));
    mutate(&mut cs, "sig-standard-base64-alphabet", &["ENV-010"], "sig uses + and / (standard alphabet) instead of - and _.",
        &|v: &mut Value| {
            let p = v.get("sig").unwrap().as_str().unwrap().replace('-', "+").replace('_', "/");
            let p = if p.contains('+') || p.contains('/') { p } else { format!("+{}", &p[1..]) };
            set(v, &["sig"], s(&p))
        }, Err(inv("malformed-signature")));
    mutate(&mut cs, "sig-truncated", &["ENV-010"], "sig decodes to 63 bytes.",
        &|v: &mut Value| {
            let b = parse_b64url(v.get("sig").unwrap().as_str().unwrap()).unwrap();
            set(v, &["sig"], s(&b64url(&b[..63])))
        }, Err(inv("malformed-signature")));
    mutate(&mut cs, "cap-access-not-string", &["ENV-001"], "cap.access is a number.", &|v: &mut Value| set(v, &["cap", "access"], Value::Number(7.0)), Err(inv("malformed-field")));
    mutate(&mut cs, "top-level-array", &["ENV-001"], "The envelope is a JSON array.", &|v: &mut Value| *v = Value::Array(vec![v.clone()]), Err(inv("malformed-field")));

    {
        let mut e = fx.send_message("exp-eq-ts");
        e.exp = e.ts;
        cs.add("exp-equals-ts", &["ENV-011"], "exp = ts.", dr(fx), txt(&fx.sign(&e)), Err(inv("exp-not-after-ts")));
        let mut e = fx.send_message("ttl-over");
        e.exp = e.ts + MAX_TTL + SEC;
        cs.add("ttl-over-max", &["ENV-011"], "exp − ts = MAX_TTL + 1 s.", dr(fx), txt(&fx.sign(&e)), Err(inv("ttl-too-long")));
    }
    {
        let e = fx.send_message("expired");
        let mut rx = dr(fx);
        rx.now = e.exp + SKEW + SEC;
        cs.add("expired", &["ENV-300"], "now = exp + SKEW + 1 s.", rx, txt(&fx.sign(&e)), Err(rj("EnvelopeExpired", "expired")));
        let e = fx.send_message("future");
        let mut rx = dr(fx);
        rx.now = e.ts - SKEW - 90 * SEC;
        cs.add("ts-in-future", &["ENV-301"], "ts = now + SKEW + 90 s: retryable, retryAfter = 90.", rx, txt(&fx.sign(&e)), Err(rj("EnvelopeNotYetValid", "ts-in-future")));
        let e = fx.send_message("watermark");
        let mut rx = dr(fx);
        rx.watermark = Some(e.exp + SKEW);
        cs.add("below-watermark", &["ENV-504"], "Fresh by the clock, but exp + SKEW ≤ the receiver's purge watermark.", rx, txt(&fx.sign(&e)), Err(rj("EnvelopeExpired", "below-watermark")));
    }
    {
        let mut e = fx.send_message("to-carol");
        e.to = "carol";
        cs.add("wrong-recipient", &["ENV-400"], "Validly signed for carol, delivered to a node that hosts only bob.", dr(fx), txt(&fx.sign(&e)), Err(inv("wrong-recipient")));
    }
    {
        let req = fx.send_message("base");
        let mut resp = fx.response_to(&req, "resp-no-irt");
        resp.ctx = Some(json!({"taskId": "task-0001", "contextId": "ctx-0001"}));
        let mut rx = dr(fx);
        rx.hosts = vec![&fx.alice];
        rx.now = resp.ts;
        cs.add("response-without-in-reply-to", &["ENV-031"], "A response without ctx.inReplyTo.", rx, txt(&fx.sign(&resp)), Err(inv("missing-field")));
    }
    {
        let mut e = fx.send_message("unknown-op");
        e.op = "FrobnicateTask";
        cs.add("op-unknown", &["ENV-022"], "op is neither an A2A method nor an extension URI#name.", dr(fx), txt(&fx.sign(&e)), Err(rj("UnsupportedOperationError", "unsupported-op")));
    }

    // --- signer form (validly signed, body in the wrong form)
    let form = |label: &str, f: &dyn Fn(&mut J)| {
        let mut e = fx.send_message(label);
        f(&mut e.body);
        fx.sign(&e)
    };
    cs.add("signer-form-enum-number", &["ENV-121"], "role as the enum number 1 instead of \"ROLE_USER\".", dr(fx),
        txt(&form("sf-enum", &|b| b["message"]["role"] = json!(1))), Err(inv("signer-form")));
    cs.add("signer-form-proto-field-name", &["ENV-121"], "message_id (proto name) instead of messageId.", dr(fx),
        txt(&form("sf-name", &|b| {
            let id = b["message"]["messageId"].clone();
            let m = b["message"].as_object_mut().unwrap();
            m.shift_remove("messageId");
            m.insert("message_id".into(), id);
        })), Err(inv("signer-form")));
    cs.add("signer-form-explicit-default", &["ENV-121"], "tenant present with its default value \"\".", dr(fx),
        txt(&form("sf-default", &|b| b["tenant"] = json!(""))), Err(inv("signer-form")));
    cs.add("signer-form-unspecified-enum", &["ENV-121"], "role = ROLE_UNSPECIFIED (the default) emitted explicitly.", dr(fx),
        txt(&form("sf-unspec", &|b| b["message"]["role"] = json!("ROLE_UNSPECIFIED"))), Err(inv("signer-form")));
    cs.add("signer-form-bytes-unpadded", &["ENV-121"], "Part.raw as base64 without padding.", dr(fx),
        txt(&form("sf-bytes", &|b| b["message"]["parts"][0] = json!({"raw": "aGVsbG8", "mediaType": "text/plain"}))), Err(inv("signer-form")));

    // --- ctx and prov
    {
        let mut e = fx.send_message("ctx-mismatch");
        e.ctx = Some(json!({"contextId": "ctx-0002"}));
        cs.add("ctx-mismatch", &["ENV-030"], "ctx.contextId differs from body.message.contextId.", dr(fx), txt(&fx.sign(&e)), Err(inv("ctx-mismatch")));
    }
    {
        let mut e = fx.send_message("two-parts-one-taint");
        e.body["message"]["parts"] = json!([{"text": "part one"}, {"text": "part two"}]);
        cs.add("prov-missing-entry", &["ENV-050"], "Two Parts, taint for only the first.", dr(fx), txt(&fx.sign(&e)), Err(inv("missing-taint")));
        let mut e = fx.send_message("no-prov");
        e.prov = None;
        cs.add("prov-absent", &["ENV-050"], "A body with a Part and no prov member.", dr(fx), txt(&fx.sign(&e)), Err(inv("missing-taint")));
        let mut e = fx.send_message("prov-no-taint");
        e.prov = Some(json!({"parts": {"/message/parts/0": {"contentKind": "text"}}}));
        cs.add("prov-entry-without-taint", &["ENV-050"], "A prov entry without taint.", dr(fx), txt(&fx.sign(&e)), Err(inv("missing-taint")));
        let mut e = fx.send_message("prov-dangling");
        e.prov = Some(json!({"parts": {"/message/parts/0": fx.taint_a(), "/message/parts/5": fx.taint_a()}}));
        cs.add("prov-pointer-not-a-part", &["ENV-051"], "A prov key that does not resolve to a Part.", dr(fx), txt(&fx.sign(&e)), Err(inv("bad-prov")));
        let mut e = fx.send_message("prov-empty-owners");
        e.prov = Some(json!({"parts": {"/message/parts/0": {"taint": {"owners": [], "unverified": false}}}}));
        cs.add("prov-empty-owners", &["ENV-051"], "taint.owners is empty.", dr(fx), txt(&fx.sign(&e)), Err(inv("bad-prov")));
    }

    // --- parser hardening (text-level edits; the signature is never reached)
    let gt = compact(&good);
    let to_member = format!("\"to\":\"{}\"", fx.bob.id());
    let text = |cs: &mut Cases, id: &str, desc: &str, t: String, why: Reject| {
        let rx = dr(fx);
        cs.add(id, &["ENV-100"], desc, rx, Input::Text(t), Err(why));
    };
    text(&mut cs, "duplicate-key-header", "Two `to` members (carol, then bob). Parsers that keep the first or the last would disagree.",
        gt.replacen(&to_member, &format!("\"to\":\"{}\",{}", fx.carol.id(), to_member), 1), inv("duplicate-key"));
    text(&mut cs, "duplicate-key-after-unescape", "`role` and `\\u0072ole` are the same name once unescaped.",
        gt.replacen("\"role\":\"ROLE_USER\"", "\"role\":\"ROLE_USER\",\"\\u0072ole\":\"ROLE_AGENT\"", 1), inv("duplicate-key"));
    text(&mut cs, "unsafe-integer-in-body", "A plain integer 9007199254740993 (2^53 + 1) in body metadata.",
        gt.replacen("\"message\":{", "\"metadata\":{\"n\":9007199254740993},\"message\":{", 1), inv("unsafe-integer"));
    text(&mut cs, "unsafe-integer-exponent-in-body", "1e16 in body metadata: an unsafe integral value, whatever its spelling.",
        gt.replacen("\"message\":{", "\"metadata\":{\"n\":1e16},\"message\":{", 1), inv("unsafe-integer"));
    text(&mut cs, "number-overflow-in-body", "1e400 in body metadata.",
        gt.replacen("\"message\":{", "\"metadata\":{\"n\":1e400},\"message\":{", 1), inv("number-out-of-range"));
    text(&mut cs, "lone-surrogate", "A lone high-surrogate escape in a Part's text.",
        gt.replacen("main.", "main.\\ud800", 1), inv("invalid-unicode"));
    text(&mut cs, "trailing-comma", "A trailing comma after the last member.", format!("{},}}", &gt[..gt.len() - 1]), inv("not-json"));
    {
        let mut b = gt.clone().into_bytes();
        let pos = gt.find("main.").unwrap();
        b[pos] = 0xff;
        let rx = dr(fx);
        cs.add("invalid-utf8", &["ENV-100"], "A byte 0xFF inside a string (given as input_hex).", rx, Input::Hex(b), Err(inv("invalid-unicode")));
    }
    {
        let deep = format!("{}1{}", "[".repeat(70), "]".repeat(70));
        let t = gt.replacen("\"message\":{", &format!("\"metadata\":{{\"deep\":{deep}}},\"message\":{{"), 1);
        let rx = dr(fx);
        cs.add("too-deep", &["ENV-101"], "Body metadata nested 70 arrays deep (over MAX_DEPTH = 64).", rx, Input::Text(t), Err(inv("too-deep")));
    }

    file("envelope-verify", "Receive one envelope and verify it (spec §9 steps 1–7).", cs.out)
}

// ---------------------------------------------------------------------------------------------
// header-only.json (ENV-213)

pub fn header_only(fx: &Fx) -> J {
    let good = fx.sign(&fx.send_message("base"));
    let mut e = fx.send_message("hdr-unknown");
    e.extra.push(("x-future", json!(true)));
    let with_unknown = fx.sign(&e);
    let mut out = vec![];
    let mut add = |id: &str, desc: &str, v: Value, valid: bool| {
        let v = v.without(&["body"]);
        let si = verify::signing_input(&v.without(&["sig"]));
        let from = parse_agent_id(v.get("from").unwrap().as_str().unwrap()).unwrap();
        let got = verify::check_signature(&from, &sig_bytes(&v), &si);
        assert_eq!(got.is_ok(), valid, "{id}");
        let expect = if valid { json!({"result": "accept"}) } else { json!({"result": "reject", "error": err_json(&sinv("verification-failed"), None)}) };
        out.push(json!({"id": id, "requirements": ["ENV-213"], "description": desc, "input": compact(&v), "expect": expect}));
    };
    add("header-only-valid", "A stored signed header (body redacted) still verifies.", good, true);
    add("header-only-with-unknown-member", "A stored header that kept an unknown member verifies.", with_unknown.clone(), true);
    let mut stripped = with_unknown;
    remove(&mut stripped, "x-future");
    add("header-only-unknown-member-dropped", "A store that dropped the unknown member can no longer verify the header.", stripped, false);
    file("header-signature", "Verify only the signature of a stored signed header (no body): steps 3–4 on the envelope without `body`.", out)
}

// ---------------------------------------------------------------------------------------------
// freshness.json

pub fn freshness(fx: &Fx) -> J {
    let t = fx.t0;
    let mut out = vec![];
    let mut add = |id: &str, reqs: &[&str], desc: &str, now: Nanos, ts: Nanos, exp: Nanos, w: Option<Nanos>, expect: Result<(), Reject>| {
        let got = verify::check_freshness(now, ts, exp, w);
        assert_eq!(got, expect, "{id}");
        let mut c = Map::new();
        c.insert("id".into(), json!(id));
        c.insert("requirements".into(), json!(reqs));
        c.insert("description".into(), json!(desc));
        c.insert("now".into(), json!(fmt_ts(now)));
        c.insert("ts".into(), json!(fmt_ts(ts)));
        c.insert("exp".into(), json!(fmt_ts(exp)));
        if let Some(w) = w {
            c.insert("watermark".into(), json!(fmt_ts(w)));
        }
        let ex = match &expect {
            Ok(()) => json!({"result": "accept"}),
            Err(r) => {
                let ra = (r.typ == "EnvelopeNotYetValid").then(|| ((ts - SKEW - now + SEC - 1) / SEC) as i64);
                json!({"result": "reject", "error": err_json(r, ra)})
            }
        };
        c.insert("expect".into(), ex);
        out.push(J::Object(c));
    };
    let h = 3600 * SEC;
    let ms = SEC / 1000;
    add("fresh", &["ENV-300"], "Just sent.", t + SEC, t, t + h, None, Ok(()));
    add("mailbox-dwell", &["ENV-302"], "Waited 3 h in a mailbox; exp is 4 h after ts.", t + 3 * h, t, t + 4 * h, None, Ok(()));
    add("at-exp", &["ENV-300"], "now = exp.", t + h, t, t + h, None, Ok(()));
    add("at-exp-plus-skew", &["ENV-300", "ENV-303"], "now = exp + SKEW: inclusive bound.", t + h + SKEW, t, t + h, None, Ok(()));
    add("past-exp-plus-skew-1ms", &["ENV-300", "ENV-303"], "now = exp + SKEW + 1 ms: full precision.", t + h + SKEW + ms, t, t + h, None, Err(rj("EnvelopeExpired", "expired")));
    add("past-exp-plus-skew-1d", &["ENV-300"], "A day late.", t + 25 * h, t, t + h, None, Err(rj("EnvelopeExpired", "expired")));
    add("ts-at-now-plus-skew", &["ENV-301", "ENV-303"], "Sender clock ahead by exactly SKEW.", t, t + SKEW, t + h, None, Ok(()));
    add("ts-past-now-plus-skew-1ms", &["ENV-301", "ENV-303"], "Sender clock ahead by SKEW + 1 ms: retryAfter rounds up to 1 s.", t, t + SKEW + ms, t + h, None, Err(rj("EnvelopeNotYetValid", "ts-in-future")));
    add("ts-far-future", &["ENV-301"], "Sender clock ahead by 1 h.", t, t + h, t + 2 * h, None, Err(rj("EnvelopeNotYetValid", "ts-in-future")));
    add("old-ts-long-ttl", &["ENV-302"], "ts 6 days ago, exp tomorrow.", t, t - 144 * h, t + 24 * h, None, Ok(()));
    add("exp-equals-ts", &["ENV-011"], "exp = ts.", t, t, t, None, Err(inv("exp-not-after-ts")));
    add("exp-before-ts", &["ENV-011"], "exp before ts.", t, t, t - SEC, None, Err(inv("exp-not-after-ts")));
    add("ttl-max", &["ENV-011", "ENV-900"], "exp − ts = MAX_TTL.", t, t, t + MAX_TTL, None, Ok(()));
    add("ttl-over-max", &["ENV-011", "ENV-900"], "exp − ts = MAX_TTL + 1 ms.", t, t, t + MAX_TTL + ms, None, Err(inv("ttl-too-long")));
    add("watermark-blocks-rollback", &["ENV-504"], "The receiver's clock stepped back 2 h; the envelope looks fresh, but its exp + SKEW is at or below the watermark.",
        t, t - h, t + 600 * SEC, Some(t + 600 * SEC + SKEW), Err(rj("EnvelopeExpired", "below-watermark")));
    add("watermark-below", &["ENV-504"], "exp + SKEW is above the watermark: accepted.", t, t, t + h, Some(t + h), Ok(()));
    file("freshness", "Pure function (now, ts, exp, watermark?) → accept or error (spec §6, ENV-504). Constants as in `constants`.", out)
}

// ---------------------------------------------------------------------------------------------
// replay.json

struct Scenario<'a> {
    #[allow(dead_code)]
    fx: &'a Fx,
    node: verify::Node,
    envs: Map<String, J>,
    steps: Vec<J>,
    raw: std::collections::HashMap<String, String>,
    start: Nanos,
}

impl<'a> Scenario<'a> {
    fn new(fx: &'a Fx, hosts: &[&Key]) -> Self {
        let start = fx.t0 - 86400 * SEC;
        Scenario { fx, node: verify::Node::new(hosts.iter().map(|k| k.pk).collect(), start), envs: Map::new(), steps: vec![], raw: Default::default(), start }
    }
    fn env(&mut self, name: &str, text: String) {
        self.envs.insert(name.into(), json!(text));
        self.raw.insert(name.into(), text);
    }
    fn sent(&mut self, name: &str) {
        let v = json::parse(self.raw[name].as_bytes()).unwrap();
        let g = |k: &str| v.get(k).unwrap().as_str().unwrap().to_string();
        self.node.record_sent(parse_agent_id(&g("from")).unwrap(), parse_agent_id(&g("to")).unwrap(), &g("id"));
        self.steps.push(json!({"action": "sent", "envelope": name}));
    }
    fn purge(&mut self, at: Nanos) {
        self.node.purge(at);
        self.steps.push(json!({"action": "purge", "now": fmt_ts(at)}));
    }
    fn recv(&mut self, name: &str, now: Nanos, app: &str, auth: bool, expect: Outcome) {
        let got = self.node.receive(self.raw[name].as_bytes(), now, app, auth);
        assert_eq!(got, expect, "step {} ({name})", self.steps.len());
        let mut st = Map::new();
        st.insert("action".into(), json!("receive"));
        st.insert("envelope".into(), json!(name));
        st.insert("now".into(), json!(fmt_ts(now)));
        st.insert("transport".into(), json!(if auth { "authenticated" } else { "unauthenticated" }));
        if app != "ok" {
            st.insert("app_result".into(), json!(app));
        }
        let ex = match &expect {
            Outcome::Process { entry } => json!({"outcome": "process", "dedupe_entry": entry}),
            Outcome::Deliver => json!({"outcome": "deliver"}),
            Outcome::Duplicate { answer } => json!({"outcome": "duplicate", "answer": answer}),
            Outcome::DropDuplicate => json!({"outcome": "drop-duplicate"}),
            Outcome::Discard => json!({"outcome": "discard", "reason": "unsolicited"}),
            Outcome::Reject(r) => json!({"outcome": "reject", "error": err_json(r, None)}),
        };
        st.insert("expect".into(), ex);
        self.steps.push(J::Object(st));
    }
    fn finish(self, id: &str, reqs: &[&str], desc: &str) -> J {
        json!({
            "id": id, "requirements": reqs, "description": desc,
            "receiver": {"hosts": self.node.hosts.iter().map(agent_id).collect::<Vec<_>>(), "initial_watermark": fmt_ts(self.start)},
            "envelopes": self.envs, "steps": self.steps
        })
    }
}

pub fn replay(fx: &Fx) -> J {
    let t = fx.t0;
    let mut out = vec![];
    let e1 = fx.send_message("replay-e1");
    let e1v = fx.sign(&e1);
    let e1t = compact(&e1v);
    let fresh = t + 10 * SEC;

    {
        let mut sc = Scenario::new(fx, &[&fx.bob]);
        sc.env("E1", e1t.clone());
        sc.recv("E1", fresh, "ok", true, Outcome::Process { entry: true });
        sc.recv("E1", fresh + 5 * SEC, "ok", true, Outcome::Duplicate { answer: "stored" });
        out.push(sc.finish("lost-ack-retry", &["ENV-500", "ENV-501", "ENV-510", "ENV-520", "ENV-530"],
            "The ack is lost and the sender's outbox resends the identical envelope: processed once, the retry gets the stored response."));
    }
    {
        let mut sc = Scenario::new(fx, &[&fx.bob]);
        sc.env("E1", e1t.clone());
        sc.env("E1-reserialised", to_text(&e1v, true));
        sc.recv("E1", fresh, "ok", true, Outcome::Process { entry: true });
        sc.recv("E1-reserialised", fresh + SEC, "ok", true, Outcome::Duplicate { answer: "stored" });
        out.push(sc.finish("duplicate-reserialised", &["ENV-511"], "A duplicate re-serialised by an intermediary is still a duplicate (header digest over the canonical form)."));
    }
    {
        let mut sc = Scenario::new(fx, &[&fx.bob]);
        sc.env("E1", e1t.clone());
        sc.recv("E1", fresh, "ok", true, Outcome::Process { entry: true });
        sc.recv("E1", fresh + SEC, "ok", false, Outcome::Duplicate { answer: "ack" });
        out.push(sc.finish("duplicate-unauthenticated-transport", &["ENV-531"],
            "A third party replays a captured envelope over a connection not authenticated as alice's node: it gets only the duplicate ack."));
    }
    {
        let mut sc = Scenario::new(fx, &[&fx.bob]);
        let mut e1b = e1.clone();
        e1b.body["message"]["parts"][0]["text"] = json!("Run the test suite on branch dev.");
        sc.env("E1", e1t.clone());
        sc.env("E1-other-body", compact(&fx.sign(&e1b)));
        sc.recv("E1", fresh, "ok", true, Outcome::Process { entry: true });
        sc.recv("E1-other-body", fresh + SEC, "ok", true, Outcome::Reject(inv("id-reuse")));
        out.push(sc.finish("id-reuse", &["ENV-500", "ENV-510"], "alice signs a second, different envelope with the same id: rejected, not processed."));
    }
    {
        let mut sc = Scenario::new(fx, &[&fx.bob]);
        sc.env("E1", e1t.clone());
        sc.recv("E1", fresh, "ok", true, Outcome::Process { entry: true });
        sc.purge(e1.exp + SKEW);
        sc.recv("E1", e1.exp + SKEW, "ok", true, Outcome::Duplicate { answer: "stored" });
        sc.purge(e1.exp + SKEW + SEC);
        sc.recv("E1", e1.exp + SKEW + SEC, "ok", true, Outcome::Reject(rj("EnvelopeExpired", "expired")));
        out.push(sc.finish("horizon", &["ENV-502", "ENV-300"],
            "The entry survives a purge at exactly exp + SKEW and still deduplicates; one second later the entry may go and the envelope is expired."));
    }
    {
        let mut sc = Scenario::new(fx, &[&fx.bob]);
        sc.env("E1", e1t.clone());
        sc.recv("E1", fresh, "ok", true, Outcome::Process { entry: true });
        sc.purge(e1.exp + SKEW + 60 * SEC);
        sc.recv("E1", fresh, "ok", true, Outcome::Reject(rj("EnvelopeExpired", "below-watermark")));
        out.push(sc.finish("clock-rollback-after-purge", &["ENV-504", "ENV-502"],
            "After the entry is purged the receiver's clock steps back to before exp. The watermark still rejects the replay."));
    }
    {
        let mut sc = Scenario::new(fx, &[&fx.bob]);
        sc.env("E1", e1t.clone());
        sc.recv("E1", fresh, "retryable-error", true, Outcome::Process { entry: false });
        sc.recv("E1", fresh + 30 * SEC, "ok", true, Outcome::Process { entry: true });
        sc.recv("E1", fresh + 60 * SEC, "ok", true, Outcome::Duplicate { answer: "stored" });
        out.push(sc.finish("retryable-failure-no-entry", &["ENV-521", "ENV-520"],
            "Processing fails with a retryable error (e.g. MailboxFull): no entry, so the retry is processed as new."));
    }
    {
        let mut sc = Scenario::new(fx, &[&fx.bob]);
        sc.env("E1", e1t.clone());
        sc.recv("E1", fresh, "fatal-error", true, Outcome::Process { entry: true });
        sc.recv("E1", fresh + SEC, "ok", true, Outcome::Duplicate { answer: "stored" });
        out.push(sc.finish("fatal-failure-stored", &["ENV-520"], "A non-retryable processing error (e.g. CapabilityDenied) is stored and returned for the retry."));
    }
    {
        let mut sc = Scenario::new(fx, &[&fx.bob]);
        let bad = fx.sign_with(&e1, &fx.mallory.sk);
        sc.env("E1-bad-sig", compact(&bad));
        sc.env("E1", e1t.clone());
        sc.recv("E1-bad-sig", fresh, "ok", true, Outcome::Reject(sinv("verification-failed")));
        sc.recv("E1", fresh + SEC, "ok", true, Outcome::Process { entry: true });
        out.push(sc.finish("invalid-envelope-creates-no-entry", &["ENV-501", "ENV-600"],
            "A forged envelope with alice's id fails verification and must not poison the dedupe store: the genuine one is processed."));
    }
    {
        let mut sc = Scenario::new(fx, &[&fx.bob]);
        let mut e1m = e1.clone();
        e1m.from = "carol";
        e1m.to = "bob";
        sc.env("E1", e1t.clone());
        sc.env("E1-from-carol", compact(&fx.sign(&e1m)));
        sc.recv("E1", fresh, "ok", true, Outcome::Process { entry: true });
        sc.recv("E1-from-carol", fresh + SEC, "ok", true, Outcome::Process { entry: true });
        out.push(sc.finish("same-id-other-sender", &["ENV-510"], "The dedupe key includes the sender: the same id from carol is a different message."));
    }
    {
        // alice's node receives answers.
        let mut sc = Scenario::new(fx, &[&fx.alice]);
        let resp = fx.response_to(&e1, "replay-resp");
        let resp_t = compact(&fx.sign(&resp));
        let other_req = fx.send_message("replay-other");
        let stray = fx.response_to(&other_req, "replay-stray");
        let mut forged_from = resp.clone();
        forged_from.from = "carol";
        sc.env("E1", e1t.clone());
        sc.env("R1", resp_t);
        sc.env("R-unsolicited", compact(&fx.sign(&stray)));
        sc.env("R-from-carol", compact(&fx.sign(&forged_from)));
        let at = resp.ts + SEC;
        sc.recv("R1", at, "ok", true, Outcome::Discard);
        sc.sent("E1");
        sc.recv("R1", at, "ok", true, Outcome::Deliver);
        sc.recv("R1", at + SEC, "ok", true, Outcome::DropDuplicate);
        sc.recv("R-unsolicited", at, "ok", true, Outcome::Discard);
        sc.recv("R-from-carol", at, "ok", true, Outcome::Discard);
        out.push(sc.finish("answers", &["ENV-401", "ENV-402", "ENV-512"],
            "A response is delivered only if it answers an envelope the node sent (matching from, to and inReplyTo), at most once, and is never answered with an error."));
    }
    file("replay", "Stateful scenarios against one receiving node (spec §8). Steps run in order; `purge` removes entries with exp + SKEW < now and raises the watermark.", out)
}

// ---------------------------------------------------------------------------------------------
// jcs.json

pub fn jcs_cases() -> J {
    let mut out = vec![];
    let mut add = |id: &str, desc: &str, input: Input, expect: Result<&str, &'static str>| {
        let got = json::parse(&input.bytes()).map(|v| jcs(&v)).map_err(|e| e.reason());
        assert_eq!(got.as_ref().map(|s| s.as_str()).map_err(|e| *e), expect, "{id}");
        let mut c = Map::new();
        c.insert("id".into(), json!(id));
        let reqs: &[&str] = if expect.is_ok() { &["ENV-110", "ENV-111"] } else { &["ENV-100"] };
        let reqs: Vec<&str> = if id.starts_with("depth") { vec!["ENV-101"] } else { reqs.to_vec() };
        c.insert("requirements".into(), json!(reqs));
        c.insert("description".into(), json!(desc));
        input.write(&mut c);
        c.insert(
            "expect".into(),
            match expect {
                Ok(canon) => json!({"result": "canonical", "canonical": canon}),
                Err(reason) => json!({"result": "reject", "error": err_json(&inv(reason), None)}),
            },
        );
        out.push(J::Object(c));
    };
    let t = |s: &str| Input::Text(s.to_string());
    add("rfc8785-sorting", "RFC 8785 §3.2.3: keys sorted by UTF-16 code units.",
        t(r#"{"\u20ac":"Euro Sign","\r":"Carriage Return","\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\ud83d\ude00":"Emoji: Grinning Face","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis"}"#),
        Ok("{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u{80}\":\"Control\",\"ö\":\"Latin Small Letter O With Diaeresis\",\"€\":\"Euro Sign\",\"😀\":\"Emoji: Grinning Face\",\"\u{fb33}\":\"Hebrew Letter Dalet With Dagesh\"}"));
    add("whitespace-and-nesting", "Insignificant whitespace removed, nested objects sorted.",
        t("{ \"b\" : [ 1 , { \"z\":true, \"a\":null } ] ,\n\t\"a\" : { } , \"c\":[ ] }"), Ok(r#"{"a":{},"b":[1,{"a":null,"z":true}],"c":[]}"#));
    add("numbers-es6", "Numbers serialised as ECMAScript Number.prototype.toString.",
        t("[1.0, -0, 1E-7, 0.000001, 123.4560, 5e-324, 9007199254740991, -9007199254740991, 9.007199254740991e15, 0.1, 100e-2, 2e0, 0.30000000000000004, 4.5e-10, 1e15, 123456789012345.67]"),
        Ok("[1,0,1e-7,0.000001,123.456,5e-324,9007199254740991,-9007199254740991,9007199254740991,0.1,1,2,0.30000000000000004,4.5e-10,1000000000000000,123456789012345.67]"));
    add("number-safe-after-rounding", "9007199254740991.4 rounds to the double 2^53 − 1, which is safe.", t("[9007199254740991.4]"), Ok("[9007199254740991]"));
    add("unsafe-integer-with-fraction", "9007199254740993.0 is written with a fraction but its value (the double 2^53) is integral and unsafe. The rule is on the value, not the spelling.",
        t("[9007199254740993.0]"), Err("unsafe-integer"));
    add("unsafe-integer-exponent", "1e16 is an unsafe integral value written with an exponent. Its JCS form 10000000000000000 would otherwise be rejected on re-parse.",
        t("[1e16]"), Err("unsafe-integer"));
    add("unsafe-integer-large-double", "1e21 and up: every double ≥ 2^53 is integral, so all are unsafe. Large numbers belong in strings.",
        t("[1.7976931348623157e308]"), Err("unsafe-integer"));
    add("number-underflow", "1e-400 underflows to 0 (only overflow is rejected).", t("[1e-400]"), Ok("[0]"));
    add("string-escapes", "Only \", \\ and control characters are escaped; \\/ and \\u0041 are unescaped; U+007F is emitted raw.",
        t(r#"["\u0041\u00e9\/\b\f\n\r\t\u001f\u007f\"\\"]"#), Ok("[\"Aé/\\b\\f\\n\\r\\t\\u001f\u{7f}\\\"\\\\\"]"));
    add("surrogate-pair", "An escaped surrogate pair and a raw emoji both become raw UTF-8.", t(r#"["\ud83d\ude80", "🚀"]"#), Ok("[\"🚀\",\"🚀\"]"));
    add("literals", "true, false, null.", t("[true,false,null]"), Ok("[true,false,null]"));
    add("depth-64", "64 nested arrays: at MAX_DEPTH, accepted.", Input::Text(format!("{}{}", "[".repeat(64), "]".repeat(64))), Ok(&format!("{}{}", "[".repeat(64), "]".repeat(64))));
    add("depth-65", "65 nested arrays: over MAX_DEPTH.", Input::Text(format!("{}{}", "[".repeat(65), "]".repeat(65))), Err("too-deep"));
    add("duplicate-key", "Two members named a.", t(r#"{"a":1,"a":2}"#), Err("duplicate-key"));
    add("duplicate-key-escaped", "\"a\" and \"\\u0061\" are the same name.", t(r#"{"a":1,"\u0061":2}"#), Err("duplicate-key"));
    add("duplicate-key-nested", "Duplicate inside a nested object.", t(r#"{"x":{"k":1,"k":1}}"#), Err("duplicate-key"));
    add("lone-high-surrogate", "\\ud800 not followed by a low surrogate.", t(r#"["\ud800x"]"#), Err("invalid-unicode"));
    add("lone-low-surrogate", "\\udc00 on its own.", t(r#"["\udc00"]"#), Err("invalid-unicode"));
    add("invalid-utf8", "Byte 0xC3 followed by an ASCII byte.", Input::Hex(b"[\"\xc3(\"]".to_vec()), Err("invalid-unicode"));
    add("unsafe-integer-positive", "2^53 written as a plain integer.", t("[9007199254740992]"), Err("unsafe-integer"));
    add("unsafe-integer-negative", "−2^53 written as a plain integer.", t("[-9007199254740992]"), Err("unsafe-integer"));
    add("number-overflow", "1e400 overflows a double.", t("[1e400]"), Err("number-out-of-range"));
    add("number-overflow-negative", "−1e400.", t("[-1e400]"), Err("number-out-of-range"));
    add("not-json-trailing-comma", "Trailing comma.", t("[1,]"), Err("not-json"));
    add("not-json-leading-zero", "Leading zero.", t("[01]"), Err("not-json"));
    add("not-json-nan", "NaN is not JSON.", t("[NaN]"), Err("not-json"));
    add("not-json-single-quotes", "Single-quoted string.", t("['a']"), Err("not-json"));
    add("not-json-raw-control", "A raw tab inside a string.", t("[\"a\tb\"]"), Err("not-json"));
    file("jcs", "Parse as I-JSON (spec §4.1) and canonicalise with RFC 8785 (§4.2).", out)
}

// ---------------------------------------------------------------------------------------------

pub fn keys(fx: &Fx) -> J {
    let mut m = Map::new();
    for k in fx.keys() {
        let role = match k.name {
            "alice" => "agent, owner A, node alpha (usual sender)",
            "bob" => "agent, owner B, node beta (usual receiver)",
            "carol" => "agent, owner B, another node",
            "mallory" => "attacker",
            "owner-a" => "owner A root key (taint owner)",
            "owner-b" => "owner B root key",
            _ => unreachable!(),
        };
        let mut e = Map::new();
        e.insert("role".into(), json!(role));
        e.insert("seed_hex".into(), json!(hex::encode(k.seed)));
        e.insert("public_hex".into(), json!(hex::encode(k.pk)));
        if k.name.starts_with("owner") {
            e.insert("did_key".into(), json!(did_key(&k.pk)));
        } else {
            e.insert("agent_id".into(), json!(k.id()));
        }
        m.insert(k.name.into(), J::Object(e));
    }
    json!({
        "description": "TEST KEYS ONLY. Never use them outside tests. seed = BLAKE3(\"argent-webway/test-vectors/envelope/v0/\" + name); Ed25519 key pair from the 32-byte seed (RFC 8032).",
        "keys": m
    })
}

fn file(kind: &str, desc: &str, cases: Vec<J>) -> J {
    json!({
        "spec": "spec/ext/envelope.md",
        "version": VERSION,
        "kind": kind,
        "description": desc,
        "generator": "conformance/tools/envelope-vectors",
        "constants": {"SKEW_SECONDS": 300, "MAX_TTL_SECONDS": 604800, "MAX_ENVELOPE_BYTES": 1048576, "MAX_DEPTH": 64},
        "cases": cases
    })
}

/// All files: (name, content).
pub fn all() -> Vec<(&'static str, J)> {
    let fx = Fx::new();
    vec![
        ("keys.json", keys(&fx)),
        ("jcs.json", jcs_cases()),
        ("envelopes.json", envelopes(&fx)),
        ("header-only.json", header_only(&fx)),
        ("freshness.json", freshness(&fx)),
        ("replay.json", replay(&fx)),
    ]
}
