//! Builds the audit/v0 test vectors from a small, deterministic scenario: beta's log (the receiver in M1),
//! alpha's log, a forked copy of beta's log, beta's next epoch, and a log with a bad stub signature.
//! Every case is run through the verifier in `audit.rs`, and generation panics if the verdict differs from
//! the one the case states.

use crate::audit::{self, *};
use crate::merkle::{self, H};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Map, Value};

pub fn key(name: &str) -> SigningKey {
    let seed = blake3::hash(format!("argent-webway audit/v0 test key: {name}").as_bytes());
    SigningKey::from_bytes(seed.as_bytes())
}

pub const KEY_NAMES: [&str; 6] = [
    "beta-node",
    "alpha-node",
    "planner",
    "tester",
    "alpha-owner",
    "mallory",
];

fn obj(v: Value) -> Map<String, Value> {
    v.as_object().unwrap().clone()
}

fn did_key(k: &SigningKey) -> String {
    let mut b = vec![0xed, 0x01];
    b.extend(k.verifying_key().as_bytes());
    format!("did:key:z{}", bs58::encode(&b).into_string())
}

fn nid(k: &SigningKey) -> String {
    node_id(&k.verifying_key())
}
fn aid(k: &SigningKey) -> String {
    agent_id(&k.verifying_key())
}

/// A signed envelope (envelope/v0 §5.1).
fn envelope(
    from: &SigningKey,
    to: &str,
    typ: &str,
    op: &str,
    id: &str,
    ts: &str,
    exp: &str,
    ctx: Value,
    body: Value,
    prov: Option<Value>,
) -> Value {
    let mut e = obj(json!({
        "v": ENVELOPE_V, "typ": typ, "op": op, "from": aid(from), "to": to, "id": id, "ts": ts, "exp": exp,
        "ctx": ctx, "body_hash": hash_str(blake3::hash(&jcs(&body)).as_bytes()),
    }));
    if let Some(p) = prov {
        e.insert("prov".into(), p);
    }
    let sig = from.sign(&envelope_signing_input(&e));
    e.insert("sig".into(), json!(URL_SAFE_NO_PAD.encode(sig.to_bytes())));
    e.insert("body".into(), body);
    Value::Object(e)
}

fn stub(env: &Value) -> Map<String, Value> {
    let mut s = env.as_object().unwrap().clone();
    s.remove("body");
    s
}

pub struct Log {
    pub entries: Vec<Value>,
    pub leaves: Vec<H>,
    node: SigningKey,
    epoch: u64,
}

impl Log {
    fn new(node: &SigningKey, epoch: u64) -> Self {
        Log {
            entries: vec![],
            leaves: vec![],
            node: node.clone(),
            epoch,
        }
    }
    fn append(&mut self, time: &str, ty: &str, parties: Option<Value>, data: Value) -> usize {
        let i = self.entries.len();
        let mut e =
            obj(json!({"v": ENTRY_V, "log": nid(&self.node), "epoch": self.epoch, "index": i}));
        if i > 0 {
            e.insert("prev".into(), json!(hash_str(&self.leaves[i - 1])));
        }
        e.insert("time".into(), json!(time));
        e.insert("type".into(), json!(ty));
        if let Some(p) = parties {
            e.insert("parties".into(), p);
        }
        e.insert("data".into(), data);
        let e = Value::Object(e);
        self.leaves.push(audit::entry_hash(&e));
        self.entries.push(e);
        i
    }
    fn envelope_entry(&mut self, time: &str, ty: &str, env: &Value, extra: Value) -> usize {
        let s = stub(env);
        let mut data = obj(extra);
        data.insert("hd".into(), json!(header_digest(&s)));
        data.insert("stub".into(), Value::Object(s.clone()));
        self.append(
            time,
            ty,
            Some(json!([s["from"], s["to"]])),
            Value::Object(data),
        )
    }
    /// The Merkle tree over the first `size` entries (leaf value = JCS(entry), leaf hash = entry hash).
    fn tree(&self, size: usize) -> merkle::Tree {
        merkle::tree(self.entries[..size].iter().map(jcs))
    }
    pub fn root(&self, size: usize) -> H {
        merkle::root(&self.tree(size))
    }
    fn checkpoint(&self, size: usize, time: &str) -> Value {
        let mut c = obj(
            json!({"v": CHECKPOINT_V, "log": nid(&self.node), "epoch": self.epoch, "size": size,
            "root": hash_str(&self.root(size)), "time": time}),
        );
        sign_obj(&self.node, CHECKPOINT_V, &mut c);
        Value::Object(c)
    }
    fn receipt(&self, index: usize) -> Value {
        let e = &self.entries[index];
        let s = &e["data"]["stub"];
        let mut r = obj(
            json!({"v": RECEIPT_V, "log": nid(&self.node), "epoch": self.epoch, "index": index,
            "entry": hash_str(&self.leaves[index]), "root": hash_str(&self.root(index + 1)), "time": e["time"],
            "env": e["data"]["hd"], "id": s["id"], "from": s["from"], "to": s["to"]}),
        );
        sign_obj(&self.node, RECEIPT_V, &mut r);
        Value::Object(r)
    }
    fn incl(&self, index: usize, size: usize) -> Value {
        hl(&merkle::path(&self.tree(size), index))
    }
    fn cons(&self, from: usize, to: usize) -> Value {
        hl(&merkle::consistency(&self.tree(to), from))
    }
}

fn hl(h: &[H]) -> Value {
    Value::Array(h.iter().map(|x| json!(hash_str(x))).collect())
}

pub struct World {
    pub beta: Log,
    pub alpha: Log,
    pub fork: Log,
    pub beta1: Log,
    pub badstub: Log,
    pub e1: Value,

    pub e3: Value,
}

const ID1: &str = "019a5d2e-7b40-7c3a-9d1e-0a1b2c3d4e5f";
const ID2: &str = "019a5d2e-7d10-7a01-8b2c-3d4e5f60718a";
const ID3: &str = "019a5d2f-0a00-7b11-9c22-d33e44f55a66";
const ID4: &str = "019a5d2f-1b00-7c22-a033-e44f55a66b77";

pub fn world() -> World {
    let (beta_node, alpha_node, planner, tester, alpha_owner, mallory) = (
        key("beta-node"),
        key("alpha-node"),
        key("planner"),
        key("tester"),
        key("alpha-owner"),
        key("mallory"),
    );
    let taint = |owner: &str| json!({"parts": {"/message/parts/0": {"taint": {"owners": [owner], "unverified": false}}}});
    let msg = |id: &str, text: &str| json!({"message": {"messageId": id, "role": "ROLE_USER", "parts": [{"text": text}]}});
    let ao = did_key(&alpha_owner);

    let e1 = envelope(
        &planner,
        &aid(&tester),
        "request",
        "SendMessage",
        ID1,
        "2026-11-07T12:00:00Z",
        "2026-11-07T13:00:00Z",
        json!({"contextId": "ctx-42"}),
        msg(ID1, "run the tests"),
        Some(taint(&ao)),
    );
    let e2 = envelope(
        &tester,
        &aid(&planner),
        "response",
        "SendMessage",
        ID2,
        "2026-11-07T12:00:01Z",
        "2026-11-07T13:00:00Z",
        json!({"inReplyTo": ID1, "taskId": "task-7", "contextId": "ctx-42"}),
        json!({"task": {"id": "task-7", "contextId": "ctx-42", "status": {"state": "TASK_STATE_SUBMITTED"}}}),
        None,
    );
    let e3 = envelope(
        &planner,
        &aid(&tester),
        "request",
        "GetTask",
        ID3,
        "2026-11-07T12:00:05Z",
        "2026-11-07T12:05:05Z",
        json!({"taskId": "task-7"}),
        json!({"id": "task-7"}),
        None,
    );
    // mallory claims to be planner: signed with mallory's key, from = planner. Logged as rejected.
    let forged = {
        let mut f = envelope(
            &mallory,
            &aid(&tester),
            "request",
            "CancelTask",
            ID4,
            "2026-11-07T12:00:06Z",
            "2026-11-07T12:05:06Z",
            json!({"taskId": "task-7"}),
            json!({"id": "task-7"}),
            None,
        );
        f["from"] = json!(aid(&planner));
        f
    };
    let (an, pl, te) = (nid(&alpha_node), aid(&planner), aid(&tester));

    // alpha's log
    let mut alpha = Log::new(&alpha_node, 0);
    alpha.append(
        "2026-11-07T11:59:00Z",
        "log.genesis",
        None,
        json!({"node": an, "reason": "new", "profile": "webway-profile/0.1"}),
    );
    alpha.envelope_entry("2026-11-07T11:59:59.900Z", "envelope.sent", &e1, json!({}));
    alpha.envelope_entry(
        "2026-11-07T12:00:01.400Z",
        "envelope.received",
        &e2,
        json!({"via": nid(&beta_node), "outcome": "accepted"}),
    );

    // beta's log
    let build_beta = |variant: u8| {
        let mut l = Log::new(&beta_node, 0);
        l.append(
            "2026-11-07T12:00:00Z",
            "log.genesis",
            None,
            json!({"node": nid(&beta_node), "reason": "new", "profile": "webway-profile/0.1"}),
        );
        l.append(
            "2026-11-07T12:00:00Z",
            "node.event",
            None,
            json!({"event": "start"}),
        );
        l.envelope_entry(
            "2026-11-07T12:00:01.250Z",
            "envelope.received",
            &e1,
            json!({"via": an, "outcome": "accepted", "trust": {"/message/parts/0": "foreign"}}),
        );
        l.append("2026-11-07T12:00:01.251Z", "authz.decision", Some(json!([pl])), json!({"hd": l.entries[2]["data"]["hd"],
            "decision": "allow", "presenter": pl, "capability": "skill:run-tests", "operation": "SendMessage"}));
        l.append("2026-11-07T12:00:01.252Z", "task.transition", Some(json!([pl, te])),
            json!({"taskId": "task-7", "to": "TASK_STATE_SUBMITTED", "seq": 0, "cause": l.entries[2]["data"]["hd"]}));
        l.envelope_entry("2026-11-07T12:00:01.300Z", "envelope.sent", &e2, json!({}));
        l.append("2026-11-07T12:00:02Z", "task.transition", Some(json!([pl, te])),
            json!({"taskId": "task-7", "from": "TASK_STATE_SUBMITTED", "to": "TASK_STATE_WORKING", "seq": 1}));
        let outcome = if variant == 1 { "rejected" } else { "accepted" };
        let mut extra = json!({"via": an, "outcome": outcome});
        if variant == 1 {
            extra["error"] = json!({"type": "CapabilityDenied", "reason": "not-granted"});
        }
        l.envelope_entry("2026-11-07T12:00:05.010Z", "envelope.received", &e3, extra);
        l
    };
    let mut beta = build_beta(0);
    let fork = build_beta(1);
    beta.append(
        "2026-11-07T12:00:05.011Z",
        "node.anomaly",
        Some(json!([pl])),
        json!({"name": "trust-claim-ignored", "hd": beta.entries[7]["data"]["hd"]}),
    );
    beta.envelope_entry("2026-11-07T12:00:06.500Z", "envelope.received", &forged,
        json!({"via": an, "outcome": "rejected", "error": {"type": "SignatureInvalid", "reason": "verification-failed"}}));
    beta.append(
        "2026-11-07T12:00:07Z",
        "checkpoint.peer",
        None,
        json!({"checkpoint": alpha.checkpoint(3, "2026-11-07T12:00:02Z"), "result": "first"}),
    );
    beta.append(
        "2026-11-07T12:00:07Z",
        "example.custom",
        None,
        json!({"anything": [1, 2, 3]}),
    );
    let mut last = beta.entries.last().unwrap().as_object().unwrap().clone();
    last.insert("x-extra".into(), json!("unknown top-level member"));
    let n = beta.entries.len() - 1;
    beta.entries[n] = Value::Object(last);
    beta.leaves[n] = audit::entry_hash(&beta.entries[n]);

    // beta after data loss: epoch 1
    let mut beta1 = Log::new(&beta_node, 1);
    beta1.append("2026-11-08T09:00:00Z", "log.genesis", None, json!({"node": nid(&beta_node), "reason": "data-loss",
        "predecessor": {"epoch": 0, "size": 4, "root": hash_str(&beta.root(4))}, "profile": "webway-profile/0.1"}));

    // a log that claims to have accepted an envelope whose signature does not verify
    let mut badstub = Log::new(&beta_node, 0);
    badstub.append(
        "2026-11-07T12:00:00Z",
        "log.genesis",
        None,
        json!({"node": nid(&beta_node), "reason": "new", "profile": "webway-profile/0.1"}),
    );
    let mut tampered = e1.clone();
    tampered["exp"] = json!("2026-11-07T14:00:00Z");
    badstub.envelope_entry(
        "2026-11-07T12:00:01Z",
        "envelope.received",
        &tampered,
        json!({"via": an, "outcome": "accepted"}),
    );

    World {
        beta,
        alpha,
        fork,
        beta1,
        badstub,
        e1,
        e3,
    }
}

// ---------- vector files ----------

pub struct File {
    pub name: &'static str,
    pub kind: &'static str,
    pub description: &'static str,
    pub spec: &'static str,
    pub cases: Vec<Value>,
}

enum Want {
    Accept,
    Reject(&'static str),
}

fn case<F: Fn(&Value) -> audit::R<Value>>(
    f: &F,
    id: &str,
    desc: &str,
    reqs: &[&str],
    input: Value,
    want: Want,
) -> Value {
    let got = f(&input);
    let expect = match (&want, got) {
        (Want::Accept, Ok(out)) => {
            if out.is_null() {
                json!({"result": "accept"})
            } else {
                json!({"result": "accept", "output": out})
            }
        }
        (Want::Reject(n), Err(e)) if *n == e.name => json!({"result": "reject", "error": n}),
        (_, got) => panic!("case {id}: verifier says {got:?}"),
    };
    let mut reqs: Vec<&str> = reqs.to_vec();
    if matches!(want, Want::Reject(_)) {
        reqs.push("AUD-900"); // every rejection checks the result name of §12.2
    }
    json!({"id": id, "description": desc, "requirements": reqs, "input": input, "expect": expect})
}

fn set(v: &Value, path: &[&str], x: Value) -> Value {
    let mut v = v.clone();
    let mut cur = &mut v;
    for p in &path[..path.len() - 1] {
        cur = cur.get_mut(*p).unwrap();
    }
    cur.as_object_mut()
        .unwrap()
        .insert(path[path.len() - 1].into(), x);
    v
}
fn del(v: &Value, k: &str) -> Value {
    let mut v = v.clone();
    v.as_object_mut().unwrap().remove(k);
    v
}
fn resign(v: &Value, k: &SigningKey, ver: &str) -> Value {
    let mut o = v.as_object().unwrap().clone();
    sign_obj(k, ver, &mut o);
    Value::Object(o)
}
fn flip_sig(v: &Value) -> Value {
    let s = v["sig"].as_str().unwrap();
    let mut b = URL_SAFE_NO_PAD.decode(s).unwrap();
    b[10] ^= 0x01;
    set(v, &["sig"], json!(URL_SAFE_NO_PAD.encode(b)))
}

pub fn files() -> Vec<File> {
    let w = world();
    let b = &w.beta;
    let bk = key("beta-node");
    vec![
        entry_hash_file(&w),
        chain_file(&w),
        inclusion_file(b),
        consistency_file(b),
        checkpoint_file(&w, &bk),
        receipt_file(&w, &bk),
        compare_file(&w),
        evidence_file(&w, &bk),
    ]
}

fn entry_hash_file(w: &World) -> File {
    let f = |i: &Value| audit::check_entry(&i["entry"]).map(|h| json!({"hash": hash_str(&h)}));
    let b = &w.beta;
    let e2 = &b.entries[2];
    let e5 = &b.entries[5];
    let mut cases = vec![
        case(
            &f,
            "genesis",
            "Genesis entry at index 0, no prev",
            &["AUD-001"],
            json!({"entry": b.entries[0]}),
            Want::Accept,
        ),
        case(
            &f,
            "envelope-received",
            "Received envelope with stub, hd and parties",
            &["AUD-001", "AUD-020"],
            json!({"entry": e2}),
            Want::Accept,
        ),
        case(
            &f,
            "envelope-sent",
            "Sent envelope entry",
            &["AUD-001", "AUD-020"],
            json!({"entry": e5}),
            Want::Accept,
        ),
        case(
            &f,
            "rejected-with-forged-stub",
            "A rejected envelope's stub is a record, its signature is not checked here",
            &["AUD-001", "AUD-020"],
            json!({"entry": b.entries[9]}),
            Want::Accept,
        ),
        case(
            &f,
            "unknown-type-and-members",
            "Unknown type and unknown members are kept and hashed",
            &["AUD-003"],
            json!({"entry": b.entries[11]}),
            Want::Accept,
        ),
        case(
            &f,
            "missing-time",
            "time is required",
            &["AUD-001"],
            json!({"entry": del(e2, "time")}),
            Want::Reject("EntryInvalid"),
        ),
        case(
            &f,
            "missing-data",
            "data is required",
            &["AUD-001"],
            json!({"entry": del(e2, "data")}),
            Want::Reject("EntryInvalid"),
        ),
        case(
            &f,
            "fraction-in-data",
            "Numbers in entries are integers",
            &["AUD-001"],
            json!({"entry": set(e2, &["data", "detail"], json!(1.5))}),
            Want::Reject("EntryInvalid"),
        ),
        case(
            &f,
            "unsafe-integer-in-data",
            "Integers in entries are at most 2^53 - 1, at any depth",
            &["AUD-001"],
            json!({"entry": set(e2, &["data", "detail"], json!({"n": [9007199254740992u64]}))}),
            Want::Reject("EntryInvalid"),
        ),
        case(
            &f,
            "prev-at-genesis",
            "No prev at index 0",
            &["AUD-001"],
            json!({"entry": set(&b.entries[0], &["prev"], e2["prev"].clone())}),
            Want::Reject("EntryInvalid"),
        ),
        case(
            &f,
            "missing-prev",
            "prev is required at index > 0",
            &["AUD-001"],
            json!({"entry": del(e2, "prev")}),
            Want::Reject("EntryInvalid"),
        ),
        case(
            &f,
            "index-string",
            "index must be an integer",
            &["AUD-001"],
            json!({"entry": set(e2, &["index"], json!("2"))}),
            Want::Reject("EntryInvalid"),
        ),
        case(
            &f,
            "index-unsafe",
            "index above 2^53 - 1",
            &["AUD-001"],
            json!({"entry": set(e2, &["index"], json!(9007199254740992u64))}),
            Want::Reject("EntryInvalid"),
        ),
        case(
            &f,
            "prev-uppercase",
            "Hashes are lowercase hex",
            &["AUD-001"],
            json!({"entry": set(e2, &["prev"], json!(e2["prev"].as_str().unwrap().to_uppercase().replace("BLAKE3", "blake3")))}),
            Want::Reject("EntryInvalid"),
        ),
        case(
            &f,
            "time-offset",
            "Times are UTC with Z",
            &["AUD-001"],
            json!({"entry": set(e2, &["time"], json!("2026-11-07T13:00:01.250+01:00"))}),
            Want::Reject("EntryInvalid"),
        ),
        case(
            &f,
            "time-two-fraction-digits",
            "Fractions have 3, 6 or 9 digits",
            &["AUD-001"],
            json!({"entry": set(e2, &["time"], json!("2026-11-07T12:00:01.25Z"))}),
            Want::Reject("EntryInvalid"),
        ),
        case(
            &f,
            "type-uppercase",
            "type is lowercase area.name",
            &["AUD-001"],
            json!({"entry": set(e2, &["type"], json!("Envelope.Received"))}),
            Want::Reject("EntryInvalid"),
        ),
        case(
            &f,
            "type-no-area",
            "type needs a dot",
            &["AUD-001"],
            json!({"entry": set(e2, &["type"], json!("received"))}),
            Want::Reject("EntryInvalid"),
        ),
        case(
            &f,
            "log-is-agent",
            "log is a node identifier",
            &["AUD-001"],
            json!({"entry": set(e2, &["log"], e2["parties"][0].clone())}),
            Want::Reject("EntryInvalid"),
        ),
        case(
            &f,
            "data-not-object",
            "data is an object",
            &["AUD-001"],
            json!({"entry": set(e2, &["data"], json!([]))}),
            Want::Reject("EntryInvalid"),
        ),
        case(
            &f,
            "unknown-version",
            "v must be webway-audit-entry/0",
            &["AUD-002", "AUD-910"],
            json!({"entry": set(e2, &["v"], json!("webway-audit-entry/1"))}),
            Want::Reject("EntryInvalid"),
        ),
        case(
            &f,
            "hd-mismatch",
            "data.hd must be the stub's header digest",
            &["AUD-020"],
            json!({"entry": set(e2, &["data", "hd"], e5["data"]["hd"].clone())}),
            Want::Reject("EntryInvalid"),
        ),
        case(
            &f,
            "stub-changed",
            "A changed stub no longer matches hd",
            &["AUD-020"],
            json!({"entry": set(e2, &["data", "stub", "exp"], json!("2026-11-07T14:00:00Z"))}),
            Want::Reject("EntryInvalid"),
        ),
        case(
            &f,
            "parties-mismatch",
            "parties must be [from, to] of the stub",
            &["AUD-020"],
            json!({"entry": set(e2, &["parties"], json!([e2["parties"][1], e2["parties"][0]]))}),
            Want::Reject("EntryInvalid"),
        ),
    ];
    // exact-hash check: the hash is BLAKE3(0x00 || JCS(entry)), computed independently here
    let h0 = blake3::Hasher::new()
        .update(&[0])
        .update(&jcs(&b.entries[0]))
        .finalize();
    assert_eq!(
        cases[0]["expect"]["output"]["hash"],
        json!(hash_str(h0.as_bytes()))
    );
    cases.retain(|_| true);
    File { name: "entry-hash", kind: "audit/entry-hash", spec: "ext/audit.md#4-entries", cases,
        description: "Entry well-formedness and entry hash. Input {\"entry\": E}. Accept: {\"hash\": entry hash}. Reject: EntryInvalid." }
}

fn chain_file(w: &World) -> File {
    let f = |i: &Value| audit::verify_chain(i["entries"].as_array().unwrap());
    let b = &w.beta;
    let all = b.entries.clone();
    let mut swapped = all.clone();
    swapped.swap(3, 4);
    let mut edited = all.clone();
    edited[3] = set(&edited[3], &["data", "decision"], json!("deny"));
    let mut gap = all.clone();
    gap.remove(4);
    let mut epoch = all.clone();
    epoch[5] = set(&epoch[5], &["epoch"], json!(1));
    let mut logm = all.clone();
    logm[5] = set(&logm[5], &["log"], w.alpha.entries[0]["log"].clone());
    let mut timed = all[..4].to_vec();
    timed[3] = set(&timed[3], &["time"], json!("2026-11-07T12:00:01.249Z"));
    let mut bad = all[..4].to_vec();
    bad[3] = del(&bad[3], "time");
    let cases = vec![
        case(
            &f,
            "beta-log",
            "beta's whole log: 12 entries, equal times, unknown type at the end",
            &["AUD-100", "AUD-101", "AUD-102", "AUD-110", "AUD-003"],
            json!({"entries": all}),
            Want::Accept,
        ),
        case(
            &f,
            "genesis-only",
            "A log of size 1: root is the genesis entry hash",
            &["AUD-100", "AUD-110"],
            json!({"entries": [all[0]]}),
            Want::Accept,
        ),
        case(
            &f,
            "alpha-log",
            "alpha's log of 3 entries",
            &["AUD-100", "AUD-101", "AUD-110"],
            json!({"entries": w.alpha.entries}),
            Want::Accept,
        ),
        case(
            &f,
            "empty",
            "No entries",
            &["AUD-100"],
            json!({"entries": []}),
            Want::Reject("ChainBroken"),
        ),
        case(
            &f,
            "no-genesis",
            "Starts at index 1",
            &["AUD-100"],
            json!({"entries": all[1..4]}),
            Want::Reject("ChainBroken"),
        ),
        case(
            &f,
            "gap",
            "Entry 4 removed",
            &["AUD-100", "AUD-101"],
            json!({"entries": gap}),
            Want::Reject("ChainBroken"),
        ),
        case(
            &f,
            "swapped",
            "Entries 3 and 4 swapped",
            &["AUD-100", "AUD-101"],
            json!({"entries": swapped}),
            Want::Reject("ChainBroken"),
        ),
        case(
            &f,
            "edited",
            "Entry 3 edited after the fact: entry 4's prev no longer matches",
            &["AUD-101"],
            json!({"entries": edited}),
            Want::Reject("ChainBroken"),
        ),
        case(
            &f,
            "epoch-mismatch",
            "Entry 5 claims another epoch",
            &["AUD-100"],
            json!({"entries": epoch}),
            Want::Reject("ChainBroken"),
        ),
        case(
            &f,
            "log-mismatch",
            "Entry 5 claims another log",
            &["AUD-100"],
            json!({"entries": logm}),
            Want::Reject("ChainBroken"),
        ),
        case(
            &f,
            "time-decreased",
            "Entry 3 is 1 ms earlier than entry 2",
            &["AUD-102"],
            json!({"entries": timed}),
            Want::Reject("ChainBroken"),
        ),
        case(
            &f,
            "malformed-entry",
            "A malformed entry inside the chain",
            &["AUD-001"],
            json!({"entries": bad}),
            Want::Reject("EntryInvalid"),
        ),
    ];
    // independent check of the root of the full log
    assert_eq!(
        cases[0]["expect"]["output"]["root"],
        json!(hash_str(&b.root(b.entries.len())))
    );
    File { name: "chain", kind: "audit/chain", spec: "ext/audit.md#5-hash-chain-and-merkle-tree", cases,
        description: "Verify a whole log from index 0. Input {\"entries\": [E...]}. Accept: {\"log\", \"epoch\", \"size\", \"root\", \"head\"} (head = last entry hash). Reject: ChainBroken or EntryInvalid." }
}

fn inclusion_file(b: &Log) -> File {
    let f = |i: &Value| {
        audit::verify_inclusion(&i["index"], &i["size"], &i["leaf"], &i["root"], &i["proof"])
            .map(|_| Value::Null)
    };
    let inp = |i: usize, n: usize| json!({"index": i, "size": n, "leaf": hash_str(&b.leaves[i]), "root": hash_str(&b.root(n)), "proof": b.incl(i, n)});
    let mut cases = vec![];
    for (i, n) in [
        (0, 1),
        (0, 12),
        (2, 12),
        (7, 12),
        (11, 12),
        (3, 4),
        (2, 3),
        (4, 5),
        (8, 9),
    ] {
        cases.push(case(
            &f,
            &format!("index-{i}-size-{n}"),
            &format!("Entry {i} in the tree of size {n}"),
            &["AUD-120"],
            inp(i, n),
            Want::Accept,
        ));
    }
    let base = inp(7, 12);
    let p = base["proof"].as_array().unwrap().clone();
    let mut longer = p.clone();
    longer.push(base["root"].clone());
    let too_many: Vec<Value> = std::iter::repeat_n(base["root"].clone(), 129).collect();
    cases.extend([
        case(
            &f,
            "wrong-leaf",
            "Proof for entry 7 with entry 6's hash",
            &["AUD-120"],
            set(&base, &["leaf"], json!(hash_str(&b.leaves[6]))),
            Want::Reject("ProofInvalid"),
        ),
        case(
            &f,
            "wrong-index",
            "Proof for entry 7 claimed for index 6",
            &["AUD-120"],
            set(&base, &["index"], json!(6)),
            Want::Reject("ProofInvalid"),
        ),
        case(
            &f,
            "wrong-size",
            "Proof for size 12 checked against size 8 (a different path shape)",
            &["AUD-120"],
            set(&base, &["size"], json!(8)),
            Want::Reject("ProofInvalid"),
        ),
        case(
            &f,
            "wrong-root",
            "Root of size 11",
            &["AUD-120"],
            set(&base, &["root"], json!(hash_str(&b.root(11)))),
            Want::Reject("ProofInvalid"),
        ),
        case(
            &f,
            "truncated",
            "Last proof hash missing",
            &["AUD-120"],
            set(&base, &["proof"], json!(p[..p.len() - 1])),
            Want::Reject("ProofInvalid"),
        ),
        case(
            &f,
            "extra-hash",
            "One hash too many",
            &["AUD-120"],
            set(&base, &["proof"], json!(longer)),
            Want::Reject("ProofInvalid"),
        ),
        case(
            &f,
            "too-many-hashes",
            "More than MAX_PROOF_HASHES",
            &["AUD-120"],
            set(&base, &["proof"], json!(too_many)),
            Want::Reject("ProofInvalid"),
        ),
        case(
            &f,
            "index-equals-size",
            "index must be below size",
            &["AUD-120"],
            set(&base, &["index"], json!(12)),
            Want::Reject("ProofInvalid"),
        ),
        case(
            &f,
            "size-zero",
            "No empty tree",
            &["AUD-120"],
            set(&set(&base, &["size"], json!(0)), &["index"], json!(0)),
            Want::Reject("ProofInvalid"),
        ),
        case(
            &f,
            "single-with-proof",
            "A tree of size 1 has an empty proof",
            &["AUD-120"],
            set(&inp(0, 1), &["proof"], json!([hash_str(&b.leaves[1])])),
            Want::Reject("ProofInvalid"),
        ),
        case(
            &f,
            "malformed-hash",
            "Proof element not in blake3: hex form",
            &["AUD-120"],
            set(&base, &["proof"], json!(["sha256:00"])),
            Want::Reject("ProofInvalid"),
        ),
    ]);
    File { name: "inclusion", kind: "audit/inclusion", spec: "ext/audit.md#53-proofs", cases,
        description: "RFC 9162 inclusion proof with BLAKE3. Input {\"index\", \"size\", \"leaf\", \"root\", \"proof\"}. Accept (no output) or reject ProofInvalid. Uses beta's log." }
}

fn consistency_file(b: &Log) -> File {
    let f = |i: &Value| {
        audit::verify_consistency(
            &i["size1"],
            &i["root1"],
            &i["size2"],
            &i["root2"],
            &i["proof"],
        )
        .map(|_| Value::Null)
    };
    let inp = |m: usize, n: usize| json!({"size1": m, "root1": hash_str(&b.root(m)), "size2": n, "root2": hash_str(&b.root(n)), "proof": b.cons(m, n)});
    let mut cases = vec![];
    for (m, n) in [
        (1, 12),
        (3, 8),
        (4, 12),
        (8, 12),
        (6, 7),
        (2, 4),
        (5, 11),
        (11, 12),
    ] {
        cases.push(case(
            &f,
            &format!("size-{m}-to-{n}"),
            &format!("Tree of size {n} extends size {m}"),
            &["AUD-120"],
            inp(m, n),
            Want::Accept,
        ));
    }
    cases.push(case(
        &f,
        "equal-sizes",
        "Equal sizes and roots, empty proof",
        &["AUD-121", "AUD-701"],
        inp(12, 12),
        Want::Accept,
    ));
    let base = inp(3, 8);
    let p = base["proof"].as_array().unwrap().clone();
    let mut longer = p.clone();
    longer.push(base["root2"].clone());
    cases.extend([
        case(&f, "wrong-old-root", "root1 is the root of size 2", &["AUD-120", "AUD-701"], set(&base, &["root1"], json!(hash_str(&b.root(2)))), Want::Reject("ProofInvalid")),
        case(&f, "wrong-new-root", "root2 is the root of size 9", &["AUD-120"], set(&base, &["root2"], json!(hash_str(&b.root(9)))), Want::Reject("ProofInvalid")),
        case(&f, "truncated", "Last proof hash missing", &["AUD-120"], set(&base, &["proof"], json!(p[..p.len() - 1])), Want::Reject("ProofInvalid")),
        case(&f, "extra-hash", "One hash too many", &["AUD-120"], set(&base, &["proof"], json!(longer)), Want::Reject("ProofInvalid")),
        case(&f, "empty-proof", "Different sizes need a proof", &["AUD-120"], set(&base, &["proof"], json!([])), Want::Reject("ProofInvalid")),
        case(&f, "shrinking", "size1 > size2", &["AUD-120"], json!({"size1": 8, "root1": base["root2"], "size2": 3, "root2": base["root1"], "proof": p}), Want::Reject("ProofInvalid")),
        case(&f, "size-zero", "size1 must be at least 1", &["AUD-120"], set(&base, &["size1"], json!(0)), Want::Reject("ProofInvalid")),
        case(&f, "equal-sizes-with-proof", "Equal sizes accept only the empty proof", &["AUD-121"], set(&inp(12, 12), &["proof"], json!([hash_str(&b.leaves[0])])), Want::Reject("ProofInvalid")),
        case(&f, "equal-sizes-different-roots", "Equal sizes, different roots", &["AUD-121"], set(&inp(12, 12), &["root2"], json!(hash_str(&b.root(11)))), Want::Reject("ProofInvalid")),
    ]);
    File { name: "consistency", kind: "audit/consistency", spec: "ext/audit.md#53-proofs", cases,
        description: "RFC 9162 consistency proof with BLAKE3. Input {\"size1\", \"root1\", \"size2\", \"root2\", \"proof\"}. Accept (no output) or reject ProofInvalid. Uses beta's log." }
}

fn checkpoint_file(w: &World, bk: &SigningKey) -> File {
    let f = |i: &Value| audit::verify_checkpoint(&i["checkpoint"]).map(|c| c.out());
    let b = &w.beta;
    let cp = b.checkpoint(12, "2026-11-07T12:05:00Z");
    let with_extra = resign(
        &set(&cp, &["note"], json!("unknown member, signed")),
        bk,
        CHECKPOINT_V,
    );
    // non-canonical S: S + L
    let mut sig = URL_SAFE_NO_PAD.decode(cp["sig"].as_str().unwrap()).unwrap();
    let l: [u8; 32] =
        hex::decode("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
            .unwrap()
            .try_into()
            .unwrap();
    let mut carry = 0u16;
    for i in 0..32 {
        let s = sig[32 + i] as u16 + l[i] as u16 + carry;
        sig[32 + i] = s as u8;
        carry = s >> 8;
    }
    let noncanon = set(&cp, &["sig"], json!(URL_SAFE_NO_PAD.encode(&sig)));
    // the identity point, a small-order key
    let mut ident = [0u8; 32];
    ident[0] = 1;
    let weak = set(&cp, &["log"], json!(format!("wwn:{}", base32(&ident))));
    let other = resign(&cp, &key("mallory"), CHECKPOINT_V);
    let cases = vec![
        case(
            &f,
            "valid",
            "beta's checkpoint at size 12",
            &["AUD-200", "AUD-201", "AUD-202", "AUD-701"],
            json!({"checkpoint": cp}),
            Want::Accept,
        ),
        case(
            &f,
            "valid-size-1",
            "Checkpoint of a log of size 1 (beta, epoch 1)",
            &["AUD-200", "AUD-201"],
            json!({"checkpoint": w.beta1.checkpoint(1, "2026-11-08T09:00:01Z")}),
            Want::Accept,
        ),
        case(
            &f,
            "unknown-member",
            "An unknown member is signed and kept",
            &["AUD-202"],
            json!({"checkpoint": with_extra}),
            Want::Accept,
        ),
        case(
            &f,
            "unknown-member-added",
            "An unknown member added after signing breaks the signature",
            &["AUD-201"],
            json!({"checkpoint": set(&cp, &["note"], json!("added"))}),
            Want::Reject("CheckpointInvalid"),
        ),
        case(
            &f,
            "bad-signature",
            "One signature bit flipped",
            &["AUD-201", "AUD-701"],
            json!({"checkpoint": flip_sig(&cp)}),
            Want::Reject("CheckpointInvalid"),
        ),
        case(
            &f,
            "other-signer",
            "Signed by a key other than log",
            &["AUD-200", "AUD-201"],
            json!({"checkpoint": other}),
            Want::Reject("CheckpointInvalid"),
        ),
        case(
            &f,
            "size-changed",
            "size changed after signing",
            &["AUD-201"],
            json!({"checkpoint": set(&cp, &["size"], json!(11))}),
            Want::Reject("CheckpointInvalid"),
        ),
        case(
            &f,
            "non-canonical-s",
            "S + L instead of S",
            &["AUD-201"],
            json!({"checkpoint": noncanon}),
            Want::Reject("CheckpointInvalid"),
        ),
        case(
            &f,
            "weak-key",
            "log is the identity point",
            &["AUD-201"],
            json!({"checkpoint": weak}),
            Want::Reject("CheckpointInvalid"),
        ),
        case(
            &f,
            "padded-signature",
            "sig with base64 padding",
            &["AUD-202"],
            json!({"checkpoint": set(&cp, &["sig"], json!(format!("{}==", cp["sig"].as_str().unwrap())))}),
            Want::Reject("CheckpointInvalid"),
        ),
        case(
            &f,
            "missing-root",
            "root is required",
            &["AUD-202"],
            json!({"checkpoint": resign(&del(&cp, "root"), bk, CHECKPOINT_V)}),
            Want::Reject("CheckpointInvalid"),
        ),
        case(
            &f,
            "size-zero",
            "size is at least 1, even when signed",
            &["AUD-202"],
            json!({"checkpoint": resign(&set(&cp, &["size"], json!(0)), bk, CHECKPOINT_V)}),
            Want::Reject("CheckpointInvalid"),
        ),
        case(
            &f,
            "size-string",
            "size is an integer",
            &["AUD-202"],
            json!({"checkpoint": resign(&set(&cp, &["size"], json!("12")), bk, CHECKPOINT_V)}),
            Want::Reject("CheckpointInvalid"),
        ),
        case(
            &f,
            "unknown-version",
            "v is webway-checkpoint/1",
            &["AUD-202", "AUD-910"],
            json!({"checkpoint": resign(&set(&cp, &["v"], json!("webway-checkpoint/1")), bk, "webway-checkpoint/1")}),
            Want::Reject("CheckpointInvalid"),
        ),
        case(
            &f,
            "receipt-as-checkpoint",
            "A receipt is not a checkpoint",
            &["AUD-202"],
            json!({"checkpoint": b.receipt(2)}),
            Want::Reject("CheckpointInvalid"),
        ),
    ];
    File { name: "checkpoint", kind: "audit/checkpoint", spec: "ext/audit.md#62-checkpoints", cases,
        description: "Verify a checkpoint's form and signature. Input {\"checkpoint\": C}. Accept: {\"log\", \"epoch\", \"size\", \"root\"}. Reject: CheckpointInvalid." }
}

fn receipt_file(w: &World, bk: &SigningKey) -> File {
    let f = |i: &Value| audit::verify_receipt(&i["receipt"], i.get("envelope")).map(|c| c.out());
    let b = &w.beta;
    let r = b.receipt(2);
    let r7 = b.receipt(7);
    let cases = vec![
        case(
            &f,
            "valid",
            "Receipt for E1 at index 2 (commits to size 3)",
            &["AUD-200", "AUD-201", "AUD-202"],
            json!({"receipt": r}),
            Want::Accept,
        ),
        case(
            &f,
            "valid-with-envelope",
            "Receipt matches the envelope it is for",
            &["AUD-301", "AUD-611"],
            json!({"receipt": r, "envelope": w.e1}),
            Want::Accept,
        ),
        case(
            &f,
            "valid-second",
            "Receipt for E3 at index 7",
            &["AUD-301"],
            json!({"receipt": r7, "envelope": w.e3}),
            Want::Accept,
        ),
        case(
            &f,
            "other-envelope",
            "Receipt for E1 checked against E3",
            &["AUD-301", "AUD-611"],
            json!({"receipt": r, "envelope": w.e3}),
            Want::Reject("ReceiptInvalid"),
        ),
        case(
            &f,
            "envelope-changed",
            "The envelope's exp changed after the receipt",
            &["AUD-301"],
            json!({"receipt": r, "envelope": set(&w.e1, &["exp"], json!("2026-11-07T14:00:00Z"))}),
            Want::Reject("ReceiptInvalid"),
        ),
        case(
            &f,
            "id-mismatch",
            "Signed receipt whose id is not the envelope's",
            &["AUD-301"],
            json!({"receipt": resign(&set(&r, &["id"], w.e3["id"].clone()), bk, RECEIPT_V), "envelope": w.e1}),
            Want::Reject("ReceiptInvalid"),
        ),
        case(
            &f,
            "from-mismatch",
            "Signed receipt whose from is the recipient",
            &["AUD-301"],
            json!({"receipt": resign(&set(&r, &["from"], r["to"].clone()), bk, RECEIPT_V), "envelope": w.e1}),
            Want::Reject("ReceiptInvalid"),
        ),
        case(
            &f,
            "bad-signature",
            "One signature bit flipped",
            &["AUD-201"],
            json!({"receipt": flip_sig(&r)}),
            Want::Reject("ReceiptInvalid"),
        ),
        case(
            &f,
            "root-changed",
            "root changed after signing",
            &["AUD-201"],
            json!({"receipt": set(&r, &["root"], json!(hash_str(&b.root(4))))}),
            Want::Reject("ReceiptInvalid"),
        ),
        case(
            &f,
            "signed-by-agent",
            "Signed by the recipient agent key, not the node key",
            &["AUD-200", "AUD-201"],
            json!({"receipt": resign(&r, &key("tester"), RECEIPT_V)}),
            Want::Reject("ReceiptInvalid"),
        ),
        case(
            &f,
            "missing-entry",
            "entry is required",
            &["AUD-202"],
            json!({"receipt": resign(&del(&r, "entry"), bk, RECEIPT_V)}),
            Want::Reject("ReceiptInvalid"),
        ),
        case(
            &f,
            "bad-id",
            "id is a UUIDv7",
            &["AUD-202"],
            json!({"receipt": resign(&set(&r, &["id"], json!("not-a-uuid")), bk, RECEIPT_V)}),
            Want::Reject("ReceiptInvalid"),
        ),
        case(
            &f,
            "index-unsafe",
            "index above 2^53 - 2",
            &["AUD-202"],
            json!({"receipt": resign(&set(&r, &["index"], json!(9007199254740991u64)), bk, RECEIPT_V)}),
            Want::Reject("ReceiptInvalid"),
        ),
        case(
            &f,
            "unknown-version",
            "v is webway-receipt/1",
            &["AUD-202", "AUD-910"],
            json!({"receipt": resign(&set(&r, &["v"], json!("webway-receipt/1")), bk, "webway-receipt/1")}),
            Want::Reject("ReceiptInvalid"),
        ),
        case(
            &f,
            "checkpoint-signature-reused",
            "A checkpoint signature over receipt content fails: prefixes differ",
            &["AUD-200", "AUD-201"],
            json!({"receipt": resign(&r, bk, CHECKPOINT_V)}),
            Want::Reject("ReceiptInvalid"),
        ),
    ];
    File { name: "receipt", kind: "audit/receipt", spec: "ext/audit.md#63-receipts", cases,
        description: "Verify a receipt, optionally against its envelope. Input {\"receipt\": R, \"envelope\"?: X}. Accept: {\"log\", \"epoch\", \"size\", \"root\"} with size = index + 1. Reject: ReceiptInvalid." }
}

fn compare_file(w: &World) -> File {
    let f = |i: &Value| audit::compare(&i["a"], &i["b"], &i["proof"]);
    let b = &w.beta;
    let c4 = b.checkpoint(4, "2026-11-07T12:00:02Z");
    let c8 = b.checkpoint(8, "2026-11-07T12:05:00Z");
    let c12 = b.checkpoint(12, "2026-11-07T12:10:00Z");
    let f8 = w.fork.checkpoint(8, "2026-11-07T12:05:00Z");
    let r2 = b.receipt(2);
    let r7 = b.receipt(7);
    let e1 = w.beta1.checkpoint(1, "2026-11-08T09:00:01Z");
    let a3 = w.alpha.checkpoint(3, "2026-11-07T12:00:02Z");
    let cases = vec![
        case(
            &f,
            "equal",
            "The same checkpoint twice",
            &["AUD-710"],
            json!({"a": c8, "b": c8, "proof": []}),
            Want::Accept,
        ),
        case(
            &f,
            "receipt-equals-checkpoint",
            "Receipt at index 7 and checkpoint at size 8 agree",
            &["AUD-211", "AUD-710"],
            json!({"a": r7, "b": c8, "proof": []}),
            Want::Accept,
        ),
        case(
            &f,
            "consistent",
            "Checkpoint 4 then checkpoint 12",
            &["AUD-710"],
            json!({"a": c4, "b": c12, "proof": b.cons(4, 12)}),
            Want::Accept,
        ),
        case(
            &f,
            "consistent-reversed",
            "Larger commitment first",
            &["AUD-710"],
            json!({"a": c12, "b": c4, "proof": b.cons(4, 12)}),
            Want::Accept,
        ),
        case(
            &f,
            "receipt-then-checkpoint",
            "Receipt at index 2 (size 3) and checkpoint 12",
            &["AUD-211", "AUD-710"],
            json!({"a": r2, "b": c12, "proof": b.cons(3, 12)}),
            Want::Accept,
        ),
        case(
            &f,
            "other-epoch",
            "Epoch 0 and epoch 1 are not compared",
            &["AUD-710"],
            json!({"a": c8, "b": e1, "proof": []}),
            Want::Accept,
        ),
        case(
            &f,
            "other-log",
            "beta's and alpha's logs are not compared",
            &["AUD-710"],
            json!({"a": c8, "b": a3, "proof": []}),
            Want::Accept,
        ),
        case(
            &f,
            "fork",
            "Two checkpoints of size 8 with different roots: transferable proof of a fork",
            &["AUD-211", "AUD-703", "AUD-710"],
            json!({"a": c8, "b": f8, "proof": []}),
            Want::Reject("LogInconsistent"),
        ),
        case(
            &f,
            "fork-against-receipt",
            "beta's receipt at index 7 against the forked checkpoint of size 8",
            &["AUD-211", "AUD-710"],
            json!({"a": r7, "b": f8, "proof": []}),
            Want::Reject("LogInconsistent"),
        ),
        case(
            &f,
            "fork-needs-proof",
            "Checkpoint 4 against the forked checkpoint 8, with beta's real proof",
            &["AUD-710"],
            json!({"a": c4, "b": f8, "proof": b.cons(4, 8)}),
            Want::Reject("ProofInvalid"),
        ),
        case(
            &f,
            "no-proof",
            "Different sizes without a proof are not consistent",
            &["AUD-710"],
            json!({"a": c4, "b": c12, "proof": []}),
            Want::Reject("ProofInvalid"),
        ),
    ];
    File { name: "compare", kind: "audit/compare", spec: "ext/audit.md#103-fork-and-rollback-evidence", cases,
        description: "Compare two commitments (checkpoints or receipts; signatures are not checked here). Input {\"a\", \"b\", \"proof\"}, proof from the smaller size to the larger. Accept: {\"relation\": \"equal\" | \"consistent\" | \"unrelated\"}. Reject: LogInconsistent (equal size, different roots) or ProofInvalid." }
}

fn evidence_file(w: &World, bk: &SigningKey) -> File {
    let f = |i: &Value| audit::verify_evidence(&i["bundle"]);
    let b = &w.beta;
    let cp = b.checkpoint(12, "2026-11-07T12:10:00Z");
    let item = |l: &Log, i: usize, n: usize| json!({"entry": l.entries[i], "proof": l.incl(i, n)});
    let body1 = w.e1["body"].clone();
    let bh1 = w.e1["body_hash"].as_str().unwrap().to_string();
    let good = json!({
        "v": EVIDENCE_V, "checkpoint": cp,
        "entries": [item(b, 2, 12), item(b, 3, 12), item(b, 9, 12)],
        "receipts": [{"receipt": b.receipt(2), "proof": b.cons(3, 12)}],
        "bodies": {bh1.clone(): body1.clone()},
    });
    let minimal = json!({"v": EVIDENCE_V, "checkpoint": b.checkpoint(8, "2026-11-07T12:05:00Z"), "entries": [item(b, 7, 8)]});
    let alpha_item = item(&w.alpha, 1, 3);
    let bad_proof = json!({"entry": b.entries[3], "proof": b.incl(4, 12)});
    let edited = json!({"entry": set(&b.entries[3], &["data", "decision"], json!("deny")), "proof": b.incl(3, 12)});
    let wrong_receipt = resign(
        &set(&b.receipt(2), &["entry"], json!(hash_str(&b.leaves[3]))),
        bk,
        RECEIPT_V,
    );
    let wrong_id_receipt = resign(
        &set(&b.receipt(2), &["id"], w.e3["id"].clone()),
        bk,
        RECEIPT_V,
    );
    let mut ns = Log::new(&key("beta-node"), 0);
    ns.append(
        "2026-11-07T12:00:00Z",
        "log.genesis",
        None,
        json!({"node": nid(&key("beta-node")), "reason": "new", "profile": "webway-profile/0.1"}),
    );
    ns.append(
        "2026-11-07T12:00:01Z",
        "envelope.received",
        None,
        json!({"via": nid(&key("alpha-node")), "outcome": "accepted"}),
    );
    let nostub_bundle = json!({"v": EVIDENCE_V, "checkpoint": ns.checkpoint(2, "2026-11-07T12:00:02Z"),
        "entries": [{"entry": ns.entries[1], "proof": ns.incl(1, 2)}]});
    let bs = &w.badstub;
    let badstub = json!({"v": EVIDENCE_V, "checkpoint": bs.checkpoint(2, "2026-11-07T12:00:02Z"), "entries": [item(bs, 1, 2)]});
    let cases = vec![
        case(
            &f,
            "valid",
            "Entries 2, 3, 9 of beta's log, receipt for E1, E1's body",
            &["AUD-800", "AUD-801", "AUD-802", "AUD-302"],
            json!({"bundle": good}),
            Want::Accept,
        ),
        case(
            &f,
            "valid-minimal",
            "One entry and a checkpoint",
            &["AUD-800", "AUD-801"],
            json!({"bundle": minimal}),
            Want::Accept,
        ),
        case(
            &f,
            "unknown-version",
            "v is webway-audit-evidence/1",
            &["AUD-800", "AUD-910"],
            json!({"bundle": set(&good, &["v"], json!("webway-audit-evidence/1"))}),
            Want::Reject("EvidenceInvalid"),
        ),
        case(
            &f,
            "no-checkpoint",
            "checkpoint is required",
            &["AUD-800"],
            json!({"bundle": del(&good, "checkpoint")}),
            Want::Reject("EvidenceInvalid"),
        ),
        case(
            &f,
            "no-entries",
            "entries must not be empty",
            &["AUD-800"],
            json!({"bundle": set(&good, &["entries"], json!([]))}),
            Want::Reject("EvidenceInvalid"),
        ),
        case(
            &f,
            "bad-checkpoint",
            "Checkpoint signature fails",
            &["AUD-801"],
            json!({"bundle": set(&good, &["checkpoint"], flip_sig(&cp))}),
            Want::Reject("CheckpointInvalid"),
        ),
        case(
            &f,
            "foreign-entry",
            "An entry of alpha's log in beta's bundle",
            &["AUD-800"],
            json!({"bundle": set(&good, &["entries"], json!([alpha_item]))}),
            Want::Reject("EvidenceInvalid"),
        ),
        case(
            &f,
            "entry-beyond-checkpoint",
            "Entry 9 with a checkpoint of size 8",
            &["AUD-800"],
            json!({"bundle": set(&minimal, &["entries"], json!([item(b, 9, 12)]))}),
            Want::Reject("EvidenceInvalid"),
        ),
        case(
            &f,
            "wrong-inclusion-proof",
            "Entry 3 with entry 4's proof",
            &["AUD-801"],
            json!({"bundle": set(&good, &["entries"], json!([bad_proof]))}),
            Want::Reject("ProofInvalid"),
        ),
        case(
            &f,
            "edited-entry",
            "Entry 3 edited: its hash is not in the tree",
            &["AUD-801"],
            json!({"bundle": set(&good, &["entries"], json!([edited]))}),
            Want::Reject("ProofInvalid"),
        ),
        case(
            &f,
            "malformed-entry",
            "An entry without time",
            &["AUD-801"],
            json!({"bundle": set(&good, &["entries"], json!([{"entry": del(&b.entries[3], "time"), "proof": b.incl(3, 12)}]))}),
            Want::Reject("EntryInvalid"),
        ),
        case(
            &f,
            "stub-signature",
            "The log claims it accepted an envelope whose signature fails",
            &["AUD-802"],
            json!({"bundle": badstub}),
            Want::Reject("EvidenceInvalid"),
        ),
        case(
            &f,
            "receipt-bad-proof",
            "Receipt with a consistency proof for the wrong size",
            &["AUD-801"],
            json!({"bundle": set(&good, &["receipts"], json!([{"receipt": b.receipt(2), "proof": b.cons(4, 12)}]))}),
            Want::Reject("ProofInvalid"),
        ),
        case(
            &f,
            "receipt-bad-signature",
            "Receipt signature fails",
            &["AUD-801"],
            json!({"bundle": set(&good, &["receipts"], json!([{"receipt": flip_sig(&b.receipt(2)), "proof": b.cons(3, 12)}]))}),
            Want::Reject("ReceiptInvalid"),
        ),
        case(
            &f,
            "checkpoint-as-receipt",
            "alpha's checkpoint in the receipts list is not a receipt",
            &["AUD-801"],
            json!({"bundle": set(&good, &["receipts"], json!([{"receipt": w.alpha.checkpoint(3, "2026-11-07T12:00:02Z"), "proof": []}]))}),
            Want::Reject("ReceiptInvalid"),
        ),
        case(
            &f,
            "receipt-other-log",
            "A valid receipt of alpha's log in beta's bundle",
            &["AUD-800"],
            json!({"bundle": set(&good, &["receipts"], json!([{"receipt": w.alpha.receipt(2), "proof": []}]))}),
            Want::Reject("EvidenceInvalid"),
        ),
        case(
            &f,
            "receipt-beyond-checkpoint",
            "Receipt at index 7 (size 8) with a checkpoint of size 4",
            &["AUD-800"],
            json!({"bundle": {"v": EVIDENCE_V, "checkpoint": b.checkpoint(4, "2026-11-07T12:00:02Z"),
                "entries": [item(b, 2, 4)], "receipts": [{"receipt": b.receipt(7), "proof": []}]}}),
            Want::Reject("EvidenceInvalid"),
        ),
        case(
            &f,
            "receipt-id-mismatch",
            "Signed receipt with the right entry hash but another envelope id",
            &["AUD-302"],
            json!({"bundle": set(&good, &["receipts"], json!([{"receipt": wrong_id_receipt, "proof": b.cons(3, 12)}]))}),
            Want::Reject("ReceiptInvalid"),
        ),
        case(
            &f,
            "missing-stub",
            "The log claims an accepted envelope but kept no stub",
            &["AUD-802"],
            json!({"bundle": nostub_bundle}),
            Want::Reject("EvidenceInvalid"),
        ),
        case(
            &f,
            "receipt-entry-mismatch",
            "Signed receipt naming another entry hash than the entry at its index",
            &["AUD-302"],
            json!({"bundle": set(&good, &["receipts"], json!([{"receipt": wrong_receipt, "proof": b.cons(3, 12)}]))}),
            Want::Reject("ReceiptInvalid"),
        ),
        case(
            &f,
            "body-mismatch",
            "Body changed after logging",
            &["AUD-801"],
            json!({"bundle": set(&good, &["bodies"], json!({bh1.clone(): set(&body1, &["message", "parts"], json!([{"text": "accept 0 EUR"}]))}))}),
            Want::Reject("EvidenceInvalid"),
        ),
        case(
            &f,
            "foreign-body",
            "A body no stub in the bundle refers to",
            &["AUD-800"],
            json!({"bundle": set(&good, &["bodies"], json!({hash_str(blake3::hash(b"{}").as_bytes()): {}}))}),
            Want::Reject("EvidenceInvalid"),
        ),
    ];
    File { name: "evidence", kind: "audit/evidence", spec: "ext/audit.md#11-evidence-bundles", cases,
        description: "Verify an evidence bundle. Input {\"bundle\": B}. Accept: {\"entries\": number of entries}. Reject: EvidenceInvalid, CheckpointInvalid, EntryInvalid, ProofInvalid or ReceiptInvalid (the first failing check, AUD-801)." }
}
