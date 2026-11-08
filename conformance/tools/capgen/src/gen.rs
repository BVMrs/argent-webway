//! Vector generation. Every case is built from fixed test keys, run through the reference
//! model, and checked against the expected verdict before it is written.
//!
//! The world (S4): owner A runs `planner` on node alpha, owner B runs `broker` and helpers on
//! node beta, owner C runs `runner` on node gamma. The verifier is C's node gamma unless a case
//! says otherwise. Owner X is unpinned (a stranger or attacker).

use crate::cap::{self, attenuate, b64, mint, third_party};
use crate::err::E;
use crate::ids;
use crate::keys;
use crate::model;
use crate::stmt::{self, commitment, sign, sign_raw};
use data_encoding::BASE64URL_NOPAD as B64;
use serde_json::{json, Value};

pub const NOW: &str = "2026-11-07T12:00:00Z";
const CERT_IAT: &str = "2026-11-01T00:00:00Z";
const ISSUER_EXP: &str = "2026-11-30T00:00:00Z";
const AGENT_EXP: &str = "2027-10-01T00:00:00Z";
const T_ISSUED: &str = "2026-11-07T11:30:00Z";
const T_EXPIRES: &str = "2026-11-07T12:30:00Z";
const LONG_ISSUED: &str = "2026-11-01T00:00:00Z";
const LONG_EXPIRES: &str = "2026-11-21T00:00:00Z";
const TASK: &str = "0190f1c2-7d3a-7000-8000-000000000001";
const ORIGIN_TASK: &str = "0190f1c0-0000-7000-8000-0000000000aa";

pub struct Case {
    pub id: String,
    pub description: String,
    pub requirements: Vec<&'static str>,
    pub input: Value,
    pub expect: Result<(), E>,
}

pub struct File {
    pub path: &'static str,
    pub kind: &'static str,
    pub description: &'static str,
    pub spec: &'static str,
    pub cases: Vec<Case>,
}

fn case(id: &str, d: &str, reqs: &[&'static str], input: Value, expect: Result<(), E>) -> Case {
    Case { id: id.into(), description: d.into(), requirements: reqs.to_vec(), input, expect }
}

// ---------------------------------------------------------------- world

fn sk(n: &str) -> ed25519_dalek::SigningKey {
    keys::signing(n)
}
fn owner(o: &str) -> String {
    ids::owner(&format!("owner:{o}"))
}
fn issuer(i: &str) -> String {
    ids::issuer(&format!("issuer:{i}"))
}
fn node(n: &str) -> String {
    ids::node(&format!("node:{n}"))
}
fn agent(a: &str) -> String {
    ids::agent(&format!("agent:{a}"))
}
/// Key name of an agent, for signing holder blocks.
fn ak(a: &str) -> String {
    format!("agent:{a}")
}
fn ik(i: &str) -> String {
    format!("issuer:{i}")
}

fn full_scope() -> Value {
    json!({
        "resource": ["skill:*", "task:*", "invite:*", "blob:*", "mailbox:*"],
        "mandate": {"targets": ["*"], "capabilities": ["skill:*"], "maxTtl": 3600},
        "agentCerts": true, "cards": true, "invites": true
    })
}

fn issuer_cert_full(o: &str, i: &str, n: &str, scope: Value, iat: &str, exp: &str) -> Value {
    sign(
        stmt::ISSUER_CERT,
        &sk(&format!("owner:{o}")),
        &owner(o),
        json!({"owner": owner(o), "issuer": issuer(i), "node": node(n), "iat": iat, "exp": exp, "scope": scope}),
    )
}
fn issuer_cert(o: &str, i: &str, n: &str) -> Value {
    issuer_cert_full(o, i, n, full_scope(), CERT_IAT, ISSUER_EXP)
}
fn agent_cert(o: &str, a: &str, n: &str) -> Value {
    sign(
        stmt::AGENT_CERT,
        &sk(&format!("owner:{o}")),
        &owner(o),
        json!({"owner": owner(o), "agent": agent(a), "node": node(n), "iat": CERT_IAT, "exp": AGENT_EXP}),
    )
}

/// The presenter's agent-cert (the envelope layer has linked it to `from`).
fn presenter_certs(a: &str) -> Vec<Value> {
    let (o, n) = match a {
        "planner" => ("A", "alpha"),
        "runner" => ("C", "gamma"),
        "mallory" | "invitee" => ("X", "x"),
        _ => ("B", "beta"),
    };
    vec![agent_cert(o, a, n)]
}

/// Authority block of an access token.
fn access_code(iss: &str, own: &str, rights: &[&str], holder: &str, issued: &str, expires: &str, extra: &str) -> String {
    let rights: String = rights.iter().map(|r| format!("right(\"{r}\");\n")).collect();
    format!(
        "webway(\"capability/v0\", \"access\");\nissuer(\"{}\");\nowner(\"{}\");\nissued({issued});\nexpires({expires});\n{rights}holder(\"{}\", 0);\ncheck if presenter($k), current_holder($k);\ncheck if time($t), $t <= {expires};\n{extra}",
        issuer(iss),
        owner(own),
        agent(holder)
    )
}

/// The standard access token: C's issuing key grants broker `skill:run-tests` for one hour.
fn std_access(extra: &str, eph: &str) -> biscuit_auth::Biscuit {
    mint(&ik("C"), &access_code("C", "C", &["skill:run-tests"], "broker", T_ISSUED, T_EXPIRES, extra), eph)
}

fn mandate_code(iss: &str, own: &str, principal: &str, grants: &[(&str, &str)], holder: &str, issued: &str, expires: &str, extra: &str) -> String {
    let grants: String = grants.iter().map(|(o, c)| format!("grant(\"{}\", \"{c}\");\n", owner(o))).collect();
    format!(
        "webway(\"capability/v0\", \"mandate\");\nissuer(\"{}\");\nowner(\"{}\");\nissued({issued});\nexpires({expires});\nprincipal(\"{}\");\n{grants}origin_task(\"{ORIGIN_TASK}\");\nholder(\"{}\", 0);\ncheck if presenter($k), current_holder($k);\n{extra}",
        issuer(iss),
        owner(own),
        agent(principal),
        agent(holder)
    )
}

/// The standard mandate: A's issuing key says broker may use `skill:run-tests` at C for planner.
fn std_mandate(extra: &str, eph: &str) -> biscuit_auth::Biscuit {
    mint(
        &ik("A"),
        &mandate_code("A", "A", "planner", &[("C", "skill:run-tests")], "broker", T_ISSUED, T_EXPIRES, extra),
        eph,
    )
}

fn mandate_obj(token: &biscuit_auth::Biscuit) -> Value {
    json!({
        "token": b64(token),
        "issuerCert": issuer_cert("A", "A", "alpha"),
        "principalCert": agent_cert("A", "planner", "alpha"),
    })
}

fn revocation_list(signer_key: &str, kid: &str, own: &str, seq: i64, iat: &str, valid_until: &str, revoked: Vec<String>) -> Value {
    sign(
        stmt::REVOCATION,
        &sk(signer_key),
        kid,
        json!({"owner": owner(own), "seq": seq, "iat": iat, "validUntil": valid_until, "revoked": revoked}),
    )
}
fn issuer_list(i: &str, own: &str, seq: i64, revoked: Vec<String>) -> Value {
    revocation_list(&ik(i), &issuer(i), own, seq, "2026-11-07T06:00:00Z", "2026-11-08T06:00:00Z", revoked)
}

/// A `capability/authorize` input with C's node gamma as verifier.
fn auth_input(presenter: &str, capability: &str, access: Option<String>) -> Value {
    let mut cap = json!({"capability": capability});
    if let Some(a) = access {
        cap["access"] = json!(a);
    }
    json!({
        "now": NOW,
        "verifier": {
            "owner": owner("C"), "node": node("gamma"), "recipient": agent("runner"),
            "pins": [owner("A"), owner("B")],
            "issuerCerts": [issuer_cert("C", "C", "gamma")],
            "agentCerts": presenter_certs(presenter),
        },
        "request": {"presenter": agent(presenter), "operation": "SendMessage", "taskId": TASK, "args": {"repo": "github.com/acme/app", "suite": "unit"}},
        "cap": cap,
        "state": {"calls": {"access": 0, "mandate": 0}, "revocations": []},
    })
}

fn std_input(t: &biscuit_auth::Biscuit) -> Value {
    auth_input("broker", "skill:run-tests", Some(b64(t)))
}

fn with_mandate(mut input: Value, m: Value) -> Value {
    input["cap"]["mandate"] = m;
    input
}

// ---------------------------------------------------------------- capability/authorize

fn authorize_cases() -> Vec<Case> {
    use E::*;
    let mut v = vec![];
    let ok = Ok(());

    // --- allow
    let t = std_access("", "eph:basic");
    v.push(case("access-basic", "C-rooted access token held by broker, presented by broker", &["CAP-110", "CAP-120", "CAP-121", "CAP-160"], std_input(&t), ok));

    let t3 = {
        let t = std_access("", "eph:chain3:0");
        let t = delegate(&t, &ak("broker"), "helper", 1, "", "eph:chain3:1");
        delegate(&t, &ak("helper"), "helper2", 2, "check if time($t), $t <= 2026-11-07T12:15:00Z;", "eph:chain3:2")
    };
    v.push(case("chain-3-hops", "broker -> helper -> helper2, presented by the last holder", &["CAP-120", "CAP-121"], auth_input("helper2", "skill:run-tests", Some(b64(&t3))), ok));

    let t = attenuate(&std_access("", "eph:att"), "check if time($t), $t <= 2026-11-07T12:10:00Z;\ncheck if calls($n), $n < 5;\ncheck if arg(\"repo\", \"github.com/acme/app\");", "eph:att:1");
    let mut i = std_input(&t);
    i["state"]["calls"]["access"] = json!(4);
    v.push(case("attenuated-within-limits", "TTL, calls (4 < 5) and argument caveats all satisfied", &["CAP-130", "CAP-160"], i, ok));

    let t = mint(&ik("C"), &access_code("C", "C", &["task:0190f1c2-7d3a-7000-8000-000000000001#read"], "broker", T_ISSUED, T_EXPIRES, "check if task($id), $id == \"0190f1c2-7d3a-7000-8000-000000000001\";"), "eph:taskread");
    let mut i = auth_input("broker", &format!("task:{TASK}#read"), Some(b64(&t)));
    i["request"]["operation"] = json!("GetTask");
    v.push(case("task-read", "task:<id>#read allows GetTask on that task", &["CAP-102"], i, ok));

    // long-lived token with fresh list (not revoking)
    let tl = mint(&ik("C"), &access_code("C", "C", &["skill:run-tests"], "broker", LONG_ISSUED, LONG_EXPIRES, ""), "eph:long");
    let mut i = std_input(&tl);
    i["state"]["revocations"] = json!([issuer_list("C", "C", 7, vec![])]);
    v.push(case("long-lived-fresh-list", "20-day token with a fresh list from its issuing key", &["CAP-172"], i, ok));
    let mut i = std_input(&tl);
    i["cap"]["revocations"] = json!([issuer_list("C", "C", 7, vec![])]);
    v.push(case("long-lived-stapled-list", "the fresh list is stapled by the sender", &["CAP-173", "CAP-172"], i, ok));

    // a list signed by another owner's issuing key cannot revoke C's token
    let tb = std_access("", "eph:basic");
    let mut i = std_input(&tb);
    i["state"]["revocations"] = json!([issuer_list("A", "A", 1, cap::revocation_ids(&tb))]);
    v.push(case("revocation-list-other-issuer-ignored", "A's issuing key lists C's token: not its token, ignored", &["CAP-170"], i, ok));

    // --- mandates (S4)
    let m = std_mandate("check if calls($n), $n < 1;", "eph:m:std");
    let i = with_mandate(std_input(&std_access("", "eph:basic")), mandate_obj(&m));
    v.push(case("mandate-valid", "S4: access (C-rooted) + mandate (A-rooted), both held by broker", &["CAP-180", "CAP-030", "CAP-031"], i, ok));

    // C's issuing key grants broker run-tests only on behalf of owner A.
    let ta_code_fixed = access_code("C", "C", &["skill:run-tests"], "broker", T_ISSUED, T_EXPIRES, &format!("check if mandate_owner(\"{}\");", owner("A")));
    let ta = mint(&ik("C"), &ta_code_fixed, "eph:onbehalf");
    let i = with_mandate(std_input(&ta), mandate_obj(&std_mandate("", "eph:m:ob")));
    v.push(case("on-behalf-only-with-mandate", "access usable only on behalf of owner A, mandate from A present", &["CAP-182"], i, ok));

    let mr = delegate(&std_mandate("", "eph:m:re:0"), &ak("broker"), "helper", 1, "check if arg(\"suite\", \"unit\");", "eph:m:re:1");
    let ar = delegate(&std_access("", "eph:a:re:0"), &ak("broker"), "helper", 1, "", "eph:a:re:1");
    let mut i = with_mandate(auth_input("helper", "skill:run-tests", Some(b64(&ar))), mandate_obj(&mr));
    i["request"]["presenter"] = json!(agent("helper"));
    v.push(case("mandate-redelegated", "broker re-delegates both mandate and access to helper", &["CAP-120", "CAP-180"], i, ok));

    // --- presence and presenter identity
    v.push(case("missing-access", "no access token", &["CAP-160"], auth_input("broker", "skill:run-tests", None), Err(CapabilityMissing)));
    let mut i = std_input(&std_access("", "eph:basic"));
    i["verifier"]["agentCerts"] = json!([]);
    v.push(case("presenter-uncertified", "the presenter has no agent-cert", &["CAP-041"], i, Err(CapabilityDenied)));
    let tm = mint(&ik("C"), &access_code("C", "C", &["skill:run-tests"], "mallory", T_ISSUED, T_EXPIRES, ""), "eph:mallory");
    v.push(case("presenter-unpinned-owner", "a valid token held by an agent of an unpinned owner", &["CAP-041"], auth_input("mallory", "skill:run-tests", Some(b64(&tm))), Err(CapabilityDenied)));

    // --- encoding, signature, issuer
    v.push(case("not-base64url", "access is not base64url", &["CAP-100"], auth_input("broker", "skill:run-tests", Some("not a token!".into())), Err(CapabilityInvalid)));
    let mut padded = b64(&std_access("", "eph:basic"));
    padded.push('=');
    v.push(case("padded-base64", "base64url with padding is not accepted", &["CAP-100"], auth_input("broker", "skill:run-tests", Some(padded)), Err(CapabilityInvalid)));
    let big: String = (0..300).map(|n| format!("note(\"padding-fact-{n:04}-xxxxxxxxxxxxxxxx\");\n")).collect();
    let tbig = std_access(&big, "eph:big");
    assert!(tbig.to_vec().unwrap().len() > cap::MAX_TOKEN_BYTES);
    v.push(case("too-large", "token larger than MAX_TOKEN_BYTES", &["CAP-100"], std_input(&tbig), Err(CapabilityInvalid)));
    let mut tmany = std_access("", "eph:many:0");
    for n in 1..17 {
        tmany = attenuate(&tmany, "check if true;", &format!("eph:many:{n}"));
    }
    v.push(case("too-many-blocks", "17 blocks, MAX_BLOCKS is 16", &["CAP-100"], std_input(&tmany), Err(CapabilityInvalid)));
    let twrong = mint(&ik("X"), &access_code("C", "C", &["skill:run-tests"], "broker", T_ISSUED, T_EXPIRES, ""), "eph:wrongkey");
    v.push(case("wrong-root-key", "claims C's issuing key but is signed by another key", &["CAP-100", "CAP-104"], std_input(&twrong), Err(CapabilityInvalid)));
    let tunk = mint(&ik("X"), &access_code("X", "C", &["skill:run-tests"], "broker", T_ISSUED, T_EXPIRES, ""), "eph:unknown");
    v.push(case("unknown-issuer", "signed by an issuing key with no issuer-cert of C", &["CAP-110"], std_input(&tunk), Err(CapabilityInvalid)));
    let tfor = mint(&ik("A"), &access_code("A", "A", &["skill:run-tests"], "broker", T_ISSUED, T_EXPIRES, ""), "eph:foreign");
    let mut i = std_input(&tfor);
    i["verifier"]["issuerCerts"].as_array_mut().unwrap().push(issuer_cert("A", "A", "alpha"));
    v.push(case("access-from-other-owner", "a valid A-rooted token is not access at C", &["CAP-110"], i, Err(CapabilityInvalid)));
    let mut i = std_input(&std_access("", "eph:basic"));
    i["verifier"]["issuerCerts"] = json!([issuer_cert_full("C", "C", "gamma", json!({"resource": ["skill:lint"]}), CERT_IAT, ISSUER_EXP)]);
    v.push(case("scope-exceeded", "issuer-cert resource scope does not cover skill:run-tests", &["CAP-030"], i, Err(CapabilityInvalid)));
    let mut i = std_input(&std_access("", "eph:basic"));
    i["verifier"]["issuerCerts"] = json!([issuer_cert_full("C", "C", "gamma", full_scope(), "2026-10-01T00:00:00Z", "2026-10-30T00:00:00Z")]);
    v.push(case("issuer-cert-expired", "the issuing key's certificate has expired", &["CAP-030"], i, Err(CapabilityInvalid)));

    // --- schema
    let tres = std_access(&format!("presenter(\"{}\");", agent("mallory")), "eph:res1");
    v.push(case("reserved-fact-authority", "authority block pre-sets presenter()", &["CAP-103"], std_input(&tres), Err(CapabilityInvalid)));
    let tres2 = attenuate(&std_access("", "eph:res2"), "time(2026-01-01T00:00:00Z) <- right($c);", "eph:res2:1");
    v.push(case("reserved-rule-head-attenuation", "attenuation block has a rule producing time()", &["CAP-103"], std_input(&tres2), Err(CapabilityInvalid)));
    let tnorole = mint(&ik("C"), &access_code("C", "C", &["skill:run-tests"], "broker", T_ISSUED, T_EXPIRES, "").replace("webway(\"capability/v0\", \"access\");\n", ""), "eph:norole");
    v.push(case("missing-role-fact", "authority block without webway(\"capability/v0\", _)", &["CAP-104"], std_input(&tnorole), Err(CapabilityInvalid)));
    let tmand = std_mandate("", "eph:m:asaccess");
    let mut i = std_input(&tmand);
    i["verifier"]["issuerCerts"].as_array_mut().unwrap().push(issuer_cert("A", "A", "alpha"));
    v.push(case("mandate-as-access", "a mandate in the access slot", &["CAP-104", "CAP-110"], i, Err(CapabilityInvalid)));
    let ttl = mint(&ik("C"), &access_code("C", "C", &["skill:run-tests"], "broker", "2026-11-01T00:00:00Z", "2026-12-02T00:00:00Z", ""), "eph:ttl");
    v.push(case("ttl-too-long", "access token valid 31 days, MAX_ACCESS_TTL is 30", &["CAP-111"], std_input(&ttl), Err(CapabilityInvalid)));
    let tfut = mint(&ik("C"), &access_code("C", "C", &["skill:run-tests"], "broker", "2026-11-07T12:10:00Z", "2026-11-07T13:00:00Z", ""), "eph:future");
    v.push(case("issued-in-future", "issued 10 minutes ahead, SKEW is 5", &["CAP-111"], std_input(&tfut), Err(CapabilityInvalid)));

    // --- expiry, presenter
    let texp = mint(&ik("C"), &access_code("C", "C", &["skill:run-tests"], "broker", "2026-11-07T10:00:00Z", "2026-11-07T11:00:00Z", ""), "eph:expired");
    v.push(case("expired", "now is after expires", &["CAP-111"], std_input(&texp), Err(CapabilityDenied)));
    let texp1 = mint(&ik("C"), &access_code("C", "C", &["skill:run-tests"], "broker", "2026-11-07T11:00:00Z", "2026-11-07T11:59:59Z", ""), "eph:expired1");
    v.push(case("expired-by-one-second", "no tolerance on expires", &["CAP-111"], std_input(&texp1), Err(CapabilityDenied)));
    let t2 = delegate(&std_access("", "eph:prev:0"), &ak("broker"), "helper", 1, "", "eph:prev:1");
    v.push(case("presented-by-previous-holder", "broker delegated to helper, then presents the token itself", &["CAP-121"], std_input(&t2), Err(CapabilityDenied)));
    v.push(case("stolen-token", "helper presents broker's token (no holder block for helper)", &["CAP-121"], auth_input("helper", "skill:run-tests", Some(b64(&std_access("", "eph:basic")))), Err(CapabilityDenied)));

    // --- holder chain
    let tw = third_party(&std_access("", "eph:hw:0"), &ak("helper"), &format!("holder(\"{}\", 1);", agent("helper")), "eph:hw:1");
    v.push(case("holder-block-wrong-key", "holder block naming helper is signed by helper, not by broker", &["CAP-120"], auth_input("helper", "skill:run-tests", Some(b64(&tw))), Err(CapabilityInvalid)));
    let te = attenuate(&std_access("", "eph:he:0"), &format!("holder(\"{}\", 1);", agent("helper")), "eph:he:1");
    v.push(case("ephemeral-block-sets-holder", "an ordinary attenuation block tries to name a new holder", &["CAP-120"], auth_input("helper", "skill:run-tests", Some(b64(&te))), Err(CapabilityInvalid)));
    let tg = third_party(&std_access("", "eph:hg:0"), &ak("broker"), &format!("holder(\"{}\", 2);", agent("helper")), "eph:hg:1");
    v.push(case("holder-depth-gap", "holder block jumps from depth 0 to 2", &["CAP-120"], auth_input("helper", "skill:run-tests", Some(b64(&tg))), Err(CapabilityInvalid)));
    let tf = third_party(&std_access("", "eph:hf:0"), &ak("broker"), &format!("holder(\"{}\", 1);\nholder(\"{}\", 1);", agent("helper"), agent("helper2")), "eph:hf:1");
    v.push(case("holder-block-two-holders", "one holder block names two next holders (fork)", &["CAP-120"], auth_input("helper", "skill:run-tests", Some(b64(&tf))), Err(CapabilityInvalid)));
    let tc = {
        let t = delegate(&std_access("", "eph:hc:0"), &ak("broker"), "helper", 1, "", "eph:hc:1");
        delegate(&t, &ak("helper"), "broker", 2, "", "eph:hc:2")
    };
    v.push(case("holder-cycle", "broker -> helper -> broker", &["CAP-120"], std_input(&tc), Err(CapabilityInvalid)));
    let names = ["broker", "helper", "helper2", "helper3", "helper4", "helper5"];
    let mut td = std_access("", "eph:hd:0");
    for d in 1..names.len() {
        td = delegate(&td, &ak(names[d - 1]), names[d], d as i64, "", &format!("eph:hd:{d}"));
    }
    v.push(case("holder-depth-exceeded", "five re-delegations, MAX_HOLDER_DEPTH is 4", &["CAP-120"], auth_input("helper5", "skill:run-tests", Some(b64(&td))), Err(CapabilityInvalid)));
    let mut td4 = std_access("", "eph:hd4:0");
    for d in 1..5 {
        td4 = delegate(&td4, &ak(names[d - 1]), names[d], d as i64, "", &format!("eph:hd4:{d}"));
    }
    v.push(case("holder-depth-max", "four re-delegations, at the limit", &["CAP-120"], auth_input("helper4", "skill:run-tests", Some(b64(&td4))), ok));

    // --- over-attenuated and widening attempts
    let to = attenuate(&std_access("", "eph:oa:0"), "check if time($t), $t <= 2026-11-07T11:45:00Z;", "eph:oa:1");
    v.push(case("over-attenuated-ttl", "an attenuation block cut the TTL to before now", &["CAP-160"], std_input(&to), Err(CapabilityDenied)));
    let to = delegate(&std_access("", "eph:oaa:0"), &ak("broker"), "helper", 1, "check if arg(\"suite\", \"lint\");", "eph:oaa:1");
    v.push(case("over-attenuated-args", "helper's holder block only allows suite=lint, request has suite=unit", &["CAP-160"], auth_input("helper", "skill:run-tests", Some(b64(&to))), Err(CapabilityDenied)));
    let to = attenuate(&std_access("", "eph:oac:0"), "check if calls($n), $n < 5;", "eph:oac:1");
    let mut i = std_input(&to);
    i["state"]["calls"]["access"] = json!(5);
    v.push(case("calls-exhausted", "five calls already counted for this authority block", &["CAP-130"], i, Err(CapabilityDenied)));
    let to = attenuate(&std_access("", "eph:oao:0"), "check if operation(\"SendMessage\");", "eph:oao:1");
    let mut i = std_input(&to);
    i["request"]["operation"] = json!("SendStreamingMessage");
    v.push(case("over-attenuated-operation", "attenuated to SendMessage, request streams", &["CAP-160"], i, Err(CapabilityDenied)));
    let tw = attenuate(&std_access("", "eph:wd:0"), "right(\"skill:deploy\");", "eph:wd:1");
    v.push(case("attenuation-cannot-widen", "an attenuation block adds right(skill:deploy)", &["CAP-160"], auth_input("broker", "skill:deploy", Some(b64(&tw))), Err(CapabilityDenied)));
    let tw = delegate(&std_access("", "eph:wh:0"), &ak("broker"), "helper", 1, "right(\"skill:deploy\");", "eph:wh:1");
    v.push(case("holder-block-cannot-widen", "a holder block adds right(skill:deploy)", &["CAP-160"], auth_input("helper", "skill:deploy", Some(b64(&tw))), Err(CapabilityDenied)));
    v.push(case("capability-not-granted", "token grants skill:run-tests, request uses skill:deploy", &["CAP-160"], auth_input("broker", "skill:deploy", Some(b64(&std_access("", "eph:basic")))), Err(CapabilityDenied)));
    let mut i = std_input(&std_access("", "eph:basic"));
    i["request"]["operation"] = json!("CancelTask");
    v.push(case("operation-not-allowed", "skill capability does not allow CancelTask", &["CAP-102"], i, Err(CapabilityDenied)));
    let mut i = std_input(&std_access("", "eph:basic"));
    i["verifier"]["policy"] = json!(format!("deny if presenter(\"{}\");", agent("broker")));
    v.push(case("local-policy-deny", "owner policy denies this presenter", &["CAP-160"], i, Err(CapabilityDenied)));
    let blowup: String = (0..40).map(|n| format!("a({n});\n")).collect::<String>() + "p($x, $y) <- a($x), a($y);\ncheck if p(0, 0);";
    let tl2 = attenuate(&std_access("", "eph:dl:0"), &blowup, "eph:dl:1");
    v.push(case("datalog-limits", "an attenuation block whose rules derive thousands of facts", &["CAP-101"], std_input(&tl2), Err(CapabilityInvalid)));
    let mut i = std_input(&mint(&ik("C"), &access_code("C", "C", &["skill:run-tests"], "broker", T_ISSUED, T_EXPIRES, &format!("check if mandate_owner(\"{}\");", owner("A"))), "eph:onward"));
    i["cap"]["onward"] = json!([mandate_obj(&std_mandate("", "eph:m:onward"))]);
    v.push(case("onward-is-not-a-mandate", "a valid mandate in cap.onward does not satisfy a mandate requirement", &["CAP-181", "CAP-182"], i, Err(CapabilityDenied)));

    // --- revocation
    let tr = std_access("", "eph:rev");
    let ids = cap::revocation_ids(&tr);
    let mut i = std_input(&tr);
    i["state"]["revocations"] = json!([issuer_list("C", "C", 3, vec![ids[0].clone()])]);
    v.push(case("revoked-authority", "C's issuing key revoked the authority block", &["CAP-171"], i, Err(CapabilityRevoked)));
    let trh = delegate(&std_access("", "eph:revh:0"), &ak("broker"), "helper", 1, "", "eph:revh:1");
    let mut i = auth_input("helper", "skill:run-tests", Some(b64(&trh)));
    i["state"]["revocations"] = json!([issuer_list("C", "C", 3, vec![cap::revocation_ids(&trh)[1].clone()])]);
    v.push(case("revoked-holder-block", "the holder block (broker -> helper) is revoked", &["CAP-171"], i, Err(CapabilityRevoked)));
    let mut i = std_input(&tr);
    let icid = stmt::statement_id(&issuer_cert("C", "C", "gamma")).unwrap();
    i["state"]["revocations"] = json!([revocation_list("owner:C", &owner("C"), "C", 1, "2026-11-05T00:00:00Z", "2026-12-01T00:00:00Z", vec![icid])]);
    v.push(case("revoked-issuer-cert", "C's root key revoked the issuing key's certificate", &["CAP-171", "CAP-015"], i, Err(CapabilityRevoked)));
    let mut i = std_input(&tr);
    i["state"]["revocations"] = json!([revocation_list(&ik("C"), &issuer("C"), "C", 3, "2026-11-06T00:00:00Z", "2026-11-07T00:00:00Z", vec![ids[0].clone()])]);
    v.push(case("revoked-by-stale-list", "a stale list still proves what it lists", &["CAP-171"], i, Err(CapabilityRevoked)));
    let mut i = std_input(&tr);
    i["state"]["revocations"] = json!([issuer_list("C", "C", 5, vec![ids[0].clone()])]);
    i["cap"]["revocations"] = json!([issuer_list("C", "C", 4, vec![])]);
    v.push(case("revocation-rollback", "a stapled older list (seq 4) does not replace seq 5", &["CAP-170", "CAP-173"], i, Err(CapabilityRevoked)));
    let mut i = std_input(&tl);
    i["state"]["revocations"] = json!([]);
    v.push(case("revocation-status-unavailable", "20-day token, no list from its issuing key", &["CAP-172"], i, Err(RevocationStatusUnavailable)));
    let mut i = std_input(&tl);
    i["state"]["revocations"] = json!([revocation_list(&ik("C"), &issuer("C"), "C", 3, "2026-11-06T00:00:00Z", "2026-11-07T00:00:00Z", vec![])]);
    v.push(case("revocation-list-stale", "20-day token, only a stale list", &["CAP-172"], i, Err(RevocationStatusUnavailable)));

    // --- mandates: deny
    let ta_ob = mint(&ik("C"), &ta_code_fixed, "eph:onbehalf");
    v.push(case("mandate-required-missing", "access usable only on behalf of A, no mandate", &["CAP-182"], std_input(&ta_ob), Err(CapabilityDenied)));
    let mx = mint(&ik("X"), &mandate_code("X", "X", "mallory", &[("C", "skill:run-tests")], "broker", T_ISSUED, T_EXPIRES, ""), "eph:m:x");
    let i = with_mandate(std_input(&std_access("", "eph:basic")), json!({"token": b64(&mx), "issuerCert": issuer_cert("X", "X", "x"), "principalCert": agent_cert("X", "mallory", "x")}));
    v.push(case("mandate-unpinned-owner", "mandate rooted in an owner C has not pinned", &["CAP-180"], i, Err(CapabilityInvalid)));
    let mo = mint(&ik("A"), &mandate_code("A", "A", "planner", &[("B", "skill:run-tests")], "broker", T_ISSUED, T_EXPIRES, ""), "eph:m:other");
    let i = with_mandate(std_input(&std_access("", "eph:basic")), mandate_obj(&mo));
    v.push(case("mandate-grant-other-owner", "mandate grants run-tests at B's resources, not C's", &["CAP-180"], i, Err(CapabilityDenied)));
    let mo = mint(&ik("A"), &mandate_code("A", "A", "planner", &[("C", "skill:lint")], "broker", T_ISSUED, T_EXPIRES, ""), "eph:m:othercap");
    let i = with_mandate(std_input(&std_access("", "eph:basic")), mandate_obj(&mo));
    v.push(case("mandate-other-capability", "mandate grants skill:lint, request is skill:run-tests", &["CAP-180"], i, Err(CapabilityDenied)));
    let narrow = json!({"resource": [], "mandate": {"targets": [owner("C")], "capabilities": ["skill:lint"], "maxTtl": 3600}});
    let mut mobj = mandate_obj(&std_mandate("", "eph:m:std2"));
    mobj["issuerCert"] = issuer_cert_full("A", "A", "alpha", narrow, CERT_IAT, ISSUER_EXP);
    v.push(case("mandate-broader-than-scope", "A's issuing key may only mandate skill:lint", &["CAP-030"], with_mandate(std_input(&std_access("", "eph:basic")), mobj), Err(CapabilityInvalid)));
    let mut mobj = mandate_obj(&std_mandate("", "eph:m:std3"));
    mobj["issuerCert"] = issuer_cert_full("A", "A", "alpha", json!({"resource": ["skill:*"]}), CERT_IAT, ISSUER_EXP);
    v.push(case("mandate-no-mandate-scope", "A's issuing key has no mandate scope", &["CAP-030"], with_mandate(std_input(&std_access("", "eph:basic")), mobj), Err(CapabilityInvalid)));
    let ml = mint(&ik("A"), &mandate_code("A", "A", "planner", &[("C", "skill:run-tests")], "broker", "2026-11-07T11:30:00Z", "2026-11-07T13:30:00Z", ""), "eph:m:ttl");
    v.push(case("mandate-ttl-over-scope", "mandate valid 2 hours, scope maxTtl is 1 hour", &["CAP-030", "CAP-111"], with_mandate(std_input(&std_access("", "eph:basic")), mandate_obj(&ml)), Err(CapabilityInvalid)));
    let mut mobj = mandate_obj(&std_mandate("", "eph:m:std4"));
    mobj["principalCert"] = agent_cert("A", "planner", "beta");
    v.push(case("mandate-principal-other-node", "principal is certified to a node other than the issuing key's", &["CAP-031"], with_mandate(std_input(&std_access("", "eph:basic")), mobj), Err(CapabilityInvalid)));
    let mut mobj = mandate_obj(&std_mandate("", "eph:m:std5"));
    mobj.as_object_mut().unwrap().remove("principalCert");
    v.push(case("mandate-principal-cert-missing", "no principal agent-cert", &["CAP-031"], with_mandate(std_input(&std_access("", "eph:basic")), mobj), Err(CapabilityInvalid)));
    let mp = delegate(&std_mandate("", "eph:m:prev:0"), &ak("broker"), "helper", 1, "", "eph:m:prev:1");
    v.push(case("mandate-previous-holder", "broker re-delegated the mandate to helper, then presents it", &["CAP-180", "CAP-121"], with_mandate(std_input(&std_access("", "eph:basic")), mandate_obj(&mp)), Err(CapabilityDenied)));
    let mh = attenuate(&std_mandate("", "eph:m:hop:0"), &format!("holder(\"{}\", 1);", agent("helper")), "eph:m:hop:1");
    let ar2 = delegate(&std_access("", "eph:a:hop:0"), &ak("broker"), "helper", 1, "", "eph:a:hop:1");
    v.push(case("mandate-hop-without-identity", "mandate passed to helper by an ephemeral-key block", &["CAP-120", "CAP-180"], with_mandate(auth_input("helper", "skill:run-tests", Some(b64(&ar2))), mandate_obj(&mh)), Err(CapabilityInvalid)));
    let mut mobj = mandate_obj(&std_mandate("", "eph:m:std6"));
    mobj["token"] = json!(b64(&mint(&ik("A"), &access_code("A", "A", &["skill:run-tests"], "broker", T_ISSUED, T_EXPIRES, ""), "eph:m:asacc")));
    v.push(case("access-as-mandate", "an access token in the mandate slot", &["CAP-104", "CAP-180"], with_mandate(std_input(&std_access("", "eph:basic")), mobj), Err(CapabilityInvalid)));
    let me = mint(&ik("A"), &mandate_code("A", "A", "planner", &[("C", "skill:run-tests")], "broker", "2026-11-07T10:30:00Z", "2026-11-07T11:30:00Z", ""), "eph:m:exp");
    v.push(case("mandate-expired", "mandate past its expires", &["CAP-180"], with_mandate(std_input(&std_access("", "eph:basic")), mandate_obj(&me)), Err(CapabilityDenied)));
    let mut i = with_mandate(std_input(&std_access("", "eph:basic")), mandate_obj(&m));
    i["state"]["calls"]["mandate"] = json!(1);
    v.push(case("mandate-calls-exhausted", "one-use mandate already used at C", &["CAP-130", "CAP-180"], i, Err(CapabilityDenied)));
    let ma = std_mandate("check if arg(\"repo\", \"github.com/acme/other\");", "eph:m:arg");
    v.push(case("mandate-arg-mismatch", "mandate constrains repo, request names another", &["CAP-180"], with_mandate(std_input(&std_access("", "eph:basic")), mandate_obj(&ma)), Err(CapabilityDenied)));
    let mrv = std_mandate("", "eph:m:rev");
    let mut i = with_mandate(std_input(&std_access("", "eph:basic")), mandate_obj(&mrv));
    i["cap"]["revocations"] = json!([issuer_list("A", "A", 2, vec![cap::revocation_ids(&mrv)[0].clone()])]);
    v.push(case("mandate-revoked", "A revoked the mandate; the list is stapled", &["CAP-171", "CAP-173"], i, Err(CapabilityRevoked)));
    let mut i = with_mandate(std_input(&std_access("", "eph:basic")), mandate_obj(&std_mandate("", "eph:m:pol")));
    i["verifier"]["policy"] = json!(format!("deny if mandate_owner(\"{}\");", owner("A")));
    v.push(case("mandate-policy-deny-owner", "C's policy refuses work on behalf of owner A", &["CAP-182"], i, Err(CapabilityDenied)));
    let mut mobj = mandate_obj(&std_mandate("", "eph:m:bad"));
    let mut tokb = B64.decode(mobj["token"].as_str().unwrap().as_bytes()).unwrap();
    let n = tokb.len();
    tokb[n - 70] ^= 1;
    mobj["token"] = json!(B64.encode(&tokb));
    v.push(case("mandate-invalid-not-ignored", "a corrupted mandate fails the request, even though access alone would pass", &["CAP-180"], with_mandate(std_input(&std_access("", "eph:basic")), mobj), Err(CapabilityInvalid)));
    let mb = std_mandate("", "eph:m:holder");
    let ah = delegate(&std_access("", "eph:a:mh:0"), &ak("broker"), "helper", 1, "", "eph:a:mh:1");
    v.push(case("mandate-holder-not-presenter", "access re-delegated to helper, mandate still held by broker", &["CAP-180", "CAP-121"], with_mandate(auth_input("helper", "skill:run-tests", Some(b64(&ah))), mandate_obj(&mb)), Err(CapabilityDenied)));

    // --- order of checks
    let mut i = std_input(&texp);
    i["state"]["revocations"] = json!([issuer_list("C", "C", 3, vec![cap::revocation_ids(&texp)[0].clone()])]);
    v.push(case("order-expired-before-revoked", "expired and revoked: expiry (step 5) is reported", &["CAP-160"], i, Err(CapabilityDenied)));
    let mut i = auth_input("broker", "skill:run-tests", Some("not a token!".into()));
    i["verifier"]["agentCerts"] = json!([]);
    v.push(case("order-presenter-before-token", "uncertified presenter and garbage token: step 2 is reported", &["CAP-160", "CAP-041"], i, Err(CapabilityDenied)));

    // --- invite redemption
    v.extend(redeem_cases());
    v.extend(followup_cases());
    v
}

const INVITE_ID: &str = "0190f1d0-1111-7000-8000-000000000001";

fn redeem_token() -> biscuit_auth::Biscuit {
    let ikey = ids::agent("invite-key:1");
    mint(
        &ik("C"),
        &format!(
            "webway(\"capability/v0\", \"access\");\nissuer(\"{}\");\nowner(\"{}\");\nissued(2026-11-07T08:00:00Z);\nexpires(2026-11-08T08:00:00Z);\nright(\"invite:{INVITE_ID}#redeem\");\nholder(\"{ikey}\", 0);\ncheck if presenter($k), current_holder($k);\n",
            issuer("C"),
            owner("C")
        ),
        "eph:inv:0",
    )
}

fn redeem_cases() -> Vec<Case> {
    let t = redeem_token();
    let t = delegate(&t, "invite-key:1", "invitee", 1, "", "eph:inv:1");
    let mut i = auth_input("invitee", &format!("invite:{INVITE_ID}#redeem"), Some(b64(&t)));
    i["request"]["operation"] = json!("InviteRedeem");
    i["state"]["revocations"] = json!([issuer_list("C", "C", 7, vec![])]);
    let mut consumed = i.clone();
    consumed["state"]["consumedInvites"] = json!([INVITE_ID]);
    let mut wrongop = i.clone();
    wrongop["request"]["operation"] = json!("SendMessage");
    vec![
        case("invite-redeem", "the invitee (unpinned owner X) redeems a redeem-mode invite via the invite key's holder block", &["CAP-203", "CAP-120"], i, Ok(())),
        case("invite-redeem-consumed", "the invite was already redeemed", &["CAP-203"], consumed, Err(E::InviteConsumed)),
        case("invite-redeem-wrong-operation", "a redeem token cannot send messages", &["CAP-102"], wrongop, Err(E::CapabilityDenied)),
    ]
}

// ---------------------------------------------------------------- identity/statement

fn stmt_input(typ: &str, s: Value, pins: Value) -> Value {
    json!({"now": NOW, "typ": typ, "statement": s, "pins": pins})
}
fn pin_c() -> Value {
    json!([{"owner": owner("C")}])
}
fn node_cert() -> Value {
    sign(stmt::NODE_CERT, &sk("owner:C"), &owner("C"), json!({"owner": owner("C"), "node": node("gamma"), "iat": CERT_IAT, "exp": AGENT_EXP}))
}

fn add_l_to_s(sig: &mut [u8]) {
    // L = 2^252 + 27742317777372353535851937790883648493, little-endian.
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let mut carry = 0u16;
    for k in 0..32 {
        let s = sig[32 + k] as u16 + L[k] as u16 + carry;
        sig[32 + k] = s as u8;
        carry = s >> 8;
    }
}

fn statement_cases() -> Vec<Case> {
    use E::*;
    let ok = Ok(());
    let mut v = vec![];
    let nc = node_cert();
    v.push(case("node-cert", "root-signed node-cert", &["CAP-010", "CAP-011", "CAP-013"], stmt_input(stmt::NODE_CERT, nc.clone(), pin_c()), ok));
    v.push(case("issuer-cert", "root-signed issuer-cert", &["CAP-013"], stmt_input(stmt::ISSUER_CERT, issuer_cert("C", "C", "gamma"), pin_c()), ok));
    v.push(case("agent-cert-root", "root-signed agent-cert", &["CAP-013"], stmt_input(stmt::AGENT_CERT, agent_cert("C", "runner", "gamma"), pin_c()), ok));
    let ac_iss = sign(stmt::AGENT_CERT, &sk(&ik("C")), &issuer("C"), json!({"owner": owner("C"), "agent": agent("runner"), "node": node("gamma"), "iat": CERT_IAT, "exp": ISSUER_EXP}));
    let mut i = stmt_input(stmt::AGENT_CERT, ac_iss.clone(), pin_c());
    i["issuerCert"] = issuer_cert("C", "C", "gamma");
    v.push(case("agent-cert-issuer", "agent-cert signed by an issuing key with agentCerts scope on the same node", &["CAP-040", "CAP-013"], i, ok));
    let mut i = stmt_input(stmt::AGENT_CERT, ac_iss.clone(), pin_c());
    i["issuerCert"] = issuer_cert_full("C", "C", "gamma", json!({"resource": ["skill:*"], "agentCerts": false}), CERT_IAT, ISSUER_EXP);
    v.push(case("agent-cert-issuer-no-scope", "the issuing key lacks agentCerts", &["CAP-040"], i, Err(StatementUntrusted)));
    let ac_other = sign(stmt::AGENT_CERT, &sk(&ik("C")), &issuer("C"), json!({"owner": owner("C"), "agent": agent("runner"), "node": node("beta"), "iat": CERT_IAT, "exp": ISSUER_EXP}));
    let mut i = stmt_input(stmt::AGENT_CERT, ac_other, pin_c());
    i["issuerCert"] = issuer_cert("C", "C", "gamma");
    v.push(case("agent-cert-issuer-other-node", "issuing key on gamma certifies an agent on beta", &["CAP-040"], i, Err(StatementUntrusted)));
    let ac_long = sign(stmt::AGENT_CERT, &sk(&ik("C")), &issuer("C"), json!({"owner": owner("C"), "agent": agent("runner"), "node": node("gamma"), "iat": CERT_IAT, "exp": "2026-12-15T00:00:00Z"}));
    let mut i = stmt_input(stmt::AGENT_CERT, ac_long, pin_c());
    i["issuerCert"] = issuer_cert("C", "C", "gamma");
    v.push(case("agent-cert-outlives-issuer", "agent-cert signed by an issuing key expires after its issuer-cert", &["CAP-014"], i, Err(StatementInvalid)));
    let nc_iss = sign(stmt::NODE_CERT, &sk(&ik("C")), &issuer("C"), json!({"owner": owner("C"), "node": node("gamma"), "iat": CERT_IAT, "exp": ISSUER_EXP}));
    let mut i = stmt_input(stmt::NODE_CERT, nc_iss, pin_c());
    i["issuerCert"] = issuer_cert("C", "C", "gamma");
    v.push(case("node-cert-by-issuer", "issuing keys cannot sign node-certs", &["CAP-013"], i, Err(StatementUntrusted)));
    let rl = issuer_list("C", "C", 1, vec![]);
    let mut i = stmt_input(stmt::REVOCATION, rl, pin_c());
    i["issuerCert"] = issuer_cert("C", "C", "gamma");
    v.push(case("revocation-list-issuer", "revocation list signed by an issuing key", &["CAP-013"], i, ok));
    let rl_long = revocation_list(&ik("C"), &issuer("C"), "C", 1, "2026-11-07T06:00:00Z", "2026-11-09T06:00:00Z", vec![]);
    let mut i = stmt_input(stmt::REVOCATION, rl_long, pin_c());
    i["issuerCert"] = issuer_cert("C", "C", "gamma");
    v.push(case("revocation-list-too-long", "issuer-signed list valid 48 hours, MAX_LIST_VALIDITY is 24", &["CAP-014"], i, Err(StatementInvalid)));

    // format
    let mut bad = nc.clone();
    let mut sig = B64.decode(bad["signature"].as_str().unwrap().as_bytes()).unwrap();
    sig[5] ^= 1;
    bad["signature"] = json!(B64.encode(&sig));
    v.push(case("sig-bad", "one bit of the signature flipped", &["CAP-011", "CAP-002"], stmt_input(stmt::NODE_CERT, bad, pin_c()), Err(StatementInvalid)));
    let mut bad = nc.clone();
    let mut sig = B64.decode(bad["signature"].as_str().unwrap().as_bytes()).unwrap();
    add_l_to_s(&mut sig);
    bad["signature"] = json!(B64.encode(&sig));
    v.push(case("sig-non-canonical-s", "S replaced by S + L (malleated signature)", &["CAP-002"], stmt_input(stmt::NODE_CERT, bad, pin_c()), Err(StatementInvalid)));
    let mut small = vec![0xed, 0x01, 0x01];
    small.extend_from_slice(&[0u8; 31]);
    let small_did = format!("did:key:z{}", bs58::encode(small).into_string());
    let s = sign_raw(&sk("owner:C"), &format!("{{\"alg\":\"EdDSA\",\"kid\":\"{small_did}\",\"typ\":\"{}\"}}", stmt::NODE_CERT), &format!("{{\"exp\":\"{AGENT_EXP}\",\"iat\":\"{CERT_IAT}\",\"iss\":\"{small_did}\",\"node\":\"{}\",\"owner\":\"{small_did}\"}}", node("gamma")));
    v.push(case("kid-small-order", "kid is the identity point (small order)", &["CAP-002", "CAP-001"], stmt_input(stmt::NODE_CERT, s, json!([{"owner": small_did}])), Err(StatementInvalid)));
    v.push(case("typ-mismatch", "a node-cert presented where an agent-cert is expected", &["CAP-012"], stmt_input(stmt::AGENT_CERT, nc.clone(), pin_c()), Err(StatementInvalid)));
    let payload = |extra: &str| format!("{{\"exp\":\"{AGENT_EXP}\",\"iat\":\"{CERT_IAT}\",\"iss\":\"{}\",\"node\":\"{}\",\"owner\":\"{}\"{extra}}}", owner("C"), node("gamma"), owner("C"));
    let hdr = |extra: &str| format!("{{\"alg\":\"EdDSA\"{extra},\"kid\":\"{}\",\"typ\":\"{}\"}}", owner("C"), stmt::NODE_CERT);
    v.push(case("header-extra-member", "protected header has an extra member (crit)", &["CAP-010"], stmt_input(stmt::NODE_CERT, sign_raw(&sk("owner:C"), &hdr(",\"crit\":[\"b64\"]"), &payload("")), pin_c()), Err(StatementInvalid)));
    let s = sign_raw(&sk("owner:C"), &format!("{{\"alg\":\"ES256\",\"kid\":\"{}\",\"typ\":\"{}\"}}", owner("C"), stmt::NODE_CERT), &payload(""));
    v.push(case("alg-not-eddsa", "alg is ES256", &["CAP-010"], stmt_input(stmt::NODE_CERT, s, pin_c()), Err(StatementInvalid)));
    let s = sign_raw(&sk("owner:C"), &hdr(""), &payload("").replace(",\"iat\"", ", \"iat\""));
    v.push(case("payload-not-jcs", "payload has a space, so it is not its JCS form", &["CAP-010"], stmt_input(stmt::NODE_CERT, s, pin_c()), Err(StatementInvalid)));
    let s = sign_raw(&sk("owner:C"), &hdr(""), &payload("").replace("\"exp\":\"2027-10-01T00:00:00Z\",", "\"exp\":\"2027-10-01T00:00:00Z\",\"exp\":\"2027-10-01T00:00:00Z\","));
    v.push(case("payload-duplicate-key", "payload repeats a member (not I-JSON)", &["CAP-010"], stmt_input(stmt::NODE_CERT, s, pin_c()), Err(StatementInvalid)));
    let s = sign(stmt::NODE_CERT, &sk("owner:C"), &owner("C"), json!({"owner": owner("C"), "node": node("gamma"), "iat": CERT_IAT, "exp": AGENT_EXP}));
    let p = String::from_utf8(B64.decode(s["payload"].as_str().unwrap().as_bytes()).unwrap()).unwrap();
    let p = p.replace(&format!("\"iss\":\"{}\"", owner("C")), &format!("\"iss\":\"{}\"", owner("B")));
    let s2 = sign_raw(&sk("owner:C"), &hdr(""), &p);
    v.push(case("iss-not-kid", "claims iss differs from kid", &["CAP-010"], stmt_input(stmt::NODE_CERT, s2, pin_c()), Err(StatementInvalid)));
    let mut extra = nc.clone();
    extra["header"] = json!({});
    v.push(case("jws-extra-member", "the JWS object has an unprotected header", &["CAP-010"], stmt_input(stmt::NODE_CERT, extra, pin_c()), Err(StatementInvalid)));

    // trust
    v.push(case("unpinned-owner", "a valid node-cert of an owner the verifier has not pinned", &["CAP-013"], stmt_input(stmt::NODE_CERT, nc.clone(), json!([{"owner": owner("A")}])), Err(StatementUntrusted)));
    let forged = sign(stmt::NODE_CERT, &sk("owner:X"), &owner("X"), json!({"owner": owner("C"), "node": node("x"), "iat": CERT_IAT, "exp": AGENT_EXP}));
    v.push(case("signer-not-owner-root", "X signs a node-cert claiming owner C", &["CAP-013"], stmt_input(stmt::NODE_CERT, forged, json!([{"owner": owner("C")}, {"owner": owner("X")}])), Err(StatementUntrusted)));

    // time
    let exp = sign(stmt::NODE_CERT, &sk("owner:C"), &owner("C"), json!({"owner": owner("C"), "node": node("gamma"), "iat": "2026-01-01T00:00:00Z", "exp": "2026-11-07T11:59:59Z"}));
    v.push(case("expired", "node-cert expired one second ago", &["CAP-014"], stmt_input(stmt::NODE_CERT, exp, pin_c()), Err(StatementExpired)));
    let fut = sign(stmt::NODE_CERT, &sk("owner:C"), &owner("C"), json!({"owner": owner("C"), "node": node("gamma"), "iat": "2026-11-07T12:06:00Z", "exp": AGENT_EXP}));
    v.push(case("iat-future", "iat 6 minutes ahead, SKEW is 5", &["CAP-014"], stmt_input(stmt::NODE_CERT, fut, pin_c()), Err(StatementExpired)));
    let fut_ok = sign(stmt::NODE_CERT, &sk("owner:C"), &owner("C"), json!({"owner": owner("C"), "node": node("gamma"), "iat": "2026-11-07T12:04:00Z", "exp": AGENT_EXP}));
    v.push(case("iat-within-skew", "iat 4 minutes ahead is accepted", &["CAP-014"], stmt_input(stmt::NODE_CERT, fut_ok, pin_c()), ok));
    let long = issuer_cert_full("C", "C", "gamma", full_scope(), "2026-11-01T00:00:00Z", "2026-12-02T00:00:00Z");
    v.push(case("issuer-cert-ttl-too-long", "issuer-cert valid 31 days", &["CAP-014"], stmt_input(stmt::ISSUER_CERT, long, pin_c()), Err(StatementInvalid)));

    // revocation
    let mut i = stmt_input(stmt::NODE_CERT, nc.clone(), pin_c());
    i["revocations"] = json!([revocation_list("owner:C", &owner("C"), "C", 1, "2026-11-05T00:00:00Z", "2026-12-01T00:00:00Z", vec![stmt::statement_id(&nc).unwrap()])]);
    v.push(case("revoked", "C's root list revokes the node-cert", &["CAP-015"], i, Err(StatementRevoked)));
    let mut i = stmt_input(stmt::AGENT_CERT, ac_iss.clone(), pin_c());
    i["issuerCert"] = issuer_cert("C", "C", "gamma");
    i["revocations"] = json!([revocation_list("owner:C", &owner("C"), "C", 1, "2026-11-05T00:00:00Z", "2026-12-01T00:00:00Z", vec![stmt::statement_id(&issuer_cert("C", "C", "gamma")).unwrap()])]);
    v.push(case("revoked-chain", "the issuer-cert that signs the agent-cert is revoked", &["CAP-015"], i, Err(StatementRevoked)));

    // rotation
    let (events, _) = rotation_events(false);
    let old_signed = node_cert();
    v.push(case("rotated-old-key-valid", "after a normal rotation, a cert signed by the old root key stays valid", &["CAP-021"], stmt_input(stmt::NODE_CERT, old_signed.clone(), json!([{"owner": owner("C"), "events": events}])), ok));
    let new_signed = sign(stmt::NODE_CERT, &sk("owner:C:root1"), &ids::owner("owner:C:root1"), json!({"owner": owner("C"), "node": node("gamma"), "iat": CERT_IAT, "exp": AGENT_EXP}));
    v.push(case("rotated-new-key", "a cert signed by the rotated-to root key", &["CAP-021", "CAP-013"], stmt_input(stmt::NODE_CERT, new_signed.clone(), json!([{"owner": owner("C"), "events": rotation_events(false).0}])), ok));
    v.push(case("rotated-new-key-not-known", "the same cert, but the verifier never saw the rotation", &["CAP-013"], stmt_input(stmt::NODE_CERT, new_signed, pin_c()), Err(StatementUntrusted)));
    let (cevents, _) = rotation_events(true);
    v.push(case("rotated-compromised-old-key", "after a rotation marked compromised, the old key's certs are rejected", &["CAP-021"], stmt_input(stmt::NODE_CERT, old_signed, json!([{"owner": owner("C"), "events": cevents}])), Err(StatementUntrusted)));
    v
}

fn owner_event(signer: &str, own: &str, seq: i64, prev: Option<String>, next_of: Option<&str>, compromised: bool) -> Value {
    let mut c = json!({"owner": own, "seq": seq, "key": ids::owner(signer), "iat": "2026-11-02T00:00:00Z"});
    if let Some(p) = prev {
        c["prev"] = json!(p);
    }
    if let Some(n) = next_of {
        c["next"] = json!(commitment(&keys::public(n)));
    }
    if compromised {
        c["compromised"] = json!(true);
    }
    sign(stmt::OWNER_KEY, &sk(signer), &ids::owner(signer), c)
}

/// Inception of owner C (key owner:C, committing to owner:C:root1), then a rotation to root1.
fn rotation_events(compromised: bool) -> (Vec<Value>, Value) {
    let e0 = owner_event("owner:C", &owner("C"), 0, None, Some("owner:C:root1"), false);
    let e1 = owner_event("owner:C:root1", &owner("C"), 1, stmt::statement_id(&e0), Some("owner:C:root2"), compromised);
    (vec![e0.clone(), e1], e0)
}

fn owner_key_cases() -> Vec<Case> {
    use E::*;
    let o = owner("C");
    let pin = json!({"owner": o});
    let e0 = owner_event("owner:C", &o, 0, None, Some("owner:C:root1"), false);
    let e0n = owner_event("owner:C", &o, 0, None, None, false);
    let e1 = owner_event("owner:C:root1", &o, 1, stmt::statement_id(&e0), Some("owner:C:root2"), false);
    let e2 = owner_event("owner:C:root2", &o, 2, stmt::statement_id(&e1), None, false);
    let thief = owner_event("owner:X", &o, 1, stmt::statement_id(&e0), None, false);
    let from_no_next = owner_event("owner:C:root1", &o, 1, stmt::statement_id(&e0n), None, false);
    let bad_prev = owner_event("owner:C:root1", &o, 1, stmt::statement_id(&e0n), None, false);
    let skip = owner_event("owner:C:root1", &o, 2, stmt::statement_id(&e0), None, false);
    let other_owner = owner_event("owner:C:root1", &owner("B"), 1, stmt::statement_id(&e0), None, false);
    let inc_other = owner_event("owner:C:root1", &o, 0, None, None, false);
    let mk = |evs: Vec<Value>| json!({"pin": pin, "events": evs});
    vec![
        case("inception", "inception event with a pre-rotation commitment", &["CAP-020"], mk(vec![e0.clone()]), Ok(())),
        case("rotation", "rotation to the committed key", &["CAP-020"], mk(vec![e0.clone(), e1.clone()]), Ok(())),
        case("two-rotations", "two rotations in a row", &["CAP-020"], mk(vec![e0.clone(), e1.clone(), e2]), Ok(())),
        case("rotation-uncommitted-key", "a thief of the current key rotates to its own key", &["CAP-020"], mk(vec![e0.clone(), thief]), Err(StatementUntrusted)),
        case("rotation-without-commitment", "the inception event has no next: no rotation possible", &["CAP-020"], mk(vec![e0n, from_no_next]), Err(StatementUntrusted)),
        case("rotation-wrong-prev", "prev is not the ID of the held event", &["CAP-020"], mk(vec![e0.clone(), bad_prev]), Err(StatementUntrusted)),
        case("rotation-seq-skip", "seq jumps from 0 to 2", &["CAP-020"], mk(vec![e0.clone(), skip]), Err(StatementUntrusted)),
        case("rotation-other-owner", "the event names another owner", &["CAP-020"], mk(vec![e0, other_owner]), Err(StatementUntrusted)),
        case("inception-not-owner-key", "inception signed by a key other than the owner identifier", &["CAP-020"], mk(vec![inc_other]), Err(StatementUntrusted)),
    ]
}

// ---------------------------------------------------------------- identity/id

fn id_cases() -> Vec<Case> {
    use E::*;
    let a = agent("planner");
    let mut v = vec![
        case("owner", "did:key owner", &["CAP-001"], json!({"id": owner("A")}), Ok(())),
        case("issuer", "wwi issuing key", &["CAP-001"], json!({"id": issuer("A")}), Ok(())),
        case("node", "wwn node", &["CAP-001"], json!({"id": node("alpha")}), Ok(())),
        case("agent", "wwa agent", &["CAP-001"], json!({"id": a.clone()}), Ok(())),
    ];
    let bad = |id: &str, d: &str, s: String| case(id, d, &["CAP-001"], json!({"id": s}), Err(IdentifierInvalid));
    v.push(bad("unknown-prefix", "wwx: is not a role", a.replacen("wwa:", "wwx:", 1)));
    v.push(bad("uppercase", "base32 must be lowercase", format!("wwa:{}", a[4..].to_uppercase())));
    v.push(bad("padding", "no base32 padding", format!("{a}====")));
    v.push(bad("too-short", "51 characters", a[..a.len() - 1].to_string()));
    v.push(bad("bad-alphabet", "the digit 1 is not in the alphabet", format!("{}1", &a[..a.len() - 1])));
    // 52 base32 chars = 260 bits for 256 bits of key: the last char carries 4 unused bits.
    let last = a.chars().last().unwrap();
    let alphabet = "abcdefghijklmnopqrstuvwxyz234567";
    let idx = alphabet.find(last).unwrap();
    let noncanon = alphabet.chars().nth(idx ^ 1).unwrap();
    v.push(bad("non-canonical-trailing-bits", "the unused trailing bits are not zero", format!("{}{noncanon}", &a[..a.len() - 1])));
    let mut x25519 = vec![0xec, 0x01];
    x25519.extend_from_slice(&keys::public("owner:A"));
    v.push(bad("did-key-not-ed25519", "multicodec 0xec01 (X25519)", format!("did:key:z{}", bs58::encode(x25519).into_string())));
    v.push(bad("did-key-not-base58btc", "did:key without the z multibase prefix", owner("A").replacen("did:key:z", "did:key:f", 1)));
    let mut small = vec![0xed, 0x01, 0x01];
    small.extend_from_slice(&[0u8; 31]);
    v.push(bad("did-key-small-order", "the identity point is not a usable key", format!("did:key:z{}", bs58::encode(small).into_string())));
    let mut so = [0u8; 32];
    so[0] = 1;
    v.push(bad("agent-small-order", "wwa with the identity point", ids::encode(ids::Role::Agent, &so)));
    v
}

// ---------------------------------------------------------------- capability/invite

struct InviteOpts {
    mode: &'static str,
    signer: &'static str,
    issuer_cert: Value,
    grants: Vec<String>,
    invitee: Option<String>,
    invite_key: Option<String>,
    iat: &'static str,
    exp: &'static str,
    agent_cert: Value,
    agent: String,
}

fn invite_default(mode: &'static str) -> InviteOpts {
    let grants = if mode == "bound" {
        vec![b64(&mint(&ik("B"), &access_code("B", "B", &["skill:run-tests"], "planner", "2026-11-07T11:30:00Z", "2026-11-07T12:30:00Z", "check if calls($n), $n < 5;"), "eph:invb"))]
    } else {
        vec![b64(&invite_redeem_grant("B", "invite-key:2", INVITE_ID))]
    };
    InviteOpts {
        mode,
        signer: "B",
        issuer_cert: issuer_cert("B", "B", "beta"),
        grants,
        invitee: (mode == "bound").then(|| agent("planner")),
        invite_key: (mode == "redeem").then(|| B64.encode(&keys::seed("invite-key:2"))),
        iat: "2026-11-07T11:00:00Z",
        exp: "2026-11-08T11:00:00Z",
        agent_cert: agent_cert("B", "broker", "beta"),
        agent: agent("broker"),
    }
}

fn invite_redeem_grant(iss: &str, invite_key: &str, id: &str) -> biscuit_auth::Biscuit {
    mint(
        &ik(iss),
        &format!(
            "webway(\"capability/v0\", \"access\");\nissuer(\"{}\");\nowner(\"{}\");\nissued(2026-11-07T11:00:00Z);\nexpires(2026-11-08T11:00:00Z);\nright(\"invite:{id}#redeem\");\nholder(\"{}\", 0);\ncheck if presenter($k), current_holder($k);\n",
            issuer(iss),
            owner(iss),
            ids::agent(invite_key)
        ),
        &format!("eph:invr:{invite_key}"),
    )
}

fn invite_string(o: &InviteOpts) -> String {
    let mut c = json!({
        "owner": owner("B"),
        "issuerCert": o.issuer_cert,
        "id": INVITE_ID,
        "node": node("beta"),
        "relays": ["https://relay.b.example"],
        "agents": [{"agent": o.agent, "cert": o.agent_cert}],
        "mode": o.mode,
        "grants": o.grants,
        "iat": o.iat,
        "exp": o.exp,
    });
    if let Some(i) = &o.invitee {
        c["invitee"] = json!(i);
    }
    if let Some(k) = &o.invite_key {
        c["inviteKey"] = json!(k);
    }
    let s = sign(stmt::INVITE, &sk(&ik(o.signer)), &issuer(o.signer), c);
    format!("{}{}", model::INVITE_PREFIX, B64.encode(crate::jcs::canonical(&s).unwrap().as_bytes()))
}

fn invite_cases() -> Vec<Case> {
    use E::*;
    let inp = |o: &InviteOpts| json!({"now": NOW, "invite": invite_string(o), "acceptingAgent": agent("planner")});
    let inp_r = |o: &InviteOpts| json!({"now": NOW, "invite": invite_string(o)});
    let mut v = vec![];
    v.push(case("bound", "bound invite from B to planner, one grant", &["CAP-201", "CAP-200"], inp(&invite_default("bound")), Ok(())));
    v.push(case("redeem", "redeem-mode invite with one redemption grant", &["CAP-201", "CAP-200"], inp_r(&invite_default("redeem")), Ok(())));
    let mut o = invite_default("bound");
    o.iat = "2026-11-06T11:00:00Z";
    o.exp = "2026-11-07T11:00:00Z";
    v.push(case("expired", "invite past its exp", &["CAP-201"], inp(&o), Err(InviteExpired)));
    let mut o = invite_default("bound");
    o.exp = "2026-11-15T11:00:00Z";
    v.push(case("ttl-too-long", "invite valid 8 days, MAX_INVITE_TTL is 7", &["CAP-201"], inp(&o), Err(InviteInvalid)));
    let mut s = invite_string(&invite_default("bound"));
    let n = s.len();
    s.replace_range(n - 6..n - 5, if &s[n - 6..n - 5] == "A" { "B" } else { "A" });
    v.push(case("bad-signature", "a character of the encoded invite changed", &["CAP-201"], json!({"now": NOW, "invite": s, "acceptingAgent": agent("planner")}), Err(InviteInvalid)));
    v.push(case("wrong-prefix", "not a webway-invite: string", &["CAP-201"], json!({"now": NOW, "invite": invite_string(&invite_default("bound")).replacen("webway-invite:", "webway-invitation:", 1)}), Err(InviteInvalid)));
    let mut o = invite_default("bound");
    o.issuer_cert = issuer_cert_full("B", "B", "beta", json!({"resource": ["skill:*"], "invites": false}), CERT_IAT, ISSUER_EXP);
    v.push(case("issuer-no-invite-scope", "the issuing key may not sign invites", &["CAP-201"], inp(&o), Err(InviteInvalid)));
    let mut o = invite_default("bound");
    o.issuer_cert = issuer_cert("X", "B", "beta");
    v.push(case("issuer-cert-other-owner", "issuer-cert signed by owner X, invite claims owner B", &["CAP-201"], inp(&o), Err(InviteInvalid)));
    let mut o = invite_default("bound");
    o.invitee = Some(agent("helper"));
    v.push(case("bound-holder-not-invitee", "grant held by planner, invitee is helper", &["CAP-200"], json!({"now": NOW, "invite": invite_string(&o), "acceptingAgent": agent("helper")}), Err(InviteInvalid)));
    v.push(case("bound-wrong-accepting-agent", "another agent tries to accept a bound invite", &["CAP-201"], json!({"now": NOW, "invite": invite_string(&invite_default("bound")), "acceptingAgent": agent("mallory")}), Err(InviteInvalid)));
    let mut o = invite_default("bound");
    o.invite_key = Some(B64.encode(&keys::seed("invite-key:3")));
    v.push(case("bound-with-invite-key", "bound mode must not carry an invite key", &["CAP-200"], inp(&o), Err(InviteInvalid)));
    let mut o = invite_default("redeem");
    let wide = mint(&ik("B"), &format!("webway(\"capability/v0\", \"access\");\nissuer(\"{}\");\nowner(\"{}\");\nissued(2026-11-07T11:00:00Z);\nexpires(2026-11-08T11:00:00Z);\nright(\"invite:{INVITE_ID}#redeem\");\nright(\"skill:run-tests\");\nholder(\"{}\", 0);\n", issuer("B"), owner("B"), ids::agent("invite-key:2")), "eph:invwide");
    o.grants = vec![b64(&wide)];
    v.push(case("redeem-bearer-right", "the redeem grant also carries skill:run-tests (a bearer capability)", &["CAP-200"], inp_r(&o), Err(InviteInvalid)));
    let mut o = invite_default("redeem");
    o.grants.push(o.grants[0].clone());
    v.push(case("redeem-two-grants", "redeem mode with two grants", &["CAP-200"], inp_r(&o), Err(InviteInvalid)));
    let mut o = invite_default("redeem");
    o.grants = vec![b64(&invite_redeem_grant("B", "invite-key:9", INVITE_ID))];
    v.push(case("redeem-holder-not-invite-key", "the redeem grant is held by a key other than inviteKey", &["CAP-200"], inp_r(&o), Err(InviteInvalid)));
    let mut o = invite_default("redeem");
    o.grants = vec![b64(&invite_redeem_grant("B", "invite-key:2", "0190f1d0-1111-7000-8000-000000000002"))];
    v.push(case("redeem-other-invite-id", "the redeem right names another invite", &["CAP-200"], inp_r(&o), Err(InviteInvalid)));
    let mut o = invite_default("bound");
    o.grants = vec![b64(&mint(&ik("X"), &access_code("B", "B", &["skill:run-tests"], "planner", "2026-11-07T11:30:00Z", "2026-11-07T12:30:00Z", ""), "eph:invx"))];
    v.push(case("grant-wrong-key", "a grant not signed by the invite's issuing key", &["CAP-201"], inp(&o), Err(InviteInvalid)));
    let mut o = invite_default("bound");
    o.agent = agent("helper");
    v.push(case("agent-cert-mismatch", "the listed agent differs from its certificate", &["CAP-201"], inp(&o), Err(InviteInvalid)));
    let mut o = invite_default("bound");
    o.signer = "C";
    o.issuer_cert = issuer_cert("C", "C", "gamma");
    v.push(case("signed-by-other-owner", "owner C's issuing key signs an invite claiming owner B", &["CAP-201"], inp(&o), Err(InviteInvalid)));
    v
}

// ---------------------------------------------------------------- files

pub fn files() -> Vec<File> {
    vec![
        File { path: "identity/id.json", kind: "identity/id", spec: "ext/capability.md#3-identifiers-and-keys",
            description: "Identifier syntax (CAP-001). Input {\"id\": string}. Accept with output {\"role\", \"key\" (base64url)}; reject IdentifierInvalid.",
            cases: id_cases() },
        File { path: "identity/statement.json", kind: "identity/statement", spec: "ext/capability.md#42-verification",
            description: "Verify a signed statement as type `typ` at time `now`. Input {now, typ, statement, pins: [{owner, events?}], issuerCert?, revocations?}. `pins[].events` are owner-key events (identity/owner-key). Accept with output = the verified claims; reject StatementInvalid | StatementUntrusted | StatementExpired | StatementRevoked.",
            cases: statement_cases() },
        File { path: "identity/owner-key.json", kind: "identity/owner-key", spec: "ext/capability.md#43-owner-keys-rotation-and-pre-rotation",
            description: "Verify an owner-key event chain from seq 0. Input {pin: {owner}, events: [statement]}. Accept with output {key, next, seq}; reject StatementInvalid | StatementUntrusted.",
            cases: owner_key_cases() },
        File { path: "capability/authorize.json", kind: "capability/authorize", spec: "ext/capability.md#6-authorisation-algorithm",
            description: "Run the authorisation algorithm of spec §6.2 (with §7.3 for mandates and §6.4 for follow-ups). Input {now, verifier: {owner, node, recipient, pins, issuerCerts, agentCerts, policy?}, request: {presenter, operation, taskId?, contextId?, args?}, cap: {capability, access?, mandate?: {token, issuerCert, principalCert}, onward?, revocations?}, state: {calls: {access, mandate}, revocations, consumedInvites?, task?: {taskId, creator, authorizedBy: [{owner, issuer, ids}]}}}. The envelope is already verified: request.presenter is the authentic `from`. Accept with output {holders, mandateHolders?, principal?} or, for a follow-up, {followUp: true}.",
            cases: authorize_cases() },
        File { path: "capability/invite.json", kind: "capability/invite", spec: "ext/capability.md#83-accepting-an-invite",
            description: "Verify an invite before accepting it (CAP-200, CAP-201). Input {now, invite: \"webway-invite:...\", acceptingAgent?}. Accept with output {owner, node, mode, agents, grants}; reject InviteInvalid | InviteExpired.",
            cases: invite_cases() },
        File { path: "capability/outbound.json", kind: "capability/outbound", spec: "ext/capability.md#10-obligations-of-issuers-and-senders",
            description: "The sender's mandate decision (CAP-186). Input {now, node: {owner}, task?: {originatorOwner, onward: [{token, issuerCert, principalCert}]}, request: {targetOwner, capability}, policy?: {selfPrincipal: [patterns]}}. Accept with output {mandate: index into task.onward | null, selfPrincipal?: true}; reject MandateRequired when the request must not be sent.",
            cases: outbound_cases() },
    ]
}

fn followup_cases() -> Vec<Case> {
    let t = std_access("", "eph:fu");
    let ids = cap::revocation_ids(&t);
    let task = json!({"taskId": TASK, "creator": agent("broker"), "authorizedBy": [{"owner": owner("C"), "issuer": issuer("C"), "ids": ids}]});
    let base = |op: &str, presenter: &str| {
        let mut i = auth_input(presenter, "skill:run-tests", None);
        i["cap"] = json!({});
        i["request"]["operation"] = json!(op);
        i["state"]["task"] = task.clone();
        i
    };
    let mut revoked = base("GetTask", "broker");
    revoked["state"]["revocations"] = json!([issuer_list("C", "C", 9, vec![ids[0].clone()])]);
    let mut other_task = base("CancelTask", "broker");
    other_task["request"]["taskId"] = json!("0190f1c2-7d3a-7000-8000-0000000000ff");
    vec![
        case("followup-creator-get", "the creator polls its task without a token", &["CAP-161"], base("GetTask", "broker"), Ok(())),
        case("followup-creator-cancel", "the creator cancels its task without a token", &["CAP-161"], base("CancelTask", "broker"), Ok(())),
        case("followup-other-agent", "another agent of the same owner has no token for the task", &["CAP-161"], base("GetTask", "helper"), Err(E::CapabilityMissing)),
        case("followup-other-task", "the creator of one task cannot cancel another without a token", &["CAP-161"], other_task, Err(E::CapabilityMissing)),
        case("followup-after-revocation", "the token that created the task was revoked: follow-ups stop", &["CAP-161", "CAP-174"], revoked, Err(E::CapabilityRevoked)),
    ]
}

fn outbound_cases() -> Vec<Case> {
    let m_c = mandate_obj(&std_mandate("", "eph:ob:c"));
    let m_lint = mandate_obj(&mint(&ik("A"), &mandate_code("A", "A", "planner", &[("C", "skill:lint")], "broker", T_ISSUED, T_EXPIRES, ""), "eph:ob:lint"));
    let m_exp = mandate_obj(&mint(&ik("A"), &mandate_code("A", "A", "planner", &[("C", "skill:run-tests")], "broker", "2026-11-07T10:30:00Z", "2026-11-07T11:30:00Z", ""), "eph:ob:exp"));
    // B's node (owner B) serves a task started by owner A and calls C.
    let inp = |onward: Vec<Value>, target: &str, policy: Option<Value>| {
        let mut i = json!({
            "now": NOW,
            "node": {"owner": owner("B")},
            "task": {"originatorOwner": owner("A"), "onward": onward},
            "request": {"targetOwner": owner(target), "capability": "skill:run-tests"},
        });
        if let Some(p) = policy {
            i["policy"] = p;
        }
        i
    };
    let mut local = inp(vec![], "C", None);
    local.as_object_mut().unwrap().remove("task");
    vec![
        case("attach", "the onward mandate covers the request to C", &["CAP-186"], inp(vec![m_c.clone()], "C", None), Ok(())),
        case("attach-the-covering-one", "the first onward mandate is for skill:lint, the second covers", &["CAP-186"], inp(vec![m_lint.clone(), m_c.clone()], "C", None), Ok(())),
        case("no-mandate", "no onward mandate: the request must not be sent", &["CAP-186"], inp(vec![], "C", None), Err(E::MandateRequired)),
        case("only-uncovering", "the only onward mandate is for another capability", &["CAP-186"], inp(vec![m_lint], "C", None), Err(E::MandateRequired)),
        case("only-expired", "the only covering mandate has expired", &["CAP-186"], inp(vec![m_exp], "C", None), Err(E::MandateRequired)),
        case("self-principal-policy", "no mandate, but B's owner allows acting as its own principal for skill:*", &["CAP-186"], inp(vec![], "C", Some(json!({"selfPrincipal": ["skill:*"]}))), Ok(())),
        case("self-principal-other-skill", "the self-principal policy covers skill:lint only", &["CAP-186"], inp(vec![], "C", Some(json!({"selfPrincipal": ["skill:lint"]}))), Err(E::MandateRequired)),
        case("reply-to-originator", "a request back to the originator's owner needs no mandate", &["CAP-186"], inp(vec![], "A", None), Ok(())),
        case("same-owner-target", "a request to B's own agents is not cross-owner", &["CAP-186"], inp(vec![], "B", None), Ok(())),
        case("local-task", "a task started by B itself needs no mandate", &["CAP-186"], local, Ok(())),
    ]
}

/// Runs every case through the model, checks the verdict, and renders the vector file.
pub fn render(f: File) -> Result<Value, String> {
    let mut cases = vec![];
    for c in f.cases {
        let got = model::run(f.kind, &c.input).expect("known kind");
        let expect = match (&c.expect, got) {
            (Ok(()), Ok(out)) => json!({"result": "accept", "output": out}),
            (Err(e), Err(g)) if *e == g => json!({"result": "reject", "error": e.name()}),
            (want, got) => return Err(format!("{}#{}: expected {want:?}, model gave {got:?}", f.path, c.id)),
        };
        cases.push(json!({
            "id": c.id, "description": c.description, "requirements": c.requirements,
            "input": c.input, "expect": expect,
        }));
    }
    Ok(json!({
        "$schema": "../vector.schema.json",
        "format": "webway-vectors/v0",
        "kind": f.kind,
        "description": f.description,
        "spec": f.spec,
        "cases": cases,
    }))
}


/// Re-delegation from the agent key `from` to the agent with short name `to` (or a full key name
/// containing ':').
fn delegate(t: &biscuit_auth::Biscuit, from: &str, to: &str, depth: i64, extra: &str, eph: &str) -> biscuit_auth::Biscuit {
    let to_key = if to.contains(':') { to.to_string() } else { ak(to) };
    cap::delegate(t, from, &to_key, depth, extra, eph)
}
