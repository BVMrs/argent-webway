//! Capability tokens (spec §5–§7): minting helpers for the generator, and the reference
//! authorisation algorithm of §6.2 with mandates (§7.3).

use crate::err::{E, R};
use crate::ids::{self, Role};
use crate::stmt::{self, Ctx, Pin};
use crate::{keys, time};
use biscuit_auth::builder::{boolean, date, fact, int, string, Fact, Rule, Term};
use biscuit_auth::datalog::{RunLimits, SymbolTable};
use biscuit_auth::{AuthorizerBuilder, Biscuit, BlockBuilder, PublicKey, UnverifiedBiscuit};
use data_encoding::BASE64URL_NOPAD as B64;
use prost::Message;
use serde_json::{json, Value};

pub const MAX_TOKEN_BYTES: usize = 8192;
pub const MAX_BLOCKS: usize = 16;
pub const MAX_HOLDER_DEPTH: i64 = 4;
pub const MAX_ACCESS_TTL: i64 = 30 * time::DAY;
pub const MAX_MANDATE_TTL: i64 = time::DAY;
pub const REVOCATION_EXEMPT_TTL: i64 = time::HOUR;

pub const RESERVED: &[&str] = &[
    "time", "presenter", "current_holder", "resource_owner", "node", "recipient", "operation",
    "capability", "task", "context", "arg", "calls", "mandate_principal", "mandate_owner",
    "mandate_depth",
];

pub const ACCESS_POLICY: &str =
    r#"allow if webway("capability/v0", "access"), right($c), capability($c); deny if true;"#;
pub const MANDATE_POLICY: &str =
    r#"allow if webway("capability/v0", "mandate"), grant($o, $c), resource_owner($o), capability($c); deny if true;"#;

// ---------------------------------------------------------------- minting (generator side)

/// Mints a token whose authority block is `code`, signed by the issuing key `root`.
/// The ephemeral next key is derived from `eph` so output is reproducible.
pub fn mint(root: &str, code: &str, eph: &str) -> Biscuit {
    Biscuit::builder()
        .code(code)
        .unwrap_or_else(|e| panic!("authority code: {e:?}\n{code}"))
        .build_with_key_pair(&keys::biscuit_keypair(root), SymbolTable::default(), &keys::biscuit_keypair(eph))
        .unwrap()
}

/// Appends an ordinary (ephemeral-key) attenuation block.
pub fn attenuate(t: &Biscuit, code: &str, eph: &str) -> Biscuit {
    t.append_with_keypair(&keys::biscuit_keypair(eph), BlockBuilder::new().code(code).unwrap()).unwrap()
}

/// Appends a third-party block signed by the agent key `signer` (a holder block when `code`
/// contains the holder fact).
pub fn third_party(t: &Biscuit, signer: &str, code: &str, eph: &str) -> Biscuit {
    let kp = keys::biscuit_keypair(signer);
    let req = t.third_party_request().unwrap();
    let blk = req.create_block(&kp.private(), BlockBuilder::new().code(code).unwrap()).unwrap();
    t.append_third_party_with_keypair(kp.public(), blk, keys::biscuit_keypair(eph)).unwrap()
}

/// Re-delegates from the agent `from` (current holder at depth `depth`) to agent `to`.
pub fn delegate(t: &Biscuit, from: &str, to: &str, depth: i64, extra: &str, eph: &str) -> Biscuit {
    third_party(t, from, &format!("holder(\"{}\", {depth});\n{extra}", ids::agent(to)), eph)
}

pub fn b64(t: &Biscuit) -> String {
    B64.encode(&t.to_vec().unwrap())
}

pub fn revocation_ids(t: &Biscuit) -> Vec<String> {
    t.revocation_identifiers().iter().map(|v| hex(v)).collect()
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ---------------------------------------------------------------- parsed token

struct BlockInfo {
    facts: Vec<Fact>,

    external: Option<[u8; 32]>,
}

struct Token {
    biscuit: Biscuit,
    blocks: Vec<BlockInfo>,
    ids: Vec<String>,
}

fn block_source_dump(src: &str) -> R<(Vec<Fact>, Vec<Rule>)> {
    let (f, r, _) = Biscuit::builder().code(src).map_err(|_| E::CapabilityInvalid)?.dump();
    Ok((f, r))
}

fn facts_named<'a>(facts: &'a [Fact], name: &str) -> Vec<&'a [Term]> {
    facts.iter().filter(|f| f.predicate.name == name).map(|f| f.predicate.terms.as_slice()).collect()
}

fn one<'a>(facts: &'a [Fact], name: &str) -> R<&'a [Term]> {
    match facts_named(facts, name).as_slice() {
        [t] => Ok(t),
        _ => Err(E::CapabilityInvalid),
    }
}

fn term_str(t: &Term) -> R<&str> {
    match t {
        Term::Str(s) => Ok(s),
        _ => Err(E::CapabilityInvalid),
    }
}
fn term_date(t: &Term) -> R<i64> {
    match t {
        Term::Date(d) => Ok(*d as i64),
        _ => Err(E::CapabilityInvalid),
    }
}
fn term_int(t: &Term) -> R<i64> {
    match t {
        Term::Integer(i) => Ok(*i),
        _ => Err(E::CapabilityInvalid),
    }
}

/// Decodes the bytes, reads the `issuer` fact before verification (a lookup hint only).
fn peek_issuer(s: &str) -> R<(Vec<u8>, String)> {
    let bytes = B64.decode(s.as_bytes()).map_err(|_| E::CapabilityInvalid)?;
    if bytes.len() > MAX_TOKEN_BYTES {
        return Err(E::CapabilityInvalid);
    }
    let u = UnverifiedBiscuit::from(&bytes).map_err(|_| E::CapabilityInvalid)?;
    let (facts, _) = block_source_dump(&u.print_block_source(0).map_err(|_| E::CapabilityInvalid)?)?;
    let iss = term_str(&one(&facts, "issuer")?[0])?.to_string();
    Ok((bytes, iss))
}

/// Signature and format checks (CAP-100), block contents (CAP-103).
fn open(bytes: &[u8], root: &[u8; 32]) -> R<Token> {
    let schema = biscuit_auth::format::schema::Biscuit::decode(bytes).map_err(|_| E::CapabilityInvalid)?;
    let ed = biscuit_auth::format::schema::public_key::Algorithm::Ed25519 as i32;
    for b in std::iter::once(&schema.authority).chain(schema.blocks.iter()) {
        if b.next_key.algorithm != ed || b.external_signature.as_ref().map_or(false, |x| x.public_key.algorithm != ed) {
            return Err(E::CapabilityInvalid);
        }
        if b.external_signature.is_some() && b.version != Some(1) {
            return Err(E::CapabilityInvalid);
        }
    }
    let pk = PublicKey::from_bytes(root, biscuit_auth::Algorithm::Ed25519).map_err(|_| E::CapabilityInvalid)?;
    let biscuit = Biscuit::from(bytes, pk).map_err(|_| E::CapabilityInvalid)?;
    if biscuit.block_count() > MAX_BLOCKS {
        return Err(E::CapabilityInvalid);
    }
    let mut blocks = vec![];
    for i in 0..biscuit.block_count() {
        let (facts, rules) = block_source_dump(&biscuit.print_block_source(i).map_err(|_| E::CapabilityInvalid)?)?;
        if facts.iter().any(|f| RESERVED.contains(&f.predicate.name.as_str()))
            || rules.iter().any(|r| RESERVED.contains(&r.head.name.as_str()))
        {
            return Err(E::CapabilityInvalid); // CAP-103
        }
        let external = biscuit
            .block_external_key(i)
            .map_err(|_| E::CapabilityInvalid)?
            .map(|k| k.to_bytes().try_into().map_err(|_| E::CapabilityInvalid))
            .transpose()?;
        blocks.push(BlockInfo { facts, external });
    }
    let ids = revocation_ids(&biscuit);
    Ok(Token { biscuit, blocks, ids })
}

struct Authority {
    role: String,
    owner: String,
    issued: i64,
    expires: i64,
}

/// CAP-104.
fn authority(t: &Token, issuer: &str) -> R<Authority> {
    let f = &t.blocks[0].facts;
    let w = one(f, "webway")?;
    if w.len() != 2 || term_str(&w[0])? != "capability/v0" {
        return Err(E::CapabilityInvalid);
    }
    let role = term_str(&w[1])?.to_string();
    if term_str(&one(f, "issuer")?[0])? != issuer {
        return Err(E::CapabilityInvalid);
    }
    let owner = term_str(&one(f, "owner")?[0])?.to_string();
    let issued = term_date(&one(f, "issued")?[0])?;
    let expires = term_date(&one(f, "expires")?[0])?;
    let ok = match role.as_str() {
        "access" => !facts_named(f, "right").is_empty() && facts_named(f, "principal").is_empty(),
        "mandate" => {
            facts_named(f, "principal").len() == 1 && !facts_named(f, "grant").is_empty() && facts_named(f, "right").is_empty()
        }
        _ => false,
    };
    if !ok {
        return Err(E::CapabilityInvalid);
    }
    Ok(Authority { role, owner, issued, expires })
}

/// CAP-120: the holder chain, walked in code.
fn holder_chain(t: &Token) -> R<Vec<String>> {
    let first = facts_named(&t.blocks[0].facts, "holder");
    let [h0] = first.as_slice() else { return Err(E::CapabilityInvalid) };
    if h0.len() != 2 || term_int(&h0[1])? != 0 {
        return Err(E::CapabilityInvalid);
    }
    let mut chain = vec![term_str(&h0[0])?.to_string()];
    ids::parse_role(&chain[0], Role::Agent).ok_or(E::CapabilityInvalid)?;
    for b in &t.blocks[1..] {
        let hs = facts_named(&b.facts, "holder");
        match b.external {
            None => {
                if !hs.is_empty() {
                    return Err(E::CapabilityInvalid);
                }
            }
            Some(k) => {
                let current = ids::parse_role(chain.last().unwrap(), Role::Agent).unwrap();
                if k != current {
                    return Err(E::CapabilityInvalid);
                }
                let [h] = hs.as_slice() else { return Err(E::CapabilityInvalid) };
                if h.len() != 2 || term_int(&h[1])? != chain.len() as i64 {
                    return Err(E::CapabilityInvalid);
                }
                let next = term_str(&h[0])?.to_string();
                ids::parse_role(&next, Role::Agent).ok_or(E::CapabilityInvalid)?;
                if chain.contains(&next) || chain.len() as i64 > MAX_HOLDER_DEPTH {
                    return Err(E::CapabilityInvalid);
                }
                chain.push(next);
            }
        }
    }
    Ok(chain)
}

fn map_stmt(e: E) -> E {
    match e {
        E::StatementRevoked => E::CapabilityRevoked,
        _ => E::CapabilityInvalid,
    }
}

// ---------------------------------------------------------------- authorisation

struct Req<'a> {
    now: i64,
    presenter: &'a str,
    owner: &'a str,
    node: &'a str,
    recipient: &'a str,
    operation: &'a str,
    capability: &'a str,
    task: Option<&'a str>,
    context: Option<&'a str>,
    args: serde_json::Map<String, Value>,
}

fn request_facts(r: &Req, holder: &str, calls: i64) -> Vec<Fact> {
    let s = |x: &str| string(x);
    let mut v = vec![
        fact("time", &[date(&time::system(r.now))]),
        fact("presenter", &[s(r.presenter)]),
        fact("current_holder", &[s(holder)]),
        fact("resource_owner", &[s(r.owner)]),
        fact("node", &[s(r.node)]),
        fact("recipient", &[s(r.recipient)]),
        fact("operation", &[s(r.operation)]),
        fact("capability", &[s(r.capability)]),
        fact("calls", &[int(calls)]),
    ];
    if let Some(t) = r.task {
        v.push(fact("task", &[s(t)]));
    }
    if let Some(c) = r.context {
        v.push(fact("context", &[s(c)]));
    }
    for (k, val) in &r.args {
        let term = match val {
            Value::String(x) => s(x),
            Value::Bool(b) => boolean(*b),
            Value::Number(n) => match n.as_i64().filter(|i| i.unsigned_abs() <= 1 << 53) {
                Some(i) => int(i),
                None => continue,
            },
            _ => continue,
        };
        v.push(fact("arg", &[s(k), term]));
    }
    v
}

fn run_datalog(token: &Biscuit, facts: Vec<Fact>, policy: Option<&str>, allow: &str) -> R<()> {
    let mut b = AuthorizerBuilder::new();
    for f in facts {
        b = b.fact(f).map_err(|_| E::CapabilityInvalid)?;
    }
    if let Some(p) = policy {
        b = b.code(p).map_err(|_| E::CapabilityInvalid)?;
    }
    b = b.code(allow).unwrap();
    // MAX_TIME is a SHOULD; the model uses a generous bound so results are deterministic.
    b = b.set_limits(RunLimits { max_facts: 1000, max_iterations: 100, max_time: std::time::Duration::from_secs(2) });
    let mut a = b.build(token).map_err(|_| E::CapabilityInvalid)?;
    match a.authorize() {
        Ok(_) => Ok(()),
        Err(biscuit_auth::error::Token::FailedLogic(_)) => Err(E::CapabilityDenied),
        Err(_) => Err(E::CapabilityInvalid),
    }
}

/// Which operations a capability allows (CAP-102).
pub fn operation_allowed(cap: &str, op: &str) -> bool {
    let (kind, rest) = cap.split_once(':').unwrap_or(("", ""));
    let opname = rest.rsplit_once('#').map(|(_, o)| o);
    match (kind, opname, op) {
        ("skill", None, "SendMessage" | "SendStreamingMessage") => true,
        ("task", Some("read"), "GetTask" | "SubscribeToTask") => true,
        ("task", Some("cancel"), "CancelTask") => true,
        ("invite", Some("redeem"), "InviteRedeem") => true,
        ("blob", Some("read"), "BlobGet") => true,
        ("doc", Some("read"), "DocSync") => true,
        ("doc", Some("append"), "DocAppend") => true,
        ("mailbox", Some("deposit"), "MailboxDeposit") => true,
        _ => false,
    }
}

fn sget<'a>(v: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter().try_fold(v, |v, k| v.get(*k))
}
fn sstr<'a>(v: &'a Value, path: &[&str]) -> Option<&'a str> {
    sget(v, path).and_then(Value::as_str)
}
fn arr(v: &Value, path: &[&str]) -> Vec<Value> {
    sget(v, path).and_then(Value::as_array).cloned().unwrap_or_default()
}

/// `capability/authorize` (spec §6.2, §7.3).
pub fn authorize(input: &Value) -> R<Value> {
    let bad_input = E::CapabilityInvalid;
    let now = time::parse(sstr(input, &["now"]).ok_or(bad_input)?).ok_or(bad_input)?;
    let v = input.get("verifier").ok_or(bad_input)?;
    let own = sstr(v, &["owner"]).ok_or(bad_input)?;
    let mut pins = vec![Pin::simple(own)];
    for p in arr(v, &["pins"]) {
        pins.push(Pin::simple(p.as_str().ok_or(bad_input)?));
    }
    let mut pool = arr(v, &["issuerCerts"]);
    if let Some(c) = sget(input, &["cap", "mandate", "issuerCert"]) {
        pool.push(c.clone());
    }
    let mut ctx = Ctx::new(now, pins, pool);
    let mut lists = arr(input, &["state", "revocations"]);
    lists.extend(arr(input, &["cap", "revocations"])); // CAP-173
    ctx.add_lists(&lists);

    let presenter = sstr(input, &["request", "presenter"]).ok_or(bad_input)?;
    let capability = sstr(input, &["cap", "capability"]);
    let access = sstr(input, &["cap", "access"]);

    // 0. Follow-up on an existing task by its creator, without a token (§6.4, CAP-161).
    let operation = sstr(input, &["request", "operation"]).ok_or(bad_input)?;
    let task = sget(input, &["state", "task"]);
    let followup = access.is_none()
        && matches!(operation, "GetTask" | "SubscribeToTask" | "CancelTask" | "SendMessage" | "SendStreamingMessage")
        && task.and_then(|t| t.get("creator")).and_then(Value::as_str) == Some(presenter)
        && sstr(input, &["request", "taskId"]).is_some()
        && task.and_then(|t| t.get("taskId")) == sget(input, &["request", "taskId"]);

    // 1. Presence.
    if access.is_none() && !followup {
        return Err(E::CapabilityMissing);
    }

    // 2. Presenter identity (CAP-041). For InviteRedeem the presenter's owner is not pinned yet:
    //    the cert in the request body is checked on its own chain (CAP-203).
    let invite = capability.map_or(false, |c| c.starts_with("invite:"));
    let cert = arr(v, &["agentCerts"])
        .into_iter()
        .find(|c| stmt::parse(c).ok().map_or(false, |p| p.claims.get("agent").and_then(Value::as_str) == Some(presenter)))
        .ok_or(E::CapabilityDenied)?;
    if invite {
        if let Ok(p) = stmt::parse(&cert) {
            if let Some(o) = p.claims.get("owner").and_then(Value::as_str) {
                if ctx.pin(o).is_none() {
                    ctx.pins.push(Pin::simple(o));
                }
            }
        }
    }
    ctx.verify(stmt::AGENT_CERT, &cert).map_err(|_| E::CapabilityDenied)?;

    if followup {
        // Step 6 against the revocation IDs recorded when the task was created (CAP-161, CAP-174).
        for a in arr(input, &["state", "task", "authorizedBy"]) {
            let (Some(o), Some(i)) = (a.get("owner").and_then(Value::as_str), a.get("issuer").and_then(Value::as_str)) else {
                return Err(bad_input);
            };
            if arr(&a, &["ids"]).iter().filter_map(Value::as_str).any(|id| ctx.is_revoked(o, i, id)) {
                return Err(E::CapabilityRevoked);
            }
        }
        return Ok(json!({"followUp": true}));
    }
    let (Some(capability), Some(access)) = (capability, access) else { return Err(E::CapabilityMissing) };

    let req = Req {
        now,
        presenter,
        owner: own,
        node: sstr(v, &["node"]).ok_or(bad_input)?,
        recipient: sstr(v, &["recipient"]).ok_or(bad_input)?,
        operation: sstr(input, &["request", "operation"]).ok_or(bad_input)?,
        capability,
        task: sstr(input, &["request", "taskId"]),
        context: sstr(input, &["request", "contextId"]),
        args: sget(input, &["request", "args"]).and_then(Value::as_object).cloned().unwrap_or_default(),
    };

    // 3–6. Access token.
    let (tok, auth, holders, _) = verify_token(&ctx, access, "access", own, &req, None)?;
    let _ = auth;

    // 7. Mandate.
    let mut mandate_facts = vec![];
    let mut out = json!({ "holders": holders });
    if let Some(m) = sget(input, &["cap", "mandate"]) {
        let mtoken = sstr(m, &["token"]).ok_or(E::CapabilityInvalid)?;
        let (mt, mauth, mholders, principal) = verify_token(&ctx, mtoken, "mandate", own, &req, Some(m))?;
        // M4: same holder as the access token, which is the presenter.
        // M5: mandate Datalog.
        let calls = sget(input, &["state", "calls", "mandate"]).and_then(Value::as_i64).unwrap_or(0);
        run_datalog(&mt.biscuit, request_facts(&req, mholders.last().unwrap(), calls), None, MANDATE_POLICY)?;
        let principal = principal.unwrap();
        mandate_facts = vec![
            fact("mandate_principal", &[string(&principal)]),
            fact("mandate_owner", &[string(&mauth.owner)]),
            fact("mandate_depth", &[int(mholders.len() as i64 - 1)]),
        ];
        out["mandateHolders"] = json!(mholders);
        out["principal"] = json!(principal);
    }

    // 8. Operation (CAP-102), single-use invites (CAP-203).
    if !operation_allowed(capability, req.operation) {
        return Err(E::CapabilityDenied);
    }
    if invite {
        let id = capability.trim_start_matches("invite:").trim_end_matches("#redeem");
        if arr(input, &["state", "consumedInvites"]).iter().any(|c| c.as_str() == Some(id)) {
            return Err(E::InviteConsumed);
        }
    }

    // 9. Datalog with local policy.
    let calls = sget(input, &["state", "calls", "access"]).and_then(Value::as_i64).unwrap_or(0);
    let mut facts = request_facts(&req, holders.last().unwrap(), calls);
    facts.extend(mandate_facts);
    run_datalog(&tok.biscuit, facts, sstr(v, &["policy"]), ACCESS_POLICY)?;
    Ok(out)
}

/// Steps 3–6 for an access token, or M1–M4 for a mandate (`mandate` = the `cap.mandate` object).
fn verify_token(
    ctx: &Ctx,
    encoded: &str,
    role: &str,
    verifier_owner: &str,
    req: &Req,
    mandate: Option<&Value>,
) -> R<(Token, Authority, Vec<String>, Option<String>)> {
    let (bytes, iss) = peek_issuer(encoded)?;
    // Find and verify the issuer-cert (CAP-030, M1).
    let cert = if let Some(m) = mandate {
        m.get("issuerCert").ok_or(E::CapabilityInvalid)?.clone()
    } else {
        ctx.issuer_certs
            .iter()
            .find(|c| stmt::parse(c).ok().map_or(false, |p| p.claims.get("issuer").and_then(Value::as_str) == Some(iss.as_str())))
            .cloned()
            .ok_or(E::CapabilityInvalid)?
    };
    let ic = ctx.verify(stmt::ISSUER_CERT, &cert).map_err(map_stmt)?;
    let ic_issuer = stmt::str_claim(&ic.claims, "issuer").map_err(map_stmt)?;
    if ic_issuer != iss {
        return Err(E::CapabilityInvalid);
    }
    let ic_owner = stmt::str_claim(&ic.claims, "owner").map_err(map_stmt)?.to_string();
    let root = ids::parse_role(&iss, Role::Issuer).ok_or(E::CapabilityInvalid)?;
    let tok = open(&bytes, &root)?;
    let auth = authority(&tok, &iss)?;
    if auth.role != role || auth.owner != ic_owner {
        return Err(E::CapabilityInvalid);
    }
    let scope = ic.claims.get("scope").cloned().unwrap_or(Value::Null);
    let auth_facts = &tok.blocks[0].facts;
    let mut principal = None;
    let max_ttl;
    if role == "access" {
        // CAP-110: rooted in the verifier's own owner.
        if auth.owner != verifier_owner {
            return Err(E::CapabilityInvalid);
        }
        let patterns: Vec<String> =
            scope.get("resource").and_then(Value::as_array).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
        for r in facts_named(auth_facts, "right") {
            let c = term_str(&r[0])?;
            if !patterns.iter().any(|p| stmt::pattern_matches(p, c)) {
                return Err(E::CapabilityInvalid);
            }
        }
        max_ttl = MAX_ACCESS_TTL;
    } else {
        // M1: mandate scope; the owner must be pinned (ctx.verify already required it).
        let ms = scope.get("mandate").filter(|m| !m.is_null()).ok_or(E::CapabilityInvalid)?;
        let targets: Vec<&str> = ms.get("targets").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
        let caps: Vec<&str> = ms.get("capabilities").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
        for g in facts_named(auth_facts, "grant") {
            if g.len() != 2 {
                return Err(E::CapabilityInvalid);
            }
            let (o, c) = (term_str(&g[0])?, term_str(&g[1])?);
            if !(targets == ["*"] || targets.contains(&o)) || !caps.iter().any(|p| stmt::pattern_matches(p, c)) {
                return Err(E::CapabilityInvalid);
            }
        }
        max_ttl = ms.get("maxTtl").and_then(Value::as_i64).unwrap_or(0).min(MAX_MANDATE_TTL);
        // M2 (CAP-031): principal certified to the issuing key's node.
        let p = term_str(&one(auth_facts, "principal")?[0])?.to_string();
        let pc = mandate.and_then(|m| m.get("principalCert")).ok_or(E::CapabilityInvalid)?;
        let pv = ctx.verify(stmt::AGENT_CERT, pc).map_err(map_stmt)?;
        if pv.claims.get("agent").and_then(Value::as_str) != Some(p.as_str())
            || pv.claims.get("owner").and_then(Value::as_str) != Some(auth.owner.as_str())
            || pv.claims.get("node") != ic.claims.get("node")
        {
            return Err(E::CapabilityInvalid);
        }
        principal = Some(p);
    }
    // CAP-111.
    if auth.expires - auth.issued > max_ttl || auth.expires < auth.issued || auth.issued > req.now + time::SKEW {
        return Err(E::CapabilityInvalid);
    }
    // 4. Holder chain (CAP-120).
    let holders = holder_chain(&tok)?;
    // 5. Expiry and presenter (CAP-111, CAP-121).
    if req.now > auth.expires || holders.last().map(String::as_str) != Some(req.presenter) {
        return Err(E::CapabilityDenied);
    }
    // 6. Revocation (CAP-171, CAP-172). The issuer-cert was checked by ctx.verify.
    if tok.ids.iter().any(|id| ctx.is_revoked(&auth.owner, &iss, id)) {
        return Err(E::CapabilityRevoked);
    }
    if auth.expires - auth.issued > REVOCATION_EXEMPT_TTL && !ctx.fresh_list(&auth.owner, &iss) {
        return Err(E::RevocationStatusUnavailable);
    }
    Ok((tok, auth, holders, principal))
}
