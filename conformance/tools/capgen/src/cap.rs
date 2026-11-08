//! Capability tokens (spec §5–§7): minting helpers for the generator, and the reference
//! authorisation algorithm of §6.2 with mandates (§7.3).

use crate::err::{E, R};
use crate::ids::{self, Role};
use crate::stmt::{self, Ctx, Pin};
use crate::{keys, time};
use biscuit_auth::builder::{boolean, date, fact, int, string, Fact};
use biscuit_auth::datalog::{RunLimits, SymbolTable};
use biscuit_auth::format::schema;
use biscuit_auth::{AuthorizerBuilder, Biscuit, BlockBuilder, PublicKey};
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
    "time",
    "presenter",
    "current_holder",
    "resource_owner",
    "node",
    "recipient",
    "operation",
    "capability",
    "task",
    "context",
    "arg",
    "calls",
    "mandate_principal",
    "mandate_owner",
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

/// Re-delegates from the agent key `from` (current holder at depth `depth - 1`) to the agent key `to`.
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

// ---------------------------------------------------------------- exact block decoding

/// A term of a token fact, decoded from the block protobuf (not from printed source, so
/// strings that look like Datalog stay strings).
#[derive(Clone, Debug, PartialEq)]
pub enum T {
    Str(String),
    Int(i64),
    Date(i64),
    Other,
}

#[derive(Clone, Debug)]
pub struct F {
    pub name: String,
    pub terms: Vec<T>,
}

pub struct BlockInfo {
    pub facts: Vec<F>,
    pub rule_heads: Vec<String>,
    pub external: Option<[u8; 32]>,
}

/// Decodes every block's facts and rule heads with exact symbol resolution. Does not verify
/// signatures: callers do that separately (`open`) or use the result only as a lookup hint.
pub fn decode_blocks(bytes: &[u8]) -> R<Vec<BlockInfo>> {
    let bad = E::CapabilityInvalid;
    let token = schema::Biscuit::decode(bytes).map_err(|_| bad)?;
    let defaults = SymbolTable::new();
    let mut shared: Vec<String> = vec![];
    let mut out = vec![];
    for sb in std::iter::once(&token.authority).chain(token.blocks.iter()) {
        let block = schema::Block::decode(sb.block.as_slice()).map_err(|_| bad)?;
        let external = match &sb.external_signature {
            None => None,
            Some(x) => Some(<[u8; 32]>::try_from(x.public_key.key.as_slice()).map_err(|_| bad)?),
        };
        // Third-party blocks have their own symbol table; the others extend the shared one.
        let table: Vec<String> = if external.is_some() {
            block.symbols.clone()
        } else {
            shared.extend(block.symbols.iter().cloned());
            shared.clone()
        };
        let sym = |i: u64| -> R<String> {
            if i < 1024 {
                defaults.get_symbol(i).map(String::from).ok_or(bad)
            } else {
                table.get((i - 1024) as usize).cloned().ok_or(bad)
            }
        };
        let term = |t: &schema::Term| -> R<T> {
            use schema::term::Content;
            Ok(match &t.content {
                Some(Content::String(i)) => T::Str(sym(*i)?),
                Some(Content::Integer(i)) => T::Int(*i),
                Some(Content::Date(d)) => T::Date(*d as i64),
                _ => T::Other,
            })
        };
        let mut facts = vec![];
        for f in &block.facts {
            facts
                .push(F { name: sym(f.predicate.name)?, terms: f.predicate.terms.iter().map(term).collect::<R<_>>()? });
        }
        let rule_heads = block.rules.iter().map(|r| sym(r.head.name)).collect::<R<_>>()?;
        out.push(BlockInfo { facts, rule_heads, external });
    }
    Ok(out)
}

pub fn facts_named<'a>(facts: &'a [F], name: &str) -> Vec<&'a [T]> {
    facts.iter().filter(|f| f.name == name).map(|f| f.terms.as_slice()).collect()
}

fn one<'a>(facts: &'a [F], name: &str) -> R<&'a [T]> {
    match facts_named(facts, name).as_slice() {
        [t] => Ok(t),
        _ => Err(E::CapabilityInvalid),
    }
}

pub fn t_str(t: &T) -> R<&str> {
    match t {
        T::Str(s) => Ok(s),
        _ => Err(E::CapabilityInvalid),
    }
}
fn t_date(t: &T) -> R<i64> {
    match t {
        T::Date(d) => Ok(*d),
        _ => Err(E::CapabilityInvalid),
    }
}
fn t_int(t: &T) -> R<i64> {
    match t {
        T::Int(i) => Ok(*i),
        _ => Err(E::CapabilityInvalid),
    }
}

// ---------------------------------------------------------------- parsed token

struct Token {
    biscuit: Biscuit,
    blocks: Vec<BlockInfo>,
    ids: Vec<String>,
}

/// Decodes the bytes, reads the `issuer` fact before verification (a lookup hint only).
fn peek_issuer(s: &str) -> R<(Vec<u8>, String)> {
    let bytes = B64.decode(s.as_bytes()).map_err(|_| E::CapabilityInvalid)?;
    if bytes.len() > MAX_TOKEN_BYTES {
        return Err(E::CapabilityInvalid);
    }
    let blocks = decode_blocks(&bytes)?;
    let iss = t_str(&one(&blocks[0].facts, "issuer")?[0])?.to_string();
    Ok((bytes, iss))
}

/// Signature and format checks (CAP-100), block contents (CAP-103, CAP-105).
fn open(bytes: &[u8], root: &[u8; 32]) -> R<Token> {
    let sch = schema::Biscuit::decode(bytes).map_err(|_| E::CapabilityInvalid)?;
    let ed = schema::public_key::Algorithm::Ed25519 as i32;
    for b in std::iter::once(&sch.authority).chain(sch.blocks.iter()) {
        if b.next_key.algorithm != ed || b.external_signature.as_ref().is_some_and(|x| x.public_key.algorithm != ed) {
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
    let blocks = decode_blocks(bytes)?;
    for b in &blocks {
        if b.facts.iter().any(|f| RESERVED.contains(&f.name.as_str()))
            || b.rule_heads.iter().any(|h| RESERVED.contains(&h.as_str()))
        {
            return Err(E::CapabilityInvalid); // CAP-103
        }
    }
    if !blocks[0].rule_heads.is_empty() {
        return Err(E::CapabilityInvalid); // CAP-105
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
    if w.len() != 2 || t_str(&w[0])? != "capability/v0" {
        return Err(E::CapabilityInvalid);
    }
    let role = t_str(&w[1])?.to_string();
    if t_str(&one(f, "issuer")?[0])? != issuer {
        return Err(E::CapabilityInvalid);
    }
    let owner = t_str(&one(f, "owner")?[0])?.to_string();
    let issued = t_date(&one(f, "issued")?[0])?;
    let expires = t_date(&one(f, "expires")?[0])?;
    let ok = match role.as_str() {
        "access" => !facts_named(f, "right").is_empty() && facts_named(f, "principal").is_empty(),
        "mandate" => {
            facts_named(f, "principal").len() == 1
                && !facts_named(f, "grant").is_empty()
                && facts_named(f, "right").is_empty()
        }
        _ => false,
    };
    if !ok {
        return Err(E::CapabilityInvalid);
    }
    Ok(Authority { role, owner, issued, expires })
}

/// CAP-120: the holder chain, walked in code.
pub fn holder_chain(blocks: &[BlockInfo]) -> R<Vec<String>> {
    let first = facts_named(&blocks[0].facts, "holder");
    let [h0] = first.as_slice() else { return Err(E::CapabilityInvalid) };
    if h0.len() != 2 || t_int(&h0[1])? != 0 {
        return Err(E::CapabilityInvalid);
    }
    let mut chain = vec![t_str(&h0[0])?.to_string()];
    ids::parse_role(&chain[0], Role::Agent).ok_or(E::CapabilityInvalid)?;
    for b in &blocks[1..] {
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
                if h.len() != 2 || t_int(&h[1])? != chain.len() as i64 {
                    return Err(E::CapabilityInvalid);
                }
                let next = t_str(&h[0])?.to_string();
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
        ("task", Some("write"), "SendMessage" | "SendStreamingMessage") => true,
        ("task", Some("cancel"), "CancelTask") => true,
        ("invite", Some("redeem"), "InviteRedeem") => true,
        ("blob", Some("read"), "BlobGet") => true,
        ("doc", Some("read"), "DocSync") => true,
        ("doc", Some("append"), "DocAppend") => true,
        ("mailbox", Some("deposit"), "MailboxDeposit") => true,
        _ => false,
    }
}

/// CAP-106: the resource named in the capability is the one the request touches.
fn resource_bound(cap: &str, input: &Value, presenter: &str) -> R<()> {
    let (kind, rest) = cap.split_once(':').ok_or(E::CapabilityDenied)?;
    let name = rest.rsplit_once('#').map_or(rest, |(n, _)| n);
    let task_id = sstr(input, &["request", "taskId"]);
    let ok = match kind {
        // A skill capability creates tasks. Continuing one needs to be its creator, under the
        // same capability (§6.4).
        "skill" => match task_id {
            None => true,
            Some(t) => {
                sstr(input, &["state", "task", "taskId"]) == Some(t)
                    && sstr(input, &["state", "task", "creator"]) == Some(presenter)
                    && sstr(input, &["state", "task", "capability"]) == Some(cap)
            }
        },
        "task" => task_id == Some(name),
        "invite" => task_id.is_none(),
        _ => sstr(input, &["request", "resource"]) == Some(name),
    };
    if ok {
        Ok(())
    } else {
        Err(E::CapabilityDenied)
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

    // 0. Token-less follow-up by the task's creator: reads and cancel only (§6.4, CAP-161).
    let operation = sstr(input, &["request", "operation"]).ok_or(bad_input)?;
    let task = sget(input, &["state", "task"]);
    let followup = access.is_none()
        && matches!(operation, "GetTask" | "SubscribeToTask" | "CancelTask")
        && task.and_then(|t| t.get("creator")).and_then(Value::as_str) == Some(presenter)
        && sstr(input, &["request", "taskId"]).is_some()
        && task.and_then(|t| t.get("taskId")) == sget(input, &["request", "taskId"]);

    // 1. Presence.
    if access.is_none() && !followup {
        return Err(E::CapabilityMissing);
    }

    // 2. Presenter identity (CAP-041). For InviteRedeem the presenter's owner is not pinned yet:
    //    the cert in the request body is checked on its own chain, in a separate context that
    //    does not pin that owner for anything else (CAP-203).
    let invite = capability.is_some_and(|c| c.starts_with("invite:"));
    let cert = arr(v, &["agentCerts"])
        .into_iter()
        .find(|c| stmt::parse(c).ok().is_some_and(|p| p.claims.get("agent").and_then(Value::as_str) == Some(presenter)))
        .ok_or(E::CapabilityDenied)?;
    if invite {
        let o = stmt::parse(&cert).ok().and_then(|p| p.claims.get("owner").and_then(Value::as_str).map(String::from));
        let mut ictx = Ctx::new(now, vec![Pin::simple(o.as_deref().unwrap_or(own))], vec![]);
        ictx.add_lists(&lists);
        ictx.verify(stmt::AGENT_CERT, &cert).map_err(|_| E::CapabilityDenied)?;
    } else {
        ctx.verify(stmt::AGENT_CERT, &cert).map_err(|_| E::CapabilityDenied)?;
    }

    if followup {
        // Step 6 against the revocation IDs recorded when the task was created (CAP-161, CAP-174).
        for a in arr(input, &["state", "task", "authorizedBy"]) {
            let (Some(o), Some(i)) = (a.get("owner").and_then(Value::as_str), a.get("issuer").and_then(Value::as_str))
            else {
                return Err(bad_input);
            };
            if ctx.key_revoked(o, i)
                || arr(&a, &["ids"]).iter().filter_map(Value::as_str).any(|id| ctx.is_revoked(o, i, id))
            {
                return Err(E::CapabilityRevoked);
            }
        }
        return Ok(json!({"followUp": true}));
    }
    let (Some(capability), Some(access)) = (capability, access) else { return Err(E::CapabilityMissing) };
    if invite && sget(input, &["cap", "mandate"]).is_some() {
        return Err(E::CapabilityInvalid); // a redemption never acts for someone else
    }

    let req = Req {
        now,
        presenter,
        owner: own,
        node: sstr(v, &["node"]).ok_or(bad_input)?,
        recipient: sstr(v, &["recipient"]).ok_or(bad_input)?,
        operation,
        capability,
        task: sstr(input, &["request", "taskId"]),
        context: sstr(input, &["request", "contextId"]),
        args: sget(input, &["request", "args"]).and_then(Value::as_object).cloned().unwrap_or_default(),
    };

    // 3–6. Access token.
    let (tok, _, holders, _) = verify_token(&ctx, access, "access", &req, None)?;

    // 7. Mandate.
    let mut mandate_facts = vec![];
    let mut out = json!({ "holders": holders });
    if let Some(m) = sget(input, &["cap", "mandate"]) {
        let mtoken = sstr(m, &["token"]).ok_or(E::CapabilityInvalid)?;
        let (mt, mauth, mholders, principal) = verify_token(&ctx, mtoken, "mandate", &req, Some(m))?;
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

    // 8. Operation (CAP-102), resource binding (CAP-106), single-use invites (CAP-203).
    if !operation_allowed(capability, req.operation) {
        return Err(E::CapabilityDenied);
    }
    resource_bound(capability, input, presenter)?;
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

fn strings(v: Option<&Value>) -> Vec<&str> {
    v.and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default()
}

/// Steps 3–6 for an access token, or M1–M4 for a mandate (`mandate` = the `cap.mandate` object).
fn verify_token(
    ctx: &Ctx,
    encoded: &str,
    role: &str,
    req: &Req,
    mandate: Option<&Value>,
) -> R<(Token, Authority, Vec<String>, Option<String>)> {
    let (bytes, iss) = peek_issuer(encoded)?;
    // Find and verify the issuer-cert (CAP-030, M1). Its revocation, and the revocation of the
    // issuing key itself, are reported here (step 3).
    let cert = if let Some(m) = mandate {
        m.get("issuerCert").ok_or(E::CapabilityInvalid)?.clone()
    } else {
        ctx.issuer_certs
            .iter()
            .find(|c| {
                stmt::parse(c)
                    .ok()
                    .is_some_and(|p| p.claims.get("issuer").and_then(Value::as_str) == Some(iss.as_str()))
            })
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
        // CAP-110: rooted in the verifier's own owner, minted by the issuing key of this node.
        if auth.owner != req.owner || ic.claims.get("node").and_then(Value::as_str) != Some(req.node) {
            return Err(E::CapabilityInvalid);
        }
        let patterns = strings(scope.get("resource"));
        for r in facts_named(auth_facts, "right") {
            let c = t_str(&r[0])?;
            if !patterns.iter().any(|p| stmt::pattern_matches(p, c)) {
                return Err(E::CapabilityInvalid);
            }
        }
        // CAP-030: the requested capability itself must be inside the scope.
        if !patterns.iter().any(|p| stmt::pattern_matches(p, req.capability)) {
            return Err(E::CapabilityDenied);
        }
        max_ttl = MAX_ACCESS_TTL;
    } else {
        // M1: mandate scope; the owner must be pinned (ctx.verify already required it).
        let ms = scope.get("mandate").filter(|m| !m.is_null()).ok_or(E::CapabilityInvalid)?;
        let targets = strings(ms.get("targets"));
        let caps = strings(ms.get("capabilities"));
        let covered = |o: &str, c: &str| {
            (targets == ["*"] || targets.contains(&o)) && caps.iter().any(|p| stmt::pattern_matches(p, c))
        };
        for g in facts_named(auth_facts, "grant") {
            if g.len() != 2 {
                return Err(E::CapabilityInvalid);
            }
            if !covered(t_str(&g[0])?, t_str(&g[1])?) {
                return Err(E::CapabilityInvalid);
            }
        }
        if !covered(req.owner, req.capability) {
            return Err(E::CapabilityDenied);
        }
        max_ttl = ms.get("maxTtl").and_then(Value::as_i64).unwrap_or(0).min(MAX_MANDATE_TTL);
        // M2 (CAP-031): principal certified to the issuing key's node.
        let p = t_str(&one(auth_facts, "principal")?[0])?.to_string();
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
    let holders = holder_chain(&tok.blocks)?;
    // 5. Expiry and presenter (CAP-111, CAP-121).
    if req.now > auth.expires || holders.last().map(String::as_str) != Some(req.presenter) {
        return Err(E::CapabilityDenied);
    }
    // 6. Revocation of the token's blocks (CAP-171) and freshness (CAP-172).
    if tok.ids.iter().any(|id| ctx.is_revoked(&auth.owner, &iss, id)) {
        return Err(E::CapabilityRevoked);
    }
    if auth.expires - auth.issued > REVOCATION_EXEMPT_TTL
        && !(ctx.fresh_list(&auth.owner, &iss) && ctx.fresh_root_list(&auth.owner))
    {
        return Err(E::RevocationStatusUnavailable);
    }
    Ok((tok, auth, holders, principal))
}
