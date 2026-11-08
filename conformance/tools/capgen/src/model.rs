//! Dispatch of vector kinds to the reference model, and invite verification (spec §8).

use crate::cap;
use crate::err::{E, R};
use crate::ids::{self, Role};
use crate::stmt::{self, Ctx, Pin};
use crate::time;
use biscuit_auth::Biscuit;
use data_encoding::BASE64URL_NOPAD as B64;
use serde_json::{json, Value};

pub fn run(kind: &str, input: &Value) -> Option<R<Value>> {
    Some(match kind {
        "identity/id" => id(input),
        "identity/statement" => statement(input),
        "identity/owner-key" => owner_key(input),
        "capability/authorize" => cap::authorize(input),
        "capability/invite" => invite(input),
        "capability/outbound" => outbound(input),
        _ => return None,
    })
}

fn id(input: &Value) -> R<Value> {
    let s = input.get("id").and_then(Value::as_str).ok_or(E::IdentifierInvalid)?;
    let (role, key) = ids::parse(s).ok_or(E::IdentifierInvalid)?;
    Ok(json!({"role": role.name(), "key": B64.encode(&key)}))
}

fn pins(v: Option<&Value>) -> R<Vec<Pin>> {
    let mut out = vec![];
    for p in v.and_then(Value::as_array).cloned().unwrap_or_default() {
        let owner = p.get("owner").and_then(Value::as_str).ok_or(E::StatementInvalid)?;
        out.push(match p.get("events").and_then(Value::as_array) {
            Some(ev) => stmt::owner_keys(owner, ev)?,
            None => Pin::simple(owner),
        });
    }
    Ok(out)
}

fn statement(input: &Value) -> R<Value> {
    let now = time::parse(input.get("now").and_then(Value::as_str).unwrap_or("")).ok_or(E::StatementInvalid)?;
    let typ = input.get("typ").and_then(Value::as_str).ok_or(E::StatementInvalid)?;
    let issuer_certs = input.get("issuerCert").map(|c| vec![c.clone()]).unwrap_or_default();
    let mut ctx = Ctx::new(now, pins(input.get("pins"))?, issuer_certs);
    ctx.add_lists(input.get("revocations").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]));
    let v = ctx.verify(typ, input.get("statement").ok_or(E::StatementInvalid)?)?;
    Ok(Value::Object(v.claims))
}

fn owner_key(input: &Value) -> R<Value> {
    let owner = input.pointer("/pin/owner").and_then(Value::as_str).ok_or(E::StatementInvalid)?;
    let events = input.get("events").and_then(Value::as_array).ok_or(E::StatementInvalid)?;
    let p = stmt::owner_keys(owner, events)?;
    Ok(json!({"key": p.current, "next": p.next, "seq": p.seq}))
}

pub const INVITE_PREFIX: &str = "webway-invite:";

/// `capability/invite` (CAP-200, CAP-201).
fn invite(input: &Value) -> R<Value> {
    let bad = E::InviteInvalid;
    let now = time::parse(input.get("now").and_then(Value::as_str).unwrap_or("")).ok_or(bad)?;
    let s = input.get("invite").and_then(Value::as_str).ok_or(bad)?;
    let raw = B64.decode(s.strip_prefix(INVITE_PREFIX).ok_or(bad)?.as_bytes()).map_err(|_| bad)?;
    let jws: Value = serde_json::from_slice(&raw).map_err(|_| bad)?;
    // Read the claims to learn the owner and issuer-cert; the full verification follows.
    let unverified = stmt::parse(&jws).map_err(|_| bad)?;
    let owner = stmt::str_claim(&unverified.claims, "owner").map_err(|_| bad)?.to_string();
    let ic = unverified.claims.get("issuerCert").cloned().ok_or(bad)?;
    // The invite channel authenticates `owner`: verify as if it were pinned.
    // An invite may carry the owner's full key-event chain (CAP-202): it is verified from
    // inception (CAP-020), never taken as a single "latest" event.
    let pin = match unverified.claims.get("ownerKeys") {
        None => Pin::simple(&owner),
        Some(evs) => stmt::owner_keys(&owner, evs.as_array().ok_or(bad)?).map_err(|_| bad)?,
    };
    let ctx = Ctx::new(now, vec![pin.clone()], vec![ic]);
    let v = ctx.verify(stmt::INVITE, &jws).map_err(|e| match e {
        E::StatementExpired => E::InviteExpired,
        _ => bad,
    })?;
    let c = &v.claims;
    let id = stmt::str_claim(c, "id").map_err(|_| bad)?;
    let mode = stmt::str_claim(c, "mode").map_err(|_| bad)?;
    let iss = v.kid.clone();
    let root = ids::parse_role(&iss, Role::Issuer).ok_or(bad)?;

    let mut agents = vec![];
    for a in c.get("agents").and_then(Value::as_array).cloned().unwrap_or_default() {
        let agent = a.get("agent").and_then(Value::as_str).ok_or(bad)?;
        let av = ctx.verify(stmt::AGENT_CERT, a.get("cert").ok_or(bad)?).map_err(|_| bad)?;
        if av.claims.get("agent").and_then(Value::as_str) != Some(agent) {
            return Err(bad);
        }
        agents.push(agent.to_string());
    }

    let grants: Vec<String> = c
        .get("grants")
        .and_then(Value::as_array)
        .ok_or(bad)?
        .iter()
        .map(|g| g.as_str().map(String::from).ok_or(bad))
        .collect::<R<_>>()?;
    let holder0 = match mode {
        "bound" => {
            if c.contains_key("inviteKey") {
                return Err(bad);
            }
            let invitee = stmt::str_claim(c, "invitee").map_err(|_| bad)?.to_string();
            ids::parse_role(&invitee, Role::Agent).ok_or(bad)?;
            if let Some(acc) = input.get("acceptingAgent").and_then(Value::as_str) {
                if acc != invitee {
                    return Err(bad);
                }
            }
            invitee
        }
        "redeem" => {
            if c.contains_key("invitee") || grants.len() != 1 {
                return Err(bad);
            }
            let seed: [u8; 32] = B64
                .decode(stmt::str_claim(c, "inviteKey").map_err(|_| bad)?.as_bytes())
                .map_err(|_| bad)?
                .try_into()
                .map_err(|_| bad)?;
            let pk = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key().to_bytes();
            ids::encode(Role::Agent, &pk)
        }
        _ => return Err(bad),
    };
    if grants.is_empty() {
        return Err(bad);
    }
    for g in &grants {
        let bytes = B64.decode(g.as_bytes()).map_err(|_| bad)?;
        let pk = biscuit_auth::PublicKey::from_bytes(&root, biscuit_auth::Algorithm::Ed25519).map_err(|_| bad)?;
        Biscuit::from(&bytes, pk).map_err(|_| bad)?;
        let blocks = cap::decode_blocks(&bytes).map_err(|_| bad)?;
        let facts = &blocks[0].facts;
        let get = |name: &str| -> Vec<Vec<cap::T>> {
            cap::facts_named(facts, name).into_iter().map(|t| t.to_vec()).collect()
        };
        let s = |x: &str| cap::T::Str(x.to_string());
        if get("webway") != vec![vec![s("capability/v0"), s("access")]]
            || get("owner") != vec![vec![s(&owner)]]
            || get("issuer") != vec![vec![s(&iss)]]
            || get("holder") != vec![vec![s(&holder0), cap::T::Int(0)]]
        {
            return Err(bad);
        }
        if mode == "redeem" && get("right") != vec![vec![s(&format!("invite:{id}#redeem"))]] {
            return Err(bad);
        }
    }
    Ok(json!({
        "owner": owner,
        "ownerKey": pin.current,
        "node": c.get("node"),
        "mode": mode,
        "agents": agents,
        "grants": grants.len(),
    }))
}

/// `capability/outbound` (CAP-186): which mandate, if any, a node attaches to an outbound request.
fn outbound(input: &Value) -> R<Value> {
    let bad = E::CapabilityInvalid;
    let ptr = |p: &str| input.pointer(p).and_then(Value::as_str);
    let now = time::parse(ptr("/now").unwrap_or("")).ok_or(bad)?;
    let own = ptr("/node/owner").ok_or(bad)?;
    let target = ptr("/request/targetOwner").ok_or(bad)?;
    let capability = ptr("/request/capability").ok_or(bad)?;
    let originator = ptr("/task/originatorOwner");
    // The rule applies only when the request goes to another owner, for a task that a third owner
    // started (B serving A calls C).
    let applies = matches!(originator, Some(o) if o != own && o != target) && target != own;
    if !applies {
        return Ok(json!({"mandate": null}));
    }
    let onward = input.pointer("/task/onward").and_then(Value::as_array).cloned().unwrap_or_default();
    for (i, m) in onward.iter().enumerate() {
        let Some(tok) = m.get("token").and_then(Value::as_str) else { continue };
        let Ok(bytes) = B64.decode(tok.as_bytes()) else { continue };
        let Ok(blocks) = cap::decode_blocks(&bytes) else { continue };
        let facts = &blocks[0].facts;
        let s = |x: &str| cap::T::Str(x.to_string());
        let covers = cap::facts_named(facts, "grant").iter().any(|t| *t == [s(target), s(capability)]);
        let live = cap::facts_named(facts, "expires").iter().any(|t| matches!(t, [cap::T::Date(d)] if now <= *d));
        if covers && live {
            return Ok(json!({"mandate": i}));
        }
    }
    let allowed = input
        .pointer("/policy/selfPrincipal")
        .and_then(Value::as_array)
        .is_some_and(|a| a.iter().filter_map(Value::as_str).any(|p| stmt::pattern_matches(p, capability)));
    if allowed {
        return Ok(json!({"mandate": null, "selfPrincipal": true}));
    }
    Err(E::MandateRequired)
}
