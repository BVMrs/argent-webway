//! Signed statements (spec §4): JWS flattened JSON over JCS, verification with pins,
//! issuer-certs and revocation lists.

use crate::err::{E, R};
use crate::ids::{self, Role};
use crate::{jcs, time};
use data_encoding::BASE64URL_NOPAD as B64;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde_json::{json, Map, Value};
use std::collections::HashMap;

pub const MAX_STATEMENT_BYTES: usize = 16384;
pub const MAX_CERT_TTL: i64 = 400 * time::DAY;
pub const MAX_ISSUER_CERT_TTL: i64 = 30 * time::DAY;
pub const MAX_INVITE_TTL: i64 = 7 * time::DAY;
pub const MAX_LIST_VALIDITY: i64 = time::DAY;

pub const OWNER_KEY: &str = "webway-owner-key+jws";
pub const NODE_CERT: &str = "webway-node-cert+jws";
pub const ISSUER_CERT: &str = "webway-issuer-cert+jws";
pub const AGENT_CERT: &str = "webway-agent-cert+jws";
pub const REVOCATION: &str = "webway-revocation+jws";
pub const INVITE: &str = "webway-invite+jws";

pub type Claims = Map<String, Value>;

// ---------------------------------------------------------------- signing

/// Signs `claims` as a statement of type `typ` with the key `signer` whose identifier is `kid`.
/// `iss` is set to `kid`.
pub fn sign(typ: &str, signer: &SigningKey, kid: &str, mut claims: Value) -> Value {
    claims["iss"] = json!(kid);
    let header = json!({"alg": "EdDSA", "kid": kid, "typ": typ});
    sign_raw(signer, &jcs::canonical(&header).unwrap(), &jcs::canonical(&claims).unwrap())
}

/// Signs arbitrary header and payload text (used to build malformed statements too).
pub fn sign_raw(signer: &SigningKey, header: &str, payload: &str) -> Value {
    let p = B64.encode(header.as_bytes());
    let q = B64.encode(payload.as_bytes());
    let sig = signer.sign(format!("{p}.{q}").as_bytes());
    json!({"protected": p, "payload": q, "signature": B64.encode(&sig.to_bytes())})
}

pub fn statement_id(stmt: &Value) -> Option<String> {
    let p = stmt.get("protected")?.as_str()?;
    let q = stmt.get("payload")?.as_str()?;
    Some(format!("b3:{}", B64.encode(blake3::hash(format!("{p}.{q}").as_bytes()).as_bytes())))
}

// ---------------------------------------------------------------- parsing

pub struct Parsed {
    pub typ: String,
    pub kid: String,
    pub claims: Claims,
    pub id: String,
}

/// Format and signature checks (CAP-010, CAP-011, CAP-002). No trust decisions.
pub fn parse(stmt: &Value) -> R<Parsed> {
    let bad = E::StatementInvalid;
    let size = serde_json::to_string(stmt).map_err(|_| bad)?.len();
    if size > MAX_STATEMENT_BYTES {
        return Err(bad);
    }
    let o = stmt.as_object().ok_or(bad)?;
    if o.len() != 3 {
        return Err(bad);
    }
    let p = o.get("protected").and_then(Value::as_str).ok_or(bad)?;
    let q = o.get("payload").and_then(Value::as_str).ok_or(bad)?;
    let s = o.get("signature").and_then(Value::as_str).ok_or(bad)?;
    let header = jcs::parse_canonical_object(&B64.decode(p.as_bytes()).map_err(|_| bad)?).ok_or(bad)?;
    let claims = jcs::parse_canonical_object(&B64.decode(q.as_bytes()).map_err(|_| bad)?).ok_or(bad)?;
    if header.len() != 3 || header.get("alg") != Some(&json!("EdDSA")) {
        return Err(bad);
    }
    let typ = header.get("typ").and_then(Value::as_str).ok_or(bad)?.to_string();
    let kid = header.get("kid").and_then(Value::as_str).ok_or(bad)?.to_string();
    let (_, key) = ids::parse(&kid).ok_or(bad)?;
    if claims.get("iss").and_then(Value::as_str) != Some(kid.as_str()) {
        return Err(bad);
    }
    let sig: [u8; 64] = B64.decode(s.as_bytes()).map_err(|_| bad)?.try_into().map_err(|_| bad)?;
    let vk = VerifyingKey::from_bytes(&key).map_err(|_| bad)?;
    vk.verify_strict(format!("{p}.{q}").as_bytes(), &Signature::from_bytes(&sig)).map_err(|_| bad)?;
    Ok(Parsed { typ, kid, claims, id: statement_id(stmt).unwrap() })
}

pub fn str_claim<'a>(c: &'a Claims, k: &str) -> R<&'a str> {
    c.get(k).and_then(Value::as_str).ok_or(E::StatementInvalid)
}
pub fn time_claim(c: &Claims, k: &str) -> R<i64> {
    time::parse(str_claim(c, k)?).ok_or(E::StatementInvalid)
}
pub fn id_claim(c: &Claims, k: &str, role: Role) -> R<[u8; 32]> {
    ids::parse_role(str_claim(c, k)?, role).ok_or(E::StatementInvalid)
}

// ---------------------------------------------------------------- owner keys (§4.3)

/// What a verifier knows about a pinned owner: which root keys may sign.
#[derive(Clone, Debug)]
pub struct Pin {
    pub owner: String,
    pub current: String,
    /// Older root keys that still sign valid statements (rotations without `compromised`).
    pub older: Vec<String>,
    pub next: Option<String>,
    pub seq: i64,
}

impl Pin {
    pub fn simple(owner: &str) -> Pin {
        Pin { owner: owner.into(), current: owner.into(), older: vec![], next: None, seq: 0 }
    }
    pub fn may_sign(&self, did: &str) -> bool {
        self.current == did || self.older.iter().any(|k| k == did)
    }
}

pub fn commitment(key: &[u8; 32]) -> String {
    format!("b3:{}", B64.encode(blake3::hash(key).as_bytes()))
}

/// Verifies an owner-key event chain from seq 0 (CAP-020, CAP-021).
pub fn owner_keys(owner: &str, events: &[Value]) -> R<Pin> {
    let mut pin: Option<Pin> = None;
    let mut prev_id = String::new();
    for ev in events {
        let p = parse(ev)?;
        if p.typ != OWNER_KEY {
            return Err(E::StatementInvalid);
        }
        let c = &p.claims;
        let seq = c.get("seq").and_then(Value::as_i64).ok_or(E::StatementInvalid)?;
        let key = str_claim(c, "key")?;
        let key_bytes = ids::parse_role(key, Role::Owner).ok_or(E::StatementInvalid)?;
        time_claim(c, "iat")?;
        let next = match c.get("next") {
            None => None,
            Some(v) => Some(v.as_str().ok_or(E::StatementInvalid)?.to_string()),
        };
        let untrusted = E::StatementUntrusted;
        if str_claim(c, "owner")? != owner || p.kid != key {
            return Err(untrusted);
        }
        match pin.take() {
            None => {
                if seq != 0 || key != owner || c.contains_key("prev") || c.contains_key("compromised") {
                    return Err(untrusted);
                }
                pin = Some(Pin { owner: owner.into(), current: key.into(), older: vec![], next, seq });
            }
            Some(mut old) => {
                let committed = old.next.clone().ok_or(untrusted)?;
                if seq != old.seq + 1 || str_claim(c, "prev")? != prev_id || committed != commitment(&key_bytes) {
                    return Err(untrusted);
                }
                let compromised = c.get("compromised").and_then(Value::as_bool).unwrap_or(false);
                if compromised {
                    old.older.clear();
                } else {
                    old.older.push(old.current.clone());
                }
                old.current = key.into();
                old.next = next;
                old.seq = seq;
                pin = Some(old);
            }
        }
        prev_id = p.id;
    }
    pin.ok_or(E::StatementInvalid)
}

// ---------------------------------------------------------------- verification context

pub struct Ctx {
    pub now: i64,
    pub pins: Vec<Pin>,
    /// Pool of issuer-certs (unverified) used to resolve `wwi:` signers.
    pub issuer_certs: Vec<Value>,
    /// Verified revocation lists, highest `seq` per (owner, signer) (CAP-170).
    pub lists: HashMap<(String, String), List>,
}

#[derive(Clone, Debug)]
pub struct List {
    pub owner: String,
    pub iss: String,
    pub seq: i64,
    pub valid_until: i64,
    pub revoked: Vec<String>,
}

pub struct Verified {
    pub claims: Claims,
    pub kid: String,
}

impl Ctx {
    pub fn new(now: i64, pins: Vec<Pin>, issuer_certs: Vec<Value>) -> Ctx {
        Ctx { now, pins, issuer_certs, lists: HashMap::new() }
    }

    pub fn pin(&self, owner: &str) -> Option<&Pin> {
        self.pins.iter().find(|p| p.owner == owner)
    }

    /// Adds revocation lists. Invalid ones are ignored; a lower or equal `seq` never
    /// replaces a held list (CAP-170).
    pub fn add_lists(&mut self, lists: &[Value]) {
        for l in lists {
            if let Ok(v) = self.verify_inner(REVOCATION, l, false) {
                let c = &v.claims;
                let (Ok(owner), Some(seq), Ok(vu)) =
                    (str_claim(c, "owner"), c.get("seq").and_then(Value::as_i64), time_claim(c, "validUntil"))
                else {
                    continue;
                };
                let revoked = c
                    .get("revoked")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                    .unwrap_or_default();
                let key = (owner.to_string(), v.kid.clone());
                if self.lists.get(&key).is_none_or(|h| seq > h.seq) {
                    self.lists.insert(key, List { owner: owner.into(), iss: v.kid, seq, valid_until: vu, revoked });
                }
            }
        }
    }

    /// Is `entry` (a token block revocation ID or a statement ID) revoked by a list from the
    /// owner's root keys, or from `signer` (the key that issued the item)? (CAP-171, CAP-015)
    pub fn is_revoked(&self, owner: &str, signer: &str, entry: &str) -> bool {
        self.lists.values().any(|l| {
            l.owner == owner
                && (l.iss == signer || self.pin(owner).is_some_and(|p| p.may_sign(&l.iss)))
                && l.revoked.iter().any(|r| r == entry)
        })
    }

    pub fn fresh_list(&self, owner: &str, signer: &str) -> bool {
        self.lists.values().any(|l| l.owner == owner && l.iss == signer && self.now <= l.valid_until)
    }

    pub fn verify(&self, typ: &str, stmt: &Value) -> R<Verified> {
        self.verify_inner(typ, stmt, true)
    }

    fn verify_inner(&self, typ: &str, stmt: &Value, check_revoked: bool) -> R<Verified> {
        let p = parse(stmt)?;
        if p.typ != typ {
            return Err(E::StatementInvalid); // CAP-012
        }
        let c = &p.claims;
        let owner = str_claim(c, "owner")?.to_string();
        ids::parse_role(&owner, Role::Owner).ok_or(E::StatementInvalid)?;
        let iat = time_claim(c, "iat")?;
        check_schema(typ, c)?;

        // Signer authorisation (CAP-013, CAP-040).
        let (kid_role, _) = ids::parse(&p.kid).ok_or(E::StatementInvalid)?;

        let mut issuer_exp = i64::MAX;
        match kid_role {
            Role::Owner => {
                if typ == INVITE {
                    return Err(E::StatementUntrusted);
                }
                let pin = self.pin(&owner).ok_or(E::StatementUntrusted)?;
                if !pin.may_sign(&p.kid) {
                    return Err(E::StatementUntrusted);
                }
            }
            Role::Issuer => {
                if typ == NODE_CERT || typ == ISSUER_CERT {
                    return Err(E::StatementUntrusted);
                }
                let cert = self
                    .issuer_certs
                    .iter()
                    .find(|ic| {
                        parse(ic)
                            .ok()
                            .is_some_and(|pp| pp.claims.get("issuer").and_then(Value::as_str) == Some(p.kid.as_str()))
                    })
                    .ok_or(E::StatementUntrusted)?;
                let ic = self.verify_inner(ISSUER_CERT, cert, check_revoked).map_err(|e| match e {
                    E::StatementInvalid => E::StatementUntrusted,
                    e => e,
                })?;
                if str_claim(&ic.claims, "owner")? != owner {
                    return Err(E::StatementUntrusted);
                }
                let scope = ic.claims.get("scope").cloned().unwrap_or(Value::Null);
                let flag = |k: &str| scope.get(k).and_then(Value::as_bool).unwrap_or(false);
                let same_node = c.get("node").is_some() && c.get("node") == ic.claims.get("node");
                let ok = match typ {
                    AGENT_CERT => flag("agentCerts") && same_node,
                    INVITE => flag("invites"),
                    REVOCATION => true,
                    _ => false,
                };
                if !ok {
                    return Err(E::StatementUntrusted);
                }
                issuer_exp = time_claim(&ic.claims, "exp")?;
            }
            _ => return Err(E::StatementUntrusted),
        }

        // Time (CAP-014).
        if iat > self.now + time::SKEW {
            return Err(E::StatementExpired);
        }
        if typ == REVOCATION {
            let vu = time_claim(c, "validUntil")?;
            let max = if kid_role == Role::Owner { MAX_ISSUER_CERT_TTL } else { MAX_LIST_VALIDITY };
            if vu - iat > max || vu < iat {
                return Err(E::StatementInvalid);
            }
        } else {
            let exp = time_claim(c, "exp")?;
            let max = match typ {
                ISSUER_CERT => MAX_ISSUER_CERT_TTL,
                INVITE => MAX_INVITE_TTL,
                _ => MAX_CERT_TTL,
            };
            if exp - iat > max || exp < iat || exp > issuer_exp {
                return Err(E::StatementInvalid);
            }
            if self.now > exp {
                return Err(E::StatementExpired);
            }
        }

        // Revocation (CAP-015). The issuer-cert in the chain was checked by the recursive call.
        if check_revoked && self.is_revoked(&owner, &p.kid, &p.id) {
            return Err(E::StatementRevoked);
        }
        Ok(Verified { claims: p.claims, kid: p.kid })
    }
}

/// Required members and their forms, per type.
fn check_schema(typ: &str, c: &Claims) -> R<()> {
    let bad = E::StatementInvalid;
    match typ {
        NODE_CERT => {
            id_claim(c, "node", Role::Node)?;
        }
        AGENT_CERT => {
            id_claim(c, "agent", Role::Agent)?;
            id_claim(c, "node", Role::Node)?;
        }
        ISSUER_CERT => {
            id_claim(c, "issuer", Role::Issuer)?;
            id_claim(c, "node", Role::Node)?;
            let s = c.get("scope").and_then(Value::as_object).ok_or(bad)?;
            if let Some(r) = s.get("resource") {
                r.as_array().ok_or(bad)?.iter().try_for_each(|x| x.as_str().map(|_| ()).ok_or(bad))?;
            }
            if let Some(m) = s.get("mandate").filter(|m| !m.is_null()) {
                m.get("targets").and_then(Value::as_array).ok_or(bad)?;
                m.get("capabilities").and_then(Value::as_array).ok_or(bad)?;
                let t = m.get("maxTtl").and_then(Value::as_i64).ok_or(bad)?;
                if t <= 0 || t > crate::cap::MAX_MANDATE_TTL {
                    return Err(bad);
                }
            }
        }
        REVOCATION => {
            c.get("seq").and_then(Value::as_i64).ok_or(bad)?;
            c.get("revoked").and_then(Value::as_array).ok_or(bad)?;
        }
        INVITE => {
            str_claim(c, "id")?;
            id_claim(c, "node", Role::Node)?;
        }
        _ => return Err(bad),
    }
    Ok(())
}

/// Matches a capability against a scope pattern: exact, or prefix ending in `*`.
pub fn pattern_matches(pattern: &str, cap: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => cap.starts_with(prefix),
        None => pattern == cap,
    }
}
