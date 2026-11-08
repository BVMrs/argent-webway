//! Identifiers (spec §3): did:key for owners, wwi:/wwn:/wwa: + base32 for the rest.

use data_encoding::{Encoding, Specification};
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Owner,
    Issuer,
    Node,
    Agent,
}

impl Role {
    pub fn name(self) -> &'static str {
        match self {
            Role::Owner => "owner",
            Role::Issuer => "issuer",
            Role::Node => "node",
            Role::Agent => "agent",
        }
    }
}

fn b32() -> &'static Encoding {
    static E: OnceLock<Encoding> = OnceLock::new();
    E.get_or_init(|| {
        let mut s = Specification::new();
        s.symbols.push_str("abcdefghijklmnopqrstuvwxyz234567");
        // check_trailing_bits defaults to true: non-canonical encodings are rejected.
        s.encoding().unwrap()
    })
}

pub fn encode(role: Role, key: &[u8; 32]) -> String {
    match role {
        Role::Owner => {
            let mut v = vec![0xed, 0x01];
            v.extend_from_slice(key);
            format!("did:key:z{}", bs58::encode(v).into_string())
        }
        Role::Issuer => format!("wwi:{}", b32().encode(key)),
        Role::Node => format!("wwn:{}", b32().encode(key)),
        Role::Agent => format!("wwa:{}", b32().encode(key)),
    }
}

pub fn owner(name: &str) -> String {
    encode(Role::Owner, &crate::keys::public(name))
}
pub fn issuer(name: &str) -> String {
    encode(Role::Issuer, &crate::keys::public(name))
}
pub fn node(name: &str) -> String {
    encode(Role::Node, &crate::keys::public(name))
}
pub fn agent(name: &str) -> String {
    encode(Role::Agent, &crate::keys::public(name))
}

/// Parses an identifier and checks that its key is a usable Ed25519 point (CAP-001, CAP-002).
pub fn parse(id: &str) -> Option<(Role, [u8; 32])> {
    let (role, key) = if let Some(rest) = id.strip_prefix("did:key:z") {
        let raw = bs58::decode(rest).into_vec().ok()?;
        if raw.len() != 34 || raw[0] != 0xed || raw[1] != 0x01 {
            return None;
        }
        // base58 has a unique encoding for given bytes, but leading '1's encode zero bytes:
        // re-encode to reject any alternative spelling.
        if bs58::encode(&raw).into_string() != rest {
            return None;
        }
        (Role::Owner, raw[2..].try_into().ok()?)
    } else {
        let (role, rest) = if let Some(r) = id.strip_prefix("wwi:") {
            (Role::Issuer, r)
        } else if let Some(r) = id.strip_prefix("wwn:") {
            (Role::Node, r)
        } else if let Some(r) = id.strip_prefix("wwa:") {
            (Role::Agent, r)
        } else {
            return None;
        };
        if rest.len() != 52 {
            return None;
        }
        let raw = b32().decode(rest.as_bytes()).ok()?;
        (role, raw.try_into().ok()?)
    };
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&key).ok()?;
    if vk.is_weak() {
        return None;
    }
    Some((role, key))
}

pub fn parse_role(id: &str, role: Role) -> Option<[u8; 32]> {
    match parse(id) {
        Some((r, k)) if r == role => Some(k),
        _ => None,
    }
}
