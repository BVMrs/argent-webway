//! Reference model for every blob/v0 vector kind (spec/ext/blob.md §14.1). Each function takes the
//! case `input` and returns the expected `output`, or the error name of a rejection.

use crate::tree::{self, Ranges};
use serde_json::{json, Map, Value};

pub const MAX_SAFE: u64 = (1 << 53) - 1;
pub const MAX_RANGES: usize = 64;
pub const MAX_PROVIDERS: usize = 4;
pub const MAX_FETCH_TTL: i64 = 600;
pub const EXT: &str = "https://github.com/BVMrs/argent-webway/spec/ext/blob/v0";

pub type Out = Result<Value, &'static str>;

// ---------- identifiers ----------

/// `blake3:` + 64 lowercase hex digits (envelope/v0 hash format).
pub fn parse_hash(s: &str) -> Option<[u8; 32]> {
    let hex = s.strip_prefix("blake3:")?;
    if hex.len() != 64 || !hex.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

pub fn hash_str(h: &[u8; 32]) -> String {
    let mut s = String::from("blake3:");
    for b in h {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// `wwn:` / `wwa:` + 52 lowercase base32 characters encoding 32 bytes, unused trailing bits zero.
pub fn is_key_id(s: &str, prefix: &str) -> bool {
    let Some(b) = s.strip_prefix(prefix) else { return false };
    b.len() == 52
        && b.bytes().all(|c| c.is_ascii_lowercase() || (b'2'..=b'7').contains(&c))
        && matches!(b.as_bytes()[51], b'a' | b'q')
}

/// A provider: `wwn:<node>/wwa:<agent>`.
pub fn parse_provider(s: &str) -> Option<(String, String)> {
    let (n, a) = s.split_once('/')?;
    (is_key_id(n, "wwn:") && is_key_id(a, "wwa:")).then(|| (n.to_string(), a.to_string()))
}

/// Canonical decimal: no sign, no leading zeros, at most 2^53 - 1.
fn parse_decimal(s: &str) -> Option<u64> {
    if s.is_empty() || s.len() > 16 || !s.bytes().all(|c| c.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0')) {
        return None;
    }
    s.parse::<u64>().ok().filter(|&v| v <= MAX_SAFE)
}

// ---------- blob/ref ----------

pub struct BlobRef {
    pub hash: [u8; 32],
    pub size: u64,
    pub providers: Vec<String>,
}

pub fn parse_ref(url: &str) -> Option<BlobRef> {
    let rest = url.strip_prefix("webway-blob:")?;
    if rest.contains('#') {
        return None;
    }
    let (h, query) = rest.split_once('?')?;
    let hash = parse_hash(h)?;
    let mut seen: Vec<&str> = vec![];
    let (mut size, mut providers) = (None, None);
    for param in query.split('&') {
        let (name, value) = param.split_once('=')?;
        let name_ok = !name.is_empty()
            && name.as_bytes()[0].is_ascii_lowercase()
            && name.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-');
        if !name_ok || seen.contains(&name) {
            return None;
        }
        seen.push(name);
        match name {
            "size" => size = Some(parse_decimal(value)?),
            "providers" => {
                let list: Vec<&str> = value.split(',').collect();
                if list.is_empty() || list.len() > MAX_PROVIDERS {
                    return None;
                }
                let mut out: Vec<String> = vec![];
                for p in list {
                    parse_provider(p)?;
                    if out.iter().any(|q| q == p) {
                        return None;
                    }
                    out.push(p.to_string());
                }
                providers = Some(out);
            }
            _ => {} // unknown parameters are ignored (BLOB-010)
        }
    }
    Some(BlobRef { hash, size: size?, providers: providers.unwrap_or_default() })
}

pub fn blob_ref(input: &Value) -> Out {
    let url = input["url"].as_str().ok_or("BlobRefInvalid")?;
    let r = parse_ref(url).ok_or("BlobRefInvalid")?;
    Ok(json!({ "hash": hash_str(&r.hash), "size": r.size, "providers": r.providers }))
}

// ---------- ranges ----------

/// A request's `ranges`: 1 to MAX_RANGES pairs `[start, end]` of integers, `start < end <= 2^53-1`,
/// strictly increasing with a gap between consecutive pairs (BLOB-031).
pub fn parse_ranges(v: &Value) -> Option<Ranges> {
    let arr = v.as_array()?;
    if arr.is_empty() || arr.len() > MAX_RANGES {
        return None;
    }
    let mut out: Ranges = vec![];
    for p in arr {
        let p = p.as_array()?;
        if p.len() != 2 {
            return None;
        }
        let a = p[0].as_u64().filter(|&x| x <= MAX_SAFE)?;
        let b = p[1].as_u64().filter(|&x| x <= MAX_SAFE)?;
        if a >= b {
            return None;
        }
        if let Some(&(_, e)) = out.last() {
            if a <= e {
                return None;
            }
        }
        out.push((a, b));
    }
    Some(out)
}

pub fn ranges_json(r: &Ranges) -> Value {
    Value::Array(r.iter().map(|&(a, b)| json!([a, b])).collect())
}

pub fn ranges(input: &Value) -> Out {
    let req = parse_ranges(&input["ranges"]).ok_or("InvalidParamsError")?;
    let size = input["size"].as_u64().unwrap();
    Ok(json!({ "effective": ranges_json(&tree::effective(&req, tree::blocks(size))) }))
}

// ---------- data inputs ----------

pub fn data(v: &Value) -> Vec<u8> {
    if let Some(n) = v["pattern"].as_u64() {
        tree::pattern(n)
    } else {
        let h = v["hex"].as_str().unwrap();
        (0..h.len() / 2).map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap()).collect()
    }
}

pub fn hash(input: &Value) -> Out {
    let d = data(&input["data"]);
    Ok(json!({ "hash": hash_str(&tree::hash(&d)), "size": d.len(), "blocks": tree::blocks(d.len() as u64) }))
}

pub fn encode(input: &Value) -> Out {
    let d = data(&input["data"]);
    let size = d.len() as u64;
    let req = parse_ranges(&input["ranges"]).expect("encode vectors use valid ranges");
    let eff = tree::effective(&req, tree::blocks(size));
    let enc = tree::encode(&d, &eff);
    let mut out = Map::new();
    out.insert("hash".into(), json!(hash_str(&tree::hash(&d))));
    out.insert("ranges".into(), ranges_json(&eff));
    out.insert("length".into(), json!(enc.len()));
    out.insert("encodingHash".into(), json!(hash_str(blake3::hash(&enc).as_bytes())));
    if enc.len() <= 512 {
        out.insert("hex".into(), json!(enc.iter().map(|b| format!("{b:02x}")).collect::<String>()));
    }
    Ok(Value::Object(out))
}

/// The encoding the provider in a `blob/verify` case sends: the honest encoding of `data` for
/// `ranges`, then the `mutate` step applied to the bytes.
pub fn verify_stream(input: &Value) -> Vec<u8> {
    let d = data(&input["data"]);
    let r = parse_ranges(&input["ranges"]).unwrap();
    let mut enc = tree::encode(&d, &r);
    let m = &input["mutate"];
    if let Some(i) = m["flip"].as_u64() {
        enc[i as usize] ^= 0x01;
    }
    if let Some(n) = m["truncate"].as_u64() {
        enc.truncate(n as usize);
    }
    if let Some(h) = m["append"].as_str() {
        enc.extend(data(&json!({ "hex": h })));
    }
    enc
}

/// What a fetcher has after reading one reply stream. `end` says how the stream ended: `fin`
/// (the provider closed it) or `reset` (reset or connection lost). A clean FIN before the end of
/// the encoding is a protocol violation by the provider; a reset is a cut to resume (§5.4).
pub fn verify(input: &Value) -> Out {
    let hash = parse_hash(input["hash"].as_str().unwrap()).unwrap();
    let size = input["size"].as_u64().unwrap();
    let r = parse_ranges(&input["ranges"]).unwrap();
    let end = input["end"].as_str().unwrap_or("fin");
    let enc = verify_stream(input);
    let v = tree::verify(&hash, size, &r, &enc);
    let failure = match v.failure {
        Some(tree::VerifyError::Corrupt) => json!("BlobCorrupt"),
        Some(tree::VerifyError::TrailingBytes) => json!("ProtocolError"),
        None if !v.complete && end == "fin" => json!("ProtocolError"),
        None => Value::Null,
    };
    let missing = tree::subtract(&r, &v.blocks);
    Ok(json!({ "verified": ranges_json(&v.blocks), "missing": ranges_json(&missing), "complete": v.complete, "failure": failure }))
}

// ---------- time ----------

/// Seconds since the epoch of `YYYY-MM-DDTHH:MM:SS[.fff]Z` (fraction ignored).
pub fn epoch(s: &str) -> i64 {
    let n = |a: usize, b: usize| s[a..b].parse::<i64>().unwrap();
    let (y, m, d) = (n(0, 4), n(5, 7), n(8, 10));
    let (hh, mm, ss) = (n(11, 13), n(14, 16), n(17, 19));
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    days * 86400 + hh * 3600 + mm * 60 + ss
}

// ---------- blob/fetch: the provider's decision ----------

/// The provider-side decision for one Fetch request whose envelope has already passed
/// `envelope/v0` verification (signature, freshness, dedupe). Steps of spec §7.3, in order.
pub fn fetch(input: &Value) -> Out {
    let prov = &input["provider"];
    let env = &input["envelope"];
    let from = env["from"].as_str().unwrap();
    let to = env["to"].as_str().unwrap();
    // 1. Recipient (profile PROF-041).
    if !prov["agents"].as_array().unwrap().iter().any(|a| a == to) {
        return Err("RecipientUnknown");
    }
    // 2. Short-lived request: an op-specific header check, before dedupe (BLOB-031).
    if epoch(env["exp"].as_str().unwrap()) - epoch(env["ts"].as_str().unwrap()) > MAX_FETCH_TTL {
        return Err("EnvelopeInvalid");
    }
    // 3. The requester's agent is bound to the node at the other end of this connection.
    if input["bindings"][from].as_str() != input["connectionPeer"].as_str() {
        return Err("IdentityUntrusted");
    }
    // 4. Body. Unknown body members are ignored (BLOB-031).
    let body = &env["body"];
    let hash = body["hash"].as_str().and_then(parse_hash).ok_or("InvalidParamsError")?;
    let req = match body.get("ranges") {
        None => vec![(0, MAX_SAFE)],
        Some(v) => parse_ranges(v).ok_or("InvalidParamsError")?,
    };
    // 5. capability/v0 in its own order (CAP-160): presence, then the token checks, then the
    //    operation and resource check (step 8, CAP-106), then Datalog. All before any lookup.
    let Some(cap) = env["cap"]["capability"].as_str() else { return Err("CapabilityMissing") };
    let authz = input["authorization"].as_str().unwrap();
    match authz {
        "allow" | "CapabilityDenied" => {}
        "CapabilityMissing" => return Err("CapabilityMissing"),
        "CapabilityInvalid" => return Err("CapabilityInvalid"),
        "CapabilityRevoked" => return Err("CapabilityRevoked"),
        "RevocationStatusUnavailable" => return Err("RevocationStatusUnavailable"),
        other => panic!("unknown authorization result {other}"),
    }
    if cap != format!("blob:{}#read", hash_str(&hash)) || authz == "CapabilityDenied" {
        return Err("CapabilityDenied");
    }
    // 6. Lookup. A partial copy counts only once its last block is verified (BLOB-042).
    let Some(held) = input["store"].get(hash_str(&hash)) else { return Err("BlobNotFound") };
    let size = held["size"].as_u64().unwrap();
    let n = tree::blocks(size);
    let have = match held.get("blocks") {
        None => vec![(0, n)],
        Some(v) => parse_ranges(v).unwrap(),
    };
    if !have.iter().any(|&(a, b)| a < n && n <= b) {
        return Err("BlobNotFound");
    }
    let send = tree::intersect(&tree::effective(&req, n), &have);
    Ok(json!({ "hash": hash_str(&hash), "size": size, "ranges": ranges_json(&send) }))
}

// ---------- blob/provenance ----------

const LEVELS: [&str; 4] = ["self", "same-owner", "foreign", "unverified-origin"];

fn rank(l: &str) -> usize {
    LEVELS.iter().position(|x| *x == l).unwrap()
}

/// Taint and trust of fetched content (BLOB-050): from the referencing Part and its envelope's
/// verified sender only. The provider and other references to the same hash play no part.
pub fn provenance(input: &Value) -> Out {
    let me = input["receiverOwner"].as_str().unwrap();
    let r = &input["reference"];
    let taint = &r["taint"];
    let owners = taint["owners"].as_array().ok_or("EnvelopeInvalid")?;
    let unverified = taint["unverified"].as_bool().ok_or("EnvelopeInvalid")?;
    if owners.is_empty() {
        return Err("EnvelopeInvalid");
    }
    let level = |o: &str| if o == me { "same-owner" } else { "foreign" };
    let mut t = rank(level(r["senderOwner"].as_str().unwrap()));
    for o in owners {
        t = t.max(rank(level(o.as_str().unwrap())));
    }
    if unverified {
        t = rank("unverified-origin");
    }
    Ok(json!({ "trust": LEVELS[t], "taint": { "owners": owners, "unverified": unverified } }))
}

// ---------- blob/providers ----------

/// Where a fetcher may get a referenced blob (BLOB-015, BLOB-041): its own store only if the
/// fetching agent is entitled to the blob, and listed providers only if they are certified to the
/// listed node by an owner that is the fetcher's own, the sender's, or in the Part's taint (and
/// pinned or the fetcher's own), and the agent holds a grant for them. Reference order is kept.
pub fn providers(input: &Value) -> Out {
    let url = input["reference"].as_str().unwrap();
    let r = parse_ref(url).ok_or("BlobRefInvalid")?;
    let strs = |k: &str| -> Vec<&str> { input[k].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect() };
    let me = input["fetcherOwner"].as_str().unwrap();
    let sender = input["senderOwner"].as_str().unwrap();
    let pins = strs("pins");
    let taint = strs("taintOwners");
    let grants = strs("grants");
    let local = &input["local"];
    let use_local = local["held"].as_bool().unwrap_or(false) && local["entitled"].as_bool().unwrap_or(false);
    let mut out = vec![];
    for p in &r.providers {
        let (node, agent) = parse_provider(p).unwrap();
        let cert = &input["agentCerts"][&agent];
        let Some(owner) = cert["owner"].as_str() else { continue };
        if cert["node"].as_str() != Some(node.as_str()) {
            continue;
        }
        if owner != me && !pins.contains(&owner) {
            continue;
        }
        if owner != me && owner != sender && !taint.contains(&owner) {
            continue;
        }
        if !grants.contains(&p.as_str()) {
            continue;
        }
        out.push(p.clone());
    }
    Ok(json!({ "local": use_local, "contact": out }))
}

pub fn run(kind: &str, input: &Value) -> Option<Out> {
    Some(match kind {
        "blob/hash" => hash(input),
        "blob/ref" => blob_ref(input),
        "blob/ranges" => ranges(input),
        "blob/encode" => encode(input),
        "blob/verify" => verify(input),
        "blob/fetch" => fetch(input),
        "blob/provenance" => provenance(input),
        "blob/providers" => providers(input),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_known() {
        assert_eq!(epoch("1970-01-01T00:00:00Z"), 0);
        assert_eq!(epoch("2026-11-07T12:00:00Z"), 1_794_052_800);
        assert_eq!(epoch("2000-03-01T00:00:00Z"), 951_868_800);
    }
}
