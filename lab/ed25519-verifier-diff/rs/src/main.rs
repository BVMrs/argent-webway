//! Lab: Ed25519 verifier differential for envelope/v0 ENV-210/211.
//!
//! `gen <out.json>`               builds the adversarial corpus (and a reference feature vector per case)
//! `verify <in.json> <out.json>`  runs the Rust verifiers over a corpus and writes accept bits
//!
//! Corpus construction: A = a·B + T_A, R = r·B + T_R (T_* in the 8-torsion), S = r + k·a (mod L), optionally + L.
//! Then S·B − k·A − R = −(T_R + k·T_A): the cofactored equation always holds, the cofactorless one holds iff
//! T_R + k·T_A = 0. Encodings of A and R are canonical or one of the non-canonical encodings that decode.

use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT as B, EIGHT_TORSION};
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha512};

const L_BYTES: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

fn add_l(s: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut c = 0u16;
    for i in 0..32 {
        let v = s[i] as u16 + L_BYTES[i] as u16 + c;
        out[i] = v as u8;
        c = v >> 8;
    }
    out
}

fn rand_scalar(rng: &mut ChaCha20Rng) -> Scalar {
    let mut w = [0u8; 64];
    rng.fill_bytes(&mut w);
    Scalar::from_bytes_mod_order_wide(&w)
}

fn k_of(r: &[u8; 32], a: &[u8; 32], m: &[u8]) -> Scalar {
    let mut h = Sha512::new();
    h.update(r);
    h.update(a);
    h.update(m);
    Scalar::from_bytes_mod_order_wide(&h.finalize().into())
}

/// All 32-byte strings that decode (permissively, as curve25519-dalek does) but are not the canonical encoding.
fn noncanonical_encodings() -> Vec<([u8; 32], EdwardsPoint)> {
    let mut out = vec![];
    // p = 2^255 - 19
    let mut p = [0xffu8; 32];
    p[0] = 0xed;
    p[31] = 0x7f;
    let mut cands: Vec<[u8; 32]> = vec![];
    // y + p for y in 0..19 (only these fit below 2^255), both sign bits
    for y in 0u16..19 {
        let mut b = p;
        let mut c = y;
        for byte in b.iter_mut() {
            let v = *byte as u16 + c;
            *byte = v as u8;
            c = v >> 8;
        }
        assert_eq!(c, 0);
        cands.push(b);
        let mut b2 = b;
        b2[31] |= 0x80;
        cands.push(b2);
    }
    // canonical y with the sign bit flipped (only differs from canonical when x = 0)
    for t in EIGHT_TORSION.iter() {
        let mut b = t.compress().to_bytes();
        b[31] ^= 0x80;
        cands.push(b);
    }
    for b in cands {
        if let Some(pt) = CompressedEdwardsY(b).decompress() {
            if pt.compress().to_bytes() != b && !out.iter().any(|(x, _)| *x == b) {
                out.push((b, pt));
            }
        }
    }
    out
}

fn features(pk: &[u8; 32], sig: &[u8; 64], msg: &[u8]) -> Value {
    let a = CompressedEdwardsY(*pk).decompress();
    let r_b: [u8; 32] = sig[..32].try_into().unwrap();
    let s_b: [u8; 32] = sig[32..].try_into().unwrap();
    let r = CompressedEdwardsY(r_b).decompress();
    let mut f = Map::new();
    f.insert("A_decodes".into(), json!(a.is_some()));
    f.insert("R_decodes".into(), json!(r.is_some()));
    f.insert("S_lt_L".into(), json!(bool::from(Scalar::from_canonical_bytes(s_b).is_some())));
    if let Some(a) = a {
        f.insert("A_canonical".into(), json!(a.compress().to_bytes() == *pk));
        f.insert("A_small".into(), json!(a.is_small_order()));
        f.insert("A_torsion_free".into(), json!(a.is_torsion_free()));
    }
    if let Some(r) = r {
        f.insert("R_canonical".into(), json!(r.compress().to_bytes() == r_b));
        f.insert("R_small".into(), json!(r.is_small_order()));
        f.insert("R_torsion_free".into(), json!(r.is_torsion_free()));
    }
    if let (Some(a), Some(r)) = (a, r) {
        let k = k_of(&r_b, pk, msg);
        let s = Scalar::from_bytes_mod_order(s_b);
        let d = B * s - a * k - r;
        f.insert("eq_cofactorless".into(), json!(d.is_identity()));
        f.insert("eq_cofactored".into(), json!(d.mul_by_cofactor().is_identity()));
    }
    Value::Object(f)
}

enum RC {
    Prime,
    Mixed(usize),
    Small(usize),
    SmallNc([u8; 32]),
}

fn gen(out: &str) {
    let mut rng = ChaCha20Rng::seed_from_u64(0x5eed_2026_1109);
    let nc = noncanonical_encodings();
    eprintln!("non-canonical decodable encodings: {}", nc.len());
    for (b, p) in &nc {
        eprintln!("  {} small={}", hex::encode(b), p.is_small_order());
    }
    let tag = |b: &[u8; 32]| format!("{:02x}..{:02x}", b[0], b[31]);
    // key classes: (label, scalar a, encoded A)
    let mut keys: Vec<(String, Scalar, [u8; 32])> = vec![];
    let a0 = rand_scalar(&mut rng);
    keys.push(("A:prime".into(), a0, (B * a0).compress().to_bytes()));
    for j in 1..8 {
        let a = rand_scalar(&mut rng);
        keys.push((format!("A:mixed[{j}]"), a, (B * a + EIGHT_TORSION[j]).compress().to_bytes()));
    }
    for j in 0..8 {
        keys.push((format!("A:small[{j}]"), Scalar::ZERO, EIGHT_TORSION[j].compress().to_bytes()));
    }
    for (b, p) in &nc {
        // only small-order non-canonical points have a known discrete log (0, plus torsion)
        if p.is_small_order() {
            keys.push((format!("A:small-nc[{}]", tag(b)), Scalar::ZERO, *b));
        }
    }
    let mut rcs: Vec<(String, RC)> = vec![("R:prime".into(), RC::Prime)];
    for j in 1..8 {
        rcs.push((format!("R:mixed[{j}]"), RC::Mixed(j)));
    }
    for j in 0..8 {
        rcs.push((format!("R:small[{j}]"), RC::Small(j)));
    }
    for (b, p) in &nc {
        if p.is_small_order() {
            rcs.push((format!("R:small-nc[{}]", tag(b)), RC::SmallNc(*b)));
        }
    }
    let msgs_per = 16;
    let mut cases = vec![];
    for (kl, a, pk) in &keys {
        for (rl, rc) in &rcs {
            for m in 0..msgs_per {
                let mut msg = vec![0u8; 24];
                rng.fill_bytes(&mut msg);
                let (r, r_enc) = match rc {
                    RC::Prime => {
                        let r = rand_scalar(&mut rng);
                        (r, (B * r).compress().to_bytes())
                    }
                    RC::Mixed(j) => {
                        let r = rand_scalar(&mut rng);
                        (r, (B * r + EIGHT_TORSION[*j]).compress().to_bytes())
                    }
                    RC::Small(j) => (Scalar::ZERO, EIGHT_TORSION[*j].compress().to_bytes()),
                    RC::SmallNc(b) => (Scalar::ZERO, *b),
                };
                let k = k_of(&r_enc, pk, &msg);
                let s = (r + k * a).to_bytes();
                for (sl, sb) in [("S:canon", s), ("S:+L", add_l(&s))] {
                    // S+L only for the first 4 messages of each class, to keep the corpus small
                    if sl == "S:+L" && m >= 4 {
                        continue;
                    }
                    let mut sig = [0u8; 64];
                    sig[..32].copy_from_slice(&r_enc);
                    sig[32..].copy_from_slice(&sb);
                    cases.push(json!({
                        "id": format!("{kl}|{rl}|{sl}|{m}"),
                        "class": format!("{kl}|{rl}|{sl}"),
                        "pk": hex::encode(pk), "msg": hex::encode(&msg), "sig": hex::encode(sig),
                        "f": features(pk, &sig, &msg),
                    }));
                }
            }
        }
    }
    // honest signatures (sanity: nobody may reject these)
    for i in 0..20_000usize {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let mut msg = vec![0u8; i % 200];
        rng.fill_bytes(&mut msg);
        use ed25519_dalek::Signer;
        let sig = sk.sign(&msg).to_bytes();
        let pk = sk.verifying_key().to_bytes();
        cases.push(json!({"id": format!("honest|{i}"), "class": "honest",
            "pk": hex::encode(pk), "msg": hex::encode(&msg), "sig": hex::encode(sig),
            "f": features(&pk, &sig, &msg)}));
    }
    // speccheck (Chalkias, Garillot, Nikolaenko 2020) vectors 0..11
    let sc: Value =
        serde_json::from_str(&std::fs::read_to_string("../data/speccheck-cases.json").unwrap()).unwrap();
    for (i, c) in sc.as_array().unwrap().iter().enumerate() {
        let pk: [u8; 32] = hex::decode(c["pub_key"].as_str().unwrap()).unwrap().try_into().unwrap();
        let sig: [u8; 64] = hex::decode(c["signature"].as_str().unwrap()).unwrap().try_into().unwrap();
        let msg = hex::decode(c["message"].as_str().unwrap()).unwrap();
        cases.push(json!({"id": format!("speccheck|{i}"), "class": format!("speccheck[{i}]"),
            "pk": hex::encode(pk), "msg": hex::encode(&msg), "sig": hex::encode(sig),
            "f": features(&pk, &sig, &msg)}));
    }
    eprintln!("cases: {}", cases.len());
    std::fs::write(out, serde_json::to_string(&cases).unwrap()).unwrap();
}

// ---------------- verifiers ----------------

/// Copy of conformance/tools/audit-vectors/src/audit.rs `verify_strict` (ENV-210/211), on raw bytes.
fn env210(key: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    let Some(point) = CompressedEdwardsY(*key).decompress() else { return false };
    if point.compress().to_bytes() != *key || point.is_small_order() {
        return false;
    }
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(key) else { return false };
    vk.verify_strict(msg, &ed25519_dalek::Signature::from_bytes(sig)).is_ok()
}
/// What biscuit-auth 6 does (crypto/ed25519.rs: VerifyingKey::from_bytes + verify_strict).
fn dalek_strict(key: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    ed25519_dalek::VerifyingKey::from_bytes(key)
        .map(|vk| vk.verify_strict(msg, &ed25519_dalek::Signature::from_bytes(sig)).is_ok())
        .unwrap_or(false)
}
fn dalek_verify(key: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    use ed25519_dalek::Verifier;
    ed25519_dalek::VerifyingKey::from_bytes(key)
        .map(|vk| vk.verify(msg, &ed25519_dalek::Signature::from_bytes(sig)).is_ok())
        .unwrap_or(false)
}
fn zebra(key: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    ed25519_zebra::VerificationKey::try_from(*key)
        .map(|vk| vk.verify(&ed25519_zebra::Signature::from(*sig), msg).is_ok())
        .unwrap_or(false)
}
fn ring_v(key: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key).verify(msg, sig).is_ok()
}

fn verify(inp: &str, out: &str) {
    let cases: Vec<Value> = serde_json::from_str(&std::fs::read_to_string(inp).unwrap()).unwrap();
    let mut res = Map::new();
    let t = std::time::Instant::now();
    for c in &cases {
        let pk: [u8; 32] = hex::decode(c["pk"].as_str().unwrap()).unwrap().try_into().unwrap();
        let sig: [u8; 64] = hex::decode(c["sig"].as_str().unwrap()).unwrap().try_into().unwrap();
        let msg = hex::decode(c["msg"].as_str().unwrap()).unwrap();
        res.insert(
            c["id"].as_str().unwrap().into(),
            json!({
                "rs:ENV-210/211 (audit-vectors)": env210(&pk, &msg, &sig),
                "rs:ed25519-dalek 2.2 verify_strict (= biscuit-auth 6)": dalek_strict(&pk, &msg, &sig),
                "rs:ed25519-dalek 2.2 verify": dalek_verify(&pk, &msg, &sig),
                "rs:ed25519-zebra 4 (ZIP-215)": zebra(&pk, &msg, &sig),
                "rs:ring 0.17": ring_v(&pk, &msg, &sig),
            }),
        );
    }
    eprintln!("verified {} cases in {:?}", cases.len(), t.elapsed());
    std::fs::write(out, serde_json::to_string(&res).unwrap()).unwrap();
}

// ---------------- proposed audit/v0 checkpoint vectors ----------------

fn b32(b: &[u8]) -> String {
    const A: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let (mut v, mut bits, mut o) = (0u32, 0, String::new());
    for &x in b {
        v = (v << 8) | x as u32;
        bits += 8;
        while bits >= 5 {
            o.push(A[((v >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        o.push(A[((v << (5 - bits)) & 31) as usize] as char);
    }
    o
}

/// signing input = v ‖ 0x00 ‖ JCS(object minus sig). serde_json's default Map is sorted, and the checkpoint has
/// only strings and small integers, so `to_string` is the JCS form here.
fn cp_signing_input(cp: &Map<String, Value>) -> Vec<u8> {
    let mut o = cp.clone();
    o.remove("sig");
    let mut out = cp["v"].as_str().unwrap().as_bytes().to_vec();
    out.push(0);
    out.extend(serde_json::to_vec(&Value::Object(o)).unwrap());
    out
}

/// Build checkpoint vectors from `checkpoint.json` case `valid` that the current vectors lack:
/// each one is a valid equation under some widely used verifier but MUST be rejected under ENV-210/211.
fn propose(vectors: &str, out_vectors: &str, out_corpus: &str) {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let f: Value = serde_json::from_str(&std::fs::read_to_string(vectors).unwrap()).unwrap();
    let valid = f["cases"].as_array().unwrap().iter().find(|c| c["id"] == "valid").unwrap();
    let cp0 = valid["input"]["checkpoint"].as_object().unwrap().clone();
    let seed = blake3::hash(b"argent-webway audit/v0 test key: beta-node");
    let sk = ed25519_dalek::SigningKey::from_bytes(seed.as_bytes());
    let a = sk.to_scalar(); // the clamped and reduced secret scalar
    let pk = sk.verifying_key().to_bytes();
    assert_eq!((B * a).compress().to_bytes(), pk);
    assert_eq!(cp0["log"].as_str().unwrap(), format!("wwn:{}", b32(&pk)), "beta-node key mismatch");
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let ident = EdwardsPoint::default().compress().to_bytes();
    let mut ident_neg0 = ident;
    ident_neg0[31] |= 0x80;
    // an order-8 torsion point
    let t8 = EIGHT_TORSION[1];
    let mk = |cp: &Map<String, Value>, sig: [u8; 64]| {
        let mut c = cp.clone();
        c.insert("sig".into(), json!(URL_SAFE_NO_PAD.encode(sig)));
        c
    };
    let mut props: Vec<(String, String, Map<String, Value>, [u8; 32])> = vec![];
    let msg = cp_signing_input(&cp0);
    // P1: R = identity (small order, canonical), S = k·a: the cofactorless equation holds
    {
        let k = k_of(&ident, &pk, &msg);
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&ident);
        sig[32..].copy_from_slice(&(k * a).to_bytes());
        props.push(("small-order-r".into(), "R is the identity point (small order); [S]B = R + [k]A holds".into(), mk(&cp0, sig), pk));
    }
    // P2: R = r·B + T8 (mixed order), S = r + k·a: only the cofactored equation holds
    {
        let r = rand_scalar(&mut rng);
        let r_enc = (B * r + t8).compress().to_bytes();
        let k = k_of(&r_enc, &pk, &msg);
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&r_enc);
        sig[32..].copy_from_slice(&(r + k * a).to_bytes());
        props.push(("mixed-order-r".into(), "R has an order-8 torsion component; only [8][S]B = [8]R + [8][k]A holds".into(), mk(&cp0, sig), pk));
    }
    // P3: R = non-canonical encoding of the identity (sign bit set on x = 0), S = k·a
    {
        let k = k_of(&ident_neg0, &pk, &msg);
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&ident_neg0);
        sig[32..].copy_from_slice(&(k * a).to_bytes());
        props.push(("non-canonical-r".into(), "R is a non-canonical encoding (x = 0 with the sign bit set) of the identity".into(), mk(&cp0, sig), pk));
    }
    // P4: log = identity point, and a signature that satisfies the equation for it (R = r·B, S = r)
    {
        let mut cp = cp0.clone();
        cp.insert("log".into(), json!(format!("wwn:{}", b32(&ident))));
        let r = rand_scalar(&mut rng);
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&(B * r).compress().to_bytes());
        sig[32..].copy_from_slice(&r.to_bytes());
        props.push(("weak-key-valid-equation".into(), "log is the identity point and [S]B = R + [k]A holds (it holds for every message)".into(), mk(&cp, sig), ident));
    }
    let mut vecs = vec![];
    let mut corpus = vec![];
    for (id, desc, cp, key) in props {
        let sig: [u8; 64] = URL_SAFE_NO_PAD.decode(cp["sig"].as_str().unwrap()).unwrap().try_into().unwrap();
        let m = cp_signing_input(&cp);
        corpus.push(json!({"id": format!("proposed|{id}"), "class": "proposed", "pk": hex::encode(key),
            "msg": hex::encode(&m), "sig": hex::encode(sig), "f": features(&key, &sig, &m)}));
        vecs.push(json!({"id": id, "description": desc, "requirements": ["AUD-201", "AUD-900"],
            "input": {"checkpoint": cp}, "expected": {"result": "reject", "error": "CheckpointInvalid"}}));
    }
    std::fs::write(out_vectors, serde_json::to_string_pretty(&vecs).unwrap()).unwrap();
    std::fs::write(out_corpus, serde_json::to_string(&corpus).unwrap()).unwrap();
    eprintln!("wrote {} proposed vectors", vecs.len());
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(|s| s.as_str()) {
        Some("gen") => gen(&a[2]),
        Some("verify") => verify(&a[2], &a[3]),
        Some("propose") => propose(&a[2], &a[3], &a[4]),
        _ => eprintln!("usage: gen OUT | verify IN OUT | propose CHECKPOINT_JSON OUT_VECTORS OUT_CORPUS"),
    }
}
