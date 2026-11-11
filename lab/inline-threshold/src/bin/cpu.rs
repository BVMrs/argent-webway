//! CPU and byte cost of one envelope/v0 carrying an artefact of S bytes, inline (`Part.raw`, base64 in
//! the pinned proto3 JSON form) versus by reference (`webway-blob:blake3:` URL + bao-tree verified fetch,
//! 16 KiB chunk groups as pinned by the blob-bao-size-auth lab). Single thread, median of N reps.
//!
//! Sender (inline):  base64 encode, build JSON value, JCS(body), BLAKE3, JCS(header), Ed25519 sign, serialise.
//! Receiver (inline): parse generic JSON, JCS(body), BLAKE3, compare, JCS(header), verify, base64 decode.
//! Sender (ref):     bao outboard (= BLAKE3 root), same small envelope; provider: encode response.
//! Receiver (ref):   small envelope as above + bao decode/verify of the full response.
//!
//! Usage: cpu [reps]
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use bao_tree::io::{outboard::PreOrderMemOutboard, sync::{encode_ranges_validated, DecodeResponseIter}, BaoContentItem};
use bao_tree::{BlockSize, ChunkRanges};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey, Signature};
use rand::{RngCore, SeedableRng};
use serde_json::{json, Value};
use std::io::Cursor;
use std::time::Instant;

fn header(body_hash: &str, token: &str) -> Value {
    json!({
        "v": "webway-envelope/0",
        "from": "wwa:b3k4nq7x2m5p9r1t6v8y0z3c5e7g9j2l4n6q8s1u3w5y7a9c2e4g6",
        "to": "wwa:a2j4l6n8p1r3t5v7x9z2b4d6f8h1k3m5o7q9s2u4w6y8a1c3e5g7",
        "id": "01933b4e-7c2a-7d3e-9f10-2b3c4d5e6f70",
        "ts": "2026-11-10T09:00:00Z",
        "exp": "2026-11-10T10:00:00Z",
        "ctx": {"taskId": "01933b4e-7c2a-7d3e-9f10-aaaaaaaaaaaa", "contextId": "01933b4e-7c2a-7d3e-9f10-bbbbbbbbbbbb", "seq": "7"},
        "cap": {"access": token},
        "prov": [{"taint": {"owners": ["did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"], "unverified": false}, "contentKind": "artifact"}],
        "body_hash": body_hash,
    })
}

fn body(part: Value) -> Value {
    json!({"statusUpdate": null, "artifactUpdate": {
        "taskId": "01933b4e-7c2a-7d3e-9f10-aaaaaaaaaaaa",
        "contextId": "01933b4e-7c2a-7d3e-9f10-bbbbbbbbbbbb",
        "artifact": {"artifactId": "report-1", "name": "test-report", "parts": [part]},
        "lastChunk": true}})
}

struct Cost { send_us: f64, recv_us: f64, wire: usize, extra_us: f64 }

fn median(mut v: Vec<f64>) -> f64 { v.sort_by(|a, b| a.partial_cmp(b).unwrap()); v[v.len() / 2] }

fn sign_envelope(sk: &SigningKey, b: Value, token: &str) -> Vec<u8> {
    let jb = serde_json_canonicalizer::to_vec(&b).unwrap();
    let bh = blake3::hash(&jb).to_hex().to_string();
    let h = header(&bh, token);
    let jh = serde_json_canonicalizer::to_vec(&h).unwrap();
    let sig = sk.sign(&jh);
    let mut env = h;
    env["body"] = b;
    env["sig"] = Value::String(B64.encode(sig.to_bytes()));
    serde_json::to_vec(&env).unwrap()
}

fn verify_envelope(vk: &VerifyingKey, wire: &[u8]) -> Value {
    let mut env: Value = serde_json::from_slice(wire).unwrap();
    let obj = env.as_object_mut().unwrap();
    let b = obj.remove("body").unwrap();
    let sig = obj.remove("sig").unwrap();
    let jb = serde_json_canonicalizer::to_vec(&b).unwrap();
    let bh = blake3::hash(&jb).to_hex().to_string();
    assert_eq!(obj["body_hash"].as_str().unwrap(), bh);
    let jh = serde_json_canonicalizer::to_vec(&env).unwrap();
    let sig = Signature::from_slice(&B64.decode(sig.as_str().unwrap()).unwrap()).unwrap();
    vk.verify(&jh, &sig).unwrap();
    b
}

fn main() {
    let reps: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(31);
    let mut rng = rand::rngs::StdRng::seed_from_u64(1);
    let sk = SigningKey::generate(&mut rng);
    let vk = sk.verifying_key();
    let mut tok = vec![0u8; 420]; // ~ one Biscuit with a holder block, as in the biscuit-holder-chain lab
    rng.fill_bytes(&mut tok);
    let token = B64.encode(&tok);
    let sizes = [1usize << 10, 4 << 10, 16 << 10, 64 << 10, 256 << 10, 1 << 20, 4 << 20, 16 << 20];
    let mut big = vec![0u8; *sizes.last().unwrap()];
    rng.fill_bytes(&mut big);
    let block = BlockSize::from_chunk_log(4);
    println!("size\tmode\twire_bytes\twire_overhead_pct\tsend_us\trecv_us\tprovider_us\tsend_MBps\trecv_MBps");
    for &n in &sizes {
        let data = &big[..n];
        let r = if n >= 4 << 20 { reps.min(7) } else { reps };
        // inline
        let mut s = vec![]; let mut rv = vec![]; let mut wire = 0;
        for _ in 0..r {
            let t = Instant::now();
            let part = json!({"raw": B64.encode(data), "mediaType": "application/octet-stream", "filename": "report.bin"});
            let w = sign_envelope(&sk, body(part), &token);
            s.push(t.elapsed().as_secs_f64() * 1e6);
            let t = Instant::now();
            let b = verify_envelope(&vk, &w);
            let raw = B64.decode(b["artifactUpdate"]["artifact"]["parts"][0]["raw"].as_str().unwrap()).unwrap();
            assert_eq!(raw.len(), n);
            rv.push(t.elapsed().as_secs_f64() * 1e6);
            wire = w.len();
        }
        let c = Cost { send_us: median(s), recv_us: median(rv), wire, extra_us: 0.0 };
        row(n, "inline", &c);
        // by reference
        let mut s = vec![]; let mut rv = vec![]; let mut pv = vec![]; let mut wire = 0;
        for _ in 0..r {
            let t = Instant::now();
            let ob = PreOrderMemOutboard::create(data, block);
            let url = format!("webway-blob:blake3:{}?size={}&providers=wwn:b3k4nq7x2m5p9r1t6v8y0z3c5e7g9j2l4n6q8s1u3w5y7a9c2e4g6", ob.root.to_hex(), n);
            let part = json!({"url": url, "mediaType": "application/octet-stream", "filename": "report.bin"});
            let w = sign_envelope(&sk, body(part), &token);
            s.push(t.elapsed().as_secs_f64() * 1e6);
            let t = Instant::now();
            let mut enc = Vec::with_capacity(n + n / 128 + 64);
            enc.extend_from_slice(&(n as u64).to_le_bytes());
            encode_ranges_validated(data, &ob, &ChunkRanges::all(), &mut enc).unwrap();
            pv.push(t.elapsed().as_secs_f64() * 1e6);
            let t = Instant::now();
            let b = verify_envelope(&vk, &w);
            let u = b["artifactUpdate"]["artifact"]["parts"][0]["url"].as_str().unwrap();
            let hex = &u["webway-blob:blake3:".len().."webway-blob:blake3:".len() + 64];
            let root = blake3::Hash::from_hex(hex).unwrap();
            let mut out = Vec::with_capacity(n);
            for it in DecodeResponseIter::new(root, ob.tree, Cursor::new(&enc[8..]), &ChunkRanges::all()) {
                if let BaoContentItem::Leaf(l) = it.unwrap() { out.extend_from_slice(&l.data); }
            }
            assert_eq!(out.len(), n);
            rv.push(t.elapsed().as_secs_f64() * 1e6);
            wire = w.len() + enc.len();
        }
        let c = Cost { send_us: median(s), recv_us: median(rv), wire, extra_us: median(pv) };
        row(n, "ref", &c);
    }
}

fn row(n: usize, mode: &str, c: &Cost) {
    println!("{}\t{}\t{}\t{:.1}\t{:.1}\t{:.1}\t{:.1}\t{:.0}\t{:.0}", n, mode, c.wire,
        100.0 * (c.wire as f64 - n as f64) / n as f64, c.send_us, c.recv_us, c.extra_us,
        n as f64 / c.send_us, n as f64 / c.recv_us);
}
