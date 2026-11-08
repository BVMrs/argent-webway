//! The blob/v0 vector cases. Every case states its verdict by hand (and, where it is short, its
//! output). `build` runs the model on every case and panics if the model disagrees, so each vector
//! is checked once by construction. Outputs that are not written by hand come from the model,
//! whose tree part is checked against bao-tree (tests/bao_compat.rs).

use crate::model::{self, hash_str, EXT, MAX_SAFE};
use crate::tree;
use serde_json::{json, Value};

enum Expect {
    Accept,
    AcceptWith(Value),
    Reject(&'static str),
}
use Expect::*;

struct File {
    name: &'static str,
    kind: &'static str,
    description: &'static str,
    spec: &'static str,
    cases: Vec<Value>,
}

impl File {
    fn new(name: &'static str, kind: &'static str, spec: &'static str, description: &'static str) -> Self {
        File { name, kind, description, spec, cases: vec![] }
    }

    fn case(&mut self, id: &str, description: &str, reqs: &[&str], input: Value, expect: Expect) {
        let got = model::run(self.kind, &input).expect("kind");
        let expect = match (expect, got) {
            (Accept, Ok(out)) => json!({ "result": "accept", "output": out }),
            (AcceptWith(want), Ok(out)) => {
                assert_eq!(want, out, "{}#{id}: model output differs from the hand-written one", self.name);
                json!({ "result": "accept", "output": out })
            }
            (Reject(want), Err(e)) => {
                assert_eq!(want, e, "{}#{id}: model rejects with another error", self.name);
                json!({ "result": "reject", "error": e })
            }
            (Reject(want), Ok(out)) => panic!("{}#{id}: model accepts ({out}), case says {want}", self.name),
            (_, Err(e)) => panic!("{}#{id}: model rejects with {e}, case says accept", self.name),
        };
        assert!(
            !self.cases.iter().any(|c| c["id"] == id),
            "{}: duplicate case id {id}",
            self.name
        );
        self.cases.push(json!({
            "id": id, "description": description, "requirements": reqs, "input": input, "expect": expect
        }));
    }

    fn render(self) -> (&'static str, Value) {
        (
            self.name,
            json!({
                "$schema": "../vector.schema.json",
                "format": "webway-vectors/v0",
                "kind": self.kind,
                "description": self.description,
                "spec": self.spec,
                "cases": self.cases,
            }),
        )
    }
}

// ---------- fixed test identifiers (syntax only: these vectors do not check signatures) ----------

fn b32(bytes: &[u8]) -> String {
    const A: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let (mut out, mut acc, mut bits) = (String::new(), 0u32, 0u32);
    for &b in bytes {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            out.push(A[((acc >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(A[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn b58(bytes: &[u8]) -> String {
    const A: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut digits: Vec<u8> = vec![];
    for &b in bytes {
        let mut carry = b as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let zeros = bytes.iter().take_while(|&&b| b == 0).count();
    "1".repeat(zeros) + &digits.iter().rev().map(|&d| A[d as usize] as char).collect::<String>()
}

fn key(name: &str) -> [u8; 32] {
    *blake3::hash(format!("argent-webway blob/v0 test key {name}").as_bytes()).as_bytes()
}
fn node(name: &str) -> String {
    format!("wwn:{}", b32(&key(&format!("node {name}"))))
}
fn agent(name: &str) -> String {
    format!("wwa:{}", b32(&key(&format!("agent {name}"))))
}
fn owner(name: &str) -> String {
    let mut v = vec![0xed, 0x01];
    v.extend(key(&format!("owner {name}")));
    format!("did:key:z{}", b58(&v))
}
fn provider(n: &str, a: &str) -> String {
    format!("{}/{}", node(n), agent(a))
}
fn h(n: u64) -> String {
    hash_str(&tree::hash(&tree::pattern(n)))
}
fn url(hash: &str, size: u64, providers: &[String]) -> String {
    if providers.is_empty() {
        format!("webway-blob:{hash}?size={size}")
    } else {
        format!("webway-blob:{hash}?size={size}&providers={}", providers.join(","))
    }
}

// ---------- files ----------

fn hash_file() -> File {
    let mut f = File::new(
        "hash.json",
        "blob/hash",
        "ext/blob.md#3-content-and-hash",
        "Blob hash. Input {\"data\": {\"pattern\": n} | {\"hex\": string}}, where pattern n is the n bytes i mod 251 \
         (the input of the official BLAKE3 test vectors). Output {\"hash\": \"blake3:<hex>\", \"size\", \"blocks\"}.",
    );
    for n in [0u64, 1, 1023, 1024, 1025, 16383, 16384, 16385, 32768, 32769, 49152, 65536, 65537, 102_400, 1 << 20, (1 << 20) + 1] {
        f.case(&format!("pattern-{n}"), &format!("{n} bytes of the pattern"), &["BLOB-001"], json!({ "data": { "pattern": n } }), Accept);
    }
    f.case(
        "abc",
        "The three bytes \"abc\"",
        &["BLOB-001"],
        json!({ "data": { "hex": "616263" } }),
        AcceptWith(json!({ "hash": "blake3:6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85", "size": 3, "blocks": 1 })),
    );
    f.case(
        "empty",
        "The empty blob has one empty block",
        &["BLOB-001"],
        json!({ "data": { "hex": "" } }),
        AcceptWith(json!({ "hash": "blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", "size": 0, "blocks": 1 })),
    );
    f
}

fn ref_file() -> File {
    let mut f = File::new(
        "ref.json",
        "blob/ref",
        "ext/blob.md#4-references",
        "Parse a blob reference URL. Input {\"url\": string}. Output {\"hash\", \"size\", \"providers\": [\"wwn:…/wwa:…\"]} \
         (providers in URL order, [] if absent). Reject BlobRefInvalid.",
    );
    let hh = h(100_000);
    let p1 = provider("beta", "tester");
    let p2 = provider("gamma", "mirror");
    let ps: Vec<String> = ["a", "b", "c", "d", "e"].iter().map(|n| provider(n, n)).collect();
    let r = &["BLOB-010"];
    let ok = |hash: &str, size: u64, p: &[String]| json!({ "hash": hash, "size": size, "providers": p });
    f.case("no-providers", "Size only", r, json!({ "url": url(&hh, 100_000, &[]) }), AcceptWith(ok(&hh, 100_000, &[])));
    f.case("one-provider", "One provider", r, json!({ "url": url(&hh, 100_000, &[p1.clone()]) }), AcceptWith(ok(&hh, 100_000, &[p1.clone()])));
    f.case(
        "four-providers",
        "MAX_PROVIDERS providers, order kept",
        r,
        json!({ "url": url(&hh, 100_000, &ps[..4]) }),
        AcceptWith(ok(&hh, 100_000, &ps[..4])),
    );
    f.case(
        "params-reordered",
        "Parameters in any order",
        r,
        json!({ "url": format!("webway-blob:{hh}?providers={p1},{p2}&size=100000") }),
        AcceptWith(ok(&hh, 100_000, &[p1.clone(), p2.clone()])),
    );
    f.case(
        "unknown-param",
        "An unknown parameter is ignored",
        r,
        json!({ "url": format!("webway-blob:{hh}?size=100000&x-hint=fast") }),
        AcceptWith(ok(&hh, 100_000, &[])),
    );
    f.case("size-zero", "The empty blob", r, json!({ "url": url(&h(0), 0, &[]) }), AcceptWith(ok(&h(0), 0, &[])));
    f.case("size-max", "Largest size, 2^53 - 1", r, json!({ "url": url(&hh, MAX_SAFE, &[]) }), AcceptWith(ok(&hh, MAX_SAFE, &[])));
    let rej = |f: &mut File, id: &str, d: &str, u: String| f.case(id, d, &["BLOB-010"], json!({ "url": u }), Reject("BlobRefInvalid"));
    rej(&mut f, "hash-uppercase", "Hash hex must be lowercase", format!("webway-blob:{}?size=1", hh.to_uppercase().replace("BLAKE3", "blake3")));
    rej(&mut f, "hash-short", "63 hex digits", format!("webway-blob:{}?size=1", &hh[..hh.len() - 1]));
    rej(&mut f, "hash-algorithm", "Unknown hash algorithm", format!("webway-blob:sha256:{}?size=1", &hh[7..]));
    rej(&mut f, "hash-0x", "0x prefix", format!("webway-blob:blake3:0x{}?size=1", &hh[9..]));
    rej(&mut f, "scheme-case", "Scheme is lowercase", format!("Webway-Blob:{hh}?size=1"));
    rej(&mut f, "no-query", "No size", format!("webway-blob:{hh}"));
    rej(&mut f, "no-size", "Providers but no size", format!("webway-blob:{hh}?providers={p1}"));
    rej(&mut f, "size-leading-zero", "Non-canonical decimal", format!("webway-blob:{hh}?size=0100"));
    rej(&mut f, "size-too-big", "2^53", format!("webway-blob:{hh}?size=9007199254740992"));
    rej(&mut f, "size-negative", "Sign", format!("webway-blob:{hh}?size=-1"));
    rej(&mut f, "size-plus", "Sign", format!("webway-blob:{hh}?size=+1"));
    rej(&mut f, "size-percent", "Percent-encoding in a known parameter", format!("webway-blob:{hh}?size=%31"));
    rej(&mut f, "size-twice", "Duplicate parameter", format!("webway-blob:{hh}?size=1&size=1"));
    rej(&mut f, "empty-param", "Empty parameter", format!("webway-blob:{hh}?size=1&"));
    rej(&mut f, "param-no-value", "Parameter without =", format!("webway-blob:{hh}?size=1&flag"));
    rej(&mut f, "fragment", "No fragment", format!("webway-blob:{hh}?size=1#x"));
    rej(&mut f, "five-providers", "More than MAX_PROVIDERS", url(&hh, 1, &ps));
    rej(&mut f, "provider-twice", "Duplicate provider", url(&hh, 1, &[p1.clone(), p1.clone()]));
    rej(&mut f, "provider-node-only", "A provider names node and agent", url(&hh, 1, &[node("beta")]));
    rej(&mut f, "provider-swapped", "Node first, then agent", url(&hh, 1, &[format!("{}/{}", agent("tester"), node("beta"))]));
    rej(&mut f, "provider-uppercase", "Base32 is lowercase", url(&hh, 1, &[p1.to_uppercase().replace("WWN:", "wwn:").replace("WWA:", "wwa:")]));
    let mut bad_bits = p1.clone();
    let last = bad_bits.pop().unwrap();
    bad_bits.push(if last == 'a' { 'b' } else { 'r' });
    rej(&mut f, "provider-trailing-bits", "Base32 with non-zero unused bits", url(&hh, 1, &[bad_bits]));
    rej(&mut f, "providers-empty", "Empty providers list", format!("webway-blob:{hh}?size=1&providers="));
    f
}

fn ranges_file() -> File {
    let mut f = File::new(
        "ranges.json",
        "blob/ranges",
        "ext/blob.md#53-ranges",
        "Validate the ranges of a Fetch request and compute its effective ranges for a blob of the given size. \
         Input {\"ranges\": any JSON, \"size\": n}. Output {\"effective\": [[start, end], …]}. Reject InvalidParamsError.",
    );
    let s = 100_000; // 7 blocks
    let a = &["BLOB-023"];
    f.case("one", "One block", a, json!({ "ranges": [[0, 1]], "size": s }), AcceptWith(json!({ "effective": [[0, 1]] })));
    f.case("clamped", "End past the last block is clamped", a, json!({ "ranges": [[2, 1000]], "size": s }), AcceptWith(json!({ "effective": [[2, 7]] })));
    f.case("past-end", "A range wholly past the end selects the last block", a, json!({ "ranges": [[10, 11]], "size": s }), AcceptWith(json!({ "effective": [[6, 7]] })));
    f.case("past-end-merge", "The last block merges with a range that ends next to it", a, json!({ "ranges": [[1, 2], [4, 6], [9, 12]], "size": s }), AcceptWith(json!({ "effective": [[1, 2], [4, 7]] })));
    f.case("all", "[0, 2^53 - 1] is the whole blob", a, json!({ "ranges": [[0, MAX_SAFE]], "size": s }), AcceptWith(json!({ "effective": [[0, 7]] })));
    f.case("empty-blob", "The empty blob has block 0", a, json!({ "ranges": [[0, 1]], "size": 0 }), AcceptWith(json!({ "effective": [[0, 1]] })));
    f.case("empty-blob-past-end", "Past the end of the empty blob", a, json!({ "ranges": [[5, 6]], "size": 0 }), AcceptWith(json!({ "effective": [[0, 1]] })));
    let many: Vec<Value> = (0..64u64).map(|i| json!([2 * i, 2 * i + 1])).collect();
    f.case("max-ranges", "MAX_RANGES ranges", &["BLOB-031"], json!({ "ranges": many, "size": 1 << 30 }), Accept);
    let r = &["BLOB-031"];
    let rej = |f: &mut File, id: &str, d: &str, v: Value| f.case(id, d, &["BLOB-031"], json!({ "ranges": v, "size": s }), Reject("InvalidParamsError"));
    rej(&mut f, "empty", "At least one range", json!([]));
    rej(&mut f, "not-array", "An object", json!({ "start": 0 }));
    rej(&mut f, "flat", "Pairs, not a flat list", json!([0, 1]));
    rej(&mut f, "empty-range", "start = end", json!([[1, 1]]));
    rej(&mut f, "reversed", "start > end", json!([[2, 1]]));
    rej(&mut f, "overlap", "Overlapping ranges", json!([[0, 2], [1, 3]]));
    rej(&mut f, "adjacent", "Adjacent ranges must be merged", json!([[0, 1], [1, 2]]));
    rej(&mut f, "unsorted", "Ranges in ascending order", json!([[3, 4], [0, 1]]));
    rej(&mut f, "negative", "Negative start", json!([[-1, 1]]));
    rej(&mut f, "fraction", "Not an integer", json!([[0.5, 1]]));
    rej(&mut f, "triple", "Three numbers", json!([[0, 1, 2]]));
    rej(&mut f, "string", "Numbers as strings", json!([["0", "1"]]));
    rej(&mut f, "too-big", "End above 2^53 - 1", json!([[0, 9007199254740992u64]]));
    let too_many: Vec<Value> = (0..65u64).map(|i| json!([2 * i, 2 * i + 1])).collect();
    rej(&mut f, "too-many", "MAX_RANGES + 1 ranges", json!(too_many));
    let _ = r;
    f
}

fn encode_file() -> File {
    let mut f = File::new(
        "encode.json",
        "blob/encode",
        "ext/blob.md#52-encoding",
        "Encode the effective ranges of a blob. Input {\"data\": {\"pattern\": n} | {\"hex\"}, \"ranges\"}. Output \
         {\"hash\", \"ranges\" (effective), \"length\", \"encodingHash\" (BLAKE3 of the encoding, blake3:<hex>), \"hex\" \
         (the encoding itself, only when it is at most 512 bytes)}. Generated by the reference model and checked \
         against bao-tree 0.17 with 16 KiB chunk groups.",
    );
    let r = &["BLOB-020"];
    let cases: &[(&str, &str, u64, Value)] = &[
        ("empty", "Empty blob: no parents, an empty block", 0, json!([[0, 1]])),
        ("small", "Single block blob: the bytes only", 300, json!([[0, 1]])),
        ("one-block-full", "Exactly one block", 16384, json!([[0, 1]])),
        ("two-blocks-second", "Second block of two: one pair, then 1 byte", 16385, json!([[1, 2]])),
        ("two-blocks-all", "Both blocks", 16385, json!([[0, 2]])),
        ("seven-all", "Whole 7-block blob", 100_000, json!([[0, 7]])),
        ("seven-middle", "Block 3 of 7", 100_000, json!([[3, 4]])),
        ("seven-ends", "First and last block", 100_000, json!([[0, 1], [6, 7]])),
        ("seven-last-via-past-end", "Last block requested by a range past the end", 100_000, json!([[1000, 1001]])),
        ("mib-plus-one-last", "Last block of a 65-block blob (1 MiB + 1 byte)", (1 << 20) + 1, json!([[64, 65]])),
        ("mib-plus-one-scattered", "Scattered ranges of a 65-block blob", (1 << 20) + 1, json!([[10, 11], [40, 42]])),
    ];
    for (id, d, n, ranges) in cases {
        f.case(id, d, r, json!({ "data": { "pattern": n }, "ranges": ranges }), Accept);
    }
    f
}

fn verify_file() -> File {
    let mut f = File::new(
        "verify.json",
        "blob/verify",
        "ext/blob.md#54-verification",
        "Verify a Fetch reply stream. Input {\"hash\", \"size\" (from the reply), \"ranges\" (the reply's ranges), \
         \"data\": {\"pattern\": n}, \"mutate\"?: {\"flip\": byte offset} | {\"truncate\": length} | {\"append\": hex}}. \
         The stream is the honest encoding of data for ranges, then mutate applied to it. Output {\"verified\": ranges, \
         \"missing\": ranges, \"complete\": bool}. A stream that ends early is accepted with what was verified. \
         Reject BlobCorrupt (data does not match) or ProtocolError (bytes after the end).",
    );
    let s = 100_000u64;
    let hh = h(s);
    let all = json!([[0, 7]]);
    let v = |hash: &str, size: u64, ranges: &Value, n: u64, m: Value| {
        let mut x = json!({ "hash": hash, "size": size, "ranges": ranges, "data": { "pattern": n } });
        if !m.is_null() {
            x["mutate"] = m;
        }
        x
    };
    let out = |ver: Value, mis: Value, c: bool| json!({ "verified": ver, "missing": mis, "complete": c });
    f.case("whole", "Whole blob", &["BLOB-021"], v(&hh, s, &all, s, Value::Null), AcceptWith(out(json!([[0, 7]]), json!([]), true)));
    f.case("scattered", "Two ranges", &["BLOB-021"], v(&hh, s, &json!([[1, 2], [4, 6]]), s, Value::Null), AcceptWith(out(json!([[1, 2], [4, 6]]), json!([]), true)));
    f.case("empty-blob", "Empty blob, empty stream", &["BLOB-021"], v(&h(0), 0, &json!([[0, 1]]), 0, Value::Null), AcceptWith(out(json!([[0, 1]]), json!([]), true)));
    f.case("single-block", "Blob of one block", &["BLOB-021"], v(&h(300), 300, &json!([[0, 1]]), 300, Value::Null), AcceptWith(out(json!([[0, 1]]), json!([]), true)));
    f.case("last-block-proves-size", "The last block alone verifies, which proves the size", &["BLOB-024"], v(&hh, s, &json!([[6, 7]]), s, Value::Null), AcceptWith(out(json!([[6, 7]]), json!([]), true)));
    // Encoding of [[0,7]] for 100000 bytes: root pair, pair 0..4, pair 0..2, block 0, block 1, …
    let cut = 64 * 3 + 16384 * 2 + 100;
    f.case(
        "cut",
        "Stream ends inside block 2: blocks 0 and 1 are kept",
        &["BLOB-021", "BLOB-040"],
        v(&hh, s, &all, s, json!({ "truncate": cut })),
        AcceptWith(out(json!([[0, 2]]), json!([[2, 7]]), false)),
    );
    f.case("cut-empty", "Nothing arrived", &["BLOB-040"], v(&hh, s, &all, s, json!({ "truncate": 0 })), AcceptWith(out(json!([]), json!([[0, 7]]), false)));
    f.case(
        "resume",
        "The missing ranges of the cut case, fetched again (possibly from another provider)",
        &["BLOB-040"],
        v(&hh, s, &json!([[2, 7]]), s, Value::Null),
        AcceptWith(out(json!([[2, 7]]), json!([]), true)),
    );
    let c = &["BLOB-021"];
    f.case("flip-root-pair", "First parent pair altered", c, v(&hh, s, &all, s, json!({ "flip": 0 })), Reject("BlobCorrupt"));
    f.case("flip-inner-pair", "Inner parent pair altered", c, v(&hh, s, &all, s, json!({ "flip": 64 + 40 })), Reject("BlobCorrupt"));
    f.case("flip-block", "Data of block 1 altered", c, v(&hh, s, &all, s, json!({ "flip": 64 * 3 + 16384 + 5 })), Reject("BlobCorrupt"));
    let len = tree::encoded_len(s, &vec![(0, 7)]);
    f.case("flip-last-byte", "Last byte altered", c, v(&hh, s, &all, s, json!({ "flip": len - 1 })), Reject("BlobCorrupt"));
    f.case("wrong-hash", "Reply for another blob", c, v(&h(s + 1), s, &all, s, Value::Null), Reject("BlobCorrupt"));
    f.case("wrong-hash-single-block", "Single-block blob, other hash", c, v(&h(301), 300, &json!([[0, 1]]), 300, Value::Null), Reject("BlobCorrupt"));
    f.case("trailing", "Bytes after the end", &["BLOB-022"], v(&hh, s, &all, s, json!({ "append": "00" })), Reject("ProtocolError"));
    let z = &["BLOB-024"];
    f.case("size-smaller", "Reply claims 99000 bytes (same block count): the last block fails", z, v(&hh, 99_000, &all, s, Value::Null), Reject("BlobCorrupt"));
    f.case("size-larger-more-blocks", "Reply claims 140000 bytes (9 blocks): the tree shape breaks", z, v(&hh, 140_000, &json!([[0, 9]]), s, Value::Null), Reject("BlobCorrupt"));
    f.case(
        "size-larger-same-blocks",
        "Reply claims 110000 bytes (same 7 blocks): blocks 0-5 verify, block 6 can never complete",
        z,
        v(&hh, 110_000, &all, s, Value::Null),
        AcceptWith(out(json!([[0, 6]]), json!([[6, 7]]), false)),
    );
    f.case(
        "size-single-block",
        "Single-block blob, reply claims one byte more: the block never completes",
        z,
        v(&h(300), 301, &json!([[0, 1]]), 300, Value::Null),
        AcceptWith(out(json!([]), json!([[0, 1]]), false)),
    );
    f
}

fn fetch_file() -> File {
    let mut f = File::new(
        "fetch.json",
        "blob/fetch",
        "ext/blob.md#73-provider-procedure",
        "Provider decision for one Fetch whose envelope has passed envelope/v0 verification. Input {\"provider\": \
         {\"node\", \"agents\"}, \"connectionPeer\": wwn, \"bindings\": {wwa: wwn} (agent-certs the provider holds), \
         \"envelope\": {\"from\", \"to\", \"ts\", \"exp\", \"cap\"?: {\"capability\"?}, \"body\"}, \"authorization\": \
         \"allow\" or the capability/v0 error for this request, \"store\": {hash: {\"size\", \"blocks\"?}} (absent \
         blocks = whole blob)}. Output {\"hash\", \"size\", \"ranges\"} of the reply. Identifiers are syntactically \
         valid test values, not real keys.",
    );
    let (h1, h2, h3, h4) = (h(100_000), h(300_000), h(300_001), h(5));
    let pn = node("provider");
    let pa = agent("provider");
    let fnode = node("fetcher");
    let fa = agent("fetcher");
    let store = json!({
        h1.clone(): { "size": 100_000 },
        h2.clone(): { "size": 300_000, "blocks": [[0, 5]] },
        h3.clone(): { "size": 300_001, "blocks": [[0, 3], [18, 19]] },
    });
    let base = |hash: &str, body: Value, cap: Option<String>, authz: &str| {
        let mut env = json!({
            "from": fa, "to": pa, "ts": "2026-11-07T12:00:00Z", "exp": "2026-11-07T12:05:00Z", "body": body
        });
        if let Some(c) = cap {
            env["cap"] = json!({ "capability": c });
        }
        let _ = hash;
        json!({
            "provider": { "node": pn, "agents": [pa] },
            "connectionPeer": fnode,
            "bindings": { fa.clone(): fnode, agent("other"): node("other") },
            "envelope": env,
            "authorization": authz,
            "store": store,
        })
    };
    let cap = |hash: &str| Some(format!("blob:{hash}#read"));
    let req = |hash: &str, ranges: Option<Value>| match ranges {
        Some(r) => json!({ "hash": hash, "ranges": r }),
        None => json!({ "hash": hash }),
    };
    let ok = |hash: &str, size: u64, r: Value| json!({ "hash": hash, "size": size, "ranges": r });
    let a = &["BLOB-034"];
    f.case("whole", "No ranges: the whole blob", a, base(&h1, req(&h1, None), cap(&h1), "allow"), AcceptWith(ok(&h1, 100_000, json!([[0, 7]]))));
    f.case("some", "Requested ranges", a, base(&h1, req(&h1, Some(json!([[2, 4]]))), cap(&h1), "allow"), AcceptWith(ok(&h1, 100_000, json!([[2, 4]]))));
    f.case("past-end", "Clamped to the blob", &["BLOB-034", "BLOB-023"], base(&h1, req(&h1, Some(json!([[5, 100]]))), cap(&h1), "allow"), AcceptWith(ok(&h1, 100_000, json!([[5, 7]]))));
    f.case("size-probe", "A range past the end gets the last block", &["BLOB-034", "BLOB-023"], base(&h1, req(&h1, Some(json!([[1000, 1001]]))), cap(&h1), "allow"), AcceptWith(ok(&h1, 100_000, json!([[6, 7]]))));
    f.case(
        "unknown-body-member",
        "Unknown body members are ignored",
        &["BLOB-031"],
        base(&h1, json!({ "hash": h1, "ranges": [[0, 1]], "x-priority": 3 }), cap(&h1), "allow"),
        AcceptWith(ok(&h1, 100_000, json!([[0, 1]]))),
    );
    f.case("ttl-max", "exp - ts = MAX_FETCH_TTL", &["BLOB-031"], {
        let mut x = base(&h1, req(&h1, None), cap(&h1), "allow");
        x["envelope"]["exp"] = json!("2026-11-07T12:10:00Z");
        x
    }, Accept);
    let p = &["BLOB-042"];
    f.case("partial-held", "Partial copy with its last block: sends what it has", p, base(&h3, req(&h3, None), cap(&h3), "allow"), AcceptWith(ok(&h3, 300_001, json!([[0, 3], [18, 19]]))));
    f.case("partial-held-none-requested", "Partial copy, none of the requested blocks: empty reply", p, base(&h3, req(&h3, Some(json!([[5, 6]]))), cap(&h3), "allow"), AcceptWith(ok(&h3, 300_001, json!([]))));
    f.case("partial-without-last-block", "Partial copy without its last block is not served", p, base(&h2, req(&h2, Some(json!([[0, 1]]))), cap(&h2), "allow"), Reject("BlobNotFound"));
    f.case("not-held", "Authorised, not held", a, base(&h4, req(&h4, None), cap(&h4), "allow"), Reject("BlobNotFound"));
    let o = &["BLOB-033"];
    f.case("denied-held", "Denied, blob held", o, base(&h1, req(&h1, None), cap(&h1), "CapabilityDenied"), Reject("CapabilityDenied"));
    f.case("denied-not-held", "Denied, blob not held: same answer (no existence oracle)", o, base(&h4, req(&h4, None), cap(&h4), "CapabilityDenied"), Reject("CapabilityDenied"));
    f.case("missing-not-held", "No token, blob not held", o, base(&h4, req(&h4, None), cap(&h4), "CapabilityMissing"), Reject("CapabilityMissing"));
    f.case("missing-held", "No token, blob held", o, base(&h1, req(&h1, None), cap(&h1), "CapabilityMissing"), Reject("CapabilityMissing"));
    f.case("invalid", "Token does not verify", o, base(&h1, req(&h1, None), cap(&h1), "CapabilityInvalid"), Reject("CapabilityInvalid"));
    f.case("revoked", "Token revoked", o, base(&h1, req(&h1, None), cap(&h1), "CapabilityRevoked"), Reject("CapabilityRevoked"));
    f.case("revocation-unknown", "Long-lived token without a fresh revocation list", o, base(&h1, req(&h1, None), cap(&h1), "RevocationStatusUnavailable"), Reject("RevocationStatusUnavailable"));
    f.case("no-capability", "cap.capability absent", &["BLOB-031", "BLOB-033"], base(&h1, req(&h1, None), None, "allow"), Reject("CapabilityMissing"));
    f.case("capability-other-blob", "Capability names another blob", &["BLOB-031", "BLOB-033"], base(&h1, req(&h1, None), cap(&h4), "allow"), Reject("CapabilityDenied"));
    f.case("capability-other-op", "Capability is not #read", &["BLOB-031", "BLOB-033"], base(&h1, req(&h1, None), Some(format!("blob:{h1}#write")), "allow"), Reject("CapabilityDenied"));
    f.case("capability-bare-hex", "Capability without the blake3: prefix", &["BLOB-031", "BLOB-033"], base(&h1, req(&h1, None), Some(format!("blob:{}#read", &h1[7..])), "allow"), Reject("CapabilityDenied"));
    let i = &["BLOB-032"];
    f.case("not-hosted", "to is not an agent of this node", i, {
        let mut x = base(&h1, req(&h1, None), cap(&h1), "allow");
        x["envelope"]["to"] = json!(agent("elsewhere"));
        x
    }, Reject("RecipientUnknown"));
    f.case("relayed", "from is bound to another node than the connection's peer", i, {
        let mut x = base(&h1, req(&h1, None), cap(&h1), "allow");
        x["envelope"]["from"] = json!(agent("other"));
        x
    }, Reject("IdentityUntrusted"));
    f.case("unbound", "from has no agent-cert at the provider", i, {
        let mut x = base(&h1, req(&h1, None), cap(&h1), "allow");
        x["envelope"]["from"] = json!(agent("stranger"));
        x
    }, Reject("IdentityUntrusted"));
    let b = &["BLOB-031"];
    f.case("ttl-too-long", "exp - ts above MAX_FETCH_TTL", b, {
        let mut x = base(&h1, req(&h1, None), cap(&h1), "allow");
        x["envelope"]["exp"] = json!("2026-11-07T12:10:01Z");
        x
    }, Reject("EnvelopeInvalid"));
    f.case("hash-missing", "Body without hash", b, base(&h1, json!({ "ranges": [[0, 1]] }), cap(&h1), "allow"), Reject("InvalidParamsError"));
    f.case("hash-uppercase", "Hash not in canonical form", b, base(&h1, json!({ "hash": h1.to_uppercase() }), cap(&h1), "allow"), Reject("InvalidParamsError"));
    f.case("ranges-adjacent", "Non-canonical ranges", b, base(&h1, req(&h1, Some(json!([[0, 1], [1, 2]]))), cap(&h1), "allow"), Reject("InvalidParamsError"));
    f.case("ranges-empty", "Empty ranges", b, base(&h1, req(&h1, Some(json!([]))), cap(&h1), "allow"), Reject("InvalidParamsError"));
    f.case(
        "params-before-authz",
        "Invalid body and denied token: the body check comes first",
        &["BLOB-031", "BLOB-033"],
        base(&h1, req(&h1, Some(json!([[2, 1]]))), cap(&h1), "CapabilityDenied"),
        Reject("InvalidParamsError"),
    );
    f
}

fn provenance_file() -> File {
    let mut f = File::new(
        "provenance.json",
        "blob/provenance",
        "ext/blob.md#9-provenance-of-fetched-content",
        "Taint and trust of fetched content. Input {\"receiverOwner\", \"reference\": {\"senderOwner\" (verified owner \
         of the envelope that carried the referencing Part), \"taint\"}, \"providerOwner\" (owner of the node the bytes \
         came from), \"otherReferences\": [taint] (earlier Parts that referenced the same hash)}. Output {\"trust\", \
         \"taint\"}. Reject EnvelopeInvalid for a missing or malformed taint.",
    );
    let (a, b, c) = (owner("A"), owner("B"), owner("C"));
    let x = |sender: &str, owners: Vec<&String>, unv: bool, prov: &str, other: Value| {
        json!({
            "receiverOwner": a,
            "reference": { "senderOwner": sender, "taint": { "owners": owners, "unverified": unv } },
            "providerOwner": prov,
            "otherReferences": other,
        })
    };
    let out = |t: &str, owners: Vec<&String>, unv: bool| json!({ "trust": t, "taint": { "owners": owners, "unverified": unv } });
    let r = &["BLOB-050"];
    f.case("foreign", "Artefact from owner B, fetched from B", r, x(&b, vec![&b], false, &b, json!([])), AcceptWith(out("foreign", vec![&b], false)));
    f.case("same-owner", "Artefact from another node of A", r, x(&a, vec![&a], false, &a, json!([])), AcceptWith(out("same-owner", vec![&a], false)));
    f.case("same-owner-forwarding", "A node forwards B's content to A: stays foreign", r, x(&a, vec![&a, &b], false, &a, json!([])), AcceptWith(out("foreign", vec![&a, &b], false)));
    f.case("unverified", "Content that entered through an HTTP edge", r, x(&a, vec![&a], true, &a, json!([])), AcceptWith(out("unverified-origin", vec![&a], true)));
    f.case("foreign-claims-receiver", "B claims taint.owners = [A]: clamped to foreign", r, x(&b, vec![&a], false, &b, json!([])), AcceptWith(out("foreign", vec![&a], false)));
    f.case("third-owner-provider", "Bytes served by C's node: C is not added and does not change trust", r, x(&b, vec![&b], false, &c, json!([])), AcceptWith(out("foreign", vec![&b], false)));
    f.case("own-cache", "Bytes already in the receiver's own store: still foreign", r, x(&b, vec![&b], false, &a, json!([])), AcceptWith(out("foreign", vec![&b], false)));
    let d = &["BLOB-051"];
    f.case(
        "dedup-no-raise",
        "Same hash earlier referenced as same-owner content: a foreign reference stays foreign",
        d,
        x(&b, vec![&b], false, &a, json!([{ "owners": [a], "unverified": false }])),
        AcceptWith(out("foreign", vec![&b], false)),
    );
    f.case(
        "dedup-no-lower",
        "Same hash earlier referenced as unverified content: this reference keeps its own taint",
        d,
        x(&a, vec![&a], false, &a, json!([{ "owners": [b], "unverified": true }])),
        AcceptWith(out("same-owner", vec![&a], false)),
    );
    f.case("missing-taint", "Referencing Part without taint", r, json!({
        "receiverOwner": a, "reference": { "senderOwner": b }, "providerOwner": b, "otherReferences": []
    }), Reject("EnvelopeInvalid"));
    f.case("empty-owners", "taint.owners empty", r, x(&b, vec![], false, &b, json!([])), Reject("EnvelopeInvalid"));
    f
}

fn providers_file() -> File {
    let mut f = File::new(
        "providers.json",
        "blob/providers",
        "ext/blob.md#72-choosing-providers",
        "Which providers listed in a reference a fetcher may contact. Input {\"fetcherOwner\", \"pins\": [owner], \
         \"reference\": url, \"agentCerts\": {wwa: {\"owner\", \"node\"}} (verified agent-certs the fetcher holds), \
         \"grants\": [\"wwn:…/wwa:…\"] (providers for which the fetching agent holds a grant)}. Output {\"contact\": \
         [provider]} in reference order. Reject BlobRefInvalid.",
    );
    let (a, b, c) = (owner("A"), owner("B"), owner("C"));
    let hh = h(100_000);
    let pb = provider("beta", "tester");
    let pc = provider("gamma", "mirror");
    let pa = provider("alpha2", "cache");
    let certs = json!({
        agent("tester"): { "owner": b, "node": node("beta") },
        agent("mirror"): { "owner": c, "node": node("gamma") },
        agent("cache"): { "owner": a, "node": node("alpha2") },
    });
    let x = |pins: Vec<&String>, ps: Vec<&String>, grants: Vec<&String>, certs: &Value| {
        let ps: Vec<String> = ps.into_iter().cloned().collect();
        json!({ "fetcherOwner": a, "pins": pins, "reference": url(&hh, 100_000, &ps), "agentCerts": certs, "grants": grants })
    };
    let r = &["BLOB-041"];
    f.case("granted-pinned", "Provider of a pinned owner with a grant", r, x(vec![&b], vec![&pb], vec![&pb], &certs), AcceptWith(json!({ "contact": [pb] })));
    f.case("no-grant", "Provider without a grant is skipped", r, x(vec![&b], vec![&pb], vec![], &certs), AcceptWith(json!({ "contact": [] })));
    f.case("unpinned-owner", "Granted provider of an owner the fetcher has not pinned is never contacted", r, x(vec![&b], vec![&pc, &pb], vec![&pc, &pb], &certs), AcceptWith(json!({ "contact": [pb] })));
    f.case("pinned-third-owner", "Third owner, pinned and granted", r, x(vec![&b, &c], vec![&pb, &pc], vec![&pb, &pc], &certs), AcceptWith(json!({ "contact": [pb, pc] })));
    f.case("own-owner", "Provider of the fetcher's own owner with a grant", r, x(vec![&b], vec![&pa, &pb], vec![&pa, &pb], &certs), AcceptWith(json!({ "contact": [pa, pb] })));
    f.case("order-kept", "Reference order is kept", r, x(vec![&b, &c], vec![&pc, &pb], vec![&pb, &pc], &certs), AcceptWith(json!({ "contact": [pc, pb] })));
    let mut moved = certs.clone();
    moved[agent("tester")]["node"] = json!(node("elsewhere"));
    f.case("agent-on-other-node", "The agent is certified to another node than the one listed", r, x(vec![&b], vec![&pb], vec![&pb], &moved), AcceptWith(json!({ "contact": [] })));
    f.case("no-cert", "No verified agent-cert for the provider's agent", r, x(vec![&b], vec![&pb], vec![&pb], &json!({})), AcceptWith(json!({ "contact": [] })));
    f.case("bad-reference", "Malformed reference", &["BLOB-010"], json!({
        "fetcherOwner": a, "pins": [b], "reference": format!("webway-blob:{hh}?size=01"), "agentCerts": certs, "grants": []
    }), Reject("BlobRefInvalid"));
    f
}

pub fn all() -> Vec<(&'static str, Value)> {
    let _ = EXT;
    vec![
        hash_file().render(),
        ref_file().render(),
        ranges_file().render(),
        encode_file().render(),
        verify_file().render(),
        fetch_file().render(),
        provenance_file().render(),
        providers_file().render(),
    ]
}
