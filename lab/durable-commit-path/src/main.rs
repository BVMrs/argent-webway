//! Lab: durable acceptance commit path of a webway node.
//!
//! A single committer thread owns the store, the audit log head (index, prev, Merkle frontier) and the receipt
//! signing key. Every request is turned into one `envelope.received` audit entry (+ leaf hash + signed receipt);
//! an accepted request also writes dedupe (with stored response), task, first event and the `max_calls` counter.
//! A reply ("ack") is released only after the transaction holding all of it is durable (AUD-500, ENV-503).
//!
//! Subcommands:
//!   fsync  <dir>                              raw write+fdatasync latency by size
//!   cap    <dir> <backend> <mode> <conc> <secs>   closed-loop capacity: conc clients sending accepted requests
//!   flood  <dir> <backend> <policy> <stub> <bw_mbit> <peers> <secs>   honest 200/s open loop + adversary flood
//!
//! backends: redb | sqlite (WAL, synchronous=FULL) | sqlite-normal (WAL, NORMAL: not power-loss durable) |
//!           fjall (batch + SyncAll) | rawlog (append file + fdatasync, no index: lower bound)
//! modes:    serial (one txn per request) | group (drain queue, one txn per batch)
//! policies: S  spec as written, serial commit, FIFO
//!           G  spec as written, group commit, FIFO
//!           GP group commit, accepted-class first, bounded reject backlog (overflow coalesced)
//!           GC group commit, per-peer budget of individually logged rejects (rest coalesced)

use crossbeam_channel::{bounded, unbounded, Receiver, Sender, TryRecvError, TrySendError};
use ed25519_dalek::{Signer, SigningKey};
use rand::{Rng, SeedableRng};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------- records

#[derive(Clone, Copy, PartialEq, Debug)]
enum Kind {
    Accept,
    Reject,
}

struct Req {
    kind: Kind,
    peer: u32,
    key: [u8; 32],
    stub: Arc<String>,
    t0: Instant,
    reply: Sender<(u8, Duration)>,
}

/// What the committer hands to a store for one request (all bytes already built).
struct Rec {
    index: u64,
    entry: Vec<u8>,
    leaf: [u8; 32],
    receipt: Vec<u8>,
    accept: Option<AcceptRows>,
}
struct AcceptRows {
    key: [u8; 32],
    dedupe_resp: Vec<u8>,
    task: Vec<u8>,
    event: Vec<u8>,
    counter_key: [u8; 16],
}

trait Store: Send {
    /// Returns true if `key` already has a dedupe entry (read inside the serial committer, so serialisable).
    fn seen(&mut self, key: &[u8; 32]) -> bool;
    /// One durable transaction for all records.
    fn commit(&mut self, recs: &[Rec], counters: &mut HashMap<[u8; 16], u64>);
    fn bytes_on_disk(&self) -> u64;
}

fn dir_size(p: &Path) -> u64 {
    let mut s = 0;
    if let Ok(rd) = std::fs::read_dir(p) {
        for e in rd.flatten() {
            let m = e.metadata().unwrap();
            if m.is_dir() {
                s += dir_size(&e.path());
            } else {
                s += m.len();
            }
        }
    }
    s
}

// ---- redb
mod redb_store {
    use super::*;
    use redb::{Database, Durability, ReadableDatabase, TableDefinition};
    const DEDUPE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("dedupe");
    const TASK: TableDefinition<&[u8], &[u8]> = TableDefinition::new("task");
    const EVENT: TableDefinition<&[u8], &[u8]> = TableDefinition::new("event");
    const COUNTER: TableDefinition<&[u8], u64> = TableDefinition::new("counter");
    const AUDIT: TableDefinition<u64, &[u8]> = TableDefinition::new("audit");
    const LEAF: TableDefinition<u64, &[u8]> = TableDefinition::new("leaf");
    const RECEIPT: TableDefinition<u64, &[u8]> = TableDefinition::new("receipt");
    pub struct R {
        db: Database,
        dir: PathBuf,
    }
    impl R {
        pub fn open(dir: &Path) -> Self {
            let db = Database::create(dir.join("node.redb")).unwrap();
            let tx = db.begin_write().unwrap();
            for t in [DEDUPE, TASK, EVENT] {
                tx.open_table(t).unwrap();
            }
            tx.open_table(COUNTER).unwrap();
            for t in [AUDIT, LEAF, RECEIPT] {
                tx.open_table(t).unwrap();
            }
            tx.commit().unwrap();
            R { db, dir: dir.to_path_buf() }
        }
    }
    impl Store for R {
        fn seen(&mut self, key: &[u8; 32]) -> bool {
            let rx = self.db.begin_read().unwrap();
            let t = rx.open_table(DEDUPE).unwrap();
            t.get(&key[..]).unwrap().is_some()
        }
        fn commit(&mut self, recs: &[Rec], counters: &mut HashMap<[u8; 16], u64>) {
            let mut tx = self.db.begin_write().unwrap();
            tx.set_durability(Durability::Immediate).unwrap();
            {
                let mut d = tx.open_table(DEDUPE).unwrap();
                let mut t = tx.open_table(TASK).unwrap();
                let mut ev = tx.open_table(EVENT).unwrap();
                let mut c = tx.open_table(COUNTER).unwrap();
                let mut a = tx.open_table(AUDIT).unwrap();
                let mut l = tx.open_table(LEAF).unwrap();
                let mut r = tx.open_table(RECEIPT).unwrap();
                for rec in recs {
                    a.insert(rec.index, rec.entry.as_slice()).unwrap();
                    l.insert(rec.index, &rec.leaf[..]).unwrap();
                    r.insert(rec.index, rec.receipt.as_slice()).unwrap();
                    if let Some(ac) = &rec.accept {
                        d.insert(&ac.key[..], ac.dedupe_resp.as_slice()).unwrap();
                        t.insert(&ac.key[..], ac.task.as_slice()).unwrap();
                        let mut ek = ac.key.to_vec();
                        ek.extend_from_slice(&0u64.to_be_bytes());
                        ev.insert(ek.as_slice(), ac.event.as_slice()).unwrap();
                        let n = counters.entry(ac.counter_key).or_insert(0);
                        *n += 1;
                        c.insert(&ac.counter_key[..], *n).unwrap();
                    }
                }
            }
            tx.commit().unwrap();
        }
        fn bytes_on_disk(&self) -> u64 {
            dir_size(&self.dir)
        }
    }
}

// ---- sqlite
mod sqlite_store {
    use super::*;
    use rusqlite::{params, Connection};
    pub struct S {
        c: Connection,
        dir: PathBuf,
    }
    impl S {
        pub fn open(dir: &Path, full: bool) -> Self {
            let c = Connection::open(dir.join("node.sqlite")).unwrap();
            c.pragma_update(None, "journal_mode", "WAL").unwrap();
            c.pragma_update(None, "synchronous", if full { "FULL" } else { "NORMAL" }).unwrap();
            c.execute_batch(
                "CREATE TABLE dedupe(k BLOB PRIMARY KEY, v BLOB) WITHOUT ROWID;
                 CREATE TABLE task(k BLOB PRIMARY KEY, v BLOB) WITHOUT ROWID;
                 CREATE TABLE event(k BLOB, seq INTEGER, v BLOB, PRIMARY KEY(k,seq)) WITHOUT ROWID;
                 CREATE TABLE counter(k BLOB PRIMARY KEY, n INTEGER) WITHOUT ROWID;
                 CREATE TABLE audit(i INTEGER PRIMARY KEY, e BLOB, leaf BLOB, receipt BLOB);",
            )
            .unwrap();
            S { c, dir: dir.to_path_buf() }
        }
    }
    impl Store for S {
        fn seen(&mut self, key: &[u8; 32]) -> bool {
            let mut st = self.c.prepare_cached("SELECT 1 FROM dedupe WHERE k=?1").unwrap();
            st.exists(params![&key[..]]).unwrap()
        }
        fn commit(&mut self, recs: &[Rec], _counters: &mut HashMap<[u8; 16], u64>) {
            let tx = self.c.transaction().unwrap();
            {
                let mut a = tx.prepare_cached("INSERT INTO audit VALUES(?1,?2,?3,?4)").unwrap();
                let mut d = tx.prepare_cached("INSERT INTO dedupe VALUES(?1,?2)").unwrap();
                let mut t = tx.prepare_cached("INSERT INTO task VALUES(?1,?2)").unwrap();
                let mut e = tx.prepare_cached("INSERT INTO event VALUES(?1,0,?2)").unwrap();
                let mut c = tx
                    .prepare_cached("INSERT INTO counter VALUES(?1,1) ON CONFLICT(k) DO UPDATE SET n=n+1")
                    .unwrap();
                for rec in recs {
                    a.execute(params![rec.index as i64, rec.entry, &rec.leaf[..], rec.receipt]).unwrap();
                    if let Some(ac) = &rec.accept {
                        d.execute(params![&ac.key[..], ac.dedupe_resp]).unwrap();
                        t.execute(params![&ac.key[..], ac.task]).unwrap();
                        e.execute(params![&ac.key[..], ac.event]).unwrap();
                        c.execute(params![&ac.counter_key[..]]).unwrap();
                    }
                }
            }
            tx.commit().unwrap();
        }
        fn bytes_on_disk(&self) -> u64 {
            dir_size(&self.dir)
        }
    }
}

// ---- fjall
mod fjall_store {
    use super::*;
    use fjall::{Database, Keyspace, KeyspaceCreateOptions, PersistMode};
    pub struct F {
        db: Database,
        ks: Vec<Keyspace>, // dedupe task event counter audit leaf receipt
        dir: PathBuf,
    }
    impl F {
        pub fn open(dir: &Path) -> Self {
            let db = Database::builder(dir.join("fjall")).open().unwrap();
            let ks = ["dedupe", "task", "event", "counter", "audit", "leaf", "receipt"]
                .iter()
                .map(|n| db.keyspace(n, KeyspaceCreateOptions::default).unwrap())
                .collect();
            F { db, ks, dir: dir.to_path_buf() }
        }
    }
    impl Store for F {
        fn seen(&mut self, key: &[u8; 32]) -> bool {
            self.ks[0].contains_key(key).unwrap()
        }
        fn commit(&mut self, recs: &[Rec], counters: &mut HashMap<[u8; 16], u64>) {
            let mut b = self.db.batch().durability(Some(PersistMode::SyncAll));
            for rec in recs {
                let ik = rec.index.to_be_bytes();
                b.insert(&self.ks[4], ik, rec.entry.as_slice());
                b.insert(&self.ks[5], ik, &rec.leaf[..]);
                b.insert(&self.ks[6], ik, rec.receipt.as_slice());
                if let Some(ac) = &rec.accept {
                    b.insert(&self.ks[0], ac.key, ac.dedupe_resp.as_slice());
                    b.insert(&self.ks[1], ac.key, ac.task.as_slice());
                    let mut ek = ac.key.to_vec();
                    ek.extend_from_slice(&0u64.to_be_bytes());
                    b.insert(&self.ks[2], ek, ac.event.as_slice());
                    let n = counters.entry(ac.counter_key).or_insert(0);
                    *n += 1;
                    b.insert(&self.ks[3], ac.counter_key, n.to_be_bytes());
                }
            }
            b.commit().unwrap();
        }
        fn bytes_on_disk(&self) -> u64 {
            dir_size(&self.dir)
        }
    }
}

// ---- raw append log (lower bound: no index, no reads)
struct RawLog {
    f: File,
    dir: PathBuf,
    buf: Vec<u8>,
}
impl RawLog {
    fn open(dir: &Path) -> Self {
        let f = OpenOptions::new().create(true).append(true).open(dir.join("node.log")).unwrap();
        RawLog { f, dir: dir.to_path_buf(), buf: Vec::new() }
    }
}
impl Store for RawLog {
    fn seen(&mut self, _key: &[u8; 32]) -> bool {
        false
    }
    fn commit(&mut self, recs: &[Rec], _c: &mut HashMap<[u8; 16], u64>) {
        self.buf.clear();
        for rec in recs {
            for part in [&rec.entry[..], &rec.leaf[..], &rec.receipt[..]] {
                self.buf.extend_from_slice(&(part.len() as u32).to_le_bytes());
                self.buf.extend_from_slice(part);
            }
            if let Some(ac) = &rec.accept {
                for part in [&ac.dedupe_resp[..], &ac.task[..], &ac.event[..], &ac.key[..]] {
                    self.buf.extend_from_slice(&(part.len() as u32).to_le_bytes());
                    self.buf.extend_from_slice(part);
                }
            }
        }
        self.f.write_all(&self.buf).unwrap();
        self.f.sync_data().unwrap();
    }
    fn bytes_on_disk(&self) -> u64 {
        dir_size(&self.dir)
    }
}

fn open_store(backend: &str, dir: &Path) -> Box<dyn Store + Send> {
    match backend {
        "redb" => Box::new(redb_store::R::open(dir)),
        "sqlite" => Box::new(sqlite_store::S::open(dir, true)),
        "sqlite-normal" => Box::new(sqlite_store::S::open(dir, false)),
        "fjall" => Box::new(fjall_store::F::open(dir)),
        "rawlog" => Box::new(RawLog::open(dir)),
        b => panic!("unknown backend {b}"),
    }
}

// ---------------------------------------------------------------- audit log head

/// RFC 9162 Merkle tree with BLAKE3, kept as a frontier of perfect-subtree roots.
struct LogHead {
    index: u64,
    prev: [u8; 32],
    frontier: Vec<(u32, [u8; 32])>,
    key: SigningKey,
}
fn node(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&[1]);
    h.update(l);
    h.update(r);
    *h.finalize().as_bytes()
}
impl LogHead {
    fn new() -> Self {
        LogHead { index: 0, prev: [0; 32], frontier: Vec::new(), key: SigningKey::from_bytes(&[7u8; 32]) }
    }
    /// Builds entry, leaf, root and signed receipt for one envelope.received entry.
    fn append(&mut self, outcome: &str, stub: Option<&str>, extra: &str) -> (u64, Vec<u8>, [u8; 32], Vec<u8>) {
        let index = self.index;
        let entry = format!(
            "{{\"data\":{{\"hd\":\"blake3:{}\",\"outcome\":\"{}\",{}\"via\":\"wwn:r3laaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"{}}},\"epoch\":0,\"index\":{},\"log\":\"wwn:ab3kaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"parties\":[\"wwa:4f3w\",\"wwa:q2ya\"],\"prev\":\"blake3:{}\",\"time\":\"2026-11-10T12:00:01.250Z\",\"type\":\"envelope.received\",\"v\":\"webway-audit-entry/0\"}}",
            hex::encode(&self.prev[..16]),
            outcome,
            stub.map(|s| format!("\"stub\":{s},")).unwrap_or_default(),
            extra,
            index,
            hex::encode(self.prev)
        );
        let eh = *blake3::hash(entry.as_bytes()).as_bytes();
        let mut lh = blake3::Hasher::new();
        lh.update(&[0]);
        lh.update(entry.as_bytes());
        let leaf = *lh.finalize().as_bytes();
        // frontier append
        self.frontier.push((0, leaf));
        while self.frontier.len() >= 2 {
            let n = self.frontier.len();
            if self.frontier[n - 1].0 != self.frontier[n - 2].0 {
                break;
            }
            let (h, r) = self.frontier.pop().unwrap();
            let (_, l) = self.frontier.pop().unwrap();
            self.frontier.push((h + 1, node(&l, &r)));
        }
        let mut root = self.frontier.last().unwrap().1;
        for (_, l) in self.frontier.iter().rev().skip(1) {
            root = node(l, &root);
        }
        let receipt = if stub.is_some() {
            let body = format!(
                "{{\"entry\":\"blake3:{}\",\"env\":\"blake3:{}\",\"epoch\":0,\"from\":\"wwa:4f3w\",\"id\":\"019a5d2e-7b40-7c3a-9d1e-0a1b2c3d4e5f\",\"index\":{},\"log\":\"wwn:ab3k\",\"root\":\"blake3:{}\",\"time\":\"2026-11-10T12:00:01.250Z\",\"to\":\"wwa:q2ya\",\"v\":\"webway-receipt/0\"}}",
                hex::encode(eh),
                hex::encode(&eh[..16]),
                index,
                hex::encode(root)
            );
            let mut msg = b"webway-receipt/0\n".to_vec();
            msg.extend_from_slice(body.as_bytes());
            let sig = self.key.sign(&msg);
            let mut r = body.into_bytes();
            r.extend_from_slice(&sig.to_bytes());
            r
        } else {
            Vec::new()
        };
        self.prev = eh;
        self.index += 1;
        (index, entry.into_bytes(), leaf, receipt)
    }
}

// ---------------------------------------------------------------- committer

struct Stats {
    commits: AtomicU64,
    entries: AtomicU64,
    coalesced: AtomicU64,
    max_batch: AtomicU64,
}

#[derive(Clone)]
struct CommitCfg {
    group: bool,
    max_batch: usize,
    max_bytes: usize,
}

/// Committer with an accepted-class queue `hq` and a reject-class queue `rq` (same queue in FIFO policies).
/// Coalesced reject counts (per peer) are flushed as one entry per peer per second.
fn committer(
    mut store: Box<dyn Store + Send>,
    hq: Receiver<Req>,
    rq: Option<Receiver<Req>>,
    cfg: CommitCfg,
    coalesce: Arc<std::sync::Mutex<HashMap<u32, u64>>>,
    stats: Arc<Stats>,
    stop: Arc<AtomicBool>,
) -> Box<dyn Store + Send> {
    let mut head = LogHead::new();
    let mut counters = HashMap::new();
    let mut batch: Vec<Req> = Vec::new();
    let mut recs: Vec<Rec> = Vec::new();
    let mut last_flush = Instant::now();
    let task_row = vec![b't'; 800];
    let event_row = vec![b'e'; 300];
    loop {
        if stop.load(Ordering::Relaxed) {
            return store; // abandon any backlog: the caller measured it already
        }
        batch.clear();
        recs.clear();
        // block for the first request (from either queue)
        let first = match &rq {
            None => hq.recv_timeout(Duration::from_millis(20)).ok(),
            Some(rq) => {
                crossbeam_channel::select! {
                    recv(hq) -> m => m.ok(),
                    recv(rq) -> m => m.ok(),
                    default(Duration::from_millis(20)) => None,
                }
            }
        };
        if let Some(r) = first {
            batch.push(r);
        }
        if cfg.group && !batch.is_empty() {
            let mut bytes: usize = batch.iter().map(|r| r.stub.len()).sum();
            // accepted class first
            while batch.len() < cfg.max_batch && bytes < cfg.max_bytes {
                match hq.try_recv() {
                    Ok(r) => {
                        bytes += r.stub.len();
                        batch.push(r)
                    }
                    Err(_) => break,
                }
            }
            if let Some(rq) = &rq {
                while batch.len() < cfg.max_batch && bytes < cfg.max_bytes {
                    match rq.try_recv() {
                        Ok(r) => {
                            bytes += r.stub.len();
                            batch.push(r)
                        }
                        Err(_) => break,
                    }
                }
            }
        }
        // coalesced reject entries, once per second
        let mut n_coal = 0;
        if last_flush.elapsed() >= Duration::from_secs(1) {
            last_flush = Instant::now();
            let mut m = coalesce.lock().unwrap();
            for (peer, n) in m.drain() {
                let (index, entry, leaf, receipt) =
                    head.append("rejected", None, &format!(",\"detail\":{{\"count\":{n},\"peer\":{peer}}}"));
                recs.push(Rec { index, entry, leaf, receipt, accept: None });
                n_coal += 1;
            }
        }
        if batch.is_empty() && recs.is_empty() {
            continue;
        }
        for r in &batch {
            match r.kind {
                Kind::Accept => {
                    let dup = store.seen(&r.key);
                    let (index, entry, leaf, receipt) =
                        head.append(if dup { "duplicate" } else { "accepted" }, Some(&r.stub), "");
                    let mut resp = vec![b'r'; 250];
                    resp.extend_from_slice(&receipt);
                    let mut ck = [0u8; 16];
                    ck[..4].copy_from_slice(&r.peer.to_le_bytes());
                    recs.push(Rec {
                        index,
                        entry,
                        leaf,
                        receipt,
                        accept: Some(AcceptRows {
                            key: r.key,
                            dedupe_resp: resp,
                            task: task_row.clone(),
                            event: event_row.clone(),
                            counter_key: ck,
                        }),
                    });
                }
                Kind::Reject => {
                    let (index, entry, leaf, receipt) = head.append(
                        "rejected",
                        Some(&r.stub),
                        ",\"error\":{\"reason\":\"no-capability\",\"type\":\"Unauthorized\"}",
                    );
                    recs.push(Rec { index, entry, leaf, receipt, accept: None });
                }
            }
        }
        store.commit(&recs, &mut counters);
        let done = Instant::now();
        for r in batch.drain(..) {
            let _ = r.reply.send((if r.kind == Kind::Accept { 0 } else { 1 }, done - r.t0));
        }
        stats.commits.fetch_add(1, Ordering::Relaxed);
        stats.entries.fetch_add(recs.len() as u64, Ordering::Relaxed);
        stats.coalesced.fetch_add(n_coal, Ordering::Relaxed);
        stats.max_batch.fetch_max(recs.len() as u64, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------- helpers

fn make_stub(target: usize, seed: u64) -> String {
    // a JSON object of about `target` bytes, shaped like a signed header (cap token + prov dominate size)
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let fixed = format!(
        "{{\"body_hash\":\"blake3:{}\",\"cap\":{{\"access\":\"",
        hex::encode(rng.gen::<[u8; 32]>())
    );
    let tail = "\"},\"exp\":\"2026-11-10T13:00:00Z\",\"from\":\"wwa:4f3w\",\"id\":\"019a5d2e-7b40-7c3a-9d1e-0a1b2c3d4e5f\",\"prov\":{},\"sig\":\"Xr0e\",\"to\":\"wwa:q2ya\",\"ts\":\"2026-11-10T12:00:00Z\",\"v\":\"webway-envelope/0\"}";
    let pad = target.saturating_sub(fixed.len() + tail.len());
    let mut s = fixed;
    for _ in 0..pad {
        s.push((b'A' + rng.gen_range(0..26)) as char);
    }
    s.push_str(tail);
    s
}

fn pct(v: &mut [f64], p: f64) -> f64 {
    if v.is_empty() {
        return f64::NAN;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let i = ((v.len() as f64 - 1.0) * p).round() as usize;
    v[i]
}

fn fresh_dir(base: &str, tag: &str) -> PathBuf {
    let d = PathBuf::from(base).join(tag);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn key_for(ctr: u64, salt: u64) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&ctr.to_le_bytes());
    h.update(&salt.to_le_bytes());
    *h.finalize().as_bytes()
}

// ---------------------------------------------------------------- experiments

fn cmd_fsync(base: &str) {
    let d = fresh_dir(base, "fsync");
    let mut f = OpenOptions::new().create(true).append(true).open(d.join("probe")).unwrap();
    println!("size_bytes,n,p50_ms,p99_ms");
    for &sz in &[512usize, 4096, 65536, 1 << 20, 4 << 20] {
        let b = vec![b'x'; sz];
        let n = if sz >= 1 << 20 { 60 } else { 400 };
        let mut v = Vec::new();
        for _ in 0..n {
            let t = Instant::now();
            f.write_all(&b).unwrap();
            f.sync_data().unwrap();
            v.push(t.elapsed().as_secs_f64() * 1e3);
        }
        let p50 = pct(&mut v, 0.5);
        let p99 = pct(&mut v, 0.99);
        println!("{sz},{n},{p50:.3},{p99:.3}");
    }
    // CPU cost of the per-entry work done serially by the committer
    let mut head = LogHead::new();
    let stub = make_stub(1536, 1);
    let t = Instant::now();
    for _ in 0..20000 {
        head.append("accepted", Some(&stub), "");
    }
    println!("# committer CPU per 1.5 KiB entry (entry+hash+merkle+receipt sign): {:.1} us", t.elapsed().as_secs_f64() * 1e6 / 20000.0);
    let stub = make_stub(1 << 20, 1);
    let t = Instant::now();
    for _ in 0..100 {
        head.append("accepted", Some(&stub), "");
    }
    println!("# committer CPU per 1 MiB entry: {:.1} us", t.elapsed().as_secs_f64() * 1e6 / 100.0);
    let vk = head.key.verifying_key();
    let sig = head.key.sign(b"hello header");
    let t = Instant::now();
    for _ in 0..20000 {
        vk.verify_strict(b"hello header", &sig).unwrap();
    }
    println!("# ed25519 verify_strict: {:.1} us", t.elapsed().as_secs_f64() * 1e6 / 20000.0);
    let _ = std::fs::remove_dir_all(&d);
}

fn cmd_cap(base: &str, backend: &str, mode: &str, conc: usize, secs: f64) {
    let d = fresh_dir(base, &format!("cap-{backend}-{mode}-{conc}"));
    let store = open_store(backend, &d);
    let (hs, hr) = unbounded::<Req>();
    let stats = Arc::new(Stats {
        commits: AtomicU64::new(0),
        entries: AtomicU64::new(0),
        coalesced: AtomicU64::new(0),
        max_batch: AtomicU64::new(0),
    });
    let stop = Arc::new(AtomicBool::new(false));
    let cfg = CommitCfg { group: mode == "group", max_batch: 1024, max_bytes: 8 << 20 };
    let co = {
        let (stats, stop) = (stats.clone(), stop.clone());
        let co = Arc::new(std::sync::Mutex::new(HashMap::new()));
        std::thread::spawn(move || committer(store, hr, None, cfg, co, stats, stop))
    };
    let stub = Arc::new(make_stub(1536, 2));
    let deadline = Instant::now() + Duration::from_secs_f64(secs);
    let warm = Instant::now() + Duration::from_secs_f64(secs.min(1.0) * 0.2);
    let mut hs_ = Vec::new();
    for c in 0..conc {
        let hs = hs.clone();
        let stub = stub.clone();
        hs_.push(std::thread::spawn(move || {
            let (rs, rr) = unbounded();
            let mut lat = Vec::new();
            let mut i = 0u64;
            while Instant::now() < deadline {
                let t0 = Instant::now();
                hs.send(Req { kind: Kind::Accept, peer: c as u32, key: key_for(i, c as u64), stub: stub.clone(), t0, reply: rs.clone() })
                    .unwrap();
                let (_, l) = rr.recv().unwrap();
                if t0 > warm {
                    lat.push(l.as_secs_f64() * 1e3);
                }
                i += 1;
            }
            lat
        }));
    }
    let mut lat: Vec<f64> = hs_.into_iter().flat_map(|h| h.join().unwrap()).collect();
    stop.store(true, Ordering::Relaxed);
    drop(hs);
    let store = co.join().unwrap();
    let measured = secs - (warm - (deadline - Duration::from_secs_f64(secs))).as_secs_f64();
    let n = lat.len();
    let c = stats.commits.load(Ordering::Relaxed);
    let e = stats.entries.load(Ordering::Relaxed);
    println!(
        "{backend},{mode},{conc},{:.0},{:.2},{:.2},{:.2},{:.1},{:.1}",
        n as f64 / measured,
        pct(&mut lat, 0.5),
        pct(&mut lat, 0.99),
        pct(&mut lat, 0.999),
        e as f64 / c.max(1) as f64,
        store.bytes_on_disk() as f64 / e.max(1) as f64
    );
    drop(store);
    let _ = std::fs::remove_dir_all(&d);
}

#[allow(clippy::too_many_arguments)]
fn cmd_flood(base: &str, backend: &str, policy: &str, stub_sz: usize, bw_mbit: f64, peers: u32, secs: f64) {
    let d = fresh_dir(base, &format!("flood-{backend}-{policy}-{stub_sz}-{bw_mbit}-{peers}"));
    let store = open_store(backend, &d);
    let (hs, hr) = unbounded::<Req>();
    let (rs_tx, rs_rx, rq) = match policy {
        "GP" => {
            let (a, b) = bounded::<Req>(256);
            (Some(a), None::<Receiver<Req>>, Some(b))
        }
        _ => (None, None, None),
    };
    let _ = rs_rx;
    let stats = Arc::new(Stats {
        commits: AtomicU64::new(0),
        entries: AtomicU64::new(0),
        coalesced: AtomicU64::new(0),
        max_batch: AtomicU64::new(0),
    });
    let stop = Arc::new(AtomicBool::new(false));
    let cfg = CommitCfg { group: policy != "S", max_batch: 1024, max_bytes: 8 << 20 };
    let coalesce = Arc::new(std::sync::Mutex::new(HashMap::<u32, u64>::new()));
    let deadline = Instant::now() + Duration::from_secs_f64(secs);
    let warm = Instant::now() + Duration::from_secs_f64(1.0);
    let hr_probe = hr.clone();
    let rq_probe = rq.clone();
    let backlog_at_deadline = {
        let (h, r) = (hr.clone(), rq.clone());
        std::thread::spawn(move || {
            std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
            h.len() + r.as_ref().map(|r| r.len()).unwrap_or(0)
        })
    };
    let co = {
        let (stats, stop, coalesce) = (stats.clone(), stop.clone(), coalesce.clone());
        std::thread::spawn(move || committer(store, hr, rq, cfg, coalesce, stats, stop))
    };

    // honest: Poisson 200/s, 1.5 KiB stubs, all accepted
    let honest = {
        let hs = hs.clone();
        std::thread::spawn(move || {
            let stub = Arc::new(make_stub(1536, 3));
            let (rs, rr) = unbounded();
            let mut rng = rand::rngs::StdRng::seed_from_u64(42);
            let exp = rand_distr::Exp::new(200.0).unwrap();
            let mut next = Instant::now();
            let mut sent = 0u64;
            while Instant::now() < deadline {
                next += Duration::from_secs_f64(rng.sample(exp));
                let now = Instant::now();
                if next > now {
                    std::thread::sleep(next - now);
                }
                hs.send(Req { kind: Kind::Accept, peer: 0, key: key_for(sent, 999), stub: stub.clone(), t0: next, reply: rs.clone() })
                    .unwrap();
                sent += 1;
            }
            drop(rs);
            // wait for outstanding replies, up to 20 s after deadline (count the rest as unacked)
            let mut lat = Vec::new();
            let mut got = 0u64;
            let hard = deadline + Duration::from_secs(20);
            while got < sent {
                let left = hard.saturating_duration_since(Instant::now());
                match rr.recv_timeout(left) {
                    Ok((_, l)) => {
                        got += 1;
                        lat.push(l.as_secs_f64() * 1e3)
                    }
                    Err(_) => break,
                }
            }
            (lat, sent, got)
        })
    };

    // adversary: open loop at bw / stub_sz, spread over `peers` transport peers, rejected after verification
    let adv_sent = Arc::new(AtomicU64::new(0));
    let adv_coal = Arc::new(AtomicU64::new(0));
    let adversary = if bw_mbit > 0.0 {
        let (hs, rs_tx, coalesce, adv_sent, adv_coal) =
            (hs.clone(), rs_tx.clone(), coalesce.clone(), adv_sent.clone(), adv_coal.clone());
        let policy = policy.to_string();
        Some(std::thread::spawn(move || {
            let stub = Arc::new(make_stub(stub_sz, 4));
            let rate = bw_mbit * 1e6 / 8.0 / stub_sz as f64;
            let (rs, rr) = unbounded::<(u8, Duration)>();
            // drain replies in a side thread (latency of rejects is not the metric)
            let drain = std::thread::spawn(move || {
                let mut v = Vec::new();
                while let Ok((_, l)) = rr.recv() {
                    v.push(l.as_secs_f64() * 1e3);
                }
                v
            });
            let start = Instant::now();
            let mut sent = 0u64;
            // per-peer token buckets for GC: 10/s, burst 20
            let mut buckets: HashMap<u32, (f64, Instant)> = HashMap::new();
            while Instant::now() < deadline {
                let due = (start.elapsed().as_secs_f64() * rate) as u64;
                if sent >= due {
                    std::thread::sleep(Duration::from_micros(200));
                    continue;
                }
                while sent < due {
                    let peer = 1 + (sent % peers as u64) as u32;
                    let req = Req { kind: Kind::Reject, peer, key: [0; 32], stub: stub.clone(), t0: Instant::now(), reply: rs.clone() };
                    sent += 1;
                    match policy.as_str() {
                        "GC" => {
                            let now = Instant::now();
                            let b = buckets.entry(peer).or_insert((20.0, now));
                            b.0 = (b.0 + now.duration_since(b.1).as_secs_f64() * 10.0).min(20.0);
                            b.1 = now;
                            if b.0 >= 1.0 {
                                b.0 -= 1.0;
                                hs.send(req).unwrap();
                            } else {
                                *coalesce.lock().unwrap().entry(peer).or_insert(0) += 1;
                                adv_coal.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        "GP" => match rs_tx.as_ref().unwrap().try_send(req) {
                            Ok(()) => {}
                            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                                *coalesce.lock().unwrap().entry(peer).or_insert(0) += 1;
                                adv_coal.fetch_add(1, Ordering::Relaxed);
                            }
                        },
                        _ => hs.send(req).unwrap(),
                    }
                }
            }
            adv_sent.store(sent, Ordering::Relaxed);
            drop(rs);
            drain
        }))
    } else {
        None
    };
    drop(rs_tx);
    let (mut lat, h_sent, h_got) = honest.join().unwrap();
    let _ = warm;
    // discard warm-up second by dropping the first 200 samples (approximately 1 s)
    let mut lat_w: Vec<f64> = if lat.len() > 200 { lat.split_off(200) } else { lat.clone() };
    let backlog = hr_probe.len() + rq_probe.as_ref().map(|r| r.len()).unwrap_or(0);
    stop.store(true, Ordering::Relaxed);
    let adv_logged_lat = adversary.map(|a| {
        let drain = a.join().unwrap();
        drain
    });
    drop(hs);
    // the committer may still hold a FIFO backlog of rejects: measure how far behind it is, then stop
    let store = co.join().unwrap();
    drop(hr_probe);
    drop(rq_probe);
    let _ = backlog;
    let backlog_s = backlog_at_deadline.join().unwrap() as f64;
    let rejs_logged = adv_logged_lat.map(|j| j.join().unwrap().len()).unwrap_or(0);
    let e = stats.entries.load(Ordering::Relaxed);
    let c = stats.commits.load(Ordering::Relaxed);
    let disk = store.bytes_on_disk();
    println!(
        "{backend},{policy},{stub_sz},{bw_mbit},{peers},{:.0},{:.0},{:.0},{h_sent},{h_got},{:.2},{:.2},{:.2},{:.1},{:.1},{:.1}",
        adv_sent.load(Ordering::Relaxed) as f64 / secs,
        rejs_logged as f64 / secs,
        adv_coal.load(Ordering::Relaxed) as f64 / secs,
        pct(&mut lat_w, 0.5),
        pct(&mut lat_w, 0.99),
        pct(&mut lat_w, 1.0),
        e as f64 / c.max(1) as f64,
        disk as f64 / 1e6 / secs,
        backlog_s
    );
    let _ = TryRecvError::Empty;
    drop(store);
    let _ = std::fs::remove_dir_all(&d);
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(|s| s.as_str()) {
        Some("fsync") => cmd_fsync(&a[2]),
        Some("cap") => cmd_cap(&a[2], &a[3], &a[4], a[5].parse().unwrap(), a[6].parse().unwrap()),
        Some("flood") => cmd_flood(
            &a[2],
            &a[3],
            &a[4],
            a[5].parse().unwrap(),
            a[6].parse().unwrap(),
            a[7].parse().unwrap(),
            a[8].parse().unwrap(),
        ),
        _ => eprintln!("see source header for usage"),
    }
}
