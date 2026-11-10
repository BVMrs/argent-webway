//! Lab: blob/v0 over bao-tree 0.17 (the verified-streaming layer under iroh-blobs).
//!
//! E1  size aliasing: an adversarial provider sends a wrong size header. For which claimed sizes
//!     does a range response still verify, and what does the receiver get?
//! E2  mutation fuzz of honest responses: soundness (no unverified byte is ever delivered),
//!     silent acceptance, and bytes downloaded-and-discarded before detection, per chunk-group size.
//! E3  wire and storage overhead per chunk-group size and request shape.
//! E4  single-thread throughput of outboard creation / encode / verify per chunk-group size.
//!
//! Usage: blob-bao-size-auth [e1|e2|e3|e4|all] [fuzz_iterations]

use bao_tree::{
    io::{
        outboard::PreOrderMemOutboard,
        sync::{encode_ranges_validated, DecodeResponseIter},
        BaoContentItem,
    },
    BaoTree, BlockSize, ChunkNum, ChunkRanges,
};
use rand::{rngs::SmallRng, Rng, RngCore, SeedableRng};
use std::collections::BTreeMap;
use std::io::{Cursor, Read};
use std::time::Instant;

const CHUNK: u64 = 1024;

// ---------------------------------------------------------------- helpers

fn chunks(size: u64) -> u64 {
    ChunkNum::chunks(size).0
}

/// Same rule as bao-tree's private `rec::truncated_len` (copied so the attacker sees exactly the
/// ranges the decoder will walk).
fn truncate(ranges: &ChunkRanges, size: u64) -> ChunkRanges {
    let end = ChunkNum::chunks(size);
    let lc = ChunkNum(end.0.saturating_sub(1));
    let bs = ranges.boundaries();
    let n = match bs.binary_search(&lc) {
        Ok(i) if (i & 1) == 0 => i + 1,
        Ok(i) => {
            if bs.len() == i + 1 {
                i + 1
            } else {
                i
            }
        }
        Err(ip) if (ip & 1) == 0 => {
            if bs.len() == ip {
                ip
            } else {
                ip + 1
            }
        }
        Err(ip) => ip,
    };
    ChunkRanges::new(bs[..n].iter().copied().collect()).unwrap()
}

/// BLAKE3 chaining value of the real subtree covering chunks [s, e) of `data`.
fn cv(data: &[u8], s: u64, e: u64, is_root: bool) -> blake3::Hash {
    thread_local! {
        static CACHE: std::cell::RefCell<(usize, u64, std::collections::HashMap<(u64, u64, bool), blake3::Hash>)> =
            Default::default();
    }
    CACHE.with(|c| {
        let mut c = c.borrow_mut();
        let key = (data.as_ptr() as usize, GEN.load(std::sync::atomic::Ordering::Relaxed));
        if (c.0, c.1) != key {
            c.0 = key.0;
            c.1 = key.1;
            c.2.clear();
        }
        if let Some(h) = c.2.get(&(s, e, is_root)) {
            return *h;
        }
        let h = cv_raw(data, s, e, is_root);
        c.2.insert((s, e, is_root), h);
        h
    })
}

fn cv_raw(data: &[u8], s: u64, e: u64, is_root: bool) -> blake3::Hash {
    use blake3::hazmat::HasherExt;
    let lo = (s * CHUNK) as usize;
    let hi = ((e * CHUNK) as usize).min(data.len());
    let slice = &data[lo.min(hi)..hi];
    if is_root {
        blake3::hash(slice)
    } else {
        let mut h = blake3::Hasher::new();
        h.set_input_offset(s * CHUNK);
        h.update(slice);
        blake3::Hash::from(h.finalize_non_root())
    }
}

/// BLAKE3 splits a subtree of n > 1 chunks into a left part of the largest power of two < n.
fn split(s: u64, e: u64) -> ((u64, u64), (u64, u64)) {
    let n = e - s;
    let left = if n.is_power_of_two() { n / 2 } else { 1u64 << (63 - n.leading_zeros()) };
    ((s, s + left), (s + left, e))
}

/// The strongest provider that only has the real blob (no hash collisions): it answers a request
/// made against a *claimed* tree by mirroring the decoder's descent through the real tree, sending
/// the real hash pair at each step and real bytes at each leaf. Anything else fails a hash check
/// at the first deviation, so if this encoding does not verify, no encoding does.
fn liar_encode(data: &[u8], claimed: BaoTree, ranges: &ChunkRanges) -> Vec<u8> {
    let real_chunks = chunks(data.len() as u64).max(1);
    let r = truncate(ranges, claimed.size());
    let mut out = Vec::new();
    let mut stack: Vec<Option<(u64, u64)>> = vec![Some((0, real_chunks))];
    // exactly the walk the decoder does (DecodeResponseIter wraps ResponseIterRef): a block-size-0
    // tree that stops at the chunk-group level for fully requested groups and descends inside
    // partially requested ones
    for item in bao_tree::iter::ResponseIterRef::new(claimed, &r) {
        match item {
            bao_tree::iter::BaoChunk::Parent { left, right, .. } => {
                let h = stack.pop().unwrap();
                match h {
                    Some((s, e)) if e - s > 1 => {
                        let (l, rr) = split(s, e);
                        out.extend_from_slice(cv(data, l.0, l.1, false).as_bytes());
                        out.extend_from_slice(cv(data, rr.0, rr.1, false).as_bytes());
                        if right {
                            stack.push(Some(rr));
                        }
                        if left {
                            stack.push(Some(l));
                        }
                    }
                    _ => {
                        out.extend_from_slice(&[0u8; 64]);
                        if right {
                            stack.push(None);
                        }
                        if left {
                            stack.push(None);
                        }
                    }
                }
            }
            bao_tree::iter::BaoChunk::Leaf { start_chunk, size, .. } => {
                let h = stack.pop().unwrap();
                let lo = match h {
                    Some((s, _)) => s * CHUNK,
                    None => start_chunk.0 * CHUNK,
                } as usize;
                for i in 0..size {
                    out.push(*data.get(lo + i).unwrap_or(&0));
                }
            }
        }
        // A response longer than this would have to carry leaves past the end of the real data,
        // which cannot verify; stop so absurd claimed sizes stay cheap (the decoder then reports
        // a missing parent/leaf instead of a hash mismatch, still a reject).
        if out.len() as u64 > 2 * data.len() as u64 + (128 << 10) {
            break;
        }
    }
    out
}

struct CountingReader<'a> {
    inner: Cursor<&'a [u8]>,
    pos: std::rc::Rc<std::cell::Cell<u64>>,
}
impl Read for CountingReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.pos.set(self.pos.get() + n as u64);
        Ok(n)
    }
}

#[derive(Debug, Default)]
struct Decoded {
    ok: bool,
    sound: bool,                // every delivered byte equals the real byte at that offset
    delivered: Vec<(u64, u64)>, // byte ranges delivered to the application
    delivered_bytes: u64,
    consumed: u64, // bytes read from the stream
    trailing: u64, // bytes left unread after a successful decode
    leaf_end: Vec<u64>, // stream position after each delivered leaf
}

fn decode(real: &[u8], root: blake3::Hash, tree: BaoTree, enc: &[u8], ranges: &ChunkRanges) -> Decoded {
    let pos = std::rc::Rc::new(std::cell::Cell::new(0u64));
    let mut rd = CountingReader { inner: Cursor::new(enc), pos: pos.clone() };
    let mut d = Decoded { ok: true, sound: true, ..Default::default() };
    {
        let it = DecodeResponseIter::new(root, tree, &mut rd, ranges);
        for item in it {
            match item {
                Ok(BaoContentItem::Leaf(l)) => {
                    let lo = l.offset as usize;
                    let hi = lo + l.data.len();
                    if hi > real.len() || real[lo..hi] != l.data[..] {
                        d.sound = false;
                    }
                    d.delivered.push((l.offset, hi as u64));
                    d.delivered_bytes += l.data.len() as u64;
                    d.leaf_end.push(pos.get());
                }
                Ok(_) => {}
                Err(_) => {
                    d.ok = false;
                    break;
                }
            }
        }
    }
    d.consumed = pos.get();
    d.trailing = enc.len() as u64 - d.consumed;
    d
}

static GEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn rand_data(rng: &mut SmallRng, n: usize) -> Vec<u8> {
    GEN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut v = vec![0u8; n];
    rng.fill_bytes(&mut v);
    v
}

fn honest_encode(data: &[u8], ob: &PreOrderMemOutboard, ranges: &ChunkRanges) -> Vec<u8> {
    let mut enc = Vec::new();
    encode_ranges_validated(data, ob, ranges, &mut enc).unwrap();
    enc
}

// ---------------------------------------------------------------- E1

#[derive(Default, Clone)]
struct E1Row {
    cases: u64,
    accepted_true: u64,
    accepted_alias: u64,
    alias_smaller: u64,
    alias_larger: u64,
    alias_short_delivery: u64, // accepted, but delivered bytes != requested bytes of the real blob
    unsound: u64,
    panics: u64,
    blobs_with_alias: u64,
    max_alias_ratio: f64, // max claimed/real among accepted aliases
}

fn e1() {
    println!("== E1: size aliasing (adversarial size header, strongest collision-free provider)");
    let mut rng = SmallRng::seed_from_u64(1);
    // real sizes: around every chunk boundary up to 70 chunks, plus a few larger ones
    let mut reals: Vec<u64> = Vec::new();
    for c in 0..=70u64 {
        for d in [0i64, 1, 512, -1] {
            let v = c as i64 * 1024 + d;
            if v >= 0 {
                reals.push(v as u64);
            }
        }
    }
    reals.extend([65 * 1024 + 1, 300 * 1024 + 7, 1 << 20, (1 << 20) + 1]);
    reals.sort();
    reals.dedup();
    let max_real = *reals.last().unwrap();
    // claimed sizes: the same grid up to 4x the largest real, plus every real +-1 and huge values
    let mut claims: Vec<u64> = Vec::new();
    let mut c = 0u64;
    while c <= 4 * max_real {
        for d in [0i64, 1, -1, 512] {
            let v = c as i64 + d;
            if v >= 0 {
                claims.push(v as u64);
            }
        }
        c = if c < 140 * 1024 { c + 1024 } else { c * 9 / 8 / 1024 * 1024 };
    }
    for &r in &reals {
        for d in [-2i64, -1, 0, 1, 2, 1023, 1024, 1025] {
            let v = r as i64 + d;
            if v >= 0 {
                claims.push(v as u64);
            }
        }
        claims.push(2 * r);
        claims.push(2 * r + 1);
    }
    claims.extend([1u64 << 32, 1 << 40, 1 << 50, (1 << 62) + 5, 1 << 63, u64::MAX - 1, u64::MAX]);
    claims.sort();
    claims.dedup();

    let kinds = ["first-chunk", "first-16KiB", "middle-chunk", "last-chunk", "all"];
    let mut table: BTreeMap<(u8, &str), E1Row> = BTreeMap::new();
    let mut examples: Vec<String> = Vec::new();
    let mut total = 0u64;
    for bs in [0u8, 4] {
        let block = BlockSize::from_chunk_log(bs);
        for &n in &reals {
            let data = rand_data(&mut rng, n as usize);
            let root = blake3::hash(&data);
            let rc = chunks(n).max(1);
            for kind in kinds {
                let ranges = match kind {
                    "first-chunk" => ChunkRanges::from(ChunkNum(0)..ChunkNum(1)),
                    "first-16KiB" => ChunkRanges::from(ChunkNum(0)..ChunkNum(16)),
                    "middle-chunk" => ChunkRanges::from(ChunkNum(rc / 2)..ChunkNum(rc / 2 + 1)),
                    "last-chunk" => ChunkRanges::from(ChunkNum(rc - 1)..ChunkNum(rc)),
                    _ => ChunkRanges::all(),
                };
                // what an honest response for the real tree delivers
                let honest_bytes: u64 = {
                    let t = truncate(&ranges, n);
                    let mut b = 0;
                    for i in 0..rc {
                        if t.contains(&ChunkNum(i)) {
                            b += (n.min((i + 1) * CHUNK)).saturating_sub(i * CHUNK);
                        }
                    }
                    b
                };
                let row = table.entry((bs, kind)).or_default();
                let mut blob_has_alias = false;
                for &s in &claims {
                    if s > 64 * max_real && s < (1 << 32) {
                        continue;
                    }
                    total += 1;
                    row.cases += 1;
                    let claimed = BaoTree::new(s, block);
                    let res = std::panic::catch_unwind(|| {
                        let enc = liar_encode(&data, claimed, &ranges);
                        if s == n {
                            // self-check: with the true size the attacker model is the honest encoder
                            let ob = PreOrderMemOutboard::create(&data, block);
                            assert_eq!(enc, honest_encode(&data, &ob, &ranges), "model != honest at n={n} bs={bs} {kind}");
                        }
                        decode(&data, root, claimed, &enc, &ranges)
                    });
                    let d = match res {
                        Ok(d) => d,
                        Err(_) => {
                            eprintln!("panic: bs={bs} n={n} claimed={s} {kind}");
                            row.panics += 1;
                            continue;
                        }
                    };
                    if !d.sound {
                        row.unsound += 1;
                    }
                    if d.ok {
                        if s == n {
                            row.accepted_true += 1;
                        } else {
                            blob_has_alias = true;
                            row.accepted_alias += 1;
                            if s < n {
                                row.alias_smaller += 1;
                            } else {
                                row.alias_larger += 1;
                            }
                            let ratio = s as f64 / n.max(1) as f64;
                            if ratio > row.max_alias_ratio {
                                row.max_alias_ratio = ratio;
                            }
                            if d.delivered_bytes != honest_bytes {
                                row.alias_short_delivery += 1;
                                if examples.len() < 6 && kind == "middle-chunk" {
                                    examples.push(format!(
                                        "bs={bs} real={n} claimed={s} req={kind} -> accepted, delivered {:?} ({} B) instead of {} B",
                                        d.delivered, d.delivered_bytes, honest_bytes
                                    ));
                                }
                            }
                        }
                    }
                }
                if blob_has_alias {
                    row.blobs_with_alias += 1;
                }
            }
        }
    }
    println!(
        "{} real sizes x {} claimed sizes x {} request kinds x 2 block sizes = {} decodes",
        reals.len(),
        claims.len(),
        kinds.len(),
        total
    );
    println!("| block | request | cases | true size accepted | wrong size accepted | (smaller / larger) | blobs with >=1 alias | max claimed/real | accepted alias w/ different bytes delivered | unsound | panics |");
    println!("|---|---|---|---|---|---|---|---|---|---|---|");
    for ((bs, kind), r) in &table {
        println!(
            "| {} KiB | {} | {} | {} | {} | {} / {} | {}/{} | {:.3e} | {} | {} | {} |",
            1u64 << bs,
            kind,
            r.cases,
            r.accepted_true,
            r.accepted_alias,
            r.alias_smaller,
            r.alias_larger,
            r.blobs_with_alias,
            reals.len(),
            r.max_alias_ratio,
            r.alias_short_delivery,
            r.unsound,
            r.panics
        );
    }
    for e in examples {
        println!("  example: {e}");
    }

    // E1b: the alias window, as a function of the real size, for a first-chunk request.
    println!("\nE1b: alias window for a first-chunk request (bs=16 KiB), contiguous claimed sizes scanned byte-wise around the edges");
    println!("| real size | real chunks | accepted claimed sizes (min..=max) | width | all in window accepted? |");
    println!("|---|---|---|---|---|");
    for &n in &[1u64, 1024, 1025, 2048, 5000, 16 * 1024, 16 * 1024 + 1, 65 * 1024 + 1, 100_000, 1 << 20, (1 << 20) + 1] {
        let data = rand_data(&mut rng, n as usize);
        let root = blake3::hash(&data);
        let ranges = ChunkRanges::from(ChunkNum(0)..ChunkNum(1));
        let block = BlockSize::from_chunk_log(4);
        let ok = |s: u64| {
            let t = BaoTree::new(s, block);
            let enc = liar_encode(&data, t, &ranges);
            decode(&data, root, t, &enc, &ranges).ok
        };
        // the window is a union of contiguous intervals around n; find its edges by scanning
        // outward chunk by chunk and then byte-wise at the edge.
        let mut lo = n;
        while lo > 0 && ok(lo.saturating_sub(1024)) {
            lo = lo.saturating_sub(1024);
        }
        while lo > 0 && ok(lo - 1) {
            lo -= 1;
        }
        let mut hi = n;
        let mut step = 1024u64;
        while ok(hi + step) {
            hi += step;
            if hi > 64 * n.max(1024) {
                step = hi / 8;
            }
            if hi > 1 << 40 {
                break;
            }
        }
        while ok(hi + 1) {
            hi += 1;
        }
        // spot check contiguity on 2000 random points inside
        let mut contiguous = true;
        for _ in 0..2000 {
            let s = rng.random_range(lo..=hi);
            if !ok(s) {
                contiguous = false;
                break;
            }
        }
        println!("| {n} | {} | {lo}..={hi} | {} | {} |", chunks(n), hi - lo + 1, if contiguous { "yes (2000 samples)" } else { "no" });
    }
}

// ---------------------------------------------------------------- E2

#[derive(Default, Clone)]
struct E2Row {
    n: u64,
    rejected: u64,
    accepted_exact: u64,
    accepted_trailing: u64, // accepted with unread trailing bytes (mutation after the end)
    accepted_other: u64,
    unsound: u64,
    discarded_sum: u64, // on reject: bytes read from the stream minus verified bytes delivered
    discarded_max: u64,
    lost_sum: u64,
    lost_max: u64,
}

fn e2(iters: u64) {
    println!("\n== E2: mutation fuzz of honest responses ({iters} mutants per block size)");
    let muts = ["bitflip", "truncate", "insert-byte", "delete-byte", "append-garbage", "overwrite-64B-window", "swap-leaf-groups"];
    let mut table: BTreeMap<(u8, &str), E2Row> = BTreeMap::new();
    for bs in [0u8, 2, 4, 6] {
        let block = BlockSize::from_chunk_log(bs);
        let mut rng = SmallRng::seed_from_u64(100 + bs as u64);
        let mut i = 0;
        while i < iters {
            let n = match rng.random_range(0..4) {
                0 => rng.random_range(1..4096), // n = 0 encodes to an empty stream: nothing to mutate
                1 => rng.random_range(0..70_000),
                _ => rng.random_range(0..600_000),
            } as u64;
            let data = rand_data(&mut rng, n as usize);
            let ob = PreOrderMemOutboard::create(&data, block);
            let rc = chunks(n).max(1);
            let ranges = match rng.random_range(0..3) {
                0 => ChunkRanges::all(),
                1 => {
                    let a = rng.random_range(0..rc);
                    let b = rng.random_range(a + 1..=rc);
                    ChunkRanges::from(ChunkNum(a)..ChunkNum(b))
                }
                _ => {
                    let a = rng.random_range(0..rc);
                    let b = rng.random_range(a + 1..=rc);
                    let c = rng.random_range(0..rc);
                    ChunkRanges::from(ChunkNum(a)..ChunkNum(b)) | ChunkRanges::from(ChunkNum(c)..ChunkNum(c + 1))
                }
            };
            let enc = honest_encode(&data, &ob, &ranges);
            let base = decode(&data, ob.root, ob.tree, &enc, &ranges);
            assert!(base.ok && base.sound && base.trailing == 0);
            for _ in 0..8 {
                let m = muts[rng.random_range(0..muts.len())];
                let mut e = enc.clone();
                let len = e.len();
                match m {
                    "bitflip" => {
                        let p = rng.random_range(0..len);
                        e[p] ^= 1 << rng.random_range(0..8);
                    }
                    "truncate" => {
                        let p = rng.random_range(0..len);
                        e.truncate(p);
                    }
                    "insert-byte" => {
                        let p = rng.random_range(0..=len);
                        e.insert(p, rng.random());
                    }
                    "delete-byte" => {
                        let p = rng.random_range(0..len);
                        e.remove(p);
                    }
                    "append-garbage" => {
                        let k = rng.random_range(1..200);
                        for _ in 0..k {
                            e.push(rng.random());
                        }
                    }
                    "overwrite-64B-window" => {
                        if len < 128 {
                            e[0] ^= 1;
                        } else {
                            let a = rng.random_range(0..len - 64);
                            let b = rng.random_range(0..len - 64);
                            let w: Vec<u8> = e[a..a + 64].to_vec();
                            e[b..b + 64].copy_from_slice(&w);
                            if a == b {
                                e[b] ^= 1;
                            }
                        }
                    }
                    _ => {
                        // swap two whole data blocks inside the stream if there are >=2 full blocks
                        let g = block.bytes();
                        if data.len() >= 2 * g && matches!(ranges.boundaries(), [_]) {
                            // ranges == all: find the two blocks' positions by searching for them
                            let b0 = &data[0..g];
                            let b1 = &data[g..2 * g];
                            let p0 = find(&e, b0);
                            let p1 = find(&e, b1);
                            if let (Some(p0), Some(p1)) = (p0, p1) {
                                let t0 = e[p0..p0 + g].to_vec();
                                let t1 = e[p1..p1 + g].to_vec();
                                e[p0..p0 + g].copy_from_slice(&t1);
                                e[p1..p1 + g].copy_from_slice(&t0);
                            } else {
                                e[0] ^= 1;
                            }
                        } else {
                            e[len - 1] ^= 1;
                        }
                    }
                }
                let d = decode(&data, ob.root, ob.tree, &e, &ranges);
                let r = table.entry((bs, m)).or_default();
                r.n += 1;
                if !d.sound {
                    r.unsound += 1;
                }
                if d.ok {
                    if d.delivered == base.delivered && d.trailing == 0 {
                        r.accepted_exact += 1;
                    } else if d.delivered == base.delivered {
                        r.accepted_trailing += 1;
                    } else {
                        r.accepted_other += 1;
                    }
                } else {
                    r.rejected += 1;
                    // bytes read from the stream (parents + leaves) that never became delivered data
                    let disc = d.consumed.saturating_sub(d.delivered_bytes);
                    r.discarded_sum += disc;
                    r.discarded_max = r.discarded_max.max(disc);
                    // bytes read past the honest-stream position of the last delivered leaf:
                    // what an attacker makes us download and throw away at the failure point
                    let k = d.delivered.len();
                    let last_ok = if k == 0 { 0 } else { base.leaf_end[k - 1] };
                    let lost = d.consumed.saturating_sub(last_ok);
                    r.lost_sum += lost;
                    r.lost_max = r.lost_max.max(lost);
                }
                i += 1;
            }
        }
    }
    println!("| block | mutation | mutants | rejected | accepted, identical | accepted, trailing bytes unread | accepted, other | unsound deliveries | mean bytes read-not-delivered on reject (incl. parents) | max | mean bytes read past last delivered leaf | max |");
    println!("|---|---|---|---|---|---|---|---|---|---|---|---|");
    for ((bs, m), r) in &table {
        println!(
            "| {} KiB | {} | {} | {} | {} | {} | {} | {} | {:.0} | {} | {:.0} | {} |",
            1u64 << bs,
            m,
            r.n,
            r.rejected,
            r.accepted_exact,
            r.accepted_trailing,
            r.accepted_other,
            r.unsound,
            r.discarded_sum as f64 / r.rejected.max(1) as f64,
            r.discarded_max,
            r.lost_sum as f64 / r.rejected.max(1) as f64,
            r.lost_max
        );
    }
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

// ---------------------------------------------------------------- E3

fn e3() {
    println!("\n== E3: wire and storage overhead (bytes beyond payload), BLAKE3 hash of 64 B per parent pair");
    let mut rng = SmallRng::seed_from_u64(3);
    let sizes: [u64; 5] = [64 * 1024 + 1, 1 << 20, 16 << 20, 64 << 20, 256 << 20];
    println!("| blob size | chunk group | outboard stored | full fetch overhead | 1 MiB slice (middle) overhead | 1 chunk (middle) wire bytes | parents before first verified byte (full fetch) |");
    println!("|---|---|---|---|---|---|---|");
    let big = rand_data(&mut rng, *sizes.last().unwrap() as usize);
    for &n in &sizes {
        let data = &big[..n as usize];
        for bs in [0u8, 2, 4, 6, 8] {
            let block = BlockSize::from_chunk_log(bs);
            let ob = PreOrderMemOutboard::create(data, block);
            let rc = chunks(n);
            let full = honest_encode(data, &ob, &ChunkRanges::all());
            let mid = rc / 2;
            let slice = ChunkRanges::from(ChunkNum(mid.saturating_sub(512))..ChunkNum((mid + 512).min(rc)));
            let sl = honest_encode(data, &ob, &slice);
            let slice_payload = ((mid + 512).min(rc) * CHUNK).min(n) - mid.saturating_sub(512) * CHUNK;
            let one = honest_encode(data, &ob, &ChunkRanges::from(ChunkNum(mid)..ChunkNum(mid + 1)));
            // how many parent pairs precede the first leaf of a full fetch = tree depth above the block level
            let depth = {
                let mut d = 0;
                for item in ob.tree.ranges_pre_order_chunks_iter_ref(&ChunkRanges::all(), 0) {
                    match item {
                        bao_tree::iter::BaoChunk::Parent { .. } => d += 1,
                        _ => break,
                    }
                }
                d
            };
            println!(
                "| {} | {} KiB | {} B ({:.3} %) | {} B ({:.3} %) | {} B ({:.3} %) | {} B | {} ({} B) |",
                human(n),
                1u64 << bs,
                ob.data.len(),
                100.0 * ob.data.len() as f64 / n as f64,
                full.len() as u64 - n,
                100.0 * (full.len() as u64 - n) as f64 / n as f64,
                sl.len() as u64 - slice_payload,
                100.0 * (sl.len() as u64 - slice_payload) as f64 / slice_payload as f64,
                one.len(),
                depth,
                depth * 64
            );
        }
    }
}

fn human(n: u64) -> String {
    if n >= 1 << 20 && n % (1 << 20) == 0 {
        format!("{} MiB", n >> 20)
    } else {
        format!("{} B", n)
    }
}

// ---------------------------------------------------------------- E4

fn e4() {
    println!("\n== E4: single-thread throughput on 128 MiB (best of 3), release build");
    let mut rng = SmallRng::seed_from_u64(4);
    let n = 128usize << 20;
    let data = rand_data(&mut rng, n);
    let t = Instant::now();
    let _ = blake3::hash(&data);
    let plain = t.elapsed().as_secs_f64();
    println!("plain blake3::hash: {:.0} MiB/s", 128.0 / plain);
    println!("| chunk group | create outboard MiB/s | encode (validated) MiB/s | verify+decode MiB/s | decoder leaf items |");
    println!("|---|---|---|---|---|");
    for bs in [0u8, 2, 4, 6, 8] {
        let block = BlockSize::from_chunk_log(bs);
        let mut best = [f64::MAX; 3];
        let mut items = 0;
        for _ in 0..3 {
            let t = Instant::now();
            let ob = PreOrderMemOutboard::create(&data, block);
            best[0] = best[0].min(t.elapsed().as_secs_f64());
            let t = Instant::now();
            let enc = honest_encode(&data, &ob, &ChunkRanges::all());
            best[1] = best[1].min(t.elapsed().as_secs_f64());
            let t = Instant::now();
            let mut k = 0;
            for it in DecodeResponseIter::new(ob.root, ob.tree, Cursor::new(&enc[..]), &ChunkRanges::all()) {
                if let BaoContentItem::Leaf(_) = it.unwrap() {
                    k += 1;
                }
            }
            best[2] = best[2].min(t.elapsed().as_secs_f64());
            items = k;
        }
        println!(
            "| {} KiB | {:.0} | {:.0} | {:.0} | {} |",
            1u64 << bs,
            128.0 / best[0],
            128.0 / best[1],
            128.0 / best[2],
            items
        );
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let what = args.get(1).map(|s| s.as_str()).unwrap_or("all");
    let iters: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(200_000);
    if what == "e1" || what == "all" {
        e1();
    }
    if what == "e2" || what == "all" {
        e2(iters);
    }
    if what == "e3" || what == "all" {
        e3();
    }
    if what == "e4" || what == "all" {
        e4();
    }
}
