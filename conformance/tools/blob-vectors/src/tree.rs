//! The blob/v0 hash tree, encoding and verification (spec/ext/blob.md §3 and §5).
//!
//! The tree is BLAKE3's own tree, cut off at blocks of `BLOCK` bytes (16 chunks of 1024 bytes).
//! The root of the tree is the ordinary BLAKE3 hash of the content. The encoding of a set of
//! block ranges is the pre-order walk of the tree: for every parent node whose blocks intersect
//! the ranges, the 64 bytes `left CV || right CV`, then the bytes of every selected block. This is
//! the bao encoding with 16 KiB chunk groups that `bao-tree` and `iroh-blobs` use. The tests in
//! `tests/bao_compat.rs` check this against `bao-tree`.

use blake3::hazmat::{merge_subtrees_non_root, merge_subtrees_root, ChainingValue, HasherExt, Mode};

pub const BLOCK: u64 = 16 * 1024;
pub const PAIR: usize = 64;

/// A canonical set of block ranges: sorted, each `start < end`, gaps between ranges.
pub type Ranges = Vec<(u64, u64)>;

/// Number of blocks of a blob of `size` bytes. The empty blob has one empty block.
pub fn blocks(size: u64) -> u64 {
    if size == 0 {
        1
    } else {
        size.div_ceil(BLOCK)
    }
}

/// Number of blocks in the left subtree of a node that spans `n >= 2` blocks: the largest power
/// of two strictly less than `n` (BLAKE3's rule, expressed in blocks).
pub fn left_blocks(n: u64) -> u64 {
    debug_assert!(n >= 2);
    1u64 << (63 - (n - 1).leading_zeros())
}

fn block_bytes(data: &[u8], i: u64) -> &[u8] {
    let start = (i * BLOCK) as usize;
    let end = ((i + 1) * BLOCK).min(data.len() as u64) as usize;
    &data[start.min(data.len())..end]
}

fn block_len(size: u64, i: u64) -> u64 {
    ((i + 1) * BLOCK).min(size) - (i * BLOCK).min(size)
}

fn leaf_cv(bytes: &[u8], index: u64, is_root: bool) -> ChainingValue {
    if is_root {
        *blake3::hash(bytes).as_bytes()
    } else {
        let mut h = blake3::Hasher::new();
        h.set_input_offset(index * BLOCK);
        h.update(bytes);
        h.finalize_non_root()
    }
}

fn parent_cv(l: &ChainingValue, r: &ChainingValue, is_root: bool) -> ChainingValue {
    if is_root {
        *merge_subtrees_root(l, r, Mode::Hash).as_bytes()
    } else {
        merge_subtrees_non_root(l, r, Mode::Hash)
    }
}

/// Chaining value of the node spanning blocks `lo..hi` (root hash if `is_root`).
fn node_cv(data: &[u8], lo: u64, hi: u64, is_root: bool) -> ChainingValue {
    if hi - lo == 1 {
        return leaf_cv(block_bytes(data, lo), lo, is_root);
    }
    let mid = lo + left_blocks(hi - lo);
    parent_cv(&node_cv(data, lo, mid, false), &node_cv(data, mid, hi, false), is_root)
}

pub fn hash(data: &[u8]) -> [u8; 32] {
    node_cv(data, 0, blocks(data.len() as u64), true)
}

fn intersects(ranges: &Ranges, lo: u64, hi: u64) -> bool {
    ranges.iter().any(|&(a, b)| a < hi && lo < b)
}

/// Encode `ranges` (already effective, see `effective`) of `data`.
pub fn encode(data: &[u8], ranges: &Ranges) -> Vec<u8> {
    let mut out = Vec::new();
    enc(data, 0, blocks(data.len() as u64), ranges, &mut out);
    out
}

fn enc(data: &[u8], lo: u64, hi: u64, ranges: &Ranges, out: &mut Vec<u8>) {
    if !intersects(ranges, lo, hi) {
        return;
    }
    if hi - lo == 1 {
        out.extend_from_slice(block_bytes(data, lo));
        return;
    }
    let mid = lo + left_blocks(hi - lo);
    out.extend_from_slice(&node_cv(data, lo, mid, false));
    out.extend_from_slice(&node_cv(data, mid, hi, false));
    enc(data, lo, mid, ranges, out);
    enc(data, mid, hi, ranges, out);
}

/// Length of the encoding of `ranges` for a blob of `size` bytes.
pub fn encoded_len(size: u64, ranges: &Ranges) -> u64 {
    fn walk(size: u64, lo: u64, hi: u64, ranges: &Ranges) -> u64 {
        if !intersects(ranges, lo, hi) {
            return 0;
        }
        if hi - lo == 1 {
            return block_len(size, lo);
        }
        let mid = lo + left_blocks(hi - lo);
        PAIR as u64 + walk(size, lo, mid, ranges) + walk(size, mid, hi, ranges)
    }
    walk(size, 0, blocks(size), ranges)
}

#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// A parent pair or block does not match the expected chaining value.
    Corrupt,
    /// Bytes follow the complete encoding.
    TrailingBytes,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Verified {
    /// Blocks verified, in order, as canonical ranges.
    pub blocks: Ranges,
    /// Whether every block of `ranges` was verified.
    pub complete: bool,
}

/// Verify an encoding of `ranges` against `hash`, assuming the blob has `size` bytes.
///
/// A stream that ends early is not an error: the blocks verified so far are returned and
/// `complete` is false. Data that does not match is `Corrupt`, extra bytes are `TrailingBytes`.
pub fn verify(hash: &[u8; 32], size: u64, ranges: &Ranges, enc: &[u8]) -> Result<Verified, VerifyError> {
    struct St<'a> {
        size: u64,
        ranges: &'a Ranges,
        enc: &'a [u8],
        pos: usize,
        got: Vec<u64>,
        cut: bool,
    }
    fn take<'a>(st: &mut St<'a>, n: usize) -> Option<&'a [u8]> {
        if st.enc.len() - st.pos < n {
            st.cut = true;
            return None;
        }
        let s = &st.enc[st.pos..st.pos + n];
        st.pos += n;
        Some(s)
    }
    fn walk(st: &mut St, lo: u64, hi: u64, expect: ChainingValue, is_root: bool) -> Result<(), VerifyError> {
        if st.cut || !intersects(st.ranges, lo, hi) {
            return Ok(());
        }
        if hi - lo == 1 {
            let n = block_len(st.size, lo) as usize;
            let Some(bytes) = take(st, n) else { return Ok(()) };
            if leaf_cv(bytes, lo, is_root) != expect {
                return Err(VerifyError::Corrupt);
            }
            st.got.push(lo);
            return Ok(());
        }
        let Some(pair) = take(st, PAIR) else { return Ok(()) };
        let l: ChainingValue = pair[..32].try_into().unwrap();
        let r: ChainingValue = pair[32..].try_into().unwrap();
        if parent_cv(&l, &r, is_root) != expect {
            return Err(VerifyError::Corrupt);
        }
        let mid = lo + left_blocks(hi - lo);
        walk(st, lo, mid, l, false)?;
        walk(st, mid, hi, r, false)
    }
    let mut st = St { size, ranges, enc, pos: 0, got: vec![], cut: false };
    walk(&mut st, 0, blocks(size), *hash, true)?;
    if !st.cut && st.pos != enc.len() {
        return Err(VerifyError::TrailingBytes);
    }
    let want: u64 = ranges.iter().map(|&(a, b)| b - a).sum();
    Ok(Verified { complete: st.got.len() as u64 == want, blocks: to_ranges(&st.got) })
}

/// Canonical ranges from a sorted list of block indices.
pub fn to_ranges(blocks: &[u64]) -> Ranges {
    let mut out: Ranges = vec![];
    for &b in blocks {
        match out.last_mut() {
            Some((_, e)) if *e == b => *e += 1,
            _ => out.push((b, b + 1)),
        }
    }
    out
}

/// The effective ranges of a request for a blob with `n` blocks (spec BLOB-023): requested blocks
/// below `n`, plus the last block if any requested range reaches past the end.
pub fn effective(requested: &Ranges, n: u64) -> Ranges {
    let mut out: Ranges = vec![];
    let mut past_end = false;
    for &(a, b) in requested {
        if b > n {
            past_end = true;
        }
        let (a, b) = (a.min(n), b.min(n));
        if a < b {
            out.push((a, b));
        }
    }
    if past_end {
        out.push((n - 1, n));
    }
    normalise(out)
}

/// Sort and merge overlapping or adjacent ranges.
pub fn normalise(mut r: Ranges) -> Ranges {
    r.sort();
    let mut out: Ranges = vec![];
    for (a, b) in r {
        match out.last_mut() {
            Some((_, e)) if a <= *e => *e = (*e).max(b),
            _ => out.push((a, b)),
        }
    }
    out
}

pub fn intersect(x: &Ranges, y: &Ranges) -> Ranges {
    let mut out = vec![];
    for &(a, b) in x {
        for &(c, d) in y {
            let (s, e) = (a.max(c), b.min(d));
            if s < e {
                out.push((s, e));
            }
        }
    }
    normalise(out)
}

pub fn subtract(x: &Ranges, y: &Ranges) -> Ranges {
    let mut out = vec![];
    for &(a, b) in x {
        let mut cur = a;
        for &(c, d) in y {
            if d <= cur || c >= b {
                continue;
            }
            if c > cur {
                out.push((cur, c));
            }
            cur = cur.max(d);
        }
        if cur < b {
            out.push((cur, b));
        }
    }
    normalise(out)
}

/// Test content: byte `i` is `i mod 251`, the input pattern of the official BLAKE3 test vectors.
pub fn pattern(n: u64) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_is_blake3() {
        for n in [0u64, 1, 1023, 1024, 1025, 16383, 16384, 16385, 32768, 49153, 100_000, 1 << 20] {
            let d = pattern(n);
            assert_eq!(hash(&d), *blake3::hash(&d).as_bytes(), "size {n}");
        }
    }

    #[test]
    fn roundtrip_and_cut() {
        let d = pattern(200_000);
        let h = hash(&d);
        let n = blocks(d.len() as u64);
        for r in [vec![(0, n)], vec![(3, 4)], vec![(0, 1), (5, 7), (12, 13)]] {
            let e = encode(&d, &r);
            assert_eq!(e.len() as u64, encoded_len(d.len() as u64, &r));
            let v = verify(&h, d.len() as u64, &r, &e).unwrap();
            assert!(v.complete);
            assert_eq!(v.blocks, r);
            let cut = verify(&h, d.len() as u64, &r, &e[..e.len() - 1]).unwrap();
            assert!(!cut.complete);
        }
    }

    #[test]
    fn range_algebra() {
        assert_eq!(effective(&vec![(0, 100)], 7), vec![(0, 7)]);
        assert_eq!(effective(&vec![(9, 10)], 7), vec![(6, 7)]);
        assert_eq!(effective(&vec![(1, 2), (9, 10)], 7), vec![(1, 2), (6, 7)]);
        assert_eq!(subtract(&vec![(0, 10)], &vec![(2, 4), (6, 7)]), vec![(0, 2), (4, 6), (7, 10)]);
        assert_eq!(intersect(&vec![(0, 5)], &vec![(3, 9)]), vec![(3, 5)]);
    }
}
