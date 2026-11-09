//! An independent model of the audit/v0 Merkle tree (spec/ext/audit.md §5.2-§5.3), written from the recursive
//! definitions of RFC 9162 §2.1 and NOT from `ct-merkle` or the bit-twiddling verifier in
//! `conformance/tools/audit-vectors/src/merkle.rs`.
//!
//! The verifiers here walk the MTH split recursively (k = largest power of two < n) and consume the proof from
//! its end, so they need no tree and work for any u64 size. Recursion depth is at most 64.

pub type H = [u8; 32];

pub fn leaf(data: &[u8]) -> H {
    *blake3::Hasher::new().update(&[0]).update(data).finalize().as_bytes()
}

pub fn node(l: &H, r: &H) -> H {
    *blake3::Hasher::new().update(&[1]).update(l).update(r).finalize().as_bytes()
}

/// Largest power of two strictly less than n (n >= 2).
pub fn split(n: u64) -> u64 {
    debug_assert!(n >= 2);
    1u64 << (63 - (n - 1).leading_zeros())
}

/// MTH(D[n]) for n >= 1.
pub fn mth(d: &[H]) -> H {
    if d.len() == 1 {
        return d[0];
    }
    let k = split(d.len() as u64) as usize;
    node(&mth(&d[..k]), &mth(&d[k..]))
}

/// PATH(m, D[n]), RFC 9162 §2.1.3.1.
pub fn path(m: usize, d: &[H]) -> Vec<H> {
    if d.len() == 1 {
        return vec![];
    }
    let k = split(d.len() as u64) as usize;
    if m < k {
        let mut p = path(m, &d[..k]);
        p.push(mth(&d[k..]));
        p
    } else {
        let mut p = path(m - k, &d[k..]);
        p.push(mth(&d[..k]));
        p
    }
}

/// PROOF(m, D[n]), RFC 9162 §2.1.4.1 (empty for m == n).
pub fn proof(m: usize, d: &[H]) -> Vec<H> {
    fn sub(m: usize, d: &[H], b: bool) -> Vec<H> {
        let n = d.len();
        if m == n {
            return if b { vec![] } else { vec![mth(d)] };
        }
        let k = split(n as u64) as usize;
        if m <= k {
            let mut p = sub(m, &d[..k], b);
            p.push(mth(&d[k..]));
            p
        } else {
            let mut p = sub(m - k, &d[k..], false);
            p.push(mth(&d[..k]));
            p
        }
    }
    sub(m, d, true)
}

/// Length of PATH(i, D[n]) from the shape alone.
pub fn path_len(i: u64, n: u64) -> usize {
    if n == 1 {
        return 0;
    }
    let k = split(n);
    1 + if i < k { path_len(i, k) } else { path_len(i - k, n - k) }
}

/// Length of PROOF(m, D[n]) from the shape alone.
pub fn proof_len(m: u64, n: u64) -> usize {
    fn sub(m: u64, n: u64, b: bool) -> usize {
        if m == n {
            return if b { 0 } else { 1 };
        }
        let k = split(n);
        1 + if m <= k { sub(m, k, b) } else { sub(m - k, n - k, false) }
    }
    sub(m, n, true)
}

/// Root implied by `leaf` at index i of size n and the proof; None if the proof has the wrong length.
pub fn climb(i: u64, n: u64, leaf: &H, p: &[H]) -> Option<H> {
    if n == 1 {
        return p.is_empty().then_some(*leaf);
    }
    let (last, rest) = p.split_last()?;
    let k = split(n);
    Some(if i < k {
        node(&climb(i, k, leaf, rest)?, last)
    } else {
        node(last, &climb(i - k, n - k, leaf, rest)?)
    })
}

pub fn verify_inclusion(i: u64, n: u64, leaf: &H, p: &[H], root: &H) -> bool {
    n >= 1 && i < n && climb(i, n, leaf, p).as_ref() == Some(root)
}

/// (old root, new root) implied by a consistency proof from m to n. `r1` is used only where RFC 9162 omits the
/// old root (the b = true, m = n leaf of the recursion). None if the proof has the wrong length.
pub fn cons_roots(m: u64, n: u64, r1: &H, p: &[H]) -> Option<(H, H)> {
    fn sub(m: u64, n: u64, b: bool, r1: &H, p: &[H]) -> Option<(H, H)> {
        if m == n {
            return if b {
                p.is_empty().then_some((*r1, *r1))
            } else {
                (p.len() == 1).then(|| (p[0], p[0]))
            };
        }
        let (last, rest) = p.split_last()?;
        let k = split(n);
        if m <= k {
            let (o, nw) = sub(m, k, b, r1, rest)?;
            Some((o, node(&nw, last)))
        } else {
            let (o, nw) = sub(m - k, n - k, false, r1, rest)?;
            Some((node(last, &o), node(last, &nw)))
        }
    }
    sub(m, n, true, r1, p)
}

pub fn verify_consistency(m: u64, n: u64, r1: &H, r2: &H, p: &[H]) -> bool {
    if m == 0 || m > n {
        return false;
    }
    if m == n {
        return p.is_empty() && r1 == r2;
    }
    cons_roots(m, n, r1, p) == Some((*r1, *r2))
}
