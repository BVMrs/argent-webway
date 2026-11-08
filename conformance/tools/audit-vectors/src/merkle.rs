//! RFC 9162 §2.1 Merkle tree, generic over the hash function. audit/v0 uses BLAKE3; the tests also run the
//! same code with SHA-256 against the Certificate Transparency reference roots, as an independent check.
//!
//! Generation (`root`, `path`, `consistency`) follows the recursive definitions of §2.1.1, §2.1.3.1 and
//! §2.1.4.1. Verification (`verify_inclusion`, `verify_consistency`) follows the iterative algorithms of
//! §2.1.3.2 and §2.1.4.2, so the two sides are written independently.

pub type H = [u8; 32];

pub trait Hasher {
    fn hash(parts: &[&[u8]]) -> H;
}

pub struct Blake3;
impl Hasher for Blake3 {
    fn hash(parts: &[&[u8]]) -> H {
        let mut h = blake3::Hasher::new();
        for p in parts {
            h.update(p);
        }
        *h.finalize().as_bytes()
    }
}

pub fn leaf<X: Hasher>(data: &[u8]) -> H {
    X::hash(&[&[0x00], data])
}

fn node<X: Hasher>(l: &H, r: &H) -> H {
    X::hash(&[&[0x01], l, r])
}

fn split(n: usize) -> usize {
    // largest power of two strictly less than n (n > 1)
    let mut k = 1;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// MTH over leaf hashes. `d` must be non-empty (audit/v0 has no empty tree).
pub fn root<X: Hasher>(d: &[H]) -> H {
    assert!(!d.is_empty());
    if d.len() == 1 {
        return d[0];
    }
    let k = split(d.len());
    node::<X>(&root::<X>(&d[..k]), &root::<X>(&d[k..]))
}

/// PATH(m, D[n]), RFC 9162 §2.1.3.1.
pub fn path<X: Hasher>(m: usize, d: &[H]) -> Vec<H> {
    let n = d.len();
    assert!(m < n);
    if n == 1 {
        return vec![];
    }
    let k = split(n);
    if m < k {
        let mut p = path::<X>(m, &d[..k]);
        p.push(root::<X>(&d[k..]));
        p
    } else {
        let mut p = path::<X>(m - k, &d[k..]);
        p.push(root::<X>(&d[..k]));
        p
    }
}

/// PROOF(m, D[n]), RFC 9162 §2.1.4.1. Empty when m == n.
pub fn consistency<X: Hasher>(m: usize, d: &[H]) -> Vec<H> {
    assert!(m >= 1 && m <= d.len());
    if m == d.len() {
        return vec![];
    }
    subproof::<X>(m, d, true)
}

fn subproof<X: Hasher>(m: usize, d: &[H], b: bool) -> Vec<H> {
    let n = d.len();
    if m == n {
        return if b { vec![] } else { vec![root::<X>(d)] };
    }
    let k = split(n);
    if m <= k {
        let mut p = subproof::<X>(m, &d[..k], b);
        p.push(root::<X>(&d[k..]));
        p
    } else {
        let mut p = subproof::<X>(m - k, &d[k..], false);
        p.push(root::<X>(&d[..k]));
        p
    }
}

/// RFC 9162 §2.1.3.2. Returns false for any out-of-range input or wrong-length proof.
pub fn verify_inclusion<X: Hasher>(index: u64, size: u64, leaf: &H, proof: &[H], root: &H) -> bool {
    if size == 0 || index >= size {
        return false;
    }
    let (mut fn_, mut sn) = (index, size - 1);
    let mut r = *leaf;
    for p in proof {
        if sn == 0 {
            return false;
        }
        if fn_ & 1 == 1 || fn_ == sn {
            r = node::<X>(p, &r);
            if fn_ & 1 == 0 {
                while fn_ & 1 == 0 && fn_ != 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            r = node::<X>(&r, p);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    sn == 0 && &r == root
}

/// RFC 9162 §2.1.4.2, with audit/v0's rule for equal sizes (AUD-121).
pub fn verify_consistency<X: Hasher>(n1: u64, n2: u64, r1: &H, r2: &H, proof: &[H]) -> bool {
    if n1 == 0 || n1 > n2 {
        return false;
    }
    if n1 == n2 {
        return proof.is_empty() && r1 == r2;
    }
    if proof.is_empty() {
        return false;
    }
    let mut proof: Vec<H> = proof.to_vec();
    if n1.is_power_of_two() {
        proof.insert(0, *r1);
    }
    let (mut fn_, mut sn) = (n1 - 1, n2 - 1);
    if fn_ & 1 == 1 {
        while fn_ & 1 == 1 {
            fn_ >>= 1;
            sn >>= 1;
        }
    }
    let (mut fr, mut sr) = (proof[0], proof[0]);
    for c in &proof[1..] {
        if sn == 0 {
            return false;
        }
        if fn_ & 1 == 1 || fn_ == sn {
            fr = node::<X>(c, &fr);
            sr = node::<X>(c, &sr);
            if fn_ & 1 == 0 {
                while fn_ & 1 == 0 && fn_ != 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            sr = node::<X>(&sr, c);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    &fr == r1 && &sr == r2 && sn == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    struct Sha256;
    impl Hasher for Sha256 {
        fn hash(parts: &[&[u8]]) -> H {
            let mut h = sha2::Sha256::new();
            for p in parts {
                h.update(p);
            }
            h.finalize().into()
        }
    }

    fn ct_leaves() -> Vec<H> {
        [
            "",
            "00",
            "10",
            "2021",
            "3031",
            "40414243",
            "5051525354555657",
            "606162636465666768696a6b6c6d6e6f",
        ]
        .iter()
        .map(|h| leaf::<Sha256>(&hex::decode(h).unwrap()))
        .collect()
    }

    /// Roots from the Certificate Transparency reference test data (RFC 6962 / RFC 9162 trees with SHA-256).
    #[test]
    fn ct_reference_roots() {
        let want = [
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
            "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
            "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
            "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
            "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
            "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
            "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
            "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
        ];
        let d = ct_leaves();
        for n in 1..=8 {
            assert_eq!(
                hex::encode(root::<Sha256>(&d[..n])),
                want[n - 1],
                "size {n}"
            );
        }
    }

    fn leaves(n: usize) -> Vec<H> {
        (0..n)
            .map(|i| leaf::<Blake3>(format!("entry {i}").as_bytes()))
            .collect()
    }

    #[test]
    fn generated_proofs_verify() {
        let d = leaves(70);
        for n in 1..=70usize {
            let r = root::<Blake3>(&d[..n]);
            for m in 0..n {
                let p = path::<Blake3>(m, &d[..n]);
                assert!(p.len() <= 7);
                assert!(
                    verify_inclusion::<Blake3>(m as u64, n as u64, &d[m], &p, &r),
                    "incl {m} {n}"
                );
                // wrong index or leaf fails
                if n > 1 {
                    let other = (m + 1) % n;
                    assert!(
                        !verify_inclusion::<Blake3>(other as u64, n as u64, &d[m], &p, &r)
                            || d[m] == d[other]
                    );
                }
                let mut longer = p.clone();
                longer.push(r);
                assert!(!verify_inclusion::<Blake3>(
                    m as u64, n as u64, &d[m], &longer, &r
                ));
                if !p.is_empty() {
                    assert!(!verify_inclusion::<Blake3>(
                        m as u64,
                        n as u64,
                        &d[m],
                        &p[..p.len() - 1],
                        &r
                    ));
                }
            }
            for m in 1..=n {
                let r1 = root::<Blake3>(&d[..m]);
                let p = consistency::<Blake3>(m, &d[..n]);
                // consistency proof length bound: ceil(log2 n) + 1
                let bound = (usize::BITS - (n - 1).leading_zeros()) as usize + 1;
                assert!(p.len() <= bound, "len {} > {bound} for {m}->{n}", p.len());
                assert!(
                    verify_consistency::<Blake3>(m as u64, n as u64, &r1, &r, &p),
                    "cons {m} {n}"
                );
                if m < n {
                    let wrong = leaf::<Blake3>(b"x");
                    assert!(!verify_consistency::<Blake3>(
                        m as u64, n as u64, &wrong, &r, &p
                    ));
                    assert!(!verify_consistency::<Blake3>(
                        m as u64, n as u64, &r1, &wrong, &p
                    ));
                    let mut longer = p.clone();
                    longer.push(r);
                    assert!(!verify_consistency::<Blake3>(
                        m as u64, n as u64, &r1, &r, &longer
                    ));
                    assert!(!verify_consistency::<Blake3>(
                        m as u64,
                        n as u64,
                        &r1,
                        &r,
                        &p[..p.len() - 1]
                    ));
                }
            }
        }
    }
}
