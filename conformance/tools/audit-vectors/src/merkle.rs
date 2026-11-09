//! The audit/v0 Merkle tree: RFC 9162 §2.1 with BLAKE3, built on the `ct-merkle` crate.
//!
//! `ct-merkle` builds the tree, its roots and its inclusion and consistency proofs, and verifies consistency
//! proofs. The one thing it cannot do is verify an inclusion proof from a leaf *hash*: it only takes the leaf
//! value. audit/v0 needs exactly that, because a proof response carries the entry hash and discloses the entry
//! only on request (spec/ext/audit.md AUD-120, AUD-302). So `verify_inclusion` below is RFC 9162 §2.1.3.2,
//! written out.

use ct_merkle::mem_backed_tree::MemoryBackedTree;
use ct_merkle::{ConsistencyProof, RootHash};

pub type H = [u8; 32];
type Hasher = blake3::Hasher;

/// A tree over leaf values. Each value is the JCS bytes of an entry, so its leaf hash is the entry hash.
pub type Tree = MemoryBackedTree<Hasher, Vec<u8>>;

pub fn tree(leaf_values: impl IntoIterator<Item = Vec<u8>>) -> Tree {
    let mut t = Tree::new();
    for v in leaf_values {
        t.push(v);
    }
    t
}

/// The leaf hash BLAKE3(0x00 ‖ data), which is what `ct-merkle` computes for a leaf value.
pub fn leaf(data: &[u8]) -> H {
    *blake3::Hasher::new()
        .update(&[0x00])
        .update(data)
        .finalize()
        .as_bytes()
}

fn node(l: &H, r: &H) -> H {
    *blake3::Hasher::new()
        .update(&[0x01])
        .update(l)
        .update(r)
        .finalize()
        .as_bytes()
}

fn chunks(bytes: &[u8]) -> Vec<H> {
    bytes.chunks(32).map(|c| c.try_into().unwrap()).collect()
}

/// MTH(D[n]). The tree must be non-empty (audit/v0 has no empty tree).
pub fn root(t: &Tree) -> H {
    assert!(!t.is_empty());
    (*t.root().as_bytes()).into()
}

/// PATH(m, D[n]), RFC 9162 §2.1.3.1.
pub fn path(t: &Tree, m: usize) -> Vec<H> {
    chunks(t.prove_inclusion(m).as_bytes())
}

/// PROOF(m, D[n]), RFC 9162 §2.1.4.1. Empty when m == n.
pub fn consistency(t: &Tree, m: usize) -> Vec<H> {
    let n = t.len() as usize;
    assert!(m >= 1 && m <= n);
    if m == n {
        return vec![];
    }
    chunks(t.prove_consistency(n - m).as_bytes())
}

/// RFC 9162 §2.1.3.2, from a leaf hash. Returns false for any out-of-range input or wrong-length proof.
pub fn verify_inclusion(index: u64, size: u64, leaf: &H, proof: &[H], root: &H) -> bool {
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
            r = node(p, &r);
            if fn_ & 1 == 0 {
                while fn_ & 1 == 0 && fn_ != 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            r = node(&r, p);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    sn == 0 && &r == root
}

/// RFC 9162 §2.1.4.2 via `ct-merkle`, with audit/v0's rule for equal sizes (AUD-121): the proof must be empty
/// and the roots equal.
pub fn verify_consistency(n1: u64, n2: u64, r1: &H, r2: &H, proof: &[H]) -> bool {
    if n1 == 0 || n1 > n2 {
        return false;
    }
    if n1 == n2 {
        return proof.is_empty() && r1 == r2;
    }
    let Ok(proof) = ConsistencyProof::<Hasher>::try_from_bytes(proof.concat()) else {
        return false;
    };
    let old = RootHash::<Hasher>::new((*r1).into(), n1);
    let new = RootHash::<Hasher>::new((*r2).into(), n2);
    new.verify_consistency(&old, &proof).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Roots from the Certificate Transparency reference test data (RFC 6962 / RFC 9162 trees with SHA-256),
    /// to check that `ct-merkle` builds the tree shape and prefixes RFC 9162 specifies.
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
        let data = [
            "",
            "00",
            "10",
            "2021",
            "3031",
            "40414243",
            "5051525354555657",
            "606162636465666768696a6b6c6d6e6f",
        ];
        let mut t = MemoryBackedTree::<sha2::Sha256, Vec<u8>>::new();
        for (n, d) in data.iter().enumerate() {
            t.push(hex::decode(d).unwrap());
            assert_eq!(hex::encode(t.root().as_bytes()), want[n], "size {}", n + 1);
        }
    }

    #[test]
    fn leaf_matches_ct_merkle() {
        let t = tree([b"entry".to_vec()]);
        assert_eq!(root(&t), leaf(b"entry"));
    }

    #[test]
    fn generated_proofs_verify() {
        let values: Vec<Vec<u8>> = (0..70).map(|i| format!("entry {i}").into_bytes()).collect();
        let d: Vec<H> = values.iter().map(|v| leaf(v)).collect();
        for n in 1..=70usize {
            let t = tree(values[..n].iter().cloned());
            let r = root(&t);
            for m in 0..n {
                let p = path(&t, m);
                assert!(p.len() <= 7);
                assert!(
                    verify_inclusion(m as u64, n as u64, &d[m], &p, &r),
                    "incl {m} {n}"
                );
                if n > 1 {
                    let other = (m + 1) % n;
                    assert!(!verify_inclusion(other as u64, n as u64, &d[m], &p, &r));
                }
                let mut longer = p.clone();
                longer.push(r);
                assert!(!verify_inclusion(m as u64, n as u64, &d[m], &longer, &r));
                if !p.is_empty() {
                    assert!(!verify_inclusion(
                        m as u64,
                        n as u64,
                        &d[m],
                        &p[..p.len() - 1],
                        &r
                    ));
                }
            }
            for m in 1..=n {
                let r1 = root(&tree(values[..m].iter().cloned()));
                let p = consistency(&t, m);
                let bound = (usize::BITS - (n - 1).leading_zeros()) as usize + 1;
                assert!(p.len() <= bound, "len {} > {bound} for {m}->{n}", p.len());
                assert!(
                    verify_consistency(m as u64, n as u64, &r1, &r, &p),
                    "cons {m} {n}"
                );
                if m < n {
                    let wrong = leaf(b"x");
                    assert!(!verify_consistency(m as u64, n as u64, &wrong, &r, &p));
                    assert!(!verify_consistency(m as u64, n as u64, &r1, &wrong, &p));
                    let mut longer = p.clone();
                    longer.push(r);
                    assert!(!verify_consistency(m as u64, n as u64, &r1, &r, &longer));
                    assert!(!verify_consistency(
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
