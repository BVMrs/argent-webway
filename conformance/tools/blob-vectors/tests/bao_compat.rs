//! The blob/v0 encoding is the one `bao-tree` (and so `iroh-blobs`) produces with 16 KiB chunk
//! groups. These tests compare the reference model in `src/tree.rs` with `bao-tree` 0.17 in both
//! directions: same bytes when encoding, and each accepts what the other produced.

#[path = "../src/tree.rs"]
#[allow(dead_code)]
mod tree;

use bao_tree::io::outboard::PreOrderOutboard;
use bao_tree::io::sync::{decode_ranges, encode_ranges_validated, CreateOutboard};
use bao_tree::{BlockSize, ChunkNum, ChunkRanges};

const BS: BlockSize = BlockSize::from_chunk_log(4);

fn chunk_ranges(r: &tree::Ranges) -> ChunkRanges {
    let mut out = ChunkRanges::empty();
    for &(a, b) in r {
        out |= ChunkRanges::from(ChunkNum(a * 16)..ChunkNum(b * 16));
    }
    out
}

fn cases() -> Vec<(u64, tree::Ranges)> {
    let mut v = vec![];
    for size in [0u64, 1, 1024, 16384, 16385, 32768, 49152, 49153, 65537, 100_000, 300_000, 1 << 20] {
        let n = tree::blocks(size);
        v.push((size, vec![(0, n)]));
        v.push((size, vec![(n - 1, n)]));
        v.push((size, vec![(0, 1)]));
        if n > 4 {
            v.push((size, vec![(1, 2), (3, n - 1)]));
            v.push((size, tree::normalise(vec![(0, 1), (n / 2, n / 2 + 1), (n - 1, n)])));
        }
    }
    v
}

#[test]
fn same_bytes_as_bao_tree() {
    for (size, r) in cases() {
        let data = tree::pattern(size);
        let ob = PreOrderOutboard::<Vec<u8>>::create(std::io::Cursor::new(&data), BS).unwrap();
        assert_eq!(*ob.root.as_bytes(), tree::hash(&data), "root, size {size}");
        let mut theirs = vec![];
        encode_ranges_validated(&data[..], &ob, &chunk_ranges(&r), &mut theirs).unwrap();
        let ours = tree::encode(&data, &r);
        assert_eq!(ours.len(), theirs.len(), "length, size {size}, ranges {r:?}");
        assert!(ours == theirs, "bytes differ, size {size}, ranges {r:?}");
        assert_eq!(ours.len() as u64, tree::encoded_len(size, &r));
    }
}

#[test]
fn bao_tree_accepts_ours_and_rejects_a_flip() {
    for (size, r) in cases() {
        let data = tree::pattern(size);
        let src = PreOrderOutboard::<Vec<u8>>::create(std::io::Cursor::new(&data), BS).unwrap();
        let enc = tree::encode(&data, &r);
        let mut ob = PreOrderOutboard { tree: src.tree, root: src.root, data: vec![] };
        let mut target: Vec<u8> = vec![];
        decode_ranges(std::io::Cursor::new(&enc), &chunk_ranges(&r), &mut target, &mut ob)
            .unwrap_or_else(|e| panic!("bao-tree rejected size {size} ranges {r:?}: {e:?}"));
        if !enc.is_empty() {
            let mut bad = enc.clone();
            let i = bad.len() / 2;
            bad[i] ^= 1;
            let mut ob = PreOrderOutboard { tree: src.tree, root: src.root, data: vec![] };
            let mut target: Vec<u8> = vec![];
            assert!(
                decode_ranges(std::io::Cursor::new(&bad), &chunk_ranges(&r), &mut target, &mut ob).is_err(),
                "bao-tree accepted a flipped byte, size {size}"
            );
            assert_eq!(
                tree::verify(&tree::hash(&data), size, &r, &bad),
                Err(tree::VerifyError::Corrupt),
                "model accepted a flipped byte, size {size}"
            );
        }
    }
}
