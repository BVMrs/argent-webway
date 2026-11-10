# Lab 2026-11-09: blob/v0 over bao-tree: size authentication, hostile providers, chunk-group size

## Question

`blob/v0` (due diligence §4.5, roadmap T8, M1 step 5) sends large Parts by reference as
`webway-blob:blake3:<hash>?size=…&providers=wwn:…`. The receiver fetches them from one or more providers with
BLAKE3 verified streaming (bao, as in `iroh-blobs`). The root hash authenticates content. Nothing in the design
yet says what authenticates the **size**, which bytes a provider can make a receiver download and throw away, or
which **chunk-group size** the wire format uses. No lab entry covers blob/v0 yet. This lab asks three things:

1. A hostile provider sends a wrong size header but only has the real blob. For which claimed sizes and
   request shapes does the response still verify? Does the receiver ever get wrong or missing bytes?
2. Under random corruption of honest responses, does the decoder ever deliver an unverified byte? Does it
   silently accept anything? How much does a bad provider waste per detection, at each chunk-group size?
3. What does each chunk-group size cost in outboard storage, wire overhead and verification throughput?

## Method

`lab/blob-bao-size-auth/` is a Rust crate (the core language, CPU only). It uses `bao-tree` 0.17.0, the layer
under `iroh-blobs`, and `blake3` 1.8.7. Run it with `cargo run --release -- [e1|e2|e3|e4] [iters]`. Raw output is
in `out/`.

| Exp | What it does |
|---|---|
| E1 | 286 real sizes (every chunk boundary ±1 and mid-chunk up to 70 chunks, plus 64 KiB+1, ~300 KiB, 1 MiB, 1 MiB+1) × 1 383 claimed sizes (a grid up to 4× the largest real size, every real ±{0,1,2,1023,1024,1025}, 2×real, and 2^32 … u64::MAX) × 5 request shapes × chunk groups {1 KiB, 16 KiB} = **3 955 380 decodes**. The attacker is the strongest collision-free provider: it walks the *claimed* tree exactly as `DecodeResponseIter` does (`iter::ResponseIterRef`) and mirrors that descent through the *real* tree, sending real hash pairs and real bytes. Any other byte fails the first hash check it reaches, so if this response fails, every response fails. Self-check: at the true size, the attacker's bytes equal `encode_ranges_validated` byte for byte in every case. |
| E1b | For a first-chunk request, the exact set of accepted claimed sizes, scanned byte by byte at the edges and checked at 2 000 random interior points. |
| E2 | 200 000 mutants per chunk group (1, 4, 16, 64 KiB), 800 000 in total. Blobs are 1 B – 600 KB, requests are all / a random range / a range plus one chunk. Mutations are a bit flip, truncation, inserting or deleting a byte, appending garbage, overwriting with a 64 B window copied from elsewhere, and swapping two data groups. Checks: every delivered leaf equals the real bytes at its offset (soundness); whether the decode is accepted; bytes read past the last good leaf before the error. |
| E3 | Outboard size and wire bytes for a full fetch, a 1 MiB slice in the middle, and one chunk in the middle. Blobs of 64 KiB+1 B to 256 MiB, chunk groups 1–256 KiB. |
| E4 | Single-thread throughput on 128 MiB (best of 3): outboard creation, validated encode, verify+decode, against plain `blake3::hash`. |

## Results

### E1: the size header is unauthenticated unless the response covers the last chunk

| request | chunk group | true size accepted | **wrong size accepted** | blobs with ≥ 1 alias | max claimed/real | aliases that changed delivered bytes | unsound | panics |
|---|---|---|---|---|---|---|---|---|
| all | 1 / 16 KiB | 286/286 | **0** | 0 | n/a | 0 | 0 | 0 |
| last chunk | 1 / 16 KiB | 286/286 | **0** | 0 | n/a | 0 | 0 | 0 |
| first chunk | 1 / 16 KiB | 286/286 | **75 702** (33 945 smaller, 41 757 larger) | 281/286 | 2.0 | 0 | 0 | 0 |
| middle chunk | 1 / 16 KiB | 286/286 | **74 156** | 277/286 | 2.0 | 0 | 0 | 0 |
| first 16 KiB | 1 / 16 KiB | 286/286 | **71 682** | 221/286 | 2.0 | 0 | 0 | 0 |

The two chunk-group sizes give identical counts. The 5 / 9 / 65 blobs without aliases are exactly those for which
the request already reaches the last chunk, either directly or because bao-tree's `truncate_ranges` turns a request
past the end into one for the last chunk.

E1b gives the exact window. A request that does not reach the last chunk verifies for **every claimed size whose
chunk count is in the same power-of-two bracket (2^k, 2^(k+1)] as the real chunk count**:

| real size | accepted claimed sizes | width |
|---|---|---|
| 1 025 | 1 025 ..= 2 048 | 1 024 |
| 5 000 | 4 097 ..= 8 192 | 4 096 |
| 66 561 (just over the 64 KiB inline threshold) | 65 537 ..= 131 072 | 65 536 |
| 1 048 576 | 524 289 ..= 1 048 576 | 524 288 |
| 1 048 577 | 1 048 577 ..= 2 097 152 | 1 048 576 |

This is BLAKE3's tree shape. The root's left subtree is the largest power of two below the chunk count, so every
size with the same split produces the same proof for interior chunks. This matches the iroh-blobs design note
("after the first validated chunk … the uncertainty is only a factor of 2"). The new parts are the exact bracket
and the confirmation that the attacker cannot do better. **Soundness held everywhere**: no alias ever delivered a
wrong byte or a different byte range than an honest response. Claimed sizes up to u64::MAX caused no panic in the
decoder. The decoder allocates only one chunk group. Any harm comes from a caller that trusts the header: it
might preallocate, report a size, or plan ranges from it.

### E2: corruption is always caught, except bytes after the end

| chunk group | mutants | unsound deliveries | silent accepts other than trailing bytes | appended garbage accepted | mean / max bytes read past the last good leaf on reject |
|---|---|---|---|---|---|
| 1 KiB | 200 000 | **0** | 0 | 28 579 / 28 579 (+25 inserts at the end) | 967 / 1 664 |
| 4 KiB | 200 000 | **0** | 0 | 28 736 / 28 736 (+23) | 2 913 / 4 608 |
| 16 KiB | 200 000 | **0** | 0 | 28 663 / 28 663 (+16) | 8 188 / 16 768 |
| 64 KiB | 200 000 | **0** | 0 | 28 750 / 28 750 (+28) | 21 270 / 65 792 |

- Every bit flip, truncation, insertion, deletion, 64 B window copy and group swap inside the response was
  rejected (all mutation classes, every group size). No unverified byte ever reached the caller.
- **100 % of appended-garbage mutants were accepted.** `DecodeResponseIter` stops after the last expected item and
  never reads further, so trailing bytes are invisible to it. Any end-of-response check must come from the binding.
- A hostile or broken provider wastes at most **one chunk group plus its in-group hashes** per detection: about
  16.4 KiB at 16 KiB groups and 64.3 KiB at 64 KiB groups. Then the receiver switches provider.

### E3: overhead per chunk-group size

| chunk group | outboard stored (any size ≥ 1 MiB) | full-fetch overhead | 1 MiB slice of 256 MiB | 1 chunk of 256 MiB (wire) | proof before first byte, 256 MiB |
|---|---|---|---|---|---|
| 1 KiB | 6.25 % | 6.25 % | 66 496 B (6.34 %) | 2 176 B | 18 pairs (1 152 B) |
| 4 KiB | 1.56 % | 1.56 % | 17 344 B (1.65 %) | 2 176 B | 16 pairs |
| **16 KiB** | **0.39 %** | **0.39 %** | **5 056 B (0.48 %)** | 2 176 B | 14 pairs (896 B) |
| 64 KiB | 0.098 % | 0.098 % | 1 984 B (0.19 %) | 2 176 B | 12 pairs |
| 256 KiB | 0.024 % | 0.024 % | 1 216 B (0.12 %) | 2 176 B | 10 pairs |

A just-over-threshold blob (64 KiB + 1 B) costs 256 B of outboard at 16 KiB groups. A single-chunk fetch costs
the same at every group size (1.5–2.2 KiB), because bao-tree descends inside partially requested groups.

### E4: throughput (one core, 128 MiB; plain `blake3::hash` = 3 364 MiB/s)

| chunk group | create outboard | encode (validated) | verify + decode | leaf items |
|---|---|---|---|---|
| 1 KiB | 719 MiB/s | 555 | 692 | 131 072 |
| 4 KiB | 1 989 | 1 177 | 1 898 | 32 768 |
| **16 KiB** | **2 963** | **1 538** | **2 904 (86 % of plain hash)** | 8 192 |
| 64 KiB | 3 302 | 1 650 | 3 172 | 2 048 |
| 256 KiB | 3 323 | 1 630 | 3 184 | 512 |

16 KiB is the knee of the curve. 1 KiB groups (classic bao) are 4.2× slower to verify and cost 16× the outboard.
Going above 16 KiB gains at most 9 % throughput and 0.3 % space, but makes every detected corruption 4–16× more
expensive. 16 KiB is also the granularity `iroh-blobs` fixes ("the minimum granularity is a chunk group of 16KiB"),
and the group size is a **wire parameter**. The root hash does not depend on it, but encoder and decoder must use
the same value, or every response fails.

## What applies and what doesn't

- Applies: everything here runs at the bao-tree layer that iroh-blobs uses. The results carry over to any blob/v0
  implementation on iroh-blobs or bao-tree, and the bracket result carries over to any BLAKE3 verified-streaming
  implementation, because it comes from the hash's tree shape.
- Doesn't cover: iroh-blobs' own request framing, the stores (fs/mem), multi-provider scheduling, or a TypeScript
  decoder. The trailing-bytes result is a property of the decoder API. Whether iroh-blobs' get FSM then checks for
  end-of-stream was not tested.
- In webway, the URL's `size=` is inside the signed body (`body_hash`), so it is the **sender's** signed claim.
  Providers' size headers are unauthenticated. The two can disagree, and only the last chunk decides.

## Sources

- bao-tree 0.17.0 source: `src/io/sync.rs` (`DecodeResponseIter`), `src/iter.rs` (`ResponseIterRef`),
  `src/rec.rs` (`truncate_ranges`). <https://github.com/n0-computer/bao-tree>
- iroh-blobs protocol docs (0.104.1): 16 KiB minimum granularity, ranges in 1 KiB chunks.
  <https://docs.rs/iroh-blobs/latest/iroh_blobs/protocol/index.html>
- iroh-blobs DESIGN.md (0.99): the verified size is known only once the last chunk is held, and the uncertainty
  before that is a factor of 2. Outboard stored at 16 KiB groups.
  <https://docs.rs/crate/iroh-blobs/0.99.0/source/DESIGN.md>
- iroh-blobs 0.35 `get_verified_size` (requests only the last chunk):
  <https://docs.rs/iroh-blobs/0.35.0/src/iroh_blobs/get/request.rs.html>
- iroh blog, "Blob store design challenges": <https://iroh.computer/blog/blob-store-design-challenges>
- BLAKE3 spec, tree structure (§2.1, left subtree = largest power of two of chunks):
  <https://github.com/BLAKE3-team/BLAKE3-specs>

## What the planner should do next

For the `blob/v0` draft (T8), with proposed requirement text:

1. **Pin the chunk group**: "Blob responses MUST use BLAKE3 verified streaming with chunk groups of 16 KiB
   (chunk_log = 4)". This is the same as iroh-blobs. It costs 0.39 % overhead and runs at 86 % of plain-hash speed.
2. **Size is verified only via the last chunk**: "A receiver MUST NOT treat a provider-supplied size as verified
   until it has verified the last chunk. The first request to a provider MUST include the last chunk, unless the
   request is the full blob." Also: "A receiver MUST reject a provider whose stated size differs from the
   referencing Part's `size`" and "MUST NOT allocate more than the Part's `size`". If the verified size differs
   from the signed `size=`, the result is `BlobInvalid`, attributed to the **sender** in the audit log, because the
   sender signed the wrong size.
3. **End of response**: "After the last expected item, the response stream MUST end. Extra bytes are a protocol
   error." The decoder alone accepts them in 100 % of cases.
4. **Provider failover budget**: a detected corruption costs at most one group (about 16.4 KiB). Say that a
   receiver MUST drop a provider at the first hash mismatch and MAY retry the same ranges elsewhere. Verified
   ranges are kept, because no unverified byte is ever delivered.
5. **Conformance vectors** (T4), from this crate: (a) a blob of 1 048 577 B whose first chunk is served under a
   claimed size of 2 097 152, which MUST NOT be reported as verified; (b) the same response with the last chunk
   included, which MUST be rejected; (c) a full response plus 1 trailing byte, which MUST be rejected;
   (d) one bit flip in each of a parent pair and a leaf, which MUST be rejected with nothing past the last good
   group delivered.
6. A follow-up lab could run the same E1/E2 attacker against iroh-blobs' get FSM, the actual network path, to see
   whether it enforces end-of-stream and how it treats a size header that contradicts a later last chunk.
