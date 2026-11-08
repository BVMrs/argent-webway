# Extension `blob/v0`: content-addressed artefact transfer

| | |
|---|---|
| Status | **Draft v0**, for review. Date: 2026-11-08. Roadmap track T8. |
| Extension URI | `https://github.com/BVMrs/argent-webway/spec/ext/blob/v0` (written `…/ext/blob/v0` below) |
| Requirement prefix | `BLOB` ([conventions](../conventions.md)) |
| Test vectors | [`conformance/vectors/blob/`](../../conformance/vectors/blob/), generated and checked by [`conformance/tools/blob-vectors/`](../../conformance/tools/blob-vectors/) (§16) |
| Depends on | BLAKE3 ([spec][blake3-paper]), `envelope/v0` (`ext/envelope.md`), `capability/v0` (`ext/capability.md`), the profile (`profile.md`) and binding (`binding-webway-quic.md`), `provenance/v0` (`ext/provenance.md`, for the trust computation) |
| Inputs | Due diligence [§4.5](../../docs/due-diligence.md#45-delivery-offline-peers-streaming-and-artefacts) (R4), [§4.7](../../docs/due-diligence.md#47-security-model), [§6](../../docs/due-diligence.md#6-first-milestone-m1) step 5; threat model (`docs/threat-model.md`, issue #6) items ART-1 … ART-5, META-7, gaps G14, G15 |

**Summary.** Content larger than `INLINE_MAX` (64 KiB) never travels inside an envelope. The sender puts a
**reference** in the Part instead: an ordinary A2A `url` Part whose URL is
`webway-blob:blake3:<hex>?size=<n>&providers=<node>/<agent>,…`. The A2A data model is unchanged. The recipient
**fetches** the bytes from a provider on a dedicated QUIC stream. Every fetch is a signed envelope that carries a
capability `blob:blake3:<hex>#read`, rooted in the provider's owner and held by the fetching agent, and the
provider authorises it before it even looks the blob up. Knowing the hash is not enough. The bytes come back in
the **bao encoding** of BLAKE3's own hash tree, cut at 16 KiB blocks, which is what `iroh-blobs` uses. So every
16 KiB block is verified against the hash as it arrives, a cut transfer resumes from the last verified block, and
any number of providers, of any owner, can serve the same blob without being trusted for its content. Fetched
content takes its **provenance from the Part that referenced it**, never from whoever served the bytes.

---

## Contents

1. [Purpose, scope and position](#1-purpose-scope-and-position)
2. [Terminology, constants and errors](#2-terminology-constants-and-errors)
3. [Content and hash](#3-content-and-hash)
4. [References](#4-references)
5. [Tree, encoding and verification](#5-tree-encoding-and-verification)
6. [The BLOB stream](#6-the-blob-stream)
7. [Fetching](#7-fetching)
8. [Authorisation](#8-authorisation)
9. [Provenance of fetched content](#9-provenance-of-fetched-content)
10. [Audit](#10-audit)
11. [HTTP edge and MCP](#11-http-edge-and-mcp)
12. [Limits](#12-limits)
13. [Error model](#13-error-model)
14. [Versioning](#14-versioning)
15. [Security considerations](#15-security-considerations)
16. [Conformance](#16-conformance)
17. [Open questions](#17-open-questions)
- [Appendix A. Example: M1 step 5](#appendix-a-example-m1-step-5)
- [Appendix B. Changes from the due diligence](#appendix-b-changes-from-the-due-diligence)

---

## 1. Purpose, scope and position

Agents share large artefacts: datasets, logs, traces, checkpoints, build outputs (due diligence S1, S3). A2A 1.0
offers two ways to carry a file in a `Part`: inline bytes (`raw`) or a `url`. Inline bytes do not scale and every
byte would pass through signatures, mailboxes and audit logs. A plain URL has no integrity, no access control
that fits our capability model, no resume and no way to fetch from anyone but the URL's host (research §3,
due diligence §2.1 gap 6).

This extension defines:

- how content is identified (BLAKE3, §3);
- how a Part refers to content by hash (§4), and how the capability to read it reaches the recipient (§4.3, §8);
- the tree, the wire encoding of byte ranges and their incremental verification (§5);
- the fetch exchange on the binding's BLOB stream (§6, §7), including partial copies, resume and several
  providers;
- how fetched content is labelled for prompt-injection boundaries (§9), audited (§10) and bounded (§12).

Out of scope for v0: pushing bytes to a peer unasked (only the recipient pulls), blobs that grow while they are
streamed (live artefacts), deletion and garbage collection protocols, mailbox custody of blobs
([open question 2](#17-open-questions)), encryption of blob content beyond the QUIC hop ([open question 4](#17-open-questions)).

**Position relative to other protocols.**

| Protocol | Relation |
|---|---|
| A2A 1.0 | **Profile use, no change.** A reference is a standard `Part` with `url`, `mediaType` and `filename`. Stock A2A peers see an opaque URL; at the HTTP edge they get an HTTPS URL instead (§11). No new Part kind (research R-B2). |
| `iroh-blobs` | **Same hash and encoding, different request layer.** The hash is BLAKE3, the encoding is the bao pre-order encoding with 16 KiB chunk groups that `iroh-blobs` and `bao-tree` use. The vectors are checked against `bao-tree` 0.17. The request and reply are our own, because `iroh-blobs`' request carries no signature or capability, and every webway request must (profile §9). An implementation can reuse `bao-tree` for the data path. |
| MCP | **Bridge.** The MCP facade gives a local agent fetched content as a tool result or resource, never the reference's capability (§11.2). |
| HTTP Range / ETags | Used only at the HTTP edge (§11.1), where the client cannot verify bao. |

## 2. Terminology, constants and errors

- **Blob**: a finite byte string, identified by its hash.
- **Reference**: a `webway-blob:` URL (§4.1).
- **Provider**: an agent, at a node, that serves a blob. Written `wwn:<node>/wwa:<agent>`.
- **Fetcher**: the agent that reads a blob, and its node, which does the work on the agent's behalf.
- **Grant**: a capability token for `blob:<hash>#read` at one provider, held by the fetcher (§4.3).
- **Chunk**: BLAKE3's 1024-byte unit. **Block**: 16 chunks, 16 384 bytes, the unit of transfer and verification.
- **CV**: a BLAKE3 chaining value (32 bytes).

Constants:

| Name | Value | Meaning |
|---|---|---|
| `INLINE_MAX` | 65 536 bytes | From the profile. Largest Part content sent inline. |
| `BLOCK_SIZE` | 16 384 bytes | Block size. Fixed for v0: changing it changes the encoding. |
| `MAX_PROVIDERS` | 4 | Most providers in one reference. |
| `MAX_RANGES` | 64 | Most ranges in one Fetch request. |
| `MAX_FETCH_TTL` | 600 s | Largest `exp − ts` of a Fetch request envelope. |
| `MAX_BLOB_SIZE` | 2^53 − 1 bytes | Largest size a reference can state. Nodes set a much lower local limit (§12). |
| `STALL_TIMEOUT` | 30 s (default) | A fetcher abandons a BLOB stream on which the next parent pair or block (at most 16 KiB) does not complete within this time. This is a deadline per item, so a provider cannot hold a stream open by dripping a byte at a time. |

Errors this extension uses, all already registered by the profile (§10.3 there) or by `capability/v0`, plus four
**local** results that never go on the wire. Details in §13.

## 3. Content and hash

The hash of a blob is the 32-byte BLAKE3 hash (default mode, no key, 32-byte output) of its bytes. Written
everywhere as `blake3:` followed by 64 lowercase hex digits, the `envelope/v0` hash format, so a blob hash, a
`body_hash` and a `prov.derivedFrom` entry look alike and compare as strings.

- [BLOB-001] A node MUST compute blob hashes as the BLAKE3 hash of exactly the blob's bytes, and MUST write and
  accept them only as `blake3:` followed by 64 lowercase hex digits. Any other form in a reference is
  `BlobRefInvalid` (§4.1), in a Fetch body `InvalidParamsError` (§7.1).

A Part's **content bytes** are what the hash covers when a Part goes by reference:

| Part content | Content bytes | `mediaType` of the reference Part |
|---|---|---|
| `raw` | the bytes | the original `mediaType` |
| `text` | the UTF-8 encoding of the string, no BOM | `text/plain; charset=utf-8` unless the original had one |
| `data` | the JCS ([RFC 8785]) serialisation of the value | `application/json` |
| `url` | not converted: the URL is already a reference and is small | — |

- [BLOB-002] *Pending: T8.* A sender that replaces a Part's content by a reference MUST hash the content bytes of
  the table above and MUST set the reference Part's `mediaType` as the table says. A receiver hands fetched content
  to its agent as bytes with the declared media type. It MAY present them as text only if they are valid UTF-8,
  and as structured data only if they are I-JSON, and MUST otherwise hand them over as bytes.

A receiver cannot tell whether a referenced `application/json` blob was a `data` Part or a `raw` Part at the
sender, and does not need to: in both cases the content is the same bytes with the same media type.

## 4. References

### 4.1 URL

```abnf
reference  = "webway-blob:" hash "?" param *( "&" param )
hash       = "blake3:" 64HEXLOWER
param      = name "=" value
name       = LOWER *( LOWER / DIGIT / "-" )
size       = "0" / ( %x31-39 *15DIGIT )          ; value of "size", at most 2^53 - 1
providers  = provider *3( "," provider )         ; value of "providers", 1 to MAX_PROVIDERS
provider   = "wwn:" 52BASE32 "/" "wwa:" 52BASE32 ; node, then the agent at that node
```

`BASE32` is the lowercase RFC 4648 alphabet without padding, as in `capability/v0` §3: the 52 characters encode
32 bytes and the four unused bits are zero. A reference must have `size`, and may omit `providers`.

- [BLOB-010] A node MUST parse a reference by the grammar above and reject, as `BlobRefInvalid`: another scheme or
  hash algorithm, a hash not in canonical form, a missing or non-canonical `size` (sign, leading zero, above
  2^53 − 1, percent-encoding), a parameter that appears twice, a parameter without `=`, an empty parameter, a
  fragment, an empty `providers`, more than `MAX_PROVIDERS` providers, a provider listed twice, or a provider that
  is not a node identifier, `/`, and an agent identifier. Parameters with other names MUST be ignored. A node
  MUST NOT fetch anything for a reference that does not parse. It hands the Part to its agent as the opaque URL
  it is, with the Part's provenance.

A reference without `providers` is valid. It is useful only to an agent that is already entitled to the blob
(BLOB-015), for example because it produced it or received a grant for it earlier. Then its node may use its
own copy. For anyone else it resolves to nothing, exactly as if the blob did not exist.

### 4.2 The reference Part

A by-reference Part is an A2A 1.0 `Part` whose `url` is the reference. Its `mediaType` and `filename` describe the
content; both are claims of the sender, carried as data (§9).

- [BLOB-011] *Pending: T8.* A sender MUST send by reference every Part whose content bytes (§3) exceed
  `INLINE_MAX`, and MUST NOT put such content inline. It MAY send smaller content by reference. If an envelope
  would still exceed `MAX_ENVELOPE_BYTES` (`envelope/v0`), the sender MUST move further Parts, largest first, to
  references until it fits.
- [BLOB-012] *Pending: T8.* The `size` of a reference MUST be the exact length of the blob, and every provider it
  lists MUST be able to serve the complete blob to the recipient when the envelope is sent. A sender that lists
  its own node MUST hold the complete, verified blob there.

The reference is inside a Part, so it is covered by the envelope signature and by the Part's taint (`prov`, `envelope/v0`
§3.6). An intermediary cannot swap the hash or the provider list.

### 4.3 Grants travel in `cap.grants`

A reference says *what* to fetch and *where*. The right to fetch it is a capability token, and tokens never go
into Parts, URLs or metadata (profile PROF-048, `capability/v0` CAP-151). This extension adds one member to the
signed `cap` header of `envelope/v0`, alongside `capability/v0`'s `access`, `mandate` and `onward`:

```json
"cap": {
  "grants": [
    {
      "capability": "blob:blake3:d93c23ee…cc54#read",
      "provider": "wwn:mxcl…xgoq/wwa:qtga…fu2q",
      "access": "<base64url Biscuit, rooted in the provider's owner, current holder = the envelope's to>"
    }
  ]
}
```

`cap.grants` is allowed on any envelope that carries Parts: requests (`SendMessage`), responses and events (an
`artifactUpdate` with a by-reference Part, as in M1 step 5). Its entries are not used to authorise the envelope
that carries them; they are handed to the recipient for later Fetches, like `onward` mandates.

- [BLOB-013] *Pending: T8.* For every provider listed in a reference it sends, a sender MUST include in the same
  envelope's `cap.grants` a grant whose `capability` is `blob:<hash>#read` for that reference's hash, whose
  `provider` is that provider, and whose token's current holder is the envelope's `to` agent. A sender MUST NOT
  list a provider it has no such grant for. This applies to every envelope that carries a reference, including
  later answers that repeat it (`GetTask`, `SubscribeToTask`, `ListTasks`): each carries grants for its own
  recipient, minted when it is sent.
- [BLOB-014] *Pending: T8.* A node MUST take grants only from `cap.grants` of an envelope that passed `envelope/v0`
  verification, MUST store each one only for the agent that is its holder (the envelope's `to`), and MUST present
  it only in Fetch requests signed by that agent. It MUST NOT give a grant to an agent's model context.

**Grant lifetime and renewal.** A grant SHOULD stay valid at least until the referencing envelope's `exp` plus
the time the recipient needs to fetch. An envelope can wait in a mailbox for up to `MAX_TTL`. A recipient whose
grant has expired gets a fresh one by asking for the task again (`GetTask`), because BLOB-013 applies to that
answer too. There is no separate renewal operation in v0.

`capability/v0` must take this member over as written here ([open question 1](#17-open-questions)), as it did for
`onward`.

## 5. Tree, encoding and verification

### 5.1 Tree

The tree is BLAKE3's own tree ([BLAKE3 spec][blake3-paper] §2.1), seen at block granularity:

- A blob of `size` bytes has `n = max(1, ⌈size / 16384⌉)` blocks. Block `i` is bytes
  `[16384·i, min(16384·(i+1), size))`. The empty blob has one empty block.
- A node spans blocks `[lo, hi)`. If `hi − lo = 1` it is a **leaf**. Otherwise it is a **parent**, its left child
  spans the first `p` blocks, where `p` is the largest power of two strictly less than `hi − lo`, and its right
  child spans the rest. This is BLAKE3's rule ("the left subtree is the largest power of two of chunks smaller than
  the input"), counted in blocks; because blocks are 16 chunks, every block is a complete BLAKE3 subtree.
- The CV of a leaf is the BLAKE3 chaining value of that block's bytes as a subtree starting at chunk `16·i`.
  The CV of a parent is BLAKE3's parent compression of its children's CVs. Both use the root flag only for the
  root node, so the root's CV is the blob hash. For a one-block blob the leaf is the root and its CV is the plain
  BLAKE3 hash of the block.

In `blake3` 1.8 terms: leaf CV = `Hasher::new().set_input_offset(16384·i).update(block).finalize_non_root()`,
parent CV = `merge_subtrees_non_root(l, r, Mode::Hash)`, root = `merge_subtrees_root(l, r, Mode::Hash)` or
`blake3::hash(block)`. In `bao-tree` terms: `BlockSize::from_chunk_log(4)`.

### 5.2 Encoding

The encoding of a set of block ranges `R` is a pre-order walk from the root:

```text
encode(node):
  if no block of node is in R: emit nothing
  else if node is a leaf:      emit the block's bytes
  else:                        emit CV(left) || CV(right)    (64 bytes)
                               encode(left); encode(right)
```

There is no length prefix and no framing inside the encoding: the fetcher knows `size` and `R` from the signed
reply (§7.4), so it knows the shape of the walk and every length in it. The encoding of all blocks has
`64 · (n − 1) + size` bytes.

- [BLOB-020] A provider MUST send, as the data of a Fetch reply, exactly the encoding of the reply's `ranges` for
  the blob, as defined above. Effective ranges (§5.3) always lie inside the blob, and for such ranges this is
  byte for byte the output of `bao-tree`'s `encode_ranges` / `encode_ranges_validated` with 16 KiB chunk groups.
  `bao-tree`'s own rule for ranges past the end differs in corner cases and is not used.

### 5.3 Ranges

A Fetch names blocks, not bytes. `ranges` is a JSON array of pairs `[start, end]`, each a half-open interval of
block indices.

- A range may reach past the last block. The **effective ranges** of a request for a blob of `n` blocks are the
  requested blocks below `n`, plus block `n − 1` if any requested range ends after `n`, merged into canonical form.
  A request with no `ranges` means `[[0, 2^53 − 1]]`, the whole blob.
- So `[[k, k+1]]` with any `k ≥ n − 1` asks for the last block, which is how a fetcher with no reliable size learns
  and proves it (§5.4).

- [BLOB-023] A provider MUST compute the effective ranges of a request exactly as above, and a fetcher MUST
  compute the same, so both agree on the shape of the encoding.

### 5.4 Verification

The fetcher walks the same tree while reading. It starts with the expected CV of the root, the blob hash. At a
parent it reads 64 bytes, checks that the parent compression of the two halves equals the expected CV, and expects
the halves for the children. At a leaf it reads the block and checks its CV. Memory is one block plus one pair per
tree level (at most 39 for `MAX_BLOB_SIZE`).

- [BLOB-021] A fetcher MUST verify every parent pair and every block against the expected CV before it uses,
  stores as verified, forwards or serves any byte of it. On the first mismatch it MUST stop reading that stream,
  discard everything after the last verified block, and treat the stream as `BlobCorrupt` (§13). Blocks verified
  before the mismatch stay verified.
- [BLOB-022] A fetcher MUST treat bytes that arrive after the complete encoding, and a FIN from the provider
  before the encoding is complete, as a stream error `ProtocolError` (binding §11.2). It MUST record the anomaly
  (BLOB-061) and MUST NOT fetch the same blob from that provider again, so that the fetch does not loop. The blocks
  it verified stay verified.
- [BLOB-024] A fetcher MUST check that a reply's `size` equals the `size` of the reference it is fetching for, and
  MUST treat a difference as `BlobSizeMismatch` and not use that reply. It MUST NOT consider a blob complete, or
  its size proven, before it has verified the blob's last block.

A stream that is **reset** or whose connection is lost before the end is not a failure of the provider: the
verified blocks are kept and the rest is fetched again (§7.5). A provider that **closes** the stream early has
broken the grammar (BLOB-030), and BLOB-022 applies.

**Why the size needs the last block.** BLAKE3 does not hash the length separately: the tree shape encodes it, and
only the last block pins it down. A provider that lies about `size` makes the fetcher walk the wrong tree. The
fetcher detects this at the first node where the claimed tree and the true one differ, at the latest at the last
block. Blocks it verified before that point are correct whatever the size, because each block's CV binds its
position (BLAKE3's chunk counter) and the root flag. BLOB-024 adds the reference's signed `size` as a cross-check
before any data flows. The vectors show the three cases: a smaller size fails at the last block, a size with more
blocks fails where the shapes diverge, and a larger size with the same number of blocks ends in a FIN inside the
last block (`ProtocolError`, so the provider is not asked again).

## 6. The BLOB stream

Fetches use the binding's BLOB stream (binding §4, stream type `0x03`, bidirectional, opened by the fetcher), so
bulk data never shares a stream with control traffic or A2A requests. A node announces that it serves blobs by
listing `…/ext/blob/v0` in its HELLO `features` (binding §3.2).

This extension assigns three frame types from the extension range (binding §6.1):

| Type | Name | Allowed on | Payload |
|---|---|---|---|
| `0x20` | FETCH | BLOB, fetcher → provider | Signed envelope, `typ: request`, `op: …/ext/blob/v0#Fetch` (§7.1) |
| `0x21` | FETCH_REPLY | BLOB, provider → fetcher | Signed envelope, `typ: response` (§7.4), `typ: error`, or `typ: ack` (duplicate) |
| `0x22` | BLOB_DATA | BLOB, provider → fetcher | Bytes of the encoding (§5.2). Not JSON. |

Stream grammar:

```text
fetcher → provider:  FETCH  FIN
provider → fetcher:  FETCH_REPLY(response)  BLOB_DATA*  FIN     total BLOB_DATA payload = encoding length
                   | FETCH_REPLY(error)  FIN
                   | FETCH_REPLY(ack)    FIN                    duplicate FETCH (BLOB-037)
```

Who signs the FETCH_REPLY follows the binding's rule for REQUEST streams (BIND-009, BIND-013, profile PROF-078).
The request's `to` agent signs replies and the errors it decides. The provider's **node** (`from` = its `wwn:`
identity) signs errors that no hosted agent can sign: a `to` that is not hosted, and a FETCH payload that does
not parse or whose `id` cannot be read. In the last case the error has no `ctx.inReplyTo`, and the fetcher
matches it by the stream, which carries one request. Node-signed errors for failures at or before the signature check are binding-level
errors in the sense of ENV-621: they say only which node refused, and the fetcher treats them as per-hop
(ENV-622).

- [BLOB-030] *Pending: T8.* A node MUST follow this grammar: one FETCH per stream, one FETCH_REPLY, then BLOB_DATA
  frames whose payloads concatenate to exactly the encoding (none after an error or ack), then FIN. A frame of these types on another stream type
  or in the other direction is a connection error `FrameUnexpected` (binding BIND-012). A fetcher MUST NOT open a
  BLOB stream to a node that did not list `…/ext/blob/v0` in its HELLO `features`, and a node that did not list it
  MUST reset a BLOB stream with `StreamTypeUnknown`.

BLOB_DATA frames may split the encoding anywhere; boundaries carry no meaning. A fetcher stops a fetch it no longer
wants by resetting the stream with `RequestCancelled`.

## 7. Fetching

### 7.1 The Fetch request

```json
{
  "v": "webway-envelope/0", "typ": "request", "op": "https://github.com/BVMrs/argent-webway/spec/ext/blob/v0#Fetch",
  "from": "wwa:<fetching agent>", "to": "wwa:<provider agent>",
  "id": "<uuidv7>", "ts": "2026-11-07T12:00:00Z", "exp": "2026-11-07T12:05:00Z",
  "cap": { "capability": "blob:blake3:d93c…cc54#read", "access": "<grant token>" },
  "body_hash": "blake3:…",
  "body": { "hash": "blake3:d93c…cc54", "ranges": [[0, 7]] },
  "sig": "…"
}
```

The body has `hash` and, optionally, `ranges` (§5.3). It carries no Parts, so `prov` is absent.

- [BLOB-031] A Fetch request MUST have `typ: request`, `op: …/ext/blob/v0#Fetch`, `to` the provider's agent,
  `cap.capability` equal to `blob:` + the body's `hash` + `#read`, `cap.access` the grant (or another token for that
  capability), a body whose `hash` is in canonical form (BLOB-001) and whose `ranges`, if present, has 1 to
  `MAX_RANGES` pairs of integers `0 ≤ start < end ≤ 2^53 − 1`, in ascending order, with a gap between consecutive
  pairs, and `exp − ts ≤ MAX_FETCH_TTL`. A provider MUST check `exp − ts` as an operation-specific header check
  of envelope verification, before the envelope is recorded for dedupe, and answer a violation with
  `EnvelopeInvalid` (reason `ttl-too-long`). It MUST answer a body that breaks this with `InvalidParamsError`, a
  missing `cap.capability` with `CapabilityMissing`, and a `cap.capability` that is not exactly this string with
  `CapabilityDenied` at the operation and resource step of the `capability/v0` algorithm (CAP-106, step 8 of
  CAP-160, so token errors of earlier steps come first). It MUST ignore body members it does not know. A fetcher
  MUST use a new envelope `id` for every Fetch, including retries and resumes.

A Fetch is a read with no side effect and is not part of the profile's delivery state machine (profile §8.3): the
rule that a retry resends the same envelope (PROF-033, PROF-073) does not apply to it. Retrying with a new `id` is
safe, and the short `MAX_FETCH_TTL` keeps the provider's dedupe entries for Fetches short-lived.

### 7.2 Choosing providers

A fetcher gets a blob from its own store, if its agent is entitled to it (BLOB-015), or from providers listed in
the reference. It contacts a provider only if it can check who the provider is, the provider's owner already has
a part in this content, and it holds a grant for it. So a sender cannot make it dial arbitrary nodes (threat model
ART-5, G14).

- [BLOB-041] A fetcher MUST contact a provider listed in a reference only if all of these hold:
  (a) it holds a verified agent-cert for the provider's agent that names the listed node;
  (b) that cert's owner is the fetcher's own owner or an owner it has pinned (`capability/v0` §4.9);
  (c) that owner is the fetcher's own owner, the verified owner of the sender of the referencing envelope, or in
  the referencing Part's `taint.owners`, so it is an owner that already had a part in this content (G14);
  (d) the fetching agent holds a grant for that provider (BLOB-014).
  It MUST skip every other listed provider without contacting it.
- A fetcher SHOULD also check, before dialling, that the grant's authority block names an issuing key certified by
  that owner for that node (CAP-110), when it holds that issuer-cert.

Among the eligible providers the fetcher may choose any order (latency, cost, same owner first) and may fetch
different ranges from different providers at the same time: every block verifies against the same hash wherever
it came from. Fetching from other nodes of the fetcher's own owner that are not listed needs a token minted by
that node's issuing key (CAP-110), which v0 does not define a way to get ([open question 7](#17-open-questions)).

### 7.3 Provider procedure

A provider runs these steps for each FETCH, in order, and answers with the first failure:

1. **Envelope.** `envelope/v0` verification (signature, freshness, `to` hosted here), including the `exp − ts`
   check of BLOB-031 before dedupe. A duplicate gets an `ack` and no data (BLOB-037).
2. **Connection binding.** `from` is bound to the node at the other end of this connection (BLOB-032).
3. **Body.** BLOB-031.
4. **Authorisation.** The full `capability/v0` algorithm, in its own order, for `cap.capability` with the body's
   hash as the resource (BLOB-033). The match of `cap.capability` with the hash is its step 8.
5. **Lookup.** Only now does the provider look in its store (BLOB-034, BLOB-042).
6. **Reply** (§7.4), then data.

- [BLOB-032] A provider MUST answer `RecipientUnknown` if `to` is not an agent it hosts, and MUST answer
  `IdentityUntrusted` unless the request's `from` agent is bound, by a valid agent-cert, to the node authenticated
  on this connection (as binding BIND-009 requires for REQUEST streams). Fetches are never relayed or mailboxed.
- [BLOB-033] A provider MUST authorise every Fetch request with the full `capability/v0` algorithm (CAP-160),
  with operation `Fetch`, capability `cap.capability` and resource the body's `hash`, and MUST do so before it
  looks the hash up in its store. The answer to a request that fails authorisation MUST NOT depend on whether the
  provider holds the blob: the error is the `capability/v0` error, never `BlobNotFound`.
- [BLOB-034] After authorisation, a provider that holds no servable copy (BLOB-042) MUST answer `BlobNotFound`.
  Otherwise it MUST reply with `hash`, the blob's `size`, and `ranges` equal to the effective ranges of the request
  intersected with the blocks it holds (possibly empty), and then send their encoding.

The order matters. A guessed hash (for example of a well-known file) gets the same `CapabilityMissing` or
`CapabilityDenied` whether or not the provider has it, so the provider is not an existence oracle. A grant is
minted or relayed only for an agent that is itself entitled to the blob (BLOB-015), so `BlobNotFound` after
authorisation only tells the holder of a grant that the copy it was promised is gone.

- [BLOB-035] *Pending: T8.* A `response` reply MUST be signed by the request's `to` agent, with `ctx.inReplyTo`
  the request's `id`. A fetcher MUST accept a reply only on the stream of its request, only if it verifies, and only
  if it is signed by that agent or by the node it is bound to, which MUST be the node authenticated on the
  connection. It MUST NOT use data that follows a reply it did not accept.
- [BLOB-036] *Pending: T8.* A provider MUST NOT send a parent pair or block it has not itself verified against the
  blob hash (on receipt, or when it created the blob). A corrupted disk at one provider then cannot reach fetchers
  as valid-looking data, and the provider learns of corruption first.
- [BLOB-037] *Pending: T8.* A provider MUST answer a duplicate FETCH envelope with an `ack` FETCH_REPLY (the
  bodiless duplicate answer of `envelope/v0` §8.4) and FIN, and MUST NOT send blob data for it. Fetch replies are
  never stored as answers for duplicates, because the data that follows them is not part of the envelope.

### 7.4 The reply

```json
{
  "typ": "response", "op": "https://github.com/BVMrs/argent-webway/spec/ext/blob/v0#Fetch",
  "from": "wwa:<provider agent>", "to": "wwa:<fetching agent>", "ctx": { "inReplyTo": "<request id>" },
  "body": { "hash": "blake3:d93c…cc54", "size": 100000, "ranges": [[0, 7]] },
  …
}
```

The reply is signed, so a fetcher can prove later (audit, disputes) which provider claimed which size and ranges.
The data that follows is not signed, and does not need to be: it verifies against the hash.

### 7.5 Partial copies and resume

A fetcher keeps, durably, every block it verified and every parent pair on the paths to them. That is exactly
what it needs to serve those blocks itself, and to resume.

- [BLOB-040] A fetcher MUST keep the blocks and parent pairs it verified across stream failures and node restarts
  (until its retention policy drops the blob), MUST NOT overwrite a verified block, and when it resumes MUST
  request only blocks it has not verified, from the same or another eligible provider.
- [BLOB-042] A node MAY serve a blob it holds only in part, but only once it has verified the blob's last block
  (so it knows the size for certain). Before that it MUST answer `BlobNotFound` for that blob.

Resume therefore needs no session state at the provider: a resumed fetch is a new Fetch for the missing ranges,
authorised again. Each such Fetch counts as one call against the grant's `max_calls` caveat, if it has one
(`capability/v0` §5.6), so senders that set one should allow for resumes.

### 7.6 Offline providers

When no eligible provider is reachable, the fetch is `PeerUnreachable` (retryable) for the local agent (profile
§8.5). Everything else carries on: the Part that holds the reference was delivered, the task that produced it is
unaffected, and the fetcher retries with backoff and jitter while it still holds a valid grant.

- [BLOB-043] *Pending: T8.* A node MUST NOT fail, cancel or reject a task, message or event because a blob it
  references cannot be fetched yet. It MUST report the unavailable blob to its agent as `PeerUnreachable` with
  `retryable: true` and keep retrying until the grant expires or its local policy gives up.
- A receiving node SHOULD start fetching a referenced blob as soon as it accepts the referencing envelope, within
  its limits (§12), so that a sender that goes offline later does not matter. This is how blob transfer degrades
  gracefully in v0 ([open question 2](#17-open-questions) covers custody at a mailbox host).

## 8. Authorisation

The capability is `blob:<hash>#read`, where `<hash>` is the `blake3:<hex>` form, for example
`blob:blake3:d93c…cc54#read`. `capability/v0` §5.2 lists it, with the one operation `Fetch`.

**Whose key roots it.** A grant is an access token of `capability/v0` §5.4: it is minted by an issuing key of the
**provider's** owner, for the provider's node (CAP-110, per-node access tokens), and checked by the provider like
any other request (BLOB-033). This answers threat-model item ART-2: when several providers of different owners
serve one blob, each one checks a token rooted in its own owner, and a fetcher needs one grant per provider.

**How grants reach the fetcher.**

- **Sender is the provider** (the common case, M1 step 5). The sender's node holds the blob, mints a grant with
  `holder(<recipient agent>, 0)`, and attaches it in `cap.grants`.
- **Sender relays a grant from another provider.** If the sender holds a grant from provider P (P's owner rooted,
  current holder the sender), it re-delegates it to the recipient with a holder block (`capability/v0` §5.5) and
  lists P. P sees a chain rooted in its own owner ending at the presenter. The holder-chain depth limit
  (`MAX_HOLDER_DEPTH`) bounds how far such grants travel.
- **Fetcher re-shares.** A node that fetched a blob holds a verified copy and can serve it as a provider in its own
  right, minting grants rooted in its own owner when its agent forwards the reference (§9 for taint).

**Entitlement.** A node's store is shared by its agents and deduplicated, so "the node holds H" must never mean
"any agent here may read H", or knowing a hash would be enough after all. The node keeps, per agent, the hashes the
agent is **entitled** to: blobs the agent produced, and blobs for which the agent received a verified grant
(BLOB-014). An entitlement does not expire with the grant, because the agent already had access to the content.

- [BLOB-015] A node MUST use a blob from its own store for an agent, hand it to the agent, or mint or relay a grant
  for it on that agent's behalf, only if that agent is entitled to the blob. Otherwise it MUST behave exactly as
  if the blob were not in its store, including in timing as far as practical, and resolve the reference only
  through eligible providers (BLOB-041).

BLOB-015 is what stops a foreign peer from sending a provider-less reference to a hash it guessed or overheard
and having the receiving node serve its own copy to the targeted agent. It also stops a prompt-injected agent
from making its node grant outsiders access to blobs that other agents on the node produced.

**Recommended grant content.** `right("blob:blake3:<hex>#read")`, an expiry that covers the time the recipient
may need to fetch (the referencing envelope's `exp` plus a margin, at most `MAX_ACCESS_TTL`), and optionally
`max_calls`. A grant longer than `REVOCATION_EXEMPT_TTL` (1 hour) needs fresh revocation lists at the provider
(`capability/v0` §9.3). A provider SHOULD keep a blob at least as long as the grants it issued for it are valid.

Grants are bound to the recipient's key, so a mailbox host or relay that sees them in `cap.grants` cannot use them
(`capability/v0` §5.5). They do reveal to it which blobs the recipient may read (threat model META-2).

## 9. Provenance of fetched content

The bytes of a blob carry no label. The **referencing Part** does: it has a signed taint (`envelope/v0` §3.6) and
arrived in an envelope from a verified sender. That Part is the content, as far as provenance goes. The provider
only moves bytes whose integrity the hash already guarantees, so it contributes nothing to the content and is not
part of its taint (threat model ART-3).

- [BLOB-050] A node MUST label fetched content with the taint of the Part that referenced it, and MUST compute its
  trust from that taint and the verified sender of the referencing envelope with the `provenance/v0` rule
  (due diligence §4.7.4: `min(level(sender owner), level of each taint owner, unverified ? unverified-origin : top)`).
  It MUST NOT take taint or trust from the provider, the Fetch reply, the blob's bytes or `mediaType`, or from
  which node served the bytes, including its own store.
- [BLOB-051] A node that stores one copy of identical bytes for several references (deduplication) MUST keep
  provenance per reference, and MUST label content handed over through a given Part with that Part's taint. Earlier
  references to the same hash MUST NOT raise or replace the trust of a later one.
- [BLOB-052] *Pending: T8.* A node MUST give fetched content to its agents only inside the delimited, labelled
  container of profile PROF-044, together with the reference Part's `mediaType` and `filename` as untrusted data,
  and MUST NOT interpret, execute or render content because of its declared or sniffed media type
  (threat model INJ-9).
- [BLOB-053] *Pending: T8.* When a node references, in an envelope it sends, a blob it received (forwarding) or
  derived content, the new Part's taint MUST include every owner of the taint the node recorded for the content it
  is passing on, and `unverified` if that was set (`provenance/v0`). Serving the bytes itself does not change this.

So in M1 step 7 the artefact from `beta` is `foreign` at `alpha` whether `alpha` fetched it from `beta`, from a
mirror of a third owner, or found it already in its own store.

## 10. Audit

`audit/v0` records security-relevant events. For blobs:

- [BLOB-060] *Pending: T8.* A provider MUST record for each Fetch: the request envelope's signed header, the
  authorisation decision and the capability chain used (profile PROF-049), the hash, the reply's ranges, and the
  number of bytes sent when the stream ends.
- [BLOB-061] *Pending: T8.* A fetcher MUST record for each blob: the referencing envelope's `id`, the hash, each
  provider it contacted with the outcome, every `BlobCorrupt`, `BlobSizeMismatch` and `ProtocolError` as an anomaly
  naming the provider, and completion.

A signed reply plus a `BlobCorrupt` record is evidence against a provider that served bad data: the reply binds the
provider to the hash and ranges, and anyone can re-check the data against the hash.

## 11. HTTP edge and MCP

### 11.1 HTTP edge

Stock A2A peers cannot fetch over the overlay and cannot verify bao.

- [BLOB-080] *Pending: T8.* When an HTTP edge passes a by-reference Part to a stock A2A client, it MUST replace the
  `webway-blob:` URL with an `https` URL on the edge that names the hash and carries no credential. It MUST serve
  that URL only to the edge principal (profile PROF-061) whose task scope (PROF-046) received the Part, with the
  same authentication as the edge's A2A endpoint, and MUST give the same answer (404) for a hash it does not hold
  and a hash that principal may not read. It SHOULD support HTTP Range requests and SHOULD send the hash (`"blake3:<hex>"`) as the `ETag`, so
  clients that can compute BLAKE3 may check the whole download.
- [BLOB-081] *Pending: T8.* An HTTP edge MUST NOT fetch a URL supplied by a stock client unless local policy
  explicitly allows that host (SSRF). Content a stock client sends inline above `INLINE_MAX` that the edge stores as
  a blob MUST get `taint.unverified = true` (profile PROF-059) on every Part that references it.

### 11.2 MCP facade

The MCP facade fetches on its agent's behalf and returns the content as a tool result or MCP resource, with the
provenance of §9 under the facade's `_meta` prefix (profile §12.4). It never returns a reference's grant. A
facade MAY return a local `file:` path or resource URI instead of the bytes for large content.

## 12. Limits

Verification catches wrong bytes, not wasted effort (threat model ART-4, G15).

- [BLOB-070] *Pending: T8.* A fetcher MUST have a local maximum blob size and MUST NOT contact any provider for a
  reference whose `size` exceeds it; the local agent gets `BlobTooLarge`. It MUST bound the number of concurrent
  fetches per node and per provider, and MUST abandon a stream on which the next parent pair or block does not
  complete within `STALL_TIMEOUT` (a deadline per item, so a slow drip is cut too).
- [BLOB-071] *Pending: T8.* A provider MUST bound concurrent BLOB streams per peer node and bytes served per peer
  per unit of time, and answer excess with `RateLimited` (retryable) rather than queueing without bound. It MUST
  verify the Fetch envelope's signature before doing anything more expensive (binding BIND-033).

## 13. Error model

Errors on the wire are those of the profile (§10.3 there) and `capability/v0`, carried in the FETCH_REPLY as a
signed `error` envelope:

| Error | Retryable | When |
|---|---|---|
| `EnvelopeInvalid` | no | Envelope failure, or `exp − ts > MAX_FETCH_TTL` (reason `ttl-too-long`) |
| `RecipientUnknown` | no | `to` is not an agent of this node (signed by the node, §6) |
| `IdentityUntrusted` | no | `from` not bound to the connection's node (BLOB-032) |
| `InvalidParamsError` (A2A −32602) | no | Malformed body: hash form, ranges (BLOB-031) |
| `CapabilityMissing`, `CapabilityInvalid`, `CapabilityDenied`, `CapabilityRevoked` | no | `capability/v0` |
| `RevocationStatusUnavailable` | yes | `capability/v0` §9.3 |
| `BlobNotFound` (−30030) | no | Authorised, but this provider holds no servable copy (BLOB-034, BLOB-042) |
| `RateLimited` | yes | BLOB-071 |
| `PeerUnreachable` | yes | No eligible provider reachable (local result, profile §8.5) |

The profile's description of `BlobNotFound` ("or the caller may not read it") is narrowed here: an unauthorised
caller gets the `capability/v0` error (BLOB-033).

`envelope/v0` names the wrong-recipient case `EnvelopeInvalid` (reason `wrong-recipient`) while the profile has
`RecipientUnknown` (PROF-041). This document follows the profile; the two drafts need to agree.

Stream-level failures use the binding's transport codes: `ProtocolError` (grammar, trailing bytes, early FIN),
`FrameUnexpected`, `RequestCancelled`, `ExcessiveLoad`.

**Local results** (to the local agent, in vectors and in audit records; never sent to a peer):

| Name | Meaning |
|---|---|
| `BlobRefInvalid` | A reference does not parse (BLOB-010). |
| `BlobCorrupt` | A provider's data did not verify (BLOB-021). The fetcher tries another provider. |
| `BlobSizeMismatch` | A reply's `size` differs from the reference's (BLOB-024). |
| `BlobTooLarge` | The reference's `size` is above the local limit (BLOB-070). |

## 14. Versioning

- The extension URI ends in `/v0`. A node that implements it lists it in its Agent Card and in HELLO `features`.
  Nothing in this extension uses per-request activation (profile §11.3, PROF-056): a reference is a plain A2A URL,
  `cap.grants` is header data that `envelope/v0` already signs and carries (ENV-002), and the Fetch operation runs
  on a BLOB stream that is enabled by HELLO `features`, not by `a2a-extensions`. A Fetch carries no
  `a2a-extensions` service parameter.
- [BLOB-090] *Pending: T8.* A sender MUST NOT send a by-reference Part to an agent whose card does not list
  `…/ext/blob/v0`. If the content cannot go inline either, the send fails locally with
  `ContentTypeNotSupportedError`.
- **Minor revisions** may add optional body members, reference parameters (ignored by v0 parsers, BLOB-010), new
  local results and vectors.
- **A new hash algorithm** is a new `<algorithm>:` prefix in references and capabilities. A v0 node treats it as
  `BlobRefInvalid` and does not fetch. Adding one is a minor revision only if it is optional for receivers.
- **A major revision** (`…/ext/blob/v1`) is needed for any change to the tree, `BLOCK_SIZE`, the encoding, the
  frame grammar or the meaning of an existing member.

## 15. Security considerations

- **Integrity without trusting providers.** Every block verifies against a hash that came in a signed Part
  (ART-1). Providers, relays and caches are trusted for availability only. A blob's hash proves *which* bytes, not
  *who wrote them* or whether they are safe: that is the referencing envelope's signature and the Part's taint.
- **Knowing the hash is not enough** (ART-2). Authorisation runs before lookup and its answer does not depend on
  the store (BLOB-033), so a provider confirms nothing to someone guessing hashes of known files. Inside a node,
  the shared store is gated per agent by entitlement (BLOB-015), so a provider-less reference to an overheard hash
  resolves to nothing, and an agent cannot grant others access to blobs it was never entitled to. Grants are
  holder-bound, short-lived by default, and not in any Part or URL. At the HTTP edge the blob URL is tied to the
  task scope that received it (BLOB-080).
- **Provenance cannot be laundered through a cache** (ART-3). Trust comes from the referencing Part only, and
  deduplicated storage keeps provenance per reference (BLOB-050, BLOB-051).
- **No dialling on command** (ART-5, G14). A fetcher contacts only providers certified to the listed node by an owner
  it has pinned, that already has a part in this content (sender, taint, or the fetcher's own owner), and for which
  it holds a grant (BLOB-041). A provider list cannot make it connect to arbitrary NodeIds, or to a pinned owner
  that has nothing to do with the content.
- **Fetches are not relayed** (BLOB-032). The `from` agent must be bound to the connection's node, so a captured
  Fetch envelope is useless to anyone else, and the provider's dedupe stops replays on the same connection.
- **Size lies and slow drips** (ART-4). The signed reference `size` is checked against the reply before data flows
  (BLOB-024), a lie is caught at the latest at the last block, local size limits apply before any connection
  (BLOB-070), and a per-item deadline cuts both stalls and slow drips (`STALL_TIMEOUT`). A sender and provider that
  lie together about the size get an early FIN, which is `ProtocolError`, and that provider is not asked again
  (BLOB-022).
- **Second-preimage and collision resistance** of BLAKE3 (128-bit collision security at 256-bit output) is what all
  of this rests on. The encoding uses BLAKE3's own tree. BLAKE3 compresses chunks and parent nodes with different
  flags (`CHUNK_START`/`CHUNK_END` versus `PARENT`) and binds each chunk to its position by the chunk counter, so a
  parent pair cannot be passed off as data, data cannot be moved to another offset, and the `ROOT` flag stops a
  subtree from posing as a whole blob.
- **Confidentiality.** Blob bytes are protected per hop by QUIC TLS. A provider learns who fetches which hash and
  when (META-7). Blob content is not encrypted end to end in v0; a sender that uses a third-party provider gives
  that provider the content ([open question 4](#17-open-questions)).
- **Prompt injection.** A blob is data. Its media type and file name are claims of the sender and reach the agent
  only as labelled data (BLOB-052). Large artefacts are a natural place to hide instructions; the label, not the
  transport, is what lets policy treat them as `foreign`.
- **Resource use at the provider.** A Fetch costs one signature check before anything else (BLOB-071); the encoding
  is produced from stored data and a stored outboard, with no per-request hashing beyond validation.

## 16. Conformance

### 16.1 Vector kinds

The format is `webway-vectors/v0` ([`conformance/vectors/README.md`](../../conformance/vectors/README.md)).
Test content is the pattern of the official BLAKE3 test vectors (byte `i` is `i mod 251`), given by length, so large
blobs need no large files. Node, agent and owner identifiers are syntactically valid test values derived from
names; these kinds check no signatures.

| Kind | Input | Output on accept | Rejections |
|---|---|---|---|
| `blob/hash` | `{ "data": { "pattern": n } \| { "hex" } }` | `{ "hash", "size", "blocks" }` | — |
| `blob/ref` | `{ "url" }` | `{ "hash", "size", "providers": [ "wwn:…/wwa:…" ] }` | `BlobRefInvalid` |
| `blob/ranges` | `{ "ranges": any JSON, "size" }` | `{ "effective": [[start, end], …] }` | `InvalidParamsError` |
| `blob/encode` | `{ "data", "ranges" }` | `{ "hash", "ranges" (effective), "length", "encodingHash", "hex"? (≤ 512 bytes) }` | — |
| `blob/verify` | `{ "hash", "size", "ranges", "data", "mutate"?: { "flip": offset } \| { "truncate": length } \| { "append": hex }, "end"?: "fin" \| "reset" }`. The stream is the honest encoding of `data` for `ranges`, then `mutate`; `end` says whether the provider closed it (default) or it was reset. | `{ "verified", "missing", "complete", "failure": null \| "BlobCorrupt" \| "ProtocolError" }`. `verified` is what the fetcher keeps, also on failure; `complete` means every block of `ranges` verified (not the whole blob). | — |
| `blob/fetch` | `{ "provider": { "node", "agents" }, "connectionPeer", "bindings": { wwa: wwn }, "envelope": { "from", "to", "ts", "exp", "cap"?, "body" }, "authorization": "allow" or the error of the `capability/v0` token checks (CAP-160 steps 1–7 and 9), "store": { hash: { "size", "blocks"? } } }`. The step-8 match of `cap.capability` with the hash is done by the kind. | `{ "hash", "size", "ranges" }` | the errors of §7.3 |
| `blob/provenance` | `{ "receiverOwner", "reference": { "senderOwner", "taint" }, "providerOwner", "otherReferences": [taint] }` | `{ "trust", "taint" }` | `EnvelopeInvalid` |
| `blob/providers` | `{ "fetcherOwner", "pins", "senderOwner", "taintOwners", "reference", "agentCerts": { wwa: { "owner", "node" } }, "grants": [provider], "local": { "held", "entitled" } }` | `{ "local": bool, "contact": [provider] }` in reference order | `BlobRefInvalid` |

`blob/fetch` takes the result of `capability/v0` authorisation as an input, so it tests where that result is used
(order, independence from the store) without Biscuit tokens. Real `blob:` tokens belong in the
`capability/authorize` vectors ([open question 1](#17-open-questions)).

`conformance/tools/blob-vectors` (Rust) is the reference model. `cargo run -- generate` writes the vector files,
`cargo run -- check` compares them with the generator, `cargo run -- adapter` serves the model over the stdio
adapter protocol, and `cargo test` also checks that every `MUST` here has a vector or a pending marker and that
the tree model and `bao-tree` 0.17 produce identical encodings and accept each other's. Every case states its
verdict by hand and the generator refuses to write one the model disagrees with.

### 16.2 Coverage

| Requirement | Covered by |
|---|---|
| BLOB-001 | `blob/hash` (incl. values of the official BLAKE3 vectors for lengths 0, 1, 1024, 1025, 102400) |
| BLOB-010 | `blob/ref`, `blob/providers` (`bad-reference`) |
| BLOB-020 | `blob/encode` |
| BLOB-015 | `blob/providers` (`local-*`) |
| BLOB-021, BLOB-022, BLOB-024 | `blob/verify` |
| BLOB-023 | `blob/ranges`, `blob/fetch` (`past-end`, `size-probe`) |
| BLOB-031 … BLOB-034 | `blob/fetch`, `blob/ranges` |
| BLOB-040 | `blob/verify` (`cut`, `cut-empty`, `resume`, `short-fin`) |
| BLOB-041 | `blob/providers` |
| BLOB-042 | `blob/fetch` (`partial-*`) |
| BLOB-050, BLOB-051 | `blob/provenance` |
| BLOB-002, BLOB-011 … BLOB-014, BLOB-030, BLOB-035 … BLOB-037, BLOB-043, BLOB-052, BLOB-053, BLOB-060, BLOB-061, BLOB-070, BLOB-071, BLOB-080, BLOB-081, BLOB-090 | **pending**: harness scenarios against a running node (T8 implementation, M1 step 5) |

The pending requirements are behaviour of a node (what it sends, stores, logs, or gives an agent), which no
pure-function vector can test. Each carries the `*Pending: T8.*` marker of change 0001, which is proposed in the
`capability/v0` draft. Until 0001 is accepted, `conventions.md` (CONV-004) counts these 19 IDs as untested
([open question 8](#17-open-questions)).

## 17. Open questions

1. **`cap.grants` in `capability/v0`.** This document adds the `grants` member to `cap` and needs `blob:` cases in
   `capability/authorize` (valid grant, grant for another hash, grant re-delegated by the sender, grant presented by
   an agent that is not its holder). `capability/v0` should take both over, as it did for `onward`.
2. **Blob custody when the sender goes offline.** v0 relies on the recipient fetching early (§7.6). A sender could
   instead deposit the blob with its owner's mailbox host and list it as a provider. That needs a `blob:*#deposit`
   capability at the host and grants the host can mint for the recipient. Worth it before M2?
3. **Profile wording.** The profile's `BlobNotFound` text says "or the caller may not read it", and `INLINE_MAX`
   does not say what "Part size" is. This document narrows the first (§13) and defines the second (§3). The profile
   should be aligned.
4. **End-to-end confidentiality.** With third-party providers or mirrors, blob content is visible to them.
   Encrypting the content to the recipient (convergent or per-recipient keys) interacts with deduplication and with
   the hash as identifier. Deferred with sealed envelopes (T15).
5. **Live artefacts.** A2A streams artefacts in chunks (`append`, `lastChunk`). v0 blobs are complete before they
   are referenced. Long outputs either go as several blobs or wait; a growing-blob mode (hash of a prefix, later
   extended) is possible with the same tree but not specified.
6. **Range granularity.** Ranges are whole 16 KiB blocks. `iroh-blobs` can also serve sub-block chunk ranges with
   extra internal pairs. Byte-exact range reads are rarely needed by agents, so v0 leaves them out.
7. **Fetching from own-owner nodes not in the reference.** A fetcher could use a copy on another node of its own
   owner, but CAP-110 means only that node's issuing key can mint the token, and v0 defines no owner-internal way
   to ask for one. It also has to respect entitlement (BLOB-015) across nodes.
8. **Pending marker and frame registry.** This document depends on change 0001 (`*Pending:*` markers) and takes
   frame types `0x20`–`0x22` from the range the binding shares among all extensions. The binding should keep a
   registry of extension frame types so that `shared-doc/v0` cannot collide.
9. **Durable dedupe for reads.** `envelope/v0` dedupe entries are durable writes. For Fetches, which are short-lived
   reads bound to one connection, an in-memory entry until `exp + SKEW` would be enough. The envelope draft should
   say whether an operation may opt out of durability.

---

## Appendix A. Example: M1 step 5

`beta` (owner B, agent `tester`) finishes a run and produces a 100 000-byte log. `alpha` (owner A, agent
`planner`) delegated the task. Identifiers are shortened.

1. `tester` returns the log to its node. The node hashes it, `blake3:d93c23eedaf165a7e0be908ba86f1a7a520d568d2d13cde787c8580c5c72cc54`
   (the vector `ref.json#no-providers`), stores it with its outboard, and, because 100 000 > `INLINE_MAX`, emits a
   reference Part in the `artifactUpdate` event:

   ```json
   { "url": "webway-blob:blake3:d93c23ee…cc54?size=100000&providers=wwn:beta…/wwa:tester…",
     "mediaType": "text/plain; charset=utf-8", "filename": "test-run.log" }
   ```

   The event envelope's `prov` gives this Part `taint = { owners: [B], unverified: false }`, and its `cap.grants`
   holds one grant: `blob:blake3:d93c…cc54#read` at `wwn:beta…/wwa:tester…`, minted by `beta`'s issuing key,
   holder `planner`, expiring 24 hours later.
2. `alpha` verifies the event (`envelope/v0`), keeps the grant for `planner` (BLOB-014), parses the reference
   (BLOB-010), and checks the provider: `tester`'s agent-cert names node `beta` and owner B, which A pinned from the
   invite, and `planner` holds a grant for it (BLOB-041).
3. `alpha` opens a BLOB stream to `beta` (over the relay, as the devnet forbids direct dialling) and sends a FETCH
   signed by `planner` with `cap.capability = blob:blake3:d93c…cc54#read`, the grant as `cap.access`, and no
   `ranges`.
4. `beta` checks the binding of `planner` to `alpha`'s node, the TTL, the body, the capability string, runs
   `capability/v0` authorisation (holder `planner`, unexpired, issued by `beta`'s issuing key), then finds the blob
   and replies `{ size: 100000, ranges: [[0, 7]] }`, followed by `64·6 + 100000 = 100384` bytes of encoding.
5. The relay drops the connection after 33 060 bytes, inside block 2. `alpha` has verified blocks 0 and 1 (the vector
   `verify.json#cut`). It sends a new FETCH for `[[2, 7]]`, gets the remaining blocks (`verify.json#resume`),
   verifies the last block, and marks the blob complete.
6. `planner` receives the log inside a labelled container: trust `foreign`, taint owners `[B]`, origin
   `beta/tester`, with `mediaType` and `filename` as data (BLOB-050, BLOB-052). Both nodes log the fetch (§10).

## Appendix B. Changes from the due diligence

1. **Providers name an agent as well as a node** (`wwn:…/wwa:…`): a Fetch is a signed envelope, which needs a `to`
   agent, and a capability is checked for a presenter agent.
2. **Grants travel in `cap.grants`.** The due diligence said a blob read needs a capability scoped to the hash
   but not how the recipient gets one. Tokens may not go into Parts, so they travel in the signed header.
3. **Whose key roots a grant** (ART-2): the provider's owner, per node, like every `capability/v0` access token.
4. **Own request layer, `iroh-blobs` encoding.** The due diligence named `iroh-blobs` for transfer. Its hash and
   encoding are kept; its request protocol is replaced by signed, capability-checked Fetch envelopes on the
   binding's BLOB stream.
5. **Ranges in 16 KiB blocks**, and the effective-range rule for size probes.
6. **Authorisation before lookup**, so a provider is not an existence oracle.
7. **Taint from the referencing Part only** (ART-3), and per reference under deduplication.
8. **Provider eligibility** (G14 for blobs): only certified providers of pinned owners that already have a part
   in the content, and for which the agent holds a grant, are dialled.
9. **Per-agent entitlement** to blobs in a node's shared, deduplicated store, so that "knowing the hash is not
   enough" also holds inside a node.

[RFC 8785]: https://www.rfc-editor.org/rfc/rfc8785
[blake3-paper]: https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf
