# Ed25519 verifier differential against the envelope/v0 strict rule (ENV-210/211)

Track: T2 `envelope/v0` (signature vectors), T4 conformance, T19 security. Code: [`ed25519-verifier-diff/`](ed25519-verifier-diff/).

## Question

`audit/v0` AUD-201 (and, via it, `envelope/v0` ENV-210/211 and `capability/v0` CAP-002) require **strict** Ed25519:
a canonical key that is not of small order, plus ed25519-dalek `verify_strict` (`conformance/tools/audit-vectors/src/audit.rs:152`).
RFC 8032 leaves several choices to the verifier, and libraries differ. Those choices are: canonical or permissive
decoding of A and R, small-order checks, S < L, and a cofactored or cofactorless equation. Our stack already uses
several verifiers, and some others are likely:

- the Rust node, plus biscuit-auth inside it
- a TypeScript inspector UI
- the upstream A2A SDKs at the HTTP edge (a2a-js, a2a-python and a2a-go, for card JWS)
- third-party implementations that run the conformance suite

So the question has three parts:

1. Which of those verifiers accept exactly what ENV-210/211 accepts?
2. Where do they disagree?
3. Do the current conformance vectors catch the verifiers that disagree?

## Method

A Rust generator ([`rs/src/main.rs`](ed25519-verifier-diff/rs/src/main.rs), curve25519-dalek 4.1, seeded) builds
signatures with known discrete logs:

- A = a·B + T_A and R = r·B + T_R, where T is from the 8-torsion, and S = r + k·a (mod L), optionally + L.
  Then S·B − k·A − R = −(T_R + k·T_A). The cofactored equation always holds, and the cofactorless one holds iff
  T_R + k·T_A = 0.
- Key classes: prime order (1), mixed order (7), small order canonical (8), and small order non-canonical (6). The
  last are the only decodable non-canonical encodings with a known discrete log. Another 18 non-canonical
  encodings decode to points of large order, but nobody can sign under them.
- R classes: the same four classes.
- S classes: canonical, or S + L.
- 16 messages per (A, R) pair, with S + L for 4 of them: **9,680 adversarial cases**.
- **20,000 honest** signatures as a false-reject check.
- The **12 speccheck vectors** of Chalkias et al.
- Every case also records reference features (canonical, small order, torsion-free, each equation), computed
  independently of every verifier under test.

Verifiers (all accept bits from real library calls):

| Language | Verifier | Who in our stack uses it |
|---|---|---|
| Rust | audit-vectors ENV-210/211 (copied verbatim) | conformance tool, spec reference |
| Rust | ed25519-dalek 2.2 `verify_strict` | biscuit-auth 6 (`crypto/ed25519.rs`: `VerifyingKey::from_bytes` + `verify_strict`, checked in source) |
| Rust | ed25519-dalek 2.2 `verify` | default `Verifier` trait impl |
| Rust | ed25519-zebra 4.2 (ZIP-215) | Zcash/Penumbra style consensus |
| Rust | ring 0.17.14 | rustls, many HTTP stacks |
| JS | node:crypto `verify`, WebCrypto `subtle` (node 22.22.2, OpenSSL 3.6.2) | jose → a2a-js card JWS, any Node service |
| JS | the same calls under bun 1.3.3 (BoringSSL, the library in Chrome) | proxy for Chrome WebCrypto |
| JS | @noble/curves 2.4 and @noble/ed25519 3.2, default and `{zip215:false}` | most likely pick for a React UI |
| JS | tweetnacl 1.0.3 | common in browsers |
| JS | libsodium-wrappers 0.7.16 (libsodium 1.0.20, wasm) | candidate for the UI |
| Python | PyNaCl 1.6.2 (libsodium) and cryptography 50 (OpenSSL 4.0.3) | a2a-python (PyJWT → cryptography) |
| Go | crypto/ed25519 (go1.27.3) | a2a-go |

Python and Go appear only as interop probes for upstream SDKs, not as project code. The run took about 10 minutes
on CPU, mostly the pure-JS libraries. No GPU was used.

## Results

### 1. Five behaviour classes. ENV-210/211 accepts the least, and everyone accepts what it accepts.

| Implementation | honest rejected | adversarial accepted | accepts where ENV-210/211 rejects | rejects where ENV-210/211 accepts |
|---|---|---|---|---|
| **ENV-210/211**, dalek `verify_strict` (= biscuit-auth), **libsodium** (PyNaCl, libsodium.js) | 0 / 20,000 | 128 / 9,680 | 0 | 0 |
| dalek `verify`, ring, OpenSSL (node:crypto, WebCrypto, Python cryptography), BoringSSL (bun node:crypto and WebCrypto), Go crypto/ed25519 | 0 | 710 | **582** | 0 |
| tweetnacl | 0 | 889 | **761** | 0 |
| @noble/curves and @noble/ed25519 `{zip215:false}` | 0 | 2,048 | **1,920** | 0 |
| ed25519-zebra, @noble/curves and @noble/ed25519 default (ZIP-215) | 0 | 7,744 | **7,616** | 0 |
| *pre-check (canonical A and R, neither of small order, S < L) + node:crypto* | 0 | 128 | **0** | 0 |
| *pre-check + @noble/curves `{zip215:false}`* | 0 | 1,024 | **896** | 0 |

Within each row the accept sets are bit-identical over all 29,692 cases (20 verifier configurations). Full per-class tables:
[`out/tables.md`](ed25519-verifier-diff/out/tables.md).

What separates the classes:

- **OpenSSL, Go, ring and dalek `verify`** accept a small-order A or R whenever the cofactorless equation holds.
  That includes speccheck 0–2 and the "identity key, any message" signature.
- **tweetnacl** additionally accepts S + L, so its signatures are malleable.
- **noble `{zip215:false}`** decodes canonically, but its equation is **always cofactored**. It accepts every
  mixed-order or small-order R and A, and no pre-check can fix that without a torsion check on R.
- **ZIP-215** (zebra, noble default) also accepts non-canonical A and R encodings.

Every verifier tested accepts every signature that ENV-210/211 accepts. That includes the 112 accepted
mixed-order-key cases where the cofactorless equation holds. Every verifier also accepts all 20,000 honest
signatures. So the strict rule never harms interop with honest signers. The disagreements are all of one kind: a
permissive verifier accepts something the node rejects. Only the signer can produce those signatures, by choosing a
weird key or nonce.

### 2. The current audit vectors detect only tweetnacl

All 30 signature-bearing `checkpoint.json` and `receipt.json` vectors were run through every verifier
([`out/audit/matrix.md`](ed25519-verifier-diff/out/audit/matrix.md)):

- `weak-key` (log = identity point) is rejected by **all 16** verifiers that ran on the audit vectors (all but bun). It reuses beta's signature, so the equation
  fails for everyone. It cannot detect a verifier that skips the small-order key check, which is what AUD-201 says it
  tests.
- `non-canonical-s` (S + L) is accepted only by tweetnacl.
- So 11 of the 12 permissive verifiers (all but tweetnacl) would pass every current signature vector.

### 3. Four drop-in vectors close the gap

`ed25519-verifier-diff propose` re-signs the `valid` checkpoint with the beta-node test key (seed rule from the
vectors README) and writes [`proposed-checkpoint-vectors.json`](ed25519-verifier-diff/proposed-checkpoint-vectors.json).
All four expect `reject` / `CheckpointInvalid`.

| vector | ENV / dalek strict / libsodium | OpenSSL / Go / ring / dalek verify | tweetnacl | noble zip215:false | ZIP-215 (zebra, noble default) |
|---|---|---|---|---|---|
| `small-order-r`: R = identity, S = k·a | reject | **accept** | **accept** | **accept** | **accept** |
| `mixed-order-r`: R = r·B + T₈ | reject | reject | reject | **accept** | **accept** |
| `non-canonical-r`: identity with the sign bit set | reject | reject | reject | reject | **accept** |
| `weak-key-valid-equation`: log = identity, R = r·B, S = r | reject | **accept** | **accept** | reject | **accept** |

`small-order-r` **alone** separates all 12 permissive verifiers from the strict ones. The four together, plus the
existing `non-canonical-s`, separate all five classes from each other.
([`out/proposed/matrix.md`](ed25519-verifier-diff/out/proposed/matrix.md))

### 4. Speccheck (Chalkias et al.) reproduction

ENV-210/211 accepts only vector 3 of 0–11, the same as libsodium's row in the paper. dalek `verify`, ring, OpenSSL
and Go accept {0, 1, 2, 3, 11}. ZIP-215 accepts {0–5, 9–11}. noble `{zip215:false}` accepts {2–5}. tweetnacl accepts
{0–3, 6, 7, 11}, and 6–7 are the S ≥ L cases.

## What this means for argent-webway

- **Inside the Rust node, nothing to fix.** The audit-vectors rule, biscuit-auth and libsodium are bit-identical.
  The ENV key check (canonical, not small order) adds nothing over `verify_strict` for *signature* acceptance on
  this corpus. It is still worth keeping, because it rejects weak `wwa:`/`wwn:` identifiers at parse time, before
  any signature arrives.
- **A TS inspector that re-verifies would show "valid" on envelopes, checkpoints or receipts that the node
  rejected.** That happens if it uses @noble (the obvious choice), WebCrypto or tweetnacl, on adversarial input
  only. Two options match exactly:
  - (a) libsodium.js `crypto_sign_verify_detached`: 0 diffs, wasm, about 4 s for 29.7 k verifications.
  - (b) the 4-check pre-check followed by WebCrypto/OpenSSL: 0 diffs.

  Option (b) depends on the browser's WebCrypto being cofactorless. That was checked here only for OpenSSL and for
  BoringSSL via bun (Chrome's library), not for Firefox (NSS) or Safari. The simplest choice is (a), or have the UI show the node's
  verdict instead of re-verifying.
- **A2A edge.** a2a-js, a2a-python and a2a-go all sit in the OpenSSL/Go class. Cards that argent signs verify there
  (strict ⊂ permissive). Third-party cards that argent rejects but they accept need a signer that deliberately uses
  a small-order R or key. That is a curiosity, not an attack, but such a card is **repudiable**: an identity-key
  signature verifies for every message. The profile should state that a gateway applies ENV-210/211 to cards and
  owner bindings too, not the SDK's verifier.
- **Third-party implementations** using a stdlib verifier pass every current vector, but would disagree with
  reference nodes on adversarial signatures. On replicated data, such as audit evidence, that becomes a split view
  between auditors.

## Recommendation (for the planner)

1. **Keep strict (cofactorless, libsodium-equivalent) as the v0 rule.** ZIP-215 would buy consistent batch
   verification, but it would split from biscuit-auth's `verify_strict` inside the same node, and it permits
   non-canonical encodings. Make the spec text self-contained so it does not depend on a crate. Something like:
   "A and R MUST be canonical encodings and not of small order; S MUST be < L; verify [S]B = R + [k]A
   (cofactorless); equivalent to libsodium ≥ 1.0.16 `crypto_sign_verify_detached` and ed25519-dalek
   `verify_strict`".
2. **Add the 4 proposed vectors** to `checkpoint.json` (and the analogous envelope and receipt forms when ENV
   vectors land). Then **fix `weak-key`** so that its equation holds, or replace it with `weak-key-valid-equation`.
   Otherwise it tests nothing. Changing the files means regenerating through `audit-vectors` so that `--check` still
   passes. That is a master change and belongs in a PR, not the lab.
3. **Add a non-normative note** to ENV-210: "stdlib verifiers (OpenSSL, Go, ring, WebCrypto) conform when preceded by
   the 4 checks; @noble and ZIP-215 verifiers do not; tweetnacl accepts S ≥ L". For TS, recommend libsodium.js.
4. Not needed: rejecting mixed-order (non-torsion-free) keys. ENV-210/211 accepts some signatures under them, but
   every verifier tested accepts those too. It would add a scalar multiplication for no interop gain. Revisit if
   batch verification is introduced.

Open, not tested here: Firefox and Safari WebCrypto Ed25519, iroh's own signature checks on discovery records, and
aws-lc-rs (rustls' default provider).

## Sources

- RFC 8032 §5.1.7, Ed25519 verify: https://www.rfc-editor.org/rfc/rfc8032#section-5.1.7
- K. Chalkias, F. Garillot, V. Nikolaenko, "Taming the many EdDSAs", SSR 2020: https://eprint.iacr.org/2020/1244.
  Vectors at https://github.com/novifinancial/ed25519-speccheck (`cases.json`, vendored in `data/`, Apache-2.0).
- ZIP-215, explicit Ed25519 validation criteria: https://zips.z.cash/zip-0215
- H. de Valence, "It's 255:19AM. Do you know what your validation criteria are?":
  https://hdevalence.ca/blog/2020-10-04-its-25519am
- ed25519-dalek `verify_strict`: https://docs.rs/ed25519-dalek/2.2.0/ed25519_dalek/struct.VerifyingKey.html#method.verify_strict
- libsodium signatures: https://doc.libsodium.org/public-key_cryptography/public-key_signatures
- noble-curves `zip215` option: https://github.com/paulmillr/noble-curves
- Repo: `spec/ext/audit.md` AUD-201, `conformance/tools/audit-vectors/src/audit.rs:152`, `conformance/vectors/audit/checkpoint.json`

## Reproduce

`lab/ed25519-verifier-diff/run.sh`. It needs cargo, node 22 and optionally bun. Python (pynacl, cryptography) and a
Go toolchain go under `.agent-work/`.
