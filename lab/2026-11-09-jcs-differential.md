# JCS (RFC 8785) in Rust for envelope/v0: differential tests against an ECMAScript oracle

Track: T2 `envelope/v0` (critical path T0 → T2 → T5 → M1), and the I-JSON rule (ENV-100) that `audit/v0` AUD-001
already relies on. Kind: harder tests (d), plus a small prior-art check.

## Question

Every webway signature is over `JCS(x)`, and `body_hash = BLAKE3(JCS(body))`. The verifier parses the received
JSON into a generic value and canonicalises it again (due diligence §4.4). If two implementations make different
bytes from the same input, signatures fail between them. Worse, a verifier could check one value while the
application reads another. So:

**Do the Rust JCS crates we would use produce exactly the RFC 8785 bytes, and does the parse step in front of
them enforce the I-JSON rules that envelope/v0 requires (no duplicate keys, no lone surrogates, numbers in
double range and precision)? Under which build configurations?**

## Method

Code in [`lab/jcs-differential/`](jcs-differential/); run with `run.sh`. Output is in `results.txt`.

- **Oracle**: `oracle.ts`, run by Node 22 (V8 12.4). It does `JSON.parse` followed by the RFC 8785 reference
  algorithm. RFC 8785 defines number and string serialisation as ECMAScript `JSON.stringify` and key order as
  UTF-16 code-unit order, so V8 runs the spec's own model. The oracle also rejects duplicate keys (by scanning the
  text), lone surrogates and non-finite numbers, which is what ENV-100 asks for.
- **Rust pipelines**: 2 parsers × 3 canonicalisers. The parsers are `lax` (`serde_json::from_str::<Value>`) and
  `strict` (`src/strict.rs`: a key-only pass with serde that rejects duplicate keys, then the same `Value` parse).
  The canonicalisers are `serde_json_canonicalizer` 0.3.2 (used by `conformance/tools/audit-vectors` on
  master), `serde_json_canonicalizer` 0.4.1 and `serde_jcs` 0.2.0. `jcs-canonicalize` is only a wrapper around
  `serde_jcs`, so I dropped it. serde_json is 1.0.154.
- **2 600 039 generated inputs** (seed 1):

  | Category | Cases | What it tests |
  |---|---|---|
  | `num-bits` | 1 000 000 | random finite doubles from random bits, written in shortest form (serialisation) |
  | `num-short` | 300 000 | 1–17 digits, exponent ±30: the 1e-7 and 1e21 notation switches |
  | `num-dec` | 300 000 | 1–40 significant digits, exponent −345…310 (correct rounding in the parser) |
  | `num-mid` | 200 000 | the **exact** decimal midpoint between two adjacent doubles, or a hair above or below it (the hardest rounding cases; `src/bigdec.rs`) |
  | `int-*` | 400 000 | integers ≤ 2^53, 2^53…2^63, 2^63…2^64, and > 2^64 |
  | `num-edge` | 24 | `-0`, `1e21`, 2^53+1, u64::MAX, smallest subnormal and its midpoint, f64::MAX and its midpoint, overflow, underflow |
  | `str` | 200 000 | random code points (controls, DEL, U+2028, BMP private use, non-BMP), each written raw or as `\u` in either case |
  | `keys` | 200 000 | objects whose keys come from the ranges where UTF-8 order and UTF-16 order differ (U+E000–U+FFFF against non-BMP) |
  | `ijson` | 8 | duplicate keys (one written with an escape, `"a"` and `"a"`, one nested), lone high and low surrogates in values and keys |
  | `depth-*` | 7 | nesting depths 64, 127, 128, 129, 200, 1 000 and 5 000 |

- Each pipeline also checks idempotence: `canon(parse(canon(x))) == canon(x)`.
- **RFC 8785 reference data**: the 6 input/output pairs in `cyberphone/json-canonicalization/testdata`
  (commit `32a48195`).
- **Build variants**: Cargo merges the features of a crate across the whole dependency graph. So I ran the
  harness a second time with serde_json's `arbitrary_precision` feature on. A separate package
  (`parse-default/`) uses serde_json **without** `float_roundtrip` and compares its f64 parse with
  `str::parse::<f64>`, which is correctly rounded.
- **Probes** (`jcs-differential probe`):
  - AUD-001 number tokens against a copy of `numbers_ok` from `conformance/tools/audit-vectors/src/audit.rs`
    (master `10d10ad`)
  - number spellings that canonicalise to the same bytes
  - a signed header with a duplicate `to`

## Results

### 1. Canonical output: the three crates match RFC 8785 exactly

| Pipeline (each of the 6) | Agree with oracle | Different bytes | Rust error, oracle OK | Oracle error, Rust OK | Both error | Not idempotent |
|---|---|---|---|---|---|---|
| `lax` + any crate | 2 594 216 | **0** | 4 (depth) | **3 (duplicate keys)** | 5 816 | 0 |
| `strict` + any crate | 2 594 216 | **0** | 4 (depth) | **0** | 5 819 | 0 |

- No output byte differs on numbers, strings or key order. That includes all 200 000 rounding midpoints, 2^53+1
  (`9007199254740992`), u64::MAX (`18446744073709552000`), `1e21` (`1e+21`), `-0` (`0`) and the U+FFxx-versus-
  non-BMP key orders. Each crate passes all 6 RFC 8785 reference files.
- The "both error" rows are expected. 5 807 are `num-dec` values that overflow to ±Inf, 3 are edge cases that
  overflow, 5 are lone surrogates (serde_json rejects them at parse time, as V8-plus-check does), and 1 is the
  depth-5000 case (the oracle's own recursion overflowed the stack).
- **Turning on `arbitrary_precision` changes nothing.** All three crates still give identical bytes. serde_json's
  own serialisation, however, now keeps the original spelling: `[1e2,100.0]` becomes `[1e+2,100.0]` instead of
  `[100.0,100.0]`. So JCS is safe under that feature, but any code that hashes `serde_json::to_string` output is
  not.
- The first version of my strict parser built the `Value` in its own visitor. It broke under
  `arbitrary_precision`: 1 894 211 number cases per crate gave wrong output, because numbers then arrive as the private map
  `{"$serde_json::private::Number": …}`. The version kept here only checks keys and leaves `Value`
  construction to serde_json. The lesson for T5: a hand-written visitor in a verifier is fragile under feature
  merging, so CI should build with `arbitrary_precision` on as well.

### 2. Duplicate keys are silently accepted by every Rust pipeline that uses `serde_json::Value`

`{"v":"webway-envelope/0","to":"wwa:alice","to":"wwa:mallory","id":"x"}` canonicalises to
`{"id":"x","to":"wwa:mallory","v":"webway-envelope/0"}`. The signature check runs on the last `to`. A component
that keeps the first value of a duplicate key sees `wwa:alice`. Parsers do differ on which duplicate wins
([Bishop Fox 2021](https://bishopfox.com/blog/json-interoperability-vulnerabilities)), and that difference is exactly the verify-one-read-another gap. The
duplicate-key check in `serde_json_canonicalizer` 0.4 does not help here: it runs while serialising, after
`Value` has already merged the keys. The escaped form `"a"` (the same name as `"a"`) is caught only after
unescaping, which the strict pass does. The fix is the 45-line `strict.rs` (a key-only pass before the parse).
It costs one extra parse of the text and rejects all 8 I-JSON cases.

### 3. serde_json's default float parser is not correctly rounded, and only Cargo's feature merging hides it

Without `float_roundtrip`, `serde_json::from_str::<f64>` disagrees with the correctly rounded parse as follows:

| Category | Cases | Mis-rounded |
|---|---|---|
| `num-bits` (shortest round-trip strings) | 1 000 000 | **29.6 %** (all by 1 ulp) |
| `num-short` (e.g. `92e91`, `470e-28`) | 300 000 | 10.0 % |
| `num-dec` | 294 193 | 29.8 % |
| `num-mid` | 200 000 | 51.2 % |
| `num-edge` | 21 | `1.7976931348623158e308` is rejected as "out of range" (it is f64::MAX); `2.4703282292062328e-324` gives 0 instead of 5e-324 |

- **Why the harness itself is fine**: `serde_json_canonicalizer` and `serde_jcs` both turn on
  `serde_json/float_roundtrip`, and Cargo merges that into every user of serde_json in the same build
  (`cargo tree -e features` confirms it for the harness and for audit-vectors).
- **Where it breaks**: any webway binary that parses or re-serialises signed JSON without one of those crates in
  its build, such as a mailbox host, gateway or inspector back end. On about 30 % of non-integer numbers it would
  compute a different `JCS(body)`. The result is a `body_hash` mismatch, and the envelope is rejected as
  `EnvelopeInvalid` between honest nodes.
- **Why this matters for envelope/v0**: header fields are strings and safe integers, but A2A bodies carry
  arbitrary agent JSON (DataPart), where fractions are common.

### 4. Nesting depth: Rust rejects at depth 128, V8 accepts at least 1 000

serde_json's recursion limit rejects `[`×128 and deeper, and accepts 127. V8 accepted 1 000. Without a
spec constant, a JS or Go sender can produce an envelope that every Rust node rejects. A mailbox host in another
language would store it and deliver it forever until it expires. This is an interoperability and liveness issue,
not a forgery.

### 5. AUD-001 and audit-vectors disagree on integer spellings (master)

AUD-001 says "an integer of magnitude at most 2^53 − 1 (no fractions or exponents that denote non-integers)". By
that wording, `1e2`, `100.0`, `1.00e2` and `9.007199254740991e15` are allowed: they denote integers and
canonicalise to `100` and `9007199254740991`. The reference `numbers_ok` **rejects** them, because serde_json
parses any token with a fraction or exponent as f64 and `as_u64` returns `None`. It also rejects `-0` (parsed as
f64 −0.0), which the spec wording neither allows nor forbids. **No vector in `conformance/vectors/audit/`
exercises `not-ijson`** (0 hits).

The vector format stores entries as parsed JSON, so it cannot express duplicate keys or a choice of number
spelling at all. Those cases need raw-text inputs.

### 6. Spelling aliases are inherent to JCS, so any check must run on the received text

- `0`, `-0`, `0.0`, `0e9`, `1e-400` and `-1e-400` all canonicalise to `0`.
- `9007199254740993` and `9.007199254740993e15` both canonicalise to `9007199254740992`.

Because nodes "forward as received" (§4.4), a relay can change a number's spelling without breaking the signature.
A downstream decoder that uses big decimals then reads a value the signer never signed (`1e-400` ≠ 0, 2^53+1 ≠
2^53). The rule "integers outside ±2^53 MUST be strings" only helps if it is checked on the **token**: the parsed
value of `9.007199254740993e15` is exactly 2^53, which looks like a normal number.

## What applies from prior art

- **RFC 8785 §3.2.2.3** delegates numbers to ECMAScript Number::toString. All three crates use `ryu-js` and match
  V8 on about 1.8 M doubles, so we can rely on that part.
- **RFC 8785 §3.1** requires I-JSON input, but leaves enforcing it to the parser. That is exactly where the
  Rust pipelines are weak (results 2 to 4).
- **RFC 7493 §2.3** says object names MUST NOT be duplicated. **RFC 8259 §4** says that when names are not
  unique, behaviour is unpredictable. That is why "accept and take the last" is not a safe default.
- The cyberphone reference implementations (Java, Go, JS, Python, C#) also sit on their language's default
  parser, so the same duplicate-key gap is likely in those stacks. I did not test them.

## Sources

- RFC 8785, JSON Canonicalization Scheme: https://www.rfc-editor.org/rfc/rfc8785
- RFC 7493, I-JSON: https://www.rfc-editor.org/rfc/rfc7493 (§2.2 numbers, §2.3 duplicate names)
- RFC 8259 §4: https://www.rfc-editor.org/rfc/rfc8259#section-4
- ECMA-262 Number::toString: https://tc39.es/ecma262/#sec-numeric-types-number-tostring
- RFC 8785 reference test data: https://github.com/cyberphone/json-canonicalization/tree/master/testdata (commit 32a48195)
- serde_json features `float_roundtrip` and `arbitrary_precision`: https://github.com/serde-rs/json/blob/master/Cargo.toml
- serde_json_canonicalizer: https://crates.io/crates/serde_json_canonicalizer ; serde_jcs: https://crates.io/crates/serde_jcs
- Bishop Fox, "An Exploration of JSON Interoperability Vulnerabilities" (2021): https://bishopfox.com/blog/json-interoperability-vulnerabilities

## What the planner should do next

1. **T2 (envelope/v0 ENV-100)**: write the I-JSON rule as checks on the received text, done before
   canonicalisation:
   - reject duplicate names after unescaping
   - reject lone surrogates
   - reject non-finite numbers and numbers that underflow to zero from a non-zero token
   - define a `MAX_DEPTH` (suggest 64 from the envelope root, below serde_json's 128), rejected as
     `EnvelopeInvalid` with a new reason
   - consider pinning number spelling in signed data ("each number token MUST equal its JCS form"). That removes
     result 6 and makes "forward as received" byte-stable.
2. **T2 vectors**: add a raw-text vector kind (input as a string, not as a parsed object), so duplicate keys,
   `a` aliases, spellings and depth can be tested. Seed the number vectors from `num-mid`: about half of
   them catch a parser that is not correctly rounded.
3. **T5 (reference node)**: depend on `serde_json` with `float_roundtrip` **explicitly** in every crate that
   touches signed JSON, not through a transitive dependency. Put the strict pass from `strict.rs` (or an
   equivalent) in front of `Value`. Add a CI job that builds with `arbitrary_precision` on.
   `serde_json_canonicalizer` 0.3 (already used) is fine for the bytes. Moving to 0.4 changes nothing for `Value`
   input.
4. **audit/v0 (small fix, owner's choice)**: either change AUD-001 to "written as an integer token
   `-?(0|[1-9][0-9]*)`, no fraction, exponent or `-0`", which matches what audit-vectors does today, or change
   `numbers_ok` to accept integer-valued f64. In both cases, add `not-ijson` vectors. The first option is simpler
   and removes aliases.
