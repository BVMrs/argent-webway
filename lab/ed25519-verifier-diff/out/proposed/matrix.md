| impl | small-order-r | mixed-order-r | non-canonical-r | weak-key-valid-equation |
|---|---|---|---|---|
| rs:ENV-210/211 (audit-vectors) | reject | reject | reject | reject |
| rs:ed25519-dalek 2.2 verify | **accept** | reject | reject | **accept** |
| rs:ed25519-dalek 2.2 verify_strict (= biscuit-auth 6) | reject | reject | reject | reject |
| rs:ed25519-zebra 4 (ZIP-215) | **accept** | **accept** | **accept** | **accept** |
| rs:ring 0.17 | **accept** | reject | reject | **accept** |
| js:node:crypto.verify [node 22.22.2 (OpenSSL 3.6.2)] | **accept** | reject | reject | **accept** |
| js:@noble/curves 2.4 ed25519 (default zip215:true) | **accept** | **accept** | **accept** | **accept** |
| js:@noble/curves 2.4 ed25519 {zip215:false} | **accept** | **accept** | reject | reject |
| js:@noble/ed25519 3.2 (default) | **accept** | **accept** | **accept** | **accept** |
| js:@noble/ed25519 3.2 {zip215:false} | **accept** | **accept** | reject | reject |
| js:tweetnacl 1.0.3 | **accept** | reject | reject | **accept** |
| js:WebCrypto subtle [node 22.22.2 (OpenSSL 3.6.2)] | **accept** | reject | reject | **accept** |
| js:libsodium-wrappers 0.7.16 [libsodium 1.0.20] | reject | reject | reject | reject |
| py:PyNaCl 1.6.2 (bundled libsodium) | reject | reject | reject | reject |
| py:cryptography 50 [OpenSSL 4.0.3 29 Sep 2026] | **accept** | reject | reject | **accept** |
| go:crypto/ed25519 [go1.27.3] | **accept** | reject | reject | **accept** |
