## Per implementation (adversarial = all non-honest, non-speccheck cases)

| Implementation | honest rejected | adversarial accepted | accepts where ENV-210/211 rejects | rejects where ENV-210/211 accepts |
|---|---|---|---|---|
<!-- (20000 honest, 9680 adversarial cases)
 -->
| rs:ENV-210/211 (audit-vectors) | 0 / 20000 | 128 / 9680 | 0 | 0 |
| rs:ed25519-dalek 2.2 verify | 0 / 20000 | 710 / 9680 | 582 | 0 |
| rs:ed25519-dalek 2.2 verify_strict (= biscuit-auth 6) | 0 / 20000 | 128 / 9680 | 0 | 0 |
| rs:ed25519-zebra 4 (ZIP-215) | 0 / 20000 | 7744 / 9680 | 7616 | 0 |
| rs:ring 0.17 | 0 / 20000 | 710 / 9680 | 582 | 0 |
| js:node:crypto.verify [node 22.22.2 (OpenSSL 3.6.2)] | 0 / 20000 | 710 / 9680 | 582 | 0 |
| js:@noble/curves 2.4 ed25519 (default zip215:true) | 0 / 20000 | 7744 / 9680 | 7616 | 0 |
| js:@noble/curves 2.4 ed25519 {zip215:false} | 0 / 20000 | 2048 / 9680 | 1920 | 0 |
| js:@noble/ed25519 3.2 (default) | 0 / 20000 | 7744 / 9680 | 7616 | 0 |
| js:@noble/ed25519 3.2 {zip215:false} | 0 / 20000 | 2048 / 9680 | 1920 | 0 |
| js:tweetnacl 1.0.3 | 0 / 20000 | 889 / 9680 | 761 | 0 |
| js:WebCrypto subtle [node 22.22.2 (OpenSSL 3.6.2)] | 0 / 20000 | 710 / 9680 | 582 | 0 |
| js:libsodium-wrappers 0.7.16 [libsodium 1.0.20] | 0 / 20000 | 128 / 9680 | 0 | 0 |
| js:pre-check + node:crypto (OpenSSL) | 0 / 20000 | 128 / 9680 | 0 | 0 |
| js:pre-check + @noble/curves {zip215:false} | 0 / 20000 | 1024 / 9680 | 896 | 0 |
| js:node:crypto.verify [bun 1.3.3 (BoringSSL)] | 0 / 20000 | 710 / 9680 | 582 | 0 |
| js:WebCrypto subtle [bun 1.3.3 (BoringSSL)] | 0 / 20000 | 710 / 9680 | 582 | 0 |
| py:PyNaCl 1.6.2 (bundled libsodium) | 0 / 20000 | 128 / 9680 | 0 | 0 |
| py:cryptography 50 [OpenSSL 4.0.3 29 Sep 2026] | 0 / 20000 | 710 / 9680 | 582 | 0 |
| go:crypto/ed25519 [go1.27.3] | 0 / 20000 | 710 / 9680 | 582 | 0 |

## Accepted / total per case kind

| kind | n | I0 | I1 | I2 | I3 | I4 | I5 | I6 | I7 | I8 | I9 | I10 | I11 | I12 | I13 | I14 | I15 | I16 | I17 | I18 | I19 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A:mixed R:mixed S:+L cofactorless=n | 177 | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · |
| A:mixed R:mixed S:+L cofactorless=y | 19 | · | · | · | · | · | · | · | · | · | · | all | · | · | · | · | · | · | · | · | · |
| A:mixed R:mixed S:canon cofactorless=n | 691 | · | · | · | all | · | · | all | all | all | all | · | · | · | · | all | · | · | · | · | · |
| A:mixed R:mixed S:canon cofactorless=y | 93 | all | all | all | all | all | all | all | all | all | all | all | all | all | all | all | all | all | all | all | all |
| A:mixed R:prime S:+L cofactorless=n | 23 | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · |
| A:mixed R:prime S:+L cofactorless=y | 5 | · | · | · | · | · | · | · | · | · | · | all | · | · | · | · | · | · | · | · | · |
| A:mixed R:prime S:canon cofactorless=n | 93 | · | · | · | all | · | · | all | all | all | all | · | · | · | · | all | · | · | · | · | · |
| A:mixed R:prime S:canon cofactorless=y | 19 | all | all | all | all | all | all | all | all | all | all | all | all | all | all | all | all | all | all | all | all |
| A:mixed R:small S:+L cofactorless=n | 192 | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · |
| A:mixed R:small S:+L cofactorless=y | 32 | · | · | · | · | · | · | · | · | · | · | all | · | · | · | · | · | · | · | · | · |
| A:mixed R:small S:canon cofactorless=n | 775 | · | · | · | all | · | · | all | all | all | all | · | · | · | · | · | · | · | · | · | · |
| A:mixed R:small S:canon cofactorless=y | 121 | · | all | · | all | all | all | all | all | all | all | all | all | · | · | · | all | all | · | all | all |
| A:mixed R:small-nc S:+L cofactorless=n | 131 | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · |
| A:mixed R:small-nc S:+L cofactorless=y | 37 | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · |
| A:mixed R:small-nc S:canon cofactorless=n | 537 | · | · | · | all | · | · | all | · | all | · | · | · | · | · | · | · | · | · | · | · |
| A:mixed R:small-nc S:canon cofactorless=y | 135 | · | · | · | all | · | · | all | · | all | · | · | · | · | · | · | · | · | · | · | · |
| A:prime R:mixed S:+L cofactorless=n | 28 | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · |
| A:prime R:mixed S:canon cofactorless=n | 112 | · | · | · | all | · | · | all | all | all | all | · | · | · | · | all | · | · | · | · | · |
| A:prime R:prime S:+L cofactorless=y | 4 | · | · | · | · | · | · | · | · | · | · | all | · | · | · | · | · | · | · | · | · |
| A:prime R:prime S:canon cofactorless=y | 16 | all | all | all | all | all | all | all | all | all | all | all | all | all | all | all | all | all | all | all | all |
| A:prime R:small S:+L cofactorless=n | 28 | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · |
| A:prime R:small S:+L cofactorless=y | 4 | · | · | · | · | · | · | · | · | · | · | all | · | · | · | · | · | · | · | · | · |
| A:prime R:small S:canon cofactorless=n | 112 | · | · | · | all | · | · | all | all | all | all | · | · | · | · | · | · | · | · | · | · |
| A:prime R:small S:canon cofactorless=y | 16 | · | all | · | all | all | all | all | all | all | all | all | all | · | · | · | all | all | · | all | all |
| A:prime R:small-nc S:+L cofactorless=n | 12 | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · |
| A:prime R:small-nc S:+L cofactorless=y | 12 | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · |
| A:prime R:small-nc S:canon cofactorless=n | 48 | · | · | · | all | · | · | all | · | all | · | · | · | · | · | · | · | · | · | · | · |
| A:prime R:small-nc S:canon cofactorless=y | 48 | · | · | · | all | · | · | all | · | all | · | · | · | · | · | · | · | · | · | · | · |
| A:small R:mixed S:+L cofactorless=n | 200 | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · |
| A:small R:mixed S:+L cofactorless=y | 24 | · | · | · | · | · | · | · | · | · | · | all | · | · | · | · | · | · | · | · | · |
| A:small R:mixed S:canon cofactorless=n | 799 | · | · | · | all | · | · | all | · | all | · | · | · | · | · | · | · | · | · | · | · |
| A:small R:mixed S:canon cofactorless=y | 97 | · | all | · | all | all | all | all | · | all | · | all | all | · | · | · | all | all | · | all | all |
| A:small R:prime S:+L cofactorless=n | 22 | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · |
| A:small R:prime S:+L cofactorless=y | 10 | · | · | · | · | · | · | · | · | · | · | all | · | · | · | · | · | · | · | · | · |
| A:small R:prime S:canon cofactorless=n | 86 | · | · | · | all | · | · | all | · | all | · | · | · | · | · | · | · | · | · | · | · |
| A:small R:prime S:canon cofactorless=y | 42 | · | all | · | all | all | all | all | · | all | · | all | all | · | · | · | all | all | · | all | all |
| A:small R:small S:+L cofactorless=n | 225 | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · |
| A:small R:small S:+L cofactorless=y | 31 | · | · | · | · | · | · | · | · | · | · | all | · | · | · | · | · | · | · | · | · |
| A:small R:small S:canon cofactorless=n | 911 | · | · | · | all | · | · | all | · | all | · | · | · | · | · | · | · | · | · | · | · |
| A:small R:small S:canon cofactorless=y | 113 | · | all | · | all | all | all | all | · | all | · | all | all | · | · | · | all | all | · | all | all |
| A:small R:small-nc S:+L cofactorless=n | 150 | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · |
| A:small R:small-nc S:+L cofactorless=y | 42 | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · |
| A:small R:small-nc S:canon cofactorless=n | 582 | · | · | · | all | · | · | all | · | all | · | · | · | · | · | · | · | · | · | · | · |
| A:small R:small-nc S:canon cofactorless=y | 186 | · | · | · | all | · | · | all | · | all | · | · | · | · | · | · | · | · | · | · | · |
| A:small-nc R:mixed S:+L cofactorless=n | 161 | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · |
| A:small-nc R:mixed S:+L cofactorless=y | 7 | · | · | · | · | · | · | · | · | · | · | all | · | · | · | · | · | · | · | · | · |
| A:small-nc R:mixed S:canon cofactorless=n | 640 | · | · | · | all | · | · | all | · | all | · | · | · | · | · | · | · | · | · | · | · |
| A:small-nc R:mixed S:canon cofactorless=y | 32 | · | all | · | all | all | all | all | · | all | · | all | all | · | · | · | all | all | · | all | all |
| A:small-nc R:prime S:+L cofactorless=n | 9 | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · |
| A:small-nc R:prime S:+L cofactorless=y | 15 | · | · | · | · | · | · | · | · | · | · | all | · | · | · | · | · | · | · | · | · |
| A:small-nc R:prime S:canon cofactorless=n | 30 | · | · | · | all | · | · | all | · | all | · | · | · | · | · | · | · | · | · | · | · |
| A:small-nc R:prime S:canon cofactorless=y | 66 | · | all | · | all | all | all | all | · | all | · | all | all | · | · | · | all | all | · | all | all |
| A:small-nc R:small S:+L cofactorless=n | 164 | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · |
| A:small-nc R:small S:+L cofactorless=y | 28 | · | · | · | · | · | · | · | · | · | · | all | · | · | · | · | · | · | · | · | · |
| A:small-nc R:small S:canon cofactorless=n | 673 | · | · | · | all | · | · | all | · | all | · | · | · | · | · | · | · | · | · | · | · |
| A:small-nc R:small S:canon cofactorless=y | 95 | · | all | · | all | all | all | all | · | all | · | all | all | · | · | · | all | all | · | all | all |
| A:small-nc R:small-nc S:+L cofactorless=n | 87 | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · |
| A:small-nc R:small-nc S:+L cofactorless=y | 57 | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · |
| A:small-nc R:small-nc S:canon cofactorless=n | 346 | · | · | · | all | · | · | all | · | all | · | · | · | · | · | · | · | · | · | · | · |
| A:small-nc R:small-nc S:canon cofactorless=y | 230 | · | · | · | all | · | · | all | · | all | · | · | · | · | · | · | · | · | · | · | · |

I0 = rs:ENV-210/211 (audit-vectors)  
I1 = rs:ed25519-dalek 2.2 verify  
I2 = rs:ed25519-dalek 2.2 verify_strict (= biscuit-auth 6)  
I3 = rs:ed25519-zebra 4 (ZIP-215)  
I4 = rs:ring 0.17  
I5 = js:node:crypto.verify [node 22.22.2 (OpenSSL 3.6.2)]  
I6 = js:@noble/curves 2.4 ed25519 (default zip215:true)  
I7 = js:@noble/curves 2.4 ed25519 {zip215:false}  
I8 = js:@noble/ed25519 3.2 (default)  
I9 = js:@noble/ed25519 3.2 {zip215:false}  
I10 = js:tweetnacl 1.0.3  
I11 = js:WebCrypto subtle [node 22.22.2 (OpenSSL 3.6.2)]  
I12 = js:libsodium-wrappers 0.7.16 [libsodium 1.0.20]  
I13 = js:pre-check + node:crypto (OpenSSL)  
I14 = js:pre-check + @noble/curves {zip215:false}  
I15 = js:node:crypto.verify [bun 1.3.3 (BoringSSL)]  
I16 = js:WebCrypto subtle [bun 1.3.3 (BoringSSL)]  
I17 = py:PyNaCl 1.6.2 (bundled libsodium)  
I18 = py:cryptography 50 [OpenSSL 4.0.3 29 Sep 2026]  
I19 = go:crypto/ed25519 [go1.27.3]

## speccheck vectors 0–11 (Chalkias et al. 2020), V = accept

| impl | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| rs:ENV-210/211 (audit-vectors) | X | X | X | V | X | X | X | X | X | X | X | X |
| rs:ed25519-dalek 2.2 verify | V | V | V | V | X | X | X | X | X | X | X | V |
| rs:ed25519-dalek 2.2 verify_strict (= biscuit-auth 6) | X | X | X | V | X | X | X | X | X | X | X | X |
| rs:ed25519-zebra 4 (ZIP-215) | V | V | V | V | V | V | X | X | X | V | V | V |
| rs:ring 0.17 | V | V | V | V | X | X | X | X | X | X | X | V |
| js:node:crypto.verify [node 22.22.2 (OpenSSL 3.6.2)] | V | V | V | V | X | X | X | X | X | X | X | V |
| js:@noble/curves 2.4 ed25519 (default zip215:true) | V | V | V | V | V | V | X | X | X | V | V | V |
| js:@noble/curves 2.4 ed25519 {zip215:false} | X | X | V | V | V | V | X | X | X | X | X | X |
| js:@noble/ed25519 3.2 (default) | V | V | V | V | V | V | X | X | X | V | V | V |
| js:@noble/ed25519 3.2 {zip215:false} | X | X | V | V | V | V | X | X | X | X | X | X |
| js:tweetnacl 1.0.3 | V | V | V | V | X | X | V | V | X | X | X | V |
| js:WebCrypto subtle [node 22.22.2 (OpenSSL 3.6.2)] | V | V | V | V | X | X | X | X | X | X | X | V |
| js:libsodium-wrappers 0.7.16 [libsodium 1.0.20] | X | X | X | V | X | X | X | X | X | X | X | X |
| js:pre-check + node:crypto (OpenSSL) | X | X | X | V | X | X | X | X | X | X | X | X |
| js:pre-check + @noble/curves {zip215:false} | X | X | X | V | V | V | X | X | X | X | X | X |
| js:node:crypto.verify [bun 1.3.3 (BoringSSL)] | V | V | V | V | X | X | X | X | X | X | X | V |
| js:WebCrypto subtle [bun 1.3.3 (BoringSSL)] | V | V | V | V | X | X | X | X | X | X | X | V |
| py:PyNaCl 1.6.2 (bundled libsodium) | X | X | X | V | X | X | X | X | X | X | X | X |
| py:cryptography 50 [OpenSSL 4.0.3 29 Sep 2026] | V | V | V | V | X | X | X | X | X | X | X | V |
| go:crypto/ed25519 [go1.27.3] | V | V | V | V | X | X | X | X | X | X | X | V |

## Implementations with identical accept sets over all cases

- rs:ENV-210/211 (audit-vectors); rs:ed25519-dalek 2.2 verify_strict (= biscuit-auth 6); js:libsodium-wrappers 0.7.16 [libsodium 1.0.20]; js:pre-check + node:crypto (OpenSSL); py:PyNaCl 1.6.2 (bundled libsodium)
- rs:ed25519-dalek 2.2 verify; rs:ring 0.17; js:node:crypto.verify [node 22.22.2 (OpenSSL 3.6.2)]; js:WebCrypto subtle [node 22.22.2 (OpenSSL 3.6.2)]; js:node:crypto.verify [bun 1.3.3 (BoringSSL)]; js:WebCrypto subtle [bun 1.3.3 (BoringSSL)]; py:cryptography 50 [OpenSSL 4.0.3 29 Sep 2026]; go:crypto/ed25519 [go1.27.3]
- rs:ed25519-zebra 4 (ZIP-215); js:@noble/curves 2.4 ed25519 (default zip215:true); js:@noble/ed25519 3.2 (default)
- js:@noble/curves 2.4 ed25519 {zip215:false}; js:@noble/ed25519 3.2 {zip215:false}
- js:tweetnacl 1.0.3
- js:pre-check + @noble/curves {zip215:false}
