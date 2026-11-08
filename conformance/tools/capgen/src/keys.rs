//! Fixed test keys. Every key is derived from its name, so vectors are reproducible and
//! the keys are obviously test-only: seed = BLAKE3-derive_key(CONTEXT, name).

use ed25519_dalek::SigningKey;

pub const CONTEXT: &str = "argent-webway capgen test key v0";

pub fn seed(name: &str) -> [u8; 32] {
    blake3::derive_key(CONTEXT, name.as_bytes())
}

pub fn signing(name: &str) -> SigningKey {
    SigningKey::from_bytes(&seed(name))
}

pub fn public(name: &str) -> [u8; 32] {
    signing(name).verifying_key().to_bytes()
}

pub fn biscuit_keypair(name: &str) -> biscuit_auth::KeyPair {
    let pk = biscuit_auth::PrivateKey::from_bytes(&seed(name), biscuit_auth::Algorithm::Ed25519).expect("32-byte seed");
    biscuit_auth::KeyPair::from(&pk)
}
