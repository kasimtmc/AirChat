//! Cryptographic primitives, behind wrappers owned by AirChat.
//!
//! This module is the only code allowed to call a cryptographic library. Protocol code, and the
//! apps built on it, use these wrappers, so the implementation can be swapped without touching the
//! protocol.
//!
//! Primitives are never implemented here, only called: libcrux (formally verified) for everything
//! except password hashing, which uses RustCrypto's `argon2`, and the certificate signatures of
//! Android key attestation, which use `ring` (verification only).

pub mod aead;
pub mod certsig;
pub mod hash;
pub mod kdf;
pub mod kem;
pub mod pin;
pub mod random;
pub mod sign;

mod secret;

pub use secret::SecretBytes;

/// Errors from cryptographic operations.
///
/// Deliberately coarse: callers must not learn *why* a decryption or verification failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    #[error("the operating system random number generator failed")]
    Random,
    #[error("decryption failed")]
    Decrypt,
    #[error("signature verification failed")]
    InvalidSignature,
    #[error("malformed key")]
    InvalidKey,
    #[error("malformed ciphertext")]
    InvalidCiphertext,
    #[error("input exceeds the primitive's length limit")]
    InputTooLong,
    #[error("invalid key derivation parameters")]
    InvalidParameters,
}

/// Helpers for tests: hex, the published test vectors, reproducible randomness.
#[cfg(any(test, feature = "test-util"))]
#[doc(hidden)]
pub mod test_util {
    /// Decodes a hex test vector; panics on malformed input.
    pub fn hex(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2), "odd hex length");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("invalid hex"))
            .collect()
    }

    pub fn hex_array<const N: usize>(s: &str) -> [u8; N] {
        hex(s).try_into().expect("wrong vector length")
    }

    pub fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Compares a published test vector in `tests/vectors/<name>.json` with `fields`. With
    /// `AIRCHAT_UPDATE_VECTORS=1` set, rewrites the file first (after an intentional protocol change).
    pub fn check_vector(name: &str, fields: &[(&str, String)]) {
        let json = format!(
            "{{\n{}\n}}\n",
            fields
                .iter()
                .map(|(k, v)| format!("  \"{k}\": \"{v}\""))
                .collect::<Vec<_>>()
                .join(",\n")
        );
        let path = format!("{}/tests/vectors/{name}.json", env!("CARGO_MANIFEST_DIR"));
        if std::env::var_os("AIRCHAT_UPDATE_VECTORS").is_some() {
            std::fs::write(&path, &json).unwrap();
        }
        let published = std::fs::read_to_string(&path)
            .unwrap_or_else(|_| panic!("{path} missing; run with AIRCHAT_UPDATE_VECTORS=1"));
        assert_eq!(json, published, "output differs from the published vector {name}");
    }

    /// A string field of a published test vector `tests/vectors/<name>.json` (flat objects only).
    pub fn vector_field(name: &str, key: &str) -> String {
        let path = format!("{}/tests/vectors/{name}.json", env!("CARGO_MANIFEST_DIR"));
        let json = std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("{path} missing"));
        let start = json
            .find(&format!("\"{key}\": \""))
            .unwrap_or_else(|| panic!("{key} missing in {name}"))
            + key.len()
            + 5;
        let end = start + json[start..].find('"').expect("unterminated string");
        json[start..end].to_owned()
    }

    /// Reproducible randomness for test vectors: the stream of blocks
    /// `SHA-256(seed || counter)`, counter a big-endian u64 from 0. Other implementations can
    /// regenerate a vector's random inputs from its seed.
    pub struct DeterministicRng {
        seed: [u8; 32],
        counter: u64,
        buffer: Vec<u8>,
    }

    impl DeterministicRng {
        pub fn new(seed: [u8; 32]) -> Self {
            Self {
                seed,
                counter: 0,
                buffer: Vec::new(),
            }
        }
    }

    impl super::random::Rng for DeterministicRng {
        fn fill(&mut self, buf: &mut [u8]) -> Result<(), super::CryptoError> {
            while self.buffer.len() < buf.len() {
                let block = super::hash::sha256(&[&self.seed, &self.counter.to_be_bytes()]);
                self.buffer.extend_from_slice(&block);
                self.counter += 1;
            }
            buf.copy_from_slice(&self.buffer[..buf.len()]);
            self.buffer.drain(..buf.len());
            Ok(())
        }
    }
}
