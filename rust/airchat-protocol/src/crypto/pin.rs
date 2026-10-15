//! Key derivation from the app PIN with Argon2id (RFC 9106).
//!
//! A PIN has little entropy, so Argon2id alone cannot stop an offline attack. It is one of two
//! layers: the derived key is combined with a hardware-backed platform key that never leaves the
//! device. Local storage only, never on the wire; here so that apps share one vetted parameter set.

use argon2::{Algorithm, Argon2, Params, Version};

use super::{CryptoError, SecretBytes};

pub const SALT_LEN: usize = 16;
pub const KEY_LEN: usize = 32;

/// Argon2id cost parameters. Stored next to whatever they protect, so they can be raised later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl PinParams {
    /// 64 MiB, 3 passes, 1 lane: RFC 9106's memory-constrained recommendation, ~0.5–1 s on a
    /// mid-range phone.
    pub const DEFAULT: Self = Self {
        memory_kib: 64 * 1024,
        iterations: 3,
        parallelism: 1,
    };
}

pub fn derive_key(pin: &[u8], salt: &[u8; SALT_LEN], params: PinParams) -> Result<SecretBytes<KEY_LEN>, CryptoError> {
    let params = Params::new(params.memory_kib, params.iterations, params.parallelism, Some(KEY_LEN))
        .map_err(|_| CryptoError::InvalidParameters)?;
    let mut key = SecretBytes::zeroed();
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(pin, salt, key.expose_mut())
        .map_err(|_| CryptoError::InvalidParameters)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::test_util::hex;

    const CHEAP: PinParams = PinParams {
        memory_kib: 256,
        iterations: 2,
        parallelism: 1,
    };

    #[test]
    fn known_answer() {
        // Generated with OpenSSL's Argon2id (via Python `cryptography`) using the same parameters.
        let key = derive_key(b"123456", b"airchat-kat-salt", CHEAP).unwrap();
        assert_eq!(
            key.expose().as_slice(),
            hex("b83ffd4513c59ea7efd424b511e924931640504c4f3c2998ae684cf029511e8d")
        );
    }

    #[test]
    fn different_pin_or_salt_gives_different_key() {
        let salt = [1; SALT_LEN];
        let a = derive_key(b"123456", &salt, CHEAP).unwrap();
        assert_ne!(a.expose(), derive_key(b"123457", &salt, CHEAP).unwrap().expose());
        assert_ne!(
            a.expose(),
            derive_key(b"123456", &[2; SALT_LEN], CHEAP).unwrap().expose()
        );
    }

    #[test]
    fn rejects_invalid_parameters() {
        let bad = PinParams {
            memory_kib: 1,
            iterations: 1,
            parallelism: 1,
        };
        assert_eq!(
            derive_key(b"1", &[0; SALT_LEN], bad).unwrap_err(),
            CryptoError::InvalidParameters
        );
    }
}
