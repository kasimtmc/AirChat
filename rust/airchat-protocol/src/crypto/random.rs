//! Randomness from the operating system. There is no user-space RNG to seed or misuse.

use super::CryptoError;

/// Fills `buf` with cryptographically secure random bytes.
pub fn fill(buf: &mut [u8]) -> Result<(), CryptoError> {
    getrandom::fill(buf).map_err(|_| CryptoError::Random)
}

/// Random bytes for values that are not secret (nonces, identifiers).
/// Use [`super::SecretBytes::random`] for keys.
pub fn array<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut out = [0; N];
    fill(&mut out)?;
    Ok(out)
}

/// A source of randomness, so tests can make protocol runs reproducible (test vectors).
/// Everything outside tests uses [`OsRng`].
pub(crate) trait Rng {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), CryptoError>;
}

/// The operating system's generator.
pub(crate) struct OsRng;

impl Rng for OsRng {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), CryptoError> {
        fill(buf)
    }
}
