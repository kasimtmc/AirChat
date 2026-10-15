use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{CryptoError, random};

/// Fixed-size secret material that is wiped from memory when dropped and never printed.
///
/// Construct it in place ([`SecretBytes::random`], [`SecretBytes::from_slice`],
/// [`SecretBytes::zeroed`] + [`SecretBytes::expose_mut`]) rather than from an array value: arrays
/// are `Copy`, so passing one by value would leave an unwiped copy behind.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes<const N: usize>([u8; N]);

impl<const N: usize> SecretBytes<N> {
    /// All-zero secret, to be filled through [`SecretBytes::expose_mut`].
    pub fn zeroed() -> Self {
        Self([0; N])
    }

    /// Fresh secret from the operating system's random number generator.
    pub fn random() -> Result<Self, CryptoError> {
        Self::random_from(&mut random::OsRng)
    }

    pub(crate) fn random_from(rng: &mut dyn random::Rng) -> Result<Self, CryptoError> {
        let mut secret = Self::zeroed();
        rng.fill(&mut secret.0)?;
        Ok(secret)
    }

    /// Copies a secret out of a slice of exactly `N` bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != N {
            return Err(CryptoError::InvalidKey);
        }
        let mut secret = Self::zeroed();
        secret.0.copy_from_slice(bytes);
        Ok(secret)
    }

    pub fn expose(&self) -> &[u8; N] {
        &self.0
    }

    pub fn expose_mut(&mut self) -> &mut [u8; N] {
        &mut self.0
    }
}

impl<const N: usize> fmt::Debug for SecretBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes<{N}>(redacted)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_never_contains_the_secret() {
        let secret = SecretBytes::<4>::from_slice(&[0xde, 0xad, 0xbe, 0xef]).unwrap();
        let printed = format!("{secret:?}");
        assert_eq!(printed, "SecretBytes<4>(redacted)");
    }

    #[test]
    fn from_slice_rejects_wrong_length() {
        assert_eq!(
            SecretBytes::<32>::from_slice(&[0; 31]).unwrap_err(),
            CryptoError::InvalidKey
        );
    }

    #[test]
    fn random_secrets_differ() {
        let a = SecretBytes::<32>::random().unwrap();
        let b = SecretBytes::<32>::random().unwrap();
        assert_ne!(a.expose(), b.expose());
    }
}
