//! Ed25519 signatures (RFC 8032).

use core::fmt;

use super::{CryptoError, SecretBytes};

pub const SEED_LEN: usize = 32;
pub const PUBLIC_KEY_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;

/// An Ed25519 private key. Only the 32-byte seed is stored; everything else derives from it.
pub struct SigningKey {
    seed: SecretBytes<SEED_LEN>,
    verifying_key: VerifyingKey,
}

impl SigningKey {
    pub fn generate() -> Result<Self, CryptoError> {
        Ok(Self::from_seed(SecretBytes::random()?))
    }

    pub fn from_seed(seed: SecretBytes<SEED_LEN>) -> Self {
        let mut public = [0; PUBLIC_KEY_LEN];
        libcrux_ed25519::secret_to_public(&mut public, seed.expose());
        Self {
            seed,
            verifying_key: VerifyingKey(public),
        }
    }

    /// The seed, for encrypted storage only.
    pub fn seed(&self) -> &SecretBytes<SEED_LEN> {
        &self.seed
    }

    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        let signature = libcrux_ed25519::sign(message, self.seed.expose()).expect("Ed25519 message exceeds 4 GiB");
        Signature(signature)
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("verifying_key", &self.verifying_key)
            .finish_non_exhaustive()
    }
}

/// An Ed25519 public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct VerifyingKey([u8; PUBLIC_KEY_LEN]);

impl VerifyingKey {
    /// Accepts any 32 bytes; an invalid point simply never verifies.
    pub fn from_bytes(bytes: [u8; PUBLIC_KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.0
    }

    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), CryptoError> {
        libcrux_ed25519::verify(message, &self.0, &signature.0).map_err(|_| CryptoError::InvalidSignature)
    }
}

impl fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VerifyingKey(")?;
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))?;
        write!(f, ")")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; SIGNATURE_LEN]);

impl Signature {
    pub fn from_bytes(bytes: [u8; SIGNATURE_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; SIGNATURE_LEN] {
        &self.0
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Signature(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::test_util::hex_array;

    fn rfc8032_test1() -> SigningKey {
        let seed = hex_array::<32>("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        SigningKey::from_seed(SecretBytes::from_slice(&seed).unwrap())
    }

    #[test]
    fn known_answer() {
        // RFC 8032, section 7.1, TEST 1.
        let key = rfc8032_test1();
        assert_eq!(
            key.verifying_key().as_bytes(),
            &hex_array("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        );
        let signature = key.sign(b"");
        assert_eq!(
            signature.as_bytes(),
            &hex_array(concat!(
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
                "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            ))
        );
        key.verifying_key().verify(b"", &signature).unwrap();
    }

    #[test]
    fn rejects_wrong_message_key_and_signature() {
        let key = rfc8032_test1();
        let signature = key.sign(b"message");
        assert_eq!(
            key.verifying_key().verify(b"messagE", &signature),
            Err(CryptoError::InvalidSignature)
        );

        let other = SigningKey::generate().unwrap();
        assert_eq!(
            other.verifying_key().verify(b"message", &signature),
            Err(CryptoError::InvalidSignature)
        );

        let mut bytes = *signature.as_bytes();
        bytes[63] ^= 0x10;
        let bad = Signature::from_bytes(bytes);
        assert_eq!(
            key.verifying_key().verify(b"message", &bad),
            Err(CryptoError::InvalidSignature)
        );
    }

    #[test]
    fn debug_hides_seed() {
        let printed = format!("{:?}", rfc8032_test1());
        assert!(!printed.contains("9d61b1"), "{printed}");
    }
}
