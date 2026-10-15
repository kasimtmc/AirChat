//! X-Wing hybrid key encapsulation (draft-connolly-cfrg-xwing-kem-06): ML-KEM-768 + X25519.
//!
//! The shared secret stays secure as long as *either* ML-KEM-768 or X25519 is unbroken, so traffic
//! recorded today cannot be decrypted later by a quantum computer (requirement S-6).

use core::fmt;

use libcrux_kem::XWing;
use libcrux_ml_kem::mlkem768::{self, MlKem768PublicKey};
use libcrux_traits::kem::arrayref::Kem;

use super::{
    CryptoError, SecretBytes,
    random::{OsRng, Rng},
};

pub const SEED_LEN: usize = 32;
pub const ENCAPSULATION_KEY_LEN: usize = 1216;
pub const CIPHERTEXT_LEN: usize = 1120;
pub const SHARED_SECRET_LEN: usize = 32;

/// Expanded ML-KEM-768 decapsulation key (2400 bytes) followed by the X25519 secret (32 bytes).
const DECAPSULATION_KEY_LEN: usize = 2432;
const ENCAPSULATION_RANDOMNESS_LEN: usize = 64;
const MLKEM768_ENCAPSULATION_KEY_LEN: usize = 1184;

pub type SharedSecret = SecretBytes<SHARED_SECRET_LEN>;

/// An X-Wing private key. Only the 32-byte seed needs to be stored; the rest derives from it.
pub struct DecapsulationKey {
    seed: SecretBytes<SEED_LEN>,
    expanded: Box<SecretBytes<DECAPSULATION_KEY_LEN>>,
    encapsulation_key: EncapsulationKey,
}

impl DecapsulationKey {
    pub fn generate() -> Result<Self, CryptoError> {
        Self::generate_from(&mut OsRng)
    }

    pub(crate) fn generate_from(rng: &mut dyn Rng) -> Result<Self, CryptoError> {
        Self::from_seed(SecretBytes::random_from(rng)?)
    }

    pub fn from_seed(seed: SecretBytes<SEED_LEN>) -> Result<Self, CryptoError> {
        let mut expanded = Box::new(SecretBytes::zeroed());
        let mut encapsulation_key = Box::new([0; ENCAPSULATION_KEY_LEN]);
        XWing::keygen(&mut encapsulation_key, expanded.expose_mut(), seed.expose())
            .map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self {
            seed,
            expanded,
            encapsulation_key: EncapsulationKey(encapsulation_key),
        })
    }

    /// The seed, for encrypted storage only.
    pub fn seed(&self) -> &SecretBytes<SEED_LEN> {
        &self.seed
    }

    pub fn encapsulation_key(&self) -> &EncapsulationKey {
        &self.encapsulation_key
    }

    /// Never fails on a well-formed ciphertext: a tampered one yields an unrelated secret
    /// (ML-KEM implicit rejection), which the protocol then detects as a failed decryption.
    pub fn decapsulate(&self, ciphertext: &Ciphertext) -> Result<SharedSecret, CryptoError> {
        let mut shared = SharedSecret::zeroed();
        XWing::decaps(shared.expose_mut(), &ciphertext.0, self.expanded.expose())
            .map_err(|_| CryptoError::InvalidCiphertext)?;
        Ok(shared)
    }
}

impl fmt::Debug for DecapsulationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DecapsulationKey(..)")
    }
}

/// An X-Wing public key.
#[derive(Clone, PartialEq, Eq)]
pub struct EncapsulationKey(Box<[u8; ENCAPSULATION_KEY_LEN]>);

impl EncapsulationKey {
    /// Parses a public key received from a peer, including the FIPS 203 modulus check on the
    /// ML-KEM part.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let bytes: [u8; ENCAPSULATION_KEY_LEN] = bytes.try_into().map_err(|_| CryptoError::InvalidKey)?;
        let mlkem_key: [u8; MLKEM768_ENCAPSULATION_KEY_LEN] = bytes[..MLKEM768_ENCAPSULATION_KEY_LEN]
            .try_into()
            .expect("prefix of a fixed-size array");
        if !mlkem768::validate_public_key(&MlKem768PublicKey::from(mlkem_key)) {
            return Err(CryptoError::InvalidKey);
        }
        Ok(Self(Box::new(bytes)))
    }

    pub fn as_bytes(&self) -> &[u8; ENCAPSULATION_KEY_LEN] {
        &self.0
    }

    /// Creates a fresh shared secret and the ciphertext that lets the key's owner recover it.
    pub fn encapsulate(&self) -> Result<(SharedSecret, Ciphertext), CryptoError> {
        self.encapsulate_from(&mut OsRng)
    }

    pub(crate) fn encapsulate_from(&self, rng: &mut dyn Rng) -> Result<(SharedSecret, Ciphertext), CryptoError> {
        self.encapsulate_with(&SecretBytes::random_from(rng)?)
    }

    /// Deterministic encapsulation, for known-answer tests only. Reusing `randomness` is fatal.
    fn encapsulate_with(
        &self,
        randomness: &SecretBytes<ENCAPSULATION_RANDOMNESS_LEN>,
    ) -> Result<(SharedSecret, Ciphertext), CryptoError> {
        let mut shared = SharedSecret::zeroed();
        let mut ciphertext = Box::new([0; CIPHERTEXT_LEN]);
        XWing::encaps(&mut ciphertext, shared.expose_mut(), &self.0, randomness.expose())
            .map_err(|_| CryptoError::InvalidKey)?;
        Ok((shared, Ciphertext(ciphertext)))
    }
}

impl fmt::Debug for EncapsulationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EncapsulationKey(..)")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Ciphertext(Box<[u8; CIPHERTEXT_LEN]>);

impl Ciphertext {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let bytes: [u8; CIPHERTEXT_LEN] = bytes.try_into().map_err(|_| CryptoError::InvalidCiphertext)?;
        Ok(Self(Box::new(bytes)))
    }

    pub fn as_bytes(&self) -> &[u8; CIPHERTEXT_LEN] {
        &self.0
    }
}

impl fmt::Debug for Ciphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Ciphertext(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(byte: u8) -> SecretBytes<SEED_LEN> {
        SecretBytes::from_slice(&[byte; SEED_LEN]).unwrap()
    }

    #[test]
    fn round_trip() {
        let key = DecapsulationKey::generate().unwrap();
        let (sent, ciphertext) = key.encapsulation_key().encapsulate().unwrap();
        let received = key.decapsulate(&ciphertext).unwrap();
        assert_eq!(sent.expose(), received.expose());
    }

    #[test]
    fn keys_derive_deterministically_from_seed() {
        let a = DecapsulationKey::from_seed(seed(1)).unwrap();
        let b = DecapsulationKey::from_seed(seed(1)).unwrap();
        let c = DecapsulationKey::from_seed(seed(2)).unwrap();
        assert_eq!(a.encapsulation_key(), b.encapsulation_key());
        assert_ne!(a.encapsulation_key(), c.encapsulation_key());
    }

    #[test]
    fn wrong_key_or_tampered_ciphertext_gives_unrelated_secret() {
        let key = DecapsulationKey::generate().unwrap();
        let (sent, ciphertext) = key.encapsulation_key().encapsulate().unwrap();

        let other = DecapsulationKey::generate().unwrap();
        assert_ne!(other.decapsulate(&ciphertext).unwrap().expose(), sent.expose());

        let mut bytes = *ciphertext.as_bytes();
        bytes[0] ^= 1;
        let tampered = Ciphertext::from_bytes(&bytes).unwrap();
        assert_ne!(key.decapsulate(&tampered).unwrap().expose(), sent.expose());
    }

    #[test]
    fn rejects_malformed_inputs() {
        assert_eq!(
            EncapsulationKey::from_bytes(&[0; ENCAPSULATION_KEY_LEN - 1]).unwrap_err(),
            CryptoError::InvalidKey
        );
        // Coefficients of 0xfff exceed the ML-KEM modulus q = 3329.
        assert_eq!(
            EncapsulationKey::from_bytes(&[0xff; ENCAPSULATION_KEY_LEN]).unwrap_err(),
            CryptoError::InvalidKey
        );
        assert_eq!(
            Ciphertext::from_bytes(&[0; CIPHERTEXT_LEN + 1]).unwrap_err(),
            CryptoError::InvalidCiphertext
        );
    }

    #[test]
    fn parsing_a_valid_key_round_trips() {
        let key = DecapsulationKey::from_seed(seed(3)).unwrap();
        let parsed = EncapsulationKey::from_bytes(key.encapsulation_key().as_bytes()).unwrap();
        assert_eq!(&parsed, key.encapsulation_key());
    }

    /// Cross-checks libcrux against RustCrypto's independent X-Wing implementation of the same
    /// draft: identical keys, ciphertexts and shared secrets for identical randomness.
    #[test]
    fn matches_independent_implementation() {
        use x_wing::{Decapsulate, Decapsulator, KeyExport};

        for i in 0..8u8 {
            let seed_bytes = [i.wrapping_mul(37).wrapping_add(11); SEED_LEN];
            let ours = DecapsulationKey::from_seed(SecretBytes::from_slice(&seed_bytes).unwrap()).unwrap();
            let theirs = x_wing::DecapsulationKey::from(seed_bytes);
            assert_eq!(
                ours.encapsulation_key().as_bytes().as_slice(),
                theirs.encapsulation_key().to_bytes().as_slice()
            );

            let mut randomness = SecretBytes::<ENCAPSULATION_RANDOMNESS_LEN>::zeroed();
            randomness
                .expose_mut()
                .iter_mut()
                .enumerate()
                .for_each(|(j, b)| *b = i ^ j as u8);
            let (our_secret, our_ciphertext) = ours.encapsulation_key().encapsulate_with(&randomness).unwrap();
            let (their_ciphertext, their_secret) = theirs
                .encapsulation_key()
                .encapsulate_deterministic(&(*randomness.expose()).into());
            assert_eq!(our_ciphertext.as_bytes().as_slice(), their_ciphertext.as_slice());
            assert_eq!(our_secret.expose().as_slice(), their_secret.as_slice());
            assert_eq!(
                theirs.decapsulate(&their_ciphertext).as_slice(),
                our_secret.expose().as_slice()
            );
        }
    }
}
