//! Long-term identity (docs/protocol.md §4).
//!
//! An identity is an Ed25519 key pair created on the device. It never leaves the device in plaintext;
//! others know it by its public key and the [`AirChatId`] derived from that key.

mod airchat_id;

pub use airchat_id::{AirChatId, IdParseError};

use crate::{
    crypto::{
        CryptoError, SecretBytes,
        kem::EncapsulationKey,
        sign::{SEED_LEN, SIGNATURE_LEN, Signature, SigningKey, VerifyingKey},
    },
    labels,
};

/// The device owner's identity, including the private key.
#[derive(Debug)]
pub struct Identity {
    signing_key: SigningKey,
}

impl Identity {
    pub fn generate() -> Result<Self, CryptoError> {
        Ok(Self {
            signing_key: SigningKey::generate()?,
        })
    }

    /// Restores an identity from its stored seed.
    pub fn from_seed(seed: SecretBytes<SEED_LEN>) -> Self {
        Self {
            signing_key: SigningKey::from_seed(seed),
        }
    }

    /// The seed, for encrypted storage only.
    pub fn seed(&self) -> &SecretBytes<SEED_LEN> {
        self.signing_key.seed()
    }

    pub fn public(&self) -> PublicIdentity {
        PublicIdentity {
            key: *self.signing_key.verifying_key(),
        }
    }

    /// Vouches for a static key of this identity's, `version` of them (docs/protocol.md §6.9).
    pub fn sign_static_key(&self, version: u32, key: &EncapsulationKey) -> [u8; SIGNATURE_LEN] {
        *self
            .sign(labels::STATIC_KEY, &[&version.to_be_bytes(), key.as_bytes()])
            .as_bytes()
    }

    /// Signs `label || parts`. Requiring a label from [`crate::labels`] keeps a signature made
    /// for one purpose from ever being valid for another.
    pub(crate) fn sign(&self, label: &[u8], parts: &[&[u8]]) -> Signature {
        self.signing_key.sign(&labeled(label, parts))
    }
}

/// Someone's public identity: what contacts store and what the AirChat ID is derived from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicIdentity {
    key: VerifyingKey,
}

impl PublicIdentity {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            key: VerifyingKey::from_bytes(bytes),
        }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.key.as_bytes()
    }

    pub fn airchat_id(&self) -> AirChatId {
        AirChatId::derive(self)
    }

    /// Whether this identity vouched for `key` as its static key of `version`.
    pub fn vouches_for(&self, version: u32, key: &EncapsulationKey, signature: &[u8; SIGNATURE_LEN]) -> bool {
        self.verify(
            labels::STATIC_KEY,
            &[&version.to_be_bytes(), key.as_bytes()],
            &Signature::from_bytes(*signature),
        )
        .is_ok()
    }

    /// Verifies a signature made with [`Identity::sign`] over the same label and parts.
    pub(crate) fn verify(&self, label: &[u8], parts: &[&[u8]], signature: &Signature) -> Result<(), CryptoError> {
        self.key.verify(&labeled(label, parts), signature)
    }
}

fn labeled(label: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    [&[label][..], parts].concat().concat()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_round_trips_through_its_seed() {
        let identity = Identity::generate().unwrap();
        let restored = Identity::from_seed(identity.seed().clone());
        assert_eq!(identity.public(), restored.public());
    }

    #[test]
    fn signatures_are_bound_to_signer_label_and_content() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let signature = alice.sign(b"AirChat v1 test", &[b"a", b"b"]);
        alice.public().verify(b"AirChat v1 test", &[b"ab"], &signature).unwrap();
        assert!(
            alice
                .public()
                .verify(b"AirChat v1 other", &[b"ab"], &signature)
                .is_err()
        );
        assert!(
            alice
                .public()
                .verify(b"AirChat v1 test", &[b"abc"], &signature)
                .is_err()
        );
        assert!(bob.public().verify(b"AirChat v1 test", &[b"ab"], &signature).is_err());
    }
}
