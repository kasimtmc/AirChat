//! Certificate signatures (ECDSA on P-256 and P-384, RSA PKCS#1 v1.5), to check Android key
//! attestation chains (docs/protocol.md §6.10). Verification only, through `ring`: libcrux has
//! neither P-384 nor RSA PKCS#1.

use ring::signature::{self, UnparsedPublicKey, VerificationAlgorithm};

use super::CryptoError;

/// A certificate's signature algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertAlgorithm {
    EcdsaSha256,
    EcdsaSha384,
    RsaSha256,
    RsaSha384,
    RsaSha512,
}

/// A certificate's public key: an EC point (uncompressed, SEC 1) or an RSAPublicKey (DER).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertKey<'a> {
    P256(&'a [u8]),
    P384(&'a [u8]),
    Rsa(&'a [u8]),
}

/// Checks `signature` (DER for ECDSA) over `message` with `key`. RSA keys of 2048 to 8192 bits.
pub fn verify(key: CertKey<'_>, algorithm: CertAlgorithm, message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
    let (algorithm, key): (&'static dyn VerificationAlgorithm, &[u8]) = match (key, algorithm) {
        (CertKey::P256(key), CertAlgorithm::EcdsaSha256) => (&signature::ECDSA_P256_SHA256_ASN1, key),
        (CertKey::P256(key), CertAlgorithm::EcdsaSha384) => (&signature::ECDSA_P256_SHA384_ASN1, key),
        (CertKey::P384(key), CertAlgorithm::EcdsaSha256) => (&signature::ECDSA_P384_SHA256_ASN1, key),
        (CertKey::P384(key), CertAlgorithm::EcdsaSha384) => (&signature::ECDSA_P384_SHA384_ASN1, key),
        (CertKey::Rsa(key), CertAlgorithm::RsaSha256) => (&signature::RSA_PKCS1_2048_8192_SHA256, key),
        (CertKey::Rsa(key), CertAlgorithm::RsaSha384) => (&signature::RSA_PKCS1_2048_8192_SHA384, key),
        (CertKey::Rsa(key), CertAlgorithm::RsaSha512) => (&signature::RSA_PKCS1_2048_8192_SHA512, key),
        _ => return Err(CryptoError::InvalidSignature),
    };
    UnparsedPublicKey::new(algorithm, key)
        .verify(message, signature)
        .map_err(|_| CryptoError::InvalidSignature)
}
