//! Authenticated encryption: ChaCha20-Poly1305 (RFC 8439) and XChaCha20-Poly1305.
//!
//! - [`ChaCha20Poly1305`] has a 96-bit nonce. Use it only with counter nonces under keys that
//!   are used by a single sender (sessions).
//! - [`XChaCha20Poly1305`] has a 192-bit nonce, large enough to pick at random. Use it for
//!   long-lived keys that encrypt many independent items (storage).
//!
//! Ciphertexts are `encrypted plaintext || 16-byte tag`.

use zeroize::Zeroizing;

use super::{CryptoError, SecretBytes, random};

pub const KEY_LEN: usize = 32;
pub const TAG_LEN: usize = 16;

pub type Key = SecretBytes<KEY_LEN>;

/// Libcrux processes lengths as `u32`.
const MAX_INPUT_LEN: usize = u32::MAX as usize - TAG_LEN;

pub struct ChaCha20Poly1305;

impl ChaCha20Poly1305 {
    pub const NONCE_LEN: usize = 12;

    pub fn seal(key: &Key, nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        check_lengths(plaintext, aad)?;
        let mut ciphertext = vec![0; plaintext.len() + TAG_LEN];
        libcrux_chacha20poly1305::encrypt(key.expose(), plaintext, &mut ciphertext, aad, nonce)
            .map_err(|_| CryptoError::InputTooLong)?;
        Ok(ciphertext)
    }

    pub fn open(key: &Key, nonce: &[u8; 12], aad: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let mut plaintext = Zeroizing::new(vec![0; plaintext_len(ciphertext)?]);
        libcrux_chacha20poly1305::decrypt(key.expose(), &mut plaintext, ciphertext, aad, nonce)
            .map_err(|_| CryptoError::Decrypt)?;
        Ok(plaintext)
    }
}

pub struct XChaCha20Poly1305;

impl XChaCha20Poly1305 {
    pub const NONCE_LEN: usize = 24;

    pub fn seal(key: &Key, nonce: &[u8; 24], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        check_lengths(plaintext, aad)?;
        let mut ciphertext = vec![0; plaintext.len() + TAG_LEN];
        libcrux_chacha20poly1305::xchacha20_poly1305::encrypt(key.expose(), plaintext, &mut ciphertext, aad, nonce)
            .map_err(|_| CryptoError::InputTooLong)?;
        Ok(ciphertext)
    }

    /// Encrypts under a fresh random nonce and returns `nonce || ciphertext`.
    pub fn seal_with_random_nonce(key: &Key, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce = random::array::<24>()?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&Self::seal(key, &nonce, aad, plaintext)?);
        Ok(out)
    }

    pub fn open(key: &Key, nonce: &[u8; 24], aad: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let mut plaintext = Zeroizing::new(vec![0; plaintext_len(ciphertext)?]);
        libcrux_chacha20poly1305::xchacha20_poly1305::decrypt(key.expose(), &mut plaintext, ciphertext, aad, nonce)
            .map_err(|_| CryptoError::Decrypt)?;
        Ok(plaintext)
    }

    /// Opens the output of [`XChaCha20Poly1305::seal_with_random_nonce`].
    pub fn open_with_nonce_prefix(key: &Key, aad: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let (nonce, ciphertext) = sealed.split_first_chunk::<24>().ok_or(CryptoError::InvalidCiphertext)?;
        Self::open(key, nonce, aad, ciphertext)
    }
}

fn check_lengths(plaintext: &[u8], aad: &[u8]) -> Result<(), CryptoError> {
    if plaintext.len() > MAX_INPUT_LEN || aad.len() > MAX_INPUT_LEN {
        return Err(CryptoError::InputTooLong);
    }
    Ok(())
}

fn plaintext_len(ciphertext: &[u8]) -> Result<usize, CryptoError> {
    ciphertext
        .len()
        .checked_sub(TAG_LEN)
        .ok_or(CryptoError::InvalidCiphertext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::test_util::{hex, hex_array};

    const PLAINTEXT: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    const AAD: &str = "50515253c0c1c2c3c4c5c6c7";

    fn key() -> Key {
        let mut key = Key::zeroed();
        for (i, b) in key.expose_mut().iter_mut().enumerate() {
            *b = 0x80 + i as u8;
        }
        key
    }

    #[test]
    fn chacha20poly1305_known_answer() {
        // RFC 8439, section 2.8.2.
        let nonce = hex_array("070000004041424344454647");
        let expected = hex(concat!(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b",
            "1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc",
            "3ff4def08e4b7a9de576d26586cec64b6116",
            "1ae10b594f09e26a7e902ecbd0600691",
        ));
        let sealed = ChaCha20Poly1305::seal(&key(), &nonce, &hex(AAD), PLAINTEXT).unwrap();
        assert_eq!(sealed, expected);
        let opened = ChaCha20Poly1305::open(&key(), &nonce, &hex(AAD), &sealed).unwrap();
        assert_eq!(opened.as_slice(), PLAINTEXT);
    }

    #[test]
    fn xchacha20poly1305_known_answer() {
        // draft-irtf-cfrg-xchacha-03, appendix A.3.1.
        let nonce = hex_array("404142434445464748494a4b4c4d4e4f5051525354555657");
        let expected = hex(concat!(
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39",
            "ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9",
            "21f9664c97637da9768812f615c68b13b52e",
            "c0875924c1c7987947deafd8780acf49",
        ));
        let sealed = XChaCha20Poly1305::seal(&key(), &nonce, &hex(AAD), PLAINTEXT).unwrap();
        assert_eq!(sealed, expected);
        let opened = XChaCha20Poly1305::open(&key(), &nonce, &hex(AAD), &sealed).unwrap();
        assert_eq!(opened.as_slice(), PLAINTEXT);
    }

    #[test]
    fn tampering_is_detected() {
        let nonce = [7; 12];
        let mut sealed = ChaCha20Poly1305::seal(&key(), &nonce, b"aad", b"secret").unwrap();
        for i in 0..sealed.len() {
            sealed[i] ^= 1;
            assert_eq!(
                ChaCha20Poly1305::open(&key(), &nonce, b"aad", &sealed).unwrap_err(),
                CryptoError::Decrypt
            );
            sealed[i] ^= 1;
        }
        assert_eq!(
            ChaCha20Poly1305::open(&key(), &nonce, b"aaD", &sealed).unwrap_err(),
            CryptoError::Decrypt
        );
        assert_eq!(
            ChaCha20Poly1305::open(&key(), &[8; 12], b"aad", &sealed).unwrap_err(),
            CryptoError::Decrypt
        );
    }

    #[test]
    fn short_ciphertext_is_rejected() {
        assert_eq!(
            ChaCha20Poly1305::open(&key(), &[0; 12], b"", &[0; TAG_LEN - 1]).unwrap_err(),
            CryptoError::InvalidCiphertext
        );
        assert_eq!(
            XChaCha20Poly1305::open_with_nonce_prefix(&key(), b"", &[0; 23]).unwrap_err(),
            CryptoError::InvalidCiphertext
        );
    }

    #[test]
    fn random_nonce_round_trip() {
        let a = XChaCha20Poly1305::seal_with_random_nonce(&key(), b"aad", b"hello").unwrap();
        let b = XChaCha20Poly1305::seal_with_random_nonce(&key(), b"aad", b"hello").unwrap();
        assert_ne!(a, b, "nonces must be fresh");
        let opened = XChaCha20Poly1305::open_with_nonce_prefix(&key(), b"aad", &a).unwrap();
        assert_eq!(opened.as_slice(), b"hello");
    }

    #[test]
    fn empty_plaintext() {
        let sealed = ChaCha20Poly1305::seal(&key(), &[0; 12], b"", b"").unwrap();
        assert_eq!(sealed.len(), TAG_LEN);
        assert!(
            ChaCha20Poly1305::open(&key(), &[0; 12], b"", &sealed)
                .unwrap()
                .is_empty()
        );
    }
}
