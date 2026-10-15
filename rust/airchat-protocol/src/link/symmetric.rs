//! Handshake transcript and key schedule (docs/protocol.md §6.3), modelled on the Noise
//! framework's `SymmetricState`.

use zeroize::Zeroizing;

use super::LinkError;
use crate::crypto::{SecretBytes, aead::ChaCha20Poly1305, hash::sha256, kdf};

pub(crate) const KEY_LEN: usize = 32;

pub(crate) struct SymmetricState {
    /// Chaining key: accumulates every shared secret mixed in so far.
    ck: SecretBytes<KEY_LEN>,
    /// Transcript hash: commits to everything sent or known so far; the AEAD's associated data.
    h: [u8; 32],
    /// Current handshake encryption key and its nonce counter; absent until the first `mix_key`.
    k: Option<SecretBytes<KEY_LEN>>,
    n: u64,
}

impl SymmetricState {
    pub fn new(protocol_name: &[u8]) -> Self {
        let h = sha256(&[protocol_name]);
        let ck = SecretBytes::from_slice(&h).expect("hash length equals key length");
        Self { ck, h, k: None, n: 0 }
    }

    pub fn mix_hash(&mut self, data: &[u8]) {
        self.h = sha256(&[&self.h, data]);
    }

    /// `ck, k = HKDF(salt = ck, ikm)`, split into two 32-byte halves; resets the nonce.
    pub fn mix_key(&mut self, ikm: &[u8]) -> Result<(), LinkError> {
        let (ck, k) = hkdf2(&self.ck, ikm)?;
        self.ck = ck;
        self.k = Some(k);
        self.n = 0;
        Ok(())
    }

    pub fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, LinkError> {
        let k = self.k.as_ref().expect("mix_key precedes encryption");
        let ciphertext = ChaCha20Poly1305::seal(k, &nonce(self.n), &self.h, plaintext)?;
        self.n += 1;
        self.mix_hash(&ciphertext);
        Ok(ciphertext)
    }

    pub fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, LinkError> {
        let k = self.k.as_ref().expect("mix_key precedes decryption");
        let plaintext = ChaCha20Poly1305::open(k, &nonce(self.n), &self.h, ciphertext)
            .map_err(|_| LinkError::AuthenticationFailed)?;
        self.n += 1;
        self.mix_hash(ciphertext);
        Ok(plaintext)
    }

    /// The two transport keys: (initiator → responder, responder → initiator).
    pub fn split(&self) -> Result<(SecretBytes<KEY_LEN>, SecretBytes<KEY_LEN>), LinkError> {
        hkdf2(&self.ck, &[])
    }

    /// A further 32-byte secret bound to the whole handshake, independent of the [`Self::split`]
    /// keys: `HKDF-Expand(HKDF-Extract(salt = ck, ""), info = label, 32)`.
    pub fn export(&self, label: &[u8]) -> Result<SecretBytes<KEY_LEN>, LinkError> {
        Ok(kdf::expand(&kdf::extract(self.ck.expose(), &[]), label)?)
    }

    pub fn handshake_hash(&self) -> [u8; 32] {
        self.h
    }
}

/// HKDF-SHA-256 with `salt` as the extract key and empty info, expanded to two 32-byte keys.
fn hkdf2(salt: &SecretBytes<KEY_LEN>, ikm: &[u8]) -> Result<(SecretBytes<KEY_LEN>, SecretBytes<KEY_LEN>), LinkError> {
    let prk = kdf::extract(salt.expose(), ikm);
    let out = kdf::expand::<{ 2 * KEY_LEN }>(&prk, &[])?;
    let first = SecretBytes::from_slice(&out.expose()[..KEY_LEN])?;
    let second = SecretBytes::from_slice(&out.expose()[KEY_LEN..])?;
    Ok((first, second))
}

/// 96-bit AEAD nonce: four zero bytes, then the counter as a big-endian u64.
pub(crate) fn nonce(counter: u64) -> [u8; 12] {
    let mut nonce = [0; 12];
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peers_with_the_same_inputs_agree() {
        let run = |secret: &[u8]| {
            let mut s = SymmetricState::new(b"AirChat v1 test");
            s.mix_hash(b"prologue");
            s.mix_key(secret).unwrap();
            s
        };
        let mut alice = run(b"shared");
        let mut bob = run(b"shared");
        let ciphertext = alice.encrypt_and_hash(b"hello").unwrap();
        assert_eq!(bob.decrypt_and_hash(&ciphertext).unwrap().as_slice(), b"hello");
        assert_eq!(alice.handshake_hash(), bob.handshake_hash());
        assert_eq!(alice.split().unwrap().0.expose(), bob.split().unwrap().0.expose());

        let mut eve = run(b"guess");
        assert_eq!(
            eve.decrypt_and_hash(&ciphertext).unwrap_err(),
            LinkError::AuthenticationFailed
        );
    }

    #[test]
    fn transcript_divergence_breaks_decryption() {
        let mut alice = SymmetricState::new(b"AirChat v1 test");
        let mut bob = SymmetricState::new(b"AirChat v1 test");
        alice.mix_hash(b"one view");
        bob.mix_hash(b"another view");
        alice.mix_key(b"shared").unwrap();
        bob.mix_key(b"shared").unwrap();
        let ciphertext = alice.encrypt_and_hash(b"").unwrap();
        assert!(bob.decrypt_and_hash(&ciphertext).is_err());
    }

    #[test]
    fn nonce_layout() {
        assert_eq!(nonce(0x0102), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2]);
    }
}
