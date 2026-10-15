//! SHA-256 and HMAC-SHA-256.

use libcrux_sha2::Sha256Hasher;

use super::SecretBytes;

pub const SHA256_LEN: usize = 32;

/// SHA-256 over data that arrives in pieces, e.g. a file chunk by chunk.
pub struct Sha256Stream(Sha256Hasher);

impl Default for Sha256Stream {
    fn default() -> Self {
        Self(Sha256Hasher::new())
    }
}

impl Sha256Stream {
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data).expect("SHA-256 input part exceeds 4 GiB");
    }

    pub fn finish(self) -> [u8; SHA256_LEN] {
        self.0.finish_to_owned()
    }
}

/// SHA-256 over the concatenation of `parts`.
///
/// Callers must make the concatenation unambiguous (fixed-length fields or length prefixes).
pub fn sha256(parts: &[&[u8]]) -> [u8; SHA256_LEN] {
    let mut hasher = Sha256Hasher::new();
    for part in parts {
        hasher.update(part).expect("SHA-256 input part exceeds 4 GiB");
    }
    hasher.finish_to_owned()
}

/// HMAC-SHA-256 over the concatenation of `parts`. The tag is secret when the key is.
pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> SecretBytes<SHA256_LEN> {
    let mut tag = SecretBytes::zeroed();
    libcrux_hmac::hmac_sha2_256_slices(tag.expose_mut(), key, parts).expect("HMAC-SHA-256 input exceeds 4 GiB");
    tag
}

/// Whether `a` and `b` are equal, taking the same time wherever they differ. Use it to compare
/// MACs; lengths are not secret.
pub fn equal_in_constant_time(a: &[u8], b: &[u8]) -> bool {
    subtle::ConstantTimeEq::ct_eq(a, b).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::test_util::{hex, hex_array};

    #[test]
    fn sha256_known_answer() {
        // FIPS 180-2, appendix B.1.
        let expected = hex_array("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(sha256(&[b"abc"]), expected);
        assert_eq!(sha256(&[b"a", b"", b"bc"]), expected);
        let mut stream = Sha256Stream::default();
        for part in [b"a".as_slice(), b"", b"bc"] {
            stream.update(part);
        }
        assert_eq!(stream.finish(), expected);
    }

    #[test]
    fn hmac_sha256_known_answer() {
        // RFC 4231, test case 2.
        let tag = hmac_sha256(b"Jefe", &[b"what do ya want ", b"for nothing?"]);
        assert_eq!(
            tag.expose().as_slice(),
            hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        );
    }
}
