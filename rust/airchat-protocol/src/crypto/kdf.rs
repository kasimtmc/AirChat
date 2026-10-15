//! HKDF-SHA-256 (RFC 5869).

use libcrux_hkdf::Algorithm;

use super::{CryptoError, SecretBytes};

/// Largest output HKDF-SHA-256 can produce.
pub const MAX_OUTPUT_LEN: usize = 255 * 32;

/// HKDF-Extract: turns input keying material into a pseudorandom key.
pub fn extract(salt: &[u8], ikm: &[u8]) -> SecretBytes<32> {
    let mut prk = SecretBytes::zeroed();
    libcrux_hkdf::extract(Algorithm::Sha256, prk.expose_mut(), salt, ikm).expect("HKDF-Extract input exceeds 4 GiB");
    prk
}

/// HKDF-Expand: derives `N` bytes bound to `info` from a pseudorandom key.
pub fn expand<const N: usize>(prk: &SecretBytes<32>, info: &[u8]) -> Result<SecretBytes<N>, CryptoError> {
    if N > MAX_OUTPUT_LEN {
        return Err(CryptoError::InputTooLong);
    }
    let mut okm = SecretBytes::zeroed();
    libcrux_hkdf::expand(Algorithm::Sha256, okm.expose_mut(), prk.expose(), info)
        .map_err(|_| CryptoError::InputTooLong)?;
    Ok(okm)
}

/// HKDF-Extract followed by HKDF-Expand.
pub fn derive<const N: usize>(salt: &[u8], ikm: &[u8], info: &[u8]) -> Result<SecretBytes<N>, CryptoError> {
    expand(&extract(salt, ikm), info)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::test_util::hex;

    // RFC 5869, appendix A.1 (test case 1).
    const IKM: [u8; 22] = [0x0b; 22];
    const SALT: &str = "000102030405060708090a0b0c";
    const INFO: &str = "f0f1f2f3f4f5f6f7f8f9";
    const PRK: &str = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5";
    const OKM: &str = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";

    #[test]
    fn extract_known_answer() {
        assert_eq!(extract(&hex(SALT), &IKM).expose().as_slice(), hex(PRK));
    }

    #[test]
    fn derive_known_answer() {
        let okm = derive::<42>(&hex(SALT), &IKM, &hex(INFO)).unwrap();
        assert_eq!(okm.expose().as_slice(), hex(OKM));
    }

    #[test]
    fn expand_rejects_oversized_output() {
        let prk = extract(b"salt", b"ikm");
        assert_eq!(
            expand::<{ MAX_OUTPUT_LEN + 1 }>(&prk, b"").unwrap_err(),
            CryptoError::InputTooLong
        );
    }
}
