//! AirChat ID (docs/protocol.md §4.2): a short, typeable name for an identity key.
//!
//! `AIR-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX`: 24 Crockford Base32 symbols carrying the first 120 bits of a
//! hash of the identity key, plus one Luhn mod 32 check symbol that catches every single-symbol typo.

use core::{fmt, str::FromStr};

use super::PublicIdentity;
use crate::{crypto::hash::sha256, labels};

/// 120 bits: forging an ID for another key would take ~2^120 key generations.
pub const ID_LEN: usize = 15;

const SYMBOLS: usize = ID_LEN * 8 / 5;
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const PREFIX: &str = "AIR";
const GROUP_LEN: usize = 5;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct AirChatId([u8; ID_LEN]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IdParseError {
    #[error("an AirChat ID has 25 characters")]
    InvalidLength,
    #[error("'{0}' cannot appear in an AirChat ID")]
    InvalidCharacter(char),
    #[error("the AirChat ID contains a typo")]
    ChecksumMismatch,
}

impl AirChatId {
    pub fn derive(identity: &PublicIdentity) -> Self {
        let digest = sha256(&[labels::AIRCHAT_ID, identity.as_bytes()]);
        Self(
            digest[..ID_LEN]
                .try_into()
                .expect("SHA-256 output is longer than an ID"),
        )
    }

    pub fn from_bytes(bytes: [u8; ID_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; ID_LEN] {
        &self.0
    }

    /// True when this ID was derived from `identity`. Used when a contact added by typing their ID
    /// first presents their key.
    pub fn belongs_to(&self, identity: &PublicIdentity) -> bool {
        Self::derive(identity) == *self
    }

    /// Accepts any letter case, with or without the `AIR` prefix, dashes and spaces, and the Crockford
    /// look-alikes `O` → `0`, `I`/`L` → `1`.
    pub fn parse(text: &str) -> Result<Self, IdParseError> {
        let mut chars: Vec<char> = text
            .chars()
            .filter(|c| *c != '-' && !c.is_whitespace())
            .map(|c| c.to_ascii_uppercase())
            .collect();
        if chars.len() == PREFIX.len() + SYMBOLS + 1 && chars.iter().take(PREFIX.len()).copied().eq(PREFIX.chars()) {
            chars.drain(..PREFIX.len());
        }
        if chars.len() != SYMBOLS + 1 {
            return Err(IdParseError::InvalidLength);
        }

        let values = chars.into_iter().map(symbol_value).collect::<Result<Vec<u8>, _>>()?;
        let (data, check) = values.split_at(SYMBOLS);
        if check_symbol(data) != check[0] {
            return Err(IdParseError::ChecksumMismatch);
        }
        Ok(Self::from_symbols(data))
    }

    /// The ID as 5-bit values, most significant bits first.
    fn symbols(&self) -> [u8; SYMBOLS] {
        let mut symbols = [0; SYMBOLS];
        let (mut acc, mut bits, mut next) = (0u16, 0, 0);
        for &byte in &self.0 {
            acc = (acc << 8) | u16::from(byte);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                symbols[next] = ((acc >> bits) & 0x1f) as u8;
                next += 1;
            }
            acc &= (1 << bits) - 1;
        }
        symbols
    }

    fn from_symbols(symbols: &[u8]) -> Self {
        let mut bytes = [0; ID_LEN];
        let (mut acc, mut bits, mut next) = (0u16, 0, 0);
        for &symbol in symbols {
            acc = (acc << 5) | u16::from(symbol);
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                bytes[next] = (acc >> bits) as u8;
                next += 1;
                acc &= (1 << bits) - 1;
            }
        }
        Self(bytes)
    }
}

fn symbol_value(c: char) -> Result<u8, IdParseError> {
    let canonical = match c {
        'O' => '0',
        'I' | 'L' => '1',
        other => other,
    };
    ALPHABET
        .iter()
        .position(|&a| char::from(a) == canonical)
        .map(|p| p as u8)
        .ok_or(IdParseError::InvalidCharacter(c))
}

/// Luhn mod 32 check symbol: detects every single-symbol substitution.
fn check_symbol(symbols: &[u8]) -> u8 {
    const N: u32 = ALPHABET.len() as u32;
    let sum: u32 = symbols
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &s)| {
            let addend = u32::from(s) * if i % 2 == 0 { 2 } else { 1 };
            addend / N + addend % N
        })
        .sum();
    ((N - sum % N) % N) as u8
}

impl fmt::Display for AirChatId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let symbols = self.symbols();
        let check = check_symbol(&symbols);
        f.write_str(PREFIX)?;
        for (i, value) in symbols.into_iter().chain([check]).enumerate() {
            if i % GROUP_LEN == 0 {
                f.write_str("-")?;
            }
            write!(f, "{}", char::from(ALPHABET[usize::from(value)]))?;
        }
        Ok(())
    }
}

impl fmt::Debug for AirChatId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AirChatId({self})")
    }
}

impl FromStr for AirChatId {
    type Err = IdParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{SecretBytes, test_util::hex},
        identity::Identity,
    };

    /// (seed, public key, ID bytes, ID text), computed by an independent Python implementation
    /// (docs/protocol.md §4.2).
    const VECTORS: &[(&str, &str, &str, &str)] = &[
        (
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
            "d56ac318cd98bd598b52d0aa9f8adb",
            "AIR-TNNC6-66DK2-YNK2T-JT2N9-Z2PVH",
        ),
        (
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "76a1592044a6e4f511265bca73a604d90b0529d1df602be30a19a9257660d1f5",
            "806659295c21d5e08231d614cc1d62",
            "AIR-G1K5J-AAW47-AY10H-HTRAC-R7B2R",
        ),
    ];

    fn vector_identity() -> Identity {
        Identity::from_seed(SecretBytes::from_slice(&hex(VECTORS[0].0)).unwrap())
    }

    #[test]
    fn known_answers() {
        for &(seed, public_key, id_bytes, id_text) in VECTORS {
            let public = Identity::from_seed(SecretBytes::from_slice(&hex(seed)).unwrap()).public();
            assert_eq!(public.as_bytes().as_slice(), hex(public_key));
            let id = public.airchat_id();
            assert_eq!(id.as_bytes().as_slice(), hex(id_bytes));
            assert_eq!(id.to_string(), id_text);
            assert_eq!(AirChatId::parse(id_text), Ok(id));
        }
    }

    #[test]
    fn display_parses_back() {
        for _ in 0..64 {
            let id = Identity::generate().unwrap().public().airchat_id();
            let text = id.to_string();
            assert_eq!(text.len(), "AIR-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX".len());
            assert_eq!(AirChatId::parse(&text), Ok(id));
        }
    }

    #[test]
    fn parsing_is_forgiving_about_formatting() {
        let id = vector_identity().public().airchat_id();
        let text = id.to_string();
        let bare: String = text.chars().skip(4).filter(|c| *c != '-').collect();
        assert_eq!(AirChatId::parse(&bare), Ok(id));
        assert_eq!(AirChatId::parse(&text.to_lowercase()), Ok(id));
        assert_eq!(
            AirChatId::parse(&format!("  {} ", bare.replace('0', "O").replace('1', "l"))),
            Ok(id)
        );
        let spaced: String = bare.chars().flat_map(|c| [c, ' ']).collect();
        assert_eq!(AirChatId::parse(&spaced), Ok(id));
    }

    #[test]
    fn every_single_symbol_typo_is_caught() {
        let text: Vec<u8> = vector_identity().public().airchat_id().to_string().into_bytes();
        for position in (0..text.len()).filter(|&i| text[i] != b'-' && i >= PREFIX.len()) {
            for &replacement in ALPHABET.iter().filter(|&&a| a != text[position]) {
                let mut typo = text.clone();
                typo[position] = replacement;
                let typo = String::from_utf8(typo).unwrap();
                assert_eq!(AirChatId::parse(&typo), Err(IdParseError::ChecksumMismatch), "{typo}");
            }
        }
    }

    #[test]
    fn rejects_bad_input() {
        assert_eq!(AirChatId::parse(""), Err(IdParseError::InvalidLength));
        assert_eq!(AirChatId::parse("AIR-00000-00000"), Err(IdParseError::InvalidLength));
        assert_eq!(
            AirChatId::parse("AIR-0000U-00000-00000-00000-00000"),
            Err(IdParseError::InvalidCharacter('U'))
        );
    }

    #[test]
    fn belongs_only_to_its_key() {
        let alice = Identity::generate().unwrap().public();
        let bob = Identity::generate().unwrap().public();
        assert!(alice.airchat_id().belongs_to(&alice));
        assert!(!alice.airchat_id().belongs_to(&bob));
    }

    #[test]
    fn symbol_packing_round_trips() {
        for i in 0..=255u8 {
            let id = AirChatId([i.wrapping_mul(97); ID_LEN]);
            assert_eq!(AirChatId::from_symbols(&id.symbols()), id);
        }
    }
}
