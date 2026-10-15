//! The short authentication string of Nearby Pairing (docs/protocol.md §4.5): five emoji that both
//! users compare.

use core::fmt;

use crate::{crypto::hash::sha256, labels};

pub const SAS_LEN: usize = 5;

/// The 64 symbols, indexed by 6-bit value. Chosen to be common, visually distinct and available
/// as single code points since Android 10. Part of the protocol: every platform shows the same
/// emoji for the same index.
pub const SAS_EMOJI: [&str; 64] = [
    "🐶", "🐱", "🦁", "🐴", "🦄", "🐷", "🐘", "🐰", // 0
    "🐼", "🐔", "🐧", "🐢", "🐟", "🐙", "🦋", "🌻", // 8
    "🌳", "🌵", "🍄", "🌍", "🌙", "🌈", "🔥", "🍌", // 16
    "🍎", "🍓", "🌽", "🍕", "🎂", "🍇", "😀", "🤖", // 24
    "🎩", "👓", "🔧", "🐝", "👍", "🌂", "⌛", "⏰", // 32
    "🎁", "💡", "📕", "🔦", "📎", "🧲", "🔒", "🔑", // 40
    "🔨", "📞", "🚩", "🚂", "🚲", "🚁", "🚀", "🏆", // 48
    "⚽", "🎸", "🎺", "🔔", "⚓", "🎧", "📁", "📌", // 56
];

/// Five 6-bit indices into [`SAS_EMOJI`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Sas([u8; SAS_LEN]);

impl Sas {
    /// The top 30 bits of `SHA-256(label || h || nonce_i || nonce_r)`, six bits per symbol.
    pub(super) fn derive(handshake_hash: &[u8; 32], initiator_nonce: &[u8], responder_nonce: &[u8]) -> Self {
        let digest = sha256(&[labels::PAIRING_SAS, handshake_hash, initiator_nonce, responder_nonce]);
        let bits = u32::from_be_bytes(digest[..4].try_into().expect("digest is longer than 4 bytes"));
        Self(core::array::from_fn(|i| ((bits >> (26 - 6 * i)) & 0x3f) as u8))
    }

    pub fn indices(&self) -> [u8; SAS_LEN] {
        self.0
    }

    pub fn emoji(&self) -> [&'static str; SAS_LEN] {
        self.0.map(|i| SAS_EMOJI[usize::from(i)])
    }
}

impl fmt::Debug for Sas {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sas({})", self.emoji().concat())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn symbols_are_distinct_single_code_points() {
        let distinct: HashSet<_> = SAS_EMOJI.iter().collect();
        assert_eq!(distinct.len(), SAS_EMOJI.len());
        for emoji in SAS_EMOJI {
            assert_eq!(emoji.chars().count(), 1, "{emoji} must be one code point");
        }
    }

    #[test]
    fn uses_the_top_thirty_bits() {
        // Recompute by hand: the indices must come from bits 31..2 of the first four digest bytes.
        let (h, ni, nr) = ([7; 32], [1; 32], [2; 32]);
        let digest = sha256(&[labels::PAIRING_SAS, &h, &ni, &nr]);
        let bits = u32::from_be_bytes(digest[..4].try_into().unwrap());
        let sas = Sas::derive(&h, &ni, &nr);
        let rebuilt = sas.indices().iter().fold(0u32, |acc, &i| (acc << 6) | u32::from(i));
        assert_eq!(rebuilt, bits >> 2);
        assert_ne!(sas, Sas::derive(&h, &ni, &[3; 32]));
    }
}
