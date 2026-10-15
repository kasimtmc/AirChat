//! Contact cards (docs/protocol.md §4.6): what each side tells the other at the end of pairing.

use zeroize::Zeroizing;

use super::PairingError;
use crate::{
    crypto::{
        SecretBytes,
        kem::{DecapsulationKey, ENCAPSULATION_KEY_LEN, EncapsulationKey},
        sign::{SIGNATURE_LEN, Signature},
    },
    identity::{Identity, PublicIdentity},
    labels,
};

pub const PRESENCE_KEY_LEN: usize = 32;

/// First byte of a pairing channel message carrying a card.
const MESSAGE_CARD: u8 = 1;
/// First byte of one carrying only an identity key and its proof (§4.8).
const MESSAGE_IDENTITY: u8 = 2;
const CARD_VERSION: u8 = 0;
/// Every allowed name fits: at most 64 characters of at most 4 UTF-8 bytes each.
/// Longest display name, in characters.
pub const MAX_DISPLAY_NAME_CHARS: usize = 64;
const MAX_NAME_BYTES: usize = 4 * MAX_DISPLAY_NAME_CHARS;
const FIXED_LEN: usize = 2 + 32 + ENCAPSULATION_KEY_LEN + SIGNATURE_LEN + PRESENCE_KEY_LEN + 2 + SIGNATURE_LEN;

/// What this device tells a new contact about its owner.
pub struct LocalProfile<'a> {
    pub identity: &'a Identity,
    pub static_kem: &'a DecapsulationKey,
    /// Lets contacts recognise this device's discovery beacons (§5).
    pub presence_key: &'a SecretBytes<PRESENCE_KEY_LEN>,
    pub display_name: &'a str,
}

/// A new contact, authenticated by pairing. `Debug` redacts the secrets.
#[derive(Debug)]
pub struct PairedContact {
    pub identity: PublicIdentity,
    pub static_kem: EncapsulationKey,
    pub display_name: String,
    pub presence_key: SecretBytes<PRESENCE_KEY_LEN>,
    /// The pre-shared key of all future link sessions with this contact (§6).
    pub link_psk: SecretBytes<32>,
}

/// A peer's card whose signatures have been verified.
pub(crate) struct VerifiedCard {
    pub identity: PublicIdentity,
    pub static_kem: EncapsulationKey,
    pub display_name: String,
    pub presence_key: SecretBytes<PRESENCE_KEY_LEN>,
}

/// ```text
/// 0x01 || version (0x00) || IK || static KEM key || card signature || presence key
///      || name length (u16) || name (UTF-8) || proof
/// card signature = Sign(IK, "AirChat v1 contact-card" || static KEM key)
/// proof          = Sign(IK, "AirChat v1 pairing-proof" || h)
/// ```
pub(super) fn encode(profile: &LocalProfile, handshake_hash: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>, PairingError> {
    let name = check_name(profile.display_name)?;
    let static_kem = profile.static_kem.encapsulation_key().as_bytes();
    let card_signature = profile.identity.sign(labels::CONTACT_CARD, &[static_kem]);
    let proof = profile.identity.sign(labels::PAIRING_PROOF, &[handshake_hash]);

    let mut out = Zeroizing::new(Vec::with_capacity(FIXED_LEN + name.len()));
    out.extend_from_slice(&[MESSAGE_CARD, CARD_VERSION]);
    out.extend_from_slice(profile.identity.public().as_bytes());
    out.extend_from_slice(static_kem);
    out.extend_from_slice(card_signature.as_bytes());
    out.extend_from_slice(profile.presence_key.expose());
    out.extend_from_slice(&u16::try_from(name.len()).expect("name length checked").to_be_bytes());
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(proof.as_bytes());
    Ok(out)
}

/// ```text
/// 0x02 || version (0x00) || IK || proof          proof = Sign(IK, "AirChat v1 pairing-proof" || h)
/// ```
/// Who this device is, without what a card tells contacts (§4.8).
pub(super) fn encode_identity(identity: &Identity, handshake_hash: &[u8; 32]) -> Vec<u8> {
    let proof = identity.sign(labels::PAIRING_PROOF, &[handshake_hash]);
    [
        &[MESSAGE_IDENTITY, CARD_VERSION][..],
        identity.public().as_bytes(),
        proof.as_bytes(),
    ]
    .concat()
}

/// Parses an identity record and checks its proof against this session's `handshake_hash`.
pub(crate) fn decode_identity(bytes: &[u8], handshake_hash: &[u8; 32]) -> Result<PublicIdentity, PairingError> {
    let mut reader = Reader(bytes);
    match reader.take::<2>()? {
        [MESSAGE_IDENTITY, CARD_VERSION] => {}
        [MESSAGE_IDENTITY, _] => return Err(PairingError::UnsupportedVersion),
        _ => return Err(PairingError::InvalidCard),
    }
    let identity = PublicIdentity::from_bytes(*reader.take::<32>()?);
    let proof = Signature::from_bytes(*reader.take::<SIGNATURE_LEN>()?);
    if !reader.0.is_empty() {
        return Err(PairingError::InvalidCard);
    }
    identity
        .verify(labels::PAIRING_PROOF, &[handshake_hash], &proof)
        .map_err(|_| PairingError::AuthenticationFailed)?;
    Ok(identity)
}

/// Parses a card and checks both signatures; the proof must cover this session's `handshake_hash`.
pub(crate) fn decode(bytes: &[u8], handshake_hash: &[u8; 32]) -> Result<VerifiedCard, PairingError> {
    let mut reader = Reader(bytes);
    match reader.take::<2>()? {
        [MESSAGE_CARD, CARD_VERSION] => {}
        [MESSAGE_CARD, _] => return Err(PairingError::UnsupportedVersion),
        _ => return Err(PairingError::InvalidCard),
    }
    let identity = PublicIdentity::from_bytes(*reader.take::<32>()?);
    let static_kem_bytes = reader.take::<ENCAPSULATION_KEY_LEN>()?;
    let card_signature = Signature::from_bytes(*reader.take::<SIGNATURE_LEN>()?);
    let presence_key = SecretBytes::from_slice(reader.take::<PRESENCE_KEY_LEN>()?)?;
    let name_len = usize::from(u16::from_be_bytes(*reader.take::<2>()?));
    if name_len > MAX_NAME_BYTES {
        return Err(PairingError::InvalidCard);
    }
    let name = std::str::from_utf8(reader.take_slice(name_len)?).map_err(|_| PairingError::InvalidCard)?;
    let proof = Signature::from_bytes(*reader.take::<SIGNATURE_LEN>()?);
    if !reader.0.is_empty() {
        return Err(PairingError::InvalidCard);
    }

    identity
        .verify(labels::CONTACT_CARD, &[static_kem_bytes], &card_signature)
        .map_err(|_| PairingError::AuthenticationFailed)?;
    identity
        .verify(labels::PAIRING_PROOF, &[handshake_hash], &proof)
        .map_err(|_| PairingError::AuthenticationFailed)?;
    let static_kem = EncapsulationKey::from_bytes(static_kem_bytes).map_err(|_| PairingError::InvalidCard)?;
    let display_name = check_name(name).map_err(|_| PairingError::InvalidCard)?.to_owned();
    Ok(VerifiedCard {
        identity,
        static_kem,
        display_name,
        presence_key,
    })
}

fn check_name(name: &str) -> Result<&str, PairingError> {
    let name = name.trim();
    if name.is_empty()
        || name.chars().count() > MAX_DISPLAY_NAME_CHARS
        || name.len() > MAX_NAME_BYTES
        || name.chars().any(char::is_control)
    {
        return Err(PairingError::InvalidDisplayName);
    }
    Ok(name)
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take<const N: usize>(&mut self) -> Result<&'a [u8; N], PairingError> {
        Ok(self.take_slice(N)?.try_into().expect("slice has length N"))
    }

    fn take_slice(&mut self, n: usize) -> Result<&'a [u8], PairingError> {
        let (head, tail) = self.0.split_at_checked(n).ok_or(PairingError::InvalidCard)?;
        self.0 = tail;
        Ok(head)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Owner {
        identity: Identity,
        static_kem: DecapsulationKey,
        presence_key: SecretBytes<PRESENCE_KEY_LEN>,
    }

    fn owner() -> Owner {
        Owner {
            identity: Identity::generate().unwrap(),
            static_kem: DecapsulationKey::generate().unwrap(),
            presence_key: SecretBytes::random().unwrap(),
        }
    }

    fn profile<'a>(owner: &'a Owner, name: &'a str) -> LocalProfile<'a> {
        LocalProfile {
            identity: &owner.identity,
            static_kem: &owner.static_kem,
            presence_key: &owner.presence_key,
            display_name: name,
        }
    }

    #[test]
    fn round_trip() {
        let ayse = owner();
        let card = encode(&profile(&ayse, "  Ayşe  "), &[1; 32]).unwrap();
        let decoded = decode(&card, &[1; 32]).unwrap();
        assert_eq!(decoded.identity, ayse.identity.public());
        assert_eq!(&decoded.static_kem, ayse.static_kem.encapsulation_key());
        assert_eq!(decoded.display_name, "Ayşe");
        assert_eq!(decoded.presence_key.expose(), ayse.presence_key.expose());
    }

    #[test]
    fn proof_is_bound_to_the_session() {
        let card = encode(&profile(&owner(), "Ali"), &[1; 32]).unwrap();
        assert_eq!(decode(&card, &[2; 32]).err(), Some(PairingError::AuthenticationFailed));
    }

    #[test]
    fn cannot_claim_someone_elses_kem_key_or_identity() {
        let (ayse, mallory) = (owner(), owner());
        let mut card = encode(&profile(&mallory, "Mallory"), &[1; 32]).unwrap();
        // Swap in Ayşe's identity key: neither signature verifies under it.
        card[2..34].copy_from_slice(ayse.identity.public().as_bytes());
        assert_eq!(decode(&card, &[1; 32]).err(), Some(PairingError::AuthenticationFailed));
    }

    #[test]
    fn rejects_malformed_cards() {
        let card = encode(&profile(&owner(), "Ali"), &[1; 32]).unwrap();
        for cut in [0, 1, 2, 100, card.len() - 1] {
            assert!(decode(&card[..cut], &[1; 32]).is_err(), "truncated at {cut}");
        }
        let mut longer = card.to_vec();
        longer.push(0);
        assert_eq!(decode(&longer, &[1; 32]).err(), Some(PairingError::InvalidCard));
        let mut future = card.to_vec();
        future[1] = 1;
        assert_eq!(decode(&future, &[1; 32]).err(), Some(PairingError::UnsupportedVersion));
    }

    #[test]
    fn enforces_name_rules() {
        let ali = owner();
        assert_eq!(
            encode(&profile(&ali, "   "), &[1; 32]).err(),
            Some(PairingError::InvalidDisplayName)
        );
        let long = "ş".repeat(MAX_DISPLAY_NAME_CHARS + 1);
        assert_eq!(
            encode(&profile(&ali, &long), &[1; 32]).err(),
            Some(PairingError::InvalidDisplayName)
        );
        assert_eq!(
            encode(&profile(&ali, "Ali\nVeli"), &[1; 32]).err(),
            Some(PairingError::InvalidDisplayName)
        );
        let longest = "🦄".repeat(MAX_DISPLAY_NAME_CHARS);
        let card = encode(&profile(&ali, &longest), &[1; 32]).unwrap();
        assert_eq!(decode(&card, &[1; 32]).unwrap().display_name, longest);
    }
}
