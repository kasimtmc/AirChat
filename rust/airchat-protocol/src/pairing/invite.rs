//! QR invites (docs/protocol.md §4.4).
//!
//! The device that wants to be added shows a QR code with its identity key and a one-time secret.
//! Only someone who read the code knows the secret, so only they can open the pairing channel, and
//! the identity key tells them whose device they reached.

use zeroize::Zeroizing;

use super::PairingError;
use crate::{
    crypto::{
        SecretBytes, kdf,
        random::{OsRng, Rng},
    },
    discovery::{PAIRING_TOKEN_LEN, PairingToken},
    identity::PublicIdentity,
    labels,
};

pub const INVITE_SECRET_LEN: usize = 16;
pub const INVITE_ID_LEN: usize = 8;
/// How long the device showing a QR code accepts it. Invites are also single use.
pub const INVITE_LIFETIME_SECS: u64 = 600;

pub type InviteId = [u8; INVITE_ID_LEN];

pub(crate) const QR_PREFIX: &str = "AIRCHAT:";
pub(crate) const QR_VERSION: u8 = 0;
const QR_KIND_INVITE: u8 = 1;
const QR_PAYLOAD_LEN: usize = 2 + 32 + INVITE_SECRET_LEN;
/// Crockford Base32: only characters QR alphanumeric mode encodes compactly.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// An invite this device shows as a QR code.
pub struct Invite {
    identity: PublicIdentity,
    secret: SecretBytes<INVITE_SECRET_LEN>,
}

impl Invite {
    pub fn new(identity: PublicIdentity) -> Result<Self, PairingError> {
        Self::new_from(identity, &mut OsRng)
    }

    pub(crate) fn new_from(identity: PublicIdentity, rng: &mut dyn Rng) -> Result<Self, PairingError> {
        Ok(Self {
            identity,
            secret: SecretBytes::random_from(rng)?,
        })
    }

    /// The text to encode in the QR code: `AIRCHAT:` followed by Base32.
    pub fn qr_text(&self) -> Zeroizing<String> {
        let mut payload = Zeroizing::new(Vec::with_capacity(QR_PAYLOAD_LEN));
        payload.extend_from_slice(&[QR_VERSION, QR_KIND_INVITE]);
        payload.extend_from_slice(self.identity.as_bytes());
        payload.extend_from_slice(self.secret.expose());
        let mut text = Zeroizing::new(String::from(QR_PREFIX));
        text.push_str(&base32_encode(&payload));
        text
    }

    pub fn id(&self) -> InviteId {
        invite_id(&self.secret)
    }

    /// The pairing token to announce while the code is shown, so whoever scans it finds this device.
    pub fn beacon_token(&self) -> PairingToken {
        beacon_token(&self.id())
    }

    pub(super) fn psk(&self) -> Result<SecretBytes<32>, PairingError> {
        invite_psk(&self.secret)
    }
}

/// An invite read from someone else's QR code.
pub struct ScannedInvite {
    identity: PublicIdentity,
    secret: SecretBytes<INVITE_SECRET_LEN>,
}

impl ScannedInvite {
    pub fn parse(text: &str) -> Result<Self, PairingError> {
        let encoded = text.trim().strip_prefix(QR_PREFIX).ok_or(PairingError::NotAnInvite)?;
        let payload = base32_decode(encoded).ok_or(PairingError::NotAnInvite)?;
        match payload.as_slice() {
            [QR_VERSION, QR_KIND_INVITE, rest @ ..] if rest.len() == QR_PAYLOAD_LEN - 2 => {
                let (identity, secret) = rest.split_at(32);
                Ok(Self {
                    identity: PublicIdentity::from_bytes(identity.try_into().expect("length checked")),
                    secret: SecretBytes::from_slice(secret)?,
                })
            }
            [version, ..] if *version != QR_VERSION => Err(PairingError::UnsupportedVersion),
            _ => Err(PairingError::NotAnInvite),
        }
    }

    /// Whose device the code leads to; pairing fails unless that device presents this identity.
    pub fn identity(&self) -> &PublicIdentity {
        &self.identity
    }

    pub fn id(&self) -> InviteId {
        invite_id(&self.secret)
    }

    /// The pairing token the device showing the code announces: connect to the one announcing it.
    pub fn beacon_token(&self) -> PairingToken {
        beacon_token(&self.id())
    }

    pub(super) fn psk(&self) -> Result<SecretBytes<32>, PairingError> {
        invite_psk(&self.secret)
    }
}

/// The first bytes of the invite id (§4.4): announced as a pairing beacon, it tells the scanner
/// which device shows the code, and nothing to anyone else.
fn beacon_token(id: &InviteId) -> PairingToken {
    id[..PAIRING_TOKEN_LEN]
        .try_into()
        .expect("an invite id is longer than a token")
}

fn invite_id(secret: &SecretBytes<INVITE_SECRET_LEN>) -> InviteId {
    let id = kdf::derive::<INVITE_ID_LEN>(&[], secret.expose(), labels::PAIRING_INVITE_ID)
        .expect("8 bytes is within HKDF's output limit");
    *id.expose()
}

fn invite_psk(secret: &SecretBytes<INVITE_SECRET_LEN>) -> Result<SecretBytes<32>, PairingError> {
    Ok(kdf::derive(&[], secret.expose(), labels::PAIRING_INVITE_PSK)?)
}

pub(crate) fn base32_encode(bytes: &[u8]) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(bytes.len() * 8 / 5 + 1));
    let (mut acc, mut bits) = (0u16, 0);
    for &byte in bytes {
        acc = (acc << 8) | u16::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[usize::from((acc >> bits) & 0x1f)]));
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(char::from(ALPHABET[usize::from((acc << (5 - bits)) & 0x1f)]));
    }
    out
}

/// Strict inverse of [`base32_encode`]: rejects unknown characters and non-zero trailing bits.
pub(crate) fn base32_decode(text: &str) -> Option<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(text.len() * 5 / 8));
    let (mut acc, mut bits) = (0u16, 0);
    for c in text.bytes() {
        let value = ALPHABET.iter().position(|&a| a == c)?;
        acc = (acc << 5) | value as u16;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    // A valid encoding leaves fewer than five unused bits, all zero.
    (bits < 5 && acc == 0).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    #[test]
    fn qr_text_round_trips() {
        let identity = Identity::generate().unwrap().public();
        let invite = Invite::new(identity).unwrap();
        let text = invite.qr_text();
        assert!(text.starts_with("AIRCHAT:"));
        assert_eq!(text.len(), "AIRCHAT:".len() + 80, "50 bytes in Base32");
        assert!(
            text.bytes()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b':')
        );

        let scanned = ScannedInvite::parse(&text).unwrap();
        assert_eq!(scanned.identity(), &identity);
        assert_eq!(scanned.id(), invite.id());
        assert_eq!(scanned.psk().unwrap().expose(), invite.psk().unwrap().expose());
    }

    #[test]
    fn every_invite_is_new() {
        let identity = Identity::generate().unwrap().public();
        assert_ne!(Invite::new(identity).unwrap().id(), Invite::new(identity).unwrap().id());
    }

    #[test]
    fn rejects_other_codes() {
        assert_eq!(
            ScannedInvite::parse("https://example.com").err(),
            Some(PairingError::NotAnInvite)
        );
        assert_eq!(ScannedInvite::parse("AIRCHAT:").err(), Some(PairingError::NotAnInvite));
        assert_eq!(
            ScannedInvite::parse("AIRCHAT:U000").err(),
            Some(PairingError::NotAnInvite)
        );

        let identity = Identity::generate().unwrap().public();
        let text = Invite::new(identity).unwrap().qr_text();
        assert_eq!(
            ScannedInvite::parse(&text[..text.len() - 1]).err(),
            Some(PairingError::NotAnInvite)
        );
        let mut future = vec![QR_VERSION + 1, QR_KIND_INVITE];
        future.extend_from_slice(&[0; QR_PAYLOAD_LEN - 2]);
        let future = format!("{QR_PREFIX}{}", base32_encode(&future).as_str());
        assert_eq!(
            ScannedInvite::parse(&future).err(),
            Some(PairingError::UnsupportedVersion)
        );
    }

    #[test]
    fn base32_is_strict() {
        for len in 0..12 {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 37) as u8).collect();
            assert_eq!(
                base32_decode(&base32_encode(&bytes)).unwrap().as_slice(),
                bytes.as_slice()
            );
        }
        assert!(base32_decode("01").is_none(), "non-zero trailing bits");
        assert!(base32_decode("0O").is_none(), "letter O is not in the alphabet");
        assert!(base32_decode("0").is_none(), "a whole unused symbol");
    }
}
