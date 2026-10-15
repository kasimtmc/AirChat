//! Pairing (docs/protocol.md §4.3–§4.6): how two people become contacts.
//!
//! Two devices that know nothing about each other agree on keys over the radio and exchange
//! contact cards. The users authenticate the exchange out of band: by scanning a QR code
//! ([`Mode::Invite`]) or by comparing five emoji ([`Mode::Nearby`]). The result, a
//! [`PairedContact`], holds everything the link handshake (§6) needs.

mod card;
mod invite;
mod protocol;
mod sas;

#[cfg(test)]
mod tests;

#[cfg(any(test, feature = "fuzzing"))]
pub(crate) use card::decode as decode_card;
pub use card::{LocalProfile, MAX_DISPLAY_NAME_CHARS, PRESENCE_KEY_LEN, PairedContact};
pub use invite::{INVITE_LIFETIME_SECS, Invite, InviteId, ScannedInvite};
pub(crate) use invite::{QR_PREFIX, QR_VERSION, base32_decode, base32_encode};
pub use protocol::{Event, Mode, Pairing, Requester};
pub use sas::{SAS_EMOJI, SAS_LEN, Sas};

use crate::{crypto::CryptoError, link::LinkError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PairingError {
    #[error("malformed message")]
    Malformed,
    #[error("unsupported protocol version")]
    UnsupportedVersion,
    #[error("authentication failed")]
    AuthenticationFailed,
    #[error("the QR code is not an AirChat invite")]
    NotAnInvite,
    #[error("the invite is unknown or expired")]
    UnknownInvite,
    #[error("no request of this device's asks for that")]
    UnknownRequest,
    #[error("the contact card is invalid")]
    InvalidCard,
    #[error("the display name is invalid")]
    InvalidDisplayName,
    #[error("a device cannot pair with its own identity")]
    SelfPairing,
    #[error("the other device cancelled pairing")]
    Rejected,
    #[error("message arrived in the wrong state")]
    UnexpectedMessage,
    #[error(transparent)]
    Link(#[from] LinkError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}
