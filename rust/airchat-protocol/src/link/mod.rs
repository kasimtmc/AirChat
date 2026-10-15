//! Link sessions (docs/protocol.md §6): an authenticated, encrypted channel between two adjacent
//! devices whose owners are contacts. Runs over any transport that delivers messages reliably and
//! in order (BLE, Bluetooth, Wi-Fi).

mod channel;
mod handshake;
mod session;
pub(crate) mod symmetric;
mod tag;

#[cfg(test)]
mod tests;

pub use channel::{
    CHANNEL_MESSAGE_1, CHANNEL_MESSAGE_1_LEN, ChannelInitiator, ChannelKeys, ChannelResponder, Flavor, MESH_MESSAGE_1,
};
pub use handshake::{Established, Initiator, LocalKeys, MAX_HANDSHAKE_PAYLOAD, MESSAGE_1_LEN, RemoteKeys, Responder};
#[cfg(any(test, feature = "fuzzing"))]
pub(crate) use session::unpad;
pub use session::{MAX_RECORD_PAYLOAD, REKEY_INTERVAL, Record, Session};
pub use tag::{EPOCH_SECS, NONCE_LEN, Nonce, TAG_LEN, Tag, TagChecker, TagKey, epoch_at};

use crate::crypto::CryptoError;

/// First byte of every handshake message and the associated data of every record. Version 0 makes
/// no compatibility promises (docs/protocol.md §1).
pub(crate) const WIRE_VERSION: u8 = 0;

/// Deliberately coarse: a failed handshake never says which check failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LinkError {
    #[error("malformed message")]
    Malformed,
    #[error("unsupported protocol version")]
    UnsupportedVersion,
    #[error("authentication failed")]
    AuthenticationFailed,
    #[error("payload too large")]
    PayloadTooLarge,
    #[error("the session is closed")]
    Closed,
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}
