//! The AirChat protocol: identities, pairing, link sessions, messages, groups, the mesh,
//! walkie-talkie channels and paths, as specified in `docs/protocol.md`, and the cryptography
//! they use.
//!
//! Formats and cryptography only: no storage, no transports, no platform code. An application
//! keeps the state these functions take and return, and carries their bytes.

#![forbid(unsafe_code)]

pub mod attest;
pub mod channel;
pub mod chat;
pub mod crypto;
pub mod discovery;
#[cfg(any(test, feature = "fuzzing"))]
pub mod fuzz;
pub mod group;
pub mod identity;
pub mod labels;
pub mod link;
pub mod mesh;
pub mod pairing;
pub mod path;

/// Wire protocol version spoken by this build. See `docs/protocol.md`.
///
/// Stays 0 until the specification reaches 1.0; version 0 peers make no compatibility promises.
pub const PROTOCOL_VERSION: u16 = 0;
