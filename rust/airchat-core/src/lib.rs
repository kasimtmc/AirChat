//! Platform-independent AirChat core: storage, contacts, groups, routing and the node that runs them,
//! on top of the protocol in `airchat_protocol`.
//!
//! Nothing in this crate may depend on a platform or on FFI. See `docs/architecture.md`.

#![forbid(unsafe_code)]

pub mod account;
#[cfg(any(test, feature = "fuzzing"))]
pub mod fuzz;
pub mod inbox;
pub mod jitter;
pub mod media;
pub mod node;
pub mod storage;

// The protocol, in its own crate so that other implementations can build on it.
pub use airchat_protocol::{
    PROTOCOL_VERSION, attest, channel, chat, crypto, discovery, group, identity, labels, link, mesh, pairing, path,
};

/// Version of this crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
