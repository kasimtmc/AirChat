//! The channel link handshake (docs/protocol.md §11.3): between two members of a walkie-talkie
//! channel, who know the channel's key but not each other.
//!
//! ```text
//! pre-shared:  channel id, psk (from the channel key)
//! -> 1:  tag, e, AEAD()                  responder recognises the channel by `tag`
//! <- 2:  Encaps(e), AEAD(payload)        initiator now knows a member answers
//! -> 3:  AEAD(payload)                   responder now knows a member called
//! ```
//!
//! Knowing the channel key is all a member is; anyone holding it may join, as on a radio channel.
//! Mesh links (§10.2) are the same handshake under a public "channel" everyone knows, with their own
//! message numbers: they authenticate nobody, but each gets fresh keys.
//! The session keys depend on `Encaps(e)`, whose private half is deleted after the handshake, so
//! recorded sessions stay secret even if the channel key leaks later (forward secrecy), and the key
//! exchange is X-Wing, post-quantum.

use zeroize::Zeroizing;

use super::{
    Established, LinkError, WIRE_VERSION,
    handshake::{HEADER_LEN, check_header, check_payload, open_payload},
    session::{self, Session},
    symmetric::SymmetricState,
    tag::{TAG_LEN, Tag},
};
use crate::{
    crypto::{
        SecretBytes,
        aead::TAG_LEN as AEAD_TAG_LEN,
        kem::{CIPHERTEXT_LEN, Ciphertext, DecapsulationKey, ENCAPSULATION_KEY_LEN, EncapsulationKey},
        random::{OsRng, Rng},
    },
    labels,
};

/// Message numbers of the channel handshake; a connection whose first frame has `0x11` is one.
pub const CHANNEL_MESSAGE_1: u8 = 0x11;
/// The same for a mesh link (§10.2).
pub const MESH_MESSAGE_1: u8 = 0x31;

pub const CHANNEL_MESSAGE_1_LEN: usize = HEADER_LEN + TAG_LEN + ENCAPSULATION_KEY_LEN + AEAD_TAG_LEN;

/// Which handshake: a channel link's or a mesh link's. They differ in message numbers (messages 2
/// and 3 follow the first) and protocol name only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flavor {
    message_1: u8,
    name: &'static [u8],
}

impl Flavor {
    pub const CHANNEL: Self = Self {
        message_1: CHANNEL_MESSAGE_1,
        name: labels::LINK_CHANNEL,
    };
    pub const MESH: Self = Self {
        message_1: MESH_MESSAGE_1,
        name: labels::LINK_MESH,
    };
}

/// The channel a handshake is for.
pub struct ChannelKeys<'a> {
    pub id: &'a [u8],
    pub psk: &'a SecretBytes<32>,
    pub flavor: Flavor,
}

/// The initiator between sending message 1 and receiving message 2.
pub struct ChannelInitiator {
    state: SymmetricState,
    ephemeral: DecapsulationKey,
    flavor: Flavor,
}

impl ChannelInitiator {
    pub fn start(channel: &ChannelKeys, tag: &Tag) -> Result<(Self, Vec<u8>), LinkError> {
        Self::start_from(channel, tag, &mut OsRng)
    }

    pub(crate) fn start_from(
        channel: &ChannelKeys,
        tag: &Tag,
        rng: &mut dyn Rng,
    ) -> Result<(Self, Vec<u8>), LinkError> {
        let mut state = initial_state(channel)?;
        let header = [WIRE_VERSION, channel.flavor.message_1];
        state.mix_hash(&header);
        state.mix_hash(tag);
        let ephemeral = DecapsulationKey::generate_from(rng)?;
        state.mix_hash(ephemeral.encapsulation_key().as_bytes());
        let confirmation = state.encrypt_and_hash(&[])?;
        let message = [
            &header[..],
            tag,
            ephemeral.encapsulation_key().as_bytes(),
            &confirmation,
        ]
        .concat();
        Ok((
            Self {
                state,
                ephemeral,
                flavor: channel.flavor,
            },
            message,
        ))
    }

    /// Reads message 2 and returns the session together with message 3, which carries `payload`.
    pub fn finish(self, message: &[u8], payload: &[u8]) -> Result<(Established, Vec<u8>), LinkError> {
        let Self {
            mut state,
            ephemeral,
            flavor,
        } = self;
        let body = check_header(message, flavor.message_1 + 1)?;
        if body.len() < CIPHERTEXT_LEN + AEAD_TAG_LEN {
            return Err(LinkError::Malformed);
        }
        let (to_ephemeral, sealed) = body.split_at(CIPHERTEXT_LEN);
        state.mix_hash(&message[..HEADER_LEN]);
        state.mix_hash(to_ephemeral);
        state.mix_key(ephemeral.decapsulate(&Ciphertext::from_bytes(to_ephemeral)?)?.expose())?;
        drop(ephemeral);
        let peer_payload = open_payload(&mut state, sealed)?;

        let header = [WIRE_VERSION, flavor.message_1 + 2];
        state.mix_hash(&header);
        let sealed = state.encrypt_and_hash(&session::pad(0, check_payload(payload)?)?)?;
        let reply = [&header[..], &sealed].concat();
        let (send, receive) = state.split()?;
        let session = Session::new(send, receive, state.handshake_hash());
        Ok((
            Established {
                session,
                peer_payload,
                next_link_key: None,
            },
            reply,
        ))
    }
}

/// The responder between sending message 2 and receiving message 3.
pub struct ChannelResponder {
    state: SymmetricState,
    flavor: Flavor,
}

impl ChannelResponder {
    /// The recognition tag of a channel link's message 1, to find the channel before any
    /// public-key work.
    pub fn tag(message: &[u8]) -> Result<Tag, LinkError> {
        Self::tag_of(Flavor::CHANNEL, message)
    }

    fn tag_of(flavor: Flavor, message: &[u8]) -> Result<Tag, LinkError> {
        let body = check_header(message, flavor.message_1)?;
        if message.len() != CHANNEL_MESSAGE_1_LEN {
            return Err(LinkError::Malformed);
        }
        Ok(body[..TAG_LEN].try_into().expect("length checked"))
    }

    /// Reads message 1 and returns message 2, which carries `payload`.
    pub fn respond(channel: &ChannelKeys, message: &[u8], payload: &[u8]) -> Result<(Self, Vec<u8>), LinkError> {
        Self::respond_from(channel, message, payload, &mut OsRng)
    }

    pub(crate) fn respond_from(
        channel: &ChannelKeys,
        message: &[u8],
        payload: &[u8],
        rng: &mut dyn Rng,
    ) -> Result<(Self, Vec<u8>), LinkError> {
        let tag = Self::tag_of(channel.flavor, message)?;
        let body = &message[HEADER_LEN + TAG_LEN..];
        let (ephemeral_key, confirmation) = body.split_at(ENCAPSULATION_KEY_LEN);
        let mut state = initial_state(channel)?;
        state.mix_hash(&message[..HEADER_LEN]);
        state.mix_hash(&tag);
        let ephemeral_key = EncapsulationKey::from_bytes(ephemeral_key)?;
        state.mix_hash(ephemeral_key.as_bytes());
        if !state.decrypt_and_hash(confirmation)?.is_empty() {
            return Err(LinkError::Malformed);
        }

        let header = [WIRE_VERSION, channel.flavor.message_1 + 1];
        state.mix_hash(&header);
        let (shared, to_ephemeral) = ephemeral_key.encapsulate_from(rng)?;
        state.mix_hash(to_ephemeral.as_bytes());
        state.mix_key(shared.expose())?;
        let sealed = state.encrypt_and_hash(&session::pad(0, check_payload(payload)?)?)?;
        let reply = [&header[..], to_ephemeral.as_bytes(), &sealed].concat();
        Ok((
            Self {
                state,
                flavor: channel.flavor,
            },
            reply,
        ))
    }

    /// Reads message 3: only now is the initiator known to hold the channel key and its ephemeral.
    pub fn finish(self, message: &[u8]) -> Result<Established, LinkError> {
        let Self { mut state, flavor } = self;
        let sealed = check_header(message, flavor.message_1 + 2)?;
        state.mix_hash(&message[..HEADER_LEN]);
        let peer_payload: Zeroizing<Vec<u8>> = open_payload(&mut state, sealed)?;
        let (receive, send) = state.split()?;
        let session = Session::new(send, receive, state.handshake_hash());
        Ok(Established {
            session,
            peer_payload,
            next_link_key: None,
        })
    }
}

/// Transcript state both sides start from: protocol name, the channel id, then the channel's psk.
fn initial_state(channel: &ChannelKeys) -> Result<SymmetricState, LinkError> {
    let mut state = SymmetricState::new(channel.flavor.name);
    state.mix_hash(channel.id);
    state.mix_key(channel.psk.expose())?;
    Ok(state)
}
