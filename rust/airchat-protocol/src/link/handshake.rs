//! The contact link handshake (docs/protocol.md §6.3).
//!
//! ```text
//! pre-shared:  IK_i, SK_i, IK_r, SK_r (identity and static KEM keys), a link key (§6.8)
//! -> 1:  tag, e, Encaps(SK_r), AEAD()          responder recognises the initiator by `tag`
//! <- 2:  Encaps(e), Encaps(SK_i), AEAD(payload) initiator now knows it talks to the responder
//! -> 3:  AEAD(payload)                          responder now knows it talks to the initiator
//! ```
//!
//! Every message's AEAD key depends on all shared secrets so far, so:
//! - only the holder of `SK_r` can produce message 2 and only the holder of `SK_i` message 3
//!   (mutual authentication without signatures, so a transcript proves nothing to third parties);
//! - stealing either side's long-term keys does not let an attacker impersonate the *other* side;
//! - the session keys depend on `Encaps(e)`, whose private half is deleted after the handshake, so
//!   recorded sessions stay secret even if all long-term keys leak later (forward secrecy);
//! - all key exchange uses X-Wing, so this holds against quantum attackers too.

use zeroize::Zeroizing;

use super::{
    LinkError, WIRE_VERSION,
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
    identity::PublicIdentity,
    labels,
};

const MESSAGE_1: u8 = 1;
const MESSAGE_2: u8 = 2;
const MESSAGE_3: u8 = 3;
pub(super) const HEADER_LEN: usize = 2;

pub const MESSAGE_1_LEN: usize = HEADER_LEN + TAG_LEN + ENCAPSULATION_KEY_LEN + CIPHERTEXT_LEN + AEAD_TAG_LEN;
/// Largest payload messages 2 and 3 carry (capabilities, transport upgrade details).
pub const MAX_HANDSHAKE_PAYLOAD: usize = 4096;
/// The sealed, padded form of the largest payload; anything longer is rejected unread.
const MAX_SEALED_PAYLOAD: usize = (3 + MAX_HANDSHAKE_PAYLOAD).next_multiple_of(session::PAD_BLOCK) + AEAD_TAG_LEN;

/// Our own long-term link keys.
pub struct LocalKeys {
    pub identity: PublicIdentity,
    pub static_kem: DecapsulationKey,
}

/// What we know about a contact since pairing.
pub struct RemoteKeys {
    pub identity: PublicIdentity,
    pub static_kem: EncapsulationKey,
    /// The link key this handshake is made with: one of the contact's (§6.8), or a group link
    /// key (§9.4).
    pub link_psk: SecretBytes<32>,
}

/// A finished handshake.
pub struct Established {
    pub session: Session,
    /// What the peer put in its last handshake message.
    pub peer_payload: Zeroizing<Vec<u8>>,
    /// The link key that follows the one this handshake was made with (§6.8); contact links only.
    pub next_link_key: Option<SecretBytes<32>>,
}

/// The initiator between sending message 1 and receiving message 2.
pub struct Initiator {
    state: SymmetricState,
    ephemeral: DecapsulationKey,
}

impl Initiator {
    /// Starts a handshake with a contact and returns message 1. `tag` comes from the
    /// [`super::TagKey`] for links from us to that contact.
    pub fn start(local: &LocalKeys, remote: &RemoteKeys, tag: &Tag) -> Result<(Self, Vec<u8>), LinkError> {
        Self::start_from(local, remote, tag, &mut OsRng)
    }

    pub(crate) fn start_from(
        local: &LocalKeys,
        remote: &RemoteKeys,
        tag: &Tag,
        rng: &mut dyn Rng,
    ) -> Result<(Self, Vec<u8>), LinkError> {
        let mut state = initial_state(
            &local.identity,
            local.static_kem.encapsulation_key(),
            &remote.identity,
            &remote.static_kem,
            &remote.link_psk,
        )?;
        let header = [WIRE_VERSION, MESSAGE_1];
        state.mix_hash(&header);
        state.mix_hash(tag);

        let ephemeral = DecapsulationKey::generate_from(rng)?;
        state.mix_hash(ephemeral.encapsulation_key().as_bytes());

        let (shared, ciphertext) = remote.static_kem.encapsulate_from(rng)?;
        state.mix_hash(ciphertext.as_bytes());
        state.mix_key(shared.expose())?;
        let confirmation = state.encrypt_and_hash(&[])?;

        let message = [
            &header[..],
            tag,
            ephemeral.encapsulation_key().as_bytes(),
            ciphertext.as_bytes(),
            &confirmation,
        ]
        .concat();
        Ok((Self { state, ephemeral }, message))
    }

    /// Reads message 2 and returns the session together with message 3, which carries `payload`.
    pub fn finish(
        self,
        local: &LocalKeys,
        message: &[u8],
        payload: &[u8],
    ) -> Result<(Established, Vec<u8>), LinkError> {
        let Self { mut state, ephemeral } = self;
        let body = check_header(message, MESSAGE_2)?;
        if body.len() < 2 * CIPHERTEXT_LEN + AEAD_TAG_LEN {
            return Err(LinkError::Malformed);
        }
        let (to_ephemeral, rest) = body.split_at(CIPHERTEXT_LEN);
        let (to_static, sealed) = rest.split_at(CIPHERTEXT_LEN);

        state.mix_hash(&message[..HEADER_LEN]);
        let ephemeral_ciphertext = Ciphertext::from_bytes(to_ephemeral)?;
        state.mix_hash(to_ephemeral);
        state.mix_key(ephemeral.decapsulate(&ephemeral_ciphertext)?.expose())?;
        drop(ephemeral);

        let static_ciphertext = Ciphertext::from_bytes(to_static)?;
        state.mix_hash(to_static);
        state.mix_key(local.static_kem.decapsulate(&static_ciphertext)?.expose())?;
        let peer_payload = open_payload(&mut state, sealed)?;

        let header = [WIRE_VERSION, MESSAGE_3];
        state.mix_hash(&header);
        let sealed = state.encrypt_and_hash(&session::pad(0, check_payload(payload)?)?)?;
        let reply = [&header[..], &sealed].concat();

        let (send, receive) = state.split()?;
        let session = Session::new(send, receive, state.handshake_hash());
        let next_link_key = Some(state.export(labels::LINK_KEY_NEXT)?);
        Ok((
            Established {
                session,
                peer_payload,
                next_link_key,
            },
            reply,
        ))
    }
}

/// The responder between sending message 2 and receiving message 3.
pub struct Responder {
    state: SymmetricState,
}

impl Responder {
    /// The recognition tag of message 1, so the caller can find out which contact is calling
    /// (see [`super::TagChecker`]) before any public-key work is done.
    pub fn tag(message: &[u8]) -> Result<Tag, LinkError> {
        let body = check_header(message, MESSAGE_1)?;
        if message.len() != MESSAGE_1_LEN {
            return Err(LinkError::Malformed);
        }
        Ok(body[..TAG_LEN].try_into().expect("length checked"))
    }

    /// Reads message 1 from the contact `remote` and returns message 2, which carries `payload`.
    pub fn respond(
        local: &LocalKeys,
        remote: &RemoteKeys,
        message: &[u8],
        payload: &[u8],
    ) -> Result<(Self, Vec<u8>), LinkError> {
        Self::respond_from(local, remote, message, payload, &mut OsRng)
    }

    pub(crate) fn respond_from(
        local: &LocalKeys,
        remote: &RemoteKeys,
        message: &[u8],
        payload: &[u8],
        rng: &mut dyn Rng,
    ) -> Result<(Self, Vec<u8>), LinkError> {
        let tag = Self::tag(message)?;
        let body = &message[HEADER_LEN + TAG_LEN..];
        let (ephemeral_key, rest) = body.split_at(ENCAPSULATION_KEY_LEN);
        let (to_static, confirmation) = rest.split_at(CIPHERTEXT_LEN);

        let mut state = initial_state(
            &remote.identity,
            &remote.static_kem,
            &local.identity,
            local.static_kem.encapsulation_key(),
            &remote.link_psk,
        )?;
        state.mix_hash(&message[..HEADER_LEN]);
        state.mix_hash(&tag);
        let ephemeral_key = EncapsulationKey::from_bytes(ephemeral_key)?;
        state.mix_hash(ephemeral_key.as_bytes());
        state.mix_hash(to_static);
        state.mix_key(
            local
                .static_kem
                .decapsulate(&Ciphertext::from_bytes(to_static)?)?
                .expose(),
        )?;
        if !state.decrypt_and_hash(confirmation)?.is_empty() {
            return Err(LinkError::Malformed);
        }

        let header = [WIRE_VERSION, MESSAGE_2];
        state.mix_hash(&header);
        let (shared, to_ephemeral) = ephemeral_key.encapsulate_from(rng)?;
        state.mix_hash(to_ephemeral.as_bytes());
        state.mix_key(shared.expose())?;
        let (shared, to_initiator_static) = remote.static_kem.encapsulate_from(rng)?;
        state.mix_hash(to_initiator_static.as_bytes());
        state.mix_key(shared.expose())?;
        let sealed = state.encrypt_and_hash(&session::pad(0, check_payload(payload)?)?)?;

        let reply = [
            &header[..],
            to_ephemeral.as_bytes(),
            to_initiator_static.as_bytes(),
            &sealed,
        ]
        .concat();
        Ok((Self { state }, reply))
    }

    /// Reads message 3. Only now is the initiator authenticated.
    pub fn finish(self, message: &[u8]) -> Result<Established, LinkError> {
        let Self { mut state } = self;
        let sealed = check_header(message, MESSAGE_3)?;
        state.mix_hash(&message[..HEADER_LEN]);
        let peer_payload = open_payload(&mut state, sealed)?;
        let (receive, send) = state.split()?;
        let session = Session::new(send, receive, state.handshake_hash());
        let next_link_key = Some(state.export(labels::LINK_KEY_NEXT)?);
        Ok(Established {
            session,
            peer_payload,
            next_link_key,
        })
    }
}

/// Transcript state both sides start from: protocol name, both parties' long-term public keys
/// (initiator first), then the link key.
fn initial_state(
    initiator: &PublicIdentity,
    initiator_kem: &EncapsulationKey,
    responder: &PublicIdentity,
    responder_kem: &EncapsulationKey,
    psk: &SecretBytes<32>,
) -> Result<SymmetricState, LinkError> {
    let mut state = SymmetricState::new(labels::LINK_CONTACT);
    state.mix_hash(initiator.as_bytes());
    state.mix_hash(initiator_kem.as_bytes());
    state.mix_hash(responder.as_bytes());
    state.mix_hash(responder_kem.as_bytes());
    state.mix_key(psk.expose())?;
    Ok(state)
}

pub(super) fn check_header(message: &[u8], expected: u8) -> Result<&[u8], LinkError> {
    match message {
        [version, ..] if *version != WIRE_VERSION => Err(LinkError::UnsupportedVersion),
        [_, kind, body @ ..] if *kind == expected => Ok(body),
        _ => Err(LinkError::Malformed),
    }
}

pub(super) fn check_payload(payload: &[u8]) -> Result<&[u8], LinkError> {
    if payload.len() > MAX_HANDSHAKE_PAYLOAD {
        return Err(LinkError::PayloadTooLarge);
    }
    Ok(payload)
}

pub(super) fn open_payload(state: &mut SymmetricState, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, LinkError> {
    if sealed.len() > MAX_SEALED_PAYLOAD {
        return Err(LinkError::Malformed);
    }
    let plaintext = state.decrypt_and_hash(sealed)?;
    let (_, payload) = session::unpad(&plaintext)?;
    Ok(Zeroizing::new(payload.to_vec()))
}
