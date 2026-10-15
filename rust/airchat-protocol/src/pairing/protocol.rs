//! The pairing state machine (docs/protocol.md §4.3–§4.6).
//!
//! ```text
//! -> 1:  0x00 0x21 || mode || [invite id | request token] || e_pk
//! <- 2:  0x00 0x22 || Encaps(e_pk) || AEAD(nearby: commitment to nonce_r | invite, request: "")
//! -> 3:  0x00 0x23 || AEAD(nonce_i)                     nearby only
//! <- 4:  0x00 0x24 || AEAD(nonce_r)                     nearby only, both now show the emoji
//! then contact cards as link records, in an order that never reveals a card to an unverified peer
//! ```
//!
//! The caller moves bytes between the two devices and acts on the returned [`Event`]s. It never
//! needs to inspect a message.

use super::{
    PairingError,
    card::{self, LocalProfile, PairedContact, VerifiedCard},
    invite::{INVITE_ID_LEN, Invite, InviteId, ScannedInvite},
    sas::Sas,
};
use crate::{
    crypto::{
        SecretBytes,
        aead::TAG_LEN as AEAD_TAG_LEN,
        hash::sha256,
        kdf,
        kem::{CIPHERTEXT_LEN, Ciphertext, DecapsulationKey, ENCAPSULATION_KEY_LEN, EncapsulationKey},
        random::{OsRng, Rng},
    },
    discovery::{REQUEST_TOKEN_LEN, RequestToken},
    identity::{AirChatId, PublicIdentity},
    labels,
    link::{Record, Session, WIRE_VERSION, symmetric::SymmetricState},
};

const MESSAGE_1: u8 = 0x21;
const MESSAGE_2: u8 = 0x22;
const MESSAGE_3: u8 = 0x23;
const MESSAGE_4: u8 = 0x24;
const MODE_NEARBY: u8 = 1;
const MODE_INVITE: u8 = 2;
const MODE_REQUEST: u8 = 3;
const NONCE_LEN: usize = 32;

/// How the two users authenticate each other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Both users compare five emoji on their screens.
    Nearby,
    /// One user scanned the other's QR code.
    Invite,
    /// One user typed the other's AirChat ID; the other approves the request (§4.8).
    Request,
}

#[derive(Debug)]
pub enum Event {
    /// Deliver these bytes to the other device.
    Send(Vec<u8>),
    /// Show these emoji and ask the user whether the other screen shows the same; then call
    /// [`Pairing::confirm`] or [`Pairing::reject`].
    ShowSas(Sas),
    /// Pairing succeeded. Store the contact; the connection can be closed.
    Paired(PairedContact),
    /// Request mode, on the device whose ID was typed: someone asks to be added. Ask the user,
    /// then call [`Pairing::approve`] or [`Pairing::reject`].
    Requested(Requester),
}

/// Who asks to be added, as its card says: the identity key is proven, the name is its own claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requester {
    pub identity: PublicIdentity,
    pub display_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    AwaitMessage2,
    AwaitMessage3,
    AwaitMessage4,
    Cards,
    Done,
    Failed,
}

/// One side of a pairing attempt.
pub struct Pairing {
    mode: Mode,
    is_initiator: bool,
    stage: Stage,
    state: SymmetricState,
    /// Initiator's ephemeral key, until message 2.
    ephemeral: Option<DecapsulationKey>,
    own_nonce: [u8; NONCE_LEN],
    peer_commitment: [u8; 32],
    /// Invite mode, initiator: the identity the QR code promised.
    expected_peer: Option<PublicIdentity>,
    /// Invite mode, responder: which invite was used, so it can be retired.
    invite_id: Option<InviteId>,
    /// Request mode, responder: the ID its user typed; the initiator must prove it owns it.
    request_id: Option<AirChatId>,
    channel: Option<Channel>,
    sas: Option<Sas>,
    /// The user accepted (nearby: matching emoji); invite mode needs no extra step.
    confirmed: bool,
    card_sent: bool,
    peer_card: Option<VerifiedCard>,
}

struct Channel {
    session: Session,
    link_psk: SecretBytes<32>,
}

impl Pairing {
    /// Starts Nearby Pairing with a device the user picked from the list of nearby devices.
    pub fn start_nearby() -> Result<(Self, Vec<u8>), PairingError> {
        Self::start_from(Mode::Nearby, None, None, &mut OsRng)
    }

    /// Starts pairing with the device whose QR code the user scanned.
    pub fn start_invite(invite: &ScannedInvite) -> Result<(Self, Vec<u8>), PairingError> {
        Self::start_from(Mode::Invite, Some(invite), None, &mut OsRng)
    }

    /// Answers a request to add the owner of `own_id`, this device's, announced with `token`
    /// (§4.8).
    pub fn start_request(own_id: &AirChatId, token: &RequestToken) -> Result<(Self, Vec<u8>), PairingError> {
        Self::start_from(Mode::Request, None, Some((own_id, token)), &mut OsRng)
    }

    pub(crate) fn start_from(
        mode: Mode,
        invite: Option<&ScannedInvite>,
        request: Option<(&AirChatId, &RequestToken)>,
        rng: &mut dyn Rng,
    ) -> Result<(Self, Vec<u8>), PairingError> {
        let mut prefix = vec![WIRE_VERSION, MESSAGE_1];
        let psk = match (mode, invite, request) {
            (Mode::Nearby, None, None) => {
                prefix.push(MODE_NEARBY);
                None
            }
            (Mode::Invite, Some(invite), None) => {
                prefix.push(MODE_INVITE);
                prefix.extend_from_slice(&invite.id());
                Some(invite.psk()?)
            }
            (Mode::Request, None, Some((id, token))) => {
                prefix.push(MODE_REQUEST);
                prefix.extend_from_slice(token);
                Some(request_psk(id)?)
            }
            _ => unreachable!("public constructors pair each mode with what it needs"),
        };
        let mut state = SymmetricState::new(labels::PAIRING_PROTOCOL);
        state.mix_hash(&prefix);
        let ephemeral = DecapsulationKey::generate_from(rng)?;
        state.mix_hash(ephemeral.encapsulation_key().as_bytes());
        if let Some(psk) = psk {
            state.mix_key(psk.expose())?;
        }
        let message = [&prefix[..], ephemeral.encapsulation_key().as_bytes()].concat();

        let mut pairing = Self::new(mode, true, Stage::AwaitMessage2, state);
        pairing.ephemeral = Some(ephemeral);
        pairing.expected_peer = invite.map(|i| *i.identity());
        Ok((pairing, message))
    }

    /// Answers message 1 from a device that wants to pair. In invite mode, `invites` are the QR
    /// codes this device currently shows; the message must name one of them. In request mode,
    /// `requests` are the tokens this device announces for the IDs its user typed (§4.8).
    pub fn accept(
        message: &[u8],
        profile: &LocalProfile,
        invites: &[&Invite],
        requests: &[(RequestToken, AirChatId)],
    ) -> Result<(Self, Vec<Event>), PairingError> {
        Self::accept_from(message, profile, invites, requests, &mut OsRng)
    }

    pub(crate) fn accept_from(
        message: &[u8],
        profile: &LocalProfile,
        invites: &[&Invite],
        requests: &[(RequestToken, AirChatId)],
        rng: &mut dyn Rng,
    ) -> Result<(Self, Vec<Event>), PairingError> {
        let body = check_header(message, MESSAGE_1)?;
        let (mode, invite, request, rest) = match body {
            [MODE_NEARBY, rest @ ..] => (Mode::Nearby, None, None, rest),
            [MODE_INVITE, rest @ ..] if rest.len() >= INVITE_ID_LEN => {
                let (id, rest) = rest.split_at(INVITE_ID_LEN);
                let invite = invites
                    .iter()
                    .copied()
                    .find(|i| i.id() == id)
                    .ok_or(PairingError::UnknownInvite)?;
                (Mode::Invite, Some(invite), None, rest)
            }
            [MODE_REQUEST, rest @ ..] if rest.len() >= REQUEST_TOKEN_LEN => {
                let (token, rest) = rest.split_at(REQUEST_TOKEN_LEN);
                let id = requests
                    .iter()
                    .find(|(t, _)| t == token)
                    .map(|(_, id)| *id)
                    .ok_or(PairingError::UnknownRequest)?;
                (Mode::Request, None, Some(id), rest)
            }
            _ => return Err(PairingError::Malformed),
        };
        if rest.len() != ENCAPSULATION_KEY_LEN {
            return Err(PairingError::Malformed);
        }
        let mut state = SymmetricState::new(labels::PAIRING_PROTOCOL);
        state.mix_hash(&message[..message.len() - ENCAPSULATION_KEY_LEN]);
        let ephemeral_key = EncapsulationKey::from_bytes(rest)?;
        state.mix_hash(ephemeral_key.as_bytes());
        if let Some(invite) = invite {
            state.mix_key(invite.psk()?.expose())?;
        }
        if let Some(id) = &request {
            state.mix_key(request_psk(id)?.expose())?;
        }

        let header = [WIRE_VERSION, MESSAGE_2];
        state.mix_hash(&header);
        let (shared, ciphertext) = ephemeral_key.encapsulate_from(rng)?;
        state.mix_hash(ciphertext.as_bytes());
        state.mix_key(shared.expose())?;

        let mut pairing = Self::new(mode, false, Stage::AwaitMessage3, state);
        pairing.invite_id = invite.map(Invite::id);
        pairing.request_id = request;
        let sealed = match mode {
            Mode::Nearby => {
                rng.fill(&mut pairing.own_nonce)?;
                pairing.state.encrypt_and_hash(&commitment(&pairing.own_nonce))?
            }
            Mode::Invite | Mode::Request => pairing.state.encrypt_and_hash(&[])?,
        };
        let mut events = vec![Event::Send([&header[..], ciphertext.as_bytes(), &sealed].concat())];
        match mode {
            Mode::Invite => {
                // Only someone who read our QR code can decrypt this, so we can introduce ourselves
                // first.
                pairing.open_channel()?;
                pairing.confirmed = true;
                events.extend(pairing.send_card(profile)?);
            }
            // Whoever knows the ID can get this far: the other proves it owns the ID first.
            Mode::Request => pairing.open_channel()?,
            Mode::Nearby => {}
        }
        Ok((pairing, events))
    }

    /// Handles the next message from the other device.
    pub fn receive(&mut self, message: &[u8], profile: &LocalProfile) -> Result<Vec<Event>, PairingError> {
        self.receive_from(message, profile, &mut OsRng)
    }

    pub(crate) fn receive_from(
        &mut self,
        message: &[u8],
        profile: &LocalProfile,
        rng: &mut dyn Rng,
    ) -> Result<Vec<Event>, PairingError> {
        let result = match (self.stage, self.is_initiator) {
            (Stage::AwaitMessage2, true) => self.read_message2(message, profile, rng),
            (Stage::AwaitMessage3, false) if self.mode == Mode::Nearby => self.read_message3(message),
            (Stage::AwaitMessage4, true) => self.read_message4(message),
            (Stage::Cards, false) if self.mode == Mode::Request && self.expected_peer.is_none() => {
                self.read_identity(message, profile)
            }
            (Stage::Cards, _) => self.read_card(message, profile),
            _ => Err(PairingError::UnexpectedMessage),
        };
        if result.is_err() {
            self.stage = Stage::Failed;
        }
        result
    }

    /// Nearby mode: the user says both screens show the same emoji.
    pub fn confirm(&mut self, profile: &LocalProfile) -> Result<Vec<Event>, PairingError> {
        if self.mode != Mode::Nearby || self.stage != Stage::Cards || self.confirmed {
            return Err(PairingError::UnexpectedMessage);
        }
        self.confirmed = true;
        let mut events = self.send_card(profile)?;
        events.extend(self.finish_if_ready());
        Ok(events)
    }

    /// Request mode, on the device whose ID was typed: its user agrees to add the requester.
    pub fn approve(&mut self, profile: &LocalProfile) -> Result<Vec<Event>, PairingError> {
        if self.mode != Mode::Request
            || !self.is_initiator
            || self.stage != Stage::Cards
            || self.peer_card.is_none()
            || self.confirmed
        {
            return Err(PairingError::UnexpectedMessage);
        }
        self.confirmed = true;
        let mut events = self.send_card(profile)?;
        events.extend(self.finish_if_ready());
        Ok(events)
    }

    /// Request mode, on the device whose ID was typed: who asks, while its user has not approved.
    pub fn requester(&self) -> Option<PublicIdentity> {
        let waiting = self.mode == Mode::Request && self.is_initiator && !self.confirmed;
        self.peer_card.as_ref().filter(|_| waiting).map(|card| card.identity)
    }

    /// The user cancelled or the emoji differ. Returns a message telling the other device, if a
    /// channel to it exists.
    pub fn reject(&mut self) -> Option<Vec<u8>> {
        self.stage = Stage::Failed;
        self.channel.as_mut().and_then(|c| c.session.seal_close().ok())
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// The emoji to compare, once both devices have computed them.
    pub fn sas(&self) -> Option<Sas> {
        self.sas
    }

    /// Invite mode, responder: the invite that was used. Retire it once [`Event::Paired`] arrives.
    pub fn invite_id(&self) -> Option<InviteId> {
        self.invite_id
    }

    fn new(mode: Mode, is_initiator: bool, stage: Stage, state: SymmetricState) -> Self {
        Self {
            mode,
            is_initiator,
            stage,
            state,
            ephemeral: None,
            own_nonce: [0; NONCE_LEN],
            peer_commitment: [0; 32],
            expected_peer: None,
            invite_id: None,
            request_id: None,
            channel: None,
            sas: None,
            confirmed: false,
            card_sent: false,
            peer_card: None,
        }
    }

    fn read_message2(
        &mut self,
        message: &[u8],
        profile: &LocalProfile,
        rng: &mut dyn Rng,
    ) -> Result<Vec<Event>, PairingError> {
        let body = check_header(message, MESSAGE_2)?;
        let sealed_len = match self.mode {
            Mode::Nearby => 32 + AEAD_TAG_LEN,
            Mode::Invite | Mode::Request => AEAD_TAG_LEN,
        };
        if body.len() != CIPHERTEXT_LEN + sealed_len {
            return Err(PairingError::Malformed);
        }
        let (ciphertext, sealed) = body.split_at(CIPHERTEXT_LEN);
        self.state.mix_hash(&message[..2]);
        self.state.mix_hash(ciphertext);
        let ephemeral = self.ephemeral.take().ok_or(PairingError::UnexpectedMessage)?;
        let shared = ephemeral.decapsulate(&Ciphertext::from_bytes(ciphertext)?)?;
        drop(ephemeral);
        self.state.mix_key(shared.expose())?;
        let payload = self.state.decrypt_and_hash(sealed)?;

        match self.mode {
            Mode::Nearby => {
                self.peer_commitment.copy_from_slice(&payload);
                rng.fill(&mut self.own_nonce)?;
                let header = [WIRE_VERSION, MESSAGE_3];
                self.state.mix_hash(&header);
                let sealed = self.state.encrypt_and_hash(&self.own_nonce)?;
                self.stage = Stage::AwaitMessage4;
                Ok(vec![Event::Send([&header[..], &sealed].concat())])
            }
            Mode::Invite => {
                // The responder speaks first: we reveal nothing until its card proves who it is.
                self.open_channel()?;
                self.confirmed = true;
                Ok(Vec::new())
            }
            Mode::Request => {
                // Prove we own the ID, and nothing more: our card waits for the user's approval.
                self.open_channel()?;
                let channel = self.channel.as_mut().expect("just opened");
                let identity = card::encode_identity(profile.identity, channel.session.handshake_hash());
                Ok(vec![Event::Send(channel.session.seal(&identity)?)])
            }
        }
    }

    /// Request mode, on the side that typed the ID: the other proves it owns it; only then does
    /// this side show its card.
    fn read_identity(&mut self, message: &[u8], profile: &LocalProfile) -> Result<Vec<Event>, PairingError> {
        let channel = self.channel.as_mut().expect("channel open in the cards stage");
        let handshake_hash = *channel.session.handshake_hash();
        let payload = match channel.session.open(message)? {
            Record::Data(payload) => payload,
            Record::Close => return Err(PairingError::Rejected),
        };
        let identity = card::decode_identity(&payload, &handshake_hash)?;
        if identity == profile.identity.public() {
            return Err(PairingError::SelfPairing);
        }
        if !self.request_id.is_some_and(|id| id.belongs_to(&identity)) {
            return Err(PairingError::AuthenticationFailed);
        }
        self.expected_peer = Some(identity);
        self.confirmed = true;
        self.send_card(profile)
    }

    fn read_message3(&mut self, message: &[u8]) -> Result<Vec<Event>, PairingError> {
        let sealed = check_header(message, MESSAGE_3)?;
        if sealed.len() != NONCE_LEN + AEAD_TAG_LEN {
            return Err(PairingError::Malformed);
        }
        self.state.mix_hash(&message[..2]);
        let initiator_nonce = self.state.decrypt_and_hash(sealed)?;

        let header = [WIRE_VERSION, MESSAGE_4];
        self.state.mix_hash(&header);
        let sealed = self.state.encrypt_and_hash(&self.own_nonce)?;
        let sas = Sas::derive(&self.state.handshake_hash(), &initiator_nonce, &self.own_nonce);
        self.sas = Some(sas);
        self.open_channel()?;
        Ok(vec![Event::Send([&header[..], &sealed].concat()), Event::ShowSas(sas)])
    }

    fn read_message4(&mut self, message: &[u8]) -> Result<Vec<Event>, PairingError> {
        let sealed = check_header(message, MESSAGE_4)?;
        if sealed.len() != NONCE_LEN + AEAD_TAG_LEN {
            return Err(PairingError::Malformed);
        }
        self.state.mix_hash(&message[..2]);
        let responder_nonce = self.state.decrypt_and_hash(sealed)?;
        if commitment(&responder_nonce) != self.peer_commitment {
            return Err(PairingError::AuthenticationFailed);
        }
        let sas = Sas::derive(&self.state.handshake_hash(), &self.own_nonce, &responder_nonce);
        self.sas = Some(sas);
        self.open_channel()?;
        Ok(vec![Event::ShowSas(sas)])
    }

    fn read_card(&mut self, message: &[u8], profile: &LocalProfile) -> Result<Vec<Event>, PairingError> {
        if self.peer_card.is_some() {
            return Err(PairingError::UnexpectedMessage);
        }
        let channel = self.channel.as_mut().expect("channel open in the cards stage");
        let handshake_hash = *channel.session.handshake_hash();
        let payload = match channel.session.open(message)? {
            Record::Data(payload) => payload,
            Record::Close => return Err(PairingError::Rejected),
        };
        let card = card::decode(&payload, &handshake_hash)?;
        if card.identity == profile.identity.public() {
            return Err(PairingError::SelfPairing);
        }
        if self.expected_peer.is_some_and(|expected| expected != card.identity) {
            return Err(PairingError::AuthenticationFailed);
        }
        let requester = (self.mode == Mode::Request && self.is_initiator).then(|| Requester {
            identity: card.identity,
            display_name: card.display_name.clone(),
        });
        self.peer_card = Some(card);

        let mut events: Vec<Event> = requester.into_iter().map(Event::Requested).collect();
        if self.confirmed && !self.card_sent {
            events.extend(self.send_card(profile)?);
        }
        events.extend(self.finish_if_ready());
        Ok(events)
    }

    /// Ends the key agreement: derives the channel for the cards and the contacts' link key.
    fn open_channel(&mut self) -> Result<(), PairingError> {
        let (initiator_to_responder, responder_to_initiator) = self.state.split()?;
        let (send, receive) = if self.is_initiator {
            (initiator_to_responder, responder_to_initiator)
        } else {
            (responder_to_initiator, initiator_to_responder)
        };
        let handshake_hash = self.state.handshake_hash();
        let link_psk = self.state.export(labels::PAIRING_LINK_PSK)?;
        self.channel = Some(Channel {
            session: Session::new(send, receive, handshake_hash),
            link_psk,
        });
        self.stage = Stage::Cards;
        Ok(())
    }

    fn send_card(&mut self, profile: &LocalProfile) -> Result<Vec<Event>, PairingError> {
        let channel = self.channel.as_mut().expect("channel open before cards are sent");
        let card = card::encode(profile, channel.session.handshake_hash())?;
        let record = channel.session.seal(&card)?;
        self.card_sent = true;
        Ok(vec![Event::Send(record)])
    }

    fn finish_if_ready(&mut self) -> Option<Event> {
        if !(self.confirmed && self.card_sent && self.stage == Stage::Cards) {
            return None;
        }
        let card = self.peer_card.take()?;
        let channel = self.channel.as_ref().expect("channel open in the cards stage");
        self.stage = Stage::Done;
        Some(Event::Paired(PairedContact {
            identity: card.identity,
            static_kem: card.static_kem,
            display_name: card.display_name,
            presence_key: card.presence_key,
            link_psk: channel.link_psk.clone(),
        }))
    }
}

/// The pre-shared key of a pairing that answers a request for `id` (§4.8).
fn request_psk(id: &AirChatId) -> Result<SecretBytes<32>, PairingError> {
    Ok(kdf::derive(&[], id.as_bytes(), labels::ID_REQUEST_PSK)?)
}

fn commitment(nonce: &[u8]) -> [u8; 32] {
    sha256(&[labels::PAIRING_COMMIT, nonce])
}

fn check_header(message: &[u8], expected: u8) -> Result<&[u8], PairingError> {
    match message {
        [version, ..] if *version != WIRE_VERSION => Err(PairingError::UnsupportedVersion),
        [_, kind, body @ ..] if *kind == expected => Ok(body),
        _ => Err(PairingError::Malformed),
    }
}
