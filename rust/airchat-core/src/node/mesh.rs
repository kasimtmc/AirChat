//! The mesh in the node (rust/airchat-protocol/docs/protocol.md §10): links to other AirChat devices, envelopes held and
//! passed on, delivered when they are for this device, and this device's messages sent through the
//! mesh when no Wi-Fi link reaches the contact. Works while locked too: what it needs is in memory.

use std::collections::{HashMap, HashSet, VecDeque};

use zeroize::Zeroizing;

use super::{
    Action, ConnectionId, ConnectionState, Failure, Node, NodeError, Recognized, Store, channels, now_secs, paths,
    seal_chat,
};
use crate::{
    channel::{self, DEVICE_NONCE_LEN},
    chat::{self, ChatMessage},
    crypto::{SecretBytes, hash::sha256, random},
    discovery::{PresenceToken, presence_token},
    group::{self, GroupId},
    labels,
    link::{ChannelInitiator, ChannelKeys, ChannelResponder, Flavor, Session, epoch_at},
    mesh::{
        self, DropSecret, DropTag, Envelope, EnvelopeId, Header, MAX_HAVE, MAX_HOPS, MAX_LIFETIME_MINUTES, MeshTag,
        NO_DROP, Pair, STATIC_KEY, ShortId,
    },
    storage::{AttachmentState, ContactId, MessageId, MessageStatus},
};

/// Mesh peers' ids count down from here, far below channel members' (which count down from -1).
pub(super) const MESH_PEER_BASE: ContactId = -(1 << 62);
/// The "member" a group message from the mesh came from: no link's.
pub(super) const FROM_MESH: ContactId = 0;
/// How long, and how much, a device holds envelopes to pass on to neighbours that come later; Air
/// Providers too. Nobody keeps an envelope for a recipient out of reach: its sender does (§10.5).
const HOLD_SECS: u64 = 600;
const HOLD_BYTES: usize = 8 << 20;
/// What a withdraw counts against a neighbour's passing-on budget.
const WITHDRAW_COST: usize = 32;
/// What one neighbour may make this device pass on per minute: 64 KiB/s.
const PASS_ON_PER_MINUTE: usize = 64 * 1024 * 60;
/// Envelope ids remembered at most; beyond, the ones expiring first are forgotten.
const MAX_SEEN: usize = 1 << 16;
/// Mesh links at most; more are turned away.
const MAX_MESH_LINKS: usize = 16;
/// This device's group messages go into the mesh again, for neighbours that come later, while some
/// member has not acknowledged them and they are younger than this (§10.10).
const OWN_GROUP_RESEND_MS: i64 = 24 * 3600 * 1000;
/// Strangers' beacons remembered at most (they change every hour).
const MAX_TOKENS: usize = 1024;
/// Envelopes live up to a day, so their tags are recognised for the epochs of a day back, and one
/// more for clocks that differ (§10.3).
const TAG_EPOCHS_BACK: u64 = 25;

pub(super) fn is_mesh_peer(contact: ContactId) -> bool {
    contact <= MESH_PEER_BASE
}

/// Whom an envelope's tag names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Owner {
    Contact(ContactId),
    /// A part of a file from the contact (§10.8).
    ContactFile(ContactId),
    Group(GroupId),
    /// A part of the group's next update (§10.9).
    GroupUpdate(GroupId),
    /// A part of a group file (§10.10).
    GroupFile(GroupId),
}

/// An envelope id seen: another device's for as long as envelopes are held (so its sender's
/// resends go through later), this device's own and withdrawn ones until they expire.
struct Seen {
    /// Unix minutes.
    expires: u32,
    drop: DropTag,
    withdrawn: bool,
    /// When it came from a neighbour; `None` for this device's own.
    at_secs: Option<u64>,
}

/// A withdraw this device made, sent again to neighbours that come later until it expires.
struct OwnWithdraw {
    id: EnvelopeId,
    secret: DropSecret,
    expires: u32,
}

struct Held {
    /// With the hops it is passed on with.
    envelope: Envelope,
    at_secs: u64,
}

/// A link that carries mesh traffic.
#[derive(Default)]
struct Neighbour {
    /// Envelopes it has, by short id: it sent them, said so, or was sent them.
    has: HashSet<ShortId>,
    /// The minute its passing-on budget is counted for, and what was used of it.
    minute: u64,
    passed: usize,
}

impl Neighbour {
    /// Charges `bytes` it asks this device to pass on; false once over its budget for the minute.
    fn charge(&mut self, now_secs: u64, bytes: usize) -> bool {
        let minute = now_secs / 60;
        if minute != self.minute {
            self.minute = minute;
            self.passed = 0;
        }
        self.passed += bytes;
        self.passed <= PASS_ON_PER_MINUTE
    }
}

pub(crate) struct Mesh {
    /// This device's nonce on mesh links: tells two links to one device apart from two devices.
    device: [u8; DEVICE_NONCE_LEN],
    /// The id handed out for each stranger's beacon seen, so each beacon is one peer.
    by_token: HashMap<PresenceToken, ContactId>,
    /// Mesh peers linked now, by their device nonce.
    linked: HashMap<ContactId, [u8; DEVICE_NONCE_LEN]>,
    /// The beacon each id was handed out for, with its epoch: a stranger may become a contact.
    tokens: HashMap<ContactId, (PresenceToken, u64)>,
    next: ContactId,
    /// Envelopes held, oldest first.
    held: VecDeque<Held>,
    held_bytes: usize,
    /// Envelope ids seen.
    seen: HashMap<EnvelopeId, Seen>,
    own_withdraws: Vec<OwnWithdraw>,
    neighbours: HashMap<ConnectionId, Neighbour>,
    /// Tags this device recognises, for an epoch; rebuilt when it changes or keys change.
    tags: Option<(u64, HashMap<MeshTag, Owner>)>,
}

impl Mesh {
    pub(super) fn new() -> Result<Self, NodeError> {
        Ok(Self {
            device: channel::device_nonce()?,
            by_token: HashMap::new(),
            linked: HashMap::new(),
            tokens: HashMap::new(),
            next: MESH_PEER_BASE,
            held: VecDeque::new(),
            held_bytes: 0,
            seen: HashMap::new(),
            own_withdraws: Vec::new(),
            neighbours: HashMap::new(),
            tags: None,
        })
    }

    fn new_id(&mut self) -> ContactId {
        let id = self.next;
        self.next -= 1;
        id
    }

    /// Keys changed: tags are rebuilt when next needed.
    pub(super) fn keys_changed(&mut self) {
        self.tags = None;
    }

    fn remember(&mut self, id: EnvelopeId, expires: u32, drop: DropTag, now_minute: u32, at_secs: Option<u64>) {
        if self.seen.len() >= MAX_SEEN {
            self.seen.retain(|_, seen| seen.expires > now_minute);
            if self.seen.len() >= MAX_SEEN
                && let Some(first) = self.seen.iter().min_by_key(|(_, seen)| seen.expires).map(|(id, _)| *id)
            {
                self.seen.remove(&first);
            }
        }
        // Never forgets that an envelope was withdrawn.
        self.seen.entry(id).or_insert(Seen {
            expires,
            drop,
            withdrawn: false,
            at_secs,
        });
    }

    /// Holds an envelope to pass on later, within `limit` bytes, dropping the oldest first.
    fn hold(&mut self, envelope: Envelope, now_secs: u64, limit: usize) {
        self.held_bytes += envelope.body.len();
        self.held.push_back(Held {
            envelope,
            at_secs: now_secs,
        });
        self.trim(limit);
    }

    fn trim(&mut self, limit: usize) {
        while self.held_bytes > limit
            && let Some(dropped) = self.held.pop_front()
        {
            self.held_bytes -= dropped.envelope.body.len();
        }
    }

    /// Stops holding an envelope, and refuses it from now on.
    fn withdraw(&mut self, id: &EnvelopeId) {
        if let Some(seen) = self.seen.get_mut(id) {
            seen.withdrawn = true;
        }
        if let Some(at) = self.held.iter().position(|held| held.envelope.id == *id)
            && let Some(dropped) = self.held.remove(at)
        {
            self.held_bytes -= dropped.envelope.body.len();
        }
    }

    /// Sends `envelope` to every neighbour that does not have it, except `except`.
    fn flood(&mut self, envelope: &Envelope, except: Option<ConnectionId>) -> Vec<(ConnectionId, ChatMessage)> {
        let short = envelope.short_id();
        self.neighbours
            .iter_mut()
            .filter(|(connection, neighbour)| Some(**connection) != except && !neighbour.has.contains(&short))
            .map(|(connection, neighbour)| {
                neighbour.has.insert(short);
                (*connection, ChatMessage::MeshEnvelope(envelope.clone()))
            })
            .collect()
    }

    /// Whether envelope `id` was withdrawn.
    pub(super) fn withdrawn(&self, id: &EnvelopeId) -> bool {
        self.seen.get(id).is_some_and(|seen| seen.withdrawn)
    }

    /// Whether envelope `id` is held to pass on.
    pub(super) fn holds(&self, id: &EnvelopeId) -> bool {
        self.held.iter().any(|held| held.envelope.id == *id)
    }

    /// Envelope `id` if it is held.
    pub(super) fn held_envelope(&self, id: &EnvelopeId) -> Option<Envelope> {
        self.held
            .iter()
            .find(|held| held.envelope.id == *id)
            .map(|held| held.envelope.clone())
    }

    /// Mesh neighbours linked now.
    pub(super) fn neighbours(&self) -> usize {
        self.neighbours.len()
    }

    /// Withdraws for every neighbour except `except`.
    fn flood_withdraw(
        &self,
        id: EnvelopeId,
        secret: DropSecret,
        except: Option<ConnectionId>,
    ) -> Vec<(ConnectionId, ChatMessage)> {
        self.neighbours
            .keys()
            .filter(|c| Some(**c) != except)
            .map(|c| (*c, ChatMessage::MeshWithdraw { id, secret }))
            .collect()
    }

    /// The links of the mesh neighbours.
    pub(super) fn neighbour_links(&self) -> impl Iterator<Item = ConnectionId> + '_ {
        self.neighbours.keys().copied()
    }

    pub(super) fn is_neighbour(&self, connection: ConnectionId) -> bool {
        self.neighbours.contains_key(&connection)
    }

    #[cfg(test)]
    pub(super) fn held_count(&self) -> usize {
        self.held.len()
    }

    #[cfg(test)]
    pub(super) fn held_envelopes(&self) -> Vec<Envelope> {
        self.held.iter().map(|held| held.envelope.clone()).collect()
    }

    /// Lets go of everything held, as if it had been dropped for room.
    #[cfg(test)]
    pub(super) fn drop_held(&mut self) {
        self.held.clear();
        self.held_bytes = 0;
    }
}

/// The public keys of the mesh link handshake (§10.2).
pub(super) fn mesh_link_keys() -> ([u8; 16], SecretBytes<32>) {
    let id = sha256(&[labels::MESH_ID])[..16]
        .try_into()
        .expect("a hash is longer than an id");
    let psk = SecretBytes::from_slice(&sha256(&[labels::MESH_PSK])).expect("a hash is 32 bytes");
    (id, psk)
}

fn minute(now_secs: u64) -> u32 {
    u32::try_from(now_secs / 60).unwrap_or(u32::MAX)
}

impl Node {
    // Mesh links (§10.2).

    /// A presence beacon nobody here recognises: another AirChat device, to link with for the mesh
    /// when heard over Wi-Fi. Each beacon is one peer.
    pub fn recognize_stranger(&mut self, token: &PresenceToken, now_secs: u64) -> Option<Recognized> {
        let own = self.presence_token(now_secs);
        if *token == own || self.recognize_presence(token, now_secs).is_some() {
            return None;
        }
        let mesh = &mut self.mesh;
        let id = match mesh.by_token.get(token) {
            Some(&id) => id,
            None => {
                if mesh.by_token.len() >= MAX_TOKENS {
                    let linked = &mesh.linked;
                    mesh.by_token.retain(|_, id| linked.contains_key(id));
                    mesh.tokens.retain(|id, _| linked.contains_key(id));
                }
                let id = mesh.new_id();
                mesh.by_token.insert(*token, id);
                mesh.tokens.insert(id, (*token, epoch_at(now_secs)));
                id
            }
        };
        let handshaking = self.connections.values().any(|state| {
            matches!(state, ConnectionState::MeshInitiating { contact, .. } | ConnectionState::MeshResponding { contact, .. } if *contact == id)
        });
        let link = self.links.get(&id).copied();
        Some(Recognized {
            contact: id,
            opener: self.opens(id, own < *token, link.is_some() || handshaking, now_secs),
            link,
            handshaking,
        })
    }

    /// Opens a mesh link to a peer found with [`Node::recognize_stranger`].
    pub(super) fn connect_mesh_peer(
        &mut self,
        connection: ConnectionId,
        peer: ContactId,
        now_secs: u64,
    ) -> Result<Vec<Action>, NodeError> {
        let (id, psk) = mesh_link_keys();
        let keys = ChannelKeys {
            id: &id,
            psk: &psk,
            flavor: Flavor::MESH,
        };
        let (initiator, message) = ChannelInitiator::start(&keys, &random::array()?)?;
        let state = ConnectionState::MeshInitiating {
            contact: peer,
            initiator: Box::new(initiator),
        };
        let actions = self.open(connection, state, message)?;
        self.handshakes.insert(connection, now_secs);
        Ok(actions)
    }

    /// The first frame of a mesh link someone opened.
    pub(super) fn accept_mesh(
        &mut self,
        connection: ConnectionId,
        frame: &[u8],
        now_secs: u64,
    ) -> Result<Vec<Action>, Failure> {
        if self.mesh.linked.len() >= MAX_MESH_LINKS {
            return Err(Failure::NotAccepting);
        }
        let (id, psk) = mesh_link_keys();
        let keys = ChannelKeys {
            id: &id,
            psk: &psk,
            flavor: Flavor::MESH,
        };
        let (responder, message) =
            ChannelResponder::respond(&keys, frame, &self.mesh.device).map_err(|_| Failure::Protocol)?;
        let peer = self.mesh.new_id();
        self.connections.insert(
            connection,
            ConnectionState::MeshResponding {
                contact: peer,
                responder: Box::new(responder),
            },
        );
        self.handshakes.insert(connection, now_secs);
        Ok(vec![Action::Send {
            connection,
            bytes: message,
        }])
    }

    pub(super) fn mesh_initiated(
        &mut self,
        connection: ConnectionId,
        peer: ContactId,
        initiator: ChannelInitiator,
        frame: &[u8],
    ) -> Result<Vec<Action>, Failure> {
        let (established, reply) = initiator
            .finish(frame, &self.mesh.device)
            .map_err(|_| Failure::Protocol)?;
        let mut actions = vec![Action::Send {
            connection,
            bytes: reply,
        }];
        actions.extend(self.mesh_linked(connection, peer, established.session, &established.peer_payload));
        Ok(actions)
    }

    pub(super) fn mesh_responded(
        &mut self,
        connection: ConnectionId,
        peer: ContactId,
        responder: ChannelResponder,
        frame: &[u8],
    ) -> Result<Vec<Action>, Failure> {
        let established = responder.finish(frame).map_err(|_| Failure::Protocol)?;
        Ok(self.mesh_linked(connection, peer, established.session, &established.peer_payload))
    }

    /// A mesh link is up. Of two links to one device (both opened at once, or over two transports),
    /// both sides keep the one with the smaller handshake hash.
    fn mesh_linked(
        &mut self,
        connection: ConnectionId,
        peer: ContactId,
        session: Session,
        hello: &[u8],
    ) -> Vec<Action> {
        let Ok(nonce) = <[u8; DEVICE_NONCE_LEN]>::try_from(hello) else {
            return vec![Action::Close { connection }];
        };
        let mut actions = Vec::new();
        let twin = self
            .mesh
            .linked
            .iter()
            .find(|(id, n)| **id != peer && **n == nonce)
            .map(|(id, _)| *id);
        if let Some(twin) = twin {
            let twin_hash = self.links.get(&twin).and_then(|c| match self.connections.get(c) {
                Some(ConnectionState::Linked { session, .. }) => Some(*session.handshake_hash()),
                _ => None,
            });
            if twin_hash.is_some_and(|hash| &hash < session.handshake_hash()) {
                let mut session = session;
                if let Ok(bytes) = session.seal_close() {
                    actions.push(Action::Send { connection, bytes });
                }
                actions.push(Action::Close { connection });
                return self.closing_on(actions);
            }
            self.mesh.linked.remove(&twin);
            actions.extend(self.end_link(twin));
        }
        self.mesh.linked.insert(peer, nonce);
        actions.extend(self.linked(connection, peer, session));
        actions
    }

    /// Mesh peers and other mesh neighbours linked now.
    pub fn mesh_neighbours(&self) -> usize {
        self.mesh.neighbours()
    }

    // Neighbours (§10.4).

    /// A link that can carry mesh traffic is up: tell it what is held, and send it this device's
    /// own messages waiting for contacts no Wi-Fi link reaches, and what it carries as an Air
    /// Provider (§12.1). Links over paths carry none of it.
    pub(super) fn mesh_neighbour_up(&mut self, connection: ConnectionId, contact: ContactId) -> Vec<Action> {
        if channels::is_channel_peer(contact)
            || self.setup_only.contains(&connection)
            || paths::is_path_connection(connection)
        {
            return Vec::new();
        }
        self.mesh.neighbours.insert(connection, Neighbour::default());
        let have: Vec<ShortId> = self
            .mesh
            .held
            .iter()
            .rev()
            .take(MAX_HAVE)
            .map(|held| held.envelope.short_id())
            .collect();
        let mut sends = vec![(connection, ChatMessage::MeshHave(have))];
        sends.extend(self.path_offer().map(|offer| (connection, offer)));
        let now_minute = minute(now_secs());
        for envelope in self.own_waiting_envelopes(now_secs()) {
            if self.mesh.seen.get(&envelope.id).is_some_and(|seen| seen.withdrawn) {
                continue;
            }
            // Its own, whatever the mesh remembered before the app last started.
            self.mesh
                .remember(envelope.id, envelope.expires, envelope.drop, now_minute, None);
            if let Some(neighbour) = self.mesh.neighbours.get_mut(&connection)
                && neighbour.has.insert(envelope.short_id())
            {
                sends.push((connection, ChatMessage::MeshEnvelope(envelope)));
            }
        }
        sends.extend(self.release_parts(now_secs()));
        // What this device withdrew, for devices that took the envelopes along meanwhile.
        sends.extend(
            self.mesh
                .own_withdraws
                .iter()
                .filter(|w| w.expires > now_minute)
                .map(|w| {
                    (
                        connection,
                        ChatMessage::MeshWithdraw {
                            id: w.id,
                            secret: w.secret,
                        },
                    )
                }),
        );
        self.mesh_sends(sends, None)
    }

    /// Ends mesh links to strangers that have become contacts or fellow members since (paired, or
    /// added to a group): the link of their own replaces it. Only the side that opened a mesh link
    /// knows the beacon it opened it to; the other sees the link end.
    pub(super) fn end_mesh_links_to_contacts(&mut self) -> Vec<Action> {
        let known: Vec<ContactId> = self
            .mesh
            .linked
            .keys()
            .copied()
            .filter(|peer| {
                let Some((token, epoch)) = self.mesh.tokens.get(peer) else {
                    return false;
                };
                let epochs = epoch.saturating_sub(1)..=epoch.saturating_add(1);
                self.keys
                    .contacts
                    .values()
                    .any(|keys| epochs.clone().any(|e| presence_token(&keys.presence_key, e) == *token))
            })
            .collect();
        known
            .into_iter()
            .flat_map(|peer| {
                self.mesh.linked.remove(&peer);
                self.end_link(peer)
            })
            .collect()
    }

    /// A link ended: it is no neighbour any more; a mesh peer is gone.
    pub(super) fn mesh_link_ended(&mut self, connection: ConnectionId, contact: ContactId) {
        self.mesh.neighbours.remove(&connection);
        if is_mesh_peer(contact) && self.links.get(&contact).is_none_or(|c| *c == connection) {
            self.mesh.linked.remove(&contact);
        }
    }

    /// A record on a mesh peer's link: mesh traffic and liveness only.
    pub(super) fn on_mesh_peer_record(
        &mut self,
        connection: ConnectionId,
        session: &mut Session,
        record: ChatMessage,
    ) -> Result<Vec<Action>, ()> {
        match record {
            ChatMessage::Ping => {
                let bytes = seal_chat(session, &ChatMessage::Pong).map_err(|_| ())?;
                Ok(vec![Action::Send { connection, bytes }])
            }
            record @ (ChatMessage::MeshEnvelope(_) | ChatMessage::MeshHave(_) | ChatMessage::MeshWithdraw { .. }) => {
                Ok(self.on_mesh_record(connection, session, record))
            }
            record if record.is_path_record() => Ok(self.on_path_record(connection, session, record)),
            _ => Ok(Vec::new()),
        }
    }

    /// An envelope or a *have* from a neighbour.
    pub(super) fn on_mesh_record(
        &mut self,
        connection: ConnectionId,
        session: &mut Session,
        record: ChatMessage,
    ) -> Vec<Action> {
        let now = now_secs();
        let (actions, sends) = match record {
            ChatMessage::MeshHave(ids) => {
                let mut sends = Vec::new();
                if let Some(neighbour) = self.mesh.neighbours.get_mut(&connection) {
                    neighbour.has.extend(ids.iter().copied());
                    for held in self.mesh.held.iter().rev() {
                        if neighbour.has.insert(held.envelope.short_id()) {
                            sends.push((connection, ChatMessage::MeshEnvelope(held.envelope.clone())));
                        }
                    }
                }
                (Vec::new(), sends)
            }
            ChatMessage::MeshEnvelope(envelope) => self.take_envelope(Some(connection), envelope, now),
            ChatMessage::MeshWithdraw { id, secret } => (Vec::new(), self.take_withdraw(connection, id, secret, now)),
            _ => (Vec::new(), Vec::new()),
        };
        let mut actions = actions;
        actions.extend(self.mesh_sends(sends, Some((connection, session))));
        actions
    }

    /// An envelope from a neighbour (or none): delivered if it is for this device, passed on and
    /// held if it may go further. Returns actions, and records to send.
    pub(super) fn take_envelope(
        &mut self,
        from: Option<ConnectionId>,
        envelope: Envelope,
        now_secs: u64,
    ) -> (Vec<Action>, Vec<(ConnectionId, ChatMessage)>) {
        let now_minute = minute(now_secs);
        let expires = envelope.expires.min(now_minute.saturating_add(MAX_LIFETIME_MINUTES));
        if expires <= now_minute {
            return (Vec::new(), Vec::new());
        }
        let short = envelope.short_id();
        let size = envelope.body.len();
        let mut pass_on = false;
        if let Some(neighbour) = from.and_then(|c| self.mesh.neighbours.get_mut(&c)) {
            neighbour.has.insert(short);
            pass_on = neighbour.charge(now_secs, size);
        }
        if self.mesh.seen.contains_key(&envelope.id) {
            // A part this device still needs, though seen: it may have been lost before it could
            // be placed (§10.8).
            if self.expects_part(&envelope.id) {
                return self.take_file_part(&envelope, now_secs);
            }
            if self.expects_update_part(&envelope.id) {
                return (self.take_expected_update_part(&envelope), Vec::new());
            }
            return (Vec::new(), Vec::new());
        }
        self.mesh
            .remember(envelope.id, expires, envelope.drop, now_minute, Some(now_secs));
        let (actions, mut sends) = match self.mesh_owner(&envelope.tag, now_secs) {
            Some(owner) => self.deliver_envelope(owner, &envelope, now_secs),
            // An update part for a contact added to a group, who cannot recognise its tag (§10.9).
            None if self.expects_update_part(&envelope.id) => (self.take_expected_update_part(&envelope), Vec::new()),
            None => (Vec::new(), Vec::new()),
        };
        // Recipients pass it on too, so their neighbours cannot tell them from relays; unless
        // delivering it withdrew it (an answer to this device's message).
        let hops = envelope.hops.min(MAX_HOPS);
        let withdrawn = self.mesh.seen.get(&envelope.id).is_some_and(|seen| seen.withdrawn);
        if pass_on && hops > 0 && !withdrawn {
            let onward = Envelope {
                hops: hops - 1,
                ..envelope
            };
            sends.extend(self.mesh.flood(&onward, from));
            self.mesh.hold(onward, now_secs, HOLD_BYTES);
        }
        (actions, sends)
    }

    /// A withdraw from a neighbour: an envelope seen here with a matching drop goes, and the
    /// withdraw on to the other neighbours, once (§10.4).
    fn take_withdraw(
        &mut self,
        from: ConnectionId,
        id: EnvelopeId,
        secret: DropSecret,
        now_secs: u64,
    ) -> Vec<(ConnectionId, ChatMessage)> {
        let within = self
            .mesh
            .neighbours
            .get_mut(&from)
            .is_some_and(|neighbour| neighbour.charge(now_secs, WITHDRAW_COST));
        let Some(seen) = self.mesh.seen.get(&id) else {
            return Vec::new();
        };
        if !within || seen.withdrawn || seen.drop == NO_DROP || mesh::drop_tag(&secret) != seen.drop {
            return Vec::new();
        }
        self.mesh.withdraw(&id);
        self.mesh.flood_withdraw(id, secret, Some(from))
    }

    /// The contact answered message `id` (acknowledged or refused, `answer` being the answer's
    /// kind): withdraw its envelopes and the answer's from the mesh (§10.5); a file's are its
    /// offer's and its parts' (§10.8). The answer's only if seen here; the message's too if the
    /// answer came `through_mesh`, as the message most likely went the same way, perhaps before
    /// the app last started.
    pub(super) fn mesh_withdraw_answered(
        &mut self,
        contact: ContactId,
        id: &MessageId,
        answer: u8,
        through_mesh: bool,
    ) -> Vec<(ConnectionId, ChatMessage)> {
        let file = self.file_answered(contact, id);
        let Some(keys) = self.keys.contacts.get(&contact) else {
            return Vec::new();
        };
        let Some(psk) = &keys.pairing_psk else {
            return Vec::new();
        };
        let (me, them) = (&self.keys.identity, &keys.identity);
        let now_minute = minute(now_secs());
        let latest = now_minute.saturating_add(MAX_LIFETIME_MINUTES);
        let own = file.unwrap_or_else(|| vec![mesh::contact_envelope_id(me, them, chat::KIND_TEXT, id)]);
        let theirs = mesh::contact_envelope_id(them, me, answer, id);
        let mut withdraws = Vec::new();
        let envelopes = own.into_iter().map(|e| (e, me, them, true));
        for (envelope, from, to, own) in envelopes.chain([(theirs, them, me, false)]) {
            let expires = match self.mesh.seen.get(&envelope) {
                Some(seen) if seen.withdrawn || seen.drop == NO_DROP => continue,
                Some(seen) => seen.expires,
                None if own && through_mesh => latest,
                None => continue,
            };
            if let Ok(secret) = mesh::drop_secret(psk, from, to, &envelope) {
                withdraws.push((envelope, secret, expires));
            }
        }
        let mut sends = Vec::new();
        for (envelope, secret, expires) in withdraws {
            self.mesh
                .remember(envelope, expires, mesh::drop_tag(&secret), now_minute, None);
            self.mesh.withdraw(&envelope);
            sends.extend(self.mesh.flood_withdraw(envelope, secret, None));
            self.mesh.own_withdraws.push(OwnWithdraw {
                id: envelope,
                secret,
                expires,
            });
        }
        sends
    }

    /// Whom `tag` names, if this device is among them.
    fn mesh_owner(&mut self, tag: &MeshTag, now_secs: u64) -> Option<Owner> {
        let epoch = epoch_at(now_secs);
        if self.mesh.tags.as_ref().is_none_or(|(built, _)| *built != epoch) {
            let tags = self.build_mesh_tags(epoch);
            self.mesh.tags = Some((epoch, tags));
        }
        self.mesh.tags.as_ref()?.1.get(tag).copied()
    }

    fn build_mesh_tags(&self, epoch: u64) -> HashMap<MeshTag, Owner> {
        let mut tags = HashMap::new();
        let epochs = epoch.saturating_sub(TAG_EPOCHS_BACK)..=epoch.saturating_add(1);
        for (&contact, keys) in &self.keys.contacts {
            let Some(psk) = &keys.pairing_psk else {
                continue;
            };
            let them = &keys.identity;
            let (Ok(tag_key), Ok(file_tag_key)) = (
                mesh::contact_tag_key(psk, them, &self.keys.identity),
                mesh::file_tag_key(psk, them, &self.keys.identity),
            ) else {
                continue;
            };
            for e in epochs.clone() {
                tags.insert(mesh::tag(&tag_key, e), Owner::Contact(contact));
                tags.insert(mesh::tag(&file_tag_key, e), Owner::ContactFile(contact));
            }
        }
        for (group_id, group) in &self.keys.groups {
            for tag_key in &group.mesh_tag_keys {
                for e in epochs.clone() {
                    tags.insert(mesh::tag(tag_key, e), Owner::Group(*group_id));
                }
            }
            for tag_key in &group.file_tag_keys {
                for e in epochs.clone() {
                    tags.insert(mesh::tag(tag_key, e), Owner::GroupFile(*group_id));
                }
            }
            if let Some(next) = &group.next_update {
                for e in epochs.clone() {
                    tags.insert(mesh::tag(&next.tag_key, e), Owner::GroupUpdate(*group_id));
                }
            }
        }
        tags
    }

    /// An envelope for this device: a contact's record, or a group's message.
    fn deliver_envelope(
        &mut self,
        owner: Owner,
        envelope: &Envelope,
        now_secs: u64,
    ) -> (Vec<Action>, Vec<(ConnectionId, ChatMessage)>) {
        match owner {
            Owner::Contact(contact) => {
                let Some(keys) = self.keys.contacts.get(&contact) else {
                    return (Vec::new(), Vec::new());
                };
                let Some(psk) = &keys.pairing_psk else {
                    return (Vec::new(), Vec::new());
                };
                let pair = Pair {
                    from: &keys.identity,
                    to: &self.keys.identity,
                    psk,
                };
                let Ok(prekey) = mesh::sealed_to(envelope) else {
                    return (Vec::new(), Vec::new());
                };
                let opened = match prekey {
                    // Sealed to whichever of this device's static keys the contact knows: those
                    // since the one it took, newest first (§6.9).
                    STATIC_KEY => self
                        .keys
                        .locals
                        .iter()
                        .filter(|(version, _)| *version >= keys.own_key_taken)
                        .find_map(|(_, local)| mesh::open(&pair, &local.static_kem, envelope).ok()),
                    _ => match self.prekeys.own_key(contact, prekey) {
                        Some(key) => mesh::open(&pair, key, envelope).ok(),
                        // Used up: a resend of a text taken in before is answered again.
                        None => {
                            let Some(id) = self.received_in(contact, &envelope.id) else {
                                return (Vec::new(), Vec::new());
                            };
                            return (Vec::new(), self.answer(contact, ChatMessage::Ack { id }, now_secs));
                        }
                    },
                };
                let Some(payload) = opened else {
                    return (Vec::new(), Vec::new());
                };
                match ChatMessage::decode(&payload) {
                    Ok(Some(record)) => self.mesh_record_from(contact, record, prekey, now_secs),
                    _ => (Vec::new(), Vec::new()),
                }
            }
            // Held for the offer only from a contact whose files are taken.
            Owner::ContactFile(contact) if self.accepts_messages_from(contact) => {
                self.take_file_part(envelope, now_secs)
            }
            Owner::ContactFile(_) => (Vec::new(), Vec::new()),
            Owner::GroupUpdate(group_id) => (self.take_update_part(&group_id, envelope), Vec::new()),
            Owner::GroupFile(_) => self.take_file_part(envelope, now_secs),
            Owner::Group(_) => {
                let actions = if matches!(self.store, Store::Open(_)) {
                    self.take_group_message(FROM_MESH, &envelope.body).0
                } else {
                    self.inbox_group_message(FROM_MESH, envelope.body.clone())
                };
                (actions, Vec::new())
            }
        }
    }

    /// A contact's record that came through the mesh, sealed to `prekey`: as over a link, but
    /// answered over a Wi-Fi link to the contact if there is one, else through the mesh. A text's
    /// (or file offer's) prekey goes once it is taken care of.
    fn mesh_record_from(
        &mut self,
        contact: ContactId,
        record: ChatMessage,
        prekey: u32,
        now_secs: u64,
    ) -> (Vec<Action>, Vec<(ConnectionId, ChatMessage)>) {
        match record {
            ChatMessage::Text { id, .. } if !self.accepts_messages_from(contact) => {
                self.prekey_used(contact, prekey);
                (Vec::new(), self.answer(contact, ChatMessage::Refused { id }, now_secs))
            }
            ChatMessage::Text { id, sent_at_ms, text } => match self.take_text(contact, id, sent_at_ms, text) {
                Ok(arrived) => {
                    self.prekey_used(contact, prekey);
                    (
                        arrived.into_iter().collect(),
                        self.answer(contact, ChatMessage::Ack { id }, now_secs),
                    )
                }
                // Not stored: no acknowledgement, and the prekey stays for the sender's next try.
                Err(()) => (Vec::new(), Vec::new()),
            },
            ChatMessage::MeshFileOffer {
                id,
                sent_at_ms,
                key,
                meta,
            } => self.take_mesh_file_offer(contact, id, sent_at_ms, key, meta, prekey, now_secs),
            ChatMessage::MeshUpdateKey {
                group_id,
                epoch,
                update_id,
                count,
                key,
            } => (
                self.take_mesh_update_key(contact, group_id, epoch, update_id, count, &key),
                Vec::new(),
            ),
            ChatMessage::Ack { id } => (
                self.take_answer(contact, id, MessageStatus::Delivered),
                self.mesh_withdraw_answered(contact, &id, chat::KIND_ACK, true),
            ),
            ChatMessage::Refused { id } => (
                self.take_answer(contact, id, MessageStatus::Refused),
                self.mesh_withdraw_answered(contact, &id, chat::KIND_REFUSED, true),
            ),
            _ => (Vec::new(), Vec::new()),
        }
    }

    /// Sends an acknowledgement (or refusal) to a contact: over its Wi-Fi link, or through the mesh.
    pub(super) fn answer(
        &mut self,
        contact: ContactId,
        record: ChatMessage,
        now_secs: u64,
    ) -> Vec<(ConnectionId, ChatMessage)> {
        if let Some(connection) = self.data_link(contact) {
            return vec![(connection, record)];
        }
        let expires = minute(now_secs).saturating_add(MAX_LIFETIME_MINUTES);
        self.mesh_send_contact(contact, &record, expires, now_secs)
    }

    // Sending through the mesh (§10.5).

    /// A 1:1 record for a contact, sealed into an envelope (or `None` without the keys): a text or
    /// a file offer to one of the contact's prekeys if one is left (§10.7), an answer to its
    /// static key.
    pub(super) fn contact_envelope(
        &mut self,
        contact: ContactId,
        record: &ChatMessage,
        expires: u32,
        now_secs: u64,
    ) -> Option<Envelope> {
        let message_id = match record {
            ChatMessage::Text { id, .. }
            | ChatMessage::MeshFileOffer { id, .. }
            | ChatMessage::Ack { id }
            | ChatMessage::Refused { id } => *id,
            ChatMessage::MeshUpdateKey { update_id, .. } => *update_id,
            _ => return None,
        };
        let prekey = match record {
            ChatMessage::Text { .. } | ChatMessage::MeshFileOffer { .. } if self.is_contact(contact) => {
                self.prekey_for(contact, &message_id)
            }
            _ => None,
        };
        let keys = self.keys.contacts.get(&contact)?;
        let psk = keys.pairing_psk.as_ref()?;
        let payload = Zeroizing::new(record.encode().ok()?);
        let me = &self.keys.identity;
        let id = mesh::contact_envelope_id(me, &keys.identity, payload[0], &message_id);
        let tag_key = mesh::contact_tag_key(psk, me, &keys.identity).ok()?;
        let header = Header {
            id,
            expires,
            tag: mesh::tag(&tag_key, epoch_at(now_secs)),
            drop: mesh::drop_tag(&mesh::drop_secret(psk, me, &keys.identity, &id).ok()?),
        };
        let pair = Pair {
            from: me,
            to: &keys.identity,
            psk,
        };
        let (number, to) = match &prekey {
            Some((number, key)) => (*number, key),
            None => (STATIC_KEY, keys.static_kems.first()?),
        };
        let body = mesh::seal(&pair, to, number, &header, &payload).ok()?;
        Some(Envelope {
            id,
            hops: MAX_HOPS,
            expires,
            tag: header.tag,
            drop: header.drop,
            body,
        })
    }

    /// Sends a 1:1 record to every mesh neighbour, and holds it for those that come later.
    pub(super) fn mesh_send_contact(
        &mut self,
        contact: ContactId,
        record: &ChatMessage,
        expires: u32,
        now_secs: u64,
    ) -> Vec<(ConnectionId, ChatMessage)> {
        if self.mesh.neighbours.is_empty() {
            return Vec::new();
        }
        let Some(envelope) = self.contact_envelope(contact, record, expires, now_secs) else {
            return Vec::new();
        };
        self.mesh_send_envelope(envelope, now_secs)
    }

    /// Sends one of this device's envelopes to every mesh neighbour that does not have it, and
    /// holds it for those that come later; not once withdrawn.
    pub(super) fn mesh_send_envelope(&mut self, envelope: Envelope, now_secs: u64) -> Vec<(ConnectionId, ChatMessage)> {
        if self.mesh.withdrawn(&envelope.id) {
            return Vec::new();
        }
        self.mesh
            .remember(envelope.id, envelope.expires, envelope.drop, minute(now_secs), None);
        let sends = self.mesh.flood(&envelope, None);
        if !self.mesh.holds(&envelope.id) {
            self.mesh.hold(envelope, now_secs, HOLD_BYTES);
        }
        sends
    }

    /// This device's messages to contacts no Wi-Fi link reaches, still unacknowledged and
    /// unexpired, as envelopes: for a neighbour that just came. Files' parts are queued (§10.8).
    fn own_waiting_envelopes(&mut self, now_secs: u64) -> Vec<Envelope> {
        let now_minute = minute(now_secs);
        let mut records = Vec::new();
        let mut files = Vec::new();
        for (&contact, keys) in &self.keys.contacts {
            if keys.group_only || self.data_link(contact).is_some() {
                continue;
            }
            let waiting: Vec<(ChatMessage, u32)> = match &self.store {
                Store::Open(account) => {
                    let (texts, offers): (Vec<_>, Vec<_>) = account
                        .undelivered(contact)
                        .unwrap_or_default()
                        .into_iter()
                        .partition(|m| m.attachment.is_none());
                    files.extend(
                        offers
                            .into_iter()
                            .filter(|m| {
                                let complete = m
                                    .attachment
                                    .as_ref()
                                    .is_some_and(|a| a.state == AttachmentState::Complete);
                                complete && super::try_expires(m) > now_minute
                            })
                            .map(|m| (contact, m)),
                    );
                    texts
                        .iter()
                        .map(|m| (super::outgoing_record(m), sent_minute(m.tried_at_ms)))
                        .collect()
                }
                Store::Sealed(sealed) => sealed
                    .pending
                    .iter()
                    .filter(|p| p.contact == contact)
                    .map(|p| {
                        let record = super::text_message(p.id, p.sent_at_ms, &p.text);
                        (record, sent_minute(p.sent_at_ms))
                    })
                    .collect(),
            };
            for (record, written) in waiting {
                let expires = written.saturating_add(MAX_LIFETIME_MINUTES);
                if expires > now_minute {
                    records.push((contact, record, expires));
                }
            }
        }
        let mut envelopes: Vec<Envelope> = records
            .into_iter()
            .filter_map(|(contact, record, expires)| self.contact_envelope(contact, &record, expires, now_secs))
            .collect();
        envelopes.extend(
            files
                .into_iter()
                .filter_map(|(contact, message)| self.mesh_file_envelope(contact, &message, now_secs)),
        );
        envelopes.extend(self.own_waiting_updates(now_secs));
        envelopes.extend(self.own_waiting_group_envelopes(now_secs));
        envelopes
    }

    /// This device's group messages younger than a day that some member has not acknowledged, as
    /// envelopes; the parts of their files are queued (§10.10).
    fn own_waiting_group_envelopes(&mut self, now_secs: u64) -> Vec<Envelope> {
        let Store::Open(account) = &self.store else {
            return Vec::new();
        };
        let db = account.db();
        let mut envelopes = Vec::new();
        let mut rows = Vec::new();
        for row in db
            .own_unacknowledged_group_messages(super::now_ms() - OWN_GROUP_RESEND_MS)
            .unwrap_or_default()
        {
            let (Ok(Some(sealed)), Ok(Some(stored_message))) = (db.group_message_sealed(row), db.group_message(row))
            else {
                continue;
            };
            let Ok(message) = group::Message::read(&sealed) else {
                continue;
            };
            let Some(group) = db.group_by_id(&message.group_id).ok().flatten() else {
                continue;
            };
            let Some((key, _)) = group.epoch(message.epoch) else {
                continue;
            };
            let Ok(tag_key) = mesh::group_tag_key(key, &message.group_id, message.epoch) else {
                continue;
            };
            envelopes.extend(group_envelope(
                &message.group_id,
                &message.message_id,
                &sealed,
                &tag_key,
                stored_message.tried_at_ms,
                now_secs,
            ));
            rows.push(row);
        }
        for row in rows {
            self.queue_group_file_parts(row, now_secs);
        }
        envelopes
    }

    /// An update was taken in: envelopes held to pass on whose tags (a group's) this device may
    /// only now recognise are delivered (§10.9). Group messages are stored once, updates taken
    /// once, so those delivered before change nothing.
    pub(super) fn mesh_recheck_held(&mut self, now_secs: u64) -> Vec<Action> {
        // Tags for the keys now held.
        let _ = self.mesh_owner(&[0; 16], now_secs);
        let Some((_, tags)) = &self.mesh.tags else {
            return Vec::new();
        };
        let due: Vec<(Owner, Envelope)> = self
            .mesh
            .held
            .iter()
            .filter_map(|held| match tags.get(&held.envelope.tag) {
                Some(owner @ (Owner::Group(_) | Owner::GroupUpdate(_) | Owner::GroupFile(_))) => {
                    Some((*owner, held.envelope.clone()))
                }
                _ => None,
            })
            .collect();
        let mut actions = Vec::new();
        for (owner, envelope) in due {
            let (taken, sends) = self.deliver_envelope(owner, &envelope, now_secs);
            actions.extend(taken);
            actions.extend(self.mesh_sends(sends, None));
        }
        actions
    }

    /// Sends a group message this device stored to every mesh neighbour.
    pub(super) fn mesh_send_group(
        &mut self,
        group_id: &GroupId,
        message_id: &[u8; 16],
        sealed: &[u8],
        tag_key: &SecretBytes<32>,
        tried_at_ms: i64,
    ) -> Vec<Action> {
        let now = now_secs();
        let id = mesh::group_envelope_id(group_id, message_id);
        if self.mesh.neighbours.is_empty() || self.mesh.seen.contains_key(&id) {
            return Vec::new();
        }
        let Some(envelope) = group_envelope(group_id, message_id, sealed, tag_key, tried_at_ms, now) else {
            return Vec::new();
        };
        let expires = envelope.expires;
        self.mesh.remember(id, expires, NO_DROP, minute(now), None);
        let sends = self.mesh.flood(&envelope, None);
        self.mesh.hold(envelope, now, HOLD_BYTES);
        self.mesh_sends(sends, None)
    }

    /// Seals records for links: the one whose record is being handled through its `session`, the
    /// others through the table.
    pub(super) fn mesh_sends(
        &mut self,
        sends: Vec<(ConnectionId, ChatMessage)>,
        mut current: Option<(ConnectionId, &mut Session)>,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        for (connection, record) in sends {
            match current.as_mut() {
                Some((handled, session)) if *handled == connection => {
                    if let Ok(bytes) = seal_chat(session, &record) {
                        actions.push(Action::Send { connection, bytes });
                    }
                }
                _ => actions.extend(self.seal_on(connection, vec![record], false)),
            }
        }
        actions
    }

    /// Forgets envelopes held too long and ids expired.
    pub(super) fn mesh_tick(&mut self, now_secs: u64) {
        let now_minute = minute(now_secs);
        let mesh = &mut self.mesh;
        let before = mesh.held.len();
        mesh.held
            .retain(|held| held.envelope.expires > now_minute && now_secs.saturating_sub(held.at_secs) < HOLD_SECS);
        if mesh.held.len() != before {
            mesh.held_bytes = mesh.held.iter().map(|held| held.envelope.body.len()).sum();
        }
        mesh.trim(HOLD_BYTES);
        mesh.seen.retain(|_, seen| {
            seen.expires > now_minute
                && (seen.withdrawn || seen.at_secs.is_none_or(|at| now_secs.saturating_sub(at) < HOLD_SECS))
        });
        mesh.own_withdraws.retain(|w| w.expires > now_minute);
    }
}

/// A group message's envelope (§10.3); `None` if too large.
fn group_envelope(
    group_id: &GroupId,
    message_id: &[u8; 16],
    sealed: &[u8],
    tag_key: &SecretBytes<32>,
    since_ms: i64,
    now_secs: u64,
) -> Option<Envelope> {
    if sealed.len() > mesh::MAX_BODY {
        return None;
    }
    // A day after it was stored, or after its sender tried it again.
    let expires = minute(u64::try_from(since_ms / 1000).unwrap_or(0)).saturating_add(MAX_LIFETIME_MINUTES);
    Some(Envelope {
        id: mesh::group_envelope_id(group_id, message_id),
        hops: MAX_HOPS,
        expires,
        tag: mesh::tag(tag_key, epoch_at(now_secs)),
        drop: NO_DROP,
        body: sealed.to_vec(),
    })
}

fn sent_minute(sent_at_ms: i64) -> u32 {
    u32::try_from(sent_at_ms / 60_000).unwrap_or(0)
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::{account::Account, node::groups::tests::Net};

    const AYSE: usize = 0;
    const BURAK: usize = 1;
    const CEM: usize = 2;

    /// Opens a mesh link between two devices that do not know each other, from the side that opens.
    pub(in crate::node) fn mesh_link(net: &mut Net, a: usize, b: usize) {
        let now = net.now;
        let (token_a, token_b) = (net.node(a).presence_token(now), net.node(b).presence_token(now));
        let seen = net.node(a).recognize_stranger(&token_b, now).expect("a stranger");
        let (opener, other, token) = if seen.opener { (a, b, token_b) } else { (b, a, token_a) };
        let peer = net.node(opener).recognize_stranger(&token, now).unwrap();
        assert!(peer.initiate());
        let (id, _) = net.wire(opener, other);
        let first = net.node(opener).connect_contact(id, peer.contact, now).unwrap();
        net.run(opener, first);
        assert!(net.node(opener).links.contains_key(&peer.contact), "linked");
        assert_eq!(net.node(other).mesh.linked.len(), net.node(other).mesh.neighbours.len());
    }

    /// The mesh link between two devices drops.
    pub(in crate::node) fn cut_mesh(net: &mut Net, a: usize, b: usize) {
        let wires: Vec<_> = net
            .wires
            .iter()
            .filter(|((x, _), (y, _))| (*x, *y) == (a, b) || (*x, *y) == (b, a))
            .copied()
            .collect();
        for (one, other) in wires {
            for (at, connection) in [one, other] {
                if net.node(at).mesh.is_neighbour(connection) {
                    let actions = net.node(at).connection_closed(connection);
                    net.run(at, actions);
                }
            }
        }
    }

    pub(in crate::node) fn statuses(net: &Net, at: usize, of: usize) -> Vec<(String, MessageStatus)> {
        let contact = net.contact(at, of);
        net.devices[at]
            .node
            .messages(contact)
            .unwrap()
            .into_iter()
            .map(|m| (m.body, m.status))
            .collect()
    }

    /// Ayşe and Cem are contacts out of each other's reach; Burak, who knows neither, is between.
    fn bridge() -> Net {
        let mut net = Net::new(&["Ayşe", "Burak", "Cem"]);
        net.pair(AYSE, CEM);
        net
    }

    #[test]
    fn a_message_crosses_the_mesh_through_a_stranger_and_its_acknowledgement_comes_back() {
        let mut net = bridge();
        let now = net.now;
        let cem_token = net.node(CEM).presence_token(now);
        assert!(
            net.node(AYSE).recognize_stranger(&cem_token, now).is_none(),
            "contacts are no strangers"
        );
        mesh_link(&mut net, AYSE, BURAK);
        mesh_link(&mut net, BURAK, CEM);
        let cem = net.contact(AYSE, CEM);
        let (message, actions) = net.node(AYSE).send_message(cem, "köprüden selam").unwrap();
        assert_eq!(message.status, MessageStatus::Sent, "handed to the mesh");
        net.run(AYSE, actions);
        assert_eq!(
            statuses(&net, CEM, AYSE),
            [("köprüden selam".into(), MessageStatus::Received)]
        );
        assert_eq!(
            statuses(&net, AYSE, CEM),
            [("köprüden selam".into(), MessageStatus::Delivered)]
        );
        assert!(net.node(BURAK).keys.contacts.is_empty(), "the relay learned no one");
        assert!(
            net.node(BURAK).mesh.held.is_empty(),
            "Ayşe withdrew the message and the acknowledgement"
        );
    }

    #[test]
    fn a_message_written_with_nobody_around_goes_when_the_mesh_comes() {
        let mut net = bridge();
        let cem = net.contact(AYSE, CEM);
        let (message, actions) = net.node(AYSE).send_message(cem, "sonra").unwrap();
        assert_eq!(message.status, MessageStatus::Queued);
        assert!(actions.is_empty());
        mesh_link(&mut net, AYSE, BURAK);
        assert_eq!(net.node(BURAK).mesh.held.len(), 1, "Burak took it along");
        mesh_link(&mut net, BURAK, CEM);
        assert_eq!(statuses(&net, CEM, AYSE), [("sonra".into(), MessageStatus::Received)]);
        assert_eq!(statuses(&net, AYSE, CEM)[0].1, MessageStatus::Delivered);
    }

    #[test]
    fn a_locked_recipient_keeps_mesh_messages_in_its_inbox() {
        let mut net = bridge();
        mesh_link(&mut net, AYSE, BURAK);
        mesh_link(&mut net, BURAK, CEM);
        let cem = net.contact(AYSE, CEM);
        net.node(CEM).seal();
        let (_, actions) = net.node(AYSE).send_message(cem, "kilitliyken").unwrap();
        net.run(AYSE, actions);
        assert!(
            net.devices[CEM]
                .shown
                .iter()
                .any(|a| matches!(a, Action::MessageArrived { .. }))
        );
        let status = net.node(AYSE).messages(cem).unwrap()[0].status;
        assert_eq!(status, MessageStatus::Delivered, "stored durably, so acknowledged");
        let device = &mut net.devices[CEM];
        let account = Account::unlock_with_pin(device.dir.path(), &device.pin_record, b"123456").unwrap();
        device.node.unseal(account).unwrap();
        assert_eq!(
            statuses(&net, CEM, AYSE),
            [("kilitliyken".into(), MessageStatus::Received)]
        );
    }

    #[test]
    fn envelopes_are_passed_on_once_and_not_beyond_their_hops() {
        let mut net = bridge();
        mesh_link(&mut net, AYSE, BURAK);
        mesh_link(&mut net, BURAK, CEM);
        let now = now_secs();
        let envelope = |hops| Envelope {
            id: [hops; 16],
            hops,
            expires: minute(now) + 10,
            tag: [7; 16],
            drop: NO_DROP,
            body: vec![1; 300],
        };
        let (_, sends) = net.node(BURAK).take_envelope(None, envelope(0), now);
        assert!(sends.is_empty(), "no hops left");
        let (_, sends) = net.node(BURAK).take_envelope(None, envelope(3), now);
        assert_eq!(sends.len(), 0, "from no neighbour: not passed on");
        let from = *net.node(BURAK).mesh.neighbours.keys().next().unwrap();
        let (_, sends) = net.node(BURAK).take_envelope(Some(from), envelope(5), now);
        assert_eq!(sends.len(), 1, "to the other neighbour only");
        assert!(matches!(&sends[0].1, ChatMessage::MeshEnvelope(e) if e.hops == 4));
        let (_, again) = net.node(BURAK).take_envelope(Some(from), envelope(5), now);
        assert!(again.is_empty(), "seen before");
        let expired = Envelope {
            id: [9; 16],
            expires: minute(now),
            ..envelope(5)
        };
        assert!(net.node(BURAK).take_envelope(Some(from), expired, now).1.is_empty());
    }

    #[test]
    fn an_air_provider_keeps_nothing_and_the_sender_sends_again_when_it_reaches_the_mesh() {
        use crate::path::Classes;
        let mut net = bridge();
        let actions = net.node(BURAK).set_air_provider(Classes::from_bits(0x07));
        net.run(BURAK, actions);
        mesh_link(&mut net, AYSE, BURAK);
        let cem = net.contact(AYSE, CEM);
        let (_, actions) = net.node(AYSE).send_message(cem, "sonra gelirsen").unwrap();
        net.run(AYSE, actions);
        cut_mesh(&mut net, AYSE, BURAK);
        // Minutes later Burak, an Air Provider, has let it go like any device, and forgotten it.
        net.node(BURAK).mesh_tick(now_secs() + HOLD_SECS);
        assert!(net.node(BURAK).mesh.held.is_empty());
        mesh_link(&mut net, BURAK, CEM);
        assert!(statuses(&net, CEM, AYSE).is_empty(), "nothing waited for Cem");
        // Ayşe still holds it, sending; it goes when she reaches the mesh again.
        assert_eq!(statuses(&net, AYSE, CEM)[0].1, MessageStatus::Sent);
        mesh_link(&mut net, AYSE, BURAK);
        assert_eq!(
            statuses(&net, CEM, AYSE),
            [("sonra gelirsen".into(), MessageStatus::Received)]
        );
        assert_eq!(statuses(&net, AYSE, CEM)[0].1, MessageStatus::Delivered);
    }

    #[test]
    fn a_message_not_delivered_in_a_day_is_given_up_until_tried_again() {
        let mut net = bridge();
        let cem = net.contact(AYSE, CEM);
        let (message, actions) = net.node(AYSE).send_message(cem, "kimse yok").unwrap();
        net.run(AYSE, actions);
        assert_eq!(statuses(&net, AYSE, CEM)[0].1, MessageStatus::Queued);
        // A day without reaching Cem: given up, and sent no more.
        let actions = net.node(AYSE).tick(now_secs() + 24 * 3600 + 60);
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::MessageUpdated { message } if message.status == MessageStatus::Failed))
        );
        net.run(AYSE, actions);
        assert_eq!(statuses(&net, AYSE, CEM)[0].1, MessageStatus::Failed);
        mesh_link(&mut net, AYSE, BURAK);
        assert!(net.node(BURAK).mesh.held.is_empty(), "not into the mesh");
        net.link(AYSE, CEM);
        assert!(statuses(&net, CEM, AYSE).is_empty(), "nor over a link");
        // Tried again, it goes at once.
        let actions = net.node(AYSE).try_message_again(message.id).unwrap();
        net.run(AYSE, actions);
        assert_eq!(
            statuses(&net, CEM, AYSE),
            [("kimse yok".into(), MessageStatus::Received)]
        );
        assert_eq!(statuses(&net, AYSE, CEM)[0].1, MessageStatus::Delivered);
        assert!(matches!(
            net.node(AYSE).try_message_again(message.id),
            Err(NodeError::NoSuchMessage)
        ));
    }

    #[test]
    fn an_envelope_written_hours_ago_is_still_recognised_by_its_recipient() {
        let mut net = bridge();
        mesh_link(&mut net, AYSE, BURAK);
        let cem = net.contact(AYSE, CEM);
        let (_, actions) = net.node(AYSE).send_message(cem, "dünden").unwrap();
        net.run(AYSE, actions);
        let envelope = net.node(BURAK).mesh.held_envelopes().remove(0);
        // A mailbox hands it over nearly a day later: its tag is of an hour long gone.
        let later = now_secs() + 23 * 3600;
        let (actions, _) = net.node(CEM).take_envelope(None, envelope, later);
        assert!(actions.iter().any(|a| matches!(a, Action::MessageReceived { .. })));
        assert_eq!(statuses(&net, CEM, AYSE), [("dünden".into(), MessageStatus::Received)]);
    }

    #[test]
    fn strangers_who_pair_keep_one_link() {
        let mut net = Net::new(&["Ayşe", "Burak"]);
        mesh_link(&mut net, AYSE, BURAK);
        assert_eq!(
            (net.node(AYSE).mesh_neighbours(), net.node(BURAK).mesh_neighbours()),
            (1, 1)
        );
        // They meet and add each other: the link between strangers goes, the contacts' link stays.
        net.pair(AYSE, BURAK);
        assert_eq!(
            (net.node(AYSE).mesh_neighbours(), net.node(BURAK).mesh_neighbours()),
            (0, 0)
        );
        net.link(AYSE, BURAK);
        assert_eq!(
            (net.node(AYSE).mesh_neighbours(), net.node(BURAK).mesh_neighbours()),
            (1, 1)
        );
        assert!(net.node(AYSE).links.keys().all(|c| !is_mesh_peer(*c)));
        assert!(net.node(BURAK).links.keys().all(|c| !is_mesh_peer(*c)));
    }

    #[test]
    fn strangers_who_become_fellow_members_drop_their_mesh_link() {
        // Burak and Cem, strangers, have a mesh link; Ayşe, their common contact, puts them in a group.
        let mut net = Net::new(&["Ayşe", "Burak", "Cem"]);
        net.pair(AYSE, BURAK);
        net.pair(AYSE, CEM);
        mesh_link(&mut net, BURAK, CEM);
        let members = [net.contact(AYSE, BURAK), net.contact(AYSE, CEM)];
        let (_, actions) = net.node(AYSE).create_group("Kamp", &members).unwrap();
        net.run(AYSE, actions);
        net.link(AYSE, BURAK);
        net.link(AYSE, CEM);
        for at in [BURAK, CEM] {
            assert!(
                net.node(at).links.keys().all(|c| !is_mesh_peer(*c)),
                "no mesh link left"
            );
        }
        // Their group link carries what the mesh link did.
        net.link(BURAK, CEM);
        assert_eq!(net.node(BURAK).mesh_neighbours(), 2);
    }

    #[test]
    fn devices_let_envelopes_go_after_minutes() {
        let mut net = bridge();
        mesh_link(&mut net, AYSE, BURAK);
        let cem = net.contact(AYSE, CEM);
        let (_, actions) = net.node(AYSE).send_message(cem, "kısa").unwrap();
        net.run(AYSE, actions);
        assert_eq!(net.node(BURAK).mesh.held.len(), 1);
        net.node(BURAK).mesh_tick(now_secs() + HOLD_SECS);
        assert!(net.node(BURAK).mesh.held.is_empty());
    }

    #[test]
    fn only_the_drop_secret_withdraws_and_group_envelopes_cannot_be() {
        let mut net = bridge();
        mesh_link(&mut net, AYSE, BURAK);
        mesh_link(&mut net, BURAK, CEM);
        let from = net.node(BURAK).mesh.neighbour_links().next().unwrap();
        let now = now_secs();
        let secret = [6; 16];
        let envelope = |id: EnvelopeId, drop| Envelope {
            id,
            hops: 3,
            expires: minute(now) + 10,
            tag: [7; 16],
            drop,
            body: vec![1; 300],
        };
        net.node(BURAK)
            .take_envelope(Some(from), envelope([1; 16], mesh::drop_tag(&secret)), now);
        net.node(BURAK)
            .take_envelope(Some(from), envelope([2; 16], NO_DROP), now);
        assert_eq!(net.node(BURAK).mesh.held.len(), 2);
        assert!(
            net.node(BURAK).take_withdraw(from, [1; 16], [9; 16], now).is_empty(),
            "wrong secret"
        );
        assert!(
            net.node(BURAK).take_withdraw(from, [2; 16], [0; 16], now).is_empty(),
            "no drop"
        );
        assert!(
            net.node(BURAK).take_withdraw(from, [3; 16], secret, now).is_empty(),
            "never seen"
        );
        let onward = net.node(BURAK).take_withdraw(from, [1; 16], secret, now);
        assert_eq!(onward.len(), 1, "passed on to the other neighbour");
        assert_eq!(net.node(BURAK).mesh.held.len(), 1);
        assert!(
            net.node(BURAK).take_withdraw(from, [1; 16], secret, now).is_empty(),
            "once"
        );
        let (_, again) = net
            .node(BURAK)
            .take_envelope(Some(from), envelope([1; 16], mesh::drop_tag(&secret)), now);
        assert!(again.is_empty(), "refused from then on");
    }

    #[test]
    fn group_messages_cross_the_mesh() {
        let mut net = bridge();
        let contacts = [net.contact(AYSE, CEM)];
        let (_, actions) = net.node(AYSE).create_group("Köprü", &contacts).unwrap();
        net.run(AYSE, actions);
        net.link(AYSE, CEM);
        assert_eq!(net.group(CEM).name, "Köprü");
        net.cut(AYSE, CEM);
        mesh_link(&mut net, AYSE, BURAK);
        mesh_link(&mut net, BURAK, CEM);
        net.say(AYSE, "herkese");
        assert_eq!(net.texts(CEM), ["herkese"]);
        assert!(net.node(BURAK).groups().unwrap().is_empty());
    }
}
