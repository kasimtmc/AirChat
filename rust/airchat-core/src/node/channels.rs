//! Walkie-talkie channels in the node (rust/airchat-protocol/docs/protocol.md §11): the channel tuned in, its members
//! nearby and their push-to-talk. Members are not contacts: each link to one gets a negative id
//! for as long as it lasts, and carries channel talk only. Everything here but changing the channel
//! list works while locked (requirement V-5): the tuned channel's keys stay in memory with the
//! link keys.

use std::collections::HashMap;

use zeroize::Zeroizing;

use super::{
    Action, ConnectionId, ConnectionState, Failure, Node, NodeError, Recognized, is_path_connection, now_ms, now_secs,
    seal_chat,
};
use crate::{
    channel::{self, Channel, ChannelError, Hello, Token},
    chat::{ChatMessage, StreamId},
    crypto::random,
    link::{ChannelInitiator, ChannelKeys, ChannelResponder, Flavor, Session, TagKey, epoch_at},
    media::{Allowed, GroupVoice},
    path::Class,
    storage::{ContactId, channels::ChannelSummary},
};

/// The channel tuned in, with what links to its members need.
pub(super) struct TunedChannel {
    pub row: i64,
    /// Until when (Unix ms) the user muted it: its talk does not play.
    pub muted_until: i64,
    pub channel: Channel,
    /// The key of its links' tags, as [`crate::link::TagChecker`] takes it.
    pub tag_keys: [((), TagKey); 1],
}

impl TunedChannel {
    pub(super) fn new(row: i64, muted_until: i64, channel: Channel) -> Result<Self, NodeError> {
        let tag_key = channel.tag_key()?;
        Ok(Self {
            row,
            muted_until,
            channel,
            tag_keys: [((), tag_key)],
        })
    }
}

/// What the node knows of the tuned channel's members around it.
pub(crate) struct ChannelPeers {
    /// This device's nonce for [`Hello`]: new every time the app starts.
    device: [u8; channel::DEVICE_NONCE_LEN],
    /// This device's beacon and the epoch it is for.
    own: Option<(u64, Token)>,
    /// The id handed out for each member's beacon seen, so each beacon is one peer.
    by_token: HashMap<Token, ContactId>,
    /// Members linked now, and what they said of themselves.
    linked: HashMap<ContactId, Hello>,
    /// The next id to hand out; counts down from -1, so it never meets a contact's row.
    next: ContactId,
    /// This device's count, which grows every [`HEAD_EVERY_SECS`] (§11.5), and when it last grew.
    seq: u32,
    counted_at: u64,
    /// The head each linked member last reported.
    reported: HashMap<ContactId, [u8; channel::DEVICE_NONCE_LEN]>,
    /// For each head heard of: the largest count heard for it, and when that last grew.
    counts: HashMap<[u8; channel::DEVICE_NONCE_LEN], (u32, u64)>,
    /// The head last sent to the members.
    sent: Option<[u8; channel::DEVICE_NONCE_LEN]>,
}

/// How often a member's count grows and it tells its members its cluster's head (§11.5).
const HEAD_EVERY_SECS: u64 = 10;
/// A head whose count did not grow for this long is gone.
const HEAD_GONE_SECS: u64 = 30;

impl ChannelPeers {
    pub(super) fn new() -> Result<Self, NodeError> {
        Ok(Self {
            device: channel::device_nonce()?,
            own: None,
            by_token: HashMap::new(),
            linked: HashMap::new(),
            next: -1,
            seq: 0,
            counted_at: 0,
            reported: HashMap::new(),
            counts: HashMap::new(),
            sent: None,
        })
    }

    /// An id for a member not heard yet, reached through a path (§11.5).
    pub(super) fn new_peer(&mut self) -> ContactId {
        self.new_id()
    }

    fn new_id(&mut self) -> ContactId {
        let id = self.next;
        self.next -= 1;
        id
    }
}

/// A member of the tuned channel linked now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelPeer {
    pub id: ContactId,
    /// The name it chose to show; may be empty.
    pub name: String,
}

/// Whether `contact` names a channel member's link rather than a contact.
pub(super) fn is_channel_peer(contact: ContactId) -> bool {
    contact < 0 && !super::mesh::is_mesh_peer(contact)
}

impl From<ChannelError> for NodeError {
    fn from(error: ChannelError) -> Self {
        NodeError::Channel(error)
    }
}

impl Node {
    // The channel list (needs the account).

    pub fn channels(&self) -> Result<Vec<ChannelSummary>, NodeError> {
        Ok(self.account()?.db().channels()?)
    }

    /// A new channel with a random key; share it with [`Node::channel_qr`].
    pub fn create_channel(&mut self, name: &str) -> Result<ChannelSummary, NodeError> {
        channel::check_name(name)?;
        self.save_channel(&Channel::new()?, name)
    }

    /// The channel of a QR code someone shows; it keeps the name the code suggests.
    pub fn add_channel_from_qr(&mut self, qr_text: &str) -> Result<ChannelSummary, NodeError> {
        let (channel, name) = Channel::parse_qr(qr_text)?;
        self.save_channel(&channel, &name)
    }

    /// The channel everyone typing `password` reaches. Slow on purpose (Argon2id, about a second).
    pub fn add_channel_from_password(&mut self, name: &str, password: &str) -> Result<ChannelSummary, NodeError> {
        channel::check_name(name)?;
        self.save_channel(&Channel::from_password(password)?, name)
    }

    fn save_channel(&mut self, channel: &Channel, name: &str) -> Result<ChannelSummary, NodeError> {
        Ok(self.account()?.db().save_channel(channel, name.trim(), now_ms())?)
    }

    /// The text of a channel's QR code, to let others in.
    pub fn channel_qr(&self, row: i64) -> Result<Zeroizing<String>, NodeError> {
        let (summary, channel) = self.account()?.db().channel(row)?.ok_or(NodeError::NoSuchChannel)?;
        Ok(channel.qr_text(&summary.name)?)
    }

    /// Mutes a channel until `until_ms` (Unix ms; `i64::MAX` for good), or unmutes it with 0: its
    /// talk does not play, but this device stays tuned and can talk.
    pub fn mute_channel(&mut self, row: i64, until_ms: i64) -> Result<(), NodeError> {
        if !self.account()?.db().set_channel_muted(row, until_ms)? {
            return Err(NodeError::NoSuchChannel);
        }
        self.refresh_contacts();
        Ok(())
    }

    pub fn rename_channel(&mut self, row: i64, name: &str) -> Result<(), NodeError> {
        channel::check_name(name)?;
        if !self.account()?.db().rename_channel(row, name.trim())? {
            return Err(NodeError::NoSuchChannel);
        }
        Ok(())
    }

    /// Forgets a channel and its key; if it was tuned in, its links end.
    pub fn delete_channel(&mut self, row: i64) -> Result<Vec<Action>, NodeError> {
        let tuned = self.keys.channel.as_ref().is_some_and(|c| c.row == row);
        if !self.account()?.db().delete_channel(row)? {
            return Err(NodeError::NoSuchChannel);
        }
        Ok(if tuned { self.retune() } else { Vec::new() })
    }

    /// Tunes in to a channel, or to none: its members are found and linked, and their talk plays.
    pub fn tune_channel(&mut self, row: Option<i64>) -> Result<Vec<Action>, NodeError> {
        if !self.account()?.db().tune_channel(row)? {
            return Err(NodeError::NoSuchChannel);
        }
        Ok(self.retune())
    }

    /// After the tuned channel changed: links to the old one's members end.
    fn retune(&mut self) -> Vec<Action> {
        self.refresh_contacts();
        let peers: Vec<ContactId> = self.links.keys().copied().filter(|&c| is_channel_peer(c)).collect();
        let mut actions: Vec<Action> = peers.into_iter().flat_map(|peer| self.end_link(peer)).collect();
        self.channel_peers.own = None;
        self.channel_peers.by_token.clear();
        self.channel_peers.linked.clear();
        actions.push(Action::ChannelPeersChanged);
        actions
    }

    // Finding and linking members (works while locked).

    /// This device's beacon for the tuned channel, to announce besides its presence token; `None`
    /// when tuned to none. A new one every epoch.
    pub fn channel_token(&mut self, now_secs: u64) -> Option<Token> {
        let tuned = self.keys.channel.as_ref()?;
        let epoch = epoch_at(now_secs);
        if let Some((at, token)) = self.channel_peers.own
            && at == epoch
        {
            return Some(token);
        }
        let token = tuned.channel.token(epoch).ok()?;
        self.channel_peers.own = Some((epoch, token));
        // Beacons of earlier epochs are gone; keep only the ids that name links.
        let links = &self.links;
        self.channel_peers.by_token.retain(|_, id| links.contains_key(id));
        Some(token)
    }

    /// A beacon heard: a member of the tuned channel? Each beacon is one peer to link with.
    pub fn recognize_channel(&mut self, token: &Token, now_secs: u64) -> Option<Recognized> {
        let own = self.channel_token(now_secs)?;
        let tuned = self.keys.channel.as_ref()?;
        if *token == own || !tuned.channel.recognizes(token, epoch_at(now_secs)) {
            return None;
        }
        let peers = &mut self.channel_peers;
        let id = match peers.by_token.get(token) {
            Some(&id) => id,
            None => {
                let id = peers.new_id();
                peers.by_token.insert(*token, id);
                id
            }
        };
        let handshaking = self.connections.values().any(|state| {
            matches!(state, ConnectionState::ChannelInitiating { contact, .. } | ConnectionState::ChannelResponding { contact, .. } if *contact == id)
        });
        let link = self.links.get(&id).copied();
        Some(Recognized {
            contact: id,
            opener: self.opens(id, own < *token, link.is_some() || handshaking, now_secs),
            link,
            handshaking,
        })
    }

    /// Opens a link to a channel member found with [`Node::recognize_channel`].
    pub(super) fn connect_channel_peer(
        &mut self,
        connection: ConnectionId,
        peer: ContactId,
        now_secs: u64,
    ) -> Result<Vec<Action>, NodeError> {
        let tuned = self.keys.channel.as_ref().ok_or(NodeError::UnknownContact)?;
        let tag = tuned.tag_keys[0].1.tag(epoch_at(now_secs), &random::array()?);
        let keys = ChannelKeys {
            id: tuned.channel.id(),
            psk: tuned.channel.link_psk(),
            flavor: Flavor::CHANNEL,
        };
        let (initiator, message) = ChannelInitiator::start(&keys, &tag)?;
        let state = ConnectionState::ChannelInitiating {
            contact: peer,
            initiator: Box::new(initiator),
        };
        let actions = self.open(connection, state, message)?;
        self.handshakes.insert(connection, now_secs);
        Ok(actions)
    }

    /// The first frame of a channel link someone opened.
    pub(super) fn accept_channel(
        &mut self,
        connection: ConnectionId,
        frame: &[u8],
        now_secs: u64,
    ) -> Result<Vec<Action>, Failure> {
        let tuned = self.keys.channel.as_ref().ok_or(Failure::NotAccepting)?;
        let tag = ChannelResponder::tag(frame).map_err(|_| Failure::Protocol)?;
        self.tags
            .claim(&tag, epoch_at(now_secs), &tuned.tag_keys)
            .ok_or(Failure::NotAccepting)?;
        let channel_keys = ChannelKeys {
            id: tuned.channel.id(),
            psk: tuned.channel.link_psk(),
            flavor: Flavor::CHANNEL,
        };
        let (responder, message) = ChannelResponder::respond(&channel_keys, frame, &self.hello())
            .map_err(|_| Failure::AuthenticationFailed)?;
        let peer = self.channel_peers.new_id();
        self.connections.insert(
            connection,
            ConnectionState::ChannelResponding {
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

    pub(super) fn channel_initiated(
        &mut self,
        connection: ConnectionId,
        peer: ContactId,
        initiator: ChannelInitiator,
        frame: &[u8],
    ) -> Result<Vec<Action>, Failure> {
        let (established, reply) = initiator
            .finish(frame, &self.hello())
            .map_err(|_| Failure::AuthenticationFailed)?;
        let mut actions = vec![Action::Send {
            connection,
            bytes: reply,
        }];
        actions.extend(self.channel_linked(connection, peer, established.session, &established.peer_payload));
        Ok(actions)
    }

    pub(super) fn channel_responded(
        &mut self,
        connection: ConnectionId,
        peer: ContactId,
        responder: ChannelResponder,
        frame: &[u8],
    ) -> Result<Vec<Action>, Failure> {
        let established = responder.finish(frame).map_err(|_| Failure::AuthenticationFailed)?;
        Ok(self.channel_linked(connection, peer, established.session, &established.peer_payload))
    }

    /// What this device says of itself to members: its nonce and the user's name.
    fn hello(&self) -> Vec<u8> {
        Hello {
            device: self.channel_peers.device,
            name: self.keys.display_name.clone(),
        }
        .encode()
    }

    /// A channel link is up. Two links to one device (after beacons changed, or both opened at
    /// once) are told apart by its nonce: both sides keep the one with the smaller handshake hash.
    fn channel_linked(
        &mut self,
        connection: ConnectionId,
        peer: ContactId,
        session: Session,
        hello: &[u8],
    ) -> Vec<Action> {
        let Some(hello) = Hello::decode(hello) else {
            return vec![Action::Close { connection }];
        };
        let twin = self
            .channel_peers
            .linked
            .iter()
            .find(|(id, h)| **id != peer && h.device == hello.device)
            .map(|(id, _)| *id);
        let mut actions = Vec::new();
        if let Some(twin) = twin {
            let twin_hash = self.links.get(&twin).and_then(|c| match self.connections.get(c) {
                Some(ConnectionState::Linked { session, .. }) => Some(*session.handshake_hash()),
                _ => None,
            });
            // A link that carries data wins over one for setup only (§7.3), a direct one over one
            // through Air Providers (§11.5); else the hashes decide.
            let (twin_data, new_data) = (self.data_link(twin).is_some(), !self.setup_only.contains(&connection));
            let twin_direct = self.links.get(&twin).is_some_and(|c| !is_path_connection(*c));
            let new_direct = !is_path_connection(connection);
            let keep_twin = match (twin_data, new_data, twin_direct, new_direct) {
                (true, false, ..) => true,
                (false, true, ..) => false,
                (_, _, true, false) => true,
                (_, _, false, true) => false,
                _ => twin_hash.is_some_and(|hash| &hash < session.handshake_hash()),
            };
            if keep_twin {
                let mut session = session;
                if let Ok(bytes) = session.seal_close() {
                    actions.push(Action::Send { connection, bytes });
                }
                actions.push(Action::Close { connection });
                return actions;
            }
            self.channel_peers.linked.remove(&twin);
            actions.extend(self.end_link(twin));
        }
        actions.extend(self.linked(connection, peer, session));
        self.channel_peers.linked.insert(peer, hello);
        actions.push(Action::ChannelPeersChanged);
        // The new member hears of this cluster's head at once (§11.5).
        if let Some((head, seq)) = self.channel_head(now_secs()) {
            actions.extend(self.seal_on(connection, vec![ChatMessage::ChannelHead { device: head, seq }], false));
        }
        actions
    }

    /// A channel member's link ended.
    pub(super) fn channel_peer_gone(&mut self, peer: ContactId) -> Vec<Action> {
        self.channel_peers.reported.remove(&peer);
        if self.channel_peers.linked.remove(&peer).is_some() {
            vec![Action::ChannelPeersChanged]
        } else {
            Vec::new()
        }
    }

    // Clusters (§11.5).

    /// The head of this device's cluster, with its count: of this device (if it has Air Providers
    /// around, so it can look for others) and the heads its members reported whose count still
    /// grows, the one with the smallest nonce. `None` if there is none.
    pub(super) fn channel_head(&self, now_secs: u64) -> Option<([u8; channel::DEVICE_NONCE_LEN], u32)> {
        let peers = &self.channel_peers;
        let reported = peers
            .reported
            .iter()
            .filter(|(peer, _)| self.data_link(**peer).is_some())
            .filter_map(|(_, head)| {
                let (seq, grew) = peers.counts.get(head)?;
                (now_secs.saturating_sub(*grew) < HEAD_GONE_SECS).then_some((*head, *seq))
            });
        let own = (self.providers(Class::Voice) > 0).then_some((peers.device, peers.seq));
        own.into_iter().chain(reported).min_by_key(|(head, _)| *head)
    }

    /// Whether this device heads its cluster: it looks for other clusters (§11.5).
    pub(super) fn is_channel_head(&self, now_secs: u64) -> bool {
        self.channel_head(now_secs)
            .is_some_and(|(head, _)| head == self.channel_peers.device)
    }

    /// A member said what its cluster's head is. Returns what to tell the members.
    fn take_channel_head(
        &mut self,
        peer: ContactId,
        head: [u8; channel::DEVICE_NONCE_LEN],
        seq: u32,
        now_secs: u64,
    ) -> Vec<(ConnectionId, ChatMessage)> {
        let peers = &mut self.channel_peers;
        peers.reported.insert(peer, head);
        let count = peers.counts.entry(head).or_insert((seq, now_secs));
        if seq > count.0 {
            *count = (seq, now_secs);
        }
        self.channel_head_records(now_secs, false)
    }

    /// For each member linked over a transport that carries data, what this cluster's head is:
    /// `always`, or if it changed since last told.
    fn channel_head_records(&mut self, now_secs: u64, always: bool) -> Vec<(ConnectionId, ChatMessage)> {
        let head = self.channel_head(now_secs);
        if !always && self.channel_peers.sent == head.map(|(head, _)| head) {
            return Vec::new();
        }
        self.channel_peers.sent = head.map(|(head, _)| head);
        let Some((head, seq)) = head else {
            return Vec::new();
        };
        self.channel_peers
            .linked
            .keys()
            .filter_map(|peer| self.data_link(*peer))
            .map(|connection| (connection, ChatMessage::ChannelHead { device: head, seq }))
            .collect()
    }

    /// Every tick: this device's count grows every few seconds, and the members hear the head.
    pub(super) fn channel_tick(&mut self, now_secs: u64) -> Vec<Action> {
        if self.keys.channel.is_none() {
            return Vec::new();
        }
        let peers = &mut self.channel_peers;
        if now_secs.saturating_sub(peers.counted_at) < HEAD_EVERY_SECS {
            let records = self.channel_head_records(now_secs, false);
            return self.mesh_sends(records, None);
        }
        peers.seq = peers.seq.wrapping_add(1);
        peers.counted_at = now_secs;
        peers
            .counts
            .retain(|_, (_, grew)| now_secs.saturating_sub(*grew) < 2 * HEAD_GONE_SECS);
        let records = self.channel_head_records(now_secs, true);
        self.mesh_sends(records, None)
    }

    /// The members of the tuned channel linked now.
    pub fn channel_peers(&self) -> Vec<ChannelPeer> {
        let mut peers: Vec<ChannelPeer> = self
            .channel_peers
            .linked
            .iter()
            .filter(|(id, _)| self.data_link(**id).is_some())
            .map(|(id, hello)| ChannelPeer {
                id: *id,
                name: hello.name.clone(),
            })
            .collect();
        peers.sort_by(|a, b| a.name.cmp(&b.name).then(a.id.cmp(&b.id)));
        peers
    }

    // Talk.

    /// Talks to the members of the tuned channel linked now. Returns the talk's id.
    pub fn start_channel_talk(&mut self) -> Result<(StreamId, Vec<Action>), NodeError> {
        let tuned = self.keys.channel.as_ref().ok_or(NodeError::NoSuchChannel)?;
        let channel_id = *tuned.channel.id();
        let members: Vec<ContactId> = self
            .channel_peers
            .linked
            .keys()
            .copied()
            .filter(|id| self.data_link(*id).is_some())
            .collect();
        if members.is_empty() {
            return Err(NodeError::NotLinked);
        }
        let id = random::array()?;
        let effects = self.media.start_group_talk(channel_id, id, &members)?;
        Ok((id, self.apply_media(effects)))
    }

    /// Passes a talk's record heard from member `from` on to the other members linked (§11.4).
    fn relay_channel(&mut self, from: ContactId, record: ChatMessage) -> Vec<Action> {
        let others: Vec<ConnectionId> = self
            .channel_peers
            .linked
            .keys()
            .filter(|peer| **peer != from)
            .filter_map(|peer| self.data_link(*peer))
            .collect();
        others
            .into_iter()
            .flat_map(|connection| self.seal_on(connection, vec![record.clone()], false))
            .collect()
    }

    /// A record on a channel link: only channel talk and liveness count (§11.4).
    pub(super) fn on_channel_record(
        &mut self,
        connection: ConnectionId,
        peer: ContactId,
        session: &mut Session,
        record: ChatMessage,
    ) -> Result<Vec<Action>, ()> {
        match record {
            // This device's own talk, come back round through other members: nothing to do.
            ChatMessage::GroupTalkStart { id, group_id } if self.media.own_group_talk(&group_id) == Some(id) => {
                Ok(Vec::new())
            }
            ChatMessage::GroupTalkStart { id, group_id } => {
                let voice = self
                    .keys
                    .channel
                    .as_ref()
                    .filter(|tuned| *tuned.channel.id() == group_id)
                    .map(|tuned| GroupVoice {
                        row: tuned.row,
                        member: true,
                        // Muted, the channel's talk does not play (it is turned down).
                        instant_voice: now_ms() >= tuned.muted_until,
                        channel: true,
                    });
                let effects = self
                    .media
                    .receive_group(peer, ChatMessage::GroupTalkStart { id, group_id }, voice);
                let mut actions = self.media_effects_on(connection, peer, session, effects)?;
                // Taken from this member: passed on to the others, as a repeater (§11.4).
                if self.media.group_talk_in(&group_id) == Some((id, peer)) {
                    actions.extend(self.relay_channel(peer, ChatMessage::GroupTalkStart { id, group_id }));
                }
                Ok(actions)
            }
            message @ (ChatMessage::TalkEnd { .. } | ChatMessage::Audio { .. }) => {
                let stream = match &message {
                    ChatMessage::TalkEnd { id, .. } => *id,
                    ChatMessage::Audio { stream, .. } => *stream,
                    _ => unreachable!("matched above"),
                };
                let channel = self.keys.channel.as_ref().map(|tuned| *tuned.channel.id());
                let relayed = channel
                    .is_some_and(|c| self.media.group_talk_in(&c) == Some((stream, peer)))
                    .then(|| message.clone());
                let effects = self.media.receive(
                    peer,
                    message,
                    Allowed {
                        calls: false,
                        instant_voice: false,
                    },
                );
                let mut actions = self.media_effects_on(connection, peer, session, effects)?;
                if let Some(record) = relayed {
                    actions.extend(self.relay_channel(peer, record));
                }
                Ok(actions)
            }
            ChatMessage::ChannelHead { device, seq } => {
                let records = self.take_channel_head(peer, device, seq, now_secs());
                Ok(self.mesh_sends(records, None))
            }
            ChatMessage::Ping => {
                let bytes = seal_chat(session, &ChatMessage::Pong).map_err(|_| ())?;
                Ok(vec![Action::Send { connection, bytes }])
            }
            _ => Ok(Vec::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::groups::tests::Net;
    use super::*;
    use crate::account::Account;

    const A: usize = 0;
    const B: usize = 1;
    const C: usize = 2;

    /// Links two tuned devices from the side that opens, as the platform does on hearing a beacon;
    /// whether a link is up in the end.
    fn link_members(net: &mut Net, a: usize, b: usize) -> bool {
        let now = net.now;
        let token_a = net.devices[a].node.channel_token(now).unwrap();
        let token_b = net.devices[b].node.channel_token(now).unwrap();
        let seen = net.devices[a].node.recognize_channel(&token_b, now).unwrap();
        let seen_back = net.devices[b].node.recognize_channel(&token_a, now).unwrap();
        assert_ne!(seen.opener, seen_back.opener, "exactly one side opens");
        let (opener, other, peer) = if seen.opener {
            (a, b, seen.contact)
        } else {
            (b, a, seen_back.contact)
        };
        let (id, _) = net.wire(opener, other);
        let first = net.devices[opener].node.connect_contact(id, peer, now).unwrap();
        net.run(opener, first);
        net.devices[opener].node.is_linked(peer)
    }

    fn names(net: &Net, at: usize) -> Vec<String> {
        net.devices[at]
            .node
            .channel_peers()
            .into_iter()
            .map(|p| p.name)
            .collect()
    }

    /// Three devices that are not contacts, tuned to one channel shared by QR code.
    fn tuned() -> Net {
        let mut net = Net::new(&["Ayşe", "Burak", "Cem"]);
        let channel = net.node(A).create_channel("Kamp telsizi").unwrap();
        let qr = net.node(A).channel_qr(channel.row).unwrap();
        for at in [B, C] {
            let joined = net.node(at).add_channel_from_qr(&qr).unwrap();
            assert_eq!(joined.name, "Kamp telsizi");
            net.node(at).tune_channel(Some(joined.row)).unwrap();
        }
        net.node(A).tune_channel(Some(channel.row)).unwrap();
        assert!(net.devices[A].node.channels().unwrap()[0].tuned);
        net
    }

    fn talk_started(net: &Net, at: usize) -> bool {
        let row = net.devices[at].node.channels().unwrap()[0].row;
        net.devices[at]
            .shown
            .iter()
            .any(|a| matches!(a, Action::ChannelTalkStarted { channel, .. } if *channel == row))
    }

    fn heard(net: &Net, at: usize) -> usize {
        net.devices[at]
            .shown
            .iter()
            .filter(|a| matches!(a, Action::Audio { .. }))
            .count()
    }

    #[test]
    fn members_pass_talk_on_to_members_out_of_the_talkers_reach() {
        // Ayşe — Burak — Cem: Ayşe and Cem are not in reach of each other.
        let mut net = tuned();
        assert!(link_members(&mut net, A, B));
        assert!(link_members(&mut net, B, C));
        let (talk, actions) = net.node(A).start_channel_talk().unwrap();
        net.run(A, actions);
        assert!(talk_started(&net, B) && talk_started(&net, C), "Burak passed it on");
        let audio = net.node(A).send_audio(talk, b"opus");
        net.run(A, audio);
        assert_eq!((heard(&net, B), heard(&net, C)), (1, 1));
        // With everyone in reach of everyone, nobody hears anything twice, the talker nothing.
        assert!(link_members(&mut net, A, C));
        let audio = net.node(A).send_audio(talk, b"opus");
        net.run(A, audio);
        assert_eq!((heard(&net, A), heard(&net, B), heard(&net, C)), (0, 2, 2));
        let actions = net.node(A).end_talk(talk);
        net.run(A, actions);
        assert!(
            net.devices[C]
                .shown
                .iter()
                .any(|a| matches!(a, Action::TalkEnded { id, .. } if *id == talk))
        );
    }

    #[test]
    fn a_member_alone_finds_another_through_an_air_provider_and_a_direct_link_replaces_it() {
        use crate::{node::mesh::tests::mesh_link, path::Classes};
        const D: usize = 3;
        let mut net = Net::new(&["Ayşe", "Burak", "Cem", "Deniz"]);
        let channel = net.node(A).create_channel("Kamp telsizi").unwrap();
        let qr = net.node(A).channel_qr(channel.row).unwrap();
        let joined = net.node(B).add_channel_from_qr(&qr).unwrap();
        net.node(B).tune_channel(Some(joined.row)).unwrap();
        net.node(A).tune_channel(Some(channel.row)).unwrap();
        // Deniz, an Air Provider not in the channel, is all that is between Ayşe and Burak.
        let actions = net.node(D).set_air_provider(Classes::from_bits(0x01));
        net.run(D, actions);
        mesh_link(&mut net, A, D);
        mesh_link(&mut net, B, D);
        let actions = net.node(A).find_channel_path().unwrap();
        net.run(A, actions);
        assert_eq!(names(&net, A), ["Burak"]);
        assert_eq!(names(&net, B), ["Ayşe"]);
        let (talk, actions) = net.node(A).start_channel_talk().unwrap();
        net.run(A, actions);
        assert!(talk_started(&net, B));
        let actions = net.node(A).end_talk(talk);
        net.run(A, actions);
        // In reach of each other again: the direct link wins.
        assert!(link_members(&mut net, A, B));
        assert_eq!(names(&net, A), ["Burak"]);
        let peer = net.devices[A].node.channel_peers()[0].id;
        assert!(!is_path_connection(net.node(A).links[&peer]), "direct");
        assert!(net.node(D).paths_carried() == 0, "the path closed");
        // One cluster: its head looks on for others, and the other, in it, does not answer.
        let (head, other) = if net.node(A).is_channel_head(now_secs()) {
            (A, B)
        } else {
            (B, A)
        };
        assert!(
            net.node(other).find_channel_path().unwrap().is_empty(),
            "only the head looks"
        );
        let actions = net.node(head).find_channel_path().unwrap();
        assert!(!actions.is_empty());
        net.run(head, actions);
        assert_eq!((names(&net, A).len(), names(&net, B).len()), (1, 1), "nobody new");
    }

    #[test]
    fn a_cluster_finds_its_next_head_when_its_head_goes() {
        use crate::{node::mesh::tests::mesh_link, path::Classes};
        const D: usize = 3;
        let mut net = tuned();
        net.devices.push(Net::new(&["Deniz"]).devices.remove(0));
        let actions = net.node(D).set_air_provider(Classes::from_bits(0x01));
        net.run(D, actions);
        for at in [A, B, C] {
            mesh_link(&mut net, at, D);
        }
        assert!(link_members(&mut net, A, B));
        assert!(link_members(&mut net, B, C));
        assert!(link_members(&mut net, A, C));
        let heads = |net: &mut Net, of: &[usize]| {
            of.iter()
                .copied()
                .filter(|&at| net.node(at).is_channel_head(now_secs()))
                .collect::<Vec<_>>()
        };
        let head = heads(&mut net, &[A, B, C]);
        assert_eq!(head.len(), 1);
        let rest: Vec<usize> = [A, B, C].into_iter().filter(|at| *at != head[0]).collect();
        // The head tunes out. The others still name it to each other for a while...
        let actions = net.node(head[0]).tune_channel(None).unwrap();
        net.run(head[0], actions);
        assert!(heads(&mut net, &rest).is_empty());
        // ...until its count has not grown for 30 s: then the next one heads.
        for &at in &rest {
            for count in net.node(at).channel_peers.counts.values_mut() {
                count.1 -= HEAD_GONE_SECS;
            }
        }
        for &at in &rest {
            let actions = net.node(at).tick(now_secs());
            net.run(at, actions);
        }
        assert_eq!(heads(&mut net, &rest).len(), 1);
    }

    #[test]
    fn heads_bridge_two_clusters_through_an_air_provider() {
        use crate::{node::mesh::tests::mesh_link, path::Classes};
        const D: usize = 3;
        const E: usize = 4;
        let mut net = Net::new(&["Ayşe", "Burak", "Cem", "Deniz", "Ece"]);
        let channel = net.node(A).create_channel("Kamp telsizi").unwrap();
        let qr = net.node(A).channel_qr(channel.row).unwrap();
        for at in [B, C, D] {
            let joined = net.node(at).add_channel_from_qr(&qr).unwrap();
            net.node(at).tune_channel(Some(joined.row)).unwrap();
        }
        net.node(A).tune_channel(Some(channel.row)).unwrap();
        // Ece, an Air Provider not in the channel, is between Burak and Cem.
        let actions = net.node(E).set_air_provider(Classes::from_bits(0x01));
        net.run(E, actions);
        mesh_link(&mut net, B, E);
        mesh_link(&mut net, C, E);
        // Two clusters: Ayşe and Burak, Cem and Deniz. Burak and Cem have the provider around,
        // so they head them.
        assert!(link_members(&mut net, A, B));
        assert!(link_members(&mut net, C, D));
        let heads = |net: &mut Net| {
            [A, B, C, D]
                .into_iter()
                .filter(|&at| net.node(at).is_channel_head(now_secs()))
                .collect::<Vec<_>>()
        };
        assert_eq!(heads(&mut net), [B, C]);
        assert!(
            net.node(A).find_channel_path().unwrap().is_empty(),
            "Ayşe does not look"
        );
        let actions = net.node(B).find_channel_path().unwrap();
        net.run(B, actions);
        assert_eq!(names(&net, B), ["Ayşe", "Cem"]);
        // One cluster, one head.
        assert_eq!(heads(&mut net).len(), 1);
        // Ayşe's talk reaches Deniz through Burak and Cem, repeaters.
        let (talk, actions) = net.node(A).start_channel_talk().unwrap();
        net.run(A, actions);
        assert!(talk_started(&net, D));
        let audio = net.node(A).send_audio(talk, b"opus");
        net.run(A, audio);
        assert_eq!(heard(&net, D), 1);
    }

    #[test]
    fn members_link_and_hear_each_other() {
        let mut net = tuned();
        assert!(link_members(&mut net, A, B));
        assert!(link_members(&mut net, A, C));
        assert!(link_members(&mut net, B, C));
        assert_eq!(names(&net, A), ["Burak", "Cem"]);
        assert_eq!(names(&net, C), ["Ayşe", "Burak"]);
        assert!(net.devices[A].node.account().unwrap().contacts().unwrap().is_empty());

        let (talk, actions) = net.node(A).start_channel_talk().unwrap();
        net.run(A, actions);
        for at in [B, C] {
            let row = net.devices[at].node.channels().unwrap()[0].row;
            assert!(
                net.devices[at]
                    .shown
                    .iter()
                    .any(|a| matches!(a, Action::ChannelTalkStarted { channel, .. } if *channel == row)),
                "device {at} plays it"
            );
        }
        let audio = net.node(A).send_audio(talk, b"opus");
        assert_eq!(audio.len(), 2);
        net.run(A, audio);
        assert!(net.devices[C].shown.iter().any(|a| matches!(a, Action::Audio { .. })));
        // Only channel talk travels on these links.
        let peer = net.devices[A].node.channel_peers()[0].id;
        assert!(matches!(
            net.node(A).send_message(peer, "selam"),
            Err(NodeError::UnknownContact)
        ));
        assert!(net.node(A).start_call(peer, false).is_err());
    }

    #[test]
    fn a_password_reaches_the_same_channel_and_others_stay_out() {
        let mut net = Net::new(&["Ayşe", "Burak", "Cem"]);
        for at in [A, B] {
            let channel = net
                .node(at)
                .add_channel_from_password("Yayla", "kamp ateşi 2026")
                .unwrap();
            net.node(at).tune_channel(Some(channel.row)).unwrap();
        }
        let other = net
            .node(C)
            .add_channel_from_password("Başka", "kamp ateşi 2027")
            .unwrap();
        net.node(C).tune_channel(Some(other.row)).unwrap();
        assert!(link_members(&mut net, A, B));
        let now = net.now;
        let token_c = net.devices[C].node.channel_token(now).unwrap();
        assert!(net.devices[A].node.recognize_channel(&token_c, now).is_none());
        assert!(matches!(
            net.node(A).add_channel_from_password("Kısa", "kısa"),
            Err(NodeError::Channel(ChannelError::PasswordTooShort))
        ));
        // A handshake forced on Cem anyway is turned away.
        let peer = net.devices[A].node.channel_peers()[0].id;
        let (id, _) = net.wire(A, C);
        let first = net.node(A).connect_contact(id, peer - 100, now).unwrap();
        net.run(A, first);
        assert!(net.devices[C].node.channel_peers().is_empty());
    }

    #[test]
    fn talk_plays_while_locked() {
        let mut net = tuned();
        assert!(link_members(&mut net, A, B));
        net.devices[B].node.seal();
        let (_, actions) = net.node(A).start_channel_talk().unwrap();
        net.run(A, actions);
        assert!(
            net.devices[B]
                .shown
                .iter()
                .any(|a| matches!(a, Action::ChannelTalkStarted { .. }))
        );
        let device = &mut net.devices[B];
        let account = Account::unlock_with_pin(device.dir.path(), &device.pin_record, b"123456").unwrap();
        device.node.unseal(account).unwrap();
        assert_eq!(names(&net, B), ["Ayşe"]);
    }

    #[test]
    fn a_second_link_to_the_same_member_is_dropped() {
        let mut net = tuned();
        assert!(link_members(&mut net, A, B));
        // An hour on, both beacons are new: the opener links again, and one link of the two stays.
        net.now += 3_600;
        link_members(&mut net, A, B);
        assert_eq!(names(&net, A), ["Burak"]);
        assert_eq!(names(&net, B), ["Ayşe"]);
        let peer = |net: &Net, at: usize| {
            net.devices[at]
                .node
                .links
                .keys()
                .filter(|&&c| is_channel_peer(c))
                .count()
        };
        assert_eq!((peer(&net, A), peer(&net, B)), (1, 1));
        let (_, actions) = net.node(A).start_channel_talk().unwrap();
        assert_eq!(actions.iter().filter(|a| matches!(a, Action::Send { .. })).count(), 1);
    }

    #[test]
    fn a_muted_channel_stays_tuned_but_plays_nothing() {
        let mut net = tuned();
        assert!(link_members(&mut net, A, B));
        let row = net.devices[B].node.channels().unwrap()[0].row;
        net.node(B).mute_channel(row, i64::MAX).unwrap();
        let (talk, actions) = net.node(A).start_channel_talk().unwrap();
        net.run(A, actions);
        assert!(
            !net.devices[B]
                .shown
                .iter()
                .any(|a| matches!(a, Action::ChannelTalkStarted { .. }))
        );
        assert!(net.node(A).send_audio(talk, b"opus").is_empty(), "nobody to send to");
        let actions = net.node(A).end_talk(talk);
        net.run(A, actions);
        // B can still talk, and unmuted (or once the time passed) it hears again.
        let (b_talk, actions) = net.node(B).start_channel_talk().unwrap();
        net.run(B, actions);
        assert!(
            net.devices[A]
                .shown
                .iter()
                .any(|a| matches!(a, Action::ChannelTalkStarted { .. }))
        );
        let actions = net.node(B).end_talk(b_talk);
        net.run(B, actions);
        net.node(B).mute_channel(row, 1).unwrap();
        assert_eq!(net.devices[B].node.channels().unwrap()[0].muted_until, 1);
        let (_, actions) = net.node(A).start_channel_talk().unwrap();
        net.run(A, actions);
        assert!(
            net.devices[B]
                .shown
                .iter()
                .any(|a| matches!(a, Action::ChannelTalkStarted { .. }))
        );
    }

    #[test]
    fn tuning_out_ends_the_links() {
        let mut net = tuned();
        assert!(link_members(&mut net, A, B));
        let actions = net.node(B).tune_channel(None).unwrap();
        net.run(B, actions);
        assert!(names(&net, A).is_empty() && names(&net, B).is_empty());
        let now = net.now;
        assert!(net.node(B).channel_token(now).is_none());
        assert!(matches!(net.node(A).start_channel_talk(), Err(NodeError::NotLinked)));
    }
}
