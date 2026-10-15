//! The running node: the account plus everything happening on open connections.
//!
//! The platform owns the transports. It hands every frame it receives to [`Node::on_frame`] and
//! carries out the returned [`Action`]s; it never interprets protocol bytes itself, so all
//! platforms behave identically.
//!
//! A node is either **open** (unlocked: the account and its database are available) or **sealed**
//! (locked, docs/architecture.md §4.3). Sealing closes the database and wipes the master key; the
//! node keeps only what links need — its static KEM key and the contacts' link keys — plus the
//! messages still waiting to be delivered. Messages that arrive while sealed are encrypted to the
//! inbox key and moved into the database when the node is opened again. Links stay up throughout.

mod additions;
mod attestation;
mod channels;
mod emergency;
#[cfg(any(test, feature = "fuzzing"))]
pub(crate) mod fuzz;
mod group_files;
mod groups;
mod mesh;
mod mesh_files;
mod mesh_updates;
mod paths;
mod prekeys;
mod presence_keys;
mod requests;
mod static_keys;
mod voice;

use std::collections::{HashMap, HashSet};

use zeroize::Zeroizing;

pub use self::{
    channels::ChannelPeer,
    emergency::EmergencyExit,
    groups::GroupMember,
    paths::{PATH_CONNECTION_BASE, is_path_connection},
};

use crate::{
    account::{Account, AccountError},
    chat::{
        self, ChatError, ChatMessage, EndReason, HotspotOffer, MAX_FILE_SIZE, MoveTarget, StreamId, Unavailable,
        VideoState,
    },
    crypto::{CryptoError, kem::DecapsulationKey, kem::EncapsulationKey, random},
    crypto::{
        SecretBytes,
        hash::{Sha256Stream, equal_in_constant_time},
    },
    discovery::{PairingBeacon, PresenceToken, presence_token},
    group::{self, GroupError, GroupId},
    identity::PublicIdentity,
    inbox::{InboxEvent, InboxWriter},
    link::{
        CHANNEL_MESSAGE_1, ChannelInitiator, ChannelResponder, Initiator, LinkError, LocalKeys, MESH_MESSAGE_1, Record,
        RemoteKeys, Responder, Session, TagChecker, TagKey, epoch_at,
    },
    media::{Allowed, CallSelf, Effects, GroupVoice, Media, MediaError},
    pairing::{Event, INVITE_LIFETIME_SECS, Invite, Mode, Pairing, PairingError, Sas, ScannedInvite},
    path::Class,
    storage::{
        AttachmentState, ContactId, ContactState, ContactSummary, FileMeta, MessageId, MessageStatus, Permissions,
        StorageError, StoredMessage, TRY_MS,
        files::{CHUNK_LEN, chunk_count, chunk_len},
        groups::{GroupMessage, GroupSummary},
        requests::ContactRequest,
    },
};

/// Chosen by the platform; unique among its open connections.
pub type ConnectionId = u64;

/// Message types that open a connection (rust/airchat-protocol/docs/protocol.md §6.3, §4.3).
const LINK_MESSAGE_1: u8 = 0x01;

const PAIRING_MESSAGE_1: u8 = 0x21;

/// Most QR invites one device keeps open at a time; older ones are dropped.
const MAX_INVITES: usize = 4;

#[derive(Debug)]
pub enum Action {
    Send {
        connection: ConnectionId,
        bytes: Vec<u8>,
    },
    /// Close the connection once everything queued on it has been sent.
    Close {
        connection: ConnectionId,
    },
    /// Ask the user whether the other screen shows these emoji; answer with
    /// [`Node::confirm_pairing`] or [`Node::reject_pairing`].
    ShowSas {
        connection: ConnectionId,
        sas: Sas,
    },
    /// A new contact was paired and saved.
    Paired {
        connection: ConnectionId,
        contact: ContactSummary,
    },
    /// A contact proposes a group of the two of you and someone else (protocol §9.8); answer with
    /// [`Node::answer_member_proposal`].
    MemberProposed {
        contact: ContactId,
        proposal: additions::MemberProposal,
    },
    /// The contact did not agree to a group this device proposed (or it could not be made).
    MemberProposalDeclined {
        contact: ContactId,
    },
    /// Someone who typed this device's AirChat ID asks to be added (protocol §4.8); answer with
    /// [`Node::approve_contact_request`] or [`Node::decline_contact_request`].
    ContactRequest {
        connection: ConnectionId,
        request: ContactRequest,
    },
    Failed {
        connection: ConnectionId,
        reason: Failure,
    },
    /// An encrypted session with a contact is up; messages flow.
    LinkUp {
        connection: ConnectionId,
        contact: ContactId,
    },
    /// The session with a contact ended; messages wait until the next one.
    LinkDown {
        contact: ContactId,
    },
    MessageReceived {
        message: StoredMessage,
    },
    /// A message arrived while sealed. It is in the inbox, readable after unlocking; notify the
    /// user without revealing anything about it.
    MessageArrived {
        contact: ContactId,
    },
    /// A group message arrived while sealed; like [`Action::MessageArrived`]. `group` is its row,
    /// if this device is in it.
    GroupMessageArrived {
        group: Option<i64>,
    },
    /// An outgoing message changed status (sent, delivered).
    MessageUpdated {
        message: StoredMessage,
    },
    /// Something waits to be sent to the contact, whose link carries setup only (BLE, §7.3): offer
    /// to move it to Wi-Fi ([`Node::request_move`]).
    WaitingForWifi {
        contact: ContactId,
    },
    /// The contact asks this device to open `target` so the link can move there (§8.3). Answer
    /// with [`Node::offer_hotspot`] or [`Node::decline_move`].
    MoveRequested {
        contact: ContactId,
        target: MoveTarget,
    },
    /// The contact opened a hotspot for this device: join it, connect to its gateway at
    /// `offer.port` and open a link there with [`Node::connect_contact`]; it replaces the current one.
    HotspotOffered {
        contact: ContactId,
        offer: HotspotOffer,
    },
    /// The contact cannot open `target` now.
    MoveDeclined {
        contact: ContactId,
        target: MoveTarget,
    },
    /// A contact calls (§8.5): ring, and answer with [`Node::answer_call`] or decline with
    /// [`Node::end_call`]. A video call rings as one; the contact's camera may come on once
    /// answered (§8.6).
    CallRinging {
        id: StreamId,
        contact: ContactId,
        video: bool,
    },
    /// This device's call rings on the contact's device.
    CallReached {
        id: StreamId,
    },
    /// The contact answered this device's call: audio flows both ways.
    CallAccepted {
        id: StreamId,
    },
    /// The call is over, whoever ended it.
    CallEnded {
        id: StreamId,
        reason: EndReason,
    },
    /// A contact talks (push-to-talk): play its audio at once.
    TalkStarted {
        id: StreamId,
        contact: ContactId,
    },
    /// A talk is over: the contact's, or this device's when the contact turned it down or went first.
    TalkEnded {
        id: StreamId,
        reason: EndReason,
    },
    /// A packet of a call's or talk's audio from `from`, for its jitter buffer (a group call has
    /// one per participant).
    Audio {
        stream: StreamId,
        from: ContactId,
        seq: u32,
        packet: Zeroizing<Vec<u8>>,
    },
    /// The camera of `from` in call `id` went on, off or paused: the contact's in a 1:1 call, a
    /// participant's in a group call.
    VideoStateChanged {
        id: StreamId,
        from: ContactId,
        state: VideoState,
    },
    /// A frame of video in call `stream`, put back together: H.264, Annex B; a key frame carries
    /// SPS and PPS. Show it turned `rotation` quarter turns clockwise.
    Video {
        stream: StreamId,
        /// Whose video it is: the contact, or a participant of a group call (one stream each).
        from: ContactId,
        key: bool,
        rotation: u8,
        width: u16,
        height: u16,
        frame: Zeroizing<Vec<u8>>,
    },
    /// The contact cannot decode this device's video from here on: make the next frame a key frame.
    KeyFrameRequested {
        id: StreamId,
    },
    /// A member talks to a group (push-to-talk): play its audio at once.
    GroupTalkStarted {
        id: StreamId,
        group: i64,
        contact: ContactId,
    },
    /// A member called a group: ring, and join with [`Node::join_group_call`] or decline with
    /// [`Node::end_call`]. [`Action::CallEnded`] ends it, here as for 1:1 calls.
    GroupCallRinging {
        id: StreamId,
        group: i64,
        contact: ContactId,
    },
    /// Who else is in the group call this device is in.
    GroupCallChanged {
        id: StreamId,
        participants: Vec<ContactId>,
    },
    /// A member of the walkie-talkie channel tuned in talks: play it at once. `contact` names the
    /// member's link, as [`Node::channel_peers`] lists it.
    ChannelTalkStarted {
        id: StreamId,
        channel: i64,
        contact: ContactId,
    },
    /// Members of the tuned channel linked or went away; see [`Node::channel_peers`].
    ChannelPeersChanged,
    /// The platform's attested key is to sign `message` for the link to `contact`; pass the
    /// signature to [`Node::send_attestation`] (§6.10).
    AttestationWanted {
        contact: ContactId,
        message: Vec<u8>,
    },
    /// What a contact's build attestation shows changed: see the contact's `attested`.
    AttestationChanged {
        contact: ContactId,
    },
    /// A group was created, changed members, or this device left it or was removed.
    GroupChanged {
        group: GroupSummary,
    },
    GroupMessageReceived {
        message: GroupMessage,
    },
    /// An outgoing group message reached a member.
    GroupMessageUpdated {
        message: GroupMessage,
    },
    /// No path to the contact that carries `class` was found ([`Node::find_path`]).
    PathFailed {
        contact: ContactId,
        class: Class,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// The other user cancelled or said the emoji differ.
    Rejected,
    /// Wrong emoji confirmed, wrong QR code, or an attack.
    AuthenticationFailed,
    /// The QR code expired, was already used, or is not an AirChat invite.
    InvalidInvite,
    /// This device is not accepting that kind of connection right now.
    NotAccepting,
    /// The connection ended before pairing finished.
    ConnectionLost,
    /// Paired with someone this user blocked: they stay blocked and are not added again.
    Blocked,
    /// Anything else: malformed or unexpected messages, storage errors.
    Protocol,
}

#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    #[error("connection {0} is already in use")]
    ConnectionInUse(ConnectionId),
    #[error("no such contact")]
    UnknownContact,
    #[error("no link to that contact")]
    NotLinked,
    #[error("the link to that contact runs over Bluetooth: move it to Wi-Fi first")]
    NeedsWifi,
    #[error("the link to that contact runs over a path that does not carry that")]
    PathTooNarrow,
    #[error("no Air Provider around carries that")]
    NoProvider,
    #[error("no such file")]
    NoSuchFile,
    #[error("no such group, or this device is no longer in it")]
    NoSuchGroup,
    #[error("only an admin of the group can do that")]
    NotGroupAdmin,
    #[error("no such channel")]
    NoSuchChannel,
    #[error("that is not an AirChat ID")]
    InvalidId,
    #[error("that is this device's own AirChat ID")]
    OwnId,
    #[error("that AirChat ID is a contact's already")]
    AlreadyContact,
    #[error("this device is not in that group's call")]
    NotInCall,
    #[error("no such message, or it was not given up")]
    NoSuchMessage,
    #[error(transparent)]
    Channel(crate::channel::ChannelError),
    #[error(transparent)]
    Group(#[from] GroupError),
    #[error(transparent)]
    Media(#[from] MediaError),
    #[error("the app is locked")]
    Sealed,
    #[error("that account belongs to another identity")]
    WrongAccount,
    #[error(transparent)]
    Chat(#[from] ChatError),
    #[error(transparent)]
    Pairing(#[from] PairingError),
    #[error(transparent)]
    Link(#[from] LinkError),
    #[error(transparent)]
    Account(#[from] AccountError),
}

impl From<CryptoError> for NodeError {
    fn from(error: CryptoError) -> Self {
        Self::Pairing(PairingError::Crypto(error))
    }
}

impl From<StorageError> for NodeError {
    fn from(error: StorageError) -> Self {
        Self::Account(AccountError::Storage(error))
    }
}

/// A contact seen on the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Recognized {
    pub contact: ContactId,
    /// Whether this device is the one that opens links to the contact: the side the rule names
    /// (the smaller identity key, or beacon or channel token), or the other one once no link came
    /// up after a minute of seeing each other (§5.2).
    pub opener: bool,
    /// The connection carrying the established link to the contact, if any.
    pub link: Option<ConnectionId>,
    /// Whether a handshake with the contact is under way.
    pub handshaking: bool,
}

impl Recognized {
    /// Whether to open a link now: this device opens links, and none is up or being set up.
    pub fn initiate(&self) -> bool {
        self.opener && self.link.is_none() && !self.handshaking
    }

    /// Whether this device may open a second link that will replace the established one, e.g. over
    /// a faster transport. The old link closes once the new one is up.
    pub fn may_replace(&self) -> bool {
        self.opener && self.link.is_some() && !self.handshaking
    }
}

enum ConnectionState {
    Pairing(Box<Pairing>),
    /// A contact link's handshake (§6.3), with the link key it is made with (§6.8) and, on the
    /// opening side, the version of this device's static key it uses (§6.9).
    Initiating {
        contact: ContactId,
        link_key: SecretBytes<32>,
        own_key: u32,
        initiator: Box<Initiator>,
    },
    Responding {
        contact: ContactId,
        link_key: SecretBytes<32>,
        responder: Box<Responder>,
    },
    Linked {
        contact: ContactId,
        session: Box<Session>,
    },
    /// Links to walkie-talkie channel members (§11.3); `contact` is the member's negative id.
    ChannelInitiating {
        contact: ContactId,
        initiator: Box<ChannelInitiator>,
    },
    ChannelResponding {
        contact: ContactId,
        responder: Box<ChannelResponder>,
    },
    /// Mesh links (§10.2); `contact` is the peer's id from [`mesh::MESH_PEER_BASE`] down.
    MeshInitiating {
        contact: ContactId,
        initiator: Box<ChannelInitiator>,
    },
    MeshResponding {
        contact: ContactId,
        responder: Box<ChannelResponder>,
    },
}

enum Store {
    Open(Box<Account>),
    Sealed(Box<Sealed>),
}

/// What a sealed node keeps besides its link keys.
struct Sealed {
    inbox: InboxWriter,
    /// Outgoing messages not acknowledged yet, oldest first. The only plaintext a sealed node holds.
    pending: Vec<Pending>,
    /// Incoming messages already written to the inbox, so resends are not stored twice.
    stored: HashSet<(ContactId, MessageId)>,
    /// The same for group messages, by group and message id.
    group_stored: HashSet<(GroupId, MessageId)>,
}

struct Pending {
    contact: ContactId,
    id: MessageId,
    sent_at_ms: i64,
    text: Zeroizing<String>,
}

/// Everything links need, kept in memory in both modes.
struct LinkMaterial {
    identity: PublicIdentity,
    /// This device's side of links: every static key kept, with its version, newest first (§6.9).
    locals: Vec<(u32, LocalKeys)>,
    /// The newest static key, signed: what contacts and fellow members are told of it.
    announcement: ChatMessage,
    presence_key: SecretBytes<32>,
    /// The presence key's version (§5.4).
    presence_version: u32,
    contacts: HashMap<ContactId, ContactKeys>,
    /// The groups this device is in, for voice, which works while locked too.
    groups: HashMap<GroupId, GroupKeys>,
    /// The walkie-talkie channel tuned in, also while locked (requirement V-5).
    channel: Option<channels::TunedChannel>,
    /// The name channel members see (§11.3).
    display_name: String,
}

struct GroupKeys {
    row: i64,
    /// The newest epoch held.
    epoch: u64,
    /// Keys of the tags on the group's mesh envelopes, one per epoch held (§10.3).
    mesh_tag_keys: Vec<SecretBytes<32>>,
    /// Keys of the mesh copies of the next epoch's update (§10.9).
    next_update: Option<crate::mesh::UpdateKeys>,
    /// Keys of the tags on the group's file parts, one per epoch held (§10.10).
    file_tag_keys: Vec<SecretBytes<32>>,
    /// The rows of its other members (contacts or peers).
    members: Vec<ContactId>,
    /// Its push-to-talk plays at once.
    instant_voice: bool,
    /// Until when (Unix ms) the user muted it.
    muted_until: i64,
}

struct ContactKeys {
    identity: PublicIdentity,
    /// A contact's static keys, newest first: the one it was told of last, then up to two earlier
    /// ones it may still link with (§6.9).
    static_kems: Vec<EncapsulationKey>,
    /// The newest of this device's static keys it has taken.
    own_key_taken: u32,
    /// For a fellow member who is not a contact, per link key: its static key and this device's
    /// static key version, as the roster of that link key's epoch lists them.
    roster_keys: Vec<(EncapsulationKey, u32)>,
    presence_key: SecretBytes<32>,
    /// The newest of this device's presence keys it holds (§5.4): a contact's as it said, a
    /// fellow member's as the roster shows (the current one or none).
    presence_key_taken: u32,
    /// A contact's pairing secret, for the mesh (§10.3) and paths (§12.2); none for a fellow
    /// group member who is not a contact.
    pairing_psk: Option<SecretBytes<32>>,
    /// The keys links are made with: a contact's link keys, newest first (§6.8); for a fellow
    /// group member, one per epoch held of each group shared (§9.4), the current ones first.
    link_psks: Vec<SecretBytes<32>>,
    /// Kept here because messages are let in or refused while locked too.
    permissions: Permissions,
    /// A fellow group member who is not a contact: the link carries group records only.
    group_only: bool,
    /// Until when (Unix ms) the user muted the contact.
    muted_until: i64,
}

impl ContactKeys {
    /// The keys of path requests to and from it (§12.2): a contact's pairing secret, a fellow
    /// member's group link keys.
    fn path_psks(&self) -> &[SecretBytes<32>] {
        match &self.pairing_psk {
            Some(psk) => std::slice::from_ref(psk),
            None => &self.link_psks,
        }
    }
}

impl LinkMaterial {
    fn load(account: &Account) -> Result<Self, NodeError> {
        let mut contacts: HashMap<ContactId, ContactKeys> = account
            .contact_directory()?
            .into_iter()
            .map(|entry| {
                let keys = ContactKeys {
                    identity: entry.identity,
                    static_kems: entry.static_kems,
                    own_key_taken: entry.own_key_taken,
                    roster_keys: Vec::new(),
                    presence_key: entry.presence_key,
                    presence_key_taken: entry.presence_key_taken,
                    pairing_psk: Some(entry.link_psk),
                    link_psks: entry.link_keys,
                    permissions: entry.permissions,
                    group_only: false,
                    muted_until: entry.muted_until,
                };
                (entry.id, keys)
            })
            .collect();
        // Fellow members who are not contacts, with the keys from the rosters (§9.4).
        let me = account.identity().public();
        let db = account.db();
        let mut groups = HashMap::new();
        for stored in db.member_groups()? {
            let mut members = Vec::new();
            for member in stored.roster.members().iter().filter(|m| m.identity != me) {
                if let Some(row) = db.contact_by_identity(&member.identity)?
                    && row.state != ContactState::Blocked
                {
                    members.push(row.id);
                }
            }
            groups.insert(
                stored.group_id,
                GroupKeys {
                    row: stored.row,
                    epoch: stored.epoch,
                    next_update: crate::mesh::update_keys(&stored.epoch_key, &stored.group_id, stored.epoch + 1).ok(),
                    file_tag_keys: std::iter::once((&stored.epoch_key, stored.roster.epoch))
                        .chain(stored.previous.iter().map(|(key, roster)| (key, roster.epoch)))
                        .filter_map(|(key, epoch)| crate::mesh::group_file_tag_key(key, &stored.group_id, epoch).ok())
                        .collect(),
                    mesh_tag_keys: std::iter::once((&stored.epoch_key, stored.roster.epoch))
                        .chain(stored.previous.iter().map(|(key, roster)| (key, roster.epoch)))
                        .filter_map(|(key, epoch)| crate::mesh::group_tag_key(key, &stored.group_id, epoch).ok())
                        .collect(),
                    members,
                    instant_voice: stored.allow_ptt,
                    muted_until: stored.muted_until,
                },
            );
            let epochs = std::iter::once((&stored.epoch_key, &stored.roster))
                .chain(stored.previous.iter().map(|(key, roster)| (key, roster)));
            for (key, roster) in epochs {
                for member in roster.members().iter().filter(|m| m.identity != me) {
                    let Some(row) = db.contact_by_identity(&member.identity)? else {
                        continue;
                    };
                    if !matches!(row.state, ContactState::Peer | ContactState::Former) {
                        continue;
                    }
                    let psk = group::link_psk(key, &stored.group_id, roster.epoch, &me, &member.identity)?;
                    let own_version = roster.member(&me).map_or(0, |m| m.key_version);
                    let listed_presence = roster
                        .member(&me)
                        .is_some_and(|m| m.presence_key.expose() == account.presence_key().expose());
                    let keys = contacts.entry(row.id).or_insert_with(|| ContactKeys {
                        identity: member.identity,
                        static_kems: vec![member.static_kem.clone()],
                        own_key_taken: 0,
                        roster_keys: Vec::new(),
                        presence_key: member.presence_key.clone(),
                        presence_key_taken: if listed_presence { account.presence_version() } else { 0 },
                        pairing_psk: None,
                        link_psks: Vec::new(),
                        permissions: Permissions {
                            messages: false,
                            ptt: false,
                            auto_download: false,
                        },
                        group_only: true,
                        muted_until: 0,
                    });
                    keys.link_psks.push(psk);
                    keys.roster_keys.push((member.static_kem.clone(), own_version));
                }
            }
        }
        let locals = account
            .static_keys()
            .map(|(version, key)| {
                let static_kem = DecapsulationKey::from_seed(key.seed().clone())?;
                Ok((
                    version,
                    LocalKeys {
                        identity: me,
                        static_kem,
                    },
                ))
            })
            .collect::<Result<_, NodeError>>()?;
        let (version, key, signature) = account.signed_static_key();
        Ok(Self {
            identity: account.identity().public(),
            locals,
            announcement: ChatMessage::StaticKey {
                version,
                key,
                signature,
            },
            presence_key: account.presence_key().clone(),
            presence_version: account.presence_version(),
            contacts,
            groups,
            channel: match db.tuned_channel()? {
                Some((summary, channel)) => {
                    Some(channels::TunedChannel::new(summary.row, summary.muted_until, channel)?)
                }
                None => None,
            },
            display_name: account.display_name().to_owned(),
        })
    }

    /// This device's side of links: its newest static key.
    fn local(&self) -> &LocalKeys {
        &self.locals[0].1
    }

    fn own_version(&self) -> u32 {
        self.locals[0].0
    }

    /// This device's static key of `version`, if kept; else the newest.
    fn own(&self, version: u32) -> &LocalKeys {
        self.locals
            .iter()
            .find(|(v, _)| *v == version)
            .map_or(self.local(), |(_, keys)| keys)
    }

    /// The keys to open a link to `contact` with, under its link key number `psk`: its static key
    /// as known here, and the version of this device's it took (§6.9).
    fn remote(&self, contact: ContactId, psk: usize) -> Option<(RemoteKeys, u32)> {
        let keys = self.contacts.get(&contact)?;
        let link_psk = keys.link_psks.get(psk)?.clone();
        let (static_kem, own) = match keys.roster_keys.get(psk) {
            Some((key, own)) if keys.group_only => (key.clone(), *own),
            _ => (keys.static_kems.first()?.clone(), keys.own_key_taken),
        };
        let remote = RemoteKeys {
            identity: keys.identity,
            static_kem,
            link_psk,
        };
        Some((remote, own))
    }

    /// What a link `contact` opened under its link key number `psk` may have been made with: for
    /// a contact, each of this device's static keys it may know (newest first) with each of its
    /// own this device knows; for a fellow member, those of the roster.
    fn answers(&self, contact: ContactId, psk: usize) -> Vec<(RemoteKeys, u32)> {
        let Some(keys) = self.contacts.get(&contact) else {
            return Vec::new();
        };
        if keys.group_only {
            return self.remote(contact, psk).into_iter().collect();
        }
        let Some(link_psk) = keys.link_psks.get(psk) else {
            return Vec::new();
        };
        let owns = self.locals.iter().map(|(v, _)| *v).filter(|v| *v >= keys.own_key_taken);
        owns.flat_map(|own| {
            keys.static_kems.iter().map(move |static_kem| {
                let remote = RemoteKeys {
                    identity: keys.identity,
                    static_kem: static_kem.clone(),
                    link_psk: link_psk.clone(),
                };
                (remote, own)
            })
        })
        .collect()
    }
}

/// Link keys a device keeps for each contact (§6.8).
const MAX_LINK_KEYS: usize = 4;

/// Silence after which a device checks a link with a ping (§6.7).
pub const LINK_IDLE_SECS: u64 = 30;
/// How long a record that calls for an answer (a message, a ping, a move request) may go
/// unanswered before the link counts as lost (§6.7).
pub const LINK_ANSWER_SECS: u64 = 15;

/// Chunks asked for at once, and the number still outstanding below which more are asked for, so
/// the next batch is on its way before the current one ends (rust/airchat-protocol/docs/protocol.md §8.4).
const REQUEST_BATCH: u64 = 16;
const REQUEST_LOW_WATER: u64 = 8;
const MEDIA_REQUEST_BATCH: u64 = 2;
const MEDIA_REQUEST_LOW_WATER: u64 = 1;
/// How long to wait before asking again a sender that could not serve a file just then.
const NOT_NOW_RETRY_SECS: u64 = 30;
/// A device that does not open links to a peer opens one itself when none came up after it saw the
/// peer this long; sightings further apart than `SIGHTING_GAP_SECS` start the wait again (§5.2).
const OPENER_WAIT_SECS: u64 = 60;
const SIGHTING_GAP_SECS: u64 = 120;
/// Two links to one contact up this close together, opened from both sides, are a race (§5.2).
const RACE_SECS: u64 = 10;
/// How often a group call looks for a participant gone without leaving (§9.6).
const CALL_HEAL_SECS: u64 = 10;
/// Progress is reported every this many chunks (256 KiB).
const PROGRESS_EVERY: u64 = 8;

/// An outgoing file being written.
struct Import {
    contact: ContactId,
    /// What does not fill a chunk yet.
    buffer: Zeroizing<Vec<u8>>,
    written: u64,
    hasher: Sha256Stream,
}

/// An incoming file being fetched (rust/airchat-protocol/docs/protocol.md §8.4).
struct Download {
    contact: ContactId,
    file_id: MessageId,
    size: u64,
    sha256: [u8; 32],
    stored: u64,
    /// Chunks asked for so far, as an exclusive index.
    requested_until: u64,
    hasher: Sha256Stream,
    /// When the sender said it could not serve the file just then; nothing is asked meanwhile.
    /// `Some(0)` until the next tick notes the time.
    not_now_since: Option<u64>,
}

/// What a node knows about whether the other end of a link is still there.
#[derive(Default)]
struct Liveness {
    /// When a record last arrived; set by the first tick after the link came up.
    heard_at: Option<u64>,
    /// A record that calls for an answer went out after the last one arrived...
    expecting: bool,
    /// ...as first noticed by a tick.
    expecting_since: Option<u64>,
}

/// Lookup tables for recognising contacts, valid for one epoch.
struct Directory {
    epoch: u64,
    presence: HashMap<PresenceToken, ContactId>,
    /// Keys of the tags each contact puts on links it opens to this device, with the number of
    /// the link key they come from.
    tag_keys: Vec<((ContactId, usize), TagKey)>,
}

pub struct Node {
    store: Store,
    keys: LinkMaterial,
    connections: HashMap<ConnectionId, ConnectionState>,
    /// The established link per contact (the newest, if several were opened).
    links: HashMap<ContactId, ConnectionId>,
    /// Connections over a transport for discovery and setting up Wi-Fi only (BLE, §7.3): links on
    /// them carry liveness and moving the link (§8.3), nothing else.
    setup_only: HashSet<ConnectionId>,
    directory: Option<Directory>,
    /// Kept across directory rebuilds so a tag stays single-use for its whole lifetime.
    tags: TagChecker,
    /// Liveness of each established link (§6.7).
    liveness: HashMap<ConnectionId, Liveness>,
    /// When each link handshake under way began; one the other end stops answering is given up.
    handshakes: HashMap<ConnectionId, u64>,
    /// Outgoing files being written, by message row.
    imports: HashMap<i64, Import>,
    /// Incoming files being fetched, by message row.
    downloads: HashMap<i64, Download>,
    /// Files to offer and downloads to resume over the links up at the next tick (after opening
    /// or unlocking the account, whose actions the platform does not act on).
    catch_up: bool,
    /// Calls and push-to-talk.
    media: Media,
    /// This device's build attestation (§6.10).
    attestation: attestation::OwnAttestation,
    /// Connections this node closed while the other side may still be sending (a replaced link, a
    /// finished pairing). Frames arriving on them are dropped instead of read as new connections.
    closing: HashSet<ConnectionId>,
    /// Set while the user has "Add nearby" open; only then are Nearby Pairing requests accepted.
    pairing_beacon: Option<PairingBeacon>,
    /// QR codes this device shows, with their expiry (Unix seconds).
    invites: Vec<(Invite, u64)>,
    group_traffic: groups::GroupTraffic,
    /// Links opened to each contact since the last one came up; picks the link key to try.
    link_attempts: HashMap<ContactId, usize>,
    /// When static keys were last looked after (§6.9).
    static_keys_checked: Option<u64>,
    /// Requests for this device's owner answered lately, by token, and when (§4.8).
    answered_requests: HashMap<crate::discovery::RequestToken, u64>,
    /// Whether the user lets others ask to be added (C-4).
    accept_requests: bool,
    /// When outgoing messages were last checked for having been tried a day (§10.5).
    tries_checked: u64,
    /// Proposals to add someone to a conversation, and members added for a call (M-3).
    additions: additions::Additions,
    /// Members asked for a group file that did not have it.
    tried: group_files::Tried,
    /// Members of the tuned walkie-talkie channel around this device.
    channel_peers: channels::ChannelPeers,
    /// Envelopes passed on, and links to other AirChat devices (§10).
    mesh: mesh::Mesh,
    /// Paths through Air Providers: carried for others, and this device's own (§12).
    paths: paths::Paths,
    /// One-time prekeys for texts in envelopes, this device's own and its contacts' (§10.7).
    prekeys: prekeys::Prekeys,
    /// Files through the mesh: this device's parts going out, and files put together (§10.8).
    mesh_files: mesh_files::MeshFiles,
    /// Group updates put together from the mesh (§10.9).
    mesh_updates: mesh_updates::MeshUpdates,
    /// The link whose record is being handled (its session is out of the table meanwhile), and
    /// the records for it sealed later, once the session is back.
    handling: Option<(ConnectionId, Vec<(ChatMessage, bool)>)>,
    /// Peers this device does not open links to, seen with no link up: when first and last
    /// (§5.2).
    waiting: HashMap<ContactId, (u64, u64)>,
    /// Links to contacts this device is opening.
    opening: HashSet<ConnectionId>,
    /// When a group call last looked for a participant gone without leaving.
    call_healed_at: u64,
    /// When each link to a contact came up, and whether this device opened it (for races, §5.2).
    link_starts: HashMap<ConnectionId, (u64, bool)>,
}

impl Node {
    /// Starts a node on a freshly opened account. What arrived while the app was last locked is moved
    /// into the database first: the process may have been killed before it was unlocked again.
    pub fn new(account: Account) -> Result<Self, NodeError> {
        let (_, group_records) = account.absorb_inbox()?;
        let mut node = Self {
            keys: LinkMaterial::load(&account)?,
            store: Store::Open(Box::new(account)),
            connections: HashMap::new(),
            links: HashMap::new(),
            setup_only: HashSet::new(),
            directory: None,
            tags: TagChecker::default(),
            closing: HashSet::new(),
            liveness: HashMap::new(),
            handshakes: HashMap::new(),
            imports: HashMap::new(),
            downloads: HashMap::new(),
            catch_up: true,
            media: Media::default(),
            attestation: attestation::OwnAttestation::default(),
            pairing_beacon: None,
            invites: Vec::new(),
            group_traffic: groups::GroupTraffic::default(),
            link_attempts: HashMap::new(),
            static_keys_checked: None,
            answered_requests: HashMap::new(),
            accept_requests: false,
            tries_checked: 0,
            additions: additions::Additions::default(),
            tried: group_files::Tried::default(),
            channel_peers: channels::ChannelPeers::new()?,
            mesh: mesh::Mesh::new()?,
            paths: paths::Paths::default(),
            prekeys: prekeys::Prekeys::default(),
            mesh_files: mesh_files::MeshFiles::default(),
            mesh_updates: mesh_updates::MeshUpdates::default(),
            handling: None,
            waiting: HashMap::new(),
            opening: HashSet::new(),
            link_starts: HashMap::new(),
            call_healed_at: 0,
        };
        if let Store::Open(account) = &node.store {
            node.prekeys.reload(account);
        }
        // Nothing is linked yet, and the platform reads the rest from the database.
        node.take_inboxed(group_records);
        node.account()?.clear_inbox()?;
        node.resume_mesh_files(now_secs());
        Ok(node)
    }

    pub fn account(&self) -> Result<&Account, NodeError> {
        match &self.store {
            Store::Open(account) => Ok(account),
            Store::Sealed(_) => Err(NodeError::Sealed),
        }
    }

    pub fn account_mut(&mut self) -> Result<&mut Account, NodeError> {
        match &mut self.store {
            Store::Open(account) => Ok(account),
            Store::Sealed(_) => Err(NodeError::Sealed),
        }
    }

    pub fn is_sealed(&self) -> bool {
        matches!(self.store, Store::Sealed(_))
    }

    // Locking.

    /// Locks the node: closes the database, wipes the master key and ends pairing. Links stay up.
    pub fn seal(&mut self) -> Vec<Action> {
        let Store::Open(account) = &self.store else {
            return Vec::new();
        };
        let pending = account
            .all_undelivered()
            .unwrap_or_default()
            .into_iter()
            // File offers wait for the unlock; texts go out while locked.
            .filter(|m| m.attachment.is_none())
            .map(|m| Pending {
                contact: m.contact_id,
                id: m.message_id,
                sent_at_ms: m.sent_at_ms,
                text: Zeroizing::new(m.body),
            })
            .collect();
        let inbox = InboxWriter::new(account.inbox_path(), account.inbox_public_key().clone());
        self.pairing_beacon = None;
        self.invites.clear();
        let actions = self.abandon_pairings(|_| true);
        let actions = self.closing_on(actions);
        // Unfinished imports are cleared when the account opens next; downloads resume after unlocking.
        self.imports.clear();
        self.downloads.clear();
        self.mesh_files.sealed();
        // Dropping the account closes the database and wipes its keys.
        self.store = Store::Sealed(Box::new(Sealed {
            inbox,
            pending,
            stored: HashSet::new(),
            group_stored: HashSet::new(),
        }));
        actions
    }

    /// Unlocks a sealed node with the account the user just opened: moves what arrived while
    /// locked into the database. Returns the messages that arrived.
    pub fn unseal(&mut self, account: Account) -> Result<Vec<Action>, NodeError> {
        if account.identity().public() != self.keys.identity {
            return Err(NodeError::WrongAccount);
        }
        let (received, group_records) = account.absorb_inbox()?;
        self.keys = LinkMaterial::load(&account)?;
        self.prekeys.save(&account);
        self.prekeys.reload(&account);
        self.directory = None;
        self.store = Store::Open(Box::new(account));
        self.catch_up = true;
        // Acknowledgements of group messages were not taken in while locked: send them again.
        self.group_traffic.unsealed();
        let mut actions: Vec<Action> = received
            .into_iter()
            .map(|message| Action::MessageReceived { message })
            .collect();
        actions.extend(self.take_inboxed(group_records));
        self.account()?.clear_inbox()?;
        actions.extend(self.resume_mesh_files(now_secs()));
        Ok(actions)
    }

    // Pairing.

    /// Opens "Add nearby": returns the beacon to announce and to show on screen.
    pub fn open_pairing(&mut self) -> Result<PairingBeacon, NodeError> {
        self.account()?;
        let beacon = PairingBeacon::new()?;
        self.pairing_beacon = Some(beacon);
        Ok(beacon)
    }

    /// Closes "Add nearby" and abandons Nearby Pairings that have not finished.
    pub fn close_pairing(&mut self) -> Vec<Action> {
        self.pairing_beacon = None;
        let actions = self.abandon_pairings(|pairing| pairing.mode() == Mode::Nearby);
        self.closing_on(actions)
    }

    fn abandon_pairings(&mut self, which: impl Fn(&Pairing) -> bool) -> Vec<Action> {
        let open: Vec<ConnectionId> = self
            .connections
            .iter()
            .filter(|(_, state)| matches!(state, ConnectionState::Pairing(p) if which(p)))
            .map(|(id, _)| *id)
            .collect();
        open.into_iter().flat_map(|id| self.reject_pairing(id)).collect()
    }

    /// A new QR invite; returns the text to show as a QR code.
    pub fn create_invite(&mut self, now_secs: u64) -> Result<String, NodeError> {
        self.account()?;
        self.invites.retain(|(_, expires)| *expires > now_secs);
        if self.invites.len() >= MAX_INVITES {
            self.invites.remove(0);
        }
        let invite = Invite::new(self.keys.identity)?;
        let text = invite.qr_text().to_string();
        self.invites.push((invite, now_secs + INVITE_LIFETIME_SECS));
        Ok(text)
    }

    /// The user picked a nearby device in "Add nearby"; `connection` is a new connection to it.
    pub fn pair_nearby(&mut self, connection: ConnectionId) -> Result<Vec<Action>, NodeError> {
        self.account()?;
        let (pairing, message) = Pairing::start_nearby()?;
        self.open(connection, ConnectionState::Pairing(Box::new(pairing)), message)
    }

    /// The user scanned a QR code; `connection` is a new connection to the device showing it.
    pub fn pair_with_invite(&mut self, connection: ConnectionId, qr_text: &str) -> Result<Vec<Action>, NodeError> {
        self.account()?;
        let invite = ScannedInvite::parse(qr_text)?;
        let (pairing, message) = Pairing::start_invite(&invite)?;
        self.open(connection, ConnectionState::Pairing(Box::new(pairing)), message)
    }

    pub fn confirm_pairing(&mut self, connection: ConnectionId) -> Vec<Action> {
        let actions = self.confirm(connection);
        self.closing_on(actions)
    }

    fn confirm(&mut self, connection: ConnectionId) -> Vec<Action> {
        let Some(ConnectionState::Pairing(mut pairing)) = self.connections.remove(&connection) else {
            return Vec::new();
        };
        let Store::Open(account) = &self.store else {
            return failed(connection, Failure::NotAccepting);
        };
        match pairing.confirm(&account.profile()) {
            Ok(events) => self.pairing_events(connection, pairing, events),
            Err(error) => failed(connection, error.into()),
        }
    }

    pub fn reject_pairing(&mut self, connection: ConnectionId) -> Vec<Action> {
        let Some(ConnectionState::Pairing(mut pairing)) = self.connections.remove(&connection) else {
            return Vec::new();
        };
        let mut actions: Vec<Action> = pairing
            .reject()
            .map(|bytes| Action::Send { connection, bytes })
            .into_iter()
            .collect();
        actions.push(Action::Close { connection });
        self.closing_on(actions)
    }

    // Contacts and presence.

    /// What to announce so contacts recognise this device (rust/airchat-protocol/docs/protocol.md §5.2).
    pub fn presence_token(&self, now_secs: u64) -> PresenceToken {
        presence_token(&self.keys.presence_key, epoch_at(now_secs))
    }

    /// Whether `token`, seen on the network, belongs to a contact.
    pub fn recognize_presence(&mut self, token: &PresenceToken, now_secs: u64) -> Option<Recognized> {
        let contact = *self.directory(now_secs).presence.get(token)?;
        let keys = self.keys.contacts.get(&contact)?;
        // One that does not hold this device's presence key cannot see it: this device opens.
        let unseen = keys.presence_key_taken < self.keys.presence_version;
        let theirs = keys.identity;
        let handshaking = self.connections.values().any(|state| {
            matches!(state, ConnectionState::Initiating { contact: c, .. } | ConnectionState::Responding { contact: c, .. } if *c == contact)
        });
        let link = self.links.get(&contact).copied();
        let named = self.keys.identity.as_bytes() < theirs.as_bytes() || unseen;
        Some(Recognized {
            contact,
            opener: self.opens(contact, named, link.is_some() || handshaking, now_secs),
            link,
            handshaking,
        })
    }

    /// Whether this device opens a link to `contact`, seen now: if the rule names it (§5.2,
    /// `named`), or if no link came up (`settled` means one is up or being set up) after it saw
    /// the contact for a minute: the one named may not be able to reach it.
    fn opens(&mut self, contact: ContactId, named: bool, settled: bool, now_secs: u64) -> bool {
        if named || settled {
            self.waiting.remove(&contact);
            return named;
        }
        let (first, last) = self.waiting.entry(contact).or_insert((now_secs, now_secs));
        if now_secs.saturating_sub(*last) > SIGHTING_GAP_SECS {
            *first = now_secs;
        }
        *last = now_secs;
        now_secs.saturating_sub(*first) >= OPENER_WAIT_SECS
    }

    /// Opens a link session with a contact on a new outgoing connection.
    pub fn connect_contact(
        &mut self,
        connection: ConnectionId,
        contact: ContactId,
        now_secs: u64,
    ) -> Result<Vec<Action>, NodeError> {
        if self.connections.contains_key(&connection) {
            return Err(NodeError::ConnectionInUse(connection));
        }
        if mesh::is_mesh_peer(contact) {
            return self.connect_mesh_peer(connection, contact, now_secs);
        }
        if channels::is_channel_peer(contact) {
            return self.connect_channel_peer(connection, contact, now_secs);
        }
        // A fellow group member may hold other epochs than this device: each attempt tries the
        // next link key, so one both hold comes up (§9.4).
        let count = self
            .keys
            .contacts
            .get(&contact)
            .map_or(0, |keys| keys.link_psks.len())
            .max(1);
        let attempt = self.link_attempts.entry(contact).or_default();
        let psk = *attempt % count;
        *attempt = attempt.wrapping_add(1);
        let (remote, own_key) = self.keys.remote(contact, psk).ok_or(NodeError::UnknownContact)?;
        let tag = TagKey::derive(&remote.link_psk, &self.keys.identity, &remote.identity)?
            .tag(epoch_at(now_secs), &random::array()?);
        let (initiator, message) = Initiator::start(self.keys.own(own_key), &remote, &tag)?;
        let state = ConnectionState::Initiating {
            contact,
            link_key: remote.link_psk,
            own_key,
            initiator: Box::new(initiator),
        };
        let actions = self.open(connection, state, message)?;
        self.handshakes.insert(connection, now_secs);
        Ok(actions)
    }

    pub fn is_linked(&self, contact: ContactId) -> bool {
        self.links.contains_key(&contact)
    }

    pub fn linked_contacts(&self) -> Vec<ContactId> {
        self.links.keys().copied().collect()
    }

    /// Deletes a contact's keys, and its conversation unless `keep_history`, and ends any link
    /// with it (requirement C-6).
    pub fn delete_contact(&mut self, contact: ContactId, keep_history: bool) -> Result<Vec<Action>, NodeError> {
        self.account()?.delete_contact(contact, keep_history)?;
        self.imports.retain(|_, import| import.contact != contact);
        self.downloads.retain(|_, download| download.contact != contact);
        let mut actions = self.end_link(contact);
        self.refresh_contacts();
        // It knows this device's presence key: a new one, so it no longer recognises it (§5.4).
        actions.extend(self.rotate_presence_key());
        Ok(self.closing_on(actions))
    }

    /// Blocks a contact (requirement C-7): the link ends, and from now on their beacons are not
    /// recognised and their connections fail like a stranger's, so to them this device is away.
    /// Nothing is sent to them; what was queued for them waits until they are unblocked.
    pub fn block_contact(&mut self, contact: ContactId) -> Result<Vec<Action>, NodeError> {
        if !self.account()?.set_blocked(contact, true)? {
            return Err(NodeError::UnknownContact);
        }
        self.downloads.retain(|_, download| download.contact != contact);
        let mut actions = self.end_link(contact);
        self.refresh_contacts();
        actions.extend(self.rotate_presence_key());
        Ok(self.closing_on(actions))
    }

    pub fn unblock_contact(&mut self, contact: ContactId) -> Result<(), NodeError> {
        if !self.account()?.set_blocked(contact, false)? {
            return Err(NodeError::UnknownContact);
        }
        self.refresh_contacts();
        Ok(())
    }

    /// What a contact may do (requirement C-5).
    pub fn set_permissions(&mut self, contact: ContactId, permissions: Permissions) -> Result<(), NodeError> {
        if !self.account()?.set_permissions(contact, permissions)? {
            return Err(NodeError::UnknownContact);
        }
        self.refresh_contacts();
        Ok(())
    }

    /// Whether `contact` is a contact this device talks with, not a blocked or former one or a
    /// fellow group member only.
    fn is_contact(&self, contact: ContactId) -> bool {
        self.keys.contacts.get(&contact).is_some_and(|keys| !keys.group_only)
    }

    /// Whether the contact may send messages and files; refused ones are answered as such.
    fn accepts_messages_from(&self, contact: ContactId) -> bool {
        self.keys
            .contacts
            .get(&contact)
            .is_some_and(|keys| keys.permissions.messages)
    }

    // Messages.

    /// Stores a message and sends it if a link to the contact is up; otherwise it waits for one.
    pub fn send_message(&mut self, contact: ContactId, text: &str) -> Result<(StoredMessage, Vec<Action>), NodeError> {
        chat::check_text(text)?;
        let id = random::array()?;
        let Store::Open(account) = &self.store else {
            return Err(NodeError::Sealed);
        };
        // Not to blocked or former contacts: nothing is ever sent to them.
        if !self.is_contact(contact) {
            return Err(NodeError::UnknownContact);
        }
        let mut message = account.queue_message(contact, &id, text)?;
        let mut actions = Vec::new();
        if let Some(connection) = self.data_link(contact)
            && let Some(ConnectionState::Linked { session, .. }) = self.connections.get_mut(&connection)
        {
            let record = seal_chat(
                session,
                &text_message(message.message_id, message.sent_at_ms, &message.body),
            )?;
            actions.push(Action::Send {
                connection,
                bytes: record,
            });
            if let Some(sent) = account.advance_status(contact, &id, MessageStatus::Sent)? {
                message = sent;
            }
        }
        if let Some(Action::Send { connection, .. }) = actions.first() {
            self.expect_answer(*connection);
        } else {
            // No Wi-Fi link to the contact: through the mesh (§10.5), if there is one around.
            let record = outgoing_record(&message);
            let sends = self.mesh_send_contact(contact, &record, try_expires(&message), now_secs());
            if sends.is_empty() {
                if self.links.contains_key(&contact) {
                    // Linked over Bluetooth only: it waits for Wi-Fi.
                    actions.push(Action::WaitingForWifi { contact });
                }
            } else {
                actions.extend(self.mesh_sends(sends, None));
                if let Some(sent) = self
                    .account()?
                    .advance_status(contact, &message.message_id, MessageStatus::Sent)?
                {
                    message = sent;
                }
            }
        }
        Ok((message, actions))
    }

    pub fn messages(&self, contact: ContactId) -> Result<Vec<StoredMessage>, NodeError> {
        Ok(self.account()?.messages(contact)?)
    }

    /// For the chat list: each conversation with a contact, its latest message, and how many of
    /// the contact's messages are unread.
    pub fn contact_previews(&self) -> Result<Vec<(ContactId, Option<StoredMessage>, u32)>, NodeError> {
        Ok(self.account()?.db().contact_previews()?)
    }

    /// The user has read the conversation with `contact` up to its latest message.
    pub fn mark_contact_read(&self, contact: ContactId) -> Result<(), NodeError> {
        Ok(self.account()?.db().mark_contact_read(contact)?)
    }

    /// Tries a message given up again, as the user asked (§10.5): queued afresh for a day, and sent
    /// at once over the link to the contact if one is up, else into the mesh.
    pub fn try_message_again(&mut self, id: i64) -> Result<Vec<Action>, NodeError> {
        let Store::Open(account) = &self.store else {
            return Err(NodeError::Sealed);
        };
        let message = account.db().try_again(id, now_ms())?.ok_or(NodeError::NoSuchMessage)?;
        let contact = message.contact_id;
        let mut actions = vec![Action::MessageUpdated {
            message: message.clone(),
        }];
        // Never to blocked or former contacts; it is given up again after a day.
        if !self.is_contact(contact) {
            return Ok(actions);
        }
        let record = outgoing_record(&message);
        let sent = if let Some(connection) = self.data_link(contact) {
            actions.extend(self.send_records(connection, vec![record]));
            true
        } else {
            let now = now_secs();
            let sends = match message.attachment {
                Some(_) => self.mesh_send_file(contact, &message, now),
                None => self.mesh_send_contact(contact, &record, try_expires(&message), now),
            };
            let sent = !sends.is_empty();
            actions.extend(self.mesh_sends(sends, None));
            sent
        };
        if sent
            && let Some(sent) = self
                .account()?
                .advance_status(contact, &message.message_id, MessageStatus::Sent)?
        {
            actions.push(Action::MessageUpdated { message: sent });
        }
        Ok(actions)
    }

    /// Gives up the outgoing messages tried for a day without an acknowledgement, once a minute.
    fn tries_tick(&mut self, now_secs: u64) -> Vec<Action> {
        if now_secs.saturating_sub(self.tries_checked) < 60 {
            return Vec::new();
        }
        self.tries_checked = now_secs;
        let Store::Open(account) = &self.store else {
            return Vec::new();
        };
        let cutoff = i64::try_from(now_secs).unwrap_or(i64::MAX).saturating_mul(1000) - TRY_MS;
        account
            .db()
            .give_up_undelivered(cutoff)
            .unwrap_or_default()
            .into_iter()
            .map(|message| Action::MessageUpdated { message })
            .collect()
    }

    // Files (§8.4).

    /// Starts an outgoing file; write its content with [`Node::write_file`], then
    /// [`Node::finish_file`]. Returns the file (its message's row id).
    pub fn begin_file(
        &mut self,
        contact: ContactId,
        name: &str,
        mime: &str,
        thumbnail: Option<Vec<u8>>,
    ) -> Result<i64, NodeError> {
        let meta = FileMeta {
            name: name.to_owned(),
            mime: mime.to_owned(),
            size: 0,
            sha256: [0; 32],
            thumbnail,
        };
        chat::check_file(&meta)?;
        if !self.is_contact(contact) {
            return Err(NodeError::UnknownContact);
        }
        let id = random::array()?;
        let file = self
            .account()?
            .begin_file(contact, &id, name, mime, meta.thumbnail.as_deref())?;
        self.imports.insert(
            file,
            Import {
                contact,
                buffer: Zeroizing::new(Vec::with_capacity(CHUNK_LEN)),
                written: 0,
                hasher: Sha256Stream::default(),
            },
        );
        Ok(file)
    }

    /// Adds the next part of an outgoing file's content; parts may have any length. After an error
    /// the file is gone.
    pub fn write_file(&mut self, file: i64, data: &[u8]) -> Result<(), NodeError> {
        let Store::Open(account) = &self.store else {
            return Err(NodeError::Sealed);
        };
        let import = self.imports.get_mut(&file).ok_or(NodeError::NoSuchFile)?;
        let written = (|| {
            if import.written + (import.buffer.len() + data.len()) as u64 > MAX_FILE_SIZE {
                return Err(ChatError::InvalidFile.into());
            }
            import.buffer.extend_from_slice(data);
            while import.buffer.len() >= CHUNK_LEN {
                let chunk = Zeroizing::new(import.buffer.drain(..CHUNK_LEN).collect::<Vec<u8>>());
                account.write_file_chunk(file, import.written, import.written / CHUNK_LEN as u64, &chunk)?;
                import.hasher.update(&chunk);
                import.written += CHUNK_LEN as u64;
            }
            Ok::<_, NodeError>(())
        })();
        if written.is_err() {
            self.imports.remove(&file);
            let _ = account.discard_file(file);
        }
        written
    }

    /// Completes an outgoing file: it joins the conversation and its offer goes out, now if linked.
    pub fn finish_file(&mut self, file: i64) -> Result<(StoredMessage, Vec<Action>), NodeError> {
        let Store::Open(account) = &self.store else {
            return Err(NodeError::Sealed);
        };
        let mut import = self.imports.remove(&file).ok_or(NodeError::NoSuchFile)?;
        let finished = (|| {
            if !import.buffer.is_empty() {
                account.write_file_chunk(file, import.written, import.written / CHUNK_LEN as u64, &import.buffer)?;
                import.hasher.update(&import.buffer);
                import.written += import.buffer.len() as u64;
            }
            account.finish_file(file, import.written, &import.hasher.finish())
        })();
        let mut message = finished.inspect_err(|_| {
            let _ = account.discard_file(file);
        })?;
        let contact = import.contact;
        let mut actions = Vec::new();
        if let Some(connection) = self.data_link(contact)
            && let Some(ConnectionState::Linked { session, .. }) = self.connections.get_mut(&connection)
        {
            actions.push(Action::Send {
                connection,
                bytes: seal_chat(session, &outgoing_record(&message))?,
            });
            if let Some(sent) = account.advance_status(contact, &message.message_id, MessageStatus::Sent)? {
                message = sent;
            }
        }
        if let Some(Action::Send { connection, .. }) = actions.first() {
            self.expect_answer(*connection);
            return Ok((message, actions));
        }
        // No Wi-Fi link to the contact: through the mesh (§10.8), if there is one around.
        let sends = self.mesh_send_file(contact, &message, now_secs());
        if sends.is_empty() {
            if self.links.contains_key(&contact) {
                // Linked over Bluetooth only: it waits for Wi-Fi.
                actions.push(Action::WaitingForWifi { contact });
            }
        } else {
            actions.extend(self.mesh_sends(sends, None));
            if let Some(sent) = self
                .account()?
                .advance_status(contact, &message.message_id, MessageStatus::Sent)?
            {
                message = sent;
            }
        }
        Ok((message, actions))
    }

    /// Gives up an outgoing file before it was finished.
    pub fn abort_file(&mut self, file: i64) -> Result<(), NodeError> {
        if self.imports.remove(&file).is_some() {
            self.account()?.discard_file(file)?;
        }
        Ok(())
    }

    /// Starts (or retries) fetching an incoming file; it goes on whenever the sender is linked.
    pub fn download(&mut self, file: i64) -> Result<Vec<Action>, NodeError> {
        let account = self.account()?;
        let message = account.message(file)?.ok_or(NodeError::NoSuchFile)?;
        let attachment = message
            .attachment
            .as_ref()
            .filter(|_| !message.outgoing)
            .ok_or(NodeError::NoSuchFile)?;
        let updated = match attachment.state {
            AttachmentState::Complete | AttachmentState::Downloading => return Ok(Vec::new()),
            AttachmentState::Importing => return Err(NodeError::NoSuchFile),
            AttachmentState::Failed | AttachmentState::Gone => {
                account.clear_file(file)?;
                account.update_attachment(file, 0, AttachmentState::Downloading)?
            }
            AttachmentState::Offered => {
                account.update_attachment(file, attachment.stored, AttachmentState::Downloading)?
            }
        };
        let mut actions = vec![Action::MessageUpdated { message: updated }];
        if let Some(connection) = self.file_link(message.contact_id) {
            let (resumed, requests) = self.resume_downloads_from(message.contact_id);
            actions.extend(resumed);
            actions.extend(self.send_records(connection, requests));
        }
        Ok(actions)
    }

    /// Bytes `offset..offset + len` of a file stored on this device, to show or export it.
    pub fn read_file(&self, file: i64, offset: u64, len: usize) -> Result<Zeroizing<Vec<u8>>, NodeError> {
        Ok(self.account()?.read_file(file, offset, len)?)
    }

    /// Offers the files that waited for the account to unlock while linked to `contact` (offers
    /// are not sent while locked).
    fn offer_waiting_files(&mut self, contact: ContactId, connection: ConnectionId) -> Vec<Action> {
        let Store::Open(account) = &self.store else {
            return Vec::new();
        };
        let waiting: Vec<StoredMessage> = account
            .undelivered(contact)
            .unwrap_or_default()
            .into_iter()
            .filter(|m| m.attachment.is_some() && m.status == MessageStatus::Queued)
            .collect();
        let mut actions = self.send_records(connection, waiting.iter().map(outgoing_record).collect());
        if let Store::Open(account) = &self.store
            && !actions.is_empty()
        {
            for message in waiting {
                if let Ok(Some(sent)) = account.advance_status(contact, &message.message_id, MessageStatus::Sent) {
                    actions.push(Action::MessageUpdated { message: sent });
                }
            }
        }
        actions
    }

    /// Goes on with every file being fetched from `contact`. Returns actions, and the requests to
    /// send on the link.
    fn resume_downloads_from(&mut self, contact: ContactId) -> (Vec<Action>, Vec<ChatMessage>) {
        let Store::Open(account) = &self.store else {
            return (Vec::new(), Vec::new());
        };
        let mut files = Vec::new();
        for message in account.downloading(contact).unwrap_or_default() {
            let Some(attachment) = message.attachment else {
                continue;
            };
            let file = message.id;
            files.push(file);
            if let Some(download) = self.downloads.get_mut(&file) {
                // Requests made over an earlier link went with it.
                download.requested_until = chunk_count(download.stored);
                download.not_now_since = None;
                continue;
            }
            let (hasher, stored) = stored_hash(account, file, attachment.size, attachment.stored);
            self.downloads.insert(
                file,
                Download {
                    contact,
                    file_id: message.message_id,
                    size: attachment.size,
                    sha256: attachment.sha256,
                    stored,
                    requested_until: chunk_count(stored),
                    hasher,
                    not_now_since: None,
                },
            );
        }
        let mut actions = Vec::new();
        let mut requests = Vec::new();
        for file in files {
            let (done, request) = self.advance_download(file);
            actions.extend(done);
            requests.extend(request);
        }
        (actions, requests)
    }

    /// Finishes a download that has everything, or asks for more chunks when few are outstanding.
    fn advance_download(&mut self, file: i64) -> (Vec<Action>, Option<ChatMessage>) {
        let Some(download) = self.downloads.get_mut(&file) else {
            return (Vec::new(), None);
        };
        if download.stored == download.size {
            return (self.complete_download(file), None);
        }
        // During a call or talk with the sender, few chunks are on their way at once, so its audio
        // is not stuck behind them (on Bluetooth one chunk takes about 0.2 s).
        let (batch, low_water) = if self.media.active_with(download.contact) {
            (MEDIA_REQUEST_BATCH, MEDIA_REQUEST_LOW_WATER)
        } else {
            (REQUEST_BATCH, REQUEST_LOW_WATER)
        };
        let next = chunk_count(download.stored);
        let total = chunk_count(download.size);
        let asked = download.requested_until.max(next);
        if download.not_now_since.is_some() || asked >= total || asked - next >= low_water {
            return (Vec::new(), None);
        }
        let count = (total - asked).min(batch);
        download.requested_until = asked + count;
        let request = ChatMessage::ChunkRequest {
            id: download.file_id,
            first: asked,
            count: u16::try_from(count).expect("at most a batch"),
        };
        (Vec::new(), Some(request))
    }

    /// Checks a fully fetched file against its offer.
    fn complete_download(&mut self, file: i64) -> Vec<Action> {
        let Some(download) = self.downloads.remove(&file) else {
            return Vec::new();
        };
        let Store::Open(account) = &self.store else {
            return Vec::new();
        };
        let intact =
            download.hasher.finish() == download.sha256 && (download.size == 0 || account.sync_file(file).is_ok());
        let updated = if intact {
            attachment_updated(account, file, download.size, AttachmentState::Complete)
        } else {
            let _ = account.clear_file(file);
            attachment_updated(account, file, 0, AttachmentState::Failed)
        };
        self.mesh_file_done(file, intact);
        updated.into_iter().collect()
    }

    /// Sends `records` on the link over `connection`, which awaits answers to them.
    fn send_records(&mut self, connection: ConnectionId, records: Vec<ChatMessage>) -> Vec<Action> {
        self.seal_on(connection, records, true)
    }

    /// Seals `records` on the link over `connection`; with `expect`, the link awaits an answer.
    fn seal_on(&mut self, connection: ConnectionId, records: Vec<ChatMessage>, expect: bool) -> Vec<Action> {
        // The link whose record is being handled: its records are sealed once its session is back.
        if let Some((handled, deferred)) = &mut self.handling
            && *handled == connection
        {
            deferred.extend(records.into_iter().map(|record| (record, expect)));
            return Vec::new();
        }
        let Some(ConnectionState::Linked { session, .. }) = self.connections.get_mut(&connection) else {
            return Vec::new();
        };
        let actions: Vec<Action> = records
            .iter()
            .filter_map(|record| seal_chat(session, record).ok())
            .map(|bytes| Action::Send { connection, bytes })
            .collect();
        if expect && !actions.is_empty() {
            self.expect_answer(connection);
        }
        actions
    }

    /// Sends records to a contact over its link, if one that carries data is up; otherwise they
    /// are dropped.
    fn send_to(&mut self, contact: ContactId, records: Vec<ChatMessage>, expect: bool) -> Vec<Action> {
        match self.data_link(contact) {
            Some(connection) => self.seal_on(connection, records, expect),
            None => Vec::new(),
        }
    }

    /// The link to `contact` that may carry data: one not on a setup-only transport (§7.3).
    fn data_link(&self, contact: ContactId) -> Option<ConnectionId> {
        self.links
            .get(&contact)
            .copied()
            .filter(|c| !self.setup_only.contains(c))
    }

    /// The link to `contact`, if up, for a feature that needs data to flow: a link for setup only
    /// says so ([`NodeError::NeedsWifi`]), so the platform can move it to Wi-Fi first.
    fn require_data_link(&self, contact: ContactId) -> Result<ConnectionId, NodeError> {
        match self.links.get(&contact) {
            None => Err(NodeError::NotLinked),
            Some(_) => self.data_link(contact).ok_or(NodeError::NeedsWifi),
        }
    }

    /// The connection runs over a transport for discovery and setting up Wi-Fi only (BLE, §7.3).
    /// Call before its first frame.
    pub fn setup_only(&mut self, connection: ConnectionId) {
        self.setup_only.insert(connection);
    }

    /// Carries out what the media logic asks for. Its records call for no answer: a call may ring
    /// for long, and a talk flows one way.
    fn apply_media(&mut self, effects: Effects) -> Vec<Action> {
        let mut actions = Vec::new();
        for (contact, record) in effects.send {
            if is_video(&record)
                && !self
                    .data_link(contact)
                    .is_some_and(|c| self.link_carries(c, Class::Video))
            {
                continue;
            }
            actions.extend(self.send_to(contact, vec![record], false));
        }
        actions.extend(effects.actions);
        actions
    }

    /// Carries out media effects while a record from `contact` is handled: what goes back to it
    /// is sealed on its session, which is out of the table meanwhile.
    fn media_effects_on(
        &mut self,
        connection: ConnectionId,
        contact: ContactId,
        session: &mut Session,
        effects: Effects,
    ) -> Result<Vec<Action>, ()> {
        let mut actions = Vec::new();
        for (to, record) in effects.send {
            // Video goes only over links that carry it: Wi-Fi, or a video path (§8.6, §12.3).
            if to == contact {
                if is_video(&record) && !self.link_carries(connection, Class::Video) {
                    continue;
                }
                let bytes = seal_chat(session, &record).map_err(|_| ())?;
                actions.push(Action::Send { connection, bytes });
            } else {
                if is_video(&record) && !self.data_link(to).is_some_and(|c| self.link_carries(c, Class::Video)) {
                    continue;
                }
                actions.extend(self.send_to(to, vec![record], false));
            }
        }
        actions.extend(effects.actions);
        Ok(actions)
    }

    fn media_allowed(&self, contact: ContactId) -> Allowed {
        let keys = self.keys.contacts.get(&contact);
        Allowed {
            calls: keys.is_some_and(|k| k.permissions.messages),
            // Muted: its push-to-talk does not play, as if not accepted.
            instant_voice: keys.is_some_and(|k| k.permissions.ptt && !muted(k.muted_until)),
        }
    }

    /// A chunk of a file being fetched; anything but the next chunk is a duplicate or stale. Returns
    /// actions, and the next request to send, if any.
    fn on_chunk(
        &mut self,
        contact: ContactId,
        id: &MessageId,
        index: u64,
        data: &[u8],
    ) -> (Vec<Action>, Option<ChatMessage>) {
        let Store::Open(account) = &self.store else {
            return (Vec::new(), None);
        };
        let Some((&file, download)) = self
            .downloads
            .iter_mut()
            .find(|(_, d)| d.contact == contact && &d.file_id == id)
        else {
            return (Vec::new(), None);
        };
        if index != chunk_count(download.stored) {
            return (Vec::new(), None);
        }
        if data.len() != chunk_len(download.size, index)
            || account.write_file_chunk(file, download.stored, index, data).is_err()
        {
            self.downloads.remove(&file);
            let _ = account.clear_file(file);
            let failed = attachment_updated(account, file, 0, AttachmentState::Failed);
            return (failed.into_iter().collect(), None);
        }
        download.hasher.update(data);
        download.stored += data.len() as u64;
        let mut actions = Vec::new();
        // Progress is recorded only once durable, so a crash never claims more than is on disk.
        if download.stored < download.size
            && chunk_count(download.stored).is_multiple_of(PROGRESS_EVERY)
            && account.sync_file(file).is_ok()
            && let Some(updated) = attachment_updated(account, file, download.stored, AttachmentState::Downloading)
        {
            actions.push(updated);
        }
        let (more, request) = self.advance_download(file);
        actions.extend(more);
        (actions, request)
    }

    /// The answer to a contact's request for chunks of a file this device offered it.
    fn serve_chunks(&self, contact: ContactId, id: &MessageId, first: u64, count: u16) -> Vec<ChatMessage> {
        let unavailable = |reason| vec![ChatMessage::FileUnavailable { id: *id, reason }];
        let Store::Open(account) = &self.store else {
            return unavailable(Unavailable::NotNow);
        };
        let Ok(Some(message)) = account.message_by_id(contact, id) else {
            return self
                .serve_group_chunks(contact, id, first, count)
                .unwrap_or_else(|| unavailable(Unavailable::Gone));
        };
        let Some(attachment) = message
            .attachment
            .filter(|a| message.outgoing && a.state == AttachmentState::Complete)
        else {
            return unavailable(Unavailable::Gone);
        };
        let end = first.saturating_add(u64::from(count)).min(chunk_count(attachment.size));
        let mut chunks = Vec::new();
        for index in first..end {
            match account.read_file_chunk(message.id, attachment.size, index) {
                Ok(data) => chunks.push(ChatMessage::Chunk { id: *id, index, data }),
                Err(_) => return unavailable(Unavailable::Gone),
            }
        }
        chunks
    }

    // Calls and push-to-talk (§8.5). They need a link, but not an unlocked account.

    /// Calls a linked contact, as a video call or not. Returns the call's id; [`Action::CallReached`]
    /// follows when it rings there, then [`Action::CallAccepted`] or [`Action::CallEnded`].
    pub fn start_call(&mut self, contact: ContactId, video: bool) -> Result<(StreamId, Vec<Action>), NodeError> {
        if !self.is_contact(contact) {
            return Err(NodeError::UnknownContact);
        }
        let link = self.require_data_link(contact)?;
        if video && !self.link_carries(link, Class::Video) {
            return Err(NodeError::PathTooNarrow);
        }
        let id = random::array()?;
        let effects = self.media.start_call(contact, id, video)?;
        Ok((id, self.apply_media(effects)))
    }

    pub fn answer_call(&mut self, id: StreamId) -> Result<Vec<Action>, NodeError> {
        let effects = self.media.answer_call(id)?;
        Ok(self.apply_media(effects))
    }

    /// Hangs up, cancels a call still ringing there, or declines one ringing here.
    pub fn end_call(&mut self, id: StreamId) -> Vec<Action> {
        let effects = self.media.hang_up(id);
        self.apply_media(effects)
    }

    // Video in 1:1 calls (§8.6). The platform sends video only while the link runs over Wi-Fi.

    /// This device's camera in a call: on, off, or paused (on, but nothing is sent for now).
    pub fn set_camera(&mut self, id: StreamId, state: VideoState) -> Result<Vec<Action>, NodeError> {
        let link = self.media.call_contact(id).and_then(|c| self.data_link(c));
        if state == VideoState::On && link.is_some_and(|c| !self.link_carries(c, Class::Video)) {
            return Err(NodeError::PathTooNarrow);
        }
        let effects = self.media.set_camera(id, state)?;
        Ok(self.apply_media(effects))
    }

    /// One encoded frame of this device's camera for a call under way: H.264, Annex B, a key frame
    /// with SPS and PPS before it; shown upright after `rotation` quarter turns clockwise. Skip
    /// frames only before a key frame.
    pub fn send_video(
        &mut self,
        stream: StreamId,
        key: bool,
        rotation: u8,
        size: (u16, u16),
        frame: &[u8],
    ) -> Result<Vec<Action>, NodeError> {
        let records = self.media.video(stream, key, rotation, size, frame)?;
        let mut actions = Vec::new();
        for (contact, record) in records {
            if self
                .data_link(contact)
                .is_some_and(|c| self.link_carries(c, Class::Video))
            {
                actions.extend(self.send_to(contact, vec![record], false));
            }
        }
        Ok(actions)
    }

    /// The contact's video cannot be decoded from here on (say, the decoder restarted): skip
    /// frames until a key frame, and ask for one.
    pub fn request_key_frame(&mut self, stream: StreamId) -> Result<Vec<Action>, NodeError> {
        let effects = self.media.request_key_frame(stream)?;
        Ok(self.apply_media(effects))
    }

    /// The video of `member` in the group call cannot be decoded from here on: skip its frames
    /// until a key frame, and ask for one (§9.9).
    pub fn request_member_key_frame(&mut self, stream: StreamId, member: ContactId) -> Result<Vec<Action>, NodeError> {
        let effects = self.media.request_member_key_frame(stream, member)?;
        Ok(self.apply_media(effects))
    }

    /// Starts talking to a linked contact (push-to-talk). Returns the talk's id.
    pub fn start_talk(&mut self, contact: ContactId) -> Result<(StreamId, Vec<Action>), NodeError> {
        if !self.is_contact(contact) {
            return Err(NodeError::UnknownContact);
        }
        self.require_data_link(contact)?;
        let id = random::array()?;
        let effects = self.media.start_talk(contact, id)?;
        Ok((id, self.apply_media(effects)))
    }

    pub fn end_talk(&mut self, id: StreamId) -> Vec<Action> {
        let effects = self.media.end_talk(id);
        self.apply_media(effects)
    }

    /// One encoded packet (20 ms of Opus) of this device's audio for a call or talk under way.
    /// Dropped when there is none, or no link right now.
    pub fn send_audio(&mut self, stream: StreamId, packet: &[u8]) -> Vec<Action> {
        let records = self.media.audio(stream, packet);
        records
            .into_iter()
            .flat_map(|(contact, record)| self.send_to(contact, vec![record], false))
            .collect()
    }

    // Group voice (§9.6): with the members linked now; works while locked, like 1:1 voice.

    /// Talks to a group (push-to-talk), to the members linked now, and looks for paths through
    /// Air Providers to the others for the next talk (§9.6). Returns the talk's id;
    /// [`NodeError::NotLinked`] with nobody linked ([`Node::reach_group`] then).
    pub fn start_group_talk(&mut self, group: i64) -> Result<(StreamId, Vec<Action>), NodeError> {
        let (group_id, members) = self.linked_members(group)?;
        if members.is_empty() {
            return Err(NodeError::NotLinked);
        }
        let id = random::array()?;
        let effects = self.media.start_group_talk(group_id, id, &members)?;
        let mut actions = self.apply_media(effects);
        actions.extend(self.reach_members(&group_id, true).0);
        Ok((id, actions))
    }

    /// Calls a group: it rings for the members linked now, for those reached through Air Providers
    /// meanwhile (§9.6), and for those who link while it goes on.
    pub fn start_group_call(&mut self, group: i64) -> Result<(StreamId, Vec<Action>), NodeError> {
        let (group_id, members) = self.linked_members(group)?;
        let (reaching, searching) = self.reach_members(&group_id, true);
        if members.is_empty() && !searching {
            return Err(NodeError::NotLinked);
        }
        let id = random::array()?;
        let me = self.call_self()?;
        let effects = self.media.start_group_call(group_id, group, id, &members, me)?;
        let mut actions = self.apply_media(effects);
        actions.extend(reaching);
        Ok((id, actions))
    }

    /// Joins the group call ringing here, and looks for paths to the members it is not linked with
    /// (those whose identity is the greater; the others look for this device).
    pub fn join_group_call(&mut self, id: StreamId) -> Result<Vec<Action>, NodeError> {
        let group = self.media.group_call_row(id).ok_or(MediaError::NoSuchStream)?;
        let (_, members) = self.linked_members(group)?;
        let me = self.call_self()?;
        let effects = self.media.join_group_call(id, &members, me)?;
        // It hears the others through those it is linked with: no paths to look for (§9.6).
        Ok(self.apply_media(effects))
    }

    /// A 1:1 call whose link went away (a provider on the way left, or the contact went out of
    /// reach) looks for a path through Air Providers while it waits for a link (requirement AP-7):
    /// for video if this device's camera is on and some provider carries it, else for voice.
    fn keep_call_linked(&mut self) -> Vec<Action> {
        let Some((contact, video)) = self.media.call_waiting_for_link() else {
            return Vec::new();
        };
        if self.data_link(contact).is_some() || self.searching_for(contact) {
            return Vec::new();
        }
        let class = if video && self.providers(Class::Video) > 0 {
            Class::Video
        } else {
            Class::Voice
        };
        self.find_path(contact, class).unwrap_or_default()
    }

    /// This device in a group call it starts or joins: a fresh origin, and its identity key.
    fn call_self(&self) -> Result<CallSelf, NodeError> {
        Ok(CallSelf {
            origin: random::array()?,
            identity: self.keys.identity,
        })
    }

    /// The row of `member`, named in a presence from linked `contact`, if both are members of the
    /// group whose call is under way here (§9.6).
    fn call_member(&self, contact: ContactId, member: &PublicIdentity) -> Option<ContactId> {
        let (group_id, _) = self.media.group_call()?;
        let group = self.keys.groups.get(&group_id)?;
        if !group.members.contains(&contact) {
            return None;
        }
        group
            .members
            .iter()
            .copied()
            .find(|row| self.keys.contacts.get(row).is_some_and(|k| k.identity == *member))
    }

    /// In a group call, looks every so often for a path to one participant gone without leaving
    /// (a repeater left): the one with the smallest identity among those greater than this
    /// device's, which look for it otherwise (§9.6).
    fn heal_group_call(&mut self, now_secs: u64) -> Vec<Action> {
        if now_secs.saturating_sub(self.call_healed_at) < CALL_HEAL_SECS {
            return Vec::new();
        }
        self.call_healed_at = now_secs;
        let me = *self.keys.identity.as_bytes();
        let target = self
            .media
            .lost_call_members()
            .into_iter()
            .filter(|m| self.data_link(*m).is_none() && !self.searching_for(*m))
            .filter_map(|m| self.keys.contacts.get(&m).map(|k| (*k.identity.as_bytes(), m)))
            .filter(|(identity, _)| me < *identity)
            .min();
        match target {
            Some((_, member)) => self.find_path(member, Class::Voice).unwrap_or_default(),
            None => Vec::new(),
        }
    }

    /// Looks for paths through Air Providers to the members of a group no link reaches now, so its
    /// next talk or call reaches them (§9.6). Nothing without an Air Provider around.
    pub fn reach_group(&mut self, group: i64) -> Result<Vec<Action>, NodeError> {
        let (group_id, _) = self.linked_members(group)?;
        Ok(self.reach_members(&group_id, true).0)
    }

    /// Looks for paths to a group's members with no link: all of them, or (`all` false) only those
    /// whose identity is greater than this device's. Returns the actions and whether any search
    /// runs.
    fn reach_members(&mut self, group_id: &GroupId, all: bool) -> (Vec<Action>, bool) {
        let Some(group) = self.keys.groups.get(group_id) else {
            return (Vec::new(), false);
        };
        let me = *self.keys.identity.as_bytes();
        let unlinked: Vec<ContactId> = group
            .members
            .iter()
            .copied()
            .filter(|m| self.data_link(*m).is_none())
            .filter(|m| all || self.keys.contacts.get(m).is_some_and(|k| me < *k.identity.as_bytes()))
            .collect();
        let mut actions = Vec::new();
        for member in &unlinked {
            actions.extend(self.find_path(*member, Class::Voice).unwrap_or_default());
        }
        let searching = unlinked.iter().any(|m| self.searching_for(*m));
        (actions, searching)
    }

    /// Mutes a contact until `until_ms` (Unix ms; `i64::MAX` for good), or unmutes it with 0.
    pub fn mute_contact(&mut self, contact: ContactId, until_ms: i64) -> Result<(), NodeError> {
        if !self.account()?.db().set_contact_muted(contact, until_ms)? {
            return Err(NodeError::UnknownContact);
        }
        self.refresh_contacts();
        Ok(())
    }

    /// Mutes a group until `until_ms`, or unmutes it with 0.
    pub fn mute_group(&mut self, group: i64, until_ms: i64) -> Result<(), NodeError> {
        if !self.account()?.db().set_group_muted(group, until_ms)? {
            return Err(NodeError::NoSuchGroup);
        }
        self.refresh_contacts();
        Ok(())
    }

    /// Whether the user muted a contact: its messages raise no notification. Works while locked.
    pub fn contact_muted(&self, contact: ContactId) -> bool {
        self.keys.contacts.get(&contact).is_some_and(|k| muted(k.muted_until))
    }

    /// Whether the user muted a group: its messages raise no notification and its calls ring
    /// silently. Works while locked.
    pub fn group_muted(&self, group: i64) -> bool {
        self.keys
            .groups
            .values()
            .any(|g| g.row == group && muted(g.muted_until))
    }

    /// Whether a group's push-to-talk plays at once.
    pub fn set_group_ptt(&mut self, group: i64, allow: bool) -> Result<(), NodeError> {
        if !self.account()?.db().set_group_ptt(group, allow)? {
            return Err(NodeError::NoSuchGroup);
        }
        self.refresh_contacts();
        Ok(())
    }

    /// A group's id and the rows of its members linked now (at least one).
    /// A group's members linked now (maybe none).
    fn linked_members(&self, group: i64) -> Result<(GroupId, Vec<ContactId>), NodeError> {
        let (group_id, keys) = self
            .keys
            .groups
            .iter()
            .find(|(_, g)| g.row == group)
            .ok_or(NodeError::NoSuchGroup)?;
        let members: Vec<ContactId> = keys
            .members
            .iter()
            .copied()
            .filter(|m| self.data_link(*m).is_some())
            .collect();
        Ok((*group_id, members))
    }

    /// What voice needs to know about `group_id` for a record from `contact`.
    fn group_voice(&self, group_id: &GroupId, contact: ContactId) -> Option<GroupVoice> {
        self.keys.groups.get(group_id).map(|g| GroupVoice {
            row: g.row,
            member: g.members.contains(&contact),
            instant_voice: g.instant_voice && !muted(g.muted_until),
            channel: false,
        })
    }

    // Moving a link (§8.3).

    /// Asks a linked contact to open `target` for this link; the answer arrives as
    /// [`Action::HotspotOffered`] or [`Action::MoveDeclined`].
    pub fn request_move(&mut self, contact: ContactId, target: MoveTarget) -> Result<Vec<Action>, NodeError> {
        self.send_on_link(contact, &ChatMessage::MoveRequest { target: target.code() })
    }

    /// Answers [`Action::MoveRequested`]: the hotspot is up and listening on `offer.port`.
    pub fn offer_hotspot(&mut self, contact: ContactId, offer: HotspotOffer) -> Result<Vec<Action>, NodeError> {
        self.send_on_link(contact, &ChatMessage::HotspotOffer(offer))
    }

    pub fn decline_move(&mut self, contact: ContactId, target: MoveTarget) -> Result<Vec<Action>, NodeError> {
        self.send_on_link(contact, &ChatMessage::MoveDeclined { target: target.code() })
    }

    fn send_on_link(&mut self, contact: ContactId, message: &ChatMessage) -> Result<Vec<Action>, NodeError> {
        let connection = *self.links.get(&contact).ok_or(NodeError::NotLinked)?;
        let Some(ConnectionState::Linked { session, .. }) = self.connections.get_mut(&connection) else {
            return Err(NodeError::NotLinked);
        };
        let bytes = seal_chat(session, message)?;
        if matches!(message, ChatMessage::MoveRequest { .. }) {
            self.expect_answer(connection);
        }
        Ok(vec![Action::Send { connection, bytes }])
    }

    // Connections.

    /// Handles a frame received on `connection`; the first frame of an incoming connection
    /// decides what it is.
    pub fn on_frame(&mut self, connection: ConnectionId, frame: &[u8], now_secs: u64) -> Vec<Action> {
        if self.closing.contains(&connection) {
            return Vec::new();
        }
        // Anything arriving on a link shows the other end is there.
        if let Some(live) = self.liveness.get_mut(&connection) {
            *live = Liveness {
                heard_at: Some(now_secs),
                ..Liveness::default()
            };
        }
        let result = match self.connections.remove(&connection) {
            None => self.accept(connection, frame, now_secs),
            Some(state) => self.advance(connection, state, frame),
        };
        let actions = result.unwrap_or_else(|reason| failed(connection, reason));
        self.closing_on(actions)
    }

    /// The transport lost or closed `connection`.
    pub fn connection_closed(&mut self, connection: ConnectionId) -> Vec<Action> {
        self.setup_only.remove(&connection);
        if self.closing.remove(&connection) {
            return Vec::new();
        }
        match self.connections.remove(&connection) {
            Some(ConnectionState::Linked { contact, .. }) => self.unlink(connection, contact),
            Some(ConnectionState::Pairing(_)) => vec![Action::Failed {
                connection,
                reason: Failure::ConnectionLost,
            }],
            _ => Vec::new(),
        }
    }

    /// Remembers the connections `actions` close, until the transport reports them closed.
    fn closing_on(&mut self, actions: Vec<Action>) -> Vec<Action> {
        for action in &actions {
            if let Action::Close { connection } = action {
                self.closing.insert(*connection);
            }
        }
        actions
    }

    fn open(
        &mut self,
        connection: ConnectionId,
        state: ConnectionState,
        message: Vec<u8>,
    ) -> Result<Vec<Action>, NodeError> {
        if self.connections.contains_key(&connection) {
            return Err(NodeError::ConnectionInUse(connection));
        }
        self.connections.insert(connection, state);
        Ok(vec![Action::Send {
            connection,
            bytes: message,
        }])
    }

    /// The first frame of a connection someone else opened.
    fn accept(&mut self, connection: ConnectionId, frame: &[u8], now_secs: u64) -> Result<Vec<Action>, Failure> {
        // Over a path looked for to ask to be added, only the ID's owner pairing in request mode.
        if self.asks_on(connection) && (frame.get(1) != Some(&PAIRING_MESSAGE_1) || frame.get(2) != Some(&3)) {
            return Err(Failure::Protocol);
        }
        match frame.get(1) {
            Some(&PAIRING_MESSAGE_1) => {
                self.invites.retain(|(_, expires)| *expires > now_secs);
                // Nearby pairing while "Add nearby" is open; invites and requests are looked up.
                let (is_invite, is_request) = (frame.get(2) == Some(&2), frame.get(2) == Some(&3));
                if !is_invite && !is_request && self.pairing_beacon.is_none() {
                    return Err(Failure::NotAccepting);
                }
                let requests = if is_request {
                    self.request_table(now_secs)
                } else {
                    Vec::new()
                };
                let Store::Open(account) = &self.store else {
                    return Err(Failure::NotAccepting);
                };
                let invites: Vec<&Invite> = self.invites.iter().map(|(invite, _)| invite).collect();
                let (pairing, events) = Pairing::accept(frame, &account.profile(), &invites, &requests)?;
                Ok(self.pairing_events(connection, Box::new(pairing), events))
            }
            Some(&CHANNEL_MESSAGE_1) => self.accept_channel(connection, frame, now_secs),
            Some(&MESH_MESSAGE_1) => self.accept_mesh(connection, frame, now_secs),
            Some(&LINK_MESSAGE_1) => {
                let tag = Responder::tag(frame).map_err(|_| Failure::Protocol)?;
                self.directory(now_secs);
                let directory = self.directory.as_ref().expect("just built");
                let (contact, psk) = self
                    .tags
                    .claim(&tag, epoch_at(now_secs), &directory.tag_keys)
                    .ok_or(Failure::NotAccepting)?;
                // The contact may not know of this device's newest static key yet, nor this device of
                // its: each pair of keys it may have used is tried (§6.9).
                let mut answers = self.keys.answers(contact, psk).into_iter();
                let (remote, responder, message) = loop {
                    let (remote, own) = answers.next().ok_or(Failure::AuthenticationFailed)?;
                    match Responder::respond(self.keys.own(own), &remote, frame, &[]) {
                        Ok((responder, message)) => break (remote, responder, message),
                        Err(LinkError::AuthenticationFailed) => continue,
                        Err(error) => return Err(link_failure(error)),
                    }
                };
                let state = ConnectionState::Responding {
                    contact,
                    link_key: remote.link_psk,
                    responder: Box::new(responder),
                };
                self.connections.insert(connection, state);
                self.handshakes.insert(connection, now_secs);
                Ok(vec![Action::Send {
                    connection,
                    bytes: message,
                }])
            }
            _ => Err(Failure::Protocol),
        }
    }

    /// The next frame on a connection we already know. The state was taken out of the table and
    /// goes back in only if the connection continues.
    fn advance(
        &mut self,
        connection: ConnectionId,
        state: ConnectionState,
        frame: &[u8],
    ) -> Result<Vec<Action>, Failure> {
        match state {
            ConnectionState::Pairing(mut pairing) => {
                let Store::Open(account) = &self.store else {
                    return Err(Failure::NotAccepting);
                };
                let events = pairing.receive(frame, &account.profile())?;
                Ok(self.pairing_events(connection, pairing, events))
            }
            ConnectionState::Initiating {
                contact,
                link_key,
                own_key,
                initiator,
            } => {
                let (established, reply) = initiator
                    .finish(self.keys.own(own_key), frame, &[])
                    .map_err(link_failure)?;
                self.opening.insert(connection);
                self.advance_link_keys(contact, &link_key, established.next_link_key.as_ref());
                let mut actions = vec![Action::Send {
                    connection,
                    bytes: reply,
                }];
                actions.extend(self.linked(connection, contact, established.session));
                Ok(actions)
            }
            ConnectionState::Responding {
                contact,
                link_key,
                responder,
            } => {
                let established = responder.finish(frame).map_err(link_failure)?;
                self.advance_link_keys(contact, &link_key, established.next_link_key.as_ref());
                Ok(self.linked(connection, contact, established.session))
            }
            ConnectionState::ChannelInitiating { contact, initiator } => {
                self.channel_initiated(connection, contact, *initiator, frame)
            }
            ConnectionState::ChannelResponding { contact, responder } => {
                self.channel_responded(connection, contact, *responder, frame)
            }
            ConnectionState::MeshInitiating { contact, initiator } => {
                self.mesh_initiated(connection, contact, *initiator, frame)
            }
            ConnectionState::MeshResponding { contact, responder } => {
                self.mesh_responded(connection, contact, *responder, frame)
            }
            ConnectionState::Linked { contact, mut session } => match session.open(frame) {
                Ok(Record::Data(payload)) => {
                    self.handling = Some((connection, Vec::new()));
                    let handled = self.on_chat(connection, contact, &mut session, &payload);
                    let deferred = self.handling.take().map(|(_, records)| records).unwrap_or_default();
                    match handled {
                        // The link ended while the record was handled: its contact is gone.
                        Ok(actions) if self.links.get(&contact) != Some(&connection) => Ok(actions),
                        Ok(mut actions) => {
                            self.connections
                                .insert(connection, ConnectionState::Linked { contact, session });
                            // What was sealed for this link meanwhile goes now, in order.
                            for (record, expect) in deferred {
                                actions.extend(self.seal_on(connection, vec![record], expect));
                            }
                            // Group traffic for the contact queued meanwhile goes now that the session is back.
                            if self.group_traffic.take_flush() {
                                actions.extend(self.flush_group_outbox(contact));
                            }
                            Ok(actions)
                        }
                        Err(()) => {
                            let mut actions = self.unlink(connection, contact);
                            actions.push(Action::Close { connection });
                            Ok(actions)
                        }
                    }
                }
                Ok(Record::Close) | Err(_) => {
                    let mut actions = self.unlink(connection, contact);
                    actions.push(Action::Close { connection });
                    Ok(actions)
                }
            },
        }
    }

    /// A link to a contact came up, made with `used`: its link keys become the one that follows,
    /// the one used, and those newer than it (§6.8). Only while unlocked, where they can be stored;
    /// a fellow member's group link keys stay as they are.
    fn advance_link_keys(&mut self, contact: ContactId, used: &SecretBytes<32>, next: Option<&SecretBytes<32>>) {
        let (Some(next), Store::Open(account)) = (next, &self.store) else {
            return;
        };
        let Some(keys) = self.keys.contacts.get_mut(&contact).filter(|k| !k.group_only) else {
            return;
        };
        let newer = keys
            .link_psks
            .iter()
            .take_while(|key| !equal_in_constant_time(key.expose(), used.expose()));
        let mut updated = vec![next.clone(), used.clone()];
        updated.extend(newer.cloned());
        updated.truncate(MAX_LINK_KEYS);
        // Only what is stored counts: the contact may hold no other.
        if account
            .db()
            .set_link_keys(contact, &updated)
            .is_ok_and(|changed| changed)
        {
            keys.link_psks = updated;
            self.directory = None;
        }
    }

    fn pairing_events(
        &mut self,
        connection: ConnectionId,
        mut pairing: Box<Pairing>,
        events: Vec<Event>,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        let mut finished = false;
        let mut events: std::collections::VecDeque<Event> = events.into();
        while let Some(event) = events.pop_front() {
            match event {
                Event::Send(bytes) => actions.push(Action::Send { connection, bytes }),
                Event::ShowSas(sas) => actions.push(Action::ShowSas { connection, sas }),
                Event::Requested(requester) => match self.requested(connection, &mut pairing, requester) {
                    Ok((more, told)) => {
                        events.extend(more);
                        actions.extend(told);
                    }
                    Err(end) => {
                        finished = true;
                        actions.extend(end);
                    }
                },
                Event::Paired(contact) => {
                    finished = true;
                    if let Some(id) = pairing.invite_id() {
                        self.invites.retain(|(invite, _)| invite.id() != id);
                    }
                    self.request_answered(&contact.identity);
                    match self.account().and_then(|account| Ok(account.add_contact(&contact)?)) {
                        Ok(summary) => actions.push(Action::Paired {
                            connection,
                            contact: summary,
                        }),
                        Err(error) => actions.push(Action::Failed {
                            connection,
                            reason: if matches!(error, NodeError::Account(AccountError::Blocked)) {
                                Failure::Blocked
                            } else {
                                Failure::Protocol
                            },
                        }),
                    }
                    self.refresh_contacts();
                    actions.push(Action::Close { connection });
                    // A stranger no more: a mesh link to it gives way to the contact's own.
                    actions.extend(self.end_mesh_links_to_contacts());
                }
            }
        }
        if !finished {
            self.connections.insert(connection, ConnectionState::Pairing(pairing));
        }
        actions
    }

    /// A link is up: record it, replace an older link to the same contact, and send everything
    /// the contact has not acknowledged yet. A link for setup only (§7.3) sends nothing, says
    /// whether something waits for Wi-Fi, and never replaces one that carries data.
    fn linked(&mut self, connection: ConnectionId, contact: ContactId, session: Session) -> Vec<Action> {
        let mut session = Box::new(session);
        // Two paths of one class to one contact (both ends looked at once): both sides keep the
        // one with the smaller handshake hash. One of another class replaces the old: it was
        // looked for because the old one does not carry something (§12.3).
        let rival = self
            .data_link(contact)
            .filter(|c| *c != connection && is_path_connection(*c) && is_path_connection(connection))
            .filter(|c| self.path_class(*c) == self.path_class(connection));
        let rival_hash = rival.and_then(|c| match self.connections.get(&c) {
            Some(ConnectionState::Linked { session, .. }) => Some(*session.handshake_hash()),
            _ => None,
        });
        if rival_hash.is_some_and(|hash| &hash < session.handshake_hash()) {
            let mut actions = Vec::new();
            if let Ok(bytes) = session.seal_close() {
                actions.push(Action::Send { connection, bytes });
            }
            actions.push(Action::Close { connection });
            return self.closing_on(actions);
        }
        // Nor does a link over a path replace a direct one (§12.3).
        let direct = self.data_link(contact).is_some_and(|c| !is_path_connection(c));
        if self.setup_only.contains(&connection) || (is_path_connection(connection) && direct) {
            if self.data_link(contact).is_some() {
                let mut actions = Vec::new();
                if let Ok(bytes) = session.seal_close() {
                    actions.push(Action::Send { connection, bytes });
                }
                actions.push(Action::Close { connection });
                return self.closing_on(actions);
            }
            return self.setup_linked(connection, contact, session);
        }
        // Two links opened from both sides at once (one waited and opened after a minute): both
        // sides keep the one with the smaller handshake hash (§5.2).
        let now = now_secs();
        let opened_here = self.opening.remove(&connection);
        // Only between direct links: a direct one always wins over one over a path (§12.3).
        let race = self
            .links
            .get(&contact)
            .copied()
            .filter(|c| *c != connection && !is_path_connection(*c) && !is_path_connection(connection))
            .filter(|c| {
                self.link_starts
                    .get(c)
                    .is_some_and(|(at, here)| *here != opened_here && now.saturating_sub(*at) < RACE_SECS)
            });
        let race_lost = race.and_then(|c| match self.connections.get(&c) {
            Some(ConnectionState::Linked { session: other, .. }) => {
                Some(other.handshake_hash() < session.handshake_hash())
            }
            _ => None,
        });
        if race_lost == Some(true) {
            let mut actions = Vec::new();
            if let Ok(bytes) = session.seal_close() {
                actions.push(Action::Send { connection, bytes });
            }
            actions.push(Action::Close { connection });
            return self.closing_on(actions);
        }
        self.link_starts.insert(connection, (now, opened_here));
        let mut actions = self.close_link(contact);
        actions.push(Action::LinkUp { connection, contact });
        match &mut self.store {
            Store::Open(account) => {
                for message in account.undelivered(contact).unwrap_or_default() {
                    let chat = outgoing_record(&message);
                    let Ok(record) = seal_chat(&mut session, &chat) else {
                        continue;
                    };
                    actions.push(Action::Send {
                        connection,
                        bytes: record,
                    });
                    if let Ok(Some(sent)) = account.advance_status(contact, &message.message_id, MessageStatus::Sent) {
                        actions.push(Action::MessageUpdated { message: sent });
                    }
                }
            }
            Store::Sealed(sealed) => {
                for pending in sealed.pending.iter().filter(|p| p.contact == contact) {
                    let chat = text_message(pending.id, pending.sent_at_ms, &pending.text);
                    let Ok(record) = seal_chat(&mut session, &chat) else {
                        continue;
                    };
                    actions.push(Action::Send {
                        connection,
                        bytes: record,
                    });
                    let event = InboxEvent::Status {
                        contact,
                        id: pending.id,
                        status: MessageStatus::Sent,
                    };
                    let _ = sealed.inbox.append(&event);
                }
            }
        }
        self.links.insert(contact, connection);
        self.link_attempts.remove(&contact);
        self.media.linked(contact);
        // A member of the group whose call goes on hears of it.
        let call_group = self.media.group_call().filter(|(_, joined)| *joined).map(|(g, _)| g);
        let in_call_group = call_group
            .and_then(|g| self.keys.groups.get(&g))
            .is_some_and(|g| g.members.contains(&contact));
        self.connections
            .insert(connection, ConnectionState::Linked { contact, session });
        let resent = actions
            .iter()
            .any(|action| matches!(action, Action::Send { connection: c, .. } if *c == connection));
        self.liveness.insert(
            connection,
            Liveness {
                expecting: resent,
                ..Liveness::default()
            },
        );
        if self.link_carries(connection, Class::Files) {
            let (resumed, requests) = self.resume_downloads_from(contact);
            actions.extend(resumed);
            actions.extend(self.send_records(connection, requests));
        }
        actions.extend(self.flush_group_outbox(contact));
        actions.extend(self.group_source_linked(contact));
        if in_call_group {
            let effects = self.media.member_linked(contact);
            actions.extend(self.apply_media(effects));
        }
        actions.extend(self.mesh_neighbour_up(connection, contact));
        if let Some(wanted) = self.prekeys_wanted(contact) {
            actions.extend(self.seal_on(connection, vec![wanted], false));
        }
        if let Some(record) = self.static_key_for(contact) {
            actions.extend(self.seal_on(connection, vec![record], false));
        }
        if let Some(wanted) = self.attestation_wanted(contact) {
            actions.push(wanted);
        }
        if let Some(record) = self.presence_key_for(contact) {
            actions.extend(self.seal_on(connection, vec![record], false));
        }
        actions
    }

    /// A link for setup only is up (§7.3): it keeps the contact in reach and can move to Wi-Fi.
    fn setup_linked(&mut self, connection: ConnectionId, contact: ContactId, session: Box<Session>) -> Vec<Action> {
        let mut actions = self.close_link(contact);
        actions.push(Action::LinkUp { connection, contact });
        self.links.insert(contact, connection);
        self.link_attempts.remove(&contact);
        self.connections
            .insert(connection, ConnectionState::Linked { contact, session });
        self.liveness.insert(connection, Liveness::default());
        if self.waits_for(contact) {
            actions.push(Action::WaitingForWifi { contact });
        }
        actions
    }

    /// Whether messages to `contact` wait to be sent.
    fn waits_for(&self, contact: ContactId) -> bool {
        match &self.store {
            Store::Open(account) => account.undelivered(contact).is_ok_and(|m| !m.is_empty()),
            Store::Sealed(sealed) => sealed.pending.iter().any(|p| p.contact == contact),
        }
    }

    /// Notes that a record calling for an answer went out on `connection`.
    fn expect_answer(&mut self, connection: ConnectionId) {
        if let Some(live) = self.liveness.get_mut(&connection) {
            live.expecting = true;
        }
    }

    // Liveness (§6.7).

    /// Checks every link; call every few seconds. Pings links that have been silent for
    /// [`LINK_IDLE_SECS`] and closes those where an answer is [`LINK_ANSWER_SECS`] overdue, so a
    /// peer that vanished without closing (its Wi-Fi went away) is noticed and the contact can be
    /// reached another way.
    pub fn tick(&mut self, now_secs: u64) -> Vec<Action> {
        let connections = &self.connections;
        self.liveness
            .retain(|connection, _| matches!(connections.get(connection), Some(ConnectionState::Linked { .. })));
        self.handshakes.retain(|connection, _| {
            matches!(
                connections.get(connection),
                Some(
                    ConnectionState::Initiating { .. }
                        | ConnectionState::Responding { .. }
                        | ConnectionState::ChannelInitiating { .. }
                        | ConnectionState::ChannelResponding { .. }
                        | ConnectionState::MeshInitiating { .. }
                        | ConnectionState::MeshResponding { .. }
                )
            )
        });
        let stalled: Vec<ConnectionId> = self
            .handshakes
            .iter()
            .filter(|(_, began)| now_secs.saturating_sub(**began) >= LINK_ANSWER_SECS)
            .map(|(connection, _)| *connection)
            .collect();
        let (mut ping, mut lost) = (Vec::new(), Vec::new());
        for (&connection, live) in &mut self.liveness {
            let heard_at = *live.heard_at.get_or_insert(now_secs);
            if live.expecting {
                let since = *live.expecting_since.get_or_insert(now_secs);
                if now_secs.saturating_sub(since) >= LINK_ANSWER_SECS {
                    lost.push(connection);
                }
            } else if now_secs.saturating_sub(heard_at) >= LINK_IDLE_SECS {
                live.expecting = true;
                live.expecting_since = Some(now_secs);
                ping.push(connection);
            }
        }
        let connections = &self.connections;
        self.link_starts
            .retain(|connection, _| connections.contains_key(connection));
        self.opening.retain(|connection| connections.contains_key(connection));
        self.waiting
            .retain(|_, (_, last)| now_secs.saturating_sub(*last) <= SIGHTING_GAP_SECS);
        let mut actions = Vec::new();
        actions.extend(self.static_keys_tick(now_secs));
        actions.extend(self.additions_tick(now_secs));
        actions.extend(self.tries_tick(now_secs));
        self.mesh_tick(now_secs);
        actions.extend(self.mesh_files_tick(now_secs));
        actions.extend(self.paths_tick(now_secs));
        let effects = self.media.tick(now_secs);
        actions.extend(self.apply_media(effects));
        if matches!(self.store, Store::Open(_)) && std::mem::take(&mut self.catch_up) {
            let links: Vec<(ContactId, ConnectionId)> = self
                .links
                .iter()
                .filter(|(_, l)| !self.setup_only.contains(l))
                .map(|(c, l)| (*c, *l))
                .collect();
            for (contact, connection) in links {
                actions.extend(self.offer_waiting_files(contact, connection));
                if self.link_carries(connection, Class::Files) {
                    let (resumed, requests) = self.resume_downloads_from(contact);
                    actions.extend(resumed);
                    actions.extend(self.send_records(connection, requests));
                }
                actions.extend(self.flush_group_outbox(contact));
            }
            actions.extend(self.resume_group_downloads());
        }
        actions.extend(self.tick_groups(now_secs));
        actions.extend(self.expire_voice(i64::try_from(now_secs).unwrap_or(i64::MAX).saturating_mul(1000)));
        actions.extend(self.channel_tick(now_secs));
        actions.extend(self.heal_group_call(now_secs));
        actions.extend(self.keep_call_linked());
        // Ask again senders that could not serve a file a while ago.
        let mut retry = Vec::new();
        for (&file, download) in &mut self.downloads {
            if let Some(since) = download.not_now_since {
                if since == 0 {
                    download.not_now_since = Some(now_secs.max(1));
                } else if now_secs.saturating_sub(since) >= NOT_NOW_RETRY_SECS {
                    download.not_now_since = None;
                    download.requested_until = chunk_count(download.stored);
                    retry.push((file, download.contact));
                }
            }
        }
        for (file, contact) in retry {
            let (done, request) = self.advance_download(file);
            actions.extend(done);
            if let Some(connection) = self.file_link(contact) {
                actions.extend(self.send_records(connection, request.into_iter().collect()));
            }
        }
        for connection in ping {
            if let Some(ConnectionState::Linked { session, .. }) = self.connections.get_mut(&connection)
                && let Ok(bytes) = seal_chat(session, &ChatMessage::Ping)
            {
                actions.push(Action::Send { connection, bytes });
            }
        }
        for connection in stalled {
            self.handshakes.remove(&connection);
            self.connections.remove(&connection);
            actions.push(Action::Close { connection });
        }
        for connection in lost {
            self.liveness.remove(&connection);
            if let Some(ConnectionState::Linked { contact, .. }) = self.connections.remove(&connection) {
                actions.extend(self.unlink(connection, contact));
                actions.push(Action::Close { connection });
            }
        }
        self.closing_on(actions)
    }

    /// Handles a chat message on a link. `Err` means the link must end.
    /// A contact's text message: stored once (in the inbox while locked). Returns what to show, or
    /// an error if it could not be stored durably (then it is not acknowledged).
    fn take_text(
        &mut self,
        contact: ContactId,
        id: MessageId,
        sent_at_ms: u64,
        text: String,
    ) -> Result<Option<Action>, ()> {
        let text = Zeroizing::new(text);
        let sent_at_ms = i64::try_from(sent_at_ms).unwrap_or(i64::MAX);
        match &mut self.store {
            Store::Open(account) => Ok(account
                .store_incoming(contact, &id, &text, sent_at_ms)
                .map_err(|_| ())?
                .map(|message| Action::MessageReceived { message })),
            Store::Sealed(sealed) => {
                if sealed.stored.contains(&(contact, id)) {
                    return Ok(None);
                }
                let event = InboxEvent::Message {
                    contact,
                    id,
                    sent_at_ms,
                    received_at_ms: now_ms(),
                    text: text.to_string(),
                };
                sealed.inbox.append(&event).map_err(|_| ())?;
                sealed.stored.insert((contact, id));
                Ok(Some(Action::MessageArrived { contact }))
            }
        }
    }

    /// A contact acknowledged or refused one of this device's messages.
    fn take_answer(&mut self, contact: ContactId, id: MessageId, status: MessageStatus) -> Vec<Action> {
        let mut actions = Vec::new();
        match &mut self.store {
            Store::Open(account) => {
                if let Ok(Some(message)) = account.advance_status(contact, &id, status) {
                    actions.push(Action::MessageUpdated { message });
                }
            }
            Store::Sealed(sealed) => {
                let ours = sealed.pending.iter().position(|p| p.contact == contact && p.id == id);
                if let Some(index) = ours {
                    sealed.pending.remove(index);
                    let _ = sealed.inbox.append(&InboxEvent::Status { contact, id, status });
                }
            }
        }
        self.release_prekey(contact, &id);
        actions
    }

    fn on_chat(
        &mut self,
        connection: ConnectionId,
        contact: ContactId,
        session: &mut Session,
        payload: &[u8],
    ) -> Result<Vec<Action>, ()> {
        // A link over a path is of use while more than liveness crosses it (§12.3).
        if is_path_connection(connection) && !chat::is_liveness(payload) {
            self.path_used(connection);
        }
        // A mesh peer's link carries mesh traffic only (§10.2).
        if mesh::is_mesh_peer(contact) {
            return match ChatMessage::decode(payload).map_err(|_| ())? {
                Some(record) => self.on_mesh_peer_record(connection, session, record),
                None => Ok(Vec::new()),
            };
        }
        // A channel member's link carries channel talk only (§11.4).
        if channels::is_channel_peer(contact) {
            return match ChatMessage::decode(payload).map_err(|_| ())? {
                Some(record) => self.on_channel_record(connection, contact, session, record),
                None => Ok(Vec::new()),
            };
        }
        let mut actions = Vec::new();
        match ChatMessage::decode(payload).map_err(|_| ())? {
            Some(ChatMessage::Text { id, .. } | ChatMessage::FileOffer { id, .. })
                if !self.accepts_messages_from(contact) =>
            {
                let bytes = seal_chat(session, &ChatMessage::Refused { id }).map_err(|_| ())?;
                actions.push(Action::Send { connection, bytes });
            }
            Some(ChatMessage::Text { id, sent_at_ms, text }) => {
                // Not acknowledged unless durably stored: the sender keeps it and retries.
                let Ok(arrived) = self.take_text(contact, id, sent_at_ms, text) else {
                    return Ok(actions);
                };
                // Acknowledge resends too: the first acknowledgement may have been lost.
                let ack = seal_chat(session, &ChatMessage::Ack { id }).map_err(|_| ())?;
                actions.push(Action::Send { connection, bytes: ack });
                actions.extend(arrived);
            }
            Some(ChatMessage::Ack { id }) => {
                actions.extend(self.take_answer(contact, id, MessageStatus::Delivered));
                let withdraws = self.mesh_withdraw_answered(contact, &id, chat::KIND_ACK, false);
                actions.extend(self.mesh_sends(withdraws, Some((connection, session))));
            }
            Some(ChatMessage::Refused { id }) => {
                actions.extend(self.take_answer(contact, id, MessageStatus::Refused));
                let withdraws = self.mesh_withdraw_answered(contact, &id, chat::KIND_REFUSED, false);
                actions.extend(self.mesh_sends(withdraws, Some((connection, session))));
            }
            Some(
                record @ (ChatMessage::MeshEnvelope(_) | ChatMessage::MeshHave(_) | ChatMessage::MeshWithdraw { .. }),
            ) => {
                actions.extend(self.on_mesh_record(connection, session, record));
            }
            Some(
                record @ (ChatMessage::PathOffer(_)
                | ChatMessage::PathRequest(_)
                | ChatMessage::PathAnswer { .. }
                | ChatMessage::PathOpen { .. }
                | ChatMessage::PathData { .. }
                | ChatMessage::PathCredit { .. }
                | ChatMessage::PathClose { .. }),
            ) => actions.extend(self.on_path_record(connection, session, record)),
            Some(ChatMessage::FileOffer { id, sent_at_ms, meta }) => {
                let sent_at_ms = i64::try_from(sent_at_ms).unwrap_or(i64::MAX);
                let arrived = match &mut self.store {
                    Store::Open(account) => account
                        .store_incoming_file(contact, &id, &meta, sent_at_ms)
                        .map_err(|_| ())?
                        .map(|message| Action::MessageReceived { message }),
                    Store::Sealed(sealed) => {
                        if sealed.stored.contains(&(contact, id)) {
                            None
                        } else {
                            let event = InboxEvent::File {
                                contact,
                                id,
                                sent_at_ms,
                                received_at_ms: now_ms(),
                                meta,
                                mesh_key: None,
                            };
                            if sealed.inbox.append(&event).is_err() {
                                return Ok(actions);
                            }
                            sealed.stored.insert((contact, id));
                            Some(Action::MessageArrived { contact })
                        }
                    }
                };
                let ack = seal_chat(session, &ChatMessage::Ack { id }).map_err(|_| ())?;
                actions.push(Action::Send { connection, bytes: ack });
                // Fetched at once if the contact's files are downloaded without asking.
                let auto = matches!(&arrived, Some(Action::MessageReceived { message })
                    if message.attachment.as_ref().is_some_and(|a| a.state == AttachmentState::Downloading));
                actions.extend(arrived);
                if auto && self.link_carries(connection, Class::Files) {
                    let (resumed, requests) = self.resume_downloads_from(contact);
                    actions.extend(resumed);
                    for request in requests {
                        let bytes = seal_chat(session, &request).map_err(|_| ())?;
                        actions.push(Action::Send { connection, bytes });
                        self.expect_answer(connection);
                    }
                }
            }
            Some(ChatMessage::ChunkRequest { id, first, count }) => {
                let records = match self.link_carries(connection, Class::Files) {
                    true => self.serve_chunks(contact, &id, first, count),
                    // Not over a path that does not carry files (§12.3).
                    false => vec![ChatMessage::FileUnavailable {
                        id,
                        reason: Unavailable::NotNow,
                    }],
                };
                for record in records {
                    let bytes = seal_chat(session, &record).map_err(|_| ())?;
                    actions.push(Action::Send { connection, bytes });
                }
            }
            Some(ChatMessage::Chunk { id, index, data }) => {
                let (done, request) = self.on_chunk(contact, &id, index, &data);
                actions.extend(done);
                if let Some(request) = request {
                    let bytes = seal_chat(session, &request).map_err(|_| ())?;
                    actions.push(Action::Send { connection, bytes });
                    self.expect_answer(connection);
                }
            }
            Some(ChatMessage::FileUnavailable { id, reason }) => {
                let found = self
                    .downloads
                    .iter_mut()
                    .find(|(_, d)| d.contact == contact && d.file_id == id);
                match (found, reason) {
                    (Some((_, download)), Unavailable::NotNow) => download.not_now_since = Some(0),
                    // A member without the group file: ask another one.
                    (Some((&file, _)), Unavailable::Gone) if file < 0 => {
                        actions.extend(self.group_source_gone(file, contact));
                    }
                    (Some((&file, _)), Unavailable::Gone) => {
                        self.downloads.remove(&file);
                        if let Store::Open(account) = &self.store {
                            let _ = account.clear_file(file);
                            if let Ok(message) = account.update_attachment(file, 0, AttachmentState::Gone) {
                                actions.push(Action::MessageUpdated { message });
                            }
                        }
                    }
                    (None, _) => {}
                }
            }
            Some(
                message @ (ChatMessage::CallOffer { .. }
                | ChatMessage::Ringing { .. }
                | ChatMessage::CallAccept { .. }
                | ChatMessage::CallEnd { .. }
                | ChatMessage::TalkStart { .. }
                | ChatMessage::TalkEnd { .. }
                | ChatMessage::Audio { .. }
                | ChatMessage::VideoState { .. }
                | ChatMessage::Video { .. }
                | ChatMessage::KeyFrameRequest { .. }),
            ) => {
                let allowed = self.media_allowed(contact);
                let effects = self.media.receive(contact, message, allowed);
                actions.extend(self.media_effects_on(connection, contact, session, effects)?);
            }
            Some(record @ ChatMessage::CallPresence { .. }) => {
                let ChatMessage::CallPresence { member, .. } = &record else {
                    unreachable!("matched above")
                };
                if let Some(member) = self.call_member(contact, member) {
                    let effects = self.media.receive_call_presence(contact, member, record);
                    actions.extend(self.media_effects_on(connection, contact, session, effects)?);
                }
            }
            Some(record @ ChatMessage::CallAudio { .. }) => {
                let effects = self.media.receive_call_audio(contact, record);
                actions.extend(self.media_effects_on(connection, contact, session, effects)?);
            }
            Some(record @ ChatMessage::CallVideo { .. }) => {
                let effects = self.media.receive_call_video(contact, record);
                actions.extend(self.media_effects_on(connection, contact, session, effects)?);
            }
            Some(record @ ChatMessage::CallKeyFrameRequest { .. }) => {
                let effects = self.media.receive_call_key_frame_request(contact, record);
                actions.extend(self.media_effects_on(connection, contact, session, effects)?);
            }
            Some(
                message @ (ChatMessage::GroupTalkStart { .. }
                | ChatMessage::GroupCall { .. }
                | ChatMessage::GroupCallLeave { .. }),
            ) => {
                let group = match &message {
                    ChatMessage::GroupTalkStart { group_id, .. } | ChatMessage::GroupCall { group_id, .. } => {
                        self.group_voice(group_id, contact)
                    }
                    _ => None,
                };
                let effects = self.media.receive_group(contact, message, group);
                actions.extend(self.media_effects_on(connection, contact, session, effects)?);
            }
            Some(ChatMessage::MoveRequest { target: code }) => match MoveTarget::from_code(code) {
                Some(target) => actions.push(Action::MoveRequested { contact, target }),
                // A target from a later version: say no rather than leave the contact waiting.
                None => {
                    let bytes = seal_chat(session, &ChatMessage::MoveDeclined { target: code }).map_err(|_| ())?;
                    actions.push(Action::Send { connection, bytes });
                }
            },
            Some(ChatMessage::Ping) => {
                let bytes = seal_chat(session, &ChatMessage::Pong).map_err(|_| ())?;
                actions.push(Action::Send { connection, bytes });
            }
            // Its arrival is all that matters (see `on_frame`).
            Some(ChatMessage::Pong) => {}
            Some(ChatMessage::HotspotOffer(offer)) => actions.push(Action::HotspotOffered { contact, offer }),
            Some(ChatMessage::PrekeysWanted(count)) => {
                for prekeys in self.hand_out_prekeys(contact, count) {
                    let bytes = seal_chat(session, &prekeys).map_err(|_| ())?;
                    actions.push(Action::Send { connection, bytes });
                }
            }
            Some(ChatMessage::Prekeys(prekeys)) => self.take_prekeys(contact, prekeys),
            Some(ChatMessage::StaticKey {
                version,
                key,
                signature,
            }) => {
                if let Some(taken) = self.take_static_key(contact, version, key, &signature) {
                    let bytes = seal_chat(session, &taken).map_err(|_| ())?;
                    actions.push(Action::Send { connection, bytes });
                }
            }
            Some(ChatMessage::StaticKeyTaken(version)) => self.static_key_taken(contact, version),
            Some(ChatMessage::PresenceKey { version, key }) => {
                if let Some(taken) = self.take_presence_key(contact, version, &key) {
                    let bytes = seal_chat(session, &taken).map_err(|_| ())?;
                    actions.push(Action::Send { connection, bytes });
                }
            }
            Some(ChatMessage::PresenceKeyTaken(version)) => self.presence_key_taken(contact, version),
            Some(ChatMessage::BuildAttestation { certs, proof }) => {
                let hash = *session.handshake_hash();
                actions.extend(self.take_attestation(contact, &certs, &proof, &hash));
            }
            Some(ChatMessage::MemberProposal {
                id,
                person,
                person_name,
                group_name,
                expires,
            }) => {
                let proposal = additions::MemberProposal {
                    id,
                    person,
                    person_name,
                    group_name,
                    expires,
                };
                actions.extend(self.member_proposed(contact, proposal));
            }
            Some(ChatMessage::MemberProposalAnswer { id, agree }) => {
                actions.extend(self.member_proposal_answered(contact, id, agree));
            }
            // Only ever in envelopes (§10.8, §10.9), or on channel links (§11.5).
            Some(
                ChatMessage::MeshFileOffer { .. } | ChatMessage::MeshUpdateKey { .. } | ChatMessage::ChannelHead { .. },
            ) => {}
            Some(ChatMessage::MoveDeclined { target }) => {
                if let Some(target) = MoveTarget::from_code(target) {
                    actions.push(Action::MoveDeclined { contact, target });
                }
            }
            Some(
                record @ (ChatMessage::UpdatePart { .. }
                | ChatMessage::GroupMessage(_)
                | ChatMessage::GroupAck { .. }
                | ChatMessage::GroupLeave { .. }),
            ) => actions.extend(self.on_group_record(connection, contact, session, record)?),
            None => {}
        }
        Ok(actions)
    }

    /// Ends the link with a contact for good (not to replace it), reporting it down.
    fn end_link(&mut self, contact: ContactId) -> Vec<Action> {
        let linked = self.links.contains_key(&contact);
        let mut actions = self.close_link(contact);
        if linked {
            actions.push(Action::LinkDown { contact });
        }
        let effects = self.media.forget(contact);
        actions.extend(self.apply_media(effects));
        actions
    }

    /// Ends the link with a contact, if any, telling the other device.
    fn close_link(&mut self, contact: ContactId) -> Vec<Action> {
        let Some(connection) = self.links.remove(&contact) else {
            return Vec::new();
        };
        let mut actions = Vec::new();
        if let Some(ConnectionState::Linked { mut session, .. }) = self.connections.remove(&connection)
            && let Ok(bytes) = session.seal_close()
        {
            actions.push(Action::Send { connection, bytes });
        }
        actions.push(Action::Close { connection });
        self.group_traffic.link_ended(connection, Some(contact));
        self.mesh_link_ended(connection, contact);
        actions.extend(self.paths_link_ended(connection));
        actions
    }

    fn unlink(&mut self, connection: ConnectionId, contact: ContactId) -> Vec<Action> {
        self.mesh_link_ended(connection, contact);
        let mut actions = self.paths_link_ended(connection);
        let current = self.links.get(&contact) == Some(&connection);
        self.group_traffic.link_ended(connection, current.then_some(contact));
        if current {
            self.links.remove(&contact);
            actions.push(Action::LinkDown { contact });
            let effects = self.media.unlinked(contact);
            actions.extend(self.apply_media(effects));
            actions.extend(self.group_source_unlinked(contact));
            actions.extend(self.channel_peer_gone(contact));
        }
        actions
    }

    /// Reloads contacts' link keys after the contact list changed.
    fn refresh_contacts(&mut self) {
        if let Store::Open(account) = &self.store
            && let Ok(keys) = LinkMaterial::load(account)
        {
            self.keys = keys;
            self.prekeys.reload(account);
        }
        self.directory = None;
        self.mesh.keys_changed();
        self.paths.keys_changed();
    }

    /// The tables for recognising contacts, rebuilt when the epoch or the contact list changes.
    fn directory(&mut self, now_secs: u64) -> &Directory {
        let epoch = epoch_at(now_secs);
        if self.directory.as_ref().is_none_or(|d| d.epoch != epoch) {
            let mut presence = HashMap::new();
            let mut tag_keys = Vec::new();
            for (&id, contact) in &self.keys.contacts {
                for e in epoch.saturating_sub(1)..=epoch.saturating_add(1) {
                    presence.insert(presence_token(&contact.presence_key, e), id);
                }
                for (index, psk) in contact.link_psks.iter().enumerate() {
                    if let Ok(key) = TagKey::derive(psk, &contact.identity, &self.keys.identity) {
                        tag_keys.push(((id, index), key));
                    }
                }
            }
            self.directory = Some(Directory {
                epoch,
                presence,
                tag_keys,
            });
        }
        self.directory.as_ref().expect("just built")
    }
}

/// The hash over what is stored of a file being fetched, and how much that is: it goes on from
/// there. A damaged file is fetched again from the start.
fn stored_hash(account: &Account, file: i64, size: u64, stored: u64) -> (Sha256Stream, u64) {
    let mut hasher = Sha256Stream::default();
    for index in 0..chunk_count(stored) {
        match account.read_file_chunk(file, size, index) {
            Ok(chunk) => hasher.update(&chunk),
            Err(_) => {
                let _ = account.clear_file(file);
                let _ = attachment_updated(account, file, 0, AttachmentState::Downloading);
                return (Sha256Stream::default(), 0);
            }
        }
    }
    (hasher, stored)
}

/// Records how much of a file being fetched is stored and how it stands; what the platform shows.
fn attachment_updated(account: &Account, file: i64, stored: u64, state: AttachmentState) -> Option<Action> {
    if file < 0 {
        account
            .db()
            .update_group_attachment(-file, stored, state)
            .ok()
            .map(|message| Action::GroupMessageUpdated { message })
    } else {
        account
            .update_attachment(file, stored, state)
            .ok()
            .map(|message| Action::MessageUpdated { message })
    }
}

/// Whether something muted until `until_ms` is muted now.
fn muted(until_ms: i64) -> bool {
    now_ms() < until_ms
}

/// The record that delivers an outgoing message: its text, or its file's offer.
fn outgoing_record(message: &StoredMessage) -> ChatMessage {
    match &message.attachment {
        Some(attachment) => ChatMessage::FileOffer {
            id: message.message_id,
            sent_at_ms: u64::try_from(message.sent_at_ms).unwrap_or(0),
            meta: FileMeta {
                name: attachment.name.clone(),
                mime: attachment.mime.clone(),
                size: attachment.size,
                sha256: attachment.sha256,
                thumbnail: attachment.thumbnail.clone(),
            },
        },
        None => text_message(message.message_id, message.sent_at_ms, &message.body),
    }
}

fn text_message(id: MessageId, sent_at_ms: i64, text: &str) -> ChatMessage {
    ChatMessage::Text {
        id,
        sent_at_ms: u64::try_from(sent_at_ms).unwrap_or(0),
        text: text.to_owned(),
    }
}

fn seal_chat(session: &mut Session, message: &ChatMessage) -> Result<Vec<u8>, NodeError> {
    Ok(session.seal(&message.encode()?)?)
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn now_secs() -> u64 {
    u64::try_from(now_ms() / 1000).unwrap_or(0)
}

/// The last minute an outgoing message's envelopes live: a day after its current try began (§10.5).
pub(super) fn try_expires(message: &StoredMessage) -> u32 {
    u32::try_from(message.tried_at_ms / 60_000)
        .unwrap_or(0)
        .saturating_add(crate::mesh::MAX_LIFETIME_MINUTES)
}

/// Video records go only over links that carry video.
fn is_video(record: &ChatMessage) -> bool {
    matches!(record, ChatMessage::Video { .. } | ChatMessage::CallVideo { .. })
}

fn failed(connection: ConnectionId, reason: Failure) -> Vec<Action> {
    vec![Action::Failed { connection, reason }, Action::Close { connection }]
}

fn link_failure(error: LinkError) -> Failure {
    match error {
        LinkError::AuthenticationFailed => Failure::AuthenticationFailed,
        _ => Failure::Protocol,
    }
}

impl From<PairingError> for Failure {
    fn from(error: PairingError) -> Self {
        match error {
            PairingError::Rejected => Failure::Rejected,
            PairingError::AuthenticationFailed
            | PairingError::SelfPairing
            | PairingError::Link(LinkError::AuthenticationFailed) => Failure::AuthenticationFailed,
            PairingError::UnknownInvite | PairingError::NotAnInvite => Failure::InvalidInvite,
            PairingError::UnknownRequest => Failure::NotAccepting,
            _ => Failure::Protocol,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;
    use crate::discovery::PRESENCE_TOKEN_LEN;
    use crate::storage::vault::tests::TEST_PARAMS;

    struct Device {
        node: Node,
        dir: tempfile::TempDir,
        pin_record: Vec<u8>,
        /// What the platform would surface to the user.
        shown: Vec<Action>,
    }

    fn device(name: &str) -> Device {
        let dir = tempfile::tempdir().unwrap();
        let (account, pin_record) = Account::create(dir.path(), b"123456", name, TEST_PARAMS).unwrap();
        Device {
            node: Node::new(account).unwrap(),
            dir,
            pin_record,
            shown: Vec::new(),
        }
    }

    /// A perfect transport. `pairs` maps each of A's connection ids to B's id for the same
    /// connection. Delivers frames until both sides are quiet, collecting everything else as shown
    /// to the users.
    fn run(a: &mut Device, b: &mut Device, pairs: &[(ConnectionId, ConnectionId)], first: Vec<Action>, from_a: bool) {
        let mut queue: VecDeque<(bool, Action)> = first.into_iter().map(|action| (from_a, action)).collect();
        while let Some((from_a, action)) = queue.pop_front() {
            match action {
                Action::Send { connection, bytes } => {
                    let pair = pairs
                        .iter()
                        .find(|(a_id, b_id)| connection == if from_a { *a_id } else { *b_id })
                        .expect("frame on an unknown connection");
                    let (target, target_id) = if from_a { (&mut *b, pair.1) } else { (&mut *a, pair.0) };
                    let replies = target.node.on_frame(target_id, &bytes, 1_000);
                    queue.extend(replies.into_iter().map(|reply| (!from_a, reply)));
                }
                other => (if from_a { &mut *a } else { &mut *b }).shown.push(other),
            }
        }
    }

    fn sas_of(device: &Device) -> Option<Sas> {
        device.shown.iter().find_map(|a| match a {
            Action::ShowSas { sas, .. } => Some(*sas),
            _ => None,
        })
    }

    fn paired_names(device: &Device) -> Vec<String> {
        device
            .node
            .account()
            .unwrap()
            .contacts()
            .unwrap()
            .into_iter()
            .map(|c| c.display_name)
            .collect()
    }

    #[test]
    fn nearby_pairing_between_two_nodes() {
        let (mut ayse, mut burak) = (device("Ayşe"), device("Burak"));
        burak.node.open_pairing().unwrap();
        let first = ayse.node.pair_nearby(1).unwrap();
        run(&mut ayse, &mut burak, &[(1, 7)], first, true);
        assert_eq!(sas_of(&ayse), sas_of(&burak));
        assert!(sas_of(&ayse).is_some());

        let confirm = burak.node.confirm_pairing(7);
        run(&mut ayse, &mut burak, &[(1, 7)], confirm, false);
        let confirm = ayse.node.confirm_pairing(1);
        run(&mut ayse, &mut burak, &[(1, 7)], confirm, true);

        assert_eq!(paired_names(&ayse), ["Burak"]);
        assert_eq!(paired_names(&burak), ["Ayşe"]);
        assert!(
            ayse.shown
                .iter()
                .any(|a| matches!(a, Action::Paired { contact, .. } if contact.display_name == "Burak"))
        );
        assert!(burak.shown.iter().any(|a| matches!(a, Action::Close { connection: 7 })));
        assert!(ayse.node.connections.is_empty() && burak.node.connections.is_empty());
    }

    #[test]
    fn nearby_requests_are_refused_unless_add_nearby_is_open() {
        let (mut ayse, mut burak) = (device("Ayşe"), device("Burak"));
        let first = ayse.node.pair_nearby(1).unwrap();
        let replies = burak.node.on_frame(
            7,
            match &first[0] {
                Action::Send { bytes, .. } => bytes,
                _ => unreachable!(),
            },
            1_000,
        );
        assert!(matches!(
            replies[..],
            [
                Action::Failed {
                    reason: Failure::NotAccepting,
                    ..
                },
                Action::Close { .. }
            ]
        ));
        assert!(paired_names(&burak).is_empty());
    }

    #[test]
    fn invite_pairing_between_two_nodes_uses_the_invite_once() {
        let (mut ayse, mut burak, mut cem) = (device("Ayşe"), device("Burak"), device("Cem"));
        let qr = burak.node.create_invite(1_000).unwrap();
        let first = ayse.node.pair_with_invite(1, &qr).unwrap();
        run(&mut ayse, &mut burak, &[(1, 7)], first, true);
        assert_eq!(paired_names(&ayse), ["Burak"]);
        assert_eq!(paired_names(&burak), ["Ayşe"]);

        let first = cem.node.pair_with_invite(2, &qr).unwrap();
        run(&mut cem, &mut burak, &[(2, 8)], first, true);
        assert!(burak.shown.iter().any(|a| matches!(
            a,
            Action::Failed {
                reason: Failure::InvalidInvite,
                ..
            }
        )));
        assert!(paired_names(&cem).is_empty());
    }

    #[test]
    fn expired_invites_are_refused() {
        let (mut ayse, mut burak) = (device("Ayşe"), device("Burak"));
        let qr = burak.node.create_invite(0).unwrap();
        let first = ayse.node.pair_with_invite(1, &qr).unwrap();
        // `run` delivers at t = 1000 s, after the 600 s lifetime.
        run(&mut ayse, &mut burak, &[(1, 7)], first, true);
        assert!(burak.shown.iter().any(|a| matches!(
            a,
            Action::Failed {
                reason: Failure::InvalidInvite,
                ..
            }
        )));
    }

    #[test]
    fn rejecting_tells_the_other_side_and_closing_add_nearby_abandons_pairings() {
        let (mut ayse, mut burak) = (device("Ayşe"), device("Burak"));
        burak.node.open_pairing().unwrap();
        let first = ayse.node.pair_nearby(1).unwrap();
        run(&mut ayse, &mut burak, &[(1, 7)], first, true);

        let reject = burak.node.close_pairing();
        run(&mut ayse, &mut burak, &[(1, 7)], reject, false);
        assert!(ayse.shown.iter().any(|a| matches!(
            a,
            Action::Failed {
                reason: Failure::Rejected,
                ..
            }
        )));
        assert!(paired_names(&ayse).is_empty() && paired_names(&burak).is_empty());
    }

    #[test]
    fn garbage_and_unknown_connections_are_closed() {
        let mut burak = device("Burak");
        assert!(matches!(
            burak.node.on_frame(3, b"hello", 0)[..],
            [
                Action::Failed {
                    reason: Failure::Protocol,
                    ..
                },
                Action::Close { connection: 3 }
            ]
        ));
        assert!(burak.node.confirm_pairing(99).is_empty());
        assert!(burak.node.pair_nearby(5).is_ok());
        assert!(matches!(burak.node.pair_nearby(5), Err(NodeError::ConnectionInUse(5))));
    }

    // Link sessions and chat.

    /// The device's only contact; works while sealed too.
    fn contact_of(device: &Device) -> ContactId {
        *device.node.keys.contacts.keys().next().expect("one contact")
    }

    /// Two devices paired with each other through Nearby Pairing.
    fn paired() -> (Device, Device) {
        let (mut ayse, mut burak) = (device("Ayşe"), device("Burak"));
        burak.node.open_pairing().unwrap();
        let first = ayse.node.pair_nearby(1).unwrap();
        run(&mut ayse, &mut burak, &[(1, 7)], first, true);
        let confirm = burak.node.confirm_pairing(7);
        run(&mut ayse, &mut burak, &[(1, 7)], confirm, false);
        let confirm = ayse.node.confirm_pairing(1);
        run(&mut ayse, &mut burak, &[(1, 7)], confirm, true);
        ayse.shown.clear();
        burak.shown.clear();
        (ayse, burak)
    }

    /// Both see each other's presence; the side that should initiate connects on `ids`
    /// (initiator's id, responder's id). Returns whether Ayşe was the initiator.
    fn link(ayse: &mut Device, burak: &mut Device, ids: (ConnectionId, ConnectionId)) -> bool {
        let a_sees = ayse
            .node
            .recognize_presence(&burak.node.presence_token(1_000), 1_000)
            .unwrap();
        let b_sees = burak
            .node
            .recognize_presence(&ayse.node.presence_token(1_000), 1_000)
            .unwrap();
        assert_eq!(a_sees.contact, contact_of(ayse));
        assert_ne!(a_sees.initiate(), b_sees.initiate(), "exactly one side opens the link");
        if a_sees.initiate() {
            let first = ayse.node.connect_contact(ids.0, contact_of(ayse), 1_000).unwrap();
            run(ayse, burak, &[ids], first, true);
        } else {
            let first = burak.node.connect_contact(ids.0, contact_of(burak), 1_000).unwrap();
            run(burak, ayse, &[ids], first, true);
        }
        assert!(ayse.node.is_linked(contact_of(ayse)) && burak.node.is_linked(contact_of(burak)));
        a_sees.initiate()
    }

    /// Delivers `actions` from `from` to `to` over the link, whatever the initiator was.
    fn deliver(from: &mut Device, to: &mut Device, actions: Vec<Action>) {
        let (from_id, to_id) = (link_id(from), link_id(to));
        run(from, to, &[(from_id, to_id)], actions, true);
    }

    fn link_id(device: &Device) -> ConnectionId {
        device.node.links[&contact_of(device)]
    }

    fn statuses(device: &Device) -> Vec<(String, MessageStatus)> {
        device
            .node
            .messages(contact_of(device))
            .unwrap()
            .into_iter()
            .map(|m| (m.body, m.status))
            .collect()
    }

    #[test]
    fn contacts_link_and_chat() {
        let (mut ayse, mut burak) = paired();
        assert!(
            ayse.node.recognize_presence(&[0; PRESENCE_TOKEN_LEN], 1_000).is_none(),
            "strangers are not recognised"
        );
        link(&mut ayse, &mut burak, (10, 20));
        assert!(ayse.shown.iter().any(|a| matches!(a, Action::LinkUp { .. })));
        assert!(burak.shown.iter().any(|a| matches!(a, Action::LinkUp { .. })));
        let again = ayse
            .node
            .recognize_presence(&burak.node.presence_token(1_000), 1_000)
            .unwrap();
        assert!(!again.initiate(), "no second link while one is up");
        assert_eq!(again.link, Some(link_id(&ayse)));
        assert_eq!(again.may_replace(), again.opener, "only the opener may replace it");

        let (message, actions) = ayse.node.send_message(contact_of(&ayse), "selam Burak").unwrap();
        assert_eq!(message.status, MessageStatus::Sent);
        deliver(&mut ayse, &mut burak, actions);
        assert_eq!(statuses(&ayse), [("selam Burak".into(), MessageStatus::Delivered)]);
        assert_eq!(statuses(&burak), [("selam Burak".into(), MessageStatus::Received)]);
        assert!(
            burak
                .shown
                .iter()
                .any(|a| matches!(a, Action::MessageReceived { message } if message.body == "selam Burak"))
        );

        let (_, actions) = burak.node.send_message(contact_of(&burak), "selam Ayşe 👋").unwrap();
        deliver(&mut burak, &mut ayse, actions);
        assert_eq!(
            statuses(&ayse).last().unwrap(),
            &("selam Ayşe 👋".into(), MessageStatus::Received)
        );
    }

    #[test]
    fn the_chat_list_shows_the_latest_message_and_counts_the_unread() {
        let (mut ayse, mut burak) = paired();
        let burak_at_ayse = contact_of(&ayse);
        let preview = |node: &Node| node.contact_previews().unwrap().remove(0);
        assert_eq!(preview(&ayse.node), (burak_at_ayse, None, 0), "nothing yet");
        link(&mut ayse, &mut burak, (10, 20));
        for text in ["bir", "iki"] {
            let (_, actions) = burak.node.send_message(contact_of(&burak), text).unwrap();
            deliver(&mut burak, &mut ayse, actions);
        }
        let (_, last, unread) = preview(&ayse.node);
        assert_eq!((last.unwrap().body.as_str(), unread), ("iki", 2));
        ayse.node.mark_contact_read(burak_at_ayse).unwrap();
        assert_eq!(preview(&ayse.node).2, 0);
        // Her own message is the latest now, and counts for nothing.
        let (_, actions) = ayse.node.send_message(burak_at_ayse, "üç").unwrap();
        deliver(&mut ayse, &mut burak, actions);
        let (_, last, unread) = preview(&ayse.node);
        let last = last.unwrap();
        assert_eq!((last.body.as_str(), last.outgoing, unread), ("üç", true, 0));
        assert_eq!(preview(&burak.node).2, 1, "Burak has not read it");
    }

    #[test]
    fn messages_wait_for_a_link() {
        let (mut ayse, mut burak) = paired();
        let (queued, actions) = ayse.node.send_message(contact_of(&ayse), "sonra oku").unwrap();
        assert_eq!(queued.status, MessageStatus::Queued);
        assert!(actions.is_empty());
        link(&mut ayse, &mut burak, (10, 20));
        assert_eq!(statuses(&ayse), [("sonra oku".into(), MessageStatus::Delivered)]);
        assert_eq!(statuses(&burak), [("sonra oku".into(), MessageStatus::Received)]);
    }

    #[test]
    fn lost_acknowledgements_lead_to_a_resend_that_is_stored_once() {
        let (mut ayse, mut burak) = paired();
        link(&mut ayse, &mut burak, (10, 20));
        let (_, actions) = ayse.node.send_message(contact_of(&ayse), "bir kez").unwrap();
        // Burak receives the message, but his acknowledgement is lost with the connection.
        let (to_burak, a_id, b_id) = (actions, link_id(&ayse), link_id(&burak));
        for action in to_burak {
            if let Action::Send { bytes, .. } = action {
                burak.shown.extend(burak.node.on_frame(b_id, &bytes, 1_000));
            }
        }
        assert!(
            ayse.node
                .connection_closed(a_id)
                .iter()
                .any(|a| matches!(a, Action::LinkDown { .. }))
        );
        burak.node.connection_closed(b_id);
        assert_eq!(statuses(&ayse), [("bir kez".into(), MessageStatus::Sent)]);

        burak.shown.clear();
        link(&mut ayse, &mut burak, (11, 21));
        assert_eq!(statuses(&ayse), [("bir kez".into(), MessageStatus::Delivered)]);
        assert_eq!(statuses(&burak).len(), 1, "the resend is not stored twice");
        assert!(!burak.shown.iter().any(|a| matches!(a, Action::MessageReceived { .. })));
    }

    #[test]
    fn strangers_and_deleted_contacts_cannot_link() {
        let (mut ayse, mut burak) = paired();
        let (mut cem, mut deniz) = paired();
        // Cem's link handshake, meant for Deniz, reaches Burak: unknown tag.
        let first = cem.node.connect_contact(30, contact_of(&cem), 1_000).unwrap();
        let Action::Send { bytes, .. } = &first[0] else {
            unreachable!()
        };
        assert!(matches!(
            burak.node.on_frame(40, bytes, 1_000)[..],
            [
                Action::Failed {
                    reason: Failure::NotAccepting,
                    ..
                },
                Action::Close { .. }
            ]
        ));
        drop(deniz.node.connection_closed(0));

        link(&mut ayse, &mut burak, (10, 20));
        let closing = burak.node.delete_contact(contact_of(&burak), false).unwrap();
        assert!(closing.iter().any(|a| matches!(a, Action::Close { .. })));
        assert!(!burak.node.is_linked(contact_of(&ayse)));
        let first = ayse.node.connect_contact(12, contact_of(&ayse), 1_000).unwrap();
        let Action::Send { bytes, .. } = &first[0] else {
            unreachable!()
        };
        assert!(matches!(
            burak.node.on_frame(22, bytes, 1_000)[..],
            [
                Action::Failed {
                    reason: Failure::NotAccepting,
                    ..
                },
                Action::Close { .. }
            ]
        ));
    }

    #[test]
    fn moving_a_link_to_a_hotspot_is_negotiated_over_the_link() {
        let (mut ayse, mut burak) = paired();
        assert!(matches!(
            ayse.node.request_move(contact_of(&ayse), MoveTarget::Hotspot),
            Err(NodeError::NotLinked)
        ));
        link(&mut ayse, &mut burak, (10, 20));
        let request = ayse.node.request_move(contact_of(&ayse), MoveTarget::Hotspot).unwrap();
        deliver(&mut ayse, &mut burak, request);
        assert!(burak.shown.iter().any(|a| matches!(
            a,
            Action::MoveRequested {
                target: MoveTarget::Hotspot,
                ..
            }
        )));

        let offer = HotspotOffer {
            ssid: "AndroidShare_1234".into(),
            passphrase: "kV8s2Qx9rT".into(),
            port: 41_000,
        };
        let answer = burak.node.offer_hotspot(contact_of(&burak), offer.clone()).unwrap();
        deliver(&mut burak, &mut ayse, answer);
        assert!(
            ayse.shown
                .iter()
                .any(|a| matches!(a, Action::HotspotOffered { offer: o, .. } if *o == offer))
        );

        // While locked too: moving needs only the link.
        burak.node.seal();
        let no = burak
            .node
            .decline_move(contact_of(&burak), MoveTarget::Hotspot)
            .unwrap();
        deliver(&mut burak, &mut ayse, no);
        assert!(ayse.shown.iter().any(|a| matches!(a, Action::MoveDeclined { .. })));
    }

    #[test]
    fn a_request_for_an_unknown_target_is_declined() {
        let (mut ayse, mut burak) = paired();
        link(&mut ayse, &mut burak, (10, 20));
        let session_of = |device: &mut Device| {
            let id = link_id(device);
            let Some(ConnectionState::Linked { session, .. }) = device.node.connections.get_mut(&id) else {
                panic!("no link");
            };
            seal_chat(session, &ChatMessage::MoveRequest { target: 0x7f }).unwrap()
        };
        let bytes = session_of(&mut ayse);
        let (from, to) = (link_id(&ayse), link_id(&burak));
        let reply = burak.node.on_frame(to, &bytes, 1_000);
        assert!(
            matches!(reply[..], [Action::Send { .. }]),
            "only the decline goes out; nothing is asked of the platform"
        );
        run(&mut ayse, &mut burak, &[(from, to)], reply, false);
        assert!(
            ayse.shown.iter().all(|a| !matches!(a, Action::MoveDeclined { .. })),
            "a decline for a target this version does not know is not reported"
        );
        assert!(ayse.node.is_linked(contact_of(&ayse)), "and the link stays up");
    }

    // Liveness.

    fn closes_link(actions: &[Action]) -> bool {
        actions.iter().any(|a| matches!(a, Action::LinkDown { .. }))
            && actions.iter().any(|a| matches!(a, Action::Close { .. }))
    }

    #[test]
    fn an_idle_link_is_pinged_and_stays_up_while_the_other_end_answers() {
        let (mut ayse, mut burak) = paired();
        link(&mut ayse, &mut burak, (10, 20));
        assert!(ayse.node.tick(1_000).is_empty(), "the first tick only starts the clock");
        assert!(ayse.node.tick(1_000 + LINK_IDLE_SECS - 1).is_empty());
        let ping = ayse.node.tick(1_000 + LINK_IDLE_SECS);
        assert!(matches!(ping[..], [Action::Send { .. }]));
        // Burak answers at once (the harness carries his pong back), so the link stays.
        deliver(&mut ayse, &mut burak, ping);
        let later = ayse.node.tick(1_000 + LINK_IDLE_SECS + LINK_ANSWER_SECS);
        assert!(!closes_link(&later));
        assert!(ayse.node.is_linked(contact_of(&ayse)));
        assert!(
            ayse.shown
                .iter()
                .chain(&burak.shown)
                .all(|a| !matches!(a, Action::LinkDown { .. }))
        );
    }

    #[test]
    fn a_link_whose_other_end_vanished_is_closed() {
        let (mut ayse, mut burak) = paired();
        link(&mut ayse, &mut burak, (10, 20));
        let gone = link_id(&ayse);
        ayse.node.tick(1_000);
        // Burak's Wi-Fi went away: the ping never arrives, nothing comes back.
        let ping = ayse.node.tick(1_000 + LINK_IDLE_SECS);
        assert!(matches!(ping[..], [Action::Send { .. }]));
        assert!(!closes_link(
            &ayse.node.tick(1_000 + LINK_IDLE_SECS + LINK_ANSWER_SECS - 1)
        ));
        let lost = ayse.node.tick(1_000 + LINK_IDLE_SECS + LINK_ANSWER_SECS);
        assert!(closes_link(&lost));
        assert!(!ayse.node.is_linked(contact_of(&ayse)));
        assert!(
            ayse.node.on_frame(gone, &[0; 80], 1_100).is_empty(),
            "a late frame is dropped"
        );
        assert!(ayse.node.connection_closed(gone).is_empty());
    }

    #[test]
    fn a_handshake_the_other_end_never_answers_is_given_up() {
        let (mut ayse, mut burak) = paired();
        let opener_is_ayse = ayse
            .node
            .recognize_presence(&burak.node.presence_token(1_000), 1_000)
            .unwrap()
            .opener;
        let (opener, other) = if opener_is_ayse {
            (&mut ayse, &burak)
        } else {
            (&mut burak, &ayse)
        };
        let token = other.node.presence_token(1_000);
        let contact = contact_of(opener);
        opener.node.connect_contact(10, contact, 1_000).unwrap(); // the other app hangs
        assert!(
            !opener.node.recognize_presence(&token, 1_000).unwrap().initiate(),
            "no second try meanwhile"
        );
        assert!(opener.node.tick(1_000 + LINK_ANSWER_SECS - 1).is_empty());
        let given_up = opener.node.tick(1_000 + LINK_ANSWER_SECS);
        assert!(matches!(given_up[..], [Action::Close { connection: 10 }]));
        assert!(opener.node.connection_closed(10).is_empty());
        assert!(
            opener.node.recognize_presence(&token, 1_000).unwrap().initiate(),
            "the contact can be tried again"
        );
    }

    #[test]
    fn an_unanswered_message_shows_the_link_is_gone_and_waits_for_the_next() {
        let (mut ayse, mut burak) = paired();
        link(&mut ayse, &mut burak, (10, 20));
        ayse.node.tick(1_000);
        let (_, lost_on_the_way) = ayse.node.send_message(contact_of(&ayse), "kayıp").unwrap();
        assert!(!lost_on_the_way.is_empty());
        assert!(ayse.node.tick(1_005).is_empty(), "the wait for an answer starts");
        assert!(!closes_link(&ayse.node.tick(1_005 + LINK_ANSWER_SECS - 1)));
        assert!(closes_link(&ayse.node.tick(1_005 + LINK_ANSWER_SECS)));
        assert_eq!(statuses(&ayse), [("kayıp".into(), MessageStatus::Sent)]);

        // Burak's end still believes in the old link; a new one replaces it and the message arrives.
        let opener_is_ayse = ayse
            .node
            .recognize_presence(&burak.node.presence_token(1_000), 1_000)
            .unwrap()
            .opener;
        let (initiator, responder) = if opener_is_ayse {
            (&mut ayse, &mut burak)
        } else {
            (&mut burak, &mut ayse)
        };
        let contact = contact_of(initiator);
        let first = initiator.node.connect_contact(11, contact, 1_000).unwrap();
        // The old link was 10 (opener) to 20; a close record may still cross it.
        run(initiator, responder, &[(11, 21), (10, 20)], first, true);
        assert_eq!(statuses(&ayse), [("kayıp".into(), MessageStatus::Delivered)]);
        assert_eq!(statuses(&burak), [("kayıp".into(), MessageStatus::Received)]);
    }

    #[test]
    fn a_pairing_cut_off_midway_fails() {
        let (mut ayse, mut burak) = (device("Ayşe"), device("Burak"));
        burak.node.open_pairing().unwrap();
        let first = ayse.node.pair_nearby(1).unwrap();
        assert!(matches!(first[..], [Action::Send { connection: 1, .. }]));
        assert!(matches!(
            ayse.node.connection_closed(1)[..],
            [Action::Failed {
                connection: 1,
                reason: Failure::ConnectionLost
            }]
        ));
        assert!(ayse.node.connection_closed(1).is_empty(), "reported once");

        // A finished pairing is not reported again when its connection closes.
        let (mut ayse, mut burak) = paired();
        assert!(ayse.node.connection_closed(1).is_empty());
        assert!(burak.node.connection_closed(7).is_empty());
    }

    #[test]
    fn a_new_link_replaces_the_old_one() {
        let (mut ayse, mut burak) = paired();
        let ayse_initiated = link(&mut ayse, &mut burak, (10, 20));
        let (old_a, old_b) = (link_id(&ayse), link_id(&burak));
        // The initiator reconnects (e.g. after a network change) while the old link looks alive.
        let (initiator, responder) = if ayse_initiated {
            (&mut ayse, &mut burak)
        } else {
            (&mut burak, &mut ayse)
        };
        let contact = contact_of(initiator);
        let first = initiator.node.connect_contact(11, contact, 1_000).unwrap();
        run(initiator, responder, &[(11, 21), (10, 20)], first, true);
        assert_ne!((link_id(&ayse), link_id(&burak)), (old_a, old_b));
        assert!(
            ayse.shown
                .iter()
                .chain(&burak.shown)
                .any(|a| matches!(a, Action::Close { connection } if *connection == 10 || *connection == 20))
        );
        // Both sides closed the old link and sent a close record on it; each record reached a
        // connection its receiver had already closed and was dropped, not read as a new connection.
        assert!(
            !ayse
                .shown
                .iter()
                .chain(&burak.shown)
                .any(|a| matches!(a, Action::Failed { .. } | Action::LinkDown { .. })),
            "replacing a link raises no failure and no link loss"
        );
        // The transports then report the old connections closed: still no link loss.
        assert!(ayse.node.connection_closed(old_a).is_empty());
        assert!(burak.node.connection_closed(old_b).is_empty());
        assert!(ayse.node.is_linked(contact_of(&ayse)) && burak.node.is_linked(contact_of(&burak)));
        let (_, actions) = ayse.node.send_message(contact_of(&ayse), "yeni hat").unwrap();
        deliver(&mut ayse, &mut burak, actions);
        assert_eq!(statuses(&burak).last().unwrap().1, MessageStatus::Received);
    }

    /// Marks the connections of a link (both sides' ids) as Bluetooth, for setup only (§7.3).
    fn over_bluetooth(ayse: &mut Device, burak: &mut Device, ids: (ConnectionId, ConnectionId)) {
        for device in [ayse, burak] {
            device.node.setup_only(ids.0);
            device.node.setup_only(ids.1);
        }
    }

    #[test]
    fn a_bluetooth_link_carries_no_data_until_the_link_moves_to_wifi() {
        let (mut ayse, mut burak) = paired();
        let (queued, _) = ayse.node.send_message(contact_of(&ayse), "Wi-Fi'ı bekle").unwrap();
        assert_eq!(queued.status, MessageStatus::Queued);
        over_bluetooth(&mut ayse, &mut burak, (10, 20));
        let ayse_initiated = link(&mut ayse, &mut burak, (10, 20));
        assert_eq!(statuses(&burak), [], "nothing over Bluetooth");
        assert!(
            ayse.shown
                .iter()
                .any(|a| matches!(a, Action::WaitingForWifi { contact } if *contact == contact_of(&ayse)))
        );
        let (_, actions) = ayse.node.send_message(contact_of(&ayse), "bir tane daha").unwrap();
        assert!(!actions.iter().any(|a| matches!(a, Action::Send { .. })));
        assert!(actions.iter().any(|a| matches!(a, Action::WaitingForWifi { .. })));
        assert!(matches!(
            ayse.node.start_call(contact_of(&ayse), false),
            Err(NodeError::NeedsWifi)
        ));
        assert!(matches!(
            burak.node.start_talk(contact_of(&burak)),
            Err(NodeError::NeedsWifi)
        ));

        // Setting up Wi-Fi goes over it.
        let ask = ayse.node.request_move(contact_of(&ayse), MoveTarget::Hotspot).unwrap();
        deliver(&mut ayse, &mut burak, ask);
        assert!(burak.shown.iter().any(|a| matches!(a, Action::MoveRequested { .. })));

        // The link moves to Wi-Fi: what waited goes out.
        let (initiator, responder) = if ayse_initiated {
            (&mut ayse, &mut burak)
        } else {
            (&mut burak, &mut ayse)
        };
        let contact = contact_of(initiator);
        let first = initiator.node.connect_contact(11, contact, 1_000).unwrap();
        run(initiator, responder, &[(11, 21), (10, 20)], first, true);
        assert_eq!(
            statuses(&burak),
            [
                ("Wi-Fi'ı bekle".into(), MessageStatus::Received),
                ("bir tane daha".into(), MessageStatus::Received)
            ]
        );
        assert!(ayse.node.start_call(contact_of(&ayse), false).is_ok());
    }

    #[test]
    fn a_bluetooth_link_does_not_replace_one_over_wifi() {
        let (mut ayse, mut burak) = paired();
        let ayse_initiated = link(&mut ayse, &mut burak, (10, 20));
        let wifi = (link_id(&ayse), link_id(&burak));
        let (initiator, responder) = if ayse_initiated {
            (&mut ayse, &mut burak)
        } else {
            (&mut burak, &mut ayse)
        };
        over_bluetooth(initiator, responder, (11, 21));
        let contact = contact_of(initiator);
        let first = initiator.node.connect_contact(11, contact, 1_000).unwrap();
        run(initiator, responder, &[(11, 21), (10, 20)], first, true);
        assert_eq!((link_id(&ayse), link_id(&burak)), wifi, "the Wi-Fi link stays");
        let (_, actions) = ayse.node.send_message(contact_of(&ayse), "hâlâ Wi-Fi").unwrap();
        deliver(&mut ayse, &mut burak, actions);
        assert_eq!(statuses(&burak).last().unwrap().1, MessageStatus::Received);
    }

    // Locked (sealed) operation.

    fn unseal(device: &mut Device) -> Vec<Action> {
        let account = Account::unlock_with_pin(device.dir.path(), &device.pin_record, b"123456").unwrap();
        device.node.unseal(account).unwrap()
    }

    #[test]
    fn messages_arriving_while_locked_wait_encrypted_until_unlock() {
        let (mut ayse, mut burak) = paired();
        link(&mut ayse, &mut burak, (10, 20));
        burak.node.seal();
        assert!(burak.node.is_sealed());
        assert!(matches!(burak.node.messages(contact_of(&ayse)), Err(NodeError::Sealed)));

        let (_, actions) = ayse.node.send_message(contact_of(&ayse), "kilitliyken geldi").unwrap();
        deliver(&mut ayse, &mut burak, actions);
        assert!(burak.shown.iter().any(|a| matches!(a, Action::MessageArrived { .. })));
        assert!(
            !burak.shown.iter().any(|a| matches!(a, Action::MessageReceived { .. })),
            "no content while locked"
        );
        assert_eq!(
            statuses(&ayse),
            [("kilitliyken geldi".into(), MessageStatus::Delivered)]
        );

        let inbox = burak.dir.path().join("inbox");
        let bytes = std::fs::read(&inbox).unwrap();
        assert!(
            !bytes.windows(17).any(|w| w == b"kilitliyken geldi"),
            "inbox holds no plaintext"
        );

        let arrived = unseal(&mut burak);
        assert!(
            arrived
                .iter()
                .any(|a| matches!(a, Action::MessageReceived { message } if message.body == "kilitliyken geldi"))
        );
        assert_eq!(
            statuses(&burak),
            [("kilitliyken geldi".into(), MessageStatus::Received)]
        );
        assert!(!inbox.exists(), "the inbox is emptied into the database");
        assert!(
            burak.node.is_linked(contact_of(&burak)),
            "the link survived locking and unlocking"
        );
    }

    #[test]
    fn messages_received_while_locked_survive_the_app_being_killed() {
        let (mut ayse, mut burak) = paired();
        link(&mut ayse, &mut burak, (10, 20));
        burak.node.seal();
        let (_, actions) = ayse.node.send_message(contact_of(&ayse), "süreç öldü").unwrap();
        deliver(&mut ayse, &mut burak, actions);
        assert_eq!(statuses(&ayse), [("süreç öldü".into(), MessageStatus::Delivered)]);

        // The OS kills the locked app; the next unlock starts a new node from the database.
        let account = Account::unlock_with_pin(burak.dir.path(), &burak.pin_record, b"123456").unwrap();
        burak.node = Node::new(account).unwrap();
        assert_eq!(statuses(&burak), [("süreç öldü".into(), MessageStatus::Received)]);
        assert!(!burak.dir.path().join("inbox").exists());
    }

    #[test]
    fn messages_queued_before_locking_are_delivered_while_locked() {
        let (mut ayse, mut burak) = paired();
        let (queued, _) = ayse.node.send_message(contact_of(&ayse), "yolda").unwrap();
        assert_eq!(queued.status, MessageStatus::Queued);
        ayse.node.seal();
        link(&mut ayse, &mut burak, (10, 20));
        assert_eq!(statuses(&burak), [("yolda".into(), MessageStatus::Received)]);
        unseal(&mut ayse);
        assert_eq!(statuses(&ayse), [("yolda".into(), MessageStatus::Delivered)]);
    }

    #[test]
    fn a_locked_node_neither_pairs_nor_opens_its_account() {
        let (mut ayse, mut burak) = (device("Ayşe"), device("Burak"));
        burak.node.open_pairing().unwrap();
        burak.node.seal();
        assert!(matches!(burak.node.open_pairing(), Err(NodeError::Sealed)));
        assert!(matches!(burak.node.create_invite(0), Err(NodeError::Sealed)));
        assert!(matches!(burak.node.send_message(1, "x"), Err(NodeError::Sealed)));
        let first = ayse.node.pair_nearby(1).unwrap();
        run(&mut ayse, &mut burak, &[(1, 7)], first, true);
        assert!(burak.shown.iter().any(|a| matches!(
            a,
            Action::Failed {
                reason: Failure::NotAccepting,
                ..
            }
        )));
    }

    #[test]
    fn a_resend_received_while_locked_is_stored_once() {
        let (mut ayse, mut burak) = paired();
        link(&mut ayse, &mut burak, (10, 20));
        burak.node.seal();
        let (_, actions) = ayse.node.send_message(contact_of(&ayse), "tekrar").unwrap();
        let (a_id, b_id) = (link_id(&ayse), link_id(&burak));
        for action in actions {
            if let Action::Send { bytes, .. } = action {
                burak.node.on_frame(b_id, &bytes, 1_000); // the acknowledgement is lost
            }
        }
        ayse.node.connection_closed(a_id);
        burak.node.connection_closed(b_id);
        link(&mut ayse, &mut burak, (11, 21));
        assert_eq!(statuses(&ayse), [("tekrar".into(), MessageStatus::Delivered)]);
        unseal(&mut burak);
        assert_eq!(statuses(&burak).len(), 1);
    }

    #[test]
    fn unsealing_needs_the_same_account() {
        let (mut ayse, other) = (device("Ayşe"), device("Başkası"));
        ayse.node.seal();
        let wrong = Account::unlock_with_pin(other.dir.path(), &other.pin_record, b"123456").unwrap();
        drop(other.node);
        assert!(matches!(ayse.node.unseal(wrong), Err(NodeError::WrongAccount)));
        assert!(ayse.node.is_sealed());
    }

    // Files.

    fn sample(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 7 + i / 251) as u8).collect()
    }

    /// Sends `data` as a file to the device's contact, written in uneven parts.
    fn send_file(device: &mut Device, data: &[u8]) -> (StoredMessage, Vec<Action>) {
        let contact = contact_of(device);
        let file = device
            .node
            .begin_file(contact, "tatil.jpg", "image/jpeg", Some(vec![1; 100]))
            .unwrap();
        for part in data.chunks(10_000) {
            device.node.write_file(file, part).unwrap();
        }
        device.node.finish_file(file).unwrap()
    }

    /// The device's latest file message.
    fn last_file(device: &Device) -> (StoredMessage, crate::storage::Attachment) {
        let message = device
            .node
            .messages(contact_of(device))
            .unwrap()
            .into_iter()
            .rev()
            .find(|m| m.attachment.is_some())
            .expect("a file message");
        let attachment = message.attachment.clone().unwrap();
        (message, attachment)
    }

    fn stored_bytes(device: &Device) -> Vec<u8> {
        let mut all = Vec::new();
        for entry in std::fs::read_dir(device.dir.path().join("files")).unwrap() {
            all.extend(std::fs::read(entry.unwrap().path()).unwrap());
        }
        all
    }

    #[test]
    fn files_are_offered_then_fetched_on_request() {
        let (mut ayse, mut burak) = paired();
        link(&mut ayse, &mut burak, (10, 20));
        let data = sample(40 * CHUNK_LEN + 100);
        let (offered, actions) = send_file(&mut ayse, &data);
        assert_eq!(offered.status, MessageStatus::Sent);
        let sent = offered.attachment.unwrap();
        assert_eq!((sent.size, sent.state), (data.len() as u64, AttachmentState::Complete));
        deliver(&mut ayse, &mut burak, actions);

        assert_eq!(last_file(&ayse).0.status, MessageStatus::Delivered);
        let (message, attachment) = last_file(&burak);
        assert_eq!(message.status, MessageStatus::Received);
        assert_eq!(
            (attachment.name.as_str(), attachment.mime.as_str(), attachment.size),
            ("tatil.jpg", "image/jpeg", data.len() as u64)
        );
        assert_eq!(attachment.thumbnail, Some(vec![1; 100]));
        assert_eq!(attachment.state, AttachmentState::Offered, "nothing is fetched unasked");

        let actions = burak.node.download(message.id).unwrap();
        deliver(&mut burak, &mut ayse, actions);
        let (_, attachment) = last_file(&burak);
        assert_eq!(attachment.state, AttachmentState::Complete);
        assert_eq!(*burak.node.read_file(message.id, 0, data.len()).unwrap(), data);
        assert_eq!(
            *burak.node.read_file(message.id, CHUNK_LEN as u64 - 5, 10).unwrap(),
            data[CHUNK_LEN - 5..CHUNK_LEN + 5]
        );
        assert!(
            burak.shown.iter().any(|a| matches!(
                a,
                Action::MessageUpdated { message } if message.attachment.as_ref().unwrap().state == AttachmentState::Complete
            ))
        );
        for device in [&ayse, &burak] {
            let stored = stored_bytes(device);
            assert!(stored.len() > data.len());
            assert!(
                !stored.windows(64).any(|w| w == &data[1000..1064]),
                "files are encrypted at rest"
            );
        }
    }

    #[test]
    fn empty_and_single_chunk_files_arrive() {
        let (mut ayse, mut burak) = paired();
        link(&mut ayse, &mut burak, (10, 20));
        for data in [Vec::new(), sample(5), sample(CHUNK_LEN)] {
            let (_, actions) = send_file(&mut ayse, &data);
            deliver(&mut ayse, &mut burak, actions);
            let (message, _) = last_file(&burak);
            let actions = burak.node.download(message.id).unwrap();
            deliver(&mut burak, &mut ayse, actions);
            assert_eq!(last_file(&burak).1.state, AttachmentState::Complete);
            assert_eq!(*burak.node.read_file(message.id, 0, CHUNK_LEN * 2).unwrap(), data);
        }
    }

    #[test]
    fn a_file_finished_without_a_link_is_offered_when_one_comes_up() {
        let (mut ayse, mut burak) = paired();
        let data = sample(3 * CHUNK_LEN);
        let (queued, actions) = send_file(&mut ayse, &data);
        assert_eq!(queued.status, MessageStatus::Queued);
        assert!(actions.is_empty());
        link(&mut ayse, &mut burak, (10, 20));
        assert_eq!(last_file(&ayse).0.status, MessageStatus::Delivered);
        let (message, _) = last_file(&burak);
        let actions = burak.node.download(message.id).unwrap();
        deliver(&mut burak, &mut ayse, actions);
        assert_eq!(*burak.node.read_file(message.id, 0, data.len()).unwrap(), data);
    }

    /// Starts Burak fetching Ayşe's file but lets only `chunks` chunks through before both lose the
    /// connection.
    fn interrupted_download(ayse: &mut Device, burak: &mut Device, data: &[u8], chunks: usize) -> i64 {
        link(ayse, burak, (10, 20));
        let (_, actions) = send_file(ayse, data);
        deliver(ayse, burak, actions);
        let (message, _) = last_file(burak);
        let (a_id, b_id) = (link_id(ayse), link_id(burak));
        let mut chunk_frames = Vec::new();
        for action in burak.node.download(message.id).unwrap() {
            if let Action::Send { bytes, .. } = action {
                chunk_frames.extend(
                    ayse.node
                        .on_frame(a_id, &bytes, 1_000)
                        .into_iter()
                        .filter_map(|a| match a {
                            Action::Send { bytes, .. } => Some(bytes),
                            _ => None,
                        }),
                );
            }
        }
        assert_eq!(chunk_frames.len(), REQUEST_BATCH as usize);
        for bytes in &chunk_frames[..chunks] {
            burak.node.on_frame(b_id, bytes, 1_000);
        }
        ayse.node.connection_closed(a_id);
        burak.node.connection_closed(b_id);
        message.id
    }

    #[test]
    fn a_download_goes_on_where_it_stopped_when_the_link_comes_back() {
        let (mut ayse, mut burak) = paired();
        let data = sample(20 * CHUNK_LEN + 7);
        let file = interrupted_download(&mut ayse, &mut burak, &data, 5);
        let (_, attachment) = last_file(&burak);
        assert_eq!(attachment.state, AttachmentState::Downloading);

        link(&mut ayse, &mut burak, (11, 21));
        assert_eq!(last_file(&burak).1.state, AttachmentState::Complete);
        assert_eq!(*burak.node.read_file(file, 0, data.len()).unwrap(), data);
    }

    #[test]
    fn a_download_survives_the_app_being_killed() {
        let (mut ayse, mut burak) = paired();
        let data = sample(20 * CHUNK_LEN + 7);
        let file = interrupted_download(&mut ayse, &mut burak, &data, 11);
        // Progress is recorded every 8 chunks; the rest is fetched again.
        assert_eq!(last_file(&burak).1.stored, 8 * CHUNK_LEN as u64);

        let account = Account::unlock_with_pin(burak.dir.path(), &burak.pin_record, b"123456").unwrap();
        burak.node = Node::new(account).unwrap();
        link(&mut ayse, &mut burak, (11, 21));
        assert_eq!(last_file(&burak).1.state, AttachmentState::Complete);
        assert_eq!(*burak.node.read_file(file, 0, data.len()).unwrap(), data);
    }

    #[test]
    fn a_locked_sender_is_asked_again_later() {
        let (mut ayse, mut burak) = paired();
        link(&mut ayse, &mut burak, (10, 20));
        let data = sample(2 * CHUNK_LEN);
        let (_, actions) = send_file(&mut ayse, &data);
        deliver(&mut ayse, &mut burak, actions);
        // The platform has been ticking all along.
        burak.node.tick(1_000);
        ayse.node.seal();
        let (message, _) = last_file(&burak);
        let actions = burak.node.download(message.id).unwrap();
        deliver(&mut burak, &mut ayse, actions);
        assert_eq!(last_file(&burak).1.state, AttachmentState::Downloading);

        unseal(&mut ayse);
        let early = burak.node.tick(1_000);
        assert!(!early.iter().any(|a| matches!(a, Action::Send { .. })));
        let retry = burak.node.tick(1_000 + NOT_NOW_RETRY_SECS);
        deliver(&mut burak, &mut ayse, retry);
        assert_eq!(last_file(&burak).1.state, AttachmentState::Complete);
        assert_eq!(*burak.node.read_file(message.id, 0, data.len()).unwrap(), data);
    }

    #[test]
    fn a_file_the_sender_no_longer_has_is_gone() {
        let (mut ayse, mut burak) = paired();
        link(&mut ayse, &mut burak, (10, 20));
        let (sent, actions) = send_file(&mut ayse, &sample(100));
        deliver(&mut ayse, &mut burak, actions);
        ayse.node.account().unwrap().discard_file(sent.id).unwrap();
        let (message, _) = last_file(&burak);
        let actions = burak.node.download(message.id).unwrap();
        deliver(&mut burak, &mut ayse, actions);
        assert_eq!(last_file(&burak).1.state, AttachmentState::Gone);
    }

    #[test]
    fn only_files_offered_to_the_asking_contact_are_served() {
        let (mut ayse, mut burak) = paired();
        link(&mut ayse, &mut burak, (10, 20));
        let (_, actions) = send_file(&mut ayse, &sample(100));
        deliver(&mut ayse, &mut burak, actions);
        // Burak asks Ayşe for the file she offered him as if he had offered it: she has no such
        // outgoing file of his, and his own copy is not served back.
        let (message, _) = last_file(&burak);
        let request = ChatMessage::ChunkRequest {
            id: message.message_id,
            first: 0,
            count: 1,
        };
        let answer = ayse.node.serve_chunks(contact_of(&ayse), &message.message_id, 0, 1);
        assert!(
            matches!(answer[..], [ChatMessage::Chunk { .. }]),
            "Ayşe serves her own file"
        );
        let answer = burak.node.serve_chunks(contact_of(&burak), &message.message_id, 0, 1);
        assert_eq!(
            answer,
            [ChatMessage::FileUnavailable {
                id: message.message_id,
                reason: Unavailable::Gone
            }],
            "{request:?} is not served from an incoming copy"
        );
    }

    #[test]
    fn files_offered_while_locked_wait_in_the_inbox() {
        let (mut ayse, mut burak) = paired();
        link(&mut ayse, &mut burak, (10, 20));
        burak.node.seal();
        let data = sample(CHUNK_LEN + 1);
        let (_, actions) = send_file(&mut ayse, &data);
        deliver(&mut ayse, &mut burak, actions);
        assert_eq!(last_file(&ayse).0.status, MessageStatus::Delivered);
        assert!(burak.shown.iter().any(|a| matches!(a, Action::MessageArrived { .. })));
        let inbox = std::fs::read(burak.dir.path().join("inbox")).unwrap();
        assert!(!inbox.windows(9).any(|w| w == b"tatil.jpg"), "the inbox holds no names");

        unseal(&mut burak);
        let (message, attachment) = last_file(&burak);
        assert_eq!(attachment.state, AttachmentState::Offered);
        let actions = burak.node.download(message.id).unwrap();
        deliver(&mut burak, &mut ayse, actions);
        assert_eq!(*burak.node.read_file(message.id, 0, data.len()).unwrap(), data);
    }

    #[test]
    fn a_file_finished_before_locking_is_offered_after_unlocking() {
        let (mut ayse, mut burak) = paired();
        let (queued, _) = send_file(&mut ayse, &sample(10));
        assert_eq!(queued.status, MessageStatus::Queued);
        ayse.node.seal();
        link(&mut ayse, &mut burak, (10, 20));
        assert!(
            burak.node.messages(contact_of(&burak)).unwrap().is_empty(),
            "no offers while locked"
        );
        unseal(&mut ayse);
        let link = link_id(&ayse);
        let caught_up = ayse.node.tick(1_000);
        assert!(
            caught_up
                .iter()
                .any(|a| matches!(a, Action::Send { connection, .. } if *connection == link))
        );
        deliver(&mut ayse, &mut burak, caught_up);
        assert_eq!(last_file(&ayse).0.status, MessageStatus::Delivered);
        assert_eq!(last_file(&burak).1.state, AttachmentState::Offered);
    }

    #[test]
    fn unfinished_and_aborted_files_leave_nothing_behind() {
        let (mut ayse, _burak) = paired();
        let contact = contact_of(&ayse);
        let aborted = ayse
            .node
            .begin_file(contact, "a.bin", "application/octet-stream", None)
            .unwrap();
        ayse.node.write_file(aborted, &sample(2 * CHUNK_LEN)).unwrap();
        ayse.node.abort_file(aborted).unwrap();
        let unfinished = ayse
            .node
            .begin_file(contact, "b.bin", "application/octet-stream", None)
            .unwrap();
        ayse.node.write_file(unfinished, &sample(2 * CHUNK_LEN)).unwrap();
        assert!(
            ayse.node.messages(contact).unwrap().is_empty(),
            "unfinished files are not shown"
        );

        // The app dies while writing.
        let account = Account::unlock_with_pin(ayse.dir.path(), &ayse.pin_record, b"123456").unwrap();
        ayse.node = Node::new(account).unwrap();
        assert!(stored_bytes(&ayse).is_empty());
        assert!(matches!(
            ayse.node.write_file(unfinished, b"x"),
            Err(NodeError::NoSuchFile)
        ));
    }

    #[test]
    fn deleting_a_contact_deletes_their_files() {
        let (mut ayse, mut burak) = paired();
        link(&mut ayse, &mut burak, (10, 20));
        let (_, actions) = send_file(&mut ayse, &sample(2 * CHUNK_LEN));
        deliver(&mut ayse, &mut burak, actions);
        let (message, _) = last_file(&burak);
        let actions = burak.node.download(message.id).unwrap();
        deliver(&mut burak, &mut ayse, actions);
        assert!(!stored_bytes(&ayse).is_empty() && !stored_bytes(&burak).is_empty());

        for device in [&mut ayse, &mut burak] {
            let contact = contact_of(device);
            device.node.delete_contact(contact, false).unwrap();
            assert!(stored_bytes(device).is_empty(), "no file content is left");
        }
    }

    #[test]
    fn invalid_files_are_refused() {
        let (mut ayse, _burak) = paired();
        let contact = contact_of(&ayse);
        for (name, mime) in [("", "a/b"), ("a\nb", "a/b"), ("a", "nomime"), ("a", "a/b c")] {
            assert!(
                matches!(
                    ayse.node.begin_file(contact, name, mime, None),
                    Err(NodeError::Chat(ChatError::InvalidFile))
                ),
                "{name:?} {mime:?}"
            );
        }
        assert!(matches!(
            ayse.node.begin_file(contact + 1, "a", "a/b", None),
            Err(NodeError::UnknownContact)
        ));
    }

    // Contacts: permissions, blocking, deleting (requirements C-5 to C-7).

    fn permissions(messages: bool, auto_download: bool) -> Permissions {
        Permissions {
            messages,
            ptt: false,
            auto_download,
        }
    }

    /// Nearby Pairing again between two devices that may already know each other.
    fn pair_again(ayse: &mut Device, burak: &mut Device) {
        // Not the first pairing's connection ids: those are still closing.
        burak.node.open_pairing().unwrap();
        let first = ayse.node.pair_nearby(2).unwrap();
        run(ayse, burak, &[(2, 8)], first, true);
        let confirm = burak.node.confirm_pairing(8);
        run(ayse, burak, &[(2, 8)], confirm, false);
        let confirm = ayse.node.confirm_pairing(2);
        run(ayse, burak, &[(2, 8)], confirm, true);
    }

    fn state_of(device: &Device, contact: ContactId) -> crate::storage::ContactState {
        device.node.account().unwrap().contact(contact).unwrap().unwrap().state
    }

    #[test]
    fn messages_from_a_contact_without_permission_are_refused() {
        let (mut ayse, mut burak) = paired();
        burak
            .node
            .set_permissions(contact_of(&burak), permissions(false, false))
            .unwrap();
        link(&mut ayse, &mut burak, (10, 20));
        let (_, actions) = ayse.node.send_message(contact_of(&ayse), "duyuyor musun").unwrap();
        deliver(&mut ayse, &mut burak, actions);
        let (_, actions) = send_file(&mut ayse, &sample(100));
        deliver(&mut ayse, &mut burak, actions);
        assert!(
            burak.node.messages(contact_of(&burak)).unwrap().is_empty(),
            "nothing is stored"
        );
        assert!(!burak.shown.iter().any(|a| matches!(a, Action::MessageReceived { .. })));
        let sent: Vec<MessageStatus> = ayse
            .node
            .messages(contact_of(&ayse))
            .unwrap()
            .iter()
            .map(|m| m.status)
            .collect();
        assert_eq!(sent, [MessageStatus::Refused, MessageStatus::Refused]);

        // Refused messages are not sent again, also not once messages are allowed again.
        let (a_id, b_id) = (link_id(&ayse), link_id(&burak));
        ayse.node.connection_closed(a_id);
        burak.node.connection_closed(b_id);
        burak
            .node
            .set_permissions(contact_of(&burak), Permissions::default())
            .unwrap();
        link(&mut ayse, &mut burak, (11, 21));
        assert!(burak.node.messages(contact_of(&burak)).unwrap().is_empty());
        let (_, actions) = ayse.node.send_message(contact_of(&ayse), "şimdi?").unwrap();
        deliver(&mut ayse, &mut burak, actions);
        assert_eq!(statuses(&burak), [("şimdi?".into(), MessageStatus::Received)]);
    }

    #[test]
    fn locked_devices_refuse_and_learn_of_refusals_too() {
        let (mut ayse, mut burak) = paired();
        burak
            .node
            .set_permissions(contact_of(&burak), permissions(false, false))
            .unwrap();
        let (queued, _) = ayse.node.send_message(contact_of(&ayse), "kilitliyken").unwrap();
        assert_eq!(queued.status, MessageStatus::Queued);
        ayse.node.seal();
        burak.node.seal();
        link(&mut ayse, &mut burak, (10, 20));
        unseal(&mut burak);
        assert!(burak.node.messages(contact_of(&burak)).unwrap().is_empty());
        unseal(&mut ayse);
        assert_eq!(statuses(&ayse), [("kilitliyken".into(), MessageStatus::Refused)]);
    }

    #[test]
    fn a_blocked_contact_is_neither_recognised_nor_linked() {
        let (mut ayse, mut burak) = paired();
        let ayse_for_burak = contact_of(&burak);
        link(&mut ayse, &mut burak, (10, 20));
        let a_id = link_id(&ayse);
        let closing = burak.node.block_contact(ayse_for_burak).unwrap();
        assert!(closing.iter().any(|a| matches!(a, Action::Close { .. })));
        assert!(
            closing
                .iter()
                .any(|a| matches!(a, Action::LinkDown { contact } if *contact == ayse_for_burak))
        );
        assert!(!burak.node.is_linked(ayse_for_burak));
        assert_eq!(state_of(&burak, ayse_for_burak), crate::storage::ContactState::Blocked);
        ayse.node.connection_closed(a_id);

        // Burak no longer recognises her, nor messages her...
        assert!(
            burak
                .node
                .recognize_presence(&ayse.node.presence_token(1_000), 1_000)
                .is_none()
        );
        assert!(matches!(
            burak.node.send_message(ayse_for_burak, "x"),
            Err(NodeError::UnknownContact)
        ));
        // ...and her connections fail like a stranger's, with nothing sent back.
        let (queued, _) = ayse.node.send_message(contact_of(&ayse), "orada mısın").unwrap();
        assert_eq!(queued.status, MessageStatus::Queued);
        let first = ayse.node.connect_contact(30, contact_of(&ayse), 1_000).unwrap();
        let Action::Send { bytes, .. } = &first[0] else {
            panic!("a handshake message")
        };
        let answer = burak.node.on_frame(40, bytes, 1_000);
        assert!(answer.iter().any(|a| matches!(a, Action::Close { connection: 40 })));
        assert!(!answer.iter().any(|a| matches!(a, Action::Send { .. })));
        ayse.node.connection_closed(30);

        burak.node.unblock_contact(ayse_for_burak).unwrap();
        // Blocking her gave Burak a new presence key: she cannot see him, so he opens the link and
        // hands it over; then she recognises him again (§5.4).
        let token = burak.node.presence_token(1_000);
        assert!(ayse.node.recognize_presence(&token, 1_000).is_none());
        let seen = burak
            .node
            .recognize_presence(&ayse.node.presence_token(1_000), 1_000)
            .unwrap();
        assert!(seen.initiate());
        let first = burak.node.connect_contact(21, ayse_for_burak, 1_000).unwrap();
        run(&mut ayse, &mut burak, &[(11, 21)], first, false);
        assert!(ayse.node.recognize_presence(&token, 1_000).is_some());
        assert_eq!(statuses(&burak), [("orada mısın".into(), MessageStatus::Received)]);
    }

    #[test]
    fn pairing_again_with_a_blocked_contact_keeps_them_blocked() {
        let (mut ayse, mut burak) = paired();
        let ayse_for_burak = contact_of(&burak);
        burak.node.block_contact(ayse_for_burak).unwrap();
        burak.shown.clear();
        pair_again(&mut ayse, &mut burak);
        assert!(burak.shown.iter().any(|a| matches!(
            a,
            Action::Failed {
                reason: Failure::Blocked,
                ..
            }
        )));
        assert_eq!(state_of(&burak, ayse_for_burak), crate::storage::ContactState::Blocked);
        assert!(burak.node.keys.contacts.is_empty());
    }

    #[test]
    fn a_contact_deleted_with_the_history_kept_comes_back_to_it() {
        let (mut ayse, mut burak) = paired();
        let ayse_for_burak = contact_of(&burak);
        link(&mut ayse, &mut burak, (10, 20));
        let (_, actions) = ayse.node.send_message(contact_of(&ayse), "eski mesaj").unwrap();
        deliver(&mut ayse, &mut burak, actions);
        let a_id = link_id(&ayse);
        burak.node.delete_contact(ayse_for_burak, true).unwrap();
        ayse.node.connection_closed(a_id);

        assert_eq!(state_of(&burak, ayse_for_burak), crate::storage::ContactState::Former);
        assert!(burak.node.keys.contacts.is_empty(), "the keys are gone");
        assert!(
            burak
                .node
                .account()
                .unwrap()
                .remote_keys(ayse_for_burak)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            burak.node.messages(ayse_for_burak).unwrap().len(),
            1,
            "the history is kept"
        );

        pair_again(&mut ayse, &mut burak);
        assert_eq!(contact_of(&burak), ayse_for_burak, "the same contact again");
        assert_eq!(state_of(&burak, ayse_for_burak), crate::storage::ContactState::Active);
        link(&mut ayse, &mut burak, (11, 21));
        let (_, actions) = ayse.node.send_message(contact_of(&ayse), "yeniden").unwrap();
        deliver(&mut ayse, &mut burak, actions);
        assert_eq!(
            statuses(&burak),
            [
                ("eski mesaj".into(), MessageStatus::Received),
                ("yeniden".into(), MessageStatus::Received)
            ]
        );
    }

    #[test]
    fn files_from_a_contact_with_auto_download_arrive_without_asking() {
        let (mut ayse, mut burak) = paired();
        burak
            .node
            .set_permissions(contact_of(&burak), permissions(true, true))
            .unwrap();
        link(&mut ayse, &mut burak, (10, 20));
        let data = sample(3 * CHUNK_LEN + 1);
        let (_, actions) = send_file(&mut ayse, &data);
        deliver(&mut ayse, &mut burak, actions);
        let (message, attachment) = last_file(&burak);
        assert_eq!(attachment.state, AttachmentState::Complete);
        assert_eq!(*burak.node.read_file(message.id, 0, data.len()).unwrap(), data);
    }

    #[test]
    fn voice_messages_arrive_without_asking_and_go_a_quarter_hour_after_playing() {
        let (mut ayse, mut burak) = paired();
        link(&mut ayse, &mut burak, (10, 20));
        let data = sample(CHUNK_LEN + 7);
        let file = ayse
            .node
            .begin_file(contact_of(&ayse), "voice.ogg", crate::storage::VOICE_MIME, None)
            .unwrap();
        ayse.node.write_file(file, &data).unwrap();
        let (_, actions) = ayse.node.finish_file(file).unwrap();
        deliver(&mut ayse, &mut burak, actions);
        // Burak does not fetch files without asking, but voice messages he does.
        let (message, attachment) = last_file(&burak);
        assert_eq!(
            (attachment.state, attachment.played_at_ms),
            (AttachmentState::Complete, 0)
        );
        assert_eq!(*burak.node.read_file(message.id, 0, data.len()).unwrap(), data);

        // Playing starts its quarter of an hour, once; the sender's own copy has none.
        assert_eq!(burak.node.voice_played(message.id).unwrap().len(), 1);
        assert!(burak.node.voice_played(message.id).unwrap().is_empty());
        assert!(ayse.node.voice_played(file).unwrap().is_empty());
        let now = now_secs();
        burak.node.tick(now + 14 * 60);
        assert_eq!(last_file(&burak).1.state, AttachmentState::Complete);
        let expired = burak.node.tick(now + 16 * 60);
        assert!(expired.iter().any(|a| matches!(a, Action::MessageUpdated { .. })));
        let (_, attachment) = last_file(&burak);
        assert_eq!((attachment.state, attachment.stored), (AttachmentState::Gone, 0));
        assert_eq!(
            last_file(&ayse).1.state,
            AttachmentState::Complete,
            "the sender keeps its own"
        );
        // Other files are not touched.
        assert!(!crate::storage::is_voice(
            "audio/ogg",
            crate::storage::MAX_VOICE_BYTES + 1
        ));
        assert!(!crate::storage::is_voice("audio/mpeg", 10));
    }

    #[test]
    fn files_offered_while_locked_are_fetched_after_unlocking_with_auto_download() {
        let (mut ayse, mut burak) = paired();
        burak
            .node
            .set_permissions(contact_of(&burak), permissions(true, true))
            .unwrap();
        link(&mut ayse, &mut burak, (10, 20));
        burak.node.seal();
        let data = sample(CHUNK_LEN + 5);
        let (_, actions) = send_file(&mut ayse, &data);
        deliver(&mut ayse, &mut burak, actions);
        unseal(&mut burak);
        assert_eq!(last_file(&burak).1.state, AttachmentState::Downloading);
        let resumed = burak.node.tick(1_000);
        deliver(&mut burak, &mut ayse, resumed);
        let (message, attachment) = last_file(&burak);
        assert_eq!(attachment.state, AttachmentState::Complete);
        assert_eq!(*burak.node.read_file(message.id, 0, data.len()).unwrap(), data);
    }

    // Calls and push-to-talk (§8.5).

    fn heard(device: &Device) -> Vec<Vec<u8>> {
        device
            .shown
            .iter()
            .filter_map(|a| match a {
                Action::Audio { packet, .. } => Some(packet.to_vec()),
                _ => None,
            })
            .collect()
    }

    fn ringing(device: &Device) -> Option<StreamId> {
        device.shown.iter().find_map(|a| match a {
            Action::CallRinging { id, .. } => Some(*id),
            _ => None,
        })
    }

    #[test]
    fn a_call_rings_is_answered_and_carries_audio_both_ways() {
        let (mut ayse, mut burak) = paired();
        link(&mut ayse, &mut burak, (10, 20));
        let (id, actions) = ayse.node.start_call(contact_of(&ayse), false).unwrap();
        deliver(&mut ayse, &mut burak, actions);
        assert_eq!(ringing(&burak), Some(id));
        assert!(ayse.shown.iter().any(|a| matches!(a, Action::CallReached { .. })));

        let answer = burak.node.answer_call(id).unwrap();
        deliver(&mut burak, &mut ayse, answer);
        assert!(ayse.shown.iter().any(|a| matches!(a, Action::CallAccepted { .. })));

        let audio = ayse.node.send_audio(id, b"merhaba");
        deliver(&mut ayse, &mut burak, audio);
        let audio = burak.node.send_audio(id, b"selam");
        deliver(&mut burak, &mut ayse, audio);
        assert_eq!(heard(&burak), [b"merhaba".to_vec()]);
        assert_eq!(heard(&ayse), [b"selam".to_vec()]);

        let hang_up = burak.node.end_call(id);
        deliver(&mut burak, &mut ayse, hang_up);
        assert!(ayse.shown.iter().any(|a| matches!(
            a,
            Action::CallEnded {
                reason: EndReason::HungUp,
                ..
            }
        )));
        assert!(ayse.node.send_audio(id, b"x").is_empty(), "nothing after the call");
    }

    #[test]
    fn a_video_call_carries_frames_in_parts_both_ways_while_locked_too() {
        let (mut ayse, mut burak) = paired();
        link(&mut ayse, &mut burak, (10, 20));
        let (id, actions) = ayse.node.start_call(contact_of(&ayse), true).unwrap();
        let camera = ayse.node.set_camera(id, VideoState::On).unwrap();
        assert!(camera.is_empty(), "announced with the answer");
        deliver(&mut ayse, &mut burak, actions);
        assert!(
            burak
                .shown
                .iter()
                .any(|a| matches!(a, Action::CallRinging { video: true, .. }))
        );
        burak.node.seal();
        let answer = burak.node.answer_call(id).unwrap();
        deliver(&mut burak, &mut ayse, answer);
        let camera = burak.node.set_camera(id, VideoState::On).unwrap();
        deliver(&mut burak, &mut ayse, camera);
        assert!(ayse.shown.iter().any(|a| matches!(
            a,
            Action::VideoStateChanged {
                state: VideoState::On,
                ..
            }
        )));
        assert!(burak.shown.iter().any(|a| matches!(
            a,
            Action::VideoStateChanged {
                state: VideoState::On,
                ..
            }
        )));

        let frame = sample(40_000);
        let video = ayse.node.send_video(id, true, 1, (1280, 720), &frame).unwrap();
        assert_eq!(video.len(), 3, "three records");
        deliver(&mut ayse, &mut burak, video);
        let video = burak
            .node
            .send_video(id, true, 0, (640, 480), b"\0\0\0\x01kare")
            .unwrap();
        deliver(&mut burak, &mut ayse, video);
        let seen = |device: &Device| -> Vec<Vec<u8>> {
            device
                .shown
                .iter()
                .filter_map(|a| match a {
                    Action::Video { frame, .. } => Some(frame.to_vec()),
                    _ => None,
                })
                .collect()
        };
        assert_eq!(seen(&burak), [frame]);
        assert_eq!(seen(&ayse), [b"\0\0\0\x01kare".to_vec()]);

        let asked = burak.node.request_key_frame(id).unwrap();
        deliver(&mut burak, &mut ayse, asked);
        assert!(ayse.shown.iter().any(|a| matches!(a, Action::KeyFrameRequested { .. })));
    }

    #[test]
    fn calls_need_the_permission_and_ring_while_locked() {
        let (mut ayse, mut burak) = paired();
        burak
            .node
            .set_permissions(contact_of(&burak), permissions(false, false))
            .unwrap();
        link(&mut ayse, &mut burak, (10, 20));
        let (_, actions) = ayse.node.start_call(contact_of(&ayse), false).unwrap();
        deliver(&mut ayse, &mut burak, actions);
        assert_eq!(ringing(&burak), None);
        assert!(ayse.shown.iter().any(|a| matches!(
            a,
            Action::CallEnded {
                reason: EndReason::NotAllowed,
                ..
            }
        )));

        burak
            .node
            .set_permissions(contact_of(&burak), Permissions::default())
            .unwrap();
        burak.node.seal();
        let (id, actions) = ayse.node.start_call(contact_of(&ayse), false).unwrap();
        deliver(&mut ayse, &mut burak, actions);
        assert_eq!(ringing(&burak), Some(id), "rings although locked");
        let answer = burak.node.answer_call(id).unwrap();
        deliver(&mut burak, &mut ayse, answer);
        let audio = ayse.node.send_audio(id, b"kilitliyken");
        deliver(&mut ayse, &mut burak, audio);
        assert_eq!(heard(&burak), [b"kilitliyken".to_vec()]);
    }

    #[test]
    fn a_call_goes_on_over_a_new_link() {
        let (mut ayse, mut burak) = paired();
        link(&mut ayse, &mut burak, (10, 20));
        let (id, actions) = ayse.node.start_call(contact_of(&ayse), false).unwrap();
        deliver(&mut ayse, &mut burak, actions);
        let answer = burak.node.answer_call(id).unwrap();
        deliver(&mut burak, &mut ayse, answer);

        // The link drops (say, Wi-Fi went away) and comes back over another transport.
        let (a_id, b_id) = (link_id(&ayse), link_id(&burak));
        ayse.node.connection_closed(a_id);
        burak.node.connection_closed(b_id);
        assert!(
            ayse.node
                .tick(1_000)
                .iter()
                .all(|a| !matches!(a, Action::CallEnded { .. }))
        );
        link(&mut ayse, &mut burak, (11, 21));
        let audio = ayse.node.send_audio(id, b"yeni hat");
        deliver(&mut ayse, &mut burak, audio);
        assert_eq!(heard(&burak), [b"yeni hat".to_vec()]);
        let later = ayse.node.tick(1_000 + crate::media::LINK_GRACE_SECS);
        assert!(later.iter().all(|a| !matches!(a, Action::CallEnded { .. })), "still on");
    }

    #[test]
    fn push_to_talk_plays_only_with_the_permission() {
        let (mut ayse, mut burak) = paired();
        link(&mut ayse, &mut burak, (10, 20));
        let (talk, actions) = ayse.node.start_talk(contact_of(&ayse)).unwrap();
        deliver(&mut ayse, &mut burak, actions);
        assert!(ayse.shown.iter().any(|a| matches!(
            a,
            Action::TalkEnded {
                reason: EndReason::NotAllowed,
                ..
            }
        )));
        assert!(ayse.node.send_audio(talk, b"x").is_empty());

        burak
            .node
            .set_permissions(
                contact_of(&burak),
                Permissions {
                    ptt: true,
                    ..Permissions::default()
                },
            )
            .unwrap();
        let (talk, actions) = ayse.node.start_talk(contact_of(&ayse)).unwrap();
        deliver(&mut ayse, &mut burak, actions);
        assert!(burak.shown.iter().any(|a| matches!(a, Action::TalkStarted { .. })));
        let audio = ayse.node.send_audio(talk, b"tamam");
        deliver(&mut ayse, &mut burak, audio);
        assert_eq!(heard(&burak), [b"tamam".to_vec()]);
        assert!(matches!(
            burak.node.start_talk(contact_of(&burak)),
            Err(NodeError::Media(crate::media::MediaError::FloorTaken))
        ));
        let end = ayse.node.end_talk(talk);
        deliver(&mut ayse, &mut burak, end);
        assert!(burak.shown.iter().any(|a| matches!(a, Action::TalkEnded { .. })));
        assert!(burak.node.start_talk(contact_of(&burak)).is_ok(), "now Burak may talk");
    }

    #[test]
    fn downloads_hold_back_during_a_call() {
        let (mut ayse, mut burak) = paired();
        link(&mut ayse, &mut burak, (10, 20));
        let (_, actions) = send_file(&mut ayse, &sample(40 * CHUNK_LEN));
        deliver(&mut ayse, &mut burak, actions);
        let (id, actions) = ayse.node.start_call(contact_of(&ayse), false).unwrap();
        deliver(&mut ayse, &mut burak, actions);
        let call = ringing(&burak).unwrap();
        assert_eq!(call, id);
        burak.node.answer_call(call).unwrap();

        let (message, _) = last_file(&burak);
        let requests = burak.node.download(message.id).unwrap();
        let sends = requests.iter().filter(|a| matches!(a, Action::Send { .. })).count();
        assert_eq!(sends, 1, "one request");
        let Some(Download { requested_until, .. }) = burak.node.downloads.values().next() else {
            panic!("a download")
        };
        assert_eq!(
            *requested_until, MEDIA_REQUEST_BATCH,
            "only a couple of chunks at a time"
        );
    }

    // Who opens links (§5.2).

    mod openers {
        use super::super::groups::tests::Net;
        use super::*;

        const A: usize = 0;
        const B: usize = 1;

        /// Two contacts: which of them the rule names to open links, and which waits.
        fn pair() -> (Net, usize, usize) {
            let mut net = Net::new(&["Ayşe", "Burak"]);
            net.pair(A, B);
            let now = net.now;
            let token = net.devices[B].node.presence_token(now);
            let seen = net.node(A).recognize_presence(&token, now).unwrap();
            let (opener, waiter) = if seen.opener { (A, B) } else { (B, A) };
            (net, opener, waiter)
        }

        #[test]
        fn the_side_that_waits_opens_the_link_after_a_minute() {
            let (mut net, opener, waiter) = pair();
            let now = net.now;
            let token = net.devices[opener].node.presence_token(now);
            let sees = |net: &mut Net, at: u64| net.node(waiter).recognize_presence(&token, at).unwrap();
            // The opener cannot reach it (behind NAT, say): the other sees it, and waits a minute.
            assert!(!sees(&mut net, now).initiate());
            assert!(!sees(&mut net, now + 30).initiate());
            let late = sees(&mut net, now + 60);
            assert!(late.initiate(), "then opens the link itself");
            let (id, _) = net.wire(waiter, opener);
            let first = net.node(waiter).connect_contact(id, late.contact, now + 60).unwrap();
            net.run(waiter, first);
            assert!(net.node(waiter).is_linked(late.contact));
            let linked = sees(&mut net, now + 61);
            assert!(!linked.opener && !linked.may_replace(), "linked: it waits again");
            // Seen again only after a long gap, the minute starts over.
            net.cut(A, B);
            assert!(!sees(&mut net, now + 300).initiate());
            assert!(!sees(&mut net, now + 359).initiate());
            assert!(sees(&mut net, now + 360).initiate());
        }

        fn sent_on(actions: &[Action], on: ConnectionId) -> Vec<Vec<u8>> {
            actions
                .iter()
                .filter_map(|a| match a {
                    Action::Send { connection, bytes } if *connection == on => Some(bytes.clone()),
                    _ => None,
                })
                .collect()
        }

        fn deliver(net: &mut Net, to: usize, on: ConnectionId, frames: Vec<Vec<u8>>) -> Vec<Action> {
            let now = net.now;
            frames
                .into_iter()
                .flat_map(|frame| net.node(to).on_frame(on, &frame, now))
                .collect()
        }

        #[test]
        fn links_opened_from_both_sides_at_once_settle_on_one() {
            let (mut net, opener, waiter) = pair();
            let now = net.now;
            let (to_waiter, to_opener) = (net.contact(opener, waiter), net.contact(waiter, opener));
            // Each opens a link at once (the waiter after its minute, the opener as it reaches it).
            let (first, first_there) = net.wire(opener, waiter);
            let (second, second_there) = net.wire(waiter, opener);
            let one = net.node(opener).connect_contact(first, to_waiter, now).unwrap();
            let two = net.node(waiter).connect_contact(second, to_opener, now).unwrap();
            // Each side completes the other's link last.
            let one_2 = deliver(&mut net, waiter, first_there, sent_on(&one, first));
            let two_2 = deliver(&mut net, opener, second_there, sent_on(&two, second));
            let one_3 = deliver(&mut net, opener, first, sent_on(&one_2, first_there));
            let two_3 = deliver(&mut net, waiter, second, sent_on(&two_2, second_there));
            let last_waiter = deliver(&mut net, waiter, first_there, sent_on(&one_3, first));
            let last_opener = deliver(&mut net, opener, second_there, sent_on(&two_3, second));
            net.run(waiter, last_waiter);
            net.run(opener, last_opener);
            // One link, the same on both sides, and it works.
            let (at_opener, at_waiter) = (net.node(opener).links[&to_waiter], net.node(waiter).links[&to_opener]);
            assert_eq!(net.other_end((opener, at_opener)), Some((waiter, at_waiter)));
            let (_, actions) = net.node(opener).send_message(to_waiter, "tek bağlantı").unwrap();
            net.run(opener, actions);
            assert_eq!(net.node(waiter).messages(to_opener).unwrap()[0].body, "tek bağlantı");
        }

        #[test]
        fn strangers_and_channel_members_that_wait_open_after_a_minute_too() {
            let mut net = Net::new(&["Ayşe", "Burak"]);
            let now = net.now;
            let (a, b) = (
                net.devices[A].node.presence_token(now),
                net.devices[B].node.presence_token(now),
            );
            let waiter = if net.node(A).recognize_stranger(&b, now).unwrap().opener {
                B
            } else {
                A
            };
            let token = if waiter == A { b } else { a };
            assert!(!net.node(waiter).recognize_stranger(&token, now).unwrap().initiate());
            assert!(
                net.node(waiter)
                    .recognize_stranger(&token, now + 60)
                    .unwrap()
                    .initiate()
            );

            let channel = net.node(A).create_channel("Kamp").unwrap();
            let qr = net.node(A).channel_qr(channel.row).unwrap();
            let joined = net.node(B).add_channel_from_qr(&qr).unwrap();
            net.node(B).tune_channel(Some(joined.row)).unwrap();
            net.node(A).tune_channel(Some(channel.row)).unwrap();
            let (a, b) = (
                net.node(A).channel_token(now).unwrap(),
                net.node(B).channel_token(now).unwrap(),
            );
            let waiter = if net.node(A).recognize_channel(&b, now).unwrap().opener {
                B
            } else {
                A
            };
            let token = if waiter == A { b } else { a };
            assert!(!net.node(waiter).recognize_channel(&token, now).unwrap().initiate());
            assert!(net.node(waiter).recognize_channel(&token, now + 60).unwrap().initiate());
        }
    }
    /// Link keys (§6.8): every link replaces them, so keys stolen from a device stop working after
    /// two links it had with its contact without the thief.
    mod link_keys {
        use super::super::groups::tests::Net;
        use super::*;
        use crate::link::{Initiator, RemoteKeys, TagKey};

        const A: usize = 0;
        const B: usize = 1;

        /// Two contacts, and what each calls the other.
        fn pair() -> (Net, (ContactId, ContactId)) {
            let mut net = Net::new(&["Ayşe", "Burak"]);
            net.pair(A, B);
            let ids = (net.contact(A, B), net.contact(B, A));
            (net, ids)
        }

        fn keys(net: &Net, at: usize, contact: ContactId) -> Vec<[u8; 32]> {
            let keys = &net.devices[at].node.keys.contacts[&contact];
            keys.link_psks.iter().map(|k| *k.expose()).collect()
        }

        fn stored(net: &Net, at: usize, contact: ContactId) -> Vec<[u8; 32]> {
            let directory = net.devices[at].node.account().unwrap().contact_directory().unwrap();
            let entry = directory.into_iter().find(|e| e.id == contact).unwrap();
            entry.link_keys.iter().map(|k| *k.expose()).collect()
        }

        /// Links the two from the side that opens, trying again while turned away; locked
        /// devices link too.
        fn link(net: &mut Net, (a_knows_b, b_knows_a): (ContactId, ContactId)) {
            let now = net.now;
            let token = net.devices[B].node.presence_token(now);
            let seen = net.node(A).recognize_presence(&token, now).unwrap();
            let (opener, contact) = if seen.opener { (A, a_knows_b) } else { (B, b_knows_a) };
            for _ in 0..4 {
                let (id, _) = net.wire(opener, 1 - opener);
                let first = net.node(opener).connect_contact(id, contact, now).unwrap();
                net.run(opener, first);
                if net.node(opener).is_linked(contact) {
                    return;
                }
                net.node(opener).connection_closed(id);
            }
            panic!("no link");
        }

        fn cut(net: &mut Net, (a_knows_b, b_knows_a): (ContactId, ContactId)) {
            for (at, contact) in [(A, a_knows_b), (B, b_knows_a)] {
                let id = net.devices[at].node.links[&contact];
                let actions = net.node(at).connection_closed(id);
                net.run(at, actions);
            }
        }

        /// Whether Ayşe answers someone who holds Burak's long-term keys and `link_key` as if it
        /// were Burak: message 2 comes only from a device that recognised the tag and message 1.
        fn answers_thief(net: &mut Net, link_key: &[u8; 32]) -> bool {
            let link_key = SecretBytes::from_slice(link_key).unwrap();
            let ayse = net.devices[A].node.keys.local();
            let remote = RemoteKeys {
                identity: ayse.identity,
                static_kem: ayse.static_kem.encapsulation_key().clone(),
                link_psk: link_key.clone(),
            };
            let burak = &net.devices[B].node.keys;
            let tag = TagKey::derive(&link_key, &burak.identity, &remote.identity)
                .unwrap()
                .tag(epoch_at(net.now), &random::array().unwrap());
            let (_, first) = Initiator::start(burak.local(), &remote, &tag).unwrap();
            let (id, now) = (net.wire(A, B).0, net.now);
            let replies = net.node(A).on_frame(id, &first, now);
            net.node(A).connection_closed(id);
            replies
                .iter()
                .any(|a| matches!(a, Action::Send { connection, .. } if *connection == id))
        }

        #[test]
        fn every_link_replaces_the_link_keys_so_stolen_ones_stop_working() {
            let (mut net, ids) = pair();
            let paired = keys(&net, A, ids.0);
            assert_eq!(paired.len(), 1, "the pairing secret alone");
            assert_eq!(keys(&net, B, ids.1), paired);
            // Someone copies everything Burak's device holds, and can pass as Burak.
            let stolen = keys(&net, B, ids.1);
            assert!(answers_thief(&mut net, &stolen[0]));

            link(&mut net, ids);
            let first = keys(&net, A, ids.0);
            assert_eq!(first[1..], paired, "the one that follows, then the one used");
            assert_eq!(keys(&net, B, ids.1), first, "both sides agree");
            assert_eq!(stored(&net, A, ids.0), first, "and store them");
            assert_eq!(stored(&net, B, ids.1), first);

            cut(&mut net, ids);
            link(&mut net, ids);
            let second = keys(&net, A, ids.0);
            assert_eq!(second[1..], first[..1], "made with the newest; the older one is gone");
            assert_eq!(keys(&net, B, ids.1), second);
            assert!(second.iter().all(|key| !stolen.contains(key)));
            assert!(!answers_thief(&mut net, &stolen[0]), "the thief is turned away");
        }

        #[test]
        fn a_side_that_lost_its_newest_link_keys_still_links() {
            let (mut net, ids) = pair();
            let paired = keys(&net, B, ids.1);
            link(&mut net, ids);
            cut(&mut net, ids);
            // Burak's device stopped before it stored the new ones, say.
            let only = vec![SecretBytes::from_slice(&paired[0]).unwrap()];
            net.node(B).account().unwrap().db().set_link_keys(ids.1, &only).unwrap();
            net.node(B).keys.contacts.get_mut(&ids.1).unwrap().link_psks = only;
            net.node(B).directory = None;

            link(&mut net, ids);
            let (ayse, burak) = (keys(&net, A, ids.0), keys(&net, B, ids.1));
            assert_eq!(ayse[..2], burak[..2]);
            assert_eq!(ayse[1], paired[0], "made with the key both still held");
            cut(&mut net, ids);
            link(&mut net, ids);
            assert_eq!(keys(&net, A, ids.0), keys(&net, B, ids.1), "together again");
        }

        #[test]
        fn two_links_at_once_with_different_keys_leave_keys_both_hold() {
            let (mut net, ids) = pair();
            link(&mut net, ids);
            cut(&mut net, ids);
            let now = net.now;
            let sent = |actions: Vec<Action>, on: ConnectionId| -> Vec<u8> {
                actions
                    .into_iter()
                    .find_map(|a| match a {
                        Action::Send { connection, bytes } if connection == on => Some(bytes),
                        _ => None,
                    })
                    .expect("a handshake message")
            };
            // Each opens a link to the other, Burak with the older key; the four handshake steps
            // interleave, so each side stores the outcome of both, in opposite orders.
            let (a1, b1) = net.wire(A, B);
            let (b2, a2) = net.wire(B, A);
            net.node(B).link_attempts.insert(ids.1, 1);
            let first_a = sent(net.node(A).connect_contact(a1, ids.0, now).unwrap(), a1);
            let first_b = sent(net.node(B).connect_contact(b2, ids.1, now).unwrap(), b2);
            let second_a = sent(net.node(B).on_frame(b1, &first_a, now), b1);
            let second_b = sent(net.node(A).on_frame(a2, &first_b, now), a2);
            let third_a = sent(net.node(A).on_frame(a1, &second_a, now), a1);
            let third_b = sent(net.node(B).on_frame(b2, &second_b, now), b2);
            net.node(B).on_frame(b1, &third_a, now);
            net.node(A).on_frame(a2, &third_b, now);
            for (at, id) in [(A, a1), (A, a2), (B, b1), (B, b2)] {
                net.node(at).connection_closed(id);
            }
            let (ayse, burak) = (keys(&net, A, ids.0), keys(&net, B, ids.1));
            assert_ne!(ayse[0], burak[0], "they disagree on the newest");
            assert!(ayse.iter().any(|key| burak.contains(key)), "but share others");

            link(&mut net, ids);
            assert_eq!(keys(&net, A, ids.0)[..2], keys(&net, B, ids.1)[..2]);
        }

        #[test]
        fn a_locked_device_keeps_its_link_keys_until_it_can_store_them() {
            let (mut net, ids) = pair();
            let paired = keys(&net, B, ids.1);
            net.devices[B].node.seal();
            link(&mut net, ids);
            assert_eq!(keys(&net, B, ids.1), paired, "locked: nowhere to store new ones");
            assert_eq!(keys(&net, A, ids.0)[1..], paired);
            cut(&mut net, ids);

            let device = &mut net.devices[B];
            let account = Account::unlock_with_pin(device.dir.path(), &device.pin_record, b"123456").unwrap();
            device.node.unseal(account).unwrap();
            link(&mut net, ids);
            assert_eq!(keys(&net, A, ids.0)[..2], keys(&net, B, ids.1)[..2]);
        }
    }
}
