//! Paths through Air Providers in the node (rust/airchat-protocol/docs/protocol.md §12): what this device carries for
//! others, looking for paths to contacts (and to the owners of AirChat IDs typed, §4.8), carrying
//! other devices' paths, and the ends of paths. The link over a path runs on a connection of its
//! own, from [`PATH_CONNECTION_BASE`] up, which [`Node::route`] carries over the path's first hop.

use std::collections::{HashMap, VecDeque};

use super::{Action, ConnectionId, Node, NodeError, Store, channels, now_secs};
use crate::{
    channel,
    chat::ChatMessage,
    crypto::{SecretBytes, hash::equal_in_constant_time, random},
    discovery::request_token,
    identity::AirChatId,
    link::{Session, epoch_at},
    mesh,
    path::{self, Class, Classes, PathId, PathNonce, Proof, Request},
    storage::ContactId,
};

/// Connections of links over paths count up from here, far above the platform's own.
pub const PATH_CONNECTION_BASE: ConnectionId = 1 << 62;
/// Requests are remembered this long, so each is handled once.
const SEEN_SECS: u64 = 60;
/// How long an answer, and then the open, is waited for.
const ANSWER_SECS: u64 = 10;
/// A path that carried nothing this long is closed.
const IDLE_SECS: u64 = 90;
/// An end closes a path whose link carried nothing but liveness this long, outside calls and talks.
const UNUSED_SECS: u64 = 60;
/// Paths a provider carries at most, and at most of the video and files classes each. Voice is
/// light (tens of kbit/s), so a group call of seven, each member out of the others' reach, fits
/// through one provider (§12.1).
const MAX_PATHS: usize = 24;
const MAX_HEAVY_PATHS: usize = 2;
/// Answers remembered per path at most.
const MAX_ANSWERS: usize = 4;
const REQUESTS_PER_MINUTE: u32 = 20;
/// A receiving end credits what it took at least this often.
const CREDIT_EVERY: usize = 8 * 1024;
/// What a provider lets an end have outstanding beyond the window, for credits on their way.
const SLACK: usize = 16 * 1024;
const VOICE_PER_MINUTE: usize = 4 << 20;
/// What an end holds back, in windows, before it gives the path up: its sender ignored the backlog.
const HOLD_WINDOWS: usize = 8;
/// How often each contact is checked for files waiting for a path.
const FILES_CHECK_SECS: u64 = 120;
/// How often the head of a walkie-talkie cluster looks for other clusters (§11.5).
const CHANNEL_SEARCH_SECS: u64 = 30;
/// How often the owners of the AirChat IDs typed are looked for (§4.8): a request its owner
/// turned down is answered (unseen) every time, so not often.
const REQUEST_SEARCH_SECS: u64 = 300;

pub fn is_path_connection(connection: ConnectionId) -> bool {
    connection >= PATH_CONNECTION_BASE
}

/// A path this device carries between two neighbours.
struct Carried {
    class: Class,
    /// The neighbour the request came from, toward the end that opened the path.
    before: ConnectionId,
    /// The neighbour toward the other end, once open.
    after: Option<ConnectionId>,
    /// Answers passed back so far: the neighbour each came from.
    answers: Vec<(Proof, ConnectionId)>,
    /// When it was requested, or last carried something.
    active_at: u64,
    /// Data bytes passed on toward `after` and back, not yet credited.
    forward: usize,
    backward: usize,
    minute: u64,
    this_minute: usize,
}

impl Carried {
    fn new(class: Class, before: ConnectionId, now: u64) -> Self {
        Self {
            class,
            before,
            after: None,
            answers: Vec::new(),
            active_at: now,
            forward: 0,
            backward: 0,
            minute: 0,
            this_minute: 0,
        }
    }

    /// Counts `bytes` carried; false once a voice path carries more than it should.
    fn charge(&mut self, now: u64, bytes: usize) -> bool {
        if now / 60 != self.minute {
            self.minute = now / 60;
            self.this_minute = 0;
        }
        self.this_minute += bytes;
        self.class != Class::Voice || self.this_minute <= VOICE_PER_MINUTE
    }

    /// The neighbour across the path from `from`, if `from` is one of its two.
    fn across(&self, from: ConnectionId) -> Option<ConnectionId> {
        let after = self.after?;
        match from {
            _ if from == self.before => Some(after),
            _ if from == after => Some(self.before),
            _ => None,
        }
    }
}

/// What runs over a path this device is an end of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    /// A link (§6), or a channel link (§11.3).
    Link,
    /// This device asks the owner of an AirChat ID to add it: only the owner's pairing may come
    /// over the path (§4.8).
    Asks,
    /// This device owns the ID asked for: it pairs with whoever asked once the path opens.
    Answers,
}

/// A path this device is an end of.
struct End {
    path: PathId,
    class: Class,
    role: Role,
    /// The neighbour's link the path runs over.
    via: ConnectionId,
    /// Until the open arrives, the end that answered only waits.
    open: bool,
    proof: Proof,
    /// Providers on the path, as far as the answer said.
    providers: u8,
    /// Data bytes sent and not yet credited, and those held back beyond the window.
    outstanding: usize,
    held: VecDeque<(bool, Vec<u8>)>,
    held_bytes: usize,
    /// Data bytes taken since the last credit.
    taken: usize,
    /// The frame being put together.
    frame: Vec<u8>,
    active_at: u64,
    /// When something other than liveness last arrived on the link over it.
    used_at: u64,
}

impl End {
    /// Data records for what the window lets go now.
    fn release(&mut self) -> Vec<ChatMessage> {
        let mut records = Vec::new();
        while let Some((_, data)) = self.held.front()
            && self.outstanding + data.len() <= self.class.window()
        {
            let (more, data) = self.held.pop_front().expect("just looked");
            self.outstanding += data.len();
            self.held_bytes -= data.len();
            records.push(ChatMessage::PathData {
                path: self.path,
                more,
                data,
            });
        }
        records
    }
}

/// Whom a request this device recognised looks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Requester {
    /// A contact or a fellow group member, with the number of the link key the tag was made with.
    Member(ContactId, usize),
    /// Any member of the tuned walkie-talkie channel (§11.5).
    Channel,
    /// Someone who typed this device's AirChat ID and asks to be added (§4.8).
    Owner,
}

/// Whom a search looks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    /// A contact, a fellow group member, or a member of the tuned channel (a channel peer).
    Contact(ContactId),
    /// The owner of an AirChat ID this device asks to be added by.
    Owner(AirChatId),
}

/// This device looking for a path.
struct Search {
    target: Target,
    class: Class,
    nonce: PathNonce,
    /// `tag_key(contact -> this device)`: only the contact can make the proof with it (any member,
    /// for a channel's path key).
    proof_key: SecretBytes<32>,
    started: u64,
}

#[derive(Default)]
pub(crate) struct Paths {
    /// What this device carries for others; none unless Air Provider mode is on.
    offer: Classes,
    /// What each neighbour carries, as it last said.
    offers: HashMap<ConnectionId, Classes>,
    /// Requests handled, by path, with when.
    seen: HashMap<PathId, u64>,
    carried: HashMap<PathId, Carried>,
    searches: HashMap<PathId, Search>,
    /// The ends, by the connection of the link over them.
    ends: HashMap<ConnectionId, End>,
    by_path: HashMap<PathId, ConnectionId>,
    next: ConnectionId,
    /// Requests each neighbour sent in a minute.
    requests: HashMap<ConnectionId, (u64, u32)>,
    /// The keys of the tags this device recognises on requests, and whose they are; built when needed.
    tag_keys: Option<Vec<(Requester, SecretBytes<32>)>>,
    /// When each contact was last checked for files waiting for a path.
    files_checked: HashMap<ContactId, u64>,
    /// When a member of the tuned channel was last looked for.
    channel_searched: u64,
    /// The key of the tags of requests for this device's own AirChat ID; made when needed.
    own_request_key: Option<SecretBytes<32>>,
    /// When the owners of the IDs typed were last looked for.
    requests_searched: u64,
}

impl Paths {
    pub(super) fn keys_changed(&mut self) {
        self.tag_keys = None;
    }

    /// An AirChat ID was just typed: its owner is looked for at the next tick.
    pub(super) fn search_requests_soon(&mut self) {
        self.requests_searched = 0;
    }

    /// Whether this device can take one more path of `class` as a provider.
    fn room(&self, class: Class) -> bool {
        let of_class = self.carried.values().filter(|c| c.class == class).count();
        self.carried.len() < MAX_PATHS && (class == Class::Voice || of_class < MAX_HEAVY_PATHS)
    }

    fn new_connection(&mut self) -> ConnectionId {
        let connection = PATH_CONNECTION_BASE + self.next;
        self.next += 1;
        connection
    }

    fn end_of(&mut self, path: &PathId, via: ConnectionId) -> Option<(ConnectionId, &mut End)> {
        let connection = *self.by_path.get(path)?;
        let end = self.ends.get_mut(&connection).filter(|e| e.via == via)?;
        Some((connection, end))
    }
}

type Sends = Vec<(ConnectionId, ChatMessage)>;

impl Node {
    // What this device carries (§12.1).

    /// What this device carries for others as an Air Provider (requirements AP-1, AP-5). None
    /// turns the mode off and closes the paths it carries; dropping some classes keeps those it
    /// carries until they close.
    pub fn set_air_provider(&mut self, classes: Classes) -> Vec<Action> {
        if classes == self.paths.offer {
            return Vec::new();
        }
        self.paths.offer = classes;
        let mut sends: Sends = self
            .mesh
            .neighbour_links()
            .map(|c| (c, ChatMessage::PathOffer(classes)))
            .collect();
        if classes.is_empty() {
            for (path, carried) in self.paths.carried.drain() {
                sends.extend(
                    [Some(carried.before), carried.after]
                        .into_iter()
                        .flatten()
                        .map(|c| (c, ChatMessage::PathClose { path })),
                );
            }
        }
        self.mesh_sends(sends, None)
    }

    /// Mesh neighbours that carry `class` now: whether a path can be looked for.
    pub fn providers(&self, class: Class) -> usize {
        self.paths
            .offers
            .iter()
            .filter(|(c, offer)| offer.contains(class) && self.mesh.is_neighbour(**c))
            .count()
    }

    /// The offer for a neighbour whose link just came up, if this device carries anything.
    pub(super) fn path_offer(&self) -> Option<ChatMessage> {
        (!self.paths.offer.is_empty()).then_some(ChatMessage::PathOffer(self.paths.offer))
    }

    /// Whether the link on `connection` carries `class`: any direct link does; one over a path
    /// carries voice, and video or files only if its class does (§12.3).
    pub(super) fn link_carries(&self, connection: ConnectionId, class: Class) -> bool {
        if !is_path_connection(connection) {
            return true;
        }
        self.paths.ends.get(&connection).is_some_and(|end| match class {
            Class::Voice => true,
            Class::Video => end.class.carries_video(),
            Class::Files => end.class.carries_files(),
        })
    }

    /// The link to `contact` that carries files, if one is up.
    pub(super) fn file_link(&self, contact: ContactId) -> Option<ConnectionId> {
        self.data_link(contact).filter(|c| self.link_carries(*c, Class::Files))
    }

    /// The class of the path the link to `contact` runs over, and the providers on it: `None` for
    /// a direct link or none.
    pub fn link_path(&self, contact: ContactId) -> Option<(Class, u8)> {
        let connection = self.links.get(&contact)?;
        self.paths.ends.get(connection).map(|end| (end.class, end.providers))
    }

    /// Something other than liveness arrived on the link over a path: it is still of use.
    pub(super) fn path_used(&mut self, connection: ConnectionId) {
        if let Some(end) = self.paths.ends.get_mut(&connection) {
            end.used_at = now_secs();
        }
    }

    /// Bytes sent on the link over a path and not yet taken by the other end: video holds back
    /// while it grows, as for any link's queue. `None` for other connections.
    pub fn path_backlog(&self, connection: ConnectionId) -> Option<usize> {
        self.paths
            .ends
            .get(&connection)
            .map(|end| end.outstanding + end.held_bytes)
    }

    // Finding a path (§12.2).

    /// Looks for a path to `contact` that carries `class`, unless a link that carries it is up or
    /// a search is under way. A link over the path comes up ([`Action::LinkUp`]), or
    /// [`Action::PathFailed`] follows. [`NodeError::NoProvider`] if no neighbour carries `class`.
    pub fn find_path(&mut self, contact: ContactId, class: Class) -> Result<Vec<Action>, NodeError> {
        // Contacts, and fellow group members for group voice (§9.6).
        if !self.keys.contacts.contains_key(&contact) {
            return Err(NodeError::UnknownContact);
        }
        if self.data_link(contact).is_some_and(|c| self.link_carries(c, class))
            || self
                .paths
                .searches
                .values()
                .any(|s| s.target == Target::Contact(contact) && s.class == class)
        {
            return Ok(Vec::new());
        }
        self.search_for(contact, class)
    }

    /// Looks for a path to a contact or fellow member, whatever links are up.
    fn search_for(&mut self, contact: ContactId, class: Class) -> Result<Vec<Action>, NodeError> {
        let keys = self.keys.contacts.get(&contact).ok_or(NodeError::UnknownContact)?;
        let psk = keys.path_psks().first().ok_or(NodeError::UnknownContact)?;
        let tag_key = mesh::contact_tag_key(psk, &self.keys.identity, &keys.identity)?;
        let proof_key = mesh::contact_tag_key(psk, &keys.identity, &self.keys.identity)?;
        self.start_search(Target::Contact(contact), class, tag_key, proof_key, random::array()?)
    }

    /// Looks for a member of another cluster of the tuned walkie-talkie channel through Air
    /// Providers (§11.5), if this device heads its cluster and no search is under way; a channel
    /// link comes up over the path, to whichever member answers first.
    pub fn find_channel_path(&mut self) -> Result<Vec<Action>, NodeError> {
        let tuned = self.keys.channel.as_ref().ok_or(NodeError::NoSuchChannel)?;
        let key = tuned.channel.path_key()?;
        let now = now_secs();
        if !self.is_channel_head(now)
            || self
                .paths
                .searches
                .values()
                .any(|s| matches!(s.target, Target::Contact(c) if channels::is_channel_peer(c)))
        {
            return Ok(Vec::new());
        }
        let (head, _) = self.channel_head(now).ok_or(NodeError::NoProvider)?;
        let nonce = channel::cluster_nonce(&key, &head, &random::array()?);
        let peer = self.channel_peers.new_peer();
        let proof_key = key.clone();
        self.start_search(Target::Contact(peer), Class::Voice, key, proof_key, nonce)
    }

    /// Looks for a path to the owner of each AirChat ID typed whose search is not under way
    /// (§4.8). Whoever knows an ID can make its tags and proofs, so the path may lead to someone
    /// else who knows it: that one cannot prove it owns the ID in the pairing over it, before which
    /// this device shows nothing of itself.
    fn find_request_paths(&mut self) -> Vec<Action> {
        let Store::Open(account) = &self.store else {
            return Vec::new();
        };
        let ids = account.db().sent_requests().unwrap_or_default();
        let mut actions = Vec::new();
        for id in ids {
            if self.paths.searches.values().any(|s| s.target == Target::Owner(id)) {
                continue;
            }
            let (Ok(key), Ok(nonce)) = (path::request_path_key(&id), random::array()) else {
                continue;
            };
            let proof_key = key.clone();
            actions.extend(
                self.start_search(Target::Owner(id), Class::Voice, key, proof_key, nonce)
                    .unwrap_or_default(),
            );
        }
        actions
    }

    /// Sends a request with a tag made with `tag_key` to the neighbours that carry `class`.
    fn start_search(
        &mut self,
        target: Target,
        class: Class,
        tag_key: SecretBytes<32>,
        proof_key: SecretBytes<32>,
        nonce: PathNonce,
    ) -> Result<Vec<Action>, NodeError> {
        let providers: Vec<ConnectionId> = self
            .paths
            .offers
            .iter()
            .filter(|(c, offer)| offer.contains(class) && self.mesh.is_neighbour(**c))
            .map(|(c, _)| *c)
            .collect();
        if providers.is_empty() {
            return Err(NodeError::NoProvider);
        }
        let path: PathId = random::array()?;
        let request = Request {
            path,
            class,
            hops: class.max_providers(),
            nonce,
            tag: path::request_tag(&tag_key, &nonce),
        };
        let now = now_secs();
        self.paths.seen.insert(path, now);
        self.paths.searches.insert(
            path,
            Search {
                target,
                class,
                nonce,
                proof_key,
                started: now,
            },
        );
        let sends = providers
            .into_iter()
            .map(|c| (c, ChatMessage::PathRequest(request.clone())))
            .collect();
        Ok(self.mesh_sends(sends, None))
    }

    /// A path record on a mesh neighbour's link.
    pub(super) fn on_path_record(
        &mut self,
        connection: ConnectionId,
        session: &mut Session,
        record: ChatMessage,
    ) -> Vec<Action> {
        if !self.mesh.is_neighbour(connection) {
            return Vec::new();
        }
        let now = now_secs();
        let (actions, sends) = match record {
            ChatMessage::PathOffer(classes) => {
                self.paths.offers.insert(connection, classes);
                (Vec::new(), Vec::new())
            }
            ChatMessage::PathRequest(request) => (Vec::new(), self.on_path_request(connection, request, now)),
            ChatMessage::PathAnswer { path, providers, proof } => {
                self.on_path_answer(connection, path, providers, proof, now)
            }
            ChatMessage::PathOpen { path, proof } => self.on_path_open(connection, path, proof, now),
            ChatMessage::PathData { path, more, data } => self.on_path_data(connection, path, more, data, now),
            ChatMessage::PathCredit { path, bytes } => (Vec::new(), self.on_path_credit(connection, path, bytes, now)),
            ChatMessage::PathClose { path } => self.on_path_close(connection, path),
            _ => (Vec::new(), Vec::new()),
        };
        // An open goes out before the first frame of the link over the path.
        let mut out = self.mesh_sends(sends, Some((connection, session)));
        out.extend(actions);
        out
    }

    fn on_path_request(&mut self, from: ConnectionId, request: Request, now: u64) -> Sends {
        let count = self.paths.requests.entry(from).or_insert((now / 60, 0));
        if count.0 != now / 60 {
            *count = (now / 60, 0);
        }
        count.1 += 1;
        if count.1 > REQUESTS_PER_MINUTE || self.paths.seen.contains_key(&request.path) {
            return Vec::new();
        }
        self.paths.seen.insert(request.path, now);
        // A request from this device's own walkie-talkie cluster is not for it, but may go on
        // through it to another cluster (§11.5).
        let requester = self
            .requester(&request)
            .filter(|r| *r != Requester::Channel || !self.asked_by_own_cluster(&request.nonce, now));
        if let Some(requester) = requester {
            let proof = match requester {
                Requester::Member(contact, psk) if self.accepts_paths_from(contact) => {
                    self.answer_proof(contact, psk, &request)
                }
                Requester::Member(..) => None,
                Requester::Channel => self.keys.channel.as_ref().and_then(|tuned| {
                    let key = tuned.channel.path_key().ok()?;
                    Some(path::proof(&key, &request.path, &request.nonce))
                }),
                Requester::Owner => self.owner_proof(&request, now),
            };
            let Some(proof) = proof else {
                return Vec::new();
            };
            let connection = self.paths.new_connection();
            self.paths.by_path.insert(request.path, connection);
            self.paths.ends.insert(
                connection,
                End {
                    path: request.path,
                    class: request.class,
                    role: if requester == Requester::Owner {
                        Role::Answers
                    } else {
                        Role::Link
                    },
                    via: from,
                    open: false,
                    proof,
                    providers: 0,
                    outstanding: 0,
                    held: VecDeque::new(),
                    held_bytes: 0,
                    taken: 0,
                    frame: Vec::new(),
                    active_at: now,
                    used_at: now,
                },
            );
            let answer = ChatMessage::PathAnswer {
                path: request.path,
                providers: 0,
                proof,
            };
            return vec![(from, answer)];
        }
        let hops = request.hops.min(request.class.max_providers());
        if !self.paths.offer.contains(request.class) || hops == 0 || !self.paths.room(request.class) {
            return Vec::new();
        }
        self.paths
            .carried
            .insert(request.path, Carried::new(request.class, from, now));
        let onward = Request {
            hops: hops - 1,
            ..request
        };
        self.mesh
            .neighbour_links()
            .filter(|c| *c != from)
            .map(|c| (c, ChatMessage::PathRequest(onward.clone())))
            .collect()
    }

    /// Whom the request is for, if this device is (one of) them: it tries each contact's and
    /// fellow member's every link key, and the tuned channel's path key.
    fn requester(&mut self, request: &Request) -> Option<Requester> {
        if self.paths.own_request_key.is_none() {
            self.paths.own_request_key = path::request_path_key(&self.keys.identity.airchat_id()).ok();
        }
        if let Some(key) = &self.paths.own_request_key
            && equal_in_constant_time(&path::request_tag(key, &request.nonce), &request.tag)
        {
            return Some(Requester::Owner);
        }
        if self.paths.tag_keys.is_none() {
            let mut keys: Vec<(Requester, SecretBytes<32>)> = Vec::new();
            for (&contact, k) in &self.keys.contacts {
                for (index, psk) in k.path_psks().iter().enumerate() {
                    if let Ok(tag_key) = mesh::contact_tag_key(psk, &k.identity, &self.keys.identity) {
                        keys.push((Requester::Member(contact, index), tag_key));
                    }
                }
            }
            if let Some(key) = self.keys.channel.as_ref().and_then(|t| t.channel.path_key().ok()) {
                keys.push((Requester::Channel, key));
            }
            self.paths.tag_keys = Some(keys);
        }
        self.paths
            .tag_keys
            .as_ref()?
            .iter()
            .find(|(_, tag_key)| equal_in_constant_time(&path::request_tag(tag_key, &request.nonce), &request.tag))
            .map(|(requester, _)| *requester)
    }

    /// Whether a channel path request's nonce names this device's cluster's head.
    fn asked_by_own_cluster(&self, nonce: &PathNonce, now: u64) -> bool {
        let Some(key) = self.keys.channel.as_ref().and_then(|t| t.channel.path_key().ok()) else {
            return false;
        };
        self.channel_head(now)
            .is_some_and(|(head, _)| channel::from_cluster(&key, &head, nonce))
    }

    /// The proof for a request made with link key number `psk` of the contact's.
    fn answer_proof(&self, contact: ContactId, psk: usize, request: &Request) -> Option<Proof> {
        let keys = self.keys.contacts.get(&contact)?;
        let tag_key = mesh::contact_tag_key(keys.path_psks().get(psk)?, &self.keys.identity, &keys.identity).ok()?;
        Some(path::proof(&tag_key, &request.path, &request.nonce))
    }

    /// The proof for a request for this device's own AirChat ID, if it answers one now: as a
    /// request's beacon, at most once a minute, never while locked or with requests off (§4.8).
    fn owner_proof(&mut self, request: &Request, now: u64) -> Option<Proof> {
        let token = request_token(&self.keys.identity.airchat_id(), epoch_at(now)).ok()?;
        if !self.answering_request(&token, now) {
            return None;
        }
        let key = self.paths.own_request_key.as_ref()?;
        Some(path::proof(key, &request.path, &request.nonce))
    }

    /// Whether the link over `connection` is a path on which this device asks to be added: only
    /// the pairing of the ID's owner may come over it.
    pub(super) fn asks_on(&self, connection: ConnectionId) -> bool {
        self.paths
            .ends
            .get(&connection)
            .is_some_and(|end| end.role == Role::Asks)
    }

    /// Whether a path request from `contact` is answered: a contact that may send messages, or a
    /// fellow group member (for group voice).
    fn accepts_paths_from(&self, contact: ContactId) -> bool {
        self.keys
            .contacts
            .get(&contact)
            .is_some_and(|keys| keys.group_only || keys.permissions.messages)
    }

    /// The paths this device carries for others now, as an Air Provider.
    pub fn paths_carried(&self) -> usize {
        self.paths.carried.len()
    }

    /// Whether this device is looking for a path to `contact`.
    pub(super) fn searching_for(&self, contact: ContactId) -> bool {
        self.paths
            .searches
            .values()
            .any(|s| s.target == Target::Contact(contact))
    }

    /// The class of the path a link runs over, if it does.
    pub(super) fn path_class(&self, connection: ConnectionId) -> Option<Class> {
        self.paths.ends.get(&connection).map(|end| end.class)
    }

    fn on_path_answer(
        &mut self,
        from: ConnectionId,
        path: PathId,
        providers: u8,
        proof: Proof,
        now: u64,
    ) -> (Vec<Action>, Sends) {
        if let Some(search) = self.paths.searches.get(&path) {
            let expected = path::proof(&search.proof_key, &path, &search.nonce);
            if !equal_in_constant_time(&expected, &proof) {
                return (Vec::new(), Vec::new());
            }
            let search = self.paths.searches.remove(&path).expect("just found");
            let connection = self.paths.new_connection();
            self.paths.by_path.insert(path, connection);
            self.paths.ends.insert(
                connection,
                End {
                    path,
                    class: search.class,
                    role: match search.target {
                        Target::Contact(_) => Role::Link,
                        Target::Owner(_) => Role::Asks,
                    },
                    via: from,
                    open: true,
                    proof,
                    providers,
                    outstanding: 0,
                    held: VecDeque::new(),
                    held_bytes: 0,
                    taken: 0,
                    frame: Vec::new(),
                    active_at: now,
                    used_at: now,
                },
            );
            let open = vec![(from, ChatMessage::PathOpen { path, proof })];
            // The owner of an ID opens the pairing over the path itself (§4.8).
            let Target::Contact(contact) = search.target else {
                return (Vec::new(), open);
            };
            return match self.connect_contact(connection, contact, now) {
                Ok(actions) => (actions, open),
                Err(_) => {
                    self.paths.ends.remove(&connection);
                    self.paths.by_path.remove(&path);
                    (
                        vec![Action::PathFailed {
                            contact,
                            class: search.class,
                        }],
                        Vec::new(),
                    )
                }
            };
        }
        let Some(carried) = self.paths.carried.get_mut(&path) else {
            return (Vec::new(), Vec::new());
        };
        if from == carried.before || carried.after.is_some() || carried.answers.len() >= MAX_ANSWERS {
            return (Vec::new(), Vec::new());
        }
        carried.answers.push((proof, from));
        let answer = ChatMessage::PathAnswer {
            path,
            providers: providers.saturating_add(1),
            proof,
        };
        (Vec::new(), vec![(carried.before, answer)])
    }

    fn on_path_open(&mut self, from: ConnectionId, path: PathId, proof: Proof, now: u64) -> (Vec<Action>, Sends) {
        if let Some(carried) = self.paths.carried.get_mut(&path) {
            if carried.before != from || carried.after.is_some() {
                return (Vec::new(), Vec::new());
            }
            let Some(&(_, next)) = carried.answers.iter().find(|(p, _)| *p == proof) else {
                self.paths.carried.remove(&path);
                return (Vec::new(), vec![(from, ChatMessage::PathClose { path })]);
            };
            carried.after = Some(next);
            carried.answers.clear();
            carried.active_at = now;
            return (Vec::new(), vec![(next, ChatMessage::PathOpen { path, proof })]);
        }
        let close = vec![(from, ChatMessage::PathClose { path })];
        let (connection, role) = match self.paths.end_of(&path, from) {
            Some((connection, end)) if !end.open && end.proof == proof => {
                end.open = true;
                end.active_at = now;
                (connection, end.role)
            }
            _ => return (Vec::new(), close),
        };
        if role != Role::Answers {
            return (Vec::new(), Vec::new());
        }
        // The owner of the ID asked for pairs with whoever asked, as on meeting its beacon (§4.8).
        let answered = request_token(&self.keys.identity.airchat_id(), epoch_at(now))
            .map_err(NodeError::from)
            .and_then(|token| self.answer_request(connection, &token));
        match answered {
            Ok(actions) => (actions, Vec::new()),
            Err(_) => (self.drop_end(connection), close),
        }
    }

    fn on_path_data(
        &mut self,
        from: ConnectionId,
        path: PathId,
        more: bool,
        data: Vec<u8>,
        now: u64,
    ) -> (Vec<Action>, Sends) {
        if let Some(carried) = self.paths.carried.get_mut(&path) {
            let Some(to) = carried.across(from) else {
                return (Vec::new(), Vec::new());
            };
            let outstanding = match from == carried.before {
                true => &mut carried.forward,
                false => &mut carried.backward,
            };
            *outstanding += data.len();
            let over = *outstanding > carried.class.window() + SLACK;
            if over || !carried.charge(now, data.len()) {
                return (Vec::new(), self.close_carried(path));
            }
            carried.active_at = now;
            return (Vec::new(), vec![(to, ChatMessage::PathData { path, more, data })]);
        }
        let Some((connection, end)) = self.paths.end_of(&path, from).filter(|(_, e)| e.open) else {
            return (Vec::new(), Vec::new());
        };
        end.active_at = now;
        end.taken += data.len();
        end.frame.extend_from_slice(&data);
        let mut sends = Vec::new();
        if end.frame.len() > path::MAX_FRAME {
            sends.push((from, ChatMessage::PathClose { path }));
            return (self.drop_end(connection), sends);
        }
        if end.taken >= CREDIT_EVERY {
            let bytes = u32::try_from(std::mem::take(&mut end.taken)).unwrap_or(u32::MAX);
            sends.push((from, ChatMessage::PathCredit { path, bytes }));
        }
        if more {
            return (Vec::new(), sends);
        }
        let frame = std::mem::take(&mut end.frame);
        (self.on_frame(connection, &frame, now), sends)
    }

    fn on_path_credit(&mut self, from: ConnectionId, path: PathId, bytes: u32, now: u64) -> Sends {
        let credited = usize::try_from(bytes).unwrap_or(usize::MAX);
        if let Some(carried) = self.paths.carried.get_mut(&path) {
            let Some(to) = carried.across(from) else {
                return Vec::new();
            };
            // Credit from after the path is for what went toward it.
            let outstanding = match from == carried.before {
                true => &mut carried.backward,
                false => &mut carried.forward,
            };
            *outstanding = outstanding.saturating_sub(credited);
            carried.active_at = now;
            return vec![(to, ChatMessage::PathCredit { path, bytes })];
        }
        let Some((_, end)) = self.paths.end_of(&path, from) else {
            return Vec::new();
        };
        end.outstanding = end.outstanding.saturating_sub(credited);
        end.active_at = now;
        end.release().into_iter().map(|record| (from, record)).collect()
    }

    fn on_path_close(&mut self, from: ConnectionId, path: PathId) -> (Vec<Action>, Sends) {
        if let Some(carried) = self.paths.carried.get_mut(&path) {
            let Some(to) = (if carried.after.is_none() && from == carried.before {
                Some(None)
            } else {
                carried.across(from).map(Some)
            }) else {
                // A neighbour that answered gives up before the path opened.
                carried.answers.retain(|(_, c)| *c != from);
                return (Vec::new(), Vec::new());
            };
            self.paths.carried.remove(&path);
            let sends = to.map(|c| (c, ChatMessage::PathClose { path })).into_iter().collect();
            return (Vec::new(), sends);
        }
        match self.paths.end_of(&path, from) {
            Some((connection, _)) => (self.drop_end(connection), Vec::new()),
            None => (Vec::new(), Vec::new()),
        }
    }

    /// Stops carrying a path, telling both neighbours.
    fn close_carried(&mut self, path: PathId) -> Sends {
        let Some(carried) = self.paths.carried.remove(&path) else {
            return Vec::new();
        };
        [Some(carried.before), carried.after]
            .into_iter()
            .flatten()
            .map(|c| (c, ChatMessage::PathClose { path }))
            .collect()
    }

    /// Forgets an end whose path is gone; its link ends as when a transport closes.
    fn drop_end(&mut self, connection: ConnectionId) -> Vec<Action> {
        if let Some(end) = self.paths.ends.remove(&connection) {
            self.paths.by_path.remove(&end.path);
        }
        self.connection_closed(connection)
    }

    /// A neighbour's link ended: paths over it close, on both sides.
    pub(super) fn paths_link_ended(&mut self, connection: ConnectionId) -> Vec<Action> {
        self.paths.offers.remove(&connection);
        self.paths.requests.remove(&connection);
        let through: Vec<PathId> = self
            .paths
            .carried
            .iter()
            .filter(|(_, c)| c.before == connection || c.after == Some(connection))
            .map(|(path, _)| *path)
            .collect();
        let mut sends = Vec::new();
        for path in through {
            sends.extend(self.close_carried(path).into_iter().filter(|(c, _)| *c != connection));
        }
        for carried in self.paths.carried.values_mut() {
            carried.answers.retain(|(_, c)| *c != connection);
        }
        let ends: Vec<ConnectionId> = self
            .paths
            .ends
            .iter()
            .filter(|(_, e)| e.via == connection)
            .map(|(c, _)| *c)
            .collect();
        let mut actions = self.mesh_sends(sends, None);
        for end in ends {
            actions.extend(self.drop_end(end));
        }
        actions
    }

    // Carrying links over paths (§12.3).

    /// Carries what `actions` send on links over paths: hand every list of actions to this before
    /// acting on it. Frames for such a link go out as data records on the path's first hop, held
    /// back beyond its window; closing one closes its path. Other actions pass unchanged.
    ///
    /// Records sealed here come after every record already in `actions`, so they go after all of
    /// those: a link's records must leave in the order they were sealed (§6.4), and the first hop
    /// may carry records of its own in the same list.
    pub fn route(&mut self, actions: Vec<Action>) -> Vec<Action> {
        let on_path = |a: &Action| matches!(a, Action::Send { connection, .. } | Action::Close { connection } if is_path_connection(*connection));
        if !actions.iter().any(on_path) {
            return actions;
        }
        let mut out = Vec::new();
        let mut routed = Vec::new();
        // With whether it came up while routing, sealed after everything passed in.
        let mut queue: VecDeque<(Action, bool)> = actions.into_iter().map(|a| (a, false)).collect();
        while let Some((action, late)) = queue.pop_front() {
            let (sent, then) = match action {
                Action::Send { connection, bytes } if is_path_connection(connection) => {
                    self.path_send(connection, &bytes)
                }
                Action::Close { connection } if is_path_connection(connection) => self.path_close(connection),
                action => {
                    if late { &mut routed } else { &mut out }.push(action);
                    continue;
                }
            };
            routed.extend(sent);
            for action in then.into_iter().rev() {
                queue.push_front((action, true));
            }
        }
        out.extend(routed);
        out
    }

    /// A frame for the link over a path. Returns what to send now, and actions that still need
    /// routing (the path given up).
    fn path_send(&mut self, connection: ConnectionId, frame: &[u8]) -> (Vec<Action>, Vec<Action>) {
        let Some(end) = self.paths.ends.get_mut(&connection).filter(|e| e.open) else {
            return (Vec::new(), Vec::new());
        };
        let pieces = frame.len().div_ceil(path::MAX_DATA);
        for (i, piece) in frame.chunks(path::MAX_DATA).enumerate() {
            end.held.push_back((i + 1 < pieces, piece.to_vec()));
            end.held_bytes += piece.len();
        }
        if end.held_bytes > end.class.window() * HOLD_WINDOWS {
            return self.path_close(connection);
        }
        let via = end.via;
        let records = end.release();
        (self.seal_on(via, records, false), Vec::new())
    }

    /// Closes the path under a link that ends: tells the first hop, then the link ends as when a
    /// transport closes. Returns what to send, and actions that still need routing.
    fn path_close(&mut self, connection: ConnectionId) -> (Vec<Action>, Vec<Action>) {
        let sends = match self.paths.ends.remove(&connection) {
            Some(end) => {
                self.paths.by_path.remove(&end.path);
                self.seal_on(end.via, vec![ChatMessage::PathClose { path: end.path }], false)
            }
            None => Vec::new(),
        };
        (sends, self.connection_closed(connection))
    }

    /// Gives up searches nobody answered, places held for paths never opened, and paths gone
    /// quiet; looks for paths for files waiting for one.
    pub(super) fn paths_tick(&mut self, now: u64) -> Vec<Action> {
        let paths = &mut self.paths;
        paths.seen.retain(|_, at| now.saturating_sub(*at) < SEEN_SECS);
        let mut actions = Vec::new();
        let unanswered: Vec<PathId> = paths
            .searches
            .iter()
            .filter(|(_, s)| now.saturating_sub(s.started) >= ANSWER_SECS)
            .map(|(path, _)| *path)
            .collect();
        for path in unanswered {
            if let Some(Search {
                target: Target::Contact(contact),
                class,
                ..
            }) = paths.searches.remove(&path)
            {
                actions.push(Action::PathFailed { contact, class });
            }
        }
        let stale =
            |active_at: u64, open: bool| now.saturating_sub(active_at) >= if open { IDLE_SECS } else { ANSWER_SECS };
        // A place held for a path never opened is given back without a word.
        paths
            .carried
            .retain(|_, c| c.after.is_some() || !stale(c.active_at, false));
        let quiet: Vec<PathId> = paths
            .carried
            .iter()
            .filter(|(_, c)| stale(c.active_at, true))
            .map(|(path, _)| *path)
            .collect();
        let mut sends = Vec::new();
        for path in quiet {
            sends.extend(self.close_carried(path));
        }
        let ended: Vec<(ConnectionId, ConnectionId, PathId)> = self
            .paths
            .ends
            .iter()
            .filter(|(_, e)| stale(e.active_at, e.open))
            .map(|(c, e)| (*c, e.via, e.path))
            .collect();
        // A path kept up only by liveness goes, unless a call or a talk runs over it (§12.3), or it
        // carries a walkie-talkie channel's link (whose next talk may come any time).
        let unused = self.paths.ends.iter().filter(|(connection, e)| {
            let contact = self
                .links
                .iter()
                .find(|(_, c)| *c == *connection)
                .map(|(contact, _)| *contact);
            let kept = contact.is_some_and(|c| channels::is_channel_peer(c) || self.media.active_with(c));
            e.open && now.saturating_sub(e.used_at) >= UNUSED_SECS && !kept
        });
        let ended: Vec<(ConnectionId, ConnectionId, PathId)> = ended
            .into_iter()
            .chain(unused.map(|(c, e)| (*c, e.via, e.path)))
            .collect();
        for (connection, via, path) in ended {
            if self.paths.ends.contains_key(&connection) {
                sends.push((via, ChatMessage::PathClose { path }));
                actions.extend(self.drop_end(connection));
            }
        }
        let mut sent = self.mesh_sends(sends, None);
        sent.extend(actions);
        sent.extend(self.find_paths_for_files(now));
        // The head of a walkie-talkie cluster looks for others through Air Providers (§11.5).
        if self.keys.channel.is_some()
            && now.saturating_sub(self.paths.channel_searched) >= CHANNEL_SEARCH_SECS
            && self.providers(Class::Voice) > 0
        {
            self.paths.channel_searched = now;
            sent.extend(self.find_channel_path().unwrap_or_default());
        }
        if now.saturating_sub(self.paths.requests_searched) >= REQUEST_SEARCH_SECS && self.providers(Class::Voice) > 0 {
            self.paths.requests_searched = now;
            sent.extend(self.find_request_paths());
        }
        sent
    }

    /// Looks for a files path to each contact with files waiting for one: offered to it and not
    /// delivered, or being fetched from it, with no link that carries files.
    fn find_paths_for_files(&mut self, now: u64) -> Vec<Action> {
        if self.providers(Class::Files) == 0 {
            return Vec::new();
        }
        let Store::Open(account) = &self.store else {
            return Vec::new();
        };
        let due: Vec<ContactId> = self
            .keys
            .contacts
            .iter()
            .filter(|(c, k)| {
                !k.group_only
                    && self.file_link(**c).is_none()
                    && self
                        .paths
                        .files_checked
                        .get(*c)
                        .is_none_or(|at| now.saturating_sub(*at) >= FILES_CHECK_SECS)
            })
            .map(|(c, _)| *c)
            .filter(|c| {
                let offered = account
                    .undelivered(*c)
                    .is_ok_and(|m| m.iter().any(|m| m.attachment.is_some()));
                offered || account.downloading(*c).is_ok_and(|d| !d.is_empty())
            })
            .collect();
        let mut actions = Vec::new();
        for contact in due {
            self.paths.files_checked.insert(contact, now);
            actions.extend(self.find_path(contact, Class::Files).unwrap_or_default());
        }
        actions
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::Failure;
    use crate::node::{
        groups::tests::Net,
        mesh::tests::{cut_mesh, mesh_link, statuses},
    };
    use crate::storage::MessageStatus;

    const AYSE: usize = 0;
    const BURAK: usize = 1;
    const CEM: usize = 2;
    const DENIZ: usize = 3;

    fn all() -> Classes {
        Classes::from_bits(0x07)
    }

    /// Ayşe and Cem are contacts out of each other's reach; Burak, an Air Provider who knows
    /// neither, is between them.
    fn bridge() -> Net {
        let mut net = Net::new(&["Ayşe", "Burak", "Cem"]);
        net.pair(AYSE, CEM);
        let actions = net.node(BURAK).set_air_provider(all());
        net.run(BURAK, actions);
        mesh_link(&mut net, AYSE, BURAK);
        mesh_link(&mut net, BURAK, CEM);
        net
    }

    fn find(net: &mut Net, from: usize, to: usize, class: Class) {
        let contact = net.contact(from, to);
        let actions = net.node(from).find_path(contact, class).unwrap();
        net.run(from, actions);
    }

    fn path_link(net: &mut Net, at: usize, of: usize) -> Option<ConnectionId> {
        let contact = net.contact(at, of);
        net.node(at)
            .links
            .get(&contact)
            .copied()
            .filter(|c| is_path_connection(*c))
    }

    #[test]
    fn a_call_whose_provider_leaves_goes_on_over_another() {
        // Ayşe and Cem, out of each other's reach; Burak and Deniz, Air Providers, both between.
        const DENIZ: usize = 3;
        let mut net = Net::new(&["Ayşe", "Burak", "Cem", "Deniz"]);
        net.pair(AYSE, CEM);
        let actions = net.node(BURAK).set_air_provider(all());
        net.run(BURAK, actions);
        for provider in [BURAK, DENIZ] {
            mesh_link(&mut net, AYSE, provider);
            mesh_link(&mut net, provider, CEM);
        }
        find(&mut net, AYSE, CEM, Class::Voice);
        assert_eq!(net.node(BURAK).paths_carried(), 1);
        let cem = net.contact(AYSE, CEM);
        let (call, actions) = net.node(AYSE).start_call(cem, false).unwrap();
        net.run(AYSE, actions);
        let ringing = net.devices[CEM].shown.iter().find_map(|a| match a {
            Action::CallRinging { id, .. } => Some(*id),
            _ => None,
        });
        let actions = net.node(CEM).answer_call(ringing.expect("it rings")).unwrap();
        net.run(CEM, actions);
        // Deniz turns Air Provider mode on; Burak, carrying the path, leaves.
        let actions = net.node(DENIZ).set_air_provider(all());
        net.run(DENIZ, actions);
        cut_mesh(&mut net, AYSE, BURAK);
        cut_mesh(&mut net, BURAK, CEM);
        assert!(path_link(&mut net, AYSE, CEM).is_none(), "the path went with it");
        // The next tick looks for another path, while the call waits for its link.
        let now = now_secs();
        for at in [AYSE, CEM] {
            let actions = net.node(at).tick(now);
            net.run(at, actions);
        }
        assert!(path_link(&mut net, AYSE, CEM).is_some(), "linked again");
        assert_eq!(net.node(DENIZ).paths_carried(), 1, "through Deniz");
        assert!(
            !net.devices[AYSE]
                .shown
                .iter()
                .any(|a| matches!(a, Action::CallEnded { id, .. } if *id == call)),
            "the call goes on"
        );
        let actions = net.node(AYSE).send_audio(call, b"opus");
        net.run(AYSE, actions);
        assert!(net.devices[CEM].shown.iter().any(|a| matches!(a, Action::Audio { .. })));
    }

    #[test]
    fn a_link_runs_over_a_path_through_a_provider_and_carries_a_call() {
        let mut net = bridge();
        assert_eq!(net.node(AYSE).providers(Class::Video), 1, "Burak said so");
        assert_eq!(net.node(CEM).providers(Class::Files), 1);
        find(&mut net, AYSE, CEM, Class::Video);
        assert!(path_link(&mut net, AYSE, CEM).is_some(), "linked over the path");
        assert!(path_link(&mut net, CEM, AYSE).is_some());
        let cem = net.contact(AYSE, CEM);
        assert_eq!(net.node(AYSE).link_path(cem), Some((Class::Video, 1)));
        assert!(net.node(BURAK).keys.contacts.is_empty(), "the provider learned no one");

        // Messages go over the link, not the mesh.
        let (_, actions) = net.node(AYSE).send_message(cem, "yoldan").unwrap();
        net.run(AYSE, actions);
        assert_eq!(statuses(&net, CEM, AYSE), [("yoldan".into(), MessageStatus::Received)]);
        assert_eq!(statuses(&net, AYSE, CEM)[0].1, MessageStatus::Delivered);
        assert_eq!(net.node(BURAK).mesh.held_count(), 0, "nothing went through the mesh");

        // A video call, with a frame large enough to be cut into several data records.
        let (call, actions) = net.node(AYSE).start_call(cem, true).unwrap();
        net.run(AYSE, actions);
        let ringing = net.devices[CEM].shown.iter().find_map(|a| match a {
            Action::CallRinging { id, video: true, .. } => Some(*id),
            _ => None,
        });
        let actions = net.node(CEM).answer_call(ringing.expect("it rings")).unwrap();
        net.run(CEM, actions);
        let actions = net.node(AYSE).set_camera(call, crate::chat::VideoState::On).unwrap();
        net.run(AYSE, actions);
        let frame = vec![0x42; 40_000];
        let actions = net.node(AYSE).send_video(call, true, 0, (640, 480), &frame).unwrap();
        net.run(AYSE, actions);
        let shown = net.devices[CEM].shown.iter().find_map(|a| match a {
            Action::Video { frame, .. } => Some(frame.len()),
            _ => None,
        });
        assert_eq!(shown, Some(frame.len()), "the frame came through whole");
        let connection = path_link(&mut net, AYSE, CEM).unwrap();
        assert!(
            net.node(AYSE).path_backlog(connection).unwrap() < CREDIT_EVERY,
            "credited"
        );
    }

    #[test]
    fn a_voice_path_carries_no_video_and_no_files() {
        let mut net = bridge();
        find(&mut net, AYSE, CEM, Class::Voice);
        let cem = net.contact(AYSE, CEM);
        assert!(matches!(
            net.node(AYSE).start_call(cem, true),
            Err(NodeError::PathTooNarrow)
        ));
        let connection = path_link(&mut net, AYSE, CEM).unwrap();
        assert!(!net.node(AYSE).link_carries(connection, Class::Files));
        assert!(net.node(AYSE).file_link(cem).is_none());
        // A files path replaces it.
        find(&mut net, AYSE, CEM, Class::Files);
        let files = path_link(&mut net, AYSE, CEM).unwrap();
        assert_ne!(files, connection);
        assert!(net.node(AYSE).file_link(cem).is_some());
        assert!(!net.node(BURAK).paths.carried.is_empty());
        assert_eq!(net.node(BURAK).paths.carried.len(), 1, "the old path closed");
    }

    /// Ayşe and Cem, strangers out of each other's reach, Burak an Air Provider between them;
    /// Cem typed Ayşe's AirChat ID, and Ayşe takes requests if `accepting`.
    fn asking_through(accepting: bool) -> Net {
        let mut net = Net::new(&["Ayşe", "Burak", "Cem"]);
        let actions = net.node(BURAK).set_air_provider(all());
        net.run(BURAK, actions);
        mesh_link(&mut net, AYSE, BURAK);
        mesh_link(&mut net, BURAK, CEM);
        net.node(AYSE).set_accept_requests(accepting);
        let ayse = net.identity(AYSE).airchat_id().to_string();
        net.node(CEM).request_contact(&ayse).unwrap();
        net
    }

    fn names(net: &mut Net, at: usize) -> Vec<String> {
        let contacts = net.node(at).account().unwrap().contacts().unwrap();
        contacts.into_iter().map(|c| c.display_name).collect()
    }

    fn tick(net: &mut Net, at: usize) {
        let actions = net.node(at).tick(now_secs());
        net.run(at, actions);
    }

    #[test]
    fn a_typed_id_reaches_its_owner_through_a_provider() {
        let mut net = asking_through(true);
        tick(&mut net, CEM);
        let asked = net.devices[AYSE]
            .shown
            .iter()
            .any(|a| matches!(a, Action::ContactRequest { request, .. } if request.display_name == "Cem"));
        assert!(asked, "Ayşe is asked over the path");
        assert!(names(&mut net, AYSE).is_empty() && names(&mut net, CEM).is_empty());

        let cem = net.identity(CEM);
        let actions = net.node(AYSE).approve_contact_request(&cem).unwrap();
        net.run(AYSE, actions);
        assert_eq!(names(&mut net, AYSE), ["Cem"]);
        assert_eq!(names(&mut net, CEM), ["Ayşe"]);
        assert!(net.node(CEM).sent_requests().unwrap().is_empty());
        assert!(net.node(BURAK).keys.contacts.is_empty(), "the provider learned no one");
        assert_eq!(net.node(BURAK).paths_carried(), 0, "the path closed with the pairing");
    }

    #[test]
    fn an_owner_not_taking_requests_does_not_answer_and_the_asker_waits_quietly() {
        let mut net = asking_through(false);
        tick(&mut net, CEM);
        assert!(
            !net.devices[AYSE]
                .shown
                .iter()
                .any(|a| matches!(a, Action::ContactRequest { .. }))
        );
        // The search runs out without a word, and the next one waits its turn.
        let later = now_secs() + ANSWER_SECS;
        let actions = net.node(CEM).tick(later);
        assert!(!actions.iter().any(|a| matches!(a, Action::PathFailed { .. })));
        assert!(net.node(CEM).paths.searches.is_empty());
        net.run(CEM, actions);
        assert!(
            net.node(CEM).paths.searches.is_empty(),
            "not again before {REQUEST_SEARCH_SECS} s"
        );
        assert_eq!(net.node(CEM).sent_requests().unwrap().len(), 1, "still asking");
        // An ID typed now is looked for at the next tick, and so are the others.
        let burak = net.identity(BURAK).airchat_id().to_string();
        net.node(CEM).request_contact(&burak).unwrap();
        net.node(CEM).tick(later);
        assert_eq!(net.node(CEM).paths.searches.len(), 2);
    }

    #[test]
    fn only_the_owners_pairing_comes_over_a_path_looked_for_to_ask() {
        let mut net = asking_through(true);
        let node = net.node(CEM);
        let connection = node.paths.new_connection();
        node.paths.ends.insert(
            connection,
            End {
                path: [7; 16],
                class: Class::Voice,
                role: Role::Asks,
                via: 1,
                open: true,
                proof: [0; 16],
                providers: 1,
                outstanding: 0,
                held: VecDeque::new(),
                held_bytes: 0,
                taken: 0,
                frame: Vec::new(),
                active_at: 0,
                used_at: 0,
            },
        );
        // Whoever answered knew the ID; it may not start a mesh link or another kind of pairing.
        for frame in [[0, 0x31, 0, 0], [0, 0x21, 1, 0]] {
            let actions = node.on_frame(connection, &frame, now_secs());
            assert!(
                actions.iter().any(|a| matches!(
                    a,
                    Action::Failed {
                        reason: Failure::Protocol,
                        ..
                    }
                )),
                "{frame:?}"
            );
            node.closing.remove(&connection);
        }
    }

    #[test]
    fn nobody_carries_without_a_provider() {
        let mut net = Net::new(&["Ayşe", "Burak", "Cem"]);
        net.pair(AYSE, CEM);
        mesh_link(&mut net, AYSE, BURAK);
        mesh_link(&mut net, BURAK, CEM);
        let cem = net.contact(AYSE, CEM);
        assert!(matches!(
            net.node(AYSE).find_path(cem, Class::Voice),
            Err(NodeError::NoProvider)
        ));
        // A provider that carries voice only is not asked for video.
        let actions = net.node(BURAK).set_air_provider(Classes::from_bits(0x01));
        net.run(BURAK, actions);
        assert_eq!(net.node(AYSE).providers(Class::Voice), 1);
        assert!(matches!(
            net.node(AYSE).find_path(cem, Class::Video),
            Err(NodeError::NoProvider)
        ));
    }

    #[test]
    fn a_search_nobody_answers_fails() {
        let mut net = bridge();
        cut_mesh(&mut net, BURAK, CEM);
        find(&mut net, AYSE, CEM, Class::Voice);
        assert!(path_link(&mut net, AYSE, CEM).is_none());
        let later = now_secs() + ANSWER_SECS;
        let actions = net.node(AYSE).paths_tick(later);
        assert!(actions.iter().any(|a| matches!(a, Action::PathFailed { .. })));
        assert!(!net.node(BURAK).paths.carried.is_empty(), "a place held");
        let actions = net.node(BURAK).paths_tick(later);
        assert!(actions.is_empty(), "given back without a word");
        assert!(net.node(BURAK).paths.carried.is_empty());
    }

    #[test]
    fn paths_go_through_several_providers_within_the_class_limit() {
        // Ayşe — Burak — Deniz — Cem, Burak and Deniz providers.
        let mut net = Net::new(&["Ayşe", "Burak", "Cem", "Deniz"]);
        net.pair(AYSE, CEM);
        for provider in [BURAK, DENIZ] {
            let actions = net.node(provider).set_air_provider(all());
            net.run(provider, actions);
        }
        mesh_link(&mut net, AYSE, BURAK);
        mesh_link(&mut net, BURAK, DENIZ);
        mesh_link(&mut net, DENIZ, CEM);
        find(&mut net, AYSE, CEM, Class::Video);
        assert!(path_link(&mut net, AYSE, CEM).is_some());
        let cem = net.contact(AYSE, CEM);
        assert_eq!(net.node(AYSE).link_path(cem), Some((Class::Video, 2)));
        let (_, actions) = net.node(AYSE).send_message(cem, "iki köprü").unwrap();
        net.run(AYSE, actions);
        assert_eq!(statuses(&net, CEM, AYSE)[0].1, MessageStatus::Received);
    }

    #[test]
    fn a_provider_that_answers_for_others_is_not_taken() {
        let mut net = bridge();
        // Burak answers every request itself, as if it were Cem.
        let cem = net.contact(AYSE, CEM);
        let actions = net.node(AYSE).find_path(cem, Class::Voice).unwrap();
        let path = *net.node(AYSE).paths.searches.keys().next().unwrap();
        let from = net.node(AYSE).mesh.neighbour_links().next().unwrap();
        let (taken, sends) = net.node(AYSE).on_path_answer(from, path, 0, [0x66; 16], now_secs());
        assert!(taken.is_empty() && sends.is_empty(), "a wrong proof is ignored");
        assert!(net.node(AYSE).paths.searches.contains_key(&path), "still looking");
        net.run(AYSE, actions);
        assert!(path_link(&mut net, AYSE, CEM).is_some(), "Cem's answer is taken");
    }

    #[test]
    fn a_provider_that_goes_away_ends_the_link_over_the_path() {
        let mut net = bridge();
        find(&mut net, AYSE, CEM, Class::Voice);
        assert!(path_link(&mut net, AYSE, CEM).is_some());
        cut_mesh(&mut net, BURAK, CEM);
        let cem = net.contact(AYSE, CEM);
        assert!(!net.node(AYSE).links.contains_key(&cem), "Ayşe heard the path closed");
        assert!(
            net.devices[AYSE]
                .shown
                .iter()
                .any(|a| matches!(a, Action::LinkDown { contact } if *contact == cem))
        );
        assert!(net.node(BURAK).paths.carried.is_empty());
        assert!(net.node(AYSE).paths.ends.is_empty() && net.node(CEM).paths.ends.is_empty());
    }

    #[test]
    fn turning_air_provider_off_closes_what_it_carries_and_dropping_a_class_does_not() {
        let mut net = bridge();
        find(&mut net, AYSE, CEM, Class::Video);
        let actions = net.node(BURAK).set_air_provider(Classes::from_bits(0x01));
        net.run(BURAK, actions);
        assert_eq!(net.node(AYSE).providers(Class::Video), 0, "no longer offered");
        assert!(path_link(&mut net, AYSE, CEM).is_some(), "but carried on");
        let actions = net.node(BURAK).set_air_provider(Classes::NONE);
        net.run(BURAK, actions);
        assert!(path_link(&mut net, AYSE, CEM).is_none());
        assert!(path_link(&mut net, CEM, AYSE).is_none());
    }

    #[test]
    fn a_direct_link_opened_by_the_other_side_still_replaces_a_fresh_path() {
        // The path opened by one side and the direct link by the other, seconds apart: no race,
        // the direct link wins whatever the handshake hashes (four tries, as they are random).
        for _ in 0..4 {
            let mut net = bridge();
            let now = net.now;
            let token = net.devices[CEM].node.presence_token(now);
            let opener_is_ayse = net.node(AYSE).recognize_presence(&token, now).unwrap().opener;
            let (waiter, opener) = if opener_is_ayse { (CEM, AYSE) } else { (AYSE, CEM) };
            find(&mut net, waiter, opener, Class::Voice);
            assert!(path_link(&mut net, waiter, opener).is_some());
            net.link(opener, waiter);
            for (at, of) in [(AYSE, CEM), (CEM, AYSE)] {
                let contact = net.contact(at, of);
                assert!(!is_path_connection(net.node(at).links[&contact]), "direct at {at}");
            }
        }
    }

    #[test]
    fn a_direct_link_replaces_the_one_over_a_path_and_is_never_replaced_by_one() {
        let mut net = bridge();
        find(&mut net, AYSE, CEM, Class::Voice);
        net.link(AYSE, CEM);
        let cem = net.contact(AYSE, CEM);
        let direct = net.node(AYSE).links[&cem];
        assert!(!is_path_connection(direct));
        assert!(net.node(BURAK).paths.carried.is_empty(), "the path closed");
        let actions = net.node(AYSE).find_path(cem, Class::Voice).unwrap();
        assert!(actions.is_empty(), "nothing to look for");
    }

    #[test]
    fn an_end_holds_back_beyond_the_window_and_a_provider_closes_a_path_that_does_not() {
        let mut net = bridge();
        find(&mut net, AYSE, CEM, Class::Voice);
        let connection = path_link(&mut net, AYSE, CEM).unwrap();
        // Frames sent while nothing comes back: only the window goes out.
        let mut sent = 0;
        for _ in 0..4 {
            let (actions, _) = net.node(AYSE).path_send(connection, &[7; 16_000]);
            sent += actions.len();
        }
        let window = Class::Voice.window();
        assert!(sent * 16_000 <= window + 16_000, "held back");
        assert!(net.node(AYSE).path_backlog(connection).unwrap() >= 4 * 16_000);
        // A provider sees an end that ignores the window and closes the path.
        let path = net.node(AYSE).paths.ends[&connection].path;
        let before = net.node(BURAK).paths.carried[&path].before;
        let mut closed = false;
        for _ in 0..4 {
            let data = vec![7; path::MAX_DATA];
            let (_, sends) = net.node(BURAK).on_path_data(before, path, true, data, now_secs());
            closed |= sends.iter().any(|(_, r)| matches!(r, ChatMessage::PathClose { .. }));
        }
        assert!(closed);
        assert!(net.node(BURAK).paths.carried.is_empty());
    }

    #[test]
    fn a_path_kept_up_only_by_liveness_closes_but_not_during_a_call() {
        let mut net = bridge();
        find(&mut net, AYSE, CEM, Class::Voice);
        let cem = net.contact(AYSE, CEM);
        let (call, actions) = net.node(AYSE).start_call(cem, false).unwrap();
        net.run(AYSE, actions);
        let later = now_secs() + UNUSED_SECS;
        let actions = net.node(AYSE).paths_tick(later);
        net.run(AYSE, actions);
        assert!(path_link(&mut net, AYSE, CEM).is_some(), "the call holds it");
        let actions = net.node(AYSE).end_call(call);
        net.run(AYSE, actions);
        let actions = net.node(AYSE).paths_tick(later);
        net.run(AYSE, actions);
        assert!(path_link(&mut net, AYSE, CEM).is_none());
        assert!(path_link(&mut net, CEM, AYSE).is_none(), "Cem heard it close");
        assert!(net.node(BURAK).paths.carried.is_empty());
    }

    #[test]
    fn records_leave_a_link_in_the_order_they_were_sealed() {
        let mut net = bridge();
        find(&mut net, AYSE, CEM, Class::Voice);
        let connection = path_link(&mut net, AYSE, CEM).unwrap();
        let via = net.node(AYSE).paths.ends[&connection].via;
        // A ping on the first hop's link is sealed before one on the link over the path, which
        // becomes a record on that same link only when routed: it must go out after the first.
        let outer = net.node(AYSE).seal_on(via, vec![ChatMessage::Ping], false);
        let inner = net.node(AYSE).seal_on(connection, vec![ChatMessage::Ping], false);
        net.run(AYSE, inner.into_iter().chain(outer).collect());
        assert!(path_link(&mut net, AYSE, CEM).is_some(), "still over the path");
        assert_eq!(net.node(BURAK).paths.carried.len(), 1);
        assert_eq!(
            net.node(BURAK).mesh.neighbour_links().count(),
            2,
            "the link to Ayşe stays"
        );
    }

    #[test]
    fn a_group_call_reaches_members_through_a_provider_and_they_hear_each_other() {
        let mut net = Net::new(&["Ayşe", "Burak", "Cem", "Deniz"]);
        net.pair(AYSE, BURAK);
        net.pair(AYSE, CEM);
        let contacts = [net.contact(AYSE, BURAK), net.contact(AYSE, CEM)];
        let (_, actions) = net.node(AYSE).create_group("Kamp", &contacts).unwrap();
        net.run(AYSE, actions);
        net.link(AYSE, BURAK);
        net.link(AYSE, CEM);
        net.cut(AYSE, BURAK);
        net.cut(AYSE, CEM);
        // Nobody is in reach of anybody now but Deniz, an Air Provider who is in nobody's group.
        let actions = net.node(DENIZ).set_air_provider(all());
        net.run(DENIZ, actions);
        for at in [AYSE, BURAK, CEM] {
            mesh_link(&mut net, at, DENIZ);
        }
        let row = net.group(AYSE).row;
        let (call, actions) = net.node(AYSE).start_group_call(row).unwrap();
        net.run(AYSE, actions);
        for at in [BURAK, CEM] {
            let rings = net.devices[at]
                .shown
                .iter()
                .any(|a| matches!(a, Action::GroupCallRinging { id, .. } if *id == call));
            assert!(rings, "it rings for device {at} through Deniz");
        }
        for at in [BURAK, CEM] {
            let actions = net.node(at).join_group_call(call).unwrap();
            net.run(at, actions);
        }
        let participants = |net: &Net, at: usize| {
            net.devices[at]
                .shown
                .iter()
                .rev()
                .find_map(|a| match a {
                    Action::GroupCallChanged { participants, .. } => Some(participants.len()),
                    _ => None,
                })
                .unwrap_or_default()
        };
        assert_eq!(
            [
                participants(&net, AYSE),
                participants(&net, BURAK),
                participants(&net, CEM)
            ],
            [2, 2, 2]
        );
        // Burak and Cem, who are not contacts, hear each other through Ayşe: no path between them.
        assert!(path_link(&mut net, BURAK, CEM).is_none() && path_link(&mut net, CEM, BURAK).is_none());
        let audio = net.node(CEM).send_audio(call, b"opus");
        net.run(CEM, audio);
        let from_cem = net.contact(BURAK, CEM);
        assert!(
            net.devices[BURAK]
                .shown
                .iter()
                .any(|a| matches!(a, Action::Audio { from, .. } if *from == from_cem)),
            "Burak hears Cem, as Cem"
        );
        assert_eq!(
            net.node(DENIZ).paths.carried.len(),
            2,
            "one path per participant, not per pair"
        );
    }

    #[test]
    fn when_the_caller_leaves_the_others_find_each_other_with_one_path() {
        let mut net = Net::new(&["Ayşe", "Burak", "Cem", "Deniz"]);
        net.pair(AYSE, BURAK);
        net.pair(AYSE, CEM);
        let contacts = [net.contact(AYSE, BURAK), net.contact(AYSE, CEM)];
        let (_, actions) = net.node(AYSE).create_group("Kamp", &contacts).unwrap();
        net.run(AYSE, actions);
        net.link(AYSE, BURAK);
        net.link(AYSE, CEM);
        net.cut(AYSE, BURAK);
        net.cut(AYSE, CEM);
        let actions = net.node(DENIZ).set_air_provider(all());
        net.run(DENIZ, actions);
        for at in [AYSE, BURAK, CEM] {
            mesh_link(&mut net, at, DENIZ);
        }
        let row = net.group(AYSE).row;
        let (call, actions) = net.node(AYSE).start_group_call(row).unwrap();
        net.run(AYSE, actions);
        for at in [BURAK, CEM] {
            let actions = net.node(at).join_group_call(call).unwrap();
            net.run(at, actions);
        }
        // Ayşe, through whom Burak and Cem heard each other, leaves.
        let actions = net.node(AYSE).end_call(call);
        net.run(AYSE, actions);
        // Some 15 s on, each notices the other is gone; one of them looks for the other.
        let now = now_secs();
        for at in [BURAK, CEM] {
            let actions = net.node(at).tick(now);
            net.run(at, actions);
        }
        for at in [BURAK, CEM] {
            let actions = net.node(at).tick(now + 15);
            net.run(at, actions);
        }
        assert!(path_link(&mut net, BURAK, CEM).is_some() || path_link(&mut net, CEM, BURAK).is_some());
        let audio = net.node(CEM).send_audio(call, b"opus");
        net.run(CEM, audio);
        let from_cem = net.contact(BURAK, CEM);
        let heard = net.devices[BURAK]
            .shown
            .iter()
            .filter(|a| matches!(a, Action::Audio { from, .. } if *from == from_cem))
            .count();
        assert!(heard >= 1, "Burak hears Cem again");
        assert!(net.node(BURAK).media.group_call().is_some(), "the call goes on");
    }

    #[test]
    fn two_paths_found_at_once_leave_one_on_both_sides() {
        let mut net = bridge();
        let (cem, ayse) = (net.contact(AYSE, CEM), net.contact(CEM, AYSE));
        find(&mut net, AYSE, CEM, Class::Voice);
        // Cem looked for Ayşe at the same time: its path arrives once Ayşe's is up.
        let actions = net.node(CEM).search_for(ayse, Class::Voice).unwrap();
        net.run(CEM, actions);
        let at_ayse = net.node(AYSE).links[&cem];
        let at_cem = net.node(CEM).links[&ayse];
        let path_at = |net: &mut Net, at: usize, connection: ConnectionId| net.node(at).paths.ends[&connection].path;
        assert_eq!(
            path_at(&mut net, AYSE, at_ayse),
            path_at(&mut net, CEM, at_cem),
            "the same one"
        );
        assert_eq!(net.node(BURAK).paths.carried.len(), 1, "the other closed");
    }

    #[test]
    fn a_provider_carries_many_voice_paths_but_few_heavy_ones() {
        let mut net = bridge();
        let from = net.node(BURAK).mesh.neighbour_links().next().unwrap();
        let request = |path: u8, class: Class| Request {
            path: [path; 16],
            class,
            hops: class.max_providers(),
            nonce: [path; 16],
            tag: [0; 16],
        };
        let now = now_secs();
        let passed = |net: &mut Net, paths: std::ops::Range<u8>, class: Class| {
            paths
                .map(|path| net.node(BURAK).on_path_request(from, request(path, class), now).len())
                .filter(|sent| *sent > 0)
                .count()
        };
        assert_eq!(passed(&mut net, 1..4, Class::Video), 2, "video: two at most");
        assert_eq!(passed(&mut net, 10..13, Class::Files), 2, "files: two at most");
        // Voice goes well beyond the eight paths of before (a neighbour may ask 20 times a minute).
        assert_eq!(passed(&mut net, 20..34, Class::Voice), 14);
        assert_eq!(net.node(BURAK).paths.carried.len(), 18);
    }

    #[test]
    fn requests_are_handled_once_and_only_so_many_from_one_neighbour() {
        let mut net = bridge();
        let from = net.node(BURAK).mesh.neighbour_links().next().unwrap();
        let request = |path: u8| Request {
            path: [path; 16],
            class: Class::Voice,
            hops: 4,
            nonce: [path; 16],
            tag: [0; 16],
        };
        let now = now_secs();
        assert_eq!(
            net.node(BURAK).on_path_request(from, request(1), now).len(),
            1,
            "passed on"
        );
        assert!(
            net.node(BURAK).on_path_request(from, request(1), now).is_empty(),
            "seen"
        );
        let mut passed = 0;
        for path in 2..40 {
            passed += net.node(BURAK).on_path_request(from, request(path), now).len();
        }
        assert!(passed < MAX_PATHS, "room and rate limit it");
        let hops_done = Request { hops: 0, ..request(99) };
        assert!(net.node(BURAK).on_path_request(from, hops_done, now + 60).is_empty());
    }
}
