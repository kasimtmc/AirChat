//! Fuzz targets that drive a whole node (see `crate::fuzz`): frames of a connection someone just
//! opened, and records from a stranger on the mesh, a member of a walkie-talkie channel and a
//! contact, sent over links whose handshakes succeeded, so they reach everything behind the
//! decryption. Each target keeps one node per thread across inputs, as a long-running device would.

use std::{cell::RefCell, path::PathBuf};

use super::{Action, ConnectionId, ConnectionState, Node};
use crate::{
    account::Account,
    channel::{Channel, Hello},
    crypto::{pin::PinParams, random},
    fuzz::frames,
    link::{ChannelInitiator, ChannelKeys, Flavor, Session, epoch_at},
    storage::ContactId,
};

/// Cheap enough to make a node per run; the PIN guards nothing here.
const PARAMS: PinParams = PinParams {
    memory_kib: 64,
    iterations: 1,
    parallelism: 1,
};

/// A directory of its own, gone with it.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let name = format!(
            "airchat-fuzz-{}-{}",
            std::process::id(),
            hex(&random::array::<8>().expect("randomness"))
        );
        let path = std::env::temp_dir().join(name);
        std::fs::create_dir_all(&path).expect("a scratch directory");
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn device(name: &str) -> (Node, Scratch) {
    let scratch = Scratch::new();
    let (account, _) = Account::create(&scratch.0, b"123456", name, PARAMS).expect("an account");
    (Node::new(account).expect("a node"), scratch)
}

/// What `node` sent on `connection`, and whether it closed it.
fn sent(actions: &[Action], connection: ConnectionId) -> (Vec<Vec<u8>>, bool) {
    let mut frames = Vec::new();
    let mut closed = false;
    for action in actions {
        match action {
            Action::Send { connection: c, bytes } if *c == connection => frames.push(bytes.clone()),
            Action::Close { connection: c } if *c == connection => closed = true,
            _ => {}
        }
    }
    (frames, closed)
}

/// Hands `actions` to the node's router, as the platform does, and reports whether `connection`
/// closed; the transport then says so.
fn settle(node: &mut Node, actions: Vec<Action>, connection: ConnectionId) -> bool {
    let actions = node.route(actions);
    let (_, closed) = sent(&actions, connection);
    if closed {
        node.connection_closed(connection);
    }
    closed
}

/// A node that frames from a new connection reach first: any handshake's first message, then
/// whatever follows on that connection.
pub struct Newcomer {
    node: Node,
    _scratch: Scratch,
    next: ConnectionId,
    now: u64,
}

impl Default for Newcomer {
    fn default() -> Self {
        let (mut node, scratch) = device("Ayşe");
        // Accepts nearby pairing too, as while "Add nearby" is open.
        node.open_pairing().expect("opens");
        Self {
            node,
            _scratch: scratch,
            next: 1,
            now: 1_000,
        }
    }
}

impl Newcomer {
    pub fn feed(&mut self, data: &[u8]) {
        let connection = self.next;
        self.next += 1;
        for frame in frames(data) {
            let actions = self.node.on_frame(connection, frame, self.now);
            if settle(&mut self.node, actions, connection) {
                return;
            }
        }
        let actions = self.node.connection_closed(connection);
        self.node.route(actions);
    }
}

/// A node that a stranger linked to over the mesh (§10.2), which anyone can, or a member of the
/// walkie-talkie channel it is tuned to (§11.3), which anyone who knows its password can be.
pub struct Stranger {
    node: Node,
    _scratch: Scratch,
    /// The channel the node is tuned to; a mesh stranger without one.
    channel: Option<Channel>,
    link: Option<(ConnectionId, Session)>,
    next: ConnectionId,
    now: u64,
}

impl Stranger {
    pub fn on_mesh() -> Self {
        let (node, scratch) = device("Ayşe");
        Self {
            node,
            _scratch: scratch,
            channel: None,
            link: None,
            next: 1,
            now: 1_000,
        }
    }

    pub fn on_channel() -> Self {
        let mut stranger = Self::on_mesh();
        let row = stranger.node.create_channel("Kamp").expect("a channel").row;
        stranger.node.tune_channel(Some(row)).expect("tunes in");
        let account = stranger.node.account().expect("open");
        stranger.channel = Some(account.db().channel(row).expect("stored").expect("there").1);
        stranger
    }

    /// Runs the link handshake with the node as its first message's sender.
    fn connect(&mut self) -> Option<(ConnectionId, Session)> {
        let (id, psk) = super::mesh::mesh_link_keys();
        let (keys, tag, payload) = match &self.channel {
            None => (
                ChannelKeys {
                    id: &id,
                    psk: &psk,
                    flavor: Flavor::MESH,
                },
                random::array().ok()?,
                random::array::<16>().ok()?.to_vec(),
            ),
            Some(channel) => {
                let hello = Hello {
                    device: random::array().ok()?,
                    name: "Burak".into(),
                };
                let tag = channel.tag_key().ok()?.tag(epoch_at(self.now), &random::array().ok()?);
                let keys = ChannelKeys {
                    id: channel.id(),
                    psk: channel.link_psk(),
                    flavor: Flavor::CHANNEL,
                };
                (keys, tag, hello.encode())
            }
        };
        let (initiator, first) = ChannelInitiator::start(&keys, &tag).ok()?;
        let connection = self.next;
        self.next += 1;
        let actions = self.node.on_frame(connection, &first, self.now);
        let (answer, _) = sent(&actions, connection);
        let (established, last) = initiator.finish(answer.first()?, &payload).ok()?;
        let actions = self.node.on_frame(connection, &last, self.now);
        (!settle(&mut self.node, actions, connection)).then_some((connection, established.session))
    }

    pub fn feed(&mut self, data: &[u8]) {
        for frame in frames(data) {
            if self.link.is_none() {
                self.link = self.connect();
            }
            let Some((connection, session)) = &mut self.link else {
                return;
            };
            let connection = *connection;
            let Ok(record) = session.seal(frame) else {
                continue;
            };
            let actions = self.node.on_frame(connection, &record, self.now);
            if settle(&mut self.node, actions, connection) {
                self.link = None;
            }
        }
        self.now += 1;
        let actions = self.node.tick(self.now);
        if let Some((connection, _)) = self.link
            && settle(&mut self.node, actions, connection)
        {
            self.link = None;
        }
    }
}

/// A node and one of its contacts, linked: the contact's records reach everything a contact may
/// ask for (§8).
pub struct Contact {
    node: Node,
    peer: Node,
    _scratch: (Scratch, Scratch),
    /// The peer as the node knows it, and the node as the peer knows it.
    contacts: (ContactId, ContactId),
    /// The link's connection at the node and at the peer.
    link: Option<(ConnectionId, ConnectionId)>,
    next: ConnectionId,
    now: u64,
}

impl Default for Contact {
    fn default() -> Self {
        let ((node, a), (peer, b)) = (device("Ayşe"), device("Burak"));
        let mut contact = Self {
            node,
            peer,
            _scratch: (a, b),
            contacts: (0, 0),
            link: None,
            next: 1,
            now: 1_000,
        };
        contact.pair();
        contact
    }
}

impl Contact {
    /// Carries frames between the two over one connection until both are quiet.
    fn exchange(
        &mut self,
        (at_node, at_peer): (ConnectionId, ConnectionId),
        mut actions: Vec<Action>,
        mut from_node: bool,
    ) {
        while !actions.is_empty() {
            let (frames, _) = sent(&actions, if from_node { at_node } else { at_peer });
            actions = Vec::new();
            for frame in frames {
                let (to, connection) = if from_node {
                    (&mut self.peer, at_peer)
                } else {
                    (&mut self.node, at_node)
                };
                actions.extend(to.on_frame(connection, &frame, self.now));
            }
            from_node = !from_node;
        }
    }

    fn pair(&mut self) {
        let wire = (self.next, self.next + 1);
        self.next += 2;
        self.peer.open_pairing().expect("opens");
        let first = self.node.pair_nearby(wire.0).expect("starts");
        self.exchange(wire, first, true);
        let confirm = self.peer.confirm_pairing(wire.1);
        self.exchange(wire, confirm, false);
        let confirm = self.node.confirm_pairing(wire.0);
        self.exchange(wire, confirm, true);
        self.peer.close_pairing();
        let only = |node: &Node| node.account().expect("open").contacts().expect("contacts")[0].id;
        self.contacts = (only(&self.node), only(&self.peer));
    }

    /// Opens the link from the side that opens links (§5.2).
    fn connect(&mut self) -> Option<(ConnectionId, ConnectionId)> {
        let wire = (self.next, self.next + 1);
        self.next += 2;
        let node_opens = self.node.keys.identity.as_bytes() < self.peer.keys.identity.as_bytes();
        let first = if node_opens {
            self.node.connect_contact(wire.0, self.contacts.0, self.now)
        } else {
            self.peer.connect_contact(wire.1, self.contacts.1, self.now)
        }
        .ok()?;
        self.exchange(wire, first, node_opens);
        (self.node.links.get(&self.contacts.0) == Some(&wire.0)).then_some(wire)
    }

    fn unlink(&mut self, (at_node, at_peer): (ConnectionId, ConnectionId)) {
        self.link = None;
        let actions = self.peer.connection_closed(at_peer);
        self.peer.route(actions);
        if self.node.links.get(&self.contacts.0) == Some(&at_node) {
            let actions = self.node.connection_closed(at_node);
            self.node.route(actions);
        }
    }

    pub fn feed(&mut self, data: &[u8]) {
        for frame in frames(data) {
            if self.link.is_none() {
                self.link = self.connect();
            }
            let Some(wire) = self.link else {
                return;
            };
            let Some(ConnectionState::Linked { session, .. }) = self.peer.connections.get_mut(&wire.1) else {
                return self.unlink(wire);
            };
            let Ok(record) = session.seal(frame) else {
                continue;
            };
            let actions = self.node.on_frame(wire.0, &record, self.now);
            if settle(&mut self.node, actions, wire.0) {
                self.unlink(wire);
            }
        }
        self.now += 1;
        let actions = self.node.tick(self.now);
        if let Some(wire) = self.link
            && settle(&mut self.node, actions, wire.0)
        {
            self.unlink(wire);
        }
    }
}

/// Frames on a connection someone opened: each a u16 length and its bytes.
pub fn first_frames(data: &[u8]) {
    thread_local!(static NODE: RefCell<Option<Newcomer>> = const { RefCell::new(None) });
    NODE.with_borrow_mut(|node| node.get_or_insert_with(Newcomer::default).feed(data));
}

/// Records a stranger sends over a mesh link: each a u16 length and its bytes.
pub fn mesh_records(data: &[u8]) {
    thread_local!(static NODE: RefCell<Option<Stranger>> = const { RefCell::new(None) });
    NODE.with_borrow_mut(|node| node.get_or_insert_with(Stranger::on_mesh).feed(data));
}

/// Records a member of a walkie-talkie channel sends over its link: each a u16 length and its bytes.
pub fn channel_records(data: &[u8]) {
    thread_local!(static NODE: RefCell<Option<Stranger>> = const { RefCell::new(None) });
    NODE.with_borrow_mut(|node| node.get_or_insert_with(Stranger::on_channel).feed(data));
}

/// Records a contact sends over its link: each a u16 length and its bytes.
pub fn contact_records(data: &[u8]) {
    thread_local!(static NODE: RefCell<Option<Contact>> = const { RefCell::new(None) });
    NODE.with_borrow_mut(|node| node.get_or_insert_with(Contact::default).feed(data));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chat::ChatMessage,
        fuzz::harness::{Mutator, fuzz, seeds},
    };

    /// Inputs of one to three records, framed. Most are records of the published vectors, as they
    /// are or with a few changes: the node gets past decoding them.
    fn framed(name: &str, runs: usize) -> Vec<Vec<u8>> {
        let seeds = seeds();
        let records: Vec<Vec<u8>> = seeds
            .iter()
            .filter(|seed| matches!(ChatMessage::decode(seed), Ok(Some(_))))
            .cloned()
            .collect();
        let mut mutator = Mutator::new(name);
        (0..runs)
            .map(|_| {
                let mut input = Vec::new();
                for _ in 0..1 + mutator.below(3) {
                    let mut record = match mutator.below(4) {
                        0 => seeds[mutator.below(seeds.len())].clone(),
                        _ => records[mutator.below(records.len())].clone(),
                    };
                    if mutator.below(2) == 0 {
                        mutator.mutate(&mut record, &seeds);
                    }
                    record.truncate(usize::from(u16::MAX));
                    input.extend_from_slice(&(record.len() as u16).to_be_bytes());
                    input.extend_from_slice(&record);
                }
                input
            })
            .collect()
    }

    fn runs(base: usize) -> usize {
        base * std::env::var("AIRCHAT_FUZZ_RUNS")
            .ok()
            .and_then(|n| n.parse().ok())
            .unwrap_or(1)
    }

    #[test]
    fn strangers_and_contacts_link_and_stay_linked() {
        for mut stranger in [Stranger::on_mesh(), Stranger::on_channel()] {
            stranger.link = stranger.connect();
            assert!(stranger.link.is_some());
        }
        let mut contact = Contact::default();
        contact.link = contact.connect();
        assert!(contact.link.is_some());
    }

    #[test]
    fn first_frames() {
        let mut node = Newcomer::default();
        fuzz("first_frames", 0, &framed("first_frames", runs(1_000)), |data| {
            node.feed(data)
        });
    }

    #[test]
    fn mesh_records() {
        let mut node = Stranger::on_mesh();
        fuzz("mesh_records", 0, &framed("mesh_records", runs(2_000)), |data| {
            node.feed(data)
        });
    }

    #[test]
    fn channel_records() {
        let mut node = Stranger::on_channel();
        fuzz("channel_records", 0, &framed("channel_records", runs(2_000)), |data| {
            node.feed(data)
        });
    }

    #[test]
    fn contact_records() {
        let mut node = Contact::default();
        fuzz("contact_records", 0, &framed("contact_records", runs(2_000)), |data| {
            node.feed(data)
        });
    }
}
