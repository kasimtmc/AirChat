//! Group updates through the mesh (rust/airchat-protocol/docs/protocol.md §10.9): every member that makes or takes in an
//! update puts the same copies of it into the mesh; members of the epoch before recognise them by
//! their tags, and contacts added to the group take them by their ids after a *mesh update key*.

use std::collections::{HashMap, VecDeque};

use super::{Action, ConnectionId, Node, Store, mesh::FROM_MESH, now_ms, now_secs};
use crate::{
    chat::{ChatMessage, MAX_UPDATE_PARTS, UPDATE_PART_LEN},
    crypto::SecretBytes,
    group::{self, GroupId},
    inbox::InboxEvent,
    link::epoch_at,
    mesh::{self, Envelope, EnvelopeId, MAX_HOPS, MAX_LIFETIME_MINUTES, NO_DROP, UpdateKeys, UpdatePart},
    storage::{
        ContactId,
        groups::{Membership, StoredGroup},
    },
};

/// Updates put together at once; another pushes out the oldest.
const MAX_GATHERING: usize = 8;
/// Updates remembered as taken in, not to be put together again.
const MAX_TAKEN: usize = 64;
/// An update goes into the mesh again, for neighbours that come later, while it is queued for some
/// member and younger than this.
const RESEND_MS: i64 = 24 * 3600 * 1000;

type Sends = Vec<(ConnectionId, ChatMessage)>;

/// An update whose parts come through the mesh.
struct Gathering {
    update_id: [u8; 16],
    key: SecretBytes<32>,
    parts: Vec<Option<Vec<u8>>>,
}

#[derive(Default)]
pub(crate) struct MeshUpdates {
    /// Updates being put together, oldest first.
    gathering: VecDeque<Gathering>,
    /// Part ids taken whatever their tag (after a mesh update key), with their update's id.
    expected: HashMap<EnvelopeId, [u8; 16]>,
    /// Updates put together already.
    taken: VecDeque<[u8; 16]>,
}

impl MeshUpdates {
    fn gathering(&mut self, update_id: &[u8; 16]) -> Option<&mut Gathering> {
        self.gathering.iter_mut().find(|g| &g.update_id == update_id)
    }

    fn start(&mut self, update_id: [u8; 16], key: SecretBytes<32>, count: u16) {
        if self.gathering.len() >= MAX_GATHERING
            && let Some(dropped) = self.gathering.pop_front()
        {
            self.expected.retain(|_, u| *u != dropped.update_id);
        }
        self.gathering.push_back(Gathering {
            update_id,
            key,
            parts: vec![None; usize::from(count)],
        });
    }

    fn done(&mut self, update_id: [u8; 16]) {
        self.gathering.retain(|g| g.update_id != update_id);
        self.expected.retain(|_, u| *u != update_id);
        if self.taken.len() >= MAX_TAKEN {
            self.taken.pop_front();
        }
        self.taken.push_back(update_id);
    }
}

/// The keys of the mesh copies of a group's latest update: from the epoch before, or the group's
/// own for its first. `None` if this device does not hold the epoch before.
fn update_keys_of(stored: &StoredGroup) -> Option<UpdateKeys> {
    let key = match stored.epoch {
        0 => &stored.epoch_key,
        epoch => stored
            .previous
            .as_ref()
            .filter(|(_, roster)| roster.epoch + 1 == epoch)
            .map(|(key, _)| key)?,
    };
    mesh::update_keys(key, &stored.group_id, stored.epoch).ok()
}

/// How many parts `update` goes in.
fn part_count(update: &[u8]) -> Option<u16> {
    u16::try_from(update.len().div_ceil(UPDATE_PART_LEN))
        .ok()
        .filter(|count| (1..=MAX_UPDATE_PARTS).contains(count))
}

fn expiry(now_secs: u64) -> u32 {
    u32::try_from(now_secs / 60)
        .unwrap_or(u32::MAX)
        .saturating_add(MAX_LIFETIME_MINUTES)
}

/// The mesh copies of `update` (§10.9); the same from every member that makes them.
fn update_envelopes(group_id: &GroupId, update: &[u8], keys: &UpdateKeys, now_secs: u64) -> Vec<Envelope> {
    let update_id = group::update_id(update);
    let (Some(count), Ok(key)) = (part_count(update), mesh::update_part_key(&keys.base, &update_id)) else {
        return Vec::new();
    };
    let tag = mesh::tag(&keys.tag_key, epoch_at(now_secs));
    let mut envelopes = Vec::new();
    for (index, bytes) in update.chunks(UPDATE_PART_LEN).enumerate() {
        let index = u16::try_from(index).expect("at most 64 parts");
        let id = mesh::update_part_id(group_id, &update_id, index);
        let part = UpdatePart {
            update_id,
            index,
            count,
        };
        let Ok(body) = mesh::seal_update_part(&key, &id, &part, bytes) else {
            return Vec::new();
        };
        envelopes.push(Envelope {
            id,
            hops: MAX_HOPS,
            expires: expiry(now_secs),
            tag,
            drop: NO_DROP,
            body,
        });
    }
    envelopes
}

/// The *mesh update key* of `update` for a contact it adds.
fn update_key_record(group_id: &GroupId, epoch: u64, update: &[u8], keys: &UpdateKeys) -> Option<ChatMessage> {
    let update_id = group::update_id(update);
    let key = mesh::update_part_key(&keys.base, &update_id).ok()?;
    Some(ChatMessage::MeshUpdateKey {
        group_id: *group_id,
        epoch,
        update_id,
        count: part_count(update)?,
        key: zeroize::Zeroizing::new(*key.expose()),
    })
}

/// What a group's latest update needs to go into the mesh: its bytes and copies' keys, and the
/// key record for contacts it adds.
struct Outgoing {
    group_id: GroupId,
    update: Vec<u8>,
    keys: UpdateKeys,
    record: ChatMessage,
    added: Vec<ContactId>,
}

impl Node {
    // Sending.

    /// A group's latest update, ready to go into the mesh, if this device holds the epoch before
    /// (or it is the group's first); `added` are the contacts among `recipients` that were not
    /// members of the epoch before.
    fn outgoing_update(&self, group: i64, recipients: &[ContactId]) -> Option<Outgoing> {
        let Store::Open(account) = &self.store else {
            return None;
        };
        let db = account.db();
        let stored = db.group(group).ok()??;
        if stored.membership != Membership::Member {
            return None;
        }
        let row = db.group_update_row(group, stored.epoch).ok()??;
        let update = db.group_update(row).ok()??;
        let keys = update_keys_of(&stored)?;
        let record = update_key_record(&stored.group_id, stored.epoch, &update, &keys)?;
        let before = stored
            .previous
            .as_ref()
            .map(|(_, roster)| roster)
            .filter(|_| stored.epoch > 0);
        let added = recipients
            .iter()
            .copied()
            .filter(|&r| self.is_contact(r))
            .filter(|r| {
                let identity = &self.keys.contacts[r].identity;
                before.is_none_or(|roster| roster.member(identity).is_none())
            })
            .collect();
        Some(Outgoing {
            group_id: stored.group_id,
            update,
            keys,
            record,
            added,
        })
    }

    /// A group's latest update, which this device just made or took in, goes into the mesh; its key
    /// to the contacts among `recipients` it adds.
    pub(super) fn mesh_send_update(&mut self, group: i64, recipients: &[ContactId]) -> Vec<Action> {
        if self.mesh.neighbours() == 0 {
            return Vec::new();
        }
        let Some(outgoing) = self.outgoing_update(group, recipients) else {
            return Vec::new();
        };
        let now = now_secs();
        let mut sends: Sends = Vec::new();
        for envelope in update_envelopes(&outgoing.group_id, &outgoing.update, &outgoing.keys, now) {
            sends.extend(self.mesh_send_envelope(envelope, now));
        }
        for contact in outgoing.added {
            sends.extend(self.mesh_send_contact(contact, &outgoing.record, expiry(now), now));
        }
        self.mesh_sends(sends, None)
    }

    /// For a neighbour that just came: the copies of updates still queued for some member and
    /// young, and their keys for the contacts they add.
    pub(super) fn own_waiting_updates(&mut self, now_secs: u64) -> Vec<Envelope> {
        let Store::Open(account) = &self.store else {
            return Vec::new();
        };
        let queued = account.db().queued_updates(now_ms() - RESEND_MS).unwrap_or_default();
        let mut envelopes = Vec::new();
        for queued in queued {
            let Some(outgoing) = self.outgoing_update(queued.group, &queued.recipients) else {
                continue;
            };
            // Queued before a newer epoch came: that one goes instead.
            if group::Update::read(&outgoing.update).map(|u| u.epoch) != Ok(queued.epoch) {
                continue;
            }
            envelopes.extend(update_envelopes(
                &outgoing.group_id,
                &outgoing.update,
                &outgoing.keys,
                now_secs,
            ));
            for contact in outgoing.added {
                envelopes.extend(self.contact_envelope(contact, &outgoing.record, expiry(now_secs), now_secs));
            }
        }
        envelopes
    }

    // Receiving.

    /// An update part this device recognised by its tag, for group `group_id`.
    pub(super) fn take_update_part(&mut self, group_id: &GroupId, envelope: &Envelope) -> Vec<Action> {
        let Ok(part) = UpdatePart::read(envelope) else {
            return Vec::new();
        };
        if mesh::update_part_id(group_id, &part.update_id, part.index) != envelope.id {
            return Vec::new();
        }
        let Some(keys) = self.keys.groups.get(group_id).and_then(|g| g.next_update.as_ref()) else {
            return Vec::new();
        };
        let Ok(key) = mesh::update_part_key(&keys.base, &part.update_id) else {
            return Vec::new();
        };
        self.gather(key, envelope)
    }

    /// Whether `id` is a part of an update this device was given the key of: taken whatever its
    /// tag, and even if seen before.
    pub(super) fn expects_update_part(&self, id: &EnvelopeId) -> bool {
        self.mesh_updates.expected.contains_key(id)
    }

    pub(super) fn take_expected_update_part(&mut self, envelope: &Envelope) -> Vec<Action> {
        let Some(update_id) = self.mesh_updates.expected.get(&envelope.id).copied() else {
            return Vec::new();
        };
        let Some(key) = self.mesh_updates.gathering(&update_id).map(|g| g.key.clone()) else {
            return Vec::new();
        };
        self.gather(key, envelope)
    }

    /// Opens an update part; once all are in, the update is taken in as one from a link.
    fn gather(&mut self, key: SecretBytes<32>, envelope: &Envelope) -> Vec<Action> {
        let Ok((part, bytes)) = mesh::open_update_part(&key, envelope) else {
            return Vec::new();
        };
        let updates = &mut self.mesh_updates;
        if updates.taken.contains(&part.update_id) {
            return Vec::new();
        }
        if updates.gathering(&part.update_id).is_none() {
            updates.start(part.update_id, key, part.count);
        }
        let Some(gathering) = updates.gathering(&part.update_id) else {
            return Vec::new();
        };
        if gathering.parts.len() != usize::from(part.count) {
            return Vec::new();
        }
        gathering.parts[usize::from(part.index)] = Some(bytes);
        if gathering.parts.iter().any(Option::is_none) {
            return Vec::new();
        }
        let update: Vec<u8> = gathering.parts.iter().flatten().flatten().copied().collect();
        if group::update_id(&update) != part.update_id {
            // Not what its id says: start over.
            updates.gathering.retain(|g| g.update_id != part.update_id);
            return Vec::new();
        }
        updates.done(part.update_id);
        match &self.store {
            Store::Open(_) => self.take_update(FROM_MESH, update),
            Store::Provider => Vec::new(),
            Store::Sealed(sealed) => {
                let _ = sealed.inbox.append(&InboxEvent::GroupUpdate {
                    contact: FROM_MESH,
                    update,
                });
                Vec::new()
            }
        }
    }

    /// A *mesh update key* from a contact (§10.9): the parts of that update are taken by their ids,
    /// those already held to pass on at once.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn take_mesh_update_key(
        &mut self,
        contact: ContactId,
        group_id: GroupId,
        epoch: u64,
        update_id: [u8; 16],
        count: u16,
        key: &[u8; 32],
    ) -> Vec<Action> {
        let held_already = self.keys.groups.get(&group_id).is_some_and(|g| g.epoch >= epoch);
        let updates = &self.mesh_updates;
        let known = updates.taken.contains(&update_id) || updates.gathering.iter().any(|g| g.update_id == update_id);
        let Ok(key) = SecretBytes::from_slice(key) else {
            return Vec::new();
        };
        if !self.is_contact(contact) || held_already || known {
            return Vec::new();
        }
        self.mesh_updates.start(update_id, key, count);
        let ids: Vec<EnvelopeId> = (0..count)
            .map(|index| mesh::update_part_id(&group_id, &update_id, index))
            .collect();
        for id in &ids {
            self.mesh_updates.expected.insert(*id, update_id);
        }
        let held: Vec<Envelope> = ids.iter().filter_map(|id| self.mesh.held_envelope(id)).collect();
        held.iter()
            .flat_map(|envelope| self.take_expected_update_part(envelope))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        account::Account,
        node::{groups::tests::Net, mesh::tests::mesh_link},
    };

    const AYSE: usize = 0;
    const BURAK: usize = 1;
    const CEM: usize = 2;
    const DENIZ: usize = 3;

    /// Ayşe made a group with Burak, who took it in over their link; Cem is her contact too.
    /// Deniz knows none of them. Nobody is linked now.
    fn camp() -> Net {
        let mut net = Net::new(&["Ayşe", "Burak", "Cem", "Deniz"]);
        net.pair(AYSE, BURAK);
        net.pair(AYSE, CEM);
        let burak = net.contact(AYSE, BURAK);
        let (_, actions) = net.node(AYSE).create_group("Kamp", &[burak]).unwrap();
        net.run(AYSE, actions);
        net.link(AYSE, BURAK);
        assert_eq!(net.group(BURAK).epoch, 0);
        net.cut(AYSE, BURAK);
        net
    }

    fn add_cem(net: &mut Net) {
        let (row, cem) = (net.group(AYSE).row, net.contact(AYSE, CEM));
        let (_, actions) = net.node(AYSE).add_group_members(row, &[cem], 0).unwrap();
        net.run(AYSE, actions);
    }

    fn groups(net: &mut Net, at: usize) -> usize {
        net.node(at).groups().unwrap().len()
    }

    #[test]
    fn changing_a_group_keeps_the_links_to_mesh_peers() {
        let mut net = camp();
        mesh_link(&mut net, AYSE, DENIZ);
        add_cem(&mut net);
        assert_eq!(net.node(AYSE).mesh_neighbours(), 1);
    }

    #[test]
    fn a_contact_added_out_of_reach_joins_through_the_mesh() {
        let mut net = camp();
        mesh_link(&mut net, AYSE, DENIZ);
        mesh_link(&mut net, DENIZ, CEM);
        add_cem(&mut net);
        let group = net.group(CEM);
        assert_eq!((group.epoch, group.members), (1, 3), "the update came through Deniz");
        net.say(AYSE, "hoş geldin");
        assert_eq!(net.texts(CEM), ["hoş geldin"]);
        assert_eq!(groups(&mut net, DENIZ), 0, "the relay learned nothing");
    }

    #[test]
    fn a_member_out_of_reach_catches_up_with_what_a_relay_holds() {
        let mut net = camp();
        mesh_link(&mut net, AYSE, DENIZ);
        add_cem(&mut net);
        net.say(AYSE, "Cem geldi");
        // Burak comes by Deniz, who passes on the newest first: the message before the update
        // that lets him read it.
        mesh_link(&mut net, DENIZ, BURAK);
        assert_eq!(net.group(BURAK).epoch, 1);
        assert_eq!(net.texts(BURAK), ["Cem geldi"]);
    }

    #[test]
    fn two_missed_updates_are_taken_in_order_whatever_order_they_come_in() {
        let mut net = camp();
        mesh_link(&mut net, AYSE, DENIZ);
        add_cem(&mut net);
        let (row, cem) = (net.group(AYSE).row, net.identity(CEM));
        let (group, actions) = net.node(AYSE).remove_group_member(row, &cem).unwrap();
        net.run(AYSE, actions);
        assert_eq!(group.epoch, 2);
        // The second update's parts come first; Burak cannot recognise them until he has the first.
        mesh_link(&mut net, DENIZ, BURAK);
        let group = net.group(BURAK);
        assert_eq!((group.epoch, group.members), (2, 2));
    }

    #[test]
    fn a_member_out_of_reach_learns_of_its_removal_through_the_mesh() {
        let mut net = camp();
        mesh_link(&mut net, AYSE, DENIZ);
        mesh_link(&mut net, DENIZ, BURAK);
        let (row, burak) = (net.group(AYSE).row, net.identity(BURAK));
        add_cem(&mut net);
        let (_, actions) = net.node(AYSE).remove_group_member(row, &burak).unwrap();
        net.run(AYSE, actions);
        assert_eq!(net.group(BURAK).membership, Membership::Removed);
        net.say(AYSE, "Burak'sız");
        assert!(!net.texts(BURAK).contains(&"Burak'sız".to_owned()));
    }

    #[test]
    fn a_locked_member_takes_the_update_in_after_unlocking() {
        let mut net = camp();
        mesh_link(&mut net, AYSE, DENIZ);
        mesh_link(&mut net, DENIZ, BURAK);
        net.node(BURAK).seal();
        add_cem(&mut net);
        let device = &mut net.devices[BURAK];
        let account = Account::unlock_with_pin(device.dir.path(), &device.pin_record, b"123456").unwrap();
        let actions = device.node.unseal(account).unwrap();
        net.run(BURAK, actions);
        let group = net.group(BURAK);
        assert_eq!((group.epoch, group.members), (1, 3));
    }

    #[test]
    fn copies_are_the_same_from_every_member_and_only_contacts_hand_out_keys() {
        let mut net = camp();
        mesh_link(&mut net, AYSE, DENIZ);
        mesh_link(&mut net, DENIZ, BURAK);
        add_cem(&mut net);
        let now = now_secs();
        let copies = |net: &mut Net, at: usize| {
            let row = net.group(at).row;
            let outgoing = net.node(at).outgoing_update(row, &[]).unwrap();
            update_envelopes(&outgoing.group_id, &outgoing.update, &outgoing.keys, now)
        };
        assert_eq!(copies(&mut net, AYSE), copies(&mut net, BURAK));
        // A key from someone who is no contact is not taken.
        let group_id = net.group(BURAK).group_id;
        let stranger = crate::node::mesh::MESH_PEER_BASE;
        assert!(
            net.node(CEM)
                .take_mesh_update_key(stranger, group_id, 9, [1; 16], 1, &[2; 32])
                .is_empty()
        );
        assert!(net.node(CEM).mesh_updates.gathering.is_empty());
    }
}
