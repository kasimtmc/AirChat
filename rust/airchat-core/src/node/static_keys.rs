//! Static key versions in the node (rust/airchat-protocol/docs/protocol.md §6.9): every week this device makes a new
//! static key and tells its contacts of it, signed, over their links; it keeps the earlier ones
//! while someone may still use them; and the admin that keeps a group's keys starts a new epoch
//! once the roster lists an older key of someone's, so that what was sealed to a copied key stops
//! reaching whoever copied it. Fellow members who are not contacts learn keys from rosters only.

use super::{Action, ConnectionId, Node, NodeError, Store, channels::is_channel_peer, mesh::is_mesh_peer, now_ms};
use crate::{
    chat::ChatMessage,
    crypto::{kem::EncapsulationKey, sign::SIGNATURE_LEN},
    group::{Member, Role, Roster},
    storage::ContactId,
};

/// How long a static key stays the newest.
pub(super) const ROTATE_MS: i64 = 7 * 24 * 3600 * 1000;
/// Earlier keys stay at least this long after a new one is made: envelopes sealed to them may still
/// be on their way (§10.3).
const KEEP_EARLIER_MS: i64 = 25 * 3600 * 1000;
/// Static keys kept at most: past that, no new one is made until contacts have taken the newest.
const MAX_KEPT: usize = 8;
/// How many of a contact's static keys a device links with: the newest and two earlier ones.
pub(super) const THEIRS_KEPT: usize = 3;
/// How often the node looks for keys to make, forget or hand to groups.
const CHECK_EVERY_SECS: u64 = 60;

impl Node {
    /// The record that tells `contact` of this device's newest static key, if it has not taken it.
    pub(super) fn static_key_for(&self, contact: ContactId) -> Option<ChatMessage> {
        let keys = self.keys.contacts.get(&contact).filter(|k| !k.group_only)?;
        (keys.own_key_taken < self.keys.own_version()).then(|| self.keys.announcement.clone())
    }

    /// `contact` told of its newest static key: taken if it vouched for it and it is newer than the
    /// one known, and acknowledged once stored (while locked it is told again later). Only over a
    /// contact's link: a group link may be someone who copied the member's keys before the group
    /// moved on, and a key it slipped into the next roster would let it in again.
    pub(super) fn take_static_key(
        &mut self,
        contact: ContactId,
        version: u32,
        key: EncapsulationKey,
        signature: &[u8; SIGNATURE_LEN],
    ) -> Option<ChatMessage> {
        let keys = self.keys.contacts.get(&contact).filter(|k| !k.group_only)?;
        if !keys.identity.vouches_for(version, &key, signature) {
            return None;
        }
        let Store::Open(account) = &self.store else {
            return None;
        };
        let newer = account.db().set_their_static_key(contact, &key, version).ok()?;
        let keys = self.keys.contacts.get_mut(&contact)?;
        if newer && keys.static_kems.first() != Some(&key) {
            keys.static_kems.insert(0, key);
            keys.static_kems.truncate(THEIRS_KEPT);
        }
        Some(ChatMessage::StaticKeyTaken(version))
    }

    /// `contact` took this device's static key of `version`: it links with that one or a newer one
    /// from now on.
    pub(super) fn static_key_taken(&mut self, contact: ContactId, version: u32) {
        if version > self.keys.own_version() {
            return;
        }
        let Store::Open(account) = &self.store else {
            return;
        };
        if account.db().set_own_key_taken(contact, version).is_ok()
            && let Some(keys) = self.keys.contacts.get_mut(&contact)
        {
            keys.own_key_taken = keys.own_key_taken.max(version);
        }
    }

    /// Makes a new static key now and tells every contact linked.
    pub fn rotate_static_key(&mut self) -> Result<Vec<Action>, NodeError> {
        let Store::Open(account) = &mut self.store else {
            return Err(NodeError::Sealed);
        };
        account.rotate_static_key()?;
        self.refresh_contacts();
        let links: Vec<(ContactId, ConnectionId)> = self
            .links
            .iter()
            .filter(|(contact, _)| !is_mesh_peer(**contact) && !is_channel_peer(**contact))
            .map(|(contact, connection)| (*contact, *connection))
            .collect();
        let mut actions = Vec::new();
        for (contact, connection) in links {
            if let Some(record) = self.static_key_for(contact) {
                actions.extend(self.seal_on(connection, vec![record], false));
            }
        }
        Ok(actions)
    }

    /// While unlocked, now and then: a new static key once the newest is a week old, earlier ones
    /// nobody needs forgotten, and groups given the newest keys of their members.
    pub(super) fn static_keys_tick(&mut self, now_secs: u64) -> Vec<Action> {
        let Store::Open(account) = &self.store else {
            return Vec::new();
        };
        if self
            .static_keys_checked
            .is_some_and(|at| now_secs.saturating_sub(at) < CHECK_EVERY_SECS)
        {
            return Vec::new();
        }
        self.static_keys_checked = Some(now_secs);
        let mut actions = Vec::new();
        let due = now_ms().saturating_sub(account.static_created_ms()) >= ROTATE_MS;
        if due && account.static_keys().count() < MAX_KEPT {
            actions.extend(self.rotate_static_key().unwrap_or_default());
        }
        self.forget_unused_static_keys();
        actions.extend(self.rekey_groups());
        actions
    }

    /// Forgets this device's earlier static keys that no contact may still link with or seal to,
    /// and that no roster held lists for it; never within a day of the newest one's making.
    fn forget_unused_static_keys(&mut self) {
        let Store::Open(account) = &mut self.store else {
            return;
        };
        if now_ms().saturating_sub(account.static_created_ms()) < KEEP_EARLIER_MS {
            return;
        }
        let me = account.identity().public();
        let (Ok(oldest), Ok(groups)) = (account.db().oldest_own_key_taken(), account.db().member_groups()) else {
            return;
        };
        let oldest = oldest.unwrap_or(u32::MAX);
        let listed: Vec<u32> = groups
            .iter()
            .flat_map(|g| std::iter::once(&g.roster).chain(g.previous.iter().map(|(_, roster)| roster)))
            .filter_map(|roster| roster.member(&me).map(|m| m.key_version))
            .collect();
        let before = account.static_keys().count();
        if account
            .forget_static_keys(|version| version >= oldest || listed.contains(&version))
            .is_ok()
            && account.static_keys().count() < before
        {
            self.refresh_contacts();
        }
    }

    /// `members` with the newest keys known of each: this device's own static and presence keys,
    /// a contact's or peer's static key from its row when newer than the one the roster lists, and
    /// a contact's presence key if it told this device of one since pairing (§5.4).
    pub(super) fn freshened(&self, members: &[Member]) -> Result<Vec<Member>, NodeError> {
        let account = self.account()?;
        let me = account.identity().public();
        let db = account.db();
        members
            .iter()
            .map(|member| {
                let mut member = member.clone();
                if member.identity == me {
                    member.static_kem = account.link_keys().static_kem.encapsulation_key().clone();
                    member.key_version = account.static_version();
                    member.presence_key = account.presence_key().clone();
                    return Ok(member);
                }
                let Some(row) = db.contact_by_identity(&member.identity)? else {
                    return Ok(member);
                };
                if let Some((key, version)) = db.their_static_key(row.id)?
                    && version > member.key_version
                {
                    member.static_kem = key;
                    member.key_version = version;
                }
                if let Some(presence) = db.told_presence_key(row.id)? {
                    member.presence_key = presence;
                }
                Ok(member)
            })
            .collect()
    }

    /// Starts a new epoch, with the same members and their newest keys, in each group whose keys
    /// this device keeps (the admin with the smallest identity key) and whose roster lists an older
    /// static or presence key of someone's.
    fn rekey_groups(&mut self) -> Vec<Action> {
        let Ok(account) = self.account() else {
            return Vec::new();
        };
        let me = account.identity().public();
        let Ok(groups) = account.db().member_groups() else {
            return Vec::new();
        };
        let mut actions = Vec::new();
        for stored in groups {
            let keeper = stored
                .roster
                .members()
                .iter()
                .filter(|m| m.role == Role::Admin)
                .map(|m| m.identity)
                .min_by_key(|identity| *identity.as_bytes());
            if keeper != Some(me) {
                continue;
            }
            let Ok(members) = self.freshened(stored.roster.members()) else {
                continue;
            };
            let same = |fresh: &Member, listed: &Member| {
                fresh.key_version == listed.key_version && fresh.presence_key.expose() == listed.presence_key.expose()
            };
            if members.iter().zip(stored.roster.members()).all(|(f, l)| same(f, l)) {
                continue;
            }
            if let Ok(roster) = Roster::new(stored.group_id, stored.epoch + 1, &stored.name, members)
                && let Ok((_, started)) = self.start_epoch(roster, &[])
            {
                actions.extend(started);
            }
        }
        actions
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        account::Account,
        crypto::kem::DecapsulationKey,
        group::Update,
        node::{ConnectionState, groups::tests::Net},
    };

    const AYSE: usize = 0;
    const BURAK: usize = 1;
    const CEM: usize = 2;

    /// The static key `of` makes links with now.
    fn newest(net: &Net, of: usize) -> EncapsulationKey {
        net.devices[of].node.keys.local().static_kem.encapsulation_key().clone()
    }

    /// The static key `at` knows of `of`.
    fn known(net: &Net, at: usize, of: usize) -> EncapsulationKey {
        net.devices[at].node.keys.contacts[&net.contact(at, of)].static_kems[0].clone()
    }

    fn taken(net: &Net, at: usize, of: usize) -> u32 {
        net.devices[at].node.keys.contacts[&net.contact(at, of)].own_key_taken
    }

    /// Opens a link from `from`, whichever side the rule names.
    fn link_from(net: &mut Net, from: usize, to: usize) {
        let contact = net.contact(from, to);
        let (id, _) = net.wire(from, to);
        let now = net.now;
        let first = net.node(from).connect_contact(id, contact, now).unwrap();
        net.run(from, first);
        assert!(
            matches!(
                net.devices[from].node.connections.get(&id),
                Some(ConnectionState::Linked { .. })
            ),
            "linked"
        );
    }

    fn unlock(net: &mut Net, at: usize) {
        let device = &mut net.devices[at];
        let account = Account::unlock_with_pin(device.dir.path(), &device.pin_record, b"123456").unwrap();
        device.node.unseal(account).unwrap();
    }

    #[test]
    fn contacts_take_a_new_static_key_and_link_with_it_both_ways() {
        let mut net = Net::new(&["Ayşe", "Burak"]);
        net.pair(AYSE, BURAK);
        net.link(AYSE, BURAK);
        let first = newest(&net, AYSE);
        let actions = net.node(AYSE).rotate_static_key().unwrap();
        net.run(AYSE, actions);
        assert_ne!(newest(&net, AYSE), first);
        assert_eq!(known(&net, BURAK, AYSE), newest(&net, AYSE), "told over the link");
        assert_eq!(taken(&net, AYSE, BURAK), 1, "and it said so");
        let burak = net.contact(BURAK, AYSE);
        let stored = net.node(BURAK).account().unwrap().db().contact(burak).unwrap().unwrap();
        assert_eq!(stored.static_kem_version, 1);

        for (from, to) in [(AYSE, BURAK), (BURAK, AYSE)] {
            net.cut(AYSE, BURAK);
            link_from(&mut net, from, to);
        }
    }

    #[test]
    fn a_contact_that_missed_the_new_key_still_links_and_takes_it() {
        let mut net = Net::new(&["Ayşe", "Burak"]);
        net.pair(AYSE, BURAK);
        net.node(AYSE).rotate_static_key().unwrap();
        // Burak links with the key he knows; Ayşe answers with the earlier one, then tells him.
        link_from(&mut net, BURAK, AYSE);
        assert_eq!(known(&net, BURAK, AYSE), newest(&net, AYSE));
        assert_eq!(taken(&net, AYSE, BURAK), 1);
        net.cut(AYSE, BURAK);
        link_from(&mut net, AYSE, BURAK);
    }

    #[test]
    fn earlier_keys_go_once_every_contact_took_a_newer_one() {
        let mut net = Net::new(&["Ayşe", "Burak", "Cem"]);
        net.pair(AYSE, BURAK);
        net.pair(AYSE, CEM);
        net.link(AYSE, BURAK);
        let actions = net.node(AYSE).rotate_static_key().unwrap();
        net.run(AYSE, actions);
        let kept = |net: &mut Net| net.node(AYSE).account().unwrap().static_keys().count();
        net.node(AYSE).forget_unused_static_keys();
        assert_eq!(kept(&mut net), 2, "not within a day of the new one");

        let Store::Open(account) = &mut net.devices[AYSE].node.store else {
            unreachable!()
        };
        account.backdate_static_key(2 * KEEP_EARLIER_MS);
        net.node(AYSE).forget_unused_static_keys();
        assert_eq!(kept(&mut net), 2, "Cem has not taken the new one");

        net.link(AYSE, CEM);
        assert_eq!(taken(&net, AYSE, CEM), 1);
        net.node(AYSE).forget_unused_static_keys();
        assert_eq!(kept(&mut net), 1);
        assert_eq!(net.devices[AYSE].node.keys.locals.len(), 1);
        assert_eq!(net.node(AYSE).account().unwrap().db().static_keys().unwrap().len(), 1);
        net.cut(AYSE, BURAK);
        net.link(AYSE, BURAK);
    }

    #[test]
    fn a_group_gets_fresh_keys_when_a_member_makes_a_new_one() {
        let mut net = Net::new(&["Ayşe", "Burak", "Cem"]);
        net.pair(AYSE, BURAK);
        net.pair(AYSE, CEM);
        let contacts = [net.contact(AYSE, BURAK), net.contact(AYSE, CEM)];
        let (group, actions) = net.node(AYSE).create_group("Kamp", &contacts).unwrap();
        net.run(AYSE, actions);
        net.link(AYSE, BURAK);
        net.link(AYSE, CEM);
        // Someone copies Burak's static key; then Burak makes a new one.
        let copied =
            DecapsulationKey::from_seed(net.devices[BURAK].node.keys.local().static_kem.seed().clone()).unwrap();
        let actions = net.node(BURAK).rotate_static_key().unwrap();
        net.run(BURAK, actions);

        let now = net.now;
        let actions = net.node(AYSE).static_keys_tick(now);
        net.run(AYSE, actions);
        let ayse = net
            .node(AYSE)
            .account()
            .unwrap()
            .db()
            .group(group.row)
            .unwrap()
            .unwrap();
        assert_eq!(ayse.epoch, 1, "a new epoch");
        let burak = net.identity(BURAK);
        assert_eq!(ayse.roster.member(&burak).unwrap().key_version, 1);
        let held = |net: &mut Net, at: usize| {
            let db = net.node(at).account().unwrap().db();
            db.group_by_id(&group.group_id).unwrap().unwrap().epoch
        };
        assert_eq!((held(&mut net, BURAK), held(&mut net, CEM)), (1, 1), "both took it");
        let db = net.node(AYSE).account().unwrap().db();
        let update = db
            .group_update(db.group_update_row(group.row, 1).unwrap().unwrap())
            .unwrap()
            .unwrap();
        let update = Update::read(&update).unwrap();
        assert!(
            update.open(&burak, &copied).is_err(),
            "the copied key opens nothing new"
        );

        // Nothing changed since: no other epoch.
        net.devices[AYSE].node.static_keys_checked = None;
        let now = net.now;
        let actions = net.node(AYSE).static_keys_tick(now);
        net.run(AYSE, actions);
        assert_eq!(held(&mut net, AYSE), 1);
        // Burak and Cem, who are not contacts, link with the new roster's keys.
        net.cut(AYSE, BURAK);
        net.cut(AYSE, CEM);
        net.link(BURAK, CEM);
    }

    #[test]
    fn a_locked_device_takes_a_new_key_after_unlocking() {
        let mut net = Net::new(&["Ayşe", "Burak"]);
        net.pair(AYSE, BURAK);
        net.link(AYSE, BURAK);
        let before = known(&net, BURAK, AYSE);
        let (ayse, burak) = (net.contact(BURAK, AYSE), net.contact(AYSE, BURAK));
        net.devices[BURAK].node.seal();
        let actions = net.node(AYSE).rotate_static_key().unwrap();
        net.run(AYSE, actions);
        let knows = &net.devices[BURAK].node.keys.contacts[&ayse].static_kems[0];
        assert_eq!(knows, &before, "nowhere to store it");
        assert_eq!(net.devices[AYSE].node.keys.contacts[&burak].own_key_taken, 0);

        let burak_link = net.devices[AYSE].node.links[&burak];
        let actions = net.node(AYSE).connection_closed(burak_link);
        net.run(AYSE, actions);
        let ayse_link = net.devices[BURAK].node.links[&ayse];
        let actions = net.node(BURAK).connection_closed(ayse_link);
        net.run(BURAK, actions);
        unlock(&mut net, BURAK);
        net.link(AYSE, BURAK);
        assert_eq!(known(&net, BURAK, AYSE), newest(&net, AYSE));
        assert_eq!(taken(&net, AYSE, BURAK), 1);
    }

    #[test]
    fn keys_come_from_contacts_only_not_over_group_links() {
        let mut net = Net::new(&["Ayşe", "Burak", "Cem"]);
        net.pair(AYSE, BURAK);
        net.pair(AYSE, CEM);
        let contacts = [net.contact(AYSE, BURAK), net.contact(AYSE, CEM)];
        let (_, actions) = net.node(AYSE).create_group("Kamp", &contacts).unwrap();
        net.run(AYSE, actions);
        net.link(AYSE, BURAK);
        net.link(AYSE, CEM);
        net.node(CEM).rotate_static_key().unwrap();
        let signed = net.node(CEM).account().unwrap().signed_static_key();
        let cem = net.contact(BURAK, CEM);
        assert!(net.devices[BURAK].node.keys.contacts[&cem].group_only);
        assert!(
            net.node(BURAK)
                .take_static_key(cem, signed.0, signed.1, &signed.2)
                .is_none()
        );
        assert!(net.node(BURAK).static_key_for(cem).is_none(), "nor told over them");
    }

    #[test]
    fn a_static_key_someone_else_signed_is_not_taken() {
        let mut net = Net::new(&["Ayşe", "Burak", "Cem"]);
        net.pair(AYSE, BURAK);
        let cem = net.node(CEM).account().unwrap().signed_static_key();
        let burak = net.contact(BURAK, AYSE);
        let forged = net.node(BURAK).take_static_key(burak, 9, cem.1, &cem.2);
        assert!(forged.is_none());
        assert_ne!(known(&net, BURAK, AYSE), newest(&net, CEM));
    }
}
