//! Presence key versions in the node (rust/airchat-protocol/docs/protocol.md §5.4): when the user deletes or blocks a
//! contact, this device makes a new presence key, so that the one gone no longer recognises its
//! beacons, and tells the remaining contacts over their links. A contact that does not hold the
//! new key cannot see the device, so the device opens the link to it itself.

use zeroize::Zeroizing;

use super::{Action, ConnectionId, Node, Store, channels::is_channel_peer, mesh::is_mesh_peer};
use crate::{chat::ChatMessage, crypto::SecretBytes, storage::ContactId};

impl Node {
    /// The record that tells `contact` of this device's presence key, if it does not hold it.
    pub(super) fn presence_key_for(&self, contact: ContactId) -> Option<ChatMessage> {
        let keys = self.keys.contacts.get(&contact).filter(|k| !k.group_only)?;
        (keys.presence_key_taken < self.keys.presence_version).then(|| ChatMessage::PresenceKey {
            version: self.keys.presence_version,
            key: Zeroizing::new(*self.keys.presence_key.expose()),
        })
    }

    /// `contact` told of its newer presence key: from now on its beacons are recognised by it.
    /// Acknowledged once stored (while locked it is told again later).
    pub(super) fn take_presence_key(
        &mut self,
        contact: ContactId,
        version: u32,
        key: &[u8; 32],
    ) -> Option<ChatMessage> {
        self.keys.contacts.get(&contact).filter(|k| !k.group_only)?;
        let Store::Open(account) = &self.store else {
            return None;
        };
        let key = SecretBytes::from_slice(key).ok()?;
        if account.db().set_their_presence_key(contact, &key, version).ok()? {
            self.keys.contacts.get_mut(&contact)?.presence_key = key;
            self.directory = None;
        }
        Some(ChatMessage::PresenceKeyTaken(version))
    }

    /// `contact` took this device's presence key of `version`: it recognises the device again.
    pub(super) fn presence_key_taken(&mut self, contact: ContactId, version: u32) {
        if version > self.keys.presence_version {
            return;
        }
        let Store::Open(account) = &self.store else {
            return;
        };
        if account.db().set_presence_key_taken(contact, version).is_ok()
            && let Some(keys) = self.keys.contacts.get_mut(&contact)
        {
            keys.presence_key_taken = keys.presence_key_taken.max(version);
        }
    }

    /// A new presence key, after a contact was deleted or blocked; told to every contact linked.
    pub(super) fn rotate_presence_key(&mut self) -> Vec<Action> {
        let Store::Open(account) = &mut self.store else {
            return Vec::new();
        };
        if account.rotate_presence_key().is_err() {
            return Vec::new();
        }
        self.refresh_contacts();
        let links: Vec<(ContactId, ConnectionId)> = self
            .links
            .iter()
            .filter(|(contact, _)| !is_mesh_peer(**contact) && !is_channel_peer(**contact))
            .map(|(contact, connection)| (*contact, *connection))
            .collect();
        let mut actions = Vec::new();
        for (contact, connection) in links {
            if let Some(record) = self.presence_key_for(contact) {
                actions.extend(self.seal_on(connection, vec![record], false));
            }
        }
        actions
    }
}

#[cfg(test)]
mod tests {
    use crate::node::groups::tests::Net;

    const AYSE: usize = 0;
    const BURAK: usize = 1;
    const CEM: usize = 2;

    /// Whether `at` recognises the beacon `of` announces now.
    fn sees(net: &mut Net, at: usize, of: usize) -> bool {
        let now = net.now;
        let token = net.node(of).presence_token(now);
        net.node(at).recognize_presence(&token, now).is_some()
    }

    #[test]
    fn a_deleted_contact_no_longer_recognises_the_device() {
        let mut net = Net::new(&["Ayşe", "Burak", "Cem"]);
        net.pair(AYSE, BURAK);
        net.pair(AYSE, CEM);
        net.link(AYSE, BURAK);
        assert!(sees(&mut net, CEM, AYSE));
        let cem = net.contact(AYSE, CEM);
        let actions = net.node(AYSE).delete_contact(cem, false).unwrap();
        net.run(AYSE, actions);
        assert!(!sees(&mut net, CEM, AYSE), "Cem knew the old key only");
        assert!(sees(&mut net, BURAK, AYSE), "Burak was told the new one over the link");
    }

    #[test]
    fn a_contact_away_during_the_change_gets_the_new_key_when_they_meet() {
        let mut net = Net::new(&["Ayşe", "Burak", "Cem"]);
        net.pair(AYSE, BURAK);
        net.pair(AYSE, CEM);
        let cem = net.contact(AYSE, CEM);
        let actions = net.node(AYSE).block_contact(cem).unwrap();
        net.run(AYSE, actions);
        // Burak cannot see Ayşe now; she sees him, and opens the link whatever the rule says.
        assert!(!sees(&mut net, BURAK, AYSE));
        let now = net.now;
        let token = net.node(BURAK).presence_token(now);
        let seen = net.node(AYSE).recognize_presence(&token, now).unwrap();
        assert!(seen.initiate());
        let burak = net.contact(AYSE, BURAK);
        let (id, _) = net.wire(AYSE, BURAK);
        let first = net.node(AYSE).connect_contact(id, burak, now).unwrap();
        net.run(AYSE, first);
        assert!(net.node(AYSE).is_linked(burak));
        assert!(sees(&mut net, BURAK, AYSE));
        let version = net.devices[AYSE].node.keys.presence_version;
        assert_eq!(net.devices[AYSE].node.keys.contacts[&burak].presence_key_taken, version);
    }

    #[test]
    fn groups_get_the_new_presence_key() {
        let mut net = Net::new(&["Ayşe", "Burak", "Cem"]);
        net.pair(AYSE, BURAK);
        net.pair(AYSE, CEM);
        let burak = net.contact(AYSE, BURAK);
        let (group, actions) = net.node(AYSE).create_group("Kamp", &[burak]).unwrap();
        net.run(AYSE, actions);
        net.link(AYSE, BURAK);
        let cem = net.contact(AYSE, CEM);
        let actions = net.node(AYSE).delete_contact(cem, true).unwrap();
        net.run(AYSE, actions);
        let now = net.now;
        let actions = net.node(AYSE).static_keys_tick(now);
        net.run(AYSE, actions);
        let ayse = net.identity(AYSE);
        let presence = net.node(AYSE).account().unwrap().presence_key().clone();
        let db = net.node(BURAK).account().unwrap().db();
        let stored = db.group_by_id(&group.group_id).unwrap().unwrap();
        assert_eq!(stored.epoch, 1, "a new epoch");
        assert_eq!(
            stored.roster.member(&ayse).unwrap().presence_key.expose(),
            presence.expose()
        );
    }
}
