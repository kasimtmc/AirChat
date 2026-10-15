//! One-time prekeys in the node (rust/airchat-protocol/docs/protocol.md §10.7): asking contacts for theirs and handing
//! out this device's own over links, sealing texts in envelopes to the contact's, and opening
//! envelopes with this device's own, whose private halves go as soon as they were used.
//!
//! What is needed to seal and open is kept in memory, loaded at unlock, so envelopes work while
//! locked too; storage follows while unlocked, and catches up at the next unlock.

use std::collections::{HashMap, VecDeque};

use super::{Node, Store, mesh_files::content_through_mesh, now_ms};
use crate::{
    account::Account,
    chat::{self, ChatMessage, MAX_PREKEYS_PER_RECORD, MAX_PREKEYS_WANTED},
    crypto::{
        SecretBytes,
        kem::{DecapsulationKey, EncapsulationKey},
        random,
    },
    inbox::InboxEvent,
    mesh::{self, EnvelopeId, STATIC_KEY},
    storage::{AttachmentState, ContactId, MessageId, prekeys::MAX_THEIRS},
};

/// How many of a contact's unused prekeys a device would hold.
pub(super) const TARGET: usize = MAX_PREKEYS_WANTED as usize;
/// A device hands one contact at most this many prekeys it has not seen used.
const MAX_OWN: usize = 64;
const DAY_MS: i64 = 24 * 3600 * 1000;
/// Own prekeys are deleted after this long, contacts' unused ones forgotten after this long, and
/// those used for a message after this long (a text's envelopes expire within a day).
const OWN_LIFETIME_MS: i64 = 30 * DAY_MS;
const THEIRS_LIFETIME_MS: i64 = 25 * DAY_MS;
const USED_LIFETIME_MS: i64 = 2 * DAY_MS;

#[derive(Default)]
pub(crate) struct Prekeys {
    /// The private halves of the prekeys handed to each contact and not used yet.
    own: HashMap<(ContactId, u32), DecapsulationKey>,
    /// Each contact's unused prekeys, oldest first.
    theirs: HashMap<ContactId, VecDeque<(u32, EncapsulationKey)>>,
    /// The prekey each text went out sealed to, for its resends.
    bound: HashMap<(ContactId, MessageId), (u32, EncapsulationKey)>,
}

impl Prekeys {
    /// Loads what storage holds, dropping what is too old.
    pub(super) fn reload(&mut self, account: &Account) {
        let now = now_ms();
        let db = account.db();
        self.own.clear();
        for prekey in db.own_prekeys(now - OWN_LIFETIME_MS).unwrap_or_default() {
            let Ok(seed) = SecretBytes::from_slice(&prekey.seed[..]) else {
                continue;
            };
            if let Ok(key) = DecapsulationKey::from_seed(seed) {
                self.own.insert((prekey.contact, prekey.prekey), key);
            }
        }
        self.theirs.clear();
        self.bound.clear();
        let theirs = db
            .their_prekeys(now - THEIRS_LIFETIME_MS, now - USED_LIFETIME_MS)
            .unwrap_or_default();
        for prekey in theirs {
            match prekey.message_id {
                Some(message) => {
                    self.bound
                        .insert((prekey.contact, message), (prekey.prekey, prekey.key));
                }
                None => self
                    .theirs
                    .entry(prekey.contact)
                    .or_default()
                    .push_back((prekey.prekey, prekey.key)),
            }
        }
    }

    /// Writes what changed in memory while locked (prekeys taken in, prekeys taken for texts),
    /// before storage is read again at unlock.
    pub(super) fn save(&self, account: &Account) {
        let db = account.db();
        let now = now_ms();
        for (contact, theirs) in &self.theirs {
            let theirs: Vec<(u32, EncapsulationKey)> = theirs.iter().cloned().collect();
            let _ = db.add_their_prekeys(*contact, &theirs, now);
        }
        for ((contact, message), prekey) in &self.bound {
            let _ = db.add_their_prekeys(*contact, std::slice::from_ref(prekey), now);
            let _ = db.bind_their_prekey(*contact, prekey.0, message);
        }
    }

    fn unused(&self, contact: ContactId) -> usize {
        self.theirs.get(&contact).map_or(0, VecDeque::len)
    }

    fn own_count(&self, contact: ContactId) -> usize {
        self.own.keys().filter(|(c, _)| *c == contact).count()
    }

    pub(super) fn own_key(&self, contact: ContactId, prekey: u32) -> Option<&DecapsulationKey> {
        self.own.get(&(contact, prekey))
    }
}

impl Node {
    /// A link that carries data came up with a contact: ask for prekeys if few are left.
    pub(super) fn prekeys_wanted(&self, contact: ContactId) -> Option<ChatMessage> {
        if !self.is_contact(contact) {
            return None;
        }
        let missing = TARGET.saturating_sub(self.prekeys.unused(contact));
        (missing > 0).then(|| ChatMessage::PrekeysWanted(u8::try_from(missing).unwrap_or(MAX_PREKEYS_WANTED)))
    }

    /// The contact wants `count` more prekeys: new ones, stored before they go, in as many records
    /// as it takes (only while unlocked; the next link asks again).
    pub(super) fn hand_out_prekeys(&mut self, contact: ContactId, count: u8) -> Vec<ChatMessage> {
        if !self.is_contact(contact) {
            return Vec::new();
        }
        let Store::Open(account) = &self.store else {
            return Vec::new();
        };
        let room = MAX_OWN.saturating_sub(self.prekeys.own_count(contact));
        let count = usize::from(count.min(MAX_PREKEYS_WANTED)).min(room);
        let now = now_ms();
        let mut handed = Vec::new();
        while handed.len() < count {
            let (Ok(id), Ok(key)) = (random::array::<4>(), DecapsulationKey::generate()) else {
                break;
            };
            let id = u32::from_be_bytes(id);
            if id == STATIC_KEY || self.prekeys.own.contains_key(&(contact, id)) {
                continue;
            }
            match account.db().add_own_prekey(contact, id, key.seed().expose(), now) {
                Ok(true) => {}
                Ok(false) => continue,
                Err(_) => break,
            }
            handed.push((id, key.encapsulation_key().clone()));
            self.prekeys.own.insert((contact, id), key);
        }
        handed
            .chunks(MAX_PREKEYS_PER_RECORD)
            .map(|chunk| ChatMessage::Prekeys(chunk.to_vec()))
            .collect()
    }

    /// Prekeys the contact handed over.
    pub(super) fn take_prekeys(&mut self, contact: ContactId, prekeys: Vec<(u32, EncapsulationKey)>) {
        if !self.is_contact(contact) {
            return;
        }
        if let Store::Open(account) = &self.store {
            let _ = account.db().add_their_prekeys(contact, &prekeys, now_ms());
        }
        let theirs = self.prekeys.theirs.entry(contact).or_default();
        for prekey in prekeys {
            if !theirs.iter().any(|(id, _)| *id == prekey.0) {
                theirs.push_back(prekey);
            }
        }
        while theirs.len() > MAX_THEIRS {
            theirs.pop_front();
        }
    }

    /// The prekey of the contact's a text is sealed to: the one it went out with before, else the
    /// oldest unused one; `None` if none is left (then it is sealed to the static key).
    pub(super) fn prekey_for(&mut self, contact: ContactId, message: &MessageId) -> Option<(u32, EncapsulationKey)> {
        if let Some(bound) = self.prekeys.bound.get(&(contact, *message)) {
            return Some(bound.clone());
        }
        let prekey = self.prekeys.theirs.get_mut(&contact)?.pop_front()?;
        if let Store::Open(account) = &self.store {
            let _ = account.db().bind_their_prekey(contact, prekey.0, message);
        }
        self.prekeys.bound.insert((contact, *message), prekey.clone());
        Some(prekey)
    }

    /// The contact answered a text: the prekey it was sealed to is done with.
    pub(super) fn release_prekey(&mut self, contact: ContactId, message: &MessageId) {
        if self.prekeys.bound.remove(&(contact, *message)).is_some()
            && let Store::Open(account) = &self.store
        {
            let _ = account.db().release_their_prekey(contact, message);
        }
    }

    /// A prekey of this device's opened a text, which is taken care of (stored, or refused): its
    /// private half goes, from memory now and from storage now or at unlock.
    pub(super) fn prekey_used(&mut self, contact: ContactId, prekey: u32) {
        if prekey == STATIC_KEY {
            return;
        }
        // Dropping the key wipes it.
        self.prekeys.own.remove(&(contact, prekey));
        match &self.store {
            Store::Open(account) => {
                let _ = account.db().delete_own_prekey(contact, prekey);
            }
            Store::Sealed(sealed) => {
                let _ = sealed.inbox.append(&InboxEvent::PrekeyUsed { contact, prekey });
            }
        }
    }

    /// The text or file from `contact` that went in envelope `envelope`, if this device received
    /// it within the last day and it is due an acknowledgement: a resend sealed to a prekey that is
    /// gone is answered all the same.
    pub(super) fn received_in(&self, contact: ContactId, envelope: &EnvelopeId) -> Option<MessageId> {
        let them = &self.keys.contacts.get(&contact)?.identity;
        let me = &self.keys.identity;
        let sent_in = |message: &MessageId, kind| mesh::contact_envelope_id(them, me, kind, message) == *envelope;
        match &self.store {
            Store::Open(account) => {
                let since = now_ms() - DAY_MS;
                account
                    .db()
                    .messages(contact)
                    .ok()?
                    .into_iter()
                    .filter(|m| !m.outgoing && m.stored_at_ms >= since)
                    .find(|m| match &m.attachment {
                        None => sent_in(&m.message_id, chat::KIND_TEXT),
                        // A file once it is whole, or if its content does not come through the mesh.
                        Some(file) => {
                            sent_in(&m.message_id, chat::KIND_MESH_FILE_OFFER)
                                && (file.state == AttachmentState::Complete || !content_through_mesh(file.size))
                        }
                    })
                    .map(|m| m.message_id)
            }
            // Files are answered after the unlock.
            Store::Sealed(sealed) => sealed
                .stored
                .iter()
                .filter(|(c, _)| *c == contact)
                .map(|(_, message)| *message)
                .find(|message| sent_in(message, chat::KIND_TEXT)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        account::Account,
        node::{
            Action,
            groups::tests::Net,
            mesh::tests::{cut_mesh, mesh_link, statuses},
        },
        storage::MessageStatus,
    };

    const AYSE: usize = 0;
    const BURAK: usize = 1;
    const CEM: usize = 2;

    /// Ayşe and Cem met over Wi-Fi once (and handed each other prekeys); now Burak, a stranger,
    /// is all that is between them.
    fn met_then_apart() -> Net {
        let mut net = Net::new(&["Ayşe", "Burak", "Cem"]);
        net.pair(AYSE, CEM);
        net.link(AYSE, CEM);
        net.cut(AYSE, CEM);
        mesh_link(&mut net, AYSE, BURAK);
        mesh_link(&mut net, BURAK, CEM);
        net
    }

    /// The envelope Burak holds with Ayşe's text in it.
    fn held_text(net: &mut Net) -> mesh::Envelope {
        net.node(BURAK).mesh.held_envelopes().into_iter().next().expect("held")
    }

    #[test]
    fn contacts_hand_each_other_prekeys_when_they_meet() {
        let mut net = Net::new(&["Ayşe", "Burak"]);
        net.pair(AYSE, BURAK);
        net.link(AYSE, BURAK);
        let burak = net.contact(AYSE, BURAK);
        let ayse = net.contact(BURAK, AYSE);
        assert_eq!(net.node(AYSE).prekeys.unused(burak), TARGET);
        assert_eq!(net.node(BURAK).prekeys.unused(ayse), TARGET);
        assert_eq!(net.node(AYSE).prekeys.own_count(burak), TARGET);
        // Stored too: they are there after the app starts again.
        let stored = net
            .node(AYSE)
            .account()
            .unwrap()
            .db()
            .unused_their_prekeys(burak)
            .unwrap();
        assert_eq!(stored, TARGET);
        // Meeting again asks for nothing more.
        net.cut(AYSE, BURAK);
        net.link(AYSE, BURAK);
        assert_eq!(net.node(AYSE).prekeys.own_count(burak), TARGET);
    }

    #[test]
    fn a_text_through_the_mesh_is_sealed_to_a_prekey_that_is_gone_once_opened() {
        let mut net = met_then_apart();
        let cem = net.contact(AYSE, CEM);
        let ayse = net.contact(CEM, AYSE);
        let (_, actions) = net.node(AYSE).send_message(cem, "ileri gizli").unwrap();
        net.run(AYSE, actions);
        assert_eq!(
            statuses(&net, CEM, AYSE),
            [("ileri gizli".into(), MessageStatus::Received)]
        );
        assert_eq!(statuses(&net, AYSE, CEM)[0].1, MessageStatus::Delivered);
        assert_eq!(net.node(AYSE).prekeys.unused(cem), TARGET - 1, "one used");
        assert!(net.node(AYSE).prekeys.bound.is_empty(), "and let go once answered");
        assert_eq!(
            net.node(CEM).prekeys.own_count(ayse),
            TARGET - 1,
            "Cem's private half is gone"
        );
        let stored = net.node(CEM).account().unwrap().db().own_prekeys(0).unwrap();
        assert_eq!(stored.len(), TARGET - 1, "from storage too");
    }

    #[test]
    fn a_resend_whose_prekey_is_gone_is_still_acknowledged() {
        let mut net = met_then_apart();
        let cem = net.contact(AYSE, CEM);
        // Cem is away while Ayşe writes; Burak holds the envelope.
        cut_mesh(&mut net, BURAK, CEM);
        let (_, actions) = net.node(AYSE).send_message(cem, "tekrar").unwrap();
        net.run(AYSE, actions);
        let envelope = held_text(&mut net);
        assert_ne!(mesh::sealed_to(&envelope).unwrap(), mesh::STATIC_KEY);
        mesh_link(&mut net, BURAK, CEM);
        assert_eq!(statuses(&net, AYSE, CEM)[0].1, MessageStatus::Delivered);
        let prekey = mesh::sealed_to(&envelope).unwrap();
        let ayse = net.contact(CEM, AYSE);
        assert!(net.node(CEM).prekeys.own_key(ayse, prekey).is_none(), "gone");
        // A resend of it, after Cem's app started again and forgot the envelopes it saw, cannot be
        // opened any more; but Cem knows the text it carried, and answers it.
        let message = net.devices[CEM].node.messages(ayse).unwrap()[0].message_id;
        assert_eq!(net.node(CEM).received_in(ayse, &envelope.id), Some(message));
        assert_eq!(net.node(CEM).received_in(ayse, &[0; 16]), None);
    }

    #[test]
    fn a_locked_recipient_opens_with_a_prekey_and_storage_forgets_it_at_unlock() {
        let mut net = met_then_apart();
        let cem = net.contact(AYSE, CEM);
        let ayse = net.contact(CEM, AYSE);
        net.node(CEM).seal();
        let (_, actions) = net.node(AYSE).send_message(cem, "kilitliyken").unwrap();
        net.run(AYSE, actions);
        assert!(
            net.devices[CEM]
                .shown
                .iter()
                .any(|a| matches!(a, Action::MessageArrived { .. }))
        );
        assert_eq!(
            net.node(CEM).prekeys.own_count(ayse),
            TARGET - 1,
            "gone from memory at once"
        );
        let device = &mut net.devices[CEM];
        let account = Account::unlock_with_pin(device.dir.path(), &device.pin_record, b"123456").unwrap();
        device.node.unseal(account).unwrap();
        let stored = net.node(CEM).account().unwrap().db().own_prekeys(0).unwrap();
        assert_eq!(stored.len(), TARGET - 1, "and from storage at unlock");
        assert_eq!(net.node(CEM).prekeys.own_count(ayse), TARGET - 1);
    }

    #[test]
    fn without_prekeys_texts_are_sealed_to_the_static_key() {
        let mut net = Net::new(&["Ayşe", "Burak", "Cem"]);
        net.pair(AYSE, CEM);
        mesh_link(&mut net, AYSE, BURAK);
        let cem = net.contact(AYSE, CEM);
        let (_, actions) = net.node(AYSE).send_message(cem, "hiç karşılaşmadık").unwrap();
        net.run(AYSE, actions);
        assert_eq!(mesh::sealed_to(&held_text(&mut net)).unwrap(), mesh::STATIC_KEY);
        mesh_link(&mut net, BURAK, CEM);
        assert_eq!(statuses(&net, CEM, AYSE)[0].1, MessageStatus::Received);
    }
}
