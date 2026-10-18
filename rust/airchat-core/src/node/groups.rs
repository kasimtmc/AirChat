//! Groups in the node (rust/airchat-protocol/docs/protocol.md §9): creating them and changing their members (each change
//! a new epoch), taking in updates and messages, and passing group traffic on to fellow members.

use std::collections::HashMap;

use zeroize::Zeroizing;

use super::{Action, ConnectionId, ConnectionState, Node, NodeError, Store, now_ms, now_secs, seal_chat};
use crate::{
    chat::{ChatMessage, UPDATE_PART_LEN},
    crypto::{SecretBytes, random},
    group::{self, Content, GroupId, Member, Role, Roster, Update},
    identity::PublicIdentity,
    inbox::InboxEvent,
    link::Session,
    storage::{
        ContactId, ContactState, FileMeta, TRY_MS,
        groups::{GroupMessage, GroupMessageStatus, GroupSummary, Membership, Outgoing, StoredGroup},
    },
};

/// Queued group updates and leaves are given up after this long (§9.5); messages after a day
/// ([`TRY_MS`]), as 1:1 messages are.
const OUTBOX_KEEP_MS: i64 = 14 * 24 * 3600 * 1000;
/// Updates and messages kept until what they need (an earlier update) arrives.
const MAX_WAITING: usize = 64;
/// Group updates being reassembled at once on one connection.
const MAX_REASSEMBLIES: usize = 4;

/// One member of a group, as the member list shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMember {
    pub identity: PublicIdentity,
    pub name: String,
    pub admin: bool,
    /// Unix seconds when a temporary membership ends; 0 for a permanent one.
    pub expires: u64,
    pub me: bool,
    /// Their row in the contact list, if they are a contact (a peer otherwise).
    pub contact: Option<ContactId>,
    /// Their row as voice and links name them, contact or peer; none for this device.
    pub row: Option<ContactId>,
}

/// The parts of an update received so far, by index.
type Parts = Vec<Option<Vec<u8>>>;

/// Group state the node keeps in memory.
#[derive(Default)]
pub(crate) struct GroupTraffic {
    /// Updates arriving in parts, per connection and update id.
    reassembly: HashMap<(ConnectionId, [u8; 16]), Parts>,
    /// Updates that cannot be checked yet, with where they came from.
    waiting_updates: Vec<(ContactId, Vec<u8>)>,
    /// Messages of an epoch this device does not hold yet.
    waiting_messages: Vec<(ContactId, Vec<u8>)>,
    /// Group messages sent over the current link to a member and not yet acknowledged.
    in_flight: HashMap<ContactId, Vec<i64>>,
    /// When expired queue entries and memberships were last looked for.
    checked_at: u64,
    /// Acknowledgements of messages that waited for their epoch, for the contacts they came from.
    acks: Vec<(ContactId, ChatMessage)>,
    /// A group record changed what waits for the contact it came from, which cannot be sent
    /// while its session is being used.
    flush: bool,
}

impl GroupTraffic {
    /// A connection ended; `contact`, if it carried the contact's current link.
    pub(super) fn link_ended(&mut self, connection: ConnectionId, contact: Option<ContactId>) {
        self.reassembly.retain(|(c, _), _| *c != connection);
        if let Some(contact) = contact {
            self.in_flight.remove(&contact);
            // The messages come again over the next link, and are acknowledged then.
            self.acks.retain(|(to, _)| *to != contact);
        }
    }

    /// Acknowledgements are not taken in while locked; after unlocking, what was in flight goes again.
    pub(super) fn unsealed(&mut self) {
        self.in_flight.clear();
    }

    pub(super) fn take_flush(&mut self) -> bool {
        std::mem::take(&mut self.flush)
    }
}

impl Node {
    // Reading.

    pub fn groups(&self) -> Result<Vec<GroupSummary>, NodeError> {
        let account = self.account()?;
        let me = account.identity().public();
        Ok(account.db().groups()?.iter().map(|g| g.summary(&me)).collect())
    }

    pub fn group_messages(&self, group: i64) -> Result<Vec<GroupMessage>, NodeError> {
        Ok(self.account()?.db().group_messages(group)?)
    }

    /// For the chat list: each group's latest message, and how many from others are unread.
    pub fn group_previews(&self) -> Result<Vec<(i64, Option<GroupMessage>, u32)>, NodeError> {
        Ok(self.account()?.db().group_previews()?)
    }

    /// The user has read group `group` up to its latest message.
    pub fn mark_group_read(&self, group: i64) -> Result<(), NodeError> {
        Ok(self.account()?.db().mark_group_read(group)?)
    }

    pub fn group_members(&self, group: i64) -> Result<Vec<GroupMember>, NodeError> {
        let account = self.account()?;
        let me = account.identity().public();
        let stored = account.db().group(group)?.ok_or(NodeError::NoSuchGroup)?;
        stored
            .roster
            .members()
            .iter()
            .map(|member| {
                let known = account.db().contact_by_identity(&member.identity)?;
                let contact = known.as_ref().filter(|c| c.state != ContactState::Peer).map(|c| c.id);
                Ok(GroupMember {
                    row: known.map(|c| c.id),
                    identity: member.identity,
                    name: member.name.clone(),
                    admin: member.role == Role::Admin,
                    expires: member.expires,
                    me: member.identity == me,
                    contact,
                })
            })
            .collect()
    }

    // Changing groups.

    /// Creates a group of this device (its admin) and some of its contacts.
    pub fn create_group(
        &mut self,
        name: &str,
        contacts: &[ContactId],
    ) -> Result<(GroupSummary, Vec<Action>), NodeError> {
        let mut members = vec![self.me_as_member(Role::Admin, 0)?];
        for &contact in contacts {
            members.push(self.contact_as_member(contact, 0)?);
        }
        let roster = Roster::new(random::array()?, 0, name, members)?;
        self.start_epoch(roster, &[])
    }

    /// Adds contacts to a group this device administers; with `expires` (Unix seconds) they are
    /// temporary members.
    pub fn add_group_members(
        &mut self,
        group: i64,
        contacts: &[ContactId],
        expires: u64,
    ) -> Result<(GroupSummary, Vec<Action>), NodeError> {
        let stored = self.administered(group)?;
        let mut members = self.freshened(stored.roster.members())?;
        for &contact in contacts {
            let member = self.contact_as_member(contact, expires)?;
            if stored.roster.member(&member.identity).is_none() {
                members.push(member);
            }
        }
        if members.len() == stored.roster.members().len() {
            let me = self.account()?.identity().public();
            return Ok((stored.summary(&me), Vec::new()));
        }
        let roster = Roster::new(stored.group_id, stored.epoch + 1, &stored.name, members)?;
        self.start_epoch(roster, &[])
    }

    /// Removes a member from a group this device administers.
    pub fn remove_group_member(
        &mut self,
        group: i64,
        member: &PublicIdentity,
    ) -> Result<(GroupSummary, Vec<Action>), NodeError> {
        self.remove_group_members(group, std::slice::from_ref(member))
    }

    /// Removes members from a group this device administers, in one epoch.
    pub(super) fn remove_group_members(
        &mut self,
        group: i64,
        gone: &[PublicIdentity],
    ) -> Result<(GroupSummary, Vec<Action>), NodeError> {
        let stored = self.administered(group)?;
        if gone.iter().any(|member| stored.roster.member(member).is_none()) {
            return Err(NodeError::UnknownContact);
        }
        let members: Vec<Member> = self
            .freshened(stored.roster.members())?
            .into_iter()
            .filter(|m| !gone.contains(&m.identity))
            .collect();
        let roster = Roster::new(stored.group_id, stored.epoch + 1, &stored.name, members)?;
        self.start_epoch(roster, gone)
    }

    /// Makes a member an admin, or no longer one, in a group this device administers; a group
    /// keeps at least one admin. A new epoch carries the roster.
    pub fn set_group_admin(
        &mut self,
        group: i64,
        member: &PublicIdentity,
        admin: bool,
    ) -> Result<(GroupSummary, Vec<Action>), NodeError> {
        let stored = self.administered(group)?;
        if stored.roster.member(member).is_none() {
            return Err(NodeError::UnknownContact);
        }
        let role = if admin { Role::Admin } else { Role::Member };
        let members: Vec<Member> = self
            .freshened(stored.roster.members())?
            .into_iter()
            .map(|mut m| {
                if &m.identity == member {
                    m.role = role;
                }
                m
            })
            .collect();
        let roster = Roster::new(stored.group_id, stored.epoch + 1, &stored.name, members)?;
        self.start_epoch(roster, &[])
    }

    /// Leaves a group: its keys go, the history stays, and the members are told so an admin can
    /// start an epoch without this device. The last admin first makes another member admin (the one
    /// with the smallest identity key), so the group goes on.
    pub fn leave_group(&mut self, group: i64) -> Result<(GroupSummary, Vec<Action>), NodeError> {
        let mut actions = Vec::new();
        let account = self.account()?;
        let me = account.identity().public();
        let stored = account
            .db()
            .group(group)?
            .filter(|g| g.membership == Membership::Member)
            .ok_or(NodeError::NoSuchGroup)?;
        let last_admin = stored.roster.is_admin(&me)
            && !stored
                .roster
                .members()
                .iter()
                .any(|m| m.identity != me && m.role == Role::Admin);
        let heir = stored
            .roster
            .members()
            .iter()
            .filter(|m| m.identity != me)
            .map(|m| m.identity)
            .min_by_key(|identity| *identity.as_bytes());
        if let (true, Some(heir)) = (last_admin, heir) {
            actions.extend(self.set_group_admin(group, &heir, true)?.1);
        }
        let account = self.account()?;
        let stored = account.db().group(group)?.ok_or(NodeError::NoSuchGroup)?;
        let recipients = self.member_rows(&stored.roster, &[])?;
        let account = self.account()?;
        account
            .db()
            .queue_group_item(Outgoing::Leave(group), &recipients, now_ms())?;
        account.db().end_membership(group, Membership::Left)?;
        let summary = account.db().group(group)?.ok_or(NodeError::NoSuchGroup)?.summary(&me);
        actions.push(Action::GroupChanged { group: summary.clone() });
        actions.extend(self.refresh_groups());
        for recipient in recipients {
            actions.extend(self.flush_group_outbox(recipient));
        }
        Ok((summary, actions))
    }

    /// Deletes a group this device administers for every member (§9.2): a message saying so goes to
    /// the members as any other, and each member's device deletes the group's history when it
    /// takes it in. This device's history goes at once; the group stays out of sight for a day,
    /// to pass the deletion on.
    pub fn delete_group_for_everyone(&mut self, group: i64) -> Result<(GroupSummary, Vec<Action>), NodeError> {
        let stored = self.administered(group)?;
        let account = self.account()?;
        let me = account.identity().public();
        let message_id = random::array()?;
        let now = now_ms();
        let sealed = group::seal_message(
            &stored.group_id,
            stored.epoch,
            &stored.epoch_key,
            &message_id,
            account.identity(),
            u64::try_from(now).unwrap_or(0),
            &Content::Deleted,
        )?;
        let message = account
            .db()
            .insert_group_message(group, &message_id, &me, true, "", None, now, now, &sealed)?
            .ok_or(NodeError::NoSuchGroup)?;
        let mut actions = self.share_group_message(&stored.roster, message.row)?;
        let tag_key = crate::mesh::group_tag_key(&stored.epoch_key, &stored.group_id, stored.epoch)?;
        actions.extend(self.mesh_send_group(&stored.group_id, &message_id, &sealed, &tag_key, now));
        let account = self.account()?;
        account.delete_group_content(group, Some(message.row))?;
        account.db().mark_group_deleted(group)?;
        let summary = account.db().group(group)?.ok_or(NodeError::NoSuchGroup)?.summary(&me);
        actions.push(Action::GroupChanged { group: summary.clone() });
        actions.extend(self.refresh_groups());
        Ok((summary, actions))
    }

    /// Deletes the conversation of a group this device left or was removed from: the group, its
    /// history and files go, on this device only.
    pub fn delete_group(&mut self, group: i64) -> Result<Vec<Action>, NodeError> {
        let account = self.account()?;
        account
            .db()
            .group(group)?
            .filter(|g| matches!(g.membership, Membership::Left | Membership::Removed | Membership::Ended))
            .ok_or(NodeError::NoSuchGroup)?;
        account.forget_group(group)?;
        Ok(self.refresh_groups())
    }

    pub fn send_group_message(&mut self, group: i64, text: &str) -> Result<(GroupMessage, Vec<Action>), NodeError> {
        let account = self.account()?;
        let me = account.identity().public();
        let stored = account
            .db()
            .group(group)?
            .filter(|g| g.membership == Membership::Member)
            .ok_or(NodeError::NoSuchGroup)?;
        let message_id = random::array()?;
        let now = now_ms();
        let sealed = group::seal_message(
            &stored.group_id,
            stored.epoch,
            &stored.epoch_key,
            &message_id,
            account.identity(),
            u64::try_from(now).unwrap_or(0),
            &Content::Text(Zeroizing::new(text.to_owned())),
        )?;
        let message = account
            .db()
            .insert_group_message(group, &message_id, &me, true, text, None, now, now, &sealed)?
            .ok_or(NodeError::NoSuchGroup)?;
        let mut actions = self.share_group_message(&stored.roster, message.row)?;
        let tag_key = crate::mesh::group_tag_key(&stored.epoch_key, &stored.group_id, stored.epoch)?;
        actions.extend(self.mesh_send_group(&stored.group_id, &message_id, &sealed, &tag_key, now));
        Ok((message, actions))
    }

    /// Tries one of this device's group messages given up again, as the user asked (§9.5): sealed
    /// afresh with the group's current epoch, queued for its members for a day, and sent to those
    /// linked and into the mesh.
    pub fn try_group_message_again(&mut self, row: i64) -> Result<Vec<Action>, NodeError> {
        let account = self.account()?;
        let db = account.db();
        let message = db
            .group_message(row)?
            .filter(|m| m.outgoing && m.status == GroupMessageStatus::Failed)
            .ok_or(NodeError::NoSuchMessage)?;
        let stored = db
            .group(message.group)?
            .filter(|g| g.membership == Membership::Member)
            .ok_or(NodeError::NoSuchGroup)?;
        let content = match &message.attachment {
            Some(file) => Content::File(FileMeta {
                name: file.name.clone(),
                mime: file.mime.clone(),
                size: file.size,
                sha256: file.sha256,
                thumbnail: file.thumbnail.clone(),
            }),
            None => Content::Text(Zeroizing::new(message.body.clone())),
        };
        let sealed = group::seal_message(
            &stored.group_id,
            stored.epoch,
            &stored.epoch_key,
            &message.message_id,
            account.identity(),
            u64::try_from(message.sent_at_ms).unwrap_or(0),
            &content,
        )?;
        let now = now_ms();
        let message = db
            .try_group_message_again(row, now, &sealed)?
            .ok_or(NodeError::NoSuchMessage)?;
        let mut actions = vec![Action::GroupMessageUpdated {
            message: message.clone(),
        }];
        actions.extend(self.share_group_message(&stored.roster, row)?);
        let tag_key = crate::mesh::group_tag_key(&stored.epoch_key, &stored.group_id, stored.epoch)?;
        actions.extend(self.mesh_send_group(&stored.group_id, &message.message_id, &sealed, &tag_key, now));
        Ok(actions)
    }

    /// Queues one of this device's group messages for the members and sends it to those linked.
    pub(super) fn share_group_message(&mut self, roster: &Roster, row: i64) -> Result<Vec<Action>, NodeError> {
        let recipients = self.member_rows(roster, &[])?;
        self.account()?
            .db()
            .queue_group_item(Outgoing::Message(row), &recipients, now_ms())?;
        let mut actions = Vec::new();
        for recipient in recipients {
            actions.extend(self.flush_group_outbox(recipient));
        }
        Ok(actions)
    }

    /// Starts an epoch with `roster` and a fresh key; tells the members, and those in `removed`.
    pub(super) fn start_epoch(
        &mut self,
        roster: Roster,
        removed: &[PublicIdentity],
    ) -> Result<(GroupSummary, Vec<Action>), NodeError> {
        let account = self.account()?;
        let me = account.identity().public();
        let key = SecretBytes::random()?;
        let update = group::seal_update(&roster, &key, account.identity())?;
        let row = account.db().save_group_epoch(&roster, &key, &update, now_ms())?;
        let update_row = account
            .db()
            .group_update_row(row, roster.epoch)?
            .ok_or(NodeError::NoSuchGroup)?;
        let recipients = self.member_rows(&roster, removed)?;
        let account = self.account()?;
        account
            .db()
            .queue_group_item(Outgoing::Update(update_row), &recipients, now_ms())?;
        let summary = account.db().group(row)?.ok_or(NodeError::NoSuchGroup)?.summary(&me);
        let mut actions = vec![Action::GroupChanged { group: summary.clone() }];
        actions.extend(self.refresh_groups());
        for &recipient in &recipients {
            actions.extend(self.flush_group_outbox(recipient));
        }
        // And through the mesh, for members out of reach (§10.9).
        actions.extend(self.mesh_send_update(row, &recipients));
        Ok((summary, actions))
    }

    pub(super) fn administered(&self, group: i64) -> Result<StoredGroup, NodeError> {
        let account = self.account()?;
        let me = account.identity().public();
        let stored = account
            .db()
            .group(group)?
            .filter(|g| g.membership == Membership::Member)
            .ok_or(NodeError::NoSuchGroup)?;
        if !stored.roster.is_admin(&me) {
            return Err(NodeError::NotGroupAdmin);
        }
        Ok(stored)
    }

    pub(super) fn me_as_member(&self, role: Role, expires: u64) -> Result<Member, NodeError> {
        let account = self.account()?;
        Ok(Member {
            identity: account.identity().public(),
            static_kem: account.link_keys().static_kem.encapsulation_key().clone(),
            key_version: account.static_version(),
            presence_key: account.presence_key().clone(),
            role,
            expires,
            name: group::member_name(account.display_name()),
        })
    }

    pub(super) fn contact_as_member(&self, contact: ContactId, expires: u64) -> Result<Member, NodeError> {
        let stored = self
            .account()?
            .db()
            .contact(contact)?
            .ok_or(NodeError::UnknownContact)?;
        Ok(Member {
            identity: stored.summary.identity,
            static_kem: stored.static_kem,
            key_version: stored.static_kem_version,
            presence_key: stored.presence_key,
            role: Role::Member,
            expires,
            name: group::member_name(&stored.summary.display_name),
        })
    }

    /// The rows of the roster's members other than this device, and of `extra` people known here,
    /// recording members who are not contacts as peers. Blocked contacts are left out.
    fn member_rows(&self, roster: &Roster, extra: &[PublicIdentity]) -> Result<Vec<ContactId>, NodeError> {
        let account = self.account()?;
        let me = account.identity().public();
        let db = account.db();
        let mut rows = Vec::new();
        for member in roster.members().iter().filter(|m| m.identity != me) {
            let row = match db.contact_by_identity(&member.identity)? {
                Some(contact) if contact.state == ContactState::Blocked => continue,
                Some(contact) if contact.state != ContactState::Peer => contact.id,
                _ => db.upsert_peer(
                    &member.identity,
                    (&member.static_kem, member.key_version),
                    &member.presence_key,
                    &member.name,
                    now_ms(),
                )?,
            };
            rows.push(row);
        }
        for identity in extra {
            if let Some(contact) = db.contact_by_identity(identity)?
                && contact.state != ContactState::Blocked
                && !rows.contains(&contact.id)
            {
                rows.push(contact.id);
            }
        }
        Ok(rows)
    }

    /// After group membership changed: peers no longer shared with anyone are forgotten (unless
    /// something still waits for them), the link keys reloaded, and links to those no longer
    /// linkable ended.
    pub(super) fn refresh_groups(&mut self) -> Vec<Action> {
        if let Store::Open(account) = &self.store {
            let db = account.db();
            let me = account.identity().public();
            let mut keep: Vec<ContactId> = db.group_outbox_recipients().unwrap_or_default();
            for stored in db.member_groups().unwrap_or_default() {
                for member in stored.roster.members().iter().filter(|m| m.identity != me) {
                    if let Ok(Some(contact)) = db.contact_by_identity(&member.identity) {
                        keep.push(contact.id);
                    }
                }
            }
            let _ = db.delete_peers_except(&keep);
        }
        self.refresh_contacts();
        // Links to mesh peers and channel members are no business of groups.
        let gone: Vec<ContactId> = self
            .links
            .keys()
            .filter(|&&contact| !super::mesh::is_mesh_peer(contact) && !super::channels::is_channel_peer(contact))
            .filter(|contact| !self.keys.contacts.contains_key(contact))
            .copied()
            .collect();
        let mut actions: Vec<Action> = gone.into_iter().flat_map(|contact| self.end_link(contact)).collect();
        // Fellow members now: mesh links to them give way to group links.
        actions.extend(self.end_mesh_links_to_contacts());
        actions
    }

    // Passing traffic on.

    /// Sends what waits for `contact` in the group outbox, if it is linked.
    pub(super) fn flush_group_outbox(&mut self, contact: ContactId) -> Vec<Action> {
        let Some(connection) = self.data_link(contact) else {
            return Vec::new();
        };
        // Its session is out of the table while a record from it is handled; `advance` flushes after.
        if !matches!(self.connections.get(&connection), Some(ConnectionState::Linked { .. })) {
            return Vec::new();
        }
        let Store::Open(account) = &self.store else {
            return Vec::new();
        };
        let db = account.db();
        let traffic = &mut self.group_traffic;
        let mut records: Vec<ChatMessage> = Vec::new();
        traffic.acks.retain(|(to, ack)| {
            if *to == contact {
                records.push(ack.clone());
            }
            *to != contact
        });
        let in_flight = traffic.in_flight.entry(contact).or_default();
        for item in db.group_outbox(contact).unwrap_or_default() {
            match item {
                // Kept until acknowledged; sent once per link.
                Outgoing::Message(row) => {
                    if in_flight.contains(&row) {
                        continue;
                    }
                    match db.group_message_sealed(row) {
                        Ok(Some(sealed)) => {
                            in_flight.push(row);
                            records.push(ChatMessage::GroupMessage(sealed));
                        }
                        _ => {
                            let _ = db.dequeue_group_item(item, contact);
                        }
                    }
                }
                Outgoing::Update(row) => {
                    if let Ok(Some(bytes)) = db.group_update(row) {
                        records.extend(update_parts(&bytes));
                    }
                    let _ = db.dequeue_group_item(item, contact);
                }
                Outgoing::Leave(row) => {
                    if let Ok(Some(stored)) = db.group(row) {
                        records.push(ChatMessage::GroupLeave {
                            group_id: stored.group_id,
                        });
                    }
                    let _ = db.dequeue_group_item(item, contact);
                }
            }
        }
        self.seal_on(connection, records, false)
    }

    /// A group record from a linked contact or peer. Returns actions, and records to send back on
    /// the same link (acknowledgements).
    pub(super) fn on_group_record(
        &mut self,
        connection: ConnectionId,
        contact: ContactId,
        session: &mut Session,
        record: ChatMessage,
    ) -> Result<Vec<Action>, ()> {
        // Group keys live in the database: locked, records wait in the inbox.
        if !matches!(self.store, Store::Open(_)) {
            return self.inbox_group_record(connection, contact, session, record);
        }
        self.group_traffic.flush = true;
        let mut actions = Vec::new();
        match record {
            ChatMessage::UpdatePart {
                update_id,
                index,
                count,
                data,
            } => {
                if let Some(update) = self.reassemble(connection, update_id, index, count, data) {
                    actions.extend(self.take_update(contact, update));
                }
            }
            ChatMessage::GroupMessage(sealed) => {
                let (taken, ack) = self.take_group_message(contact, &sealed);
                actions.extend(taken);
                if let Some(ack) = ack {
                    let bytes = seal_chat(session, &ack).map_err(|_| ())?;
                    actions.push(Action::Send { connection, bytes });
                }
            }
            ChatMessage::GroupAck { group_id, message_id } => {
                actions.extend(self.take_ack(contact, &group_id, &message_id))
            }
            ChatMessage::GroupLeave { group_id } => actions.extend(self.take_leave(contact, &group_id)),
            _ => {}
        }
        Ok(actions)
    }

    /// A group record while locked: updates, messages and leaves go to the inbox (messages are
    /// acknowledged once there); acknowledgements are dropped, the messages go again after unlocking.
    fn inbox_group_record(
        &mut self,
        connection: ConnectionId,
        contact: ContactId,
        session: &mut Session,
        record: ChatMessage,
    ) -> Result<Vec<Action>, ()> {
        let event = match record {
            ChatMessage::UpdatePart {
                update_id,
                index,
                count,
                data,
            } => match self.reassemble(connection, update_id, index, count, data) {
                Some(update) => InboxEvent::GroupUpdate { contact, update },
                None => return Ok(Vec::new()),
            },
            ChatMessage::GroupMessage(bytes) => {
                let Ok(message) = group::Message::read(&bytes) else {
                    return Ok(Vec::new());
                };
                let (group_id, message_id) = (message.group_id, message.message_id);
                let Some(mut actions) = self.inbox_group_message_stored(contact, bytes) else {
                    // Not acknowledged unless durably stored: the sender keeps it and retries.
                    return Ok(Vec::new());
                };
                let ack = ChatMessage::GroupAck { group_id, message_id };
                let bytes = seal_chat(session, &ack).map_err(|_| ())?;
                actions.push(Action::Send { connection, bytes });
                return Ok(actions);
            }
            ChatMessage::GroupLeave { group_id } => InboxEvent::GroupLeave { contact, group_id },
            _ => return Ok(Vec::new()),
        };
        if let Store::Sealed(sealed) = &self.store {
            let _ = sealed.inbox.append(&event);
        }
        Ok(Vec::new())
    }

    /// A group message while locked, from a member's link or the mesh: into the inbox once.
    pub(super) fn inbox_group_message(&mut self, source: ContactId, bytes: Vec<u8>) -> Vec<Action> {
        self.inbox_group_message_stored(source, bytes).unwrap_or_default()
    }

    /// The same; `None` if it could not be stored durably.
    fn inbox_group_message_stored(&mut self, source: ContactId, bytes: Vec<u8>) -> Option<Vec<Action>> {
        let message = group::Message::read(&bytes).ok()?;
        let Store::Sealed(sealed) = &mut self.store else {
            return Some(Vec::new());
        };
        let key = (message.group_id, message.message_id);
        if sealed.group_stored.contains(&key) {
            return Some(Vec::new());
        }
        let event = InboxEvent::GroupMessage {
            contact: source,
            sealed: bytes,
        };
        sealed.inbox.append(&event).ok()?;
        sealed.group_stored.insert(key);
        let group = self.keys.groups.get(&message.group_id).map(|g| g.row);
        Some(vec![Action::GroupMessageArrived { group }])
    }

    /// Group records that arrived while locked, taken in after unlocking.
    pub(super) fn take_inboxed(&mut self, events: Vec<InboxEvent>) -> Vec<Action> {
        let mut actions = Vec::new();
        for event in events {
            match event {
                InboxEvent::GroupUpdate { contact, update } => actions.extend(self.take_update(contact, update)),
                // Acknowledged when it arrived.
                InboxEvent::GroupMessage { contact, sealed } => {
                    actions.extend(self.take_group_message(contact, &sealed).0);
                }
                InboxEvent::GroupLeave { contact, group_id } => actions.extend(self.take_leave(contact, &group_id)),
                _ => {}
            }
        }
        actions
    }

    fn reassemble(
        &mut self,
        connection: ConnectionId,
        update_id: [u8; 16],
        index: u16,
        count: u16,
        data: Vec<u8>,
    ) -> Option<Vec<u8>> {
        let traffic = &mut self.group_traffic;
        let key = (connection, update_id);
        if !traffic.reassembly.contains_key(&key)
            && traffic.reassembly.keys().filter(|(c, _)| *c == connection).count() >= MAX_REASSEMBLIES
        {
            return None;
        }
        let parts = traffic
            .reassembly
            .entry(key)
            .or_insert_with(|| vec![None; usize::from(count)]);
        if parts.len() != usize::from(count) {
            traffic.reassembly.remove(&key);
            return None;
        }
        parts[usize::from(index)] = Some(data);
        if parts.iter().any(Option::is_none) {
            return None;
        }
        let parts = traffic.reassembly.remove(&key)?;
        let update: Vec<u8> = parts.into_iter().flatten().flatten().collect();
        (group::update_id(&update) == update_id).then_some(update)
    }

    /// An update, wherever it came from (§9.2). Takes in any waiting ones it unblocks.
    pub(super) fn take_update(&mut self, source: ContactId, bytes: Vec<u8>) -> Vec<Action> {
        let mut actions = Vec::new();
        let mut changed = false;
        let mut queue = vec![(source, bytes)];
        while let Some((source, bytes)) = queue.pop() {
            match self.apply_update(source, &bytes) {
                Ok(Some(taken)) => {
                    changed = true;
                    actions.extend(taken);
                    // Something changed: what waited may check out now.
                    queue.append(&mut self.group_traffic.waiting_updates);
                    let messages = std::mem::take(&mut self.group_traffic.waiting_messages);
                    for (source, sealed) in messages {
                        let (taken, ack) = self.take_group_message(source, &sealed);
                        actions.extend(taken);
                        // Messages from the mesh are not acknowledged (§10.5).
                        if let Some(ack) = ack
                            && source != super::mesh::FROM_MESH
                        {
                            self.group_traffic.acks.push((source, ack));
                            actions.extend(self.flush_group_outbox(source));
                        }
                    }
                }
                Ok(None) => {}
                Err(Wait) => {
                    let waiting = &mut self.group_traffic.waiting_updates;
                    if waiting.len() >= MAX_WAITING {
                        waiting.remove(0);
                    }
                    waiting.push((source, bytes));
                }
            }
        }
        // Envelopes held to pass on may be this device's now: the next update, the new epoch's
        // messages (§10.9).
        if changed {
            actions.extend(self.mesh_recheck_held(now_secs()));
        }
        actions
    }

    /// Ok(Some) if it changed something, Ok(None) if it is old, foreign or invalid, Err to wait.
    fn apply_update(&mut self, source: ContactId, bytes: &[u8]) -> Result<Option<Vec<Action>>, Wait> {
        let Ok(update) = Update::read(bytes) else {
            return Ok(None);
        };
        let Store::Open(account) = &self.store else {
            return Ok(None);
        };
        let me = account.identity().public();
        let db = account.db();
        let held = db.group_by_id(&update.group_id).ok().flatten();
        // Another update of the epoch held: two admins changed the group at once (§9.2).
        if let Some(held) = held
            .as_ref()
            .filter(|g| g.membership == Membership::Member && g.epoch == update.epoch)
        {
            return self.take_rival_update(source, bytes, &update, held);
        }
        // Old news, also for a group this device left or was removed from; and a group deleted
        // for everyone stays so.
        if held
            .as_ref()
            .is_some_and(|held| update.epoch <= held.epoch || held.membership == Membership::Deleted)
        {
            return Ok(None);
        }
        let member = held.as_ref().filter(|g| g.membership == Membership::Member);
        if let Some(held) = member {
            if !held.roster.is_admin(&update.signer) {
                return Err(Wait);
            }
            if !update.addresses(&me) {
                // Removed by an admin.
                let _ = db.end_membership(held.row, Membership::Removed);
                let summary = db.group(held.row).ok().flatten().map(|g| g.summary(&me));
                let mut actions: Vec<Action> = summary
                    .map(|group| Action::GroupChanged { group })
                    .into_iter()
                    .collect();
                actions.extend(self.refresh_groups());
                return Ok(Some(actions));
            }
        } else if !update.addresses(&me) {
            return Ok(None);
        }
        // Sealed to whichever of this device's static keys the admin knew (§6.9).
        let Some(opened) = account.static_keys().find_map(|(_, key)| update.open(&me, key).ok()) else {
            return Ok(None);
        };
        if member.is_none() {
            // Added: by an admin of the new roster who is a contact of this device.
            let trusted = db
                .contact_by_identity(&update.signer)
                .ok()
                .flatten()
                .is_some_and(|c| c.state == ContactState::Active);
            if !trusted || !opened.roster.is_admin(&update.signer) {
                return Ok(None);
            }
        }
        let removed: Vec<PublicIdentity> = held
            .iter()
            .flat_map(|g| g.roster.members())
            .filter(|m| opened.roster.member(&m.identity).is_none())
            .map(|m| m.identity)
            .collect();
        let Ok(row) = db.save_group_epoch(&opened.roster, &opened.epoch_key, bytes, now_ms()) else {
            return Ok(None);
        };
        let update_row = db.group_update_row(row, opened.roster.epoch).ok().flatten();
        let summary = db.group(row).ok().flatten().map(|g| g.summary(&me));
        let mut recipients = self.member_rows(&opened.roster, &removed).unwrap_or_default();
        recipients.retain(|&r| r != source);
        if let (Store::Open(account), Some(update_row)) = (&self.store, update_row) {
            let _ = account
                .db()
                .queue_group_item(Outgoing::Update(update_row), &recipients, now_ms());
        }
        let mut actions: Vec<Action> = summary
            .map(|group| Action::GroupChanged { group })
            .into_iter()
            .collect();
        actions.extend(self.refresh_groups());
        for &recipient in &recipients {
            actions.extend(self.flush_group_outbox(recipient));
        }
        // And through the mesh (§10.9).
        actions.extend(self.mesh_send_update(row, &recipients));
        // Waiting messages of the members it now knows go out too.
        let members: Vec<ContactId> = self.member_rows(&opened.roster, &[]).unwrap_or_default();
        for member in members {
            actions.extend(self.flush_group_outbox(member));
        }
        Ok(Some(actions))
    }

    /// Another update of the epoch this device holds (§9.2). Of two, the one with the smaller update
    /// id is the group's: this device moves to it if it holds the other, and if this device signed
    /// the other, it makes its change again in the next epoch.
    fn take_rival_update(
        &mut self,
        source: ContactId,
        bytes: &[u8],
        update: &Update,
        held: &StoredGroup,
    ) -> Result<Option<Vec<Action>>, Wait> {
        let Store::Open(account) = &self.store else {
            return Ok(None);
        };
        let me = account.identity().public();
        let db = account.db();
        let Some(ours) = db
            .group_update_row(held.row, held.epoch)
            .ok()
            .flatten()
            .and_then(|row| db.group_update(row).ok().flatten())
        else {
            return Ok(None);
        };
        if group::update_id(bytes) >= group::update_id(&ours) {
            return Ok(None);
        }
        // Both were made from the epoch before, held here as the previous one; one this device
        // cannot check yet waits, like any update.
        let Some((_, before)) = held.previous.as_ref() else {
            return Err(Wait);
        };
        if !before.is_admin(&update.signer) {
            return Err(Wait);
        }
        if !update.addresses(&me) {
            let _ = db.end_membership(held.row, Membership::Removed);
            let summary = db.group(held.row).ok().flatten().map(|g| g.summary(&me));
            let mut actions: Vec<Action> = summary
                .map(|group| Action::GroupChanged { group })
                .into_iter()
                .collect();
            actions.extend(self.refresh_groups());
            return Ok(Some(actions));
        }
        let Some(opened) = account.static_keys().find_map(|(_, key)| update.open(&me, key).ok()) else {
            return Ok(None);
        };
        let set_aside = held.roster.clone();
        let mine = Update::read(&ours).is_ok_and(|u| u.signer == me);
        let before = before.clone();
        if db
            .replace_group_epoch(held.row, &opened.roster, &opened.epoch_key, bytes)
            .is_err()
        {
            return Ok(None);
        }
        // Passed on to the members, and to those only the other update had, so they move too.
        let extra: Vec<PublicIdentity> = set_aside
            .members()
            .iter()
            .filter(|m| opened.roster.member(&m.identity).is_none())
            .map(|m| m.identity)
            .collect();
        let mut recipients = self.member_rows(&opened.roster, &extra).unwrap_or_default();
        recipients.retain(|&r| r != source);
        let mut actions = Vec::new();
        if let Store::Open(account) = &self.store {
            let db = account.db();
            if let Some(update_row) = db.group_update_row(held.row, held.epoch).ok().flatten() {
                let _ = db.queue_group_item(Outgoing::Update(update_row), &recipients, now_ms());
            }
            if let Some(group) = db.group(held.row).ok().flatten() {
                actions.push(Action::GroupChanged {
                    group: group.summary(&me),
                });
            }
        }
        actions.extend(self.refresh_groups());
        for &recipient in &recipients {
            actions.extend(self.flush_group_outbox(recipient));
        }
        actions.extend(self.mesh_send_update(held.row, &recipients));
        actions.extend(self.reseal_group_messages(held.row));
        if mine {
            actions.extend(self.make_change_again(held.row, &before, &set_aside));
        }
        Ok(Some(actions))
    }

    /// This device's messages of the group's current epoch, sealed afresh under its key (same
    /// message ids) and queued for the members again: after it moved to the other update of the
    /// epoch, which those who hold that one could not read them under (§9.2).
    fn reseal_group_messages(&mut self, row: i64) -> Vec<Action> {
        let Ok(account) = self.account() else {
            return Vec::new();
        };
        let db = account.db();
        let Some(stored) = db.group(row).ok().flatten() else {
            return Vec::new();
        };
        let mut resealed = Vec::new();
        for message in db
            .group_messages(row)
            .unwrap_or_default()
            .into_iter()
            .filter(|m| m.outgoing)
        {
            let Some(sealed) = db.group_message_sealed(message.row).ok().flatten() else {
                continue;
            };
            if !group::Message::read(&sealed).is_ok_and(|m| m.epoch == stored.epoch) {
                continue;
            }
            let content = match &message.attachment {
                Some(file) => Content::File(FileMeta {
                    name: file.name.clone(),
                    mime: file.mime.clone(),
                    size: file.size,
                    sha256: file.sha256,
                    thumbnail: file.thumbnail.clone(),
                }),
                None => Content::Text(Zeroizing::new(message.body.clone())),
            };
            let Ok(sealed) = group::seal_message(
                &stored.group_id,
                stored.epoch,
                &stored.epoch_key,
                &message.message_id,
                account.identity(),
                u64::try_from(message.sent_at_ms).unwrap_or(0),
                &content,
            ) else {
                continue;
            };
            if db.reseal_group_message(message.row, &sealed).is_ok() {
                resealed.push((message.row, message.message_id, sealed));
            }
        }
        let mut actions = Vec::new();
        let Ok(tag_key) = crate::mesh::group_tag_key(&stored.epoch_key, &stored.group_id, stored.epoch) else {
            return actions;
        };
        // Sent over a link already, sealed the other way: it goes once more.
        for in_flight in self.group_traffic.in_flight.values_mut() {
            in_flight.retain(|row| !resealed.iter().any(|(resealed, _, _)| resealed == row));
        }
        for (row, message_id, sealed) in resealed {
            actions.extend(self.share_group_message(&stored.roster, row).unwrap_or_default());
            actions.extend(self.mesh_send_group(&stored.group_id, &message_id, &sealed, &tag_key, now_ms()));
        }
        actions
    }

    /// After this device's update of an epoch was set aside for another (§9.2): its change, from
    /// `before` to `mine`, made again on the group's roster in the next epoch: members it added are
    /// added, those it removed removed, roles and the name it changed changed, where they still can
    /// be. Nothing if it is no longer an admin, or if nothing would change.
    fn make_change_again(&mut self, row: i64, before: &Roster, mine: &Roster) -> Vec<Action> {
        let Ok(stored) = self.administered(row) else {
            return Vec::new();
        };
        let removed: Vec<PublicIdentity> = before
            .members()
            .iter()
            .filter(|m| mine.member(&m.identity).is_none())
            .map(|m| m.identity)
            .collect();
        let mut members: Vec<Member> = stored
            .roster
            .members()
            .iter()
            .filter(|m| !removed.contains(&m.identity))
            .cloned()
            .collect();
        for added in mine.members().iter().filter(|m| before.member(&m.identity).is_none()) {
            if !members.iter().any(|m| m.identity == added.identity) {
                members.push(added.clone());
            }
        }
        for member in &mut members {
            if let (Some(was), Some(now)) = (before.member(&member.identity), mine.member(&member.identity))
                && was.role != now.role
            {
                member.role = now.role;
            }
        }
        let name = if mine.name != before.name {
            mine.name.clone()
        } else {
            stored.name.clone()
        };
        let Ok(members) = self.freshened(&members) else {
            return Vec::new();
        };
        let Ok(roster) = Roster::new(stored.group_id, stored.epoch + 1, &name, members) else {
            return Vec::new();
        };
        let unchanged = Roster::new(
            stored.group_id,
            stored.epoch + 1,
            &stored.name,
            stored.roster.members().to_vec(),
        )
        .is_ok_and(|same| same.encode() == roster.encode());
        if unchanged {
            return Vec::new();
        }
        let gone: Vec<PublicIdentity> = removed
            .into_iter()
            .filter(|identity| stored.roster.member(identity).is_some())
            .collect();
        self.start_epoch(roster, &gone)
            .map(|(_, actions)| actions)
            .unwrap_or_default()
    }

    /// A group message (§9.3): stored once and passed on. Returns actions, and the acknowledgement
    /// to send back (none while it waits for its epoch).
    pub(super) fn take_group_message(
        &mut self,
        source: ContactId,
        sealed: &[u8],
    ) -> (Vec<Action>, Option<ChatMessage>) {
        let Ok(message) = group::Message::read(sealed) else {
            return (Vec::new(), None);
        };
        let ack = ChatMessage::GroupAck {
            group_id: message.group_id,
            message_id: message.message_id,
        };
        let Store::Open(account) = &self.store else {
            return (Vec::new(), None);
        };
        let db = account.db();
        let Some(held) = db
            .group_by_id(&message.group_id)
            .ok()
            .flatten()
            .filter(|g| g.membership == Membership::Member)
        else {
            // Not a member (any more): nothing to do, but the sender may stop resending.
            return (Vec::new(), Some(ack));
        };
        if message.epoch > held.epoch {
            let waiting = &mut self.group_traffic.waiting_messages;
            if waiting.len() >= MAX_WAITING {
                waiting.remove(0);
            }
            waiting.push((source, sealed.to_vec()));
            return (Vec::new(), None);
        }
        let Some((key, roster)) = held.epoch(message.epoch) else {
            // Older than this device can read.
            return (Vec::new(), Some(ack));
        };
        if roster.member(&message.sender).is_none() {
            return (Vec::new(), Some(ack));
        }
        // Someone removed (or gone) since may still hold that epoch's key and write as if before
        // it went: of an earlier epoch, only those still in the group are read (§9.3).
        if message.epoch < held.epoch && held.roster.member(&message.sender).is_none() {
            return (Vec::new(), Some(ack));
        }
        let Ok((sent_at, content)) = message.open(key) else {
            // Of the epoch held, it may be sealed under the other update of it (§9.2): it waits,
            // like a message of an epoch not held yet, and opens once this device holds that one.
            if message.epoch == held.epoch {
                let waiting = &mut self.group_traffic.waiting_messages;
                if waiting.len() >= MAX_WAITING {
                    waiting.remove(0);
                }
                waiting.push((source, sealed.to_vec()));
                return (Vec::new(), None);
            }
            // Forged or broken: whoever passes it on may stop.
            return (Vec::new(), Some(ack));
        };
        let (text, file) = match content {
            Content::Text(text) => (text, None),
            Content::File(meta) => (Zeroizing::new(String::new()), Some(meta)),
            // Only an admin deletes a group, one still an admin as far as this device knows.
            Content::Deleted if roster.is_admin(&message.sender) && held.roster.is_admin(&message.sender) => {
                let (roster, key) = (roster.clone(), key.clone());
                return (
                    self.take_deletion(source, &held, &roster, &key, &message, sealed),
                    Some(ack),
                );
            }
            Content::Deleted => return (Vec::new(), Some(ack)),
        };
        let me = account.identity().public();
        let stored = db
            .insert_group_message(
                held.row,
                &message.message_id,
                &message.sender,
                message.sender == me,
                &text,
                file.as_ref(),
                i64::try_from(sent_at).unwrap_or(i64::MAX),
                now_ms(),
                sealed,
            )
            .ok()
            .flatten();
        let Some(stored) = stored else {
            return (Vec::new(), Some(ack));
        };
        let sender_row = db.contact_by_identity(&message.sender).ok().flatten().map(|c| c.id);
        let tag_key = crate::mesh::group_tag_key(key, &message.group_id, message.epoch).ok();
        let roster = roster.clone();
        let mut recipients = self.member_rows(&roster, &[]).unwrap_or_default();
        recipients.retain(|&r| r != source && Some(r) != sender_row);
        if let Store::Open(account) = &self.store {
            let _ = account
                .db()
                .queue_group_item(Outgoing::Message(stored.row), &recipients, now_ms());
        }
        let (stored_at, stored_row, is_file) = (stored.stored_at_ms, stored.row, file.is_some());
        let voice = file.as_ref().is_some_and(|f| crate::storage::is_voice(&f.mime, f.size));
        let mut actions = vec![Action::GroupMessageReceived { message: stored }];
        for recipient in recipients {
            actions.extend(self.flush_group_outbox(recipient));
        }
        // And to the mesh (§10.5), unless it came from there.
        if let Some(tag_key) = tag_key {
            actions.extend(self.mesh_send_group(&message.group_id, &message.message_id, sealed, &tag_key, stored_at));
        }
        // A small file's message from the mesh: its content comes that way too (§10.10).
        if is_file && source == super::mesh::FROM_MESH {
            actions.extend(self.mesh_fetch_group_file(stored_row, now_secs()));
        } else if voice {
            // A voice message is fetched without asking (§9.7).
            actions.extend(self.resume_group_downloads());
        }
        (actions, Some(ack))
    }

    /// An admin deleted the group (§9.2): the deletion is passed on like a message, then the
    /// group's history goes and the group is out of sight, kept a day to pass the deletion on.
    fn take_deletion(
        &mut self,
        source: ContactId,
        held: &StoredGroup,
        roster: &Roster,
        key: &SecretBytes<32>,
        message: &group::Message,
        sealed: &[u8],
    ) -> Vec<Action> {
        let Store::Open(account) = &self.store else {
            return Vec::new();
        };
        let db = account.db();
        let me = account.identity().public();
        let now = now_ms();
        let Ok(Some(stored)) = db.insert_group_message(
            held.row,
            &message.message_id,
            &message.sender,
            false,
            "",
            None,
            now,
            now,
            sealed,
        ) else {
            return Vec::new();
        };
        let sender_row = db.contact_by_identity(&message.sender).ok().flatten().map(|c| c.id);
        let mut recipients = self.member_rows(roster, &[]).unwrap_or_default();
        recipients.retain(|&r| r != source && Some(r) != sender_row);
        let mut actions = Vec::new();
        if let Store::Open(account) = &self.store {
            let _ = account
                .db()
                .queue_group_item(Outgoing::Message(stored.row), &recipients, now);
        }
        for recipient in recipients {
            actions.extend(self.flush_group_outbox(recipient));
        }
        if let Ok(tag_key) = crate::mesh::group_tag_key(key, &message.group_id, message.epoch) {
            actions.extend(self.mesh_send_group(&message.group_id, &message.message_id, sealed, &tag_key, now));
        }
        if let Store::Open(account) = &self.store {
            let _ = account.delete_group_content(held.row, Some(stored.row));
            let _ = account.db().mark_group_deleted(held.row);
            if let Ok(Some(group)) = account.db().group(held.row) {
                actions.push(Action::GroupChanged {
                    group: group.summary(&me),
                });
            }
        }
        actions.extend(self.refresh_groups());
        actions
    }

    fn take_ack(&mut self, source: ContactId, group_id: &GroupId, message_id: &[u8; 16]) -> Vec<Action> {
        let Store::Open(account) = &self.store else {
            return Vec::new();
        };
        let db = account.db();
        let Some(held) = db.group_by_id(group_id).ok().flatten() else {
            return Vec::new();
        };
        let Some(message) = db.group_message_by_id(held.row, message_id).ok().flatten() else {
            return Vec::new();
        };
        let _ = db.dequeue_group_item(Outgoing::Message(message.row), source);
        if let Some(in_flight) = self.group_traffic.in_flight.get_mut(&source) {
            in_flight.retain(|&row| row != message.row);
        }
        match db.mark_group_message_sent(message.row) {
            Ok(Some(message)) => vec![Action::GroupMessageUpdated { message }],
            _ => Vec::new(),
        }
    }

    /// A member left: an admin starts an epoch without it. In a group of two the group ends: no
    /// roster has one member (§9.2).
    fn take_leave(&mut self, source: ContactId, group_id: &GroupId) -> Vec<Action> {
        let Store::Open(account) = &self.store else {
            return Vec::new();
        };
        let db = account.db();
        let me = account.identity().public();
        let Some(held) = db
            .group_by_id(group_id)
            .ok()
            .flatten()
            .filter(|g| g.membership == Membership::Member)
        else {
            return Vec::new();
        };
        let Some(leaver) = db.contact_summary(source).ok().flatten().map(|c| c.identity) else {
            return Vec::new();
        };
        if held.roster.member(&leaver).is_none() || leaver == me {
            return Vec::new();
        }
        if held.roster.members().len() <= group::MIN_MEMBERS {
            return self.end_group(held.row);
        }
        if !held.roster.is_admin(&me) {
            return Vec::new();
        }
        self.remove_group_member(held.row, &leaver)
            .map(|(_, actions)| actions)
            .unwrap_or_default()
    }

    /// A group of two lost its other member: it ends here, keys wiped and history kept.
    fn end_group(&mut self, row: i64) -> Vec<Action> {
        let Store::Open(account) = &self.store else {
            return Vec::new();
        };
        let db = account.db();
        let me = account.identity().public();
        if db.end_membership(row, Membership::Ended).is_err() {
            return Vec::new();
        }
        let mut actions: Vec<Action> = db
            .group(row)
            .ok()
            .flatten()
            .map(|group| Action::GroupChanged {
                group: group.summary(&me),
            })
            .into_iter()
            .collect();
        actions.extend(self.refresh_groups());
        actions
    }

    /// Every few minutes: gives up old queue entries, ends temporary memberships that ran out.
    pub(super) fn tick_groups(&mut self, now_secs: u64) -> Vec<Action> {
        if now_secs.saturating_sub(self.group_traffic.checked_at) < 60 {
            return Vec::new();
        }
        self.group_traffic.checked_at = now_secs;
        let Store::Open(account) = &self.store else {
            return Vec::new();
        };
        let db = account.db();
        let me = account.identity().public();
        let now = i64::try_from(now_secs).unwrap_or(i64::MAX).saturating_mul(1000);
        // This device's messages no member took within a day are given up (§9.5); then whatever
        // still waits for a member a day or longer goes.
        let mut actions: Vec<Action> = db
            .give_up_group_messages(now - TRY_MS)
            .unwrap_or_default()
            .into_iter()
            .map(|message| Action::GroupMessageUpdated { message })
            .collect();
        let given_up = db.expire_group_outbox(now - OUTBOX_KEEP_MS, now - TRY_MS).unwrap_or(0);
        // Groups deleted for everyone a day ago have passed the deletion on: they go entirely.
        for row in db.deleted_groups_before(now - TRY_MS).unwrap_or_default() {
            let _ = account.forget_group(row);
        }
        let mut expired = Vec::new();
        let mut alone = Vec::new();
        for held in db.member_groups().unwrap_or_default() {
            let ended = |m: &Member| m.expires != 0 && m.expires <= now_secs;
            if held.roster.member(&me).is_some_and(ended) {
                // This device's own temporary membership ran out: the content goes (M-5).
                let _ = account.delete_group_content(held.row, None);
                let _ = db.end_membership(held.row, Membership::Removed);
                if let Ok(Some(group)) = db.group(held.row).map(|g| g.map(|g| g.summary(&me))) {
                    actions.push(Action::GroupChanged { group });
                }
            } else if held.roster.members().len() <= group::MIN_MEMBERS
                && held.roster.members().iter().any(|m| m.identity != me && ended(m))
            {
                // The only other member's time ran out: a group of one is no group.
                alone.push(held.row);
            } else if held.roster.is_admin(&me) {
                for member in held.roster.members().iter().filter(|m| ended(m)) {
                    expired.push((held.row, member.identity));
                }
            }
        }
        for (group, member) in expired {
            if let Ok((_, removed)) = self.remove_group_member(group, &member) {
                actions.extend(removed);
            }
        }
        for row in alone {
            actions.extend(self.end_group(row));
        }
        if given_up > 0 || !actions.is_empty() {
            actions.extend(self.refresh_groups());
        }
        // Members that lacked a file a while ago may have it now.
        self.tried.forget();
        actions.extend(self.resume_group_downloads());
        actions
    }
}

/// An update cannot be checked yet; it waits.
struct Wait;

fn update_parts(update: &[u8]) -> Vec<ChatMessage> {
    let update_id = group::update_id(update);
    let count = update.len().div_ceil(UPDATE_PART_LEN);
    update
        .chunks(UPDATE_PART_LEN)
        .enumerate()
        .map(|(index, data)| ChatMessage::UpdatePart {
            update_id,
            index: index as u16,
            count: count as u16,
            data: data.to_vec(),
        })
        .collect()
}

#[cfg(test)]
pub(super) mod tests {
    use std::collections::VecDeque;

    use super::*;
    use crate::{
        account::Account,
        storage::{
            AttachmentState,
            groups::{GroupMessageStatus, group_file},
            vault::tests::TEST_PARAMS,
        },
    };

    const NOW: u64 = 1_000;

    pub(in crate::node) struct Device {
        pub node: Node,
        pub dir: tempfile::TempDir,
        pub pin_record: Vec<u8>,
        pub shown: Vec<Action>,
    }

    /// Devices joined by perfect connections.
    pub(in crate::node) struct Net {
        pub devices: Vec<Device>,
        /// Both ends of each connection: (device, its connection id).
        pub wires: Vec<((usize, ConnectionId), (usize, ConnectionId))>,
        pub next_id: ConnectionId,
        pub now: u64,
    }

    impl Net {
        pub(in crate::node) fn new(names: &[&str]) -> Self {
            let devices = names
                .iter()
                .map(|name| {
                    let dir = tempfile::tempdir().unwrap();
                    let (account, pin_record) = Account::create(dir.path(), b"123456", name, TEST_PARAMS).unwrap();
                    Device {
                        node: Node::new(account).unwrap(),
                        dir,
                        pin_record,
                        shown: Vec::new(),
                    }
                })
                .collect();
            Self {
                devices,
                wires: Vec::new(),
                next_id: 1,
                now: NOW,
            }
        }

        pub(in crate::node) fn wire(&mut self, a: usize, b: usize) -> (ConnectionId, ConnectionId) {
            let ids = (self.next_id, self.next_id + 1);
            self.next_id += 2;
            self.wires.push(((a, ids.0), (b, ids.1)));
            ids
        }

        pub(in crate::node) fn other_end(&self, end: (usize, ConnectionId)) -> Option<(usize, ConnectionId)> {
            self.wires.iter().find_map(|&(x, y)| {
                if x == end {
                    Some(y)
                } else if y == end {
                    Some(x)
                } else {
                    None
                }
            })
        }

        /// Carries out `actions` of device `at` until every device is quiet. Like the platform,
        /// hands every device's actions to [`Node::route`] first.
        pub(in crate::node) fn run(&mut self, at: usize, actions: Vec<Action>) {
            let actions = self.devices[at].node.route(actions);
            let mut queue: VecDeque<(usize, Action)> = actions.into_iter().map(|a| (at, a)).collect();
            while let Some((at, action)) = queue.pop_front() {
                match action {
                    Action::Send { connection, bytes } => {
                        let Some((to, id)) = self.other_end((at, connection)) else {
                            continue;
                        };
                        let replies = self.devices[to].node.on_frame(id, &bytes, self.now);
                        let replies = self.devices[to].node.route(replies);
                        queue.extend(replies.into_iter().map(|reply| (to, reply)));
                    }
                    // A link's other end hears that it closed (pairing ones need not).
                    Action::Close { connection } => {
                        if let Some((to, id)) = self.other_end((at, connection))
                            && self.devices[to].node.links.values().any(|&link| link == id)
                        {
                            let replies = self.devices[to].node.connection_closed(id);
                            let replies = self.devices[to].node.route(replies);
                            queue.extend(replies.into_iter().map(|reply| (to, reply)));
                        }
                    }
                    other => self.devices[at].shown.push(other),
                }
            }
        }

        pub(in crate::node) fn pair(&mut self, a: usize, b: usize) {
            let (id_a, id_b) = self.wire(a, b);
            self.devices[b].node.open_pairing().unwrap();
            let first = self.devices[a].node.pair_nearby(id_a).unwrap();
            self.run(a, first);
            let confirm = self.devices[b].node.confirm_pairing(id_b);
            self.run(b, confirm);
            let confirm = self.devices[a].node.confirm_pairing(id_a);
            self.run(a, confirm);
            self.devices[b].node.close_pairing();
            for device in &mut self.devices {
                device.shown.clear();
            }
        }

        /// Opens a link between two contacts or fellow members, from the side that opens links,
        /// trying again while the other side turns it away (members may hold different epochs).
        pub(in crate::node) fn link(&mut self, a: usize, b: usize) {
            assert!(self.try_link(a, b), "no link");
        }

        /// Like [`Net::link`]; whether the link is up in the end.
        pub(in crate::node) fn try_link(&mut self, a: usize, b: usize) -> bool {
            let token_b = self.devices[b].node.presence_token(self.now);
            let seen = self.devices[a].node.recognize_presence(&token_b, self.now).unwrap();
            let (opener, other) = if seen.opener { (a, b) } else { (b, a) };
            let contact = self.contact(opener, other);
            for _ in 0..4 {
                let (id, _) = self.wire(opener, other);
                let Ok(first) = self.devices[opener].node.connect_contact(id, contact, self.now) else {
                    return false;
                };
                self.run(opener, first);
                if self.devices[opener].node.is_linked(contact) {
                    assert!(self.devices[other].node.is_linked(self.contact(other, opener)));
                    return true;
                }
                // Turned away: the transport reports the connection closed.
                self.devices[opener].node.connection_closed(id);
            }
            false
        }

        /// The link between two devices drops.
        pub(in crate::node) fn cut(&mut self, a: usize, b: usize) {
            for (x, y) in [(a, b), (b, a)] {
                let contact = self.contact(x, y);
                let id = self.devices[x].node.links[&contact];
                let actions = self.devices[x].node.connection_closed(id);
                self.run(x, actions);
            }
        }

        /// The row device `at` keeps for device `of`.
        pub(in crate::node) fn contact(&self, at: usize, of: usize) -> ContactId {
            let identity = self.identity(of);
            self.devices[at]
                .node
                .account()
                .unwrap()
                .db()
                .contact_by_identity(&identity)
                .unwrap()
                .expect("known")
                .id
        }

        pub(in crate::node) fn identity(&self, of: usize) -> PublicIdentity {
            self.devices[of].node.account().unwrap().identity().public()
        }

        pub(in crate::node) fn node(&mut self, at: usize) -> &mut Node {
            &mut self.devices[at].node
        }

        /// The one group device `at` knows.
        pub(in crate::node) fn group(&self, at: usize) -> GroupSummary {
            let groups = self.devices[at].node.groups().unwrap();
            assert_eq!(groups.len(), 1, "one group");
            groups[0].clone()
        }

        pub(in crate::node) fn texts(&self, at: usize) -> Vec<String> {
            let group = self.group(at).row;
            let messages = self.devices[at].node.group_messages(group).unwrap();
            messages.into_iter().map(|m| m.body).collect()
        }

        pub(in crate::node) fn say(&mut self, at: usize, text: &str) -> GroupMessage {
            let group = self.group(at).row;
            let (message, actions) = self.devices[at].node.send_group_message(group, text).unwrap();
            self.run(at, actions);
            message
        }
    }

    const AYSE: usize = 0;
    const BURAK: usize = 1;
    const CEM: usize = 2;

    /// Ayşe is a contact of Burak and of Cem, who do not know each other; she makes a group of
    /// the three while linked to nobody, then links to both.
    fn kamp() -> Net {
        let mut net = Net::new(&["Ayşe", "Burak", "Cem"]);
        net.pair(AYSE, BURAK);
        net.pair(AYSE, CEM);
        let contacts = [net.contact(AYSE, BURAK), net.contact(AYSE, CEM)];
        let (group, actions) = net.node(AYSE).create_group("Kamp", &contacts).unwrap();
        assert_eq!((group.members, group.epoch, group.admin), (3, 0, true));
        assert!(actions.iter().all(|a| matches!(a, Action::GroupChanged { .. })));
        net.link(AYSE, BURAK);
        net.link(AYSE, CEM);
        net
    }

    #[test]
    fn members_who_are_not_contacts_chat_through_one_who_is() {
        let mut net = kamp();
        for at in [BURAK, CEM] {
            let group = net.group(at);
            assert_eq!((group.name.as_str(), group.members, group.admin), ("Kamp", 3, false));
            assert!(
                net.devices[at]
                    .shown
                    .iter()
                    .any(|a| matches!(a, Action::GroupChanged { .. }))
            );
        }
        // Cem is in Burak's member list, but not among his contacts.
        let members = net.devices[BURAK].node.group_members(net.group(BURAK).row).unwrap();
        let cem = members.iter().find(|m| m.name == "Cem").unwrap();
        assert!(cem.contact.is_none() && !cem.admin && !cem.me);
        assert!(
            members
                .iter()
                .any(|m| m.name == "Ayşe" && m.admin && m.contact.is_some())
        );
        let contacts = net.devices[BURAK].node.account().unwrap().contacts().unwrap();
        assert_eq!(contacts.len(), 1);

        let sent = net.say(BURAK, "Çadırı kim getiriyor?");
        assert_eq!(sent.status, GroupMessageStatus::Queued);
        for at in [AYSE, CEM] {
            assert_eq!(net.texts(at), ["Çadırı kim getiriyor?"]);
            let received = net.devices[at].shown.iter().find_map(|a| match a {
                Action::GroupMessageReceived { message } => Some(message),
                _ => None,
            });
            assert_eq!(received.unwrap().sender, net.identity(BURAK));
        }
        // Ayşe acknowledged it; she passes it on.
        let burak_sees = net.devices[BURAK].node.group_messages(sent.group).unwrap();
        assert_eq!(burak_sees[0].status, GroupMessageStatus::Sent);
        assert!(
            net.devices[BURAK]
                .shown
                .iter()
                .any(|a| matches!(a, Action::GroupMessageUpdated { .. }))
        );

        net.say(CEM, "Ben");
        assert_eq!(net.texts(BURAK), ["Çadırı kim getiriyor?", "Ben"]);
        // Nothing waits for linked members (Burak and Cem keep theirs for each other until they
        // meet or it expires).
        for at in [AYSE, BURAK, CEM] {
            let node = &net.devices[at].node;
            for recipient in node.linked_contacts() {
                assert!(node.account().unwrap().db().group_outbox(recipient).unwrap().is_empty());
            }
        }
    }

    #[test]
    fn messages_wait_for_the_link_and_go_once() {
        let mut net = Net::new(&["Ayşe", "Burak", "Cem"]);
        net.pair(AYSE, BURAK);
        net.pair(AYSE, CEM);
        let contacts = [net.contact(AYSE, BURAK), net.contact(AYSE, CEM)];
        let (group, actions) = net.node(AYSE).create_group("Kamp", &contacts).unwrap();
        net.run(AYSE, actions);
        let (_, actions) = net.node(AYSE).send_group_message(group.row, "Yarın 9'da").unwrap();
        assert!(!actions.iter().any(|a| matches!(a, Action::Send { .. })));
        net.link(AYSE, BURAK);
        assert_eq!(net.texts(BURAK), ["Yarın 9'da"]);
        net.link(AYSE, CEM);
        assert_eq!(net.texts(CEM), ["Yarın 9'da"]);
        // A second link to Burak sends nothing again.
        net.link(AYSE, BURAK);
        assert_eq!(net.texts(BURAK), ["Yarın 9'da"]);
    }

    #[test]
    fn a_removed_member_reads_nothing_new() {
        let mut net = kamp();
        let cem = net.identity(CEM);
        let row = net.group(AYSE).row;
        let (group, actions) = net.node(AYSE).remove_group_member(row, &cem).unwrap();
        net.run(AYSE, actions);
        assert_eq!((group.epoch, group.members), (1, 2));
        assert_eq!(net.group(BURAK).epoch, 1);
        let removed = net.group(CEM);
        assert_eq!(removed.membership, Membership::Removed);
        let stored = net.devices[CEM]
            .node
            .account()
            .unwrap()
            .db()
            .group(removed.row)
            .unwrap()
            .unwrap();
        assert_eq!(stored.epoch_key.expose(), &[0; 32], "the key is wiped");

        net.say(AYSE, "Cem gitti");
        assert_eq!(net.texts(BURAK), ["Cem gitti"]);
        assert!(net.texts(CEM).is_empty());
        // The update that let him in, coming again, does not.
        let first = {
            let db = net.devices[AYSE].node.account().unwrap().db();
            db.group_update(db.group_update_row(row, 0).unwrap().unwrap())
                .unwrap()
                .unwrap()
        };
        let from = net.contact(CEM, AYSE);
        assert!(net.node(CEM).take_update(from, first.clone()).is_empty());
        assert_eq!(net.group(CEM).membership, Membership::Removed);
        // Nor does it take Burak, a member, back to the epoch with Cem.
        let from = net.contact(BURAK, AYSE);
        assert!(net.node(BURAK).take_update(from, first).is_empty());
        assert_eq!((net.group(BURAK).epoch, net.group(BURAK).members), (1, 2));
        // Burak, a member, cannot change the members.
        let row = net.group(BURAK).row;
        let ayse = net.identity(AYSE);
        assert!(matches!(
            net.node(BURAK).remove_group_member(row, &ayse),
            Err(NodeError::NotGroupAdmin)
        ));
        // Nor can a removed member write.
        let row = net.group(CEM).row;
        assert!(matches!(
            net.node(CEM).send_group_message(row, "hâlâ burada mıyım?"),
            Err(NodeError::NoSuchGroup)
        ));
    }

    #[test]
    fn a_removed_member_cannot_write_into_the_epoch_it_was_in() {
        let mut net = kamp();
        let row = net.group(AYSE).row;
        let (group_id, old_key) = {
            let stored = net.devices[AYSE]
                .node
                .account()
                .unwrap()
                .db()
                .group(row)
                .unwrap()
                .unwrap();
            (stored.group_id, stored.epoch_key.clone())
        };
        let cem = net.identity(CEM);
        let (_, actions) = net.node(AYSE).remove_group_member(row, &cem).unwrap();
        net.run(AYSE, actions);
        assert_eq!(net.group(BURAK).epoch, 1);
        // Cem kept epoch 0's key (a modified app would) and writes as if before he was removed.
        let forged = {
            let account = net.devices[CEM].node.account().unwrap();
            group::seal_message(
                &group_id,
                0,
                &old_key,
                &[7; 16],
                account.identity(),
                1,
                &Content::Text(Zeroizing::new("eski".into())),
            )
            .unwrap()
        };
        let from = net.contact(BURAK, AYSE);
        let (actions, ack) = net.node(BURAK).take_group_message(from, &forged);
        assert!(actions.is_empty());
        assert!(ack.is_some(), "acknowledged, so whoever passes it on stops");
        assert!(net.texts(BURAK).is_empty());
        // A late message of epoch 0 from someone still in the group is read.
        let late = {
            let account = net.devices[AYSE].node.account().unwrap();
            group::seal_message(
                &group_id,
                0,
                &old_key,
                &[8; 16],
                account.identity(),
                2,
                &Content::Text(Zeroizing::new("geç".into())),
            )
            .unwrap()
        };
        net.node(BURAK).take_group_message(from, &late);
        assert_eq!(net.texts(BURAK), ["geç"]);
    }

    /// Ayşe and Burak, both admins, change the group while out of each other's reach: Ayşe removes
    /// Cem; Burak makes Cem an admin, and writes. Once they meet they hold one roster again, the
    /// same whichever update won (§9.2): Cem is out, and Burak's message reached Ayşe.
    #[test]
    fn two_admins_changing_the_group_at_once_end_up_on_one_roster() {
        let roster = |net: &Net, at: usize| {
            let db = net.devices[at].node.account().unwrap().db();
            db.group(net.group(at).row).unwrap().unwrap().roster
        };
        let update_id = |net: &Net, at: usize, epoch: u64| {
            let db = net.devices[at].node.account().unwrap().db();
            let row = db.group_update_row(net.group(at).row, epoch).unwrap().unwrap();
            group::update_id(&db.group_update(row).unwrap().unwrap())
        };
        let mut seen = [false; 2];
        for _ in 0..40 {
            let mut net = kamp();
            let (burak, cem) = (net.identity(BURAK), net.identity(CEM));
            let row = net.group(AYSE).row;
            let (_, actions) = net.node(AYSE).set_group_admin(row, &burak, true).unwrap();
            net.run(AYSE, actions);
            assert_eq!(net.group(BURAK).epoch, 1);
            net.cut(AYSE, BURAK);
            let (_, actions) = net.node(AYSE).remove_group_member(row, &cem).unwrap();
            net.run(AYSE, actions);
            let row = net.group(BURAK).row;
            let (_, actions) = net.node(BURAK).set_group_admin(row, &cem, true).unwrap();
            net.run(BURAK, actions);
            net.say(BURAK, "ayrıyken");
            let ayse_won = update_id(&net, AYSE, 2) < update_id(&net, BURAK, 2);

            net.link(AYSE, BURAK);
            let (ayse, burak_group) = (net.group(AYSE), net.group(BURAK));
            assert_eq!(ayse.epoch, burak_group.epoch);
            // Burak's change has nothing left to do once Cem is out; Ayşe's is made again.
            assert_eq!(ayse.epoch, if ayse_won { 2 } else { 3 });
            assert_eq!(roster(&net, AYSE).encode(), roster(&net, BURAK).encode());
            assert!(roster(&net, AYSE).member(&cem).is_none(), "the removal stands");
            assert!(net.texts(AYSE).iter().any(|t| t == "ayrıyken"));
            seen[usize::from(ayse_won)] = true;
            if seen == [true, true] {
                return;
            }
        }
        panic!("each update should have won at least once");
    }

    #[test]
    fn of_two_updates_of_one_epoch_the_one_with_the_smaller_id_stands() {
        let mut net = kamp();
        let cem = net.identity(CEM);
        let row = net.group(AYSE).row;
        let (_, actions) = net.node(AYSE).remove_group_member(row, &cem).unwrap();
        net.run(AYSE, actions);
        assert_eq!((net.group(BURAK).epoch, net.group(BURAK).members), (1, 2));
        let held_id = |net: &Net| {
            let db = net.devices[BURAK].node.account().unwrap().db();
            let row = db.group_update_row(net.group(BURAK).row, 1).unwrap().unwrap();
            group::update_id(&db.group_update(row).unwrap().unwrap())
        };
        // Other epochs 1, validly signed by the admin, with Cem back in (as if made elsewhere).
        let other = |net: &Net| {
            let ayse = net.devices[AYSE].node.account().unwrap();
            let burak = net.devices[BURAK].node.account().unwrap();
            let held = burak.db().group(net.group(BURAK).row).unwrap().unwrap();
            let cem_stored = net.devices[CEM]
                .node
                .account()
                .unwrap()
                .db()
                .group(net.group(CEM).row)
                .unwrap()
                .unwrap();
            let roster = Roster::new(held.group_id, 1, "Kamp", cem_stored.roster.members().to_vec()).unwrap();
            group::seal_update(&roster, &SecretBytes::random().unwrap(), ayse.identity()).unwrap()
        };
        let from = net.contact(BURAK, AYSE);
        // A larger id is set aside.
        let larger = std::iter::repeat_with(|| other(&net))
            .find(|u| group::update_id(u) > held_id(&net))
            .unwrap();
        assert!(net.node(BURAK).take_update(from, larger).is_empty());
        assert_eq!((net.group(BURAK).epoch, net.group(BURAK).members), (1, 2));
        // A smaller one replaces the epoch held; the previous one stays.
        let smaller = std::iter::repeat_with(|| other(&net))
            .find(|u| group::update_id(u) < held_id(&net))
            .unwrap();
        assert!(!net.node(BURAK).take_update(from, smaller.clone()).is_empty());
        assert_eq!((net.group(BURAK).epoch, net.group(BURAK).members), (1, 3));
        assert_eq!(
            held_id(&net),
            group::update_id(&smaller),
            "and passed on as the epoch's update"
        );
        let stored = net.devices[BURAK]
            .node
            .account()
            .unwrap()
            .db()
            .group(net.group(BURAK).row)
            .unwrap()
            .unwrap();
        assert_eq!(stored.previous.as_ref().map(|(_, r)| r.epoch), Some(0));
    }

    #[test]
    fn group_messages_are_stored_once_and_tampered_ones_not_at_all() {
        let mut net = kamp();
        let row = net.group(AYSE).row;
        let (group_id, key) = {
            let stored = net.devices[AYSE]
                .node
                .account()
                .unwrap()
                .db()
                .group(row)
                .unwrap()
                .unwrap();
            (stored.group_id, stored.epoch_key.clone())
        };
        let sealed = {
            let ayse = net.devices[AYSE].node.account().unwrap();
            group::seal_message(
                &group_id,
                0,
                &key,
                &[5; 16],
                ayse.identity(),
                1,
                &Content::Text(Zeroizing::new("bir kez".into())),
            )
            .unwrap()
        };
        let from = net.contact(BURAK, AYSE);
        net.node(BURAK).take_group_message(from, &sealed);
        // Coming again, by another way or replayed, it is acknowledged and not stored twice.
        let (actions, ack) = net.node(BURAK).take_group_message(from, &sealed);
        assert!(actions.is_empty());
        assert!(ack.is_some());
        assert_eq!(net.texts(BURAK), ["bir kez"]);
        // Any byte changed breaks it: the signature, or the ciphertext under it.
        let mut tampered = group::seal_message(
            &group_id,
            0,
            &key,
            &[6; 16],
            net.devices[AYSE].node.account().unwrap().identity(),
            2,
            &Content::Text(Zeroizing::new("değişti".into())),
        )
        .unwrap();
        for at in [tampered.len() - 1, tampered.len() - 80] {
            tampered[at] ^= 1;
            net.node(BURAK).take_group_message(from, &tampered);
            tampered[at] ^= 1;
        }
        assert_eq!(net.texts(BURAK), ["bir kez"]);
    }

    #[test]
    fn an_admin_deletes_the_group_for_everyone() {
        let mut net = kamp();
        net.say(BURAK, "Çadır bende");
        // Cem is away when it happens.
        net.cut(AYSE, CEM);
        let row = net.group(AYSE).row;
        let group_id = net.devices[AYSE]
            .node
            .account()
            .unwrap()
            .db()
            .group(row)
            .unwrap()
            .unwrap()
            .group_id;
        // Burak, a member, cannot.
        let burak_row = net.group(BURAK).row;
        assert!(matches!(
            net.node(BURAK).delete_group_for_everyone(burak_row),
            Err(NodeError::NotGroupAdmin)
        ));
        let (group, actions) = net.node(AYSE).delete_group_for_everyone(row).unwrap();
        assert_eq!(group.membership, Membership::Deleted);
        net.run(AYSE, actions);
        assert!(
            net.devices[CEM].node.groups().unwrap().len() == 1,
            "Cem has not heard yet"
        );
        net.link(AYSE, CEM);
        for at in [AYSE, BURAK, CEM] {
            let node = &net.devices[at].node;
            assert!(node.groups().unwrap().is_empty(), "out of sight");
            assert!(node.group_previews().unwrap().is_empty());
            let db = node.account().unwrap().db();
            let stored = db.group_by_id(&group_id).unwrap().unwrap();
            assert_eq!(stored.membership, Membership::Deleted);
            // Only the deletion is left, to pass on.
            let messages = db.group_messages(stored.row).unwrap();
            assert_eq!(messages.len(), 1);
            assert!(messages[0].body.is_empty() && messages[0].attachment.is_none());
        }
        // The update that made the group does not bring it back.
        let first = {
            let db = net.devices[AYSE].node.account().unwrap().db();
            db.group_update(db.group_update_row(row, 0).unwrap().unwrap())
                .unwrap()
                .unwrap()
        };
        let from = net.contact(BURAK, AYSE);
        net.node(BURAK).take_update(from, first);
        assert!(net.devices[BURAK].node.groups().unwrap().is_empty());
        // A day later the group is gone entirely.
        let later = now_secs() + 2 * 24 * 3600;
        for at in [AYSE, BURAK, CEM] {
            net.node(at).tick_groups(later);
            let db = net.devices[at].node.account().unwrap().db();
            assert!(db.group_by_id(&group_id).unwrap().is_none());
        }
    }

    #[test]
    fn only_an_admin_deletes_a_group() {
        let mut net = kamp();
        // Burak seals a deletion himself, with the group's key.
        let (group_id, epoch, key) = {
            let db = net.devices[BURAK].node.account().unwrap().db();
            let stored = db.group(net.group(BURAK).row).unwrap().unwrap();
            (stored.group_id, stored.epoch, stored.epoch_key.clone())
        };
        let sealed = {
            let account = net.devices[BURAK].node.account().unwrap();
            group::seal_message(
                &group_id,
                epoch,
                &key,
                &[0x99; 16],
                account.identity(),
                1,
                &Content::Deleted,
            )
            .unwrap()
        };
        let from = net.contact(AYSE, BURAK);
        let (actions, ack) = net.node(AYSE).take_group_message(from, &sealed);
        assert!(actions.is_empty() && ack.is_some());
        assert_eq!(net.group(AYSE).membership, Membership::Member);
    }

    #[test]
    fn a_member_who_left_deletes_the_conversation() {
        let mut net = kamp();
        net.say(AYSE, "Hoş geldiniz");
        let row = net.group(BURAK).row;
        // Not while still a member.
        assert!(matches!(net.node(BURAK).delete_group(row), Err(NodeError::NoSuchGroup)));
        let (_, actions) = net.node(BURAK).leave_group(row).unwrap();
        net.run(BURAK, actions);
        assert_eq!(net.texts(BURAK), ["Hoş geldiniz"], "the history stays");
        let actions = net.node(BURAK).delete_group(row).unwrap();
        net.run(BURAK, actions);
        assert!(net.devices[BURAK].node.groups().unwrap().is_empty());
        assert!(
            net.devices[BURAK]
                .node
                .account()
                .unwrap()
                .db()
                .group(row)
                .unwrap()
                .is_none()
        );
        // The others go on.
        assert_eq!(net.group(AYSE).membership, Membership::Member);
    }

    #[test]
    fn a_group_of_two_ends_when_the_other_leaves() {
        let mut net = Net::new(&["Ayşe", "Burak"]);
        net.pair(AYSE, BURAK);
        let burak = net.contact(AYSE, BURAK);
        let (group, actions) = net.node(AYSE).create_group("İkimiz", &[burak]).unwrap();
        net.run(AYSE, actions);
        net.link(AYSE, BURAK);
        net.say(AYSE, "Merhaba");
        // Burak is no admin; Ayşe stays one.
        let row = net.group(BURAK).row;
        let (_, actions) = net.node(BURAK).leave_group(row).unwrap();
        net.run(BURAK, actions);
        let ended = net.group(AYSE);
        assert_eq!(ended.membership, Membership::Ended);
        assert_eq!(net.texts(AYSE), ["Merhaba"], "the history stays");
        let stored = net.devices[AYSE]
            .node
            .account()
            .unwrap()
            .db()
            .group(group.row)
            .unwrap()
            .unwrap();
        assert_eq!(stored.epoch_key.expose(), &[0; 32], "the key is wiped");
        assert!(matches!(
            net.node(AYSE).send_group_message(group.row, "kimse yok mu?"),
            Err(NodeError::NoSuchGroup)
        ));
        // The conversation can go now.
        let actions = net.node(AYSE).delete_group(group.row).unwrap();
        net.run(AYSE, actions);
        assert!(net.devices[AYSE].node.groups().unwrap().is_empty());
    }

    #[test]
    fn a_group_of_two_ends_when_the_others_time_runs_out() {
        let mut net = Net::new(&["Ayşe", "Burak", "Cem"]);
        net.pair(AYSE, BURAK);
        net.pair(AYSE, CEM);
        let (burak, cem) = (net.contact(AYSE, BURAK), net.contact(AYSE, CEM));
        // Ayşe and Cem, then Burak for an hour, then Cem goes: Ayşe and a temporary Burak are left.
        let (group, actions) = net.node(AYSE).create_group("Bir saat", &[cem]).unwrap();
        net.run(AYSE, actions);
        let expires = now_secs() + 3600;
        let (_, actions) = net.node(AYSE).add_group_members(group.row, &[burak], expires).unwrap();
        net.run(AYSE, actions);
        let cem_id = net.identity(CEM);
        let (two, actions) = net.node(AYSE).remove_group_member(group.row, &cem_id).unwrap();
        net.run(AYSE, actions);
        assert_eq!(two.members, 2);
        // Before the hour nothing happens; after it the group ends at Ayşe's.
        net.node(AYSE).tick_groups(expires - 10);
        assert_eq!(net.group(AYSE).membership, Membership::Member);
        let actions = net.node(AYSE).tick_groups(expires + 120);
        net.run(AYSE, actions);
        assert_eq!(net.group(AYSE).membership, Membership::Ended);
    }

    #[test]
    fn leaving_makes_the_admin_start_an_epoch_without_the_member() {
        let mut net = kamp();
        let row = net.group(BURAK).row;
        let (group, actions) = net.node(BURAK).leave_group(row).unwrap();
        assert_eq!(group.membership, Membership::Left);
        net.run(BURAK, actions);
        let ayse = net.group(AYSE);
        assert_eq!((ayse.epoch, ayse.members), (1, 2));
        assert_eq!(net.group(CEM).epoch, 1);
        let members = net.devices[CEM].node.group_members(net.group(CEM).row).unwrap();
        assert!(members.iter().all(|m| m.name != "Burak"));
        // Burak stays a peer of Cem only while the update waits for him.
        let burak = net.identity(BURAK);
        let db = net.devices[CEM].node.account().unwrap().db();
        let peer = db.contact_by_identity(&burak).unwrap().unwrap();
        assert_eq!(peer.state, ContactState::Peer);
        assert_eq!(db.group_outbox(peer.id).unwrap().len(), 1);
        assert!(db.contacts().unwrap().iter().all(|c| c.identity != burak));
    }

    #[test]
    fn a_member_added_later_gets_the_new_epoch_through_others() {
        let mut net = Net::new(&["Ayşe", "Burak", "Cem"]);
        net.pair(AYSE, BURAK);
        net.pair(AYSE, CEM);
        let contacts = [net.contact(AYSE, BURAK)];
        let (group, actions) = net.node(AYSE).create_group("Kamp", &contacts).unwrap();
        net.run(AYSE, actions);
        net.link(AYSE, BURAK);
        let cem = net.contact(AYSE, CEM);
        let (group, actions) = net.node(AYSE).add_group_members(group.row, &[cem], 0).unwrap();
        net.run(AYSE, actions);
        assert_eq!((group.epoch, group.members), (1, 3));
        assert_eq!(net.group(BURAK).members, 3);
        // Burak writes in the new epoch before Cem has it: Ayşe passes on the update first.
        net.say(BURAK, "Hoş geldin Cem");
        net.link(AYSE, CEM);
        assert_eq!(net.group(CEM).epoch, 1);
        assert_eq!(net.texts(CEM), ["Hoş geldin Cem"]);
    }

    #[test]
    fn a_message_ahead_of_its_update_waits_for_it() {
        let mut net = kamp();
        let cem = net.identity(CEM);
        let row = net.group(AYSE).row;
        // Ayşe makes epoch 1 while cut off from Burak; a message of it reaches Burak first.
        let burak_link = net.devices[AYSE].node.links[&net.contact(AYSE, BURAK)];
        net.wires
            .retain(|&(x, y)| x != (AYSE, burak_link) && y != (AYSE, burak_link));
        let (_, actions) = net.node(AYSE).remove_group_member(row, &cem).unwrap();
        net.run(AYSE, actions);
        let (message, _) = net.node(AYSE).send_group_message(row, "Yeni dönem").unwrap();
        let sealed = net.devices[AYSE]
            .node
            .account()
            .unwrap()
            .db()
            .group_message_sealed(message.row)
            .unwrap()
            .unwrap();
        let from = net.contact(BURAK, AYSE);
        let (actions, ack) = net.node(BURAK).take_group_message(from, &sealed);
        assert!(actions.is_empty() && ack.is_none(), "kept, not acknowledged");
        assert!(net.texts(BURAK).is_empty());
        let update = {
            let db = net.devices[AYSE].node.account().unwrap().db();
            let update_row = db.group_update_row(row, 1).unwrap().unwrap();
            db.group_update(update_row).unwrap().unwrap()
        };
        let actions = net.node(BURAK).take_update(from, update);
        assert!(actions.iter().any(|a| matches!(a, Action::GroupMessageReceived { .. })));
        assert!(
            actions.iter().any(|a| matches!(a, Action::Send { .. })),
            "now acknowledged"
        );
        assert_eq!(net.texts(BURAK), ["Yeni dönem"]);
    }

    #[test]
    fn updates_from_non_admins_and_strangers_are_not_taken_in() {
        let mut net = kamp();
        let from = net.contact(CEM, AYSE);
        // Burak, a member, makes himself admin of epoch 1.
        let forged = {
            let burak = net.devices[BURAK].node.account().unwrap();
            let stored = burak.db().group(net.group(BURAK).row).unwrap().unwrap();
            let members = stored
                .roster
                .members()
                .iter()
                .cloned()
                .map(|mut m| {
                    m.role = Role::Admin;
                    m
                })
                .collect();
            let roster = Roster::new(stored.group_id, 1, "Burak'ın", members).unwrap();
            group::seal_update(&roster, &SecretBytes::random().unwrap(), burak.identity()).unwrap()
        };
        assert!(net.node(CEM).take_update(from, forged).is_empty());
        assert_eq!(net.group(CEM).epoch, 0);
        // A group made by someone who is not Cem's contact is not joined.
        let stranger = {
            let burak = net.devices[BURAK].node.account().unwrap();
            let stored = burak.db().group(net.group(BURAK).row).unwrap().unwrap();
            let mut members: Vec<Member> = stored.roster.members().to_vec();
            for m in &mut members {
                m.role = if m.identity == burak.identity().public() {
                    Role::Admin
                } else {
                    Role::Member
                };
            }
            let roster = Roster::new([9; 16], 0, "Yabancı", members).unwrap();
            group::seal_update(&roster, &SecretBytes::random().unwrap(), burak.identity()).unwrap()
        };
        assert!(net.node(CEM).take_update(from, stranger).is_empty());
        assert_eq!(net.devices[CEM].node.groups().unwrap().len(), 1);
    }

    #[test]
    fn members_who_are_not_contacts_link_for_the_group_only() {
        let mut net = Net::new(&["Ayşe", "Burak", "Cem"]);
        net.pair(AYSE, BURAK);
        net.pair(AYSE, CEM);
        let contacts = [net.contact(AYSE, BURAK), net.contact(AYSE, CEM)];
        let (_, actions) = net.node(AYSE).create_group("Kamp", &contacts).unwrap();
        net.run(AYSE, actions);
        net.link(AYSE, BURAK);
        net.link(AYSE, CEM);
        net.cut(AYSE, BURAK);
        net.cut(AYSE, CEM);

        // Burak and Cem recognise each other and link with the group's key.
        net.link(BURAK, CEM);
        net.say(BURAK, "Ayşe yokken");
        assert_eq!(net.texts(CEM), ["Ayşe yokken"]);

        // Nothing but group traffic: no 1:1 messages or calls.
        let cem = net.contact(BURAK, CEM);
        assert!(matches!(
            net.node(BURAK).send_message(cem, "selam"),
            Err(NodeError::UnknownContact)
        ));
        assert!(matches!(
            net.node(BURAK).start_call(cem, false),
            Err(NodeError::UnknownContact)
        ));
        let forged = super::super::text_message([3; 16], 0, "selam");
        let actions = net.node(BURAK).send_to(cem, vec![forged], false);
        net.run(BURAK, actions);
        let burak = net.contact(CEM, BURAK);
        assert!(net.devices[CEM].node.messages(burak).unwrap().is_empty());
        assert_eq!(net.devices[CEM].node.account().unwrap().contacts().unwrap().len(), 1);
    }

    #[test]
    fn members_link_across_an_update_one_of_them_missed() {
        const DILEK: usize = 3;
        let mut net = Net::new(&["Ayşe", "Burak", "Cem", "Dilek"]);
        net.pair(AYSE, BURAK);
        net.pair(AYSE, CEM);
        net.pair(AYSE, DILEK);
        let contacts = [net.contact(AYSE, BURAK), net.contact(AYSE, CEM)];
        let (group, actions) = net.node(AYSE).create_group("Kamp", &contacts).unwrap();
        net.run(AYSE, actions);
        net.link(AYSE, BURAK);
        net.link(AYSE, CEM);
        net.cut(AYSE, CEM);
        let dilek = net.contact(AYSE, DILEK);
        let (_, actions) = net.node(AYSE).add_group_members(group.row, &[dilek], 0).unwrap();
        net.run(AYSE, actions);
        assert_eq!((net.group(BURAK).epoch, net.group(CEM).epoch), (1, 0));

        net.link(BURAK, CEM);
        assert_eq!(net.group(CEM).epoch, 1);
        assert_eq!(net.group(CEM).members, 4);
    }

    #[test]
    fn a_removed_member_learns_of_it_and_links_no_more() {
        let mut net = kamp();
        net.cut(AYSE, CEM);
        let (row, cem) = (net.group(AYSE).row, net.identity(CEM));
        let (_, actions) = net.node(AYSE).remove_group_member(row, &cem).unwrap();
        net.run(AYSE, actions);
        // Burak passes the removal on over the link the previous epoch's key still opens.
        assert!(!net.try_link(BURAK, CEM), "ended once the removal is through");
        assert_eq!(net.group(CEM).membership, Membership::Removed);
        // Cem forgot Burak and ended the link; Burak keeps only his link to Ayşe.
        let burak = net.identity(BURAK);
        let db = net.devices[CEM].node.account().unwrap().db();
        assert!(db.contact_by_identity(&burak).unwrap().is_none());
        assert!(net.devices[CEM].node.links.is_empty());
        assert_eq!(net.devices[BURAK].node.links.len(), 1);
    }

    #[test]
    fn group_records_arriving_while_locked_wait_encrypted_until_unlock() {
        let mut net = kamp();
        let cem = net.contact(AYSE, CEM);
        net.devices[CEM].node.seal();
        let sent = net.say(BURAK, "Gizli buluşma yeri");
        // Ayşe passed it on and Cem acknowledged it from the inbox.
        let db = net.devices[AYSE].node.account().unwrap().db();
        assert!(db.group_outbox(cem).unwrap().is_empty());
        assert!(
            net.devices[CEM]
                .shown
                .iter()
                .any(|a| matches!(a, Action::GroupMessageArrived { .. }))
        );
        let (row, burak) = (net.group(AYSE).row, net.identity(BURAK));
        let (_, actions) = net.node(AYSE).remove_group_member(row, &burak).unwrap();
        net.run(AYSE, actions);
        let inbox = std::fs::read(net.devices[CEM].dir.path().join(crate::account::INBOX_FILE)).unwrap();
        assert!(!inbox.windows(5).any(|w| w == b"Gizli"), "no plaintext on disk");

        let device = &mut net.devices[CEM];
        let account = Account::unlock_with_pin(device.dir.path(), &device.pin_record, b"123456").unwrap();
        let actions = device.node.unseal(account).unwrap();
        assert!(actions.iter().any(|a| matches!(a, Action::GroupChanged { .. })));
        assert!(actions.iter().any(|a| matches!(a, Action::GroupMessageReceived { .. })));
        net.run(CEM, actions);
        assert_eq!(net.texts(CEM), [sent.body]);
        let group = net.group(CEM);
        assert_eq!((group.epoch, group.members), (1, 2));
        assert!(!net.devices[CEM].dir.path().join(crate::account::INBOX_FILE).exists());
    }

    fn shown_talks(net: &Net, at: usize) -> Vec<ContactId> {
        net.devices[at]
            .shown
            .iter()
            .filter_map(|a| match a {
                Action::GroupTalkStarted { contact, .. } => Some(*contact),
                _ => None,
            })
            .collect()
    }

    fn last_participants(net: &Net, at: usize) -> Vec<ContactId> {
        net.devices[at]
            .shown
            .iter()
            .rev()
            .find_map(|a| match a {
                Action::GroupCallChanged { participants, .. } => Some(participants.clone()),
                _ => None,
            })
            .unwrap_or_default()
    }

    #[test]
    fn group_voice_reaches_the_members_linked_also_while_locked() {
        let mut net = kamp();
        net.link(BURAK, CEM);
        let burak_row = net.group(BURAK).row;
        net.node(BURAK).set_group_ptt(burak_row, true).unwrap();
        assert!(net.group(BURAK).instant_voice);
        let row = net.group(AYSE).row;

        // Push-to-talk plays where the group's instant voice is on: Burak's, not Cem's.
        let (talk, actions) = net.node(AYSE).start_group_talk(row).unwrap();
        net.run(AYSE, actions);
        assert_eq!(shown_talks(&net, BURAK), [net.contact(BURAK, AYSE)]);
        assert!(shown_talks(&net, CEM).is_empty());
        let actions = net.node(AYSE).send_audio(talk, b"opus");
        assert_eq!(actions.len(), 1, "to Burak only");
        net.run(AYSE, actions);
        let from = net.contact(BURAK, AYSE);
        assert!(
            net.devices[BURAK]
                .shown
                .iter()
                .any(|a| matches!(a, Action::Audio { from: f, .. } if *f == from))
        );
        let actions = net.node(AYSE).end_talk(talk);
        net.run(AYSE, actions);

        // A group call rings Burak and Cem, Cem locked; both join and hear each other directly.
        net.devices[CEM].node.seal();
        let (call, actions) = net.node(AYSE).start_group_call(row).unwrap();
        net.run(AYSE, actions);
        for at in [BURAK, CEM] {
            assert!(
                net.devices[at]
                    .shown
                    .iter()
                    .any(|a| matches!(a, Action::GroupCallRinging { id, .. } if *id == call))
            );
        }
        let actions = net.node(BURAK).join_group_call(call).unwrap();
        net.run(BURAK, actions);
        let actions = net.node(CEM).join_group_call(call).unwrap();
        net.run(CEM, actions);
        assert_eq!(last_participants(&net, AYSE).len(), 2);
        assert_eq!(last_participants(&net, BURAK).len(), 2);
        assert_eq!(last_participants(&net, CEM).len(), 2);
        assert_eq!(net.node(CEM).send_audio(call, b"opus").len(), 2);

        let actions = net.node(BURAK).end_call(call);
        net.run(BURAK, actions);
        assert_eq!(last_participants(&net, AYSE).len(), 1);
        let actions = net.node(AYSE).end_call(call);
        net.run(AYSE, actions);
        assert!(
            net.devices[CEM]
                .shown
                .iter()
                .any(|a| matches!(a, Action::CallEnded { id, .. } if *id == call)),
            "Cem was left alone"
        );
    }

    #[test]
    fn a_group_message_no_member_took_in_a_day_is_given_up_until_tried_again() {
        // Ayşe makes the group and writes while linked to nobody.
        let mut net = Net::new(&["Ayşe", "Burak", "Cem"]);
        net.pair(AYSE, BURAK);
        net.pair(AYSE, CEM);
        let contacts = [net.contact(AYSE, BURAK), net.contact(AYSE, CEM)];
        let (group, _) = net.node(AYSE).create_group("Kamp", &contacts).unwrap();
        let (message, actions) = net.node(AYSE).send_group_message(group.row, "kimse yok").unwrap();
        net.run(AYSE, actions);
        assert_eq!(message.status, GroupMessageStatus::Queued);
        let actions = net.node(AYSE).tick(now_secs() + 24 * 3600 + 60);
        assert!(actions.iter().any(
            |a| matches!(a, Action::GroupMessageUpdated { message } if message.status == GroupMessageStatus::Failed)
        ));
        net.run(AYSE, actions);
        // The group still reaches them (its update waits longer); the message does not.
        net.link(AYSE, BURAK);
        let burak_row = net.group(BURAK).row;
        let burak_sees = |net: &mut Net| {
            net.node(BURAK)
                .account()
                .unwrap()
                .db()
                .group_messages(burak_row)
                .unwrap()
        };
        assert!(burak_sees(&mut net).is_empty());
        // Tried again, it goes at once.
        let actions = net.node(AYSE).try_group_message_again(message.row).unwrap();
        net.run(AYSE, actions);
        assert_eq!(burak_sees(&mut net)[0].body, "kimse yok");
        let row = net.group(AYSE).row;
        let sent = net.node(AYSE).account().unwrap().db().group_messages(row).unwrap();
        assert_eq!(sent[0].status, GroupMessageStatus::Sent);
        assert!(matches!(
            net.node(AYSE).try_group_message_again(message.row),
            Err(NodeError::NoSuchMessage)
        ));
    }

    /// Frames of `from`'s video shown at `at`, as (key, length).
    fn shown_video(net: &Net, at: usize, from: ContactId) -> Vec<(bool, usize)> {
        net.devices[at]
            .shown
            .iter()
            .filter_map(|a| match a {
                Action::Video {
                    from: f, key, frame, ..
                } if *f == from => Some((*key, frame.len())),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn group_video_goes_round_through_the_participants() {
        use crate::chat::VideoState;
        // Burak and Cem are not linked: Ayşe passes on what each sends (§9.9).
        let mut net = kamp();
        let row = net.group(AYSE).row;
        let (call, actions) = net.node(AYSE).start_group_call(row).unwrap();
        net.run(AYSE, actions);
        for at in [BURAK, CEM] {
            let actions = net.node(at).join_group_call(call).unwrap();
            net.run(at, actions);
        }
        let (burak_at_cem, burak_at_ayse) = (net.contact(CEM, BURAK), net.contact(AYSE, BURAK));

        // Burak's camera goes on; everyone hears of it in his presence.
        let actions = net.node(BURAK).set_camera(call, VideoState::On).unwrap();
        net.run(BURAK, actions);
        for (at, burak) in [(AYSE, burak_at_ayse), (CEM, burak_at_cem)] {
            assert!(net.devices[at].shown.iter().any(|a| matches!(
                a,
                Action::VideoStateChanged { from, state: VideoState::On, .. } if *from == burak
            )));
        }

        // Seen first, a frame that is not a key frame cannot be shown: a key frame is asked for.
        let actions = net
            .node(BURAK)
            .send_video(call, false, 0, (640, 360), &[0x40; 500])
            .unwrap();
        net.run(BURAK, actions);
        assert!(shown_video(&net, AYSE, burak_at_ayse).is_empty());
        assert!(shown_video(&net, CEM, burak_at_cem).is_empty());
        assert!(
            net.devices[BURAK]
                .shown
                .iter()
                .any(|a| matches!(a, Action::KeyFrameRequested { id } if *id == call))
        );
        net.devices[BURAK].shown.clear();

        // A key frame in two parts, then a frame that is not one: both shown at Ayşe and at Cem.
        let key = vec![0x65; crate::chat::VIDEO_PART_LEN + 100];
        let actions = net.node(BURAK).send_video(call, true, 0, (640, 360), &key).unwrap();
        assert_eq!(actions.len(), 2, "two parts, to Ayşe only");
        net.run(BURAK, actions);
        let actions = net
            .node(BURAK)
            .send_video(call, false, 0, (640, 360), &[0x41; 900])
            .unwrap();
        net.run(BURAK, actions);
        let expected = [(true, key.len()), (false, 900)];
        assert_eq!(shown_video(&net, AYSE, burak_at_ayse), expected);
        assert_eq!(shown_video(&net, CEM, burak_at_cem), expected, "through Ayşe");

        // Cem's decoder restarts: the key frame he asks for reaches Burak through Ayşe.
        let actions = net.node(CEM).request_member_key_frame(call, burak_at_cem).unwrap();
        net.run(CEM, actions);
        assert!(
            net.devices[BURAK]
                .shown
                .iter()
                .any(|a| matches!(a, Action::KeyFrameRequested { id } if *id == call))
        );
        // Until it comes, Cem skips Burak's frames; Ayşe still shows them.
        let actions = net
            .node(BURAK)
            .send_video(call, false, 0, (640, 360), &[0x42; 700])
            .unwrap();
        net.run(BURAK, actions);
        assert_eq!(shown_video(&net, CEM, burak_at_cem).len(), 2);
        assert_eq!(shown_video(&net, AYSE, burak_at_ayse).len(), 3);
        let actions = net
            .node(BURAK)
            .send_video(call, true, 0, (640, 360), &[0x43; 800])
            .unwrap();
        net.run(BURAK, actions);
        assert_eq!(shown_video(&net, CEM, burak_at_cem).last(), Some(&(true, 800)));

        // Camera off: no more video, and the others hear of it.
        let actions = net.node(BURAK).set_camera(call, VideoState::Off).unwrap();
        net.run(BURAK, actions);
        assert!(
            net.node(BURAK)
                .send_video(call, false, 0, (640, 360), &[1; 10])
                .is_err()
        );
        assert!(net.devices[CEM].shown.iter().any(|a| matches!(
            a,
            Action::VideoStateChanged { from, state: VideoState::Off, .. } if *from == burak_at_cem
        )));
    }

    #[test]
    fn group_files_are_fetched_from_any_member_that_has_them() {
        let mut net = kamp();
        // Larger than what goes through the mesh (§10.10): only links bring it.
        let len = crate::mesh::MAX_MESH_FILE as u32 + 40_000;
        let data: Vec<u8> = (0..len).map(|i| (i * 7 % 251) as u8).collect();
        let row = net.group(BURAK).row;
        let file = net
            .node(BURAK)
            .begin_group_file(row, "harita.pdf", "application/pdf", Some(vec![0xff, 0xd8]))
            .unwrap();
        assert!(net.texts(BURAK).is_empty(), "hidden while written");
        net.node(BURAK).write_file(file, &data).unwrap();
        let (sent, actions) = net.node(BURAK).finish_group_file(file).unwrap();
        assert_eq!(sent.attachment.as_ref().unwrap().size, data.len() as u64);
        net.run(BURAK, actions);
        let offered = |net: &Net, at: usize| {
            let group = net.group(at).row;
            net.devices[at].node.group_messages(group).unwrap().pop().unwrap()
        };
        for at in [AYSE, CEM] {
            let message = offered(&net, at);
            let attachment = message.attachment.unwrap();
            assert_eq!(
                (attachment.name.as_str(), attachment.state),
                ("harita.pdf", AttachmentState::Offered)
            );
        }

        // Cem asks Ayşe, his only link, before she has it: it waits.
        let cem_row = offered(&net, CEM).row;
        let actions = net.node(CEM).download_group_file(cem_row).unwrap();
        net.run(CEM, actions);
        assert_eq!(
            offered(&net, CEM).attachment.unwrap().state,
            AttachmentState::Downloading
        );
        // Ayşe fetches it from Burak, the sender.
        let ayse_row = offered(&net, AYSE).row;
        let actions = net.node(AYSE).download_group_file(ayse_row).unwrap();
        net.run(AYSE, actions);
        assert_eq!(offered(&net, AYSE).attachment.unwrap().state, AttachmentState::Complete);
        // A minute on, Cem asks again and gets it from Ayşe.
        let actions = net.node(CEM).tick(NOW + 120);
        net.run(CEM, actions);
        assert_eq!(offered(&net, CEM).attachment.unwrap().state, AttachmentState::Complete);
        let read = net.devices[CEM]
            .node
            .read_file(group_file(cem_row), 0, data.len())
            .unwrap();
        assert_eq!(read.as_slice(), data.as_slice());
        assert!(
            net.devices[CEM]
                .shown
                .iter()
                .any(|a| matches!(a, Action::GroupMessageUpdated { .. }))
        );
    }

    #[test]
    fn group_voice_messages_arrive_without_asking_and_go_after_playing() {
        let mut net = kamp();
        let data: Vec<u8> = (0..5_000u32).map(|i| (i * 3 % 251) as u8).collect();
        let row = net.group(BURAK).row;
        let file = net
            .node(BURAK)
            .begin_group_file(row, "voice.ogg", crate::storage::VOICE_MIME, None)
            .unwrap();
        net.node(BURAK).write_file(file, &data).unwrap();
        let (_, actions) = net.node(BURAK).finish_group_file(file).unwrap();
        net.run(BURAK, actions);
        let last = |net: &Net, at: usize| {
            let group = net.group(at).row;
            net.devices[at].node.group_messages(group).unwrap().pop().unwrap()
        };
        let message = last(&net, AYSE);
        assert_eq!(
            message.attachment.unwrap().state,
            AttachmentState::Complete,
            "nobody asked"
        );
        let actions = net.node(AYSE).voice_played(group_file(message.row)).unwrap();
        assert!(matches!(actions.as_slice(), [Action::GroupMessageUpdated { .. }]));
        net.node(AYSE).tick(now_secs() + 16 * 60);
        let attachment = last(&net, AYSE).attachment.unwrap();
        assert_eq!((attachment.state, attachment.stored), (AttachmentState::Gone, 0));
    }

    #[test]
    fn muting_a_contact_or_group_silences_it_also_while_locked() {
        let mut net = kamp();
        let (ayse, row) = (net.contact(BURAK, AYSE), net.group(BURAK).row);
        net.node(BURAK).set_group_ptt(row, true).unwrap();
        net.node(BURAK).mute_group(row, i64::MAX).unwrap();
        net.node(BURAK).mute_contact(ayse, i64::MAX).unwrap();
        assert!(net.devices[BURAK].node.group_muted(row) && net.devices[BURAK].node.contact_muted(ayse));
        let summary = net.group(BURAK);
        assert_eq!(summary.muted_until, i64::MAX);
        // The group's push-to-talk does not play while muted.
        let ayse_row = net.group(AYSE).row;
        let (_, actions) = net.node(AYSE).start_group_talk(ayse_row).unwrap();
        net.run(AYSE, actions);
        assert!(
            !net.devices[BURAK]
                .shown
                .iter()
                .any(|a| matches!(a, Action::GroupTalkStarted { .. }))
        );
        // Locked, it still knows; a group message arriving names its group.
        net.devices[BURAK].node.seal();
        assert!(net.devices[BURAK].node.group_muted(row) && net.devices[BURAK].node.contact_muted(ayse));
        net.say(AYSE, "sessiz mi?");
        assert!(
            net.devices[BURAK]
                .shown
                .iter()
                .any(|a| matches!(a, Action::GroupMessageArrived { group: Some(g) } if *g == row))
        );
        let device = &mut net.devices[BURAK];
        let account = Account::unlock_with_pin(device.dir.path(), &device.pin_record, b"123456").unwrap();
        device.node.unseal(account).unwrap();
        net.node(BURAK).mute_group(row, 0).unwrap();
        assert!(!net.devices[BURAK].node.group_muted(row));
    }

    #[test]
    fn temporary_members_go_when_their_time_is_up() {
        let mut net = Net::new(&["Ayşe", "Burak", "Cem"]);
        net.pair(AYSE, BURAK);
        net.pair(AYSE, CEM);
        let contacts = [net.contact(AYSE, BURAK)];
        let (group, actions) = net.node(AYSE).create_group("Kamp", &contacts).unwrap();
        net.run(AYSE, actions);
        let cem = net.contact(AYSE, CEM);
        let until = NOW + 3_600;
        let (_, actions) = net.node(AYSE).add_group_members(group.row, &[cem], until).unwrap();
        net.run(AYSE, actions);
        net.link(AYSE, BURAK);
        net.link(AYSE, CEM);
        net.say(BURAK, "Selam");
        assert_eq!(net.texts(CEM), ["Selam"]);
        let members = net.devices[CEM].node.group_members(net.group(CEM).row).unwrap();
        assert!(members.iter().any(|m| m.me && m.expires == until));

        net.now = until + 1;
        let actions = net.node(CEM).tick(until + 1);
        net.run(CEM, actions);
        assert_eq!(net.group(CEM).membership, Membership::Removed);
        assert!(net.texts(CEM).is_empty(), "the content is deleted");
        let actions = net.node(AYSE).tick(until + 1);
        net.run(AYSE, actions);
        let ayse = net.group(AYSE);
        assert_eq!((ayse.epoch, ayse.members), (2, 2));
        assert_eq!(net.group(BURAK).members, 2);
    }
}
