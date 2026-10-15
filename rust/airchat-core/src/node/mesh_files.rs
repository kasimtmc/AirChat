//! Files through the mesh (rust/airchat-protocol/docs/protocol.md §10.8): a file's offer goes in an envelope like a
//! text, and a small file's content in part envelopes encrypted with a key the offer carries. The
//! recipient puts the parts into the file in order, as chunks of a download, and acknowledges the
//! offer once the file is whole.

use std::collections::{BTreeMap, HashMap, VecDeque};

use zeroize::Zeroizing;

use super::{Action, ConnectionId, Download, Node, Store, mesh::FROM_MESH, now_ms, now_secs, stored_hash};
use crate::{
    chat::{self, ChatMessage},
    crypto::{SecretBytes, random},
    group::{self, GroupId},
    inbox::InboxEvent,
    link::epoch_at,
    mesh::{self, Envelope, EnvelopeId, FILE_PART_LEN, Header, MAX_HOPS, MAX_LIFETIME_MINUTES, MAX_MESH_FILE, NO_DROP},
    storage::{
        Attachment, AttachmentState, ContactId, FileMeta, MessageId, StoredMessage,
        files::{CHUNK_LEN, chunk_count},
        groups::group_file,
    },
};

/// Parts held before their offer is taken (or while locked), at most; still encrypted.
const MAX_PENDING_BYTES: usize = 2 << 20;
/// This device's own parts go into the mesh at most this fast, and in bursts of at most
/// `BURST_BYTES`: well within what a relay passes on for one neighbour (§10.4).
const PARTS_PER_SEC: usize = 32 * 1024;
const BURST_BYTES: usize = 10 * PARTS_PER_SEC;
/// Own parts waiting to go, at most; more go when the next neighbour comes.
const MAX_QUEUED_BYTES: usize = 8 << 20;

// A part is one storage chunk, so parts go into the file as downloaded chunks do.
const _: () = assert!(FILE_PART_LEN == CHUNK_LEN);

type Sends = Vec<(ConnectionId, ChatMessage)>;

/// Whose file parts are: a contact's (§10.8), acknowledged once the file is whole, or a group's
/// (§10.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    Contact(ContactId),
    Group,
}

/// A file whose parts come through the mesh.
struct Incoming {
    source: Source,
    message: MessageId,
    key: SecretBytes<32>,
    /// Parts opened that cannot go into the file yet, by index.
    waiting: BTreeMap<u32, Zeroizing<Vec<u8>>>,
}

#[derive(Default)]
pub(crate) struct MeshFiles {
    /// Parts for this device that cannot be opened yet, still encrypted.
    pending: HashMap<EnvelopeId, Envelope>,
    pending_bytes: usize,
    /// Files being put together, by file (a message row, or a group file's, see `group_file`).
    incoming: HashMap<i64, Incoming>,
    /// The file and part index of each part id expected.
    expected: HashMap<EnvelopeId, (i64, u32)>,
    /// Files whose content came through the mesh that are whole now, to acknowledge.
    whole: Vec<(ContactId, MessageId)>,
    /// This device's own parts waiting to go into the mesh, in order.
    queue: VecDeque<Envelope>,
    queued_bytes: usize,
    /// What may go now, and when that was worked out.
    budget: usize,
    budget_at: u64,
}

impl MeshFiles {
    /// The account was locked: files are put together again after the next unlock.
    pub(super) fn sealed(&mut self) {
        self.incoming.clear();
        self.expected.clear();
        self.whole.clear();
    }

    fn hold(&mut self, envelope: &Envelope) {
        let len = envelope.body.len();
        if self.pending.contains_key(&envelope.id) || self.pending_bytes + len > MAX_PENDING_BYTES {
            return;
        }
        self.pending_bytes += len;
        self.pending.insert(envelope.id, envelope.clone());
    }

    fn take_pending(&mut self, id: &EnvelopeId) -> Option<Envelope> {
        let envelope = self.pending.remove(id)?;
        self.pending_bytes -= envelope.body.len();
        Some(envelope)
    }

    /// Forgets held parts that expired.
    fn expire(&mut self, now_secs: u64) {
        let now_minute = u32::try_from(now_secs / 60).unwrap_or(u32::MAX);
        self.pending.retain(|_, envelope| envelope.expires > now_minute);
        self.pending_bytes = self.pending.values().map(|envelope| envelope.body.len()).sum();
        self.queue.retain(|envelope| envelope.expires > now_minute);
        self.queued_bytes = self.queue.iter().map(|envelope| envelope.body.len()).sum();
    }

    fn queued(&self, id: &EnvelopeId) -> bool {
        self.queue.iter().any(|envelope| envelope.id == *id)
    }

    fn unqueue(&mut self, ids: &[EnvelopeId]) {
        self.queue.retain(|envelope| !ids.contains(&envelope.id));
        self.queued_bytes = self.queue.iter().map(|envelope| envelope.body.len()).sum();
    }

    /// Own parts that may go now.
    fn release(&mut self, now_secs: u64) -> Vec<Envelope> {
        let elapsed = usize::try_from(now_secs.saturating_sub(self.budget_at)).unwrap_or(usize::MAX);
        self.budget = self
            .budget
            .saturating_add(elapsed.saturating_mul(PARTS_PER_SEC))
            .min(BURST_BYTES);
        self.budget_at = now_secs;
        let mut released = Vec::new();
        while let Some(len) = self.queue.front().map(|envelope| envelope.body.len())
            && len <= self.budget
            && let Some(envelope) = self.queue.pop_front()
        {
            self.budget -= len;
            self.queued_bytes -= len;
            released.push(envelope);
        }
        released
    }

    #[cfg(test)]
    pub(super) fn queued_count(&self) -> usize {
        self.queue.len()
    }
}

/// Whether a file's content goes through the mesh with its offer.
pub(super) fn content_through_mesh(size: u64) -> bool {
    size <= MAX_MESH_FILE
}

impl Node {
    // Sending.

    /// An outgoing file's offer as it goes into the mesh, with the key of its parts if its content
    /// goes too (made the first time, kept until the file is answered). `None` while locked.
    fn mesh_file_offer(&self, message: &StoredMessage) -> Option<(ChatMessage, Option<SecretBytes<32>>)> {
        let Store::Open(account) = &self.store else {
            return None;
        };
        let attachment = message.attachment.as_ref()?;
        let key = match content_through_mesh(attachment.size) {
            true => match account.db().mesh_key(message.id).ok()? {
                Some(key) => Some(key),
                None => {
                    let key = Zeroizing::new(random::array::<32>().ok()?);
                    account.db().set_mesh_key(message.id, Some(&key)).ok()?;
                    Some(key)
                }
            },
            false => None,
        };
        let offer = ChatMessage::MeshFileOffer {
            id: message.message_id,
            sent_at_ms: u64::try_from(message.sent_at_ms).unwrap_or(0),
            key: key.clone().unwrap_or_else(|| Zeroizing::new([0; 32])),
            meta: FileMeta {
                name: attachment.name.clone(),
                mime: attachment.mime.clone(),
                size: attachment.size,
                sha256: attachment.sha256,
                thumbnail: attachment.thumbnail.clone(),
            },
        };
        let key = match key {
            Some(key) => Some(SecretBytes::from_slice(&key[..]).ok()?),
            None => None,
        };
        Some((offer, key))
    }

    /// Queues the parts of an outgoing file that are neither queued, held nor withdrawn.
    fn queue_file_parts(
        &mut self,
        contact: ContactId,
        message: &StoredMessage,
        key: &SecretBytes<32>,
        expires: u32,
        now_secs: u64,
    ) {
        let Store::Open(account) = &self.store else {
            return;
        };
        let (Some(attachment), Some(keys)) = (message.attachment.as_ref(), self.keys.contacts.get(&contact)) else {
            return;
        };
        let Some(psk) = &keys.pairing_psk else {
            return;
        };
        let me = &self.keys.identity;
        let Ok(tag_key) = mesh::file_tag_key(psk, me, &keys.identity) else {
            return;
        };
        let tag = mesh::tag(&tag_key, epoch_at(now_secs));
        for index in 0..mesh::file_parts(attachment.size) {
            let id = mesh::file_part_id(me, &keys.identity, &message.message_id, index);
            if self.mesh_files.queued(&id) || self.mesh.withdrawn(&id) || self.mesh.holds(&id) {
                continue;
            }
            if self.mesh_files.queued_bytes >= MAX_QUEUED_BYTES {
                return;
            }
            let Ok(bytes) = account.read_file_chunk(message.id, attachment.size, u64::from(index)) else {
                return;
            };
            let Ok(secret) = mesh::drop_secret(psk, me, &keys.identity, &id) else {
                return;
            };
            let header = Header {
                id,
                expires,
                tag,
                drop: mesh::drop_tag(&secret),
            };
            let Ok(body) = mesh::seal_part(key, &header, index, &bytes) else {
                return;
            };
            self.mesh_files.queued_bytes += body.len();
            self.mesh_files.queue.push_back(Envelope {
                id,
                hops: MAX_HOPS,
                expires,
                tag,
                drop: header.drop,
                body,
            });
        }
    }

    /// A file for a contact no Wi-Fi link reaches goes into the mesh: its offer now, and its
    /// parts if small, paced. Empty without mesh neighbours.
    pub(super) fn mesh_send_file(&mut self, contact: ContactId, message: &StoredMessage, now_secs: u64) -> Sends {
        if self.mesh.neighbours() == 0 {
            return Vec::new();
        }
        let Some(offer) = self.mesh_file_envelope(contact, message, now_secs) else {
            return Vec::new();
        };
        let mut sends = self.mesh_send_envelope(offer, now_secs);
        sends.extend(self.release_parts(now_secs));
        sends
    }

    /// An outgoing file's offer envelope, with its parts queued.
    pub(super) fn mesh_file_envelope(
        &mut self,
        contact: ContactId,
        message: &StoredMessage,
        now_secs: u64,
    ) -> Option<Envelope> {
        let (offer, key) = self.mesh_file_offer(message)?;
        let expires = super::try_expires(message);
        let envelope = self.contact_envelope(contact, &offer, expires, now_secs)?;
        if let Some(key) = key {
            self.queue_file_parts(contact, message, &key, expires, now_secs);
        }
        Some(envelope)
    }

    /// Own parts that may go now, to every mesh neighbour.
    pub(super) fn release_parts(&mut self, now_secs: u64) -> Sends {
        if self.mesh.neighbours() == 0 {
            return Vec::new();
        }
        let mut sends = Vec::new();
        for part in self.mesh_files.release(now_secs) {
            sends.extend(self.mesh_send_envelope(part, now_secs));
        }
        sends
    }

    /// The contact answered message `id`: if it is an outgoing file, the key of its parts goes
    /// and they stop going. Returns the ids of the file's envelopes, its offer's first; `None` if
    /// it is no outgoing file (or the account is locked).
    pub(super) fn file_answered(&mut self, contact: ContactId, id: &MessageId) -> Option<Vec<EnvelopeId>> {
        let Store::Open(account) = &self.store else {
            return None;
        };
        let keys = self.keys.contacts.get(&contact)?;
        let message = account.message_by_id(contact, id).ok()??;
        let attachment = message.attachment.as_ref().filter(|_| message.outgoing)?;
        let _ = account.db().set_mesh_key(message.id, None);
        let (me, them) = (&self.keys.identity, &keys.identity);
        let mut ids = vec![mesh::contact_envelope_id(me, them, chat::KIND_MESH_FILE_OFFER, id)];
        if content_through_mesh(attachment.size) {
            let parts: Vec<EnvelopeId> = (0..mesh::file_parts(attachment.size))
                .map(|i| mesh::file_part_id(me, them, id, i))
                .collect();
            self.mesh_files.unqueue(&parts);
            ids.extend(parts);
        }
        Some(ids)
    }

    // Receiving.

    /// A mesh file offer from a contact, sealed to `prekey` (§10.8): taken as an offer over a
    /// link, and its content put together from parts.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn take_mesh_file_offer(
        &mut self,
        contact: ContactId,
        id: MessageId,
        sent_at_ms: u64,
        key: Zeroizing<[u8; 32]>,
        meta: FileMeta,
        prekey: u32,
        now_secs: u64,
    ) -> (Vec<Action>, Sends) {
        if !self.accepts_messages_from(contact) {
            self.prekey_used(contact, prekey);
            return (Vec::new(), self.answer(contact, ChatMessage::Refused { id }, now_secs));
        }
        let with_content = *key != [0; 32] && content_through_mesh(meta.size);
        let sent_at_ms = i64::try_from(sent_at_ms).unwrap_or(i64::MAX);
        let mut actions = Vec::new();
        let row = match &mut self.store {
            Store::Open(account) => {
                // Not stored: no acknowledgement, and the prekey stays for the sender's next try.
                let Ok(arrived) = account.store_incoming_file(contact, &id, &meta, sent_at_ms) else {
                    return (Vec::new(), Vec::new());
                };
                let new = arrived.is_some();
                let Some(mut message) = arrived.or_else(|| account.message_by_id(contact, &id).ok().flatten()) else {
                    return (Vec::new(), Vec::new());
                };
                let state = message.attachment.as_ref().map(|a| a.state);
                // Its content comes now, whatever the auto-download: parts cannot be asked for.
                let comes =
                    with_content && matches!(state, Some(AttachmentState::Offered | AttachmentState::Downloading));
                if comes {
                    let key_kept = match account.db().mesh_key(message.id) {
                        Ok(Some(_)) => true,
                        Ok(None) => account.db().set_mesh_key(message.id, Some(&key)).is_ok(),
                        Err(_) => false,
                    };
                    if !key_kept {
                        return (Vec::new(), Vec::new());
                    }
                    if state == Some(AttachmentState::Offered)
                        && let Ok(updated) = account.update_attachment(message.id, 0, AttachmentState::Downloading)
                    {
                        if !new {
                            actions.push(Action::MessageUpdated {
                                message: updated.clone(),
                            });
                        }
                        message = updated;
                    }
                }
                let row = message.id;
                if new {
                    actions.push(Action::MessageReceived { message });
                }
                self.prekey_used(contact, prekey);
                if !comes {
                    // Whole already, or its content comes another way.
                    let answer = match state == Some(AttachmentState::Complete) || !with_content {
                        true => self.answer(contact, ChatMessage::Ack { id }, now_secs),
                        false => Vec::new(),
                    };
                    return (actions, answer);
                }
                row
            }
            Store::Sealed(sealed) => {
                if !sealed.stored.contains(&(contact, id)) {
                    let event = InboxEvent::File {
                        contact,
                        id,
                        sent_at_ms,
                        received_at_ms: now_ms(),
                        meta,
                        mesh_key: with_content.then(|| key.clone()),
                    };
                    if sealed.inbox.append(&event).is_err() {
                        return (Vec::new(), Vec::new());
                    }
                    sealed.stored.insert((contact, id));
                    actions.push(Action::MessageArrived { contact });
                }
                self.prekey_used(contact, prekey);
                // One with content is acknowledged once whole, after the unlock.
                let answer = match with_content {
                    true => Vec::new(),
                    false => self.answer(contact, ChatMessage::Ack { id }, now_secs),
                };
                return (actions, answer);
            }
        };
        let (more, sends) = self.put_together(row, contact, id, &key, now_secs);
        actions.extend(more);
        (actions, sends)
    }

    /// Starts putting a contact's file together from its parts.
    fn put_together(
        &mut self,
        row: i64,
        contact: ContactId,
        message: MessageId,
        key: &[u8; 32],
        now_secs: u64,
    ) -> (Vec<Action>, Sends) {
        let Store::Open(account) = &self.store else {
            return (Vec::new(), Vec::new());
        };
        let Some(attachment) = account.message(row).ok().flatten().and_then(|m| m.attachment) else {
            return (Vec::new(), Vec::new());
        };
        let (Some(keys), Ok(key)) = (self.keys.contacts.get(&contact), SecretBytes::from_slice(key)) else {
            return (Vec::new(), Vec::new());
        };
        let (them, me) = (keys.identity, self.keys.identity);
        let part = |index| mesh::file_part_id(&them, &me, &message, index);
        let incoming = Incoming {
            source: Source::Contact(contact),
            message,
            key,
            waiting: BTreeMap::new(),
        };
        self.put_together_parts(row, incoming, &attachment, part, now_secs)
    }

    /// Starts putting `file` together from its parts, named by `part` (their index): those that
    /// came before go in at once. A file fetched over a link meanwhile goes on there.
    fn put_together_parts(
        &mut self,
        file: i64,
        incoming: Incoming,
        attachment: &Attachment,
        part: impl Fn(u32) -> EnvelopeId,
        now_secs: u64,
    ) -> (Vec<Action>, Sends) {
        let Store::Open(account) = &self.store else {
            return (Vec::new(), Vec::new());
        };
        let source = match incoming.source {
            Source::Contact(contact) => contact,
            Source::Group => FROM_MESH,
        };
        let download = self.downloads.entry(file).or_insert_with(|| {
            let (hasher, stored) = stored_hash(account, file, attachment.size, attachment.stored);
            Download {
                contact: source,
                file_id: incoming.message,
                size: attachment.size,
                sha256: attachment.sha256,
                stored,
                requested_until: chunk_count(stored),
                hasher,
                not_now_since: None,
            }
        });
        let first = u32::try_from(chunk_count(download.stored)).unwrap_or(u32::MAX);
        let mut held = Vec::new();
        for index in first..mesh::file_parts(attachment.size) {
            let id = part(index);
            self.mesh_files.expected.insert(id, (file, index));
            // Held until it could be opened, or, if that was full, among what this device passes on.
            held.extend(
                self.mesh_files
                    .take_pending(&id)
                    .or_else(|| self.mesh.held_envelope(&id)),
            );
        }
        self.mesh_files.incoming.insert(file, incoming);
        for envelope in held {
            self.open_file_part(&envelope);
        }
        self.feed(file, now_secs)
    }

    /// Whether `id` is a part this device still needs: taken even if seen before, as it may have
    /// been lost before it could be placed.
    pub(super) fn expects_part(&self, id: &EnvelopeId) -> bool {
        self.mesh_files.expected.contains_key(id)
    }

    /// A file part for this device: into its file, or held until it can be opened.
    pub(super) fn take_file_part(&mut self, envelope: &Envelope, now_secs: u64) -> (Vec<Action>, Sends) {
        match self.mesh_files.expected.get(&envelope.id).copied() {
            Some((row, _)) => {
                self.open_file_part(envelope);
                self.feed(row, now_secs)
            }
            None => {
                self.mesh_files.hold(envelope);
                (Vec::new(), Vec::new())
            }
        }
    }

    fn open_file_part(&mut self, envelope: &Envelope) {
        let Some(&(row, index)) = self.mesh_files.expected.get(&envelope.id) else {
            return;
        };
        let Some(incoming) = self.mesh_files.incoming.get_mut(&row) else {
            return;
        };
        let opened = match incoming.source {
            Source::Contact(_) => mesh::open_part(&incoming.key, envelope, index),
            Source::Group => mesh::open_group_file_part(&incoming.key, envelope, index),
        };
        if let Ok(bytes) = opened {
            incoming.waiting.insert(index, bytes);
            self.mesh_files.expected.remove(&envelope.id);
        }
    }

    /// Writes the parts that are next in order. A file done (whole, or failed) is no longer put
    /// together; a whole one is acknowledged.
    fn feed(&mut self, row: i64, now_secs: u64) -> (Vec<Action>, Sends) {
        let mut actions = Vec::new();
        while let Some(download) = self.downloads.get(&row) {
            if download.stored == download.size {
                actions.extend(self.complete_download(row));
                break;
            }
            let next = chunk_count(download.stored);
            let Some(incoming) = self.mesh_files.incoming.get_mut(&row) else {
                break;
            };
            // Parts that came another way meanwhile (over a link) are no more use.
            while incoming
                .waiting
                .first_key_value()
                .is_some_and(|(i, _)| u64::from(*i) < next)
            {
                incoming.waiting.pop_first();
            }
            let Some(bytes) = u32::try_from(next).ok().and_then(|i| incoming.waiting.remove(&i)) else {
                break;
            };
            let (contact, message) = (download.contact, incoming.message);
            // Requests are for links: parts are not asked for.
            actions.extend(self.on_chunk(contact, &message, next, &bytes).0);
        }
        if !self.downloads.contains_key(&row) {
            self.mesh_file_done(row, false);
        }
        (actions, self.acknowledge_whole(now_secs))
    }

    /// A file's download ended, `whole` or not: if it came through the mesh, it is put together
    /// no more; a contact's key goes, and a whole one is acknowledged.
    pub(super) fn mesh_file_done(&mut self, file: i64, whole: bool) {
        let Some(incoming) = self.mesh_files.incoming.remove(&file) else {
            return;
        };
        self.mesh_files.expected.retain(|_, (f, _)| *f != file);
        let Source::Contact(contact) = incoming.source else {
            return;
        };
        if let Store::Open(account) = &self.store {
            let _ = account.db().set_mesh_key(file, None);
        }
        if whole {
            self.mesh_files.whole.push((contact, incoming.message));
        }
    }

    /// Whether `file` is being put together from mesh parts (a link may bring the rest).
    pub(super) fn mesh_fed(&self, file: i64) -> bool {
        self.mesh_files.incoming.contains_key(&file)
    }

    fn acknowledge_whole(&mut self, now_secs: u64) -> Sends {
        let mut sends = Vec::new();
        for (contact, id) in std::mem::take(&mut self.mesh_files.whole) {
            sends.extend(self.answer(contact, ChatMessage::Ack { id }, now_secs));
        }
        sends
    }

    /// After the account opens or unlocks: files whose content comes through the mesh are put
    /// together again, with the parts that came meanwhile (a contact's key is in storage, a
    /// group's comes from the epoch key).
    pub(super) fn resume_mesh_files(&mut self, now_secs: u64) -> Vec<Action> {
        let Store::Open(account) = &self.store else {
            return Vec::new();
        };
        let mut files = Vec::new();
        for &contact in self.keys.contacts.keys() {
            for message in account.downloading(contact).unwrap_or_default() {
                if let Ok(Some(key)) = account.db().mesh_key(message.id) {
                    files.push((message.id, contact, message.message_id, key));
                }
            }
        }
        let group_files: Vec<i64> = account
            .db()
            .group_downloading()
            .unwrap_or_default()
            .iter()
            .map(|m| m.row)
            .collect();
        let mut actions = Vec::new();
        for (row, contact, message, key) in files {
            let (more, sends) = self.put_together(row, contact, message, &key, now_secs);
            actions.extend(more);
            actions.extend(self.mesh_sends(sends, None));
        }
        for row in group_files {
            actions.extend(self.mesh_fetch_group_file(row, now_secs));
        }
        actions
    }

    // Group files (§10.10).

    /// The group id, the key of the parts and the key of their tags of group file message `row`,
    /// from its sealed message and the epoch keys held.
    fn group_file_keys(&self, row: i64) -> Option<(GroupId, SecretBytes<32>, SecretBytes<32>)> {
        let Store::Open(account) = &self.store else {
            return None;
        };
        let db = account.db();
        let sealed = db.group_message_sealed(row).ok()??;
        let message = group::Message::read(&sealed).ok()?;
        let stored = db.group_by_id(&message.group_id).ok()??;
        let (epoch_key, _) = stored.epoch(message.epoch)?;
        let key = mesh::group_file_key(epoch_key, &message.group_id, message.epoch, &message.message_id).ok()?;
        let tag_key = mesh::group_file_tag_key(epoch_key, &message.group_id, message.epoch).ok()?;
        Some((message.group_id, key, tag_key))
    }

    /// A group file message taken from the mesh, or a group file being fetched: a file of at most
    /// 1 MiB is put together from mesh parts too. One offered is fetched now, whatever the
    /// auto-download, as its parts cannot be asked for.
    pub(super) fn mesh_fetch_group_file(&mut self, row: i64, now_secs: u64) -> Vec<Action> {
        let file = group_file(row);
        if self.mesh_files.incoming.contains_key(&file) {
            return Vec::new();
        }
        let Some((group_id, key, _)) = self.group_file_keys(row) else {
            return Vec::new();
        };
        let Store::Open(account) = &self.store else {
            return Vec::new();
        };
        let db = account.db();
        let Some(message) = db.group_message(row).ok().flatten().filter(|m| !m.outgoing) else {
            return Vec::new();
        };
        let Some(attachment) = message.attachment.as_ref().filter(|a| content_through_mesh(a.size)) else {
            return Vec::new();
        };
        let mut actions = Vec::new();
        let attachment = match attachment.state {
            AttachmentState::Downloading => attachment.clone(),
            AttachmentState::Offered => {
                match db.update_group_attachment(row, attachment.stored, AttachmentState::Downloading) {
                    Ok(updated) => {
                        let Some(attachment) = updated.attachment.clone() else {
                            return Vec::new();
                        };
                        actions.push(Action::GroupMessageUpdated { message: updated });
                        attachment
                    }
                    Err(_) => return Vec::new(),
                }
            }
            _ => return Vec::new(),
        };
        let message_id = message.message_id;
        let part = |index| mesh::group_file_part_id(&group_id, &message_id, index);
        let incoming = Incoming {
            source: Source::Group,
            message: message_id,
            key,
            waiting: BTreeMap::new(),
        };
        let (more, sends) = self.put_together_parts(file, incoming, &attachment, part, now_secs);
        actions.extend(more);
        actions.extend(self.mesh_sends(sends, None));
        actions
    }

    /// Queues the parts of this device's group file `row` that are neither queued, held nor
    /// withdrawn.
    pub(super) fn queue_group_file_parts(&mut self, row: i64, now_secs: u64) {
        let Some((group_id, key, tag_key)) = self.group_file_keys(row) else {
            return;
        };
        let Store::Open(account) = &self.store else {
            return;
        };
        let Some(message) = account.db().group_message(row).ok().flatten().filter(|m| m.outgoing) else {
            return;
        };
        let Some(attachment) = message
            .attachment
            .filter(|a| a.state == AttachmentState::Complete && content_through_mesh(a.size))
        else {
            return;
        };
        let tag = mesh::tag(&tag_key, epoch_at(now_secs));
        let expires = u32::try_from(message.stored_at_ms / 60_000)
            .unwrap_or(0)
            .saturating_add(MAX_LIFETIME_MINUTES);
        let file = group_file(row);
        for index in 0..mesh::file_parts(attachment.size) {
            let id = mesh::group_file_part_id(&group_id, &message.message_id, index);
            if self.mesh_files.queued(&id) || self.mesh.withdrawn(&id) || self.mesh.holds(&id) {
                continue;
            }
            if self.mesh_files.queued_bytes >= MAX_QUEUED_BYTES {
                return;
            }
            let Ok(bytes) = account.read_file_chunk(file, attachment.size, u64::from(index)) else {
                return;
            };
            let Ok(body) = mesh::seal_group_file_part(&key, &id, index, &bytes) else {
                return;
            };
            self.mesh_files.queued_bytes += body.len();
            self.mesh_files.queue.push_back(Envelope {
                id,
                hops: MAX_HOPS,
                expires,
                tag,
                drop: NO_DROP,
                body,
            });
        }
    }

    /// This device's group file `row` sends its parts into the mesh, paced.
    pub(super) fn mesh_send_group_file(&mut self, row: i64) -> Vec<Action> {
        if self.mesh.neighbours() == 0 {
            return Vec::new();
        }
        let now = now_secs();
        self.queue_group_file_parts(row, now);
        let sends = self.release_parts(now);
        self.mesh_sends(sends, None)
    }

    /// Every tick: own parts go on, and files made whole over a link are acknowledged.
    pub(super) fn mesh_files_tick(&mut self, now_secs: u64) -> Vec<Action> {
        self.mesh_files.expire(now_secs);
        let mut sends = self.release_parts(now_secs);
        sends.extend(self.acknowledge_whole(now_secs));
        self.mesh_sends(sends, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        account::Account,
        chat::MAX_THUMBNAIL_BYTES,
        mesh::STATIC_KEY,
        node::{
            groups::tests::Net,
            mesh::tests::{cut_mesh, mesh_link},
            now_secs,
        },
        storage::{Attachment, MessageStatus},
    };

    const AYSE: usize = 0;
    const BURAK: usize = 1;
    const CEM: usize = 2;

    /// Ayşe and Cem met (and handed each other prekeys), then went apart; Burak, who knows
    /// neither, can come between them.
    fn apart() -> Net {
        let mut net = Net::new(&["Ayşe", "Burak", "Cem"]);
        net.pair(AYSE, CEM);
        net.link(AYSE, CEM);
        net.cut(AYSE, CEM);
        net
    }

    fn bridged() -> Net {
        let mut net = apart();
        mesh_link(&mut net, AYSE, BURAK);
        mesh_link(&mut net, BURAK, CEM);
        net
    }

    fn sample(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 13 + i / 241) as u8).collect()
    }

    fn send_file_named(net: &mut Net, data: &[u8], name: &str, thumbnail: Vec<u8>) -> StoredMessage {
        let node = net.node(AYSE);
        // Cem is Ayşe's one contact (and may be locked).
        let cem = *node.keys.contacts.keys().next().unwrap();
        let file = node.begin_file(cem, name, "image/png", Some(thumbnail)).unwrap();
        for part in data.chunks(10_000) {
            node.write_file(file, part).unwrap();
        }
        let (message, actions) = node.finish_file(file).unwrap();
        net.run(AYSE, actions);
        message
    }

    /// Ayşe sends Cem a file.
    fn send_file(net: &mut Net, data: &[u8]) -> StoredMessage {
        send_file_named(net, data, "harita.png", vec![2; 64])
    }

    /// The last file message device `at` has with device `of`.
    fn last_file(net: &mut Net, at: usize, of: usize) -> (StoredMessage, Attachment) {
        let contact = net.contact(at, of);
        let message = net
            .node(at)
            .messages(contact)
            .unwrap()
            .into_iter()
            .rev()
            .find(|m| m.attachment.is_some())
            .expect("a file message");
        let attachment = message.attachment.clone().unwrap();
        (message, attachment)
    }

    fn content(net: &mut Net, at: usize, row: i64, len: usize) -> Vec<u8> {
        net.node(at).read_file(row, 0, len).unwrap().to_vec()
    }

    fn mesh_key(net: &mut Net, at: usize, row: i64) -> Option<Zeroizing<[u8; 32]>> {
        net.node(at).account().unwrap().db().mesh_key(row).unwrap()
    }

    fn unseal(net: &mut Net, at: usize) {
        let device = &mut net.devices[at];
        let account = Account::unlock_with_pin(device.dir.path(), &device.pin_record, b"123456").unwrap();
        let actions = device.node.unseal(account).unwrap();
        net.run(at, actions);
    }

    /// The id of the envelope Ayşe's offer of `message` goes in.
    fn offer_envelope(net: &Net, message: &MessageId) -> EnvelopeId {
        let (ayse, cem) = (net.identity(AYSE), net.identity(CEM));
        mesh::contact_envelope_id(&ayse, &cem, chat::KIND_MESH_FILE_OFFER, message)
    }

    #[test]
    fn a_small_file_crosses_the_mesh_and_is_acknowledged_once_whole() {
        let mut net = bridged();
        let data = sample(100_000);
        let sent = send_file(&mut net, &data);
        assert_eq!(sent.status, MessageStatus::Sent, "handed to the mesh");
        let (received, attachment) = last_file(&mut net, CEM, AYSE);
        assert_eq!(attachment.state, AttachmentState::Complete);
        assert_eq!(content(&mut net, CEM, received.id, data.len()), data);
        assert_eq!(last_file(&mut net, AYSE, CEM).0.status, MessageStatus::Delivered);
        assert!(
            net.node(BURAK).mesh.held_envelopes().is_empty(),
            "the offer, its parts and the acknowledgement were withdrawn"
        );
        assert!(mesh_key(&mut net, AYSE, sent.id).is_none(), "keys go once answered");
        assert!(mesh_key(&mut net, CEM, received.id).is_none());
        assert!(net.node(CEM).mesh_files.incoming.is_empty() && net.node(CEM).mesh_files.expected.is_empty());
        assert!(net.node(BURAK).keys.contacts.is_empty(), "the relay learned no one");
    }

    #[test]
    fn a_large_files_offer_crosses_without_its_content() {
        let mut net = bridged();
        let data = sample(MAX_MESH_FILE as usize + 1);
        // The largest offer still fits in an envelope.
        let name = "ç".repeat(127);
        send_file_named(&mut net, &data, &name, vec![3; MAX_THUMBNAIL_BYTES]);
        assert_eq!(net.node(AYSE).mesh_files.queued_count(), 0, "no parts");
        let (received, attachment) = last_file(&mut net, CEM, AYSE);
        assert_eq!(attachment.name, name);
        assert_eq!(
            attachment.state,
            AttachmentState::Offered,
            "fetched over a link, when asked"
        );
        assert!(mesh_key(&mut net, CEM, received.id).is_none());
        assert_eq!(last_file(&mut net, AYSE, CEM).0.status, MessageStatus::Delivered);
        assert!(net.node(BURAK).mesh.held_envelopes().is_empty());
    }

    #[test]
    fn a_locked_recipient_puts_the_file_together_after_unlocking() {
        let mut net = bridged();
        let cem = net.contact(AYSE, CEM);
        net.node(CEM).seal();
        let data = sample(40_000);
        let sent = send_file(&mut net, &data);
        assert_eq!(
            net.node(AYSE).messages(cem).unwrap()[0].status,
            MessageStatus::Sent,
            "not acknowledged before it is whole"
        );
        assert_eq!(net.node(CEM).mesh_files.pending.len(), 3, "its parts wait, encrypted");
        unseal(&mut net, CEM);
        let (received, attachment) = last_file(&mut net, CEM, AYSE);
        assert_eq!(attachment.state, AttachmentState::Complete);
        assert_eq!(content(&mut net, CEM, received.id, data.len()), data);
        assert!(net.node(CEM).mesh_files.pending.is_empty());
        assert_eq!(last_file(&mut net, AYSE, CEM).0.status, MessageStatus::Delivered);
        assert!(mesh_key(&mut net, AYSE, sent.id).is_none());
    }

    /// Ayşe sends a file while only Burak is around; Burak then meets Cem, who is locked: Burak
    /// passes on the newest first, so the parts come before their offer.
    fn parts_first(net: &mut Net, data: &[u8]) -> StoredMessage {
        mesh_link(net, AYSE, BURAK);
        let sent = send_file(net, data);
        let held = net.node(BURAK).mesh.held_envelopes();
        assert_eq!(held.len(), 1 + data.len().div_ceil(FILE_PART_LEN));
        assert_ne!(
            mesh::sealed_to(&held[0]).unwrap(),
            STATIC_KEY,
            "the offer is sealed to a prekey"
        );
        cut_mesh(net, AYSE, BURAK);
        net.node(CEM).seal();
        mesh_link(net, BURAK, CEM);
        assert_eq!(net.node(CEM).mesh_files.pending.len(), held.len() - 1);
        sent
    }

    #[test]
    fn parts_a_recipient_could_not_keep_are_taken_from_what_it_passes_on() {
        let mut net = apart();
        let data = sample(50_000);
        parts_first(&mut net, &data);
        // More came than it could keep: the parts are among what it passes on still.
        let files = &mut net.node(CEM).mesh_files;
        files.pending.clear();
        files.pending_bytes = 0;
        unseal(&mut net, CEM);
        let (received, attachment) = last_file(&mut net, CEM, AYSE);
        assert_eq!(attachment.state, AttachmentState::Complete);
        assert_eq!(content(&mut net, CEM, received.id, data.len()), data);
    }

    #[test]
    fn parts_lost_before_they_were_placed_are_taken_when_they_come_again() {
        let mut net = apart();
        let data = sample(50_000);
        let sent = parts_first(&mut net, &data);
        let files = &mut net.node(CEM).mesh_files;
        files.pending.clear();
        files.pending_bytes = 0;
        net.node(CEM).mesh.drop_held();
        unseal(&mut net, CEM);
        let (received, attachment) = last_file(&mut net, CEM, AYSE);
        assert_eq!(attachment.state, AttachmentState::Downloading);
        assert_eq!(attachment.stored, 0);
        let ayse = net.contact(CEM, AYSE);
        let offer = offer_envelope(&net, &sent.message_id);
        assert_eq!(
            net.node(CEM).received_in(ayse, &offer),
            None,
            "not whole: no acknowledgement"
        );
        // Burak, who still holds them, comes again: Cem has seen them, but needs them.
        cut_mesh(&mut net, BURAK, CEM);
        mesh_link(&mut net, BURAK, CEM);
        let (_, attachment) = last_file(&mut net, CEM, AYSE);
        assert_eq!(attachment.state, AttachmentState::Complete);
        assert_eq!(content(&mut net, CEM, received.id, data.len()), data);
        assert_eq!(
            net.node(CEM).received_in(ayse, &offer),
            Some(sent.message_id),
            "a resend is acknowledged again"
        );
        // Burak carries the acknowledgement back to Ayşe.
        mesh_link(&mut net, AYSE, BURAK);
        assert_eq!(last_file(&mut net, AYSE, CEM).0.status, MessageStatus::Delivered);
    }

    #[test]
    fn a_files_parts_go_into_the_mesh_paced() {
        let mut net = bridged();
        let data = sample(MAX_MESH_FILE as usize);
        send_file(&mut net, &data);
        let queued = net.node(AYSE).mesh_files.queued_count();
        assert!(queued > 0, "a burst went at once, the rest waits");
        assert_eq!(last_file(&mut net, CEM, AYSE).1.state, AttachmentState::Downloading);
        let mut ticks = 0;
        let start = now_secs();
        while net.node(AYSE).mesh_files.queued_count() > 0 {
            ticks += 1;
            assert!(ticks < 10, "it goes on every tick");
            let actions = net.node(AYSE).mesh_files_tick(start + 5 * ticks);
            net.run(AYSE, actions);
        }
        assert!(ticks > 1, "not all at once");
        let (received, attachment) = last_file(&mut net, CEM, AYSE);
        assert_eq!(attachment.state, AttachmentState::Complete);
        assert_eq!(content(&mut net, CEM, received.id, data.len()), data);
        assert_eq!(last_file(&mut net, AYSE, CEM).0.status, MessageStatus::Delivered);
    }

    #[test]
    fn a_file_waits_for_the_mesh_and_a_link_later_finishes_what_the_mesh_began() {
        let mut net = apart();
        let data = sample(MAX_MESH_FILE as usize);
        let sent = send_file(&mut net, &data);
        assert_eq!(sent.status, MessageStatus::Queued, "nobody around");
        mesh_link(&mut net, AYSE, BURAK);
        mesh_link(&mut net, BURAK, CEM);
        let (received, attachment) = last_file(&mut net, CEM, AYSE);
        assert_eq!(attachment.state, AttachmentState::Downloading, "begun through the mesh");
        // Ayşe and Cem meet: the rest comes over their link, and the mesh lets the file go.
        net.link(AYSE, CEM);
        let (_, attachment) = last_file(&mut net, CEM, AYSE);
        assert_eq!(attachment.state, AttachmentState::Complete);
        assert_eq!(content(&mut net, CEM, received.id, data.len()), data);
        assert!(mesh_key(&mut net, CEM, received.id).is_none());
        assert_eq!(last_file(&mut net, AYSE, CEM).0.status, MessageStatus::Delivered);
        assert_eq!(net.node(AYSE).mesh_files.queued_count(), 0, "no parts go any more");
    }

    // Group files (§10.10).

    /// Ayşe made a group with Cem and they parted; Burak, a stranger, may come between them.
    fn group_apart() -> Net {
        let mut net = Net::new(&["Ayşe", "Burak", "Cem"]);
        net.pair(AYSE, CEM);
        let cem = net.contact(AYSE, CEM);
        let (_, actions) = net.node(AYSE).create_group("Köprü", &[cem]).unwrap();
        net.run(AYSE, actions);
        net.link(AYSE, CEM);
        assert_eq!(net.group(CEM).name, "Köprü");
        net.cut(AYSE, CEM);
        net
    }

    /// Ayşe sends the group a file.
    fn send_group_file(net: &mut Net, data: &[u8]) -> i64 {
        let row = net.group(AYSE).row;
        let node = net.node(AYSE);
        let file = node.begin_group_file(row, "kroki.png", "image/png", None).unwrap();
        for part in data.chunks(10_000) {
            node.write_file(file, part).unwrap();
        }
        let (message, actions) = node.finish_group_file(file).unwrap();
        net.run(AYSE, actions);
        message.row
    }

    /// The last group file device `at` has: its row and how it stands.
    fn last_group_file(net: &mut Net, at: usize) -> (i64, Attachment) {
        let group = net.group(at).row;
        let message = net
            .node(at)
            .group_messages(group)
            .unwrap()
            .into_iter()
            .rev()
            .find(|m| m.attachment.is_some())
            .expect("a file message");
        (message.row, message.attachment.unwrap())
    }

    fn group_content(net: &mut Net, at: usize, row: i64, len: usize) -> Vec<u8> {
        net.node(at).read_file(group_file(row), 0, len).unwrap().to_vec()
    }

    #[test]
    fn a_small_group_file_crosses_the_mesh() {
        let mut net = group_apart();
        mesh_link(&mut net, AYSE, BURAK);
        mesh_link(&mut net, BURAK, CEM);
        let data = sample(70_000);
        send_group_file(&mut net, &data);
        let (row, attachment) = last_group_file(&mut net, CEM);
        assert_eq!(attachment.state, AttachmentState::Complete, "fetched without asking");
        assert_eq!(group_content(&mut net, CEM, row, data.len()), data);
        assert!(net.node(CEM).mesh_files.incoming.is_empty());
        assert!(
            net.node(BURAK).groups().unwrap().is_empty(),
            "the relay learned nothing"
        );
    }

    #[test]
    fn a_large_group_files_message_crosses_without_its_content() {
        let mut net = group_apart();
        mesh_link(&mut net, AYSE, BURAK);
        mesh_link(&mut net, BURAK, CEM);
        send_group_file(&mut net, &sample(MAX_MESH_FILE as usize + 1));
        assert_eq!(net.node(AYSE).mesh_files.queued_count(), 0, "no parts");
        assert_eq!(last_group_file(&mut net, CEM).1.state, AttachmentState::Offered);
    }

    #[test]
    fn a_locked_member_puts_a_group_file_together_after_unlocking() {
        let mut net = group_apart();
        mesh_link(&mut net, AYSE, BURAK);
        mesh_link(&mut net, BURAK, CEM);
        net.node(CEM).seal();
        let data = sample(40_000);
        send_group_file(&mut net, &data);
        assert_eq!(net.node(CEM).mesh_files.pending.len(), 3, "its parts wait, encrypted");
        unseal(&mut net, CEM);
        let (row, attachment) = last_group_file(&mut net, CEM);
        assert_eq!(attachment.state, AttachmentState::Complete);
        assert_eq!(group_content(&mut net, CEM, row, data.len()), data);
    }

    #[test]
    fn a_group_file_sent_with_nobody_around_goes_to_the_neighbours_that_come() {
        let mut net = group_apart();
        let data = sample(50_000);
        send_group_file(&mut net, &data);
        mesh_link(&mut net, BURAK, CEM);
        mesh_link(&mut net, AYSE, BURAK);
        let (row, attachment) = last_group_file(&mut net, CEM);
        assert_eq!(attachment.state, AttachmentState::Complete);
        assert_eq!(group_content(&mut net, CEM, row, data.len()), data);
    }

    #[test]
    fn a_group_file_offered_over_a_link_is_fetched_when_asked_from_parts_already_here() {
        let mut net = group_apart();
        net.link(AYSE, CEM);
        let data = sample(30_000);
        send_group_file(&mut net, &data);
        let (row, attachment) = last_group_file(&mut net, CEM);
        assert_eq!(attachment.state, AttachmentState::Offered, "over a link: when asked");
        // Ayşe leaves; the parts that came with the message are still here.
        net.cut(AYSE, CEM);
        let actions = net.node(CEM).download_group_file(row).unwrap();
        net.run(CEM, actions);
        assert_eq!(last_group_file(&mut net, CEM).1.state, AttachmentState::Complete);
        assert_eq!(group_content(&mut net, CEM, row, data.len()), data);
    }

    #[test]
    fn a_link_to_a_member_finishes_a_group_file_the_mesh_began() {
        let mut net = group_apart();
        mesh_link(&mut net, AYSE, BURAK);
        mesh_link(&mut net, BURAK, CEM);
        let data = sample(MAX_MESH_FILE as usize);
        send_group_file(&mut net, &data);
        let (row, attachment) = last_group_file(&mut net, CEM);
        assert_eq!(attachment.state, AttachmentState::Downloading, "parts go paced");
        net.link(AYSE, CEM);
        let (_, attachment) = last_group_file(&mut net, CEM);
        assert_eq!(attachment.state, AttachmentState::Complete);
        assert_eq!(group_content(&mut net, CEM, row, data.len()), data);
        assert!(net.node(CEM).mesh_files.incoming.is_empty());
    }
}
