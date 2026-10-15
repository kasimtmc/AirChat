//! Files in groups (rust/airchat-protocol/docs/protocol.md §9.7). A file message describes the file; members fetch the
//! content with chunk requests from any linked member that has it complete, trying the next one
//! when a member does not. Files are named in the file store by [`group_file`].

use std::collections::HashMap;

use zeroize::Zeroizing;

use super::{Action, Download, Import, Node, NodeError, Store, mesh::FROM_MESH, now_ms, stored_hash};
use crate::{
    chat::{self, ChatMessage, Unavailable},
    crypto::{hash::Sha256Stream, random},
    group::{self, Content},
    storage::{
        AttachmentState, ContactId, FileMeta, MessageId,
        files::{CHUNK_LEN, chunk_count},
        groups::{GroupMessage, Membership, group_file},
    },
};

/// The members each group file was asked for and did not have, by message row.
#[derive(Default)]
pub(crate) struct Tried(HashMap<i64, Vec<ContactId>>);

impl Tried {
    /// Everyone may be asked again: they may have fetched the files meanwhile.
    pub(super) fn forget(&mut self) {
        self.0.clear();
    }
}

impl Node {
    /// Starts an outgoing file in a group: write it with [`Node::write_file`] under the returned
    /// file name, then [`Node::finish_group_file`] (or [`Node::abort_file`]).
    pub fn begin_group_file(
        &mut self,
        group: i64,
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
        let account = self.account()?;
        account
            .db()
            .group(group)?
            .filter(|g| g.membership == Membership::Member)
            .ok_or(NodeError::NoSuchGroup)?;
        let id: MessageId = random::array()?;
        let me = account.identity().public();
        let row = account
            .db()
            .begin_group_file(group, &id, &me, name, mime, meta.thumbnail.as_deref(), now_ms())?;
        let file = group_file(row);
        self.imports.insert(
            file,
            Import {
                contact: 0,
                buffer: Zeroizing::new(Vec::with_capacity(CHUNK_LEN)),
                written: 0,
                hasher: Sha256Stream::default(),
            },
        );
        Ok(file)
    }

    /// Completes an outgoing group file: its message goes to the members, now if linked.
    pub fn finish_group_file(&mut self, file: i64) -> Result<(GroupMessage, Vec<Action>), NodeError> {
        let Store::Open(account) = &self.store else {
            return Err(NodeError::Sealed);
        };
        let mut import = self.imports.remove(&file).ok_or(NodeError::NoSuchFile)?;
        let row = -file;
        let finished = (|| {
            if !import.buffer.is_empty() {
                account.write_file_chunk(file, import.written, import.written / CHUNK_LEN as u64, &import.buffer)?;
                import.hasher.update(&import.buffer);
                import.written += import.buffer.len() as u64;
            }
            if import.written > 0 {
                account.sync_file(file)?;
            }
            let db = account.db();
            let message = db.group_message(row)?.ok_or(NodeError::NoSuchFile)?;
            let attachment = message.attachment.ok_or(NodeError::NoSuchFile)?;
            let stored = db
                .group(message.group)?
                .filter(|g| g.membership == Membership::Member)
                .ok_or(NodeError::NoSuchGroup)?;
            let sha256 = import.hasher.finish();
            let meta = FileMeta {
                name: attachment.name,
                mime: attachment.mime,
                size: import.written,
                sha256,
                thumbnail: attachment.thumbnail,
            };
            let now = now_ms();
            let sealed = group::seal_message(
                &stored.group_id,
                stored.epoch,
                &stored.epoch_key,
                &message.message_id,
                account.identity(),
                u64::try_from(now).unwrap_or(0),
                &Content::File(meta),
            )?;
            let message = db.finish_group_file(row, import.written, &sha256, &sealed, now)?;
            let tag_key = crate::mesh::group_tag_key(&stored.epoch_key, &stored.group_id, stored.epoch)?;
            Ok::<_, NodeError>((message, stored.roster, stored.group_id, sealed, tag_key, now))
        })();
        let (message, roster, group_id, sealed, tag_key, now) = finished.inspect_err(|_| {
            let _ = account.discard_file(file);
        })?;
        let mut actions = self.share_group_message(&roster, row)?;
        actions.extend(self.mesh_send_group(&group_id, &message.message_id, &sealed, &tag_key, now));
        // A small file's content goes with it (§10.10).
        actions.extend(self.mesh_send_group_file(row));
        Ok((message, actions))
    }

    /// Starts (or retries) fetching a group file; it goes on whenever a member that has it is linked.
    pub fn download_group_file(&mut self, row: i64) -> Result<Vec<Action>, NodeError> {
        let account = self.account()?;
        let db = account.db();
        let message = db.group_message(row)?.ok_or(NodeError::NoSuchFile)?;
        let attachment = message
            .attachment
            .as_ref()
            .filter(|_| !message.outgoing)
            .ok_or(NodeError::NoSuchFile)?;
        let updated = match attachment.state {
            AttachmentState::Complete | AttachmentState::Downloading => return Ok(Vec::new()),
            AttachmentState::Importing => return Err(NodeError::NoSuchFile),
            AttachmentState::Failed | AttachmentState::Gone => {
                account.clear_file(group_file(row))?;
                db.update_group_attachment(row, 0, AttachmentState::Downloading)?
            }
            AttachmentState::Offered => {
                db.update_group_attachment(row, attachment.stored, AttachmentState::Downloading)?
            }
        };
        self.tried.0.remove(&row);
        let mut actions = vec![Action::GroupMessageUpdated { message: updated }];
        // Parts that came through the mesh meanwhile go in at once (§10.10).
        actions.extend(self.mesh_fetch_group_file(row, super::now_secs()));
        actions.extend(self.resume_group_downloads());
        Ok(actions)
    }

    /// Goes on with every group file being fetched that has no member to fetch it from (or only
    /// the mesh): from one linked now that was not asked yet, the sender first.
    pub(super) fn resume_group_downloads(&mut self) -> Vec<Action> {
        let Store::Open(account) = &self.store else {
            return Vec::new();
        };
        let mut started = Vec::new();
        for message in account.db().group_downloading().unwrap_or_default() {
            let file = group_file(message.row);
            let Some(attachment) = message.attachment.as_ref() else {
                continue;
            };
            if self.downloads.get(&file).is_some_and(|d| d.contact != FROM_MESH) {
                continue;
            }
            let Some(group) = self.keys.groups.values().find(|g| g.row == message.group) else {
                continue;
            };
            let tried = self.tried.0.get(&message.row);
            let linked = |c: &ContactId| self.file_link(*c).is_some() && !tried.is_some_and(|t| t.contains(c));
            let sender = account
                .db()
                .contact_by_identity(&message.sender)
                .ok()
                .flatten()
                .map(|c| c.id)
                .filter(|c| group.members.contains(c) && linked(c));
            let Some(source) = sender.or_else(|| group.members.iter().copied().find(|c| linked(c))) else {
                continue;
            };
            // Being put together from mesh parts: a linked member brings the rest.
            if let Some(download) = self.downloads.get_mut(&file) {
                download.contact = source;
                download.requested_until = chunk_count(download.stored);
                download.not_now_since = None;
                started.push((file, source));
                continue;
            }
            let (hasher, stored) = stored_hash(account, file, attachment.size, attachment.stored);
            self.downloads.insert(
                file,
                Download {
                    contact: source,
                    file_id: message.message_id,
                    size: attachment.size,
                    sha256: attachment.sha256,
                    stored,
                    requested_until: chunk_count(stored),
                    hasher,
                    not_now_since: None,
                },
            );
            started.push((file, source));
        }
        let mut actions = Vec::new();
        for (file, source) in started {
            let (done, request) = self.advance_download(file);
            actions.extend(done);
            if let Some(connection) = self.file_link(source) {
                actions.extend(self.send_records(connection, request.into_iter().collect()));
            }
        }
        actions
    }

    /// The member a group file was being fetched from does not have it: on to the next one.
    pub(super) fn group_source_gone(&mut self, file: i64, contact: ContactId) -> Vec<Action> {
        self.drop_group_source(file);
        self.tried.0.entry(-file).or_default().push(contact);
        self.resume_group_downloads()
    }

    /// The link to `contact` ended: group files fetched from it go on from another member.
    pub(super) fn group_source_unlinked(&mut self, contact: ContactId) -> Vec<Action> {
        let from: Vec<i64> = self
            .downloads
            .iter()
            .filter(|(file, d)| **file < 0 && d.contact == contact)
            .map(|(file, _)| *file)
            .collect();
        if from.is_empty() {
            return Vec::new();
        }
        for file in from {
            self.drop_group_source(file);
        }
        self.resume_group_downloads()
    }

    /// The member a group file was fetched from is of no more use: the mesh goes on alone with a
    /// file it brings parts of (§10.10), another member is looked for.
    fn drop_group_source(&mut self, file: i64) {
        if self.mesh_fed(file)
            && let Some(download) = self.downloads.get_mut(&file)
        {
            download.contact = FROM_MESH;
            download.not_now_since = None;
        } else {
            self.downloads.remove(&file);
        }
    }

    /// A member linked: it may have files it lacked before.
    pub(super) fn group_source_linked(&mut self, contact: ContactId) -> Vec<Action> {
        for tried in self.tried.0.values_mut() {
            tried.retain(|&c| c != contact);
        }
        self.resume_group_downloads()
    }

    /// The answer to a member's request for chunks of a group file this device has complete;
    /// `None` if it has no such file of a group the member shares with it.
    pub(super) fn serve_group_chunks(
        &self,
        contact: ContactId,
        id: &MessageId,
        first: u64,
        count: u16,
    ) -> Option<Vec<ChatMessage>> {
        let Store::Open(account) = &self.store else {
            return None;
        };
        let message = account.db().complete_group_files(id).ok()?.into_iter().find(|m| {
            self.keys
                .groups
                .values()
                .any(|g| g.row == m.group && g.members.contains(&contact))
        })?;
        let attachment = message.attachment?;
        let file = group_file(message.row);
        let end = first.saturating_add(u64::from(count)).min(chunk_count(attachment.size));
        let mut chunks = Vec::new();
        for index in first..end {
            match account.read_file_chunk(file, attachment.size, index) {
                Ok(data) => chunks.push(ChatMessage::Chunk { id: *id, index, data }),
                Err(_) => {
                    return Some(vec![ChatMessage::FileUnavailable {
                        id: *id,
                        reason: Unavailable::Gone,
                    }]);
                }
            }
        }
        Some(chunks)
    }
}
