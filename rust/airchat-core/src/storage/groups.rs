//! Groups on this device (rust/airchat-protocol/docs/protocol.md §9): their epochs, the updates and messages to pass on,
//! and what waits to be passed on to whom.

use rusqlite::{OptionalExtension, Row, params};
use zeroize::Zeroizing;

use super::{Attachment, AttachmentState, ContactId, Database, FileMeta, StorageError, messages::attachment_at};
use crate::{
    crypto::SecretBytes,
    group::{GroupId, Roster},
    identity::PublicIdentity,
};

/// This device's place in a group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Membership {
    Member = 0,
    /// It left; the keys are gone, the history stays.
    Left = 1,
    /// An admin removed it; the keys are gone, the history stays.
    Removed = 2,
    /// An admin deleted the group for everyone: the history is gone, the keys stay for a day
    /// to pass the deletion on, and the group is out of sight (rust/airchat-protocol/docs/protocol.md §9.2).
    Deleted = 3,
    /// Everyone else left, or the time of the only other member ran out: a group of one is no
    /// group (rust/airchat-protocol/docs/protocol.md §9.2). The keys are gone, the history stays.
    Ended = 4,
}

impl Membership {
    fn from_i64(value: i64) -> rusqlite::Result<Self> {
        Ok(match value {
            0 => Self::Member,
            1 => Self::Left,
            2 => Self::Removed,
            3 => Self::Deleted,
            4 => Self::Ended,
            other => return Err(rusqlite::Error::IntegralValueOutOfRange(8, other)),
        })
    }
}

/// A group with the keys and rosters of its current and previous epoch.
pub struct StoredGroup {
    pub row: i64,
    pub group_id: GroupId,
    pub name: String,
    pub epoch: u64,
    pub epoch_key: SecretBytes<32>,
    pub roster: Roster,
    /// The epoch before: its messages may still arrive, and members who missed the latest update
    /// still link with its keys.
    pub previous: Option<(SecretBytes<32>, Roster)>,
    pub membership: Membership,
    /// Push-to-talk from its members plays at once (off by default, requirement V-3).
    pub allow_ptt: bool,
    /// Until when (Unix ms) it is muted; 0 if not.
    pub muted_until: i64,
}

/// What the group list shows; no keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupSummary {
    pub row: i64,
    pub group_id: GroupId,
    pub name: String,
    pub epoch: u64,
    pub members: u32,
    pub membership: Membership,
    /// This device may change the members.
    pub admin: bool,
    /// Push-to-talk from its members plays at once.
    pub instant_voice: bool,
    /// Until when (Unix ms) it is muted: its messages notify nothing, its calls ring silently and
    /// its push-to-talk does not play; 0 if not muted.
    pub muted_until: i64,
}

impl StoredGroup {
    pub fn summary(&self, me: &PublicIdentity) -> GroupSummary {
        GroupSummary {
            row: self.row,
            group_id: self.group_id,
            name: self.name.clone(),
            epoch: self.epoch,
            members: self.roster.members().len() as u32,
            membership: self.membership,
            admin: self.membership == Membership::Member && self.roster.is_admin(me),
            instant_voice: self.allow_ptt,
            muted_until: self.muted_until,
        }
    }

    /// The key and roster of `epoch`, if it is the current or the previous one.
    pub fn epoch(&self, epoch: u64) -> Option<(&SecretBytes<32>, &Roster)> {
        if epoch == self.epoch {
            return Some((&self.epoch_key, &self.roster));
        }
        self.previous
            .as_ref()
            .filter(|(_, roster)| roster.epoch == epoch)
            .map(|(key, roster)| (key, roster))
    }
}

/// An update waiting in the group outbox (`Database::queued_updates`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedUpdate {
    /// Its row in `group_updates`.
    pub update: i64,
    pub group: i64,
    pub epoch: u64,
    pub recipients: Vec<ContactId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupMessageStatus {
    /// Outgoing, not yet acknowledged by any member.
    Queued = 0,
    /// Outgoing, acknowledged by at least one member (who passes it on).
    Sent = 1,
    Received = 2,
    /// Outgoing, acknowledged by no member within a day of being sent (or tried again): no longer
    /// sent until the user tries again (rust/airchat-protocol/docs/protocol.md §9.5). Stored as a flag beside the status.
    Failed = 3,
}

impl GroupMessageStatus {
    fn from_i64(value: i64) -> rusqlite::Result<Self> {
        Ok(match value {
            0 => Self::Queued,
            1 => Self::Sent,
            2 => Self::Received,
            3 => Self::Failed,
            other => return Err(rusqlite::Error::IntegralValueOutOfRange(8, other)),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMessage {
    pub row: i64,
    pub group: i64,
    pub message_id: [u8; 16],
    pub sender: PublicIdentity,
    pub outgoing: bool,
    pub body: String,
    pub sent_at_ms: i64,
    pub stored_at_ms: i64,
    pub status: GroupMessageStatus,
    /// A file message's file; its content is in the file store under [`group_file`].
    pub attachment: Option<Attachment>,
    /// Outgoing: when the current try began (written, or tried again); a day later it is given up.
    pub tried_at_ms: i64,
}

/// The name of a group message's file in the file store: its row, negated, so it never meets a
/// 1:1 message's.
pub fn group_file(row: i64) -> i64 {
    -row
}

/// What waits in the group outbox for a member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outgoing {
    /// A group message row (`group_messages.id`), passed on as sealed.
    Message(i64),
    /// An update row (`group_updates.id`).
    Update(i64),
    /// This device's leave of a group row.
    Leave(i64),
}

impl Outgoing {
    fn parts(self) -> (i64, i64) {
        match self {
            Self::Message(row) => (0, row),
            Self::Update(row) => (1, row),
            Self::Leave(row) => (2, row),
        }
    }

    fn from_parts(kind: i64, item: i64) -> rusqlite::Result<Self> {
        Ok(match kind {
            0 => Self::Message(item),
            1 => Self::Update(item),
            2 => Self::Leave(item),
            other => return Err(rusqlite::Error::IntegralValueOutOfRange(0, other)),
        })
    }
}

const GROUP: &str =
    "id, group_id, name, epoch, epoch_key, roster, previous_key, previous_roster, state, allow_ptt, muted_until";
const SELECT_MESSAGE: &str =
    "SELECT m.id, m.group_, m.message_id, m.sender, m.outgoing, m.body, m.sent_at, m.stored_at,
        CASE WHEN m.failed = 1 THEN 3 ELSE m.status END,
        a.name, a.mime, a.size, a.sha256, a.thumbnail, a.stored, a.state, max(m.stored_at, m.tried_at),
        a.played_at
     FROM group_messages m LEFT JOIN group_attachments a ON a.message = m.id";
/// Files still being written are not part of the conversation yet.
const VISIBLE: &str = "(a.state IS NULL OR a.state != 5)";

impl Database {
    /// Stores an epoch of a group, new or newer than the one held: the one held becomes the
    /// previous epoch. Returns the group's row.
    pub fn save_group_epoch(
        &self,
        roster: &Roster,
        epoch_key: &SecretBytes<32>,
        update: &[u8],
        now_ms: i64,
    ) -> Result<i64, StorageError> {
        let encoded = roster.encode();
        let transaction = self.conn.unchecked_transaction()?;
        let row: i64 = transaction.query_row(
            "INSERT INTO groups (group_id, name, epoch, epoch_key, roster, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT (group_id) DO UPDATE SET
                name = excluded.name,
                previous_key = groups.epoch_key,
                previous_roster = groups.roster,
                epoch = excluded.epoch,
                epoch_key = excluded.epoch_key,
                roster = excluded.roster,
                state = 0
             RETURNING id",
            params![
                roster.group_id.as_slice(),
                roster.name,
                roster.epoch as i64,
                epoch_key.expose().as_slice(),
                encoded.as_slice(),
                now_ms,
            ],
            |row| row.get(0),
        )?;
        transaction.execute(
            "INSERT OR IGNORE INTO group_updates (group_, epoch, bytes) VALUES (?1, ?2, ?3)",
            params![row, roster.epoch as i64, update],
        )?;
        transaction.commit()?;
        Ok(row)
    }

    pub fn group(&self, row: i64) -> Result<Option<StoredGroup>, StorageError> {
        self.conn
            .query_row(
                &format!("SELECT {GROUP} FROM groups WHERE id = ?1"),
                params![row],
                raw_group,
            )
            .optional()?
            .map(stored_group)
            .transpose()
    }

    pub fn group_by_id(&self, group_id: &GroupId) -> Result<Option<StoredGroup>, StorageError> {
        self.conn
            .query_row(
                &format!("SELECT {GROUP} FROM groups WHERE group_id = ?1"),
                params![group_id.as_slice()],
                raw_group,
            )
            .optional()?
            .map(stored_group)
            .transpose()
    }

    /// Every group this device is a member of, with its keys: to recognise and link fellow members.
    pub fn member_groups(&self) -> Result<Vec<StoredGroup>, StorageError> {
        let mut statement = self
            .conn
            .prepare(&format!("SELECT {GROUP} FROM groups WHERE state = 0"))?;
        let rows: Vec<RawGroup> = statement.query_map([], raw_group)?.collect::<Result<_, _>>()?;
        rows.into_iter().map(stored_group).collect()
    }

    /// Every group the user sees (not those deleted), by name.
    pub fn groups(&self) -> Result<Vec<StoredGroup>, StorageError> {
        let mut statement = self.conn.prepare(&format!(
            "SELECT {GROUP} FROM groups WHERE state != 3 ORDER BY name COLLATE NOCASE, id"
        ))?;
        let rows: Vec<RawGroup> = statement.query_map([], raw_group)?.collect::<Result<_, _>>()?;
        rows.into_iter().map(stored_group).collect()
    }

    /// Contacts and peers something still waits for in the group outbox.
    pub fn group_outbox_recipients(&self) -> Result<Vec<ContactId>, StorageError> {
        let mut statement = self.conn.prepare("SELECT DISTINCT recipient FROM group_outbox")?;
        let rows = statement.query_map([], |row| row.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Left, removed or ended: the keys are overwritten, the history stays.
    pub fn end_membership(&self, row: i64, membership: Membership) -> Result<(), StorageError> {
        self.conn.execute(
            "UPDATE groups SET state = ?2, epoch_key = zeroblob(32), previous_key = NULL WHERE id = ?1",
            params![row, membership as i64],
        )?;
        Ok(())
    }

    /// Mutes a group until `until_ms` (Unix ms), or unmutes it with 0. Returns whether it exists.
    pub fn set_group_muted(&self, row: i64, until_ms: i64) -> Result<bool, StorageError> {
        Ok(self.conn.execute(
            "UPDATE groups SET muted_until = ?2 WHERE id = ?1",
            params![row, until_ms],
        )? > 0)
    }

    /// Whether the group's push-to-talk plays at once. Returns whether the group exists.
    pub fn set_group_ptt(&self, row: i64, allow: bool) -> Result<bool, StorageError> {
        Ok(self
            .conn
            .execute("UPDATE groups SET allow_ptt = ?2 WHERE id = ?1", params![row, allow])?
            > 0)
    }

    /// The group and everything about it, what waits to be passed on too.
    pub fn delete_group(&self, row: i64) -> Result<(), StorageError> {
        self.conn.execute(
            "DELETE FROM group_outbox WHERE (kind = 0 AND item IN (SELECT id FROM group_messages WHERE group_ = ?1))
                OR (kind = 1 AND item IN (SELECT id FROM group_updates WHERE group_ = ?1))
                OR (kind = 2 AND item = ?1)",
            params![row],
        )?;
        self.conn.execute("DELETE FROM groups WHERE id = ?1", params![row])?;
        Ok(())
    }

    /// An admin deleted the group for everyone: it is out of sight from now on, and kept (with its
    /// keys and the deletion, see [`Database::delete_group_messages`]) only to pass that on.
    pub fn mark_group_deleted(&self, row: i64) -> Result<(), StorageError> {
        self.conn
            .execute("UPDATE groups SET state = 3 WHERE id = ?1", params![row])?;
        Ok(())
    }

    /// Groups deleted for everyone whose deletion is older than `before_ms`: they can go.
    pub fn deleted_groups_before(&self, before_ms: i64) -> Result<Vec<i64>, StorageError> {
        let mut statement = self.conn.prepare(
            "SELECT g.id FROM groups g WHERE g.state = 3
             AND COALESCE((SELECT max(stored_at) FROM group_messages WHERE group_ = g.id), 0) < ?1",
        )?;
        let rows = statement.query_map(params![before_ms], |row| row.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn group_update(&self, update_row: i64) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self
            .conn
            .query_row(
                "SELECT bytes FROM group_updates WHERE id = ?1",
                params![update_row],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub fn group_update_row(&self, group: i64, epoch: u64) -> Result<Option<i64>, StorageError> {
        Ok(self
            .conn
            .query_row(
                "SELECT id FROM group_updates WHERE group_ = ?1 AND epoch = ?2",
                params![group, epoch as i64],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// Stores a group message unless it is a duplicate; with `file`, an incoming file message,
    /// offered. Returns it only if new.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_group_message(
        &self,
        group: i64,
        message_id: &[u8; 16],
        sender: &PublicIdentity,
        outgoing: bool,
        body: &str,
        file: Option<&FileMeta>,
        sent_at_ms: i64,
        now_ms: i64,
        sealed: &[u8],
    ) -> Result<Option<GroupMessage>, StorageError> {
        let transaction = self.conn.unchecked_transaction()?;
        let status = if outgoing {
            GroupMessageStatus::Queued
        } else {
            GroupMessageStatus::Received
        };
        let row: Option<i64> = transaction
            .query_row(
                "INSERT INTO group_messages (group_, message_id, sender, outgoing, body, sent_at, stored_at, status, sealed)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT (group_, message_id) DO NOTHING RETURNING id",
                params![
                    group,
                    message_id.as_slice(),
                    sender.as_bytes().as_slice(),
                    outgoing,
                    body,
                    sent_at_ms,
                    now_ms,
                    status as i64,
                    sealed,
                ],
                |row| row.get(0),
            )
            .optional()?;
        if let (Some(row), Some(meta)) = (row, file) {
            let size = i64::try_from(meta.size).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, i64::MAX))?;
            // A voice message is fetched without asking (§9.7).
            transaction.execute(
                "INSERT INTO group_attachments (message, name, mime, size, sha256, thumbnail, stored, state)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7)",
                params![
                    row,
                    meta.name,
                    meta.mime,
                    size,
                    meta.sha256.as_slice(),
                    meta.thumbnail,
                    i64::from(super::messages::is_voice(&meta.mime, meta.size))
                ],
            )?;
        }
        transaction.commit()?;
        row.map(|row| self.group_message(row)).transpose().map(Option::flatten)
    }

    /// Starts an outgoing group file: hidden from the conversation until finished.
    #[allow(clippy::too_many_arguments)]
    pub fn begin_group_file(
        &self,
        group: i64,
        message_id: &[u8; 16],
        sender: &PublicIdentity,
        name: &str,
        mime: &str,
        thumbnail: Option<&[u8]>,
        now_ms: i64,
    ) -> Result<i64, StorageError> {
        let transaction = self.conn.unchecked_transaction()?;
        let row: i64 = transaction.query_row(
            "INSERT INTO group_messages (group_, message_id, sender, outgoing, body, sent_at, stored_at, status, sealed)
             VALUES (?1, ?2, ?3, 1, '', ?4, ?4, 0, x'') RETURNING id",
            params![group, message_id.as_slice(), sender.as_bytes().as_slice(), now_ms],
            |row| row.get(0),
        )?;
        transaction.execute(
            "INSERT INTO group_attachments (message, name, mime, size, sha256, thumbnail, stored, state)
             VALUES (?1, ?2, ?3, 0, zeroblob(32), ?4, 0, 5)",
            params![row, name, mime, thumbnail],
        )?;
        transaction.commit()?;
        Ok(row)
    }

    /// Completes an outgoing group file with its size, hash and sealed message.
    pub fn finish_group_file(
        &self,
        row: i64,
        size: u64,
        sha256: &[u8; 32],
        sealed: &[u8],
        now_ms: i64,
    ) -> Result<GroupMessage, StorageError> {
        let size = i64::try_from(size).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, i64::MAX))?;
        let transaction = self.conn.unchecked_transaction()?;
        transaction.execute(
            "UPDATE group_attachments SET size = ?2, sha256 = ?3, stored = ?2, state = 2 WHERE message = ?1 AND state = 5",
            params![row, size, sha256.as_slice()],
        )?;
        transaction.execute(
            "UPDATE group_messages SET sent_at = ?2, stored_at = ?2, sealed = ?3 WHERE id = ?1",
            params![row, now_ms, sealed],
        )?;
        transaction.commit()?;
        self.group_message(row)?.ok_or(StorageError::Corrupt)
    }

    pub fn update_group_attachment(
        &self,
        row: i64,
        stored: u64,
        state: AttachmentState,
    ) -> Result<GroupMessage, StorageError> {
        let stored = i64::try_from(stored).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, i64::MAX))?;
        self.conn.execute(
            "UPDATE group_attachments SET stored = ?2, state = ?3 WHERE message = ?1",
            params![row, stored, state as i64],
        )?;
        self.group_message(row)?.ok_or(StorageError::Corrupt)
    }

    pub fn delete_group_message(&self, row: i64) -> Result<(), StorageError> {
        self.conn
            .execute("DELETE FROM group_messages WHERE id = ?1", params![row])?;
        Ok(())
    }

    /// A group voice message that came in was played: its time starts now, if it had not.
    pub fn group_voice_played(&self, row: i64, now_ms: i64) -> Result<bool, StorageError> {
        Ok(self.conn.execute(
            "UPDATE group_attachments SET played_at = ?2
             WHERE message = ?1 AND played_at = 0 AND state = 2 AND mime = ?3 AND size <= ?4
             AND message IN (SELECT id FROM group_messages WHERE outgoing = 0)",
            params![
                row,
                now_ms,
                super::messages::VOICE_MIME,
                super::messages::MAX_VOICE_BYTES as i64
            ],
        )? > 0)
    }

    /// Group voice messages first played before `before_ms`, marked gone; the caller deletes
    /// their files.
    pub fn expire_group_voice(&self, before_ms: i64) -> Result<Vec<GroupMessage>, StorageError> {
        let rows: Vec<i64> = {
            let mut statement = self.conn.prepare(
                "UPDATE group_attachments SET state = 4, stored = 0
                 WHERE played_at > 0 AND played_at <= ?1 AND state = 2 RETURNING message",
            )?;
            let rows = statement.query_map(params![before_ms], |row| row.get(0))?;
            rows.collect::<Result<_, _>>()?
        };
        rows.into_iter()
            .filter_map(|row| self.group_message(row).transpose())
            .collect()
    }

    /// Outgoing group files whose writing never finished (the app died meanwhile).
    pub fn unfinished_group_files(&self) -> Result<Vec<i64>, StorageError> {
        let mut statement = self
            .conn
            .prepare("SELECT message FROM group_attachments WHERE state = 5")?;
        let rows = statement.query_map([], |row| row.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Group files being fetched, in every group.
    pub fn group_downloading(&self) -> Result<Vec<GroupMessage>, StorageError> {
        let mut statement = self.conn.prepare(&format!(
            "{SELECT_MESSAGE} WHERE a.state = 1 ORDER BY m.stored_at, m.id"
        ))?;
        let rows = statement.query_map([], group_message)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Group files with this message id that this device has complete, in any group.
    pub fn complete_group_files(&self, message_id: &[u8; 16]) -> Result<Vec<GroupMessage>, StorageError> {
        let mut statement = self
            .conn
            .prepare(&format!("{SELECT_MESSAGE} WHERE m.message_id = ?1 AND a.state = 2"))?;
        let rows = statement.query_map(params![message_id.as_slice()], group_message)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// The rows of a group's messages that have a file, to delete their content.
    pub fn group_file_rows(&self, group: i64) -> Result<Vec<i64>, StorageError> {
        let mut statement = self.conn.prepare(
            "SELECT m.id FROM group_messages m JOIN group_attachments a ON a.message = m.id WHERE m.group_ = ?1",
        )?;
        let rows = statement.query_map(params![group], |row| row.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn group_message(&self, row: i64) -> Result<Option<GroupMessage>, StorageError> {
        Ok(self
            .conn
            .query_row(
                &format!("{SELECT_MESSAGE} WHERE m.id = ?1"),
                params![row],
                group_message,
            )
            .optional()?)
    }

    pub fn group_message_by_id(&self, group: i64, message_id: &[u8; 16]) -> Result<Option<GroupMessage>, StorageError> {
        Ok(self
            .conn
            .query_row(
                &format!("{SELECT_MESSAGE} WHERE m.group_ = ?1 AND m.message_id = ?2"),
                params![group, message_id.as_slice()],
                group_message,
            )
            .optional()?)
    }

    pub fn group_message_sealed(&self, row: i64) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self
            .conn
            .query_row("SELECT sealed FROM group_messages WHERE id = ?1", params![row], |row| {
                row.get(0)
            })
            .optional()?)
    }

    /// A group's conversation, oldest first.
    pub fn group_messages(&self, group: i64) -> Result<Vec<GroupMessage>, StorageError> {
        let mut statement = self.conn.prepare(&format!(
            "{SELECT_MESSAGE} WHERE m.group_ = ?1 AND {VISIBLE} ORDER BY m.stored_at, m.id"
        ))?;
        let rows = statement.query_map(params![group], group_message)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Marks an outgoing group message sent (a member has it). Returns it if that changed.
    pub fn mark_group_message_sent(&self, row: i64) -> Result<Option<GroupMessage>, StorageError> {
        let changed = self.conn.execute(
            // One given up that a member acknowledges after all is no longer failed.
            "UPDATE group_messages SET status = 1, failed = 0 WHERE id = ?1 AND outgoing = 1 AND status = 0",
            params![row],
        )? > 0;
        if changed { self.group_message(row) } else { Ok(None) }
    }

    /// A group's messages are deleted (a temporary membership ended, requirement M-5; the group
    /// was deleted), but `keep`, and with them whatever waited to pass them on.
    pub fn delete_group_messages(&self, group: i64, keep: Option<i64>) -> Result<(), StorageError> {
        let keep = keep.unwrap_or(0);
        self.conn.execute(
            "DELETE FROM group_outbox WHERE kind = 0
             AND item IN (SELECT id FROM group_messages WHERE group_ = ?1 AND id != ?2)",
            params![group, keep],
        )?;
        self.conn.execute(
            "DELETE FROM group_messages WHERE group_ = ?1 AND id != ?2",
            params![group, keep],
        )?;
        Ok(())
    }

    /// Queues `item` for each of `recipients`; already queued ones stay as they are. An update
    /// replaces the older updates of its group waiting for them: it carries everything they do.
    pub fn queue_group_item(&self, item: Outgoing, recipients: &[ContactId], now_ms: i64) -> Result<(), StorageError> {
        let (kind, item) = item.parts();
        let transaction = self.conn.unchecked_transaction()?;
        for recipient in recipients {
            if kind == 1 {
                transaction.execute(
                    "DELETE FROM group_outbox WHERE kind = 1 AND recipient = ?2 AND item IN (
                        SELECT older.id FROM group_updates older JOIN group_updates newer
                        ON older.group_ = newer.group_ AND older.epoch < newer.epoch WHERE newer.id = ?1)",
                    params![item, recipient],
                )?;
            }
            transaction.execute(
                "INSERT OR IGNORE INTO group_outbox (kind, item, recipient, queued_at) VALUES (?1, ?2, ?3, ?4)",
                params![kind, item, recipient, now_ms],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// What waits for a member, oldest first.
    pub fn group_outbox(&self, recipient: ContactId) -> Result<Vec<Outgoing>, StorageError> {
        let mut statement = self
            .conn
            .prepare("SELECT kind, item FROM group_outbox WHERE recipient = ?1 ORDER BY queued_at, kind DESC, item")?;
        let rows = statement.query_map(params![recipient], |row| Outgoing::from_parts(row.get(0)?, row.get(1)?))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn dequeue_group_item(&self, item: Outgoing, recipient: ContactId) -> Result<bool, StorageError> {
        let (kind, item) = item.parts();
        Ok(self.conn.execute(
            "DELETE FROM group_outbox WHERE kind = ?1 AND item = ?2 AND recipient = ?3",
            params![kind, item, recipient],
        )? > 0)
    }

    /// Updates queued for someone since `since_ms`: each update's row, its group's row and epoch,
    /// and for whom it is queued.
    pub fn queued_updates(&self, since_ms: i64) -> Result<Vec<QueuedUpdate>, StorageError> {
        let mut statement = self.conn.prepare(
            "SELECT u.id, u.group_, u.epoch, o.recipient FROM group_outbox o
             JOIN group_updates u ON u.id = o.item
             WHERE o.kind = 1 AND o.queued_at >= ?1 ORDER BY u.id, o.recipient",
        )?;
        let rows = statement.query_map(params![since_ms], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, ContactId>(3)?,
            ))
        })?;
        let mut updates: Vec<QueuedUpdate> = Vec::new();
        for row in rows {
            let (update, group, epoch, recipient) = row?;
            match updates.last_mut() {
                Some(last) if last.update == update => last.recipients.push(recipient),
                _ => updates.push(QueuedUpdate {
                    update,
                    group,
                    epoch: epoch as u64,
                    recipients: vec![recipient],
                }),
            }
        }
        Ok(updates)
    }

    /// This device's own group messages stored since `since_ms` that some member has not
    /// acknowledged yet, oldest first.
    pub fn own_unacknowledged_group_messages(&self, since_ms: i64) -> Result<Vec<i64>, StorageError> {
        let mut statement = self.conn.prepare(
            "SELECT DISTINCT m.id FROM group_outbox o JOIN group_messages m ON m.id = o.item
             WHERE o.kind = 0 AND m.outgoing = 1 AND m.failed = 0 AND max(m.stored_at, m.tried_at) >= ?1
             ORDER BY m.id",
        )?;
        let rows = statement.query_map(params![since_ms], |row| row.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Entries queued before `before_ms` are given up, messages already those queued before
    /// `messages_before_ms` (rust/airchat-protocol/docs/protocol.md §9.5). Returns how many.
    pub fn expire_group_outbox(&self, before_ms: i64, messages_before_ms: i64) -> Result<usize, StorageError> {
        Ok(self.conn.execute(
            "DELETE FROM group_outbox WHERE queued_at < ?1 OR (kind = 0 AND queued_at < ?2)",
            params![before_ms, messages_before_ms],
        )?)
    }

    /// Each group, with its latest message and how many messages from others came after the user
    /// last read it.
    pub fn group_previews(&self) -> Result<Vec<(i64, Option<GroupMessage>, u32)>, StorageError> {
        let rows: Vec<(i64, Option<i64>, u32)> = {
            let mut statement = self.conn.prepare(&format!(
                "SELECT g.id,
                    (SELECT m.id FROM group_messages m LEFT JOIN group_attachments a ON a.message = m.id
                     WHERE m.group_ = g.id AND {VISIBLE} ORDER BY m.stored_at DESC, m.id DESC LIMIT 1),
                    (SELECT count(*) FROM group_messages m WHERE m.group_ = g.id AND m.outgoing = 0
                     AND m.stored_at > g.read_at)
                 FROM groups g WHERE g.state != 3"
            ))?;
            let rows = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
            rows.collect::<Result<_, _>>()?
        };
        rows.into_iter()
            .map(|(group, last, unread)| {
                let last = match last {
                    Some(row) => self.group_message(row)?,
                    None => None,
                };
                Ok((group, last, unread))
            })
            .collect()
    }

    /// The user has read group `row` up to its latest message.
    pub fn mark_group_read(&self, row: i64) -> Result<(), StorageError> {
        self.conn.execute(
            "UPDATE groups SET read_at = max(read_at,
                COALESCE((SELECT max(stored_at) FROM group_messages WHERE group_ = ?1), 0))
             WHERE id = ?1",
            params![row],
        )?;
        Ok(())
    }

    /// Gives up this device's group messages no member acknowledged, tried since `cutoff_ms` or
    /// longer: they go out of the outbox. Returns them.
    pub fn give_up_group_messages(&self, cutoff_ms: i64) -> Result<Vec<GroupMessage>, StorageError> {
        let rows: Vec<i64> = {
            let mut statement = self.conn.prepare(
                "UPDATE group_messages SET failed = 1
                 WHERE outgoing = 1 AND status = 0 AND failed = 0 AND max(stored_at, tried_at) <= ?1
                 RETURNING id",
            )?;
            let rows = statement.query_map(params![cutoff_ms], |row| row.get(0))?;
            rows.collect::<Result<_, _>>()?
        };
        let mut given_up = Vec::new();
        for row in rows {
            self.conn
                .execute("DELETE FROM group_outbox WHERE kind = 0 AND item = ?1", params![row])?;
            given_up.extend(self.group_message(row)?);
        }
        Ok(given_up)
    }

    /// Tries one of this device's group messages given up again from `now_ms`, sealed afresh as
    /// `sealed`. Returns it, or `None` if `row` names none given up; the caller queues it.
    pub fn try_group_message_again(
        &self,
        row: i64,
        now_ms: i64,
        sealed: &[u8],
    ) -> Result<Option<GroupMessage>, StorageError> {
        let changed = self.conn.execute(
            "UPDATE group_messages SET failed = 0, tried_at = ?2, sealed = ?3 WHERE id = ?1 AND outgoing = 1 AND failed = 1",
            params![row, now_ms, sealed],
        )? > 0;
        if changed { self.group_message(row) } else { Ok(None) }
    }
}

type RawGroup = (
    i64,
    Vec<u8>,
    String,
    i64,
    Zeroizing<Vec<u8>>,
    Zeroizing<Vec<u8>>,
    Option<Zeroizing<Vec<u8>>>,
    Option<Zeroizing<Vec<u8>>>,
    i64,
    bool,
    i64,
);

fn raw_group(row: &Row) -> rusqlite::Result<RawGroup> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        Zeroizing::new(row.get(4)?),
        Zeroizing::new(row.get(5)?),
        row.get::<_, Option<Vec<u8>>>(6)?.map(Zeroizing::new),
        row.get::<_, Option<Vec<u8>>>(7)?.map(Zeroizing::new),
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
    ))
}

fn stored_group(raw: RawGroup) -> Result<StoredGroup, StorageError> {
    let (row, group_id, name, epoch, key, roster, previous_key, previous_roster, state, allow_ptt, muted_until) = raw;
    let corrupt = |_| StorageError::Corrupt;
    let previous = match (previous_key, previous_roster) {
        (Some(key), Some(roster)) => Some((
            SecretBytes::from_slice(&key)?,
            Roster::decode(&roster).map_err(corrupt)?,
        )),
        _ => None,
    };
    Ok(StoredGroup {
        row,
        group_id: group_id.try_into().map_err(|_| StorageError::Corrupt)?,
        name,
        epoch: epoch as u64,
        epoch_key: SecretBytes::from_slice(&key)?,
        roster: Roster::decode(&roster).map_err(corrupt)?,
        previous,
        membership: Membership::from_i64(state)?,
        allow_ptt,
        muted_until,
    })
}

fn group_message(row: &Row) -> rusqlite::Result<GroupMessage> {
    Ok(GroupMessage {
        row: row.get(0)?,
        group: row.get(1)?,
        message_id: row.get(2)?,
        sender: PublicIdentity::from_bytes(row.get(3)?),
        outgoing: row.get(4)?,
        body: row.get(5)?,
        sent_at_ms: row.get(6)?,
        stored_at_ms: row.get(7)?,
        status: GroupMessageStatus::from_i64(row.get(8)?)?,
        attachment: attachment_at(row, 9)?.map(|mut a| {
            a.played_at_ms = row.get::<_, Option<i64>>(17).ok().flatten().unwrap_or(0);
            a
        }),
        tried_at_ms: row.get(16)?,
    })
}
