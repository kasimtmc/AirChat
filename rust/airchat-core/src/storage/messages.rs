//! 1:1 conversations, and the attachments of file messages.

use rusqlite::{OptionalExtension, Row, params};

use zeroize::Zeroizing;

use super::{ContactId, Database, StorageError};

pub use crate::chat::{FileMeta, MESSAGE_ID_LEN, MessageId};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageStatus {
    /// Outgoing, waiting for a link to the contact.
    Queued = 0,
    /// Outgoing, handed to a link; not yet acknowledged.
    Sent = 1,
    /// Outgoing, acknowledged by the contact's device.
    Delivered = 2,
    /// Incoming.
    Received = 3,
    /// Outgoing, turned down by the contact's device: they do not take messages from this user.
    Refused = 4,
    /// Outgoing, not acknowledged within a day of being sent (or tried again): no longer sent until
    /// the user tries again (rust/airchat-protocol/docs/protocol.md §10.5). Stored as a flag beside the status.
    Failed = 5,
}

impl MessageStatus {
    fn from_i64(value: i64) -> rusqlite::Result<Self> {
        Ok(match value {
            0 => Self::Queued,
            1 => Self::Sent,
            2 => Self::Delivered,
            3 => Self::Received,
            4 => Self::Refused,
            5 => Self::Failed,
            other => return Err(rusqlite::Error::IntegralValueOutOfRange(7, other)),
        })
    }
}

/// Where an attachment's content stands on this device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachmentState {
    /// Incoming, offered; not asked for yet.
    Offered = 0,
    /// Incoming, being fetched (or waiting for a link to go on).
    Downloading = 1,
    /// Complete on this device (all outgoing files, and incoming ones whose hash checked out).
    Complete = 2,
    /// Incoming, arrived but did not match its hash.
    Failed = 3,
    /// Incoming, no longer available from the sender.
    Gone = 4,
    /// Outgoing, still being written; not part of the conversation yet.
    Importing = 5,
}

impl AttachmentState {
    fn from_i64(value: i64) -> rusqlite::Result<Self> {
        Ok(match value {
            0 => Self::Offered,
            1 => Self::Downloading,
            2 => Self::Complete,
            3 => Self::Failed,
            4 => Self::Gone,
            5 => Self::Importing,
            other => return Err(rusqlite::Error::IntegralValueOutOfRange(14, other)),
        })
    }
}

/// The file of a file message. Its content lives in the file store under the message's row id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    pub name: String,
    pub mime: String,
    pub size: u64,
    pub sha256: [u8; 32],
    /// A small preview (JPEG) to show before the file is fetched.
    pub thumbnail: Option<Vec<u8>>,
    /// Bytes of the content stored on this device.
    pub stored: u64,
    pub state: AttachmentState,
    /// When a voice message that came in was first played (Unix ms), 0 if not yet; it goes
    /// [`VOICE_KEEP_MS`] later.
    pub played_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMessage {
    pub id: i64,
    pub contact_id: ContactId,
    pub message_id: MessageId,
    pub outgoing: bool,
    /// The text; empty for a file message.
    pub body: String,
    /// The sender's clock (Unix ms); only for display.
    pub sent_at_ms: i64,
    /// This device's clock when the message was written or arrived; orders the conversation.
    pub stored_at_ms: i64,
    pub status: MessageStatus,
    pub attachment: Option<Attachment>,
    /// Outgoing: when the current try began (written, or tried again); a day later it is given up.
    pub tried_at_ms: i64,
}

/// How long an outgoing message is tried before it is given up (rust/airchat-protocol/docs/protocol.md §10.5).
pub const TRY_MS: i64 = 24 * 60 * 60 * 1000;

/// A voice message is an Ogg Opus file of at most [`MAX_VOICE_BYTES`] (rust/airchat-protocol/docs/protocol.md §8.4):
/// fetched without asking, and deleted [`VOICE_KEEP_MS`] after it was first played.
pub const VOICE_MIME: &str = "audio/ogg";
pub const MAX_VOICE_BYTES: u64 = 1 << 20;
pub const VOICE_KEEP_MS: i64 = 15 * 60 * 1000;

/// Whether a file is a voice message.
pub fn is_voice(mime: &str, size: u64) -> bool {
    mime == VOICE_MIME && size <= MAX_VOICE_BYTES
}

const SELECT: &str = "SELECT m.id, m.contact_id, m.message_id, m.outgoing, m.body, m.sent_at, m.stored_at,
        CASE WHEN m.failed = 1 THEN 5 ELSE m.status END,
        a.name, a.mime, a.size, a.sha256, a.thumbnail, a.stored, a.state, max(m.stored_at, m.tried_at),
        a.played_at
     FROM messages m LEFT JOIN attachments a ON a.message = m.id";
/// Files still being written are not part of the conversation yet.
const VISIBLE: &str = "(a.state IS NULL OR a.state != 5)";

impl Database {
    pub fn insert_outgoing(
        &self,
        contact_id: ContactId,
        message_id: &MessageId,
        body: &str,
        now_ms: i64,
    ) -> Result<StoredMessage, StorageError> {
        let id: i64 = self.conn.query_row(
            "INSERT INTO messages (contact_id, message_id, outgoing, body, sent_at, stored_at, status)
             VALUES (?1, ?2, 1, ?3, ?4, ?4, 0) RETURNING id",
            params![contact_id, message_id.as_slice(), body, now_ms],
            |row| row.get(0),
        )?;
        self.loaded(id)
    }

    /// Stores an incoming message unless it was already received (a resend). Returns it only if new.
    pub fn insert_incoming(
        &self,
        contact_id: ContactId,
        message_id: &MessageId,
        body: &str,
        sent_at_ms: i64,
        now_ms: i64,
    ) -> Result<Option<StoredMessage>, StorageError> {
        let id: Option<i64> = self
            .conn
            .query_row(
                "INSERT INTO messages (contact_id, message_id, outgoing, body, sent_at, stored_at, status)
                 VALUES (?1, ?2, 0, ?3, ?4, ?5, 3)
                 ON CONFLICT (contact_id, message_id) DO NOTHING RETURNING id",
                params![contact_id, message_id.as_slice(), body, sent_at_ms, now_ms],
                |row| row.get(0),
            )
            .optional()?;
        id.map(|id| self.loaded(id)).transpose()
    }

    /// Starts an outgoing file message; it stays out of the conversation until [`finish_file`].
    ///
    /// [`finish_file`]: Database::finish_file
    pub fn insert_outgoing_file(
        &self,
        contact_id: ContactId,
        message_id: &MessageId,
        name: &str,
        mime: &str,
        thumbnail: Option<&[u8]>,
        now_ms: i64,
    ) -> Result<i64, StorageError> {
        let transaction = self.conn.unchecked_transaction()?;
        let id: i64 = transaction.query_row(
            "INSERT INTO messages (contact_id, message_id, outgoing, body, sent_at, stored_at, status)
             VALUES (?1, ?2, 1, '', ?3, ?3, 0) RETURNING id",
            params![contact_id, message_id.as_slice(), now_ms],
            |row| row.get(0),
        )?;
        transaction.execute(
            "INSERT INTO attachments (message, name, mime, size, sha256, thumbnail, stored, state)
             VALUES (?1, ?2, ?3, 0, zeroblob(32), ?4, 0, 5)",
            params![id, name, mime, thumbnail],
        )?;
        transaction.commit()?;
        Ok(id)
    }

    /// Completes an outgoing file: its content is written. From now on it is queued for sending.
    pub fn finish_file(
        &self,
        id: i64,
        size: u64,
        sha256: &[u8; 32],
        now_ms: i64,
    ) -> Result<StoredMessage, StorageError> {
        let size = i64::try_from(size).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, i64::MAX))?;
        let transaction = self.conn.unchecked_transaction()?;
        transaction.execute(
            "UPDATE attachments SET size = ?2, sha256 = ?3, stored = ?2, state = 2 WHERE message = ?1 AND state = 5",
            params![id, size, sha256.as_slice()],
        )?;
        transaction.execute(
            "UPDATE messages SET sent_at = ?2, stored_at = ?2 WHERE id = ?1",
            params![id, now_ms],
        )?;
        transaction.commit()?;
        self.loaded(id)
    }

    /// Stores an incoming file offer unless it was already received. Returns it only if new.
    pub fn insert_incoming_file(
        &self,
        contact_id: ContactId,
        message_id: &MessageId,
        meta: &FileMeta,
        sent_at_ms: i64,
        now_ms: i64,
    ) -> Result<Option<StoredMessage>, StorageError> {
        let size = i64::try_from(meta.size).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, i64::MAX))?;
        let transaction = self.conn.unchecked_transaction()?;
        let id: Option<i64> = transaction
            .query_row(
                "INSERT INTO messages (contact_id, message_id, outgoing, body, sent_at, stored_at, status)
                 VALUES (?1, ?2, 0, '', ?3, ?4, 3)
                 ON CONFLICT (contact_id, message_id) DO NOTHING RETURNING id",
                params![contact_id, message_id.as_slice(), sent_at_ms, now_ms],
                |row| row.get(0),
            )
            .optional()?;
        let Some(id) = id else {
            return Ok(None);
        };
        // Offered, or already downloading if it is a voice message or the contact's files are
        // fetched without asking (`auto_download` is 0 or 1, as are those two states).
        transaction.execute(
            "INSERT INTO attachments (message, name, mime, size, sha256, thumbnail, stored, state)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0,
                     CASE WHEN ?8 THEN 1 ELSE (SELECT auto_download FROM contacts WHERE id = ?7) END)",
            params![
                id,
                meta.name,
                meta.mime,
                size,
                meta.sha256.as_slice(),
                meta.thumbnail,
                contact_id,
                is_voice(&meta.mime, meta.size)
            ],
        )?;
        transaction.commit()?;
        Ok(Some(self.loaded(id)?))
    }

    /// Records how much of an attachment is stored and where it stands.
    /// Sets (or with `None` deletes, overwriting it in the file) the key of a file's parts through
    /// the mesh (§10.8).
    pub fn set_mesh_key(&self, id: i64, key: Option<&[u8; 32]>) -> Result<(), StorageError> {
        self.conn.execute(
            "UPDATE attachments SET mesh_key = ?2 WHERE message = ?1",
            params![id, key.map(|k| k.as_slice())],
        )?;
        Ok(())
    }

    /// The key of a file's parts through the mesh, if it has one.
    pub fn mesh_key(&self, id: i64) -> Result<Option<Zeroizing<[u8; 32]>>, StorageError> {
        let key: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT mesh_key FROM attachments WHERE message = ?1",
                params![id],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        key.map(|k| {
            let key = Zeroizing::new(k);
            <[u8; 32]>::try_from(key.as_slice())
                .map(Zeroizing::new)
                .map_err(|_| StorageError::Corrupt)
        })
        .transpose()
    }

    pub fn update_attachment(
        &self,
        id: i64,
        stored: u64,
        state: AttachmentState,
    ) -> Result<StoredMessage, StorageError> {
        let stored = i64::try_from(stored).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, i64::MAX))?;
        self.conn.execute(
            "UPDATE attachments SET stored = ?2, state = ?3 WHERE message = ?1",
            params![id, stored, state as i64],
        )?;
        self.loaded(id)
    }

    pub fn delete_message(&self, id: i64) -> Result<(), StorageError> {
        self.conn.execute("DELETE FROM messages WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// A message by its row id, including one still being written.
    pub fn message(&self, id: i64) -> Result<Option<StoredMessage>, StorageError> {
        Ok(self
            .conn
            .query_row(&format!("{SELECT} WHERE m.id = ?1"), params![id], message)
            .optional()?)
    }

    /// A message by the id its sender gave it.
    pub fn message_by_id(
        &self,
        contact_id: ContactId,
        message_id: &MessageId,
    ) -> Result<Option<StoredMessage>, StorageError> {
        Ok(self
            .conn
            .query_row(
                &format!("{SELECT} WHERE m.contact_id = ?1 AND m.message_id = ?2 AND {VISIBLE}"),
                params![contact_id, message_id.as_slice()],
                message,
            )
            .optional()?)
    }

    /// Row ids of every file message with a contact, also unfinished ones (to delete their content).
    pub fn file_ids(&self, contact_id: ContactId) -> Result<Vec<i64>, StorageError> {
        let mut statement = self
            .conn
            .prepare("SELECT m.id FROM messages m JOIN attachments a ON a.message = m.id WHERE m.contact_id = ?1")?;
        let rows = statement.query_map(params![contact_id], |row| row.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Every message of a conversation goes, attachments with them (the caller deletes the files).
    pub fn delete_messages_of(&self, contact_id: ContactId) -> Result<(), StorageError> {
        self.conn
            .execute("DELETE FROM messages WHERE contact_id = ?1", params![contact_id])?;
        Ok(())
    }

    /// Outgoing files whose writing never finished (the app died meanwhile).
    pub fn unfinished_files(&self) -> Result<Vec<i64>, StorageError> {
        let mut statement = self.conn.prepare("SELECT message FROM attachments WHERE state = 5")?;
        let rows = statement.query_map([], |row| row.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Incoming files being fetched from a contact.
    pub fn downloading(&self, contact_id: ContactId) -> Result<Vec<StoredMessage>, StorageError> {
        self.list(
            &format!("{SELECT} WHERE m.contact_id = ?1 AND a.state = 1 ORDER BY m.stored_at, m.id"),
            params![contact_id],
        )
    }

    /// The conversation with a contact, oldest first.
    pub fn messages(&self, contact_id: ContactId) -> Result<Vec<StoredMessage>, StorageError> {
        self.list(
            &format!("{SELECT} WHERE m.contact_id = ?1 AND {VISIBLE} ORDER BY m.stored_at, m.id"),
            params![contact_id],
        )
    }

    /// Outgoing messages to a contact that have not been acknowledged and are still tried, oldest
    /// first.
    pub fn undelivered(&self, contact_id: ContactId) -> Result<Vec<StoredMessage>, StorageError> {
        self.list(
            &format!(
                "{SELECT} WHERE m.contact_id = ?1 AND m.outgoing = 1 AND m.status IN (0, 1) AND m.failed = 0
                    AND {VISIBLE}
                 ORDER BY m.stored_at, m.id"
            ),
            params![contact_id],
        )
    }

    /// Every unacknowledged outgoing message still tried, oldest first.
    pub fn all_undelivered(&self) -> Result<Vec<StoredMessage>, StorageError> {
        self.list(
            &format!(
                "{SELECT} WHERE m.outgoing = 1 AND m.status IN (0, 1) AND m.failed = 0 AND {VISIBLE}
                 ORDER BY m.stored_at, m.id"
            ),
            [],
        )
    }

    /// Moves an outgoing message forward (queued → sent → delivered, or to refused before it was
    /// delivered); never backwards. One given up that is acknowledged after all is no longer failed.
    /// Returns the message if its status changed.
    pub fn advance_status(
        &self,
        contact_id: ContactId,
        message_id: &MessageId,
        status: MessageStatus,
    ) -> Result<Option<StoredMessage>, StorageError> {
        let id: Option<i64> = self
            .conn
            .query_row(
                "UPDATE messages SET status = ?3, failed = CASE WHEN ?3 >= 2 THEN 0 ELSE failed END
                 WHERE contact_id = ?1 AND message_id = ?2 AND outgoing = 1 AND status < ?3
                    AND (?3 != 4 OR status < 2)
                 RETURNING id",
                params![contact_id, message_id.as_slice(), status as i64],
                |row| row.get(0),
            )
            .optional()?;
        id.map(|id| self.loaded(id)).transpose()
    }

    /// Each conversation with a contact (not peers), with its latest message and how many of the
    /// contact's messages came after the user last read it.
    pub fn contact_previews(&self) -> Result<Vec<(ContactId, Option<StoredMessage>, u32)>, StorageError> {
        let rows: Vec<(ContactId, Option<i64>, u32)> = {
            let mut statement = self.conn.prepare(&format!(
                "SELECT c.id,
                    (SELECT m.id FROM messages m LEFT JOIN attachments a ON a.message = m.id
                     WHERE m.contact_id = c.id AND {VISIBLE} ORDER BY m.stored_at DESC, m.id DESC LIMIT 1),
                    (SELECT count(*) FROM messages m WHERE m.contact_id = c.id AND m.outgoing = 0
                     AND m.stored_at > c.read_at)
                 FROM contacts c WHERE c.state != 3"
            ))?;
            let rows = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
            rows.collect::<Result<_, _>>()?
        };
        rows.into_iter()
            .map(|(contact, last, unread)| Ok((contact, last.map(|id| self.loaded(id)).transpose()?, unread)))
            .collect()
    }

    /// The user has read the conversation with `contact` up to its latest message.
    pub fn mark_contact_read(&self, contact: ContactId) -> Result<(), StorageError> {
        self.conn.execute(
            "UPDATE contacts SET read_at = max(read_at,
                COALESCE((SELECT max(stored_at) FROM messages WHERE contact_id = ?1), 0))
             WHERE id = ?1",
            params![contact],
        )?;
        Ok(())
    }

    /// A voice message that came in was played: its time starts now, if it had not started.
    /// Returns whether it started.
    pub fn voice_played(&self, id: i64, now_ms: i64) -> Result<bool, StorageError> {
        Ok(self.conn.execute(
            "UPDATE attachments SET played_at = ?2
             WHERE message = ?1 AND played_at = 0 AND state = 2 AND mime = ?3 AND size <= ?4
             AND message IN (SELECT id FROM messages WHERE outgoing = 0)",
            params![id, now_ms, VOICE_MIME, MAX_VOICE_BYTES as i64],
        )? > 0)
    }

    /// Voice messages first played before `before_ms`: their content goes (the caller deletes the
    /// files) and they are marked gone. Returns them.
    pub fn expire_voice(&self, before_ms: i64) -> Result<Vec<StoredMessage>, StorageError> {
        let ids: Vec<i64> = {
            let mut statement = self.conn.prepare(
                "UPDATE attachments SET state = 4, stored = 0
                 WHERE played_at > 0 AND played_at <= ?1 AND state = 2 RETURNING message",
            )?;
            let rows = statement.query_map(params![before_ms], |row| row.get(0))?;
            rows.collect::<Result<_, _>>()?
        };
        ids.into_iter().map(|id| self.loaded(id)).collect()
    }

    /// Gives up the outgoing messages tried since `cutoff_ms` or longer without an
    /// acknowledgement; returns them.
    pub fn give_up_undelivered(&self, cutoff_ms: i64) -> Result<Vec<StoredMessage>, StorageError> {
        let ids: Vec<i64> = {
            let mut statement = self.conn.prepare(
                "UPDATE messages SET failed = 1
                 WHERE outgoing = 1 AND status IN (0, 1) AND failed = 0 AND max(stored_at, tried_at) <= ?1
                 RETURNING id",
            )?;
            let rows = statement.query_map(params![cutoff_ms], |row| row.get(0))?;
            rows.collect::<Result<_, _>>()?
        };
        ids.into_iter().map(|id| self.loaded(id)).collect()
    }

    /// Tries a message given up again from now (`now_ms`): it is queued afresh. Returns it, or
    /// `None` if `id` names no outgoing message given up.
    pub fn try_again(&self, id: i64, now_ms: i64) -> Result<Option<StoredMessage>, StorageError> {
        let id: Option<i64> = self
            .conn
            .query_row(
                "UPDATE messages SET failed = 0, status = 0, tried_at = ?2
                 WHERE id = ?1 AND outgoing = 1 AND failed = 1
                 RETURNING id",
                params![id, now_ms],
                |row| row.get(0),
            )
            .optional()?;
        id.map(|id| self.loaded(id)).transpose()
    }

    fn loaded(&self, id: i64) -> Result<StoredMessage, StorageError> {
        Ok(self
            .conn
            .query_row(&format!("{SELECT} WHERE m.id = ?1"), params![id], message)?)
    }

    fn list(&self, sql: &str, params: impl rusqlite::Params) -> Result<Vec<StoredMessage>, StorageError> {
        let mut statement = self.conn.prepare(sql)?;
        let rows = statement.query_map(params, message)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }
}

/// The attachment in the 7 columns from `first` (name, mime, size, sha256, thumbnail, stored, state)
/// of a row joined with an attachment table; none if the join found none.
pub(super) fn attachment_at(row: &Row, first: usize) -> rusqlite::Result<Option<Attachment>> {
    Ok(match row.get::<_, Option<String>>(first)? {
        None => None,
        Some(name) => Some(Attachment {
            name,
            mime: row.get(first + 1)?,
            size: u64::try_from(row.get::<_, i64>(first + 2)?).unwrap_or(0),
            sha256: row.get(first + 3)?,
            thumbnail: row.get(first + 4)?,
            stored: u64::try_from(row.get::<_, i64>(first + 5)?).unwrap_or(0),
            state: AttachmentState::from_i64(row.get(first + 6)?)?,
            played_at_ms: 0,
        }),
    })
}

fn message(row: &Row) -> rusqlite::Result<StoredMessage> {
    let attachment = attachment_at(row, 8)?.map(|mut a| {
        a.played_at_ms = row.get::<_, Option<i64>>(16).ok().flatten().unwrap_or(0);
        a
    });
    Ok(StoredMessage {
        id: row.get(0)?,
        contact_id: row.get(1)?,
        message_id: row.get(2)?,
        outgoing: row.get::<_, i64>(3)? == 1,
        body: row.get(4)?,
        sent_at_ms: row.get(5)?,
        stored_at_ms: row.get(6)?,
        status: MessageStatus::from_i64(row.get(7)?)?,
        attachment,
        tried_at_ms: row.get(15)?,
    })
}
