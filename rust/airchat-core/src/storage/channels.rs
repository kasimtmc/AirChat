//! Walkie-talkie channels this device holds the key of (rust/airchat-protocol/docs/protocol.md §11).

use rusqlite::{OptionalExtension, Row, params};
use zeroize::Zeroizing;

use super::{Database, StorageError};
use crate::{
    channel::{Channel, ChannelId},
    crypto::SecretBytes,
};

/// What the channel list shows; no key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelSummary {
    pub row: i64,
    pub channel_id: ChannelId,
    pub name: String,
    /// This device listens on it and announces itself to its members.
    pub tuned: bool,
    /// Until when (Unix ms) its talk does not play; 0 if not muted.
    pub muted_until: i64,
}

const SUMMARY: &str = "id, channel_id, name, tuned, muted_until";

impl Database {
    /// Keeps a channel; one already kept (the same key) keeps its row and gets the new name.
    pub fn save_channel(&self, channel: &Channel, name: &str, now_ms: i64) -> Result<ChannelSummary, StorageError> {
        let row: i64 = self.conn.query_row(
            "INSERT INTO channels (channel_id, name, key, created_at) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (channel_id) DO UPDATE SET name = excluded.name
             RETURNING id",
            params![channel.id().as_slice(), name, channel.key().expose().as_slice(), now_ms],
            |row| row.get(0),
        )?;
        self.channel_summary(row)?.ok_or(StorageError::Corrupt)
    }

    pub fn channels(&self) -> Result<Vec<ChannelSummary>, StorageError> {
        let mut statement = self.conn.prepare(&format!(
            "SELECT {SUMMARY} FROM channels ORDER BY name COLLATE NOCASE, id"
        ))?;
        let rows = statement.query_map([], summary)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn channel_summary(&self, row: i64) -> Result<Option<ChannelSummary>, StorageError> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {SUMMARY} FROM channels WHERE id = ?1"),
                params![row],
                summary,
            )
            .optional()?)
    }

    /// A channel with its key.
    pub fn channel(&self, row: i64) -> Result<Option<(ChannelSummary, Channel)>, StorageError> {
        let found = self
            .conn
            .query_row(
                &format!("SELECT {SUMMARY}, key FROM channels WHERE id = ?1"),
                params![row],
                |row| Ok((summary(row)?, Zeroizing::new(row.get::<_, Vec<u8>>(5)?))),
            )
            .optional()?;
        found
            .map(|(summary, key)| {
                let channel = Channel::from_key(SecretBytes::from_slice(&key)?).map_err(|_| StorageError::Corrupt)?;
                Ok((summary, channel))
            })
            .transpose()
    }

    /// The channel tuned in, if any, with its key.
    pub fn tuned_channel(&self) -> Result<Option<(ChannelSummary, Channel)>, StorageError> {
        let row: Option<i64> = self
            .conn
            .query_row("SELECT id FROM channels WHERE tuned = 1", [], |row| row.get(0))
            .optional()?;
        row.map(|row| self.channel(row)).transpose().map(Option::flatten)
    }

    /// Tunes in to `row`, or to none; the one tuned before stops being.
    pub fn tune_channel(&self, row: Option<i64>) -> Result<bool, StorageError> {
        let transaction = self.conn.unchecked_transaction()?;
        transaction.execute("UPDATE channels SET tuned = 0 WHERE tuned = 1", [])?;
        let found = match row {
            Some(row) => transaction.execute("UPDATE channels SET tuned = 1 WHERE id = ?1", params![row])? > 0,
            None => true,
        };
        transaction.commit()?;
        Ok(found)
    }

    /// Mutes a channel until `until_ms` (Unix ms), or unmutes it with 0.
    pub fn set_channel_muted(&self, row: i64, until_ms: i64) -> Result<bool, StorageError> {
        Ok(self.conn.execute(
            "UPDATE channels SET muted_until = ?2 WHERE id = ?1",
            params![row, until_ms],
        )? > 0)
    }

    pub fn rename_channel(&self, row: i64, name: &str) -> Result<bool, StorageError> {
        Ok(self
            .conn
            .execute("UPDATE channels SET name = ?2 WHERE id = ?1", params![row, name])?
            > 0)
    }

    /// Forgets a channel and its key.
    pub fn delete_channel(&self, row: i64) -> Result<bool, StorageError> {
        Ok(self.conn.execute("DELETE FROM channels WHERE id = ?1", params![row])? > 0)
    }
}

fn summary(row: &Row) -> rusqlite::Result<ChannelSummary> {
    Ok(ChannelSummary {
        row: row.get(0)?,
        channel_id: row.get(1)?,
        name: row.get(2)?,
        tuned: row.get(3)?,
        muted_until: row.get(4)?,
    })
}
