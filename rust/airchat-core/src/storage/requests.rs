//! Adding contacts by AirChat ID (rust/airchat-protocol/docs/protocol.md §4.8): the IDs this device's user typed, and the
//! requests others made to be added.

use rusqlite::{OptionalExtension, params};

use super::{Database, StorageError};
use crate::identity::{AirChatId, PublicIdentity};

/// What the user said to a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestState {
    /// Not answered yet.
    Pending = 0,
    /// Add them: done at the next pairing with them.
    Approved = 1,
    /// Never: their next requests are turned away unseen.
    Declined = 2,
}

/// Someone who asked to be added. Its identity key is proven; the name is its own claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactRequest {
    pub identity: PublicIdentity,
    pub display_name: String,
    pub received_at_ms: i64,
}

impl Database {
    /// Remembers an ID the user typed; `false` if it was there already.
    pub fn add_sent_request(&self, id: &AirChatId, now_ms: i64) -> Result<bool, StorageError> {
        Ok(self.conn.execute(
            "INSERT OR IGNORE INTO sent_requests (airchat_id, created_at) VALUES (?1, ?2)",
            params![id.as_bytes().as_slice(), now_ms],
        )? > 0)
    }

    /// The IDs typed and not yet added, oldest first.
    pub fn sent_requests(&self) -> Result<Vec<AirChatId>, StorageError> {
        let mut statement = self
            .conn
            .prepare("SELECT airchat_id FROM sent_requests ORDER BY created_at, airchat_id")?;
        let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        rows.map(|row| {
            let bytes: [u8; 15] = row?.try_into().map_err(|_| StorageError::Corrupt)?;
            Ok(AirChatId::from_bytes(bytes))
        })
        .collect()
    }

    pub fn delete_sent_request(&self, id: &AirChatId) -> Result<bool, StorageError> {
        Ok(self.conn.execute(
            "DELETE FROM sent_requests WHERE airchat_id = ?1",
            params![id.as_bytes().as_slice()],
        )? > 0)
    }

    /// Records a request from `identity`, or updates the name of a pending one; returns what the
    /// user said to it so far.
    pub fn note_contact_request(
        &self,
        identity: &PublicIdentity,
        display_name: &str,
        now_ms: i64,
    ) -> Result<RequestState, StorageError> {
        let state: i64 = self.conn.query_row(
            "INSERT INTO contact_requests (identity, display_name, received_at) VALUES (?1, ?2, ?3)
             ON CONFLICT (identity) DO UPDATE SET
                display_name = iif(state = 0, excluded.display_name, display_name),
                received_at = iif(state = 0, excluded.received_at, received_at)
             RETURNING state",
            params![identity.as_bytes().as_slice(), display_name, now_ms],
            |row| row.get(0),
        )?;
        Ok(match state {
            1 => RequestState::Approved,
            2 => RequestState::Declined,
            _ => RequestState::Pending,
        })
    }

    /// Requests not answered yet, newest first.
    pub fn contact_requests(&self) -> Result<Vec<ContactRequest>, StorageError> {
        let mut statement = self.conn.prepare(
            "SELECT identity, display_name, received_at FROM contact_requests WHERE state = 0
             ORDER BY received_at DESC",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;
        rows.map(|row| {
            let (identity, display_name, received_at_ms) = row?;
            let identity: [u8; 32] = identity.try_into().map_err(|_| StorageError::Corrupt)?;
            Ok(ContactRequest {
                identity: PublicIdentity::from_bytes(identity),
                display_name,
                received_at_ms,
            })
        })
        .collect()
    }

    /// What the user said to `identity`'s request, if it made one.
    pub fn contact_request_state(&self, identity: &PublicIdentity) -> Result<Option<RequestState>, StorageError> {
        let state: Option<i64> = self
            .conn
            .query_row(
                "SELECT state FROM contact_requests WHERE identity = ?1",
                params![identity.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        Ok(state.map(|state| match state {
            1 => RequestState::Approved,
            2 => RequestState::Declined,
            _ => RequestState::Pending,
        }))
    }

    /// Records the user's answer to a request; `false` if there is none from `identity`.
    pub fn answer_contact_request(&self, identity: &PublicIdentity, state: RequestState) -> Result<bool, StorageError> {
        Ok(self.conn.execute(
            "UPDATE contact_requests SET state = ?2 WHERE identity = ?1",
            params![identity.as_bytes().as_slice(), state as i64],
        )? > 0)
    }

    /// Forgets a request, once its sender is a contact.
    pub fn delete_contact_request(&self, identity: &PublicIdentity) -> Result<(), StorageError> {
        self.conn.execute(
            "DELETE FROM contact_requests WHERE identity = ?1",
            params![identity.as_bytes().as_slice()],
        )?;
        Ok(())
    }
}
