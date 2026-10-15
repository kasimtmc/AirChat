//! One-time prekeys for texts in mesh envelopes (rust/airchat-protocol/docs/protocol.md §10.7): the private halves of
//! those this device handed to its contacts, and the public ones its contacts handed to it.

use rusqlite::{OptionalExtension, params};
use zeroize::Zeroizing;

use super::{ContactId, Database, MessageId, StorageError};
use crate::crypto::kem::{ENCAPSULATION_KEY_LEN, EncapsulationKey, SEED_LEN};

/// A prekey this device handed to a contact: its id and the seed of its private half.
pub struct OwnPrekey {
    pub contact: ContactId,
    pub prekey: u32,
    pub seed: Zeroizing<[u8; SEED_LEN]>,
}

/// A contact's prekey, and the message sealed to it, if one was.
pub struct TheirPrekey {
    pub contact: ContactId,
    pub prekey: u32,
    pub key: EncapsulationKey,
    pub message_id: Option<MessageId>,
}

/// A device keeps at most this many of one contact's prekeys.
pub const MAX_THEIRS: usize = 48;

impl Database {
    /// Stores the private half of a prekey just handed to a contact; false if the id is taken.
    pub fn add_own_prekey(
        &self,
        contact: ContactId,
        prekey: u32,
        seed: &[u8; SEED_LEN],
        created_at_ms: i64,
    ) -> Result<bool, StorageError> {
        let added = self.conn.execute(
            "INSERT OR IGNORE INTO own_prekeys (contact_id, prekey, seed, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![contact, prekey, seed.as_slice(), created_at_ms],
        )?;
        Ok(added > 0)
    }

    /// Every prekey this device handed out and has not used, deleting those created before
    /// `cutoff_ms` first.
    pub fn own_prekeys(&self, cutoff_ms: i64) -> Result<Vec<OwnPrekey>, StorageError> {
        self.conn
            .execute("DELETE FROM own_prekeys WHERE created_at < ?1", params![cutoff_ms])?;
        let mut statement = self
            .conn
            .prepare("SELECT contact_id, prekey, seed FROM own_prekeys ORDER BY contact_id, created_at")?;
        let rows = statement.query_map([], |row| {
            let seed: Zeroizing<Vec<u8>> = Zeroizing::new(row.get(2)?);
            Ok((row.get(0)?, row.get(1)?, seed))
        })?;
        let mut prekeys = Vec::new();
        for row in rows {
            let (contact, prekey, seed) = row?;
            let mut own = Zeroizing::new([0; SEED_LEN]);
            if seed.len() != SEED_LEN {
                return Err(StorageError::Corrupt);
            }
            own.copy_from_slice(&seed);
            prekeys.push(OwnPrekey {
                contact,
                prekey,
                seed: own,
            });
        }
        Ok(prekeys)
    }

    /// A prekey was used: its private half goes (`secure_delete` overwrites it in the file).
    pub fn delete_own_prekey(&self, contact: ContactId, prekey: u32) -> Result<(), StorageError> {
        self.conn.execute(
            "DELETE FROM own_prekeys WHERE contact_id = ?1 AND prekey = ?2",
            params![contact, prekey],
        )?;
        Ok(())
    }

    /// Stores prekeys a contact handed over, keeping at most [`MAX_THEIRS`] of theirs: the oldest
    /// unused ones go first.
    pub fn add_their_prekeys(
        &self,
        contact: ContactId,
        prekeys: &[(u32, EncapsulationKey)],
        received_at_ms: i64,
    ) -> Result<(), StorageError> {
        let transaction = self.conn.unchecked_transaction()?;
        for (prekey, key) in prekeys {
            transaction.execute(
                "INSERT OR IGNORE INTO their_prekeys (contact_id, prekey, key, received_at) VALUES (?1, ?2, ?3, ?4)",
                params![contact, prekey, key.as_bytes().as_slice(), received_at_ms],
            )?;
        }
        transaction.execute(
            "DELETE FROM their_prekeys WHERE contact_id = ?1 AND message_id IS NULL AND prekey NOT IN (
                SELECT prekey FROM their_prekeys WHERE contact_id = ?1 AND message_id IS NULL
                ORDER BY received_at DESC, rowid DESC LIMIT ?2)",
            params![contact, MAX_THEIRS as i64],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Every contact's prekeys, oldest first, deleting unused ones received before
    /// `unused_cutoff_ms` and used ones before `used_cutoff_ms` first.
    pub fn their_prekeys(&self, unused_cutoff_ms: i64, used_cutoff_ms: i64) -> Result<Vec<TheirPrekey>, StorageError> {
        self.conn.execute(
            "DELETE FROM their_prekeys WHERE (message_id IS NULL AND received_at < ?1)
                OR (message_id IS NOT NULL AND received_at < ?2)",
            params![unused_cutoff_ms, used_cutoff_ms],
        )?;
        let mut statement = self.conn.prepare(
            "SELECT contact_id, prekey, key, message_id FROM their_prekeys ORDER BY contact_id, received_at, rowid",
        )?;
        let rows = statement.query_map([], |row| {
            let key: Vec<u8> = row.get(2)?;
            let message: Option<Vec<u8>> = row.get(3)?;
            Ok((row.get(0)?, row.get(1)?, key, message))
        })?;
        let mut prekeys = Vec::new();
        for row in rows {
            let (contact, prekey, key, message) = row?;
            if key.len() != ENCAPSULATION_KEY_LEN {
                return Err(StorageError::Corrupt);
            }
            let message_id = message
                .map(|m| MessageId::try_from(m.as_slice()).map_err(|_| StorageError::Corrupt))
                .transpose()?;
            prekeys.push(TheirPrekey {
                contact,
                prekey,
                key: EncapsulationKey::from_bytes(&key)?,
                message_id,
            });
        }
        Ok(prekeys)
    }

    /// A contact's prekey is used for a message (and its resends).
    pub fn bind_their_prekey(
        &self,
        contact: ContactId,
        prekey: u32,
        message_id: &MessageId,
    ) -> Result<(), StorageError> {
        self.conn.execute(
            "UPDATE their_prekeys SET message_id = ?3 WHERE contact_id = ?1 AND prekey = ?2",
            params![contact, prekey, message_id.as_slice()],
        )?;
        Ok(())
    }

    /// The message sealed to a contact's prekey was answered: the prekey is done with.
    pub fn release_their_prekey(&self, contact: ContactId, message_id: &MessageId) -> Result<(), StorageError> {
        self.conn.execute(
            "DELETE FROM their_prekeys WHERE contact_id = ?1 AND message_id = ?2",
            params![contact, message_id.as_slice()],
        )?;
        Ok(())
    }

    /// How many of a contact's prekeys this device holds unused.
    pub fn unused_their_prekeys(&self, contact: ContactId) -> Result<usize, StorageError> {
        let count: Option<i64> = self
            .conn
            .query_row(
                "SELECT count(*) FROM their_prekeys WHERE contact_id = ?1 AND message_id IS NULL",
                params![contact],
                |row| row.get(0),
            )
            .optional()?;
        Ok(usize::try_from(count.unwrap_or(0)).unwrap_or(0))
    }

    /// Both sides' prekeys of a contact go: its keys changed or were forgotten.
    pub(super) fn forget_prekeys(&self, contact: ContactId) -> Result<(), StorageError> {
        self.conn
            .execute("DELETE FROM own_prekeys WHERE contact_id = ?1", params![contact])?;
        self.conn
            .execute("DELETE FROM their_prekeys WHERE contact_id = ?1", params![contact])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto::kem::DecapsulationKey, storage::database::tests::test_db_with_contact};

    #[test]
    fn prekeys_are_stored_bound_released_and_capped() {
        let (db, contact) = test_db_with_contact();
        let mine = DecapsulationKey::generate().unwrap();
        assert!(
            db.add_own_prekey(contact, 7, &mine.seed().expose().clone(), 1_000)
                .unwrap()
        );
        assert!(!db.add_own_prekey(contact, 7, &[1; 32], 1_000).unwrap(), "id taken");
        assert_eq!(db.own_prekeys(0).unwrap().len(), 1);
        db.delete_own_prekey(contact, 7).unwrap();
        assert!(db.own_prekeys(0).unwrap().is_empty());

        let theirs: Vec<(u32, EncapsulationKey)> = (1..=50)
            .map(|i| (i, DecapsulationKey::generate().unwrap().encapsulation_key().clone()))
            .collect();
        db.add_their_prekeys(contact, &theirs, 2_000).unwrap();
        assert_eq!(db.unused_their_prekeys(contact).unwrap(), MAX_THEIRS);
        let oldest = db.their_prekeys(0, 0).unwrap()[0].prekey;
        db.bind_their_prekey(contact, oldest, &[9; 16]).unwrap();
        assert_eq!(db.unused_their_prekeys(contact).unwrap(), MAX_THEIRS - 1);
        let bound = db
            .their_prekeys(0, 0)
            .unwrap()
            .into_iter()
            .find(|p| p.prekey == oldest)
            .unwrap();
        assert_eq!(bound.message_id, Some([9; 16]));
        db.release_their_prekey(contact, &[9; 16]).unwrap();
        assert_eq!(db.their_prekeys(0, 0).unwrap().len(), MAX_THEIRS - 1);
        // Old ones expire.
        assert!(db.their_prekeys(3_000, 3_000).unwrap().is_empty());
        db.forget_prekeys(contact).unwrap();
    }
}
