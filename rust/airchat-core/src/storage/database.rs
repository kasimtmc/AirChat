//! The encrypted SQLite (SQLCipher) database.

use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};
use zeroize::Zeroizing;

use super::{StorageError, vault::Vault};
use crate::{crypto::SecretBytes, identity::Identity};

/// Schema migrations, applied in order. `PRAGMA user_version` records how many have run.
/// Never edit a released migration; append a new one.
const MIGRATIONS: &[&str] = &[
    // 1: the owner's identity.
    "CREATE TABLE identity (
        id           INTEGER PRIMARY KEY CHECK (id = 1),
        seed         BLOB    NOT NULL CHECK (length(seed) = 32),
        display_name TEXT    NOT NULL,
        created_at   INTEGER NOT NULL
    ) STRICT;",
    // 2: the owner's link keys, and contacts. The keys are NULL only in accounts created before
    // this migration; the account generates them on first open.
    "ALTER TABLE identity ADD COLUMN static_kem_seed BLOB CHECK (length(static_kem_seed) = 32);
     ALTER TABLE identity ADD COLUMN presence_key BLOB CHECK (length(presence_key) = 32);
     CREATE TABLE contacts (
        id           INTEGER PRIMARY KEY,
        identity     BLOB    NOT NULL UNIQUE CHECK (length(identity) = 32),
        static_kem   BLOB    NOT NULL CHECK (length(static_kem) = 1216),
        display_name TEXT    NOT NULL,
        presence_key BLOB    NOT NULL CHECK (length(presence_key) = 32),
        link_psk     BLOB    NOT NULL CHECK (length(link_psk) = 32),
        added_at     INTEGER NOT NULL
     ) STRICT;",
    // 3: 1:1 messages. Deleting a contact deletes the conversation.
    "CREATE TABLE messages (
        id          INTEGER PRIMARY KEY,
        contact_id  INTEGER NOT NULL REFERENCES contacts (id) ON DELETE CASCADE,
        message_id  BLOB    NOT NULL CHECK (length(message_id) = 16),
        outgoing    INTEGER NOT NULL CHECK (outgoing IN (0, 1)),
        body        TEXT    NOT NULL,
        sent_at     INTEGER NOT NULL,
        stored_at   INTEGER NOT NULL,
        status      INTEGER NOT NULL CHECK (status BETWEEN 0 AND 3),
        UNIQUE (contact_id, message_id)
     ) STRICT;
     CREATE INDEX messages_by_contact ON messages (contact_id, stored_at, id);",
    // 4: the key that messages received while the app is locked are encrypted to.
    "ALTER TABLE identity ADD COLUMN inbox_seed BLOB CHECK (length(inbox_seed) = 32);",
    // 5: the files of file messages; their content is in the file store, named by the message row.
    "CREATE TABLE attachments (
        message   INTEGER PRIMARY KEY REFERENCES messages (id) ON DELETE CASCADE,
        name      TEXT    NOT NULL,
        mime      TEXT    NOT NULL,
        size      INTEGER NOT NULL CHECK (size >= 0),
        sha256    BLOB    NOT NULL CHECK (length(sha256) = 32),
        thumbnail BLOB,
        stored    INTEGER NOT NULL CHECK (stored BETWEEN 0 AND size),
        state     INTEGER NOT NULL CHECK (state BETWEEN 0 AND 5)
     ) STRICT;",
    // 6: blocked contacts, contacts deleted with their history kept (keys wiped), per-contact
    // permissions (requirements C-5 to C-7); and a fifth message status, refused. A CHECK
    // constraint cannot be altered, so the messages table is rebuilt.
    "ALTER TABLE contacts ADD COLUMN state INTEGER NOT NULL DEFAULT 0 CHECK (state BETWEEN 0 AND 2);
     ALTER TABLE contacts ADD COLUMN allow_messages INTEGER NOT NULL DEFAULT 1 CHECK (allow_messages IN (0, 1));
     ALTER TABLE contacts ADD COLUMN allow_ptt INTEGER NOT NULL DEFAULT 0 CHECK (allow_ptt IN (0, 1));
     ALTER TABLE contacts ADD COLUMN auto_download INTEGER NOT NULL DEFAULT 0 CHECK (auto_download IN (0, 1));
     CREATE TABLE messages_new (
        id          INTEGER PRIMARY KEY,
        contact_id  INTEGER NOT NULL REFERENCES contacts (id) ON DELETE CASCADE,
        message_id  BLOB    NOT NULL CHECK (length(message_id) = 16),
        outgoing    INTEGER NOT NULL CHECK (outgoing IN (0, 1)),
        body        TEXT    NOT NULL,
        sent_at     INTEGER NOT NULL,
        stored_at   INTEGER NOT NULL,
        status      INTEGER NOT NULL CHECK (status BETWEEN 0 AND 4),
        UNIQUE (contact_id, message_id)
     ) STRICT;
     INSERT INTO messages_new SELECT id, contact_id, message_id, outgoing, body, sent_at, stored_at, status FROM messages;
     DROP TABLE messages;
     ALTER TABLE messages_new RENAME TO messages;
     CREATE INDEX messages_by_contact ON messages (contact_id, stored_at, id);",
    // 7: groups (rust/airchat-protocol/docs/protocol.md §9). Contacts get a fourth state, peer: someone known only
    // through a group, whose keys come from its roster (the contacts table is rebuilt for the new
    // CHECK). A group keeps its current and previous epoch (key and roster), the updates to pass
    // on, its messages, and what waits to be passed on to whom.
    "CREATE TABLE contacts_new (
        id             INTEGER PRIMARY KEY,
        identity       BLOB    NOT NULL UNIQUE CHECK (length(identity) = 32),
        static_kem     BLOB    NOT NULL CHECK (length(static_kem) = 1216),
        display_name   TEXT    NOT NULL,
        presence_key   BLOB    NOT NULL CHECK (length(presence_key) = 32),
        link_psk       BLOB    NOT NULL CHECK (length(link_psk) = 32),
        added_at       INTEGER NOT NULL,
        state          INTEGER NOT NULL DEFAULT 0 CHECK (state BETWEEN 0 AND 3),
        allow_messages INTEGER NOT NULL DEFAULT 1 CHECK (allow_messages IN (0, 1)),
        allow_ptt      INTEGER NOT NULL DEFAULT 0 CHECK (allow_ptt IN (0, 1)),
        auto_download  INTEGER NOT NULL DEFAULT 0 CHECK (auto_download IN (0, 1))
     ) STRICT;
     INSERT INTO contacts_new SELECT id, identity, static_kem, display_name, presence_key, link_psk, added_at,
        state, allow_messages, allow_ptt, auto_download FROM contacts;
     DROP TABLE contacts;
     ALTER TABLE contacts_new RENAME TO contacts;
     CREATE TABLE groups (
        id              INTEGER PRIMARY KEY,
        group_id        BLOB    NOT NULL UNIQUE CHECK (length(group_id) = 16),
        name            TEXT    NOT NULL,
        epoch           INTEGER NOT NULL CHECK (epoch >= 0),
        epoch_key       BLOB    NOT NULL CHECK (length(epoch_key) = 32),
        roster          BLOB    NOT NULL,
        previous_key    BLOB    CHECK (length(previous_key) = 32),
        previous_roster BLOB,
        state           INTEGER NOT NULL DEFAULT 0 CHECK (state BETWEEN 0 AND 2),
        created_at      INTEGER NOT NULL
     ) STRICT;
     CREATE TABLE group_updates (
        id      INTEGER PRIMARY KEY,
        group_  INTEGER NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
        epoch   INTEGER NOT NULL,
        bytes   BLOB    NOT NULL,
        UNIQUE (group_, epoch)
     ) STRICT;
     CREATE TABLE group_messages (
        id         INTEGER PRIMARY KEY,
        group_     INTEGER NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
        message_id BLOB    NOT NULL CHECK (length(message_id) = 16),
        sender     BLOB    NOT NULL CHECK (length(sender) = 32),
        outgoing   INTEGER NOT NULL CHECK (outgoing IN (0, 1)),
        body       TEXT    NOT NULL,
        sent_at    INTEGER NOT NULL,
        stored_at  INTEGER NOT NULL,
        status     INTEGER NOT NULL CHECK (status BETWEEN 0 AND 2),
        sealed     BLOB    NOT NULL,
        UNIQUE (group_, message_id)
     ) STRICT;
     CREATE INDEX group_messages_by_group ON group_messages (group_, stored_at, id);
     CREATE TABLE group_outbox (
        kind      INTEGER NOT NULL CHECK (kind BETWEEN 0 AND 2),
        item      INTEGER NOT NULL,
        recipient INTEGER NOT NULL REFERENCES contacts (id) ON DELETE CASCADE,
        queued_at INTEGER NOT NULL,
        PRIMARY KEY (kind, item, recipient)
     ) STRICT;
     CREATE INDEX group_outbox_by_recipient ON group_outbox (recipient);",
    // 8: whether a group's push-to-talk plays at once (requirement V-3).
    "ALTER TABLE groups ADD COLUMN allow_ptt INTEGER NOT NULL DEFAULT 0 CHECK (allow_ptt IN (0, 1));",
    // 9: the files of group file messages; their content is in the file store under the negated
    // message row (docs/architecture.md §4.5).
    "CREATE TABLE group_attachments (
        message   INTEGER PRIMARY KEY REFERENCES group_messages (id) ON DELETE CASCADE,
        name      TEXT    NOT NULL,
        mime      TEXT    NOT NULL,
        size      INTEGER NOT NULL CHECK (size >= 0),
        sha256    BLOB    NOT NULL CHECK (length(sha256) = 32),
        thumbnail BLOB,
        stored    INTEGER NOT NULL CHECK (stored BETWEEN 0 AND size),
        state     INTEGER NOT NULL CHECK (state BETWEEN 0 AND 5)
     ) STRICT;",
    // 10: walkie-talkie channels (rust/airchat-protocol/docs/protocol.md §11); at most one is tuned in.
    "CREATE TABLE channels (
        id         INTEGER PRIMARY KEY,
        channel_id BLOB    NOT NULL UNIQUE CHECK (length(channel_id) = 16),
        name       TEXT    NOT NULL,
        key        BLOB    NOT NULL CHECK (length(key) = 32),
        tuned      INTEGER NOT NULL DEFAULT 0 CHECK (tuned IN (0, 1)),
        created_at INTEGER NOT NULL
     ) STRICT;
     CREATE UNIQUE INDEX one_tuned_channel ON channels (tuned) WHERE tuned = 1;",
    // 11: muting a contact, a group or a channel until a time (Unix ms; 0 for not muted).
    "ALTER TABLE contacts ADD COLUMN muted_until INTEGER NOT NULL DEFAULT 0;
     ALTER TABLE groups ADD COLUMN muted_until INTEGER NOT NULL DEFAULT 0;
     ALTER TABLE channels ADD COLUMN muted_until INTEGER NOT NULL DEFAULT 0;",
    // 12: one-time prekeys for texts in mesh envelopes (rust/airchat-protocol/docs/protocol.md §10.7): the private halves
    // of those this device handed to each contact, and those each contact handed to it, with the
    // message each was used for, so resends use the same one.
    "CREATE TABLE own_prekeys (
        contact_id INTEGER NOT NULL REFERENCES contacts (id) ON DELETE CASCADE,
        prekey     INTEGER NOT NULL CHECK (prekey > 0 AND prekey <= 4294967295),
        seed       BLOB    NOT NULL CHECK (length(seed) = 32),
        created_at INTEGER NOT NULL,
        PRIMARY KEY (contact_id, prekey)
     ) STRICT;
     CREATE TABLE their_prekeys (
        contact_id  INTEGER NOT NULL REFERENCES contacts (id) ON DELETE CASCADE,
        prekey      INTEGER NOT NULL CHECK (prekey > 0 AND prekey <= 4294967295),
        key         BLOB    NOT NULL CHECK (length(key) = 1216),
        received_at INTEGER NOT NULL,
        message_id  BLOB    CHECK (message_id IS NULL OR length(message_id) = 16),
        PRIMARY KEY (contact_id, prekey)
     ) STRICT;",
    // 13: the key of a file's parts through the mesh (rust/airchat-protocol/docs/protocol.md §10.8), kept by the sender
    // until the file is answered and by the recipient until it is whole.
    "ALTER TABLE attachments ADD COLUMN mesh_key BLOB CHECK (mesh_key IS NULL OR length(mesh_key) = 32);",
    // 14: the keys a contact's links are made with (rust/airchat-protocol/docs/protocol.md §6.8), newest first, 32 bytes
    // each; NULL until the first link after pairing, which means the pairing secret alone.
    "ALTER TABLE contacts ADD COLUMN link_keys BLOB
        CHECK (link_keys IS NULL OR (length(link_keys) % 32 = 0 AND length(link_keys) BETWEEN 32 AND 128));",
    // 15: static key versions (rust/airchat-protocol/docs/protocol.md §6.9): the owner's, kept while someone may still
    // use them (the newest is also in `identity`); each contact's or peer's version of its key, up
    // to two earlier keys of a contact, and the newest of the owner's a contact has taken.
    "CREATE TABLE static_keys (
        version    INTEGER PRIMARY KEY CHECK (version BETWEEN 0 AND 4294967295),
        seed       BLOB    NOT NULL CHECK (length(seed) = 32),
        created_at INTEGER NOT NULL
     ) STRICT;
     ALTER TABLE contacts ADD COLUMN static_kem_version INTEGER NOT NULL DEFAULT 0;
     ALTER TABLE contacts ADD COLUMN earlier_static_kems BLOB
        CHECK (earlier_static_kems IS NULL OR length(earlier_static_kems) IN (1216, 2432));
     ALTER TABLE contacts ADD COLUMN own_key_taken INTEGER NOT NULL DEFAULT 0;",
    // 16: adding contacts by AirChat ID (rust/airchat-protocol/docs/protocol.md §4.8): the IDs this device's user typed,
    // and the requests others made, with what the user said to them.
    "CREATE TABLE sent_requests (
        airchat_id BLOB    PRIMARY KEY CHECK (length(airchat_id) = 15),
        created_at INTEGER NOT NULL
     ) STRICT;
     CREATE TABLE contact_requests (
        identity     BLOB    PRIMARY KEY CHECK (length(identity) = 32),
        display_name TEXT    NOT NULL,
        received_at  INTEGER NOT NULL,
        state        INTEGER NOT NULL DEFAULT 0 CHECK (state BETWEEN 0 AND 2)
     ) STRICT;",
    // 17: presence key versions (rust/airchat-protocol/docs/protocol.md §5.4): the owner's, and of each contact both
    // its own (as last told) and the newest of the owner's it took.
    "ALTER TABLE identity ADD COLUMN presence_version INTEGER NOT NULL DEFAULT 0;
     ALTER TABLE contacts ADD COLUMN presence_version INTEGER NOT NULL DEFAULT 0;
     ALTER TABLE contacts ADD COLUMN presence_key_taken INTEGER NOT NULL DEFAULT 0;",
    // 18: an outgoing message, 1:1 or in a group, not acknowledged within a day is given up
    // (rust/airchat-protocol/docs/protocol.md §9.5, §10.5) until the user tries it again: when the current try began (0: when it was written), and
    // whether it was given up. A flag rather than a status: the status CHECK cannot be altered.
    "ALTER TABLE messages ADD COLUMN tried_at INTEGER NOT NULL DEFAULT 0;
     ALTER TABLE messages ADD COLUMN failed INTEGER NOT NULL DEFAULT 0 CHECK (failed IN (0, 1));
     ALTER TABLE group_messages ADD COLUMN tried_at INTEGER NOT NULL DEFAULT 0;
     ALTER TABLE group_messages ADD COLUMN failed INTEGER NOT NULL DEFAULT 0 CHECK (failed IN (0, 1));",
    // 19: how far the user has read each conversation (this device's clock, as `stored_at`), for
    // the unread counts of the chat list; what is stored already counts as read.
    "ALTER TABLE contacts ADD COLUMN read_at INTEGER NOT NULL DEFAULT 0;
     ALTER TABLE groups ADD COLUMN read_at INTEGER NOT NULL DEFAULT 0;
     UPDATE contacts SET read_at = COALESCE((SELECT max(stored_at) FROM messages WHERE contact_id = contacts.id), 0);
     UPDATE groups SET read_at = COALESCE((SELECT max(stored_at) FROM group_messages WHERE group_ = groups.id), 0);",
    // 20: a group an admin deleted for every member (state 3), kept out of sight for a day to pass
    // the deletion on (rust/airchat-protocol/docs/protocol.md §9.2). The state CHECK cannot be altered: the table is rebuilt.
    "CREATE TABLE groups_new (
        id              INTEGER PRIMARY KEY,
        group_id        BLOB    NOT NULL UNIQUE CHECK (length(group_id) = 16),
        name            TEXT    NOT NULL,
        epoch           INTEGER NOT NULL CHECK (epoch >= 0),
        epoch_key       BLOB    NOT NULL CHECK (length(epoch_key) = 32),
        roster          BLOB    NOT NULL,
        previous_key    BLOB    CHECK (length(previous_key) = 32),
        previous_roster BLOB,
        state           INTEGER NOT NULL DEFAULT 0 CHECK (state BETWEEN 0 AND 3),
        created_at      INTEGER NOT NULL,
        allow_ptt       INTEGER NOT NULL DEFAULT 0 CHECK (allow_ptt IN (0, 1)),
        muted_until     INTEGER NOT NULL DEFAULT 0,
        read_at         INTEGER NOT NULL DEFAULT 0
     ) STRICT;
     INSERT INTO groups_new (id, group_id, name, epoch, epoch_key, roster, previous_key, previous_roster,
                             state, created_at, allow_ptt, muted_until, read_at)
        SELECT id, group_id, name, epoch, epoch_key, roster, previous_key, previous_roster,
               state, created_at, allow_ptt, muted_until, read_at FROM groups;
     DROP TABLE groups;
     ALTER TABLE groups_new RENAME TO groups;",
    // 21: a group of two whose other member left or ran out ends (state 4, rust/airchat-protocol/docs/protocol.md §9.2).
    // The table is rebuilt for the state CHECK again.
    "CREATE TABLE groups_new (
        id              INTEGER PRIMARY KEY,
        group_id        BLOB    NOT NULL UNIQUE CHECK (length(group_id) = 16),
        name            TEXT    NOT NULL,
        epoch           INTEGER NOT NULL CHECK (epoch >= 0),
        epoch_key       BLOB    NOT NULL CHECK (length(epoch_key) = 32),
        roster          BLOB    NOT NULL,
        previous_key    BLOB    CHECK (length(previous_key) = 32),
        previous_roster BLOB,
        state           INTEGER NOT NULL DEFAULT 0 CHECK (state BETWEEN 0 AND 4),
        created_at      INTEGER NOT NULL,
        allow_ptt       INTEGER NOT NULL DEFAULT 0 CHECK (allow_ptt IN (0, 1)),
        muted_until     INTEGER NOT NULL DEFAULT 0,
        read_at         INTEGER NOT NULL DEFAULT 0
     ) STRICT;
     INSERT INTO groups_new (id, group_id, name, epoch, epoch_key, roster, previous_key, previous_roster,
                             state, created_at, allow_ptt, muted_until, read_at)
        SELECT id, group_id, name, epoch, epoch_key, roster, previous_key, previous_roster,
               state, created_at, allow_ptt, muted_until, read_at FROM groups;
     DROP TABLE groups;
     ALTER TABLE groups_new RENAME TO groups;",
    // 22: when a voice message that came in was first played; it goes 15 minutes later
    // (rust/airchat-protocol/docs/protocol.md §8.4).
    "ALTER TABLE attachments ADD COLUMN played_at INTEGER NOT NULL DEFAULT 0;
     ALTER TABLE group_attachments ADD COLUMN played_at INTEGER NOT NULL DEFAULT 0;",
    // 23: whether a contact's build was attested as the official one on a verified phone
    // (rust/airchat-protocol/docs/protocol.md §6.10): 0 not, 1 by its trusted environment, 2 by its StrongBox; and its
    // security patch level.
    "ALTER TABLE contacts ADD COLUMN attested INTEGER NOT NULL DEFAULT 0 CHECK (attested BETWEEN 0 AND 2);
     ALTER TABLE contacts ADD COLUMN attested_patch INTEGER NOT NULL DEFAULT 0;",
];

/// The migration after which stored rosters list their members' static key versions.
const ROSTER_KEY_VERSIONS: usize = 15;

/// Rewrites the rosters stored before members' static keys had versions (§9.1), giving each
/// member version 0.
fn add_key_versions_to_rosters(tx: &rusqlite::Transaction) -> Result<(), StorageError> {
    let mut statement = tx.prepare("SELECT id, roster, previous_roster FROM groups")?;
    let rows: Vec<(i64, Vec<u8>, Option<Vec<u8>>)> = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<Result<_, _>>()?;
    drop(statement);
    let convert = |bytes: &[u8]| {
        crate::group::Roster::decode_unversioned(bytes)
            .map(|roster| roster.encode())
            .map_err(|_| StorageError::Corrupt)
    };
    for (id, roster, previous) in rows {
        let roster = Zeroizing::new(roster);
        let previous = previous.map(Zeroizing::new);
        let previous = previous.as_deref().map(|bytes| convert(bytes)).transpose()?;
        tx.execute(
            "UPDATE groups SET roster = ?2, previous_roster = ?3 WHERE id = ?1",
            params![
                id,
                convert(&roster)?.as_slice(),
                previous.as_deref().map(|bytes| bytes.as_slice())
            ],
        )?;
    }
    Ok(())
}

pub struct Database {
    pub(super) conn: Connection,
}

impl Database {
    /// Opens (or creates) the database at `path` with the vault's key.
    pub fn open(path: &Path, vault: &Vault) -> Result<Self, StorageError> {
        let conn = Connection::open(path)?;
        let key = vault.database_key()?;
        // SQLCipher raw-key syntax: the key is used as is, without SQLCipher's own PBKDF2.
        let pragma = Zeroizing::new(format!("x'{}'", hex(&key).as_str()));
        conn.pragma_update(None, "key", pragma.as_str())?;

        // A wrong key only shows up on the first read.
        if let Err(e) = conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(())) {
            return Err(match e.sqlite_error_code() {
                Some(rusqlite::ErrorCode::NotADatabase) => StorageError::WrongKey,
                _ => e.into(),
            });
        }

        // Wipe SQLite's heap allocations when freed, keep temporary data in memory, and overwrite
        // deleted rows.
        conn.pragma_update(None, "cipher_memory_security", "ON")?;
        conn.pragma_update(None, "temp_store", "MEMORY")?;
        conn.pragma_update(None, "secure_delete", "ON")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "journal_mode", "WAL")?;

        let mut db = Self { conn };
        db.migrate()?;
        Ok(db)
    }

    /// Applies the migrations not applied yet. Foreign keys are off meanwhile, so a table can be
    /// rebuilt without cascading deletes (the procedure SQLite documents for schema changes), and
    /// checked before each commit.
    fn migrate(&mut self) -> Result<(), StorageError> {
        let applied: i64 = self.conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
        let applied = usize::try_from(applied).map_err(|_| StorageError::NewerSchema)?;
        if applied > MIGRATIONS.len() {
            return Err(StorageError::NewerSchema);
        }
        if applied == MIGRATIONS.len() {
            return Ok(());
        }
        self.conn.pragma_update(None, "foreign_keys", "OFF")?;
        let migrated = (|| {
            for (index, migration) in MIGRATIONS.iter().enumerate().skip(applied) {
                let tx = self.conn.transaction()?;
                tx.execute_batch(migration)?;
                if index + 1 == ROSTER_KEY_VERSIONS {
                    add_key_versions_to_rosters(&tx)?;
                }
                let violations: i64 =
                    tx.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| row.get(0))?;
                if violations > 0 {
                    return Err(StorageError::Corrupt);
                }
                tx.pragma_update(None, "user_version", index as i64 + 1)?;
                tx.commit()?;
            }
            Ok(())
        })();
        self.conn.pragma_update(None, "foreign_keys", "ON")?;
        migrated
    }

    pub fn identity(&self) -> Result<Option<(Identity, String)>, StorageError> {
        let row = self
            .conn
            .query_row("SELECT seed, display_name FROM identity WHERE id = 1", [], |row| {
                Ok((Zeroizing::new(row.get::<_, Vec<u8>>(0)?), row.get::<_, String>(1)?))
            })
            .optional()?;
        row.map(|(seed, name)| Ok((Identity::from_seed(SecretBytes::from_slice(&seed)?), name)))
            .transpose()
    }

    pub fn save_identity(
        &self,
        identity: &Identity,
        display_name: &str,
        created_at_ms: i64,
    ) -> Result<(), StorageError> {
        self.conn.execute(
            "INSERT INTO identity (id, seed, display_name, created_at) VALUES (1, ?1, ?2, ?3)",
            params![identity.seed().expose().as_slice(), display_name, created_at_ms],
        )?;
        Ok(())
    }
}

/// The owner's long-term link keys: static KEM seed and presence key.
pub type IdentityKeys = (SecretBytes<32>, SecretBytes<32>);

/// One of the owner's static keys (rust/airchat-protocol/docs/protocol.md §6.9).
pub struct StaticKeySeed {
    pub version: u32,
    pub seed: SecretBytes<32>,
    pub created_at_ms: i64,
}

impl Database {
    pub fn identity_keys(&self) -> Result<Option<IdentityKeys>, StorageError> {
        let row = self
            .conn
            .query_row(
                "SELECT static_kem_seed, presence_key FROM identity
                 WHERE id = 1 AND static_kem_seed IS NOT NULL AND presence_key IS NOT NULL",
                [],
                |row| {
                    Ok((
                        Zeroizing::new(row.get::<_, Vec<u8>>(0)?),
                        Zeroizing::new(row.get::<_, Vec<u8>>(1)?),
                    ))
                },
            )
            .optional()?;
        row.map(|(kem, presence)| Ok((SecretBytes::from_slice(&kem)?, SecretBytes::from_slice(&presence)?)))
            .transpose()
    }

    pub fn set_identity_keys(
        &self,
        static_kem_seed: &SecretBytes<32>,
        presence_key: &SecretBytes<32>,
    ) -> Result<(), StorageError> {
        self.conn.execute(
            "UPDATE identity SET static_kem_seed = ?1, presence_key = ?2 WHERE id = 1",
            params![static_kem_seed.expose().as_slice(), presence_key.expose().as_slice()],
        )?;
        Ok(())
    }

    /// The version of the owner's presence key (rust/airchat-protocol/docs/protocol.md §5.4).
    pub fn presence_version(&self) -> Result<u32, StorageError> {
        Ok(self
            .conn
            .query_row("SELECT presence_version FROM identity WHERE id = 1", [], |row| {
                row.get(0)
            })?)
    }

    /// Replaces the owner's presence key; `secure_delete` overwrites the old one in the file.
    pub fn set_presence_key(&self, key: &SecretBytes<32>, version: u32) -> Result<(), StorageError> {
        self.conn.execute(
            "UPDATE identity SET presence_key = ?1, presence_version = ?2 WHERE id = 1",
            params![key.expose().as_slice(), version],
        )?;
        Ok(())
    }

    /// The owner's static keys (rust/airchat-protocol/docs/protocol.md §6.9), newest first.
    pub fn static_keys(&self) -> Result<Vec<StaticKeySeed>, StorageError> {
        let mut statement = self
            .conn
            .prepare("SELECT version, seed, created_at FROM static_keys ORDER BY version DESC")?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, u32>(0)?,
                Zeroizing::new(row.get::<_, Vec<u8>>(1)?),
                row.get::<_, i64>(2)?,
            ))
        })?;
        rows.map(|row| {
            let (version, seed, created_at_ms) = row?;
            Ok(StaticKeySeed {
                version,
                seed: SecretBytes::from_slice(&seed)?,
                created_at_ms,
            })
        })
        .collect()
    }

    /// Stores a new static key; it is the newest, so it also becomes the identity's.
    pub fn add_static_key(&self, key: &StaticKeySeed) -> Result<(), StorageError> {
        let transaction = self.conn.unchecked_transaction()?;
        transaction.execute(
            "INSERT INTO static_keys (version, seed, created_at) VALUES (?1, ?2, ?3)",
            params![key.version, key.seed.expose().as_slice(), key.created_at_ms],
        )?;
        transaction.execute(
            "UPDATE identity SET static_kem_seed = ?1 WHERE id = 1",
            params![key.seed.expose().as_slice()],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Forgets static keys nobody needs any more; `secure_delete` overwrites them in the file.
    pub fn delete_static_keys(&self, versions: &[u32]) -> Result<(), StorageError> {
        for version in versions {
            self.conn
                .execute("DELETE FROM static_keys WHERE version = ?1", params![version])?;
        }
        Ok(())
    }

    pub fn inbox_seed(&self) -> Result<Option<SecretBytes<32>>, StorageError> {
        let seed = self
            .conn
            .query_row(
                "SELECT inbox_seed FROM identity WHERE id = 1 AND inbox_seed IS NOT NULL",
                [],
                |row| Ok(Zeroizing::new(row.get::<_, Vec<u8>>(0)?)),
            )
            .optional()?;
        seed.map(|seed| Ok(SecretBytes::from_slice(&seed)?)).transpose()
    }

    pub fn set_inbox_seed(&self, seed: &SecretBytes<32>) -> Result<(), StorageError> {
        self.conn.execute(
            "UPDATE identity SET inbox_seed = ?1 WHERE id = 1",
            params![seed.expose().as_slice()],
        )?;
        Ok(())
    }

    /// Simulates an account created before migration 2.
    #[cfg(test)]
    pub(crate) fn forget_identity_keys(&self) -> Result<(), StorageError> {
        self.conn
            .execute("UPDATE identity SET static_kem_seed = NULL, presence_key = NULL", [])?;
        Ok(())
    }

    pub fn set_display_name(&self, display_name: &str) -> Result<(), StorageError> {
        self.conn.execute(
            "UPDATE identity SET display_name = ?1 WHERE id = 1",
            params![display_name],
        )?;
        Ok(())
    }
}

fn hex(key: &SecretBytes<32>) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(64));
    for byte in key.expose() {
        out.push(char::from_digit(u32::from(byte >> 4), 16).expect("nibble"));
        out.push(char::from_digit(u32::from(byte & 0xf), 16).expect("nibble"));
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::storage::vault::tests::TEST_PARAMS;

    /// A database in memory with every migration, and one contact (id 7).
    pub(crate) fn test_db_with_contact() -> (Database, crate::storage::ContactId) {
        let conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();
        let mut db = Database { conn };
        db.migrate().unwrap();
        db.conn
            .execute_batch(
                "INSERT INTO contacts (id, identity, static_kem, display_name, presence_key, link_psk, added_at)
                    VALUES (7, zeroblob(32), zeroblob(1216), 'Burak', zeroblob(32), zeroblob(32), 1);",
            )
            .unwrap();
        (db, 7)
    }

    fn temp_db_path() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("airchat.db");
        (dir, path)
    }

    #[test]
    fn stores_and_reloads_the_identity() {
        let (_dir, path) = temp_db_path();
        let (vault, record) = Vault::create(b"123456", TEST_PARAMS).unwrap();
        let identity = Identity::generate().unwrap();
        {
            let db = Database::open(&path, &vault).unwrap();
            assert!(db.identity().unwrap().is_none());
            db.save_identity(&identity, "Ayşe", 1_760_000_000_000).unwrap();
        }
        let vault = Vault::unlock_with_pin(&record, b"123456").unwrap();
        let db = Database::open(&path, &vault).unwrap();
        let (loaded, name) = db.identity().unwrap().unwrap();
        assert_eq!(loaded.public(), identity.public());
        assert_eq!(name, "Ayşe");
    }

    /// A database from before migration 6 (when the messages table was rebuilt) keeps its
    /// messages and attachments, and deleting a contact still cascades.
    #[test]
    fn migrating_keeps_messages_and_their_attachments() {
        let conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();
        for migration in &MIGRATIONS[..5] {
            conn.execute_batch(migration).unwrap();
        }
        conn.pragma_update(None, "user_version", 5).unwrap();
        conn.execute_batch(&format!(
            "INSERT INTO contacts (id, identity, static_kem, display_name, presence_key, link_psk, added_at)
                VALUES (7, zeroblob(32), zeroblob(1216), 'Burak', zeroblob(32), zeroblob(32), 1);
             INSERT INTO messages VALUES (1, 7, zeroblob(16), 0, '', 2, 2, 3);
             INSERT INTO messages VALUES (2, 7, {}, 1, 'selam', 3, 3, 2);
             INSERT INTO attachments VALUES (1, 'a.jpg', 'image/jpeg', 10, zeroblob(32), NULL, 0, 0);",
            "x'01010101010101010101010101010101'"
        ))
        .unwrap();

        let mut db = Database { conn };
        db.migrate().unwrap();
        let count = |sql: &str| db.conn.query_row(sql, [], |row| row.get::<_, i64>(0)).unwrap();
        assert_eq!(count("PRAGMA user_version"), MIGRATIONS.len() as i64);
        assert_eq!(count("SELECT count(*) FROM messages"), 2);
        assert_eq!(count("SELECT count(*) FROM attachments"), 1);
        assert_eq!(count("SELECT state FROM contacts WHERE id = 7"), 0);
        assert_eq!(count("SELECT allow_messages FROM contacts WHERE id = 7"), 1);
        assert_eq!(count("PRAGMA foreign_keys"), 1, "foreign keys are on again");

        db.conn.execute("DELETE FROM contacts WHERE id = 7", []).unwrap();
        assert_eq!(count("SELECT count(*) FROM messages"), 0);
        assert_eq!(
            count("SELECT count(*) FROM attachments"),
            0,
            "the attachments still follow their message"
        );
    }

    #[test]
    fn migrating_gives_stored_rosters_key_versions() {
        use crate::group::{
            Role, Roster,
            test_util::{member, person},
        };
        let conn = Connection::open_in_memory().unwrap();
        for migration in &MIGRATIONS[..ROSTER_KEY_VERSIONS - 1] {
            conn.execute_batch(migration).unwrap();
        }
        conn.pragma_update(None, "user_version", ROSTER_KEY_VERSIONS as i64 - 1)
            .unwrap();
        let (ayse, burak) = (person("Ayşe"), person("Burak"));
        let members = vec![member(&ayse, Role::Admin), member(&burak, Role::Member)];
        let roster = Roster::new([1; 16], 0, "Kamp", members).unwrap();
        // The layout before versions: no key version after each member's static key.
        let mut unversioned = [&roster.group_id[..], &roster.epoch.to_be_bytes(), &[4], b"Kamp", &[2]].concat();
        for m in roster.members() {
            unversioned.extend_from_slice(m.identity.as_bytes());
            unversioned.extend_from_slice(m.static_kem.as_bytes());
            unversioned.extend_from_slice(m.presence_key.expose());
            unversioned.push(m.role as u8);
            unversioned.extend_from_slice(&m.expires.to_be_bytes());
            unversioned.push(m.name.len() as u8);
            unversioned.extend_from_slice(m.name.as_bytes());
        }
        conn.execute(
            "INSERT INTO groups (group_id, name, epoch, epoch_key, roster, previous_key, previous_roster, created_at)
             VALUES (?1, 'Kamp', 0, zeroblob(32), ?2, zeroblob(32), ?2, 1)",
            params![&roster.group_id[..], unversioned],
        )
        .unwrap();

        let mut db = Database { conn };
        db.migrate().unwrap();
        let stored = db.group(1).unwrap().unwrap();
        assert_eq!(stored.roster.encode(), roster.encode(), "version 0 for everyone");
        assert_eq!(stored.previous.unwrap().1.encode(), roster.encode());
    }

    #[test]
    fn wrong_key_is_detected() {
        let (_dir, path) = temp_db_path();
        let (vault, _) = Vault::create(b"123456", TEST_PARAMS).unwrap();
        Database::open(&path, &vault).unwrap();
        let (other, _) = Vault::create(b"123456", TEST_PARAMS).unwrap();
        assert!(matches!(Database::open(&path, &other), Err(StorageError::WrongKey)));
    }

    #[test]
    fn files_contain_no_plaintext() {
        let (dir, path) = temp_db_path();
        let (vault, _) = Vault::create(b"123456", TEST_PARAMS).unwrap();
        let identity = Identity::generate().unwrap();
        let assert_no_plaintext = || {
            for entry in std::fs::read_dir(dir.path()).unwrap() {
                let path = entry.unwrap().path();
                let bytes = std::fs::read(&path).unwrap();
                assert!(!contains(&bytes, b"PLAINTEXT-CANARY"), "{path:?}");
                assert!(
                    !contains(&bytes, b"SQLite format 3"),
                    "{path:?}: header must be encrypted too"
                );
                assert!(!contains(&bytes, identity.seed().expose()), "{path:?}");
            }
        };
        let db = Database::open(&path, &vault).unwrap();
        db.save_identity(&identity, "PLAINTEXT-CANARY", 0).unwrap();
        // While open, the new rows sit in the write-ahead log.
        assert!(dir.path().join("airchat.db-wal").metadata().unwrap().len() > 0);
        assert_no_plaintext();
        drop(db);
        assert_no_plaintext();
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
