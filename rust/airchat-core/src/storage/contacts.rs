//! The contact list.

use rusqlite::{OptionalExtension, Row, params};
use zeroize::Zeroizing;

use super::{Database, StorageError};
use crate::{
    crypto::{
        SecretBytes,
        kem::{ENCAPSULATION_KEY_LEN, EncapsulationKey},
    },
    identity::PublicIdentity,
    pairing::PairedContact,
};

pub type ContactId = i64;

/// Where a contact stands (requirements C-6, C-7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContactState {
    Active = 0,
    /// Kept, keys included, but neither recognised nor linked: they see this device as away.
    Blocked = 1,
    /// Deleted with the conversation kept: the keys are wiped, the history stays on this device.
    /// Pairing again makes them active again, with the same history.
    Former = 2,
    /// Not a contact: known only through a shared group, with the keys from its roster
    /// (rust/airchat-protocol/docs/protocol.md §9.4). Never in the contact list; pairing makes them a contact.
    Peer = 3,
}

impl ContactState {
    fn from_i64(value: i64) -> rusqlite::Result<Self> {
        Ok(match value {
            0 => Self::Active,
            1 => Self::Blocked,
            2 => Self::Former,
            3 => Self::Peer,
            other => return Err(rusqlite::Error::IntegralValueOutOfRange(4, other)),
        })
    }
}

/// What a contact may do (requirement C-5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Permissions {
    /// Send messages and files, and call. Refused messages are answered as such.
    pub messages: bool,
    /// Instant voice, which plays without the user accepting it.
    pub ptt: bool,
    /// Files they offer are fetched without asking.
    pub auto_download: bool,
}

impl Default for Permissions {
    fn default() -> Self {
        Self {
            messages: true,
            ptt: false,
            auto_download: false,
        }
    }
}

/// What the contact list shows; no secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactSummary {
    pub id: ContactId,
    pub identity: PublicIdentity,
    pub display_name: String,
    pub added_at_ms: i64,
    pub state: ContactState,
    pub permissions: Permissions,
    /// Until when (Unix ms) its messages notify nothing and its push-to-talk does not play; 0 if not
    /// muted.
    pub muted_until: i64,
    /// Its build was last attested as the official one, on a verified phone (rust/airchat-protocol/docs/protocol.md §6.10).
    pub attested: Option<crate::attest::Attested>,
}

/// Everything known about a contact, including the keys for link sessions.
pub struct StoredContact {
    pub summary: ContactSummary,
    pub static_kem: EncapsulationKey,
    /// The version of `static_kem` (rust/airchat-protocol/docs/protocol.md §6.9); 0 for the key from pairing.
    pub static_kem_version: u32,
    pub presence_key: SecretBytes<32>,
    pub link_psk: SecretBytes<32>,
}

/// What recognising and connecting to contacts needs, for every active contact at once.
pub struct DirectoryEntry {
    pub id: ContactId,
    pub identity: PublicIdentity,
    /// Its newest static key, then up to two earlier ones it may still link with (§6.9).
    pub static_kems: Vec<EncapsulationKey>,
    /// The newest of this device's static keys it has taken.
    pub own_key_taken: u32,
    pub presence_key: SecretBytes<32>,
    /// The newest of this device's presence keys it has taken (§5.4).
    pub presence_key_taken: u32,
    /// The pairing secret, for the mesh and paths (rust/airchat-protocol/docs/protocol.md §10.3, §12.2).
    pub link_psk: SecretBytes<32>,
    /// The keys its links are made with, newest first (§6.8); at least one.
    pub link_keys: Vec<SecretBytes<32>>,
    pub permissions: Permissions,
    pub muted_until: i64,
}

const SUMMARY: &str =
    "id, identity, display_name, added_at, state, allow_messages, allow_ptt, auto_download, muted_until,
    attested, attested_patch";
/// The columns in [`SUMMARY`]: what a query selects after them starts here.
const SUMMARY_LEN: usize = 11;

impl Database {
    /// Active contacts only: blocked and former ones are neither recognised nor linked.
    pub fn contact_directory(&self) -> Result<Vec<DirectoryEntry>, StorageError> {
        let mut statement = self.conn.prepare(&format!(
            "SELECT {SUMMARY}, static_kem, presence_key, link_psk, link_keys, earlier_static_kems, own_key_taken,
                presence_key_taken
             FROM contacts WHERE state = 0"
        ))?;
        let rows = statement.query_map([], |row| {
            Ok((
                summary(row)?,
                row.get::<_, Vec<u8>>(SUMMARY_LEN)?,
                Zeroizing::new(row.get::<_, Vec<u8>>(SUMMARY_LEN + 1)?),
                Zeroizing::new(row.get::<_, Vec<u8>>(SUMMARY_LEN + 2)?),
                row.get::<_, Option<Vec<u8>>>(SUMMARY_LEN + 3)?.map(Zeroizing::new),
                row.get::<_, Option<Vec<u8>>>(SUMMARY_LEN + 4)?,
                row.get::<_, u32>(SUMMARY_LEN + 5)?,
                row.get::<_, u32>(SUMMARY_LEN + 6)?,
            ))
        })?;
        rows.map(|row| {
            let (summary, static_kem, presence_key, link_psk, link_keys, earlier, own_key_taken, presence_key_taken) =
                row?;
            let link_keys = match link_keys {
                Some(keys) => keys.chunks(32).map(SecretBytes::from_slice).collect::<Result<_, _>>()?,
                None => vec![SecretBytes::from_slice(&link_psk)?],
            };
            let static_kems = std::iter::once(&static_kem[..])
                .chain(earlier.as_deref().unwrap_or_default().chunks(ENCAPSULATION_KEY_LEN))
                .map(EncapsulationKey::from_bytes)
                .collect::<Result<_, _>>()?;
            Ok(DirectoryEntry {
                id: summary.id,
                identity: summary.identity,
                static_kems,
                own_key_taken,
                presence_key: SecretBytes::from_slice(&presence_key)?,
                presence_key_taken,
                link_psk: SecretBytes::from_slice(&link_psk)?,
                link_keys,
                permissions: summary.permissions,
                muted_until: summary.muted_until,
            })
        })
        .collect()
    }

    /// Stores a newly paired contact. Pairing again with someone already in the list replaces
    /// their keys and name but keeps their id, history and permissions, and makes a former contact
    /// active again. `None` if they are blocked: they stay blocked and keep their old keys.
    /// `own_keys` are the versions of this device's static and presence keys pairing handed over.
    pub fn save_contact(
        &self,
        contact: &PairedContact,
        own_keys: (u32, u32),
        added_at_ms: i64,
    ) -> Result<Option<ContactSummary>, StorageError> {
        let id: Option<ContactId> = self
            .conn
            .query_row(
                "INSERT INTO contacts (identity, static_kem, display_name, presence_key, link_psk, added_at,
                    own_key_taken, presence_key_taken)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT (identity) DO UPDATE SET
                    static_kem = excluded.static_kem,
                    display_name = excluded.display_name,
                    presence_key = excluded.presence_key,
                    link_psk = excluded.link_psk,
                    link_keys = NULL,
                    static_kem_version = 0,
                    earlier_static_kems = NULL,
                    own_key_taken = excluded.own_key_taken,
                    presence_version = 0,
                    presence_key_taken = excluded.presence_key_taken,
                    state = 0
                 WHERE contacts.state != 1
                 RETURNING id",
                params![
                    contact.identity.as_bytes().as_slice(),
                    contact.static_kem.as_bytes().as_slice(),
                    contact.display_name,
                    contact.presence_key.expose().as_slice(),
                    contact.link_psk.expose().as_slice(),
                    added_at_ms,
                    own_keys.0,
                    own_keys.1,
                ],
                |row| row.get(0),
            )
            .optional()?;
        // New keys: the prekeys of the old ones are no use.
        if let Some(id) = id {
            self.forget_prekeys(id)?;
        }
        id.map(|id| self.contact_summary(id)).transpose().map(Option::flatten)
    }

    /// All contacts, blocked and former ones included, ordered by name; not group peers.
    pub fn contacts(&self) -> Result<Vec<ContactSummary>, StorageError> {
        let mut statement = self.conn.prepare(&format!(
            "SELECT {SUMMARY} FROM contacts WHERE state != 3 ORDER BY display_name COLLATE NOCASE, id"
        ))?;
        let rows = statement.query_map([], summary)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn contact_summary(&self, id: ContactId) -> Result<Option<ContactSummary>, StorageError> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {SUMMARY} FROM contacts WHERE id = ?1"),
                params![id],
                summary,
            )
            .optional()?)
    }

    /// Blocks or unblocks a contact (not a former one). Returns whether it changed.
    pub fn set_blocked(&self, id: ContactId, blocked: bool) -> Result<bool, StorageError> {
        let (from, to) = if blocked { (0, 1) } else { (1, 0) };
        Ok(self.conn.execute(
            "UPDATE contacts SET state = ?3 WHERE id = ?1 AND state = ?2",
            params![id, from, to],
        )? > 0)
    }

    /// Replaces an active contact's link keys (rust/airchat-protocol/docs/protocol.md §6.8), newest first: 1 to 4.
    pub fn set_link_keys(&self, id: ContactId, keys: &[SecretBytes<32>]) -> Result<bool, StorageError> {
        let joined = Zeroizing::new(
            keys.iter()
                .flat_map(|key| key.expose().iter().copied())
                .collect::<Vec<u8>>(),
        );
        Ok(self.conn.execute(
            "UPDATE contacts SET link_keys = ?2 WHERE id = ?1 AND state = 0",
            params![id, joined.as_slice()],
        )? > 0)
    }

    /// Takes a newer static key of a contact (rust/airchat-protocol/docs/protocol.md §6.9): its current one goes first
    /// among its earlier ones (two kept). Returns whether it was newer.
    pub fn set_their_static_key(
        &self,
        id: ContactId,
        key: &EncapsulationKey,
        version: u32,
    ) -> Result<bool, StorageError> {
        let row = self
            .conn
            .query_row(
                "SELECT static_kem, static_kem_version, earlier_static_kems FROM contacts WHERE id = ?1 AND state = 0",
                params![id],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, u32>(1)?,
                        row.get::<_, Option<Vec<u8>>>(2)?,
                    ))
                },
            )
            .optional()?;
        let Some((mut earlier, _, older)) = row.filter(|(_, stored, _)| version > *stored) else {
            return Ok(false);
        };
        earlier.extend(older.unwrap_or_default());
        earlier.truncate(2 * ENCAPSULATION_KEY_LEN);
        self.conn.execute(
            "UPDATE contacts SET static_kem = ?2, static_kem_version = ?3, earlier_static_kems = ?4 WHERE id = ?1",
            params![id, key.as_bytes().as_slice(), version, earlier],
        )?;
        Ok(true)
    }

    /// Takes a contact's newer presence key (rust/airchat-protocol/docs/protocol.md §5.4); whether it was newer.
    pub fn set_their_presence_key(
        &self,
        id: ContactId,
        key: &SecretBytes<32>,
        version: u32,
    ) -> Result<bool, StorageError> {
        Ok(self.conn.execute(
            "UPDATE contacts SET presence_key = ?2, presence_version = ?3
             WHERE id = ?1 AND state = 0 AND presence_version < ?3",
            params![id, key.expose().as_slice(), version],
        )? > 0)
    }

    /// A contact took this device's presence key of `version`, or a newer one.
    pub fn set_presence_key_taken(&self, id: ContactId, version: u32) -> Result<(), StorageError> {
        self.conn.execute(
            "UPDATE contacts SET presence_key_taken = max(presence_key_taken, ?2) WHERE id = ?1",
            params![id, version],
        )?;
        Ok(())
    }

    /// A contact's presence key, if it told this device of one since pairing.
    pub fn told_presence_key(&self, id: ContactId) -> Result<Option<SecretBytes<32>>, StorageError> {
        let key: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT presence_key FROM contacts WHERE id = ?1 AND state = 0 AND presence_version > 0",
                params![id],
                |row| row.get(0),
            )
            .optional()?;
        key.map(|key| Ok(SecretBytes::from_slice(&Zeroizing::new(key))?))
            .transpose()
    }

    /// A contact took this device's static key of `version`, or a newer one.
    pub fn set_own_key_taken(&self, id: ContactId, version: u32) -> Result<(), StorageError> {
        self.conn.execute(
            "UPDATE contacts SET own_key_taken = max(own_key_taken, ?2) WHERE id = ?1",
            params![id, version],
        )?;
        Ok(())
    }

    /// The oldest of this device's static keys an active contact may still use: the oldest any
    /// has taken (`None` without contacts). Peers know this device's keys from rosters only.
    pub fn oldest_own_key_taken(&self) -> Result<Option<u32>, StorageError> {
        Ok(self
            .conn
            .query_row("SELECT min(own_key_taken) FROM contacts WHERE state = 0", [], |row| {
                row.get(0)
            })?)
    }

    /// A peer's static key and its version, as known here.
    pub fn their_static_key(&self, id: ContactId) -> Result<Option<(EncapsulationKey, u32)>, StorageError> {
        let row = self
            .conn
            .query_row(
                "SELECT static_kem, static_kem_version FROM contacts WHERE id = ?1 AND state IN (0, 3)",
                params![id],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, u32>(1)?)),
            )
            .optional()?;
        row.map(|(key, version)| Ok((EncapsulationKey::from_bytes(&key)?, version)))
            .transpose()
    }

    /// Mutes a contact until `until_ms` (Unix ms), or unmutes it with 0.
    pub fn set_contact_muted(&self, id: ContactId, until_ms: i64) -> Result<bool, StorageError> {
        Ok(self.conn.execute(
            "UPDATE contacts SET muted_until = ?2 WHERE id = ?1",
            params![id, until_ms],
        )? > 0)
    }

    pub fn set_permissions(&self, id: ContactId, permissions: Permissions) -> Result<bool, StorageError> {
        Ok(self.conn.execute(
            "UPDATE contacts SET allow_messages = ?2, allow_ptt = ?3, auto_download = ?4 WHERE id = ?1",
            params![id, permissions.messages, permissions.ptt, permissions.auto_download],
        )? > 0)
    }

    /// Deletes a contact's keys but keeps the conversation (the contact becomes former). The keys
    /// are overwritten in place, so they leave the file too (`secure_delete`).
    /// Files they offered and this device did not get are gone.
    pub fn forget_contact_keys(&self, id: ContactId) -> Result<bool, StorageError> {
        let transaction = self.conn.unchecked_transaction()?;
        let changed = transaction.execute(
            "UPDATE contacts SET state = 2, static_kem = zeroblob(1216), presence_key = zeroblob(32),
                link_psk = zeroblob(32), link_keys = NULL, earlier_static_kems = NULL
             WHERE id = ?1",
            params![id],
        )? > 0;
        transaction.execute(
            "UPDATE attachments SET state = 4, stored = 0
             WHERE state IN (0, 1) AND message IN (SELECT id FROM messages WHERE contact_id = ?1 AND outgoing = 0)",
            params![id],
        )?;
        transaction.execute("DELETE FROM own_prekeys WHERE contact_id = ?1", params![id])?;
        transaction.execute("DELETE FROM their_prekeys WHERE contact_id = ?1", params![id])?;
        transaction.commit()?;
        Ok(changed)
    }

    /// An active contact with its keys.
    pub fn contact(&self, id: ContactId) -> Result<Option<StoredContact>, StorageError> {
        let row = self
            .conn
            .query_row(
                &format!(
                    "SELECT {SUMMARY}, static_kem, presence_key, link_psk, static_kem_version FROM contacts
                     WHERE id = ?1 AND state = 0"
                ),
                params![id],
                |row| {
                    Ok((
                        summary(row)?,
                        row.get::<_, Vec<u8>>(SUMMARY_LEN)?,
                        Zeroizing::new(row.get::<_, Vec<u8>>(SUMMARY_LEN + 1)?),
                        Zeroizing::new(row.get::<_, Vec<u8>>(SUMMARY_LEN + 2)?),
                        row.get::<_, u32>(SUMMARY_LEN + 3)?,
                    ))
                },
            )
            .optional()?;
        row.map(|(summary, static_kem, presence_key, link_psk, static_kem_version)| {
            Ok(StoredContact {
                summary,
                static_kem: EncapsulationKey::from_bytes(&static_kem)?,
                static_kem_version,
                presence_key: SecretBytes::from_slice(&presence_key)?,
                link_psk: SecretBytes::from_slice(&link_psk)?,
            })
        })
        .transpose()
    }

    /// Someone met through a group, by identity: a contact (any state) or a peer.
    pub fn contact_by_identity(&self, identity: &PublicIdentity) -> Result<Option<ContactSummary>, StorageError> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {SUMMARY} FROM contacts WHERE identity = ?1"),
                params![identity.as_bytes().as_slice()],
                summary,
            )
            .optional()?)
    }

    /// Records a group member who is not a contact as a peer, with the keys from the roster (its
    /// static key only if newer than the one known); a contact stays as it is. Returns the row
    /// either way.
    pub fn upsert_peer(
        &self,
        identity: &PublicIdentity,
        static_kem: (&EncapsulationKey, u32),
        presence_key: &SecretBytes<32>,
        name: &str,
        now_ms: i64,
    ) -> Result<ContactId, StorageError> {
        let id: Option<ContactId> = self
            .conn
            .query_row(
                "INSERT INTO contacts (identity, static_kem, static_kem_version, display_name, presence_key, link_psk,
                    added_at, state, allow_messages)
                 VALUES (?1, ?2, ?3, ?4, ?5, zeroblob(32), ?6, 3, 0)
                 ON CONFLICT (identity) DO UPDATE SET
                    static_kem = iif(excluded.static_kem_version > contacts.static_kem_version,
                        excluded.static_kem, contacts.static_kem),
                    static_kem_version = max(excluded.static_kem_version, contacts.static_kem_version),
                    display_name = excluded.display_name,
                    presence_key = excluded.presence_key
                 WHERE contacts.state = 3
                 RETURNING id",
                params![
                    identity.as_bytes().as_slice(),
                    static_kem.0.as_bytes().as_slice(),
                    static_kem.1,
                    name,
                    presence_key.expose().as_slice(),
                    now_ms,
                ],
                |row| row.get(0),
            )
            .optional()?;
        match id {
            Some(id) => Ok(id),
            None => Ok(self.conn.query_row(
                "SELECT id FROM contacts WHERE identity = ?1",
                params![identity.as_bytes().as_slice()],
                |row| row.get(0),
            )?),
        }
    }

    /// Peers in none of these rows any more (no shared group left) are forgotten.
    pub fn delete_peers_except(&self, keep: &[ContactId]) -> Result<Vec<ContactId>, StorageError> {
        let mut statement = self.conn.prepare("SELECT id FROM contacts WHERE state = 3")?;
        let peers: Vec<ContactId> = statement.query_map([], |row| row.get(0))?.collect::<Result<_, _>>()?;
        let gone: Vec<ContactId> = peers.into_iter().filter(|id| !keep.contains(id)).collect();
        for id in &gone {
            self.conn.execute("DELETE FROM contacts WHERE id = ?1", params![id])?;
        }
        Ok(gone)
    }

    /// Deletes a contact, its keys and its conversation. Returns whether it existed.
    /// What the contact's latest build attestation showed: verified, or not (None).
    pub fn set_attested(&self, id: ContactId, attested: Option<crate::attest::Attested>) -> Result<bool, StorageError> {
        let (level, patch) = match attested {
            None => (0, 0),
            Some(a) => (
                match a.level {
                    crate::attest::SecurityLevel::TrustedEnvironment => 1,
                    crate::attest::SecurityLevel::StrongBox => 2,
                },
                a.os_patch_level,
            ),
        };
        Ok(self.conn.execute(
            "UPDATE contacts SET attested = ?2, attested_patch = ?3 WHERE id = ?1",
            params![id, level, patch],
        )? > 0)
    }

    pub fn delete_contact(&self, id: ContactId) -> Result<bool, StorageError> {
        Ok(self.conn.execute("DELETE FROM contacts WHERE id = ?1", params![id])? > 0)
    }
}

/// A row starting with the columns in [`SUMMARY`].
fn summary(row: &Row) -> rusqlite::Result<ContactSummary> {
    let identity: [u8; 32] = row.get(1)?;
    Ok(ContactSummary {
        id: row.get(0)?,
        identity: PublicIdentity::from_bytes(identity),
        display_name: row.get(2)?,
        added_at_ms: row.get(3)?,
        state: ContactState::from_i64(row.get(4)?)?,
        permissions: Permissions {
            messages: row.get(5)?,
            ptt: row.get(6)?,
            auto_download: row.get(7)?,
        },
        muted_until: row.get(8)?,
        attested: match row.get::<_, i64>(9)? {
            0 => None,
            level => Some(crate::attest::Attested {
                level: if level == 2 {
                    crate::attest::SecurityLevel::StrongBox
                } else {
                    crate::attest::SecurityLevel::TrustedEnvironment
                },
                os_patch_level: row.get(10)?,
            }),
        },
    })
}
