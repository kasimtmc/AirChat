//! The user's account on this device: unlocked vault, open database and identity.

use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    crypto::{
        CryptoError, SecretBytes,
        kem::{DecapsulationKey, EncapsulationKey},
        pin::PinParams,
        sign::SIGNATURE_LEN,
    },
    identity::{AirChatId, Identity},
    inbox::{self, InboxError, InboxEvent},
    link::{LocalKeys, RemoteKeys},
    pairing::{LocalProfile, PRESENCE_KEY_LEN, PairedContact},
    storage::{
        AttachmentState, ContactId, ContactSummary, Database, DirectoryEntry, FileMeta, MessageId, MessageStatus,
        Permissions, StaticKeySeed, StorageError, StoredMessage, UNLOCK_SECRET_LEN, Vault, VaultError,
        files::FileStore, groups::group_file,
    },
};

const DATABASE_FILE: &str = "airchat.db";
pub(crate) const INBOX_FILE: &str = "inbox";

/// Shortest accepted PIN. Six digits are still weak against an attacker who has extracted the
/// hardware-wrapped record, which is why longer passphrases are allowed.
pub const MIN_PIN_LEN: usize = 6;
pub use crate::pairing::MAX_DISPLAY_NAME_CHARS;

#[derive(Debug, thiserror::Error)]
pub enum AccountError {
    #[error("an account already exists on this device")]
    AlreadyExists,
    #[error("no account exists on this device")]
    NotFound,
    #[error("the account database is missing its identity")]
    MissingIdentity,
    #[error("the PIN must have at least {MIN_PIN_LEN} characters")]
    PinTooShort,
    #[error("the name must have 1 to {MAX_DISPLAY_NAME_CHARS} characters and no control characters")]
    InvalidDisplayName,
    #[error(transparent)]
    Vault(#[from] VaultError),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Inbox(#[from] InboxError),
    #[error("no such file")]
    NoSuchFile,
    #[error("the contact is blocked")]
    Blocked,
}

pub struct Account {
    dir: PathBuf,
    vault: Vault,
    db: Database,
    identity: Identity,
    display_name: String,
    /// Our side of every link session: the newest static KEM key.
    link_keys: LocalKeys,
    /// The newest static key's version and when it was made (rust/airchat-protocol/docs/protocol.md §6.9).
    static_version: u32,
    static_created_ms: i64,
    /// Earlier static keys someone may still use, newest first.
    older_static: Vec<(u32, DecapsulationKey)>,
    /// Shared with all contacts so they can recognise our discovery beacons.
    presence_key: SecretBytes<PRESENCE_KEY_LEN>,
    /// Its version: a new one replaces it when a contact is deleted or blocked (protocol §5.4).
    presence_version: u32,
    /// Messages that arrive while the app is locked are encrypted to this key's public half.
    inbox_key: DecapsulationKey,
    /// Attachment content, encrypted at rest.
    files: FileStore,
}

/// The owner's link keys as loaded.
struct OwnKeys {
    link_keys: LocalKeys,
    static_version: u32,
    static_created_ms: i64,
    older_static: Vec<(u32, DecapsulationKey)>,
    presence_key: SecretBytes<PRESENCE_KEY_LEN>,
    presence_version: u32,
}

/// A random unlock secret and the record it opens. The platform keeps the secret behind biometric
/// authentication and stores the record next to the PIN record.
pub struct SecretUnlock {
    pub secret: SecretBytes<UNLOCK_SECRET_LEN>,
    pub record: Vec<u8>,
}

impl Account {
    pub fn exists(dir: &Path) -> bool {
        database_path(dir).exists()
    }

    /// Creates the account and returns it with its PIN record, which the platform must store.
    pub fn create(
        dir: &Path,
        pin: &[u8],
        display_name: &str,
        params: PinParams,
    ) -> Result<(Self, Vec<u8>), AccountError> {
        if Self::exists(dir) {
            return Err(AccountError::AlreadyExists);
        }
        check_pin(pin)?;
        let display_name = check_display_name(display_name)?;
        // Left by an account whose database is gone; unreadable without its key anyway.
        let _ = std::fs::remove_dir_all(dir.join(FILES_DIR));
        let (vault, pin_record) = Vault::create(pin, params)?;
        let created = (|| {
            let db = Database::open(&database_path(dir), &vault)?;
            let identity = Identity::generate().map_err(StorageError::from)?;
            db.save_identity(&identity, display_name, now_ms())?;
            let keys = Self::load_or_create_keys(&db, &identity)?;
            let inbox_key = Self::load_or_create_inbox_key(&db)?;
            Ok::<_, AccountError>((db, identity, keys, inbox_key))
        })();
        let (db, identity, keys, inbox_key) = created.inspect_err(|_| remove_database(dir))?;
        let files = FileStore::new(dir.join(FILES_DIR), vault.file_key().map_err(StorageError::from)?);
        let account = Self {
            dir: dir.to_owned(),
            vault,
            db,
            identity,
            display_name: display_name.to_owned(),
            link_keys: keys.link_keys,
            static_version: keys.static_version,
            static_created_ms: keys.static_created_ms,
            older_static: keys.older_static,
            presence_key: keys.presence_key,
            presence_version: keys.presence_version,
            inbox_key,
            files,
        };
        Ok((account, pin_record))
    }

    pub fn unlock_with_pin(dir: &Path, pin_record: &[u8], pin: &[u8]) -> Result<Self, AccountError> {
        Self::open(dir, Vault::unlock_with_pin(pin_record, pin)?)
    }

    pub fn unlock_with_secret(
        dir: &Path,
        secret_record: &[u8],
        secret: &SecretBytes<UNLOCK_SECRET_LEN>,
    ) -> Result<Self, AccountError> {
        Self::open(dir, Vault::unlock_with_secret(secret_record, secret)?)
    }

    fn open(dir: &Path, vault: Vault) -> Result<Self, AccountError> {
        if !Self::exists(dir) {
            return Err(AccountError::NotFound);
        }
        let db = Database::open(&database_path(dir), &vault)?;
        let (identity, display_name) = db.identity()?.ok_or(AccountError::MissingIdentity)?;
        let keys = Self::load_or_create_keys(&db, &identity)?;
        let inbox_key = Self::load_or_create_inbox_key(&db)?;
        let files = FileStore::new(dir.join(FILES_DIR), vault.file_key().map_err(StorageError::from)?);
        // Files the app was still writing when it died are of no use.
        for file in db.unfinished_files()? {
            files.delete(file)?;
            db.delete_message(file)?;
        }
        for row in db.unfinished_group_files()? {
            files.delete(group_file(row))?;
            db.delete_group_message(row)?;
        }
        Ok(Self {
            dir: dir.to_owned(),
            vault,
            db,
            identity,
            display_name,
            link_keys: keys.link_keys,
            static_version: keys.static_version,
            static_created_ms: keys.static_created_ms,
            older_static: keys.older_static,
            presence_key: keys.presence_key,
            presence_version: keys.presence_version,
            inbox_key,
            files,
        })
    }

    fn load_or_create_inbox_key(db: &Database) -> Result<DecapsulationKey, AccountError> {
        let seed = match db.inbox_seed()? {
            Some(seed) => seed,
            None => {
                let seed = SecretBytes::random().map_err(crypto)?;
                db.set_inbox_seed(&seed)?;
                seed
            }
        };
        DecapsulationKey::from_seed(seed).map_err(crypto)
    }

    /// Accounts created before the keys existed get them on first open; those created before
    /// static keys had versions get their key as version 0, made now.
    fn load_or_create_keys(db: &Database, identity: &Identity) -> Result<OwnKeys, AccountError> {
        let (kem_seed, presence_key) = match db.identity_keys()? {
            Some(keys) => keys,
            None => {
                let keys = (
                    SecretBytes::random().map_err(crypto)?,
                    SecretBytes::random().map_err(crypto)?,
                );
                db.set_identity_keys(&keys.0, &keys.1)?;
                keys
            }
        };
        let mut statics = db.static_keys()?;
        if statics.is_empty() {
            let first = StaticKeySeed {
                version: 0,
                seed: kem_seed,
                created_at_ms: now_ms(),
            };
            db.add_static_key(&first)?;
            statics.push(first);
        }
        let mut statics = statics.into_iter();
        let newest = statics.next().expect("one at least");
        Ok(OwnKeys {
            link_keys: LocalKeys {
                identity: identity.public(),
                static_kem: DecapsulationKey::from_seed(newest.seed).map_err(crypto)?,
            },
            static_version: newest.version,
            static_created_ms: newest.created_at_ms,
            older_static: statics
                .map(|key| Ok((key.version, DecapsulationKey::from_seed(key.seed).map_err(crypto)?)))
                .collect::<Result<_, AccountError>>()?,
            presence_key,
            presence_version: db.presence_version()?,
        })
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn airchat_id(&self) -> AirChatId {
        self.identity.public().airchat_id()
    }

    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// A new PIN record for `new_pin`. The old record stops being needed once the platform has
    /// replaced it; the stored data is not re-encrypted.
    pub fn change_pin(&self, new_pin: &[u8], params: PinParams) -> Result<Vec<u8>, AccountError> {
        check_pin(new_pin)?;
        Ok(self.vault.pin_record(new_pin, params)?)
    }

    /// Sets up unlocking without the PIN (biometrics).
    pub fn create_secret_unlock(&self) -> Result<SecretUnlock, AccountError> {
        let secret = SecretBytes::random().map_err(VaultError::from)?;
        let record = self.vault.secret_record(&secret)?;
        Ok(SecretUnlock { secret, record })
    }

    pub fn set_display_name(&mut self, display_name: &str) -> Result<(), AccountError> {
        let display_name = check_display_name(display_name)?;
        self.db.set_display_name(display_name)?;
        display_name.clone_into(&mut self.display_name);
        Ok(())
    }

    /// What pairing tells a new contact about us.
    pub fn profile(&self) -> LocalProfile<'_> {
        LocalProfile {
            identity: &self.identity,
            static_kem: &self.link_keys.static_kem,
            presence_key: &self.presence_key,
            display_name: &self.display_name,
        }
    }

    pub fn link_keys(&self) -> &LocalKeys {
        &self.link_keys
    }

    /// The newest static key's version (rust/airchat-protocol/docs/protocol.md §6.9).
    pub fn static_version(&self) -> u32 {
        self.static_version
    }

    /// When the newest static key was made (Unix ms).
    pub fn static_created_ms(&self) -> i64 {
        self.static_created_ms
    }

    /// Every static key kept, with its version, newest first.
    pub fn static_keys(&self) -> impl Iterator<Item = (u32, &DecapsulationKey)> {
        std::iter::once((self.static_version, &self.link_keys.static_kem))
            .chain(self.older_static.iter().map(|(version, key)| (*version, key)))
    }

    /// The newest static key, signed: what contacts are told (§6.9).
    pub fn signed_static_key(&self) -> (u32, EncapsulationKey, [u8; SIGNATURE_LEN]) {
        let key = self.link_keys.static_kem.encapsulation_key().clone();
        let signature = self.identity.sign_static_key(self.static_version, &key);
        (self.static_version, key, signature)
    }

    /// Makes a new static key, the newest; the others stay until [`Account::forget_static_keys`].
    pub fn rotate_static_key(&mut self) -> Result<(), AccountError> {
        let key = StaticKeySeed {
            version: self
                .static_version
                .checked_add(1)
                .ok_or_else(|| crypto(CryptoError::InvalidParameters))?,
            seed: SecretBytes::random().map_err(crypto)?,
            created_at_ms: now_ms(),
        };
        self.db.add_static_key(&key)?;
        let newest = DecapsulationKey::from_seed(key.seed).map_err(crypto)?;
        let older = std::mem::replace(&mut self.link_keys.static_kem, newest);
        self.older_static.insert(0, (self.static_version, older));
        self.static_version = key.version;
        self.static_created_ms = key.created_at_ms;
        Ok(())
    }

    /// Pretends the newest static key was made `ms` earlier.
    #[cfg(test)]
    pub(crate) fn backdate_static_key(&mut self, ms: i64) {
        self.static_created_ms -= ms;
    }

    /// Forgets the earlier static keys `keep` says nobody needs, from storage and memory.
    pub fn forget_static_keys(&mut self, keep: impl Fn(u32) -> bool) -> Result<(), AccountError> {
        let gone: Vec<u32> = self
            .older_static
            .iter()
            .map(|(version, _)| *version)
            .filter(|version| !keep(*version))
            .collect();
        self.db.delete_static_keys(&gone)?;
        self.older_static.retain(|(version, _)| !gone.contains(version));
        Ok(())
    }

    /// The database, for the node's group logic.
    pub(crate) fn db(&self) -> &Database {
        &self.db
    }

    /// Stores a newly paired contact; [`AccountError::Blocked`] if the user blocked them.
    pub fn add_contact(&self, contact: &PairedContact) -> Result<ContactSummary, AccountError> {
        self.db
            .save_contact(contact, (self.static_version, self.presence_version), now_ms())?
            .ok_or(AccountError::Blocked)
    }

    pub fn contacts(&self) -> Result<Vec<ContactSummary>, AccountError> {
        Ok(self.db.contacts()?)
    }

    pub fn contact(&self, id: ContactId) -> Result<Option<ContactSummary>, AccountError> {
        Ok(self.db.contact_summary(id)?)
    }

    /// Blocks or unblocks a contact. Returns whether anything changed.
    pub fn set_blocked(&self, id: ContactId, blocked: bool) -> Result<bool, AccountError> {
        Ok(self.db.set_blocked(id, blocked)?)
    }

    pub fn set_permissions(&self, id: ContactId, permissions: Permissions) -> Result<bool, AccountError> {
        Ok(self.db.set_permissions(id, permissions)?)
    }

    /// The keys for a link session with a contact, or `None` if there is no such contact.
    pub fn remote_keys(&self, id: ContactId) -> Result<Option<RemoteKeys>, AccountError> {
        Ok(self.db.contact(id)?.map(|c| RemoteKeys {
            identity: c.summary.identity,
            static_kem: c.static_kem,
            link_psk: c.link_psk,
        }))
    }

    /// Deletes a contact's keys and, unless `keep_history`, the conversation and the content of
    /// its files (requirement C-6).
    pub fn delete_contact(&self, id: ContactId, keep_history: bool) -> Result<bool, AccountError> {
        if keep_history {
            // Files still on their way can no longer arrive.
            for message in self.db.downloading(id)? {
                self.files.delete(message.id)?;
            }
            return Ok(self.db.forget_contact_keys(id)?);
        }
        for file in self.db.file_ids(id)? {
            self.files.delete(file)?;
        }
        Ok(self.db.delete_contact(id)?)
    }

    /// A conversation's messages and files go; the contact stays.
    pub fn delete_history(&self, id: ContactId) -> Result<(), AccountError> {
        for file in self.db.file_ids(id)? {
            self.files.delete(file)?;
        }
        Ok(self.db.delete_messages_of(id)?)
    }

    /// Presence keys and link keys of every contact, to recognise and accept them.
    pub fn contact_directory(&self) -> Result<Vec<DirectoryEntry>, AccountError> {
        Ok(self.db.contact_directory()?)
    }

    pub fn presence_key(&self) -> &SecretBytes<PRESENCE_KEY_LEN> {
        &self.presence_key
    }

    pub fn presence_version(&self) -> u32 {
        self.presence_version
    }

    /// Replaces the presence key, so that someone who knew the old one no longer recognises this
    /// device (protocol §5.4); contacts are told the new one over their links.
    pub fn rotate_presence_key(&mut self) -> Result<(), AccountError> {
        let key = SecretBytes::random().map_err(crypto)?;
        let version = self
            .presence_version
            .checked_add(1)
            .ok_or_else(|| crypto(CryptoError::InvalidParameters))?;
        self.db.set_presence_key(&key, version)?;
        self.presence_key = key;
        self.presence_version = version;
        Ok(())
    }

    // Messages.

    pub fn queue_message(
        &self,
        contact: ContactId,
        message_id: &MessageId,
        body: &str,
    ) -> Result<StoredMessage, AccountError> {
        Ok(self.db.insert_outgoing(contact, message_id, body, now_ms())?)
    }

    // Files (rust/airchat-protocol/docs/protocol.md §8.4). A file is named by its message's row id.

    /// Starts an outgoing file message; it stays out of the conversation until [`Account::finish_file`].
    pub fn begin_file(
        &self,
        contact: ContactId,
        message_id: &MessageId,
        name: &str,
        mime: &str,
        thumbnail: Option<&[u8]>,
    ) -> Result<i64, AccountError> {
        Ok(self
            .db
            .insert_outgoing_file(contact, message_id, name, mime, thumbnail, now_ms())?)
    }

    /// Writes chunk `index` of `file`, of which `stored` bytes are on disk already. Not durable
    /// until [`Account::sync_file`].
    pub fn write_file_chunk(&self, file: i64, stored: u64, index: u64, data: &[u8]) -> Result<(), AccountError> {
        Ok(self.files.write_chunk(file, stored, index, data)?)
    }

    /// Makes the chunks written to `file` durable.
    pub fn sync_file(&self, file: i64) -> Result<(), AccountError> {
        Ok(self.files.sync(file)?)
    }

    pub fn finish_file(&self, file: i64, size: u64, sha256: &[u8; 32]) -> Result<StoredMessage, AccountError> {
        if size > 0 {
            self.files.sync(file)?;
        }
        Ok(self.db.finish_file(file, size, sha256, now_ms())?)
    }

    /// Removes a file message and its content (a group one too, named by [`group_file`]).
    pub fn discard_file(&self, file: i64) -> Result<(), AccountError> {
        self.files.delete(file)?;
        if file < 0 {
            Ok(self.db.delete_group_message(-file)?)
        } else {
            Ok(self.db.delete_message(file)?)
        }
    }

    /// Chunk `index` of a file of `size` bytes.
    pub fn read_file_chunk(
        &self,
        file: i64,
        size: u64,
        index: u64,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, AccountError> {
        Ok(self.files.read_chunk(file, size, index)?)
    }

    /// Bytes `offset..offset + len` of the stored part of a file, to show or export it.
    /// A group file is named by [`group_file`].
    pub fn read_file(&self, file: i64, offset: u64, len: usize) -> Result<zeroize::Zeroizing<Vec<u8>>, AccountError> {
        let attachment = if file < 0 {
            self.db.group_message(-file)?.and_then(|message| message.attachment)
        } else {
            self.db.message(file)?.and_then(|message| message.attachment)
        }
        .ok_or(AccountError::NoSuchFile)?;
        Ok(self.files.read(file, file_size_stored(&attachment), offset, len)?)
    }

    /// Deletes a group's messages and their files (a temporary membership ended, M-5; the group
    /// was deleted), but the message `keep`.
    pub fn delete_group_content(&self, group: i64, keep: Option<i64>) -> Result<(), AccountError> {
        for row in self.db.group_file_rows(group)? {
            if Some(row) != keep {
                self.files.delete(group_file(row))?;
            }
        }
        Ok(self.db.delete_group_messages(group, keep)?)
    }

    /// Deletes a group, its messages and their files.
    pub fn forget_group(&self, group: i64) -> Result<(), AccountError> {
        self.delete_group_content(group, None)?;
        Ok(self.db.delete_group(group)?)
    }

    /// Forgets the stored part of a file, e.g. before fetching it again.
    pub fn clear_file(&self, file: i64) -> Result<(), AccountError> {
        Ok(self.files.delete(file)?)
    }

    /// Stores an incoming file offer unless it was already received. Returns it only if new.
    pub fn store_incoming_file(
        &self,
        contact: ContactId,
        message_id: &MessageId,
        meta: &FileMeta,
        sent_at_ms: i64,
    ) -> Result<Option<StoredMessage>, AccountError> {
        Ok(self
            .db
            .insert_incoming_file(contact, message_id, meta, sent_at_ms, now_ms())?)
    }

    pub fn message(&self, file: i64) -> Result<Option<StoredMessage>, AccountError> {
        Ok(self.db.message(file)?)
    }

    pub fn message_by_id(
        &self,
        contact: ContactId,
        message_id: &MessageId,
    ) -> Result<Option<StoredMessage>, AccountError> {
        Ok(self.db.message_by_id(contact, message_id)?)
    }

    pub fn update_attachment(
        &self,
        file: i64,
        stored: u64,
        state: AttachmentState,
    ) -> Result<StoredMessage, AccountError> {
        Ok(self.db.update_attachment(file, stored, state)?)
    }

    /// Incoming files being fetched from a contact.
    pub fn downloading(&self, contact: ContactId) -> Result<Vec<StoredMessage>, AccountError> {
        Ok(self.db.downloading(contact)?)
    }

    /// Stores an incoming message; `None` if it is a resend of one already stored.
    pub fn store_incoming(
        &self,
        contact: ContactId,
        message_id: &MessageId,
        body: &str,
        sent_at_ms: i64,
    ) -> Result<Option<StoredMessage>, AccountError> {
        Ok(self
            .db
            .insert_incoming(contact, message_id, body, sent_at_ms, now_ms())?)
    }

    pub fn all_undelivered(&self) -> Result<Vec<StoredMessage>, AccountError> {
        Ok(self.db.all_undelivered()?)
    }

    // The locked-mode inbox.

    pub fn inbox_path(&self) -> PathBuf {
        self.dir.join(INBOX_FILE)
    }

    pub fn inbox_public_key(&self) -> &crate::crypto::kem::EncapsulationKey {
        self.inbox_key.encapsulation_key()
    }

    /// Moves everything received while locked into the database. Returns the messages that are
    /// new, and the group records for the node to take in; delete the inbox with
    /// [`Account::clear_inbox`] once it has. Applying an event twice changes nothing, so a crash
    /// before the deletion is harmless.
    pub fn absorb_inbox(&self) -> Result<(Vec<StoredMessage>, Vec<InboxEvent>), AccountError> {
        let path = self.inbox_path();
        let mut received = Vec::new();
        let mut group = Vec::new();
        for event in inbox::read(&path, &self.inbox_key)? {
            match event {
                InboxEvent::Message {
                    contact,
                    id,
                    sent_at_ms,
                    received_at_ms,
                    text,
                } => {
                    // A contact deleted in the meantime makes the insert fail; skip its messages.
                    if let Ok(Some(message)) = self.db.insert_incoming(contact, &id, &text, sent_at_ms, received_at_ms)
                    {
                        received.push(message);
                    }
                }
                InboxEvent::File {
                    contact,
                    id,
                    sent_at_ms,
                    received_at_ms,
                    meta,
                    mesh_key,
                } => {
                    if let Ok(Some(message)) =
                        self.db
                            .insert_incoming_file(contact, &id, &meta, sent_at_ms, received_at_ms)
                    {
                        // Its content comes through the mesh: it is being fetched (§10.8).
                        let message = match mesh_key {
                            Some(key) => {
                                self.db.set_mesh_key(message.id, Some(&key))?;
                                self.db.update_attachment(message.id, 0, AttachmentState::Downloading)?
                            }
                            None => message,
                        };
                        received.push(message);
                    }
                }
                InboxEvent::Status { contact, id, status } => {
                    self.db.advance_status(contact, &id, status)?;
                }
                InboxEvent::PrekeyUsed { contact, prekey } => self.db.delete_own_prekey(contact, prekey)?,
                InboxEvent::GroupUpdate { .. } | InboxEvent::GroupMessage { .. } | InboxEvent::GroupLeave { .. } => {
                    group.push(event);
                }
            }
        }
        Ok((received, group))
    }

    pub fn clear_inbox(&self) -> Result<(), AccountError> {
        Ok(inbox::clear(&self.inbox_path())?)
    }

    pub fn messages(&self, contact: ContactId) -> Result<Vec<StoredMessage>, AccountError> {
        Ok(self.db.messages(contact)?)
    }

    pub fn undelivered(&self, contact: ContactId) -> Result<Vec<StoredMessage>, AccountError> {
        Ok(self.db.undelivered(contact)?)
    }

    pub fn advance_status(
        &self,
        contact: ContactId,
        message_id: &MessageId,
        status: MessageStatus,
    ) -> Result<Option<StoredMessage>, AccountError> {
        Ok(self.db.advance_status(contact, message_id, status)?)
    }
}

fn crypto(error: CryptoError) -> AccountError {
    AccountError::Storage(StorageError::Crypto(error))
}

fn database_path(dir: &Path) -> PathBuf {
    dir.join(DATABASE_FILE)
}

/// Removes a database left behind by a failed account creation.
fn remove_database(dir: &Path) {
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(dir.join(format!("{DATABASE_FILE}{suffix}")));
    }
}

fn check_pin(pin: &[u8]) -> Result<(), AccountError> {
    let chars = std::str::from_utf8(pin).map_or(pin.len(), |s| s.chars().count());
    if chars < MIN_PIN_LEN {
        return Err(AccountError::PinTooShort);
    }
    Ok(())
}

fn check_display_name(name: &str) -> Result<&str, AccountError> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > MAX_DISPLAY_NAME_CHARS || name.chars().any(char::is_control) {
        return Err(AccountError::InvalidDisplayName);
    }
    Ok(name)
}

/// Attachment content, next to the database (docs/architecture.md §4).
const FILES_DIR: &str = "files";

/// The plaintext size a stored file's chunks were written for: the whole file, also while it is
/// still arriving (all chunks but the last are full either way).
fn file_size_stored(attachment: &crate::storage::Attachment) -> u64 {
    if attachment.state == AttachmentState::Complete {
        attachment.size
    } else {
        attachment.stored
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::vault::tests::TEST_PARAMS;

    #[test]
    fn create_lock_and_unlock() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!Account::exists(dir.path()));
        let (account, pin_record) = Account::create(dir.path(), b"123456", "Ayşe", TEST_PARAMS).unwrap();
        let id = account.airchat_id();
        drop(account);

        assert!(Account::exists(dir.path()));
        let mut account = Account::unlock_with_pin(dir.path(), &pin_record, b"123456").unwrap();
        assert_eq!(account.airchat_id(), id);
        assert_eq!(account.display_name(), "Ayşe");
        account.set_display_name("Ayşe K.").unwrap();
        drop(account);
        let account = Account::unlock_with_pin(dir.path(), &pin_record, b"123456").unwrap();
        assert_eq!(account.display_name(), "Ayşe K.");

        assert!(matches!(
            Account::unlock_with_pin(dir.path(), &pin_record, b"000000"),
            Err(AccountError::Vault(VaultError::WrongCredential))
        ));
    }

    #[test]
    fn never_overwrites_an_existing_account() {
        let dir = tempfile::tempdir().unwrap();
        Account::create(dir.path(), b"123456", "A", TEST_PARAMS).unwrap();
        assert!(matches!(
            Account::create(dir.path(), b"654321", "B", TEST_PARAMS),
            Err(AccountError::AlreadyExists)
        ));
    }

    #[test]
    fn secret_unlock_and_pin_change() {
        let dir = tempfile::tempdir().unwrap();
        let (account, _) = Account::create(dir.path(), b"123456", "A", TEST_PARAMS).unwrap();
        let unlock = account.create_secret_unlock().unwrap();
        let new_pin_record = account.change_pin(b"999999", TEST_PARAMS).unwrap();
        let id = account.airchat_id();
        drop(account);

        let by_secret = Account::unlock_with_secret(dir.path(), &unlock.record, &unlock.secret).unwrap();
        assert_eq!(by_secret.airchat_id(), id);
        assert!(by_secret.db.identity().unwrap().is_some());
        drop(by_secret);

        let by_new_pin = Account::unlock_with_pin(dir.path(), &new_pin_record, b"999999").unwrap();
        assert_eq!(by_new_pin.airchat_id(), id);
    }

    #[test]
    fn enforces_pin_and_name_rules() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            Account::create(dir.path(), b"12345", "A", TEST_PARAMS),
            Err(AccountError::PinTooShort)
        ));
        assert!(matches!(
            Account::create(dir.path(), b"123456", "   ", TEST_PARAMS),
            Err(AccountError::InvalidDisplayName)
        ));
        assert!(
            !Account::exists(dir.path()),
            "rejected input must not leave files behind"
        );

        let (mut account, _) = Account::create(dir.path(), "çğüşöı".as_bytes(), "  Ali  ", TEST_PARAMS).unwrap();
        assert_eq!(account.display_name(), "Ali");
        assert!(matches!(
            account.change_pin(b"123", TEST_PARAMS),
            Err(AccountError::PinTooShort)
        ));
        let long_name = "x".repeat(MAX_DISPLAY_NAME_CHARS + 1);
        assert!(matches!(
            account.set_display_name(&long_name),
            Err(AccountError::InvalidDisplayName)
        ));
        assert!(matches!(
            account.set_display_name("Ali\u{7}"),
            Err(AccountError::InvalidDisplayName)
        ));
    }

    #[test]
    fn link_keys_persist_across_unlocks() {
        let dir = tempfile::tempdir().unwrap();
        let (account, record) = Account::create(dir.path(), b"123456", "A", TEST_PARAMS).unwrap();
        let kem = account.link_keys().static_kem.encapsulation_key().clone();
        let presence = *account.profile().presence_key.expose();
        drop(account);
        let account = Account::unlock_with_pin(dir.path(), &record, b"123456").unwrap();
        assert_eq!(account.link_keys().static_kem.encapsulation_key(), &kem);
        assert_eq!(account.profile().presence_key.expose(), &presence);
    }

    #[test]
    fn accounts_from_before_link_keys_get_them_on_open() {
        let dir = tempfile::tempdir().unwrap();
        let (account, record) = Account::create(dir.path(), b"123456", "A", TEST_PARAMS).unwrap();
        account.db.forget_identity_keys().unwrap();
        drop(account);
        let account = Account::unlock_with_pin(dir.path(), &record, b"123456").unwrap();
        assert!(account.db.identity_keys().unwrap().is_some());
    }

    #[test]
    fn contacts_are_stored_listed_and_deleted() {
        use crate::{crypto::kem::DecapsulationKey, pairing::PairedContact};

        let dir = tempfile::tempdir().unwrap();
        let (account, record) = Account::create(dir.path(), b"123456", "A", TEST_PARAMS).unwrap();
        let contact = |name: &str| PairedContact {
            identity: Identity::generate().unwrap().public(),
            static_kem: DecapsulationKey::generate().unwrap().encapsulation_key().clone(),
            display_name: name.into(),
            presence_key: SecretBytes::random().unwrap(),
            link_psk: SecretBytes::random().unwrap(),
        };
        let (zeynep, burak) = (contact("Zeynep"), contact("burak"));
        let z = account.add_contact(&zeynep).unwrap();
        let b = account.add_contact(&burak).unwrap();
        assert_eq!(
            account
                .contacts()
                .unwrap()
                .iter()
                .map(|c| c.display_name.as_str())
                .collect::<Vec<_>>(),
            ["burak", "Zeynep"],
            "sorted by name, ignoring case"
        );

        // Links replace a contact's link keys; they start as the pairing secret alone.
        let link_keys = |account: &Account, id| -> Vec<[u8; 32]> {
            let entry = account
                .contact_directory()
                .unwrap()
                .into_iter()
                .find(|e| e.id == id)
                .unwrap();
            entry.link_keys.iter().map(|k| *k.expose()).collect()
        };
        assert_eq!(link_keys(&account, z.id), [*zeynep.link_psk.expose()]);
        let newer = [SecretBytes::random().unwrap(), zeynep.link_psk.clone()];
        assert!(account.db.set_link_keys(z.id, &newer).unwrap());
        assert_eq!(link_keys(&account, z.id), newer.map(|k| *k.expose()));

        // Pairing again replaces keys and name but keeps the id; the link keys start over.
        let again = PairedContact {
            display_name: "Zeynep K.".into(),
            link_psk: SecretBytes::random().unwrap(),
            ..zeynep
        };
        assert_eq!(account.add_contact(&again).unwrap().id, z.id);
        assert_eq!(link_keys(&account, z.id), [*again.link_psk.expose()]);
        drop(account);

        let account = Account::unlock_with_pin(dir.path(), &record, b"123456").unwrap();
        let keys = account.remote_keys(z.id).unwrap().unwrap();
        assert_eq!(keys.identity, again.identity);
        assert_eq!(keys.link_psk.expose(), again.link_psk.expose());
        assert!(account.delete_contact(b.id, false).unwrap());
        assert!(!account.delete_contact(b.id, false).unwrap());
        assert!(account.remote_keys(b.id).unwrap().is_none());
        assert_eq!(account.contacts().unwrap().len(), 1);
    }

    #[test]
    fn unlocking_without_an_account_fails() {
        let dir = tempfile::tempdir().unwrap();
        let (_, record) = Vault::create(b"123456", TEST_PARAMS).unwrap();
        assert!(matches!(
            Account::unlock_with_pin(dir.path(), &record, b"123456"),
            Err(AccountError::NotFound)
        ));
    }
}
