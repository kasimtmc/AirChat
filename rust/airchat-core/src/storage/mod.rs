//! Encrypted storage: key hierarchy and database (requirement S-2).

pub mod channels;
mod contacts;
mod database;
pub mod groups;
mod messages;
pub mod prekeys;
pub mod requests;

/// The key hierarchy, encrypted files and the database engine are shared with AirChat+.
pub use airchat_storage::{StorageError, files, vault};

pub use contacts::{ContactId, ContactState, ContactSummary, DirectoryEntry, Permissions, StoredContact};
pub use database::{Database, IdentityKeys, StaticKeySeed};
pub use messages::{
    Attachment, AttachmentState, FileMeta, MAX_VOICE_BYTES, MESSAGE_ID_LEN, MessageId, MessageStatus, StoredMessage,
    TRY_MS, VOICE_KEEP_MS, VOICE_MIME, is_voice,
};
pub use vault::{UNLOCK_SECRET_LEN, Vault, VaultError};

#[cfg(test)]
pub(crate) mod tests {
    use crate::crypto::pin::PinParams;

    /// Fast Argon2id parameters, for tests only.
    pub(crate) const TEST_PARAMS: PinParams = PinParams {
        memory_kib: 64,
        iterations: 1,
        parallelism: 1,
    };
}
