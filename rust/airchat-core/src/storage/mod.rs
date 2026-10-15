//! Encrypted storage: key hierarchy and database (requirement S-2).

pub mod channels;
mod contacts;
mod database;
pub mod files;
pub mod groups;
mod messages;
pub mod prekeys;
pub mod requests;
pub mod vault;

pub use contacts::{ContactId, ContactState, ContactSummary, DirectoryEntry, Permissions, StoredContact};
pub use database::{Database, IdentityKeys, StaticKeySeed};
pub use messages::{
    Attachment, AttachmentState, FileMeta, MAX_VOICE_BYTES, MESSAGE_ID_LEN, MessageId, MessageStatus, StoredMessage,
    TRY_MS, VOICE_KEEP_MS, VOICE_MIME, is_voice,
};
pub use vault::{UNLOCK_SECRET_LEN, Vault, VaultError};

use crate::crypto::CryptoError;

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("the database key is wrong")]
    WrongKey,
    #[error("the database was created by a newer version of AirChat")]
    NewerSchema,
    #[error("database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("file error: {0}")]
    Io(String),
    #[error("the database is inconsistent")]
    Corrupt,
}
