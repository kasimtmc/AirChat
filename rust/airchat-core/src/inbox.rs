//! The locked-mode inbox (docs/architecture.md §4.3).
//!
//! While the app is locked the database and its key are gone from memory, yet messages keep
//! arriving. Each event is encrypted to the inbox public key and appended to a file; the matching
//! private key is stored in the database, so the entries become readable only after the next unlock,
//! when they are moved into the database.
//!
//! Every entry has its own X-Wing encapsulation, so the key that encrypted an entry is forgotten as
//! soon as the entry is written: a memory dump of the locked app reveals no earlier entry.
//!
//! ```text
//! file  = (length (u32, big-endian) || entry)*
//! entry = ct || ChaCha20-Poly1305(key = HKDF(ss, "AirChat v1 inbox-entry"), nonce = 0, aad = ct, event)
//! ```

use std::{
    fs::{self, OpenOptions},
    io::{ErrorKind, Write},
    path::{Path, PathBuf},
};

use zeroize::Zeroizing;

use crate::{
    crypto::{
        CryptoError, SecretBytes,
        aead::ChaCha20Poly1305,
        kdf,
        kem::{CIPHERTEXT_LEN, Ciphertext, DecapsulationKey, EncapsulationKey},
    },
    group::GroupId,
    labels,
    storage::{ContactId, FileMeta, MESSAGE_ID_LEN, MessageId, MessageStatus},
};

const KIND_MESSAGE: u8 = 1;
const KIND_STATUS: u8 = 2;
const KIND_FILE: u8 = 3;
const KIND_GROUP_UPDATE: u8 = 4;
const KIND_GROUP_MESSAGE: u8 = 5;
const KIND_GROUP_LEAVE: u8 = 6;
const KIND_PREKEY_USED: u8 = 7;
/// A file offer that came through the mesh, with the key of its parts.
const KIND_MESH_FILE: u8 = 8;
/// The single use of each entry key makes a fixed nonce safe.
const NONCE: [u8; 12] = [0; 12];

/// Something that happened while locked, to be applied to the database at unlock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboxEvent {
    Message {
        contact: ContactId,
        id: MessageId,
        sent_at_ms: i64,
        received_at_ms: i64,
        text: String,
    },
    /// A file offer: what the file is; its content is fetched after unlocking.
    File {
        contact: ContactId,
        id: MessageId,
        sent_at_ms: i64,
        received_at_ms: i64,
        meta: FileMeta,
        /// The key of its parts, if its content comes through the mesh (rust/airchat-protocol/docs/protocol.md §10.8).
        mesh_key: Option<Zeroizing<[u8; 32]>>,
    },
    /// An outgoing message was handed to a link (sent) or acknowledged (delivered).
    Status {
        contact: ContactId,
        id: MessageId,
        status: MessageStatus,
    },
    /// Group records (rust/airchat-protocol/docs/protocol.md §9), as received from `contact`: the node takes them in
    /// after unlocking, as if they arrived then.
    GroupUpdate {
        contact: ContactId,
        update: Vec<u8>,
    },
    GroupMessage {
        contact: ContactId,
        sealed: Vec<u8>,
    },
    /// A prekey handed to `contact` opened an envelope (rust/airchat-protocol/docs/protocol.md §10.7): its private half
    /// goes from storage at unlock (from memory it went at once).
    PrekeyUsed {
        contact: ContactId,
        prekey: u32,
    },
    GroupLeave {
        contact: ContactId,
        group_id: GroupId,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum InboxError {
    #[error("inbox file error: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// Appends events while locked. Holds only the public key.
pub struct InboxWriter {
    path: PathBuf,
    key: EncapsulationKey,
}

impl InboxWriter {
    pub fn new(path: PathBuf, key: EncapsulationKey) -> Self {
        Self { path, key }
    }

    /// Encrypts and durably appends `event`. Only once this returns may the event be acknowledged.
    pub fn append(&self, event: &InboxEvent) -> Result<(), InboxError> {
        let (shared, ciphertext) = self.key.encapsulate()?;
        let key: SecretBytes<32> = kdf::derive(&[], shared.expose(), labels::INBOX_ENTRY)?;
        let sealed = ChaCha20Poly1305::seal(&key, &NONCE, ciphertext.as_bytes(), &encode(event))?;
        let entry = [ciphertext.as_bytes().as_slice(), &sealed].concat();

        let mut file = OpenOptions::new().create(true).append(true).open(&self.path)?;
        let length = u32::try_from(entry.len()).expect("an entry is far below 4 GiB");
        file.write_all(&[&length.to_be_bytes()[..], &entry].concat())?;
        file.sync_data()?;
        Ok(())
    }
}

/// Reads every entry that decrypts. A torn last entry (the app died while writing) is skipped; its
/// event was never acknowledged, so the sender still has it.
pub fn read(path: &Path, key: &DecapsulationKey) -> Result<Vec<InboxEvent>, InboxError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let mut events = Vec::new();
    let mut rest = bytes.as_slice();
    while let Some((length, tail)) = rest.split_first_chunk::<4>() {
        let length = u32::from_be_bytes(*length) as usize;
        let Some((entry, tail)) = tail.split_at_checked(length) else {
            break;
        };
        rest = tail;
        if let Some(event) = open(entry, key) {
            events.push(event);
        }
    }
    Ok(events)
}

/// Deletes the inbox after its events have been applied.
pub fn clear(path: &Path) -> Result<(), InboxError> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != ErrorKind::NotFound => Err(e.into()),
        _ => Ok(()),
    }
}

fn open(entry: &[u8], key: &DecapsulationKey) -> Option<InboxEvent> {
    let (ciphertext, sealed) = entry.split_at_checked(CIPHERTEXT_LEN)?;
    let shared = key.decapsulate(&Ciphertext::from_bytes(ciphertext).ok()?).ok()?;
    let entry_key: SecretBytes<32> = kdf::derive(&[], shared.expose(), labels::INBOX_ENTRY).ok()?;
    let plaintext = ChaCha20Poly1305::open(&entry_key, &NONCE, ciphertext, sealed).ok()?;
    decode(&plaintext)
}

pub(crate) fn encode(event: &InboxEvent) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::new());
    match event {
        InboxEvent::Message {
            contact,
            id,
            sent_at_ms,
            received_at_ms,
            text,
        } => {
            out.push(KIND_MESSAGE);
            out.extend_from_slice(&contact.to_be_bytes());
            out.extend_from_slice(id);
            out.extend_from_slice(&sent_at_ms.to_be_bytes());
            out.extend_from_slice(&received_at_ms.to_be_bytes());
            out.extend_from_slice(text.as_bytes());
        }
        InboxEvent::File {
            contact,
            id,
            sent_at_ms,
            received_at_ms,
            meta,
            mesh_key,
        } => {
            out.push(if mesh_key.is_some() { KIND_MESH_FILE } else { KIND_FILE });
            out.extend_from_slice(&contact.to_be_bytes());
            out.extend_from_slice(id);
            out.extend_from_slice(&sent_at_ms.to_be_bytes());
            out.extend_from_slice(&received_at_ms.to_be_bytes());
            if let Some(key) = mesh_key {
                out.extend_from_slice(&key[..]);
            }
            out.extend_from_slice(&meta.size.to_be_bytes());
            out.extend_from_slice(&meta.sha256);
            for field in [
                meta.name.as_bytes(),
                meta.mime.as_bytes(),
                meta.thumbnail.as_deref().unwrap_or_default(),
            ] {
                let len = u32::try_from(field.len()).expect("checked when the offer arrived");
                out.extend_from_slice(&len.to_be_bytes());
                out.extend_from_slice(field);
            }
        }
        InboxEvent::Status { contact, id, status } => {
            out.push(KIND_STATUS);
            out.extend_from_slice(&contact.to_be_bytes());
            out.extend_from_slice(id);
            out.push(*status as u8);
        }
        InboxEvent::GroupUpdate { contact, update } => {
            out.push(KIND_GROUP_UPDATE);
            out.extend_from_slice(&contact.to_be_bytes());
            out.extend_from_slice(update);
        }
        InboxEvent::GroupMessage { contact, sealed } => {
            out.push(KIND_GROUP_MESSAGE);
            out.extend_from_slice(&contact.to_be_bytes());
            out.extend_from_slice(sealed);
        }
        InboxEvent::GroupLeave { contact, group_id } => {
            out.push(KIND_GROUP_LEAVE);
            out.extend_from_slice(&contact.to_be_bytes());
            out.extend_from_slice(group_id);
        }
        InboxEvent::PrekeyUsed { contact, prekey } => {
            out.push(KIND_PREKEY_USED);
            out.extend_from_slice(&contact.to_be_bytes());
            out.extend_from_slice(&prekey.to_be_bytes());
        }
    }
    out
}

pub(crate) fn decode(bytes: &[u8]) -> Option<InboxEvent> {
    let (&kind, rest) = bytes.split_first()?;
    let (contact, rest) = rest.split_first_chunk::<8>()?;
    let contact = i64::from_be_bytes(*contact);
    match kind {
        KIND_GROUP_UPDATE => {
            return Some(InboxEvent::GroupUpdate {
                contact,
                update: rest.to_vec(),
            });
        }
        KIND_GROUP_MESSAGE => {
            return Some(InboxEvent::GroupMessage {
                contact,
                sealed: rest.to_vec(),
            });
        }
        KIND_GROUP_LEAVE => {
            return Some(InboxEvent::GroupLeave {
                contact,
                group_id: rest.try_into().ok()?,
            });
        }
        KIND_PREKEY_USED => {
            let prekey: [u8; 4] = rest.try_into().ok()?;
            return Some(InboxEvent::PrekeyUsed {
                contact,
                prekey: u32::from_be_bytes(prekey),
            });
        }
        _ => {}
    }
    let (id, rest) = rest.split_first_chunk::<MESSAGE_ID_LEN>()?;
    match kind {
        KIND_MESSAGE => {
            let (sent_at, rest) = rest.split_first_chunk::<8>()?;
            let (received_at, text) = rest.split_first_chunk::<8>()?;
            Some(InboxEvent::Message {
                contact,
                id: *id,
                sent_at_ms: i64::from_be_bytes(*sent_at),
                received_at_ms: i64::from_be_bytes(*received_at),
                text: std::str::from_utf8(text).ok()?.to_owned(),
            })
        }
        KIND_FILE | KIND_MESH_FILE => {
            let (sent_at, rest) = rest.split_first_chunk::<8>()?;
            let (received_at, rest) = rest.split_first_chunk::<8>()?;
            let (mesh_key, rest) = match kind {
                KIND_MESH_FILE => {
                    let (key, rest) = rest.split_first_chunk::<32>()?;
                    (Some(Zeroizing::new(*key)), rest)
                }
                _ => (None, rest),
            };
            let (size, rest) = rest.split_first_chunk::<8>()?;
            let (sha256, mut rest) = rest.split_first_chunk::<32>()?;
            let mut fields = Vec::new();
            for _ in 0..3 {
                let (len, tail) = rest.split_first_chunk::<4>()?;
                let (field, tail) = tail.split_at_checked(usize::try_from(u32::from_be_bytes(*len)).ok()?)?;
                fields.push(field);
                rest = tail;
            }
            if !rest.is_empty() {
                return None;
            }
            Some(InboxEvent::File {
                contact,
                id: *id,
                sent_at_ms: i64::from_be_bytes(*sent_at),
                received_at_ms: i64::from_be_bytes(*received_at),
                meta: FileMeta {
                    name: std::str::from_utf8(fields[0]).ok()?.to_owned(),
                    mime: std::str::from_utf8(fields[1]).ok()?.to_owned(),
                    size: u64::from_be_bytes(*size),
                    sha256: *sha256,
                    thumbnail: (!fields[2].is_empty()).then(|| fields[2].to_vec()),
                },
                mesh_key,
            })
        }
        KIND_STATUS => {
            let status = match rest {
                [1] => MessageStatus::Sent,
                [2] => MessageStatus::Delivered,
                [4] => MessageStatus::Refused,
                _ => return None,
            };
            Some(InboxEvent::Status {
                contact,
                id: *id,
                status,
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn events() -> Vec<InboxEvent> {
        vec![
            InboxEvent::Message {
                contact: 3,
                id: [1; 16],
                sent_at_ms: 10,
                received_at_ms: 20,
                text: "gizli mesaj".into(),
            },
            InboxEvent::Status {
                contact: 3,
                id: [2; 16],
                status: MessageStatus::Delivered,
            },
            InboxEvent::File {
                contact: 3,
                id: [5; 16],
                sent_at_ms: 30,
                received_at_ms: 40,
                meta: FileMeta {
                    name: "gizli belge.pdf".into(),
                    mime: "application/pdf".into(),
                    size: 1_000_000,
                    sha256: [6; 32],
                    thumbnail: Some(vec![7; 100]),
                },
                mesh_key: None,
            },
            InboxEvent::File {
                contact: 3,
                id: [6; 16],
                sent_at_ms: 31,
                received_at_ms: 41,
                meta: FileMeta {
                    name: "not.txt".into(),
                    mime: "text/plain".into(),
                    size: 5,
                    sha256: [6; 32],
                    thumbnail: None,
                },
                mesh_key: Some(Zeroizing::new([9; 32])),
            },
            InboxEvent::GroupUpdate {
                contact: 5,
                update: vec![8; 300],
            },
            InboxEvent::GroupMessage {
                contact: 5,
                sealed: vec![9; 200],
            },
            InboxEvent::GroupLeave {
                contact: 6,
                group_id: [10; 16],
            },
            InboxEvent::PrekeyUsed {
                contact: 3,
                prekey: 0xdead_beef,
            },
            InboxEvent::Status {
                contact: 4,
                id: [3; 16],
                status: MessageStatus::Sent,
            },
        ]
    }

    #[test]
    fn written_entries_read_back_only_with_the_private_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("inbox");
        let key = DecapsulationKey::generate().unwrap();
        let writer = InboxWriter::new(path.clone(), key.encapsulation_key().clone());
        for event in events() {
            writer.append(&event).unwrap();
        }
        assert_eq!(read(&path, &key).unwrap(), events());

        let other = DecapsulationKey::generate().unwrap();
        assert!(read(&path, &other).unwrap().is_empty());

        let bytes = fs::read(&path).unwrap();
        assert!(!bytes.windows(11).any(|w| w == b"gizli mesaj"), "no plaintext on disk");

        clear(&path).unwrap();
        clear(&path).unwrap();
        assert!(read(&path, &key).unwrap().is_empty());
    }

    #[test]
    fn a_torn_last_entry_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("inbox");
        let key = DecapsulationKey::generate().unwrap();
        let writer = InboxWriter::new(path.clone(), key.encapsulation_key().clone());
        for event in events() {
            writer.append(&event).unwrap();
        }
        let bytes = fs::read(&path).unwrap();
        fs::write(&path, &bytes[..bytes.len() - 5]).unwrap();
        let events = events();
        assert_eq!(read(&path, &key).unwrap(), events[..events.len() - 1]);
    }
}
