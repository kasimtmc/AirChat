//! Files at the server (docs/protocol.md §18): a file's content, sealed end to end under a key of
//! its own, waits at the sender's server until every recipient took it, at most 7 days. The sender
//! uploads it once; each recipient downloads it with a token of its own and says when it took it.
//!
//! ```text
//! sealed chunk i = ChaCha20-Poly1305(key, nonce = i (u64) || last (u32), aad = message_id, 64 KiB chunk)
//! 0x63 file drop (mail) / group content 0x07 = reference (16) || Name(server) || file (16) || token (32) || key (32)
//! 0xb0 upload:   file (16) || upload (32) || sealed content
//! 0xb1 download: file (16) || token (32)        answer 0xb3 content: sealed content
//! 0xb2 taken:    file (16) || token (32)
//! ```

use zeroize::Zeroizing;

use crate::{
    account::{AccountError, Answer, Failure, Reader, check_server, put_name},
    crypto::{
        CryptoError, SecretBytes,
        aead::{self, ChaCha20Poly1305},
        hash::sha256,
    },
    labels,
};

/// Files are sealed in chunks of this many bytes, the last one padded.
pub const CHUNK_LEN: usize = 65_536;
pub const SEALED_CHUNK_LEN: usize = CHUNK_LEN + aead::TAG_LEN;
/// A file has at most this many chunks: 64 MiB.
pub const MAX_CHUNKS: u64 = 1024;
pub const FILE_ID_LEN: usize = 16;
pub const TOKEN_LEN: usize = 32;
pub const KEY_LEN: usize = 32;
/// One file is taken by at most this many: the other members of the largest group.
pub const MAX_RECIPIENTS: usize = 31;
/// How long a file waits at the server at most (M-5).
pub const KEEP_DAYS: i64 = 7;

pub type FileId = [u8; FILE_ID_LEN];

const VERSION: u8 = 0x00;
const UPLOAD: u8 = 0xb0;
const DOWNLOAD: u8 = 0xb1;
const TAKEN: u8 = 0xb2;
const CONTENT: u8 = 0xb3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DropError {
    #[error("malformed file frame or record")]
    Malformed,
    #[error("the file is larger than 64 MiB")]
    TooLarge,
    /// Not sealed under this key, tampered with, or cut short.
    #[error("the file does not open")]
    DoesNotOpen,
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

impl From<AccountError> for DropError {
    fn from(_: AccountError) -> Self {
        Self::Malformed
    }
}

/// Chunks of a file of `size` bytes: at least one.
pub fn chunk_count(size: u64) -> u64 {
    size.div_ceil(CHUNK_LEN as u64).max(1)
}

/// Bytes of the sealed content of a file of `size` bytes, as the server stores it.
pub fn sealed_len(size: u64) -> u64 {
    chunk_count(size) * SEALED_CHUNK_LEN as u64
}

/// Seals a file under its key (§18.1); `message_id` is that of the message offering it.
pub fn seal(key: &SecretBytes<KEY_LEN>, message_id: &[u8; 16], file: &[u8]) -> Result<Vec<u8>, DropError> {
    let count = chunk_count(file.len() as u64);
    if count > MAX_CHUNKS {
        return Err(DropError::TooLarge);
    }
    let mut sealed = Vec::with_capacity(sealed_len(file.len() as u64) as usize);
    let mut chunk = Zeroizing::new(vec![0; CHUNK_LEN]);
    for index in 0..count {
        let start = (index as usize * CHUNK_LEN).min(file.len());
        let end = (start + CHUNK_LEN).min(file.len());
        chunk.fill(0);
        chunk[..end - start].copy_from_slice(&file[start..end]);
        sealed.extend_from_slice(&ChaCha20Poly1305::seal(
            key,
            &nonce(index, index + 1 == count),
            message_id,
            &chunk,
        )?);
    }
    Ok(sealed)
}

/// Opens a file of `size` bytes (as its offer says) and strips the padding.
pub fn open(
    key: &SecretBytes<KEY_LEN>,
    message_id: &[u8; 16],
    size: u64,
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, DropError> {
    let count = chunk_count(size);
    if count > MAX_CHUNKS || sealed.len() as u64 != sealed_len(size) {
        return Err(DropError::DoesNotOpen);
    }
    let mut file = Zeroizing::new(Vec::with_capacity(count as usize * CHUNK_LEN));
    for (index, chunk) in sealed.chunks(SEALED_CHUNK_LEN).enumerate() {
        let index = index as u64;
        let opened = ChaCha20Poly1305::open(key, &nonce(index, index + 1 == count), message_id, chunk)
            .map_err(|_| DropError::DoesNotOpen)?;
        file.extend_from_slice(&opened);
    }
    // The padding is zeros; anything else was not sealed by this format.
    if file[size as usize..].iter().any(|&b| b != 0) {
        return Err(DropError::DoesNotOpen);
    }
    file.truncate(size as usize);
    Ok(file)
}

/// What the server keeps of a download token (§18.2).
pub fn token_hash(token: &[u8; TOKEN_LEN]) -> [u8; 32] {
    sha256(&[labels::FILE_TOKEN, token])
}

fn nonce(index: u64, last: bool) -> [u8; 12] {
    let mut nonce = [0; 12];
    nonce[..8].copy_from_slice(&index.to_be_bytes());
    nonce[8..].copy_from_slice(&u32::from(last).to_be_bytes());
    nonce
}

/// Where a recipient's file waits and how to open it (§18.3), mailed to it (0x63) or, in a group,
/// sent to it alone (content 0x07).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Drop {
    /// The message that offers the file: a file offer (0x20) or a group file message (0x02).
    pub reference: [u8; 16],
    /// The server it waits at.
    pub server: String,
    pub file: FileId,
    pub token: Zeroizing<[u8; TOKEN_LEN]>,
    pub key: Zeroizing<[u8; KEY_LEN]>,
}

impl Drop {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.reference);
        put_name(&mut out, &self.server);
        out.extend_from_slice(&self.file);
        out.extend_from_slice(&self.token[..]);
        out.extend_from_slice(&self.key[..]);
        out
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, DropError> {
        let mut reader = Reader(bytes);
        let reference = reader.array()?;
        let server = reader.name()?;
        check_server(&server)?;
        let drop = Self {
            reference,
            server,
            file: reader.array()?,
            token: Zeroizing::new(reader.array()?),
            key: Zeroizing::new(reader.array()?),
        };
        reader.end()?;
        Ok(drop)
    }
}

/// What a device sends on the server's files endpoint, not signed in (§18.2, §18.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileRequest {
    Upload {
        file: FileId,
        upload: Zeroizing<[u8; TOKEN_LEN]>,
        content: Vec<u8>,
    },
    Download {
        file: FileId,
        token: Zeroizing<[u8; TOKEN_LEN]>,
    },
    Taken {
        file: FileId,
        token: Zeroizing<[u8; TOKEN_LEN]>,
    },
}

impl FileRequest {
    pub fn encode(&self) -> Vec<u8> {
        let (kind, file, token, content): (u8, &FileId, &[u8; TOKEN_LEN], &[u8]) = match self {
            Self::Upload { file, upload, content } => (UPLOAD, file, upload, content),
            Self::Download { file, token } => (DOWNLOAD, file, token, &[]),
            Self::Taken { file, token } => (TAKEN, file, token, &[]),
        };
        [&[VERSION, kind][..], file, &token[..], content].concat()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DropError> {
        let [VERSION, kind, rest @ ..] = bytes else {
            return Err(DropError::Malformed);
        };
        if rest.len() < FILE_ID_LEN + TOKEN_LEN {
            return Err(DropError::Malformed);
        }
        let (file, rest) = rest.split_at(FILE_ID_LEN);
        let (token, content) = rest.split_at(TOKEN_LEN);
        let file: FileId = file.try_into().expect("length checked");
        let token = Zeroizing::new(token.try_into().expect("length checked"));
        match (*kind, content) {
            (UPLOAD, content) => {
                if content.is_empty()
                    || !content.len().is_multiple_of(SEALED_CHUNK_LEN)
                    || content.len() as u64 > MAX_CHUNKS * SEALED_CHUNK_LEN as u64
                {
                    return Err(DropError::Malformed);
                }
                Ok(Self::Upload {
                    file,
                    upload: token,
                    content: content.to_vec(),
                })
            }
            (DOWNLOAD, []) => Ok(Self::Download { file, token }),
            (TAKEN, []) => Ok(Self::Taken { file, token }),
            _ => Err(DropError::Malformed),
        }
    }
}

/// What the files endpoint answers: the sealed content of a download, or done, or a failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileAnswer {
    Content(Vec<u8>),
    Done,
    Failure(Failure),
}

impl FileAnswer {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Content(content) => [&[VERSION, CONTENT][..], content].concat(),
            Self::Done => Answer::Done.encode(),
            Self::Failure(failure) => Answer::Failure {
                failure: *failure,
                retry_after: 0,
            }
            .encode(),
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DropError> {
        match bytes {
            [VERSION, CONTENT, content @ ..] => Ok(Self::Content(content.to_vec())),
            _ => match Answer::decode(bytes)? {
                Answer::Done => Ok(Self::Done),
                Answer::Failure { failure, .. } => Ok(Self::Failure(failure)),
                _ => Err(DropError::Malformed),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::test_util::{check_vector, to_hex};

    fn key() -> SecretBytes<KEY_LEN> {
        SecretBytes::from_slice(&[0x4b; 32]).unwrap()
    }

    #[test]
    fn files_seal_in_padded_chunks_and_open_only_whole() {
        for size in [0, 1, CHUNK_LEN - 1, CHUNK_LEN, CHUNK_LEN + 1, 3 * CHUNK_LEN + 17] {
            let file: Vec<u8> = (0..size).map(|i| (i % 251) as u8 + 1).collect();
            let sealed = seal(&key(), &[1; 16], &file).unwrap();
            assert_eq!(sealed.len() as u64, sealed_len(size as u64));
            assert_eq!(&open(&key(), &[1; 16], size as u64, &sealed).unwrap()[..], &file[..]);
        }
        let file = vec![7; 2 * CHUNK_LEN + 5];
        let sealed = seal(&key(), &[1; 16], &file).unwrap();
        // Another key or message, a chunk cut off, chunks swapped, or a lie about the size.
        let other = SecretBytes::from_slice(&[0x4c; 32]).unwrap();
        assert!(open(&other, &[1; 16], file.len() as u64, &sealed).is_err());
        assert!(open(&key(), &[2; 16], file.len() as u64, &sealed).is_err());
        assert!(open(&key(), &[1; 16], 2 * CHUNK_LEN as u64, &sealed[..2 * SEALED_CHUNK_LEN]).is_err());
        let mut swapped = sealed.clone();
        swapped[..SEALED_CHUNK_LEN].copy_from_slice(&sealed[SEALED_CHUNK_LEN..2 * SEALED_CHUNK_LEN]);
        swapped[SEALED_CHUNK_LEN..2 * SEALED_CHUNK_LEN].copy_from_slice(&sealed[..SEALED_CHUNK_LEN]);
        assert!(open(&key(), &[1; 16], file.len() as u64, &swapped).is_err());
        assert!(
            open(&key(), &[1; 16], file.len() as u64 - 1, &sealed).is_err(),
            "padding is zeros"
        );
        assert_eq!(
            seal(&key(), &[1; 16], &vec![0; MAX_CHUNKS as usize * CHUNK_LEN + 1]),
            Err(DropError::TooLarge)
        );
    }

    #[test]
    fn records_and_frames_round_trip() {
        let drop = Drop {
            reference: [1; 16],
            server: "chat.example.org".into(),
            file: [2; 16],
            token: Zeroizing::new([3; 32]),
            key: Zeroizing::new([4; 32]),
        };
        assert_eq!(Drop::decode(&drop.encode()).unwrap(), drop);
        assert!(Drop::decode(&drop.encode()[1..]).is_err());
        for request in [
            FileRequest::Upload {
                file: [5; 16],
                upload: Zeroizing::new([6; 32]),
                content: vec![7; SEALED_CHUNK_LEN],
            },
            FileRequest::Download {
                file: [5; 16],
                token: Zeroizing::new([8; 32]),
            },
            FileRequest::Taken {
                file: [5; 16],
                token: Zeroizing::new([8; 32]),
            },
        ] {
            assert_eq!(FileRequest::decode(&request.encode()).unwrap(), request);
        }
        // An upload is whole chunks.
        let short = [&[VERSION, UPLOAD][..], &[0; 48], &[0; 10]].concat();
        assert!(FileRequest::decode(&short).is_err());
        for answer in [
            FileAnswer::Content(vec![9; 40]),
            FileAnswer::Done,
            FileAnswer::Failure(Failure::Refused),
        ] {
            assert_eq!(FileAnswer::decode(&answer.encode()).unwrap(), answer);
        }
    }

    /// `tests/vectors/file_drop.json`; `check_file_drop.py` re-derives it from §18.
    #[test]
    fn vector() {
        let file: Vec<u8> = (0..70_000u32).map(|i| (i * 13 % 256) as u8).collect();
        let message_id = [0x6d; 16];
        let sealed = seal(&key(), &message_id, &file).unwrap();
        let drop = Drop {
            reference: message_id,
            server: "chat.example.org".into(),
            file: [0x66; 16],
            token: Zeroizing::new([0x74; 32]),
            key: Zeroizing::new(*key().expose()),
        };
        let fields = [
            ("key", to_hex(key().expose())),
            ("message_id", to_hex(&message_id)),
            ("file_len", file.len().to_string()),
            ("sealed_len", sealed.len().to_string()),
            ("sealed_sha256", to_hex(&sha256(&[&sealed]))),
            ("last_chunk_tag", to_hex(&sealed[sealed.len() - aead::TAG_LEN..])),
            ("token_hash", to_hex(&token_hash(&[0x74; 32]))),
            (
                "drop_record",
                to_hex(&crate::chat::ChatMessage::FileDrop(drop).encode().unwrap()),
            ),
            (
                "download",
                to_hex(
                    &FileRequest::Download {
                        file: [0x66; 16],
                        token: Zeroizing::new([0x74; 32]),
                    }
                    .encode(),
                ),
            ),
        ];
        check_vector("file_drop", &fields);
    }
}
