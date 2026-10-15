//! Attachment files at rest (docs/architecture.md §4): encrypted in chunks, so a file can be read
//! at any position and written as it arrives.
//!
//! ```text
//! file  = chunk*            every chunk holds CHUNK_LEN bytes of the plaintext, the last one fewer
//! chunk = nonce (24) || XChaCha20-Poly1305(file key, nonce,
//!                       aad = "AirChat v1 storage file-chunk" || file (i64) || index (u64), plaintext)
//! ```
//!
//! A file is named by its row in the database, never by anything a contact chose. The database
//! records how many bytes are stored; a chunk torn by a crash is cut off when writing resumes.

use std::{
    fs::{self, File, OpenOptions},
    io::{ErrorKind, Read, Seek, SeekFrom, Write},
    path::PathBuf,
};

use zeroize::Zeroizing;

use super::StorageError;
use crate::{
    crypto::{CryptoError, SecretBytes, aead::XChaCha20Poly1305},
    labels,
};

/// Plaintext bytes per chunk, at rest as on the wire.
pub use crate::chat::CHUNK_LEN;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const SEALED_CHUNK_LEN: u64 = (NONCE_LEN + CHUNK_LEN + TAG_LEN) as u64;

/// Number of chunks a file of `size` bytes has.
pub fn chunk_count(size: u64) -> u64 {
    size.div_ceil(CHUNK_LEN as u64)
}

/// Plaintext length of chunk `index` of a file of `size` bytes.
pub fn chunk_len(size: u64, index: u64) -> usize {
    let start = index.saturating_mul(CHUNK_LEN as u64);
    usize::try_from(size.saturating_sub(start).min(CHUNK_LEN as u64)).expect("at most CHUNK_LEN")
}

pub struct FileStore {
    dir: PathBuf,
    key: SecretBytes<32>,
}

impl FileStore {
    pub fn new(dir: PathBuf, key: SecretBytes<32>) -> Self {
        Self { dir, key }
    }

    fn path(&self, file: i64) -> PathBuf {
        self.dir.join(file.to_string())
    }

    /// Writes chunk `index` of `file`, of which `stored` bytes are already on disk. Chunks go in
    /// order; anything beyond `stored` (a chunk torn by a crash) is cut off first. Not durable
    /// until [`FileStore::sync`].
    pub fn write_chunk(&self, file: i64, stored: u64, index: u64, data: &[u8]) -> Result<(), StorageError> {
        if index != chunk_count(stored) || data.is_empty() || data.len() > CHUNK_LEN {
            return Err(CryptoError::InvalidParameters.into());
        }
        // Only the last chunk may be short, so a short one must not have stored data after it.
        if !stored.is_multiple_of(CHUNK_LEN as u64) {
            return Err(CryptoError::InvalidParameters.into());
        }
        fs::create_dir_all(&self.dir).map_err(io)?;
        let mut out = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(self.path(file))
            .map_err(io)?;
        let end = index * SEALED_CHUNK_LEN;
        out.set_len(end).map_err(io)?;
        out.seek(SeekFrom::Start(end)).map_err(io)?;
        let sealed = XChaCha20Poly1305::seal_with_random_nonce(&self.key, &aad(file, index), data)?;
        out.write_all(&sealed).map_err(io)?;
        Ok(())
    }

    /// Makes the chunks written to `file` durable; call before recording how much is stored.
    pub fn sync(&self, file: i64) -> Result<(), StorageError> {
        File::open(self.path(file)).and_then(|f| f.sync_data()).map_err(io)
    }

    /// Chunk `index` of `file` (whose plaintext is `size` bytes long).
    pub fn read_chunk(&self, file: i64, size: u64, index: u64) -> Result<Zeroizing<Vec<u8>>, StorageError> {
        let len = chunk_len(size, index);
        if len == 0 {
            return Err(CryptoError::InvalidParameters.into());
        }
        let mut input = File::open(self.path(file)).map_err(io)?;
        input
            .seek(SeekFrom::Start(index.saturating_mul(SEALED_CHUNK_LEN)))
            .map_err(io)?;
        let mut sealed = vec![0; NONCE_LEN + len + TAG_LEN];
        input.read_exact(&mut sealed).map_err(io)?;
        Ok(XChaCha20Poly1305::open_with_nonce_prefix(
            &self.key,
            &aad(file, index),
            &sealed,
        )?)
    }

    /// Plaintext bytes `offset..offset + len` (clamped to the file) of `file`.
    pub fn read(&self, file: i64, size: u64, offset: u64, len: usize) -> Result<Zeroizing<Vec<u8>>, StorageError> {
        let end = size.min(offset.saturating_add(len as u64));
        let mut out = Zeroizing::new(Vec::with_capacity(
            usize::try_from(end.saturating_sub(offset)).unwrap_or(0),
        ));
        let mut position = offset;
        while position < end {
            let index = position / CHUNK_LEN as u64;
            let chunk = self.read_chunk(file, size, index)?;
            let from = usize::try_from(position - index * CHUNK_LEN as u64).expect("within a chunk");
            let to = chunk
                .len()
                .min(from + usize::try_from(end - position).unwrap_or(usize::MAX));
            out.extend_from_slice(&chunk[from..to]);
            position += (to - from) as u64;
        }
        Ok(out)
    }

    pub fn delete(&self, file: i64) -> Result<(), StorageError> {
        match fs::remove_file(self.path(file)) {
            Err(e) if e.kind() != ErrorKind::NotFound => Err(io(e)),
            _ => Ok(()),
        }
    }
}

fn aad(file: i64, index: u64) -> Vec<u8> {
    [labels::STORAGE_FILE_CHUNK, &file.to_be_bytes(), &index.to_be_bytes()].concat()
}

fn io(error: std::io::Error) -> StorageError {
    StorageError::Io(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(dir: &tempfile::TempDir) -> FileStore {
        FileStore::new(dir.path().join("files"), SecretBytes::from_slice(&[3; 32]).unwrap())
    }

    fn sample(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 7 % 251) as u8).collect()
    }

    fn write_all(store: &FileStore, file: i64, data: &[u8]) {
        let mut stored = 0u64;
        for (index, chunk) in data.chunks(CHUNK_LEN).enumerate() {
            store.write_chunk(file, stored, index as u64, chunk).unwrap();
            stored += chunk.len() as u64;
        }
    }

    #[test]
    fn chunks_read_back_at_any_position_and_nothing_is_plain_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir);
        let data = sample(2 * CHUNK_LEN + 1000);
        write_all(&store, 7, &data);
        let size = data.len() as u64;
        assert_eq!(*store.read(7, size, 0, data.len()).unwrap(), data);
        let middle = store.read(7, size, CHUNK_LEN as u64 - 10, 30).unwrap();
        assert_eq!(*middle, data[CHUNK_LEN - 10..CHUNK_LEN + 20]);
        assert_eq!(
            store.read(7, size, size - 5, 100).unwrap().len(),
            5,
            "clamped to the file"
        );
        assert!(store.read_chunk(7, size, u64::MAX).is_err(), "past the end");

        let on_disk = fs::read(dir.path().join("files/7")).unwrap();
        for start in [0, CHUNK_LEN, 2 * CHUNK_LEN] {
            let plain = &data[start..start + 64];
            assert!(!on_disk.windows(64).any(|w| w == plain), "plaintext at {start} on disk");
        }
        store.delete(7).unwrap();
        store.delete(7).unwrap();
    }

    #[test]
    fn chunks_are_bound_to_their_file_and_position() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir);
        let data = sample(2 * CHUNK_LEN);
        write_all(&store, 1, &data);
        let files = dir.path().join("files");
        fs::copy(files.join("1"), files.join("2")).unwrap();
        assert!(
            store.read_chunk(2, data.len() as u64, 0).is_err(),
            "another file's chunk"
        );

        let mut swapped = fs::read(files.join("1")).unwrap();
        let (first, second) = swapped.split_at_mut(SEALED_CHUNK_LEN as usize);
        first.swap_with_slice(second);
        fs::write(files.join("1"), swapped).unwrap();
        assert!(store.read_chunk(1, data.len() as u64, 0).is_err(), "chunks swapped");
    }

    #[test]
    fn a_torn_chunk_is_cut_off_when_writing_resumes() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir);
        let data = sample(3 * CHUNK_LEN);
        store.write_chunk(5, 0, 0, &data[..CHUNK_LEN]).unwrap();
        // The app died while writing chunk 1: half of it is on disk, the database says one chunk.
        let mut torn = OpenOptions::new()
            .append(true)
            .open(dir.path().join("files/5"))
            .unwrap();
        torn.write_all(&[9; 1000]).unwrap();
        store
            .write_chunk(5, CHUNK_LEN as u64, 1, &data[CHUNK_LEN..2 * CHUNK_LEN])
            .unwrap();
        assert_eq!(
            *store.read(5, 2 * CHUNK_LEN as u64, 0, 2 * CHUNK_LEN).unwrap(),
            data[..2 * CHUNK_LEN]
        );
    }

    #[test]
    fn chunks_must_come_in_order_and_fit() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir);
        assert!(store.write_chunk(1, 0, 1, &[1]).is_err(), "skipping ahead");
        assert!(store.write_chunk(1, 0, 0, &[]).is_err(), "empty");
        assert!(store.write_chunk(1, 0, 0, &sample(CHUNK_LEN + 1)).is_err(), "too long");
        store.write_chunk(1, 0, 0, &[1, 2, 3]).unwrap();
        assert!(store.write_chunk(1, 3, 1, &[4]).is_err(), "after a short (last) chunk");
        assert_eq!(chunk_count(0), 0);
        assert_eq!(chunk_count(CHUNK_LEN as u64), 1);
        assert_eq!(chunk_count(CHUNK_LEN as u64 + 1), 2);
        assert_eq!(chunk_len(CHUNK_LEN as u64 + 1, 1), 1);
    }
}
