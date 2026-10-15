//! Key hierarchy for data at rest (docs/architecture.md §4).
//!
//! A random master key protects everything the app stores. It never touches disk in plaintext:
//!
//! - A **PIN record** wraps it under a key derived from the PIN with Argon2id. The platform wraps
//!   this record once more with a hardware-backed key before storing it, so unlocking needs both
//!   the PIN and the device's secure hardware.
//! - An optional **secret record** wraps it under a random 32-byte unlock secret that the platform
//!   keeps behind biometric authentication.
//!
//! Changing the PIN re-wraps the master key; the stored data is never re-encrypted.

use crate::{
    crypto::{
        CryptoError, SecretBytes,
        aead::XChaCha20Poly1305,
        kdf,
        pin::{self, PinParams},
        random,
    },
    labels,
};

const FORMAT_VERSION: u8 = 1;
const KIND_PIN: u8 = 1;
const KIND_SECRET: u8 = 2;

const MASTER_KEY_LEN: usize = 32;
/// Nonce, encrypted master key, tag.
const SEALED_LEN: usize = 24 + MASTER_KEY_LEN + 16;
const PIN_HEADER_LEN: usize = 2 + 3 * 4 + pin::SALT_LEN;
const SECRET_HEADER_LEN: usize = 2;

/// Upper bounds on parameters read from a record, so a corrupted record cannot make unlocking
/// allocate gigabytes or spin for minutes.
const MAX_MEMORY_KIB: u32 = 1024 * 1024;
const MAX_ITERATIONS: u32 = 64;
const MAX_PARALLELISM: u32 = 16;

pub const UNLOCK_SECRET_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum VaultError {
    #[error("wrong PIN or unlock secret")]
    WrongCredential,
    #[error("the key record is corrupted")]
    CorruptRecord,
    #[error("the key record was written by a newer version of AirChat")]
    UnsupportedVersion,
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// The unlocked master key.
pub struct Vault {
    master_key: SecretBytes<MASTER_KEY_LEN>,
}

impl Vault {
    /// Creates a new master key and the PIN record that protects it.
    pub fn create(pin: &[u8], params: PinParams) -> Result<(Self, Vec<u8>), VaultError> {
        let vault = Self {
            master_key: SecretBytes::random()?,
        };
        let record = vault.pin_record(pin, params)?;
        Ok((vault, record))
    }

    pub fn unlock_with_pin(record: &[u8], pin: &[u8]) -> Result<Self, VaultError> {
        let (header, sealed) = split_record(record, KIND_PIN, PIN_HEADER_LEN)?;
        let params = PinParams {
            memory_kib: read_u32(header, 2),
            iterations: read_u32(header, 6),
            parallelism: read_u32(header, 10),
        };
        if params.memory_kib > MAX_MEMORY_KIB
            || params.iterations > MAX_ITERATIONS
            || params.parallelism > MAX_PARALLELISM
        {
            return Err(VaultError::CorruptRecord);
        }
        let salt: &[u8; pin::SALT_LEN] = header[14..].try_into().expect("header length checked");
        let kek = pin_kek(pin, salt, params)?;
        Self::unseal(&kek, header, sealed)
    }

    /// A new PIN record for the same master key, for setting or changing the PIN.
    pub fn pin_record(&self, pin: &[u8], params: PinParams) -> Result<Vec<u8>, VaultError> {
        let salt = random::array::<{ pin::SALT_LEN }>()?;
        let mut header = vec![FORMAT_VERSION, KIND_PIN];
        for value in [params.memory_kib, params.iterations, params.parallelism] {
            header.extend_from_slice(&value.to_be_bytes());
        }
        header.extend_from_slice(&salt);
        let kek = pin_kek(pin, &salt, params)?;
        self.seal(&kek, header)
    }

    pub fn unlock_with_secret(record: &[u8], secret: &SecretBytes<UNLOCK_SECRET_LEN>) -> Result<Self, VaultError> {
        let (header, sealed) = split_record(record, KIND_SECRET, SECRET_HEADER_LEN)?;
        Self::unseal(&secret_kek(secret)?, header, sealed)
    }

    /// A record that unlocks this vault with `secret` instead of the PIN (biometric unlock).
    pub fn secret_record(&self, secret: &SecretBytes<UNLOCK_SECRET_LEN>) -> Result<Vec<u8>, VaultError> {
        self.seal(&secret_kek(secret)?, vec![FORMAT_VERSION, KIND_SECRET])
    }

    /// Raw SQLCipher key for the database.
    pub(crate) fn database_key(&self) -> Result<SecretBytes<32>, CryptoError> {
        kdf::derive(&[], self.master_key.expose(), labels::STORAGE_DATABASE_KEY)
    }

    /// Key for attachment files at rest.
    pub(crate) fn file_key(&self) -> Result<SecretBytes<32>, CryptoError> {
        kdf::derive(&[], self.master_key.expose(), labels::STORAGE_FILE_KEY)
    }

    /// The header is authenticated, so parameters and salt cannot be swapped or downgraded.
    fn seal(&self, kek: &SecretBytes<32>, mut header: Vec<u8>) -> Result<Vec<u8>, VaultError> {
        let sealed = XChaCha20Poly1305::seal_with_random_nonce(kek, &header, self.master_key.expose())?;
        header.extend_from_slice(&sealed);
        Ok(header)
    }

    fn unseal(kek: &SecretBytes<32>, header: &[u8], sealed: &[u8]) -> Result<Self, VaultError> {
        let master_key = XChaCha20Poly1305::open_with_nonce_prefix(kek, header, sealed).map_err(|e| match e {
            CryptoError::Decrypt => VaultError::WrongCredential,
            _ => VaultError::CorruptRecord,
        })?;
        Ok(Self {
            master_key: SecretBytes::from_slice(&master_key)?,
        })
    }
}

fn split_record(record: &[u8], kind: u8, header_len: usize) -> Result<(&[u8], &[u8]), VaultError> {
    match record {
        [version, ..] if *version > FORMAT_VERSION => Err(VaultError::UnsupportedVersion),
        [FORMAT_VERSION, k, ..] if *k == kind && record.len() == header_len + SEALED_LEN => {
            Ok(record.split_at(header_len))
        }
        _ => Err(VaultError::CorruptRecord),
    }
}

fn read_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(bytes[at..at + 4].try_into().expect("header length checked"))
}

fn pin_kek(pin: &[u8], salt: &[u8; pin::SALT_LEN], params: PinParams) -> Result<SecretBytes<32>, CryptoError> {
    let stretched = pin::derive_key(pin, salt, params)?;
    kdf::derive(&[], stretched.expose(), labels::VAULT_PIN_KEK)
}

fn secret_kek(secret: &SecretBytes<UNLOCK_SECRET_LEN>) -> Result<SecretBytes<32>, CryptoError> {
    kdf::derive(&[], secret.expose(), labels::VAULT_SECRET_KEK)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Fast parameters for tests only.
    pub(crate) const TEST_PARAMS: PinParams = PinParams {
        memory_kib: 64,
        iterations: 1,
        parallelism: 1,
    };

    #[test]
    fn unlocks_with_the_right_pin_only() {
        let (vault, record) = Vault::create(b"123456", TEST_PARAMS).unwrap();
        let unlocked = Vault::unlock_with_pin(&record, b"123456").unwrap();
        assert_eq!(unlocked.master_key.expose(), vault.master_key.expose());
        assert_eq!(
            Vault::unlock_with_pin(&record, b"123457").err(),
            Some(VaultError::WrongCredential)
        );
    }

    #[test]
    fn changing_the_pin_keeps_the_master_key() {
        let (vault, old_record) = Vault::create(b"111111", TEST_PARAMS).unwrap();
        let new_record = vault.pin_record(b"222222", TEST_PARAMS).unwrap();
        let unlocked = Vault::unlock_with_pin(&new_record, b"222222").unwrap();
        assert_eq!(
            unlocked.database_key().unwrap().expose(),
            vault.database_key().unwrap().expose()
        );
        assert!(Vault::unlock_with_pin(&new_record, b"111111").is_err());
        assert!(Vault::unlock_with_pin(&old_record, b"111111").is_ok());
    }

    #[test]
    fn unlock_secret_works_independently_of_the_pin() {
        let (vault, _) = Vault::create(b"123456", TEST_PARAMS).unwrap();
        let secret = SecretBytes::random().unwrap();
        let record = vault.secret_record(&secret).unwrap();
        let unlocked = Vault::unlock_with_secret(&record, &secret).unwrap();
        assert_eq!(unlocked.master_key.expose(), vault.master_key.expose());

        let wrong = SecretBytes::random().unwrap();
        assert_eq!(
            Vault::unlock_with_secret(&record, &wrong).err(),
            Some(VaultError::WrongCredential)
        );
    }

    #[test]
    fn header_is_authenticated() {
        let (_, record) = Vault::create(b"123456", TEST_PARAMS).unwrap();
        // Lower the iteration count and change the salt: both must be detected.
        for position in [9, 20] {
            let mut tampered = record.clone();
            tampered[position] ^= 1;
            assert!(Vault::unlock_with_pin(&tampered, b"123456").is_err(), "byte {position}");
        }
    }

    #[test]
    fn rejects_malformed_records() {
        let (vault, pin_record) = Vault::create(b"123456", TEST_PARAMS).unwrap();
        let secret = SecretBytes::random().unwrap();
        let secret_record = vault.secret_record(&secret).unwrap();

        assert_eq!(Vault::unlock_with_pin(&[], b"1").err(), Some(VaultError::CorruptRecord));
        assert_eq!(
            Vault::unlock_with_pin(&pin_record[..pin_record.len() - 1], b"123456").err(),
            Some(VaultError::CorruptRecord)
        );
        // A secret record is not a PIN record and vice versa.
        assert_eq!(
            Vault::unlock_with_pin(&secret_record, b"123456").err(),
            Some(VaultError::CorruptRecord)
        );
        assert_eq!(
            Vault::unlock_with_secret(&pin_record, &secret).err(),
            Some(VaultError::CorruptRecord)
        );

        let mut future = pin_record.clone();
        future[0] = FORMAT_VERSION + 1;
        assert_eq!(
            Vault::unlock_with_pin(&future, b"123456").err(),
            Some(VaultError::UnsupportedVersion)
        );
    }

    #[test]
    fn rejects_absurd_cost_parameters() {
        let (_, mut record) = Vault::create(b"123456", TEST_PARAMS).unwrap();
        record[2..6].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(
            Vault::unlock_with_pin(&record, b"123456").err(),
            Some(VaultError::CorruptRecord)
        );
    }
}
