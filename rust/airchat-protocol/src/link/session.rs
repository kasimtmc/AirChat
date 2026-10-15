//! Encrypted records of an established link session (docs/protocol.md §6.4).
//!
//! The transport delivers records reliably and in order; any failure to decrypt ends the session.

use zeroize::Zeroizing;

use super::{
    LinkError, WIRE_VERSION,
    symmetric::{KEY_LEN, nonce},
};
use crate::{
    crypto::{SecretBytes, aead::ChaCha20Poly1305, kdf},
    labels,
};

/// Largest payload one record carries.
pub const MAX_RECORD_PAYLOAD: usize = 16 * 1024;
/// Records per key before both sides switch to the next key.
pub const REKEY_INTERVAL: u64 = 1 << 16;
/// Plaintexts are padded to a multiple of this, so record sizes reveal little about content.
pub(super) const PAD_BLOCK: usize = 64;

const TYPE_DATA: u8 = 1;
const TYPE_CLOSE: u8 = 2;

#[derive(Debug, PartialEq, Eq)]
pub enum Record {
    Data(Zeroizing<Vec<u8>>),
    /// The peer ended the session; nothing more will arrive.
    Close,
}

pub struct Session {
    send: Direction,
    receive: Direction,
    handshake_hash: [u8; 32],
    closed: bool,
}

struct Direction {
    key: SecretBytes<KEY_LEN>,
    counter: u64,
}

impl Direction {
    fn new(key: SecretBytes<KEY_LEN>) -> Self {
        Self { key, counter: 0 }
    }

    /// The key and nonce for the next record, switching keys every [`REKEY_INTERVAL`] records.
    fn advance(&mut self) -> Result<[u8; 12], LinkError> {
        if self.counter > 0 && self.counter.is_multiple_of(REKEY_INTERVAL) {
            self.key = kdf::derive(&[], self.key.expose(), labels::LINK_REKEY)?;
        }
        let nonce = nonce(self.counter);
        self.counter = self.counter.checked_add(1).ok_or(LinkError::Closed)?;
        Ok(nonce)
    }
}

impl Session {
    pub(crate) fn new(send: SecretBytes<KEY_LEN>, receive: SecretBytes<KEY_LEN>, handshake_hash: [u8; 32]) -> Self {
        Self {
            send: Direction::new(send),
            receive: Direction::new(receive),
            handshake_hash,
            closed: false,
        }
    }

    /// Commits to the whole handshake; identical on both sides. Usable for channel binding.
    pub fn handshake_hash(&self) -> &[u8; 32] {
        &self.handshake_hash
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    pub fn seal(&mut self, payload: &[u8]) -> Result<Vec<u8>, LinkError> {
        if payload.len() > MAX_RECORD_PAYLOAD {
            return Err(LinkError::PayloadTooLarge);
        }
        self.seal_record(TYPE_DATA, payload)
    }

    /// Tells the peer the session is over. Nothing can be sent afterwards.
    pub fn seal_close(&mut self) -> Result<Vec<u8>, LinkError> {
        let record = self.seal_record(TYPE_CLOSE, &[])?;
        self.closed = true;
        Ok(record)
    }

    pub fn open(&mut self, record: &[u8]) -> Result<Record, LinkError> {
        if self.closed {
            return Err(LinkError::Closed);
        }
        let nonce = self.receive.advance()?;
        let plaintext = match ChaCha20Poly1305::open(&self.receive.key, &nonce, &[WIRE_VERSION], record) {
            Ok(plaintext) => plaintext,
            Err(_) => {
                self.closed = true;
                return Err(LinkError::AuthenticationFailed);
            }
        };
        let (record_type, payload) = unpad(&plaintext).inspect_err(|_| self.closed = true)?;
        match record_type {
            TYPE_DATA => Ok(Record::Data(Zeroizing::new(payload.to_vec()))),
            TYPE_CLOSE if payload.is_empty() => {
                self.closed = true;
                Ok(Record::Close)
            }
            _ => {
                self.closed = true;
                Err(LinkError::Malformed)
            }
        }
    }

    fn seal_record(&mut self, record_type: u8, payload: &[u8]) -> Result<Vec<u8>, LinkError> {
        if self.closed {
            return Err(LinkError::Closed);
        }
        let plaintext = pad(record_type, payload)?;
        let nonce = self.send.advance()?;
        Ok(ChaCha20Poly1305::seal(
            &self.send.key,
            &nonce,
            &[WIRE_VERSION],
            &plaintext,
        )?)
    }
}

/// `type || length (u16) || payload || zeros`, padded to a multiple of [`PAD_BLOCK`].
pub(super) fn pad(record_type: u8, payload: &[u8]) -> Result<Zeroizing<Vec<u8>>, LinkError> {
    let length = u16::try_from(payload.len()).map_err(|_| LinkError::PayloadTooLarge)?;
    let unpadded = 3 + payload.len();
    let mut plaintext = Zeroizing::new(Vec::with_capacity(unpadded.next_multiple_of(PAD_BLOCK)));
    plaintext.push(record_type);
    plaintext.extend_from_slice(&length.to_be_bytes());
    plaintext.extend_from_slice(payload);
    plaintext.resize(unpadded.next_multiple_of(PAD_BLOCK), 0);
    Ok(plaintext)
}

/// Inverse of [`pad`]. Rejects anything but a well-formed, zero-padded plaintext.
pub(crate) fn unpad(plaintext: &[u8]) -> Result<(u8, &[u8]), LinkError> {
    let [record_type, high, low, rest @ ..] = plaintext else {
        return Err(LinkError::Malformed);
    };
    let length = usize::from(u16::from_be_bytes([*high, *low]));
    if !plaintext.len().is_multiple_of(PAD_BLOCK) || length > rest.len() {
        return Err(LinkError::Malformed);
    }
    let (payload, padding) = rest.split_at(length);
    if padding.iter().any(|&b| b != 0) {
        return Err(LinkError::Malformed);
    }
    Ok((*record_type, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (Session, Session) {
        let a = || SecretBytes::from_slice(&[1; 32]).unwrap();
        let b = || SecretBytes::from_slice(&[2; 32]).unwrap();
        (Session::new(a(), b(), [9; 32]), Session::new(b(), a(), [9; 32]))
    }

    #[test]
    fn records_flow_both_ways_in_order() {
        let (mut alice, mut bob) = pair();
        for i in 0..5u8 {
            let record = alice.seal(&[i; 10]).unwrap();
            assert_eq!(bob.open(&record).unwrap(), Record::Data(Zeroizing::new(vec![i; 10])));
            let reply = bob.seal(b"ok").unwrap();
            assert_eq!(
                alice.open(&reply).unwrap(),
                Record::Data(Zeroizing::new(b"ok".to_vec()))
            );
        }
    }

    #[test]
    fn sizes_are_padded() {
        let (mut alice, _) = pair();
        assert_eq!(alice.seal(b"").unwrap().len(), PAD_BLOCK + 16);
        assert_eq!(alice.seal(&[0; 61]).unwrap().len(), PAD_BLOCK + 16);
        assert_eq!(alice.seal(&[0; 62]).unwrap().len(), 2 * PAD_BLOCK + 16);
    }

    #[test]
    fn replayed_reordered_or_tampered_records_end_the_session() {
        let (mut alice, mut bob) = pair();
        let first = alice.seal(b"first").unwrap();
        let second = alice.seal(b"second").unwrap();
        assert!(
            matches!(bob.open(&second), Err(LinkError::AuthenticationFailed)),
            "reordered"
        );
        assert!(bob.is_closed());
        assert!(matches!(bob.open(&first), Err(LinkError::Closed)));

        let (mut alice, mut bob) = pair();
        let mut record = alice.seal(b"hello").unwrap();
        record[3] ^= 1;
        assert!(matches!(bob.open(&record), Err(LinkError::AuthenticationFailed)));
    }

    #[test]
    fn close_is_final() {
        let (mut alice, mut bob) = pair();
        let close = alice.seal_close().unwrap();
        assert!(matches!(alice.seal(b"late"), Err(LinkError::Closed)));
        assert_eq!(bob.open(&close).unwrap(), Record::Close);
        assert!(bob.is_closed());
    }

    #[test]
    fn rekeying_stays_in_step() {
        let (mut alice, mut bob) = pair();
        let first_key = *alice.send.key.expose();
        for _ in 0..REKEY_INTERVAL + 2 {
            let record = alice.seal(b"x").unwrap();
            bob.open(&record).unwrap();
        }
        assert_ne!(*alice.send.key.expose(), first_key);
    }

    #[test]
    fn rejects_oversized_payloads_and_bad_padding() {
        let (mut alice, _) = pair();
        assert!(matches!(
            alice.seal(&vec![0; MAX_RECORD_PAYLOAD + 1]),
            Err(LinkError::PayloadTooLarge)
        ));

        let mut padded = pad(TYPE_DATA, b"abc").unwrap();
        assert_eq!(unpad(&padded).unwrap(), (TYPE_DATA, b"abc".as_slice()));
        padded[10] = 1;
        assert!(unpad(&padded).is_err(), "non-zero padding");
        let mut padded = pad(TYPE_DATA, b"abc").unwrap();
        padded[1] = 0xff;
        assert!(unpad(&padded).is_err(), "length beyond plaintext");
        assert!(unpad(&padded[..63]).is_err(), "not a whole number of blocks");
    }
}
