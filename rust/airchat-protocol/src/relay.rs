//! Relays (docs/protocol.md §15): invitations to a room, sent in mail, and the frames a device and
//! a server's relay exchange to join one. After *ready*, the relay passes every frame on unchanged;
//! what runs over it (a contact link, §6) is protected end to end.
//!
//! ```text
//! invite (in a 0x62 record) = room (16) || token (32) || size (u8) || purpose (u8) || reference (16)
//! 0xa0 join:  room (16) || token (32) || size (u8) || wait (u16, minutes)
//! 0xa1 ready: (empty)
//! ```

use zeroize::Zeroizing;

use crate::{
    account::{Answer, Failure},
    crypto::{CryptoError, hash::equal_in_constant_time, random},
};

pub const ROOM_LEN: usize = 16;
pub const TOKEN_LEN: usize = 32;
/// Rooms hold 2 to 33: two contacts, or a group of 32 and one more.
pub const MIN_SIZE: u8 = 2;
pub const MAX_SIZE: u8 = 33;
/// How long a room waits for its members at most: 3 hours, for a file (§15.3).
pub const MAX_WAIT_MINUTES: u16 = 180;

const VERSION: u8 = 0x00;
const JOIN: u8 = 0xa0;
const READY: u8 = 0xa1;
const INVITE_LEN: usize = ROOM_LEN + TOKEN_LEN + 1 + 1 + 16;

pub type RoomId = [u8; ROOM_LEN];

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RelayError {
    #[error("malformed relay frame")]
    Malformed,
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// What a room is for (§15.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// A file's content; the reference is the offer's message id.
    File = 1,
    /// A call; the reference is its stream id.
    Call = 2,
    /// Push-to-talk; the reference is the talk's stream id.
    Talk = 3,
}

/// An invitation to a room, sent in mail (§15.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    pub room: RoomId,
    pub token: Zeroizing<[u8; TOKEN_LEN]>,
    pub size: u8,
    pub purpose: Purpose,
    pub reference: [u8; 16],
}

impl Invite {
    /// A new room for `size` members.
    pub fn new(size: u8, purpose: Purpose, reference: [u8; 16]) -> Result<Self, RelayError> {
        if !(MIN_SIZE..=MAX_SIZE).contains(&size) {
            return Err(RelayError::Malformed);
        }
        Ok(Self {
            room: random::array()?,
            token: Zeroizing::new(random::array()?),
            size,
            purpose,
            reference,
        })
    }

    /// The join for this room, waiting `wait_minutes` (1 to 180) if it opens it.
    pub fn join(&self, wait_minutes: u16) -> Result<Join, RelayError> {
        Join::new(self.room, self.token.clone(), self.size, wait_minutes)
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        [
            &self.room[..],
            &self.token[..],
            &[self.size, self.purpose as u8],
            &self.reference,
        ]
        .concat()
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, RelayError> {
        if bytes.len() != INVITE_LEN {
            return Err(RelayError::Malformed);
        }
        let (room, rest) = bytes.split_at(ROOM_LEN);
        let (token, rest) = rest.split_at(TOKEN_LEN);
        let size = rest[0];
        let purpose = match rest[1] {
            1 => Purpose::File,
            2 => Purpose::Call,
            3 => Purpose::Talk,
            _ => return Err(RelayError::Malformed),
        };
        if !(MIN_SIZE..=MAX_SIZE).contains(&size) {
            return Err(RelayError::Malformed);
        }
        Ok(Self {
            room: room.try_into().expect("length checked"),
            token: Zeroizing::new(token.try_into().expect("length checked")),
            size,
            purpose,
            reference: rest[2..].try_into().expect("length checked"),
        })
    }
}

/// A device's first and only frame of its own to a relay (§15.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Join {
    pub room: RoomId,
    pub token: Zeroizing<[u8; TOKEN_LEN]>,
    pub size: u8,
    pub wait_minutes: u16,
}

impl Join {
    pub fn new(
        room: RoomId,
        token: Zeroizing<[u8; TOKEN_LEN]>,
        size: u8,
        wait_minutes: u16,
    ) -> Result<Self, RelayError> {
        if !(MIN_SIZE..=MAX_SIZE).contains(&size) || !(1..=MAX_WAIT_MINUTES).contains(&wait_minutes) {
            return Err(RelayError::Malformed);
        }
        Ok(Self {
            room,
            token,
            size,
            wait_minutes,
        })
    }

    /// Whether `other` is a join for the same room with the same token and size, in constant time
    /// for the token.
    pub fn matches(&self, other: &Join) -> bool {
        self.room == other.room && self.size == other.size && equal_in_constant_time(&self.token[..], &other.token[..])
    }

    pub fn encode(&self) -> Vec<u8> {
        [
            &[VERSION, JOIN][..],
            &self.room,
            &self.token[..],
            &[self.size],
            &self.wait_minutes.to_be_bytes(),
        ]
        .concat()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RelayError> {
        let [VERSION, JOIN, rest @ ..] = bytes else {
            return Err(RelayError::Malformed);
        };
        if rest.len() != ROOM_LEN + TOKEN_LEN + 1 + 2 {
            return Err(RelayError::Malformed);
        }
        let (room, rest) = rest.split_at(ROOM_LEN);
        let (token, rest) = rest.split_at(TOKEN_LEN);
        Self::new(
            room.try_into().expect("length checked"),
            Zeroizing::new(token.try_into().expect("length checked")),
            rest[0],
            u16::from_be_bytes([rest[1], rest[2]]),
        )
    }
}

/// What a relay answers a join (§15.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinAnswer {
    Ready,
    Refused,
}

impl JoinAnswer {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Ready => vec![VERSION, READY],
            Self::Refused => Answer::Failure {
                failure: Failure::Refused,
                retry_after: 0,
            }
            .encode(),
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RelayError> {
        match bytes {
            [VERSION, READY] => Ok(Self::Ready),
            _ => match Answer::decode(bytes) {
                Ok(Answer::Failure { .. }) => Ok(Self::Refused),
                _ => Err(RelayError::Malformed),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat::ChatMessage;

    #[test]
    fn invites_and_joins_round_trip() {
        let invite = Invite::new(2, Purpose::File, [7; 16]).unwrap();
        let record = ChatMessage::RelayInvite(invite.clone()).encode().unwrap();
        assert_eq!(record[0], 0x62);
        assert_eq!(
            ChatMessage::decode(&record).unwrap(),
            Some(ChatMessage::RelayInvite(invite.clone()))
        );
        let join = invite.join(180).unwrap();
        assert_eq!(Join::decode(&join.encode()).unwrap(), join);
        assert!(join.matches(&invite.join(1).unwrap()), "the wait is the opener's alone");
        let other = Invite::new(2, Purpose::File, [7; 16]).unwrap();
        assert!(!join.matches(&other.join(1).unwrap()));
        for answer in [JoinAnswer::Ready, JoinAnswer::Refused] {
            assert_eq!(JoinAnswer::decode(&answer.encode()).unwrap(), answer);
        }
        for purpose in [Purpose::Call, Purpose::Talk] {
            let invite = Invite::new(2, purpose, [8; 16]).unwrap();
            assert_eq!(Invite::decode(&invite.encode()).unwrap(), invite);
        }
    }

    #[test]
    fn published_relay_vector() {
        use crate::crypto::test_util::{check_vector, to_hex};
        let invite = Invite {
            room: [0x0a; ROOM_LEN],
            token: Zeroizing::new([0x7b; TOKEN_LEN]),
            size: 2,
            purpose: Purpose::File,
            reference: [0x0f; 16],
        };
        let record = ChatMessage::RelayInvite(invite.clone()).encode().unwrap();
        check_vector(
            "relay",
            &[
                ("room", to_hex(&invite.room)),
                ("token", to_hex(&invite.token[..])),
                ("reference", to_hex(&invite.reference)),
                ("invite_record", to_hex(&record)),
                ("join", to_hex(&invite.join(180).unwrap().encode())),
                ("ready", to_hex(&JoinAnswer::Ready.encode())),
                ("refused", to_hex(&JoinAnswer::Refused.encode())),
            ],
        );
    }

    #[test]
    fn out_of_range_is_refused() {
        assert!(Invite::new(1, Purpose::Call, [0; 16]).is_err());
        assert!(Invite::new(34, Purpose::Call, [0; 16]).is_err());
        let invite = Invite::new(2, Purpose::Call, [0; 16]).unwrap();
        assert!(invite.join(0).is_err() && invite.join(181).is_err());
        let mut bytes = invite.encode();
        bytes[ROOM_LEN + TOKEN_LEN + 1] = 4;
        assert!(Invite::decode(&bytes).is_err(), "no such purpose");
        let mut join = invite.join(1).unwrap().encode();
        join.push(0);
        assert!(Join::decode(&join).is_err(), "trailing byte");
    }
}
