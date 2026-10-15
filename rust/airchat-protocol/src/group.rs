//! Groups (docs/protocol.md §9): rosters, the updates that hand each member an epoch's key, group
//! messages, and the keys of group links. Formats and cryptography only; storage and delivery live
//! elsewhere.

use zeroize::Zeroizing;

use crate::{
    chat::{self, FileMeta},
    crypto::{
        CryptoError, SecretBytes,
        aead::{ChaCha20Poly1305, XChaCha20Poly1305},
        hash::sha256,
        kdf,
        kem::{CIPHERTEXT_LEN, Ciphertext, DecapsulationKey, ENCAPSULATION_KEY_LEN, EncapsulationKey},
        random::{OsRng, Rng},
        sign::{SIGNATURE_LEN, Signature},
    },
    identity::{Identity, PublicIdentity},
    labels,
};

pub const GROUP_ID_LEN: usize = 16;
pub type GroupId = [u8; GROUP_ID_LEN];
pub const MIN_MEMBERS: usize = 2;
pub const MAX_MEMBERS: usize = 32;
pub const MAX_NAME_CHARS: usize = 64;
/// A name's length is one byte; a display name may be one byte longer (§4.6, §9.1).
pub const MAX_NAME_BYTES: usize = 255;
pub const MAX_TEXT_BYTES: usize = 8192;

const IDENTITY_LEN: usize = 32;
const PRESENCE_KEY_LEN: usize = 32;
const SEALED_KEY_LEN: usize = 32 + 16;
const ENVELOPE_LEN: usize = IDENTITY_LEN + CIPHERTEXT_LEN + SEALED_KEY_LEN;
const NONCE_LEN: usize = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GroupError {
    #[error("malformed group record")]
    Malformed,
    #[error("a group or member name needs 1 to {MAX_NAME_CHARS} characters and at most {MAX_NAME_BYTES} bytes")]
    InvalidName,
    #[error("a group has {MIN_MEMBERS} to {MAX_MEMBERS} members, each once, and at least one admin")]
    InvalidMembers,
    #[error("the signature or encryption does not check out")]
    NotAuthentic,
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Member = 0,
    Admin = 1,
}

#[derive(Clone)]
pub struct Member {
    pub identity: PublicIdentity,
    pub static_kem: EncapsulationKey,
    /// Which of the member's static keys `static_kem` is (§6.9).
    pub key_version: u32,
    pub presence_key: SecretBytes<PRESENCE_KEY_LEN>,
    pub role: Role,
    /// Unix seconds when a temporary membership ends; 0 for a permanent one.
    pub expires: u64,
    pub name: String,
}

/// The members of one epoch of a group, sorted by identity key.
#[derive(Clone)]
pub struct Roster {
    pub group_id: GroupId,
    pub epoch: u64,
    pub name: String,
    members: Vec<Member>,
}

impl Roster {
    pub fn new(group_id: GroupId, epoch: u64, name: &str, mut members: Vec<Member>) -> Result<Self, GroupError> {
        check_name(name)?;
        members.sort_by(|a, b| a.identity.as_bytes().cmp(b.identity.as_bytes()));
        let roster = Self {
            group_id,
            epoch,
            name: name.to_owned(),
            members,
        };
        roster.check()?;
        Ok(roster)
    }

    pub fn members(&self) -> &[Member] {
        &self.members
    }

    pub fn member(&self, identity: &PublicIdentity) -> Option<&Member> {
        self.members.iter().find(|m| &m.identity == identity)
    }

    pub fn is_admin(&self, identity: &PublicIdentity) -> bool {
        self.member(identity).is_some_and(|m| m.role == Role::Admin)
    }

    fn check(&self) -> Result<(), GroupError> {
        let sorted = self
            .members
            .windows(2)
            .all(|pair| pair[0].identity.as_bytes() < pair[1].identity.as_bytes());
        let admin = self.members.iter().any(|m| m.role == Role::Admin);
        if !(MIN_MEMBERS..=MAX_MEMBERS).contains(&self.members.len()) || !sorted || !admin {
            return Err(GroupError::InvalidMembers);
        }
        self.members.iter().try_for_each(|m| check_name(&m.name))
    }

    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::new());
        out.extend_from_slice(&self.group_id);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        push_name(&mut out, &self.name);
        out.push(self.members.len() as u8);
        for member in &self.members {
            out.extend_from_slice(member.identity.as_bytes());
            out.extend_from_slice(member.static_kem.as_bytes());
            out.extend_from_slice(&member.key_version.to_be_bytes());
            out.extend_from_slice(member.presence_key.expose());
            out.push(member.role as u8);
            out.extend_from_slice(&member.expires.to_be_bytes());
            push_name(&mut out, &member.name);
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, GroupError> {
        Self::decode_with(bytes, true)
    }

    /// A roster stored before members' static keys had versions: each gets version 0.
    pub fn decode_unversioned(bytes: &[u8]) -> Result<Self, GroupError> {
        Self::decode_with(bytes, false)
    }

    fn decode_with(bytes: &[u8], versions: bool) -> Result<Self, GroupError> {
        let mut reader = Reader(bytes);
        let group_id = reader.array::<GROUP_ID_LEN>()?;
        let epoch = u64::from_be_bytes(reader.array()?);
        let name = reader.name()?;
        let count = reader.byte()?;
        let mut members = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            let identity = PublicIdentity::from_bytes(reader.array()?);
            let static_kem = EncapsulationKey::from_bytes(reader.take(ENCAPSULATION_KEY_LEN)?)?;
            let key_version = if versions {
                u32::from_be_bytes(reader.array()?)
            } else {
                0
            };
            let presence_key = SecretBytes::from_slice(reader.take(PRESENCE_KEY_LEN)?)?;
            let role = match reader.byte()? {
                0 => Role::Member,
                1 => Role::Admin,
                _ => return Err(GroupError::Malformed),
            };
            let expires = u64::from_be_bytes(reader.array()?);
            let name = reader.name()?;
            members.push(Member {
                identity,
                static_kem,
                key_version,
                presence_key,
                role,
                expires,
                name,
            });
        }
        reader.end()?;
        let roster = Self {
            group_id,
            epoch,
            name,
            members,
        };
        roster.check()?;
        Ok(roster)
    }
}

/// An update read and its signature verified; who signed it still has to be checked against the
/// roster the device holds (§9.2).
pub struct Update {
    pub group_id: GroupId,
    pub epoch: u64,
    pub signer: PublicIdentity,
    envelopes: Vec<(PublicIdentity, Ciphertext, [u8; SEALED_KEY_LEN])>,
    roster_nonce: [u8; NONCE_LEN],
    sealed_roster: Vec<u8>,
}

/// What a member gets out of an update meant for it.
pub struct Opened {
    pub epoch_key: SecretBytes<32>,
    pub roster: Roster,
}

/// Starts an epoch: hands `epoch_key` to every member of `roster`, signed by `signer`.
pub fn seal_update(roster: &Roster, epoch_key: &SecretBytes<32>, signer: &Identity) -> Result<Vec<u8>, GroupError> {
    seal_update_from(roster, epoch_key, signer, &mut OsRng)
}

pub(crate) fn seal_update_from(
    roster: &Roster,
    epoch_key: &SecretBytes<32>,
    signer: &Identity,
    rng: &mut dyn Rng,
) -> Result<Vec<u8>, GroupError> {
    let (group_id, epoch) = (roster.group_id, roster.epoch);
    let aad = [&group_id[..], &epoch.to_be_bytes()].concat();
    let mut out = Vec::new();
    out.extend_from_slice(&group_id);
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(signer.public().as_bytes());
    out.push(roster.members.len() as u8);
    for member in &roster.members {
        let (shared, ciphertext) = member.static_kem.encapsulate_from(rng)?;
        let key = envelope_key(&shared, &group_id, epoch, &member.identity)?;
        let sealed = ChaCha20Poly1305::seal(&key, &[0; 12], &aad, epoch_key.expose())?;
        out.extend_from_slice(member.identity.as_bytes());
        out.extend_from_slice(ciphertext.as_bytes());
        out.extend_from_slice(&sealed);
    }
    let mut nonce = [0; NONCE_LEN];
    rng.fill(&mut nonce)?;
    let sealed_roster = XChaCha20Poly1305::seal(
        &roster_key(epoch_key, &group_id, epoch)?,
        &nonce,
        &aad,
        &roster.encode(),
    )?;
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&(sealed_roster.len() as u32).to_be_bytes());
    out.extend_from_slice(&sealed_roster);
    let signature = signer.sign(labels::GROUP_UPDATE, &[&out]);
    out.extend_from_slice(signature.as_bytes());
    Ok(out)
}

impl Update {
    /// Parses an update and verifies its signature.
    pub fn read(bytes: &[u8]) -> Result<Self, GroupError> {
        let (signed, signature) = bytes.split_last_chunk::<SIGNATURE_LEN>().ok_or(GroupError::Malformed)?;
        let mut reader = Reader(signed);
        let group_id = reader.array::<GROUP_ID_LEN>()?;
        let epoch = u64::from_be_bytes(reader.array()?);
        let signer = PublicIdentity::from_bytes(reader.array()?);
        let count = usize::from(reader.byte()?);
        if !(MIN_MEMBERS..=MAX_MEMBERS).contains(&count) {
            return Err(GroupError::InvalidMembers);
        }
        let mut envelopes = Vec::with_capacity(count);
        for _ in 0..count {
            let envelope = reader.take(ENVELOPE_LEN)?;
            let (identity, rest) = envelope.split_at(IDENTITY_LEN);
            let (ciphertext, sealed) = rest.split_at(CIPHERTEXT_LEN);
            envelopes.push((
                PublicIdentity::from_bytes(identity.try_into().expect("split")),
                Ciphertext::from_bytes(ciphertext)?,
                sealed.try_into().expect("split"),
            ));
        }
        let roster_nonce = reader.array()?;
        let length = u32::from_be_bytes(reader.array()?) as usize;
        let sealed_roster = reader.take(length)?.to_vec();
        reader.end()?;
        signer
            .verify(labels::GROUP_UPDATE, &[signed], &Signature::from_bytes(*signature))
            .map_err(|_| GroupError::NotAuthentic)?;
        Ok(Self {
            group_id,
            epoch,
            signer,
            envelopes,
            roster_nonce,
            sealed_roster,
        })
    }

    /// Whether the update holds a key for `identity`; one that does not, from an admin, means the
    /// member was removed.
    pub fn addresses(&self, identity: &PublicIdentity) -> bool {
        self.envelopes.iter().any(|(member, ..)| member == identity)
    }

    /// The epoch key and roster, for the member with `identity` and its static KEM key.
    pub fn open(&self, identity: &PublicIdentity, static_kem: &DecapsulationKey) -> Result<Opened, GroupError> {
        let (_, ciphertext, sealed) = self
            .envelopes
            .iter()
            .find(|(member, ..)| member == identity)
            .ok_or(GroupError::NotAuthentic)?;
        let aad = [&self.group_id[..], &self.epoch.to_be_bytes()].concat();
        let shared = static_kem.decapsulate(ciphertext)?;
        let key = envelope_key(&shared, &self.group_id, self.epoch, identity)?;
        let epoch_key = ChaCha20Poly1305::open(&key, &[0; 12], &aad, sealed).map_err(|_| GroupError::NotAuthentic)?;
        let epoch_key = SecretBytes::from_slice(&epoch_key)?;
        let roster = XChaCha20Poly1305::open(
            &roster_key(&epoch_key, &self.group_id, self.epoch)?,
            &self.roster_nonce,
            &aad,
            &self.sealed_roster,
        )
        .map_err(|_| GroupError::NotAuthentic)?;
        let roster = Roster::decode(&roster)?;
        // The envelopes must be exactly the roster's members, so nobody else got the key.
        let addressed: Vec<&PublicIdentity> = self.envelopes.iter().map(|(member, ..)| member).collect();
        let members: Vec<&PublicIdentity> = roster.members.iter().map(|m| &m.identity).collect();
        if roster.group_id != self.group_id || roster.epoch != self.epoch || addressed != members {
            return Err(GroupError::NotAuthentic);
        }
        Ok(Opened { epoch_key, roster })
    }
}

/// Names an update in transit: the first 16 bytes of its SHA-256.
pub fn update_id(update: &[u8]) -> [u8; 16] {
    sha256(&[update])[..16].try_into().expect("16 of 32")
}

/// What a group message carries (§9.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Content {
    Text(Zeroizing<String>),
    /// A file's description; members fetch its content from each other (§9.7).
    File(FileMeta),
    /// An admin deleted the group, for every member (§9.2).
    Deleted,
}

const CONTENT_TEXT: u8 = 0x01;
const CONTENT_FILE: u8 = 0x02;
const CONTENT_DELETED: u8 = 0x03;

impl Content {
    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>, GroupError> {
        Ok(Zeroizing::new(match self {
            Self::Text(text) => {
                if text.is_empty() || text.len() > MAX_TEXT_BYTES {
                    return Err(GroupError::Malformed);
                }
                [&[CONTENT_TEXT][..], text.as_bytes()].concat()
            }
            Self::File(meta) => [
                &[CONTENT_FILE][..],
                &chat::encode_file(meta).map_err(|_| GroupError::Malformed)?,
            ]
            .concat(),
            Self::Deleted => vec![CONTENT_DELETED],
        }))
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, GroupError> {
        match bytes.split_first() {
            Some((&CONTENT_TEXT, text)) => {
                let text = std::str::from_utf8(text).map_err(|_| GroupError::Malformed)?;
                if text.is_empty() || text.len() > MAX_TEXT_BYTES {
                    return Err(GroupError::Malformed);
                }
                Ok(Self::Text(Zeroizing::new(text.to_owned())))
            }
            Some((&CONTENT_FILE, file)) => Ok(Self::File(chat::decode_file(file).map_err(|_| GroupError::Malformed)?)),
            Some((&CONTENT_DELETED, [])) => Ok(Self::Deleted),
            _ => Err(GroupError::Malformed),
        }
    }
}

/// A group message, read but not yet authenticated (that needs the epoch's key and roster).
pub struct Message {
    pub group_id: GroupId,
    pub epoch: u64,
    pub message_id: [u8; 16],
    pub sender: PublicIdentity,
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
    signature: [u8; SIGNATURE_LEN],
    signed_len: usize,
    bytes: Vec<u8>,
}

pub fn seal_message(
    group_id: &GroupId,
    epoch: u64,
    epoch_key: &SecretBytes<32>,
    message_id: &[u8; 16],
    sender: &Identity,
    sent_at_ms: u64,
    content: &Content,
) -> Result<Vec<u8>, GroupError> {
    seal_message_from(
        group_id, epoch, epoch_key, message_id, sender, sent_at_ms, content, &mut OsRng,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn seal_message_from(
    group_id: &GroupId,
    epoch: u64,
    epoch_key: &SecretBytes<32>,
    message_id: &[u8; 16],
    sender: &Identity,
    sent_at_ms: u64,
    content: &Content,
    rng: &mut dyn Rng,
) -> Result<Vec<u8>, GroupError> {
    let body = content.encode()?;
    let sender_id = sender.public();
    let aad = [&group_id[..], &epoch.to_be_bytes(), message_id, sender_id.as_bytes()].concat();
    let plaintext = Zeroizing::new([&sent_at_ms.to_be_bytes()[..], &body].concat());
    let mut nonce = [0; NONCE_LEN];
    rng.fill(&mut nonce)?;
    let ciphertext = XChaCha20Poly1305::seal(&message_key(epoch_key, group_id, epoch)?, &nonce, &aad, &plaintext)?;
    let mut out = aad;
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    let signature = sender.sign(labels::GROUP_MESSAGE, &[&out]);
    out.extend_from_slice(signature.as_bytes());
    Ok(out)
}

impl Message {
    pub fn read(bytes: &[u8]) -> Result<Self, GroupError> {
        let (signed, signature) = bytes.split_last_chunk::<SIGNATURE_LEN>().ok_or(GroupError::Malformed)?;
        let mut reader = Reader(signed);
        let group_id = reader.array()?;
        let epoch = u64::from_be_bytes(reader.array()?);
        let message_id = reader.array()?;
        let sender = PublicIdentity::from_bytes(reader.array()?);
        let nonce = reader.array()?;
        let ciphertext = reader.0.to_vec();
        if ciphertext.len() < 16 + 8 + 1 {
            return Err(GroupError::Malformed);
        }
        Ok(Self {
            group_id,
            epoch,
            message_id,
            sender,
            nonce,
            ciphertext,
            signature: *signature,
            signed_len: signed.len(),
            bytes: bytes.to_vec(),
        })
    }

    /// Checks the sender's signature and decrypts: the time it was sent (Unix ms) and the content.
    pub fn open(&self, epoch_key: &SecretBytes<32>) -> Result<(u64, Content), GroupError> {
        self.sender
            .verify(
                labels::GROUP_MESSAGE,
                &[&self.bytes[..self.signed_len]],
                &Signature::from_bytes(self.signature),
            )
            .map_err(|_| GroupError::NotAuthentic)?;
        let aad = [
            &self.group_id[..],
            &self.epoch.to_be_bytes(),
            &self.message_id,
            self.sender.as_bytes(),
        ]
        .concat();
        let plaintext = XChaCha20Poly1305::open(
            &message_key(epoch_key, &self.group_id, self.epoch)?,
            &self.nonce,
            &aad,
            &self.ciphertext,
        )
        .map_err(|_| GroupError::NotAuthentic)?;
        let (sent_at, body) = plaintext.split_first_chunk::<8>().ok_or(GroupError::Malformed)?;
        Ok((u64::from_be_bytes(*sent_at), Content::decode(body)?))
    }

    /// The message as received, to pass on unchanged.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// The link key of two members who are not contacts (§9.4).
pub fn link_psk(
    epoch_key: &SecretBytes<32>,
    group_id: &GroupId,
    epoch: u64,
    a: &PublicIdentity,
    b: &PublicIdentity,
) -> Result<SecretBytes<32>, GroupError> {
    let (low, high) = if a.as_bytes() <= b.as_bytes() { (a, b) } else { (b, a) };
    let info = [
        labels::GROUP_LINK,
        group_id,
        &epoch.to_be_bytes(),
        low.as_bytes(),
        high.as_bytes(),
    ]
    .concat();
    Ok(kdf::derive(&[], epoch_key.expose(), &info)?)
}

fn envelope_key(
    shared: &SecretBytes<32>,
    group_id: &GroupId,
    epoch: u64,
    member: &PublicIdentity,
) -> Result<SecretBytes<32>, GroupError> {
    let info = [
        labels::GROUP_ENVELOPE,
        group_id,
        &epoch.to_be_bytes(),
        member.as_bytes(),
    ]
    .concat();
    Ok(kdf::derive(&[], shared.expose(), &info)?)
}

fn roster_key(epoch_key: &SecretBytes<32>, group_id: &GroupId, epoch: u64) -> Result<SecretBytes<32>, GroupError> {
    let info = [labels::GROUP_ROSTER, group_id, &epoch.to_be_bytes()].concat();
    Ok(kdf::derive(&[], epoch_key.expose(), &info)?)
}

fn message_key(epoch_key: &SecretBytes<32>, group_id: &GroupId, epoch: u64) -> Result<SecretBytes<32>, GroupError> {
    let info = [labels::GROUP_MESSAGE, group_id, &epoch.to_be_bytes()].concat();
    Ok(kdf::derive(&[], epoch_key.expose(), &info)?)
}

fn check_name(name: &str) -> Result<(), GroupError> {
    let chars = name.chars().count();
    if (1..=MAX_NAME_CHARS).contains(&chars) && name.len() <= MAX_NAME_BYTES && !name.chars().any(char::is_control) {
        Ok(())
    } else {
        Err(GroupError::InvalidName)
    }
}

/// A display name as a roster carries it: cut to [`MAX_NAME_BYTES`] on a character boundary (§9.1).
pub fn member_name(display_name: &str) -> String {
    let mut end = display_name.len().min(MAX_NAME_BYTES);
    while !display_name.is_char_boundary(end) {
        end -= 1;
    }
    display_name[..end].to_owned()
}

fn push_name(out: &mut Vec<u8>, name: &str) {
    out.push(name.len() as u8);
    out.extend_from_slice(name.as_bytes());
}

/// Reads fields front to back; any shortfall is malformed.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], GroupError> {
        if self.0.len() < len {
            return Err(GroupError::Malformed);
        }
        let (head, rest) = self.0.split_at(len);
        self.0 = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], GroupError> {
        Ok(self.take(N)?.try_into().expect("taken N"))
    }

    fn byte(&mut self) -> Result<u8, GroupError> {
        Ok(self.take(1)?[0])
    }

    fn name(&mut self) -> Result<String, GroupError> {
        let len = usize::from(self.byte()?);
        let name = std::str::from_utf8(self.take(len)?).map_err(|_| GroupError::Malformed)?;
        check_name(name)?;
        Ok(name.to_owned())
    }

    fn end(&self) -> Result<(), GroupError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(GroupError::Malformed)
        }
    }
}

/// Group members made up for tests.
#[cfg(any(test, feature = "test-util"))]
#[doc(hidden)]
pub mod test_util {
    use super::*;

    pub struct Person {
        pub identity: Identity,
        pub kem: DecapsulationKey,
        pub presence: SecretBytes<32>,
        pub name: &'static str,
    }

    pub fn person(name: &'static str) -> Person {
        Person {
            identity: Identity::generate().unwrap(),
            kem: DecapsulationKey::generate().unwrap(),
            presence: SecretBytes::random().unwrap(),
            name,
        }
    }

    pub fn member(person: &Person, role: Role) -> Member {
        Member {
            identity: person.identity.public(),
            static_kem: person.kem.encapsulation_key().clone(),
            key_version: 0,
            presence_key: person.presence.clone(),
            role,
            expires: 0,
            name: person.name.into(),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    pub(crate) use super::test_util::{member, person};
    use super::*;

    #[test]
    fn an_update_hands_each_member_the_key_and_roster() {
        let (ayse, burak, cem, eda) = (person("Ayşe"), person("Burak"), person("Cem"), person("Eda"));
        let roster = Roster::new(
            [1; 16],
            0,
            "Kamp ✨",
            vec![
                member(&ayse, Role::Admin),
                member(&burak, Role::Member),
                member(&cem, Role::Member),
            ],
        )
        .unwrap();
        let key = SecretBytes::random().unwrap();
        let update = seal_update(&roster, &key, &ayse.identity).unwrap();

        let read = Update::read(&update).unwrap();
        assert_eq!(
            (read.group_id, read.epoch, read.signer),
            ([1; 16], 0, ayse.identity.public())
        );
        for person in [&ayse, &burak, &cem] {
            let opened = read.open(&person.identity.public(), &person.kem).unwrap();
            assert_eq!(opened.epoch_key.expose(), key.expose());
            assert_eq!(opened.roster.encode(), roster.encode());
            assert!(opened.roster.is_admin(&ayse.identity.public()));
        }
        assert!(!read.addresses(&eda.identity.public()));
        assert!(
            read.open(&eda.identity.public(), &eda.kem).is_err(),
            "not for outsiders"
        );
        // Someone else's KEM key does not open Burak's envelope.
        assert!(read.open(&burak.identity.public(), &cem.kem).is_err());

        let mut forged = update.clone();
        forged[20] ^= 1;
        assert!(matches!(Update::read(&forged), Err(GroupError::NotAuthentic)));
        assert!(!update.windows(4).any(|w| w == b"Kamp"), "the roster travels sealed");
    }

    #[test]
    fn messages_open_only_with_the_epoch_key_and_the_senders_signature() {
        let (ayse, burak) = (person("Ayşe"), person("Burak"));
        let key = SecretBytes::random().unwrap();
        let text = Content::Text(Zeroizing::new("merhaba grup".into()));
        let sealed = seal_message(&[3; 16], 4, &key, &[9; 16], &ayse.identity, 1_000, &text).unwrap();
        assert!(!sealed.windows(12).any(|w| w == b"merhaba grup"));
        let message = Message::read(&sealed).unwrap();
        assert_eq!(
            (message.group_id, message.epoch, message.message_id, message.sender),
            ([3; 16], 4, [9; 16], ayse.identity.public())
        );
        assert_eq!(message.open(&key).unwrap(), (1_000, text));
        assert!(
            message.open(&SecretBytes::random().unwrap()).is_err(),
            "wrong epoch key"
        );

        // Claiming another sender breaks the signature.
        let mut spoofed = sealed.clone();
        spoofed[40..72].copy_from_slice(burak.identity.public().as_bytes());
        assert!(Message::read(&spoofed).unwrap().open(&key).is_err());

        // A file message carries the file's description.
        let file = Content::File(FileMeta {
            name: "harita.pdf".into(),
            mime: "application/pdf".into(),
            size: 70_000,
            sha256: [5; 32],
            thumbnail: Some(vec![1; 300]),
        });
        let sealed = seal_message(&[3; 16], 4, &key, &[8; 16], &ayse.identity, 2_000, &file).unwrap();
        assert!(!sealed.windows(6).any(|w| w == b"harita"));
        assert_eq!(Message::read(&sealed).unwrap().open(&key).unwrap(), (2_000, file));
        let empty = Content::Text(Zeroizing::new(String::new()));
        assert!(seal_message(&[3; 16], 4, &key, &[8; 16], &ayse.identity, 2_000, &empty).is_err());

        // Deleting the group carries nothing more.
        let sealed = seal_message(&[3; 16], 4, &key, &[7; 16], &ayse.identity, 3_000, &Content::Deleted).unwrap();
        assert_eq!(
            Message::read(&sealed).unwrap().open(&key).unwrap(),
            (3_000, Content::Deleted)
        );
        assert_eq!(Content::decode(&[0x03]).unwrap(), Content::Deleted);
        assert!(Content::decode(&[0x03, 0]).is_err());
    }

    #[test]
    fn rosters_are_canonical() {
        let (ayse, burak) = (person("Ayşe"), person("Burak"));
        let roster = Roster::new(
            [1; 16],
            2,
            "Aile",
            vec![member(&burak, Role::Member), member(&ayse, Role::Admin)],
        )
        .unwrap();
        assert_eq!(Roster::decode(&roster.encode()).unwrap().encode(), roster.encode());
        assert!(matches!(
            Roster::new(
                [1; 16],
                2,
                "Aile",
                vec![member(&ayse, Role::Member), member(&burak, Role::Member)]
            ),
            Err(GroupError::InvalidMembers)
        ));
        assert!(matches!(
            Roster::new(
                [1; 16],
                2,
                "Aile",
                vec![member(&ayse, Role::Admin), member(&ayse, Role::Member)]
            ),
            Err(GroupError::InvalidMembers)
        ));
        assert!(matches!(
            Roster::new(
                [1; 16],
                2,
                "",
                vec![member(&ayse, Role::Admin), member(&burak, Role::Member)]
            ),
            Err(GroupError::InvalidName)
        ));

        // The longest display name, 64 characters of 4 bytes, does not fit a name's length byte:
        // it is cut to fit, and the roster still reads back.
        let longest = "🦄".repeat(MAX_NAME_CHARS);
        let mut unicorn = member(&burak, Role::Member);
        unicorn.name = member_name(&longest);
        assert_eq!(unicorn.name, "🦄".repeat(MAX_NAME_CHARS - 1));
        let roster = Roster::new([1; 16], 2, "Aile", vec![member(&ayse, Role::Admin), unicorn]).unwrap();
        assert_eq!(Roster::decode(&roster.encode()).unwrap().encode(), roster.encode());
        assert!(matches!(
            Roster::new(
                [1; 16],
                2,
                &longest,
                vec![member(&ayse, Role::Admin), member(&burak, Role::Member)]
            ),
            Err(GroupError::InvalidName)
        ));
    }

    /// `tests/vectors/group.json`; `check_group.py` re-derives it from docs/protocol.md §9.
    #[test]
    fn vector() {
        use crate::crypto::test_util::{DeterministicRng, check_vector, to_hex};
        let people: Vec<(Identity, DecapsulationKey, SecretBytes<32>, &str, Role, u64)> = [
            (1u8, "Ayşe", Role::Admin, 0u64),
            (2, "Burak", Role::Member, 0),
            (3, "Cem", Role::Member, 1_800_000_000),
        ]
        .into_iter()
        .map(|(n, name, role, expires)| {
            (
                Identity::from_seed(SecretBytes::from_slice(&[n; 32]).unwrap()),
                DecapsulationKey::from_seed(SecretBytes::from_slice(&[0x40 + n; 32]).unwrap()).unwrap(),
                SecretBytes::from_slice(&[0x80 + n; 32]).unwrap(),
                name,
                role,
                expires,
            )
        })
        .collect();
        let members = people
            .iter()
            .zip([0, 3, 7])
            .map(|((identity, kem, presence, name, role, expires), key_version)| Member {
                identity: identity.public(),
                static_kem: kem.encapsulation_key().clone(),
                key_version,
                presence_key: presence.clone(),
                role: *role,
                expires: *expires,
                name: (*name).into(),
            })
            .collect();
        let group_id = [0x67; 16];
        let roster = Roster::new(group_id, 5, "Kamp ateşi", members).unwrap();
        let epoch_key = SecretBytes::from_slice(&[0x5e; 32]).unwrap();
        let rng_seed = [0x77; 32];
        let mut rng = DeterministicRng::new(rng_seed);
        let update = seal_update_from(&roster, &epoch_key, &people[0].0, &mut rng).unwrap();
        let read = Update::read(&update).unwrap();
        let mut fields = vec![
            ("group_id", to_hex(&group_id)),
            ("epoch", "5".to_owned()),
            ("epoch_key", to_hex(epoch_key.expose())),
            ("rng_seed", to_hex(&rng_seed)),
        ];
        // In roster order; the KEM shared secrets are listed (and re-derived here by decapsulating).
        let mut secrets = Vec::new();
        for (index, member) in roster.members().iter().enumerate() {
            let person = people.iter().find(|p| p.0.public() == member.identity).unwrap();
            let (_, ciphertext, _) = &read.envelopes[index];
            secrets.push(to_hex(person.1.decapsulate(ciphertext).unwrap().expose()));
            assert!(read.open(&member.identity, &person.1).is_ok());
        }
        fields.push(("roster", to_hex(&roster.encode())));
        fields.push(("signer_seed", to_hex(people[0].0.seed().expose())));
        fields.push(("envelope_shared_secrets", secrets.join(",")));
        fields.push(("update", to_hex(&update)));
        let message = seal_message_from(
            &group_id,
            5,
            &epoch_key,
            &[0x11; 16],
            &people[1].0,
            1_791_400_000_000,
            &Content::Text(Zeroizing::new("Ateşi kim yakıyor?".into())),
            &mut rng,
        )
        .unwrap();
        fields.push(("message_sender_seed", to_hex(people[1].0.seed().expose())));
        fields.push(("message", to_hex(&message)));
        // A file message from Cem: the description of a 70 000-byte PDF with a 4-byte thumbnail.
        let file = seal_message_from(
            &group_id,
            5,
            &epoch_key,
            &[0x12; 16],
            &people[2].0,
            1_791_400_060_000,
            &Content::File(FileMeta {
                name: "harita.pdf".into(),
                mime: "application/pdf".into(),
                size: 70_000,
                sha256: [0xab; 32],
                thumbnail: Some(vec![0xff, 0xd8, 0xff, 0xd9]),
            }),
            &mut rng,
        )
        .unwrap();
        fields.push(("file_message", to_hex(&file)));
        // Ayşe, an admin, deletes the group.
        let deleted = seal_message_from(
            &group_id,
            5,
            &epoch_key,
            &[0x13; 16],
            &people[0].0,
            1_791_400_120_000,
            &Content::Deleted,
            &mut rng,
        )
        .unwrap();
        fields.push(("deleted_message", to_hex(&deleted)));
        let psk = link_psk(&epoch_key, &group_id, 5, &people[1].0.public(), &people[2].0.public()).unwrap();
        fields.push(("link_psk_burak_cem", to_hex(psk.expose())));
        check_vector("group", &fields);
    }

    #[test]
    fn link_keys_are_the_same_both_ways_and_differ_per_pair_and_epoch() {
        let (a, b, c) = (person("A"), person("B"), person("C"));
        let key = SecretBytes::random().unwrap();
        let ab = link_psk(&key, &[1; 16], 0, &a.identity.public(), &b.identity.public()).unwrap();
        let ba = link_psk(&key, &[1; 16], 0, &b.identity.public(), &a.identity.public()).unwrap();
        let ac = link_psk(&key, &[1; 16], 0, &a.identity.public(), &c.identity.public()).unwrap();
        let ab1 = link_psk(&key, &[1; 16], 1, &a.identity.public(), &b.identity.public()).unwrap();
        assert_eq!(ab.expose(), ba.expose());
        assert_ne!(ab.expose(), ac.expose());
        assert_ne!(ab.expose(), ab1.expose());
    }
}
