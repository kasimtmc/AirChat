//! Mail between AirChat+ accounts (docs/protocol.md §14): contact requests and their accepts, which
//! make two accounts contacts without meeting; mail between contacts, sealed so that only the
//! recipient opens it and its server cannot tell who sent it; delivery keys; and the frames of the
//! mailbox connection.
//!
//! ```text
//! request = v_B (u32) || ct_1 (1120) || ChaCha20-Poly1305(k_1, padded card of the requester)   4096 bytes
//! mail    = tag (32) || field (u32) || ct (1120) || ChaCha20-Poly1305(key, padded payload)    2048, 4096 or 16384 bytes
//! group   = tag (32) || ChaCha20-Poly1305(key, padded record)                                 2048, 4096 or 16384 bytes
//! ```
//!
//! Group mail (§16.3) is sealed under a group's epoch key, for each member alike.

use zeroize::Zeroizing;

use crate::{
    account::{self, Answer, Authorized, Failure, NONCE_LEN, Reader, Request, put_name},
    crypto::{
        CryptoError, SecretBytes,
        aead::{self, ChaCha20Poly1305},
        hash::{equal_in_constant_time, hmac_sha256, sha256},
        kdf,
        kem::{CIPHERTEXT_LEN, Ciphertext, DecapsulationKey, ENCAPSULATION_KEY_LEN, EncapsulationKey},
        random::{OsRng, Rng},
        sign::{SIGNATURE_LEN, Signature},
    },
    group::GroupId,
    identity::{Identity, PublicIdentity},
    labels,
};

pub use crate::mesh::Pair;

pub const DELIVERY_KEY_LEN: usize = 32;
/// Every request is this long (§14.2).
pub const REQUEST_LEN: usize = 4096;
/// Every piece of mail is one of these long (§14.3).
pub const MAIL_SIZES: [usize; 3] = [2048, 4096, 16384];
pub const TAG_LEN: usize = 32;
/// `version (u32) || SK.pk || signature`, as §6.9 signs it.
pub const SIGNED_STATIC_KEY_LEN: usize = 4 + ENCAPSULATION_KEY_LEN + SIGNATURE_LEN;
/// Mail sealed to the recipient's static key names this prekey (§14.3).
pub const STATIC_KEY: u32 = 0;

const NONCE_HALF: usize = 16;
const MAIL_HEADER_LEN: usize = TAG_LEN + 4 + CIPHERTEXT_LEN;
const REQUEST_HEADER_LEN: usize = 4 + CIPHERTEXT_LEN;
/// The largest payload: that of the largest mail.
pub const MAX_PAYLOAD: usize = MAIL_SIZES[2] - MAIL_HEADER_LEN - aead::TAG_LEN - 2;
/// The most update data a part carries in mail, so that it fits in the largest mail of either kind
/// (§16.3); on a link a part carries more ([`crate::chat::UPDATE_PART_LEN`]).
pub const MAIL_PART_LEN: usize = 15_000;
const ZERO_NONCE: [u8; 12] = [0; 12];

const MAIL_FRAME: u8 = 0x90;
const REQUEST_FRAME: u8 = 0x91;
const TAKEN_FRAME: u8 = 0x92;
const FRAME_VERSION: u8 = 0x00;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MailError {
    #[error("malformed mail")]
    Malformed,
    /// Not for this key or pair, or tampered with.
    #[error("the mail does not open")]
    DoesNotOpen,
    #[error("the payload is too long for mail")]
    TooLong,
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

impl From<account::AccountError> for MailError {
    fn from(_: account::AccountError) -> Self {
        Self::Malformed
    }
}

/// A static key and its owner's signature over it (§6.9), as a server hands it out (§14.1) and as
/// a card carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedStaticKey {
    pub version: u32,
    pub key: EncapsulationKey,
    pub signature: [u8; SIGNATURE_LEN],
}

impl SignedStaticKey {
    pub fn new(identity: &Identity, version: u32, key: &EncapsulationKey) -> Self {
        Self {
            version,
            key: key.clone(),
            signature: identity.sign_static_key(version, key),
        }
    }

    /// Whether `identity` signed this key.
    pub fn vouched_by(&self, identity: &PublicIdentity) -> bool {
        identity.vouches_for(self.version, &self.key, &self.signature)
    }

    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(self.key.as_bytes());
        out.extend_from_slice(&self.signature);
    }

    /// Parses exactly [`SIGNED_STATIC_KEY_LEN`] bytes; the key must be a valid X-Wing key. The
    /// signature is not checked here ([`Self::vouched_by`]).
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let (version, rest) = bytes.split_first_chunk::<4>()?;
        if rest.len() != ENCAPSULATION_KEY_LEN + SIGNATURE_LEN {
            return None;
        }
        let (key, signature) = rest.split_at(ENCAPSULATION_KEY_LEN);
        Some(Self {
            version: u32::from_be_bytes(*version),
            key: EncapsulationKey::from_bytes(key).ok()?,
            signature: signature.try_into().ok()?,
        })
    }
}

/// An account as its server gives it (§14.1): where it is, and its keys.
#[derive(Debug, Clone)]
pub struct Peer {
    pub server: String,
    pub name: String,
    pub identity: PublicIdentity,
    pub static_key: SignedStaticKey,
}

/// What an account tells a new contact of itself, in its request or accept (§14.2, §14.3).
#[derive(Debug, Clone)]
pub struct Card {
    pub server: String,
    pub name: String,
    pub identity: PublicIdentity,
    pub static_key: SignedStaticKey,
    pub delivery_key: SecretBytes<DELIVERY_KEY_LEN>,
}

impl Card {
    /// Everything before the proof.
    fn fields(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_name(&mut out, &self.server);
        put_name(&mut out, &self.name);
        out.extend_from_slice(self.identity.as_bytes());
        self.static_key.encode(&mut out);
        out.extend_from_slice(self.delivery_key.expose());
        out
    }

    /// The card with its proof over `transcript`, signed by `own`, whose public key it carries.
    fn sign(&self, own: &Identity, label: &[u8], transcript: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>, MailError> {
        if own.public() != self.identity {
            return Err(MailError::Malformed);
        }
        let mut out = Zeroizing::new(self.fields());
        let proof = own.sign(label, &[transcript, &out]);
        out.extend_from_slice(proof.as_bytes());
        Ok(out)
    }

    /// Parses a card and checks both its signatures: of its static key, and its proof over
    /// `transcript`.
    fn open(bytes: &[u8], label: &[u8], transcript: &[u8; 32]) -> Result<Self, MailError> {
        let mut reader = Reader(bytes);
        let server = reader.server()?;
        let name = reader.name()?;
        let identity = PublicIdentity::from_bytes(reader.array()?);
        let static_key = SignedStaticKey::decode(reader.take(SIGNED_STATIC_KEY_LEN)?).ok_or(MailError::Malformed)?;
        let delivery_key = reader.secret()?;
        let proof: [u8; SIGNATURE_LEN] = reader.array()?;
        reader.end()?;
        let fields = &bytes[..bytes.len() - SIGNATURE_LEN];
        if !static_key.vouched_by(&identity)
            || identity
                .verify(label, &[transcript, fields], &Signature::from_bytes(proof))
                .is_err()
        {
            return Err(MailError::DoesNotOpen);
        }
        Ok(Self {
            server,
            name,
            identity,
            static_key,
            delivery_key,
        })
    }
}

/// A request this device sent, kept until it is answered or given up (§14.2).
#[derive(Debug, Clone)]
pub struct PendingRequest {
    pub to: Peer,
    /// `ss_1`.
    pub secret: SecretBytes<32>,
    /// `h_1`.
    pub transcript: [u8; 32],
}

/// A request this device opened, kept until its user answers (§14.2).
#[derive(Debug, Clone)]
pub struct IncomingRequest {
    /// Who asks, by their own word; the device checks it with a lookup before showing it.
    pub from: Card,
    pub secret: SecretBytes<32>,
    pub transcript: [u8; 32],
}

/// Asks to become `to`'s contact: the request to deposit (§14.5) and what to keep.
pub fn request(own: &Identity, own_card: &Card, to: &Peer) -> Result<(Vec<u8>, PendingRequest), MailError> {
    request_from(own, own_card, to, &mut OsRng)
}

pub(crate) fn request_from(
    own: &Identity,
    own_card: &Card,
    to: &Peer,
    rng: &mut dyn Rng,
) -> Result<(Vec<u8>, PendingRequest), MailError> {
    if !to.static_key.vouched_by(&to.identity) || to.identity == own.public() {
        return Err(MailError::Malformed);
    }
    let (secret, ciphertext) = to.static_key.key.encapsulate_from(rng)?;
    let transcript = request_transcript(&to.server, &to.name, &to.identity, to.static_key.version, &ciphertext);
    let key = kdf::derive(b"", secret.expose(), &[labels::MAIL_REQUEST_KEY, &transcript].concat())?;
    let card = own_card.sign(own, labels::MAIL_REQUEST_PROOF, &transcript)?;
    let padded = pad(&card, REQUEST_LEN - REQUEST_HEADER_LEN - aead::TAG_LEN)?;
    let sealed = ChaCha20Poly1305::seal(&key, &ZERO_NONCE, &[], &padded)?;
    let request = [&to.static_key.version.to_be_bytes()[..], ciphertext.as_bytes(), &sealed].concat();
    debug_assert_eq!(request.len(), REQUEST_LEN);
    Ok((
        request,
        PendingRequest {
            to: to.clone(),
            secret,
            transcript,
        },
    ))
}

/// The version of the recipient's static key a request is sealed to.
pub fn requested_version(request: &[u8]) -> Result<u32, MailError> {
    if request.len() != REQUEST_LEN {
        return Err(MailError::Malformed);
    }
    Ok(u32::from_be_bytes(request[..4].try_into().expect("length checked")))
}

/// Opens a request to this account (`own`, `name@server`) with its static key of the version the
/// request names ([`requested_version`]). Does not check the requester's name: look it up and
/// compare its identity key before showing the request (§14.2).
pub fn open_request(
    own: &PublicIdentity,
    server: &str,
    name: &str,
    static_key: &DecapsulationKey,
    request: &[u8],
) -> Result<IncomingRequest, MailError> {
    let version = requested_version(request)?;
    let (ciphertext, sealed) = request[4..].split_at(CIPHERTEXT_LEN);
    let ciphertext = Ciphertext::from_bytes(ciphertext)?;
    let secret = static_key.decapsulate(&ciphertext)?;
    let transcript = request_transcript(server, name, own, version, &ciphertext);
    let key = kdf::derive(b"", secret.expose(), &[labels::MAIL_REQUEST_KEY, &transcript].concat())?;
    let padded = ChaCha20Poly1305::open(&key, &ZERO_NONCE, &[], sealed).map_err(|_| MailError::DoesNotOpen)?;
    let from = Card::open(unpad(&padded)?, labels::MAIL_REQUEST_PROOF, &transcript)?;
    if from.identity == *own {
        return Err(MailError::DoesNotOpen);
    }
    Ok(IncomingRequest {
        from,
        secret,
        transcript,
    })
}

/// Accepts a request: the accept to deposit at the requester's server, and the pairing secret.
pub fn accept(
    own: &Identity,
    own_card: &Card,
    request: &IncomingRequest,
) -> Result<(Vec<u8>, SecretBytes<32>), MailError> {
    accept_from(own, own_card, request, &mut OsRng)
}

pub(crate) fn accept_from(
    own: &Identity,
    own_card: &Card,
    request: &IncomingRequest,
    rng: &mut dyn Rng,
) -> Result<(Vec<u8>, SecretBytes<32>), MailError> {
    let them = &request.from;
    let tag = new_tag(&accept_tag_key(&request.secret, &request.transcript)?, rng)?;
    let (secret_2, ciphertext) = them.static_key.key.encapsulate_from(rng)?;
    let transcript_2 = accept_transcript(
        &request.transcript,
        &them.identity,
        them.static_key.version,
        &ciphertext,
    );
    let key = kdf::derive(
        b"",
        secret_2.expose(),
        &[labels::MAIL_ACCEPT_KEY, &transcript_2, &tag].concat(),
    )?;
    let card = own_card.sign(own, labels::MAIL_ACCEPT_PROOF, &transcript_2)?;
    let mail = seal_mail(&tag, them.static_key.version, &ciphertext, &key, &card)?;
    let psk = pairing_secret(&request.secret, &secret_2, &transcript_2)?;
    Ok((mail, psk))
}

/// Whether `mail` answers `request`, by its tag.
pub fn is_accept(request: &PendingRequest, mail: &[u8]) -> bool {
    accept_tag_key(&request.secret, &request.transcript).is_ok_and(|key| tag_matches(&key, mail))
}

/// The version of the recipient's static key an accept is sealed to ([`open_accept`]).
pub fn sealed_to(mail: &[u8]) -> Result<u32, MailError> {
    if !MAIL_SIZES.contains(&mail.len()) {
        return Err(MailError::Malformed);
    }
    Ok(u32::from_be_bytes(
        mail[TAG_LEN..TAG_LEN + 4].try_into().expect("length checked"),
    ))
}

/// Opens the accept of a request this device (`own`) sent, with its static key of the version the
/// accept names ([`sealed_to`]): the new contact's card and the pairing secret.
pub fn open_accept(
    own: &PublicIdentity,
    static_key: &DecapsulationKey,
    request: &PendingRequest,
    mail: &[u8],
) -> Result<(Card, SecretBytes<32>), MailError> {
    if !is_accept(request, mail) {
        return Err(MailError::DoesNotOpen);
    }
    let version = sealed_to(mail)?;
    let (tag, ciphertext, sealed) = split_mail(mail)?;
    let secret_2 = static_key.decapsulate(&ciphertext)?;
    let transcript_2 = accept_transcript(&request.transcript, own, version, &ciphertext);
    let key = kdf::derive(
        b"",
        secret_2.expose(),
        &[labels::MAIL_ACCEPT_KEY, &transcript_2, tag].concat(),
    )?;
    let padded = ChaCha20Poly1305::open(&key, &ZERO_NONCE, &[], sealed).map_err(|_| MailError::DoesNotOpen)?;
    let card = Card::open(unpad(&padded)?, labels::MAIL_ACCEPT_PROOF, &transcript_2)?;
    if card.identity != request.to.identity || card.server != request.to.server || card.name != request.to.name {
        return Err(MailError::DoesNotOpen);
    }
    let psk = pairing_secret(&request.secret, &secret_2, &transcript_2)?;
    Ok((card, psk))
}

/// The key a contact's mail tags are made with (§14.3).
pub fn tag_key(pair: &Pair) -> Result<SecretBytes<32>, MailError> {
    Ok(kdf::derive(
        b"",
        pair.psk.expose(),
        &[labels::MAIL_TAG_KEY, pair.from.as_bytes(), pair.to.as_bytes()].concat(),
    )?)
}

/// Whether `mail`'s tag was made with `tag_key`, in constant time.
pub fn tag_matches(tag_key: &SecretBytes<32>, mail: &[u8]) -> bool {
    let Some(tag) = mail.get(..TAG_LEN) else {
        return false;
    };
    let (nonce, mac) = tag.split_at(NONCE_HALF);
    equal_in_constant_time(&tag_mac(tag_key, nonce)[..], mac)
}

/// Seals a §8.1 record from `pair.from` to `pair.to`: to one of the recipient's one-time prekeys
/// (`to`, numbered `prekey`), or its static key ([`STATIC_KEY`]); padded to a size of
/// [`MAIL_SIZES`].
pub fn seal(pair: &Pair, to: &EncapsulationKey, prekey: u32, payload: &[u8]) -> Result<Vec<u8>, MailError> {
    seal_from(pair, to, prekey, payload, &mut OsRng)
}

pub(crate) fn seal_from(
    pair: &Pair,
    to: &EncapsulationKey,
    prekey: u32,
    payload: &[u8],
    rng: &mut dyn Rng,
) -> Result<Vec<u8>, MailError> {
    let tag = new_tag(&tag_key(pair)?, rng)?;
    let (secret, ciphertext) = to.encapsulate_from(rng)?;
    let key = seal_key(pair, &secret, &tag, prekey)?;
    seal_mail(&tag, prekey, &ciphertext, &key, payload)
}

/// Opens mail from `pair.from` with the key it is sealed to ([`sealed_to`]): the payload.
pub fn open(pair: &Pair, own: &DecapsulationKey, mail: &[u8]) -> Result<Zeroizing<Vec<u8>>, MailError> {
    let prekey = sealed_to(mail)?;
    let (tag, ciphertext, sealed) = split_mail(mail)?;
    let secret = own.decapsulate(&ciphertext)?;
    let key = seal_key(pair, &secret, tag, prekey)?;
    let padded = ChaCha20Poly1305::open(&key, &ZERO_NONCE, &[], sealed).map_err(|_| MailError::DoesNotOpen)?;
    Ok(Zeroizing::new(unpad(&padded)?.to_vec()))
}

/// The key a group's mail tags are made with in `epoch` (§16.3); [`tag_matches`] checks them.
pub fn group_tag_key(
    epoch_key: &SecretBytes<32>,
    group_id: &GroupId,
    epoch: u64,
) -> Result<SecretBytes<32>, MailError> {
    Ok(kdf::derive(
        b"",
        epoch_key.expose(),
        &[labels::MAIL_GROUP_TAG_KEY, group_id, &epoch.to_be_bytes()].concat(),
    )?)
}

/// Seals a group record (§16.3) for one member of `group_id`, under the key of `epoch`; padded to
/// a size of [`MAIL_SIZES`]. Every member gets a piece of its own, with a fresh tag.
pub fn seal_group(
    epoch_key: &SecretBytes<32>,
    group_id: &GroupId,
    epoch: u64,
    record: &[u8],
) -> Result<Vec<u8>, MailError> {
    seal_group_from(epoch_key, group_id, epoch, record, &mut OsRng)
}

pub(crate) fn seal_group_from(
    epoch_key: &SecretBytes<32>,
    group_id: &GroupId,
    epoch: u64,
    record: &[u8],
    rng: &mut dyn Rng,
) -> Result<Vec<u8>, MailError> {
    let tag = new_tag(&group_tag_key(epoch_key, group_id, epoch)?, rng)?;
    let key = group_seal_key(epoch_key, group_id, epoch, &tag)?;
    let size = MAIL_SIZES
        .into_iter()
        .find(|size| record.len() + 2 <= size - TAG_LEN - aead::TAG_LEN)
        .ok_or(MailError::TooLong)?;
    let padded = pad(record, size - TAG_LEN - aead::TAG_LEN)?;
    let sealed = ChaCha20Poly1305::seal(&key, &ZERO_NONCE, &[], &padded)?;
    Ok([&tag[..], &sealed].concat())
}

/// Opens group mail whose tag matched the tag key of `epoch`: the record.
pub fn open_group(
    epoch_key: &SecretBytes<32>,
    group_id: &GroupId,
    epoch: u64,
    mail: &[u8],
) -> Result<Zeroizing<Vec<u8>>, MailError> {
    if !MAIL_SIZES.contains(&mail.len()) {
        return Err(MailError::Malformed);
    }
    let (tag, sealed) = mail.split_first_chunk::<TAG_LEN>().expect("length checked");
    let key = group_seal_key(epoch_key, group_id, epoch, tag)?;
    let padded = ChaCha20Poly1305::open(&key, &ZERO_NONCE, &[], sealed).map_err(|_| MailError::DoesNotOpen)?;
    Ok(Zeroizing::new(unpad(&padded)?.to_vec()))
}

/// What a server keeps of a delivery key (§14.4).
pub fn delivery_key_hash(delivery_key: &SecretBytes<DELIVERY_KEY_LEN>) -> [u8; 32] {
    sha256(&[labels::MAIL_DELIVERY_KEY, delivery_key.expose()])
}

/// What a server sends on a mailbox connection (§14.6).
#[derive(Debug, Clone)]
pub enum ServerFrame {
    Challenge { nonce: [u8; NONCE_LEN] },
    Done,
    Failure { failure: Failure, retry_after: u32 },
    Mail { id: u64, mail: Vec<u8> },
    Request { id: u64, request: Vec<u8> },
}

impl ServerFrame {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Challenge { nonce } => Answer::Challenge { nonce: *nonce }.encode(),
            Self::Done => Answer::Done.encode(),
            Self::Failure { failure, retry_after } => Answer::Failure {
                failure: *failure,
                retry_after: *retry_after,
            }
            .encode(),
            Self::Mail { id, mail } => [&[FRAME_VERSION, MAIL_FRAME][..], &id.to_be_bytes(), mail].concat(),
            Self::Request { id, request } => [&[FRAME_VERSION, REQUEST_FRAME][..], &id.to_be_bytes(), request].concat(),
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, MailError> {
        match bytes {
            [FRAME_VERSION, MAIL_FRAME, rest @ ..] => {
                let (id, mail) = rest.split_first_chunk::<8>().ok_or(MailError::Malformed)?;
                if !MAIL_SIZES.contains(&mail.len()) {
                    return Err(MailError::Malformed);
                }
                Ok(Self::Mail {
                    id: u64::from_be_bytes(*id),
                    mail: mail.to_vec(),
                })
            }
            [FRAME_VERSION, REQUEST_FRAME, rest @ ..] => {
                let (id, request) = rest.split_first_chunk::<8>().ok_or(MailError::Malformed)?;
                if request.len() != REQUEST_LEN {
                    return Err(MailError::Malformed);
                }
                Ok(Self::Request {
                    id: u64::from_be_bytes(*id),
                    request: request.to_vec(),
                })
            }
            _ => match Answer::decode(bytes)? {
                Answer::Challenge { nonce } => Ok(Self::Challenge { nonce }),
                Answer::Done => Ok(Self::Done),
                Answer::Failure { failure, retry_after } => Ok(Self::Failure { failure, retry_after }),
                _ => Err(MailError::Malformed),
            },
        }
    }
}

/// What a device sends on its mailbox connection (§14.6).
#[derive(Debug, Clone)]
pub enum DeviceFrame {
    Authorized(Box<Authorized>),
    Taken { id: u64 },
}

impl DeviceFrame {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Authorized(authorized) => Request::Authorized((**authorized).clone()).encode(),
            Self::Taken { id } => [&[FRAME_VERSION, TAKEN_FRAME][..], &id.to_be_bytes()].concat(),
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, MailError> {
        match bytes {
            [FRAME_VERSION, TAKEN_FRAME, rest @ ..] => Ok(Self::Taken {
                id: u64::from_be_bytes(rest.try_into().map_err(|_| MailError::Malformed)?),
            }),
            _ => match Request::decode(bytes)? {
                Request::Authorized(authorized) => Ok(Self::Authorized(Box::new(authorized))),
                _ => Err(MailError::Malformed),
            },
        }
    }
}

fn request_transcript(
    server: &str,
    name: &str,
    identity: &PublicIdentity,
    version: u32,
    ciphertext: &Ciphertext,
) -> [u8; 32] {
    let mut names = Vec::new();
    put_name(&mut names, server);
    put_name(&mut names, name);
    sha256(&[
        labels::MAIL_REQUEST,
        &names,
        identity.as_bytes(),
        &version.to_be_bytes(),
        ciphertext.as_bytes(),
    ])
}

fn accept_transcript(
    request_transcript: &[u8; 32],
    requester: &PublicIdentity,
    version: u32,
    ciphertext: &Ciphertext,
) -> [u8; 32] {
    sha256(&[
        labels::MAIL_ACCEPT,
        request_transcript,
        requester.as_bytes(),
        &version.to_be_bytes(),
        ciphertext.as_bytes(),
    ])
}

fn accept_tag_key(secret: &SecretBytes<32>, transcript: &[u8; 32]) -> Result<SecretBytes<32>, CryptoError> {
    kdf::derive(
        b"",
        secret.expose(),
        &[labels::MAIL_ACCEPT_TAG_KEY, transcript].concat(),
    )
}

fn pairing_secret(
    secret_1: &SecretBytes<32>,
    secret_2: &SecretBytes<32>,
    transcript_2: &[u8; 32],
) -> Result<SecretBytes<32>, CryptoError> {
    kdf::derive(
        secret_1.expose(),
        secret_2.expose(),
        &[labels::MAIL_PSK, transcript_2].concat(),
    )
}

fn seal_key(
    pair: &Pair,
    secret: &SecretBytes<32>,
    tag: &[u8; TAG_LEN],
    prekey: u32,
) -> Result<SecretBytes<32>, CryptoError> {
    let info = [
        labels::MAIL_SEAL,
        pair.from.as_bytes(),
        pair.to.as_bytes(),
        tag,
        &prekey.to_be_bytes(),
    ]
    .concat();
    kdf::derive(pair.psk.expose(), secret.expose(), &info)
}

fn group_seal_key(
    epoch_key: &SecretBytes<32>,
    group_id: &GroupId,
    epoch: u64,
    tag: &[u8; TAG_LEN],
) -> Result<SecretBytes<32>, CryptoError> {
    let info = [labels::MAIL_GROUP_SEAL, group_id, &epoch.to_be_bytes(), tag].concat();
    kdf::derive(b"", epoch_key.expose(), &info)
}

fn tag_mac(tag_key: &SecretBytes<32>, nonce: &[u8]) -> [u8; NONCE_HALF] {
    let mac = hmac_sha256(tag_key.expose(), &[labels::MAIL_TAG, nonce]);
    mac.expose()[..NONCE_HALF].try_into().expect("a MAC is longer")
}

fn new_tag(tag_key: &SecretBytes<32>, rng: &mut dyn Rng) -> Result<[u8; TAG_LEN], CryptoError> {
    let mut tag = [0; TAG_LEN];
    rng.fill(&mut tag[..NONCE_HALF])?;
    let mac = tag_mac(tag_key, &tag[..NONCE_HALF]);
    tag[NONCE_HALF..].copy_from_slice(&mac);
    Ok(tag)
}

/// `tag || field || ct || AEAD(key, padded payload)`, the smallest of [`MAIL_SIZES`] it fits.
fn seal_mail(
    tag: &[u8; TAG_LEN],
    field: u32,
    ciphertext: &Ciphertext,
    key: &SecretBytes<32>,
    payload: &[u8],
) -> Result<Vec<u8>, MailError> {
    let size = MAIL_SIZES
        .into_iter()
        .find(|size| payload.len() + 2 <= size - MAIL_HEADER_LEN - aead::TAG_LEN)
        .ok_or(MailError::TooLong)?;
    let padded = pad(payload, size - MAIL_HEADER_LEN - aead::TAG_LEN)?;
    let sealed = ChaCha20Poly1305::seal(key, &ZERO_NONCE, &[], &padded)?;
    Ok([&tag[..], &field.to_be_bytes(), ciphertext.as_bytes(), &sealed].concat())
}

fn split_mail(mail: &[u8]) -> Result<(&[u8; TAG_LEN], Ciphertext, &[u8]), MailError> {
    if !MAIL_SIZES.contains(&mail.len()) {
        return Err(MailError::Malformed);
    }
    let (tag, rest) = mail.split_first_chunk::<TAG_LEN>().expect("length checked");
    let (ciphertext, sealed) = rest[4..].split_at(CIPHERTEXT_LEN);
    Ok((tag, Ciphertext::from_bytes(ciphertext)?, sealed))
}

/// `len (u16) || bytes || zeros`, exactly `padded_len` long.
fn pad(bytes: &[u8], padded_len: usize) -> Result<Zeroizing<Vec<u8>>, MailError> {
    let len = u16::try_from(bytes.len()).map_err(|_| MailError::TooLong)?;
    if bytes.len() + 2 > padded_len {
        return Err(MailError::TooLong);
    }
    let mut padded = Zeroizing::new(Vec::with_capacity(padded_len));
    padded.extend_from_slice(&len.to_be_bytes());
    padded.extend_from_slice(bytes);
    padded.resize(padded_len, 0);
    Ok(padded)
}

fn unpad(padded: &[u8]) -> Result<&[u8], MailError> {
    let (len, rest) = padded.split_first_chunk::<2>().ok_or(MailError::Malformed)?;
    let len = usize::from(u16::from_be_bytes(*len));
    if len > rest.len() || rest[len..].iter().any(|&b| b != 0) {
        return Err(MailError::Malformed);
    }
    Ok(&rest[..len])
}

/// Requests and accepts whose sealed plaintext is chosen, for fuzz targets: what a recipient parses
/// once it decrypted (the padding, the card) is fuzzed too, not only what comes before the AEAD.
#[cfg(any(test, feature = "fuzzing"))]
pub(crate) mod fuzzing {
    use super::*;

    /// A request to `to` (its static key `to_static`, of `version`) sealing `plaintext`, cut or
    /// filled with zeros to the request's size.
    pub(crate) fn request(
        server: &str,
        name: &str,
        to: &PublicIdentity,
        to_static: &EncapsulationKey,
        version: u32,
        plaintext: &[u8],
    ) -> Vec<u8> {
        let (secret, ciphertext) = to_static.encapsulate().expect("a valid key");
        let transcript = request_transcript(server, name, to, version, &ciphertext);
        let key =
            kdf::derive(b"", secret.expose(), &[labels::MAIL_REQUEST_KEY, &transcript].concat()).expect("32 bytes");
        let mut padded = plaintext.to_vec();
        padded.resize(REQUEST_LEN - REQUEST_HEADER_LEN - aead::TAG_LEN, 0);
        let sealed = ChaCha20Poly1305::seal(&key, &ZERO_NONCE, &[], &padded).expect("a fitting plaintext");
        [&version.to_be_bytes()[..], ciphertext.as_bytes(), &sealed].concat()
    }

    /// An accept of `request` to its requester `to` (static key `to_static`, of `version`) sealing
    /// `plaintext`, filled with zeros to the smallest mail size it fits (cut to the largest).
    pub(crate) fn accept(
        request: &PendingRequest,
        to: &PublicIdentity,
        to_static: &EncapsulationKey,
        version: u32,
        plaintext: &[u8],
    ) -> Vec<u8> {
        let tag_key = accept_tag_key(&request.secret, &request.transcript).expect("32 bytes");
        let tag = new_tag(&tag_key, &mut OsRng).expect("randomness");
        let (secret, ciphertext) = to_static.encapsulate().expect("a valid key");
        let transcript = accept_transcript(&request.transcript, to, version, &ciphertext);
        let key = kdf::derive(
            b"",
            secret.expose(),
            &[labels::MAIL_ACCEPT_KEY, &transcript, &tag].concat(),
        )
        .expect("32 bytes");
        let room = |size: usize| size - MAIL_HEADER_LEN - aead::TAG_LEN;
        let size = MAIL_SIZES
            .into_iter()
            .find(|&size| plaintext.len() <= room(size))
            .unwrap_or(MAIL_SIZES[2]);
        let mut padded = plaintext.to_vec();
        padded.resize(room(size), 0);
        let sealed = ChaCha20Poly1305::seal(&key, &ZERO_NONCE, &[], &padded).expect("a fitting plaintext");
        [&tag[..], &version.to_be_bytes(), ciphertext.as_bytes(), &sealed].concat()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat::ChatMessage;

    struct Account {
        identity: Identity,
        static_key: DecapsulationKey,
        server: &'static str,
        name: &'static str,
        delivery_key: SecretBytes<32>,
    }

    impl Account {
        fn new(byte: u8, server: &'static str, name: &'static str) -> Self {
            Self {
                identity: Identity::from_seed(SecretBytes::from_slice(&[byte; 32]).unwrap()),
                static_key: DecapsulationKey::from_seed(SecretBytes::from_slice(&[byte ^ 0xff; 32]).unwrap()).unwrap(),
                server,
                name,
                delivery_key: SecretBytes::from_slice(&[byte ^ 0x0f; 32]).unwrap(),
            }
        }

        fn signed_static_key(&self) -> SignedStaticKey {
            SignedStaticKey::new(&self.identity, 3, self.static_key.encapsulation_key())
        }

        fn peer(&self) -> Peer {
            Peer {
                server: self.server.into(),
                name: self.name.into(),
                identity: self.identity.public(),
                static_key: self.signed_static_key(),
            }
        }

        fn card(&self) -> Card {
            Card {
                server: self.server.into(),
                name: self.name.into(),
                identity: self.identity.public(),
                static_key: self.signed_static_key(),
                delivery_key: self.delivery_key.clone(),
            }
        }
    }

    fn pair_up(a: &Account, b: &Account) -> (SecretBytes<32>, SecretBytes<32>) {
        let (request, pending) = request(&a.identity, &a.card(), &b.peer()).unwrap();
        assert_eq!(request.len(), REQUEST_LEN);
        assert_eq!(requested_version(&request).unwrap(), 3);
        let incoming = open_request(&b.identity.public(), b.server, b.name, &b.static_key, &request).unwrap();
        assert_eq!(incoming.from.name, a.name);
        assert_eq!(incoming.from.delivery_key.expose(), a.delivery_key.expose());
        let (mail, psk_b) = accept(&b.identity, &b.card(), &incoming).unwrap();
        assert!(is_accept(&pending, &mail));
        assert_eq!(sealed_to(&mail).unwrap(), 3);
        let (card, psk_a) = open_accept(&a.identity.public(), &a.static_key, &pending, &mail).unwrap();
        assert_eq!(card.identity, b.identity.public());
        assert_eq!(card.delivery_key.expose(), b.delivery_key.expose());
        (psk_a, psk_b)
    }

    #[test]
    fn a_request_and_its_accept_give_both_one_pairing_secret() {
        let ayse = Account::new(0xa1, "chat.example.org", "ayse");
        let burak = Account::new(0xb2, "chat.example.org", "burak");
        let (psk_a, psk_b) = pair_up(&ayse, &burak);
        assert_eq!(psk_a.expose(), psk_b.expose());
        // A second pairing gives another secret.
        let (again, _) = pair_up(&ayse, &burak);
        assert_ne!(again.expose(), psk_a.expose());
    }

    #[test]
    fn a_request_opens_only_for_its_recipient() {
        let ayse = Account::new(0xa1, "chat.example.org", "ayse");
        let burak = Account::new(0xb2, "chat.example.org", "burak");
        let cem = Account::new(0xc3, "chat.example.org", "cem");
        let (request, _) = request(&ayse.identity, &ayse.card(), &burak.peer()).unwrap();
        // Another account, or the right one under another name or server.
        assert!(open_request(&cem.identity.public(), cem.server, cem.name, &cem.static_key, &request).is_err());
        assert!(
            open_request(
                &burak.identity.public(),
                burak.server,
                "cem",
                &burak.static_key,
                &request
            )
            .is_err()
        );
        assert!(
            open_request(
                &burak.identity.public(),
                "other.example.org",
                burak.name,
                &burak.static_key,
                &request
            )
            .is_err()
        );
        // Any changed byte.
        for at in [0, 10, 2000, REQUEST_LEN - 1] {
            let mut tampered = request.clone();
            tampered[at] ^= 1;
            assert!(
                open_request(
                    &burak.identity.public(),
                    burak.server,
                    burak.name,
                    &burak.static_key,
                    &tampered
                )
                .is_err()
            );
        }
    }

    #[test]
    fn a_card_cannot_claim_another_identity() {
        let ayse = Account::new(0xa1, "chat.example.org", "ayse");
        let burak = Account::new(0xb2, "chat.example.org", "burak");
        let mut card = ayse.card();
        card.identity = burak.identity.public();
        assert!(request(&ayse.identity, &card, &burak.peer()).is_err());
        // Nor ask oneself, nor trust a static key its owner did not sign.
        assert!(request(&ayse.identity, &ayse.card(), &ayse.peer()).is_err());
        let mut peer = burak.peer();
        peer.static_key.version = 4;
        assert!(request(&ayse.identity, &ayse.card(), &peer).is_err());
    }

    #[test]
    fn an_accept_answers_only_its_request() {
        let ayse = Account::new(0xa1, "chat.example.org", "ayse");
        let burak = Account::new(0xb2, "chat.example.org", "burak");
        let (first, pending_first) = request(&ayse.identity, &ayse.card(), &burak.peer()).unwrap();
        let (_, pending_second) = request(&ayse.identity, &ayse.card(), &burak.peer()).unwrap();
        let incoming = open_request(
            &burak.identity.public(),
            burak.server,
            burak.name,
            &burak.static_key,
            &first,
        )
        .unwrap();
        let (mail, _) = accept(&burak.identity, &burak.card(), &incoming).unwrap();
        assert!(!is_accept(&pending_second, &mail));
        assert!(open_accept(&ayse.identity.public(), &ayse.static_key, &pending_second, &mail).is_err());
        // An accept from someone else than asked is refused.
        let cem = Account::new(0xc3, "chat.example.org", "cem");
        let (_, pending_cem) = request(&ayse.identity, &ayse.card(), &cem.peer()).unwrap();
        let forged = IncomingRequest {
            from: ayse.card(),
            secret: pending_cem.secret.clone(),
            transcript: pending_cem.transcript,
        };
        let (mail, _) = accept(&burak.identity, &burak.card(), &forged).unwrap();
        assert!(is_accept(&pending_cem, &mail));
        assert!(open_accept(&ayse.identity.public(), &ayse.static_key, &pending_cem, &mail).is_err());
        assert!(open_accept(&ayse.identity.public(), &ayse.static_key, &pending_first, &mail).is_err());
    }

    #[test]
    fn mail_between_contacts() {
        let ayse = Account::new(0xa1, "chat.example.org", "ayse");
        let burak = Account::new(0xb2, "chat.example.org", "burak");
        let (psk, _) = pair_up(&ayse, &burak);
        let (a, b) = (ayse.identity.public(), burak.identity.public());
        let a_to_b = Pair {
            from: &a,
            to: &b,
            psk: &psk,
        };
        let b_to_a = Pair {
            from: &b,
            to: &a,
            psk: &psk,
        };
        let prekey = DecapsulationKey::from_seed(SecretBytes::from_slice(&[0x7a; 32]).unwrap()).unwrap();
        let text = ChatMessage::Text {
            id: [9; 16],
            sent_at_ms: 1,
            text: "merhaba".into(),
        }
        .encode()
        .unwrap();
        let mail = seal(&a_to_b, prekey.encapsulation_key(), 7, &text).unwrap();
        assert_eq!(mail.len(), MAIL_SIZES[0]);
        assert_eq!(sealed_to(&mail).unwrap(), 7);
        assert!(tag_matches(&tag_key(&a_to_b).unwrap(), &mail));
        assert!(!tag_matches(&tag_key(&b_to_a).unwrap(), &mail));
        assert_eq!(&open(&a_to_b, &prekey, &mail).unwrap()[..], &text[..]);
        // Not with another key, nor as from the other side.
        assert!(open(&a_to_b, &burak.static_key, &mail).is_err());
        assert!(open(&b_to_a, &prekey, &mail).is_err());
        // Two pieces of mail never share a tag.
        let again = seal(&a_to_b, prekey.encapsulation_key(), 7, &text).unwrap();
        assert_ne!(mail[..TAG_LEN], again[..TAG_LEN]);
        // Sizes: the smallest that fits, up to the largest payload.
        for (len, size) in [(800, 2048), (1000, 4096), (MAX_PAYLOAD, 16_384)] {
            let mail = seal(&b_to_a, ayse.static_key.encapsulation_key(), STATIC_KEY, &vec![1; len]).unwrap();
            assert_eq!(mail.len(), size);
            assert_eq!(open(&b_to_a, &ayse.static_key, &mail).unwrap().len(), len);
        }
        assert_eq!(
            seal(
                &b_to_a,
                ayse.static_key.encapsulation_key(),
                STATIC_KEY,
                &vec![1; MAX_PAYLOAD + 1]
            ),
            Err(MailError::TooLong)
        );
    }

    #[test]
    fn group_mail() {
        let epoch_key = SecretBytes::from_slice(&[0x5a; 32]).unwrap();
        let ack = ChatMessage::GroupAck {
            group_id: [1; 16],
            message_id: [2; 16],
        }
        .encode()
        .unwrap();
        let mail = seal_group(&epoch_key, &[1; 16], 3, &ack).unwrap();
        assert_eq!(mail.len(), MAIL_SIZES[0]);
        assert!(tag_matches(&group_tag_key(&epoch_key, &[1; 16], 3).unwrap(), &mail));
        assert_eq!(&open_group(&epoch_key, &[1; 16], 3, &mail).unwrap()[..], &ack[..]);
        // Bound to the group and the epoch, and to the key.
        for (group_id, epoch) in [([9; 16], 3), ([1; 16], 4)] {
            assert!(!tag_matches(
                &group_tag_key(&epoch_key, &group_id, epoch).unwrap(),
                &mail
            ));
            assert!(open_group(&epoch_key, &group_id, epoch, &mail).is_err());
        }
        let other = SecretBytes::from_slice(&[0x5b; 32]).unwrap();
        assert!(!tag_matches(&group_tag_key(&other, &[1; 16], 3).unwrap(), &mail));
        assert!(open_group(&other, &[1; 16], 3, &mail).is_err());
        // Each piece has a tag of its own.
        let again = seal_group(&epoch_key, &[1; 16], 3, &ack).unwrap();
        assert_ne!(mail[..TAG_LEN], again[..TAG_LEN]);
        // The largest update part in mail fits both kinds of mail.
        let part = ChatMessage::UpdatePart {
            update_id: [3; 16],
            index: 0,
            count: 1,
            data: vec![4; MAIL_PART_LEN],
        }
        .encode()
        .unwrap();
        assert!(part.len() <= MAX_PAYLOAD);
        let mail = seal_group(&epoch_key, &[1; 16], 3, &part).unwrap();
        assert_eq!(mail.len(), MAIL_SIZES[2]);
        assert_eq!(&open_group(&epoch_key, &[1; 16], 3, &mail).unwrap()[..], &part[..]);
        let room = MAIL_SIZES[2] - TAG_LEN - aead::TAG_LEN - 2;
        assert!(seal_group(&epoch_key, &[1; 16], 3, &vec![1; room]).is_ok());
        assert_eq!(
            seal_group(&epoch_key, &[1; 16], 3, &vec![1; room + 1]),
            Err(MailError::TooLong)
        );
    }

    /// `tests/vectors/group_mail.json`; `check_group_mail.py` re-derives it from §16.
    #[test]
    fn published_group_mail_vector() {
        use crate::{
            crypto::test_util::{DeterministicRng, check_vector, to_hex},
            group::{Content, seal_message_from},
        };
        let epoch_key = SecretBytes::from_slice(&[0x51; 32]).unwrap();
        let (group_id, epoch) = ([0x67; 16], 5);
        let sender = Identity::from_seed(SecretBytes::from_slice(&[2; 32]).unwrap());
        let dk = Zeroizing::new([0x5e; 32]);
        let message = seal_message_from(
            &group_id,
            epoch,
            &epoch_key,
            &[0x14; 16],
            &sender,
            1_791_400_180_000,
            &Content::DeliveryKey(dk.clone()),
            &mut DeterministicRng::new([0x31; 32]),
        )
        .unwrap();
        let record = ChatMessage::GroupMessage(message).encode().unwrap();
        let mail = seal_group_from(
            &epoch_key,
            &group_id,
            epoch,
            &record,
            &mut DeterministicRng::new([0x32; 32]),
        )
        .unwrap();
        assert_eq!(
            &open_group(&epoch_key, &group_id, epoch, &mail).unwrap()[..],
            &record[..]
        );
        let tag_key = group_tag_key(&epoch_key, &group_id, epoch).unwrap();
        assert!(tag_matches(&tag_key, &mail));
        let tag: [u8; TAG_LEN] = mail[..TAG_LEN].try_into().unwrap();
        let key = group_seal_key(&epoch_key, &group_id, epoch, &tag).unwrap();
        let fields = [
            ("epoch_key", to_hex(epoch_key.expose())),
            ("group_id", to_hex(&group_id)),
            ("epoch", epoch.to_string()),
            ("sender_seed", to_hex(&[2; 32])),
            ("delivery_key", to_hex(&dk[..])),
            ("message_rng_seed", to_hex(&[0x31; 32])),
            ("record", to_hex(&record)),
            ("tag_rng_seed", to_hex(&[0x32; 32])),
            ("tag_key", to_hex(tag_key.expose())),
            ("tag", to_hex(&tag)),
            ("key", to_hex(key.expose())),
            ("mail", to_hex(&mail)),
        ];
        check_vector("group_mail", &fields);
    }

    #[test]
    fn published_mail_vector() {
        use crate::{
            account::Request,
            crypto::test_util::{DeterministicRng, check_vector, to_hex},
        };
        let ayse = Account::new(0xa1, "chat.example.org", "ayse");
        let burak = Account::new(0xb2, "chat.example.org", "burak");
        let (a, b) = (ayse.identity.public(), burak.identity.public());
        let (request, pending) = request_from(
            &ayse.identity,
            &ayse.card(),
            &burak.peer(),
            &mut DeterministicRng::new([0x11; 32]),
        )
        .unwrap();
        let incoming = open_request(&b, burak.server, burak.name, &burak.static_key, &request).unwrap();
        let (accept, psk) = accept_from(
            &burak.identity,
            &burak.card(),
            &incoming,
            &mut DeterministicRng::new([0x22; 32]),
        )
        .unwrap();
        let (_, psk_a) = open_accept(&a, &ayse.static_key, &pending, &accept).unwrap();
        assert_eq!(psk.expose(), psk_a.expose());
        let accept_ss = ayse
            .static_key
            .decapsulate(&Ciphertext::from_bytes(&accept[36..36 + CIPHERTEXT_LEN]).unwrap())
            .unwrap();

        let a_to_b = Pair {
            from: &a,
            to: &b,
            psk: &psk,
        };
        let b_to_a = Pair {
            from: &b,
            to: &a,
            psk: &psk,
        };
        let prekey = DecapsulationKey::from_seed(SecretBytes::from_slice(&[0x7a; 32]).unwrap()).unwrap();
        let text = ChatMessage::Text {
            id: [0x0f; 16],
            sent_at_ms: 1_794_600_000_000,
            text: "posta kutusundan selam".into(),
        }
        .encode()
        .unwrap();
        let mail = seal_from(
            &a_to_b,
            prekey.encapsulation_key(),
            7,
            &text,
            &mut DeterministicRng::new([0x33; 32]),
        )
        .unwrap();
        let mail_ss = prekey
            .decapsulate(&Ciphertext::from_bytes(&mail[36..36 + CIPHERTEXT_LEN]).unwrap())
            .unwrap();
        let ack = ChatMessage::Ack { id: [0x0f; 16] }.encode().unwrap();
        let ack_mail = seal_from(
            &b_to_a,
            ayse.static_key.encapsulation_key(),
            STATIC_KEY,
            &ack,
            &mut DeterministicRng::new([0x44; 32]),
        )
        .unwrap();
        let ack_ss = ayse
            .static_key
            .decapsulate(&Ciphertext::from_bytes(&ack_mail[36..36 + CIPHERTEXT_LEN]).unwrap())
            .unwrap();
        let delivery_key = ChatMessage::DeliveryKey(Zeroizing::new([0x0d; 32])).encode().unwrap();

        let deposit = Request::Deposit {
            name: burak.name.into(),
            delivery_key: burak.delivery_key.clone(),
            mail: mail.clone(),
        }
        .encode();
        let deposit_request = Request::DepositRequest {
            name: burak.name.into(),
            request: request.clone(),
        }
        .encode();
        let mail_frame = ServerFrame::Mail {
            id: 42,
            mail: mail.clone(),
        }
        .encode();
        let taken_frame = DeviceFrame::Taken { id: 42 }.encode();

        let fields = [
            ("server", burak.server.to_owned()),
            ("name_a", ayse.name.to_owned()),
            ("name_b", burak.name.to_owned()),
            ("ik_seed_a", to_hex(ayse.identity.seed().expose())),
            ("ik_seed_b", to_hex(burak.identity.seed().expose())),
            ("ik_a", to_hex(a.as_bytes())),
            ("ik_b", to_hex(b.as_bytes())),
            ("static_version", "3".to_owned()),
            ("sk_a", to_hex(ayse.static_key.encapsulation_key().as_bytes())),
            ("sk_b", to_hex(burak.static_key.encapsulation_key().as_bytes())),
            ("sk_signature_a", to_hex(&ayse.signed_static_key().signature)),
            ("sk_signature_b", to_hex(&burak.signed_static_key().signature)),
            ("dk_a", to_hex(ayse.delivery_key.expose())),
            ("dk_b", to_hex(burak.delivery_key.expose())),
            ("request_rng_seed", to_hex(&[0x11; 32])),
            ("request_ss", to_hex(pending.secret.expose())),
            ("request_transcript", to_hex(&pending.transcript)),
            ("request", to_hex(&request)),
            ("accept_rng_seed", to_hex(&[0x22; 32])),
            ("accept_ss", to_hex(accept_ss.expose())),
            ("accept", to_hex(&accept)),
            ("psk", to_hex(psk.expose())),
            ("tag_key_a_to_b", to_hex(tag_key(&a_to_b).unwrap().expose())),
            ("prekey", "7".to_owned()),
            ("prekey_key", to_hex(prekey.encapsulation_key().as_bytes())),
            ("text_payload", to_hex(&text)),
            ("mail_rng_seed", to_hex(&[0x33; 32])),
            ("mail_ss", to_hex(mail_ss.expose())),
            ("mail", to_hex(&mail)),
            ("ack_payload", to_hex(&ack)),
            ("ack_rng_seed", to_hex(&[0x44; 32])),
            ("ack_ss", to_hex(ack_ss.expose())),
            ("ack_mail", to_hex(&ack_mail)),
            ("delivery_key_record", to_hex(&delivery_key)),
            ("delivery_key_hash_b", to_hex(&delivery_key_hash(&burak.delivery_key))),
            ("deposit", to_hex(&deposit)),
            ("deposit_request", to_hex(&deposit_request)),
            ("mail_frame", to_hex(&mail_frame)),
            ("taken_frame", to_hex(&taken_frame)),
        ];
        check_vector("mail", &fields);
    }

    /// The fuzzing builders reach the parsers behind the AEAD: a real card in them opens.
    #[test]
    fn fuzzing_builders_reach_the_card() {
        let ayse = Account::new(0xa1, "chat.example.org", "ayse");
        let burak = Account::new(0xb2, "chat.example.org", "burak");
        let b = burak.identity.public();
        // The card goes in as plaintext; its proof cannot match the builder's transcript, so the
        // parse runs to the signature check and stops there.
        let signed = ayse
            .card()
            .sign(&ayse.identity, labels::MAIL_REQUEST_PROOF, &[0; 32])
            .unwrap();
        let card = pad(&signed, signed.len() + 2).unwrap();
        let sealed = fuzzing::request(
            burak.server,
            burak.name,
            &b,
            burak.static_key.encapsulation_key(),
            3,
            &card,
        );
        assert_eq!(
            open_request(&b, burak.server, burak.name, &burak.static_key, &sealed).unwrap_err(),
            MailError::DoesNotOpen,
            "decrypted and parsed, refused at the proof"
        );
        let garbage = fuzzing::request(
            burak.server,
            burak.name,
            &b,
            burak.static_key.encapsulation_key(),
            3,
            &[0xff; 3],
        );
        assert_eq!(
            open_request(&b, burak.server, burak.name, &burak.static_key, &garbage).unwrap_err(),
            MailError::Malformed,
            "decrypted, refused by the padding"
        );
        let (_, pending) = request(&ayse.identity, &ayse.card(), &burak.peer()).unwrap();
        let a = ayse.identity.public();
        let accept = fuzzing::accept(&pending, &a, ayse.static_key.encapsulation_key(), 3, &card);
        assert!(is_accept(&pending, &accept));
        assert_eq!(
            open_accept(&a, &ayse.static_key, &pending, &accept).unwrap_err(),
            MailError::DoesNotOpen
        );
    }

    #[test]
    fn frames_round_trip() {
        let mail = vec![5; 2048];
        for frame in [
            ServerFrame::Challenge { nonce: [1; 32] },
            ServerFrame::Done,
            ServerFrame::Mail {
                id: 42,
                mail: mail.clone(),
            },
            ServerFrame::Request {
                id: 43,
                request: vec![6; REQUEST_LEN],
            },
        ] {
            let bytes = frame.encode();
            assert_eq!(ServerFrame::decode(&bytes).unwrap().encode(), bytes);
        }
        assert!(ServerFrame::decode(&[0, MAIL_FRAME, 0, 0, 0, 0, 0, 0, 0, 1, 5]).is_err());
        let taken = DeviceFrame::Taken { id: 7 }.encode();
        assert!(matches!(DeviceFrame::decode(&taken), Ok(DeviceFrame::Taken { id: 7 })));
        assert!(DeviceFrame::decode(&[0, TAKEN_FRAME, 1]).is_err());
    }
}
