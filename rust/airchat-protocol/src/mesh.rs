//! The mesh (docs/protocol.md §10): envelopes that other AirChat devices pass on, sealed for their
//! recipients and addressed with tags only they recognise. Formats and cryptography only; passing
//! envelopes on lives in the node.

use zeroize::Zeroizing;

use crate::{
    chat::{MAX_UPDATE_PARTS, UPDATE_PART_LEN},
    crypto::{
        CryptoError, SecretBytes,
        aead::ChaCha20Poly1305,
        hash::{hmac_sha256, sha256},
        kdf,
        kem::{CIPHERTEXT_LEN, Ciphertext, DecapsulationKey, EncapsulationKey},
        random::{OsRng, Rng},
    },
    identity::PublicIdentity,
    labels,
};

pub const ENVELOPE_ID_LEN: usize = 16;
pub type EnvelopeId = [u8; ENVELOPE_ID_LEN];
pub const SHORT_ID_LEN: usize = 8;
pub type ShortId = [u8; SHORT_ID_LEN];
pub const TAG_LEN: usize = 16;
pub type MeshTag = [u8; TAG_LEN];
/// Commits to the secret that withdraws an envelope (§10.4).
pub type DropTag = [u8; 16];
pub type DropSecret = [u8; 16];
/// The drop of an envelope that cannot be withdrawn: a group's.
pub const NO_DROP: DropTag = [0; 16];
/// Largest file whose content goes through the mesh (§10.8), and the bytes of it one part carries
/// (a storage chunk).
pub const MAX_MESH_FILE: u64 = 1 << 20;
pub const FILE_PART_LEN: usize = 15 * 1024;
/// How many times an envelope may be passed on, at most.
pub const MAX_HOPS: u8 = 8;
/// How far ahead an envelope may expire, in minutes.
pub const MAX_LIFETIME_MINUTES: u32 = 24 * 60;
pub const MAX_BODY: usize = 15_872;
/// Short ids in one *have* record, at most.
pub const MAX_HAVE: usize = 1024;
const HEADER_LEN: usize = ENVELOPE_ID_LEN + 1 + 4 + TAG_LEN + 16;
const PAD_TO: usize = 256;
const ZERO_NONCE: [u8; 12] = [0; 12];

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MeshError {
    #[error("malformed envelope")]
    Malformed,
    #[error("the envelope does not open")]
    DoesNotOpen,
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// An envelope as it travels (§10.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub id: EnvelopeId,
    pub hops: u8,
    /// Unix time in minutes after which nobody passes it on.
    pub expires: u32,
    pub tag: MeshTag,
    /// Lets the sender withdraw it once delivered; [`NO_DROP`] if it cannot be.
    pub drop: DropTag,
    pub body: Vec<u8>,
}

/// What the seal of a 1:1 envelope binds besides its payload: everything but the hops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub id: EnvelopeId,
    pub expires: u32,
    pub tag: MeshTag,
    pub drop: DropTag,
}

impl Envelope {
    pub fn encode(&self) -> Result<Vec<u8>, MeshError> {
        if !(1..=MAX_BODY).contains(&self.body.len()) {
            return Err(MeshError::Malformed);
        }
        Ok([
            &self.id[..],
            &[self.hops],
            &self.expires.to_be_bytes(),
            &self.tag,
            &self.drop,
            &self.body,
        ]
        .concat())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, MeshError> {
        if bytes.len() <= HEADER_LEN || bytes.len() > HEADER_LEN + MAX_BODY {
            return Err(MeshError::Malformed);
        }
        let (id, rest) = bytes
            .split_first_chunk::<ENVELOPE_ID_LEN>()
            .ok_or(MeshError::Malformed)?;
        let (&hops, rest) = rest.split_first().ok_or(MeshError::Malformed)?;
        let (expires, rest) = rest.split_first_chunk::<4>().ok_or(MeshError::Malformed)?;
        let (tag, rest) = rest.split_first_chunk::<TAG_LEN>().ok_or(MeshError::Malformed)?;
        let (drop, body) = rest.split_first_chunk::<16>().ok_or(MeshError::Malformed)?;
        Ok(Self {
            id: *id,
            hops,
            expires: u32::from_be_bytes(*expires),
            tag: *tag,
            drop: *drop,
            body: body.to_vec(),
        })
    }

    pub fn short_id(&self) -> ShortId {
        short_id(&self.id)
    }

    pub fn header(&self) -> Header {
        Header {
            id: self.id,
            expires: self.expires,
            tag: self.tag,
            drop: self.drop,
        }
    }
}

pub fn short_id(id: &EnvelopeId) -> ShortId {
    id[..SHORT_ID_LEN]
        .try_into()
        .expect("an id is longer than its short form")
}

/// The key of the tags on envelopes from contact `from` to contact `to`.
pub fn contact_tag_key(
    psk: &SecretBytes<32>,
    from: &PublicIdentity,
    to: &PublicIdentity,
) -> Result<SecretBytes<32>, CryptoError> {
    let info = [labels::MESH_TAG_KEY, from.as_bytes(), to.as_bytes()].concat();
    kdf::derive(&[], psk.expose(), &info)
}

/// The key of the tags on envelopes for a group, in one of its epochs.
pub fn group_tag_key(
    epoch_key: &SecretBytes<32>,
    group_id: &[u8; 16],
    group_epoch: u64,
) -> Result<SecretBytes<32>, CryptoError> {
    let info = [labels::MESH_GROUP_TAG_KEY, group_id, &group_epoch.to_be_bytes()].concat();
    kdf::derive(&[], epoch_key.expose(), &info)
}

/// The tag for `epoch` (an hour, as presence tokens).
pub fn tag(tag_key: &SecretBytes<32>, epoch: u64) -> MeshTag {
    hmac_sha256(tag_key.expose(), &[labels::MESH_TAG, &epoch.to_be_bytes()]).expose()[..TAG_LEN]
        .try_into()
        .expect("a MAC is longer than a tag")
}

/// The id of an envelope carrying a 1:1 record of `kind` about `message_id`: the same each time
/// it is sent again.
pub fn contact_envelope_id(from: &PublicIdentity, to: &PublicIdentity, kind: u8, message_id: &[u8; 16]) -> EnvelopeId {
    sha256(&[
        labels::MESH_ENVELOPE,
        from.as_bytes(),
        to.as_bytes(),
        &[kind],
        message_id,
    ])[..ENVELOPE_ID_LEN]
        .try_into()
        .expect("a hash is longer than an id")
}

pub fn group_envelope_id(group_id: &[u8; 16], message_id: &[u8; 16]) -> EnvelopeId {
    sha256(&[labels::MESH_ENVELOPE, group_id, message_id])[..ENVELOPE_ID_LEN]
        .try_into()
        .expect("a hash is longer than an id")
}

/// The secret that withdraws the 1:1 envelope `id` from contact `from` to contact `to`: only the
/// two contacts can make it.
pub fn drop_secret(
    psk: &SecretBytes<32>,
    from: &PublicIdentity,
    to: &PublicIdentity,
    id: &EnvelopeId,
) -> Result<DropSecret, CryptoError> {
    let info = [labels::MESH_DROP_SECRET, from.as_bytes(), to.as_bytes(), id].concat();
    let secret: SecretBytes<32> = kdf::derive(&[], psk.expose(), &info)?;
    Ok(secret.expose()[..16].try_into().expect("a key is longer than a secret"))
}

/// What an envelope carries to commit to its drop secret.
pub fn drop_tag(secret: &DropSecret) -> DropTag {
    sha256(&[labels::MESH_DROP, secret])[..16]
        .try_into()
        .expect("a hash is longer than a drop")
}

/// The key of the tags on file parts from contact `from` to contact `to` (§10.8).
pub fn file_tag_key(
    psk: &SecretBytes<32>,
    from: &PublicIdentity,
    to: &PublicIdentity,
) -> Result<SecretBytes<32>, CryptoError> {
    let info = [labels::MESH_FILE_TAG_KEY, from.as_bytes(), to.as_bytes()].concat();
    kdf::derive(&[], psk.expose(), &info)
}

/// The id of part `index` of the file `message_id` from `from` to `to`.
pub fn file_part_id(from: &PublicIdentity, to: &PublicIdentity, message_id: &[u8; 16], index: u32) -> EnvelopeId {
    sha256(&[
        labels::MESH_FILE_PART,
        from.as_bytes(),
        to.as_bytes(),
        message_id,
        &index.to_be_bytes(),
    ])[..ENVELOPE_ID_LEN]
        .try_into()
        .expect("a hash is longer than an id")
}

/// How many parts a file of `size` bytes goes in.
pub fn file_parts(size: u64) -> u32 {
    u32::try_from(size.div_ceil(FILE_PART_LEN as u64)).unwrap_or(u32::MAX)
}

fn part_nonce(index: u32) -> [u8; 12] {
    let mut nonce = [0; 12];
    nonce[8..].copy_from_slice(&index.to_be_bytes());
    nonce
}

fn part_aad(header: &Header) -> Vec<u8> {
    [&header.id[..], &header.expires.to_be_bytes(), &header.drop].concat()
}

/// The body of file part `index`: its bytes, padded, encrypted with the file's key.
pub fn seal_part(key: &SecretBytes<32>, header: &Header, index: u32, bytes: &[u8]) -> Result<Vec<u8>, MeshError> {
    if bytes.len() > FILE_PART_LEN {
        return Err(MeshError::Malformed);
    }
    let padded = pad_part(bytes)?;
    Ok(ChaCha20Poly1305::seal(
        key,
        &part_nonce(index),
        &part_aad(header),
        &padded,
    )?)
}

/// The bytes of file part `index` in `envelope`, with the file's key.
pub fn open_part(key: &SecretBytes<32>, envelope: &Envelope, index: u32) -> Result<Zeroizing<Vec<u8>>, MeshError> {
    let padded = ChaCha20Poly1305::open(key, &part_nonce(index), &part_aad(&envelope.header()), &envelope.body)
        .map_err(|_| MeshError::DoesNotOpen)?;
    unpad_part(&padded)
}

/// The key of the tags on a group's file parts in epoch `group_epoch` (§10.10).
pub fn group_file_tag_key(
    epoch_key: &SecretBytes<32>,
    group_id: &[u8; 16],
    group_epoch: u64,
) -> Result<SecretBytes<32>, CryptoError> {
    let info = [labels::MESH_GROUP_FILE_TAG_KEY, group_id, &group_epoch.to_be_bytes()].concat();
    kdf::derive(&[], epoch_key.expose(), &info)
}

/// The key of the parts of the group file of message `message_id`, sent in epoch `group_epoch`.
pub fn group_file_key(
    epoch_key: &SecretBytes<32>,
    group_id: &[u8; 16],
    group_epoch: u64,
    message_id: &[u8; 16],
) -> Result<SecretBytes<32>, CryptoError> {
    let info = [
        labels::MESH_GROUP_FILE_KEY,
        group_id,
        &group_epoch.to_be_bytes(),
        message_id,
    ]
    .concat();
    kdf::derive(&[], epoch_key.expose(), &info)
}

/// The id of part `index` of the group file of message `message_id`.
pub fn group_file_part_id(group_id: &[u8; 16], message_id: &[u8; 16], index: u32) -> EnvelopeId {
    sha256(&[labels::MESH_GROUP_FILE_PART, group_id, message_id, &index.to_be_bytes()])[..ENVELOPE_ID_LEN]
        .try_into()
        .expect("a hash is longer than an id")
}

/// The body of group file part `index` (envelope `id`): its bytes, padded, encrypted.
pub fn seal_group_file_part(
    key: &SecretBytes<32>,
    id: &EnvelopeId,
    index: u32,
    bytes: &[u8],
) -> Result<Vec<u8>, MeshError> {
    if bytes.len() > FILE_PART_LEN {
        return Err(MeshError::Malformed);
    }
    let padded = pad_part(bytes)?;
    Ok(ChaCha20Poly1305::seal(key, &part_nonce(index), id, &padded)?)
}

/// The bytes of group file part `index` in `envelope`.
pub fn open_group_file_part(
    key: &SecretBytes<32>,
    envelope: &Envelope,
    index: u32,
) -> Result<Zeroizing<Vec<u8>>, MeshError> {
    let padded = ChaCha20Poly1305::open(key, &part_nonce(index), &envelope.id, &envelope.body)
        .map_err(|_| MeshError::DoesNotOpen)?;
    unpad_part(&padded)
}

/// A part's bytes, their length first, padded to a multiple of 256 bytes.
fn pad_part(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, MeshError> {
    let len = u16::try_from(bytes.len()).map_err(|_| MeshError::Malformed)?;
    let mut padded = Zeroizing::new(Vec::with_capacity(bytes.len() + PAD_TO));
    padded.extend_from_slice(&len.to_be_bytes());
    padded.extend_from_slice(bytes);
    let padded_len = padded.len().div_ceil(PAD_TO) * PAD_TO;
    padded.resize(padded_len, 0);
    Ok(padded)
}

pub(crate) fn unpad_part(padded: &[u8]) -> Result<Zeroizing<Vec<u8>>, MeshError> {
    let (len, rest) = padded.split_first_chunk::<2>().ok_or(MeshError::Malformed)?;
    let len = usize::from(u16::from_be_bytes(*len));
    if len > rest.len() || len > FILE_PART_LEN || rest[len..].iter().any(|&b| b != 0) {
        return Err(MeshError::Malformed);
    }
    Ok(Zeroizing::new(rest[..len].to_vec()))
}

/// The keys of the mesh copies of a group's update of epoch `epoch` (§10.9), from the key of the
/// epoch before (the group's own for epoch 0): `tag_key` for their tags, `base` for their content.
pub struct UpdateKeys {
    pub tag_key: SecretBytes<32>,
    pub base: SecretBytes<32>,
}

pub fn update_keys(epoch_key: &SecretBytes<32>, group_id: &[u8; 16], epoch: u64) -> Result<UpdateKeys, CryptoError> {
    let derive = |label: &[u8]| {
        kdf::derive(
            &[],
            epoch_key.expose(),
            &[label, group_id, &epoch.to_be_bytes()].concat(),
        )
    };
    Ok(UpdateKeys {
        tag_key: derive(labels::MESH_UPDATE_TAG_KEY)?,
        base: derive(labels::MESH_UPDATE_KEY)?,
    })
}

/// The key of the parts of update `update_id`.
pub fn update_part_key(base: &SecretBytes<32>, update_id: &[u8; 16]) -> Result<SecretBytes<32>, CryptoError> {
    kdf::derive(&[], base.expose(), &[labels::MESH_UPDATE_PART_KEY, update_id].concat())
}

/// The id of part `index` of update `update_id` of group `group_id`.
pub fn update_part_id(group_id: &[u8; 16], update_id: &[u8; 16], index: u16) -> EnvelopeId {
    sha256(&[labels::MESH_UPDATE_PART, group_id, update_id, &index.to_be_bytes()])[..ENVELOPE_ID_LEN]
        .try_into()
        .expect("a hash is longer than an id")
}

/// What an update part's body says in the clear: which update, which part, of how many.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpdatePart {
    pub update_id: [u8; 16],
    pub index: u16,
    pub count: u16,
}

const UPDATE_PART_HEADER: usize = 16 + 2 + 2;

impl UpdatePart {
    fn encode(&self) -> [u8; UPDATE_PART_HEADER] {
        let mut header = [0; UPDATE_PART_HEADER];
        header[..16].copy_from_slice(&self.update_id);
        header[16..18].copy_from_slice(&self.index.to_be_bytes());
        header[18..].copy_from_slice(&self.count.to_be_bytes());
        header
    }

    /// The clear part of an update part envelope's body.
    pub fn read(envelope: &Envelope) -> Result<Self, MeshError> {
        let header: &[u8; UPDATE_PART_HEADER] = envelope.body.first_chunk().ok_or(MeshError::Malformed)?;
        let part = Self {
            update_id: header[..16].try_into().expect("16 bytes"),
            index: u16::from_be_bytes([header[16], header[17]]),
            count: u16::from_be_bytes([header[18], header[19]]),
        };
        if !(1..=MAX_UPDATE_PARTS).contains(&part.count) || part.index >= part.count {
            return Err(MeshError::Malformed);
        }
        Ok(part)
    }

    fn aad(&self, id: &EnvelopeId) -> Vec<u8> {
        [&id[..], &self.encode()].concat()
    }
}

/// The body of an update part envelope `id`: `bytes` of the update, padded, encrypted with `key`.
pub fn seal_update_part(
    key: &SecretBytes<32>,
    id: &EnvelopeId,
    part: &UpdatePart,
    bytes: &[u8],
) -> Result<Vec<u8>, MeshError> {
    if bytes.is_empty() || bytes.len() > UPDATE_PART_LEN || !(1..=MAX_UPDATE_PARTS).contains(&part.count) {
        return Err(MeshError::Malformed);
    }
    let padded = pad_part(bytes)?;
    let sealed = ChaCha20Poly1305::seal(key, &part_nonce(u32::from(part.index)), &part.aad(id), &padded)?;
    Ok([&part.encode()[..], &sealed].concat())
}

/// The update bytes in update part `envelope`, with its update's key.
pub fn open_update_part(key: &SecretBytes<32>, envelope: &Envelope) -> Result<(UpdatePart, Vec<u8>), MeshError> {
    let part = UpdatePart::read(envelope)?;
    let padded = ChaCha20Poly1305::open(
        key,
        &part_nonce(u32::from(part.index)),
        &part.aad(&envelope.id),
        &envelope.body[UPDATE_PART_HEADER..],
    )
    .map_err(|_| MeshError::DoesNotOpen)?;
    let bytes = unpad_part(&padded)?;
    if bytes.is_empty() {
        return Err(MeshError::Malformed);
    }
    Ok((part, bytes.to_vec()))
}

/// The two contacts an envelope goes between, and their pairing secret.
pub struct Pair<'a> {
    pub from: &'a PublicIdentity,
    pub to: &'a PublicIdentity,
    pub psk: &'a SecretBytes<32>,
}

/// The prekey that marks a body sealed to the recipient's static key (§10.3).
pub const STATIC_KEY: u32 = 0;

/// Seals a 1:1 record (a §8.1 payload) to one of the recipient's prekeys (`to`, numbered
/// `prekey`), or its static key ([`STATIC_KEY`]), and to the pairing secret.
pub fn seal(
    pair: &Pair,
    to: &EncapsulationKey,
    prekey: u32,
    header: &Header,
    payload: &[u8],
) -> Result<Vec<u8>, MeshError> {
    seal_from(pair, to, prekey, header, payload, &mut OsRng)
}

pub(crate) fn seal_from(
    pair: &Pair,
    to: &EncapsulationKey,
    prekey: u32,
    header: &Header,
    payload: &[u8],
    rng: &mut dyn Rng,
) -> Result<Vec<u8>, MeshError> {
    let len = u16::try_from(payload.len()).map_err(|_| MeshError::Malformed)?;
    let (shared, ciphertext) = to.encapsulate_from(rng)?;
    let key = seal_key(pair, &shared, header, prekey)?;
    let mut padded = Zeroizing::new(Vec::with_capacity(payload.len() + PAD_TO));
    padded.extend_from_slice(&len.to_be_bytes());
    padded.extend_from_slice(payload);
    let padded_len = padded.len().div_ceil(PAD_TO) * PAD_TO;
    padded.resize(padded_len, 0);
    let sealed = ChaCha20Poly1305::seal(&key, &ZERO_NONCE, &[], &padded)?;
    let body = [&prekey.to_be_bytes()[..], &ciphertext.as_bytes()[..], &sealed].concat();
    if body.len() > MAX_BODY {
        return Err(MeshError::Malformed);
    }
    Ok(body)
}

/// The prekey a 1:1 envelope's body is sealed to ([`STATIC_KEY`] for the static key).
pub fn sealed_to(envelope: &Envelope) -> Result<u32, MeshError> {
    let (prekey, _) = envelope.body.split_first_chunk::<4>().ok_or(MeshError::Malformed)?;
    Ok(u32::from_be_bytes(*prekey))
}

/// Opens a 1:1 envelope's body for its recipient with the key it is sealed to ([`sealed_to`]):
/// the payload, or [`MeshError::DoesNotOpen`].
pub fn open(pair: &Pair, own: &DecapsulationKey, envelope: &Envelope) -> Result<Zeroizing<Vec<u8>>, MeshError> {
    let prekey = sealed_to(envelope)?;
    let rest = &envelope.body[4..];
    if rest.len() < CIPHERTEXT_LEN {
        return Err(MeshError::Malformed);
    }
    let (ciphertext, sealed) = rest.split_at(CIPHERTEXT_LEN);
    let shared = own.decapsulate(&Ciphertext::from_bytes(ciphertext)?)?;
    let key = seal_key(pair, &shared, &envelope.header(), prekey)?;
    let padded = ChaCha20Poly1305::open(&key, &ZERO_NONCE, &[], sealed).map_err(|_| MeshError::DoesNotOpen)?;
    let (len, rest) = padded.split_first_chunk::<2>().ok_or(MeshError::Malformed)?;
    let len = usize::from(u16::from_be_bytes(*len));
    if len > rest.len() || rest[len..].iter().any(|&b| b != 0) || padded.len() % PAD_TO != 0 {
        return Err(MeshError::Malformed);
    }
    Ok(Zeroizing::new(rest[..len].to_vec()))
}

fn seal_key(
    pair: &Pair,
    shared: &SecretBytes<32>,
    header: &Header,
    prekey: u32,
) -> Result<SecretBytes<32>, CryptoError> {
    let info = [
        labels::MESH_SEAL,
        pair.from.as_bytes(),
        pair.to.as_bytes(),
        &header.id,
        &header.tag,
        &header.expires.to_be_bytes(),
        &header.drop,
        &prekey.to_be_bytes(),
    ]
    .concat();
    kdf::derive(pair.psk.expose(), shared.expose(), &info)
}

/// The *have* record's body: short ids, newest first.
pub fn encode_have(ids: &[ShortId]) -> Vec<u8> {
    ids.iter().take(MAX_HAVE).flatten().copied().collect()
}

pub fn decode_have(bytes: &[u8]) -> Result<Vec<ShortId>, MeshError> {
    if !bytes.len().is_multiple_of(SHORT_ID_LEN) || bytes.len() > MAX_HAVE * SHORT_ID_LEN {
        return Err(MeshError::Malformed);
    }
    Ok(bytes.as_chunks::<SHORT_ID_LEN>().0.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto::kem::DecapsulationKey, identity::Identity};

    fn identities() -> (PublicIdentity, PublicIdentity) {
        (
            Identity::generate().unwrap().public(),
            Identity::generate().unwrap().public(),
        )
    }

    #[test]
    fn sealed_envelopes_open_only_for_their_recipient() {
        let (ayse, burak) = identities();
        let psk = SecretBytes::random().unwrap();
        let burak_static = DecapsulationKey::generate().unwrap();
        let pair = Pair {
            from: &ayse,
            to: &burak,
            psk: &psk,
        };
        let tag_key = contact_tag_key(&psk, &ayse, &burak).unwrap();
        let tag = tag(&tag_key, 500_000);
        let id = contact_envelope_id(&ayse, &burak, 0x01, &[9; 16]);
        let secret = drop_secret(&psk, &ayse, &burak, &id).unwrap();
        let header = Header {
            id,
            expires: 1_000,
            tag,
            drop: drop_tag(&secret),
        };
        let body = seal(&pair, burak_static.encapsulation_key(), STATIC_KEY, &header, b"merhaba").unwrap();
        assert_eq!((body.len() - 4 - CIPHERTEXT_LEN - 16) % PAD_TO, 0, "padded");
        let envelope = Envelope {
            id,
            hops: MAX_HOPS,
            expires: 1_000,
            tag,
            drop: header.drop,
            body,
        };
        let read = Envelope::decode(&envelope.encode().unwrap()).unwrap();
        assert_eq!(read, envelope);
        assert_eq!(&*open(&pair, &burak_static, &read).unwrap(), b"merhaba");

        // Relays may lower the hops, nothing else.
        let relayed = Envelope {
            hops: 3,
            ..read.clone()
        };
        assert!(open(&pair, &burak_static, &relayed).is_ok());
        let longer = Envelope {
            expires: 2_000,
            ..read.clone()
        };
        assert_eq!(open(&pair, &burak_static, &longer), Err(MeshError::DoesNotOpen));
        let undroppable = Envelope {
            drop: NO_DROP,
            ..read.clone()
        };
        assert_eq!(open(&pair, &burak_static, &undroppable), Err(MeshError::DoesNotOpen));
        // Someone else, or the wrong direction, cannot open it.
        let stranger = DecapsulationKey::generate().unwrap();
        assert!(open(&pair, &stranger, &read).is_err());
        let backwards = Pair {
            from: &burak,
            to: &ayse,
            psk: &psk,
        };
        assert_eq!(open(&backwards, &burak_static, &read), Err(MeshError::DoesNotOpen));
        let other_psk = SecretBytes::random().unwrap();
        let wrong = Pair {
            psk: &other_psk,
            ..pair
        };
        assert_eq!(open(&wrong, &burak_static, &read), Err(MeshError::DoesNotOpen));

        // Sealed to a prekey: only its private half opens it, and the prekey's id is bound too.
        let prekey = DecapsulationKey::generate().unwrap();
        let body = seal(&pair, prekey.encapsulation_key(), 7, &header, b"ileri gizli").unwrap();
        let to_prekey = Envelope { body, ..read.clone() };
        assert_eq!(sealed_to(&to_prekey), Ok(7));
        assert_eq!(&*open(&pair, &prekey, &to_prekey).unwrap(), b"ileri gizli");
        assert_eq!(open(&pair, &burak_static, &to_prekey), Err(MeshError::DoesNotOpen));
        let mut renumbered = to_prekey.clone();
        renumbered.body[3] = 8;
        assert_eq!(open(&pair, &prekey, &renumbered), Err(MeshError::DoesNotOpen));
    }

    #[test]
    fn update_parts_open_only_with_their_key_and_id_and_a_full_one_fits() {
        let (group_id, update_id) = ([4; 16], [5; 16]);
        let keys = update_keys(&SecretBytes::from_slice(&[6; 32]).unwrap(), &group_id, 3).unwrap();
        let key = update_part_key(&keys.base, &update_id).unwrap();
        let part = UpdatePart {
            update_id,
            index: 1,
            count: 2,
        };
        let id = update_part_id(&group_id, &update_id, 1);
        let bytes = vec![7; UPDATE_PART_LEN];
        let body = seal_update_part(&key, &id, &part, &bytes).unwrap();
        assert!(body.len() <= MAX_BODY, "a full part fits");
        let envelope = Envelope {
            id,
            hops: MAX_HOPS,
            expires: 1,
            tag: tag(&keys.tag_key, 9),
            drop: NO_DROP,
            body,
        };
        assert_eq!(UpdatePart::read(&envelope).unwrap(), part);
        assert_eq!(open_update_part(&key, &envelope).unwrap(), (part, bytes));
        let other = update_part_key(&keys.base, &[8; 16]).unwrap();
        assert!(open_update_part(&other, &envelope).is_err(), "another update's key");
        let moved = Envelope {
            id: update_part_id(&group_id, &update_id, 0),
            ..envelope.clone()
        };
        assert!(open_update_part(&key, &moved).is_err(), "another id");
        let next_epoch = update_keys(&SecretBytes::from_slice(&[6; 32]).unwrap(), &group_id, 4).unwrap();
        assert_ne!(next_epoch.tag_key.expose(), keys.tag_key.expose());
        let too_many = UpdatePart { count: 65, ..part };
        assert!(seal_update_part(&key, &id, &too_many, &[1]).is_err());
    }

    #[test]
    fn file_parts_open_only_with_their_key_index_and_header() {
        let (ayse, burak) = identities();
        let key = SecretBytes::random().unwrap();
        let id = file_part_id(&ayse, &burak, &[3; 16], 1);
        assert_ne!(id, file_part_id(&ayse, &burak, &[3; 16], 2));
        let header = Header {
            id,
            expires: 99,
            tag: [4; 16],
            drop: [5; 16],
        };
        let bytes = vec![7; FILE_PART_LEN];
        let body = seal_part(&key, &header, 1, &bytes).unwrap();
        assert!(body.len() <= MAX_BODY, "a full part fits");
        let envelope = Envelope {
            id,
            hops: 3,
            expires: 99,
            tag: [4; 16],
            drop: [5; 16],
            body,
        };
        assert_eq!(&*open_part(&key, &envelope, 1).unwrap(), bytes.as_slice());
        assert_eq!(
            open_part(&key, &envelope, 2),
            Err(MeshError::DoesNotOpen),
            "another index"
        );
        let other = SecretBytes::random().unwrap();
        assert_eq!(open_part(&other, &envelope, 1), Err(MeshError::DoesNotOpen));
        let longer = Envelope {
            expires: 100,
            ..envelope.clone()
        };
        assert_eq!(open_part(&key, &longer, 1), Err(MeshError::DoesNotOpen));
        assert_eq!(file_parts(0), 0);
        assert_eq!(file_parts(FILE_PART_LEN as u64 + 1), 2);
    }

    #[test]
    fn tags_and_ids_depend_on_direction_epoch_and_message() {
        let (ayse, burak) = identities();
        let psk = SecretBytes::random().unwrap();
        let there = contact_tag_key(&psk, &ayse, &burak).unwrap();
        let back = contact_tag_key(&psk, &burak, &ayse).unwrap();
        assert_ne!(tag(&there, 7), tag(&back, 7));
        assert_ne!(tag(&there, 7), tag(&there, 8));
        assert_eq!(tag(&there, 7), tag(&there, 7));
        assert_ne!(
            contact_envelope_id(&ayse, &burak, 1, &[1; 16]),
            contact_envelope_id(&ayse, &burak, 2, &[1; 16])
        );
        assert_ne!(
            group_envelope_id(&[1; 16], &[2; 16]),
            group_envelope_id(&[1; 16], &[3; 16])
        );
        let id = contact_envelope_id(&ayse, &burak, 1, &[1; 16]);
        let secret = drop_secret(&psk, &ayse, &burak, &id).unwrap();
        assert_ne!(secret, drop_secret(&psk, &burak, &ayse, &id).unwrap());
        assert_ne!(drop_tag(&secret), NO_DROP);
    }

    #[test]
    fn envelopes_and_have_lists_check_their_limits() {
        let envelope = |len| Envelope {
            id: [1; 16],
            hops: 8,
            expires: 1,
            tag: [2; 16],
            drop: [4; 16],
            body: vec![3; len],
        };
        assert!(envelope(0).encode().is_err());
        assert!(envelope(MAX_BODY + 1).encode().is_err());
        assert!(Envelope::decode(&envelope(MAX_BODY).encode().unwrap()).is_ok());
        assert!(Envelope::decode(&[0; HEADER_LEN]).is_err());
        let ids: Vec<ShortId> = (0..1100u32).map(|i| [i as u8; 8]).collect();
        let have = encode_have(&ids);
        assert_eq!(have.len(), MAX_HAVE * SHORT_ID_LEN, "cut at the limit");
        assert_eq!(decode_have(&have).unwrap().len(), MAX_HAVE);
        assert!(decode_have(&[0; 9]).is_err());
    }

    /// The published mesh vector (docs/protocol.md §10): tags, ids, a sealed 1:1 envelope, a group
    /// tag, a *have* record and a mesh link handshake. `check_mesh.py` recomputes it.
    #[test]
    fn published_mesh_vector() {
        use crate::{
            chat::ChatMessage,
            crypto::{
                kem::Ciphertext,
                test_util::{DeterministicRng, check_vector, to_hex},
            },
            link::{ChannelInitiator, ChannelKeys, ChannelResponder, Flavor},
        };
        let ayse = Identity::from_seed(SecretBytes::from_slice(&[0xa1; 32]).unwrap()).public();
        let burak = Identity::from_seed(SecretBytes::from_slice(&[0xb2; 32]).unwrap()).public();
        let psk = SecretBytes::from_slice(&[0x5a; 32]).unwrap();
        let epoch = 490_000;
        let tag_key = contact_tag_key(&psk, &ayse, &burak).unwrap();
        let tag_ab = tag(&tag_key, epoch);
        let message_id = [0x0f; 16];
        let payload = ChatMessage::Text {
            id: message_id,
            sent_at_ms: 1_791_400_000_000,
            text: "köprüden selam".into(),
        }
        .encode()
        .unwrap();
        let id = contact_envelope_id(&ayse, &burak, payload[0], &message_id);
        let expires = 29_856_700;
        let pair = Pair {
            from: &ayse,
            to: &burak,
            psk: &psk,
        };
        let seal_seed = [0x88; 32];
        let secret = drop_secret(&psk, &ayse, &burak, &id).unwrap();
        let header = Header {
            id,
            expires,
            tag: tag_ab,
            drop: drop_tag(&secret),
        };
        let (prekey_id, prekey) = (
            7,
            DecapsulationKey::from_seed(SecretBytes::from_slice(&[0x7a; 32]).unwrap()).unwrap(),
        );
        let body = seal_from(
            &pair,
            prekey.encapsulation_key(),
            prekey_id,
            &header,
            &payload,
            &mut DeterministicRng::new(seal_seed),
        )
        .unwrap();
        let ss = prekey
            .decapsulate(&Ciphertext::from_bytes(&body[4..4 + CIPHERTEXT_LEN]).unwrap())
            .unwrap();
        let envelope = Envelope {
            id,
            hops: MAX_HOPS,
            expires,
            tag: tag_ab,
            drop: header.drop,
            body,
        };
        assert_eq!(&*open(&pair, &prekey, &envelope).unwrap(), payload.as_slice());
        let record = ChatMessage::MeshEnvelope(envelope.clone()).encode().unwrap();
        let have = ChatMessage::MeshHave(vec![envelope.short_id(), [0x22; 8]])
            .encode()
            .unwrap();
        let withdraw = ChatMessage::MeshWithdraw { id, secret }.encode().unwrap();
        let prekeys = ChatMessage::Prekeys(vec![(prekey_id, prekey.encapsulation_key().clone())])
            .encode()
            .unwrap();
        let prekeys_wanted = ChatMessage::PrekeysWanted(5).encode().unwrap();
        // A small file through the mesh (§10.8): its offer's payload, and its one part.
        let file_message = [0x1f; 16];
        let file_key = SecretBytes::from_slice(&[0x5f; 32]).unwrap();
        let file_meta = crate::chat::FileMeta {
            name: "not.txt".into(),
            mime: "text/plain".into(),
            size: 5,
            sha256: sha256(&[b"selam"]),
            thumbnail: None,
        };
        let file_offer = ChatMessage::MeshFileOffer {
            id: file_message,
            sent_at_ms: 1_791_400_000_000,
            key: Zeroizing::new(*file_key.expose()),
            meta: file_meta,
        }
        .encode()
        .unwrap();
        let part_id = file_part_id(&ayse, &burak, &file_message, 0);
        let part_tag = tag(&file_tag_key(&psk, &ayse, &burak).unwrap(), epoch);
        let part_header = Header {
            id: part_id,
            expires,
            tag: part_tag,
            drop: drop_tag(&drop_secret(&psk, &ayse, &burak, &part_id).unwrap()),
        };
        let part_body = seal_part(&file_key, &part_header, 0, b"selam").unwrap();
        let part = Envelope {
            id: part_id,
            hops: MAX_HOPS,
            expires,
            tag: part_tag,
            drop: part_header.drop,
            body: part_body,
        };
        assert_eq!(&*open_part(&file_key, &part, 0).unwrap(), b"selam");
        let part_record = ChatMessage::MeshEnvelope(part).encode().unwrap();
        // A group's update through the mesh (§10.9): the update key for an added contact, and a part.
        let (update_epoch_key, update_bytes) = (SecretBytes::from_slice(&[0x6e; 32]).unwrap(), vec![0x75; 700]);
        let update_id: [u8; 16] = sha256(&[&update_bytes])[..16].try_into().unwrap();
        let update_group = [0x47; 16];
        let keys = update_keys(&update_epoch_key, &update_group, 4).unwrap();
        let update_key = update_part_key(&keys.base, &update_id).unwrap();
        let update_key_payload = ChatMessage::MeshUpdateKey {
            group_id: update_group,
            epoch: 4,
            update_id,
            count: 1,
            key: Zeroizing::new(*update_key.expose()),
        }
        .encode()
        .unwrap();
        let update_part = UpdatePart {
            update_id,
            index: 0,
            count: 1,
        };
        let update_part_id = update_part_id(&update_group, &update_id, 0);
        let update_envelope = Envelope {
            id: update_part_id,
            hops: MAX_HOPS,
            expires,
            tag: tag(&keys.tag_key, epoch),
            drop: NO_DROP,
            body: seal_update_part(&update_key, &update_part_id, &update_part, &update_bytes).unwrap(),
        };
        assert_eq!(open_update_part(&update_key, &update_envelope).unwrap().1, update_bytes);
        let update_part_record = ChatMessage::MeshEnvelope(update_envelope).encode().unwrap();

        let (epoch_key, group_id, group_epoch) = (SecretBytes::from_slice(&[0x67; 32]).unwrap(), [0x47; 16], 3);
        let group_tag = tag(&group_tag_key(&epoch_key, &group_id, group_epoch).unwrap(), epoch);
        // A group file's part (§10.10): the file of message `file_message`, sent in that epoch.
        let group_file_key = group_file_key(&epoch_key, &group_id, group_epoch, &file_message).unwrap();
        let group_part_id = group_file_part_id(&group_id, &file_message, 0);
        let group_part = Envelope {
            id: group_part_id,
            hops: MAX_HOPS,
            expires,
            tag: tag(&group_file_tag_key(&epoch_key, &group_id, group_epoch).unwrap(), epoch),
            drop: NO_DROP,
            body: seal_group_file_part(&group_file_key, &group_part_id, 0, b"selam").unwrap(),
        };
        assert_eq!(
            &*open_group_file_part(&group_file_key, &group_part, 0).unwrap(),
            b"selam"
        );
        let group_part_record = ChatMessage::MeshEnvelope(group_part).encode().unwrap();

        let (link_id, link_psk) = (
            sha256(&[labels::MESH_ID])[..16].to_vec(),
            SecretBytes::from_slice(&sha256(&[labels::MESH_PSK])).unwrap(),
        );
        let keys = ChannelKeys {
            id: &link_id,
            psk: &link_psk,
            flavor: Flavor::MESH,
        };
        let (initiator_seed, responder_seed, link_tag) = ([0x33; 32], [0x44; 32], [0x99; 32]);
        let (nonce2, nonce3) = ([0xd2; 16], [0xd3; 16]);
        let (start, message1) =
            ChannelInitiator::start_from(&keys, &link_tag, &mut DeterministicRng::new(initiator_seed)).unwrap();
        let (answer, message2) =
            ChannelResponder::respond_from(&keys, &message1, &nonce2, &mut DeterministicRng::new(responder_seed))
                .unwrap();
        let (mut a, message3) = start.finish(&message2, &nonce3).unwrap();
        let mut b = answer.finish(&message3).unwrap();
        let link_ss = {
            let mut seed = SecretBytes::zeroed();
            use crate::crypto::random::Rng;
            DeterministicRng::new(initiator_seed).fill(seed.expose_mut()).unwrap();
            DecapsulationKey::from_seed(seed)
                .unwrap()
                .decapsulate(&Ciphertext::from_bytes(&message2[2..2 + CIPHERTEXT_LEN]).unwrap())
                .unwrap()
        };
        let record1 = a.session.seal(b"hello").unwrap();
        let record2 = b.session.seal(b"hi").unwrap();

        let fields: Vec<(&str, String)> = vec![
            ("ik_a", to_hex(ayse.as_bytes())),
            ("ik_b", to_hex(burak.as_bytes())),
            ("psk", to_hex(psk.expose())),
            ("epoch", epoch.to_string()),
            ("tag_key", to_hex(tag_key.expose())),
            ("tag", to_hex(&tag_ab)),
            ("message_id", to_hex(&message_id)),
            ("payload", to_hex(&payload)),
            ("envelope_id", to_hex(&id)),
            ("expires", expires.to_string()),
            ("seal_rng_seed", to_hex(&seal_seed)),
            ("ss", to_hex(ss.expose())),
            ("prekey", prekey_id.to_string()),
            ("prekey_key", to_hex(prekey.encapsulation_key().as_bytes())),
            ("drop_secret", to_hex(&secret)),
            ("drop", to_hex(&header.drop)),
            ("envelope_record", to_hex(&record)),
            ("have_record", to_hex(&have)),
            ("withdraw_record", to_hex(&withdraw)),
            ("prekeys_record", to_hex(&prekeys)),
            ("file_message_id", to_hex(&file_message)),
            ("file_key", to_hex(file_key.expose())),
            ("file_offer_payload", to_hex(&file_offer)),
            ("file_part_record", to_hex(&part_record)),
            ("update_epoch_key", to_hex(update_epoch_key.expose())),
            ("update_id", to_hex(&update_id)),
            ("update_key_payload", to_hex(&update_key_payload)),
            ("update_part_record", to_hex(&update_part_record)),
            ("prekeys_wanted_record", to_hex(&prekeys_wanted)),
            ("group_epoch_key", to_hex(epoch_key.expose())),
            ("group_id", to_hex(&group_id)),
            ("group_epoch", group_epoch.to_string()),
            ("group_tag", to_hex(&group_tag)),
            ("group_envelope_id", to_hex(&group_envelope_id(&group_id, &message_id))),
            ("group_file_part_record", to_hex(&group_part_record)),
            ("link_tag", to_hex(&link_tag)),
            ("link_initiator_rng_seed", to_hex(&initiator_seed)),
            ("link_responder_rng_seed", to_hex(&responder_seed)),
            ("link_ss", to_hex(link_ss.expose())),
            ("link_message1", to_hex(&message1)),
            ("link_message2", to_hex(&message2)),
            ("link_message3", to_hex(&message3)),
            ("link_handshake_hash", to_hex(a.session.handshake_hash())),
            ("link_record1_initiator_hello", to_hex(&record1)),
            ("link_record2_responder_hi", to_hex(&record2)),
        ];
        check_vector("mesh", &fields);
    }
}
