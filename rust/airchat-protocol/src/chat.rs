//! Messages exchanged inside a link session between two contacts (docs/protocol.md §8).
//!
//! ```text
//! record payload = kind (u8) || body
//! 0x01 text: message id (16) || sent at (u64, Unix ms) || UTF-8 text (1..=8192 bytes)
//! 0x02 ack:  message id (16)
//! 0x03 ping: (empty)                                  answered at once with a pong (§6.7)
//! 0x04 pong: (empty)
//! 0x05 refused: message id (16)                     not stored: the contact takes no messages from us
//! 0x10 move request:  target (u8)                     0x01 local-only hotspot (§8.3)
//! 0x11 hotspot offer: port (u16) || ssid length (u8) || ssid || passphrase length (u8) || passphrase
//! 0x12 move declined: target (u8)
//! 0x20 file offer:    id (16) || sent at (u64) || size (u64) || sha256 (32) || mime length (u8) || mime
//!                     || name length (u8) || name || thumbnail length (u16) || thumbnail      (§8.4)
//! 0x21 chunk request: id (16) || first chunk (u64) || count (u16, 1..=32)
//! 0x22 chunk:         id (16) || index (u64) || data (1..=15360 bytes)
//! 0x23 unavailable:   id (16) || reason (u8)          0x01 not now, 0x02 gone
//! 0x30 call offer:    stream id (16) || media (u8, optional: 0x01 video)                 (§8.5)
//! 0x31 call accept:   stream id (16)
//! 0x32 call end:      stream id (16) || reason (u8)
//! 0x33 talk start:    stream id (16)                  push-to-talk
//! 0x34 talk end:      stream id (16) || reason (u8)
//! 0x35 audio:         stream id (16) || sequence (u32) || Opus packet (1..=1275 bytes)
//! 0x36 ringing:       stream id (16)                  the call rings on the receiver
//! 0x37 group talk start, 0x38 group call, 0x39 group call leave                        (§9.6)
//! 0x3a video state:   stream id (16) || state (u8)    0x00 off, 0x01 on, 0x02 paused    (§8.6)
//! 0x3b video:         stream id (16) || frame (u32) || flags (u8) || rotation (u8) || width (u16)
//!                     || height (u16) || part (u8) || parts (u8, 1..=64) || data (1..=16320 bytes)
//! 0x3c key frame request: stream id (16)
//! 0x40 update part:   update id (16) || index (u16) || count (u16, 1..=64) || data      (§9.5)
//! 0x41 group message: sealed group message (§9.3)
//! 0x42 group ack:     group id (16) || message id (16)
//! 0x43 group leave:   group id (16)
//! 0x44 member proposal: id (16) || expires (u64) || person (32) || person name (u8-prefixed)
//!                     || group name (u8-prefixed)                                    (§9.8)
//! 0x45 member proposal answer: id (16) || agree (u8: 0x00 no, 0x01 yes)
//! 0x50 envelope:      a mesh envelope (§10.3)
//! 0x51 have:          short envelope ids (8 bytes each, up to 1024)                    (§10.4)
//! 0x5a prekeys, 0x5b prekeys wanted                                                     (§10.7)
//! 0x5c static key:    version (u32) || static key (1216) || signature (64)            (§6.9)
//! 0x5d static key taken: version (u32)
//! 0x5e presence key:  version (u32) || presence key (32)                                (§5.4)
//! 0x5f presence key taken: version (u32)
//! ```
//! Other kinds are ignored, so later versions can add some without breaking this one.

use zeroize::Zeroizing;

use crate::{
    crypto::{
        kem::{ENCAPSULATION_KEY_LEN, EncapsulationKey},
        sign::SIGNATURE_LEN,
    },
    identity::PublicIdentity,
    link::MAX_RECORD_PAYLOAD,
    mesh::{self, DropSecret, Envelope, EnvelopeId, ShortId},
    path::{self, Class, Classes, PathId, Proof},
};

pub const MESSAGE_ID_LEN: usize = 16;
/// A message's id, chosen by its sender at random.
pub type MessageId = [u8; MESSAGE_ID_LEN];

/// Plaintext bytes per file chunk, on the wire and, in the reference app, at rest
/// (docs/protocol.md §8.4). A chunk with its message header fits in one link record (16 KiB).
pub const CHUNK_LEN: usize = 15 * 1024;

/// What a file offer says about a file (docs/protocol.md §8.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMeta {
    pub name: String,
    pub mime: String,
    pub size: u64,
    pub sha256: [u8; 32],
    pub thumbnail: Option<Vec<u8>>,
}

/// Longest message text, in UTF-8 bytes.
pub const MAX_TEXT_BYTES: usize = 8192;

pub const KIND_TEXT: u8 = 0x01;
pub const KIND_ACK: u8 = 0x02;
const KIND_PING: u8 = 0x03;
const KIND_PONG: u8 = 0x04;
pub const KIND_REFUSED: u8 = 0x05;
const KIND_MOVE_REQUEST: u8 = 0x10;
const KIND_HOTSPOT_OFFER: u8 = 0x11;
const KIND_MOVE_DECLINED: u8 = 0x12;
const KIND_FILE_OFFER: u8 = 0x20;
const KIND_CHUNK_REQUEST: u8 = 0x21;
const KIND_CHUNK: u8 = 0x22;
const KIND_FILE_UNAVAILABLE: u8 = 0x23;
pub const KIND_MESH_FILE_OFFER: u8 = 0x24;
pub(crate) const KIND_MESH_UPDATE_KEY: u8 = 0x25;
const KIND_CALL_OFFER: u8 = 0x30;
const KIND_CALL_ACCEPT: u8 = 0x31;
const KIND_CALL_END: u8 = 0x32;
const KIND_TALK_START: u8 = 0x33;
const KIND_TALK_END: u8 = 0x34;
const KIND_AUDIO: u8 = 0x35;
const KIND_RINGING: u8 = 0x36;
const KIND_GROUP_TALK_START: u8 = 0x37;
const KIND_GROUP_CALL: u8 = 0x38;
const KIND_GROUP_CALL_LEAVE: u8 = 0x39;
const KIND_VIDEO_STATE: u8 = 0x3a;
const KIND_VIDEO: u8 = 0x3b;
const KIND_KEY_FRAME_REQUEST: u8 = 0x3c;
const KIND_CHANNEL_HEAD: u8 = 0x3d;
const KIND_CALL_PRESENCE: u8 = 0x3e;
const KIND_CALL_AUDIO: u8 = 0x3f;
const KIND_UPDATE_PART: u8 = 0x40;
const KIND_GROUP_MESSAGE: u8 = 0x41;
const KIND_GROUP_ACK: u8 = 0x42;
const KIND_GROUP_LEAVE: u8 = 0x43;
const KIND_MEMBER_PROPOSAL: u8 = 0x44;
const KIND_MEMBER_PROPOSAL_ANSWER: u8 = 0x45;
const KIND_CALL_VIDEO: u8 = 0x46;
const KIND_CALL_KEY_FRAME_REQUEST: u8 = 0x47;
const KIND_MESH_ENVELOPE: u8 = 0x50;
const KIND_MESH_HAVE: u8 = 0x51;
const KIND_PATH_OFFER: u8 = 0x52;
const KIND_PATH_REQUEST: u8 = 0x53;
const KIND_PATH_ANSWER: u8 = 0x54;
const KIND_PATH_OPEN: u8 = 0x55;
const KIND_PATH_DATA: u8 = 0x56;
const KIND_PATH_CREDIT: u8 = 0x57;
const KIND_PATH_CLOSE: u8 = 0x58;
const KIND_MESH_WITHDRAW: u8 = 0x59;
const KIND_PREKEYS: u8 = 0x5a;
const KIND_PREKEYS_WANTED: u8 = 0x5b;
const KIND_STATIC_KEY: u8 = 0x5c;
const KIND_STATIC_KEY_TAKEN: u8 = 0x5d;
const KIND_PRESENCE_KEY: u8 = 0x5e;
const KIND_PRESENCE_KEY_TAKEN: u8 = 0x5f;
const KIND_BUILD_ATTESTATION: u8 = 0x60;
/// Prekeys in one record at most, and asked for at most (§10.7).
pub const MAX_PREKEYS_PER_RECORD: usize = 12;
pub const MAX_PREKEYS_WANTED: u8 = 24;

/// Group updates travel in parts of at most this many bytes (§9.5).
pub const UPDATE_PART_LEN: usize = 15 * 1024;
pub const MAX_UPDATE_PARTS: u16 = 64;

/// Names a call or a push-to-talk turn; random.
pub type StreamId = [u8; 16];
/// The largest Opus packet.
pub const MAX_AUDIO_PACKET: usize = 1275;
/// Who a group call's presence and audio come from: random, chosen by each participant (§9.6).
pub type CallOrigin = [u8; 8];

/// Video frames travel in parts of at most this many bytes (§8.6), so a frame is at most about 1 MB.
pub const VIDEO_PART_LEN: usize = 16_320;
pub const MAX_VIDEO_PARTS: u8 = 64;
/// Largest width or height of a video frame a receiver takes.
pub const MAX_VIDEO_SIDE: u16 = 1920;
const VIDEO_KEY_FRAME: u8 = 0x01;
/// The media byte of a call offer for a video call.
const MEDIA_VIDEO: u8 = 0x01;

fn check_video_part(part: u8, parts: u8, data: &[u8]) -> Result<(), ChatError> {
    if (1..=MAX_VIDEO_PARTS).contains(&parts) && part < parts && (1..=VIDEO_PART_LEN).contains(&data.len()) {
        Ok(())
    } else {
        Err(ChatError::Malformed)
    }
}

// A full record of prekeys fits in one record.
const _: () = assert!(MAX_PREKEYS_PER_RECORD * (4 + ENCAPSULATION_KEY_LEN) < MAX_RECORD_PAYLOAD);

// The largest piece of a frame on a path fits in one record.
const _: () = assert!(1 + 16 + 1 + path::MAX_DATA <= MAX_RECORD_PAYLOAD);

// The largest video part fits in one record.
const _: () = assert!(1 + 16 + 4 + 1 + 1 + 2 + 2 + 1 + 1 + VIDEO_PART_LEN <= MAX_RECORD_PAYLOAD);
// A group call's video carries its origin too (§9.9).
const _: () = assert!(1 + 16 + 8 + 4 + 1 + 1 + 2 + 2 + 1 + 1 + VIDEO_PART_LEN <= MAX_RECORD_PAYLOAD);

/// What a device's camera does in a call (§8.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoState {
    Off = 0x00,
    On = 0x01,
    /// On, but nothing is sent: the link is too slow for video, or the app cannot use the camera now.
    Paused = 0x02,
}

impl VideoState {
    /// States from a later version mean off.
    fn from_code(code: u8) -> Self {
        match code {
            0x01 => Self::On,
            0x02 => Self::Paused,
            _ => Self::Off,
        }
    }
}

/// What describes a video frame, in each of its parts (§8.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VideoHeader {
    /// Numbered per call and sender from 0. Frames are skipped only before a key frame.
    pub frame: u32,
    /// An H.264 IDR frame, with the stream's SPS and PPS before it: decodable on its own.
    pub key: bool,
    /// Quarter turns clockwise that show the frame upright.
    pub rotation: u8,
    pub width: u16,
    pub height: u16,
}

impl VideoHeader {
    fn check(&self) -> Result<(), ChatError> {
        let sides = (1..=MAX_VIDEO_SIDE).contains(&self.width) && (1..=MAX_VIDEO_SIDE).contains(&self.height);
        if sides && self.rotation <= 3 {
            Ok(())
        } else {
            Err(ChatError::Malformed)
        }
    }
}

/// Why a call or a push-to-talk turn ended (§8.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndReason {
    HungUp = 0x01,
    Declined = 0x02,
    /// Already in a call.
    Busy = 0x03,
    /// The receiver does not take calls (or instant voice) from the sender.
    NotAllowed = 0x04,
    NoAnswer = 0x05,
    /// The link was gone for too long.
    Lost = 0x06,
    /// Both pressed to talk at once and the other one goes first.
    Interrupted = 0x07,
}

impl EndReason {
    /// Reasons from a later version end the call all the same.
    fn from_code(code: u8) -> Self {
        match code {
            0x02 => Self::Declined,
            0x03 => Self::Busy,
            0x04 => Self::NotAllowed,
            0x05 => Self::NoAnswer,
            0x06 => Self::Lost,
            0x07 => Self::Interrupted,
            _ => Self::HungUp,
        }
    }
}

/// Limits of a file offer (§8.4), which with its thumbnail fits in one link record.
pub const MAX_FILE_NAME_BYTES: usize = 255;
pub const MAX_MIME_BYTES: usize = 127;
pub const MAX_THUMBNAIL_BYTES: usize = 12 * 1024;
pub const MAX_FILE_SIZE: u64 = 1 << 32;
pub const MAX_CHUNKS_PER_REQUEST: u16 = 32;

// The largest file offer and chunk each fit in one record.
const _: () = assert!(
    1 + MESSAGE_ID_LEN + 8 + 8 + 32 + 1 + MAX_MIME_BYTES + 1 + MAX_FILE_NAME_BYTES + 2 + MAX_THUMBNAIL_BYTES
        <= MAX_RECORD_PAYLOAD
);
const _: () = assert!(1 + MESSAGE_ID_LEN + 8 + CHUNK_LEN <= MAX_RECORD_PAYLOAD);

/// Why a sender cannot serve a file (§8.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unavailable {
    /// Try again later, e.g. the sender's app is locked.
    NotNow = 0x01,
    /// The sender no longer has it.
    Gone = 0x02,
}

/// Checks what a file offer may carry. Names and types are only shown, never used as paths.
/// What describes a file in an offer (§8.4) and a group file message (§9.3):
/// size (u64) || sha256 (32) || mime (u8-prefixed) || name (u8-prefixed) || thumbnail (u16-prefixed).
pub(crate) fn encode_file(meta: &FileMeta) -> Result<Vec<u8>, ChatError> {
    check_file(meta)?;
    let thumbnail = meta.thumbnail.as_deref().unwrap_or_default();
    let thumbnail_len = u16::try_from(thumbnail.len()).expect("checked");
    Ok([
        &meta.size.to_be_bytes()[..],
        &meta.sha256,
        &[meta.mime.len() as u8],
        meta.mime.as_bytes(),
        &[meta.name.len() as u8],
        meta.name.as_bytes(),
        &thumbnail_len.to_be_bytes(),
        thumbnail,
    ]
    .concat())
}

pub(crate) fn decode_file(bytes: &[u8]) -> Result<FileMeta, ChatError> {
    let (size, rest) = bytes.split_first_chunk::<8>().ok_or(ChatError::Malformed)?;
    let (sha256, rest) = rest.split_first_chunk::<32>().ok_or(ChatError::Malformed)?;
    let (mime, rest) = length_prefixed(rest)?;
    let (name, rest) = length_prefixed(rest)?;
    let (thumbnail_len, thumbnail) = rest.split_first_chunk::<2>().ok_or(ChatError::Malformed)?;
    if thumbnail.len() != usize::from(u16::from_be_bytes(*thumbnail_len)) {
        return Err(ChatError::Malformed);
    }
    let meta = FileMeta {
        name: std::str::from_utf8(name).map_err(|_| ChatError::Malformed)?.to_owned(),
        mime: std::str::from_utf8(mime).map_err(|_| ChatError::Malformed)?.to_owned(),
        size: u64::from_be_bytes(*size),
        sha256: *sha256,
        thumbnail: (!thumbnail.is_empty()).then(|| thumbnail.to_vec()),
    };
    check_file(&meta).map_err(|_| ChatError::Malformed)?;
    Ok(meta)
}

pub fn check_file(meta: &FileMeta) -> Result<(), ChatError> {
    let name_ok = (1..=MAX_FILE_NAME_BYTES).contains(&meta.name.len()) && !meta.name.chars().any(char::is_control);
    let mime_ok = (1..=MAX_MIME_BYTES).contains(&meta.mime.len())
        && meta.mime.bytes().all(|b| b.is_ascii_graphic())
        && meta.mime.contains('/');
    let thumbnail_ok = meta
        .thumbnail
        .as_ref()
        .is_none_or(|t| (1..=MAX_THUMBNAIL_BYTES).contains(&t.len()));
    if name_ok && mime_ok && thumbnail_ok && meta.size <= MAX_FILE_SIZE {
        Ok(())
    } else {
        Err(ChatError::InvalidFile)
    }
}

/// Where a link can be moved on request (§8.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MoveTarget {
    /// A local-only hotspot the other device opens and this one joins.
    Hotspot,
}

impl MoveTarget {
    pub fn code(self) -> u8 {
        match self {
            Self::Hotspot => 0x01,
        }
    }

    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0x01 => Some(Self::Hotspot),
            _ => None,
        }
    }
}

/// A hotspot opened for a contact: join it and connect to its gateway at `port`. The password is
/// not a security boundary (the link session is); it only keeps strangers off the network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HotspotOffer {
    pub ssid: String,
    pub passphrase: String,
    pub port: u16,
}

impl HotspotOffer {
    fn check(&self) -> Result<(), ChatError> {
        let ssid_ok = (1..=32).contains(&self.ssid.len());
        let passphrase_ok =
            (8..=63).contains(&self.passphrase.len()) && self.passphrase.bytes().all(|b| (0x20..=0x7e).contains(&b));
        if ssid_ok && passphrase_ok && self.port != 0 {
            Ok(())
        } else {
            Err(ChatError::InvalidOffer)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChatMessage {
    Text {
        id: MessageId,
        sent_at_ms: u64,
        text: String,
    },
    /// The message with this id arrived and was stored.
    Ack {
        id: MessageId,
    },
    /// The message (or file offer) with this id arrived but was turned down: the receiver does not
    /// take messages from the sender (requirement C-5). It is not sent again.
    Refused {
        id: MessageId,
    },
    /// Is the link still there? Answered with a [`ChatMessage::Pong`].
    Ping,
    Pong,
    FileOffer {
        id: MessageId,
        sent_at_ms: u64,
        meta: FileMeta,
    },
    /// Asks for `count` chunks of a file, starting with chunk `first`.
    ChunkRequest {
        id: MessageId,
        first: u64,
        count: u16,
    },
    Chunk {
        id: MessageId,
        index: u64,
        data: Zeroizing<Vec<u8>>,
    },
    FileUnavailable {
        id: MessageId,
        reason: Unavailable,
    },
    /// Asks the contact to open a move target (a [`MoveTarget`] code, which may be unknown here).
    MoveRequest {
        target: u8,
    },
    /// A call: rings until accepted or ended. A video call rings as one; either side may turn its
    /// camera on in any call (§8.6).
    CallOffer {
        id: StreamId,
        video: bool,
    },
    /// The call offer arrived and rings.
    Ringing {
        id: StreamId,
    },
    CallAccept {
        id: StreamId,
    },
    CallEnd {
        id: StreamId,
        reason: EndReason,
    },
    /// Push-to-talk: the sender talks until it ends the turn; plays at once on the receiver.
    TalkStart {
        id: StreamId,
    },
    TalkEnd {
        id: StreamId,
        reason: EndReason,
    },
    /// Push-to-talk to the members of a group (§9.6); ends with [`ChatMessage::TalkEnd`].
    GroupTalkStart {
        id: StreamId,
        group_id: [u8; 16],
    },
    /// The sender is in group call `id`: it started or joined it (§9.6).
    GroupCall {
        id: StreamId,
        group_id: [u8; 16],
    },
    /// The sender left group call `id`.
    GroupCallLeave {
        id: StreamId,
    },
    /// One Opus packet of a call or talk, numbered per stream and sender from 0.
    Audio {
        stream: StreamId,
        seq: u32,
        packet: Zeroizing<Vec<u8>>,
    },
    /// A participant of group call `stream` is in it: its origin, its identity key, a count that
    /// grows every few seconds, and its camera (§9.6, §9.9). Passed on by every participant.
    CallPresence {
        stream: StreamId,
        origin: CallOrigin,
        member: crate::identity::PublicIdentity,
        count: u32,
        camera: VideoState,
    },
    /// One Opus packet of a group call, from the participant with `origin`, numbered from 0.
    /// Passed on by every participant.
    CallAudio {
        stream: StreamId,
        origin: CallOrigin,
        seq: u32,
        packet: Zeroizing<Vec<u8>>,
    },
    /// The sender's camera went on, off or paused in call `id`.
    VideoState {
        id: StreamId,
        state: VideoState,
    },
    /// Part `part` of `parts` of a frame of the video of the participant with `origin` in group
    /// call `stream` (§9.9). Passed on by every participant.
    CallVideo {
        stream: StreamId,
        origin: CallOrigin,
        header: VideoHeader,
        part: u8,
        parts: u8,
        data: Zeroizing<Vec<u8>>,
    },
    /// Someone in group call `stream` cannot decode the video of the participant with `origin`:
    /// it should send a key frame soon. `nonce` names the request as it is passed on.
    CallKeyFrameRequest {
        stream: StreamId,
        origin: CallOrigin,
        nonce: [u8; 8],
    },
    /// Part `part` of `parts` of a frame of the sender's video in call `stream`.
    Video {
        stream: StreamId,
        header: VideoHeader,
        part: u8,
        parts: u8,
        data: Zeroizing<Vec<u8>>,
    },
    /// The receiver cannot decode what comes next: send a key frame soon.
    KeyFrameRequest {
        id: StreamId,
    },
    /// The head of the sender's walkie-talkie cluster: its device nonce and how far its count has
    /// gone (§11.5).
    ChannelHead {
        device: [u8; crate::channel::DEVICE_NONCE_LEN],
        seq: u32,
    },
    /// An envelope passed on through the mesh (§10.4).
    MeshEnvelope(Envelope),
    /// The envelopes the sender holds, by short id, newest first.
    MeshHave(Vec<ShortId>),
    /// A file offer that goes through the mesh (§10.8), with the key of the file's parts (zero when
    /// its content comes over a link).
    MeshFileOffer {
        id: MessageId,
        sent_at_ms: u64,
        key: Zeroizing<[u8; 32]>,
        meta: FileMeta,
    },
    /// For a contact added to a group: the key and number of the parts of an update that goes
    /// through the mesh (§10.9).
    MeshUpdateKey {
        group_id: crate::group::GroupId,
        epoch: u64,
        update_id: [u8; 16],
        count: u16,
        key: Zeroizing<[u8; 32]>,
    },
    /// Envelope `id` was delivered: its sender withdraws it with the drop secret (§10.4).
    MeshWithdraw {
        id: EnvelopeId,
        secret: DropSecret,
    },
    /// One-time prekeys of the sender's, for texts to it in envelopes (§10.7).
    Prekeys(Vec<(u32, EncapsulationKey)>),
    /// How many more of the receiver's prekeys the sender would hold.
    PrekeysWanted(u8),
    /// The sender's newest static key, signed with its identity key (§6.9).
    StaticKey {
        version: u32,
        key: EncapsulationKey,
        signature: [u8; SIGNATURE_LEN],
    },
    /// The receiver's static key of `version` was taken.
    StaticKeyTaken(u32),
    /// The sender's newest presence key (§5.4).
    PresenceKey {
        version: u32,
        key: Zeroizing<[u8; 32]>,
    },
    /// The receiver's presence key of `version` was taken.
    PresenceKeyTaken(u32),
    /// The sender's Android key attestation (§6.10): the attested certificate first, at most
    /// [`crate::attest::MAX_CERTS`]; and the attested key's signature over this link's handshake hash.
    BuildAttestation {
        certs: Vec<Vec<u8>>,
        proof: Vec<u8>,
    },
    /// The classes of paths the sender carries for others now (§12.1).
    PathOffer(Classes),
    /// Looking for a path (§12.2).
    PathRequest(path::Request),
    /// The contact a request looked for answers; `providers` passed it so far.
    PathAnswer {
        path: PathId,
        providers: u8,
        proof: Proof,
    },
    /// Opens the path along the answer with `proof` (§12.3).
    PathOpen {
        path: PathId,
        proof: Proof,
    },
    /// Bytes of a frame of the link over a path; `more` while the frame goes on in the next.
    PathData {
        path: PathId,
        more: bool,
        data: Vec<u8>,
    },
    /// The receiving end took `bytes` more data bytes.
    PathCredit {
        path: PathId,
        bytes: u32,
    },
    PathClose {
        path: PathId,
    },
    /// Part `index` of `count` of a group update (§9.5).
    UpdatePart {
        update_id: [u8; 16],
        index: u16,
        count: u16,
        data: Vec<u8>,
    },
    /// A sealed group message (§9.3), passed on unchanged.
    GroupMessage(Vec<u8>),
    GroupAck {
        group_id: [u8; 16],
        message_id: [u8; 16],
    },
    GroupLeave {
        group_id: [u8; 16],
    },
    /// The sender would make a group of the two of them and `person`, a contact of its own
    /// (§9.8); `expires` (Unix seconds) ends the person's membership, 0 for a permanent one.
    MemberProposal {
        id: [u8; 16],
        person: PublicIdentity,
        person_name: String,
        group_name: String,
        expires: u64,
    },
    MemberProposalAnswer {
        id: [u8; 16],
        agree: bool,
    },
    HotspotOffer(HotspotOffer),
    /// The contact cannot open the requested target now.
    MoveDeclined {
        target: u8,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ChatError {
    #[error("malformed chat message")]
    Malformed,
    #[error("message text must have 1 to {MAX_TEXT_BYTES} bytes")]
    InvalidText,
    #[error("a hotspot offer needs a 1–32 byte name, an 8–63 character ASCII password and a port")]
    InvalidOffer,
    #[error("a file needs a name, a type, a thumbnail of at most 16 KiB and at most 4 GiB of content")]
    InvalidFile,
}

/// Whether an encoded record is a ping or a pong (§6.7), which only keep a link alive.
pub fn is_liveness(payload: &[u8]) -> bool {
    matches!(payload.first(), Some(&(KIND_PING | KIND_PONG)))
}

impl ChatMessage {
    /// Whether it is one of the records that find, open and carry paths (§12).
    pub fn is_path_record(&self) -> bool {
        matches!(
            self,
            Self::PathOffer(_)
                | Self::PathRequest(_)
                | Self::PathAnswer { .. }
                | Self::PathOpen { .. }
                | Self::PathData { .. }
                | Self::PathCredit { .. }
                | Self::PathClose { .. }
        )
    }

    pub fn encode(&self) -> Result<Vec<u8>, ChatError> {
        Ok(match self {
            Self::Text { id, sent_at_ms, text } => {
                check_text(text)?;
                [&[KIND_TEXT][..], id, &sent_at_ms.to_be_bytes(), text.as_bytes()].concat()
            }
            Self::Ack { id } => [&[KIND_ACK][..], id].concat(),
            Self::Refused { id } => [&[KIND_REFUSED][..], id].concat(),
            Self::Ping => vec![KIND_PING],
            Self::Pong => vec![KIND_PONG],
            Self::FileOffer { id, sent_at_ms, meta } => [
                &[KIND_FILE_OFFER][..],
                id,
                &sent_at_ms.to_be_bytes(),
                &encode_file(meta)?,
            ]
            .concat(),
            Self::ChunkRequest { id, first, count } => {
                if !(1..=MAX_CHUNKS_PER_REQUEST).contains(count) {
                    return Err(ChatError::Malformed);
                }
                [
                    &[KIND_CHUNK_REQUEST][..],
                    id,
                    &first.to_be_bytes(),
                    &count.to_be_bytes(),
                ]
                .concat()
            }
            Self::Chunk { id, index, data } => {
                if !(1..=CHUNK_LEN).contains(&data.len()) {
                    return Err(ChatError::Malformed);
                }
                [&[KIND_CHUNK][..], id, &index.to_be_bytes(), data].concat()
            }
            Self::FileUnavailable { id, reason } => [&[KIND_FILE_UNAVAILABLE][..], id, &[*reason as u8]].concat(),
            Self::MoveRequest { target } => vec![KIND_MOVE_REQUEST, *target],
            Self::CallOffer { id, video: false } => [&[KIND_CALL_OFFER][..], id].concat(),
            Self::CallOffer { id, video: true } => [&[KIND_CALL_OFFER][..], id, &[MEDIA_VIDEO]].concat(),
            Self::VideoState { id, state } => [&[KIND_VIDEO_STATE][..], id, &[*state as u8]].concat(),
            Self::KeyFrameRequest { id } => [&[KIND_KEY_FRAME_REQUEST][..], id].concat(),
            Self::Video {
                stream,
                header,
                part,
                parts,
                data,
            } => {
                header.check()?;
                check_video_part(*part, *parts, data)?;
                [
                    &[KIND_VIDEO][..],
                    stream,
                    &header.frame.to_be_bytes(),
                    &[if header.key { VIDEO_KEY_FRAME } else { 0 }, header.rotation],
                    &header.width.to_be_bytes(),
                    &header.height.to_be_bytes(),
                    &[*part, *parts],
                    data,
                ]
                .concat()
            }
            Self::CallAccept { id } => [&[KIND_CALL_ACCEPT][..], id].concat(),
            Self::Ringing { id } => [&[KIND_RINGING][..], id].concat(),
            Self::UpdatePart {
                update_id,
                index,
                count,
                data,
            } => {
                if !(1..=MAX_UPDATE_PARTS).contains(count)
                    || index >= count
                    || !(1..=UPDATE_PART_LEN).contains(&data.len())
                {
                    return Err(ChatError::Malformed);
                }
                [
                    &[KIND_UPDATE_PART][..],
                    update_id,
                    &index.to_be_bytes(),
                    &count.to_be_bytes(),
                    data,
                ]
                .concat()
            }
            Self::GroupMessage(sealed) => [&[KIND_GROUP_MESSAGE][..], sealed].concat(),
            Self::ChannelHead { device, seq } => [&[KIND_CHANNEL_HEAD][..], device, &seq.to_be_bytes()].concat(),
            Self::MeshEnvelope(envelope) => [
                &[KIND_MESH_ENVELOPE][..],
                &envelope.encode().map_err(|_| ChatError::Malformed)?,
            ]
            .concat(),
            Self::MeshHave(ids) => [&[KIND_MESH_HAVE][..], &mesh::encode_have(ids)].concat(),
            Self::MeshWithdraw { id, secret } => [&[KIND_MESH_WITHDRAW][..], id, secret].concat(),
            Self::MeshFileOffer {
                id,
                sent_at_ms,
                key,
                meta,
            } => [
                &[KIND_MESH_FILE_OFFER][..],
                id,
                &sent_at_ms.to_be_bytes(),
                &key[..],
                &encode_file(meta)?,
            ]
            .concat(),
            Self::MeshUpdateKey {
                group_id,
                epoch,
                update_id,
                count,
                key,
            } => {
                if !(1..=MAX_UPDATE_PARTS).contains(count) {
                    return Err(ChatError::Malformed);
                }
                [
                    &[KIND_MESH_UPDATE_KEY][..],
                    group_id,
                    &epoch.to_be_bytes(),
                    update_id,
                    &count.to_be_bytes(),
                    &key[..],
                ]
                .concat()
            }
            Self::Prekeys(prekeys) => {
                if !(1..=MAX_PREKEYS_PER_RECORD).contains(&prekeys.len()) || prekeys.iter().any(|(id, _)| *id == 0) {
                    return Err(ChatError::Malformed);
                }
                let mut out = vec![KIND_PREKEYS];
                for (id, key) in prekeys {
                    out.extend_from_slice(&id.to_be_bytes());
                    out.extend_from_slice(key.as_bytes());
                }
                out
            }
            Self::PrekeysWanted(count) => {
                if !(1..=MAX_PREKEYS_WANTED).contains(count) {
                    return Err(ChatError::Malformed);
                }
                vec![KIND_PREKEYS_WANTED, *count]
            }
            Self::StaticKey {
                version,
                key,
                signature,
            } => [
                &[KIND_STATIC_KEY][..],
                &version.to_be_bytes(),
                key.as_bytes(),
                signature,
            ]
            .concat(),
            Self::StaticKeyTaken(version) => [&[KIND_STATIC_KEY_TAKEN][..], &version.to_be_bytes()].concat(),
            Self::PresenceKey { version, key } => [&[KIND_PRESENCE_KEY][..], &version.to_be_bytes(), &key[..]].concat(),
            Self::PresenceKeyTaken(version) => [&[KIND_PRESENCE_KEY_TAKEN][..], &version.to_be_bytes()].concat(),
            Self::BuildAttestation { certs, proof } => {
                let mut out = vec![KIND_BUILD_ATTESTATION, u8::try_from(certs.len()).unwrap_or(u8::MAX)];
                for cert in certs {
                    out.extend_from_slice(&u16::try_from(cert.len()).unwrap_or(u16::MAX).to_be_bytes());
                    out.extend_from_slice(cert);
                }
                out.push(u8::try_from(proof.len()).unwrap_or(u8::MAX));
                out.extend_from_slice(proof);
                out
            }
            Self::PathOffer(classes) => vec![KIND_PATH_OFFER, classes.bits()],
            Self::PathRequest(request) => [
                &[KIND_PATH_REQUEST][..],
                &request.path,
                &[request.class.bit(), request.hops],
                &request.nonce,
                &request.tag,
            ]
            .concat(),
            Self::PathAnswer { path, providers, proof } => {
                [&[KIND_PATH_ANSWER][..], path, &[*providers], proof].concat()
            }
            Self::PathOpen { path, proof } => [&[KIND_PATH_OPEN][..], path, proof].concat(),
            Self::PathData { path, more, data } => {
                if !(1..=path::MAX_DATA).contains(&data.len()) {
                    return Err(ChatError::Malformed);
                }
                [&[KIND_PATH_DATA][..], path, &[u8::from(*more)], data].concat()
            }
            Self::PathCredit { path, bytes } => [&[KIND_PATH_CREDIT][..], path, &bytes.to_be_bytes()].concat(),
            Self::PathClose { path } => [&[KIND_PATH_CLOSE][..], path].concat(),
            Self::GroupAck { group_id, message_id } => [&[KIND_GROUP_ACK][..], group_id, message_id].concat(),
            Self::GroupLeave { group_id } => [&[KIND_GROUP_LEAVE][..], group_id].concat(),
            Self::MemberProposal {
                id,
                person,
                person_name,
                group_name,
                expires,
            } => {
                if !short_name_ok(person_name) || !short_name_ok(group_name) {
                    return Err(ChatError::Malformed);
                }
                [
                    &[KIND_MEMBER_PROPOSAL][..],
                    id,
                    &expires.to_be_bytes(),
                    person.as_bytes(),
                    &[person_name.len() as u8],
                    person_name.as_bytes(),
                    &[group_name.len() as u8],
                    group_name.as_bytes(),
                ]
                .concat()
            }
            Self::MemberProposalAnswer { id, agree } => {
                [&[KIND_MEMBER_PROPOSAL_ANSWER][..], id, &[u8::from(*agree)]].concat()
            }
            Self::CallEnd { id, reason } => [&[KIND_CALL_END][..], id, &[*reason as u8]].concat(),
            Self::TalkStart { id } => [&[KIND_TALK_START][..], id].concat(),
            Self::GroupTalkStart { id, group_id } => [&[KIND_GROUP_TALK_START][..], id, group_id].concat(),
            Self::GroupCall { id, group_id } => [&[KIND_GROUP_CALL][..], id, group_id].concat(),
            Self::GroupCallLeave { id } => [&[KIND_GROUP_CALL_LEAVE][..], id].concat(),
            Self::TalkEnd { id, reason } => [&[KIND_TALK_END][..], id, &[*reason as u8]].concat(),
            Self::Audio { stream, seq, packet } => {
                if !(1..=MAX_AUDIO_PACKET).contains(&packet.len()) {
                    return Err(ChatError::Malformed);
                }
                [&[KIND_AUDIO][..], stream, &seq.to_be_bytes(), packet].concat()
            }
            Self::CallPresence {
                stream,
                origin,
                member,
                count,
                camera,
            } => {
                // A camera that is off is left out, as before there was video in group calls.
                let camera: &[u8] = match camera {
                    VideoState::Off => &[],
                    VideoState::On => &[VideoState::On as u8],
                    VideoState::Paused => &[VideoState::Paused as u8],
                };
                [
                    &[KIND_CALL_PRESENCE][..],
                    stream,
                    origin,
                    member.as_bytes(),
                    &count.to_be_bytes(),
                    camera,
                ]
                .concat()
            }
            Self::CallVideo {
                stream,
                origin,
                header,
                part,
                parts,
                data,
            } => {
                header.check()?;
                check_video_part(*part, *parts, data)?;
                [
                    &[KIND_CALL_VIDEO][..],
                    stream,
                    origin,
                    &header.frame.to_be_bytes(),
                    &[if header.key { VIDEO_KEY_FRAME } else { 0 }, header.rotation],
                    &header.width.to_be_bytes(),
                    &header.height.to_be_bytes(),
                    &[*part, *parts],
                    data,
                ]
                .concat()
            }
            Self::CallKeyFrameRequest { stream, origin, nonce } => {
                [&[KIND_CALL_KEY_FRAME_REQUEST][..], stream, origin, nonce].concat()
            }
            Self::CallAudio {
                stream,
                origin,
                seq,
                packet,
            } => {
                if !(1..=MAX_AUDIO_PACKET).contains(&packet.len()) {
                    return Err(ChatError::Malformed);
                }
                [&[KIND_CALL_AUDIO][..], stream, origin, &seq.to_be_bytes(), packet].concat()
            }
            Self::HotspotOffer(offer) => {
                offer.check()?;
                let (ssid, passphrase) = (offer.ssid.as_bytes(), offer.passphrase.as_bytes());
                [
                    &[KIND_HOTSPOT_OFFER][..],
                    &offer.port.to_be_bytes(),
                    &[ssid.len() as u8],
                    ssid,
                    &[passphrase.len() as u8],
                    passphrase,
                ]
                .concat()
            }
            Self::MoveDeclined { target } => vec![KIND_MOVE_DECLINED, *target],
        })
    }

    /// `Ok(None)` for kinds this version does not know.
    pub fn decode(bytes: &[u8]) -> Result<Option<Self>, ChatError> {
        let Some((&kind, body)) = bytes.split_first() else {
            return Err(ChatError::Malformed);
        };
        match kind {
            KIND_TEXT => {
                let (id, rest) = body.split_first_chunk::<MESSAGE_ID_LEN>().ok_or(ChatError::Malformed)?;
                let (sent_at, text) = rest.split_first_chunk::<8>().ok_or(ChatError::Malformed)?;
                let text = std::str::from_utf8(text).map_err(|_| ChatError::Malformed)?;
                check_text(text).map_err(|_| ChatError::Malformed)?;
                Ok(Some(Self::Text {
                    id: *id,
                    sent_at_ms: u64::from_be_bytes(*sent_at),
                    text: text.to_owned(),
                }))
            }
            KIND_ACK | KIND_REFUSED => {
                let id: MessageId = body.try_into().map_err(|_| ChatError::Malformed)?;
                Ok(Some(if kind == KIND_ACK {
                    Self::Ack { id }
                } else {
                    Self::Refused { id }
                }))
            }
            KIND_FILE_OFFER => {
                let (id, rest) = body.split_first_chunk::<MESSAGE_ID_LEN>().ok_or(ChatError::Malformed)?;
                let (sent_at, rest) = rest.split_first_chunk::<8>().ok_or(ChatError::Malformed)?;
                Ok(Some(Self::FileOffer {
                    id: *id,
                    sent_at_ms: u64::from_be_bytes(*sent_at),
                    meta: decode_file(rest)?,
                }))
            }
            KIND_CHUNK_REQUEST => {
                let (id, rest) = body.split_first_chunk::<MESSAGE_ID_LEN>().ok_or(ChatError::Malformed)?;
                let (first, rest) = rest.split_first_chunk::<8>().ok_or(ChatError::Malformed)?;
                let count: [u8; 2] = rest.try_into().map_err(|_| ChatError::Malformed)?;
                let count = u16::from_be_bytes(count);
                if !(1..=MAX_CHUNKS_PER_REQUEST).contains(&count) {
                    return Err(ChatError::Malformed);
                }
                Ok(Some(Self::ChunkRequest {
                    id: *id,
                    first: u64::from_be_bytes(*first),
                    count,
                }))
            }
            KIND_CHUNK => {
                let (id, rest) = body.split_first_chunk::<MESSAGE_ID_LEN>().ok_or(ChatError::Malformed)?;
                let (index, data) = rest.split_first_chunk::<8>().ok_or(ChatError::Malformed)?;
                if !(1..=CHUNK_LEN).contains(&data.len()) {
                    return Err(ChatError::Malformed);
                }
                Ok(Some(Self::Chunk {
                    id: *id,
                    index: u64::from_be_bytes(*index),
                    data: Zeroizing::new(data.to_vec()),
                }))
            }
            KIND_FILE_UNAVAILABLE => {
                let (id, rest) = body.split_first_chunk::<MESSAGE_ID_LEN>().ok_or(ChatError::Malformed)?;
                let reason = match rest {
                    [0x01] => Unavailable::NotNow,
                    [0x02] => Unavailable::Gone,
                    _ => return Err(ChatError::Malformed),
                };
                Ok(Some(Self::FileUnavailable { id: *id, reason }))
            }
            KIND_CALL_OFFER => {
                let (id, media) = body.split_first_chunk::<16>().ok_or(ChatError::Malformed)?;
                // Media from a later version ring as a voice call.
                let video = match media {
                    [] => false,
                    &[code] => code == MEDIA_VIDEO,
                    _ => return Err(ChatError::Malformed),
                };
                Ok(Some(Self::CallOffer { id: *id, video }))
            }
            KIND_VIDEO_STATE => {
                let (id, rest) = body.split_first_chunk::<16>().ok_or(ChatError::Malformed)?;
                let &[code] = rest else {
                    return Err(ChatError::Malformed);
                };
                Ok(Some(Self::VideoState {
                    id: *id,
                    state: VideoState::from_code(code),
                }))
            }
            KIND_VIDEO => {
                let (stream, rest) = body.split_first_chunk::<16>().ok_or(ChatError::Malformed)?;
                let (frame, rest) = rest.split_first_chunk::<4>().ok_or(ChatError::Malformed)?;
                let (&[flags, rotation], rest) = rest.split_first_chunk::<2>().ok_or(ChatError::Malformed)?;
                let (width, rest) = rest.split_first_chunk::<2>().ok_or(ChatError::Malformed)?;
                let (height, rest) = rest.split_first_chunk::<2>().ok_or(ChatError::Malformed)?;
                let (&[part, parts], data) = rest.split_first_chunk::<2>().ok_or(ChatError::Malformed)?;
                let header = VideoHeader {
                    frame: u32::from_be_bytes(*frame),
                    key: flags & VIDEO_KEY_FRAME != 0,
                    rotation,
                    width: u16::from_be_bytes(*width),
                    height: u16::from_be_bytes(*height),
                };
                header.check()?;
                check_video_part(part, parts, data)?;
                Ok(Some(Self::Video {
                    stream: *stream,
                    header,
                    part,
                    parts,
                    data: Zeroizing::new(data.to_vec()),
                }))
            }
            KIND_CALL_ACCEPT | KIND_RINGING | KIND_TALK_START | KIND_GROUP_CALL_LEAVE | KIND_KEY_FRAME_REQUEST => {
                let id: StreamId = body.try_into().map_err(|_| ChatError::Malformed)?;
                Ok(Some(match kind {
                    KIND_KEY_FRAME_REQUEST => Self::KeyFrameRequest { id },
                    KIND_CALL_ACCEPT => Self::CallAccept { id },
                    KIND_RINGING => Self::Ringing { id },
                    KIND_GROUP_CALL_LEAVE => Self::GroupCallLeave { id },
                    _ => Self::TalkStart { id },
                }))
            }
            KIND_GROUP_TALK_START | KIND_GROUP_CALL => {
                let (id, group_id) = body.split_first_chunk::<16>().ok_or(ChatError::Malformed)?;
                let group_id: [u8; 16] = group_id.try_into().map_err(|_| ChatError::Malformed)?;
                Ok(Some(if kind == KIND_GROUP_CALL {
                    Self::GroupCall { id: *id, group_id }
                } else {
                    Self::GroupTalkStart { id: *id, group_id }
                }))
            }
            KIND_CALL_END | KIND_TALK_END => {
                let (id, rest) = body.split_first_chunk::<16>().ok_or(ChatError::Malformed)?;
                let &[code] = rest else {
                    return Err(ChatError::Malformed);
                };
                let reason = EndReason::from_code(code);
                Ok(Some(if kind == KIND_CALL_END {
                    Self::CallEnd { id: *id, reason }
                } else {
                    Self::TalkEnd { id: *id, reason }
                }))
            }
            KIND_UPDATE_PART => {
                let (update_id, rest) = body.split_first_chunk::<16>().ok_or(ChatError::Malformed)?;
                let (index, rest) = rest.split_first_chunk::<2>().ok_or(ChatError::Malformed)?;
                let (count, data) = rest.split_first_chunk::<2>().ok_or(ChatError::Malformed)?;
                let (index, count) = (u16::from_be_bytes(*index), u16::from_be_bytes(*count));
                if !(1..=MAX_UPDATE_PARTS).contains(&count)
                    || index >= count
                    || !(1..=UPDATE_PART_LEN).contains(&data.len())
                {
                    return Err(ChatError::Malformed);
                }
                Ok(Some(Self::UpdatePart {
                    update_id: *update_id,
                    index,
                    count,
                    data: data.to_vec(),
                }))
            }
            KIND_GROUP_MESSAGE if !body.is_empty() => Ok(Some(Self::GroupMessage(body.to_vec()))),
            KIND_GROUP_ACK => {
                let (group_id, message_id) = body.split_first_chunk::<16>().ok_or(ChatError::Malformed)?;
                let message_id: [u8; 16] = message_id.try_into().map_err(|_| ChatError::Malformed)?;
                Ok(Some(Self::GroupAck {
                    group_id: *group_id,
                    message_id,
                }))
            }
            KIND_GROUP_LEAVE => {
                let group_id: [u8; 16] = body.try_into().map_err(|_| ChatError::Malformed)?;
                Ok(Some(Self::GroupLeave { group_id }))
            }
            KIND_MEMBER_PROPOSAL => {
                let (id, rest) = body.split_first_chunk::<16>().ok_or(ChatError::Malformed)?;
                let (expires, rest) = rest.split_first_chunk::<8>().ok_or(ChatError::Malformed)?;
                let (person, rest) = rest.split_first_chunk::<32>().ok_or(ChatError::Malformed)?;
                let (person_name, rest) = length_prefixed(rest)?;
                let (group_name, rest) = length_prefixed(rest)?;
                let text = |bytes: &[u8]| {
                    std::str::from_utf8(bytes)
                        .ok()
                        .filter(|s| short_name_ok(s))
                        .map(str::to_owned)
                        .ok_or(ChatError::Malformed)
                };
                if !rest.is_empty() {
                    return Err(ChatError::Malformed);
                }
                Ok(Some(Self::MemberProposal {
                    id: *id,
                    person: PublicIdentity::from_bytes(*person),
                    person_name: text(person_name)?,
                    group_name: text(group_name)?,
                    expires: u64::from_be_bytes(*expires),
                }))
            }
            KIND_MEMBER_PROPOSAL_ANSWER => match body.split_first_chunk::<16>() {
                Some((id, [answer @ (0 | 1)])) => Ok(Some(Self::MemberProposalAnswer {
                    id: *id,
                    agree: *answer == 1,
                })),
                _ => Err(ChatError::Malformed),
            },
            KIND_GROUP_MESSAGE => Err(ChatError::Malformed),
            KIND_MESH_ENVELOPE => Ok(Some(Self::MeshEnvelope(
                Envelope::decode(body).map_err(|_| ChatError::Malformed)?,
            ))),
            KIND_MESH_HAVE => Ok(Some(Self::MeshHave(
                mesh::decode_have(body).map_err(|_| ChatError::Malformed)?,
            ))),
            KIND_MESH_FILE_OFFER => {
                let (id, rest) = body.split_first_chunk::<16>().ok_or(ChatError::Malformed)?;
                let (sent_at, rest) = rest.split_first_chunk::<8>().ok_or(ChatError::Malformed)?;
                let (key, rest) = rest.split_first_chunk::<32>().ok_or(ChatError::Malformed)?;
                Ok(Some(Self::MeshFileOffer {
                    id: *id,
                    sent_at_ms: u64::from_be_bytes(*sent_at),
                    key: Zeroizing::new(*key),
                    meta: decode_file(rest)?,
                }))
            }
            KIND_CHANNEL_HEAD => {
                let body: &[u8; 20] = body.try_into().map_err(|_| ChatError::Malformed)?;
                Ok(Some(Self::ChannelHead {
                    device: body[..16].try_into().expect("16 bytes"),
                    seq: u32::from_be_bytes(body[16..].try_into().expect("4 bytes")),
                }))
            }
            KIND_MESH_UPDATE_KEY => {
                let body: &[u8; 16 + 8 + 16 + 2 + 32] = body.try_into().map_err(|_| ChatError::Malformed)?;
                let count = u16::from_be_bytes([body[40], body[41]]);
                if !(1..=MAX_UPDATE_PARTS).contains(&count) {
                    return Err(ChatError::Malformed);
                }
                Ok(Some(Self::MeshUpdateKey {
                    group_id: body[..16].try_into().expect("16 bytes"),
                    epoch: u64::from_be_bytes(body[16..24].try_into().expect("8 bytes")),
                    update_id: body[24..40].try_into().expect("16 bytes"),
                    count,
                    key: Zeroizing::new(body[42..].try_into().expect("32 bytes")),
                }))
            }
            KIND_PREKEYS => {
                const ENTRY: usize = 4 + ENCAPSULATION_KEY_LEN;
                if body.is_empty() || !body.len().is_multiple_of(ENTRY) || body.len() / ENTRY > MAX_PREKEYS_PER_RECORD {
                    return Err(ChatError::Malformed);
                }
                let mut prekeys = Vec::new();
                for entry in body.chunks(ENTRY) {
                    let (id, key) = entry.split_first_chunk::<4>().ok_or(ChatError::Malformed)?;
                    let id = u32::from_be_bytes(*id);
                    if id == 0 {
                        return Err(ChatError::Malformed);
                    }
                    prekeys.push((id, EncapsulationKey::from_bytes(key).map_err(|_| ChatError::Malformed)?));
                }
                Ok(Some(Self::Prekeys(prekeys)))
            }
            KIND_PREKEYS_WANTED => match body {
                [count] if (1..=MAX_PREKEYS_WANTED).contains(count) => Ok(Some(Self::PrekeysWanted(*count))),
                _ => Err(ChatError::Malformed),
            },
            KIND_STATIC_KEY => {
                let (version, rest) = body.split_first_chunk::<4>().ok_or(ChatError::Malformed)?;
                if rest.len() != ENCAPSULATION_KEY_LEN + SIGNATURE_LEN {
                    return Err(ChatError::Malformed);
                }
                let (key, signature) = rest.split_at(ENCAPSULATION_KEY_LEN);
                Ok(Some(Self::StaticKey {
                    version: u32::from_be_bytes(*version),
                    key: EncapsulationKey::from_bytes(key).map_err(|_| ChatError::Malformed)?,
                    signature: signature.try_into().expect("length checked"),
                }))
            }
            KIND_STATIC_KEY_TAKEN => {
                let version: [u8; 4] = body.try_into().map_err(|_| ChatError::Malformed)?;
                Ok(Some(Self::StaticKeyTaken(u32::from_be_bytes(version))))
            }
            KIND_PRESENCE_KEY => {
                let (version, key) = body.split_first_chunk::<4>().ok_or(ChatError::Malformed)?;
                let key: [u8; 32] = key.try_into().map_err(|_| ChatError::Malformed)?;
                Ok(Some(Self::PresenceKey {
                    version: u32::from_be_bytes(*version),
                    key: Zeroizing::new(key),
                }))
            }
            KIND_PRESENCE_KEY_TAKEN => {
                let version: [u8; 4] = body.try_into().map_err(|_| ChatError::Malformed)?;
                Ok(Some(Self::PresenceKeyTaken(u32::from_be_bytes(version))))
            }
            KIND_BUILD_ATTESTATION => {
                let (&count, mut rest) = body.split_first().ok_or(ChatError::Malformed)?;
                if count == 0 || usize::from(count) > crate::attest::MAX_CERTS {
                    return Err(ChatError::Malformed);
                }
                let mut certs = Vec::with_capacity(usize::from(count));
                for _ in 0..count {
                    let (length, after) = rest.split_first_chunk::<2>().ok_or(ChatError::Malformed)?;
                    let length = usize::from(u16::from_be_bytes(*length));
                    if length == 0 || length > crate::attest::MAX_CERT_LEN || after.len() < length {
                        return Err(ChatError::Malformed);
                    }
                    certs.push(after[..length].to_vec());
                    rest = &after[length..];
                }
                let (&length, proof) = rest.split_first().ok_or(ChatError::Malformed)?;
                if length == 0 || proof.len() != usize::from(length) {
                    return Err(ChatError::Malformed);
                }
                Ok(Some(Self::BuildAttestation {
                    certs,
                    proof: proof.to_vec(),
                }))
            }
            KIND_MESH_WITHDRAW => {
                let (id, secret) = body.split_first_chunk::<16>().ok_or(ChatError::Malformed)?;
                Ok(Some(Self::MeshWithdraw {
                    id: *id,
                    secret: secret.try_into().map_err(|_| ChatError::Malformed)?,
                }))
            }
            KIND_PATH_OFFER => match body {
                [bits] => Ok(Some(Self::PathOffer(Classes::from_bits(*bits)))),
                _ => Err(ChatError::Malformed),
            },
            KIND_PATH_REQUEST => {
                let (path, rest) = body.split_first_chunk::<16>().ok_or(ChatError::Malformed)?;
                let ([class, hops], rest) = rest.split_first_chunk::<2>().ok_or(ChatError::Malformed)?;
                let (nonce, tag) = rest.split_first_chunk::<16>().ok_or(ChatError::Malformed)?;
                Ok(Some(Self::PathRequest(path::Request {
                    path: *path,
                    class: Class::from_bit(*class).ok_or(ChatError::Malformed)?,
                    hops: *hops,
                    nonce: *nonce,
                    tag: tag.try_into().map_err(|_| ChatError::Malformed)?,
                })))
            }
            KIND_PATH_ANSWER => {
                let (path, rest) = body.split_first_chunk::<16>().ok_or(ChatError::Malformed)?;
                let ([providers], proof) = rest.split_first_chunk::<1>().ok_or(ChatError::Malformed)?;
                Ok(Some(Self::PathAnswer {
                    path: *path,
                    providers: *providers,
                    proof: proof.try_into().map_err(|_| ChatError::Malformed)?,
                }))
            }
            KIND_PATH_OPEN => {
                let (path, proof) = body.split_first_chunk::<16>().ok_or(ChatError::Malformed)?;
                Ok(Some(Self::PathOpen {
                    path: *path,
                    proof: proof.try_into().map_err(|_| ChatError::Malformed)?,
                }))
            }
            KIND_PATH_DATA => {
                let (path, rest) = body.split_first_chunk::<16>().ok_or(ChatError::Malformed)?;
                let ([more], data) = rest.split_first_chunk::<1>().ok_or(ChatError::Malformed)?;
                if *more > 1 || !(1..=path::MAX_DATA).contains(&data.len()) {
                    return Err(ChatError::Malformed);
                }
                Ok(Some(Self::PathData {
                    path: *path,
                    more: *more == 1,
                    data: data.to_vec(),
                }))
            }
            KIND_PATH_CREDIT => {
                let (path, bytes) = body.split_first_chunk::<16>().ok_or(ChatError::Malformed)?;
                let bytes: [u8; 4] = bytes.try_into().map_err(|_| ChatError::Malformed)?;
                Ok(Some(Self::PathCredit {
                    path: *path,
                    bytes: u32::from_be_bytes(bytes),
                }))
            }
            KIND_PATH_CLOSE => Ok(Some(Self::PathClose {
                path: body.try_into().map_err(|_| ChatError::Malformed)?,
            })),
            KIND_AUDIO => {
                let (stream, rest) = body.split_first_chunk::<16>().ok_or(ChatError::Malformed)?;
                let (seq, packet) = rest.split_first_chunk::<4>().ok_or(ChatError::Malformed)?;
                if !(1..=MAX_AUDIO_PACKET).contains(&packet.len()) {
                    return Err(ChatError::Malformed);
                }
                Ok(Some(Self::Audio {
                    stream: *stream,
                    seq: u32::from_be_bytes(*seq),
                    packet: Zeroizing::new(packet.to_vec()),
                }))
            }
            KIND_CALL_PRESENCE => {
                let (body, camera) = body
                    .split_first_chunk::<{ 16 + 8 + 32 + 4 }>()
                    .ok_or(ChatError::Malformed)?;
                let camera = match camera {
                    [] => VideoState::Off,
                    &[code] => VideoState::from_code(code),
                    _ => return Err(ChatError::Malformed),
                };
                Ok(Some(Self::CallPresence {
                    stream: body[..16].try_into().expect("16 bytes"),
                    origin: body[16..24].try_into().expect("8 bytes"),
                    member: crate::identity::PublicIdentity::from_bytes(body[24..56].try_into().expect("32 bytes")),
                    count: u32::from_be_bytes(body[56..].try_into().expect("4 bytes")),
                    camera,
                }))
            }
            KIND_CALL_VIDEO => {
                let (stream, rest) = body.split_first_chunk::<16>().ok_or(ChatError::Malformed)?;
                let (origin, rest) = rest.split_first_chunk::<8>().ok_or(ChatError::Malformed)?;
                let (frame, rest) = rest.split_first_chunk::<4>().ok_or(ChatError::Malformed)?;
                let (&[flags, rotation], rest) = rest.split_first_chunk::<2>().ok_or(ChatError::Malformed)?;
                let (width, rest) = rest.split_first_chunk::<2>().ok_or(ChatError::Malformed)?;
                let (height, rest) = rest.split_first_chunk::<2>().ok_or(ChatError::Malformed)?;
                let (&[part, parts], data) = rest.split_first_chunk::<2>().ok_or(ChatError::Malformed)?;
                let header = VideoHeader {
                    frame: u32::from_be_bytes(*frame),
                    key: flags & VIDEO_KEY_FRAME != 0,
                    rotation,
                    width: u16::from_be_bytes(*width),
                    height: u16::from_be_bytes(*height),
                };
                header.check()?;
                check_video_part(part, parts, data)?;
                Ok(Some(Self::CallVideo {
                    stream: *stream,
                    origin: *origin,
                    header,
                    part,
                    parts,
                    data: Zeroizing::new(data.to_vec()),
                }))
            }
            KIND_CALL_KEY_FRAME_REQUEST => {
                let body: &[u8; 16 + 8 + 8] = body.try_into().map_err(|_| ChatError::Malformed)?;
                Ok(Some(Self::CallKeyFrameRequest {
                    stream: body[..16].try_into().expect("16 bytes"),
                    origin: body[16..24].try_into().expect("8 bytes"),
                    nonce: body[24..].try_into().expect("8 bytes"),
                }))
            }
            KIND_CALL_AUDIO => {
                let (stream, rest) = body.split_first_chunk::<16>().ok_or(ChatError::Malformed)?;
                let (origin, rest) = rest.split_first_chunk::<8>().ok_or(ChatError::Malformed)?;
                let (seq, packet) = rest.split_first_chunk::<4>().ok_or(ChatError::Malformed)?;
                if !(1..=MAX_AUDIO_PACKET).contains(&packet.len()) {
                    return Err(ChatError::Malformed);
                }
                Ok(Some(Self::CallAudio {
                    stream: *stream,
                    origin: *origin,
                    seq: u32::from_be_bytes(*seq),
                    packet: Zeroizing::new(packet.to_vec()),
                }))
            }
            KIND_PING | KIND_PONG if body.is_empty() => {
                Ok(Some(if kind == KIND_PING { Self::Ping } else { Self::Pong }))
            }
            KIND_PING | KIND_PONG => Err(ChatError::Malformed),
            KIND_MOVE_REQUEST | KIND_MOVE_DECLINED => {
                let &[target] = body else {
                    return Err(ChatError::Malformed);
                };
                Ok(Some(if kind == KIND_MOVE_REQUEST {
                    Self::MoveRequest { target }
                } else {
                    Self::MoveDeclined { target }
                }))
            }
            KIND_HOTSPOT_OFFER => {
                let (port, rest) = body.split_first_chunk::<2>().ok_or(ChatError::Malformed)?;
                let (ssid, rest) = length_prefixed(rest)?;
                let (passphrase, rest) = length_prefixed(rest)?;
                if !rest.is_empty() {
                    return Err(ChatError::Malformed);
                }
                let offer = HotspotOffer {
                    ssid: std::str::from_utf8(ssid).map_err(|_| ChatError::Malformed)?.to_owned(),
                    passphrase: std::str::from_utf8(passphrase)
                        .map_err(|_| ChatError::Malformed)?
                        .to_owned(),
                    port: u16::from_be_bytes(*port),
                };
                offer.check().map_err(|_| ChatError::Malformed)?;
                Ok(Some(Self::HotspotOffer(offer)))
            }
            _ => Ok(None),
        }
    }
}

/// A name a one-byte length carries: 1 to 255 bytes, no control characters.
fn short_name_ok(name: &str) -> bool {
    (1..=255).contains(&name.len()) && !name.chars().any(char::is_control)
}

fn length_prefixed(bytes: &[u8]) -> Result<(&[u8], &[u8]), ChatError> {
    let (&length, rest) = bytes.split_first().ok_or(ChatError::Malformed)?;
    rest.split_at_checked(usize::from(length)).ok_or(ChatError::Malformed)
}

pub fn check_text(text: &str) -> Result<(), ChatError> {
    if text.is_empty() || text.len() > MAX_TEXT_BYTES {
        return Err(ChatError::InvalidText);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every message kind with fixed inputs, in `tests/vectors/chat_messages.json`
    /// (`check_chat.py` re-derives them from docs/protocol.md §8).
    #[test]
    fn vector() {
        use crate::crypto::{
            hash::sha256,
            test_util::{check_vector, to_hex},
        };
        let id: MessageId = std::array::from_fn(|i| i as u8 + 1);
        let sent_at_ms = 1_791_400_000_000;
        let file: Vec<u8> = (0..CHUNK_LEN + 40).map(|i| (i * 7 + 3) as u8).collect();
        let meta = FileMeta {
            name: "tatil fotoğrafı.jpg".into(),
            mime: "image/jpeg".into(),
            size: file.len() as u64,
            sha256: sha256(&[&file]),
            thumbnail: Some(vec![0xff, 0xd8, 0xff, 0xd9]),
        };
        let encode = |message: ChatMessage| to_hex(&message.encode().unwrap());
        let chunk = |index: usize| ChatMessage::Chunk {
            id,
            index: index as u64,
            data: Zeroizing::new(file[index * CHUNK_LEN..file.len().min((index + 1) * CHUNK_LEN)].to_vec()),
        };
        // Version 5 of a static key, signed by its owner's identity key (§6.9).
        let owner = crate::identity::Identity::from_seed(crate::crypto::SecretBytes::from_slice(&[0x51; 32]).unwrap());
        let key = crate::crypto::kem::DecapsulationKey::from_seed(
            crate::crypto::SecretBytes::from_slice(&[0x52; 32]).unwrap(),
        )
        .unwrap()
        .encapsulation_key()
        .clone();
        let static_key = ChatMessage::StaticKey {
            version: 5,
            signature: owner.sign_static_key(5, &key),
            key,
        };
        check_vector(
            "chat_messages",
            &[
                ("message_id", to_hex(&id)),
                ("sent_at_ms", sent_at_ms.to_string()),
                (
                    "text",
                    encode(ChatMessage::Text {
                        id,
                        sent_at_ms,
                        text: "Merhaba 👋".into(),
                    }),
                ),
                ("ack", encode(ChatMessage::Ack { id })),
                ("refused", encode(ChatMessage::Refused { id })),
                ("call_offer", encode(ChatMessage::CallOffer { id, video: false })),
                ("video_call_offer", encode(ChatMessage::CallOffer { id, video: true })),
                (
                    "video_state",
                    encode(ChatMessage::VideoState {
                        id,
                        state: VideoState::Paused,
                    }),
                ),
                (
                    "video",
                    encode(ChatMessage::Video {
                        stream: id,
                        header: VideoHeader {
                            frame: 300,
                            key: true,
                            rotation: 3,
                            width: 1280,
                            height: 720,
                        },
                        part: 1,
                        parts: 3,
                        data: Zeroizing::new(vec![0x65; 40]),
                    }),
                ),
                ("key_frame_request", encode(ChatMessage::KeyFrameRequest { id })),
                ("ringing", encode(ChatMessage::Ringing { id })),
                (
                    "update_part",
                    encode(ChatMessage::UpdatePart {
                        update_id: id,
                        index: 1,
                        count: 2,
                        data: vec![0xab; 5],
                    }),
                ),
                ("group_message", encode(ChatMessage::GroupMessage(vec![0xcd; 4]))),
                (
                    "group_ack",
                    encode(ChatMessage::GroupAck {
                        group_id: [0x67; 16],
                        message_id: id,
                    }),
                ),
                ("group_leave", encode(ChatMessage::GroupLeave { group_id: [0x67; 16] })),
                (
                    "group_talk_start",
                    encode(ChatMessage::GroupTalkStart {
                        id,
                        group_id: [0x67; 16],
                    }),
                ),
                (
                    "group_call",
                    encode(ChatMessage::GroupCall {
                        id,
                        group_id: [0x67; 16],
                    }),
                ),
                ("group_call_leave", encode(ChatMessage::GroupCallLeave { id })),
                (
                    "call_presence",
                    encode(ChatMessage::CallPresence {
                        stream: id,
                        origin: [0x0c; 8],
                        member: crate::identity::PublicIdentity::from_bytes([0x5e; 32]),
                        count: 7,
                        camera: VideoState::Off,
                    }),
                ),
                (
                    "call_presence_camera",
                    encode(ChatMessage::CallPresence {
                        stream: id,
                        origin: [0x0c; 8],
                        member: crate::identity::PublicIdentity::from_bytes([0x5e; 32]),
                        count: 8,
                        camera: VideoState::On,
                    }),
                ),
                (
                    "call_video",
                    encode(ChatMessage::CallVideo {
                        stream: id,
                        origin: [0x0c; 8],
                        header: VideoHeader {
                            frame: 41,
                            key: false,
                            rotation: 1,
                            width: 640,
                            height: 360,
                        },
                        part: 0,
                        parts: 2,
                        data: Zeroizing::new(vec![0x41; 24]),
                    }),
                ),
                (
                    "call_key_frame_request",
                    encode(ChatMessage::CallKeyFrameRequest {
                        stream: id,
                        origin: [0x0c; 8],
                        nonce: [0x7a; 8],
                    }),
                ),
                (
                    "call_audio",
                    encode(ChatMessage::CallAudio {
                        stream: id,
                        origin: [0x0c; 8],
                        seq: 9,
                        packet: Zeroizing::new(b"opus".to_vec()),
                    }),
                ),
                ("call_accept", encode(ChatMessage::CallAccept { id })),
                (
                    "call_end",
                    encode(ChatMessage::CallEnd {
                        id,
                        reason: EndReason::Declined,
                    }),
                ),
                ("talk_start", encode(ChatMessage::TalkStart { id })),
                (
                    "talk_end",
                    encode(ChatMessage::TalkEnd {
                        id,
                        reason: EndReason::Interrupted,
                    }),
                ),
                (
                    "audio",
                    encode(ChatMessage::Audio {
                        stream: id,
                        seq: 70_000,
                        packet: Zeroizing::new(vec![0x4b; 60]),
                    }),
                ),
                ("ping", encode(ChatMessage::Ping)),
                ("pong", encode(ChatMessage::Pong)),
                (
                    "move_request",
                    encode(ChatMessage::MoveRequest {
                        target: MoveTarget::Hotspot.code(),
                    }),
                ),
                (
                    "hotspot_offer",
                    encode(ChatMessage::HotspotOffer(HotspotOffer {
                        ssid: "AndroidShare_4821".into(),
                        passphrase: "k7q2m9x4p1".into(),
                        port: 40123,
                    })),
                ),
                (
                    "move_declined",
                    encode(ChatMessage::MoveDeclined {
                        target: MoveTarget::Hotspot.code(),
                    }),
                ),
                ("static_key_identity_seed", to_hex(owner.seed().expose())),
                ("static_key", encode(static_key)),
                ("static_key_taken", encode(ChatMessage::StaticKeyTaken(5))),
                (
                    "presence_key",
                    encode(ChatMessage::PresenceKey {
                        version: 2,
                        key: Zeroizing::new([0x6b; 32]),
                    }),
                ),
                ("presence_key_taken", encode(ChatMessage::PresenceKeyTaken(2))),
                (
                    "build_attestation",
                    encode(ChatMessage::BuildAttestation {
                        certs: vec![vec![0x30, 0x03, 0x02, 0x01, 0x07], vec![0x30; 300]],
                        proof: vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02],
                    }),
                ),
                (
                    "member_proposal",
                    encode(ChatMessage::MemberProposal {
                        id,
                        person: owner.public(),
                        person_name: "Cem".into(),
                        group_name: "Üçümüz".into(),
                        expires: 1_800_000_000,
                    }),
                ),
                (
                    "member_proposal_answer",
                    encode(ChatMessage::MemberProposalAnswer { id, agree: true }),
                ),
                ("file_size", file.len().to_string()),
                ("file_sha256", to_hex(&meta.sha256)),
                ("file_offer", encode(ChatMessage::FileOffer { id, sent_at_ms, meta })),
                (
                    "chunk_request",
                    encode(ChatMessage::ChunkRequest {
                        id,
                        first: 0,
                        count: 16,
                    }),
                ),
                ("chunk_0_sha256", to_hex(&sha256(&[&chunk(0).encode().unwrap()]))),
                ("chunk_1", encode(chunk(1))),
                (
                    "unavailable_not_now",
                    encode(ChatMessage::FileUnavailable {
                        id,
                        reason: Unavailable::NotNow,
                    }),
                ),
                (
                    "unavailable_gone",
                    encode(ChatMessage::FileUnavailable {
                        id,
                        reason: Unavailable::Gone,
                    }),
                ),
            ],
        );
    }

    #[test]
    fn round_trip() {
        for message in [
            ChatMessage::Text {
                id: [7; 16],
                sent_at_ms: 1_760_000_000_000,
                text: "merhaba 👋".into(),
            },
            ChatMessage::Ack { id: [9; 16] },
            ChatMessage::Refused { id: [8; 16] },
            ChatMessage::CallOffer {
                id: [1; 16],
                video: false,
            },
            ChatMessage::CallOffer {
                id: [1; 16],
                video: true,
            },
            ChatMessage::Ringing { id: [1; 16] },
            ChatMessage::VideoState {
                id: [1; 16],
                state: VideoState::On,
            },
            ChatMessage::Video {
                stream: [1; 16],
                header: VideoHeader {
                    frame: u32::MAX,
                    key: false,
                    rotation: 1,
                    width: 640,
                    height: 480,
                },
                part: MAX_VIDEO_PARTS - 1,
                parts: MAX_VIDEO_PARTS,
                data: Zeroizing::new(vec![3; VIDEO_PART_LEN]),
            },
            ChatMessage::KeyFrameRequest { id: [1; 16] },
            ChatMessage::UpdatePart {
                update_id: [4; 16],
                index: 2,
                count: 3,
                data: vec![1; UPDATE_PART_LEN],
            },
            ChatMessage::GroupMessage(vec![5; 300]),
            ChatMessage::GroupAck {
                group_id: [6; 16],
                message_id: [7; 16],
            },
            ChatMessage::GroupLeave { group_id: [6; 16] },
            ChatMessage::GroupTalkStart {
                id: [8; 16],
                group_id: [6; 16],
            },
            ChatMessage::GroupCall {
                id: [9; 16],
                group_id: [6; 16],
            },
            ChatMessage::GroupCallLeave { id: [9; 16] },
            ChatMessage::CallAccept { id: [1; 16] },
            ChatMessage::CallEnd {
                id: [1; 16],
                reason: EndReason::Busy,
            },
            ChatMessage::TalkStart { id: [2; 16] },
            ChatMessage::TalkEnd {
                id: [2; 16],
                reason: EndReason::HungUp,
            },
            ChatMessage::Audio {
                stream: [2; 16],
                seq: u32::MAX,
                packet: Zeroizing::new(vec![7; MAX_AUDIO_PACKET]),
            },
            ChatMessage::Ping,
            ChatMessage::Pong,
            ChatMessage::FileOffer {
                id: [4; 16],
                sent_at_ms: 99,
                meta: file(),
            },
            ChatMessage::FileOffer {
                id: [4; 16],
                sent_at_ms: 99,
                meta: FileMeta {
                    thumbnail: None,
                    ..file()
                },
            },
            ChatMessage::ChunkRequest {
                id: [4; 16],
                first: 3,
                count: 32,
            },
            ChatMessage::Chunk {
                id: [4; 16],
                index: 3,
                data: Zeroizing::new(vec![5; CHUNK_LEN]),
            },
            ChatMessage::FileUnavailable {
                id: [4; 16],
                reason: Unavailable::Gone,
            },
            ChatMessage::MoveRequest { target: 1 },
            ChatMessage::MoveDeclined { target: 7 },
            ChatMessage::HotspotOffer(offer()),
        ] {
            assert_eq!(ChatMessage::decode(&message.encode().unwrap()), Ok(Some(message)));
        }
    }

    fn file() -> FileMeta {
        FileMeta {
            name: "kedi fotoğrafı.jpg".into(),
            mime: "image/jpeg".into(),
            size: 123_456,
            sha256: [8; 32],
            thumbnail: Some(vec![1, 2, 3]),
        }
    }

    #[test]
    fn file_messages_check_their_limits() {
        for bad in [
            FileMeta {
                name: String::new(),
                ..file()
            },
            FileMeta {
                name: "a\nb".into(),
                ..file()
            },
            FileMeta {
                name: "x".repeat(256),
                ..file()
            },
            FileMeta {
                mime: "jpeg".into(),
                ..file()
            },
            FileMeta {
                mime: "image/ jpeg".into(),
                ..file()
            },
            FileMeta {
                thumbnail: Some(Vec::new()),
                ..file()
            },
            FileMeta {
                thumbnail: Some(vec![0; MAX_THUMBNAIL_BYTES + 1]),
                ..file()
            },
            FileMeta {
                size: MAX_FILE_SIZE + 1,
                ..file()
            },
        ] {
            let offer = ChatMessage::FileOffer {
                id: [1; 16],
                sent_at_ms: 1,
                meta: bad,
            };
            assert_eq!(offer.encode(), Err(ChatError::InvalidFile));
        }
        let request = |count| ChatMessage::ChunkRequest {
            id: [1; 16],
            first: 0,
            count,
        };
        assert_eq!(request(0).encode(), Err(ChatError::Malformed));
        assert_eq!(request(MAX_CHUNKS_PER_REQUEST + 1).encode(), Err(ChatError::Malformed));
        let chunk = |len| ChatMessage::Chunk {
            id: [1; 16],
            index: 0,
            data: Zeroizing::new(vec![0; len]),
        };
        assert_eq!(chunk(0).encode(), Err(ChatError::Malformed));
        assert_eq!(chunk(CHUNK_LEN + 1).encode(), Err(ChatError::Malformed));
        assert_eq!(
            ChatMessage::decode(&[[0x23].as_slice(), &[1; 16], &[3]].concat()),
            Err(ChatError::Malformed)
        );

        let encoded = ChatMessage::FileOffer {
            id: [1; 16],
            sent_at_ms: 1,
            meta: file(),
        }
        .encode()
        .unwrap();
        assert_eq!(
            ChatMessage::decode(&encoded[..encoded.len() - 1]),
            Err(ChatError::Malformed),
            "short thumbnail"
        );
    }

    fn offer() -> HotspotOffer {
        HotspotOffer {
            ssid: "AndroidShare_4821".into(),
            passphrase: "x9Fq2mZ7pL".into(),
            port: 40_123,
        }
    }

    #[test]
    fn hotspot_offer_layout_and_limits() {
        let bytes = ChatMessage::HotspotOffer(offer()).encode().unwrap();
        assert_eq!(
            bytes,
            [&[0x11, 0x9c, 0xbb, 17][..], b"AndroidShare_4821", &[10], b"x9Fq2mZ7pL"].concat()
        );
        assert_eq!(
            ChatMessage::decode(&[&bytes[..], &[0]].concat()),
            Err(ChatError::Malformed),
            "trailing"
        );
        assert_eq!(
            ChatMessage::decode(&bytes[..bytes.len() - 1]),
            Err(ChatError::Malformed),
            "short"
        );
        for bad in [
            HotspotOffer {
                ssid: String::new(),
                ..offer()
            },
            HotspotOffer {
                ssid: "x".repeat(33),
                ..offer()
            },
            HotspotOffer {
                passphrase: "short".into(),
                ..offer()
            },
            HotspotOffer {
                passphrase: "şifre1234".into(),
                ..offer()
            },
            HotspotOffer { port: 0, ..offer() },
        ] {
            assert_eq!(ChatMessage::HotspotOffer(bad).encode(), Err(ChatError::InvalidOffer));
        }
        assert_eq!(ChatMessage::decode(&[0x10]), Err(ChatError::Malformed));
        assert_eq!(
            ChatMessage::decode(&[0x03, 0]),
            Err(ChatError::Malformed),
            "a ping has no body"
        );
        assert_eq!(ChatMessage::decode(&[0x12, 1, 2]), Err(ChatError::Malformed));
        assert_eq!(
            MoveTarget::from_code(MoveTarget::Hotspot.code()),
            Some(MoveTarget::Hotspot)
        );
        assert_eq!(MoveTarget::from_code(9), None);
    }

    #[test]
    fn video_records_check_their_limits_and_tolerate_later_versions() {
        let header = VideoHeader {
            frame: 0,
            key: true,
            rotation: 0,
            width: 1280,
            height: 720,
        };
        let part = |header, part, parts, len| ChatMessage::Video {
            stream: [1; 16],
            header,
            part,
            parts,
            data: Zeroizing::new(vec![0; len]),
        };
        for bad in [
            part(header, 0, 1, 0),
            part(header, 0, 1, VIDEO_PART_LEN + 1),
            part(header, 1, 1, 10),
            part(header, 0, 0, 10),
            part(header, 0, MAX_VIDEO_PARTS + 1, 10),
            part(VideoHeader { rotation: 4, ..header }, 0, 1, 10),
            part(VideoHeader { width: 0, ..header }, 0, 1, 10),
            part(
                VideoHeader {
                    height: MAX_VIDEO_SIDE + 1,
                    ..header
                },
                0,
                1,
                10,
            ),
        ] {
            assert_eq!(bad.encode(), Err(ChatError::Malformed));
        }
        let mut bytes = part(header, 0, 1, 10).encode().unwrap();
        bytes[21] |= 0x80;
        assert!(
            matches!(
                ChatMessage::decode(&bytes),
                Ok(Some(ChatMessage::Video {
                    header: VideoHeader { key: true, .. },
                    ..
                }))
            ),
            "unknown flags are ignored"
        );
        let state = |code| ChatMessage::decode(&[[0x3a].as_slice(), &[1; 16], &[code]].concat());
        assert_eq!(
            state(9),
            Ok(Some(ChatMessage::VideoState {
                id: [1; 16],
                state: VideoState::Off
            }))
        );
        let offer = |media: &[u8]| ChatMessage::decode(&[[0x30].as_slice(), &[1; 16], media].concat());
        assert_eq!(
            offer(&[7]),
            Ok(Some(ChatMessage::CallOffer {
                id: [1; 16],
                video: false
            })),
            "media from a later version ring as a voice call"
        );
        assert_eq!(offer(&[1, 1]), Err(ChatError::Malformed));
    }

    #[test]
    fn layout() {
        let text = ChatMessage::Text {
            id: [1; 16],
            sent_at_ms: 2,
            text: "a".into(),
        };
        assert_eq!(
            text.encode().unwrap(),
            [&[1][..], &[1; 16], &[0, 0, 0, 0, 0, 0, 0, 2], b"a"].concat()
        );
    }

    #[test]
    fn rejects_bad_messages_and_ignores_unknown_kinds() {
        assert_eq!(ChatMessage::decode(&[]), Err(ChatError::Malformed));
        assert_eq!(ChatMessage::decode(&[1; 20]), Err(ChatError::Malformed), "too short");
        assert_eq!(
            ChatMessage::decode(&[[1u8].as_slice(), &[0; 24]].concat()),
            Err(ChatError::Malformed),
            "empty text"
        );
        assert_eq!(
            ChatMessage::decode(&[[1u8].as_slice(), &[0; 24], &[0xff]].concat()),
            Err(ChatError::Malformed),
            "not UTF-8"
        );
        assert_eq!(ChatMessage::decode(&[2; 16]), Err(ChatError::Malformed), "short ack");
        assert_eq!(ChatMessage::decode(&[0x7f, 1, 2]), Ok(None));
        let long = ChatMessage::Text {
            id: [0; 16],
            sent_at_ms: 0,
            text: "x".repeat(MAX_TEXT_BYTES + 1),
        };
        assert_eq!(long.encode(), Err(ChatError::InvalidText));
    }
}
