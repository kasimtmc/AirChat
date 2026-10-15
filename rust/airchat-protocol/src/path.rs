//! Paths through Air Providers (docs/protocol.md §12): classes, the records that find, open and
//! carry a path, and the tags and proofs only its two ends can make. Formats and cryptography only;
//! finding and carrying paths lives in the node.

use crate::{
    crypto::{CryptoError, SecretBytes, hash::hmac_sha256, kdf},
    identity::AirChatId,
    labels,
};

pub const PATH_ID_LEN: usize = 16;
pub type PathId = [u8; PATH_ID_LEN];
pub type PathNonce = [u8; 16];
pub const TAG_LEN: usize = 16;
pub type PathTag = [u8; TAG_LEN];
pub type Proof = [u8; 16];
/// Bytes of a frame one data record carries at most.
pub const MAX_DATA: usize = 16_366;
/// Largest frame carried over a path.
pub const MAX_FRAME: usize = 65_536;

/// What a path carries (§12.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Class {
    /// Messages, calls and push-to-talk.
    Voice,
    /// As voice, and video.
    Video,
    /// Messages and files.
    Files,
}

impl Class {
    pub const ALL: [Class; 3] = [Class::Voice, Class::Video, Class::Files];

    pub fn bit(self) -> u8 {
        match self {
            Class::Voice => 0x01,
            Class::Video => 0x02,
            Class::Files => 0x04,
        }
    }

    pub fn from_bit(bit: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.bit() == bit)
    }

    /// Providers a path of this class runs through at most.
    pub fn max_providers(self) -> u8 {
        match self {
            Class::Voice => 4,
            Class::Video => 2,
            Class::Files => 6,
        }
    }

    /// Data bytes an end may have sent and not yet credited.
    pub fn window(self) -> usize {
        match self {
            Class::Voice => 32 * 1024,
            Class::Video => 128 * 1024,
            Class::Files => 256 * 1024,
        }
    }

    pub fn carries_video(self) -> bool {
        self == Class::Video
    }

    pub fn carries_files(self) -> bool {
        self == Class::Files
    }
}

/// The classes a provider carries for others, as offered (§12.1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Classes(u8);

impl Classes {
    pub const NONE: Classes = Classes(0);

    /// From an offer's bits; unknown bits are ignored.
    pub fn from_bits(bits: u8) -> Self {
        Self(bits & Class::ALL.iter().fold(0, |all, c| all | c.bit()))
    }

    pub fn bits(self) -> u8 {
        self.0
    }

    pub fn contains(self, class: Class) -> bool {
        self.0 & class.bit() != 0
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// A request for a path (§12.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub path: PathId,
    pub class: Class,
    /// How many more providers may carry it.
    pub hops: u8,
    pub nonce: PathNonce,
    pub tag: PathTag,
}

/// The tag on a request from `a` for its contact `b`, made with `tag_key(a -> b)` of §10.3.
pub fn request_tag(tag_key: &SecretBytes<32>, nonce: &PathNonce) -> PathTag {
    hmac_sha256(tag_key.expose(), &[labels::PATH_TAG, nonce]).expose()[..TAG_LEN]
        .try_into()
        .expect("a MAC is longer than a tag")
}

/// The key of the tags and proofs of a path to the owner of `id`, for a request to add them
/// (§4.8): whoever knows the ID can make both, as with the request's beacon.
pub fn request_path_key(id: &AirChatId) -> Result<SecretBytes<32>, CryptoError> {
    kdf::derive(&[], id.as_bytes(), labels::ID_REQUEST_PATH_KEY)
}

/// The proof in `b`'s answer, made with `tag_key(b -> a)`.
pub fn proof(tag_key: &SecretBytes<32>, path: &PathId, nonce: &PathNonce) -> Proof {
    hmac_sha256(tag_key.expose(), &[labels::PATH_ANSWER, path, nonce]).expose()[..16]
        .try_into()
        .expect("a MAC is longer than a proof")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{chat::ChatMessage, identity::Identity, mesh::contact_tag_key};

    #[test]
    fn offers_keep_known_classes_only() {
        let classes = Classes::from_bits(0xff);
        assert_eq!(classes.bits(), 0x07);
        assert!(Class::ALL.iter().all(|c| classes.contains(*c)));
        assert!(Classes::from_bits(0x08).is_empty());
        assert_eq!(Class::from_bit(0x03), None);
    }

    #[test]
    fn only_the_two_contacts_make_tags_and_proofs() {
        let ayse = Identity::generate().unwrap().public();
        let burak = Identity::generate().unwrap().public();
        let psk = SecretBytes::random().unwrap();
        let (to_burak, to_ayse) = (
            contact_tag_key(&psk, &ayse, &burak).unwrap(),
            contact_tag_key(&psk, &burak, &ayse).unwrap(),
        );
        let (path, nonce) = ([1; 16], [2; 16]);
        assert_ne!(
            request_tag(&to_burak, &nonce),
            request_tag(&to_burak, &[3; 16]),
            "new each time"
        );
        assert_ne!(request_tag(&to_burak, &nonce), request_tag(&to_ayse, &nonce));
        assert_ne!(proof(&to_ayse, &path, &nonce), proof(&to_burak, &path, &nonce));
        let other = SecretBytes::random().unwrap();
        assert_ne!(proof(&to_ayse, &path, &nonce), proof(&other, &path, &nonce));
    }

    #[test]
    fn path_records_round_trip() {
        let records = [
            ChatMessage::PathOffer(Classes::from_bits(0x05)),
            ChatMessage::PathRequest(Request {
                path: [1; 16],
                class: Class::Video,
                hops: 2,
                nonce: [2; 16],
                tag: [3; 16],
            }),
            ChatMessage::PathAnswer {
                path: [1; 16],
                providers: 1,
                proof: [4; 16],
            },
            ChatMessage::PathOpen {
                path: [1; 16],
                proof: [4; 16],
            },
            ChatMessage::PathData {
                path: [1; 16],
                more: true,
                data: vec![9; MAX_DATA],
            },
            ChatMessage::PathCredit {
                path: [1; 16],
                bytes: 8192,
            },
            ChatMessage::PathClose { path: [1; 16] },
        ];
        for record in records {
            let bytes = record.encode().unwrap();
            assert!(bytes.len() <= crate::link::MAX_RECORD_PAYLOAD);
            assert_eq!(ChatMessage::decode(&bytes).unwrap(), Some(record));
        }
        let empty = [&[0x56][..], &[1; 16], &[0]].concat();
        assert!(ChatMessage::decode(&empty).is_err(), "data carries bytes");
        let two_classes = [&[0x53][..], &[1; 16], &[0x03, 2], &[2; 16], &[3; 16]].concat();
        assert!(ChatMessage::decode(&two_classes).is_err());
    }

    #[test]
    fn published_paths_vector() {
        use crate::{crypto::test_util::check_vector, crypto::test_util::to_hex};
        let ayse = Identity::from_seed(SecretBytes::from_slice(&[0xa1; 32]).unwrap()).public();
        let burak = Identity::from_seed(SecretBytes::from_slice(&[0xb2; 32]).unwrap()).public();
        let psk = SecretBytes::from_slice(&[0x5a; 32]).unwrap();
        let (path, nonce) = ([0x3c; 16], [0x6e; 16]);
        let tag = request_tag(&contact_tag_key(&psk, &ayse, &burak).unwrap(), &nonce);
        let proof = proof(&contact_tag_key(&psk, &burak, &ayse).unwrap(), &path, &nonce);
        let encode = |record: ChatMessage| to_hex(&record.encode().unwrap());
        // A walkie-talkie channel's members (§11.5): one key, for tags and proofs alike.
        let channel = crate::channel::Channel::from_key(SecretBytes::from_slice(&[0x4b; 32]).unwrap()).unwrap();
        let channel_key = channel.path_key().unwrap();
        let proof_for = super::proof;
        let (head, cluster_random) = ([0xd1; 16], [0x7c; 8]);
        let cluster_nonce = crate::channel::cluster_nonce(&channel_key, &head, &cluster_random);
        assert!(crate::channel::from_cluster(&channel_key, &head, &cluster_nonce));
        assert!(!crate::channel::from_cluster(&channel_key, &[0xd2; 16], &cluster_nonce));
        let id_key = request_path_key(&burak.airchat_id()).unwrap();
        let fields: Vec<(&str, String)> = vec![
            ("ik_a", to_hex(ayse.as_bytes())),
            ("ik_b", to_hex(burak.as_bytes())),
            ("psk", to_hex(psk.expose())),
            ("path", to_hex(&path)),
            ("nonce", to_hex(&nonce)),
            ("tag", to_hex(&tag)),
            ("proof", to_hex(&proof)),
            ("offer_record", encode(ChatMessage::PathOffer(Classes::from_bits(0x03)))),
            (
                "request_record",
                encode(ChatMessage::PathRequest(Request {
                    path,
                    class: Class::Video,
                    hops: Class::Video.max_providers(),
                    nonce,
                    tag,
                })),
            ),
            (
                "answer_record",
                encode(ChatMessage::PathAnswer {
                    path,
                    providers: 1,
                    proof,
                }),
            ),
            ("open_record", encode(ChatMessage::PathOpen { path, proof })),
            (
                "data_record",
                encode(ChatMessage::PathData {
                    path,
                    more: false,
                    data: b"frame".to_vec(),
                }),
            ),
            ("credit_record", encode(ChatMessage::PathCredit { path, bytes: 8192 })),
            ("close_record", encode(ChatMessage::PathClose { path })),
            ("channel_key", to_hex(&[0x4b; 32])),
            ("channel_path_key", to_hex(channel_key.expose())),
            ("channel_tag", to_hex(&request_tag(&channel_key, &nonce))),
            ("channel_proof", to_hex(&proof_for(&channel_key, &path, &nonce))),
            // A request from the cluster whose head is `head`, and the head as members tell it.
            ("channel_head", to_hex(&head)),
            ("cluster_random", to_hex(&cluster_random)),
            ("cluster_nonce", to_hex(&cluster_nonce)),
            (
                "channel_head_record",
                encode(ChatMessage::ChannelHead { device: head, seq: 42 }),
            ),
            // A path to the owner of an AirChat ID, for a request to add them (§4.8): Burak's.
            ("id", to_hex(burak.airchat_id().as_bytes())),
            ("id_path_key", to_hex(id_key.expose())),
            ("id_tag", to_hex(&request_tag(&id_key, &nonce))),
            ("id_proof", to_hex(&proof_for(&id_key, &path, &nonce))),
        ];
        check_vector("paths", &fields);
    }
}
