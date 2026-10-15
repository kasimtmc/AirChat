//! Fuzz targets: every parser of bytes that come from another device, each a function that must
//! not panic whatever its input, and that checks what it can: what a decoder accepts encodes back
//! to the same bytes (or, where decoding normalises, to the same value).
//!
//! `cargo test` runs them over mutations of the published test vectors ([`harness`]); `fuzz/` runs
//! them under libFuzzer, guided by coverage. An application on top adds its own targets for what it
//! keeps and for its node as a whole (the AirChat app does, in `airchat_core::fuzz`).

use std::sync::OnceLock;

use crate::{
    channel::{Channel, Hello},
    chat::ChatMessage,
    crypto::{SecretBytes, kem::DecapsulationKey},
    discovery::{AwareBeacon, BleBeacon},
    group::{Content, Message, Roster, Update},
    identity::{AirChatId, Identity},
    link::{
        self, ChannelInitiator, ChannelKeys, ChannelResponder, Flavor, Initiator, LocalKeys, RemoteKeys, Responder,
    },
    mesh::{self, Envelope, Pair, UpdatePart},
    pairing::{self, LocalProfile, Pairing, ScannedInvite},
};

/// Keys of a device the targets play, made once.
struct Keys {
    identity: Identity,
    kem: DecapsulationKey,
    /// Another device's: a contact, a pair's sender.
    other: Identity,
    other_kem: DecapsulationKey,
    secret: SecretBytes<32>,
}

fn keys() -> &'static Keys {
    static KEYS: OnceLock<Keys> = OnceLock::new();
    KEYS.get_or_init(|| Keys {
        identity: Identity::from_seed(SecretBytes::from_slice(&[1; 32]).expect("32 bytes")),
        kem: DecapsulationKey::from_seed(SecretBytes::from_slice(&[2; 32]).expect("32 bytes")).expect("a seed"),
        other: Identity::from_seed(SecretBytes::from_slice(&[3; 32]).expect("32 bytes")),
        other_kem: DecapsulationKey::from_seed(SecretBytes::from_slice(&[4; 32]).expect("32 bytes")).expect("a seed"),
        secret: SecretBytes::from_slice(&[5; 32]).expect("32 bytes"),
    })
}

impl Keys {
    fn local(&self) -> LocalKeys {
        LocalKeys {
            identity: self.identity.public(),
            static_kem: DecapsulationKey::from_seed(self.kem.seed().clone()).expect("a seed"),
        }
    }

    fn remote(&self) -> RemoteKeys {
        RemoteKeys {
            identity: self.other.public(),
            static_kem: self.other_kem.encapsulation_key().clone(),
            link_psk: self.secret.clone(),
        }
    }

    fn profile(&self) -> LocalProfile<'_> {
        LocalProfile {
            identity: &self.identity,
            static_kem: &self.kem,
            presence_key: &self.secret,
            display_name: "Ayşe",
        }
    }

    fn channel(&self, flavor: Flavor) -> ChannelKeys<'_> {
        ChannelKeys {
            id: &[6; 16],
            psk: &self.secret,
            flavor,
        }
    }
}

/// A record a link carries, once decrypted (§8).
pub fn chat_message(data: &[u8]) {
    if let Ok(Some(message)) = ChatMessage::decode(data) {
        let encoded = message.encode().expect("what decodes encodes");
        assert_eq!(ChatMessage::decode(&encoded), Ok(Some(message)));
    }
}

/// A mesh envelope (§10.1), and everything that reads one.
pub fn envelope(data: &[u8]) {
    let Ok(envelope) = Envelope::decode(data) else {
        return;
    };
    assert_eq!(envelope.encode().expect("what decodes encodes"), data);
    let keys = keys();
    let _ = mesh::sealed_to(&envelope);
    let _ = UpdatePart::read(&envelope);
    let pair = Pair {
        from: &keys.other.public(),
        to: &keys.identity.public(),
        psk: &keys.secret,
    };
    let _ = mesh::open(&pair, &keys.kem, &envelope);
    let _ = mesh::open_part(&keys.secret, &envelope, 0);
    let _ = mesh::open_group_file_part(&keys.secret, &envelope, 0);
    let _ = mesh::open_update_part(&keys.secret, &envelope);
}

/// A list of envelopes a neighbour holds (§10.4).
pub fn have(data: &[u8]) {
    if let Ok(ids) = mesh::decode_have(data) {
        assert_eq!(mesh::encode_have(&ids), data);
    }
}

/// What is left of a record or a mesh part once decrypted: the padding around the content.
pub fn padding(data: &[u8]) {
    let _ = link::unpad(data);
    let _ = mesh::unpad_part(data);
}

/// A group's roster (§9.1).
pub fn roster(data: &[u8]) {
    if let Ok(roster) = Roster::decode(data) {
        assert_eq!(&roster.encode()[..], data);
    }
}

/// A group update (§9.2) and a group message (§9.3), and what a message carries.
pub fn group_records(data: &[u8]) {
    let keys = keys();
    if let Ok(update) = Update::read(data) {
        let _ = update.addresses(&keys.identity.public());
        let _ = update.open(&keys.identity.public(), &keys.kem);
    }
    if let Ok(message) = Message::read(data) {
        let _ = message.open(&keys.secret);
    }
    if let Ok(content) = Content::decode(data) {
        assert_eq!(&content.encode().expect("what decodes encodes")[..], data);
    }
}

/// Text from a QR code or typed in: invites (§4.4), channels (§11.1) and AirChat IDs.
pub fn text(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(invite) = ScannedInvite::parse(text) {
        let _ = (invite.id(), invite.beacon_token());
    }
    if let Ok((channel, name)) = Channel::parse_qr(text) {
        assert_eq!(
            channel.qr_text(&name).expect("what parses encodes").as_str(),
            text.trim()
        );
    }
    if let Ok(id) = AirChatId::parse(text) {
        assert_eq!(AirChatId::parse(&id.to_string()), Ok(id));
    }
    if let Some(bytes) = pairing::base32_decode(text) {
        assert_eq!(pairing::base32_encode(&bytes).as_str(), text);
    }
}

/// Beacons heard over BLE and Wi-Fi Aware (§5), and the hello of a channel link (§11.3).
pub fn beacons(data: &[u8]) {
    if let Some(beacon) = BleBeacon::decode(data) {
        assert_eq!(beacon.encode().as_deref(), Some(data));
    }
    if let Some(beacon) = AwareBeacon::decode(data) {
        assert_eq!(beacon.encode(), data);
    }
    if let Some(hello) = Hello::decode(data) {
        assert_eq!(hello.encode(), data);
    }
}

/// The first message of every handshake: links to contacts (§6), channel and mesh links (§10.2,
/// §11.3), and pairing (§4.3).
pub fn handshake_first(data: &[u8]) {
    let keys = keys();
    let _ = Responder::tag(data);
    let _ = ChannelResponder::tag(data);
    let _ = Responder::respond(&keys.local(), &keys.remote(), data, &[]);
    for flavor in [Flavor::CHANNEL, Flavor::MESH] {
        let _ = ChannelResponder::respond(&keys.channel(flavor), data, &[]);
    }
    let request = (
        crate::discovery::request_token(&keys.identity.public().airchat_id(), 0).expect("a token"),
        keys.identity.public().airchat_id(),
    );
    let _ = Pairing::accept(data, &keys.profile(), &[], &[request]);
}

/// The answer to a first message, as the side that sent it reads it.
pub fn handshake_answer(data: &[u8]) {
    let keys = keys();
    let (initiator, _) = Initiator::start(&keys.local(), &keys.remote(), &[7; 32]).expect("starts");
    let _ = initiator.finish(&keys.local(), data, &[]);
    for flavor in [Flavor::CHANNEL, Flavor::MESH] {
        let (initiator, _) = ChannelInitiator::start(&keys.channel(flavor), &[7; 32]).expect("starts");
        let _ = initiator.finish(data, &[]);
    }
    let (mut pairing, _) = Pairing::start_nearby().expect("starts");
    let _ = pairing.receive(data, &keys.profile());
}

/// The third message, as the side that answered reads it; and a contact card (§4.6).
pub fn handshake_last(data: &[u8]) {
    let keys = keys();
    let (_, first) = ChannelInitiator::start(&keys.channel(Flavor::MESH), &[7; 32]).expect("starts");
    let (responder, _) = ChannelResponder::respond(&keys.channel(Flavor::MESH), &first, &[]).expect("answers");
    let _ = responder.finish(data);
    let _ = pairing::decode_card(data, &[8; 32]);
}

/// A build attestation (§6.10): the input as one certificate, and as a chain in frames; under
/// Google's roots and a test signer, whatever it says.
pub fn attestation(data: &[u8]) {
    let keys = keys();
    let trust = crate::attest::Trust::google(&[[0xab; 32]]);
    let identity = keys.identity.public();
    let _ = crate::attest::verify(&[data.to_vec()], &identity, &[0x5a; 32], data, &trust);
    let chain: Vec<Vec<u8>> = frames(data)
        .take(crate::attest::MAX_CERTS + 1)
        .map(<[u8]>::to_vec)
        .collect();
    let _ = crate::attest::verify(&chain, &identity, &[0x5a; 32], data, &trust);
    // DER alone, element by element.
    let mut reader = crate::attest::der::Reader::new(data);
    while let Ok(Some(element)) = reader.element() {
        let _ = (element.small(crate::attest::der::INTEGER), element.boolean());
    }
}

/// Splits fuzz input into frames: each a u16 length, then that many bytes (fewer at the end).
pub fn frames(data: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut rest = data;
    std::iter::from_fn(move || {
        let (len, tail) = rest.split_first_chunk::<2>()?;
        let len = usize::from(u16::from_be_bytes(*len)).min(tail.len());
        let (frame, tail) = tail.split_at(len);
        rest = tail;
        Some(frame)
    })
}

/// Runs fuzz targets in-process over mutations of the test vectors: quick, reproducible, and
/// part of `cargo test`.
#[cfg(any(test, feature = "test-util"))]
#[doc(hidden)]
pub mod harness {
    use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

    use crate::crypto::test_util::to_hex;

    /// How many mutated inputs each target gets; `AIRCHAT_FUZZ_RUNS` multiplies it for a longer
    /// run, `AIRCHAT_FUZZ_SEED` picks other mutations.
    pub fn runs(base: usize) -> usize {
        base * std::env::var("AIRCHAT_FUZZ_RUNS")
            .ok()
            .and_then(|n| n.parse().ok())
            .unwrap_or(1)
    }

    /// The published test vectors (`tests/vectors/`): each value, as bytes if it is hex, and as text.
    pub fn seeds() -> Vec<Vec<u8>> {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors");
        let mut seeds = vec![Vec::new()];
        let mut files: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|e| e == "json"))
            .collect();
        files.sort();
        for file in files {
            for line in std::fs::read_to_string(file).unwrap().lines() {
                let Some((_, value)) = line.split_once("\": \"") else {
                    continue;
                };
                let value = value.trim_end_matches(',').trim_end_matches('"');
                if let Some(bytes) = from_hex(value) {
                    seeds.push(bytes);
                }
                seeds.push(value.as_bytes().to_vec());
            }
        }
        seeds
    }

    fn from_hex(text: &str) -> Option<Vec<u8>> {
        if text.is_empty() || !text.len().is_multiple_of(2) {
            return None;
        }
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
            .collect()
    }

    /// SplitMix64: reproducible, and plenty for picking mutations.
    pub struct Mutator(u64);

    impl Mutator {
        pub fn new(name: &str) -> Self {
            let seed: u64 = std::env::var("AIRCHAT_FUZZ_SEED")
                .ok()
                .and_then(|n| n.parse().ok())
                .unwrap_or(0);
            Self(name.bytes().fold(seed, |h, b| h.rotate_left(5) ^ u64::from(b)))
        }

        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }

        pub fn below(&mut self, n: usize) -> usize {
            (self.next() % n.max(1) as u64) as usize
        }

        fn byte(&mut self) -> u8 {
            self.next() as u8
        }

        /// One to four changes of the kinds that find parser bugs: flipped bits, boundary values in
        /// length and count fields, bytes added and removed, cut short, mixed with another input.
        pub fn mutate(&mut self, input: &mut Vec<u8>, seeds: &[Vec<u8>]) {
            for _ in 0..1 + self.below(4) {
                let at = self.below(input.len() + 1);
                let last = at.min(input.len().saturating_sub(1));
                match self.below(9) {
                    0 if !input.is_empty() => input[last] ^= 1 << self.below(8),
                    1 if !input.is_empty() => input[last] = [0, 1, 0x7f, 0x80, 0xff][self.below(5)],
                    2 if !input.is_empty() => input[last] = self.byte(),
                    3 => {
                        let added: Vec<u8> = (0..1 + self.below(16)).map(|_| self.byte()).collect();
                        input.splice(at..at, added);
                    }
                    4 => {
                        let end = (at + 1 + self.below(32)).min(input.len());
                        input.drain(at..end);
                    }
                    5 => input.truncate(at),
                    6 => {
                        let width = [1, 2, 4, 8][self.below(4)];
                        let len = input.len() as u64;
                        let value = [0, 1, len.wrapping_sub(1), len, len + 1, u64::MAX, 0x7fff_ffff][self.below(7)];
                        let bytes = value.to_be_bytes();
                        let field = &bytes[8 - width..];
                        let end = (at + width).min(input.len());
                        input.splice(at..end, field.iter().copied());
                    }
                    7 => {
                        let other = &seeds[self.below(seeds.len())];
                        let from = self.below(other.len() + 1);
                        let end = (from + self.below(other.len() + 1)).min(other.len());
                        input.truncate(at);
                        input.extend_from_slice(&other[from..end]);
                    }
                    _ => {
                        let len = self.below(64);
                        *input = (0..len).map(|_| self.byte()).collect();
                    }
                }
            }
        }
    }

    /// Feeds `target` every seed, then `runs` mutations of them; a failing input is printed in hex.
    pub fn fuzz(name: &str, runs: usize, seeds: &[Vec<u8>], mut target: impl FnMut(&[u8])) {
        let mut mutator = Mutator::new(name);
        let inputs = seeds.iter().cloned().chain((0..runs).map(|_| {
            let mut input = seeds[mutator.below(seeds.len())].clone();
            mutator.mutate(&mut input, seeds);
            input
        }));
        for input in inputs {
            if let Err(panic) = catch_unwind(AssertUnwindSafe(|| target(&input))) {
                eprintln!("fuzz target {name} failed on {}", to_hex(&input));
                resume_unwind(panic);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::harness::{fuzz, runs, seeds};
    use crate::crypto::test_util::to_hex;

    macro_rules! fuzz_tests {
        ($($target:ident: $runs:expr),* $(,)?) => {$(
            #[test]
            fn $target() {
                fuzz(stringify!($target), runs($runs), &seeds(), super::$target);
            }
        )*};
    }

    fuzz_tests! {
        chat_message: 20_000,
        envelope: 3_000,
        have: 5_000,
        padding: 5_000,
        roster: 5_000,
        group_records: 5_000,
        text: 10_000,
        beacons: 10_000,
        handshake_first: 2_000,
        handshake_answer: 500,
        handshake_last: 500,
        attestation: 5_000,
    }

    /// Writes the seeds where libFuzzer starts from, `fuzz/corpus/<target>/` (see
    /// `fuzz/README.md`).
    #[test]
    #[ignore = "writes fuzz/corpus"]
    fn write_fuzz_corpus() {
        use crate::crypto::hash::sha256;
        let seeds = seeds();
        let decoders = [
            "chat_message",
            "envelope",
            "have",
            "padding",
            "roster",
            "group_records",
            "text",
            "beacons",
            "handshake_first",
            "handshake_answer",
            "handshake_last",
            "attestation",
        ];
        for target in decoders {
            let dir = format!("{}/fuzz/corpus/{target}", env!("CARGO_MANIFEST_DIR"));
            std::fs::create_dir_all(&dir).unwrap();
            for input in &seeds {
                std::fs::write(format!("{dir}/{}", to_hex(&sha256(&[input])[..8])), input).unwrap();
            }
        }
    }

    #[test]
    fn frames_split_input_by_length() {
        let frames: Vec<&[u8]> = super::frames(&[0, 2, 7, 8, 0, 0, 0, 5, 9]).collect();
        assert_eq!(frames, [&[7, 8][..], &[], &[9]]);
    }
}
