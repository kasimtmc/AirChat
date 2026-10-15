//! Fuzz targets (requirement S-11): every parser of bytes that come from outside the device, each a
//! function that must not panic whatever its input, and that checks what it can.
//!
//! The protocol's parsers are `airchat_protocol::fuzz`, re-exported here; this module adds what the
//! app reads back from its own storage and its audio buffer, and `node::fuzz` the targets that drive
//! a whole node (a first frame, a stranger on the mesh, a channel member, a contact). `cargo test`
//! runs them over mutations of the published test vectors; `rust/fuzz` runs them under libFuzzer.

use zeroize::Zeroizing;

pub use airchat_protocol::fuzz::*;

pub use crate::node::fuzz::{channel_records, contact_records, first_frames, mesh_records};
use crate::{
    crypto::{SecretBytes, kem::EncapsulationKey},
    inbox,
    jitter::JitterBuffer,
    storage::Vault,
};

/// Device-local data read back: inbox entries (written while locked) and the vault record.
pub fn stored(data: &[u8]) {
    if let Some(event) = inbox::decode(data) {
        assert_eq!(inbox::decode(&inbox::encode(&event)), Some(event));
    }
    let secret = SecretBytes::from_slice(&[5; 32]).expect("32 bytes");
    let _ = Vault::unlock_with_secret(data, &secret);
    if let Ok(key) = EncapsulationKey::from_bytes(data) {
        assert_eq!(&key.as_bytes()[..], data);
    }
}

/// Audio packets in the order the network delivers them: a byte below 0x80 plays a frame, any
/// other is followed by a sequence number (u32) to push.
pub fn jitter(data: &[u8]) {
    let mut buffer = JitterBuffer::new(3, 10);
    let mut rest = data;
    while let Some((&op, tail)) = rest.split_first() {
        rest = tail;
        if op < 0x80 {
            let _ = buffer.pop();
        } else if let Some((seq, tail)) = rest.split_first_chunk::<4>() {
            rest = tail;
            buffer.push(u32::from_be_bytes(*seq), Zeroizing::new(vec![op]));
        }
    }
}

#[cfg(test)]
mod tests {
    use airchat_protocol::fuzz::harness::{fuzz, runs, seeds};

    use crate::crypto::test_util::to_hex;

    #[test]
    fn stored() {
        fuzz("stored", runs(5_000), &seeds(), super::stored);
    }

    #[test]
    fn jitter() {
        fuzz("jitter", runs(5_000), &seeds(), super::jitter);
    }

    /// Writes the seeds where libFuzzer starts from, `rust/fuzz/corpus/<target>/` (see
    /// `rust/fuzz/README.md`), for the protocol's targets and the app's; the node targets get each
    /// seed as one frame.
    #[test]
    #[ignore = "writes rust/fuzz/corpus"]
    fn write_fuzz_corpus() {
        use crate::crypto::hash::sha256;
        let seeds = seeds();
        let framed: Vec<Vec<u8>> = seeds
            .iter()
            .filter(|seed| seed.len() <= usize::from(u16::MAX))
            .map(|seed| [&(seed.len() as u16).to_be_bytes()[..], seed].concat())
            .collect();
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
            "stored",
            "jitter",
            "attestation",
        ];
        let nodes = ["first_frames", "mesh_records", "channel_records", "contact_records"];
        let targets = decoders
            .iter()
            .map(|t| (t, &seeds))
            .chain(nodes.iter().map(|t| (t, &framed)));
        for (target, inputs) in targets {
            let dir = format!("{}/../fuzz/corpus/{target}", env!("CARGO_MANIFEST_DIR"));
            std::fs::create_dir_all(&dir).unwrap();
            for input in inputs {
                std::fs::write(format!("{dir}/{}", to_hex(&sha256(&[input])[..8])), input).unwrap();
            }
        }
    }
}
