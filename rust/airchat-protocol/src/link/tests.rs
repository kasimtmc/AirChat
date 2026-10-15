//! End-to-end tests of link handshakes and sessions, plus the published test vector.

use super::*;
use crate::{
    crypto::{
        SecretBytes,
        kem::{CIPHERTEXT_LEN, Ciphertext, DecapsulationKey, ENCAPSULATION_KEY_LEN},
        test_util::{DeterministicRng, check_vector, hex, hex_array, to_hex},
    },
    identity::Identity,
};

struct Party {
    identity: Identity,
    keys: LocalKeys,
}

impl Party {
    fn new() -> Self {
        let identity = Identity::generate().unwrap();
        let keys = LocalKeys {
            identity: identity.public(),
            static_kem: DecapsulationKey::generate().unwrap(),
        };
        Self { identity, keys }
    }

    fn from_seeds(identity_seed: u8, kem_seed: u8) -> Self {
        let identity = Identity::from_seed(SecretBytes::from_slice(&[identity_seed; 32]).unwrap());
        let static_kem = DecapsulationKey::from_seed(SecretBytes::from_slice(&[kem_seed; 32]).unwrap()).unwrap();
        let keys = LocalKeys {
            identity: identity.public(),
            static_kem,
        };
        Self { identity, keys }
    }

    /// How `other` knows this party after pairing.
    fn as_remote(&self, psk: &SecretBytes<32>) -> RemoteKeys {
        RemoteKeys {
            identity: self.identity.public(),
            static_kem: self.keys.static_kem.encapsulation_key().clone(),
            link_psk: psk.clone(),
        }
    }
}

fn psk(byte: u8) -> SecretBytes<32> {
    SecretBytes::from_slice(&[byte; 32]).unwrap()
}

fn tag_for(from: &Party, to: &Party, psk: &SecretBytes<32>) -> Tag {
    TagKey::derive(psk, &from.identity.public(), &to.identity.public())
        .unwrap()
        .tag(480_000, &[3; NONCE_LEN])
}

fn handshake(alice: &Party, bob: &Party, psk: &SecretBytes<32>) -> Result<(Established, Established), LinkError> {
    let (initiator, message1) = Initiator::start(&alice.keys, &bob.as_remote(psk), &tag_for(alice, bob, psk))?;
    let (responder, message2) = Responder::respond(&bob.keys, &alice.as_remote(psk), &message1, b"bob says hi")?;
    let (alice_side, message3) = initiator.finish(&alice.keys, &message2, b"alice says hi")?;
    let bob_side = responder.finish(&message3)?;
    Ok((alice_side, bob_side))
}

#[test]
fn contacts_establish_a_session_and_exchange_records() {
    let (alice, bob, psk) = (Party::new(), Party::new(), psk(1));
    let (mut a, mut b) = handshake(&alice, &bob, &psk).unwrap();
    assert_eq!(a.peer_payload.as_slice(), b"bob says hi");
    assert_eq!(b.peer_payload.as_slice(), b"alice says hi");
    assert_eq!(a.session.handshake_hash(), b.session.handshake_hash());

    let record = a.session.seal(b"hello bob").unwrap();
    assert!(matches!(b.session.open(&record).unwrap(), Record::Data(d) if d.as_slice() == b"hello bob"));
    let record = b.session.seal(b"hello alice").unwrap();
    assert!(matches!(a.session.open(&record).unwrap(), Record::Data(d) if d.as_slice() == b"hello alice"));
}

#[test]
fn every_handshake_is_fresh() {
    let (alice, bob, psk) = (Party::new(), Party::new(), psk(1));
    let (a1, _) = handshake(&alice, &bob, &psk).unwrap();
    let (a2, _) = handshake(&alice, &bob, &psk).unwrap();
    assert_ne!(a1.session.handshake_hash(), a2.session.handshake_hash());
}

#[test]
fn the_tag_is_readable_before_any_key_work() {
    let (alice, bob, psk) = (Party::new(), Party::new(), psk(1));
    let tag = tag_for(&alice, &bob, &psk);
    let (_, message1) = Initiator::start(&alice.keys, &bob.as_remote(&psk), &tag).unwrap();
    assert_eq!(message1.len(), MESSAGE_1_LEN);
    assert_eq!(Responder::tag(&message1), Ok(tag));
}

#[test]
fn wrong_pairing_secret_fails_at_message_1() {
    let (alice, bob) = (Party::new(), Party::new());
    let (_, message1) = Initiator::start(&alice.keys, &bob.as_remote(&psk(1)), &[0; TAG_LEN]).unwrap();
    let result = Responder::respond(&bob.keys, &alice.as_remote(&psk(2)), &message1, b"");
    assert!(matches!(result, Err(LinkError::AuthenticationFailed)));
}

#[test]
fn only_the_real_responder_can_answer() {
    // Mallory knows Bob's public keys and even the pairing secret, but not Bob's static private key.
    let (alice, bob, psk) = (Party::new(), Party::new(), psk(1));
    let (_, message1) = Initiator::start(&alice.keys, &bob.as_remote(&psk), &[0; TAG_LEN]).unwrap();
    let mallory = LocalKeys {
        identity: bob.identity.public(),
        static_kem: DecapsulationKey::generate().unwrap(),
    };
    let result = Responder::respond(&mallory, &alice.as_remote(&psk), &message1, b"");
    assert!(matches!(result, Err(LinkError::AuthenticationFailed)));
}

#[test]
fn stolen_responder_keys_do_not_allow_impersonating_the_initiator() {
    // Mallory has Bob's keys and the pairing secret, so she can produce a message 1 Bob accepts as
    // Alice's. She lacks Alice's static private key, so she can never send message 3.
    let (alice, bob, psk) = (Party::new(), Party::new(), psk(1));
    let (initiator, message1) = Initiator::start(&alice.keys, &bob.as_remote(&psk), &[0; TAG_LEN]).unwrap();
    let (_, message2) = Responder::respond(&bob.keys, &alice.as_remote(&psk), &message1, b"").unwrap();
    let mallory = LocalKeys {
        identity: alice.identity.public(),
        static_kem: DecapsulationKey::generate().unwrap(),
    };
    assert!(matches!(
        initiator.finish(&mallory, &message2, b""),
        Err(LinkError::AuthenticationFailed)
    ));
}

#[test]
fn tampering_with_any_message_fails() {
    let (alice, bob, psk) = (Party::new(), Party::new(), psk(1));
    let (bob_remote, alice_remote) = (bob.as_remote(&psk), alice.as_remote(&psk));
    let (_, message1) = Initiator::start(&alice.keys, &bob_remote, &[0; TAG_LEN]).unwrap();
    for position in (HEADER_LEN_FOR_TESTS..message1.len())
        .step_by(97)
        .chain([message1.len() - 1])
    {
        let mut tampered = message1.clone();
        tampered[position] ^= 0x01;
        assert!(
            Responder::respond(&bob.keys, &alice_remote, &tampered, b"").is_err(),
            "message 1 byte {position}"
        );
    }

    let message2_for = || {
        let (initiator, message1) = Initiator::start(&alice.keys, &bob_remote, &[0; TAG_LEN]).unwrap();
        let (responder, message2) = Responder::respond(&bob.keys, &alice_remote, &message1, b"x").unwrap();
        (initiator, responder, message2)
    };
    let (_, _, sample) = message2_for();
    for position in (HEADER_LEN_FOR_TESTS..sample.len())
        .step_by(211)
        .chain([sample.len() - 1])
    {
        let (initiator, _, mut message2) = message2_for();
        message2[position] ^= 0x01;
        assert!(
            initiator.finish(&alice.keys, &message2, b"").is_err(),
            "message 2 byte {position}"
        );
    }

    let (initiator, responder, message2) = message2_for();
    let (_, mut message3) = initiator.finish(&alice.keys, &message2, b"y").unwrap();
    let last = message3.len() - 1;
    message3[last] ^= 0x01;
    assert!(matches!(
        responder.finish(&message3),
        Err(LinkError::AuthenticationFailed)
    ));
}

const HEADER_LEN_FOR_TESTS: usize = 2;

#[test]
fn messages_from_another_handshake_are_rejected() {
    let (alice, bob, psk) = (Party::new(), Party::new(), psk(1));
    let (bob_remote, alice_remote) = (bob.as_remote(&psk), alice.as_remote(&psk));
    let (initiator1, message1a) = Initiator::start(&alice.keys, &bob_remote, &[0; TAG_LEN]).unwrap();
    let (_, message1b) = Initiator::start(&alice.keys, &bob_remote, &[0; TAG_LEN]).unwrap();
    let (responder_a, message2a) = Responder::respond(&bob.keys, &alice_remote, &message1a, b"").unwrap();
    let (_, message2b) = Responder::respond(&bob.keys, &alice_remote, &message1b, b"").unwrap();

    assert!(
        initiator1.finish(&alice.keys, &message2b, b"").is_err(),
        "message 2 of another run"
    );

    let (initiator2, message1c) = Initiator::start(&alice.keys, &bob_remote, &[0; TAG_LEN]).unwrap();
    let (_, message2c) = Responder::respond(&bob.keys, &alice_remote, &message1c, b"").unwrap();
    let (_, message3c) = initiator2.finish(&alice.keys, &message2c, b"").unwrap();
    assert!(responder_a.finish(&message3c).is_err(), "message 3 of another run");
    drop(message2a);
}

#[test]
fn rejects_wrong_version_type_and_length() {
    let (alice, bob, psk) = (Party::new(), Party::new(), psk(1));
    let (_, message1) = Initiator::start(&alice.keys, &bob.as_remote(&psk), &[0; TAG_LEN]).unwrap();

    let mut future = message1.clone();
    future[0] = WIRE_VERSION + 1;
    assert_eq!(Responder::tag(&future), Err(LinkError::UnsupportedVersion));
    let mut wrong_type = message1.clone();
    wrong_type[1] = 2;
    assert_eq!(Responder::tag(&wrong_type), Err(LinkError::Malformed));
    assert_eq!(
        Responder::tag(&message1[..MESSAGE_1_LEN - 1]),
        Err(LinkError::Malformed)
    );
    assert_eq!(Responder::tag(&[]), Err(LinkError::Malformed));
}

#[test]
fn oversized_handshake_messages_are_rejected_unread() {
    let (alice, bob, psk) = (Party::new(), Party::new(), psk(1));
    let (initiator, message1) = Initiator::start(&alice.keys, &bob.as_remote(&psk), &[0; TAG_LEN]).unwrap();
    let (_, mut message2) = Responder::respond(&bob.keys, &alice.as_remote(&psk), &message1, b"").unwrap();
    message2.resize(message2.len() + (1 << 20), 0);
    assert!(matches!(
        initiator.finish(&alice.keys, &message2, b""),
        Err(LinkError::Malformed)
    ));
}

#[test]
fn handshake_payloads_are_limited() {
    let (alice, bob, psk) = (Party::new(), Party::new(), psk(1));
    let (_, message1) = Initiator::start(&alice.keys, &bob.as_remote(&psk), &[0; TAG_LEN]).unwrap();
    let too_big = vec![0; MAX_HANDSHAKE_PAYLOAD + 1];
    let result = Responder::respond(&bob.keys, &alice.as_remote(&psk), &message1, &too_big);
    assert!(matches!(result, Err(LinkError::PayloadTooLarge)));
}

/// Generates the published test vector (docs/protocol.md §6.6) and checks it against
/// `tests/vectors/link_contact_handshake.json`. Set `AIRCHAT_UPDATE_VECTORS=1` to rewrite the file
/// after an intentional protocol change. `check_link_handshake.py` in the same directory
/// recomputes the vector's symmetric part independently.
#[test]
fn published_test_vector() {
    let alice = Party::from_seeds(0xa1, 0xa2);
    let bob = Party::from_seeds(0xb1, 0xb2);
    let psk = psk(0x5c);
    let (epoch, nonce) = (480_000, hex_array::<NONCE_LEN>("000102030405060708090a0b0c0d0e0f"));
    let tag = TagKey::derive(&psk, &alice.identity.public(), &bob.identity.public())
        .unwrap()
        .tag(epoch, &nonce);
    let (initiator_seed, responder_seed) = ([0x11; 32], [0x22; 32]);
    let (payload2, payload3) = (
        b"responder capabilities".as_slice(),
        b"initiator capabilities".as_slice(),
    );

    let (initiator, message1) = Initiator::start_from(
        &alice.keys,
        &bob.as_remote(&psk),
        &tag,
        &mut DeterministicRng::new(initiator_seed),
    )
    .unwrap();
    let (responder, message2) = Responder::respond_from(
        &bob.keys,
        &alice.as_remote(&psk),
        &message1,
        payload2,
        &mut DeterministicRng::new(responder_seed),
    )
    .unwrap();
    let (mut a, message3) = initiator.finish(&alice.keys, &message2, payload3).unwrap();
    let mut b = responder.finish(&message3).unwrap();
    let record1 = a.session.seal(b"hello").unwrap();
    let record2 = b.session.seal(b"hi").unwrap();
    let next_link_key = a.next_link_key.clone().unwrap();
    assert_eq!(next_link_key.expose(), b.next_link_key.as_ref().unwrap().expose());

    // The shared secrets, recomputed from the messages with each party's private keys.
    let ephemeral = {
        let mut seed = SecretBytes::zeroed();
        use crate::crypto::random::Rng;
        DeterministicRng::new(initiator_seed).fill(seed.expose_mut()).unwrap();
        DecapsulationKey::from_seed(seed).unwrap()
    };
    let ct = |message: &[u8], at: usize| Ciphertext::from_bytes(&message[at..at + CIPHERTEXT_LEN]).unwrap();
    let ss1 = bob
        .keys
        .static_kem
        .decapsulate(&ct(&message1, 2 + TAG_LEN + ENCAPSULATION_KEY_LEN))
        .unwrap();
    let ss2 = ephemeral.decapsulate(&ct(&message2, 2)).unwrap();
    let ss3 = alice
        .keys
        .static_kem
        .decapsulate(&ct(&message2, 2 + CIPHERTEXT_LEN))
        .unwrap();

    let fields: Vec<(&str, String)> = vec![
        ("protocol", "AirChat v1 link-contact, wire version 0".into()),
        ("initiator_identity", to_hex(alice.identity.public().as_bytes())),
        (
            "initiator_static_kem_seed",
            to_hex(alice.keys.static_kem.seed().expose()),
        ),
        (
            "initiator_static_kem",
            to_hex(alice.keys.static_kem.encapsulation_key().as_bytes()),
        ),
        ("responder_identity", to_hex(bob.identity.public().as_bytes())),
        ("responder_static_kem_seed", to_hex(bob.keys.static_kem.seed().expose())),
        (
            "responder_static_kem",
            to_hex(bob.keys.static_kem.encapsulation_key().as_bytes()),
        ),
        ("link_psk", to_hex(psk.expose())),
        ("tag_epoch", epoch.to_string()),
        ("tag_nonce", to_hex(&nonce)),
        ("tag", to_hex(&tag)),
        ("initiator_rng_seed", to_hex(&initiator_seed)),
        ("responder_rng_seed", to_hex(&responder_seed)),
        ("ss1", to_hex(ss1.expose())),
        ("ss2", to_hex(ss2.expose())),
        ("ss3", to_hex(ss3.expose())),
        ("payload2", to_hex(payload2)),
        ("payload3", to_hex(payload3)),
        ("message1", to_hex(&message1)),
        ("message2", to_hex(&message2)),
        ("message3", to_hex(&message3)),
        ("handshake_hash", to_hex(a.session.handshake_hash())),
        ("next_link_key", to_hex(next_link_key.expose())),
        ("record1_initiator_hello", to_hex(&record1)),
        ("record2_responder_hi", to_hex(&record2)),
    ];
    check_vector("link_contact_handshake", &fields);
    assert_eq!(hex(&to_hex(&message1)), message1);
}

// The channel handshake (docs/protocol.md §11.3).

fn channel(byte: u8) -> (Vec<u8>, SecretBytes<32>) {
    (vec![byte; 16], psk(byte))
}

fn channel_tag(id: &[u8], psk: &SecretBytes<32>) -> Tag {
    TagKey::for_channel(psk, id).unwrap().tag(480_000, &[4; NONCE_LEN])
}

fn channel_handshake(
    initiator: (&[u8], &SecretBytes<32>),
    responder: (&[u8], &SecretBytes<32>),
) -> Result<(Established, Established), LinkError> {
    let keys_i = ChannelKeys {
        id: initiator.0,
        psk: initiator.1,
        flavor: Flavor::CHANNEL,
    };
    let keys_r = ChannelKeys {
        id: responder.0,
        psk: responder.1,
        flavor: Flavor::CHANNEL,
    };
    let (start, message1) = ChannelInitiator::start(&keys_i, &channel_tag(initiator.0, initiator.1))?;
    let (answer, message2) = ChannelResponder::respond(&keys_r, &message1, b"from the responder")?;
    let (a, message3) = start.finish(&message2, b"from the initiator")?;
    let b = answer.finish(&message3)?;
    Ok((a, b))
}

#[test]
fn channel_members_establish_a_session_and_exchange_records() {
    let (id, psk) = channel(9);
    let (mut a, mut b) = channel_handshake((&id, &psk), (&id, &psk)).unwrap();
    assert_eq!(a.peer_payload.as_slice(), b"from the responder");
    assert_eq!(b.peer_payload.as_slice(), b"from the initiator");
    assert_eq!(a.session.handshake_hash(), b.session.handshake_hash());
    let record = a.session.seal(b"ses var mi").unwrap();
    assert_eq!(
        b.session.open(&record).unwrap(),
        Record::Data(zeroize::Zeroizing::new(b"ses var mi".to_vec()))
    );
    let record = b.session.seal(b"tamam").unwrap();
    assert_eq!(
        a.session.open(&record).unwrap(),
        Record::Data(zeroize::Zeroizing::new(b"tamam".to_vec()))
    );
    // Every handshake is fresh, even between the same members.
    let (c, _) = channel_handshake((&id, &psk), (&id, &psk)).unwrap();
    assert_ne!(a.session.handshake_hash(), c.session.handshake_hash());
}

#[test]
fn outsiders_and_other_channels_fail_at_message_1() {
    let (id, psk) = channel(9);
    let (other_id, other_psk) = channel(10);
    assert!(channel_handshake((&id, &psk), (&id, &other_psk)).is_err(), "wrong key");
    assert!(
        channel_handshake((&id, &psk), (&other_id, &psk)).is_err(),
        "wrong channel"
    );
}

#[test]
fn tampering_with_a_channel_handshake_fails() {
    let (id, psk) = channel(9);
    let keys = ChannelKeys {
        id: &id,
        psk: &psk,
        flavor: Flavor::CHANNEL,
    };
    let tag = channel_tag(&id, &psk);
    for at in [3, 40, CHANNEL_MESSAGE_1_LEN - 1] {
        let (_, mut message1) = ChannelInitiator::start(&keys, &tag).unwrap();
        message1[at] ^= 1;
        assert!(
            ChannelResponder::respond(&keys, &message1, &[]).is_err(),
            "message 1 at {at}"
        );
    }
    let (start, message1) = ChannelInitiator::start(&keys, &tag).unwrap();
    let (_, mut message2) = ChannelResponder::respond(&keys, &message1, &[]).unwrap();
    let last = message2.len() - 1;
    message2[last] ^= 1;
    assert!(start.finish(&message2, &[]).is_err(), "message 2");
    let (start, message1) = ChannelInitiator::start(&keys, &tag).unwrap();
    let (answer, message2) = ChannelResponder::respond(&keys, &message1, &[]).unwrap();
    let (_, mut message3) = start.finish(&message2, &[]).unwrap();
    message3[5] ^= 1;
    assert!(answer.finish(&message3).is_err(), "message 3");
    assert_eq!(ChannelResponder::tag(&message1).unwrap(), tag);
    assert!(ChannelResponder::tag(&message1[..100]).is_err());
}

/// The published channel vector (docs/protocol.md §11.5): the channel from a password, its beacon,
/// QR code and a complete link handshake. `check_channel.py` recomputes it.
#[test]
fn published_channel_vector() {
    use crate::channel::{Channel, Hello};
    let password = "kamp ateşi 2026";
    let channel = Channel::from_password(password).unwrap();
    let (token_epoch, token_nonce) = (490_000u64, [0xc1, 0xc2, 0xc3, 0xc4]);
    let token = channel.token_with(token_epoch, &token_nonce);
    let (epoch, nonce) = (490_000, hex_array::<NONCE_LEN>("101112131415161718191a1b1c1d1e1f"));
    let tag = channel.tag_key().unwrap().tag(epoch, &nonce);
    let keys = ChannelKeys {
        id: channel.id(),
        psk: channel.link_psk(),
        flavor: Flavor::CHANNEL,
    };
    let (initiator_seed, responder_seed) = ([0x33; 32], [0x44; 32]);
    let payload2 = Hello {
        device: [0xd2; 16],
        name: "Burak".into(),
    }
    .encode();
    let payload3 = Hello {
        device: [0xd3; 16],
        name: "Ayşe".into(),
    }
    .encode();
    let (start, message1) =
        ChannelInitiator::start_from(&keys, &tag, &mut DeterministicRng::new(initiator_seed)).unwrap();
    let (answer, message2) =
        ChannelResponder::respond_from(&keys, &message1, &payload2, &mut DeterministicRng::new(responder_seed))
            .unwrap();
    let (mut a, message3) = start.finish(&message2, &payload3).unwrap();
    let mut b = answer.finish(&message3).unwrap();
    let record1 = a.session.seal(b"hello").unwrap();
    let record2 = b.session.seal(b"hi").unwrap();
    let ephemeral = {
        let mut seed = SecretBytes::zeroed();
        use crate::crypto::random::Rng;
        DeterministicRng::new(initiator_seed).fill(seed.expose_mut()).unwrap();
        DecapsulationKey::from_seed(seed).unwrap()
    };
    let ss = ephemeral
        .decapsulate(&Ciphertext::from_bytes(&message2[2..2 + CIPHERTEXT_LEN]).unwrap())
        .unwrap();

    let fields: Vec<(&str, String)> = vec![
        ("protocol", "AirChat v1 link-channel, wire version 0".into()),
        ("password", password.into()),
        ("argon2id", "m=65536 KiB, t=3, p=1, 32-byte output".into()),
        ("channel_key", to_hex(channel.key().expose())),
        ("channel_id", to_hex(channel.id())),
        ("link_psk", to_hex(channel.link_psk().expose())),
        ("token_epoch", token_epoch.to_string()),
        ("token", to_hex(&token)),
        ("qr_text", channel.qr_text("Kamp telsizi").unwrap().to_string()),
        ("tag_epoch", epoch.to_string()),
        ("tag_nonce", to_hex(&nonce)),
        ("tag", to_hex(&tag)),
        ("initiator_rng_seed", to_hex(&initiator_seed)),
        ("responder_rng_seed", to_hex(&responder_seed)),
        ("ss", to_hex(ss.expose())),
        ("payload2", to_hex(&payload2)),
        ("payload3", to_hex(&payload3)),
        ("message1", to_hex(&message1)),
        ("message2", to_hex(&message2)),
        ("message3", to_hex(&message3)),
        ("handshake_hash", to_hex(a.session.handshake_hash())),
        ("record1_initiator_hello", to_hex(&record1)),
        ("record2_responder_hi", to_hex(&record2)),
    ];
    check_vector("channel", &fields);
}
