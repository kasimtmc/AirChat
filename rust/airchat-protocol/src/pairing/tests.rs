//! End-to-end pairing tests, including attacks, and the published test vectors.

use super::*;
use crate::{
    crypto::{
        SecretBytes,
        kem::{CIPHERTEXT_LEN, Ciphertext, DecapsulationKey},
        random::Rng,
        test_util::{DeterministicRng, check_vector, to_hex},
    },
    identity::Identity,
    link::{self, Initiator, LocalKeys, Record, RemoteKeys, Responder, TagKey},
};

struct Owner {
    identity: Identity,
    static_kem: DecapsulationKey,
    presence_key: SecretBytes<PRESENCE_KEY_LEN>,
    name: &'static str,
}

impl Owner {
    fn new(name: &'static str) -> Self {
        Self {
            identity: Identity::generate().unwrap(),
            static_kem: DecapsulationKey::generate().unwrap(),
            presence_key: SecretBytes::random().unwrap(),
            name,
        }
    }

    fn from_seed(name: &'static str, seed: u8) -> Self {
        let secret = |n: u8| SecretBytes::from_slice(&[seed.wrapping_add(n); 32]).unwrap();
        Self {
            identity: Identity::from_seed(secret(0)),
            static_kem: DecapsulationKey::from_seed(secret(1)).unwrap(),
            presence_key: secret(2),
            name,
        }
    }

    fn profile(&self) -> LocalProfile<'_> {
        LocalProfile {
            identity: &self.identity,
            static_kem: &self.static_kem,
            presence_key: &self.presence_key,
            display_name: self.name,
        }
    }
}

/// Splits events into messages to deliver, emoji shown, and contacts paired.
fn split(events: Vec<Event>) -> (Vec<Vec<u8>>, Option<Sas>, Option<PairedContact>) {
    let (mut sends, mut sas, mut paired) = (Vec::new(), None, None);
    for event in events {
        match event {
            Event::Send(bytes) => sends.push(bytes),
            Event::ShowSas(s) => sas = Some(s),
            Event::Paired(c) => paired = Some(c),
            Event::Requested(_) => panic!("no request in this mode"),
        }
    }
    (sends, sas, paired)
}

fn one(messages: Vec<Vec<u8>>) -> Vec<u8> {
    assert_eq!(messages.len(), 1, "expected exactly one message");
    messages.into_iter().next().unwrap()
}

fn assert_paired_with(contact: &PairedContact, owner: &Owner) {
    assert_eq!(contact.identity, owner.identity.public());
    assert_eq!(&contact.static_kem, owner.static_kem.encapsulation_key());
    assert_eq!(contact.display_name, owner.name);
    assert_eq!(contact.presence_key.expose(), owner.presence_key.expose());
}

/// Runs Nearby Pairing up to the emoji on both screens.
fn nearby_until_sas(initiator: &Owner, responder: &Owner) -> (Pairing, Pairing, Sas, Sas) {
    let (mut i, m1) = Pairing::start_nearby().unwrap();
    let (mut r, events) = Pairing::accept(&m1, &responder.profile(), &[], &[]).unwrap();
    let (m2, ..) = split(events);
    let (m3, ..) = split(i.receive(&one(m2), &initiator.profile()).unwrap());
    let (m4, sas_r, _) = split(r.receive(&one(m3), &responder.profile()).unwrap());
    let (none, sas_i, _) = split(i.receive(&one(m4), &initiator.profile()).unwrap());
    assert!(none.is_empty(), "no card before the user confirms");
    (i, r, sas_i.unwrap(), sas_r.unwrap())
}

#[test]
fn nearby_pairing_end_to_end() {
    let (ayse, burak) = (Owner::new("Ayşe"), Owner::new("Burak"));
    let (mut i, mut r, sas_i, sas_r) = nearby_until_sas(&ayse, &burak);
    assert_eq!(sas_i, sas_r);
    assert_eq!(i.sas(), Some(sas_i));

    // Burak confirms first; Ayşe receives his card before she has confirmed and must hold it.
    let (card_r, _, none) = split(r.confirm(&burak.profile()).unwrap());
    assert!(none.is_none());
    let (nothing, _, held) = split(i.receive(&one(card_r), &ayse.profile()).unwrap());
    assert!(
        nothing.is_empty() && held.is_none(),
        "not paired before the own user confirms"
    );
    let (card_i, _, ayse_got) = split(i.confirm(&ayse.profile()).unwrap());
    let (_, _, burak_got) = split(r.receive(&one(card_i), &burak.profile()).unwrap());

    let (ayse_got, burak_got) = (ayse_got.unwrap(), burak_got.unwrap());
    assert_paired_with(&ayse_got, &burak);
    assert_paired_with(&burak_got, &ayse);
    assert_eq!(ayse_got.link_psk.expose(), burak_got.link_psk.expose());
}

#[test]
fn paired_contacts_can_open_a_link_session() {
    let (ayse, burak) = (Owner::new("Ayşe"), Owner::new("Burak"));
    let (mut i, mut r, ..) = nearby_until_sas(&ayse, &burak);
    let (card_i, ..) = split(i.confirm(&ayse.profile()).unwrap());
    let (card_r, ..) = split(r.confirm(&burak.profile()).unwrap());
    let (_, _, burak_contact) = split(i.receive(&one(card_r), &ayse.profile()).unwrap());
    let (_, _, ayse_contact) = split(r.receive(&one(card_i), &burak.profile()).unwrap());
    let (burak_contact, ayse_contact) = (burak_contact.unwrap(), ayse_contact.unwrap());

    let remote = |c: &PairedContact| RemoteKeys {
        identity: c.identity,
        static_kem: c.static_kem.clone(),
        link_psk: c.link_psk.clone(),
    };
    let ayse_keys = LocalKeys {
        identity: ayse.identity.public(),
        static_kem: DecapsulationKey::from_seed(ayse.static_kem.seed().clone()).unwrap(),
    };
    let burak_keys = LocalKeys {
        identity: burak.identity.public(),
        static_kem: DecapsulationKey::from_seed(burak.static_kem.seed().clone()).unwrap(),
    };
    let tag = TagKey::derive(
        &burak_contact.link_psk,
        &ayse.identity.public(),
        &burak.identity.public(),
    )
    .unwrap()
    .tag(1, &[0; 16]);
    let (initiator, m1) = Initiator::start(&ayse_keys, &remote(&burak_contact), &tag).unwrap();
    let (responder, m2) = Responder::respond(&burak_keys, &remote(&ayse_contact), &m1, b"").unwrap();
    let (mut a, m3) = initiator.finish(&ayse_keys, &m2, b"").unwrap();
    let mut b = responder.finish(&m3).unwrap();
    let record = a.session.seal(b"merhaba").unwrap();
    assert!(matches!(b.session.open(&record).unwrap(), Record::Data(d) if d.as_slice() == b"merhaba"));
}

#[test]
fn a_man_in_the_middle_shows_different_emoji() {
    // Mallory sits between Ayşe and Burak, pairing separately with each. Whatever she does, the
    // commitment forces her to fix her contribution before learning theirs, so the two screens
    // differ except with probability 2^-30. Deterministic randomness keeps the test stable.
    let (ayse, burak, mallory) = (Owner::new("Ayşe"), Owner::new("Burak"), Owner::new("Mallory"));
    let rng = |seed: u8| DeterministicRng::new([seed; 32]);
    let (mut rng_a, mut rng_b, mut rng_m1, mut rng_m2) = (rng(1), rng(2), rng(3), rng(4));

    // Ayşe ↔ Mallory (Mallory plays the responder).
    let (mut a, a1) = Pairing::start_from(Mode::Nearby, None, None, &mut rng_a).unwrap();
    let (mut m_resp, e) = Pairing::accept_from(&a1, &mallory.profile(), &[], &[], &mut rng_m1).unwrap();
    let (a3, ..) = split(a.receive_from(&one(split(e).0), &ayse.profile(), &mut rng_a).unwrap());
    let (a4, sas_m1, _) = split(m_resp.receive(&one(a3), &mallory.profile()).unwrap());
    let (_, sas_a, _) = split(a.receive(&one(a4), &ayse.profile()).unwrap());

    // Mallory ↔ Burak (Mallory plays the initiator).
    let (mut m_init, b1) = Pairing::start_from(Mode::Nearby, None, None, &mut rng_m2).unwrap();
    let (mut b, e) = Pairing::accept_from(&b1, &burak.profile(), &[], &[], &mut rng_b).unwrap();
    let (b3, ..) = split(
        m_init
            .receive_from(&one(split(e).0), &mallory.profile(), &mut rng_m2)
            .unwrap(),
    );
    let (_, sas_b, _) = split(b.receive(&one(b3), &burak.profile()).unwrap());

    assert_eq!(sas_a, sas_m1, "each half looks consistent to Mallory");
    assert_ne!(sas_a.unwrap(), sas_b.unwrap(), "but Ayşe's and Burak's screens differ");
}

#[test]
fn rejection_reaches_the_other_device() {
    let (ayse, burak) = (Owner::new("Ayşe"), Owner::new("Burak"));
    let (mut i, mut r, ..) = nearby_until_sas(&ayse, &burak);
    let close = r.reject().unwrap();
    assert_eq!(i.receive(&close, &ayse.profile()).err(), Some(PairingError::Rejected));
    assert_eq!(i.confirm(&ayse.profile()).err(), Some(PairingError::UnexpectedMessage));
}

#[test]
fn a_device_cannot_pair_with_itself() {
    let ayse = Owner::new("Ayşe");
    let (mut i, mut r, ..) = nearby_until_sas(&ayse, &ayse);
    let (card_i, ..) = split(i.confirm(&ayse.profile()).unwrap());
    r.confirm(&ayse.profile()).unwrap();
    assert_eq!(
        r.receive(&one(card_i), &ayse.profile()).err(),
        Some(PairingError::SelfPairing)
    );
}

#[test]
fn invite_pairing_end_to_end() {
    let (ayse, burak) = (Owner::new("Ayşe"), Owner::new("Burak"));
    let invite = Invite::new(burak.identity.public()).unwrap();
    let scanned = ScannedInvite::parse(&invite.qr_text()).unwrap();

    let (mut a, m1) = Pairing::start_invite(&scanned).unwrap();
    let (mut b, events) = Pairing::accept(&m1, &burak.profile(), &[&invite], &[]).unwrap();
    assert_eq!(b.invite_id(), Some(invite.id()));
    let (mut to_ayse, ..) = split(events);
    assert_eq!(to_ayse.len(), 2, "message 2 and Burak's card");
    let burak_card = to_ayse.pop().unwrap();

    let (nothing, ..) = split(a.receive(&one(to_ayse), &ayse.profile()).unwrap());
    assert!(
        nothing.is_empty(),
        "Ayşe reveals nothing before Burak's card is verified"
    );
    let (ayse_card, _, burak_contact) = split(a.receive(&burak_card, &ayse.profile()).unwrap());
    let (_, _, ayse_contact) = split(b.receive(&one(ayse_card), &burak.profile()).unwrap());

    let (burak_contact, ayse_contact) = (burak_contact.unwrap(), ayse_contact.unwrap());
    assert_paired_with(&burak_contact, &burak);
    assert_paired_with(&ayse_contact, &ayse);
    assert_eq!(burak_contact.link_psk.expose(), ayse_contact.link_psk.expose());
}

#[test]
fn invite_needs_the_secret_from_the_qr_code() {
    // Mallory overheard the invite id on the air but never saw the QR code.
    let burak = Owner::new("Burak");
    let invite = Invite::new(burak.identity.public()).unwrap();
    let other = ScannedInvite::parse(&Invite::new(burak.identity.public()).unwrap().qr_text()).unwrap();
    let (mut mallory, mut m1) = Pairing::start_invite(&other).unwrap();
    m1[3..3 + 8].copy_from_slice(&invite.id());

    let (_, events) = Pairing::accept(&m1, &burak.profile(), &[&invite], &[]).unwrap();
    let (mut sends, ..) = split(events);
    sends.pop();
    let result = mallory.receive(&one(sends), &Owner::new("Mallory").profile());
    assert!(matches!(
        result,
        Err(PairingError::Link(link::LinkError::AuthenticationFailed))
    ));
}

#[test]
fn invite_rejects_a_device_that_is_not_the_one_in_the_qr_code() {
    // Mallory photographed Burak's QR code and answers in his place, with her own identity.
    let (ayse, burak, mallory) = (Owner::new("Ayşe"), Owner::new("Burak"), Owner::new("Mallory"));
    let real = Invite::new_from(burak.identity.public(), &mut DeterministicRng::new([9; 32])).unwrap();
    let copy = Invite::new_from(mallory.identity.public(), &mut DeterministicRng::new([9; 32])).unwrap();
    let scanned = ScannedInvite::parse(&real.qr_text()).unwrap();

    let (mut a, m1) = Pairing::start_invite(&scanned).unwrap();
    let (_, events) = Pairing::accept(&m1, &mallory.profile(), &[&copy], &[]).unwrap();
    let (mut sends, ..) = split(events);
    let mallory_card = sends.pop().unwrap();
    a.receive(&one(sends), &ayse.profile()).unwrap();
    assert_eq!(
        a.receive(&mallory_card, &ayse.profile()).err(),
        Some(PairingError::AuthenticationFailed)
    );
}

#[test]
fn unknown_invites_and_misplaced_messages_are_refused() {
    let (ayse, burak) = (Owner::new("Ayşe"), Owner::new("Burak"));
    let scanned = ScannedInvite::parse(&Invite::new(burak.identity.public()).unwrap().qr_text()).unwrap();
    let (_, m1) = Pairing::start_invite(&scanned).unwrap();
    assert_eq!(
        Pairing::accept(&m1, &burak.profile(), &[], &[]).err(),
        Some(PairingError::UnknownInvite)
    );

    let (mut i, m1) = Pairing::start_nearby().unwrap();
    assert_eq!(i.confirm(&ayse.profile()).err(), Some(PairingError::UnexpectedMessage));
    assert_eq!(i.receive(&m1, &ayse.profile()).err(), Some(PairingError::Malformed));
    assert_eq!(
        i.receive(&m1, &ayse.profile()).err(),
        Some(PairingError::UnexpectedMessage),
        "failed for good"
    );
    assert_eq!(
        Pairing::accept(&m1[..100], &burak.profile(), &[], &[]).err(),
        Some(PairingError::Malformed)
    );
    let mut future = m1.clone();
    future[0] = 1;
    assert_eq!(
        Pairing::accept(&future, &burak.profile(), &[], &[]).err(),
        Some(PairingError::UnsupportedVersion)
    );
}

#[test]
fn tampering_breaks_pairing() {
    let (ayse, burak) = (Owner::new("Ayşe"), Owner::new("Burak"));
    let (mut i, m1) = Pairing::start_nearby().unwrap();
    let (_, events) = Pairing::accept(&m1, &burak.profile(), &[], &[]).unwrap();
    let mut m2 = one(split(events).0);
    let last = m2.len() - 1;
    m2[last] ^= 1;
    assert!(i.receive(&m2, &ayse.profile()).is_err());

    let (mut i, mut r, ..) = nearby_until_sas(&ayse, &burak);
    let (card_i, ..) = split(i.confirm(&ayse.profile()).unwrap());
    r.confirm(&burak.profile()).unwrap();
    let mut card = one(card_i);
    card[10] ^= 1;
    assert!(r.receive(&card, &burak.profile()).is_err());
}

/// Published vectors (docs/protocol.md §4.7). `check_pairing.py` recomputes them from the spec.
#[test]
fn published_test_vectors() {
    let (ayse, burak) = (Owner::from_seed("Ayşe", 0xa0), Owner::from_seed("Burak", 0xb0));
    let ct_at = |m: &[u8], at: usize| Ciphertext::from_bytes(&m[at..at + CIPHERTEXT_LEN]).unwrap();
    let ephemeral_of = |seed: [u8; 32]| {
        let mut s = SecretBytes::zeroed();
        DeterministicRng::new(seed).fill(s.expose_mut()).unwrap();
        DecapsulationKey::from_seed(s).unwrap()
    };
    let common = |fields: &mut Vec<(&str, String)>| {
        for (role, owner) in [("initiator", &ayse), ("responder", &burak)] {
            fields.push((
                leak(format!("{role}_identity")),
                to_hex(owner.identity.public().as_bytes()),
            ));
            fields.push((
                leak(format!("{role}_identity_seed")),
                to_hex(owner.identity.seed().expose()),
            ));
            fields.push((
                leak(format!("{role}_static_kem")),
                to_hex(owner.static_kem.encapsulation_key().as_bytes()),
            ));
            fields.push((
                leak(format!("{role}_presence_key")),
                to_hex(owner.presence_key.expose()),
            ));
            fields.push((leak(format!("{role}_name")), to_hex(owner.name.as_bytes())));
        }
    };

    // Nearby.
    let (seed_i, seed_r) = ([0x31; 32], [0x32; 32]);
    let (mut rng_i, mut rng_r) = (DeterministicRng::new(seed_i), DeterministicRng::new(seed_r));
    let (mut i, m1) = Pairing::start_from(Mode::Nearby, None, None, &mut rng_i).unwrap();
    let (mut r, e) = Pairing::accept_from(&m1, &burak.profile(), &[], &[], &mut rng_r).unwrap();
    let m2 = one(split(e).0);
    let m3 = one(split(i.receive_from(&m2, &ayse.profile(), &mut rng_i).unwrap()).0);
    let (m4, sas, _) = split(r.receive(&m3, &burak.profile()).unwrap());
    let m4 = one(m4);
    i.receive(&m4, &ayse.profile()).unwrap();
    let card_i = one(split(i.confirm(&ayse.profile()).unwrap()).0);
    let card_r = one(split(r.confirm(&burak.profile()).unwrap()).0);
    let paired = split(i.receive(&card_r, &ayse.profile()).unwrap()).2.unwrap();
    let ss = ephemeral_of(seed_i).decapsulate(&ct_at(&m2, 2)).unwrap();

    let mut fields: Vec<(&str, String)> =
        vec![("protocol", "AirChat v1 pairing-protocol, nearby, wire version 0".into())];
    common(&mut fields);
    fields.extend([
        ("initiator_rng_seed", to_hex(&seed_i)),
        ("responder_rng_seed", to_hex(&seed_r)),
        ("ss", to_hex(ss.expose())),
        ("message1", to_hex(&m1)),
        ("message2", to_hex(&m2)),
        ("message3", to_hex(&m3)),
        ("message4", to_hex(&m4)),
        ("sas_indices", to_hex(&sas.unwrap().indices())),
        ("sas_emoji", sas.unwrap().emoji().concat()),
        ("initiator_card_record", to_hex(&card_i)),
        ("responder_card_record", to_hex(&card_r)),
        ("link_psk", to_hex(paired.link_psk.expose())),
    ]);
    check_vector("pairing_nearby", &fields);

    // Invite: Burak shows the QR code, Ayşe scans it.
    let (seed_i, seed_r, seed_invite) = ([0x41; 32], [0x42; 32], [0x43; 32]);
    let (mut rng_i, mut rng_r) = (DeterministicRng::new(seed_i), DeterministicRng::new(seed_r));
    let invite = Invite::new_from(burak.identity.public(), &mut DeterministicRng::new(seed_invite)).unwrap();
    let qr = invite.qr_text();
    let scanned = ScannedInvite::parse(&qr).unwrap();
    let (mut a, m1) = Pairing::start_from(Mode::Invite, Some(&scanned), None, &mut rng_i).unwrap();
    let (_b, e) = Pairing::accept_from(&m1, &burak.profile(), &[&invite], &[], &mut rng_r).unwrap();
    let (mut sends, ..) = split(e);
    let card_r = sends.pop().unwrap();
    let m2 = one(sends);
    a.receive(&m2, &ayse.profile()).unwrap();
    let (card_i, _, paired) = split(a.receive(&card_r, &ayse.profile()).unwrap());
    let ss = ephemeral_of(seed_i).decapsulate(&ct_at(&m2, 2)).unwrap();

    let mut fields: Vec<(&str, String)> =
        vec![("protocol", "AirChat v1 pairing-protocol, invite, wire version 0".into())];
    common(&mut fields);
    fields.extend([
        ("invite_rng_seed", to_hex(&seed_invite)),
        ("qr_text", qr.to_string()),
        ("beacon_token", to_hex(&scanned.beacon_token())),
        ("initiator_rng_seed", to_hex(&seed_i)),
        ("responder_rng_seed", to_hex(&seed_r)),
        ("ss", to_hex(ss.expose())),
        ("message1", to_hex(&m1)),
        ("message2", to_hex(&m2)),
        ("responder_card_record", to_hex(&card_r)),
        ("initiator_card_record", to_hex(&one(card_i))),
        ("link_psk", to_hex(paired.unwrap().link_psk.expose())),
    ]);
    check_vector("pairing_invite", &fields);

    // Request: Burak typed Ayşe's AirChat ID; her device answers, and she approves.
    let (seed_i, seed_r) = ([0x51; 32], [0x52; 32]);
    let (mut rng_i, mut rng_r) = (DeterministicRng::new(seed_i), DeterministicRng::new(seed_r));
    let id = ayse.identity.public().airchat_id();
    let epoch = 490_000;
    let token = crate::discovery::request_token(&id, epoch).unwrap();
    let (mut a, m1) = Pairing::start_from(Mode::Request, None, Some((&id, &token)), &mut rng_i).unwrap();
    let (mut b, e) = Pairing::accept_from(&m1, &burak.profile(), &[], &[(token, id)], &mut rng_r).unwrap();
    let m2 = one(sent(&e));
    let identity_i = one(sent(&a.receive(&m2, &ayse.profile()).unwrap()));
    let card_r = one(sent(&b.receive(&identity_i, &burak.profile()).unwrap()));
    a.receive(&card_r, &ayse.profile()).unwrap();
    let (card_i, _, paired) = split(a.approve(&ayse.profile()).unwrap());
    let ss = ephemeral_of(seed_i).decapsulate(&ct_at(&m2, 2)).unwrap();

    let mut fields: Vec<(&str, String)> = vec![(
        "protocol",
        "AirChat v1 pairing-protocol, request, wire version 0".into(),
    )];
    common(&mut fields);
    fields.extend([
        ("airchat_id", id.to_string()),
        ("epoch", epoch.to_string()),
        ("request_token", to_hex(&token)),
        ("initiator_rng_seed", to_hex(&seed_i)),
        ("responder_rng_seed", to_hex(&seed_r)),
        ("ss", to_hex(ss.expose())),
        ("message1", to_hex(&m1)),
        ("message2", to_hex(&m2)),
        ("initiator_identity_record", to_hex(&identity_i)),
        ("responder_card_record", to_hex(&card_r)),
        ("initiator_card_record", to_hex(&one(card_i))),
        ("link_psk", to_hex(paired.unwrap().link_psk.expose())),
    ]);
    check_vector("pairing_request", &fields);
}

/// Field names built at runtime need `'static` lifetime for the vector table; fine in a test.
fn leak(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

// Request mode (§4.8): Burak typed Ayşe's AirChat ID; her device answers his request.

fn sent(events: &[Event]) -> Vec<Vec<u8>> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::Send(bytes) => Some(bytes.clone()),
            _ => None,
        })
        .collect()
}

/// Runs a request up to Ayşe's device asking her, with `answerer` as whoever answers it.
fn request_until_asked(
    answerer: &Owner,
    ayse: &Owner,
    burak: &Owner,
) -> Result<(Pairing, Pairing, Vec<Event>), PairingError> {
    let id = ayse.identity.public().airchat_id();
    let token = crate::discovery::request_token(&id, 7).unwrap();
    let (mut a, m1) = Pairing::start_request(&id, &token).unwrap();
    let (mut b, events) = Pairing::accept(&m1, &burak.profile(), &[], &[(token, id)]).unwrap();
    let identity = one(sent(&a.receive(&one(sent(&events)), &answerer.profile())?));
    let card = one(sent(&b.receive(&identity, &burak.profile())?));
    let asked = a.receive(&card, &answerer.profile())?;
    Ok((a, b, asked))
}

#[test]
fn a_request_needs_the_owner_of_the_id_and_its_approval() {
    let (ayse, burak) = (Owner::new("Ayşe"), Owner::new("Burak"));
    let (mut a, mut b, asked) = request_until_asked(&ayse, &ayse, &burak).unwrap();
    let [Event::Requested(requester)] = &asked[..] else {
        panic!("Ayşe is asked, nothing is sent yet: {asked:?}");
    };
    assert_eq!(requester.identity, burak.identity.public());
    assert_eq!(requester.display_name, "Burak");
    assert_eq!(a.requester(), Some(burak.identity.public()));

    let (cards, _, paired_a) = split(a.approve(&ayse.profile()).unwrap());
    let paired_a = paired_a.expect("Ayşe adds Burak");
    assert_paired_with(&paired_a, &burak);
    let (_, _, paired_b) = split(b.receive(&one(cards), &burak.profile()).unwrap());
    let paired_b = paired_b.expect("Burak adds Ayşe");
    assert_paired_with(&paired_b, &ayse);
    assert_eq!(paired_a.link_psk.expose(), paired_b.link_psk.expose());
}

#[test]
fn whoever_only_knows_the_id_learns_nothing_of_the_requester() {
    let (ayse, burak, mallory) = (Owner::new("Ayşe"), Owner::new("Burak"), Owner::new("Mallory"));
    // Mallory answers Burak's request for Ayşe, but cannot prove she is Ayşe: Burak shows nothing.
    assert_eq!(
        request_until_asked(&mallory, &ayse, &burak).err(),
        Some(PairingError::AuthenticationFailed)
    );
    // A request for someone else's ID is not this device's to accept.
    let id = mallory.identity.public().airchat_id();
    let token = crate::discovery::request_token(&id, 7).unwrap();
    let (_, m1) = Pairing::start_request(&id, &token).unwrap();
    let ayse_id = ayse.identity.public().airchat_id();
    let theirs = crate::discovery::request_token(&ayse_id, 7).unwrap();
    assert_eq!(
        Pairing::accept(&m1, &burak.profile(), &[], &[(theirs, ayse_id)]).err(),
        Some(PairingError::UnknownRequest)
    );
}

#[test]
fn a_declined_request_ends_without_the_owners_card() {
    let (ayse, burak) = (Owner::new("Ayşe"), Owner::new("Burak"));
    let (mut a, mut b, _) = request_until_asked(&ayse, &ayse, &burak).unwrap();
    let close = a.reject().expect("a close record");
    assert_eq!(b.receive(&close, &burak.profile()).err(), Some(PairingError::Rejected));
    assert!(a.approve(&ayse.profile()).is_err(), "too late");
}
