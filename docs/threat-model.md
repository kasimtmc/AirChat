# AirChat — Threat model

Status: **draft v0.2** (2026-10-18), written to prepare an independent audit (requirement S-11).
It says what AirChat protects, from whom, on what it relies, and where it knowingly falls short.
Details are in [protocol.md](../rust/airchat-protocol/docs/protocol.md) (`§`), [requirements.md](requirements.md) (`S-2`, `AP-4`, …)
and [architecture.md](architecture.md) (`arch §`). Where this document and those disagree, they win
and this one is wrong.

## 1. The system in one paragraph

Phones running AirChat talk to each other directly, with no server and no internet: Bluetooth Low
Energy finds devices and sets up connections, and data goes over Wi-Fi (the same network, Wi-Fi
Aware, or a local-only hotspot one phone opens). Every device passes on others' encrypted messages
(the mesh, §10), and devices in Air Provider mode also carry others' calls, video and files over
multi-hop paths (§12). Contacts are made in person (emoji comparison or QR code, §4.3–4.5) or by
AirChat ID (§4.8). Content is end-to-end encrypted to its recipients, every hop is encrypted again by
an authenticated link session (§6), and everything is stored encrypted under a key that only the
user's PIN (with the phone's secure hardware) or fingerprint opens (arch §4).

## 2. What is protected

| Asset | Meaning |
|---|---|
| **Content** | Text, files, voice and video of 1:1 conversations, groups, calls, push-to-talk and walkie-talkie channels. |
| **Authenticity** | That a message, call or group change comes from who it claims, unchanged. |
| **Social graph** | Who is whose contact, who is in which group, who talks to whom and when. |
| **Location and presence** | That a given person is nearby, or was at a place at a time. |
| **Identity** | The link between a device and a person: name, AirChat ID, identity key. |
| **Keys** | Identity key, static keys, link keys, pairing secrets, group epoch keys, channel keys, the master key, the PIN. |
| **Data at rest** | The database and files on the phone, and anything that might leak beside them (caches, logs, backups, clipboard, notifications, screenshots). |
| **Availability** | That messages and calls get through, and the battery lasts. |

## 3. What AirChat relies on

These are assumptions, not guarantees; if one fails, so may the properties below.

- **The device and its operating system** are not compromised while the user uses AirChat: no root,
  no malicious accessibility service or keyboard, an unmodified AirChat build.
- **The Android Keystore** (StrongBox or the TEE) keeps its keys inside the secure hardware, and
  enforces biometric authentication for the key that guards the fingerprint unlock (arch §4.2).
- **The cryptographic primitives** behave as specified: X-Wing (ML-KEM-768 + X25519), Ed25519,
  ChaCha20-Poly1305 and XChaCha20-Poly1305, SHA-256, HMAC, HKDF (libcrux, formally verified), Argon2id
  (RustCrypto), and the operating system's random number generator (§3, arch §3.2).
- **The users verify contacts**: they compare the five emoji, or scan the QR code in person. Adding
  by AirChat ID trusts that the ID was obtained from its owner over a channel the attacker does not
  control (§4.8).
- **No clock is trusted.** Time only rotates identifiers and expires things; clocks may be off by up
  to an hour either way (§5.2).
- **The build** contains what the source says: the toolchain is pinned (`rust/rust-toolchain.toml`),
  dependencies are locked (`Cargo.lock`, Gradle catalogue), but builds are not yet reproducible and
  there is no release signing process yet (section 7 below).

## 4. Adversaries

Each adversary is listed with what it can do and what AirChat promises against it. Several may work
together; the table in section 5 sums up what holds against whom.

### A1. Passive radio observer

Someone nearby who records Bluetooth and Wi-Fi traffic (an RF sniffer, a "Bluetooth tracker"
network, a curious person).

- **Sees:** that AirChat devices are present (beacon formats and the mDNS service type are
  recognisable), when they are active, how much they send (sizes rounded up to 256 bytes in the
  mesh, §10.3), and the radio addresses chosen by the operating system.
- **Does not learn:** content, names, AirChat IDs or identity keys. Presence, pairing, request and
  channel tokens look random and change every hour (§5, §11.2); mDNS instance names are random and
  new at each start (§7.2); identities never appear on the air (§6.5).
- **Limits:** radio-level fingerprinting (signal strength, hardware quirks, timing) and the
  platform's Bluetooth/Wi-Fi address randomisation are outside AirChat's control. Within one hour a
  device's tokens are stable, so it can be followed for up to that long, and a device that
  is always on can be followed across hours by continuity. AirChat reduces what is broadcast; it
  cannot hide that a radio is talking (requirements §5 *Known limits*).

### A2. Active radio attacker

Someone nearby who also transmits: injects, replays, relays or jams radio traffic, or runs a fake
access point.

- **Cannot:** read or change content, or pose as a contact — link sessions authenticate both sides
  with their keys and a pre-shared key, are forward secret and resist key-compromise impersonation
  (§6.3, §6.5). Pairing cannot be intercepted without the users noticing that the emoji differ, or
  without having the QR code (§4.3–4.5).
- **Can:** replay a contact's presence beacon elsewhere and watch whether a nearby device starts a
  handshake, which shows that some device there is that contact's contact (§6.5 *Limits*);
  disrupt or jam everything (out of scope, section 6 below); make devices try handshakes that fail, which costs
  battery (bounded by rate limits).

### A3. Operator or member of a shared network

Anyone on the same Wi-Fi network or local hotspot, or running it: sees IP and MAC addresses, mDNS
announcements, TCP connections and their sizes and timing.

- **Learns:** what A1 learns, plus which IP addresses talk to which. No content, no identities:
  every connection is a link session (§6) or a pairing (§4.3).
- **Limits:** the router may log the device's MAC address and the hostname the operating system
  sends; AirChat does not choose those.

### A4. Malicious relay or Air Provider

A device that relays mesh envelopes or carries paths, possibly many such devices working together;
mesh links are not authenticated, so anyone can be a relay (§10.2).

- **Sees:** envelope sizes (rounded), arrival times and the neighbour they came from, hop counts,
  tags (stable for an hour per conversation direction or group), and whether a text was sealed to
  a one-time prekey (§10.6). On a path: its class, its size and timing, its two neighbours (§12.4).
- **Cannot:** read or forge envelopes or path traffic, or tell whose they are; everything is sealed
  end to end and authenticated (§10.3, §12.3). A relay that changes an envelope only breaks it.
- **Can:** drop, delay, replay or flood. Replays are recognised by id; what one neighbour can make
  others pass on is bounded by a budget per neighbour (§10.4); a dropped message is sent again by
  its sender until it is delivered or given up after a day (§10.5, M-8). A provider that drops a path makes the app look for another (AP-7).
  Many colluding relays around a victim learn more about timing; there is no cover traffic.
- **Holds nothing:** relays and providers keep envelopes in memory for minutes only, never for
  recipients out of reach (AP-6).

### A5. Malicious contact

Someone the user added as a contact.

- **Can, by design:** read and keep everything the user sends them, record calls, photograph the
  screen; recognise the user's presence beacons and so tell when the user is nearby (that is what
  presence keys are for, §5.2); share the user's AirChat ID.
- **The user's answer** is the emergency exit (C-7): block, delete the conversation here, remove
  them from the groups the user administers, leave the others if wished. It works whatever app the
  contact runs, and changes nothing on the contact's device: what was sent stays sent. A modified
  client is not detected: the other side could only take its own word for it.
- **Cannot:** read the user's conversations with others, pose as other contacts, or keep tracking
  the user after being deleted or blocked — the device then makes a new presence key and tells only
  the remaining contacts (§5.4), and turns the blocked one's connections away (C-7). Exception: a
  deleted or blocked contact who shares a group with the user learns the new key from the group's
  next roster, as every member does (§5.4).
- **Limit:** without the "instant voice" permission (off by default), a contact's push-to-talk does
  not play; calls still ring (C-5). It arrives as a voice message instead (V-3), which the user's
  device deletes 15 minutes after it was first played; the sender, or a modified client, may keep
  a copy.

### A6. Malicious group member or admin

- **A member can:** read and keep the group's content of its epochs, see when fellow members are
  nearby (as a contact would, §9.4), and pass group traffic on selectively. It cannot read epochs
  before it joined or after it left or was removed (M-4, §9.2), or change the members. Once removed,
  it cannot write into the group either: a device that holds the new epoch reads earlier epochs'
  messages only from those still in it (§9.3), even though a removed member's modified client may
  keep the old key. The date a member puts on a message is its own claim; apps show when a message
  arrived.
- **An admin can, by design:** add and remove members, make others admins, and delete the group for
  everyone, which deletes its history from every member's device as soon as the deletion reaches it
  (M-2, §9.2). Only an admin of the epoch, still an admin in the newest roster a member holds, is
  obeyed; a forged deletion from a member is ignored.
- **A temporary member** with a modified client can keep what it saw; deleting at the end of a
  membership is best effort (M-5).

### A7. Stranger who knows the user's AirChat ID

- **Can:** send a contact request, which the user approves or declines (C-4). While the user accepts
  requests and the app is unlocked, a request beacon for the user's ID nearby makes the user's
  device answer it, so someone who knows the ID can learn that its owner is nearby — at most once a
  minute (§4.8). Turning "accept requests" off stops this.
- **Cannot:** message or call the user, or see anything else, without becoming a contact.

### A8. Thief of the phone

- **Locked or switched off:** the database and files are encrypted under a master key that only the
  PIN (stretched with Argon2id and bound to this phone's Keystore) or the fingerprint opens (arch
  §4.1, §4.2). After 5 wrong PINs each attempt waits, up to an hour. While locked, the app still
  holds in memory what links need: the static key, contacts' and fellow members' link and presence
  keys, messages not yet delivered; incoming messages are kept encrypted to an inbox key whose
  private half is in the database (arch §4.3). Someone who can read the memory of a running, locked
  phone gets those.
- **Unlocked:** everything the user sees. The app locks after 60 s in the background.
- **Limit:** on a rooted phone that is unlocked (the phone, not AirChat), the Keystore key can be
  used to guess the PIN offline; a 6-digit PIN does not survive that, a passphrase does (arch §4.2).
- **After the fact:** a thief who copied the device's keys can pose as it to its contacts only until
  it has linked twice with each without the thief, and read new group updates and envelopes only
  until its next weekly static key is taken (S-7, §6.5, §6.9). Mesh envelopes stay forgeable with a
  copied pairing secret until the two pair again (§10.6).

### A9. Malware or a compromised operating system

Out of scope beyond what the app can do from inside: screenshots and recent-app previews are blocked
(`FLAG_SECURE`), backups are off, notifications carry no content, keyboards are asked not to learn,
copied text is marked sensitive and cleared after a minute, PIN fields show accessibility services
only a mask, and release builds log no content (S-9). A rooted or compromised phone can read the
screen while AirChat is open (requirements §5 *Known limits*).

### A10. Future quantum adversary

Someone who records traffic now to decrypt it with a quantum computer later ("harvest now, decrypt
later"). Every key exchange uses X-Wing, a hybrid of ML-KEM-768 and X25519 (S-6, §3), so recorded
traffic stays confidential if either holds. Signatures (Ed25519) are not post-quantum; that matters
only for forging in the future, not for reading the past. Password-derived channel keys are as
strong as the password (§11.1).

### A11. Supply chain

A compromised dependency, toolchain, build machine or distribution channel. Mitigated so far by a
small set of dependencies, a pinned toolchain and locked versions, and by `cargo deny check`
(`rust/deny.toml`): RustSec advisories, licences compatible with GPL-3.0-or-later, and crates.io as
the only source. Android dependencies were checked against OSV by hand (2026-10-14: none affected).
GitHub Actions (`.github/workflows/ci.yml`, its actions pinned to commit SHAs) runs these checks,
the tests and the Android build on every push to master and every pull request. Not yet:
reproducible builds.

### A12. A contact running a modified build

They can do everything a malicious contact can (A5), and skip what is left to their app: deleting
voice messages, ending temporary memberships, deleting groups, blocking screenshots. A verified
build (S-12, §6.10) shows that a contact's AirChat is the official build on a locked, verified
phone. It is a sign, not a proof: someone holding a leaked attestation key can fake it until Google
revokes that key, the receiver's revocation list is as old as its build, and a phone can be
compromised after it was verified. Its absence means nothing: phones with unlocked bootloaders,
builds of one's own and other platforms simply have no badge. The chain shows contacts the phone's
security patch level and, through its certificates, roughly its maker.

## 5. Properties at a glance

| Property | Holds against | Fails or is limited when | Spec |
|---|---|---|---|
| Confidentiality of content | A1–A4, A7, A10; A5/A6 for what is not theirs | the recipient's device or the OS is compromised (A9) | §6, §8, §9, §10, §12 |
| Authenticity of content | A1–A4, A7 | keys copied from a device (A8), for a while; mesh envelopes until re-pairing | §6.5, §10.6 |
| Forward secrecy | everyone, for links and calls; mesh texts sealed to a one-time prekey once read | mesh texts until read; those sealed to the static key (no prekey left) and acknowledgements until that key is deleted: at least 25 hours after the next weekly one, longer while a contact has not taken that yet | §6.5, §6.9, §10.6 |
| Post-compromise security | A8 after the fact | identity key never changes; mesh envelopes until re-pairing | S-7, §6.8, §6.9 |
| No identifiers on the air | A1–A4 | within one hour (stable tokens); radio fingerprinting | §5, §7, S-8 |
| Hiding the social graph from relays | A4 | timing correlation by many colluding relays | §10.6, §12.4 |
| Presence hidden from strangers | A1–A4 | beacon replay (A2); request beacons while requests are accepted (A7) | §5, §4.8 |
| Data at rest | A8 locked or off | memory of a running locked phone; a rooted phone with a weak PIN | arch §4 |
| Availability | — | jamming; floods are bounded, not prevented | §10.4, AP-3 |

## 6. Out of scope

- A recipient who shares, records or photographs what they received.
- A compromised or rooted phone, or a modified AirChat client, on either side.
- Jamming, and other denial of service at the radio level.
- Hiding that AirChat is installed or in use from someone who can see the phone or its radio.
- Anonymity against an observer who covers every radio around the user at once.
- Coercion of the user to unlock the phone.

## 7. Known weaknesses and open questions

Listed for the audit; some are deliberate trade-offs, some may change.

1. The identity key never changes; the AirChat ID is derived from it (§6.5).
2. Mesh envelopes can be forged with a copied pairing secret until the two contacts pair again
   (§10.6).
3. A replayed presence beacon shows that some nearby device is a contact of the beacon's owner
   (§6.5).
4. Request beacons let anyone who knows an ID learn that its owner is nearby while requests are
   accepted (§4.8).
5. Password-derived channel keys use a fixed salt, so one password is one channel everywhere and
   guesses can be precomputed (§11.1).
6. Mesh tags stay the same for an hour per conversation direction or group, so a relay can group
   that hour's envelopes (§10.6).
7. A deleted or blocked contact who shares a group with the user keeps recognising the user's
   presence through the group's rosters (§5.4).
8. The JVM may keep copies of decrypted text in memory until they are garbage collected
   (arch §6).
9. While locked, undelivered messages and the keys links need stay in memory (arch §4.3).
10. Debug builds carry switches and log more; only release builds are meant for use (arch §5).
11. Builds are not reproducible yet. Release APKs are signed by Gradle with the developer's key
    (v3) and published as GitHub releases with their SHA-256; there is no store or other channel.
12. The contact link handshake (secrecy, forward secrecy, key compromise impersonation, mutual
    authentication, healing), pairing in its three modes (link secret, peer authentication,
    presence keys), group keys (epoch key secrecy, removal, update and message authenticity, the
    removed member kept out) and 1:1 mesh envelopes (secrecy from relays, forward secrecy of
    prekey texts, authenticity) are modelled formally, in Tamarin
    (`rust/airchat-protocol/formal/`), symbolically and with ideal primitives; the emoji are
    compared as whole hashes, and the group model has one shape (three members, one removal).
    Group, channel and mesh links, paths, two updates of one epoch and privacy (identity hiding,
    unlinkability) are not; test vectors are re-derived
    from the spec by independent scripts, and every parser of outside bytes is fuzzed (arch §3.3).
13. Whatever happens on the other side's device is only as good as the app there: voice messages
    deleted after playing (V-3), a temporary member's content deleted at the end (M-5), a group
    deleted for everyone (M-2), screenshots blocked (S-9). A modified client can skip all of it and
    cannot be told apart for sure (A5): a verified build (S-12) is a sign of an unmodified one; the
    user's own answer is the emergency exit (C-7).
14. Verified builds trust Google's attestation roots and a revocation list as recent as the build;
    leaked attestation keys pass until revoked and the user updates (§6.10, A12).
15. Two admins who change a group at the same time, out of each other's reach, both start the
    same epoch. The update with the smaller id stands everywhere and the other admin makes its
    change again in the next epoch (§9.2), so no removal is lost; but until that admin is back in
    reach, a member it removed may hold the key of the epoch that stood, and messages of that
    epoch reach those on the other update only once their senders moved over and sealed them
    afresh. A message of the current epoch that does not open now waits instead of being
    acknowledged, so whoever passes on a forged one may send it again for up to a day. The rule
    is tested, not modelled formally.

## 8. Suggested audit priorities

1. The link handshake, link key replacement and static key versions (§6), and pairing (§4.3–4.8).
2. Group epochs, updates, removal and deletion (§9).
3. Mesh envelopes, prekeys and what relays learn (§10); paths through Air Providers (§12).
4. The Rust core's handling of outside bytes, key lifetimes and wiping, and encrypted storage.
5. The Android app: Keystore use, lock and lockout, the locked mode, data leaving through the
   clipboard, notifications, file export and logs.
6. Radio privacy on real devices: BLE advertisements, Wi-Fi Aware, hotspot and mDNS.
