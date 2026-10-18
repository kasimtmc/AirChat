# AirChat — Architecture

Status: **v0.2** (2026-10-19), describing the Android app as built. Requirements referenced as `S-2`, `T-1`, … are in
[requirements.md](requirements.md).

## 1. Layers

```
┌────────────────────────────────────────────────────────────────────┐
│ UI (platform)          Contacts · Chats · Calls · PTT · Walkie-talkie │
├────────────────────────────────────────────────────────────────────┤
│ Platform services      Media capture/playback · codecs · app lock ·   │
│                        background service · notifications             │
├────────────────────────────────────────────────────────────────────┤
│ Rust core (shared)     Identity · contacts · conversations · groups · │
│                        handshake · sessions · message encryption ·    │
│                        framing · routing · encrypted storage          │
├────────────────────────────────────────────────────────────────────┤
│ Link interface         send(frame) / receive(frame) / link quality    │
├────────────────────────────────────────────────────────────────────┤
│ Transports (platform)  BLE · Wi-Fi Aware · local-only hotspot · LAN  │
│                        (no Bluetooth Classic or Wi-Fi Direct: T-5)   │
└────────────────────────────────────────────────────────────────────┘
```

**The rule:** the platform moves bytes, the core decides what they mean. Transports never see plaintext,
and plaintext only leaves the core to be shown on screen or played back.

## 2. Repository layout

```
AirChat/
├── app/            Android app: Compose UI, platform services, transports
├── core-bridge/    Android library: builds the Rust core for Android and exposes it to Kotlin
├── rust/           Cargo workspace, platform-independent
│   ├── airchat-protocol/ The protocol: formats and crypto (also kasimtmc/airchat-protocol)
│   │   ├── docs/protocol.md  Protocol specification
│   │   ├── tests/vectors/    Protocol test vectors and the scripts that re-derive them
│   │   └── fuzz/             libFuzzer targets of the protocol alone
│   ├── airchat-core/     Storage, contacts, groups, routing, the node. No FFI, no platform code.
│   ├── airchat-ffi/      UniFFI interface exported to Kotlin (later Swift)
│   ├── uniffi-bindgen/   Binding generator used by the build
│   ├── fuzz/             libFuzzer targets (a workspace of its own)
│   └── deny.toml         What dependencies may be (cargo-deny)
├── docs/           Requirements, architecture, threat model
└── .github/        CI (GitHub Actions)
```

iOS and Linux apps will get their own top-level directories and reuse `rust/` unchanged.

`rust/airchat-protocol` is also published on its own as `kasimtmc/airchat-protocol` (MIT or
Apache-2.0, its specification CC BY 4.0), so that other apps can speak the protocol. That
repository is a copy with a history of its own, not a submodule: a change to the protocol is made
here and carried there in the same form.

## 3. Rust core

### 3.1 Why a shared core

The protocol must behave identically on Android, iOS and Linux (`P-2`). Writing it once removes a whole
class of interoperability and security bugs. Rust adds memory safety, and key material can be reliably
wiped from memory (`zeroize`), which the JVM cannot guarantee.

### 3.2 Crypto primitives

We write the protocol; we never write primitives (`S-5`). All primitive calls go through one internal
module (`airchat_protocol::crypto`, re-exported as `airchat_core::crypto`) so the provider can be
swapped without touching protocol code.

| Purpose | Algorithm | Implementation |
|---|---|---|
| Key encapsulation | X-Wing (ML-KEM-768 + X25519), draft-connolly-cfrg-xwing-kem-06 | `libcrux-kem` |
| Signatures | Ed25519 | `libcrux-ed25519` |
| AEAD (sessions, counter nonces) | ChaCha20-Poly1305 | `libcrux-chacha20poly1305` |
| AEAD (storage, random nonces) | XChaCha20-Poly1305 | `libcrux-chacha20poly1305` |
| Hash / MAC / KDF | SHA-256, HMAC-SHA-256, HKDF-SHA-256 | `libcrux-sha2`, `libcrux-hmac`, `libcrux-hkdf` |
| PIN stretching | Argon2id | RustCrypto `argon2` |
| Randomness | OS generator | `getrandom` |
| Secret hygiene | — | `zeroize` |
| Certificate signatures of key attestation (ECDSA P-256/P-384, RSA PKCS#1 v1.5), verification only | — | `ring` |

libcrux is formally verified (HACL\*, hax) and its ML-KEM is used in production by Signal. Every
primitive is tested against published known-answer vectors, which were first re-checked against
OpenSSL; X-Wing is additionally cross-checked against RustCrypto's independent `x-wing` crate.

### 3.3 Assurance

Every format and handshake has published test vectors (`rust/airchat-protocol/tests/vectors/`), checked
by the code and re-derived from `rust/airchat-protocol/docs/protocol.md` by independent Python scripts. Every parser of
bytes from outside the device is a fuzz target in `airchat_protocol::fuzz` or `airchat_core::fuzz` (`S-11`): it must not panic on
any input, and a value it accepts must encode back to the same bytes. Four targets drive a whole
node: the frames of a connection someone opened, and records from a stranger on the mesh, a member
of a walkie-talkie channel and a contact, sent over links whose handshakes succeeded so they reach
everything behind decryption.
`cargo test` runs all of them over mutations of the test vectors; `rust/fuzz/run.sh` runs one under
libFuzzer, guided by coverage, on the pinned toolchain.

Dependencies are checked by `cargo deny check` against `rust/deny.toml` (RustSec advisories,
licences compatible with GPL-3.0-or-later, crates.io only). GitHub Actions
(`.github/workflows/ci.yml`) runs formatting, clippy, the tests, the vector scripts, cargo-deny and
the Android build and lint on every push to master and every pull request. What AirChat protects
against, and what not, is in [threat-model.md](threat-model.md).

### 3.4 FFI

UniFFI generates Kotlin (and later Swift) bindings from the `airchat-ffi` crate. The FFI surface is kept
small and coarse-grained: the platform hands in received frames and user actions, the core hands back
frames to send, events and decrypted content for display.

## 4. Storage and keys

The core owns the encrypted store, so the "never plaintext on disk" rule (`S-2`) is enforced in one
place for every platform (`rust/airchat-core/src/storage/`).

- **Database:** SQLCipher (via `rusqlite`, OpenSSL built from source). The whole file is encrypted,
  including the SQLite header and the write-ahead log, so not even the number of contacts or messages
  is visible. Temporary data stays in memory, freed memory is wiped (`cipher_memory_security`) and
  deleted rows are overwritten (`secure_delete`). A test asserts that no plaintext, key or SQLite
  header appears in any file.
- **Files** (media, documents): each file is its own file in `files/`, named by its message's row
  id and encrypted in 15 KiB chunks with XChaCha20-Poly1305 under the file key; each chunk is bound
  to its file and position (`storage/files.rs`, protocol §8.4). Name, type, size, hash and
  thumbnail live in the database. Chunks are written in order; progress is recorded in the database
  only after an `fsync`, so after a crash the recorded size never claims more than is on disk, and
  a torn tail is cut off before the next chunk. Files still being imported when the app died are
  deleted at the next open.

### 4.1 Key hierarchy

```
PIN ──Argon2id──HKDF──► PIN KEK ──┐
                                  ├──unwraps──► master key ──HKDF──► database key, file key, …
unlock secret ──HKDF──► secret KEK┘
(biometric-protected)
```

- The **master key** is 32 random bytes and never touches disk in plaintext. Changing the PIN
  re-wraps it; stored data is never re-encrypted.
- **PIN record** (102 bytes): format version, kind, Argon2id parameters, 16-byte salt, then the
  master key sealed with XChaCha20-Poly1305 under the PIN KEK. The header is the AEAD's associated
  data, so parameters and salt cannot be downgraded or swapped.
- **Secret record** (74 bytes): the master key sealed under a key derived from a random 32-byte
  unlock secret.
- PIN rules (in the core, identical on every platform): at least 6 characters; longer passphrases
  are allowed. Default Argon2id cost: 64 MiB, 3 passes.

### 4.2 Android

- The PIN record is wrapped once more with an AES-256-GCM key in the Android Keystore (StrongBox when
  available, otherwise the TEE), so unlocking needs both the PIN and this device's secure hardware.
  The files live in `noBackupFilesDir`.
- We deliberately do **not** use `setUnlockedDeviceRequired`: Android deletes such keys when the user
  removes the phone's screen lock, which would make the account permanently unopenable (verified on
  API 34). It also cannot be created on phones without a screen lock.
- Biometric unlock: the unlock secret is encrypted with a second Keystore key that requires a strong
  biometric for every use and is invalidated when new biometrics are enrolled or the screen lock is
  removed. AirChat then turns biometric unlock off; the PIN keeps working.
- App lock: the app locks after 60 s in the background (see §4.3 for what locking keeps). The timer
  does not run while the CPU sleeps, so the elapsed time is checked again when the screen turns on
  and when the app returns. After 5 wrong PINs, each further attempt waits 30 s, doubling up to 1 h.
  "Forgot PIN" deletes the account and its keys and starts over.
- Known limit: an attacker who controls an *unlocked, rooted* device can use the Keystore key and
  then guess the PIN offline against Argon2id. A 6-digit PIN does not survive that; a passphrase
  does. The onboarding screen offers a passphrase for this reason.
- PIN fields expose only a mask (`••••••`, flagged as a password) to accessibility services and
  nothing to autofill services. Compose's secure text field would otherwise report the real typed
  text to any app holding the accessibility permission. Focus, typing and the IME action still work
  for TalkBack.

### 4.3 While locked

Locking does not stop AirChat from receiving messages, but it does take the stored data out of reach.
The core's node has two modes (`rust/airchat-core/src/node/`):

| | Open (unlocked) | Sealed (locked) |
|---|---|---|
| Master key, database, identity signing key | in memory | **wiped / closed** |
| Static KEM key, contacts' and fellow group members' link keys and presence keys | in memory | in memory (links need them) |
| Messages not yet delivered | in the database | in memory (to send them when the contact appears) |
| Incoming messages | written to the database | encrypted to the **inbox key**, appended to a file |
| Incoming file offers | written to the database | in the inbox, like messages |
| Group updates, messages, leaves | taken in and passed on | in the inbox as received (still sealed under the group's keys); taken in and passed on after unlocking |
| File content (sending, fetching, viewing) | allowed | **paused**: needs the file key |
| Pairing, reading or writing messages | allowed | refused |
| A contact's link keys after a link (protocol §6.8) | replaced and stored | kept as they are |
| Static keys (protocol §6.9) | a new one weekly; contacts' new ones taken | neither: contacts tell again later |

- **Inbox:** an X-Wing key pair whose private half lives only in the database. Each incoming message
  (and each status change of an outgoing one) gets its own encapsulation, is sealed with
  ChaCha20-Poly1305 and appended durably (`fsync`) before it is acknowledged. A memory dump of the
  locked app therefore reveals neither the history nor messages received earlier while locked.
- **Unlock:** the PIN (or biometric) opens the account; the inbox is applied to the database and
  deleted. Applying an event twice changes nothing, so a crash midway is harmless. Links stay up
  across locking and unlocking.
- **Limits:** while locked, memory holds the keys that keep links alive (someone extracting them
  could impersonate the user to a contact until the two have linked twice without them after the
  next unlock, protocol §6.8) and the plaintext of undelivered outgoing messages. If Android kills the process while locked, nothing is received until the next
  unlock, because the link keys are only in the encrypted database; what had already arrived in the
  inbox is applied at that unlock.
- **Files** need the file key, so transfers pause while either side is locked: a locked sender
  answers chunk requests with *not now* and the receiver asks again later; a locked receiver asks
  for nothing. Both go on after the unlock. Offers of files finished before locking wait for the
  unlock too.
- **Setting:** "Receive messages while locked" (default on). Off, locking closes the account and the
  network completely, as before.

**Android.** The account and the network belong to `AirChatRuntime`, which lives as long as the
process, not to a screen. After the first unlock a foreground service (`AirChatService`, type
`connectedDevice`) keeps the process alive with a minimal ongoing notification, so links survive
leaving the app and locking it. The service stops when the account is closed (setting off, or
"Forgot PIN"); after a process death it does not restart, since nothing can run until the next unlock.

Notifications never name a contact or show content, on the lock screen or anywhere else (S-9). A
message notification says only "New message" or "N new messages" and opens AirChat, which asks for
the PIN if locked. It is posted for arrivals while locked, while in the background, or for a
conversation other than the one on screen, and cleared on unlock or return to the app. On Android
13+ the notification permission is asked once, after the first unlock.

What is copied in the app (selected text, text fields) goes through `ui/SensitiveClipboard.kt`,
which wraps Compose's `LocalClipboard` for the whole app (S-9): each clip is marked
`android.content.extra.IS_SENSITIVE`, so the system preview shows dots and keyboards do not offer
it, and carries a per-process label. After 60 s, or when AirChat locks, the clip is cleared if it
still has that label. Android lets only the focused app read the clipboard, so a clip whose time ran
out in the background is cleared when AirChat next gets focus.

### 4.4 Contacts

Each contact's row keeps the pairing secret (for the mesh and paths) and the contact's link keys,
newest first (protocol §6.8): every link replaces them in the database before it carries anything,
so keys copied from a device stop working after two links without the thief (requirement S-7).
Locked, the database is closed and the keys stay as they were; the contact still holds the key used,
so the next link comes up. Pairing again starts them over from the new pairing secret.

Static keys have versions (protocol §6.9, `node/static_keys.rs`). The owner's are in the
`static_keys` table (the newest also in `identity`); a new one is made a week after the last, while
unlocked, and told to contacts over their links, signed. Each contact's row keeps its newest static
key with its version, its two earlier ones and the newest of the owner's it took; together they
decide which keys a link is tried with. The owner's earlier keys are deleted once no contact may
still use them and no roster held lists them (never within 25 hours of a new one). The admin with
the smallest identity key in a group starts an epoch whenever it holds a newer static key of a
member than the roster lists, so the group stops sealing updates to keys that may have been copied.
Migration 15 gave stored rosters' members version 0 (rosters now carry versions).

Verified builds (requirement S-12, protocol §6.10): the core parses certificates and Android's key
description with a small DER reader of its own (`attest/der.rs`, `attest/cert.rs`; a fuzz target),
checks the chain against Google's root keys and the revocation list compiled in (`attest/roots.rs`,
`attest/revoked.txt`, refreshed by `rust/airchat-protocol/scripts/update-attestation-status.py` before each release), and
keeps each contact's result (`contacts.attested`, `.attested_patch`, migration 23). On Android
(`security/BuildAttestation.kt`) the app makes the attested P-256 key once per account in the
Keystore, gives the chain to the core when the network starts, and signs each link when the core
asks (`AttestationWanted`). Debug builds also trust their own signing certificate, so verified
builds can be tested between them; release builds trust only the official one.

Adding by AirChat ID (requirement C-2, protocol §4.8, `node/requests.rs`): the IDs the user typed
are in `sent_requests`, and the device announces a request token for each while unlocked; requests
from others are in `contact_requests` with the user's answer (pending, approved, declined). An
approval while the requester is still connected pairs at once; a later one completes when the two
meet next. The platform answers request beacons for this device's ID on its own connection, like
a pairing it started; the core decides whether to, and answers paths through Air Providers itself
(`node/paths.rs`): the device looks for a path to each ID's owner when one is typed and then every
5 minutes, and the owner pairs over it once it opens. With the debug switch for direct links off, a
device answers requests only over paths, to test them. Both only while the user accepts requests (C-4), which the platform
tells the core (`set_accept_requests`, off until then).

A contact is *active*, *blocked* or *former* (requirements C-5 to C-7):

- **Blocked:** the keys stay (encrypted, like everything), but the contact leaves the in-memory
  directory of keys that recognises beacons and accepts handshakes. Their beacons go unnoticed,
  their connections fail like a stranger's, and nothing is sent to them, so to them this device is
  simply away; they are not told. Pairing again with them fails on this side. Blocking, like
  deleting, gives this device a new presence key (protocol §5.4), handed to the other contacts over
  their links, so the beacons they still recognise no longer tell the blocked one that it is near.
- **Former:** deleted with the conversation kept. The keys are overwritten in the database; files
  still being fetched from them are dropped. Pairing again makes them active, with the same
  conversation. Deleting without keeping the history removes the contact, the messages and the
  files' content.
- **Emergency exit** (C-7, `node/emergency.rs`): blocks the contact, deletes the conversation's
  messages and files (the contact row stays, blocked), and for each group shared with them: removes
  them where this device is an admin (a new epoch), deletes a group of the two for everyone, and
  leaves the others if the user asked. Groups go first, while the contact's keys still seal the
  update that tells them of their removal.
- **Permissions:** messages and calls (on by default; refused messages are answered as such,
  protocol §8.1), instant voice (off by default; for push-to-talk) and automatic file download
  (off). They live with the keys in memory, so they apply while the app is locked too.

### 4.5 Groups

Groups follow protocol §9; the core keeps them in the database (`storage/groups.rs`) and runs them
in the node (`node/groups.rs`).

- **What is stored:** per group, the current and the previous epoch (key and roster), every update
  it accepted (to pass on), and the group's messages with their sealed form (to pass on unchanged).
  Leaving or being removed overwrites the keys; the history stays, until the user deletes the
  conversation. A group an admin deleted for everyone (protocol §9.2) keeps its keys and the
  deletion only, out of sight (`groups.state` 3, migration 20), and goes entirely a day later.
  A group of two whose other member left or ran out ends on the remaining device (`groups.state`
  4, migration 21): keys wiped, history kept.
- **Two updates of one epoch** (protocol §9.2): the node keeps the one with the smaller update id,
  replacing the epoch it holds in place (`replace_group_epoch`; the previous epoch stays), seals
  its own messages of that epoch afresh under the new key (`reseal_group_messages`, which also lets
  them go once more over links they went over already), and, if the update set aside was its own,
  makes its change again in the next epoch (`make_change_again`). Messages of the epoch held that
  do not open wait with those of epochs not held yet.
- **Peers:** members who are not contacts are kept as contact rows in a fourth state, *peer*, with
  the keys from the roster. They never appear in the contact list and are forgotten once no group
  or queued item is shared with them. Pairing with a peer makes them an ordinary contact.
- **Group links:** fellow members recognise each other's beacons and link with the group's link key
  (§9.4), as contacts do. Such links carry group records only; 1:1 messages and calls over them are
  refused. Links to members no longer shared end when the groups change.
- **Passing on:** a per-member outbox in the database. Messages stay queued until the member
  acknowledges them and go once per link; updates and leaves are dequeued once sent; a newer update
  of a group replaces older ones in the queue; anything older than 14 days is dropped. A message
  of an epoch not yet known waits in memory for its update.
- **While locked:** group records go to the inbox as received (still sealed under the group's keys)
  and are taken in and passed on after the unlock (§4.3).
- **Membership:** only an admin (the creator) adds and removes members, each change a new epoch
  (M-4). Temporary members carry an end time: the admin's device removes them when it passes, and
  their own device deletes the group's messages and keys then (M-5, best effort). A member who
  leaves tells the others; the admin starts an epoch without them.
- **Files:** a file message carries the file's description; members fetch the content from any
  linked member that has it (protocol §9.7). At rest a group file is in the file store under its
  message row negated, so it never meets a 1:1 file; it goes with the group's content when a
  temporary membership ends.
- **Voice:** group push-to-talk and group calls go over the links to the members this device is
  linked with, not passed on (protocol §9.6). Each group has its own "accept push-to-talk" setting.
  Group membership is kept in memory with the link keys, so voice works while locked. Android mixes
  the participants of a group call: one jitter buffer and Opus decoder per sender.
- Group calls are relayed through participants (§7, protocol §9.6); push-to-talk is not.
- **M-3** (`node/additions.rs`, protocol §9.2, §9.8): admins make others admins; the last admin
  leaving names one first. A third person joins a conversation of two as a new group of the three
  once the other agrees. Members added "for the call" leave when the admin who added them is no
  longer in the group's call (12 hours at most); the node checks on every tick, so leaving the call
  and the call ending are alike. Proposals and call memberships live in memory: a restart forgets
  them, and the membership then ends at its 12 hours.
  The call screen covers everything during a call, so an admin adds people from a button there,
  with "until this call ends" chosen already.

### 4.6 Walkie-talkie channels

Channels follow protocol §11; the core keeps their keys in the database (`storage/channels.rs`) and
runs the tuned one in the node (`node/channels.rs`).

- **One channel tuned in** at a time, like a radio. Its key stays in memory with the link keys, so
  its beacon goes out, members link and talk plays while AirChat is locked (requirement V-5, under
  the same "receive while locked" setting as messages).
- **Members are not contacts.** Each link to one gets a negative id for as long as it lasts, which
  never meets a contact's row; the link carries channel talk and liveness only. Members show the
  name they chose (the user's display name), sent inside the encrypted handshake.
- **Talk** reuses group push-to-talk (§9.6): to every member linked, one talk at a time, plays at
  once — tuning in is the consent.
- A link to a member stays on the transport it came up on (it is not moved to a faster one), and two
  links to the same device are told apart by the nonce it sends and the larger one dropped.

### 4.7 Muting

A contact, group or channel row has `muted_until` (Unix ms; 0 is not muted, `i64::MAX` until
unmuted), saved with the row and kept in memory with the link keys, so it applies while locked too
(requirement M-9). Only this device knows; nothing is sent to the others.

- **Contact:** no message notification; push-to-talk is answered "not allowed", as without the
  instant voice permission. Calls ring as usual.
- **Group:** no message notification; group push-to-talk does not play; a group call rings
  without sound or vibration.
- **Channel:** talk does not play (answered "not allowed"), but the channel stays tuned in, so its
  members still link and this device can still talk.

### 4.8 Chat list

The main screen has three tabs: chats, walkie-talkie and settings. The chats tab lists contacts and
groups together, the latest first, each with its last message (a file by its name, a group's with
its sender) and how many arrived unread. The core works these out with one query per kind
(`contact_previews`, `group_previews`) and the FFI hands them over as `ChatPreview`. How far the
user has read is the time of the newest message read, per conversation (`contacts.read_at`,
`groups.read_at`, migration 19, which marked everything already there as read). Opening a
conversation, or a message arriving while it is open, moves it up to the newest message. Like
muting, it stays on this device; senders learn nothing of it. Blocked contacts are not listed, and
peers (group members who are not contacts) have no conversation of their own.

### 4.9 The look

- **Theme:** AirChat's own sky blue, light and dark (`ui/theme`), the same on every phone whatever
  its wallpaper (no dynamic colour). Each person and group has an avatar: an initial or a group
  icon on a colour picked from the name, with a dot while they are nearby.
- **Conversations** (`ui/screens/Conversation.kt`, shared by 1:1 and group chats): messages grouped
  by day and by sender, bubbles with a pointed corner on the last of a run, group senders' names in
  their avatar's colour, and a round message field whose button talks while it is empty and sends
  once something is typed.
- **Calls** are dark whatever the theme; welcome, lock and "Add nearby" open with a round icon.
- **Launcher icon:** an adaptive icon, a speech bubble holding three linked devices on sky blue
  turning to teal, with a one-colour version for themed icons (Android 13+).
- **Clipboard (S-9):** `ui/SensitiveClipboard.kt` replaces Compose's `LocalClipboard` so copies,
  text fields' included, are marked sensitive and cleared after a minute. It must stay an
  `AndroidClipboard`: Compose's text fields require one to offer pasting, and crashed on a long
  press when it was not.

## 5. Transports

Each transport implements the same `Link` interface: an ordered, reliable frame stream, plus an optional
unreliable datagram path for real-time audio/video on transports that offer one.

- **Discovery** runs on BLE: low-power advertising with rotating identifiers (`S-8`).

Implemented so far (Android, `app/src/main/java/com/plyg/airchat/net/`):

| Transport | Finds devices with | Connects with | Notes |
|---|---|---|---|
| LAN (`LanTransport`) | DNS-SD (`_airchat._tcp`) | TCP | same Wi-Fi network or hotspot |
| Wi-Fi Aware (`AwareTransport`) | NAN publish/subscribe | NAN data path, TCP over IPv6 link-local | phones with Wi-Fi Aware only |
| Local-only hotspot (`HotspotLink`) | — (agreed over a link, on demand) | TCP to the hotspot's gateway | the joining user confirms a system dialog |
| BLE (`BleTransport`) | advertisements with service data | LE L2CAP CoC, no Bluetooth pairing | screen-off scanning needs the scan filter |

- **LAN on two Wi-Fi networks of one router** (MIUI's dual Wi-Fi joins its 2.4 and 5 GHz networks
  at once): Android announces on both under two host names, each takes the other for a conflicting
  device, and the service is renamed every few seconds without end; a device behind NAT never found
  it. While two Wi-Fi networks share a subnet, `LanTransport` announces and looks on one of them
  only (the default network if it is one; Android 13 and later), under new names when that changes.
- Every transport feeds one `ConnectionHub`; the runtime merges what they see. A contact or a device
  in "Add nearby" seen on several transports is reached over the preferred one (LAN, then BLE), and
  over the next one if that fails.
- **BLE throughput** (`BleLink`). Android tunes LE links only through GATT, so each L2CAP channel
  gets a GATT client on the same link that never discovers services or reads anything: it exchanges
  the ATT MTU (517), after which the stack sends long link-layer packets (data length extension;
  HyperOS leaves it off for L2CAP channels otherwise), asks for the 2M PHY, and asks for a short
  connection interval only while bulk data flows, going back to the normal one after 10 s of quiet.
  Over the air this adds only parameter negotiations, no identifiers. Measured between the Xiaomi
  and the Redmi: 22 KB/s before, about 75 KB/s after.
- **Who opens.** The core decides in `recognize_*` (§5.2 of the protocol): the side the rule names,
  or, once no link came up after a minute of seeing each other, the other one, since the named side
  may not reach it (NAT, one-way client isolation; an emulator behind its NAT is the everyday case).
  The runtime asks every 30 s, so the other side opens within 60 to 90 s. Two links to a contact
  that come up within 10 s from both sides settle on the one with the smaller handshake hash.
- **Moving links.** When the opener (§5.2 of the protocol) sees a linked contact over a transport it
  prefers to the link's, it opens a new link there, which replaces the old one once up. Messages
  are not lost: unacknowledged ones are resent and duplicates dropped. A failed move is retried
  after 1 minute, doubling up to 10 minutes, while the old link keeps working. When a link drops,
  the runtime reconnects at once over whatever still sees the contact.
- Preference: LAN, Wi-Fi Aware, hotspot, BLE. Since 2026-10-09 BLE links carry setup only
  (requirements T-7, protocol §7.3): the platform marks every BLE connection (`markSetupOnly`) and
  the core sends nothing else on links over them, raising `WaitingForWifi` when messages wait and
  refusing calls and push-to-talk with `NeedsWifi`. Wi-Fi Aware peers are found and used
  automatically; a hotspot is set up on demand (`AirChatRuntime.requestFastLink`): from the chat's
  "Switch to Wi-Fi" (shown while the link runs over Bluetooth), on pressing call or push-to-talk
  there (a call then starts by itself once the link is on Wi-Fi, within 2 minutes), on downloading
  a file, and during a video call. The device that asks joins, the other hosts, and the hotspot
  closes once no connection uses it. The joining device leaves it once what it joined for is over:
  its downloads, the call, or 3 minutes without a message either way; the link falls back to
  whatever else reaches the contact.
- Hotspot tests between the Xiaomi (HyperOS, Android 16) and the Redmi (MIUI 14, Android 12):
  - Redmi hosting, Xiaomi joining: works. About 15 s including the user's confirmation; messages
    both ways, acknowledged in about 145 ms; the joining phone used a random client address. The
    host kept its router connection (station and access point at once; its hotspot moved to the
    router's channel). The Xiaomi left its router network while joined (it cannot join a local-only
    network next to its usual one). Both times, about 48 s after joining, the Xiaomi's Wi-Fi
    firmware reported a fatal event and Android dropped the network, with AirChat in front: a vendor
    fault, not something the app does.
  - Xiaomi hosting, Redmi joining: fails. Within seconds the Xiaomi stops its hotspot to run a
    second station for its "multi-internet" feature; its chip cannot run two stations and an access
    point at once.
  - Asking for a Wi-Fi scan before joining made the system dialog find the hotspot at once (3 of 3
    tries); without it the first search always failed.
- Issues these tests uncovered, and what was done:
  - A link whose peer vanished (its Wi-Fi went away) stayed half-open on the other side until TCP
    gave up, minutes later. Fixed by link liveness (protocol §6.7): silent links are pinged, a link
    whose other end stops answering is closed within about 15 s, and a stalled handshake is given
    up, after which the contact is reached another way. Nothing was lost meanwhile: unacknowledged
    messages go out again on the next link. Verified by freezing the app on one phone: the other
    pinged after 30 s of silence and closed the link 15 s later (25 s after the freeze), gave up
    its next handshake 20 s later, and was linked again 14 s after the app resumed.
  - On the Redmi, BLE scanning and advertising stopped while the app was locked in the background,
    around the 25-minute scan restart and the hourly token rotation, and came back only when the
    transport restarted in the foreground. The cause is not confirmed (MIUI background limits are
    suspected); the transport now avoids starting anything in the background: no periodic scan
    restart (a filtered scan is exempt from Android's 30-minute downgrade), advertising data changed
    in place on rotation (`AdvertisingSet`), failed starts retried with backoff, scan and advertising
    refreshed when the app comes to the front, and transports that failed to start retried every
    30 s. Verified: with the Redmi locked in the background across the hourly rotation, each phone
    heard the other's new PSM within 25 s.
  - The hotspot host did not notice the system stopping its hotspot. The Xiaomi stops it about 7 s
    after starting, to run a second station, and Android then calls `onFailed` rather than
    `onStopped`. Both are now handled: the host tells the contact (a decline), and the joining side
    withdraws its request instead of waiting out its 2 minutes. Verified: the Redmi asked at
    03:17:33, the Xiaomi's hotspot was up at :36 and stopped by the system at :40, and the Redmi
    withdrew at :41. Android then shows its own "the app cancelled the request" dialog; a feature
    using this should explain in its own words that fast Wi-Fi was not available.
  - So a device that could not keep the hotspot asks the contact to host instead, unless it asked
    that contact for one itself in the last 5 minutes (no asking back and forth); at first only
    during a call, since 2026-10-13 whatever the move was for (it then stays for the call, else
    while messages or file chunks flow: `FramedConnection.bulkAt`). A hosting device also stops
    Wi-Fi Aware meanwhile (many chips cannot run both), and starts it again once the hotspot is gone.
  - 2026-10-13, the Redmi on LineageOS (Android 16) by now, both phones' LAN transport off: the
    Redmi's "Switch to Wi-Fi" asked at 04:34:07; the Xiaomi could not host (within 1 s, its dual
    Wi-Fi) and asked back; the Redmi's hotspot was up at :11; the Xiaomi joined once the user
    confirmed the system dialog, and a message went over the hotspot, delivered. No Wi-Fi firmware
    fault this time. After 3 quiet minutes the Xiaomi left and the link fell back to BLE.
- Wi-Fi Aware: verified to attach, publish and subscribe on the Xiaomi; not yet tested end to end,
  since the Redmi lacks Wi-Fi Aware.
- LAN is preferred for bandwidth (media and files), not latency: between the test phones a message
  round trip took about 190 ms over Wi-Fi and 60 ms over BLE, probably because of Wi-Fi power
  saving.
- BLE scans run in low-power mode and switch to low-latency while "Add nearby" is open; presence is
  advertised slowly, pairing beacons fast. Android turns a scan that runs for 30 minutes into an
  opportunistic one, so the scan is restarted every 25 minutes.
- Permissions: Android 12+ asks for "nearby devices" (`BLUETOOTH_SCAN` flagged `neverForLocation`,
  `BLUETOOTH_ADVERTISE`, `BLUETOOTH_CONNECT`); Android 10 and 11 need location access for BLE scan
  results. They are asked once after the first unlock and again from "Add nearby" while missing. The
  chat list says when Bluetooth is off or not allowed.
- Debug builds have switches to turn a transport off, to test the others on their own.
- Verified between a Xiaomi (HyperOS, Android 16) and a Redmi (MIUI 14, Android 12): discovery,
  Nearby Pairing and messages over BLE alone, with a round trip of about 60 ms, including to a
  device in forced deep doze. Moving a link from BLE to Wi-Fi took about 0.4 s after the other
  device appeared on the network; falling back to BLE when Wi-Fi went away took 1 to 1.5 s.
- **Fast Wi-Fi without a shared network** (requirements T-5, T-6): Wi-Fi Aware where both devices
  support it, found and used automatically like any transport; otherwise, on demand, a local-only
  hotspot whose name and password travel to the contact over the encrypted link (§8.3 of the protocol).
  The Wi-Fi password is not a security boundary — the AirChat session is.
- **Background:** an Android foreground service (types `connectedDevice`, `microphone`, `camera` as
  needed) keeps links and walkie-talkie alive with the screen off.

## 6. Media

- **Audio:** platform capture with the voice-communication source (hardware echo cancellation and noise
  suppression) → Opus → encrypted datagrams → jitter buffer → playback. Calls are full duplex; PTT and
  walkie-talkie are half duplex with floor control.
- **Video:** platform camera → hardware H.264 encoder → frames in parts, encrypted (protocol §8.6)
  → hardware decoder. Wi-Fi only (`T-3`). In group calls (protocol §9.9, `media/group.rs`) every
  participant passes every video on, as it does audio, so a device sends at most 640 pixels a side
  at 15 frames a second, at most four cameras are on at once, and each participant's picture has a
  decoder of its own (`runtime/Voice.kt`); the slowest link to a participant sets the bitrate.
- Codecs run on the platform (hardware acceleration); packetization and encryption run in the core.
- **Voice messages** (requirement V-3, protocol §8.4): while this device talks to a contact or a
  group, `runtime/Voice.kt` keeps a copy of the Opus packets in memory (up to what a voice message
  may hold). When the talk ends as *not allowed* or *busy* (in a group: when nobody is left to hear
  it), capture goes on into that copy only, the screen says a voice message is being recorded, and
  letting go of the button wraps the packets in Ogg (`audio/OggOpus.kt`, in memory) and sends them
  as an ordinary file, `voice-<time>.ogg`. A voice message plays in its bubble straight from the
  encrypted store through a `MediaDataSource`; the first play of one that came in is recorded
  (`attachments.played_at`, `group_attachments.played_at`, migration 22), and the node's tick
  deletes its content 15 minutes later and marks it gone (`node/voice.rs`). While locked nothing is
  deleted: the file stays encrypted until the next unlocked tick.
- **Voice on Android** (`audio/VoiceEngine.kt`, `runtime/Voice.kt`): the microphone (voice
  communication source, echo canceller and noise suppressor where available) at 16 kHz, Opus on the
  platform codec at 24 kbit/s constant bitrate where supported, 20 ms packets; incoming packets go
  through the core's jitter buffer (60 ms) to the decoder and a voice-call audio track. Calls start
  on the earpiece, push-to-talk on the loudspeaker; a connected headset (wired, USB, Bluetooth,
  hearing aid) always takes over unless the user picks the loudspeaker during a call, and the route
  follows headsets plugged in or out. A push-to-talk turn opens with a short synthesized
  walkie-talkie chirp on both sides; the talker's microphone ignores it. Calls ring with a
  full-screen notification that never names the caller; the call screen shows the name only when
  AirChat is unlocked. Audio buffers are wiped after use; nothing is recorded.
- **Video on Android** (`video/`, `runtime/Voice.kt`): Camera2 draws into the encoder's input
  surface and a local preview; the platform H.264 encoder (constant bitrate where supported, 1280 ×
  720 or the nearest the camera and encoder share, 30 frames a second, a key frame every 2 s and on
  request) hands frames to the core, which splits and encrypts them. The encoder's SPS and PPS are
  put before every key frame that comes without them. Incoming frames go from the core to the
  platform decoder, which draws on a `TextureView`; it starts at a key frame and asks for one when
  it cannot go on. The rotation travels with each frame (from the sensor and how the device is held),
  so the call screen stays portrait and turns the picture. Video runs only while AirChat is
  unlocked (the picture shows who calls) and the call screen is visible; otherwise the camera is
  *paused*. It is sent only while the link runs over Wi-Fi: over BLE the camera is paused and,
  once the call is answered, the caller (only it, so the two do not both open a hotspot) asks to
  move the link to a hotspot, for its own camera or the contact's; it leaves the hotspot after the
  call. Video calls start on the
  loudspeaker unless a headset is connected.
- **Video congestion:** TCP sockets keep a small send buffer (64 KiB) with Nagle off, so what waits
  to be sent waits in the connection's own queue, where the sender sees it. When more than about a
  quarter second of video (at least 64 KiB) waits, frames are skipped and the bitrate drops by 30 %;
  once the queue is down to 16 KiB the encoder is asked for a key frame and sending resumes with it.
  The bitrate rises by 10 % every 2 s after 4 s without skipping. Audio thus never waits behind more
  than a fraction of a second of video. Frames are wiped from memory once handed on; nothing is
  recorded.
- **Files** (Android, `ui/Files.kt`, `ui/screens/FileViewer.kt`): the user picks with the system photo
  picker or document picker, so AirChat needs no storage permission. The picked file is read through
  the content resolver straight into the core's encrypted store; its thumbnail (the system's, or a
  decoded picture or video frame) is made in memory and travels in the offer as a JPEG of at most
  12 KiB. Viewing happens in the app and in memory (S-10): pictures are decoded with `ImageDecoder`
  (no image library, so no disk cache), video and audio play through `MediaPlayer` from a
  `MediaDataSource` that decrypts chunks as they are read, PDFs render page by page from a copy in
  anonymous memory (`memfd`, Android 11+), text is shown as text; other types can only be saved. Saving outside AirChat takes an explicit action and a warning that the copy is not
  encrypted, and goes through the system "Save as" dialog; a failed save deletes the partial copy.
  Plaintext buffers are wiped after use where the code owns them, but the JVM may keep copies until
  they are garbage collected.

## 7. Mesh and Air Provider

- **Mesh** (protocol §10, requirements AP-0; `mesh.rs` for formats and sealing, `node/mesh.rs` for
  the rest). Every device links over Wi-Fi with the AirChat devices it does not know (mesh links,
  opened to presence beacons it does not recognise; at most 16) and treats those and its Wi-Fi links
  to contacts and fellow members as mesh neighbours. Envelopes are held in memory only (10 minutes,
  8 MiB), passed on with a hop limit, and remembered by id until they expire. The tags it recognises
  are rebuilt every hour, for a day back (envelopes live that long), from keys kept in memory with the
  link keys (contacts' pairing secrets, the groups' epoch keys turned into tag keys at load), so
  delivery works while locked: 1:1 messages and group messages then go to the encrypted inbox like
  those from links. A message to a contact with
  no Wi-Fi link goes into the mesh at once and again to each neighbour that comes later, sealed
  afresh from the database while unacknowledged; the acknowledgement comes back the same way unless
  a Wi-Fi link to the sender is up. Once acknowledged, the sender withdraws both envelopes: it floods the
  drop secret committed to in each, and every device that saw the envelope stops holding it.
- **Files through the mesh** (protocol §10.8; `node/mesh_files.rs`). A file to a contact with no
  Wi-Fi link sends its offer as an envelope; a file of at most 1 MiB also sends its content as part
  envelopes, one per storage chunk, encrypted with a key the offer carries. The key is kept in the
  attachment's row on both sides (the database is encrypted) until the file is answered or whole.
  The sender reads and encrypts the parts from its stored file when a neighbour comes and paces them
  out from a queue (32 KiB/s); the recipient feeds them in order into the ordinary download, so a link
  to the sender can bring the rest, and acknowledges once the hash matches. Parts that come before
  their offer, or while locked, wait in memory still encrypted; at unlock the file is put together
  from them, or from what the device holds to pass on. Group files of at most 1 MiB work the same
  way (protocol §10.10), with keys every member derives from the epoch key, so nothing new is sent
  but the parts. A member fetches a file whose message came through the mesh at once, one offered
  over a link when asked (from parts already held, if they came); its download takes parts from the
  mesh and chunks from a linked member alike. The sender's group messages under a day old that some member has not acknowledged go
  again, with their parts, to each mesh neighbour that comes.
- **Group updates through the mesh** (protocol §10.9; `node/mesh_updates.rs`). Every member that
  makes or takes in an update puts the same encrypted copies of it into the mesh (keys from the
  epoch before, kept in memory with the tag keys, so it works while locked), and again for each
  neighbour that comes while the update is queued and less than a day old. Contacts added to the
  group get the copies' key in a 1:1 envelope and take the parts by id. After taking an update in,
  a device delivers the envelopes it holds to pass on whose tags it recognises only now, so a member
  that missed several updates catches up from what one relay holds.
- **Prekeys** (protocol §10.7, requirement S-7; `node/prekeys.rs`, `storage/prekeys.rs`). Contacts
  hand each other one-time X-Wing keys whenever a link that carries data comes up (24 each), and a
  text that goes into an envelope is sealed to one of them, the same one for its resends. The
  recipient deletes the private half as soon as the text is stored (while locked: from memory at
  once, from the database through the encrypted inbox at unlock), so a recorded envelope cannot be
  opened later even with the device. Both sides' prekeys live in the database and in memory, loaded
  at unlock, so envelopes are sealed and opened while locked too.
- **No mailbox** (requirements AP-6, M-8, since 2026-10-13). Every device, Air Providers too, holds
  envelopes it passes on for 10 minutes and remembers their ids as long (its own and withdrawn ones
  until they expire), so a sender's resends get through again. The sender keeps unacknowledged
  messages in its database and sends them whenever it reaches the contact; a node tick gives up
  those tried for a day (`messages.failed`, migration 18), and "Try again" starts a new day
  (`messages.tried_at`). Group messages likewise (`group_messages.failed`, `.tried_at`): given up
  when no member took them in a day, and their outbox entries (all queued messages, others' too)
  go after a day; a group message tried again is sealed afresh with the current epoch.
- **Paths through Air Providers** (protocol §12, requirements AP-1, AP-5, AP-7; `path.rs` for formats,
  `node/paths.rs` for the rest). A provider tells its mesh neighbours which classes (voice, video,
  files) it carries now; the platform sets them from battery, charging and temperature. A device that
  needs a call, push-to-talk, video or a file with a contact no direct Wi-Fi link reaches floods a
  request through the providers that carry the class, tagged so only the contact recognises it; the
  contact's answer comes back along the same way and marks it, and the first answer with a valid
  proof is opened. The path is then a transport like any other: the core gives it a connection id
  of its own (from `PATH_CONNECTION_BASE` up) and runs an ordinary contact link over it. The
  platform hands every action list to `Node::route` (the FFI does it for every call), which turns
  frames for path connections into data records on the first hop's link and holds them back beyond
  the class's window; frames coming back are put together and handled as on any connection. A path
  link never replaces a direct Wi-Fi link, carries video and files only if its class allows them,
  and carries no mesh traffic. Providers relay records between the two neighbours of each path
  without reading them, enforce the window, and close paths whose neighbour went or that went quiet.
- On Android, `runtime/AirProvider` holds the switch (off by default) and turns battery, charging and
  thermal state into the classes it hands the core: all three while charging or above 50 %, voice
  from 20 %, and below 20 % or at `THERMAL_STATUS_SEVERE` it switches itself off and notifies. Links
  over paths show as `TransportKind.RELAY` (ranked after the hotspot, before BLE, so a direct Wi-Fi
  link replaces them); `ConnectionHub` reads their backlog from the core, so video holds back on a
  slow path as on a slow socket. The view model picks the way for a call or a talk: a direct Wi-Fi
  link, a hotspot for a contact nearby over BLE, else a path (video if a provider around carries it,
  voice otherwise); a video call whose path search fails retries as a voice call. A 1:1 call whose
  link goes away (a provider on the way left) looks for a path on each tick while it waits the 20 s
  it gives a link to come back, for video if the camera is on and a provider carries video. Files need no
  asking: the core looks for a files path on its tick for contacts with files waiting.
- Group voice and channels over paths (protocol §9.6, §11.4, §11.5). Paths also lead to fellow
  group members who are not contacts (tagged with a group link key), so a group call's caller
  reaches those out of reach. Group calls are repeated (`media/group.rs`): each participant sends
  a presence (a random origin and its identity) every 5 s and its audio under that origin, and
  passes on what it takes to its other participant links once (a 64-packet window per origin), so
  a call needs a path per participant, not per pair. The platform mixes by member (the `from` of
  each audio action is the origin's member row). When a participant stops being heard without
  leaving, the others look for one path every 10 s to bring it back (the smaller identity looks).
  Two paths of one class found at once settle on the one with the smaller handshake hash on both
  sides. Walkie-talkie members pass a talk taken from one link on to
  their other channel links, so one member acts as a repeater for those around it. Members linked
  this way form a cluster, which elects a head among its members with providers around (smallest
  device nonce, kept alive by a count it raises every 10 s and the others pass on); the head looks
  for members of other clusters through providers every 30 s (tagged with a key every member holds,
  the nonce naming its head so its own cluster stays silent), so separate clusters join into one.
  A direct channel link replaces one over a path.
- **Provider devices** (requirements AP-1, AP-8 to AP-11; planned, 2026-10-19). The provider app
  is a build of this code with the account, contacts and conversations left out, and the node in a
  provider-only mode: mesh links, paths and the backbone between providers (AP-2), nothing else. It
  is found over Wi-Fi Aware (or a shared network, §7.2), never through a Wi-Fi network of its own,
  so it needs a phone with Wi-Fi Aware; others reach it through the mesh. It stores nothing of anyone:
  what it passes on stays in memory as on every device (10 minutes, 8 MiB), and its keys are its
  own, in the Keystore, with no PIN since there is nothing of a user to protect. Plan, each step
  released only past its gate:
  1. Documents (this). Gate: no provider gains anything it can read or change.
  2. The Wi-Fi check (AP-10). Gate: nothing about the network leaves the device; mDNS names stay
     random.
  3. The provider app (AP-8), and the Air Provider switch tied to Wi-Fi Aware (AP-1). Gate: a test
     shows no envelope, message or contact in the provider's storage after it carried traffic, and
     its beacons are those of any phone.
  4. Before release: a Tamarin model of paths (§12), long fuzzing of what reaches a provider, abuse
     limits (AP-3), and the provider app in the audit's scope.
  5. Linux providers once Wi-Fi Aware is common there (AP-11).
- Routing uses rotating pseudonymous addresses derived from secrets shared between the communicating
  contacts, so relays cannot tell who is talking to whom (`AP-4`).
- Hop budget: messages through the mesh, 8 hops; files 6 providers; voice and push-to-talk 4; video 2.

## 8. Status and next steps

Everything in the requirements is built on Android, except where they say otherwise: identity,
pairing (emoji, QR code, AirChat ID), app lock and encrypted storage; BLE discovery with LAN, Wi-Fi
Aware and local-only hotspot links; 1:1 and group chat with files; voice and video calls, also in
groups; push-to-talk and walkie-talkie channels; the mesh and Air Provider paths. (Store-and-forward
through providers was dropped on 2026-10-13: senders keep their messages, M-8.) Next:

- **Assurance before a stable release (S-11):** the threat model, dependency checks, formal models
  of the contact link handshake, pairing, group keys and mesh envelopes
  (`rust/airchat-protocol/formal/`) and hours of fuzzing of every target are done; an independent
  audit remains.
- **Air Provider app** (AP-8 to AP-10): spare phones with Wi-Fi Aware as always-on providers, with
  no registry (§7, provider devices).
- **Wi-Fi Aware end to end:** needs a second phone that has it.
- **Releases:** reproducible builds, a store or other way to distribute beyond GitHub releases.
- **iOS and Linux (P-2):** platform code over the same Rust core.

### Testing

Two emulators (API 34) on one virtual Wi-Fi network reach each other over LAN, BLE (the emulator's
virtual Bluetooth) and a local-only hotspot, which covers functional tests of all three, including
moving a link between them. A third instance joins the same network (`-wifi-client-port` like the
second), enough for groups whose members are not all contacts. Wi-Fi Aware, real throughput and vendor behaviour need physical devices.
