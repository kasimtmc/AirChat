# AirChat — Requirements

Status: **v0.2** (2026-10-15): everything here is implemented on Android unless marked otherwise.
This document records product decisions; change it when a decision changes.

## 1. Vision

AirChat is an open-source communication app that works without the internet. Devices talk to each other
directly over Bluetooth Low Energy (BLE) and Wi-Fi — including device-to-device Wi-Fi,
not only devices that share an access point. There are no servers, accounts or phone numbers.

Everything is end-to-end encrypted in transit and encrypted at rest from the moment it enters the app.
Nobody but the user can read the user's data, during or after transmission.

## 2. Platforms

- **P-1** Android first (minSdk 29).
- **P-2** iOS and Linux (mobile) follow later. All platforms must interoperate, so the protocol is
  specified independently of any platform (see [protocol.md](../rust/airchat-protocol/docs/protocol.md)).
- **P-3** Platform-independent logic (protocol, cryptography, storage encryption, groups, routing) lives in a
  shared Rust core. Platform code is limited to radios, media capture/playback and UI.

## 3. Transports

| Transport | Typical throughput | Used for |
|---|---|---|
| BLE (L2CAP CoC) | ~100–700 kbps | Discovery, presence, pairing, setting up Wi-Fi (T-7) |
| Wi-Fi Aware (NAN) | 20–100+ Mbps | Everything, and the mesh (AP); found and used automatically, on devices that support it |
| Local-only hotspot | 20–100+ Mbps | Everything, on demand, for devices without Wi-Fi Aware |
| Shared network (LAN + mDNS) | high | Everything, between devices on the same network, including a hotspot a user turned on |

- **T-1** We write our own transport layer. No dependency on Google Play Services / Nearby Connections.
- **T-2** Features are transport-agnostic among Wi-Fi-class transports (T-7). The app picks the best
  available one and moves links automatically (e.g. discover over BLE, then link over Wi-Fi Aware).
- **T-7** *(2026-10-09)* BLE is for finding devices, adding contacts and channels, and setting up Wi-Fi
  (passing a hotspot's details over the encrypted link) only. Chat, files, push-to-talk,
  walkie-talkie, calls and video go over Wi-Fi-class transports. When something waits to be sent
  and only Bluetooth reaches the contact, it waits encrypted and the app offers to set up a hotspot;
  a call or push-to-talk asked for over Bluetooth sets it up first. Reasons: BLE is too slow for
  the mesh (AP), which runs on Wi-Fi.
- **T-3** Video calls run only over Wi-Fi-class transports.
- **T-4** Air Provider relaying runs only over Wi-Fi-class transports (no BLE).
- **T-5** No transport may broadcast a name or a stable identifier (`S-8`), even at the cost of reach.
  Rejected for this reason (2026-10-08): **Bluetooth Classic** — every connection reveals the phone's
  public Bluetooth address, and learning it needs the phone to be made discoverable — and **Wi-Fi
  Direct** — a group owner answers nearby probes with the phone's device name and P2P address and
  lists its clients' names, which apps cannot change.
- **T-6** Devices without Wi-Fi Aware still get fast device-to-device Wi-Fi: on demand, one device opens
  a local-only hotspot (random name and password, chosen by the system) and passes it to the contact
  over the encrypted link. Android asks the joining user to confirm once per connection.

## 4. Features

### 4.1 Identity, contacts and access list

- **C-1** Each user has a key pair generated on the device. The **AirChat ID** is derived from the public
  key (e.g. `AIR-TNNC6-66DK2-YNK2T-JT2N9-Z2PVH`: 120 bits plus a typo-catching check symbol, so it
  cannot be forged by key grinding).
  Hardware addresses (MAC) are not used: Android hides them and they are not bound to keys.
- **C-2** Ways to add a contact:
  - **QR code** — A shows a QR containing the full public key and a one-time, short-lived invite token.
    One scan by B adds both sides.
  - **Nearby Pairing** — both users open "Add nearby", one picks the other, and both screens show the
    same five emoji (a 30-bit short authentication string). Both confirm → added. No camera or typing
    needed.
  - **AirChat ID entry** — B types A's ID; a request is sent when the devices first meet (directly or via
    an Air Provider). The key must match the ID, and A must approve. *(2026-10-12)* Directly (protocol
    §4.8); A's device proves it owns the ID before B's shows who B is, and shows A's card
    only once A approved. *(2026-10-13)* Also through Air Providers: B's device looks for a path to
    A's every few minutes (protocol §4.8, §12.2).
- **C-3** Contact relationships are mutual. A one-sided add is a pending request.
- **C-4** Non-contacts cannot message or call the user. They can only send add requests, which the user
  can turn off.
- **C-5** Per-contact permissions: messages and calls (default on), instant voice / PTT (default off,
  because PTT audio plays without the receiver accepting), automatic file download (default off).
- **C-6** **Delete** removes the contact and its keys; the user chooses whether to delete the chat
  history too. A deleted contact may send a new request later.
- **C-7** **Block** keeps the contact's key (encrypted) on a block list. Their connections are rejected
  during the handshake, nothing is sent to them and they cannot send requests. They are not notified and
  simply see the user as offline. *(2026-10-14)* **Emergency exit** does in one step everything the
  user's own device can do to cut a contact off, whatever app the contact runs: block them, delete the
  conversation here, remove them from the groups the user administers (deleting a group of the two),
  and, if the user agrees, leave the other groups shared with them. It says plainly that what was
  already sent stays with the contact. A modified client cannot be told apart reliably, and nothing
  can delete or lock what is on the contact's device, so neither is attempted.

### 4.2 Conversations

- **M-1** Tapping a contact opens a 1:1 chat.
- **M-2** Users can create group chats. Groups have admins. *(2026-10-13)* An admin can delete a
  group for everyone: every member is out of it, and its messages and files are deleted from each
  member's device as soon as the deletion reaches it (best effort, as M-5). Someone who left or
  was removed can delete the group's conversation from their own device. A group of two ends when
  the other member leaves or their time runs out.
- **M-3** A participant can be added to an existing chat as **permanent** or **temporary** (one-time,
  limited by time or by session, e.g. "until this call ends"). In a 1:1 chat, adding a participant
  requires the other member's approval. *(2026-10-12)* A third person in a conversation of two
  makes a new group of the three, the two its admins; what the two said before stays out of the
  newcomer's reach. "Until this call ends" means until the admin who added them leaves the call.
- **M-4** Every membership change (join, leave, expiry) re-keys the conversation: a joiner cannot read
  earlier messages and a leaver cannot read later ones.
- **M-5** When a temporary membership ends, the app deletes that conversation's content from the
  participant's device. This is best effort: a modified client could keep what it already saw.
- **M-6** Content types: text, images, video, audio, documents, and voice messages (V-3).
- **M-7** File transfers are chunked and resumable.
- **M-8** *(2026-10-13: dropped)* Store-and-forward delivery through Air Providers. Instead the
  sender keeps what it sent until it reaches the recipient (directly, through the mesh or over a
  path) and shows it as being sent; after 24 hours without reaching it, the message shows as not
  delivered and is no longer sent, until the user tries it again (long press, "Try again"). Group
  messages too, when no member took them within 24 hours; members who still lack one after a day are
  no longer sent it.
- **M-9** Contacts, group chats and walkie-talkie channels can be muted for an hour, 8 hours, a week
  or until unmuted. A muted chat gives no notifications and its push-to-talk does not play; calls
  still come through (silently for a muted group). A muted channel stays tuned in.

### 4.3 Voice and video

- **V-1** 1:1 and group voice calls (full duplex) on every Wi-Fi-class transport. *(2026-10-09)* Not
  over BLE any more (T-7).
- **V-2** Video calls on Wi-Fi-class transports only. *(2026-10-13)* Group calls too, with up to
  four cameras on at once (protocol §9.9).
- **V-3** **PTT (push-to-talk):** hold to talk to a specific contact or group. Half duplex with floor
  control. Audio plays immediately on the receiver, so it requires the per-contact PTT permission.
  *(2026-10-14)* A talk the other side does not take live (push-to-talk not allowed, muted, or in a
  call) goes on as a **voice message**, sent when the button is let go; in a group, when no member
  took it live. A voice message arrives without asking and is deleted from the receiving device
  15 minutes after it was first played; the sender keeps its own copy.
- **V-4** **Walkie-talkie:** channels that everyone holding the channel key can hear. The channel key is
  shared by QR code or derived from a channel password.
- **V-5** Walkie-talkie listening continues while the app is locked. User setting, **default on**.
  Session keys stay in RAM only, never on disk.

### 4.4 Air Provider mode

- **AP-0** *(2026-10-09)* AirChat devices form a mesh that extends range for 1:1 and group
  conversations: every device passes on other devices' encrypted messages and files over Wi-Fi while
  the app runs (also locked), within rate and battery limits, whether or not it knows the sender or
  the recipient. Group membership changes go through it too, so members out of reach learn of new
  members, new keys and their own removal. A file of up to 1 MiB, 1:1 or in a group, goes through
  the mesh whole and, when it comes that way, is fetched whatever the auto-download setting (its
  parts cannot be asked for again); a larger one sends its offer through the mesh and its content
  over a link or a path (AP-7).
- **AP-1** A user can turn on Air Provider mode: one switch, **off by default**. The device then also
  carries other devices' calls, push-to-talk, video and files over Wi-Fi (paths, protocol §12).
  There are no user-chosen levels: what it carries
  at a given moment follows AP-5, and routing knows it (AP-7), so a provider that cannot carry
  something never breaks it, it is simply not chosen for it.
- **AP-2** Providers connect to each other to form a multi-hop backbone.
- **AP-3** **Anyone** can use a provider. Rate limiting protects against abuse.
- **AP-4** Providers only see ciphertext and rotating pseudonymous routing addresses. They cannot read,
  modify or identify the traffic they relay.
- **AP-5** *(2026-10-09)* Battery warning when enabling. The device decides what it carries from its
  state and tells its neighbours: everything while charging or above 50 % battery; calls and
  push-to-talk only between 20 % and 50 %; nothing below 20 % or when hot, and Air Provider mode then
  turns itself off and says so. It also takes no more than its radios and limits allow (protocol
  §12.1). Something it accepted (a call, a file) it carries to the end, even if its state changes
  meanwhile; only turning the mode off cuts it.
- **AP-7** *(2026-10-09)* The app chooses the way, never the user: a direct Wi-Fi link when there is
  one; otherwise the mesh for messages (AP-0); otherwise, for calls, push-to-talk, video and files, a
  path through providers that carry that kind right now, the shortest that answers first. Video goes
  through at most 2 providers, voice 4, files 6. A video call with no path for video falls back to a
  voice call; if the path weakens during a call, video pauses and voice goes on. When a provider on
  the way disappears, the app looks for another path. Group calls and group push-to-talk reach
  members out of reach the same way; in a group call the participants repeat each other's voice,
  so each needs one path, not one per member; walkie-talkie members repeat the channel's talk to
  one another, and groups of members out of each other's reach join through
  providers.
- **AP-6** *(2026-10-13: replaced)* Air Providers keep nothing for recipients out of reach: like
  every device they hold what they pass on for a few minutes only, in memory. The sender keeps its
  messages until they are delivered or given up (M-8).

## 5. Security and privacy

- **S-1** All data is end-to-end encrypted in transit, on every transport and through every relay.
- **S-2** All data is encrypted at rest from the moment it enters the app: database, files, thumbnails,
  caches, drafts. **Plaintext is never written to disk.** Media captured with the in-app camera never
  touches the gallery.
- **S-3** Nobody but the user can access the user's data, during or after transmission.
- **S-4** App lock with an app-specific **PIN** and **biometrics**. A forgotten PIN means the data is
  unrecoverable — there is no server and no backdoor.
- **S-5** We design and implement **our own protocol** and publish its specification. No protocol
  libraries (e.g. libsignal). Cryptographic primitives come from a small, vetted library and are
  **never hand-written**.
- **S-6** Hybrid post-quantum key exchange (X25519 + ML-KEM) from the first version.
- **S-7** Forward secrecy and post-compromise security for sessions and conversations. *(2026-10-12)*
  Every link replaces the keys links are made with, and every device replaces its static key each
  week, so keys copied from a device stop working: for links after two links without the thief, for
  groups and messages through the mesh once the new static key is taken (protocol §6.8, §6.9). The
  identity key never changes; messages through the mesh can still be forged with a copied pairing
  secret until the two pair again.
- **S-8** Metadata minimization: no names or stable identifiers in broadcasts; rotating identifiers that
  only contacts can recognize; length padding.
- **S-9** On-device leaks: backups disabled; screenshots and recent-apps previews blocked
  (`FLAG_SECURE`); notifications without content; keyboard learning disabled in text fields; copied text
  marked sensitive and cleared after a timeout; no content in release logs.
- **S-10** Media and documents open in in-app viewers. Exporting or opening in another app only happens
  on explicit user action, with a warning.
- **S-11** Assurance: published test vectors, fuzzing, and an independent audit before a stable release
  (*not done yet*: the audit; preparing it, the threat model, dependency checks and CI are). The
  [threat model](threat-model.md) says what is protected, from whom, and the known weaknesses.

- **S-12** *(2026-10-14)* **Verified builds:** a contact's chat shows a badge when their AirChat is
  the official build on a phone whose bootloader is locked and whose system is verified, as Android
  key attestation shows it (protocol §6.10). Nothing is shown for anyone else: a phone with an
  unlocked bootloader, a build of one's own, or another platform is not marked as suspicious. The
  revocation list of leaked attestation keys is compiled into each release; the app never goes
  online to fetch it.

### Known limits

These are documented to users rather than promised away:

- A recipient can photograph the screen with another device.
- A rooted or compromised device can read the screen while the app is unlocked.
- Radio activity (that two devices communicate, and when) can be reduced but not hidden. BLE beacons and
  Wi-Fi Aware announcements reveal that an AirChat device is nearby, though not which one.
- A temporary participant using a modified client can keep what they saw during their membership.

## 6. Open source

- **L-1** License: GPL-3.0-or-later.
- **L-2** Before accepting external contributions, set up a contributor agreement so the app can also be
  distributed through the iOS App Store.
