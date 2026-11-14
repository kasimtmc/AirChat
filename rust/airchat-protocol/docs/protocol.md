# AirChat Protocol Specification

Status: **complete, not yet stable** (2026-10-18). Every section is specified, implemented by
the reference implementation in this repository (`src/`) and pinned by test vectors
(`tests/vectors/`) that independent scripts re-derive from this text. It has not been audited, and
formats may still change until version 1.0 of this document; a change updates the spec, the code
and the vectors together.

This document must be complete enough for an independent implementation (e.g. iOS or Linux) to
interoperate with the reference implementation. Every section ships with test vectors in
`tests/vectors/`. Requirement numbers (C-2, S-12, T-5, …) refer to the requirements of the AirChat
app, the protocol's first user, and those of §13 and §14 to AirChat+, its internet sibling; they say why
something is so, never what an implementation must do.

## 1. Goals

1. Confidentiality and integrity of all content against anyone but the intended recipients, including
   relays (`S-1`, `AP-4`).
2. Forward secrecy and post-compromise security (`S-7`).
3. Hybrid post-quantum security for key exchange (`S-6`).
4. Minimal metadata: no stable identifiers on the air; relays cannot tell who talks to whom (`S-8`).
5. Works over links ranging from ~100 kbps BLE to Wi-Fi, with no server and no reliable clock.
6. Versioned from the first byte so it can evolve without breaking deployed clients.

## 2. Layers

| Layer | Responsibility | Section |
|---|---|---|
| Identity | Long-term keys, AirChat ID, pairing, contact verification | 4 |
| Discovery | Beacons that let devices find each other without identifying anyone | 5 |
| Link session | Authenticated hop-by-hop channel between two adjacent devices | 6 |
| Transport | Framing; how each radio or network carries messages | 7 |
| Message | End-to-end encryption to the final recipient(s), independent of hops | 8 |
| Group | Membership, temporary participants, re-keying | 9 |
| Routing | The mesh, and paths through Air Providers, with pseudonymous addresses | 10, 12 |
| Real-time media | Encrypted audio and video records | 8.5, 8.6 |
| Channels | Walkie-talkie channels | 11 |
| Accounts | Accounts at a server, for AirChat+ over the internet | 13 |

A message relayed through providers is protected twice: end-to-end by the message layer and on every
hop by the link session.

## 3. Conventions and primitives

- Cipher suite `AIRCHAT_V1`:
  - KEM: X-Wing as specified in draft-connolly-cfrg-xwing-kem-06 (ML-KEM-768 + X25519).
    Encapsulation key 1216 bytes, ciphertext 1120 bytes, shared secret 32 bytes, private key = 32-byte seed.
  - Signatures: Ed25519 (RFC 8032).
  - AEAD: ChaCha20-Poly1305 (RFC 8439) with counter nonces for sessions; XChaCha20-Poly1305 with
    random 192-bit nonces for local storage.
  - Hash, MAC, KDF: SHA-256, HMAC-SHA-256, HKDF-SHA-256 (RFC 5869).
  - PIN stretching (local only, never on the wire): Argon2id, default 64 MiB, 3 passes, 1 lane.
- Encoding: fixed binary layouts, given byte by byte where each format is defined: fixed-size
  fields, explicit lengths and counts, nothing left to the encoder, so everything signed or hashed
  has exactly one encoding. Decoders reject trailing bytes. (Deterministic CBOR was considered and
  not used; this stays so for version 1.)
- Every frame starts with a protocol version and a frame type.
- `||` is byte concatenation. Integers are big-endian unless stated otherwise.
- **Domain separation.** Every hash, KDF and signature input starts with a label of the form
  `"AirChat v1 <purpose>"` (ASCII, no terminator). No label is a prefix of another. The reference
  list is `src/labels.rs`; each label is also named in the section that uses it.

## 4. Identity

### 4.1 Identity key

Each user has one long-term Ed25519 key pair, generated on the device from 32 bytes of OS randomness
(the RFC 8032 private key "seed"). The private key never leaves the device unencrypted. The 32-byte
public key `IK` is the user's identity; everything else about the user is bound to it by signatures.

### 4.2 AirChat ID

A short, typeable name for `IK`, used to add a contact by typing (requirement C-2).

```
id      = SHA-256("AirChat v1 airchat-id" || IK)[0..15]     -- first 120 bits
symbols = id as 24 five-bit values, most significant bits first
check   = LuhnMod32(symbols)
text    = "AIR-" + groups of 5 over Crockford32(symbols || check), joined by "-"
```

- **Alphabet** (Crockford Base32): `0123456789ABCDEFGHJKMNPQRSTVWXYZ`, value = index.
- **LuhnMod32:** walk the 24 data symbols from the rightmost one, multiplying alternately by 2
  (first) and 1; for each product `p` add `p / 32 + p % 32` to a sum; `check = (32 - sum % 32) % 32`.
  This detects every single-symbol substitution.
- **Parsing** must accept any letter case, ignore `-` and whitespace, accept the text with or without
  the `AIR` prefix (decided by length: 28 symbols with prefix, 25 without), and map `O` → `0`,
  `I` and `L` → `1`. Any other character, a wrong length or a wrong check symbol is rejected.
- **Security.** An ID is not secret. Possessing an ID only lets a device recognise the right key
  when it is presented: `id == SHA-256(...)[0..15]`. Forging a key for a given ID requires about
  2^120 key generations.

Test vectors (seed → `IK` → ID):

| Seed | `IK` | `id` | Text |
|---|---|---|---|
| `000102…1e1f` | `03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8` | `d56ac318cd98bd598b52d0aa9f8adb` | `AIR-TNNC6-66DK2-YNK2T-JT2N9-Z2PVH` |
| `ff` × 32 | `76a1592044a6e4f511265bca73a604d90b0529d1df602be30a19a9257660d1f5` | `806659295c21d5e08231d614cc1d62` | `AIR-G1K5J-AAW47-AY10H-HTRAC-R7B2R` |

### 4.3 Pairing

Pairing turns two devices that know nothing about each other into contacts. They agree on keys over
the radio; the users authenticate the exchange out of band, by scanning a QR code (§4.4) or by
comparing five emoji (§4.5). Reference implementation: `src/pairing/`.

The *initiator* is the device that scanned the QR code or picked the other from the list of nearby
devices, or whose AirChat ID the other's user typed (§4.8). `e` is a fresh X-Wing key pair of the initiator, deleted after message 2. Transcript and key
schedule are those of §6.3 (`MixHash`, `MixKey`, `EncryptAndHash`, `Split`), plus

- `Export(label)`: `HKDF-Expand(HKDF-Extract(salt = ck, ""), info = label, 32)`.

```
-> 1:  0x00 0x21 || mode || [invite id (8) | request token (8)] || e_pk
                                                          mode: 0x01 nearby, 0x02 invite, 0x03 request
<- 2:  0x00 0x22 || ct || c2                              ct = Encaps(e_pk)
-> 3:  0x00 0x23 || c3                                    nearby only
<- 4:  0x00 0x24 || c4                                    nearby only
```

```
init with "AirChat v1 pairing-protocol"
MixHash(message 1 without e_pk); MixHash(e_pk)
invite mode: MixKey(invite_psk)                                          (§4.4)
request mode: MixKey(request_psk)                                        (§4.8)
-- message 2
MixHash(0x00 0x22); MixHash(ct); MixKey(ss)
c2 = EncryptAndHash(nearby: commitment | invite, request: "")            (§4.5)
-- nearby: message 3, message 4
MixHash(0x00 0x23); c3 = EncryptAndHash(nonce_i)
MixHash(0x00 0x24); c4 = EncryptAndHash(nonce_r)
-- both modes
k_i2r || k_r2i = Split(); link_psk = Export("AirChat v1 pairing-link-psk")
```

After `Split`, both sides open a link session (§6.4) with `k_i2r`, `k_r2i` and handshake hash `h`,
and exchange contact cards (§4.6) as its data records. `link_psk` becomes the `psk` of every future
link session between the two (§6.1). Pairing message types (`0x21`–`0x24`) never collide with link
handshake types (`0x01`–`0x03`), so a responder can tell the two apart from the second byte.

**Who reveals what, when.** A card is sent only once the peer is authenticated well enough that the
card cannot reach an impostor:

| Mode | Responder sends its card | Initiator sends its card | Each accepts the other's card |
|---|---|---|---|
| Invite | right after message 2 (only holders of the QR secret can decrypt) | after verifying the responder's card | when it arrives |
| Nearby | when its user confirms the emoji | when its user confirms the emoji | only after its own user confirmed |
| Request | after the initiator proved it owns the ID typed | when its user approves | when it arrives |

A user who says the emoji differ ends the attempt; the device sends a close record (§6.4) if the
channel is open. Any failure ends the attempt; errors do not say which check failed.

### 4.4 QR invites

The device that wants to be added (the responder) shows

```
qr_text      = "AIRCHAT:" || Crockford32(0x00 || 0x01 || IK || invite_secret)       -- 88 characters
invite_id    = HKDF(salt = "", ikm = invite_secret, info = "AirChat v1 pairing-invite-id")[0..8]
invite_psk   = HKDF(salt = "", ikm = invite_secret, info = "AirChat v1 pairing-invite-psk")    -- 32 bytes
```

- `invite_secret` is 16 random bytes. Crockford Base32 (§4.2 alphabet) packs bits most significant
  first and pads the last symbol with zero bits; only characters of QR alphanumeric mode are used.
  Parsers reject other characters, non-zero padding bits and wrong lengths.
- An invite is valid for 10 minutes and for one successful pairing.
- **Finding the device.** While it shows the code, the responder announces a pairing beacon (§5.1)
  whose token is `invite_id[0..4]`; the scanner computes the same from the code and connects to the
  device announcing it. Nobody without the code can tell that beacon from a Nearby Pairing one.
- Message 1 names the invite by `invite_id`; the responder looks it up among the invites it shows.
- Because `invite_psk` enters the key schedule before message 2, only someone who read the QR code
  can decrypt anything the responder sends. The initiator accepts the responder's card only if its
  `IK` equals the one in the QR code.
- Known limit: whoever photographs a QR code before it is used can pair with its owner as
  themselves (never as someone else). Invites are short-lived and single use, and the new contact
  is shown by name.

### 4.5 Nearby Pairing

Both users open "Add nearby"; one picks the other's device from a list (discovery: §5).

```
nonce_r, nonce_i = 32 random bytes each
commitment       = SHA-256("AirChat v1 pairing-commit" || nonce_r)
sas_bits         = SHA-256("AirChat v1 pairing-sas" || h || nonce_i || nonce_r)[0..4]   -- h after message 4
emoji[k]         = SAS_EMOJI[(sas_bits >> (26 - 6k)) & 63],  k = 0..4                  -- 30 bits
```

- The responder commits to `nonce_r` in message 2, before it sees `nonce_i`; the initiator reveals
  `nonce_i` before it sees `nonce_r`. A man in the middle must therefore fix her contribution in each
  half before learning the honest party's, and both screens show the same emoji with probability
  2^-30 per attempt. The initiator rejects message 4 if `nonce_r` does not open the commitment.
- Both devices show the five emoji; each user confirms only if the other screen shows the same.

`SAS_EMOJI`, indexed 0–63 (single code points, all available since Android 10):

```
 0 🐶   1 🐱   2 🦁   3 🐴   4 🦄   5 🐷   6 🐘   7 🐰   8 🐼   9 🐔  10 🐧  11 🐢  12 🐟  13 🐙  14 🦋  15 🌻
16 🌳  17 🌵  18 🍄  19 🌍  20 🌙  21 🌈  22 🔥  23 🍌  24 🍎  25 🍓  26 🌽  27 🍕  28 🎂  29 🍇  30 😀  31 🤖
32 🎩  33 👓  34 🔧  35 🐝  36 👍  37 🌂  38 ⌛  39 ⏰  40 🎁  41 💡  42 📕  43 🔦  44 📎  45 🧲  46 🔒  47 🔑
48 🔨  49 📞  50 🚩  51 🚂  52 🚲  53 🚁  54 🚀  55 🏆  56 ⚽  57 🎸  58 🎺  59 🔔  60 ⚓  61 🎧  62 📁  63 📌
```

### 4.6 Contact cards

Each side sends one card as a link data record:

```
card           = 0x01 || 0x00 || IK || SK.pk || card_signature || presence_key || len(name) (u16) || name || proof
card_signature = Ed25519(IK, "AirChat v1 contact-card" || SK.pk)
proof          = Ed25519(IK, "AirChat v1 pairing-proof" || h)
```

- `SK` is the sender's static X-Wing key (§6.1); `card_signature` binds it to `IK`.
- `proof` shows that the holder of `IK` took part in *this* pairing (`h` is the handshake hash at
  `Split`), so nobody can present someone else's card.
- `presence_key` (32 bytes) lets contacts recognise the sender's discovery beacons (§5).
- `name` is UTF-8, trimmed, 1–64 characters (at most 256 bytes), none of them control characters.
- The receiver verifies both signatures, validates `SK.pk` (FIPS 203 check), and rejects its own
  `IK`, trailing bytes and unknown versions.

### 4.7 Test vectors

`tests/vectors/pairing_nearby.json` and `pairing_invite.json` contain complete runs:
inputs (identity seeds, static keys, presence keys, names, random seeds), the X-Wing shared secret,
all messages, the emoji, both card records and `link_psk`. Random values come from the stream of
§6.6, drawn in protocol order: the initiator draws `e`'s seed (32), then `nonce_i` (32); the
responder draws 64 bytes for `Encaps(e_pk)`, then `nonce_r` (32); the invite secret is the first 16
bytes of its own stream.

`check_pairing.py` in the same directory recomputes the QR payload, transcript, commitment, emoji,
`link_psk` and cards, including both signatures, from this specification alone.

### 4.8 Adding by AirChat ID

A user who types someone's AirChat ID (requirement C-2) asks to be added. Their device, the
*requester*, announces a request beacon (§5.3) for that ID until the two are contacts or the user
withdraws the request; the device whose ID it is answers by connecting and pairing in request mode
(§4.3) as the initiator:

```
request_key   = HKDF(salt = "", ikm = id (15 bytes, §4.2), info = "AirChat v1 id-request-key")
request_token = HMAC-SHA-256(request_key, "AirChat v1 id-request-token" || epoch (u64))[0..8]
request_psk   = HKDF(salt = "", ikm = id, info = "AirChat v1 id-request-psk")
identity      = 0x02 || 0x00 || IK || Ed25519(IK, "AirChat v1 pairing-proof" || h)    -- a data record
```

- `epoch` is that of §5.2. The answering device recognises tokens for its own ID of the epochs
  `e - 1` to `e + 1`, answers the same token at most once a minute, and answers none while locked
  or while its user turned requests off (C-4).
- Message 1 carries the token; the requester looks it up among those of the IDs its user typed
  (epochs `e - 1` to `e + 1`). `request_psk` enters the key schedule like `invite_psk`: only those
  who know the ID get past message 2.
- **Who shows what.** After message 2 the initiator sends only `identity`, which proves it holds
  the `IK` of the ID typed (`id == SHA-256("AirChat v1 airchat-id" || IK)[0..15]`). Only then does
  the requester send its card (§4.6). The initiator's device shows its user the requester's name
  (its own claim) and AirChat ID, and sends its card once the user approves; the requester takes it
  if its `IK` is the one proven. Someone who merely knows the ID and answers the beacon learns
  nothing of the requester; the answering device's card goes only to whom its user approved.
- **Answers.** A user who approves while the two are still connected is paired at once. An approval
  given later, or an approval for a contact already, completes the next time the two meet: the
  answering device then sends its card without asking. A declined requester is turned away unseen
  in later attempts; it is not told. A blocked contact is turned away too.
- **Limits.** Someone who knows a device's AirChat ID can find out whether it is nearby by
  announcing requests for it (the device answers at most once a minute per token); turning requests
  off prevents that. Bystanders who know the ID can tell that someone near them asks for it. The
  name a requester shows is its own claim; its AirChat ID is not.
- **Through Air Providers.** While a mesh neighbour carries voice (§12.1), the requester also
  looks for a path (§12.2) to the owner of each ID typed, as soon as one is typed and then every
  5 minutes, its tags and proofs made with

  ```
  request_path_key = HKDF(salt = "", ikm = id, info = "AirChat v1 id-request-path-key")
  ```

  The owner answers such a request as it answers a beacon: not while locked or with requests off,
  and at most once a minute, counted against its own token of the epoch. Once the path opens, the
  owner pairs over it as the initiator, as above. Whoever knows the ID can answer too; the
  requester takes the first answer whose proof is right, and one who is not the owner cannot send
  `identity`, so learns nothing of the requester. Over such a path the requester takes nothing
  but pairing in request mode. A request its owner declined is still answered (and turned away)
  each time, hence the 5 minutes.

`tests/vectors/pairing_request.json` contains a complete request-mode run;
`check_pairing.py` re-derives the ID's bytes, the token, `request_psk`, the transcript, the
identity record and both cards.

## 5. Discovery

How devices find each other before connecting. Beacons never carry a name, an identity key or any
other stable identifier.

`tests/vectors/discovery.json` lists a presence token, a pairing label, a request
token and the BLE (§7.3) and Wi-Fi Aware (§7.4) beacons; `check_discovery.py` recomputes them from
this specification.

### 5.1 Pairing beacons

While its user has "Add nearby" open, a device announces a **pairing token**: 4 random bytes, new
each time the screen opens. The token identifies the device for this pairing only. Its label is
shown both on the device's own screen and in other devices' lists, so the user picks the device in
front of them:

```
label = SAS_EMOJI[token[0] & 63] || " " || decimal(u16(token[1..3]) mod 10000, 4 digits)      e.g. "🦄 0427"
```

A device accepts Nearby Pairing (§4.5) only while it announces a pairing token, and invite pairing
(§4.4) only for invites it currently shows.

### 5.2 Presence beacons

Every device announces a **presence token** while it is unlocked. Only its contacts, who received its
presence key during pairing (§4.6), can recognise it; to everyone else it is 8 random-looking bytes
that change every hour.

```
presence_token = HMAC-SHA-256(presence_key, "AirChat v1 presence-token" || epoch (u64))[0..8]
epoch          = floor(unix_time_seconds / 3600)                                    -- as in §6.2
```

- A device recognises a contact's token for the epochs `e - 1`, `e`, `e + 1` (clock skew).
- A provider device (§12) has no contacts. It announces a token under a presence key it makes at
  random every time it starts and keeps in memory only: nobody recognises it, so every device that
  sees it opens a mesh link to it (§10.2), and nothing ties it to itself before the restart.
- Eight bytes fit a BLE advertisement (§7.3). The token only decides whether to connect; the link
  handshake (§6) authenticates the device, so a chance match with a stranger costs one failed
  connection attempt and nothing more.
- **Who connects.** When two contacts see each other, only the one whose identity key `IK` is smaller
  (as a big-endian number), the *opener*, opens the link session (§6); the other waits. No second
  handshake starts while one is under way. The opener may be unable to reach the other (one side
  behind NAT, a network that lets connections through one way only): when no link has come up after
  the two have seen each other for 60 s, the other opens it. Seeing each other means at least once
  every 120 s; after a longer gap the 60 s start again.
- **Races.** Two direct links to one contact that come up within 10 s of each other, one opened
  by each side, are a race: both sides keep the one with the smaller handshake hash (compared byte
  by byte) and close the other. A link over a path never wins over a direct one (§12.3).
- **Moving a link.** While a link is up, the opener may open a second one, e.g. because it now sees
  the contact over a transport it prefers; so may the device that asked for a move both sides agreed
  on (§8.3). When the new link completes, it replaces the old one:
  each side sends a close record on the old link and closes it, and frames still arriving on it are
  dropped. Unacknowledged messages are sent again on the new link; receivers ignore duplicates
  (§8.1).
- A contact deleted or blocked holds the presence key it was given: the device then makes a new
  one (§5.4).

### 5.3 Request beacons

A device whose user typed someone's AirChat ID announces, for each such ID, the request token of
§4.8 (8 bytes), new every epoch. Only those who know the ID can tell whom it asks for; the device
that owns the ID answers by connecting (§4.8).

### 5.4 Presence key versions

When its user deletes or blocks a contact, a device makes a new presence key, numbered one higher
than the last, so that the one gone no longer recognises its beacons. It tells its remaining
contacts over their links:

```
0x5e presence key:        version (u32) || presence key (32)
0x5f presence key taken:  version (u32)
```

- When a link with a contact comes up, and right after making a new key, a device sends *presence
  key* unless the contact has taken its newest (the key of pairing counts as the version current
  then). The receiver stores a newer key and answers *presence key taken*; a locked device does
  neither and is told again at the next link.
- A contact that does not hold the newest key cannot see the device; the device still sees the
  contact, whose key did not change, and therefore opens the link itself, whatever the rule of §5.2
  says.
- Rosters (§9.1) carry members' presence keys: an admin starting an epoch lists its own newest and
  the one each contact told it, and the admin that keeps the group's keys (§6.9) starts an epoch
  when a roster lists an older one. Fellow members who are not contacts and hold an older roster
  cannot see the device until then; it opens group links to them itself.
- Known limit: a deleted or blocked contact that shares a group with the device learns the new key
  from the group's next roster, as every member does.

## 6. Link session

A link session is an authenticated, encrypted channel between two adjacent devices whose owners are
contacts. It runs over any transport that delivers messages reliably and in order; the transport
frames each handshake message and record (e.g. with a length prefix) and is otherwise untrusted.
Reference implementation: `src/link/`.

### 6.1 Keys known before a session

Since pairing (§4.3, §4.4) each side knows, for itself and for the contact:

| Name | What |
|---|---|
| `IK` | Ed25519 identity public key (§4.1) |
| `SK` | Static X-Wing key pair; the contact's public `SK` is bound to its `IK` at pairing, and replaced every week by a newer one signed with `IK` (§6.9) |
| `psk` | 32-byte pairing secret shared by the two contacts |
| `lk` | Link keys: one to four, starting as `psk` alone, replaced by every handshake (§6.8) |

The party that opens the connection is the *initiator* (`_i`), the other the *responder* (`_r`).

### 6.2 Recognition tags

The initiator starts every handshake with a 32-byte tag that only the responder can recognise. It
tells the responder which contact is calling without either identity appearing on the air, and lets
the responder discard strangers before doing any public-key operation.

```
tag_key(i → r) = HKDF(salt = "", ikm = lk, info = "AirChat v1 link-tag-key" || IK_i || IK_r)   -- 32 bytes
epoch          = floor(unix_time_seconds / 3600)
nonce          = 16 random bytes, new for every attempt
tag            = nonce || HMAC-SHA-256(tag_key, "AirChat v1 link-tag-mac" || epoch (u64) || nonce)[0..16]
```

- `lk` is the link key the attempt is made with (§6.8). The responder checks the MAC with the tag
  key of each of each contact's link keys for the epochs `e - 1`, `e`, `e + 1` (clock skew),
  comparing in constant time: three MACs per link key, no public-key work for strangers. The tag
  also tells it which link key the initiator used.
- It accepts each nonce **once**, remembering used nonces while their epoch can still verify. An
  unknown or reused tag ends the connection without any reply, so a recorded first message cannot be
  replayed to find out whether the responder is nearby.
- Tags differ for every attempt and direction, so observers cannot link two connections. There is no
  limit on attempts per epoch.

An earlier draft drew a counter from 16 precomputed tags per epoch instead of a nonce. Two attempts
within an hour then collided with probability 1/16 and were refused as a replay, and the seventeenth
attempt in an hour always failed.

### 6.3 Handshake

Three messages. Each starts with a two-byte header: the wire version (`0x00`) and the message number.

```
-> 1:  0x00 0x01 || tag || e_pk || ct1 || c1        ct1 = Encaps(SK_r)          2386 bytes
<- 2:  0x00 0x02 || ct2 || ct3 || c2                ct2 = Encaps(e_pk), ct3 = Encaps(SK_i)
-> 3:  0x00 0x03 || c3
```

`e` is a fresh X-Wing key pair of the initiator, deleted after message 2. Both sides keep a
transcript hash `h` and a chaining key `ck` (as in the Noise framework):

- `init`: `h = SHA-256("AirChat v1 link-contact")`, `ck = h`, no key.
- `MixHash(d)`: `h = SHA-256(h || d)`.
- `MixKey(ikm)`: `ck || k = HKDF-Expand(HKDF-Extract(salt = ck, ikm), info = "", 64)`; the nonce
  counter `n` restarts at 0.
- `EncryptAndHash(p)`: `c = ChaCha20-Poly1305(k, nonce(n), aad = h, p)`; `n += 1`; `MixHash(c)`.
  `nonce(n)` is four zero bytes followed by `n` as a big-endian u64.
- `Split()`: `k_i2r || k_r2i = HKDF-Expand(HKDF-Extract(salt = ck, ""), info = "", 64)`.

Processing, identical on both sides:

```
init
MixHash(IK_i); MixHash(SK_i.pk); MixHash(IK_r); MixHash(SK_r.pk); MixKey(lk)
-- message 1
MixHash(0x00 0x01); MixHash(tag); MixHash(e_pk); MixHash(ct1); MixKey(ss1); c1 = EncryptAndHash("")
-- message 2
MixHash(0x00 0x02); MixHash(ct2); MixKey(ss2); MixHash(ct3); MixKey(ss3); c2 = EncryptAndHash(Pad(0, payload2))
-- message 3
MixHash(0x00 0x03); c3 = EncryptAndHash(Pad(0, payload3))
Split()
```

- The responder reads the tag, looks up the contact (§6.2), then decapsulates `ct1`. If `c1` does not
  decrypt to the empty string, it stops without replying.
- The responder must validate `e_pk` as an X-Wing encapsulation key (FIPS 203 modulus check on the
  ML-KEM part) before encapsulating to it.
- `payload2` and `payload3` (at most 4096 bytes) carry capabilities and transport-upgrade details.
  `Pad` is defined in §6.4.
- The initiator treats the responder as authenticated after decrypting `c2`. The responder treats
  the initiator as authenticated only after decrypting `c3`; it must not act on anything earlier.
- Any failure ends the handshake. Errors do not say which check failed.

### 6.4 Records

After the handshake the initiator sends with `k_i2r` and receives with `k_r2i`; the responder the
opposite. Each direction has its own record counter `n`, starting at 0.

```
Pad(type, payload) = type (u8) || len(payload) (u16) || payload || zeros up to a multiple of 64 bytes
record             = ChaCha20-Poly1305(key, nonce(n), aad = 0x00, Pad(type, payload))
```

- Types: `1` data, `2` close (empty payload; nothing follows). Handshake payloads use type `0`.
- A data payload is at most 16 KiB.
- Before record number `n` is sealed or opened, if `n > 0` and `n` is a multiple of 65536, the
  direction's key is replaced by `HKDF(salt = "", ikm = key, info = "AirChat v1 link-rekey")`.
- The receiver rejects a record whose padding is not all zeros or whose length exceeds the
  plaintext. Any record that fails to decrypt or parse ends the session.

### 6.5 Security properties

- **Mutual authentication without signatures.** Only the holder of `SK_r` can derive `ss1`, which
  every key after message 1 depends on; only the holder of `SK_i` can derive `ss3`. A transcript
  therefore proves nothing to a third party (deniability).
- **Key-compromise impersonation resistance.** Stolen long-term keys of one side (and `psk`) do not
  allow impersonating the *other* side to it.
- **Forward secrecy.** Session keys depend on `ss2`, which needs `e`'s private key, deleted after
  the handshake. Recording a session and later stealing all long-term keys and `psk` reveals nothing.
- **Post-quantum confidentiality.** All key exchange uses X-Wing (§3).
- **Identity hiding.** Identities never appear on the air. Strangers cannot produce a valid tag, so
  a responder never answers them. X-Wing ciphertexts do not reveal the recipient's public key.
- **Post-compromise security.** Someone who copies a device's keys, its link keys included, can
  pass as that device to its contacts only until it has linked twice with each of them without
  the thief taking part (§6.8). What was sealed to its static key (group updates, envelopes) stays
  open to the thief only until the device's next static key is taken (§6.9).
- **Limits.** Someone who replays a contact's discovery beacon (§5) elsewhere can observe that a
  nearby device starts a handshake, i.e. that some device there is that contact's contact. The
  identity key `IK` never changes (the AirChat ID is derived from it).

### 6.6 Test vector

`tests/vectors/link_contact_handshake.json` contains a complete handshake: all
inputs (identity keys, static X-Wing seeds and keys, `psk`, tag epoch and nonce), the shared
secrets `ss1`–`ss3`, all three messages, the handshake hash, the next link key (§6.8) and the first
record in each direction. Its link key is the pairing secret `psk`, as in a first handshake. Random values come from `SHA-256(seed || counter)` blocks (counter: big-endian u64 from
0) with the listed seeds, drawn in protocol order: the initiator draws `e`'s 32-byte seed, then 64
bytes for `Encaps(SK_r)`; the responder draws 64 bytes for `Encaps(e_pk)`, then 64 for
`Encaps(SK_i)`.

`check_link_handshake.py` in the same directory recomputes the tag, transcript, key schedule,
ciphertexts, next link key and records from this specification alone and must report `all checks
passed`.

### 6.7 Liveness

A link can die without either side closing it: a phone's Wi-Fi goes away, and the other phone's
connection stays open, half dead, until TCP gives up minutes later. Each side therefore watches its
links:

- Records that call for an answer: a text message (answered by its ack, §8.1), a ping, a move
  request (§8.3). A device answers a ping (`0x03`, empty) at once with a pong (`0x04`, empty).
- A device that has received nothing on a link for **30 s** sends a ping.
- If a record that calls for an answer goes **15 s** without any record arriving, the link counts as
  lost: the device closes it and reaches the contact another way (§5.2). Unacknowledged messages
  stay and go out on the next link.
- Any record arriving shows the other end is there.
- A link handshake (§6.3) that has not completed after **15 s** is given up, so a contact whose app
  hangs mid-handshake can be tried again.

Answering needs no timer, so a phone whose processor sleeps still answers as soon as the ping wakes
it; only the side that checks needs to be awake.

### 6.8 Link keys

Each side keeps for each contact a list of *link keys*, newest first: at most four, and at first
the pairing secret `psk` alone. Every handshake is made with one of them (`lk` in §6.2 and §6.3)
and replaces them, so that keys someone copied from a device stop working (post-compromise
security). Once both transport keys are split off, both sides derive

```
next = HKDF-Expand(HKDF-Extract(salt = ck, ""), info = "AirChat v1 link-key-next", 32)
```

- The initiator tries its link keys in order, one per connection attempt, starting again from the
  newest once a link is up. The responder recognises the tags of all of them (§6.2).
- When its side of the handshake is done (message 2 read by the initiator, message 3 by the
  responder), each side replaces its list with `next`, the key used, and the keys before that one
  in the list, in their order, cut to four; it stores the list before the link carries anything.
  A device that cannot store it (while locked, its database is closed) keeps its list as it was.
- The key used stays on both lists, whatever else happens: the other side may have failed to store
  its new list, or two links may have come up at once with different keys and each side stored
  their outcomes in another order. So the next link always comes up, at worst after the initiator
  tried the keys before it. Keys older than the one used are of no further use and go.
- Group links (§9.4) are made with the group's link keys, which change with the epoch, not with
  links. Channel and mesh links have no link keys. Envelopes (§10.3) and path requests (§12.2) use
  `psk`, not link keys: an envelope may wait in the mesh for a day.

`next` depends on `ss2`, so whoever did not take part in the handshake cannot derive it, even with
copies of both sides' keys. After someone copies a device's keys, the first link the device has
with a contact without the thief is made with a copied key, the second with that link's `next`;
then neither side holds a key the thief knows. Until then, or while the thief takes part in the
handshakes (actively, between the two), it can pass as the device to the contact. It cannot pass as
the contact to the device: that needs the contact's static key (§6.5).

### 6.9 Static key versions

Each device makes a new static key `SK` every week and numbers its static keys from 0. It tells its
contacts of the newest over their links, signed:

```
0x5c static key:        version (u32) || SK.pk (1216) || signature (64)
                        signature = Ed25519(IK, "AirChat v1 static-key" || version || SK.pk)
0x5d static key taken:  version (u32)
```

- **Telling.** When a link with a contact comes up, and when it makes a new key while linked, a
  device sends *static key* unless the contact has taken its newest.
- **Taking.** The receiver checks the signature with the sender's `IK`. If the version is newer
  than the one it holds of the sender (the key from pairing counts as version 0), it stores the
  key, keeping the sender's two keys before it, and answers *static key taken* with the version,
  also when it held that version already. A locked device does neither (it cannot store); it is
  told again at the next link. Only contact links carry these records: over a group link (§9.4),
  someone who copied a member's keys before the group moved on could hand over a key of its own.
- **Linking.** A contact link's initiator uses the newest static key it holds of the responder as
  `SK_r` and, as its own `SK_i`, the version the responder took last. The responder tries its own
  static keys from that version on, newest first, each with every key it holds of the initiator,
  until message 1 decrypts (§6.3): the initiator may have missed a newer key, or an answer may have
  been lost. Group links use the keys their epoch's roster lists, on both sides (§9.1).
- **Sealing.** Envelopes (§10.3) are sealed to the newest static key of the recipient's the sender
  holds; the recipient tries its own from the version the sender took last. Group updates are
  sealed to the keys the roster lists; a member tries the ones it holds.
- **Keeping.** A device keeps an earlier static key while a contact may still use it (from the
  oldest version any contact took on), while a roster it holds (current or previous epoch) lists
  it, and for at least 25 hours after making a newer one (envelopes may still be on their way). It
  makes no new key while it holds eight. It deletes the others.
- **Groups.** A roster lists each member's static key and its version (§9.1); an admin starting an
  epoch lists the newest key of each member it holds. The admin with the smallest identity key in
  the roster also starts an epoch with the same members whenever it holds a newer key of one of
  them (its own included) than the roster lists. Fellow members who are not contacts learn each
  other's keys from rosters only.

Someone who copied a device's static key can open what is sealed to it only until its contacts
take the next one, at most a week later plus until they link: group updates once the admin that
keeps the group's keys started an epoch with the new key, envelopes once their sender took it. The
identity key does not change: such a thief can sign static keys as the device, but only contact
links carry them, and those need link keys (§6.8). Known limit: a member who is not a contact of
the admin that keeps the group's keys keeps its old key in the group until an admin who is its
contact starts an epoch (adding or removing someone); and if that admin stays away, nobody starts
epochs for new keys.

### 6.10 Build attestation

A device can show its contacts that it runs the official AirChat build on a phone whose bootloader
is locked and whose system is verified (requirement S-12). On Android it uses key attestation: the
phone's secure hardware makes a P-256 key and a certificate chain for it, leading to Google's
attestation roots, whose first certificate carries Android's key description (extension
`1.3.6.1.4.1.11129.2.1.17`, source.android.com/docs/security/features/keystore/attestation). The
key is made with the challenge

```
challenge = SHA-256("AirChat v1 build-attest-challenge" || IK)
```

and signs, for each link, the link's handshake hash `h` (§6.3), so a chain cannot be replayed on
another link or by another identity:

```
proof     = ECDSA-P256-SHA256(attested key, "AirChat v1 build-attest-proof" || h)    -- DER
0x60 build attestation: count (u8, 1–5) || (length (u16, 1–3072) || certificate (DER))* ||
                        proof length (u8, ≥ 1) || proof
```

The attested key's certificate comes first, each certificate is signed by the next, and the root
may be left out. A device sends it on each link with a contact, once its link is up; a device
without an attestation (another platform, no secure hardware, no attestation keys yet) sends
nothing. Links of fellow group members, mesh peers and channel members do not carry it.

The receiver verifies it and keeps the result with the contact; a failed verification clears an
earlier one:

1. Each certificate's signature verifies with the next one's key (ECDSA on P-256 or P-384 with
   SHA-256 or SHA-384, or RSA PKCS#1 v1.5 of 2048 to 8192 bits with SHA-256 to SHA-512); the last
   is one of Google's roots, or is signed by one (by public key: the RSA-4096 key of serial
   `f92009e853b6b045`, and "Key Attestation CA1", P-384, signing since 2026-02-01). Validity dates
   are not checked: phones have no reliable clock here, and Google revokes rather than expires.
2. No certificate's serial number (lowercase hexadecimal, no leading zeros) is on Google's
   revocation list (android.googleapis.com/attestation/status), as compiled into the receiver's
   build.
3. Only the first certificate carries a key description: anyone holding an attested key can sign a
   certificate below it that says anything.
4. In the key description: the attestation and KeyMint security levels are the trusted
   environment (1) or StrongBox (2); the challenge is the sender's, as above; the root of trust
   (tag 704, hardware-enforced) says the bootloader is locked and the boot verified (state 0);
   and the application id (tag 709) names exactly one package, `com.plyg.airchat`, whose signing
   certificates' SHA-256 are all official ones. The application id comes from the system, so it
   only counts on a verified phone.
5. The proof verifies with the first certificate's key, a P-256 key.

Only then does the receiver show the contact's build as verified, with the security patch level
(tag 706) if given. A sign, not a proof: phones whose attestation keys leaked can pass until
Google revokes those keys, and a receiver's revocation list is only as recent as its build
(the AirChat app's threat model).

`tests/vectors/attestation.json` holds chains under a test root: one that
passes, one from an unlocked phone and one of another app, with their proofs. `make_attestation.py`
made it; `check_attestation.py` checks it from this section.

## 7. Transports

### 7.1 Framing on stream transports

On transports that deliver a byte stream (TCP, RFCOMM, L2CAP), every protocol message — pairing
messages, link handshake messages and records — travels as one frame:

```
frame = length (u32, big-endian) || message          1 <= length <= 65536
```

A frame outside these bounds ends the connection. The first frame of a connection decides its
purpose by its message type: `0x21` pairing (§4.3), `0x01` link session (§6.3), `0x11` channel link
(§11.3), `0x31` mesh link (§10.2); anything else ends the connection.

### 7.2 Local network (LAN)

Devices on the same IP network (Wi-Fi access point, hotspot) connect over TCP and find each other
with DNS-SD over multicast DNS:

- Service type `_airchat._tcp`. The instance name is 16 random hexadecimal characters chosen when
  the app starts, never the device or user name.
- TXT record: `v=0` (protocol version).
- While "Add nearby" is open, a second instance with its own random name (new each time) and the
  same port adds `p=`, the pairing token (§5.1) in lowercase hexadecimal. A separate instance avoids
  re-registering one name with a changed TXT record, whose "removed" and "added" announcements
  other devices may receive in either order.
- While tuned to a walkie-talkie channel, a third instance (own random name, same port) adds `c=`,
  the channel token (§11.2) in lowercase hexadecimal.
- For a request (§4.8), another instance (own random name, same port) adds `r=`, the request
  token in lowercase hexadecimal.
- Every connection is answered; the first frame decides what happens (§7.1).

Android needs the `INTERNET` permission for any socket, including local ones; AirChat never
contacts a server.

### 7.3 Bluetooth Low Energy (BLE)

Devices find each other with BLE advertisements and connect over an LE L2CAP connection-oriented
channel (CoC), a byte stream framed as in §7.1.

- **Beacons.** A legacy (31-byte) connectable advertisement carries one beacon as service data under
  the 128-bit UUID `5decc7aa-bcb2-413d-97bc-4e02358f29a6`, and nothing else: no device name, no TX
  power, no other service.

  ```
  service_data = kind (1) || psm (1) || token
    kind 0x01, presence: token = presence token (§5.2), 8 bytes
    kind 0x02, pairing:  token = pairing token (§5.1), 4 bytes
    kind 0x03, channel:  token = channel token (§11.2), 8 bytes
    kind 0x04, request:  token = request token (§4.8), 8 bytes
    psm: the L2CAP PSM the device listens on, from the LE dynamic range 0x80..0xFF
  ```

  With the flags field a presence advertisement is exactly 31 bytes. Receivers ignore service data
  with an unknown kind, another length or a PSM outside the range. A later protocol version uses a
  new UUID.
- Presence, pairing, channel and request beacons are separate advertising sets (as the DNS-SD
  instances of §7.2), so they do not share an address. Advertising uses the platform's random, changing device address.
- **Connections.** The connecting device opens an L2CAP channel to the advertised PSM without
  Bluetooth pairing or bonding; pairing (§4.3) and the link session (§6) protect everything. The
  first frame decides the purpose, as on every stream transport.
- When its presence token changes, a device listens on a new channel (new PSM) and announces both
  beacons again, so the PSM does not link the two epochs' announcements.
- A device ends a connection only after the other side has closed it or a few seconds have passed:
  a Bluetooth socket may drop data still queued when it closes.
- **For setup only** (requirements T-7). Over BLE a device pairs (§4) and opens link sessions (§6,
  §11.3), but a link on BLE carries only liveness (ping and pong, §6.7) and moving the link (§8.3),
  so that the two can set up Wi-Fi. Everything else — messages and their acknowledgements, files,
  calls, push-to-talk, video, group and channel traffic — is sent only over a link on a Wi-Fi
  transport (§7.2, §7.4, §8.3) and waits until there is one; unacknowledged messages go out on it
  as on every new link (§8.1). A link on BLE never replaces one on Wi-Fi to the same contact (or
  channel member); one on Wi-Fi replaces one on BLE. A receiver handles any record it gets, on any
  transport, so older versions keep working.

### 7.4 Wi-Fi Aware (NAN)

Devices that support Wi-Fi Aware find each other and connect without a shared network.

- Service name `airchat-v0`. The radio carries only its hash (the NAN service ID), which reveals that
  an AirChat device is nearby, as the BLE UUID does. Publications are unsolicited, subscriptions
  passive.
- Service-specific information = `kind (1) || token`, the kinds of §7.3 without a PSM: `0x01`
  presence (8 bytes), `0x02` pairing (4 bytes), `0x03` channel (8 bytes), `0x04` request (8 bytes).
  Each is a separate publication; they
  share the device's NAN address, which the platform randomizes and changes (Android: every 30
  minutes). When the presence token changes, the presence publication is updated.
- To connect, the subscriber sends the follow-up message `0x01` to the publication it wants to
  reach, and both sides request a NAN data path. The publisher announces a TCP port in the data path
  setup; the subscriber connects to the publisher's IPv6 link-local address at that port. Frames as
  §7.1.
- The data path uses the passphrase `AirChat v0 data path`. It is not a secret: Android carries the
  port only on a secured data path, and the link session protects everything.
- No device name is sent (requirements T-5). This is why Wi-Fi Direct is not used: a group owner
  answers probes with the phone's device name and P2P address.

## 8. Message layer

### 8.1 Direct 1:1 messages

Between two contacts with a link session (§6) — which is end-to-end, since the session's endpoints
are the two contacts' devices — messages travel as link data records:

```
payload = kind (u8) || body
0x01 text:  message_id (16 random bytes) || sent_at (u64, Unix ms) || text (UTF-8, 1–8192 bytes)
0x02 ack:   message_id (16)
0x03 ping:  (empty); answered at once with a pong (§6.7)
0x04 pong:  (empty)
0x05 refused: message_id (16)
0x10–0x12:  moving the link (§8.3)
0x20–0x23:  files (§8.4)
0x24–0x25:  mesh file offer and mesh update key (§10.8, §10.9)
0x30–0x36:  calls and push-to-talk (§8.5)
0x37–0x39:  group voice (§9.6)
0x3a–0x3c:  video (§8.6)
0x3d:       channel head (§11.5)
0x3e–0x3f:  group call presence and audio (§9.6)
0x40–0x43:  groups (§9.5)
0x44–0x45:  adding to a conversation of two (§9.8)
0x46–0x47:  group video (§9.9)
0x50–0x51:  mesh (§10.4)
0x52–0x58:  paths (§12)
0x59:       mesh withdraw (§10.4)
0x5a–0x5b:  prekeys (§10.7)
0x5c–0x5d:  static key versions (§6.9)
0x5e–0x5f:  presence key versions (§5.4)
0x60:       build attestation (§6.10)
0x61:       delivery key (§14.4)
0x62:       relay invite (§15.1)
```

- The receiver stores a text message or file offer (§8.4), then acknowledges it, also when it is a
  resend of a message it already has (identified by `message_id` per contact; stored once).
- A receiver whose user does not take messages from this contact (requirements C-5) answers
  *refused* instead and stores nothing. The sender marks the message refused and never sends it
  again. A message already acknowledged is not refused later.
- The sender keeps every message it has not seen acknowledged and sends it again on each new link
  with that contact, in the original order. A message's status only moves forward: queued (no
  link), sent (handed to a link), delivered (acknowledged).
- `sent_at` is the sender's clock and only for display; each device orders a conversation by when it
  stored the messages.
- Unknown kinds are ignored, so later versions can add kinds. A malformed message ends the link.

### 8.2 Relayed delivery

Messages to a contact out of reach of a Wi-Fi link travel through other AirChat devices, sealed to
the recipient: §10. Calls, push-to-talk, video and files reach such a contact over a path through Air
Providers: §12.

### 8.3 Moving a link to a hotspot

Two contacts that share no network and cannot both use Wi-Fi Aware (§7.4) can still get a Wi-Fi link,
on demand (requirements T-6). They agree on it over their current link, typically one on BLE, which
carries nothing else (§7.3):

```
0x10 move request:  target (u8)              0x01 local-only hotspot
0x11 hotspot offer: port (u16) || ssid length (u8) || ssid (1–32 bytes)
                    || passphrase length (u8) || passphrase (8–63 printable ASCII characters)
0x12 move declined: target (u8)
```

1. A sends a move request.
2. B opens a local-only hotspot — the system picks a random name and password — listens on a TCP
   port on it and answers with an offer, or declines. A device declines targets it does not know.
3. A joins the hotspot, connects to its gateway (B) at the port and opens a link session there (§6),
   which replaces the old link (§5.2). Frames as §7.1.
4. B closes the hotspot when no connection uses it any more, or when A has not come within a few
   minutes.

The offer travels only inside the link session. The password is not a security boundary — the new
link session is; it keeps strangers off the network. The hotspot sends no device name; the network
name is random and the platform randomizes the radio addresses.

### 8.4 Files

Media and documents travel as a file offer, delivered and acknowledged like a text message (§8.1),
followed by the file's content in chunks that the receiver asks for (requirements M-6, M-7):

```
0x20 file offer:    message_id (16) || sent_at (u64) || size (u64) || sha256 (32)
                    || mime length (u8) || mime (1–127 printable ASCII bytes, containing "/")
                    || name length (u8) || name (UTF-8, 1–255 bytes, no control characters)
                    || thumbnail length (u16) || thumbnail (0 or 1–12288 bytes, JPEG)
0x21 chunk request: message_id (16) || first (u64) || count (u16, 1–32)
0x22 chunk:         message_id (16) || index (u64) || data (1–15360 bytes)
0x23 unavailable:   message_id (16) || reason (u8)        0x01 not now, 0x02 gone
```

- A file is cut into chunks of 15360 bytes, the last one shorter; chunk `i` holds bytes
  `i·15360 .. min((i+1)·15360, size)`. A file of size 0 has no chunks. `size` is at most 2³² bytes.
  `sha256` is SHA-256 of the whole file. The largest offer and the largest chunk each fit in one
  record (§6.4).
- `name` and `mime` are only shown, never used as paths or to pick code to run. The thumbnail is a
  small preview of a picture or video, shown before the file is fetched.
- The receiver fetches a file only when its user asks (automatic download is a per-contact choice,
  off by default, requirements C-5). It asks for chunks in order, up to 16 at a time, and asks for the
  next ones while 8 are still on their way, so the link stays busy. It accepts only the next chunk it
  expects, of exactly the right length; anything else is a duplicate or stale and is ignored. When it
  has `size` bytes it checks `sha256` and discards the file on a mismatch.
- The sender answers a request only for files it offered to that same contact and still has
  complete, with the chunks `first .. first+count` that exist; otherwise with *gone*. A sender that
  cannot read its files right now (its app is locked) answers *not now*; the receiver asks again
  after 30 s.
- Transfers resume: after a link drops, or either app restarts, the receiver asks again from the
  first chunk it does not have durably. Requests sent over an earlier link are not remembered.
- Chunk requests call for an answer (§6.7); the chunks are answers.
- **Voice messages.** A file whose type is `audio/ogg` (Ogg Opus, RFC 7845) and whose size is at
  most 1 MiB is a voice message: a receiver fetches it without asking, whatever its auto-download
  setting, and deletes its content 15 minutes after its user first played it, keeping the message
  as "expired". The sender keeps its own copy. Nothing on the wire marks it otherwise.

`tests/vectors/chat_messages.json` holds every message kind of §8.1 and §8.3 to
§8.6, and the group call records of §9.6 and §9.9, with fixed inputs, including a file of two chunks; `check_chat.py` encodes them again from this
specification.

At rest a file is encrypted in chunks of the same size with XChaCha20-Poly1305 under a file key
derived from the master key (label `AirChat v1 storage file-key`); each chunk is
`nonce (24, random) || ciphertext`, with associated data `"AirChat v1 storage file-chunk" ||
file (i64) || index (u64)`, binding it to its file and position. This is local storage, not part of
the wire protocol.

### 8.5 Calls and push-to-talk

Voice travels in the link session like everything else (requirements V-1, V-3), so it is end-to-end
encrypted and padded, and a call goes on when the link moves to another transport.

```
0x30 call offer:    stream id (16, random) || media (u8, optional; §8.6)
0x36 ringing:       stream id (16)
0x31 call accept:   stream id (16)
0x32 call end:      stream id (16) || reason (u8)
0x33 talk start:    stream id (16, random)
0x34 talk end:      stream id (16) || reason (u8)
0x35 audio:         stream id (16) || sequence (u32) || Opus packet (1–1275 bytes)

reasons: 0x01 hung up, 0x02 declined, 0x03 busy, 0x04 not allowed, 0x05 no answer,
         0x06 lost, 0x07 interrupted; unknown reasons mean hung up
```

- **Calls.** The caller sends an offer. A device that takes calls from the caller (requirements C-5)
  and is not in another call answers *ringing* and rings; otherwise it answers *call end* with *not
  allowed* or *busy*. Accepting sends *call accept*; from then on both send audio. Either side ends
  the call with *call end* (*declined* while it rings, *hung up* otherwise). An unanswered call is
  given up after 45 s (*no answer*). Without a link to the other side a call waits up to 20 s for
  the next one, then ends (*lost*). One call at a time.
- **Push-to-talk.** The talker sends *talk start*, audio, then *talk end*. Audio plays at once on the
  receiver, so only a receiver whose user allows instant voice from the talker (C-5) plays it; any
  other answers *talk end* with *not allowed* (or *busy* during a call). It is half duplex per pair
  of contacts: a device does not start talking while it hears the contact, and if both start at
  once, the talk whose stream id is smaller (byte by byte) goes on and the other device ends its own
  with *interrupted*. A talk heard nothing from for 5 s is over. An incoming call ends talks.
- **Audio.** 20 ms Opus frames, mono, constant bitrate, so packet sizes say nothing about the
  speech; records are padded to 64 bytes besides. Each sender numbers its packets per stream from 0.
  Audio for a stream that is not under way is ignored. None of these records calls for an answer
  (§6.7): a call may ring for long, and a talk flows one way.
- While a call or talk with a contact is under way, a device fetching a file from that contact keeps
  at most two chunks on their way (instead of 16), so audio does not wait behind them.
- Nothing about calls or talks is stored. They work while the app is locked.

### 8.6 Video

A 1:1 call carries video too (requirements V-2), in the link session like its audio:

```
0x30 call offer:    stream id (16) || media (u8, optional)     0x01 video call; absent: voice call
0x3a video state:   stream id (16) || state (u8)               0x00 off, 0x01 on, 0x02 paused
0x3b video:         stream id (16) || frame (u32) || flags (u8) || rotation (u8) || width (u16)
                    || height (u16) || part (u8) || parts (u8, 1–64) || data (1–16320 bytes)
0x3c key frame request: stream id (16)

flags: bit 0 key frame; other bits are sent as zero and ignored
```

- **Video calls.** An offer with media `0x01` rings as a video call; any other media value rings as
  a voice call. In any answered call either side may turn its camera on or off. A device sends
  *video state* when its camera changes, and with the answer (callee) or on receiving it (caller)
  if its camera is on by then; until told otherwise a side takes the other's camera to be off.
  Unknown states mean off. *Paused* means the camera is on but nothing is sent for now: the link is
  too slow (below), or the app cannot use the camera at the moment.
- **Only over Wi-Fi.** Video is sent only while the link runs over a Wi-Fi-class transport — local
  network, Wi-Fi Aware or hotspot (requirements T-3). Over BLE the sender says *paused* and the
  call goes on with audio; once the call is answered, the caller — only the caller, so that the two
  do not both open a hotspot — asks to move the link to a hotspot (§8.3) if its camera is on or the
  contact's is paused.
- **Frames.** H.264, Constrained Baseline profile, as an Annex B byte stream; at most 1920 pixels a
  side (devices send at most 1280 × 720) and 30 frames a second. A key frame is an IDR picture with
  the stream's SPS and PPS before it, so it decodes on its own. *width* and *height* are those of
  the encoded picture; *rotation* is the number of quarter turns clockwise that show it upright.
- **Parts.** A frame travels in 1 to 64 parts of at most 16 320 bytes (so at most about 1 MiB), each
  carrying the frame's number and header. Frames are numbered per call and sender from 0. A sender
  sends a frame's parts one after another, so on the link they arrive in order.
- **Skipping and loss.** A sender may skip frames, say when its link cannot keep up, but only before
  a key frame: once it skipped one, it sends nothing until its next key frame. A receiver that finds
  a part out of place, a frame left unfinished, or a frame number skipped before a frame that is not
  a key frame drops what it has, skips frames until a key frame and sends a *key frame request*,
  repeated every second until a key frame arrives. It may also ask for one at any time (say, for a
  new decoder). A sender answers a request by making its next frame a key frame.
- None of these records calls for an answer (§6.7), and nothing about video is stored. Frame sizes
  follow what the camera sees, and records are only padded to 64 bytes, so someone watching the
  encrypted traffic can tell roughly how much moves in the picture; constant-bitrate encoding
  narrows this. Group calls carry no video yet.

## 9. Groups

A group is a set of up to 32 members who all hold the group's current **epoch key** (requirements
M-2 to M-5). Every membership change starts a new epoch with a fresh random key, handed only to the
members of the new epoch: someone added cannot read what came before, someone removed cannot read
what comes after. Members who are not contacts of each other still link directly (§9.4), and every
member passes group traffic on to the others (§9.5), so a message reaches members its sender never
meets. Nothing about a group leaves its members: relays are members.

### 9.1 Roster

The roster lists the members of an epoch, sorted by identity key, each once:

```
member = identity (32) || static_kem (1216) || key version (u32) || presence_key (32) || role (u8)
         || expires (u64) || name length (u8) || name (UTF-8, 1–64 characters)
roster = group_id (16) || epoch (u64) || name length (u8) || name (UTF-8, 1–64 characters)
         || count (u8, 2–32) || member*
role: 0x00 member, 0x01 admin       expires: Unix seconds, 0 for a permanent member
```

Names have no control characters and at most 255 bytes. A member's name is its display name (§4.6);
one of 256 bytes is cut to 255 on a character boundary.

`identity`, `static_kem` and `presence_key` are the member's own keys (§4, §5.2), the same its
contacts know: a member's fellow members can recognise its beacons and link to it. `key version` is
which of the member's static keys `static_kem` is (§6.9), as the admin knew it; the key from
pairing counts as version 0 until the member said otherwise.

### 9.2 Group update

An admin starts each epoch with an update; epoch 0 is the group's creation.

```
envelope = identity (32) || X-Wing ciphertext (1120) || sealed epoch key (48)
update   = group_id (16) || epoch (u64) || signer (32) || count (u8) || envelope*
           || roster nonce (24) || sealed roster length (u32) || sealed roster || signature (64)

for each member M of the new roster:   ct, ss = Encaps(M.static_kem)
  k_M              = HKDF(salt = "", ikm = ss,
                          info = "AirChat v1 group-envelope" || group_id || epoch || M.identity)
  sealed epoch key = ChaCha20-Poly1305(k_M, nonce(0), aad = group_id || epoch, epoch_key)
roster key    = HKDF(salt = "", ikm = epoch_key, info = "AirChat v1 group-roster" || group_id || epoch)
sealed roster = XChaCha20-Poly1305(roster key, roster nonce, aad = group_id || epoch, roster)
signature     = Ed25519(signer, "AirChat v1 group-update" || every field before the signature)
```

`epoch` is a big-endian u64; envelopes appear in roster order. A device accepts an update when:

- the signature verifies, the device finds its own envelope and opens it, the roster decrypts, and
  the roster's `group_id` and `epoch` match the update's;
- for an unknown group (being added): the signer is one of its contacts and an admin in the roster;
- for a known group: the epoch is newer than the one it holds and the signer is an admin in the
  roster it holds (or the epoch is the one it holds: see below). An update it cannot verify yet
  (the signer became an admin in an epoch it missed) waits until the missing updates arrive.

An update without the device's envelope, signed by an admin of the roster it holds and newer than
it, tells it that it was removed: it drops the group's keys. A device keeps the group's updates to
pass them on (§9.5).

**Two updates of one epoch.** Two admins who change a group out of each other's reach both start
the next epoch. Of two valid updates of the same epoch, the one with the smaller update id (§9.5,
compared as bytes) is the group's, at every member:

- A device that holds the other takes it when it comes, if its signer is an admin in the roster of
  the device's previous epoch (else it waits, as above). It replaces the epoch's key and roster (the
  previous epoch stays), passes the update on like any other, also to those only the other update
  had, and seals its own messages of that epoch afresh under the new key, with the same message
  ids, queuing them for the members again. If the update leaves it out, it was removed.
- An update of the epoch held with a larger id changes nothing.
- The admin whose update was set aside makes its change again on the roster that stands, in the
  next epoch: members it added are added, members it removed are removed, roles and the name it
  changed are changed, as far as that is still possible. A removal is so never lost; until it is
  made again, the member removed may hold the key of the epoch that stood.

**Admins and members** (requirement M-3). An admin makes another member an admin, or no longer one,
with a new epoch; a roster always has an admin. A member who leaves sends *group leave* (`0x43`)
to the members, and the admins remove it; the last admin first starts an epoch in which the member
with the smallest identity key is an admin too, so someone can. Temporary members carry `expires`
(§9.1); the admin that added one ends its membership then. A member added "for the call" is
temporary for at most 12 hours, and the admin that added it removes it as soon as that admin is no
longer in the group's call (§9.6).

**Deleting a group** (requirement M-2). An admin deletes a group for everyone with a group message
whose content is *deleted* (`0x03`, §9.3), sealed under the current epoch and passed on like any
other (§9.5, §10.3). A member takes it in only when its sender is an admin both in the roster of
the message's epoch and in the newest roster the member holds; it then passes it on, deletes the
group's messages and files, and keeps the group out of sight, with its keys and the deletion only,
for a day (as long as messages are passed on), after which everything about the group goes.
Updates of a deleted group are ignored, so it does not come back. A device that left or was
removed holds no keys and does not take the deletion in; its user deletes the conversation there.
A group of two has no member to remove (§9.1): an admin ends it by deleting it, and when its other
member leaves (or its temporary membership runs out) it ends on the remaining device, without an
update: the keys go and the history stays, as when leaving.

### 9.3 Messages

```
0x41 group message: group_id (16) || epoch (u64) || message_id (16) || sender (32) || nonce (24)
                    || ciphertext || signature (64)
  message key = HKDF(salt = "", ikm = epoch_key, info = "AirChat v1 group-message" || group_id || epoch)
  ciphertext  = XChaCha20-Poly1305(message key, nonce, aad = group_id || epoch || message_id || sender,
                                   sent_at (u64, Unix ms) || content)
  signature   = Ed25519(sender, "AirChat v1 group-message" || every field before the signature)

content = 0x01 || text (UTF-8, 1–8192 bytes)
        | 0x02 || size (u64) || sha256 (32) || mime || name || thumbnail     a file (§9.7), its
          fields as in a file offer (§8.4)
        | 0x03                                                               the group is deleted
                                                                             (an admin only, §9.2)
        | 0x04 || dk (32)                                                    a group delivery key
                                                                             (AirChat+ only, §16.2)
        | 0x05 || message id (16)                                            received (AirChat+
                                                                             only, §16.3)
        | 0x06                                                               leaving (AirChat+ only,
                                                                             §16.3)
        | 0x07 || relay invite (66, as §15.1's 0x62 after its kind)          a room for a group
                                                                             file (AirChat+ only,
                                                                             §16.4)
```

A device without AirChat+ acknowledges a message whose content is `0x04` to `0x07` and ignores it.

A device stores a group message once (by `group_id` and `message_id`) when the sender is a member of
that epoch, the signature verifies and it decrypts. Messages of an epoch the device does not hold
yet wait for its update, and so do messages of the epoch it holds that do not open, which may be
sealed under the other update of that epoch (§9.2); messages of an epoch older than the newest one
it holds are still read if it holds that epoch's key (they may arrive late) and the sender is also
in the newest roster it holds. Someone removed, or gone, may still hold an earlier epoch's key and write as if before it
went, which nothing could tell from a message that was late; so its late messages are lost with it.

`sent_at` is the sender's claim, signed but not proven: a member can date a message as it likes.
Devices show and order messages by when they arrived, and do not present `sent_at` as the time a
message was written.

### 9.4 Group links

Two members of a group who are not contacts link like contacts (§6.3) with each other's keys from
the roster and

```
link_psk = HKDF(salt = "", ikm = epoch_key,
                info = "AirChat v1 group-link" || group_id || epoch || min(IK_a, IK_b) || max(IK_a, IK_b))
```

(identity keys compared byte by byte). A device recognises its fellow members' presence beacons like
its contacts' (§5.2), and accepts handshakes under the `link_psk` of the current and the previous
epoch of every group it shares with the member. The opener tries those keys in turn, one per
attempt, so members link across an update one of them has not seen yet (and the update then goes
over the link). Contacts link with their link keys (§6.8) only, groups shared or not. A link that exists
only because of a group carries group records (§9.5) and liveness (§6.7) only: 1:1 messages and
calls over it are refused (C-4). Sharing a group with someone shows them when this device is nearby,
as a contact would. A removed member still links under the previous epoch's key until the next
update, which is how it learns of its removal; its device then drops the keys and ends the links,
and the others no longer queue anything else for it.

`tests/vectors/group.json` holds a three-member roster, its update, a message, a
file message, an admin's deletion and a link key; `check_group.py` re-derives all of it from this section (X-Wing shared secrets are
listed rather than recomputed).

### 9.5 Passing group traffic on

```
0x40 update part:  update id (16) || index (u16) || count (u16, 1–64) || data (1–15360 bytes)
0x42 group ack:    group_id (16) || message_id (16)
0x43 group leave:  group_id (16)
```

- Updates are larger than a record (32 members make about 80 KiB), so they travel in parts. The
  update id is the first 16 bytes of SHA-256 of the update. A receiver reassembles the parts it gets
  in order and drops incomplete ones when the link ends.
- Flooding: when a device stores a group message (its own included) or accepts an update, it queues
  it for every member of the group except itself and the one it came from; an update also for the
  members it removed. Whenever it is linked to such a member it sends what is queued for them.
  Messages are acknowledged with *group ack* (also duplicates) and sent at most once per link until
  then; updates need no ack (they are idempotent) and are dequeued once sent, and a newer update of
  a group replaces older ones still queued for the same member. Queued messages expire after a day,
  updates and leaves after 14 days. Messages, updates and small files also go through the mesh
  (§10.3, §10.9, §10.10), to members no link reaches.
- **Giving up.** A device's own message that no member acknowledged a day after its try began
  (when it was written) is given up, as a 1:1 message is (§10.5): shown as not delivered, dequeued
  and sent no more. Its user may try it again: sealed afresh with the group's current epoch (same
  message id), it is queued for the members again and its new try begins then. A message some
  member took shows as such; whoever still lacks it a day later is no longer sent it. An
  acknowledgement that comes for a message given up still counts.
- A message of an epoch the device does not hold yet waits, unacknowledged, for its update, as does
  one of the epoch it holds that does not open (§9.2); so does an update signed by someone who is
  not an admin in the roster held. An update of a group the
  device does not know is taken only if it addresses the device and its signer is an admin of the
  new roster and an active contact of the device.
- A member leaves with *group leave*, queued for every member (and not passed on): an admin who
  learns of it starts a new epoch without the member. Until then the
  member could still read new messages; its device drops the group's keys at once.
- A temporary member (`expires` > 0) is removed by an admin's next update after that time; its own
  device deletes the group's messages and keys when the time comes (best effort, M-5).

### 9.6 Group voice

```
0x37 group talk start: stream id (16, random) || group_id (16)
0x38 group call:       stream id (16) || group_id (16)
0x39 group call leave: stream id (16)
0x3e call presence:    stream id (16) || origin (8) || member (32) || count (u32) || camera (u8, optional; §9.9)
0x3f call audio:       stream id (16) || origin (8) || seq (u32) || packet (Opus, 1–1275 bytes)
```

Talk end (0x34) and audio (0x35) are those of §8.5. Group voice goes over the links a device has
to fellow members (contacts or group links, §9.4, directly or over paths through Air Providers,
§12). Push-to-talk is not passed on: a member hears those it is linked with. Calls are: every
participant repeats them, so a participant hears everyone linked to it through others. A device
takes group voice only for a group it is a member of, and only from a member of that group in its
current roster.

- **Reaching members.** With Air Providers around (§12.1), a device that starts a call or a talk
  looks for a path (voice class) to each member it has no link to: the call rings for them as
  their paths come up; a talk goes to those linked now, the others hear the next one. A member
  that joins a call hears the others through those it is linked with and looks for no path. A
  participant that stops hearing participants it heard in the last minute (a repeater left) looks
  for a path to one of them every 10 s: the one with the smallest identity among those whose
  identity is greater than its own (the others look for it), until it hears them again. So the
  call keeps one path per participant, not one per pair.

- **Push-to-talk.** The talker sends *group talk start* to every member it is linked with, then
  audio to each, then *talk end*. A receiver plays it only if its user lets that group's
  push-to-talk play at once (a per-group setting, off by default; C-5 for groups); otherwise it
  answers *talk end* with *not allowed* (*busy* during a call). A talker who hears *not allowed* or
  *busy* stops sending to that member and goes on with the others. One talk per group: a device
  does not start talking in a group while it hears a talk there, and when it holds two talks of one
  group (its own or heard), the one with the smaller stream id goes on and it ends the other with
  *talk end* *interrupted* (to the talker; its own talk, to everyone it went to). A talker told
  *interrupted* ends its talk for everyone. Talks silent for 5 s are over.
- **Calls.** The caller picks a stream id and sends *group call* to every member it is linked with;
  later it sends it to members who link while the call goes on. A member not in a call rings;
  during another call it ignores it. Joining sends *group call* with the same id to every member it
  is linked with. A device in the call that gets *group call* from a device it did not know to be
  in it notes it as linked to it and answers with *group call*, so both know of each other.
- **Presence and audio.** A participant picks a random *origin* when it starts or joins the call.
  It sends *call presence* with its own identity key as `member` to the participants it is linked
  with when it joins, when one of them links, and every 5 s, counting up from 0. To one that just
  linked it also sends the latest presence it holds of every other participant. It sends its audio
  as *call audio* with its origin and its own sequence numbers. A participant that takes a call
  presence or call audio record for the first time passes it on unchanged to every other
  participant it is linked with: presence when its count is larger than any heard for its origin,
  audio when its sequence number is new among the 64 below the largest heard for its origin;
  older ones and its own come back are dropped. A presence whose `member` is not in the group's
  roster is dropped. Receivers play audio of the origins whose presence they hold, each as its
  member's stream, and mix the streams.
- **Leaving and losing.** Leaving sends *group call leave* to the participants linked; they drop
  that member's origin at once, the others when its presence stops. A presence not renewed for
  15 s is gone. The call is over for a device once everyone else who was in it with it has gone;
  one nobody joins within 45 s is given up (*no answer*), and a device stops ringing after 45 s or
  once every participant it knows left. One call at a time, 1:1 or group.
- Known limit: a participant that repeats a call can drop, delay or change what it passes on,
  and could send audio under another participant's origin or presence under another member's
  identity: as in channels (§11.3), members trust each other with their voice in a call. Presence
  is not signed because a device in a call while locked holds no identity key to sign with.

### 9.7 Group files

A file message (content 0x02) describes a file; the content is not in it. A member fetches it with
*chunk request* (§8.4), naming the file by the message's `message_id`, from a member it is linked
with that has the file complete: the sender, or any member who fetched it already. It asks the
sender first if linked. A member that does not have the file complete answers *file unavailable*
(*gone*); the fetcher then asks another linked member, and asks again members it already asked a
minute later or when they link anew (they may have fetched it meanwhile). A device serves a group
file only to members of that group and only when it has it complete; the fetcher checks the whole
file against `sha256` as in §8.4. Over links, files are not passed on unasked: each member fetches
the ones it wants. A file of at most 1 MiB also goes through the mesh with its message (§10.10).
A voice message (§8.4) is fetched without asking, and deleted 15 minutes after it was first
played, as in a conversation of two.

### 9.8 Adding to a conversation of two

Adding a third person to a conversation of two needs the other's agreement (requirement M-3). The
one who proposes it, `a`, linked with the other, `b`, sends over the link:

```
0x44 member proposal:         id (16) || expires (u64) || person (32) || person name (u8-prefixed)
                              || group name (u8-prefixed)
0x45 member proposal answer:  id (16) || agree (u8: 0x00 no, 0x01 yes)
```

- `id` is random; `person` is the identity key of a contact of `a`'s, shown to `b` with its
  AirChat ID and `a`'s name for it; `expires` ends the person's membership (0: permanent). Names
  are 1 to 255 bytes of UTF-8 without control characters.
- `b`'s user answers. On yes, `a` makes a group (§9.2) of the three, `a` and `b` its admins, with
  the group name given; the person's device takes the update like any from a contact (§9.2). On no,
  nothing happens; `a` tells its user. The two-person conversation stays as it was: the group
  starts afresh, so nothing said before reaches the newcomer (M-4).
- Proposals are answered over a link; a device forgets its own unanswered ones, and those it
  received, after 15 minutes.

### 9.9 Group video

A group call carries video too (requirements V-2), the way it carries audio (§9.6):

```
0x3e call presence:          ... || camera (u8, optional)      0x01 on, 0x02 paused; absent: off
0x46 call video:             stream id (16) || origin (8) || frame (u32) || flags (u8) || rotation (u8)
                             || width (u16) || height (u16) || part (u8) || parts (u8, 1–64) || data (1–16320 bytes)
0x47 call key frame request: stream id (16) || origin (8) || nonce (8)
```

- **Camera.** A participant's presence says whether its camera is on, off or paused, as *video
  state* does in a 1:1 call (§8.6; unknown states mean off). When its camera changes, a participant
  sends its presence at once, counted on, so the change goes round with it.
- **Frames** are those of §8.6 (H.264, parts, numbering per sender, skipping only before a key
  frame), each part also carrying the sender's origin. Devices send at most 640 pixels a side and
  15 frames a second in a group call, as every participant passes every video on. A device does
  not turn its camera on while it hears four others with theirs on.
- **Passing on.** A participant takes a part only from an origin whose presence it holds, and only
  once: it remembers which parts of the 16 newest frames of each origin it took, and drops parts of
  older frames. It passes each part it takes on, unchanged, to every other participant it is linked
  with over a link that carries video: a Wi-Fi-class transport or a video path (§12.3). Others hear
  the call without its video.
- **Key frames.** A receiver puts each origin's frames together as in §8.6, and skips its frames
  until a key frame when one went missing, when its decoder starts again, or when the first frame
  it takes from an origin is not a key frame (it joined in the middle). It then sends *call key
  frame request* for that origin, with a random nonce, to every participant it is linked with,
  again every second until a key frame comes. A participant passes on a request whose nonce it has
  not seen in the last minute to its other links; the one whose origin it names makes its next
  frame a key frame, if its camera is on.
- None of these records calls for an answer (§6.7).

## 10. Mesh

AirChat devices pass on each other's encrypted traffic over Wi-Fi, so conversations reach beyond one
radio hop (requirements AP-0). Every device does it while the app runs, locked too, whether or not it
knows the sender or the recipient. What travels is an *envelope*: sealed so that only its recipients
can read it, addressed with a tag only they recognise, and flooded with a hop limit and an expiry.
It carries 1:1 messages with their acknowledgements, group messages, files of up to 1 MiB
(§10.8, §10.10) and group updates (§10.9). Calls, push-to-talk, video and larger files go over
paths through Air Providers instead (§12).

### 10.1 Overview

- A device has *mesh neighbours*: every link on a Wi-Fi transport (LAN §7.2, Wi-Fi Aware §7.4,
  hotspot §8.3) to a contact or a fellow group member, and a *mesh link* (§10.2) to every other
  AirChat device it sees over Wi-Fi. Links on BLE carry no mesh traffic (§7.3); channel links (§11.3)
  carry channel traffic only.
- A device that has something for a contact and no Wi-Fi link to it sends it in an envelope to all
  its mesh neighbours (§10.5). Each device that receives an envelope it has not seen delivers it if
  it is one of its recipients, and passes it on to its other neighbours while hops and time remain
  (§10.4). Recipients pass envelopes on too, so their neighbours cannot tell them from relays.

### 10.2 Mesh links

Two AirChat devices that see each other's presence beacon (§5.2) over LAN or Wi-Fi Aware and do not
recognise it — they are not contacts or fellow group members — open a mesh link. The device whose
presence token is smaller (byte by byte) opens it; the other opens it if no link has come up after
60 s, as in §5.2.

The handshake is the channel handshake (§11.3) with these differences:

```
message numbers   0x31, 0x32, 0x33  (instead of 0x11, 0x12, 0x13)
protocol name     "AirChat v1 link-mesh"
channel id        SHA-256("AirChat v1 mesh-id")[0..16]
psk               SHA-256("AirChat v1 mesh-psk")
tag               32 random bytes; the responder takes any
payload           device nonce (16): random, new every time the app starts
```

Everything in it is public, so the link authenticates nobody: the two ends are strangers, and either
could be anyone. It still gives each link its own keys from fresh X-Wing ephemerals, so others nearby
cannot read or link what passes over it, and envelopes are sealed end to end anyway (§10.3). Like
channel links, a device keeps one mesh link per device nonce: of two links to the same nonce, both
sides keep the one with the smaller handshake hash. A mesh link carries mesh records (§10.4) and
liveness (§6.7) only. When the two become contacts (§4) or fellow members of a group (§9), the
device that opened the mesh link finds the beacon it opened it to among the new contact's tokens
(for that beacon's epoch, ± 1) and closes the link: their own link carries the mesh traffic.

### 10.3 Envelopes

```
envelope = id (16) || hops (u8) || expires (u32) || tag (16) || drop (16) || body (1–15872 bytes)

  id       names the envelope across the mesh (below)
  hops     how many more times it may be passed on; at most 8
  expires  Unix time in minutes after which nobody passes it on; at most 24 hours ahead
  tag      who it is for: only the recipients recognise it
  drop     lets its sender withdraw it once delivered (§10.4); 16 zero bytes if it cannot be
  body     sealed for the recipients
```

**Tags** change every hour (`epoch` as in §5.2). For a contact `b` of `a`, and for a group:

```
tag_key(a → b)   = HKDF(salt = "", ikm = psk, info = "AirChat v1 mesh-tag-key" || IK_a || IK_b)
tag_key(group)   = HKDF(salt = "", ikm = epoch_key,
                        info = "AirChat v1 mesh-group-tag-key" || group_id || group epoch (u64))
tag              = HMAC-SHA-256(tag_key, "AirChat v1 mesh-tag" || epoch (u64))[0..16]
```

A device recognises the tags of the epochs `e - 25` to `e + 1` from each contact to itself and for
each group epoch it holds: an envelope lives up to 24 hours, and may arrive late in its life, its
tag being of the hour it was sealed in.

**Drop** of a 1:1 envelope from `a` to `b` (group envelopes carry 16 zero bytes):

```
drop_secret = HKDF(salt = "", ikm = psk, info = "AirChat v1 mesh-drop-secret" || IK_a || IK_b || id)[0..16]
drop        = SHA-256("AirChat v1 mesh-drop" || drop_secret)[0..16]
```

**1:1 bodies** are sealed to one of the recipient's one-time prekeys (§10.7), or else to its static
X-Wing key `SK_b` (§6.1; the newest the sender holds, §6.9), and to the pairing secret:

```
prekey   = the id of b's one-time prekey for a it is sealed to; 0 for SK_b
(ss, ct) = X-Wing.Encaps(that prekey's key, or SK_b)
key      = HKDF(salt = psk, ikm = ss,
                info = "AirChat v1 mesh-seal" || IK_a || IK_b || id || tag || expires (u32) || drop
                       || prekey (u32))
body     = prekey (u32) || ct (1120) || ChaCha20-Poly1305(key, nonce = 12 zero bytes, aad = "", padded)
padded   = len (u16) || payload || zeros up to a multiple of 256 bytes
payload  = a §8.1 message: text (0x01), ack (0x02) or refused (0x05), a mesh file offer
           (0x24, §10.8) or a mesh update key (0x25, §10.9); other kinds are ignored
```

The key binds the id, the tag, the expiry and the drop, so relays cannot change them unnoticed; only
`hops` is theirs to change. Only the two contacts hold `psk` and only `b` can decapsulate, so `b` knows the envelope is
from `a`, and `a` cannot be impersonated by a relay. `psk` is the contacts' pairing secret, never a link key (§6.8).

**Group bodies** are a group message as on a link (§9.3, the `0x41` record without its kind byte),
already encrypted and signed for the group.

**Ids**, so that sending the same thing again gives the same id:

```
1:1:    SHA-256("AirChat v1 mesh-envelope" || IK_a || IK_b || payload kind (u8) || message_id)[0..16]
group:  SHA-256("AirChat v1 mesh-envelope" || group_id || message_id)[0..16]
```

### 10.4 Passing on

```
0x50 envelope:  an envelope (§10.3)
0x51 have:      short ids (8 bytes each, at most 1024): the first 8 bytes of envelope ids
0x59 withdraw:  id (16) || drop_secret (16)
```

- **New neighbour.** On a new mesh neighbour each side sends *have* with the short ids of the
  envelopes it holds, newest first. On receiving *have*, a device sends the envelopes it holds whose
  short id is not in it, newest first.
- **New envelope.** An envelope a device has not seen (by id) and that has not expired is delivered
  if it is one of its recipients, then passed on with `hops - 1` to every mesh neighbour except the
  one it came from, if `hops` > 0, and held to pass on to neighbours that come later. A device
  remembers the ids of envelopes it was passed for 10 minutes, and drops envelopes seen before
  meanwhile; its own, and those withdrawn, until they expire. So a sender's resend gets through
  again once the mesh has let the envelope go.
- **Holding.** A device holds envelopes in memory only, for at most 10 minutes and within 8 MiB,
  dropping the oldest first; Air Providers too (*(2026-10-13)* they no longer keep envelopes for
  recipients out of reach). Nobody but the sender keeps an envelope for a recipient out of reach
  (§10.5).
- **Withdrawing.** A *withdraw* names an envelope and reveals its drop secret. A device that has seen
  that envelope (by id), and whose drop is not zero and matches `SHA-256("AirChat v1 mesh-drop" ||
  drop_secret)[0..16]`, stops holding it, refuses it from then on, and passes the withdraw on to
  its other mesh neighbours once; it ignores withdraws for envelopes it has not seen. A withdraw
  counts 32 bytes against the sending neighbour's passing-on budget.
- **Limits.** A `hops` above 8 counts as 8; an `expires` more than 24 hours ahead counts as 24 hours.
  A device passes on at most 64 KiB per second, averaged over a minute, of what one neighbour sent
  it; beyond that it still delivers what is for it but passes nothing on from that neighbour.
- None of these records calls for an answer (§6.7).

### 10.5 Sending through the mesh

- **1:1.** A message (text, §8.1) to a contact with no Wi-Fi link right now goes out in an envelope
  (hops 8, expiring 24 hours after its try began, below) to every mesh neighbour, and again to every
  neighbour that comes later, while it is unacknowledged and unexpired; each time sealed afresh, with
  the same id (and drop). It still goes over the next link with the contact as usual (§8.1); the
  recipient stores it once. The recipient acknowledges a message that came in an envelope over its
  Wi-Fi link with the sender if there is one, else in an envelope; *refused* likewise.
- **Giving up.** The sender keeps every message (and file offer) it has not had acknowledged, shown
  as being sent, and sends it whenever it reaches the contact: over a link, or into the mesh as
  above. A message not acknowledged 24 hours after its try began (when it was written) is given up:
  shown as not delivered, and sent no more, over links or through the mesh. Its user may try it
  again; the new try begins then, with the same message id. An acknowledgement that comes for a
  message given up still counts.
- **Withdrawing.** Once the sender has the acknowledgement (or *refused*), however it came, it
  withdraws the answer's envelope if it has seen it, and the message's envelope if it has seen it
  or the answer came in an envelope (the message most likely went the same way, perhaps before the
  app last started and forgot what it had seen); from every mesh neighbour, and again from every
  neighbour that comes later until they expire. Recipients never withdraw: that would single them
  out.
- **Groups.** A device that stores a group message (§9.5), its own or another's, also sends it in an
  envelope (hops 8, expiring 24 hours after it was stored, or after its sender tried it again) to
  every mesh neighbour; its own unacknowledged ones again to every neighbour that comes later, until
  given up (§9.5). Members store it once as usual; group acknowledgements stay on links.

### 10.6 What the mesh reveals

- Relays see envelopes' sizes (in steps of 256 bytes), when and from which neighbour they arrive,
  their hop counts and tags, and whether a text is sealed to a prekey (by its id, used once) or to
  the static key. A tag stays the same for an hour per direction of a conversation (or per
  group), so a relay can tell which envelopes of that hour belong together, but not whose they are.
  Flooding means every device in reach sees every envelope.
- Envelopes can be read only with the recipient's key **and** the pairing secret. A text sealed to
  a one-time prekey is forward secret: once the recipient has opened it the prekey is gone, so
  someone who recorded it and later takes the device learns nothing from it. Until then (also
  while the app is locked, until it is next unlocked) and for texts sealed to `SK_b` (no prekey
  left, a contact never met over Wi-Fi since) and for acknowledgements, it is not.
- Envelopes heal only in part after a compromise: someone who copied a device's keys can make
  envelopes its contacts take as from it for as long as the pairing secret stays the same, which
  is until they pair again. Reading them is another matter: envelopes sealed to prekeys handed over
  links since, or to a static key made since (§6.9), are out of the thief's reach.
- A withdraw shows that a conversation's message got through, and, like an envelope, most likely
  comes first from its sender. Only the two contacts can make a drop secret, so nobody else can
  withdraw their envelopes; a relay that changes the drop field breaks the envelope for its
  recipient, which is no more than dropping it.
- Mesh links are not authenticated, so a device may be talking to anyone; it learns nothing but the
  envelopes, as any relay does. Anyone can make envelopes; the limits above bound what one neighbour
  can make others carry.

### 10.7 One-time prekeys

Each device hands each contact one-time X-Wing keys of its own, *prekeys*, for the texts the
contact seals to it in envelopes; it deletes each one's private half as soon as it opened an
envelope with it, which makes those texts forward secret (§10.6).

```
0x5a prekeys:         (prekey (u32, not 0) || encapsulation key (1216))*, 1 to 12 of them
0x5b prekeys wanted:  count (u8, 1 to 24)
```

- **Handing out.** When a link that carries data (§7.3) comes up with a contact (not a group peer),
  each side holding fewer than 24 of the other's unused prekeys asks for the difference with
  *prekeys wanted*. The other answers with that many new prekeys, with random ids, in records of
  at most 12; it hands one contact at most 64 it has not seen used. A device keeps at most 48 of a contact's prekeys, dropping the oldest,
  and forgets those it held 25 days; it deletes its own after 30 days.
- **Sealing.** A text going into an envelope for the first time takes the contact's oldest unused
  prekey; resends of it (§10.5) use the same one. Acknowledgements and *refused* use `SK_b`, as
  does a text when no prekey is left. A sender forgets a prekey once its text is answered.
- **Opening.** A recipient opens an envelope with the private half of the prekey it names, then
  deletes it (while locked: from memory at once, and from storage at the next unlock). It
  acknowledges a resend whose prekey is gone if it remembers having opened that envelope, by id,
  since; otherwise the text waits for a link to the sender.
- None of these records calls for an answer (§6.7).

### 10.8 Files through the mesh

```
0x24 mesh file offer:  id (16) || sent at (u64) || key (32) || file (as in 0x20, §8.4)
```

- **Sending.** A file to a contact no Wi-Fi link reaches goes into the mesh like a text (§10.5):
  its offer in an envelope (a 1:1 body, sealed to a prekey, §10.7), and, for a file of at most
  1 MiB, its content in *part envelopes* encrypted with `key`, a random key the sender makes for the
  file and keeps until the file is answered. A larger file's offer carries 32 zero bytes; its
  content comes over a link (§8.4) or a path (§12). The offer and the parts go to every mesh
  neighbour, and again to every neighbour that comes later while the file is unanswered and
  unexpired, with the same ids and key. The sender lets its parts go at most 32 KiB/s on average,
  in bursts of at most 320 KiB, well within what relays pass on for one neighbour (§10.4).
- **Parts.** Part `i` (from 0) carries the file's bytes `i·15360` up to `(i+1)·15360`:

```
id            = SHA-256("AirChat v1 mesh-file-part" || IK_a || IK_b || message id || i (u32))[0..16]
file_tag_key  = HKDF(salt = "", ikm = psk, info = "AirChat v1 mesh-file-tag-key" || IK_a || IK_b)
tag           = HMAC-SHA-256(file_tag_key, "AirChat v1 mesh-tag" || epoch (u64))[0..16]
drop          = as for 1:1 envelopes (§10.3), of this id
body          = ChaCha20-Poly1305(key, nonce = 8 zero bytes || i (u32), aad = id || expires (u32) || drop,
                                  len (u16) || bytes || zeros up to a multiple of 256 bytes)
```

- **Receiving.** The recipient recognises file tags like 1:1 tags (§10.3). It takes the offer as a
  file offer over a link (§8.4; refused without the messages permission), keeping the key, and
  fetches the file whatever its auto-download setting, as parts cannot be asked for. It holds parts
  it cannot open or place yet in memory (at most 2 MiB, until they expire), and puts the parts into
  the file in order, as chunks (a link to the sender may bring the rest meanwhile). A part it still
  needs is taken even if seen before, as it may have been lost before it was placed. Once the file
  is whole and its SHA-256 matches the offer's, it deletes the key and acknowledges the offer
  (§10.5). An offer whose content does not come through the mesh is acknowledged at once. While
  locked, the offer goes to the inbox with its key, unacknowledged, and parts wait in memory, still
  encrypted, for the unlock. A resend whose prekey is gone is acknowledged again only once the file
  is whole (§10.7).
- **Withdrawing.** Once answered, the sender withdraws the offer's, the answer's and every part's
  envelope (§10.4).
- Relays see that two devices exchange a file and roughly its size (its parts, padded to 256 bytes),
  and the parts' tags, which change every hour and differ from the texts'.

### 10.9 Group updates through the mesh

```
0x25 mesh update key:  group_id (16) || epoch (u64) || update id (16) || count (u16) || key (32)
```

An update (§9.2) also goes into the mesh, so that members out of reach learn of a new epoch, or of
their removal, as messages reach them. For an update of epoch `e`, with `K` the epoch key of epoch
`e - 1` (for the update that creates a group, `e = 0`, its own epoch key):

```
tag_key = HKDF(salt = "", ikm = K, info = "AirChat v1 mesh-update-tag-key" || group_id || e (u64))
base    = HKDF(salt = "", ikm = K, info = "AirChat v1 mesh-update-key" || group_id || e (u64))
key     = HKDF(salt = "", ikm = base, info = "AirChat v1 mesh-update-part-key" || update id)
id      = SHA-256("AirChat v1 mesh-update-part" || group_id || update id || index (u16))[0..16]
tag     = HMAC-SHA-256(tag_key, "AirChat v1 mesh-tag" || epoch (u64, §10.3))[0..16]
drop    = 16 zero bytes
body    = update id (16) || index (u16) || count (u16)
          || ChaCha20-Poly1305(key, nonce = 8 zero bytes || index (u32), aad = id || update id || index || count,
                               len (u16) || bytes || zeros up to a multiple of 256 bytes)
```

Part `index` (from 0) of `count` (1–64) carries the update's bytes from `index · 15360`, as the
update parts of §9.5 do, and the update id is theirs.

- **Sending.** A device that makes an update, or takes one in while holding epoch `e - 1`, sends
  its parts to every mesh neighbour, and again to each neighbour that comes later while the update
  is queued for some member (§9.5) and less than 24 hours old. Every member makes the same
  envelopes, so relays pass each on once. To a contact it queues the update for who was not a
  member of epoch `e - 1` (someone added, who cannot recognise the tag), it also sends *mesh update
  key* in a 1:1 envelope (§10.3, sealed to the static key), as long as it sends the parts. Two
  admins' updates of one epoch have different update ids, so different keys and part ids.
- **Receiving.** For each of its groups, a member recognises the update tags of the epoch after the
  newest it holds (from that epoch's key); after a *mesh update key* from a contact, it also takes
  that update's parts by id, whatever their tag, including parts it saw before and still holds to
  pass on. Once it has every part and their SHA-256 matches the update id, it takes the update in
  as one from a link (§9.2, §9.5; while locked, into the inbox). Taking an update in, it looks again
  at the envelopes it holds to pass on: those whose tags it recognises only now (the next update,
  the new epoch's messages) are delivered.
- Relays see that some group changed and roughly how large its update is (its parts, padded), not
  which group or who is in it.

### 10.10 Group files through the mesh

A group file (content `0x02`, §9.7) of at most 1 MiB also sends its content through the mesh, in
part envelopes every member of the message's epoch can recognise and open. With `K` that epoch's
key and `id_m` the message id:

```
tag_key = HKDF(salt = "", ikm = K, info = "AirChat v1 mesh-group-file-tag-key" || group_id || epoch (u64))
key     = HKDF(salt = "", ikm = K, info = "AirChat v1 mesh-group-file-key" || group_id || epoch (u64) || id_m)
id      = SHA-256("AirChat v1 mesh-group-file-part" || group_id || id_m || index (u32))[0..16]
tag     = HMAC-SHA-256(tag_key, "AirChat v1 mesh-tag" || epoch (u64, §10.3))[0..16]
drop    = 16 zero bytes
body    = ChaCha20-Poly1305(key, nonce = 8 zero bytes || index (u32), aad = id,
                            len (u16) || bytes || zeros up to a multiple of 256 bytes)
```

Part `index` (from 0) carries the file's bytes from `index · 15360`, as a chunk (§8.4).

- **Sending.** The sender puts its file message into the mesh as any group message (§10.3) and the
  parts after it, paced as in §10.8. Its group messages younger than 24 hours that some member has
  not acknowledged (§9.5) go again, with their parts, to each mesh neighbour that comes later.
- **Receiving.** A member recognises the file tags of the epochs it holds and holds parts it cannot
  place yet in memory (at most 2 MiB with those of §10.8; while locked they wait there, still
  encrypted). Taking a file message of at most 1 MiB from the mesh, it fetches the file whatever its
  auto-download setting, as parts cannot be asked for again; one that came over a link is fetched
  when asked (§9.7). Either way, a file being fetched takes the parts into the file in order, as
  chunks, and a member it is linked with that has the file may bring the rest. The file is checked
  against the message's `sha256`; nothing is acknowledged through the mesh.

### 10.11 Test vectors

`tests/vectors/mesh.json` holds tags for a contact and a group, envelope ids, a
1:1 envelope sealed to a prekey with its drop and record, a *have*, a *withdraw*, a *prekeys* and a
*prekeys wanted* record, a mesh file offer and a file part (§10.8), a mesh update key and an update
part (§10.9), a group file part (§10.10) and a mesh link handshake; `check_mesh.py` re-derives all of it from this section
(X-Wing shared secrets are listed rather than recomputed).

## 11. Walkie-talkie channels

A channel is a key: everyone holding it hears the push-to-talk of the members around them
(requirements V-4, V-5), as on a radio channel. Members need not be contacts and do not learn each
other's identities. Knowing the key is all membership is; there is no admin and no member list.

`tests/vectors/channel.json` holds a channel derived from a password, its beacon
token, QR code and a complete link handshake; `check_channel.py` recomputes all of it from this
section (the X-Wing shared secret is listed).

### 11.1 Keys

```
channel_key  = 32 random bytes, shared by QR code
             | Argon2id(password (UTF-8), salt = SHA-256("AirChat v1 channel-password")[0..16],
                        m = 64 MiB, t = 3, p = 1, 32 bytes)               -- the same everywhere
channel_id   = HKDF(salt = "", ikm = channel_key, info = "AirChat v1 channel-id")[0..16]
presence_key = HKDF(salt = "", ikm = channel_key, info = "AirChat v1 channel-presence")
link_psk     = HKDF(salt = "", ikm = channel_key, info = "AirChat v1 channel-link-psk")
qr_text      = "AIRCHAT:" || Crockford32(0x00 || 0x02 || channel_key || name (UTF-8, 1–64 bytes))
```

- A password-derived channel is as secret as its password: anyone who guesses it hears the
  channel. Passwords have at least 8 characters; the fixed salt makes one password one channel
  everywhere, so it also lets an attacker precompute guesses. A QR code channel has a random key.
- The QR code is read as in §4.4 (kind `0x02`); its name is a suggestion each user may change.

### 11.2 Beacons

A device tuned to a channel announces a **channel token** besides its presence token, as a separate
beacon (§7.2–7.4):

```
channel_token = nonce (4 random bytes) || HMAC-SHA-256(presence_key, "AirChat v1 channel-token"
                                                       || epoch (u64) || nonce)[0..4]
```

- A new nonce every epoch (as in §5.2), so tokens of different devices differ and a device's token
  does not link its epochs. Members recognise a token for the epochs `e - 1`, `e`, `e + 1`; with
  four MAC bytes a stranger's token matches by chance once in 2³², which costs one failed handshake.
- **Who connects:** of two members that see each other, the one whose current channel token is
  smaller (byte by byte) opens the link; the other opens it if no link has come up after 60 s, as
  in §5.2. Members link with every member they see.

### 11.3 Links

Three messages, like §6.3 but without identities: both sides prove only that they hold the channel
key; forward secrecy comes from the initiator's ephemeral X-Wing key.

```
-> 1:  0x00 0x11 || tag || e_pk || c1                      1266 bytes
<- 2:  0x00 0x12 || ct || c2                               ct = Encaps(e_pk)
-> 3:  0x00 0x13 || c3

tag_key = HKDF(salt = "", ikm = link_psk, info = "AirChat v1 channel-tag-key" || channel_id)
tag     = as in §6.2, with this key

init: h = SHA-256("AirChat v1 link-channel"), ck = h; MixHash(channel_id); MixKey(link_psk)
-- message 1
MixHash(0x00 0x11); MixHash(tag); MixHash(e_pk); c1 = EncryptAndHash("")
-- message 2
MixHash(0x00 0x12); MixHash(ct); MixKey(ss); c2 = EncryptAndHash(Pad(0, payload2))
-- message 3
MixHash(0x00 0x13); c3 = EncryptAndHash(Pad(0, payload3))
Split()

payload = device_nonce (16) || name length (u8) || name (UTF-8, 0–64 bytes)
```

- The functions are those of §6.3; records are those of §6.4. Tags work as in §6.2 (single-use
  nonces, three epochs), so a recorded message 1 cannot be replayed.
- `device_nonce` is random each time the app starts. Two links between the same two devices (after
  tokens change, or both opened at once) are found by it; both sides close the one whose handshake
  hash is larger. `name` is what the other members see when the device talks; it may be empty.
- Known limits: a member cannot tell members apart beyond their nonce and chosen name, and anyone
  with the key may join or pose under any name. Holding the key is the trust.

### 11.4 Push-to-talk

Over a channel link only *group talk start* (`0x37`, §9.6) naming the `channel_id`, *talk end*,
*audio* (§8.5), *channel head* (§11.5) and ping/pong (§6.7) count; other records are ignored. A
device sends its talk to every member it is linked with. Talks play at once on every member's
device (tuning in is the consent), during no call, and while the app is locked (V-5). One talk per channel at a time: the
smaller stream id goes on, as in §9.6. A talk silent for 5 s is over.

Members are repeaters: a member that takes a talk from one link passes its *group talk start*,
*audio* and *talk end* on unchanged to every other member it is linked with, so a talk reaches
members out of the talker's reach through those in between. A member takes a talk from one link
only (the first to bring it) and ignores the same talk from others, and a talker ignores its own
talk coming back, so nothing goes round twice. A member that does not play a talk (muted, or in a
call) does not pass it on either.

### 11.5 Clusters and Air Providers

Members linked with each other, directly or through repeaters, form a *cluster*. Its *head* is, of
its members with Air Providers around (§12.1), the one with the smallest device nonce (§11.3,
compared byte by byte):

```
0x3d channel head:  device nonce (16) || seq (u32)
```

- A member's own `seq` grows by one every 10 s. Every 10 s, and when it changes, a member sends on
  each of its channel links that carry data the head it knows: of itself (if it has Air Providers
  around) and the nonces its linked members reported whose `seq` grew in the last 30 s, the
  smallest, with the largest `seq` heard for it; it sends nothing while it knows none. A head that
  is gone, or no longer counts itself, stops growing; 30 s later nobody counts it, and the cluster
  has the next.
- The head looks for a member of another cluster every 30 s: a
  path request (§12.2, voice class) whose tag and proof are made with the channel's path key, which
  every member holds, and whose nonce tells members which cluster asks:

```
path_key = HKDF(salt = "", ikm = link_psk, info = "AirChat v1 channel-path-key" || channel_id)
nonce    = r (8 random bytes) || HMAC-SHA-256(path_key, "AirChat v1 channel-cluster" || head || r)[0..8]
tag      = HMAC-SHA-256(path_key, "AirChat v1 path-tag" || nonce)[0..16]
proof    = HMAC-SHA-256(path_key, "AirChat v1 path-answer" || path || nonce)[0..16]
```

- A tuned member answers unless the nonce names its own head: then it is in the asking cluster.
  Over the path the two open a channel link (§11.3), and the clusters, bridged by repeaters (§11.4),
  become one, with one head that goes on looking. A member alone is its own head. Providers see
  only random-looking nonces.
- Of two links to the same member (§11.3, by device nonce), one over a direct transport wins over
  one over a path. A channel link over a path stays up while the channel is tuned, though it may
  carry nothing but heads and liveness.

1:1 voice calls and push-to-talk: §8.5. Group calls and group push-to-talk: §9.6. Video in 1:1 calls: §8.6.

## 12. Paths through Air Providers

A device with Air Provider mode on (requirements AP-1) carries other devices' links. A *path* runs
from a device through one or more providers to one of its contacts, and the two contacts run an
ordinary link (§6) over it, so everything a link carries works through it while providers see only
that link's ciphertext. Paths carry what the mesh (§10) cannot: calls, push-to-talk, video and files.
They run over mesh neighbours' links (§10.1); every record below travels on such a link, hop by hop.
A *provider device* does nothing else: it has no account and no contacts, makes its keys anew in
memory every time it starts (§5.2), stores nothing, and is the recipient of nothing; on the wire
it is any device with Air Provider mode on.

### 12.1 Classes and offers

```
class   bit    carries                               providers at most   window
voice   0x01   messages, calls, push-to-talk          4                   32 KiB
video   0x02   as voice, and video                    2                   128 KiB
files   0x04   messages and files                     6                   256 KiB

0x52 offer:  classes (u8): the bits of the classes the sender carries for others now; 0 for none
```

- A provider decides which classes it carries from its own state (battery, charging, temperature;
  requirements AP-5) and sends an offer to each mesh neighbour when the link comes up, if it carries
  any, and whenever that changes. A device that sent no offer carries none.
- A provider carries at most 24 paths, at most 2 of them video and 2 files: voice is light, and a
  group call whose members are out of each other's reach needs a path per pair (§9.6), 21 for
  seven members. A path it accepted it carries until the path closes, even if it stops offering
  the class meanwhile; only turning Air Provider mode off closes them.

### 12.2 Finding a path

```
0x53 request:  path (16) || class (u8) || hops (u8) || nonce (16) || tag (16)
0x54 answer:   path (16) || providers (u8) || proof (16)

path       random; names the path on every hop
class      one bit of §12.1
hops       how many more providers may carry it
nonce      random
tag        HMAC-SHA-256(tag_key(a -> b), "AirChat v1 path-tag" || nonce)[0..16]
providers  how many providers the answer passed
proof      HMAC-SHA-256(tag_key(b -> a), "AirChat v1 path-answer" || path || nonce)[0..16]
```

`tag_key` is that of §10.3, made with the pairing secret of contacts (not their link keys, §6.8),
or a group link key of fellow members who are not contacts (§9.4, group voice). Device `a`, looking for
`b`, sends a request with hops = the class's provider limit to every mesh neighbour whose offer has
the class. Requests for a walkie-talkie channel's members use the channel's path key instead
(§11.5), and requests for the owner of an AirChat ID, from someone asking to be added, its
`request_path_key` (§4.8), for the tag and the proof alike, with the voice class.

A device receiving a request whose path it has not seen in the last minute:

1. If the tag is one of a contact's or fellow member's `c` — it tries `tag_key(c -> itself)` with
   each link key it has for each of them — and it accepts messages from `c` (any fellow member is
   accepted), it answers to the neighbour the request came from, with providers 0 and the proof
   made with the same link key, and waits 10 s for the path to open. A tuned device answers a
   request for its channel likewise, and a device a request for its own AirChat ID when §4.8 lets
   it.
2. Otherwise, if it offers the class, has room for another path of the class, and hops is at least
   1, it passes the request on with hops − 1 to all its other mesh neighbours and holds a place for
   the path for 10 s.
3. Otherwise it does nothing. It also does nothing beyond 20 requests a minute from one neighbour.

A provider passes each answer for a path it passed on, from any neighbour but the one the request
came from, back to that one with providers + 1, remembering who sent it; at most 4 per path. Only
`b` can make the proof, so `a` takes the first answer whose proof is right and ignores the rest; a
provider cannot draw paths to itself by answering for others. Without an answer within 10 s, `a`
gives up.

### 12.3 Opening and carrying

```
0x55 open:    path (16) || proof (16)
0x56 data:    path (16) || more (u8) || bytes (1–16366)
0x57 credit:  path (16) || bytes (u32)
0x58 close:   path (16)
```

- **Open.** `a` sends open, with the proof of the answer it took, to the neighbour that answer came
  from. Each provider passes it on to the neighbour whose answer had that proof and forgets the
  others; from then on it passes data, credit and close between those two neighbours, both ways. A
  provider (or `b`) without such an answer sends close back.
- **Data.** Over the path `a` opens a link to `b` (§6.3), as over any transport; over a path to
  the owner of an AirChat ID, the owner `b` opens the pairing instead (§4.8). Each of the link's
  frames (at most 65536 bytes) travels in data records, cut where needed: `more` is 1 in every
  record of a frame but its last, and 0 there.
- **Flow.** Each end may have at most the class's window of data bytes (the bytes after `more`) sent
  and not yet credited, and holds back the rest. A receiver credits what it took in credit records,
  at least once every 8 KiB. A provider closes a path that has more than the window plus 16 KiB
  outstanding in either direction, and a voice path that carries more than 4 MiB in a minute.
- **Close.** Either end, or a provider, closes the path with close; providers pass it on. A provider
  closes the paths over a neighbour whose link ended, and paths that carried nothing for 90 s (the
  link over a path sends liveness at least every 30 s, §6.7). An end closes a path whose link
  carried nothing but liveness for 60 s while no call or talk runs over it, so providers do not
  carry idle links (a channel link stays, §11.5).
- **Two paths.** Of two paths of one class between the same two devices (both looked at once),
  both keep the one whose link has the smaller handshake hash; a path of another class replaces the
  one there, as it was looked for to carry what that one does not.
- **What the link carries** depends on the class: messages, acknowledgements, calls and
  push-to-talk on every path; video on video paths only; files on files paths only. It carries no
  mesh traffic. A link over a path never replaces a link over a direct Wi-Fi transport to the same
  contact, and one over a direct transport replaces it.
- None of these records calls for an answer (§6.7).

### 12.4 What paths reveal

- Providers see a path's class and id, the two neighbours it runs between, when it carries how much,
  and how many providers lie behind it. They do not see whose it is: every request carries a new
  tag, and the link over the path is encrypted end to end with its own keys (§6). Providers on one
  path can tell, by its id, that they carry the same one.
- The first provider sees the device that opened the path as a neighbour; over a mesh link, a
  stranger (§10.2). The last sees `b` the same way.
- Anyone can send requests; a provider takes part only within its limits above.

### 12.5 Test vectors

`tests/vectors/paths.json` holds a request tag and an answer proof for a contact
pair, the records of §12.1 to §12.3, a channel's path key with a tag and proof, a cluster
nonce and a *channel head* record (§11.5), and an AirChat ID's path key with a tag and proof
(§4.8); `check_paths.py` re-derives them from this section.

## 13. Accounts

AirChat+ (requirements `A-1` to `A-9` of AirChat+) runs over the internet: each user has an account at
a server, `name@server`, which exists only so that envelopes find their recipient. This section is
what a device and its own server exchange to create an account, sign in and prove a session.
Nothing here is ever sent between devices, and nothing here protects content: secrecy and
authenticity of messages never depend on the server (§1).

Every message below is a two-byte header, the wire version `0x00` and its number, then its fields.
A device sends one request as the body of an HTTPS `POST` to the server's account endpoint and
gets one answer (`0x7f` on failure). Decoders reject wrong lengths and trailing bytes.

### 13.1 Names

```
name    = 3–32 bytes of a–z 0–9 . _ ; not starting or ending with . or _ ; no two of . _ in a row
server  = the server's DNS name, lowercase ASCII, 1–253 bytes
Name(x) = len(x) (u8) || x
```

A device lowercases what the user types before checking it; anything else is rejected, so two
names that look alike cannot both exist. `name@server` is the account's address.

### 13.2 Password and auth key

```
params   = memory_kib (u32) || iterations (u32) || parallelism (u8)
root     = Argon2id(password, salt, params) -> 32 bytes          (RFC 9106, version 0x13)
auth_key = HKDF(salt = "", ikm = root, info = "AirChat v1 account-auth" || Name(server) || Name(name), 32)
```

- `password` is the UTF-8 of what the user typed, in Unicode NFC; at least 10 characters.
- `salt` is 16 random bytes the device makes when it registers or changes the password.
- `params` are the server's current ones (§13.3); a server accepts nothing below 64 MiB, 3 passes,
  1 lane, nor above 1 GiB, 10 passes, 4 lanes.
- `auth_key` is all the server ever gets. Binding it to the server and the name makes it useless at
  any other server or for any other name; `root` is used for nothing else.
- The server stores `verifier = Argon2id(auth_key, server_salt, server_params)` with a random
  16-byte `server_salt` of its own (server-local; any slow hash will do), so a stolen account table
  costs a guesser both derivations per password tried.

### 13.3 Prelogin

```
0x70 prelogin:    Name(name)
0x71 parameters:  salt (16) || params (9)
```

The answer for an account is its salt and parameters. For a name with no account it is
`salt = HMAC-SHA-256(server_secret, "AirChat v1 account-fake-salt" || Name(name))[0..16]` and the
server's current parameters, so the answer does not show whether the account exists, and is the same
every time it is asked. When the server raises its parameters, accounts keep their old ones until
their next sign in (§13.5), which re-derives the key with the new ones; meanwhile those accounts can
be told apart from names without one.

### 13.4 Register

```
0x72 register:  Name(name) || salt (16) || params (9) || auth_key (32) || IK (32) || signature (64)
signature = Sign(IK, "AirChat v1 account-register" || Name(server) || all fields before it)
```

`IK` is the identity key of §4.1, made on the device for this account. The server checks the name
(§13.1), the parameters (§13.2) and the signature, refuses a name in use or in quarantine (a deleted
account's, for 30 days), stores the account, and answers as a sign in does (`0x76`).

### 13.5 Sign in

```
0x73 challenge request:  (empty)
0x74 challenge:          nonce (32)
0x75 sign in:            Name(name) || auth_key (32) || IK (32) || nonce (32) || rekey || signature (64)
0x76 session:            token (32) || replaced (u8)
rekey     = 0x00, or 0x01 || salt (16) || params (9) || new_auth_key (32)
signature = Sign(IK, "AirChat v1 account-sign-in" || Name(server) || all fields before it)
```

- A challenge is random, used once, and good for 60 s.
- The server checks the challenge, `auth_key` against the verifier, and the signature. A device
  re-keys (`0x01`) when the account's parameters are not the server's current ones; the server then
  also replaces salt, parameters and verifier.
- If `IK` is not the account's key, the device is new (`A-5`): the server makes `IK` the account's
  key, ends every session of the old one, and answers `replaced = 1`; else `replaced = 0`.
- `token` is 32 random bytes. The server keeps only `SHA-256(token)` and the `IK` it is bound to.

### 13.6 Requests on a session

```
0x77 authorized:  token (32) || nonce (32) || kind (u8) || body || signature (64)
signature = Sign(IK, "AirChat v1 account-session" || Name(server) || all fields before it)
0x78 done:        (empty)

kind 1  sign out:         body empty                       ends this session
kind 2  delete account:   body = auth_key (32)              ends every session, deletes everything
kind 3  change password:  body = auth_key (32) || salt (16) || params (9) || new_auth_key (32)
                                                            ends every other session
kind 4  publish static key:  body = version (u32) || SK.pk (1216) || signature (64)       §14.1
kind 5  set delivery key:    body = SHA-256("AirChat v1 mail-delivery-key" || dk) (32)    §14.4
kind 6  open mailbox:        body empty; only as the first frame of a mailbox connection  §14.6
kind 7  add delivery key:    body = SHA-256("AirChat v1 mail-delivery-key" || dk) (32)    §16.2
kind 8  remove delivery key: body = the same hash (32)                                   §16.2
```

`nonce` is a fresh challenge (§13.5): every request on a session proves both the token and the
identity key, so neither alone, nor a copy of what the server stores, is enough (`A-6`).

### 13.7 Failures

```
0x7f failure:  code (u8) || retry_after (u32, seconds; 0 if none)

code 1  malformed           2  name taken          3  wrong credentials
     4  too many attempts   5  challenge expired   6  invalid name
     7  parameters refused  8  session refused     9  refused (§14)
```

- An unknown name and a wrong password both give `3`, after the same work: the server checks the
  `auth_key` against a dummy verifier when there is no account.
- `4` comes from limits per name and per source address, the same for names with and without an
  account.

### 13.8 What a server learns

The name, the identity key, the salt and parameters, a slow hash of `auth_key`, hashes of session
tokens, and when sessions are used. Never the password, nor anything to sign in with elsewhere, nor
anything about the account's contacts or messages.

### 13.9 Test vectors

`tests/vectors/account.json` holds `auth_key` for a password and salt with cheap parameters, the fake
salt for a name and server secret, and a register, sign in and authorized request with their
signatures; `check_account.py` re-derives them from this section.

## 14. Mail

Two AirChat+ accounts never connect to each other. A device leaves what it sends at the
recipient's server, sealed so that only the recipient can open it and the server cannot tell who
sent it (requirements M-2, M-3); the recipient's device takes it over its own connection to that
server (N-1). This section is how contacts are made without meeting (requirement C-2), and how
they then exchange mail. Messages to and from the server have the two-byte header of §13 and the
same failures (§13.7); the server's DNS name is `server` as in §13.1.

`a` is the sender of a piece of mail and `b` its recipient. As in AirChat, every device has an
identity key `IK` (§4.1) and weekly static X-Wing keys `SK` (§6.1, §6.9); contacts share a pairing
secret `psk`, from which everything else between them is derived.

### 14.1 Static keys and lookup

An account publishes its newest static key at its server, on its session (§13.6, kind 4), in the
signed form of §6.9: `version (u32) || SK.pk (1216) || signature (64)`. The server checks the
signature with the session's `IK` and keeps the newest version; a device publishes each new static
key when it makes it.

```
0x80 lookup:  Name(name)
0x81 keys:    IK (32) || version (u32) || SK.pk (1216) || signature (64)
```

Anyone may look a name up, over a connection not signed in; the answer for a name without an
account, or one that has published no static key, is failure `9`. The asker checks the signature
before using the key. Looking a name up tells the asker that the account exists (threat model B6);
the server rate-limits lookups per source as it does prelogins.

### 14.2 Contact requests

A user who types `name@server` asks to become that account's contact. Their device `A` looks the
name up (§14.1) and leaves a *request*; the device `B` of the account opens it, shows its user who
asks, and if the user accepts, mails back an *accept* (§14.3). Both then hold `psk`.

**Request.** `A` encapsulates to the static key `SK_B` (version `v_B`) it was given:

```
(ss_1, ct_1) = X-Wing.Encaps(SK_B)
h_1      = SHA-256("AirChat v1 mail-request-hash" || Name(server_B) || Name(name_B) || IK_B || v_B (u32) || ct_1)
k_1      = HKDF(salt = "", ikm = ss_1, info = "AirChat v1 mail-request-key" || h_1)
inner_1  = Name(server_A) || Name(name_A) || IK_A || v_A (u32) || SK_A.pk (1216) || sk_signature_A (64)
           || dk_A (32) || proof_A (64)
proof_A  = Ed25519(IK_A, "AirChat v1 mail-request-proof" || h_1 || all of inner_1 before it)
request  = v_B (u32) || ct_1 (1120) || ChaCha20-Poly1305(k_1, nonce = 12 zero bytes, aad = "", padded_1)
padded_1 = len (u16) || inner_1 || zeros, making the request exactly 4096 bytes
```

- `SK_A` is `A`'s newest static key, `sk_signature_A` its §6.9 signature, and `dk_A` `A`'s
  delivery key (§14.4), so that `B` can mail back.
- `proof_A` binds `A`'s identity to this request alone: it covers `ct_1`, whose secret only `A`
  and `B` hold, and everything `A` says of itself.
- `A` keeps `ss_1` and `h_1` until the request is answered, withdrawn or 30 days old.

**Opening.** `B` takes `v_B` as the version of its own static key to decapsulate with, recomputes
`h_1` with its own name and server, decrypts, and checks: the padding is zeros, `IK_A` is not its
own, `sk_signature_A` and `proof_A` verify with `IK_A`, and `SK_A.pk` is a valid X-Wing key (FIPS
203 check). It looks `name_A` up at `server_A` and shows the request only if the key it gets is
`IK_A`. A request that fails any check is dropped without a word; so is one from a blocked contact.

**Answers.** A user who declines drops the request; `A` is not told. A user who accepts makes `B`
send the accept (§14.3). Requests are rate-limited at the server (§14.5); a request repeated by
the same `IK_A` replaces the one shown.

### 14.3 Mail

Everything between contacts after the request travels as *mail*: `tag || body`, deposited at the
recipient's server (§14.5) and padded to one of three sizes (M-4).

```
mail     = tag (32) || field (u32) || ct (1120) || ChaCha20-Poly1305(key, nonce = 12 zero bytes, aad = "", padded)
tag      = nonce (16 random bytes) || HMAC-SHA-256(tag_key, "AirChat v1 mail-tag-mac" || nonce)[0..16]
padded   = len (u16) || payload || zeros, making the mail exactly 2048, 4096 or 16384 bytes (the smallest that fits)
```

**Accept.** The first mail from `B` to `A` answers the request. `B` encapsulates to `SK_A`
(version `v_A`) from the request:

```
tag_key  = HKDF(salt = "", ikm = ss_1, info = "AirChat v1 mail-accept-tag-key" || h_1)
(ss_2, ct = ct_2) = X-Wing.Encaps(SK_A);  field = v_A
h_2      = SHA-256("AirChat v1 mail-accept-hash" || h_1 || IK_A || v_A (u32) || ct_2)
key      = HKDF(salt = "", ikm = ss_2, info = "AirChat v1 mail-accept-key" || h_2 || tag)
payload  = Name(server_B) || Name(name_B) || IK_B || v_B' (u32) || SK_B'.pk (1216) || sk_signature_B (64)
           || dk_B (32) || proof_B (64)
proof_B  = Ed25519(IK_B, "AirChat v1 mail-accept-proof" || h_2 || all of the payload before it)
psk      = HKDF(salt = ss_1, ikm = ss_2, info = "AirChat v1 mail-psk" || h_2)
```

`A` recognises the tag with the tag key of each request it has pending, decrypts, and checks that
`IK_B` is the key it looked up, that `name_B` and `server_B` are those it asked for, and the
signatures; `SK_B'` (version `v_B'`) is `B`'s newest static key, which may be newer than the one
`A` was given. Both then hold `psk`, which needs both `ss_1` and `ss_2`: nobody learns it without
both static keys used. `A` forgets `ss_1`; `B` forgets `ss_1` once it sent the accept.

**Between contacts.** All other mail from `a` to `b` is sealed as an AirChat envelope body (§10.3)
is, to one of `b`'s one-time prekeys or to `b`'s static key:

```
tag_key  = HKDF(salt = "", ikm = psk, info = "AirChat v1 mail-tag-key" || IK_a || IK_b)
field    = the id of b's one-time prekey for a it is sealed to (§14.7); 0 for SK_b
(ss, ct) = X-Wing.Encaps(that prekey's key, or SK_b)
key      = HKDF(salt = psk, ikm = ss, info = "AirChat v1 mail-seal" || IK_a || IK_b || tag || field (u32))
payload  = a §8.1 record of a kind below
```

- **Recognising.** The recipient checks the tag against the tag key of each contact (one HMAC
  each, in constant time) and of each request it has pending; mail that matches none is taken from
  the mailbox and dropped. Tags are new for every mail, so the server cannot tell two pieces of mail
  from one sender apart from two senders' (M-3).
- **Static keys.** Sealed to `SK_b`, mail is sealed to the newest static key of `b`'s that `a`
  holds; `b` tries its own from the version `a` took last (§6.9). A device makes a new static key
  every week, publishes it at its server (§14.1) and tells its contacts in mail (`0x5c`, until they
  answer `0x5d`). It keeps an older one until every contact took a newer one **and** for at least
  30 days after making the next: mail and requests sealed to it may wait that long at the server
  (§14.5). §6.9's 25 hours are for mesh envelopes, which live a day.
- **Kinds.** A payload is one of: text `0x01`, ack `0x02`, refused `0x05` (§8.1); file offer
  `0x20` (§8.4; its content goes over a relay, §15.3); prekeys `0x5a` and prekeys wanted `0x5b`
  (§14.7); static key `0x5c` and static key taken `0x5d` (§6.9); relay invite `0x62` (§15.1);
  update part `0x40` (§16.3, from the admin adding the recipient to a group); and

  ```
  0x61 delivery key:  dk (32)        the sender's new delivery key (§14.4)
  ```

  Other kinds are ignored. Texts are acknowledged as on a link (§8.1), the ack sealed to `SK_a`.
- **Replays.** The server can hand the same mail again. Opening mail sealed to a prekey deletes the
  prekey (§14.7), so a copy no longer opens; texts are stored once per `message_id`, and the other
  kinds are idempotent.

### 14.4 Delivery keys

Only contacts can leave mail for an account (C-5): every deposit shows the recipient's *delivery
key* `dk`, 32 random bytes the recipient gives all its contacts alike, in its request or accept and
later in mail of kind `0x61`. Its server keeps only `SHA-256("AirChat v1 mail-delivery-key" || dk)`,
set on the session (§13.6, kind 5), and refuses mail that shows another key (failure `9`).

- The server learns that a contact deposited, never which: all contacts show the same key (threat
  model §7.4). A copy of the server's database is no key to deposit with.
- **Blocking** a contact makes a new `dk`: the device sets it at its server at once, then mails it
  to every other contact. Mail deposited with the old key is refused from then on; its sender keeps
  it as sending and deposits it again once it has the new key.
- `dk` travels inside TLS; the server sees it at every deposit. Seeing it lets the server do
  nothing it could not anyway (fill its own mailbox).

### 14.5 Deposits

```
0x82 deposit:          Name(name) || dk (32) || mail (2048, 4096 or 16384 bytes)
0x83 deposit request:  Name(name) || request (4096)
                       answers: 0x78 done, or failure 9 (no such account, or a wrong delivery key)
```

- A device deposits over a connection **not signed in**, also at its own server, so the deposit is
  not tied to its account (threat model B2 says what the source address still shows).
- The server keeps mail until the recipient's device takes it, and at most 30 days (M-5). It keeps
  at most 50 requests per account and rate-limits deposits of requests per source; a request beyond
  the limit is refused like an unknown name.
- A deposit's answer is the same for an unknown name and a wrong key, and takes about as long.

### 14.6 The mailbox connection

A device signed in keeps one connection to its server open (N-1): a WebSocket on the server's
mailbox endpoint, over TLS, each frame one binary WebSocket message.

```
server → device:  0x74 challenge (§13.5), once, on connecting
device → server:  0x77 authorized (§13.6), kind 6, with that challenge's nonce
server → device:  0x78 done, or a failure, after which it closes the connection
server → device:  0x90 mail:     id (u64) || mail
                  0x91 request:  id (u64) || request
device → server:  0x92 taken:    id (u64)
```

- After *done* the server sends everything waiting for the account, then each new piece of mail or
  request as it arrives. `id` is the server's own number for it.
- The device sends *taken* once it has stored what came, or dropped it; the server then deletes it.
  What is not taken is sent again on the next connection.
- Signing in elsewhere (A-5) ends the session and closes the connection. Unknown frame kinds end it
  too.

### 14.7 Prekeys between contacts

Contacts hand each other one-time prekeys inside mail, as AirChat contacts do over links (§10.7),
with the same records (`0x5a`, `0x5b`) and the same rules for keeping, sealing and deleting, except
when they are asked for:

- Right after pairing, both sides ask for 24 (`0x5b`), the request's sender once it has opened the
  accept, the other once it has sent it.
- A device holding fewer than 8 unused prekeys of a contact asks for `24 −` the number it holds, at
  most once a day while unanswered.
- Prekey records are sealed to the recipient's static key; texts take the oldest unused prekey, and
  `SK_b` when none is left.

The server holds no prekeys, so it cannot hand out the same one twice nor count how fast they go.

### 14.8 What a server learns

From deposits: that a piece of mail or a request arrived for one of its accounts, when, its padded
size, and the address it came from (§14.5) — never from whom. From lookups: which names are asked
for, by which addresses. From the mailbox connection: when the account's device is online, how much
it takes, and its address. Mail is ciphertext under keys only the two contacts derive; requests are
sealed to the recipient's static key. The server keeps the newest static key and the delivery key's
hash of each account, waiting mail and requests, nothing else (requirement S-4).

### 14.9 Test vectors

`tests/vectors/mail.json` holds a request and its accept between two accounts, the `psk` they
derive, a text mailed to a prekey and its ack mailed to a static key, a delivery-key hash, and the
deposit and mailbox frames; `check_mail.py` re-derives them from this section.

## 15. Relay

Some things between AirChat+ contacts need both of them at once: the content of a file (§8.4) and
calls (§8.5, §8.6, §9.6). They meet at a *relay* on a server, never at each other, so neither learns
the other's address (requirement M-7). A relay passes bytes between the connections that joined
the same room and keeps nothing: no file, no stream, no log.

### 15.1 Invitations

```
0x62 relay invite:  room (16) || token (32) || size (u8, 2–33) || purpose (u8) || reference (16)
                    purpose 0x01 a file      reference: the offer's message_id (§8.4)
                            0x02 a call      reference: the call's stream id (§8.5)
```

- The inviter makes `room` and `token` at random and mails the invite (§14.3) to each invitee,
  sealed like any other record. The room is at the inviter's server.
- `size` is how many join the room, the inviter among them: 2 for a file or a call between two.
- An invite is answered by joining, or not at all: the inviter learns nothing of an invitee that
  stays away. A device joins only from a contact, and only for a file offered to it (§15.3) or a
  call it would ring for (§17).

### 15.2 Rooms

A device joins over a WebSocket on the server's relay endpoint, **not signed in**, each frame one
binary WebSocket message:

```
device → server:  0xa0 join:   room (16) || token (32) || size (u8) || wait (u16, minutes, 1–180)
server → device:  0xa1 ready:  (empty)          everyone joined; from now on frames are passed on
                  0x7f failure 9 (§13.7)        another token or size for the room, or it is full
```

- The first join opens the room and says how long it waits for the others: 1 minute for a call, up
  to 3 hours (180) for a file; then it closes. A later join's `wait` is ignored. A join with the
  right token takes the next place; one more than `size`, or with another token or size, is
  refused.
- After *ready*, every binary message a member sends goes to every other member, unchanged and in
  order. The room closes when a member leaves; a room of more than two, when fewer than two remain.
- A room lives at most 6 hours. The server keeps rooms in memory only and rate-limits joins per
  source address.

### 15.3 Over a relay

The relay is only a transport (§7): what runs over it is protected end to end.

- **Between two contacts** the inviter opens a contact link (§6) as initiator, the invitee
  responds. Their link key is their pairing secret `psk` (§14.3) and their static keys are those
  they hold of each other. The link session then carries the file's chunk requests and chunks
  (§8.4: `0x21`, `0x22`, `0x23`) or the call's records (§8.5, §8.6).
- **Files.** The sender mails the file offer and, with it, an invite (purpose `0x01`), and waits in
  the room (`wait` up to 180). The receiver's device joins as soon as it gets the invite and fetches
  the whole file at once, whatever its auto-download setting (§8.4 does not apply here): nothing
  waits for it at the server. A sender cut off invites again over a new room, and the transfer
  resumes (§8.4). **Three hours** after the offer the sender stops: no more invites, no more chunks,
  and the message shows as *could not be sent*; the receiver drops an offer whose content it did not
  get by then. The server never holds a byte of a file, only the room while it waits.
- Whoever controls the server sees two connections that joined one room, their addresses, timing
  and volume. It cannot read or change what passes (the link session's AEAD), nor pose as either
  end (the handshake proves `psk` and the static keys), nor tell from the relay alone which
  accounts the ends belong to.

### 15.4 Test vectors

`tests/vectors/relay.json` holds a relay invite and the join, ready and failure frames;
`check_relay.py` encodes them again from this section.

## 16. Groups by mail

AirChat+ groups are AirChat's (§9): epochs, signed updates, rosters, admins, group messages sealed
once under the epoch key. What changes is how they travel: as mail (§14), deposited by the sender
at each member's server, since members need not be contacts of each other and never meet. Servers
learn nothing of groups: not who is in one, nor that a piece of mail belongs to one.

### 16.1 Rosters

A roster (§9.1) is unchanged on the wire; two of a member's fields carry what mail needs:

- `name` is the member's address, `name@server` (§13.1), so at most 64 characters: a member whose
  address is longer cannot be in a group until this changes with federation.
- `presence_key` (there are no beacons over the internet) is the member's **group delivery key**
  `dk_G` (§16.2) for this group, or 32 zero bytes while the admin does not know it.

### 16.2 Group delivery keys

Each member makes a delivery key of its own for each group it is in, so that only the group's
members can leave its group mail (C-5), and so that someone removed loses that right in that group
alone:

- An account may hold several delivery keys at its server: the one of §14.4 (kind 5 replaces it)
  and up to 64 more, added and removed on its session (§13.6, kinds 7 and 8). A deposit (§14.5)
  may show any of them.
- A member adds `dk_G` at its server when it joins (it accepts the update that adds it), and tells
  the group, then again in each epoch it accepts (so members added since learn it), in a group
  message whose content is
  ```
  0x04 delivery key:  dk (32)        the sender's group delivery key (§16.2)
  ```
  Members take it from the message and admins put it in later rosters. Members added together
  know only the keys the roster had: an admin therefore passes each such message it takes on,
  unchanged, to every other member whose key it knows (its sender's signature still holds).
- When an epoch removes someone, every remaining member makes a new `dk_G`, adds it, tells the
  group, and removes the old one an hour later (mail still on its way may show it).
- The server sees how many keys an account holds, and which of them a deposit shows: it can tell
  that two deposits for an account were for the same group, never which group nor who is in it.

### 16.3 Group mail

What goes to the members of a group goes as *group mail*, one piece per member, each deposited at
that member's server with that member's `dk_G`:

```
group mail = tag (32) || ChaCha20-Poly1305(key, nonce = 12 zero bytes, aad = "", padded)
tag_key    = HKDF(salt = "", ikm = epoch_key, info = "AirChat v1 mail-group-tag-key" || group_id || epoch (u64))
tag        = nonce (16 random bytes) || HMAC-SHA-256(tag_key, "AirChat v1 mail-tag-mac" || nonce)[0..16]
key        = HKDF(salt = "", ikm = epoch_key, info = "AirChat v1 mail-group-seal" || group_id || epoch (u64) || tag)
padded     = len (u16) || record || zeros, making the mail exactly 2048, 4096 or 16384 bytes
record     = a group message (0x41) or an update part (0x40), each as on a link (§9.3, §9.5)
```

- `epoch_key` is the key of the epoch the record belongs to; for an update part, of the epoch
  before the update. A recipient checks the tag against the tag key of every epoch it holds of
  every group, as it checks contacts' tags (§14.3). The server sees a fresh tag every time; it
  can tell group mail from a contact's by the delivery key shown (and by the bytes where a
  contact's mail names its prekey), and one group's from another's by their keys, but not which
  group, who sent it, nor what it carries.
- The record inside is what §9 makes it, sealed and signed by its sender as on a link; the outer
  seal hides from the server who sent it and to which group, which the record shows in clear.
- Group acks (`0x42`) and group leaves (`0x43`) do not go in group mail: they name no sender, and
  in mail, unlike on a link, nothing would vouch for one. Group messages carry them instead, signed
  by their sender like any other:
  ```
  0x05 received:  message id (16)    the sender stored that group message
  0x06 leaving                       the sender leaves the group
  ```
- **Updates.** An update goes in parts (§9.5) of at most 15000 bytes of data each, so a part fits
  in the largest mail of either kind. Members of the previous epoch, the removed ones included, get
  it as group mail under that epoch's key; a member being added, which holds no key yet, gets it in
  mail from the admin, who is its contact (§9.2): parts `0x40` are a kind contact mail may carry
  (§14.3).
- **Acknowledgements.** A member that stores a group message answers its sender alone with a group
  message whose content is *received* (`0x05`); the sender shows who has it. Such a message is not
  shown, and is not answered in turn. A message no member took within 30 days (the most mail
  waits, §14.5) is shown as not delivered.
- **Leaving.** A member that leaves sends every member a group message whose content is *leaving*
  (`0x06`) and drops the group; members show it, and an admin removes the sender with a new epoch.
- **Deleting.** An admin's *deleted* (`0x03`, §9.2) goes to every member in group mail. A member
  remembers a deleted group for 30 days, not a day, since an update of it may wait at its server
  that long.
- **Two updates of one epoch** (§9.2) are settled as on links. A device that takes the other update
  seals its own messages of that epoch afresh, queues them again, and tells its delivery key in the
  epoch again; the admin whose update was set aside makes its change again in the next epoch.
- **Mail that does not open yet.** Group mail whose tag matches no epoch the device holds is kept
  for a day (at most 256 pieces) and tried again whenever the device takes an update: it may be of
  an epoch whose update is still on its way, or of the other update of an epoch.
- A member whose `dk_G` the sender does not know yet gets nothing until it does: its first group
  message tells everyone.
- Flooding (§9.5) does not apply: every sender deposits for every member itself, but for the
  delivery keys an admin passes on (§16.2).

### 16.4 Group files

A file sent to a group goes like a file between two (§15.3), member by member: the file message
(content `0x02`, §9.3) to everyone in group mail, its content over relay rooms, never stored at a
server, for **three hours** after the message.

- **Rooms.** A room for a group file is one of two, the sender and one member. Whoever opens it
  tells the other in a group message to that member alone whose content is a relay invite (`0x07`:
  purpose file, `size` 2, `reference` the file message's `message_id`), and waits in it. The other
  joins at once if the file is one it should send or fetch.
- **Small files, to everyone.** For a file of at most 5 MiB (5 242 880 bytes) the sender opens a room
  for each member, waiting what is left of the three hours, and each member's device joins as soon
  as it gets the invite and fetches the file.
- **Larger files, when asked.** A member's device fetches a larger file only when its user asks: it
  opens a room, waiting 5 minutes, and invites the sender, which joins if the three hours have not
  passed and it holds the file whole. A sender that does not come leaves the file to be asked for
  again.
- **The link.** In the room the two run a link (§6) as members, with the group link key `link_psk`
  of §9.4 for the file message's epoch and each other's identity and static keys from that epoch's
  roster, whether they are contacts or not; whoever opened the room initiates. Over it the fetcher
  asks for the file's chunks by the message's `message_id` and checks the whole file against
  `sha256`, and acknowledges it, as in §8.4. A device serves a group file only to a member of the
  group in the message's epoch, and only the file of that message.
- After three hours the sender serves the file no more; a member that does not have it shows it as
  no longer available.

### 16.5 Test vectors

`tests/vectors/group_mail.json` holds a piece of group mail carrying a group message whose
content is the sender's group delivery key, with its tag key, tag, key and padding;
`check_group_mail.py` re-derives them from this section and §9.3.

## 17. Calls over a relay

AirChat+ contacts never meet, so a call runs over a relay room (§15) between them: the link of
§15.3, carrying the call records of §8.5 and §8.6 unchanged. This section adds no format; its
vectors are §15's.

### 17.1 Calls between two

- **Calling.** The caller picks the call's stream id, mails an invite (`0x62`, purpose `0x02`,
  `size` 2, `reference` the stream id) to the contact, and opens the room with `wait` 1: the room
  closes after a minute if the contact's device does not come. Once the link is up it sends the
  *call offer* (§8.5) over it, and from then on the call goes as in §8.5: *ringing*, *call accept*
  or *call end*, audio, video (§8.6), 45 s without an answer ending it (*no answer*).
- **Being called.** A device that gets the invite joins the room at once, before it rings, if it
  takes calls from the contact (C-5) and is in no other call; else it stays away and the call ends
  at the caller unanswered. It rings when the offer comes over the link. Joining tells the caller
  that the device is online now, as *ringing* does in AirChat.
- **Missed calls.** An invite that does not lead to an offer within a minute, because the room is
  gone (the invite waited at the server while the device was away) or never got ready, is shown as
  a missed call from the contact. The device does not call back by itself.
- **Video.** The relay is a fast transport for §8.6: video is sent over it from the start, without
  the move to a hotspot. An app may hold its camera back (*paused*) on a metered network.
- **Losing the link.** When the relay connection drops, the call waits 20 s as in §8.5 and then
  ends (*lost*); a call is not taken to another room.
- Whoever controls the server sees two connections in one room for as long as the call lasts,
  their addresses, timing and volume (which follow speech and the picture, padded to 64 bytes per
  record, §8.5); never who calls whom, nor what is said.

### 17.2 Group calls

Not yet: how participants who are not each other's contacts share a call over relays (one room
per pair of participants, or a room of `size` N that passes each frame to everyone) is still to be
decided.
