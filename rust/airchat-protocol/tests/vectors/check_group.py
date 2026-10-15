#!/usr/bin/env python3
"""Independent check of the group test vector (docs/protocol.md §9).

Rebuilds the roster from its members, re-derives every key and checks every ciphertext and
signature of the group update and the group message from the specification alone. X-Wing is the
one thing not reimplemented: the vector lists the shared secret of each envelope, and its
randomness comes from the listed RNG stream. Needs the `cryptography` package (ChaCha20-Poly1305,
Ed25519); XChaCha20 is built here from HChaCha20.

    python3 check_group.py
"""

import hashlib
import hmac
import json
import pathlib
import struct
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

EK_LEN, CT_LEN, SEALED_KEY_LEN, KEM_RANDOMNESS = 1216, 1120, 48, 64

v = json.loads((pathlib.Path(__file__).parent / "group.json").read_text())
field = lambda name: bytes.fromhex(v[name])
failures = 0


def check(what, actual, expected):
    global failures
    ok = actual == expected
    failures += not ok
    print(f"  {'ok  ' if ok else 'FAIL'} {what}")


def hkdf(salt, ikm, info, length=32):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out, counter = out + block, counter + 1
    return out[:length]


def rng_stream(seed, length):
    out, counter = b"", 0
    while len(out) < length:
        out, counter = out + hashlib.sha256(seed + counter.to_bytes(8, "big")).digest(), counter + 1
    return out[:length]


def hchacha20(key, nonce16):
    def rotl(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    def quarter(s, a, b, c, d):
        s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = rotl(s[d] ^ s[a], 16)
        s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = rotl(s[b] ^ s[c], 12)
        s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = rotl(s[d] ^ s[a], 8)
        s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = rotl(s[b] ^ s[c], 7)

    s = list(struct.unpack("<4I", b"expand 32-byte k")) + list(struct.unpack("<8I", key)) + list(struct.unpack("<4I", nonce16))
    for _ in range(10):
        quarter(s, 0, 4, 8, 12); quarter(s, 1, 5, 9, 13); quarter(s, 2, 6, 10, 14); quarter(s, 3, 7, 11, 15)
        quarter(s, 0, 5, 10, 15); quarter(s, 1, 6, 11, 12); quarter(s, 2, 7, 8, 13); quarter(s, 3, 4, 9, 14)
    return struct.pack("<8I", *(s[0:4] + s[12:16]))


def xchacha_open(key, nonce24, aad, sealed):
    return ChaCha20Poly1305(hchacha20(key, nonce24[:16])).decrypt(bytes(4) + nonce24[16:], sealed, aad)


def name(text):
    raw = text.encode()
    return bytes([len(raw)]) + raw


def roster_role(identity):
    for seed, _, role, _, _ in people:
        if public(seed) == identity:
            return role
    return None


def public(seed):
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()


print("group.json")
group_id, epoch, epoch_key = field("group_id"), int(v["epoch"]), field("epoch_key")
epoch_be = epoch.to_bytes(8, "big")
roster = field("roster")

# §9.1: the roster, rebuilt from its members (the X-Wing public keys are taken from the roster).
people = [
    (bytes([1] * 32), "Ayşe", 1, 0, 0),
    (bytes([2] * 32), "Burak", 0, 0, 3),
    (bytes([3] * 32), "Cem", 0, 1_800_000_000, 7),
]
offset, kems = 16 + 8 + len(name("Kamp ateşi")) + 1, {}
for _ in people:
    identity = roster[offset:offset + 32]
    kems[identity] = roster[offset + 32:offset + 32 + EK_LEN]
    offset += 32 + EK_LEN + 4 + 32 + 1 + 8
    offset += 1 + roster[offset]
members = []
for seed, member_name, role, expires, key_version in people:
    identity = public(seed)
    presence = bytes([0x80 + seed[0]] * 32)
    member = identity + kems[identity] + key_version.to_bytes(4, "big") + presence + bytes([role])
    members.append((identity, member + expires.to_bytes(8, "big") + name(member_name)))
members.sort()
rebuilt = group_id + epoch_be + name("Kamp ateşi") + bytes([len(members)]) + b"".join(m for _, m in members)
check("roster", rebuilt.hex(), v["roster"])

# §9.2: the update.
update = field("update")
signer = public(field("signer_seed"))
signed, signature = update[:-64], update[-64:]
check("update header", signed[:56], group_id + epoch_be + signer)
count = signed[56]
check("envelope count", count, len(members))
secrets = [bytes.fromhex(s) for s in v["envelope_shared_secrets"].split(",")]
aad = group_id + epoch_be
at = 57
for (identity, _), secret in zip(members, secrets):
    envelope = signed[at:at + 32 + CT_LEN + SEALED_KEY_LEN]
    at += len(envelope)
    k = hkdf(b"", secret, b"AirChat v1 group-envelope" + group_id + epoch_be + identity)
    sealed = ChaCha20Poly1305(k).encrypt(bytes(12), epoch_key, aad)
    check("envelope identity", envelope[:32], identity)
    check("sealed epoch key", envelope[32 + CT_LEN:], sealed)
roster_nonce = signed[at:at + 24]
check("roster nonce from the RNG stream", roster_nonce, rng_stream(field("rng_seed"), count * KEM_RANDOMNESS + 24)[-24:])
length = int.from_bytes(signed[at + 24:at + 28], "big")
sealed_roster = signed[at + 28:at + 28 + length]
check("update length", at + 28 + length, len(signed))
roster_key = hkdf(b"", epoch_key, b"AirChat v1 group-roster" + group_id + epoch_be)
check("sealed roster", xchacha_open(roster_key, roster_nonce, aad, sealed_roster), roster)
try:
    Ed25519PublicKey.from_public_bytes(signer).verify(signature, b"AirChat v1 group-update" + signed)
    check("update signature", True, True)
except Exception:
    check("update signature", False, True)

# §9.3: the message.
message = field("message")
sender = public(field("message_sender_seed"))
signed, signature = message[:-64], message[-64:]
message_id = bytes([0x11] * 16)
check("message header", signed[:72], group_id + epoch_be + message_id + sender)
nonce = signed[72:96]
check("message nonce from the RNG stream", nonce, rng_stream(field("rng_seed"), count * KEM_RANDOMNESS + 48)[-24:])
message_key = hkdf(b"", epoch_key, b"AirChat v1 group-message" + group_id + epoch_be)
plaintext = xchacha_open(message_key, nonce, group_id + epoch_be + message_id + sender, signed[96:])
# sent_at || 0x01 (text) || UTF-8.
check("message plaintext", plaintext, (1_791_400_000_000).to_bytes(8, "big") + b"\x01" + "Ateşi kim yakıyor?".encode())
try:
    Ed25519PublicKey.from_public_bytes(sender).verify(signature, b"AirChat v1 group-message" + signed)
    check("message signature", True, True)
except Exception:
    check("message signature", False, True)

# A file message: sent_at || 0x02 (file) || size || sha256 || mime || name || thumbnail (§8.4's fields).
message = field("file_message")
sender = public(bytes([3] * 32))
signed, signature = message[:-64], message[-64:]
file_id = bytes([0x12] * 16)
check("file message header", signed[:72], group_id + epoch_be + file_id + sender)
nonce = signed[72:96]
check("file message nonce from the RNG stream", nonce, rng_stream(field("rng_seed"), count * KEM_RANDOMNESS + 72)[-24:])
plaintext = xchacha_open(message_key, nonce, group_id + epoch_be + file_id + sender, signed[96:])
mime, file_name, thumbnail = b"application/pdf", b"harita.pdf", bytes.fromhex("ffd8ffd9")
expected = (
    (1_791_400_060_000).to_bytes(8, "big") + b"\x02" + (70_000).to_bytes(8, "big") + bytes([0xAB] * 32)
    + bytes([len(mime)]) + mime + bytes([len(file_name)]) + file_name + len(thumbnail).to_bytes(2, "big") + thumbnail
)
check("file message plaintext", plaintext, expected)
try:
    Ed25519PublicKey.from_public_bytes(sender).verify(signature, b"AirChat v1 group-message" + signed)
    check("file message signature", True, True)
except Exception:
    check("file message signature", False, True)

# Deleting the group: sent_at || 0x03, from Ayşe, an admin of the roster.
message = field("deleted_message")
sender = public(bytes([1] * 32))
signed, signature = message[:-64], message[-64:]
deleted_id = bytes([0x13] * 16)
check("deleted message header", signed[:72], group_id + epoch_be + deleted_id + sender)
nonce = signed[72:96]
check("deleted message nonce from the RNG stream", nonce, rng_stream(field("rng_seed"), count * KEM_RANDOMNESS + 96)[-24:])
plaintext = xchacha_open(message_key, nonce, group_id + epoch_be + deleted_id + sender, signed[96:])
check("deleted message plaintext", plaintext, (1_791_400_120_000).to_bytes(8, "big") + b"\x03")
check("deleted message sender is an admin", roster_role(sender), 1)
try:
    Ed25519PublicKey.from_public_bytes(sender).verify(signature, b"AirChat v1 group-message" + signed)
    check("deleted message signature", True, True)
except Exception:
    check("deleted message signature", False, True)

# §9.4: the link key of Burak and Cem.
burak, cem = public(bytes([2] * 32)), public(bytes([3] * 32))
low, high = sorted([burak, cem])
psk = hkdf(b"", epoch_key, b"AirChat v1 group-link" + group_id + epoch_be + low + high)
check("link psk", psk.hex(), v["link_psk_burak_cem"])

print("all checks passed" if not failures else f"{failures} check(s) failed")
sys.exit(1 if failures else 0)
