#!/usr/bin/env python3
"""Independent check of the group mail test vector (docs/protocol.md §16).

Recomputes from the specification alone: the tag key of a group's epoch, the tag (its nonce
regenerated from the listed seed), the key, the padding to the smallest mail size and the AEAD; and,
inside, the group message (§9.3) whose content is the sender's group delivery key (§16.2), with its
signature. Needs the `cryptography` package; XChaCha20 is built here from HChaCha20.

    python3 check_group_mail.py
"""

import hashlib
import hmac
import json
import pathlib
import struct
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

MAIL_SIZES, TAG_LEN, AEAD_TAG_LEN = (2048, 4096, 16384), 32, 16

vector = json.loads(pathlib.Path(__file__).with_name("group_mail.json").read_text())
field = lambda name: bytes.fromhex(vector[name])
failures = 0


def check(what, actual, expected):
    global failures
    ok = actual == expected
    failures += not ok
    print(f"{'ok  ' if ok else 'FAIL'} {what}")


def hkdf(salt, ikm, info, length=32):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out, counter = out + block, counter + 1
    return out[:length]


def rng(seed, length):
    """The test vectors' randomness: SHA-256(seed || counter), counter a big-endian u64 from 0."""
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


print("group_mail.json")
epoch_key, group_id, epoch = field("epoch_key"), field("group_id"), int(vector["epoch"])
epoch_be = epoch.to_bytes(8, "big")
record, mail = field("record"), field("mail")

# §16.3: the outer layer.
tag_key = hkdf(b"", epoch_key, b"AirChat v1 mail-group-tag-key" + group_id + epoch_be)
check("tag key", tag_key, field("tag_key"))
nonce = rng(field("tag_rng_seed"), 16)
tag = nonce + hmac.new(tag_key, b"AirChat v1 mail-tag-mac" + nonce, hashlib.sha256).digest()[:16]
check("tag", tag, field("tag"))
key = hkdf(b"", epoch_key, b"AirChat v1 mail-group-seal" + group_id + epoch_be + tag)
check("key", key, field("key"))
size = next(size for size in MAIL_SIZES if len(record) + 2 <= size - TAG_LEN - AEAD_TAG_LEN)
padded = len(record).to_bytes(2, "big") + record + bytes(size - TAG_LEN - AEAD_TAG_LEN - 2 - len(record))
check("mail", mail, tag + ChaCha20Poly1305(key).encrypt(bytes(12), padded, b""))
check("smallest size", len(mail), MAIL_SIZES[0])

# Inside: a group message record (0x41, §9.3) whose content is a group delivery key (0x04, §16.2).
check("record kind", record[0], 0x41)
message = record[1:]
signed, signature = message[:-64], message[-64:]
sender = Ed25519PrivateKey.from_private_bytes(field("sender_seed")).public_key().public_bytes_raw()
message_id = bytes([0x14] * 16)
check("message header", signed[:72], group_id + epoch_be + message_id + sender)
message_nonce = signed[72:96]
check("message nonce from the RNG stream", message_nonce, rng(field("message_rng_seed"), 24))
message_key = hkdf(b"", epoch_key, b"AirChat v1 group-message" + group_id + epoch_be)
plaintext = xchacha_open(message_key, message_nonce, signed[:72], signed[96:])
check("message plaintext", plaintext, (1_791_400_180_000).to_bytes(8, "big") + b"\x04" + field("delivery_key"))
try:
    Ed25519PublicKey.from_public_bytes(sender).verify(signature, b"AirChat v1 group-message" + signed)
    check("message signature", True, True)
except Exception:
    check("message signature", False, True)

sys.exit(1 if failures else 0)
