#!/usr/bin/env python3
"""Independent check of the walkie-talkie channel test vector (docs/protocol.md §11).

Recomputes from the specification alone: the channel key from its password (Argon2id), everything
derived from it, the beacon token, the QR code, the recognition tag, and the link handshake's
transcript, key schedule, ciphertexts and first records. The X-Wing shared secret is listed rather
than recomputed. Needs the `cryptography` package (Argon2id, ChaCha20-Poly1305).

    python3 check_channel.py
"""

import hashlib
import hmac
import json
import pathlib
import sys

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

TAG_LEN, EK_LEN, CT_LEN = 32, 1216, 1120
CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

vector = json.loads(pathlib.Path(__file__).with_name("channel.json").read_text())
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


def crockford32(data):
    bits = "".join(f"{b:08b}" for b in data)
    bits += "0" * (-len(bits) % 5)
    return "".join(CROCKFORD[int(bits[i : i + 5], 2)] for i in range(0, len(bits), 5))


def nonce(counter):
    return bytes(4) + counter.to_bytes(8, "big")


def pad(kind, payload):
    plaintext = bytes([kind]) + len(payload).to_bytes(2, "big") + payload
    return plaintext + bytes(-len(plaintext) % 64)


class SymmetricState:
    def __init__(self, protocol_name):
        self.h = hashlib.sha256(protocol_name).digest()
        self.ck, self.k, self.n = self.h, None, 0

    def mix_hash(self, data):
        self.h = hashlib.sha256(self.h + data).digest()

    def mix_key(self, ikm):
        out = hkdf(self.ck, ikm, b"", 64)
        self.ck, self.k, self.n = out[:32], out[32:], 0

    def encrypt_and_hash(self, plaintext):
        ciphertext = ChaCha20Poly1305(self.k).encrypt(nonce(self.n), plaintext, self.h)
        self.n += 1
        self.mix_hash(ciphertext)
        return ciphertext

    def split(self):
        out = hkdf(self.ck, b"", b"", 64)
        return out[:32], out[32:]


print("channel.json")

# §11.1 The channel key from the password, and what derives from it.
salt = hashlib.sha256(b"AirChat v1 channel-password").digest()[:16]
key = Argon2id(salt=salt, length=32, iterations=3, lanes=1, memory_cost=65536).derive(vector["password"].encode())
check("channel key (Argon2id)", key, field("channel_key"))
channel_id = hkdf(b"", key, b"AirChat v1 channel-id", 16)
check("channel id", channel_id, field("channel_id"))
presence_key = hkdf(b"", key, b"AirChat v1 channel-presence")
psk = hkdf(b"", key, b"AirChat v1 channel-link-psk")
check("link psk", psk, field("link_psk"))

# §11.2 Beacon token: nonce (4) || HMAC(presence key, label || epoch || nonce)[0..4].
token = field("token")
mac = hmac.new(presence_key, b"AirChat v1 channel-token" + int(vector["token_epoch"]).to_bytes(8, "big") + token[:4], hashlib.sha256)
check("token", token[:4] + mac.digest()[:4], token)

# §11.1 QR code: "AIRCHAT:" || Crockford32(0x00 || 0x02 || key || name).
check("QR text", "AIRCHAT:" + crockford32(b"\x00\x02" + key + "Kamp telsizi".encode()), vector["qr_text"])

# §11.3 Recognition tag, with the channel's tag key.
tag_key = hkdf(b"", psk, b"AirChat v1 channel-tag-key" + channel_id)
tag_nonce = field("tag_nonce")
tag_input = b"AirChat v1 link-tag-mac" + int(vector["tag_epoch"]).to_bytes(8, "big") + tag_nonce
check("tag", tag_nonce + hmac.new(tag_key, tag_input, hashlib.sha256).digest()[:16], field("tag"))

# Handshake. Message 1: header 0x00 0x11, tag, e, AEAD().
m1, m2, m3 = field("message1"), field("message2"), field("message3")
check("message 1 header and length", (m1[:2], len(m1)), (b"\x00\x11", 2 + TAG_LEN + EK_LEN + 16))
state = SymmetricState(b"AirChat v1 link-channel")
state.mix_hash(channel_id)
state.mix_key(psk)
state.mix_hash(m1[:2])
check("message 1 tag", m1[2 : 2 + TAG_LEN], field("tag"))
state.mix_hash(m1[2 : 2 + TAG_LEN])
state.mix_hash(m1[2 + TAG_LEN : 2 + TAG_LEN + EK_LEN])
check("message 1 confirmation", state.encrypt_and_hash(b""), m1[2 + TAG_LEN + EK_LEN :])

# Message 2: header 0x00 0x12, Encaps(e), AEAD(payload).
check("message 2 header", m2[:2], b"\x00\x12")
state.mix_hash(m2[:2])
state.mix_hash(m2[2 : 2 + CT_LEN])
state.mix_key(field("ss"))
check("message 2 payload", state.encrypt_and_hash(pad(0, field("payload2"))), m2[2 + CT_LEN :])

# Message 3: header 0x00 0x13, AEAD(payload).
check("message 3 header", m3[:2], b"\x00\x13")
state.mix_hash(m3[:2])
check("message 3 payload", state.encrypt_and_hash(pad(0, field("payload3"))), m3[2:])
check("handshake hash", state.h, field("handshake_hash"))

# The payloads: device nonce (16) || name length (u8) || name.
burak = bytes([0xD2] * 16) + bytes([5]) + b"Burak"
check("payload 2 (hello)", field("payload2"), burak)
ayse = "Ayşe".encode()
check("payload 3 (hello)", field("payload3"), bytes([0xD3] * 16) + bytes([len(ayse)]) + ayse)

# Records, as on every link (§6.4).
i2r, r2i = state.split()
check("first initiator record", ChaCha20Poly1305(i2r).encrypt(nonce(0), pad(1, b"hello"), b"\x00"), field("record1_initiator_hello"))
check("first responder record", ChaCha20Poly1305(r2i).encrypt(nonce(0), pad(1, b"hi"), b"\x00"), field("record2_responder_hi"))

print("all checks passed" if not failures else f"{failures} check(s) failed")
sys.exit(1 if failures else 0)
