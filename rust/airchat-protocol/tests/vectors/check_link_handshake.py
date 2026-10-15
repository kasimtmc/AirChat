#!/usr/bin/env python3
"""Independent check of the contact link handshake test vector (docs/protocol.md §6.6).

Recomputes everything except the KEM operations, whose shared secrets the vector lists, from the
specification alone: the recognition tag, transcript hash, key schedule, handshake ciphertexts, the
next link key and the first record in each direction. Needs the `cryptography` package for ChaCha20-Poly1305.

    python3 check_link_handshake.py
"""

import hashlib
import hmac
import json
import pathlib
import sys

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

TAG_LEN, EK_LEN, CT_LEN = 32, 1216, 1120

vector = json.loads(pathlib.Path(__file__).with_name("link_contact_handshake.json").read_text())
field = lambda name: bytes.fromhex(vector[name])
failures = 0


def check(what, actual, expected):
    global failures
    ok = actual == expected
    failures += not ok
    print(f"{'ok  ' if ok else 'FAIL'} {what}")


def hkdf(salt, ikm, info, length):
    """RFC 5869 with SHA-256."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out, counter = out + block, counter + 1
    return out[:length]


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


ik_i, sk_i = field("initiator_identity"), field("initiator_static_kem")
ik_r, sk_r = field("responder_identity"), field("responder_static_kem")
psk = field("link_psk")
m1, m2, m3 = field("message1"), field("message2"), field("message3")

# §6.2 Recognition tag: nonce || HMAC(tag_key, label || epoch || nonce), truncated to 16 bytes.
tag_key = hkdf(b"", psk, b"AirChat v1 link-tag-key" + ik_i + ik_r, 32)
tag_nonce = field("tag_nonce")
tag_input = b"AirChat v1 link-tag-mac" + int(vector["tag_epoch"]).to_bytes(8, "big") + tag_nonce
check("tag", tag_nonce + hmac.new(tag_key, tag_input, hashlib.sha256).digest()[:16], field("tag"))

# §6.3 Message 1: header, tag, e, Encaps(SK_r), AEAD().
check("message 1 header and length", (m1[:2], len(m1)), (b"\x00\x01", 2 + TAG_LEN + EK_LEN + CT_LEN + 16))
tag, rest = m1[2 : 2 + TAG_LEN], m1[2 + TAG_LEN :]
ephemeral, ct1, confirmation = rest[:EK_LEN], rest[EK_LEN : EK_LEN + CT_LEN], rest[EK_LEN + CT_LEN :]
check("message 1 tag", tag, field("tag"))

state = SymmetricState(b"AirChat v1 link-contact")
for key in (ik_i, sk_i, ik_r, sk_r):
    state.mix_hash(key)
state.mix_key(psk)
state.mix_hash(m1[:2])
state.mix_hash(tag)
state.mix_hash(ephemeral)
state.mix_hash(ct1)
state.mix_key(field("ss1"))
check("message 1 confirmation", state.encrypt_and_hash(b""), confirmation)

# Message 2: header, Encaps(e), Encaps(SK_i), AEAD(payload).
check("message 2 header", m2[:2], b"\x00\x02")
ct2, ct3, sealed2 = m2[2 : 2 + CT_LEN], m2[2 + CT_LEN : 2 + 2 * CT_LEN], m2[2 + 2 * CT_LEN :]
state.mix_hash(m2[:2])
state.mix_hash(ct2)
state.mix_key(field("ss2"))
state.mix_hash(ct3)
state.mix_key(field("ss3"))
check("message 2 payload", state.encrypt_and_hash(pad(0, field("payload2"))), sealed2)

# Message 3: header, AEAD(payload).
check("message 3 header", m3[:2], b"\x00\x03")
state.mix_hash(m3[:2])
check("message 3 payload", state.encrypt_and_hash(pad(0, field("payload3"))), m3[2:])
check("handshake hash", state.h, field("handshake_hash"))

# §6.8 The link key that follows.
check("next link key", hkdf(state.ck, b"", b"AirChat v1 link-key-next", 32), field("next_link_key"))

# §6.4 Records.
initiator_to_responder, responder_to_initiator = state.split()
record1 = ChaCha20Poly1305(initiator_to_responder).encrypt(nonce(0), pad(1, b"hello"), b"\x00")
record2 = ChaCha20Poly1305(responder_to_initiator).encrypt(nonce(0), pad(1, b"hi"), b"\x00")
check("first initiator record", record1, field("record1_initiator_hello"))
check("first responder record", record2, field("record2_responder_hi"))

print("all checks passed" if not failures else f"{failures} check(s) failed")
sys.exit(1 if failures else 0)
