#!/usr/bin/env python3
"""Independent check of the mail test vector (docs/protocol.md §14).

Recomputes from the specification alone: the static key signatures, a contact request (transcript,
key, card and its proof, padding, AEAD), its accept (tag, transcript, key, card, padding, AEAD) and
the pairing secret, a text mailed to a one-time prekey and its ack mailed to a static key (tag keys,
tags, seal keys, padding to the mail sizes), a delivery key record and its hash, and the deposit and
mailbox frames. X-Wing shared secrets are listed rather than recomputed; the random tag nonces are
regenerated from the listed seeds. Needs the `cryptography` package.

    python3 check_mail.py
"""

import hashlib
import hmac
import json
import pathlib
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

CT_LEN, REQUEST_LEN, MAIL_SIZES = 1120, 4096, (2048, 4096, 16384)

vector = json.loads(pathlib.Path(__file__).with_name("mail.json").read_text())
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


def sha256(*parts):
    return hashlib.sha256(b"".join(parts)).digest()


def name(text):
    raw = text.encode()
    return bytes([len(raw)]) + raw


def u32(n):
    return n.to_bytes(4, "big")


def u64(n):
    return n.to_bytes(8, "big")


def rng(seed, length):
    """The test vectors' randomness: SHA-256(seed || counter), counter a big-endian u64 from 0."""
    out, counter = b"", 0
    while len(out) < length:
        out, counter = out + sha256(seed, u64(counter)), counter + 1
    return out[:length]


def padded(payload, length):
    """len (u16) || payload || zeros, exactly `length` bytes."""
    return len(payload).to_bytes(2, "big") + payload + bytes(length - 2 - len(payload))


def seal(key, plaintext):
    return ChaCha20Poly1305(key).encrypt(bytes(12), plaintext, b"")


def tag(tag_key, nonce):
    return nonce + hmac.new(tag_key, b"AirChat v1 mail-tag-mac" + nonce, hashlib.sha256).digest()[:16]


def mail(tag_, field_, ct, key, payload):
    """tag || field || ct || AEAD(padded), the smallest of the mail sizes that fits."""
    size = next(s for s in MAIL_SIZES if len(payload) + 2 <= s - 32 - 4 - CT_LEN - 16)
    return tag_ + u32(field_) + ct + seal(key, padded(payload, size - 32 - 4 - CT_LEN - 16))


print("mail.json")
server, name_a, name_b = vector["server"], vector["name_a"], vector["name_b"]
key_a = Ed25519PrivateKey.from_private_bytes(field("ik_seed_a"))
key_b = Ed25519PrivateKey.from_private_bytes(field("ik_seed_b"))
ik_a, ik_b = key_a.public_key().public_bytes_raw(), key_b.public_key().public_bytes_raw()
check("identity key a", ik_a, field("ik_a"))
check("identity key b", ik_b, field("ik_b"))
version = int(vector["static_version"])
sk_a, sk_b, dk_a, dk_b = field("sk_a"), field("sk_b"), field("dk_a"), field("dk_b")

# §6.9: signature = Ed25519(IK, "AirChat v1 static-key" || version || SK.pk).
check("static key signature a", key_a.sign(b"AirChat v1 static-key" + u32(version) + sk_a), field("sk_signature_a"))
check("static key signature b", key_b.sign(b"AirChat v1 static-key" + u32(version) + sk_b), field("sk_signature_b"))


def card(key, server_, name_, ik, sk, sk_signature, dk, label, transcript):
    """§14.2: Name(server) || Name(name) || IK || v || SK.pk || sk_signature || dk || proof."""
    fields = name(server_) + name(name_) + ik + u32(version) + sk + sk_signature + dk
    return fields + key.sign(label + transcript + fields)


# §14.2: the request, sealed to B's static key.
request = field("request")
ct_1, ss_1 = request[4 : 4 + CT_LEN], field("request_ss")
h_1 = sha256(b"AirChat v1 mail-request-hash", name(server), name(name_b), ik_b, u32(version), ct_1)
check("request transcript", h_1, field("request_transcript"))
k_1 = hkdf(b"", ss_1, b"AirChat v1 mail-request-key" + h_1)
inner_1 = card(key_a, server, name_a, ik_a, sk_a, field("sk_signature_a"), dk_a, b"AirChat v1 mail-request-proof", h_1)
expected = u32(version) + ct_1 + seal(k_1, padded(inner_1, REQUEST_LEN - 4 - CT_LEN - 16))
check("request", request, expected)

# §14.3: the accept, sealed to A's static key, tagged with a key from the request.
accept = field("accept")
accept_tag = tag(hkdf(b"", ss_1, b"AirChat v1 mail-accept-tag-key" + h_1), rng(field("accept_rng_seed"), 16))
ct_2, ss_2 = accept[36 : 36 + CT_LEN], field("accept_ss")
h_2 = sha256(b"AirChat v1 mail-accept-hash", h_1, ik_a, u32(version), ct_2)
key = hkdf(b"", ss_2, b"AirChat v1 mail-accept-key" + h_2 + accept_tag)
payload = card(key_b, server, name_b, ik_b, sk_b, field("sk_signature_b"), dk_b, b"AirChat v1 mail-accept-proof", h_2)
check("accept", accept, mail(accept_tag, version, ct_2, key, payload))
psk = hkdf(ss_1, ss_2, b"AirChat v1 mail-psk" + h_2)
check("pairing secret", psk, field("psk"))

# §14.3: a text from A to B, sealed to B's prekey 7.
tag_key_ab = hkdf(b"", psk, b"AirChat v1 mail-tag-key" + ik_a + ik_b)
check("tag key a to b", tag_key_ab, field("tag_key_a_to_b"))
text = field("text_payload")
check("text payload", text[0:1] + text[17:25], b"\x01" + (1_794_600_000_000).to_bytes(8, "big"))
sent = field("mail")
mail_tag = tag(tag_key_ab, rng(field("mail_rng_seed"), 16))
ct = sent[36 : 36 + CT_LEN]
key = hkdf(psk, field("mail_ss"), b"AirChat v1 mail-seal" + ik_a + ik_b + mail_tag + u32(7))
check("text mail", sent, mail(mail_tag, 7, ct, key, text))

# Its ack from B to A, sealed to A's static key (field 0).
ack, ack_mail = field("ack_payload"), field("ack_mail")
check("ack payload", ack, b"\x02" + text[1:17])
tag_key_ba = hkdf(b"", psk, b"AirChat v1 mail-tag-key" + ik_b + ik_a)
ack_tag = tag(tag_key_ba, rng(field("ack_rng_seed"), 16))
key = hkdf(psk, field("ack_ss"), b"AirChat v1 mail-seal" + ik_b + ik_a + ack_tag + u32(0))
check("ack mail", ack_mail, mail(ack_tag, 0, ack_mail[36 : 36 + CT_LEN], key, ack))

# §14.4: delivery keys.
check("delivery key record", field("delivery_key_record"), b"\x61" + bytes([0x0D] * 32))
check("delivery key hash", sha256(b"AirChat v1 mail-delivery-key", dk_b), field("delivery_key_hash_b"))

# §14.5, §14.6: deposits and mailbox frames.
check("deposit", field("deposit"), b"\x00\x82" + name(name_b) + dk_b + sent)
check("deposit request", field("deposit_request"), b"\x00\x83" + name(name_b) + request)
check("mail frame", field("mail_frame"), b"\x00\x90" + u64(42) + sent)
check("taken frame", field("taken_frame"), b"\x00\x92" + u64(42))

sys.exit(1 if failures else 0)
