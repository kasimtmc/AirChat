#!/usr/bin/env python3
"""Independent check of the pairing test vectors (docs/protocol.md §4.7).

Recomputes everything except the KEM operations, whose shared secrets the vectors list, from the
specification alone: QR invite, transcript, commitment, emoji, link key, and the contact cards
including both Ed25519 signatures. Needs the `cryptography` package.

    python3 check_pairing.py
"""

import hashlib
import hmac
import json
import pathlib
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

EK_LEN, CT_LEN, TAG = 1216, 1120, 16
CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
SAS_EMOJI = (
    "🐶🐱🦁🐴🦄🐷🐘🐰🐼🐔🐧🐢🐟🐙🦋🌻🌳🌵🍄🌍🌙🌈🔥🍌🍎🍓🌽🍕🎂🍇😀🤖"
    "🎩👓🔧🐝👍🌂⌛⏰🎁💡📕🔦📎🧲🔒🔑🔨📞🚩🚂🚲🚁🚀🏆⚽🎸🎺🔔⚓🎧📁📌"
)
here = pathlib.Path(__file__).parent
failures = 0


def check(what, actual, expected):
    global failures
    ok = actual == expected
    failures += not ok
    print(f"  {'ok  ' if ok else 'FAIL'} {what}")


def sha256(*parts):
    return hashlib.sha256(b"".join(parts)).digest()


def hkdf(salt, ikm, info, length):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out, counter = out + block, counter + 1
    return out[:length]


def nonce(counter):
    return bytes(4) + counter.to_bytes(8, "big")


def rng_stream(seed, length):
    """SHA-256(seed || counter) blocks, counter a big-endian u64 from 0."""
    out, counter = b"", 0
    while len(out) < length:
        out, counter = out + sha256(seed, counter.to_bytes(8, "big")), counter + 1
    return out[:length]


class SymmetricState:
    def __init__(self, name):
        self.h = sha256(name)
        self.ck, self.k, self.n = self.h, None, 0

    def mix_hash(self, data):
        self.h = sha256(self.h, data)

    def mix_key(self, ikm):
        out = hkdf(self.ck, ikm, b"", 64)
        self.ck, self.k, self.n = out[:32], out[32:], 0

    def encrypt_and_hash(self, plaintext):
        c = ChaCha20Poly1305(self.k).encrypt(nonce(self.n), plaintext, self.h)
        self.n += 1
        self.mix_hash(c)
        return c

    def decrypt_and_hash(self, ciphertext):
        p = ChaCha20Poly1305(self.k).decrypt(nonce(self.n), ciphertext, self.h)
        self.n += 1
        self.mix_hash(ciphertext)
        return p

    def split(self):
        out = hkdf(self.ck, b"", b"", 64)
        return out[:32], out[32:]

    def export(self, label):
        return hkdf(self.ck, b"", label, 32)


def check_card(what, record, key, h, v, role, counter=0):
    plaintext = ChaCha20Poly1305(key).decrypt(nonce(counter), record, b"\x00")
    kind, length = plaintext[0], int.from_bytes(plaintext[1:3], "big")
    card, padding = plaintext[3 : 3 + length], plaintext[3 + length :]
    check(f"{what}: record type, padding", (kind, len(plaintext) % 64, set(padding) <= {0}), (1, 0, True))
    check(f"{what}: message kind, version", card[:2], b"\x01\x00")
    ik, rest = card[2:34], card[34:]
    static_kem, rest = rest[:EK_LEN], rest[EK_LEN:]
    card_sig, presence, rest = rest[:64], rest[64:96], rest[96:]
    name_len = int.from_bytes(rest[:2], "big")
    name, proof = rest[2 : 2 + name_len], rest[2 + name_len :]
    check(f"{what}: identity, static KEM, presence key, name", (ik, static_kem, presence, name), (
        bytes.fromhex(v[f"{role}_identity"]),
        bytes.fromhex(v[f"{role}_static_kem"]),
        bytes.fromhex(v[f"{role}_presence_key"]),
        bytes.fromhex(v[f"{role}_name"]),
    ))
    key_obj = Ed25519PublicKey.from_public_bytes(ik)
    try:
        key_obj.verify(card_sig, b"AirChat v1 contact-card" + static_kem)
        key_obj.verify(proof, b"AirChat v1 pairing-proof" + h)
        check(f"{what}: card signature and session proof", True, True)
    except Exception:
        check(f"{what}: card signature and session proof", False, True)


def check_nearby(v):
    print("nearby:")
    f = lambda name: bytes.fromhex(v[name])
    m1, m2, m3, m4 = f("message1"), f("message2"), f("message3"), f("message4")
    check("message 1 layout", (m1[:3], len(m1)), (b"\x00\x21\x01", 3 + EK_LEN))
    s = SymmetricState(b"AirChat v1 pairing-protocol")
    s.mix_hash(m1[:3])
    s.mix_hash(m1[3:])
    check("message 2 layout", (m2[:2], len(m2)), (b"\x00\x22", 2 + CT_LEN + 32 + TAG))
    s.mix_hash(m2[:2])
    s.mix_hash(m2[2 : 2 + CT_LEN])
    s.mix_key(f("ss"))
    commitment = s.decrypt_and_hash(m2[2 + CT_LEN :])
    s.mix_hash(m3[:2])
    nonce_i = s.decrypt_and_hash(m3[2:])
    s.mix_hash(m4[:2])
    nonce_r = s.decrypt_and_hash(m4[2:])
    check("headers of messages 3 and 4", (m3[:2], m4[:2]), (b"\x00\x23", b"\x00\x24"))
    check("commitment opens to the responder nonce", commitment, sha256(b"AirChat v1 pairing-commit", nonce_r))
    check("initiator nonce is its second 32 random bytes", nonce_i, rng_stream(f("initiator_rng_seed"), 64)[32:])
    check("responder nonce follows its 64 encapsulation bytes", nonce_r, rng_stream(f("responder_rng_seed"), 96)[64:])

    bits = int.from_bytes(sha256(b"AirChat v1 pairing-sas", s.h, nonce_i, nonce_r)[:4], "big")
    indices = bytes((bits >> (26 - 6 * i)) & 63 for i in range(5))
    check("emoji indices", indices, f("sas_indices"))
    check("emoji", "".join(SAS_EMOJI[i] for i in indices), v["sas_emoji"])

    k_i2r, k_r2i = s.split()
    check("link pre-shared key", s.export(b"AirChat v1 pairing-link-psk"), f("link_psk"))
    check_card("initiator card", f("initiator_card_record"), k_i2r, s.h, v, "initiator")
    check_card("responder card", f("responder_card_record"), k_r2i, s.h, v, "responder")


def check_invite(v):
    print("invite:")
    f = lambda name: bytes.fromhex(v[name])
    qr = v["qr_text"]
    check("QR prefix", qr[:8], "AIRCHAT:")
    bits = "".join(format(CROCKFORD.index(c), "05b") for c in qr[8:])
    payload = int(bits[: len(bits) // 8 * 8], 2).to_bytes(len(bits) // 8, "big")
    secret = payload[34:]
    check("QR payload: version, kind, identity", (payload[:2], payload[2:34]), (b"\x00\x01", f("responder_identity")))
    check("invite secret is the first 16 random bytes", secret, rng_stream(f("invite_rng_seed"), 16))

    invite_id = hkdf(b"", secret, b"AirChat v1 pairing-invite-id", 8)
    psk = hkdf(b"", secret, b"AirChat v1 pairing-invite-psk", 32)
    m1, m2 = f("message1"), f("message2")
    check("message 1 layout and invite id", (m1[:3], m1[3:11], len(m1)), (b"\x00\x21\x02", invite_id, 11 + EK_LEN))
    check("beacon token is the invite id's first 4 bytes", invite_id[:4], f("beacon_token"))
    s = SymmetricState(b"AirChat v1 pairing-protocol")
    s.mix_hash(m1[:11])
    s.mix_hash(m1[11:])
    s.mix_key(psk)
    check("message 2 layout", (m2[:2], len(m2)), (b"\x00\x22", 2 + CT_LEN + TAG))
    s.mix_hash(m2[:2])
    s.mix_hash(m2[2 : 2 + CT_LEN])
    s.mix_key(f("ss"))
    check("message 2 confirmation", s.encrypt_and_hash(b""), m2[2 + CT_LEN :])

    k_i2r, k_r2i = s.split()
    check("link pre-shared key", s.export(b"AirChat v1 pairing-link-psk"), f("link_psk"))
    check_card("responder card", f("responder_card_record"), k_r2i, s.h, v, "responder")
    check_card("initiator card", f("initiator_card_record"), k_i2r, s.h, v, "initiator")


def check_request(v):
    print("request:")
    f = lambda name: bytes.fromhex(v[name])
    # §4.2: the typed ID names the initiator's identity key; §4.8: the token and key come from it.
    ik = f("initiator_identity")
    id_bytes = sha256(b"AirChat v1 airchat-id", ik)[:15]
    symbols = v["airchat_id"].removeprefix("AIR-").replace("-", "")[:24]
    typed = sum(CROCKFORD.index(c) << (5 * (23 - i)) for i, c in enumerate(symbols)).to_bytes(15, "big")
    check("the typed ID names the initiator", typed, id_bytes)
    request_key = hkdf(b"", id_bytes, b"AirChat v1 id-request-key", 32)
    epoch = int(v["epoch"]).to_bytes(8, "big")
    token = hmac.new(request_key, b"AirChat v1 id-request-token" + epoch, hashlib.sha256).digest()[:8]
    check("request token", token, f("request_token"))
    psk = hkdf(b"", id_bytes, b"AirChat v1 id-request-psk", 32)

    m1, m2 = f("message1"), f("message2")
    check("message 1 layout and token", (m1[:3], m1[3:11], len(m1)), (b"\x00\x21\x03", token, 11 + EK_LEN))
    s = SymmetricState(b"AirChat v1 pairing-protocol")
    s.mix_hash(m1[:11])
    s.mix_hash(m1[11:])
    s.mix_key(psk)
    check("message 2 layout", (m2[:2], len(m2)), (b"\x00\x22", 2 + CT_LEN + TAG))
    s.mix_hash(m2[:2])
    s.mix_hash(m2[2 : 2 + CT_LEN])
    s.mix_key(f("ss"))
    check("message 2 confirmation", s.encrypt_and_hash(b""), m2[2 + CT_LEN :])

    k_i2r, k_r2i = s.split()
    check("link pre-shared key", s.export(b"AirChat v1 pairing-link-psk"), f("link_psk"))
    # The initiator's first record proves its identity key and nothing more.
    plaintext = ChaCha20Poly1305(k_i2r).decrypt(nonce(0), f("initiator_identity_record"), b"\x00")
    length = int.from_bytes(plaintext[1:3], "big")
    record = plaintext[3 : 3 + length]
    check("identity record: type, kind, version, key", (plaintext[0], record[:2], record[2:34], len(record)), (1, b"\x02\x00", ik, 2 + 32 + 64))
    try:
        Ed25519PublicKey.from_public_bytes(ik).verify(record[34:], b"AirChat v1 pairing-proof" + s.h)
        check("identity record: session proof", True, True)
    except Exception:
        check("identity record: session proof", False, True)
    check_card("responder card", f("responder_card_record"), k_r2i, s.h, v, "responder")
    check_card("initiator card", f("initiator_card_record"), k_i2r, s.h, v, "initiator", counter=1)


check_nearby(json.loads((here / "pairing_nearby.json").read_text()))
check_invite(json.loads((here / "pairing_invite.json").read_text()))
check_request(json.loads((here / "pairing_request.json").read_text()))
print("all checks passed" if not failures else f"{failures} check(s) failed")
sys.exit(1 if failures else 0)
