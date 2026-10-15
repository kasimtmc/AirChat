#!/usr/bin/env python3
"""Independent check of the mesh test vector (docs/protocol.md §10).

Recomputes from the specification alone: envelope tags for a contact and a group, envelope ids, a
1:1 envelope's drop, its sealing to a one-time prekey (key schedule, padding, AEAD), the envelope,
*have*, *withdraw*, *prekeys* and *prekeys wanted* records, a mesh file offer and a file part
envelope, a mesh update key and an update part envelope, a group file part envelope, and the mesh
link handshake's transcript, key schedule, ciphertexts and first records.
X-Wing shared secrets are listed rather than recomputed. Needs the `cryptography` package (ChaCha20-Poly1305).

    python3 check_mesh.py
"""

import hashlib
import hmac
import json
import pathlib
import sys

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

TAG_LEN, EK_LEN, CT_LEN = 32, 1216, 1120

vector = json.loads(pathlib.Path(__file__).with_name("mesh.json").read_text())
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


def u32(n):
    return n.to_bytes(4, "big")


def u64(n):
    return n.to_bytes(8, "big")


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


print("mesh.json")
ik_a, ik_b, psk = field("ik_a"), field("ik_b"), field("psk")
epoch = int(vector["epoch"])
message_id = field("message_id")

# §10.3 Tags: HKDF of the pairing secret for the direction a → b, then an HMAC per hour.
tag_key = hkdf(b"", psk, b"AirChat v1 mesh-tag-key" + ik_a + ik_b)
check("tag key a -> b", tag_key, field("tag_key"))
tag = hmac.new(tag_key, b"AirChat v1 mesh-tag" + u64(epoch), hashlib.sha256).digest()[:16]
check("tag", tag, field("tag"))

# The payload is a §8.1 text message: 0x01 || message id || sent at (u64, ms) || UTF-8 text.
payload = field("payload")
check("payload (text)", payload, bytes([0x01]) + message_id + u64(1_791_400_000_000) + "köprüden selam".encode())

# Ids: the same each time the same thing is sent again.
envelope_id = hashlib.sha256(b"AirChat v1 mesh-envelope" + ik_a + ik_b + bytes([0x01]) + message_id).digest()[:16]
check("envelope id", envelope_id, field("envelope_id"))

# §10.3 Drop: a secret only the two contacts can make, and the envelope commits to it.
drop_secret = hkdf(b"", psk, b"AirChat v1 mesh-drop-secret" + ik_a + ik_b + envelope_id)[:16]
check("drop secret", drop_secret, field("drop_secret"))
drop = hashlib.sha256(b"AirChat v1 mesh-drop" + drop_secret).digest()[:16]
check("drop", drop, field("drop"))

# The envelope record: 0x50 || id || hops || expires (u32, minutes) || tag || drop || body.
record = field("envelope_record")
expires = int(vector["expires"])
check("record kind", record[0], 0x50)
check("envelope id in record", record[1:17], envelope_id)
check("hops", record[17], 8)
check("expires", record[18:22], u32(expires))
check("tag in record", record[22:38], tag)
check("drop in record", record[38:54], drop)
body = record[54:]

# §10.3 Body: the prekey it is sealed to, the X-Wing ciphertext to that key, then the padded
# payload sealed with a key that binds the pairing secret, both identities, the id, the tag, the
# expiry, the drop and the prekey.
prekey = int(vector["prekey"])
check("prekey in body", body[:4], u32(prekey))
body = body[4:]
ss = field("ss")
key = hkdf(psk, ss, b"AirChat v1 mesh-seal" + ik_a + ik_b + envelope_id + tag + u32(expires) + drop + u32(prekey))
padded = len(payload).to_bytes(2, "big") + payload
padded += bytes(-len(padded) % 256)
check("padding to 256 bytes", len(padded), 256)
sealed = ChaCha20Poly1305(key).encrypt(bytes(12), padded, b"")
check("body length", len(body), CT_LEN + len(sealed))
check("sealed payload", body[CT_LEN:], sealed)

# §10.4 have: 0x51 || short ids (the first 8 bytes of envelope ids).
check("have record", field("have_record"), bytes([0x51]) + envelope_id[:8] + bytes([0x22] * 8))
# §10.4 withdraw: 0x59 || id || drop secret.
check("withdraw record", field("withdraw_record"), bytes([0x59]) + envelope_id + drop_secret)
# §10.7 prekeys: 0x5a || (prekey (u32) || encapsulation key (1216))*; prekeys wanted: 0x5b || count.
check("prekeys record", field("prekeys_record"), bytes([0x5A]) + u32(prekey) + field("prekey_key"))
check("prekeys wanted record", field("prekeys_wanted_record"), bytes([0x5B, 5]))

# §10.8 Files through the mesh. The offer: 0x24 || id || sent at || key || file (as in 0x20, §8.4).
file_message, file_key, content = field("file_message_id"), field("file_key"), b"selam"
name, mime = b"not.txt", b"text/plain"
file_meta = u64(len(content)) + hashlib.sha256(content).digest() + bytes([len(mime)]) + mime + bytes([len(name)]) + name + bytes(2)
check("mesh file offer payload", field("file_offer_payload"), bytes([0x24]) + file_message + u64(1_791_400_000_000) + file_key + file_meta)
# A part: its id, tag and drop, then its bytes padded and sealed with the file's key.
part_id = hashlib.sha256(b"AirChat v1 mesh-file-part" + ik_a + ik_b + file_message + u32(0)).digest()[:16]
file_tag_key = hkdf(b"", psk, b"AirChat v1 mesh-file-tag-key" + ik_a + ik_b)
part_tag = hmac.new(file_tag_key, b"AirChat v1 mesh-tag" + u64(epoch), hashlib.sha256).digest()[:16]
part_drop = hashlib.sha256(b"AirChat v1 mesh-drop" + hkdf(b"", psk, b"AirChat v1 mesh-drop-secret" + ik_a + ik_b + part_id)[:16]).digest()[:16]
part = field("file_part_record")
check("part record header", part[:54], bytes([0x50]) + part_id + bytes([8]) + u32(expires) + part_tag + part_drop)
check("part tag differs from the text tag", part_tag != tag, True)
padded = len(content).to_bytes(2, "big") + content
padded += bytes(-len(padded) % 256)
part_body = ChaCha20Poly1305(file_key).encrypt(bytes(8) + u32(0), padded, part_id + u32(expires) + part_drop)
check("part body", part[54:], part_body)

# §10.9 Group updates through the mesh, for an update of group epoch 4 (its bytes stand in for a
# real update: 700 bytes of 0x75). Keys come from the epoch key before.
u16 = lambda n: n.to_bytes(2, "big")
update_key_epoch, group, update = field("update_epoch_key"), field("group_id"), bytes([0x75] * 700)
update_id = hashlib.sha256(update).digest()[:16]
check("update id", update_id, field("update_id"))
update_tag_key = hkdf(b"", update_key_epoch, b"AirChat v1 mesh-update-tag-key" + group + u64(4))
base = hkdf(b"", update_key_epoch, b"AirChat v1 mesh-update-key" + group + u64(4))
update_key = hkdf(b"", base, b"AirChat v1 mesh-update-part-key" + update_id)
check("mesh update key payload", field("update_key_payload"), bytes([0x25]) + group + u64(4) + update_id + u16(1) + update_key)
update_part_id = hashlib.sha256(b"AirChat v1 mesh-update-part" + group + update_id + u16(0)).digest()[:16]
update_tag = hmac.new(update_tag_key, b"AirChat v1 mesh-tag" + u64(epoch), hashlib.sha256).digest()[:16]
part = field("update_part_record")
check("update part header", part[:54], bytes([0x50]) + update_part_id + bytes([8]) + u32(expires) + update_tag + bytes(16))
header = update_id + u16(0) + u16(1)
padded = len(update).to_bytes(2, "big") + update
padded += bytes(-len(padded) % 256)
sealed = ChaCha20Poly1305(update_key).encrypt(bytes(8) + u32(0), padded, update_part_id + header)
check("update part body", part[54:], header + sealed)

# Groups: the tag key comes from the epoch key; the id from the group and the message.
group_id = field("group_id")
group_tag_key = hkdf(b"", field("group_epoch_key"), b"AirChat v1 mesh-group-tag-key" + group_id + u64(int(vector["group_epoch"])))
group_tag = hmac.new(group_tag_key, b"AirChat v1 mesh-tag" + u64(epoch), hashlib.sha256).digest()[:16]
check("group tag", group_tag, field("group_tag"))
group_envelope_id = hashlib.sha256(b"AirChat v1 mesh-envelope" + group_id + message_id).digest()[:16]
check("group envelope id", group_envelope_id, field("group_envelope_id"))

# §10.10 A group file's part: keys from the epoch key, for the file of message file_message_id
# ("selam", part 0).
group_epoch_key, group_epoch = field("group_epoch_key"), u64(int(vector["group_epoch"]))
file_tag = hmac.new(hkdf(b"", group_epoch_key, b"AirChat v1 mesh-group-file-tag-key" + group_id + group_epoch),
                    b"AirChat v1 mesh-tag" + u64(epoch), hashlib.sha256).digest()[:16]
group_file_key = hkdf(b"", group_epoch_key, b"AirChat v1 mesh-group-file-key" + group_id + group_epoch + file_message)
group_part_id = hashlib.sha256(b"AirChat v1 mesh-group-file-part" + group_id + file_message + u32(0)).digest()[:16]
group_part = field("group_file_part_record")
check("group file part header", group_part[:54], bytes([0x50]) + group_part_id + bytes([8]) + u32(expires) + file_tag + bytes(16))
padded = len(content).to_bytes(2, "big") + content
padded += bytes(-len(padded) % 256)
check("group file part body", group_part[54:], ChaCha20Poly1305(group_file_key).encrypt(bytes(8) + u32(0), padded, group_part_id))

# §10.2 Mesh link: the channel handshake (§11.3) under a public channel, messages 0x31 to 0x33.
channel_id = hashlib.sha256(b"AirChat v1 mesh-id").digest()[:16]
link_psk = hashlib.sha256(b"AirChat v1 mesh-psk").digest()
m1, m2, m3 = field("link_message1"), field("link_message2"), field("link_message3")
check("message 1 header and length", (m1[:2], len(m1)), (b"\x00\x31", 2 + TAG_LEN + EK_LEN + 16))
check("message 1 tag (random)", m1[2 : 2 + TAG_LEN], field("link_tag"))
state = SymmetricState(b"AirChat v1 link-mesh")
state.mix_hash(channel_id)
state.mix_key(link_psk)
state.mix_hash(m1[:2])
state.mix_hash(m1[2 : 2 + TAG_LEN])
state.mix_hash(m1[2 + TAG_LEN : 2 + TAG_LEN + EK_LEN])
check("message 1 confirmation", state.encrypt_and_hash(b""), m1[2 + TAG_LEN + EK_LEN :])
check("message 2 header", m2[:2], b"\x00\x32")
state.mix_hash(m2[:2])
state.mix_hash(m2[2 : 2 + CT_LEN])
state.mix_key(field("link_ss"))
check("message 2 payload (device nonce)", state.encrypt_and_hash(pad(0, bytes([0xD2] * 16))), m2[2 + CT_LEN :])
check("message 3 header", m3[:2], b"\x00\x33")
state.mix_hash(m3[:2])
check("message 3 payload (device nonce)", state.encrypt_and_hash(pad(0, bytes([0xD3] * 16))), m3[2:])
check("handshake hash", state.h, field("link_handshake_hash"))
i2r, r2i = state.split()
check("first initiator record", ChaCha20Poly1305(i2r).encrypt(nonce(0), pad(1, b"hello"), b"\x00"), field("link_record1_initiator_hello"))
check("first responder record", ChaCha20Poly1305(r2i).encrypt(nonce(0), pad(1, b"hi"), b"\x00"), field("link_record2_responder_hi"))

print("all checks passed" if not failures else f"{failures} check(s) failed")
sys.exit(1 if failures else 0)
