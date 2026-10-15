#!/usr/bin/env python3
"""Independent check of the paths test vector (docs/protocol.md §12).

Recomputes from the specification alone: the tag on a request from a to b, the proof in b's answer,
the layout of every path record (offer, request, answer, open, data, credit, close), and a
walkie-talkie channel's path key with its tag and proof, a cluster's request nonce and a channel
head record (§11.5), and the path key of an AirChat ID with its tag and proof (§4.8).

    python3 check_paths.py
"""

import hashlib
import hmac
import json
import pathlib
import sys

vector = json.loads(pathlib.Path(__file__).with_name("paths.json").read_text())
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


print("paths.json")
ik_a, ik_b, psk = field("ik_a"), field("ik_b"), field("psk")
path, nonce = field("path"), field("nonce")

# §12.2: tag_key is that of §10.3, for each direction.
tag_key_ab = hkdf(b"", psk, b"AirChat v1 mesh-tag-key" + ik_a + ik_b)
tag_key_ba = hkdf(b"", psk, b"AirChat v1 mesh-tag-key" + ik_b + ik_a)
tag = hmac.new(tag_key_ab, b"AirChat v1 path-tag" + nonce, hashlib.sha256).digest()[:16]
check("request tag (a -> b)", tag, field("tag"))
proof = hmac.new(tag_key_ba, b"AirChat v1 path-answer" + path + nonce, hashlib.sha256).digest()[:16]
check("answer proof (b -> a)", proof, field("proof"))

# §12.1 and §12.3: the records, kind byte first.
VOICE, VIDEO, FILES = 0x01, 0x02, 0x04
check("offer: voice and video", field("offer_record"), bytes([0x52, VOICE | VIDEO]))
check("request: video, 2 providers", field("request_record"), bytes([0x53]) + path + bytes([VIDEO, 2]) + nonce + tag)
check("answer: through 1 provider", field("answer_record"), bytes([0x54]) + path + bytes([1]) + proof)
check("open", field("open_record"), bytes([0x55]) + path + proof)
check("data: the last piece of a frame", field("data_record"), bytes([0x56]) + path + bytes([0]) + b"frame")
check("credit: 8 KiB", field("credit_record"), bytes([0x57]) + path + (8192).to_bytes(4, "big"))
check("close", field("close_record"), bytes([0x58]) + path)

# §11.5: a walkie-talkie channel's path key, from its key: the link psk and id as in §11.1.
channel_key = field("channel_key")
link_psk = hkdf(b"", channel_key, b"AirChat v1 channel-link-psk")
channel_id = hkdf(b"", channel_key, b"AirChat v1 channel-id", 16)
path_key = hkdf(b"", link_psk, b"AirChat v1 channel-path-key" + channel_id)
check("channel path key", path_key, field("channel_path_key"))
check("channel request tag", hmac.new(path_key, b"AirChat v1 path-tag" + nonce, hashlib.sha256).digest()[:16], field("channel_tag"))
check(
    "channel answer proof",
    hmac.new(path_key, b"AirChat v1 path-answer" + path + nonce, hashlib.sha256).digest()[:16],
    field("channel_proof"),
)

# §11.5: a cluster's request nonce (random half, then a MAC over the head's device nonce), and the
# channel head record: 0x3d || device nonce || seq (u32).
head, cluster_random = field("channel_head"), field("cluster_random")
cluster_mac = hmac.new(path_key, b"AirChat v1 channel-cluster" + head + cluster_random, hashlib.sha256).digest()[:8]
check("cluster nonce", cluster_random + cluster_mac, field("cluster_nonce"))
check("channel head record", field("channel_head_record"), bytes([0x3D]) + head + (42).to_bytes(4, "big"))

# §12.2: a path to the owner of an AirChat ID (§4.8), from the ID's 15 bytes; one key, for tags and
# proofs alike. The ID is ik_b's: SHA-256("AirChat v1 airchat-id" || IK)[0..15] (§4.2).
airchat_id = field("id")
check("id is ik_b's", hashlib.sha256(b"AirChat v1 airchat-id" + ik_b).digest()[:15], airchat_id)
id_path_key = hkdf(b"", airchat_id, b"AirChat v1 id-request-path-key")
check("id path key", id_path_key, field("id_path_key"))
check("id request tag", hmac.new(id_path_key, b"AirChat v1 path-tag" + nonce, hashlib.sha256).digest()[:16], field("id_tag"))
check(
    "id answer proof",
    hmac.new(id_path_key, b"AirChat v1 path-answer" + path + nonce, hashlib.sha256).digest()[:16],
    field("id_proof"),
)

print("all checks passed" if not failures else f"{failures} check(s) failed")
sys.exit(1 if failures else 0)
