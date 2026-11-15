#!/usr/bin/env python3
"""Independent check of the group call test vector (docs/protocol.md §17.2).

Recomputes from the specification alone: the key of a group call's room from the epoch key, and a
frame of the room: origin (8) || counter (u32) || ChaCha20-Poly1305(key, nonce = origin || counter,
aad = "", len (u16) || record || zeros to a multiple of 64). Needs the `cryptography` package.

    python3 check_group_call.py
"""

import hashlib
import hmac
import json
import pathlib
import sys

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

vector = json.loads(pathlib.Path(__file__).with_name("group_call.json").read_text())
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


print("group_call.json")
epoch_key, group_id, stream = field("epoch_key"), field("group_id"), field("stream")
epoch = int(vector["epoch"]).to_bytes(8, "big")
key = hkdf(b"", epoch_key, b"AirChat v1 group-call-key" + group_id + epoch + stream)
check("call key", key, field("call_key"))

# §9.6: 0x38 group call = stream id || group_id.
record = b"\x38" + stream + group_id
check("record", record, field("record"))

origin, counter = bytes([0x0A] * 8), (7).to_bytes(4, "big")
padded = len(record).to_bytes(2, "big") + record
padded += bytes(-len(padded) % 64)
frame = origin + counter + ChaCha20Poly1305(key).encrypt(origin + counter, padded, b"")
check("frame", frame, field("frame"))

sys.exit(1 if failures else 0)
