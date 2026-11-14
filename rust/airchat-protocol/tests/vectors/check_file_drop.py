#!/usr/bin/env python3
"""Independent check of the file drop test vector (docs/protocol.md §18).

Recomputes from the specification alone: the sealing of a 70 000-byte file in 64 KiB chunks (the
last padded with zeros), each chunk under ChaCha20-Poly1305 with nonce = index (u64) || last (u32)
and the offering message's id as associated data; the hash a server keeps of a download token; the
0x63 file drop record; and the download frame. Needs the `cryptography` package.

    python3 check_file_drop.py
"""

import hashlib
import json
import pathlib
import sys

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

CHUNK = 65536

vector = json.loads(pathlib.Path(__file__).with_name("file_drop.json").read_text())
field = lambda name: bytes.fromhex(vector[name])
failures = 0


def check(what, actual, expected):
    global failures
    ok = actual == expected
    failures += not ok
    print(f"{'ok  ' if ok else 'FAIL'} {what}")


def name(text):
    raw = text.encode()
    return bytes([len(raw)]) + raw


print("file_drop.json")
key, message_id = field("key"), field("message_id")
size = int(vector["file_len"])
file = bytes((i * 13) % 256 for i in range(size))

# §18.1: chunks of 64 KiB, the last padded with zeros; at least one.
count = max(1, -(-size // CHUNK))
sealed = b""
for i in range(count):
    chunk = file[i * CHUNK:(i + 1) * CHUNK]
    chunk += bytes(CHUNK - len(chunk))
    nonce = i.to_bytes(8, "big") + (1 if i == count - 1 else 0).to_bytes(4, "big")
    sealed += ChaCha20Poly1305(key).encrypt(nonce, chunk, message_id)
check("sealed length", len(sealed), int(vector["sealed_len"]))
check("sealed content", hashlib.sha256(sealed).digest(), field("sealed_sha256"))
check("last chunk's tag", sealed[-16:], field("last_chunk_tag"))

# §18.2: the server keeps SHA-256("AirChat v1 file-token" || token).
token = bytes([0x74] * 32)
check("token hash", hashlib.sha256(b"AirChat v1 file-token" + token).digest(), field("token_hash"))

# §18.3: 0x63 file drop = reference || Name(server) || file || token || key.
file_id = bytes([0x66] * 16)
record = b"\x63" + message_id + name("chat.example.org") + file_id + token + key
check("file drop record", record, field("drop_record"))

# §18.4: 0xb1 download = version 0x00 || 0xb1 || file || token.
check("download frame", b"\x00\xb1" + file_id + token, field("download"))

sys.exit(1 if failures else 0)
