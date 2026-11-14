#!/usr/bin/env python3
"""Independent check of the accounts test vector (docs/protocol.md §13).

Recomputes from the specification alone: the auth key of a password (Argon2id, then HKDF bound to
the server and the name), the fake salt a server gives for a name with no account, and the layout and
signatures of a prelogin, a register, a sign in and a password change on a session.

    python3 check_account.py
"""

import hashlib
import hmac
import json
import pathlib
import struct
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

vector = json.loads(pathlib.Path(__file__).with_name("account.json").read_text())
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


def name(text):
    raw = text.encode()
    return bytes([len(raw)]) + raw


print("account.json")
server, user = vector["server"], vector["name"]
password, salt, params = field("password"), field("salt"), field("params")
memory_kib, iterations, lanes = struct.unpack(">IIB", params)

# §13.2: root = Argon2id(password, salt, params); auth_key = HKDF(info = label || Name(server) || Name(name)).
root = Argon2id(salt=salt, length=32, iterations=iterations, lanes=lanes, memory_cost=memory_kib).derive(password)
auth_key = hkdf(b"", root, b"AirChat v1 account-auth" + name(server) + name(user))
check("auth key", auth_key, field("auth_key"))

# §13.3: fake salt for a name with no account.
fake = hmac.new(field("server_secret"), b"AirChat v1 account-fake-salt" + name("nobody"), hashlib.sha256).digest()[:16]
check("fake salt", fake, field("fake_salt"))

check("prelogin", b"\x00\x70" + name(user), field("prelogin"))

key = Ed25519PrivateKey.from_private_bytes(field("identity_seed"))
ik = key.public_key().public_bytes_raw()


def signed(label, fields):
    return key.sign(label + name(server) + fields)


# §13.4: register = Name(name) || salt || params || auth_key || IK || signature.
fields = name(user) + salt + params + auth_key + ik
check("register", b"\x00\x72" + fields + signed(b"AirChat v1 account-register", fields), field("register"))

# §13.5: sign in = Name(name) || auth_key || IK || nonce || rekey (0x00: none) || signature.
fields = name(user) + auth_key + ik + bytes([0x22] * 32) + b"\x00"
check("sign in", b"\x00\x75" + fields + signed(b"AirChat v1 account-sign-in", fields), field("sign_in"))

# §13.6: authorized = token || nonce || kind 3 || auth_key || salt || params || new auth key || signature.
fields = bytes([0x33] * 32) + bytes([0x44] * 32) + b"\x03" + auth_key + bytes([0x55] * 16) + params + auth_key
check("change password", b"\x00\x77" + fields + signed(b"AirChat v1 account-session", fields), field("change_password"))

sys.exit(1 if failures else 0)
