#!/usr/bin/env python3
"""Makes the build attestation test vector (docs/protocol.md §6.10): a chain like an Android key
attestation's, under a test root instead of Google's. Run once; signatures are random, so running
it again gives another, equally valid, vector. The core checks it (attest::tests), and
check_attestation.py checks it again from the specification.

    python3 make_attestation.py

Needs the `cryptography` package.
"""

import datetime
import hashlib
import json
import pathlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID


def der(tag_class, constructed, number, content):
    first = (tag_class << 6) | (0x20 if constructed else 0)
    if number < 31:
        head = bytes([first | number])
    else:
        digits = []
        while True:
            digits.insert(0, number & 0x7F)
            number >>= 7
            if not number:
                break
        head = bytes([first | 0x1F] + [d | 0x80 for d in digits[:-1]] + [digits[-1]])
    n = len(content)
    if n < 0x80:
        length = bytes([n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return head + length + content


def integer(value):
    raw = value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big")
    return der(0, False, 2, raw)


def enumerated(value):
    return der(0, False, 10, integer(value)[2:])


def octets(value):
    return der(0, False, 4, value)


def boolean(value):
    return der(0, False, 1, b"\xff" if value else b"\x00")


def sequence(*items):
    return der(0, True, 16, b"".join(items))


def set_of(*items):
    return der(0, True, 17, b"".join(sorted(items)))


def tagged(number, value):
    return der(2, True, number, value)


def key_description(challenge, package, signer, locked):
    application = sequence(set_of(sequence(octets(package), integer(1))), set_of(octets(signer)))
    software = sequence(tagged(701, integer(1791900000000)), tagged(709, octets(application)))
    hardware = sequence(
        tagged(1, set_of(integer(2))),
        tagged(2, integer(3)),
        tagged(704, sequence(octets(bytes([0x42] * 32)), boolean(locked), enumerated(0 if locked else 2), octets(bytes([0x43] * 32)))),
        tagged(705, integer(160000)),
        tagged(706, integer(202609)),
    )
    return sequence(
        integer(300), enumerated(1), integer(300), enumerated(1),
        octets(challenge), octets(b""), software, hardware,
    )


def name(text):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, text)])


def certificate(subject, issuer, public_key, signing_key, algorithm, serial, extension=None):
    now = datetime.datetime(2026, 10, 14, tzinfo=datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name(subject))
        .issuer_name(name(issuer))
        .public_key(public_key)
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
    )
    if extension is not None:
        oid = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")
        builder = builder.add_extension(x509.UnrecognizedExtension(oid, extension), critical=False)
    return builder.sign(signing_key, algorithm).public_bytes(serialization.Encoding.DER)


root = rsa.generate_private_key(public_exponent=65537, key_size=2048)
intermediate = ec.generate_private_key(ec.SECP384R1())
identity = ed25519.Ed25519PrivateKey.from_private_bytes(bytes([0x0A] * 32)).public_key().public_bytes_raw()
challenge = hashlib.sha256(b"AirChat v1 build-attest-challenge" + identity).digest()
signer = bytes([0xAB] * 32)
handshake_hash = bytes([0x5A] * 32)
proof_message = b"AirChat v1 build-attest-proof" + handshake_hash

intermediate_cert = certificate("Test attestation intermediate", "Test attestation root",
                                intermediate.public_key(), root, hashes.SHA256(), 0x1001)


def chain(prefix, description, serial):
    """The attested certificate, the intermediate, and the attested key's proof."""
    leaf = ec.generate_private_key(ec.SECP256R1())
    leaf_cert = certificate("Android Keystore Key", "Test attestation intermediate",
                            leaf.public_key(), intermediate, hashes.SHA384(), serial, description)
    proof = leaf.sign(proof_message, ec.ECDSA(hashes.SHA256()))
    return {f"{prefix}_leaf": leaf_cert.hex(), f"{prefix}_intermediate": intermediate_cert.hex(), f"{prefix}_proof": proof.hex()}


# Flat, like the other vectors: every value a string.
vector = {
    "root_rsa_public_key": root.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1).hex(),
    "identity_seed": (bytes([0x0A] * 32)).hex(),
    "identity": identity.hex(),
    "challenge": challenge.hex(),
    "package": "com.plyg.airchat",
    "signer": signer.hex(),
    "handshake_hash": handshake_hash.hex(),
    "os_patch_level": "202609",
    **chain("official", key_description(challenge, b"com.plyg.airchat", signer, True), 0x2001),
    **chain("unlocked", key_description(challenge, b"com.plyg.airchat", signer, False), 0x2002),
    **chain("other_app", key_description(challenge, b"com.example.other", signer, True), 0x2003),
}
out = pathlib.Path(__file__).parent / "attestation.json"
out.write_text(json.dumps(vector, indent=2) + "\n")
print(out)
