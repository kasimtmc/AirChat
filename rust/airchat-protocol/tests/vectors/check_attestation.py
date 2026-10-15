#!/usr/bin/env python3
"""Independent check of the build attestation test vector (docs/protocol.md §6.10).

Verifies each chain from the specification alone: the signatures up to the test root, the
challenge bound to the identity, the key description (package, signer, root of trust, patch
level), and the attested key's proof over the handshake hash. Needs the `cryptography` package.

    python3 check_attestation.py
"""

import hashlib
import json
import pathlib
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

v = json.loads((pathlib.Path(__file__).parent / "attestation.json").read_text())
field = lambda name: bytes.fromhex(v[name])
failures = 0


def check(what, actual, expected):
    global failures
    ok = actual == expected
    failures += not ok
    print(f"  {'ok  ' if ok else 'FAIL'} {what}")


def tlv(data):
    """One DER element: (class, constructed, tag number, content, rest)."""
    first = data[0]
    number, at = first & 0x1F, 1
    if number == 0x1F:
        number = 0
        while True:
            b = data[at]
            at += 1
            number = (number << 7) | (b & 0x7F)
            if not b & 0x80:
                break
    length = data[at]
    at += 1
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(data[at:at + count], "big")
        at += count
    return first >> 6, bool(first & 0x20), number, data[at:at + length], data[at + length:]


def children(content):
    out = []
    while content:
        *element, content = tlv(content)
        out.append(element)
    return out


def verify_signature(cert, issuer_key):
    if isinstance(issuer_key, ec.EllipticCurvePublicKey):
        issuer_key.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
    else:
        issuer_key.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)


print("attestation.json")
identity = ed25519.Ed25519PrivateKey.from_private_bytes(field("identity_seed")).public_key().public_bytes_raw()
check("identity from its seed", identity, field("identity"))
challenge = hashlib.sha256(b"AirChat v1 build-attest-challenge" + identity).digest()
check("challenge", challenge, field("challenge"))
# The root's RSAPublicKey: SEQUENCE { modulus, publicExponent }.
modulus, exponent = (int.from_bytes(element[3], "big") for element in children(tlv(field("root_rsa_public_key"))[3]))
root = rsa.RSAPublicNumbers(exponent, modulus).public_key()
proof_message = b"AirChat v1 build-attest-proof" + field("handshake_hash")
KEY_DESCRIPTION = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")

expected = {
    "official": ("com.plyg.airchat", True),
    "unlocked": ("com.plyg.airchat", False),
    "other_app": ("com.example.other", True),
}
for name, (package, locked) in expected.items():
    leaf = x509.load_der_x509_certificate(field(f"{name}_leaf"))
    intermediate = x509.load_der_x509_certificate(field(f"{name}_intermediate"))
    try:
        verify_signature(leaf, intermediate.public_key())
        verify_signature(intermediate, root)
        check(f"{name}: chain up to the root", True, True)
    except Exception:
        check(f"{name}: chain up to the root", False, True)
    check(f"{name}: only the attested certificate describes a key",
          [c for c in (leaf, intermediate) if any(e.oid == KEY_DESCRIPTION for e in c.extensions)], [leaf])
    description = leaf.extensions.get_extension_for_oid(KEY_DESCRIPTION).value.value
    fields = children(tlv(description)[3])
    check(f"{name}: attested in the trusted environment", fields[1][3], b"\x01")
    check(f"{name}: challenge", fields[4][3], challenge)
    software = {number: children(content)[0] for _, _, number, content in children(fields[6][3])}
    hardware = {number: children(content)[0] for _, _, number, content in children(fields[7][3])}
    application = children(tlv(software[709][3])[3])
    packages = [children(info[3])[0][3] for info in children(application[0][3])]
    signers = [digest[3] for digest in children(application[1][3])]
    check(f"{name}: package", packages, [package.encode()])
    check(f"{name}: signer", signers, [field("signer")])
    root_of_trust = children(hardware[704][3])
    check(f"{name}: device locked", root_of_trust[1][3] != b"\x00", locked)
    check(f"{name}: verified boot", root_of_trust[2][3] == b"\x00", locked)
    check(f"{name}: patch level", int.from_bytes(hardware[706][3], "big"), int(v["os_patch_level"]))
    try:
        leaf.public_key().verify(field(f"{name}_proof"), proof_message, ec.ECDSA(hashes.SHA256()))
        check(f"{name}: proof over the handshake hash", True, True)
    except Exception:
        check(f"{name}: proof over the handshake hash", False, True)

print("all checks passed" if not failures else f"{failures} check(s) failed")
sys.exit(1 if failures else 0)
