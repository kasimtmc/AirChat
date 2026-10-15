# AirChat Protocol

End-to-end encrypted messaging, calls, groups and walkie-talkie channels between nearby devices,
with no internet, no servers and no accounts. Bluetooth Low Energy finds devices, Wi-Fi carries
everything, and every device relays for the others (a mesh).

This repository holds everything needed to build an interoperable implementation:

| | |
|---|---|
| [`docs/protocol.md`](docs/protocol.md) | The specification, byte by byte. |
| [`tests/vectors/`](tests/vectors/) | Test vectors for every part (JSON), and `check_*.py` scripts that re-derive them from the specification alone. |
| [`src/`](src/) | The reference implementation in Rust (`airchat-protocol`): formats and cryptography, no storage, no transports, no platform code, `#![forbid(unsafe_code)]`. |
| [`fuzz/`](fuzz/) | libFuzzer targets for every parser of bytes that come from another device. |
| [`formal/`](formal/) | Tamarin models: the contact link handshake (secrecy, forward secrecy, mutual authentication, healing) and pairing in its three modes. |

It is the protocol of the [AirChat](https://github.com/kasimtmc/AirChat) Android app, which uses
this crate unchanged.

**Status: version 0, not yet stable and not audited.** Every section is specified, implemented and
pinned by test vectors, but formats may change until version 1.0 of the specification, and no one
outside the project has reviewed it yet. Do not rely on it to protect anyone until it has been.

## What it provides

- **Identity and pairing** (§4): an Ed25519 identity key per device and a short, typeable AirChat ID;
  pairing by QR code, by comparing five emoji with someone nearby, or by typing an ID.
- **Discovery** (§5): BLE and Wi-Fi Aware beacons that contacts recognise and no one else can link
  to a person or a device.
- **Link sessions** (§6): a three-message handshake that authenticates both sides without signatures
  (deniable), hides both identities, gives forward secrecy, is post-quantum (X-Wing, i.e. ML-KEM-768 +
  X25519), and heals after a device's keys were copied (post-compromise security).
- **Messages, files, calls and video** (§8); **groups** of up to 32 (§9) with epoch keys and
  rosters only admins change (signed updates); the **mesh** (§10) with sealed envelopes and
  one-time prekeys; **walkie-talkie channels** (§11); and **paths** through relaying devices (§12).
- **Build attestation** (§6.10): Android key attestation that shows a contact runs the official
  build on a verified phone.

Cryptography: X-Wing (draft-connolly-cfrg-xwing-kem-06), Ed25519, ChaCha20-Poly1305 and
XChaCha20-Poly1305, SHA-256, HMAC and HKDF, all from [libcrux](https://github.com/cryspen/libcrux)
(formally verified); Argon2id for PINs (local only); `ring` to verify attestation certificates. No
primitive is implemented here: `airchat_protocol::crypto` wraps the libraries, and nothing else
calls them.

## Using it

### From Rust

Until the specification reaches 1.0 the crate is not on crates.io; depend on a tag:

```toml
[dependencies]
airchat-protocol = { git = "https://github.com/kasimtmc/airchat-protocol", tag = "v0.1.0" }
```

Each module follows a section of the specification: `pairing` (§4), `discovery` (§5), `link` (§6),
`chat` (§8), `group` (§9), `mesh` (§10), `channel` (§11), `path` (§12), `attest` (§6.10). The
functions take and return state and bytes; your app stores the state (encrypted) and carries the
bytes over its transports.

### In another language

Read the specification, then check your implementation against `tests/vectors/`. Each vector lists
all inputs (with the seeds its randomness came from), every intermediate value and the bytes on the
wire; §4.7, §6.6, §10.11 and the other vector sections say how to read them. The `check_*.py`
scripts show the same derivations in a few hundred lines of Python each.

## Checks

```sh
cargo fmt --check
cargo clippy --all-targets --features fuzzing -- -D warnings
cargo test                     # also runs every fuzz target over mutated test vectors
cargo deny check               # advisories, licences, sources (cargo install cargo-deny)
for f in tests/vectors/check_*.py; do python3 "$f"; done   # pip install cryptography
```

GitHub Actions runs them on every push and pull request
([.github/workflows/ci.yml](.github/workflows/ci.yml)). Longer, coverage-guided fuzzing is described
in [fuzz/README.md](fuzz/README.md).

A change to the protocol updates the specification, the code and the vectors together:
`AIRCHAT_UPDATE_VECTORS=1 cargo test` rewrites the vectors after an intentional change, and the
checkers must still pass. `attestation.json` is the exception: `tests/vectors/make_attestation.py`
made it (random signatures, a test root); the code and `check_attestation.py` only verify it. The
revocation list of Android attestation keys is compiled in; refresh it with
`python3 scripts/update-attestation-status.py` before a release.

## Licence

- The specification (`docs/`) is licensed under [CC BY 4.0](LICENSE-CC-BY-4.0).
- The code, test vectors and scripts are licensed under either of [MIT](LICENSE-MIT) or
  [Apache-2.0](LICENSE-APACHE), at your option.

Unless you say otherwise, a contribution you submit for inclusion is licensed as above, without any
additional terms.
