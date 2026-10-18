# Audit brief

For whoever reviews AirChat independently: what to look at, where it is, how to run what we ran,
and what has and has not been done. What AirChat protects from whom, its known weaknesses and our
suggested priorities are in [threat-model.md](threat-model.md) (§7, §8).

## What to review

| Repository | What | Version |
|---|---|---|
| [kasimtmc/airchat-protocol](https://github.com/kasimtmc/airchat-protocol) | The protocol: specification, test vectors and checkers, the Rust crate `airchat-protocol` (formats and cryptography), fuzz targets, Tamarin models | tag `audit-1` |
| [kasimtmc/AirChat](https://github.com/kasimtmc/AirChat) | The Android app: the Rust core on top of the protocol (`rust/airchat-core`: storage, contacts, groups, the mesh, the node), its FFI, and the Kotlin app | tag `audit-1` |

`rust/airchat-protocol` in AirChat is the same code as the protocol repository at the same tag.
Out of scope, as the threat model says (§6): a compromised phone or OS, the cryptographic libraries'
own implementations, radio-level fingerprinting.

## Where things are

| | |
|---|---|
| Specification | `airchat-protocol/docs/protocol.md` |
| Threat model, requirements, architecture | `AirChat/docs/` |
| Cryptographic primitives (the only code that calls a crypto library) | `airchat-protocol/src/crypto/` |
| Handshakes: links, pairing | `airchat-protocol/src/link/`, `src/pairing/` |
| Groups, mesh, channels, paths (formats) | `airchat-protocol/src/group.rs`, `mesh.rs`, `channel.rs`, `path.rs` |
| What a device does with them (state, acceptance rules) | `AirChat/rust/airchat-core/src/node/` |
| Encrypted storage (SQLCipher, key hierarchy) | `AirChat/rust/airchat-core/src/storage/` |
| Android: lock, Keystore, transports, UI | `AirChat/app/src/main/java/com/plyg/airchat/` |
| Test vectors and independent checkers | `airchat-protocol/tests/vectors/` |
| Fuzz targets | `airchat-protocol/src/fuzz.rs`, `AirChat/rust/airchat-core/src/fuzz.rs`, `node/fuzz.rs` |
| Formal models | `airchat-protocol/formal/` |

## How to run the checks

From `AirChat/rust` (the protocol crate is a member of this workspace):

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test                                   # also runs every fuzz target over mutated vectors
cargo deny check                             # and in airchat-protocol/ with its own deny.toml
for f in airchat-protocol/tests/vectors/check_*.py; do python3 "$f"; done
fuzz/run.sh <target> -max_total_time=3600    # libFuzzer, see fuzz/README.md
```

Tamarin (`airchat-protocol/formal/README.md` gives the flags):
`tamarin-prover --prove <model>.spthy` for `link`, `pairing`, `group` and `mesh`.

The Android app: `./gradlew assembleDebug lintDebug` (JDK 25, Android SDK 37, NDK 29, cargo-ndk).
GitHub Actions runs all of the above on every push.

## What has been done (2026-10-18)

- **Tests:** 374 in the Rust workspace (protocol and core), including the core's acceptance rules
  for groups (non-admin, stale, replayed and rival updates, removed members, tampered and replayed
  messages), link keys under concurrent and interrupted links, prekeys and mesh limits.
- **Test vectors** for every format and handshake, re-derived from the specification by nine
  independent Python scripts.
- **Fuzzing:** every parser of bytes from another device is a target (12 in the protocol, 18 with
  the app's). All 18 ran under libFuzzer for 45 minutes each, and the four that drive a whole node
  for 4 hours each more: no crash. That run found the tag checker pruning every nonce on every
  attempt (fixed).
- **Formal models** in Tamarin, 46 lemmas, all verified: the link handshake (secrecy, forward
  secrecy, key compromise impersonation, mutual authentication, healing), pairing in its three
  modes, group keys (epoch key secrecy, removal, authenticity, the removed member kept out) and
  1:1 mesh envelopes (secrecy from relays, forward secrecy, authenticity). For each model, a
  deliberately broken variant makes Tamarin find the attack, so the lemmas are not vacuous.
- **Dependencies:** cargo-deny (advisories, licences, sources); Android dependencies checked by
  hand against OSV. Actions pinned to commit SHAs.

## What has not

- No independent review of any of it yet: this one.
- Not modelled formally: group links, channel and mesh links, paths, two updates of one epoch
  (§9.2, tested only), and privacy properties (identity hiding, unlinkability). The models use
  ideal primitives; each model's header lists its abstractions.
- Builds are not reproducible.
- Wi-Fi Aware has not been tested end to end between two phones that support it.
- The JVM side (Kotlin) holds decrypted text in memory as the threat model describes (§7, item 8).

## What we would most like an opinion on

1. Whether the handshakes, as specified and implemented, give the properties §6.5 and the models
   claim, including what the models abstract away (X-Wing used as a KEM, key schedules, nonces).
2. Group epochs: the acceptance rules in `node/groups.rs`, removal, and the rule for two updates of
   one epoch (§9.2).
3. What relays and Air Providers learn (§10.6, §12.4), and whether the mesh's limits hold against
   flooding.
4. Key lifetimes and wiping in the core, the encrypted storage, and the Android lock and Keystore
   use.

Reports go to the maintainer through GitHub (kasimtmc).
