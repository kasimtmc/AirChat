# AirChat

AirChat is a messaging app that works without the internet and without servers. Messages, calls,
push-to-talk and walkie-talkie channels travel from phone to phone over Wi-Fi (Bluetooth only finds
nearby devices), and people out of direct reach are reached through the AirChat users in between.
Everything is end-to-end encrypted: no one but you can see the content, neither on the way nor
afterwards.

> **Status:** in development, Android only. Every feature below is implemented and tested between
> two phones and on emulators, but AirChat has not had a security audit yet. Do not rely on it
> where your safety depends on it.

## Features

- **Chat:** 1:1 and group conversations with photos, video, audio and documents. Messages show
  whether they are being sent or delivered; one that cannot be delivered within a day is marked
  so, and can be tried again.
- **Groups:** up to 32 members and several admins. Members can be permanent or temporary (for a
  while, or until a call ends), and every change of members changes the group's key. An admin can
  delete a group for everyone; someone who left can delete its conversation on their own phone.
- **Calls:** voice and video calls, also in groups.
- **Push-to-talk and walkie-talkie:** hold to talk to a contact or a group, or tune in to a
  walkie-talkie channel shared by QR code or password. Someone who does not take push-to-talk
  right now gets what you said as a voice message, deleted 15 minutes after they first play it.
- **Contacts:** added in person (emoji comparison or QR code) or by AirChat ID. They can be muted,
  blocked and deleted, and an emergency exit cuts one off in a single step: blocked, the
  conversation deleted, removed from your groups.
- **Mesh:** every AirChat device passes on others' encrypted messages, so people out of direct
  reach are reached through the users in between. Nothing is stored on the way; the sender keeps
  its messages until they are delivered.
- **Air Provider:** one switch turns a phone into a relay for others' calls, push-to-talk, video
  and files too. It decides by itself what it can carry, from its battery and temperature, and the
  app picks the route; there is nothing to set up.

Bluetooth Low Energy only finds devices and sets up connections; everything else goes over Wi-Fi:
the same network, Wi-Fi Aware, or a hotspot one phone opens for the other. Bluetooth Classic and
Wi-Fi Direct are not used, because they broadcast names or fixed addresses.

## Security principles

- Everything is end-to-end encrypted in transit and encrypted at rest. Plaintext never touches
  disk: not in the database, files, thumbnails, caches or logs.
- No servers, no accounts, no phone numbers. Nothing broadcast over the air identifies you.
- The app is locked with a PIN or fingerprint. Screenshots and backups are blocked, and
  notifications never show content.
- Our own open protocol ([spec](rust/airchat-protocol/docs/protocol.md)), built on vetted
  cryptographic primitives, with hybrid post-quantum key exchange (X-Wing). The protocol has test
  vectors that independent scripts re-derive from the spec, and every parser of outside data is
  fuzzed. It is a reusable library of its own (`rust/airchat-protocol`, published as
  `kasimtmc/airchat-protocol`), so other apps can speak it too.

## Building (Android)

You need:

- Android Studio, or the Android SDK with platform 37 and NDK 29.0.14206865. Gradle fetches the
  JDK it runs on (25) by itself.
- Rust through `rustup`, and `cargo-ndk`. The toolchain and its Android targets are pinned in
  `rust/rust-toolchain.toml`; `rustup` installs them on first use.

```sh
cargo install cargo-ndk
./gradlew assembleDebug
```

The Rust core is compiled for arm64-v8a, armeabi-v7a and x86_64 as part of the Gradle build. The
app runs on Android 10 (API 29) and later.

### Release builds

Release builds are signed by Gradle with a v3 signature, which lets the key be rotated later; every
Android the app runs on checks it, so no v2 block is added.
Put a `keystore.properties` next to `settings.gradle.kts`; git ignores it:

```properties
storeFile=/path/to/airchat-release.jks
keyAlias=airchat
# Or leave these out and set AIRCHAT_STORE_PASSWORD and AIRCHAT_KEY_PASSWORD in the environment.
storePassword=...
keyPassword=...
```

`./gradlew assembleRelease` writes `app/build/outputs/apk/release/app-release.apk`. Android
Studio's "Generate Signed APK" wizard signs without v3.

To make a release:

1. Raise `versionCode` and set `versionName` in `app/build.gradle.kts`.
2. Refresh the revocation list of Android key attestation that verified builds use. It is
   compiled in, as the app never goes online:
   ```sh
   python3 rust/airchat-protocol/scripts/update-attestation-status.py
   ```
3. Run the [checks](#checks).
4. Build the release APK, install it on a phone and open it: R8 shrinks only release builds, so
   their faults show nowhere else.
5. Commit, push, and wait for CI to pass.
6. Tag the commit `vX.Y.Z` and publish a GitHub release with the APK and its SHA-256
   (`sha256sum AirChat-X.Y.Z.apk`).

## Checks

GitHub Actions runs all of these on every push to `master` and every pull request
([.github/workflows/ci.yml](.github/workflows/ci.yml)). To run them yourself:

```sh
cd rust
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test                     # also runs every fuzz target over mutated test vectors
cargo deny check               # advisories, licences, sources (cargo install cargo-deny)
for f in airchat-protocol/tests/vectors/check_*.py; do python3 "$f"; done   # pip install cryptography
```

The protocol's test vectors are in `rust/airchat-protocol/tests/vectors/`; the `check_*.py` scripts
re-derive them from the specification alone. The protocol crate also has its own `deny.toml`, which
allows permissive licences only: run `cargo deny check` in `rust/airchat-protocol` too. Longer fuzzing under libFuzzer is described in
[rust/fuzz/README.md](rust/fuzz/README.md), and `./gradlew lintDebug` checks the app.

## Documentation

- [Requirements](docs/requirements.md): what AirChat does and the decisions behind it.
- [Architecture](docs/architecture.md): how it is built, storage and keys, transports, mesh.
- [Protocol](rust/airchat-protocol/docs/protocol.md): the wire protocol, byte by byte; with its
  test vectors and Rust implementation in [rust/airchat-protocol](rust/airchat-protocol/README.md).
- [Threat model](docs/threat-model.md): what is protected from whom, and the known weaknesses.

## What comes next

- An independent security audit, after formal models of the remaining handshakes (the contact
  link handshake and pairing are modelled).
- Reproducible builds.
- Wi-Fi Aware tested end to end between two phones that have it.
- iOS and Linux apps, sharing the same Rust core.

## License

AirChat is free software, licensed under the [GNU General Public License v3.0 or later](LICENSE).
The protocol in `rust/airchat-protocol` is licensed more permissively, so that any app can use it:
its code under MIT or Apache-2.0, its specification under CC BY 4.0 (see its README).
