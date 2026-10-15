# Fuzzing the core

The parsers of everything that reaches a device from outside (requirement S-11) are fuzz targets
in `airchat_core::fuzz`, which re-exports the protocol's (`airchat_protocol::fuzz`). Each must not
panic on any input, and checks what it can: what a decoder accepts encodes back to the same bytes. Four targets drive a whole node: the frames of a new
connection, and records from a stranger on the mesh, a member of a walkie-talkie channel and a
contact, over links whose handshakes succeeded.

`cargo test` already runs every target over mutations of the published test vectors
(`AIRCHAT_FUZZ_RUNS=20` runs twenty times as many, `AIRCHAT_FUZZ_SEED=n` other mutations). This
crate runs them under libFuzzer, guided by coverage, which finds much more.

Write the test vectors as the starting corpus (from `rust/`):

```sh
cargo test -p airchat-core write_fuzz_corpus -- --ignored
```

Then run a target on the pinned stable toolchain (from `rust/fuzz`; `ls fuzz_targets` names them):

```sh
./run.sh chat_message -max_total_time=600
```

With a nightly toolchain and `cargo install cargo-fuzz`, `cargo +nightly fuzz run chat_message`
does the same and adds AddressSanitizer, which only matters for the C in SQLCipher: the core
forbids `unsafe`.

A failing input lands in `artifacts/<target>/`; `./run.sh <target> <file>` replays it. The node
targets keep one node across inputs, like a long-running device, so a failure may need the inputs
before it: replay with the corpus.
