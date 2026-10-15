# Fuzzing the protocol

Every parser of bytes that come from another device is a fuzz target in `airchat_protocol::fuzz`.
Each must not panic on any input, and checks what it can: what a decoder accepts encodes back to
the same bytes.

`cargo test` already runs every target over mutations of the published test vectors
(`AIRCHAT_FUZZ_RUNS=20` runs twenty times as many, `AIRCHAT_FUZZ_SEED=n` other mutations). This
crate runs them under libFuzzer, guided by coverage, which finds much more.

Write the test vectors as the starting corpus (from the repository root):

```sh
cargo test --lib write_fuzz_corpus -- --ignored
```

Then run a target on the pinned stable toolchain (from `fuzz/`; `ls fuzz_targets` names them):

```sh
./run.sh chat_message -max_total_time=600
```

With a nightly toolchain and `cargo install cargo-fuzz`, `cargo +nightly fuzz run chat_message`
does the same. The library forbids `unsafe`, so sanitizers add little.

A failing input lands in `artifacts/<target>/`; `./run.sh <target> <file>` replays it.
