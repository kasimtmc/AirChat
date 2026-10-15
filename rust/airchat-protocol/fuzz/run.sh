#!/bin/sh
# Builds one fuzz target and runs it under libFuzzer on the pinned stable toolchain, without
# cargo-fuzz: the coverage instrumentation libFuzzer needs is stable; only sanitizers need nightly.
# Usage: ./run.sh <target> [libFuzzer options], e.g. ./run.sh chat_message -max_total_time=600
set -eu
cd "$(dirname "$0")"
target=$1
shift
host=$(rustc -vV | sed -n 's/^host: //p')
RUSTFLAGS="-Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=4 \
-Cllvm-args=-sanitizer-coverage-inline-8bit-counters -Cllvm-args=-sanitizer-coverage-pc-table \
-Cllvm-args=-sanitizer-coverage-trace-compares --cfg fuzzing -Cdebug-assertions -Coverflow-checks" \
    cargo build --release --target "$host" --bin "$target"
mkdir -p "corpus/$target" "artifacts/$target"
exec "target/$host/release/$target" "corpus/$target" -artifact_prefix="artifacts/$target/" "$@"
