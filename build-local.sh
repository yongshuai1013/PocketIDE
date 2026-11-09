#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

printf '%s\n' '== GingerVM host tests =='
cargo test --all-targets

printf '%s\n' '== GingerVM host release build =='
cargo build --release

if command -v rustup >/dev/null 2>&1 && rustup target list --installed | grep -qx 'aarch64-linux-android'; then
  printf '%s\n' '== Android arm64 Rust target check =='
  cargo check --lib --target aarch64-linux-android
else
  printf '%s\n' 'SKIP: aarch64-linux-android target is not installed.'
fi

printf '\nHost binary: %s/target/release/gingervm\n' "$PWD"
printf '%s\n' 'Note: Android SDK/NDK is needed to link an Android native library or assemble an APK.'
