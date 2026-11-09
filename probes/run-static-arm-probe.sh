#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$ROOT/build/arm-static-probe"
ELF="$BUILD_DIR/armv7-static-probe.elf"
ROOTFS="$BUILD_DIR/rootfs"
LOG="$BUILD_DIR/run.log"

if [[ -n "${CLANG:-}" ]]; then
  CLANG_BIN="$CLANG"
elif command -v clang-18 >/dev/null 2>&1; then
  CLANG_BIN="$(command -v clang-18)"
elif command -v clang >/dev/null 2>&1; then
  CLANG_BIN="$(command -v clang)"
else
  echo "error: Clang is required to build the ARM guest probe" >&2
  exit 1
fi

if command -v ld.lld-18 >/dev/null 2>&1; then
  LLD_DRIVER="lld-18"
elif command -v ld.lld >/dev/null 2>&1; then
  LLD_DRIVER="lld"
else
  echo "error: LLD is required to link the static ARM guest probe" >&2
  exit 1
fi

for tool in cargo readelf file cmp; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "error: required tool not found: $tool" >&2
    exit 1
  fi
done

mkdir -p "$BUILD_DIR"
rm -rf "$ROOTFS"
mkdir -p "$ROOTFS"
trap 'rm -rf "$ROOTFS"' EXIT

printf '%s\n' '== Build host GingerVM CLI =='
cargo build --release --manifest-path "$ROOT/Cargo.toml"

printf '%s\n' '== Cross-compile static ARMv7 EABI guest =='
"$CLANG_BIN" \
  --target=armv7-linux-gnueabi \
  -march=armv7-a \
  -marm \
  -fuse-ld="$LLD_DRIVER" \
  -nostdlib \
  -static \
  -Wl,-e,_start \
  -Wl,--build-id=none \
  -Wl,-z,noexecstack \
  -o "$ELF" \
  "$ROOT/probes/armv7-static-probe.S"

file "$ELF"
readelf -h "$ELF" | grep -E 'Class:|Type:|Machine:|Flags:'
if readelf -l "$ELF" | grep -q 'INTERP'; then
  echo 'error: probe unexpectedly has a dynamic interpreter' >&2
  exit 1
fi

printf '%s\n' '== Execute the genuine ARM ELF in GingerVM =='
"$ROOT/target/release/gingervm" run-elf "$ROOTFS" "$ELF" | tee "$LOG"
grep -Fq 'Instruction set: ARM' "$LOG"
grep -Fq 'Brokered syscall events: 12' "$LOG"
grep -Fq 'Guest exit code: 0' "$LOG"

printf '%s\n' '== Verify guest file read/write round-trip =='
EXPECTED='GingerVM ARM EABI static probe: file round-trip OK'
printf '%s\n' "$EXPECTED" | cmp - "$ROOTFS/tmp/gingervm-arm-source.txt"
cmp "$ROOTFS/tmp/gingervm-arm-source.txt" "$ROOTFS/tmp/gingervm-arm-copy.txt"
printf '%s\n' 'Source and copied guest files match the expected payload.'
printf 'Probe ELF: %s\n' "$ELF"
printf 'Execution log: %s\n' "$LOG"
