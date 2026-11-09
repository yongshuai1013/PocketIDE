#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$ROOT/build/bionic-needed-probe"
ROOTFS="$BUILD_DIR/rootfs"
AOSP_LINKER="${AOSP_LINKER:-$ROOT/build/aosp/rootfs/system/bin/linker}"
LIBRARY_NAME="libgingervm-bionic-probe.so"
MARKER="$ROOTFS/tmp/gingervm-bionic-needed.txt"
LOG="$BUILD_DIR/run.log"

if [[ -n "${CLANG:-}" ]]; then
  CLANG_BIN="$CLANG"
elif command -v clang-18 >/dev/null 2>&1; then
  CLANG_BIN="$(command -v clang-18)"
elif command -v clang >/dev/null 2>&1; then
  CLANG_BIN="$(command -v clang)"
else
  echo "error: Clang is required to build the ARMv5T probe" >&2
  exit 1
fi
if command -v ld.lld-18 >/dev/null 2>&1; then
  LLD_DRIVER="lld-18"
elif command -v ld.lld >/dev/null 2>&1; then
  LLD_DRIVER="lld"
else
  echo "error: LLD is required to link the ARMv5T probe" >&2
  exit 1
fi
for tool in cargo readelf file cmp; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "error: required tool not found: $tool" >&2
    exit 1
  fi
done
if [[ ! -f "$AOSP_LINKER" ]]; then
  echo "error: exact AOSP android-2.3.7_r1 ARM linker not found: $AOSP_LINKER" >&2
  echo "Build/stage that linker first, or set AOSP_LINKER to its file path." >&2
  exit 1
fi

mkdir -p "$BUILD_DIR"
python3 -c 'import shutil, sys; shutil.rmtree(sys.argv[1], ignore_errors=True)' "$ROOTFS"
mkdir -p "$ROOTFS/system/bin" "$ROOTFS/system/lib"

printf '%s\n' '== Build ARMv5T DT_NEEDED shared library =='
"$CLANG_BIN" \
  --target=armv5-linux-gnueabi \
  -march=armv5te \
  -marm \
  -fPIC \
  -fno-stack-protector \
  -fno-builtin \
  -O1 \
  -nostdlib \
  -fuse-ld="$LLD_DRIVER" \
  -shared \
  -Wl,-soname,"$LIBRARY_NAME" \
  -Wl,--hash-style=sysv \
  -Wl,--build-id=none \
  -Wl,-z,max-page-size=4096 \
  -o "$BUILD_DIR/$LIBRARY_NAME" \
  "$ROOT/probes/armv5t-bionic-needed-library.c"

printf '%s\n' '== Build ARMv5T ET_EXEC app with PT_INTERP and DT_NEEDED =='
"$CLANG_BIN" \
  --target=armv5-linux-gnueabi \
  -march=armv5te \
  -marm \
  -fPIC \
  -fno-stack-protector \
  -fno-builtin \
  -O1 \
  -nostdlib \
  -fuse-ld="$LLD_DRIVER" \
  -Wl,-no-pie \
  -Wl,-e,_start \
  -Wl,--dynamic-linker=/system/bin/linker \
  -Wl,--hash-style=sysv \
  -Wl,--build-id=none \
  -Wl,-z,max-page-size=4096 \
  -L"$BUILD_DIR" \
  -Wl,-rpath-link,"$BUILD_DIR" \
  -o "$BUILD_DIR/main.elf" \
  "$ROOT/probes/armv5t-bionic-needed-main.c" \
  -lgingervm-bionic-probe

file "$BUILD_DIR/main.elf" "$BUILD_DIR/$LIBRARY_NAME" "$AOSP_LINKER"
readelf -l "$BUILD_DIR/main.elf" | grep -F 'Requesting program interpreter: /system/bin/linker'
readelf -d "$BUILD_DIR/main.elf" | grep -F "$LIBRARY_NAME"
readelf -r "$BUILD_DIR/main.elf" | grep -F 'R_ARM_GLOB_DAT'
readelf -r "$BUILD_DIR/main.elf" | grep -F 'R_ARM_JUMP_SLOT'
if readelf -r "$BUILD_DIR/main.elf" | grep -Fq 'R_ARM_COPY'; then
  echo 'error: probe must not use R_ARM_COPY; Gingerbread linker has a self-lookup limitation for it' >&2
  exit 1
fi

cp "$AOSP_LINKER" "$ROOTFS/system/bin/linker"
cp "$BUILD_DIR/$LIBRARY_NAME" "$ROOTFS/system/lib/$LIBRARY_NAME"
cargo build --release --manifest-path "$ROOT/Cargo.toml"
printf '%s\n' '== Run the app through real guest PT_INTERP; host dependency preload is disabled =='
GINGERVM_TRACE_SYSCALLS=1 \
  "$ROOT/target/release/gingervm" run-elf-interp "$ROOTFS" "$BUILD_DIR/main.elf" \
  >"$LOG" 2>&1

grep -Fq 'Dependency loading: guest PT_INTERP (host preload disabled)' "$LOG"
grep -Fq "stat64 /system/lib/$LIBRARY_NAME -> 96 bytes" "$LOG"
grep -Fq "open /system/lib/$LIBRARY_NAME -> guest fd" "$LOG"
grep -Fq 'lseek' "$LOG"
grep -Fq 'mmap2' "$LOG"
# The main ELF has mapped bytes on both pages; Linux mprotect is page-granular,
# so byte gaps between PT_LOAD payloads must not make this range look unmapped.
grep -Eq 'guest syscall #125 mprotect args=\[65536, 8192, 5, [^]]+\] -> 0 at ' "$LOG"
grep -Fq 'Guest exit code: 0' "$LOG"
printf '%s\n' 'AOSP Bionic loaded DT_NEEDED shared library' | cmp - "$MARKER"
printf '%s\n' 'Verified: Bionic loaded the rootfs DSO, resolved GLOB_DAT/JUMP_SLOT, and the app wrote its marker.'
printf 'App ELF: %s\n' "$BUILD_DIR/main.elf"
printf 'Shared library: %s\n' "$ROOTFS/system/lib/$LIBRARY_NAME"
printf 'Run log: %s\n' "$LOG"
