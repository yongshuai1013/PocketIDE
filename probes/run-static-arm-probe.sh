#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$ROOT/build/arm-static-probe"
ELF="$BUILD_DIR/armv7-static-probe.elf"
ROOTFS="$BUILD_DIR/rootfs"
LOG="$BUILD_DIR/run.log"
THUMB_ELF="$BUILD_DIR/thumbv1-static-probe.elf"
THUMB_ROOTFS="$BUILD_DIR/thumb-rootfs"
THUMB_LOG="$BUILD_DIR/thumb-run.log"
MEMORY_ELF="$BUILD_DIR/armv7-memory-probe.elf"
MEMORY_ROOTFS="$BUILD_DIR/memory-rootfs"
MEMORY_LOG="$BUILD_DIR/memory-run.log"
PIE_ELF="$BUILD_DIR/armv7-pie-probe.elf"
PIE_ROOTFS="$BUILD_DIR/pie-rootfs"
PIE_LOG="$BUILD_DIR/pie-run.log"
INTERP_ELF="$BUILD_DIR/armv7-test-linker.so"
INTERP_MAIN_ELF="$BUILD_DIR/armv7-interp-main.elf"
INTERP_ROOTFS="$BUILD_DIR/interp-rootfs"
INTERP_LOG="$BUILD_DIR/interp-run.log"
DYNAMIC_LINKER_ELF="$BUILD_DIR/armv7-dynamic-linker.so"
DYNAMIC_MAIN_ELF="$BUILD_DIR/armv7-shared-main.elf"
DYNAMIC_LIBRARY_ELF="$BUILD_DIR/libgingervm-probe.so"
DYNAMIC_ROOTFS="$BUILD_DIR/dynamic-rootfs"
DYNAMIC_LOG="$BUILD_DIR/dynamic-run.log"
COPY_MAIN_ELF="$BUILD_DIR/armv5t-copy-main.elf"
COPY_LIBRARY_ELF="$BUILD_DIR/libgingervm-copy.so"
COPY_LOG="$BUILD_DIR/copy-relocation-run.log"
TLS_ELF="$BUILD_DIR/armv7-tls-probe.elf"
TLS_ROOTFS="$BUILD_DIR/tls-rootfs"
TLS_LOG="$BUILD_DIR/tls-run.log"
EMUTLS_ELF="$BUILD_DIR/armv7-emutls-probe.elf"
EMUTLS_ROOTFS="$BUILD_DIR/emutls-rootfs"
EMUTLS_LOG="$BUILD_DIR/emutls-run.log"

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
rm -rf "$ROOTFS" "$TLS_ROOTFS" "$EMUTLS_ROOTFS" "$THUMB_ROOTFS" "$MEMORY_ROOTFS" "$PIE_ROOTFS" "$INTERP_ROOTFS" "$DYNAMIC_ROOTFS"
mkdir -p "$ROOTFS" "$TLS_ROOTFS" "$EMUTLS_ROOTFS" "$THUMB_ROOTFS" "$MEMORY_ROOTFS" "$PIE_ROOTFS" "$INTERP_ROOTFS/system/bin" "$DYNAMIC_ROOTFS/system/bin" "$DYNAMIC_ROOTFS/system/lib"
trap 'rm -rf "$ROOTFS" "$TLS_ROOTFS" "$EMUTLS_ROOTFS" "$THUMB_ROOTFS" "$MEMORY_ROOTFS" "$PIE_ROOTFS" "$INTERP_ROOTFS" "$DYNAMIC_ROOTFS"' EXIT

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

printf '%s\n' '== Cross-compile the Gingerbread ARM TLS ABI probe =='
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
  -o "$TLS_ELF" \
  "$ROOT/probes/armv7-tls-probe.S"
file "$TLS_ELF"
readelf -h "$TLS_ELF" | grep -E 'Class:|Type:|Machine:|Flags:'

printf '%s\n' '== Execute ARM_set_tls, startup getpid, and TPIDRURO MRC in GingerVM =='
"$ROOT/target/release/gingervm" run-elf "$TLS_ROOTFS" "$TLS_ELF" | tee "$TLS_LOG"
grep -Fq 'Instruction set: ARM' "$TLS_LOG"
grep -Fq 'Brokered syscall events: 1' "$TLS_LOG"
grep -Fq 'Guest exit code: 0' "$TLS_LOG"
printf 'TLS probe ELF: %s\n' "$TLS_ELF"
printf 'TLS execution log: %s\n' "$TLS_LOG"

printf '%s\n' '== Cross-compile Gingerbread-style Android __thread via emulated TLS =='
"$CLANG_BIN" \
  --target=armv7-linux-android10 \
  -march=armv5te \
  -marm \
  -mfloat-abi=soft \
  -femulated-tls \
  -ffreestanding \
  -fno-builtin \
  -fno-stack-protector \
  -O1 \
  -fuse-ld="$LLD_DRIVER" \
  -nostdlib \
  -static \
  -Wl,-e,_start \
  -Wl,--build-id=none \
  -Wl,-z,noexecstack \
  -o "$EMUTLS_ELF" \
  "$ROOT/probes/armv7-emutls-probe.c"
file "$EMUTLS_ELF"
readelf -h "$EMUTLS_ELF" | grep -E 'Class:|Type:|Machine:|Flags:'
readelf -sW "$EMUTLS_ELF" | grep -F '__emutls_get_address'
if readelf -lW "$EMUTLS_ELF" | grep -Eq '^[[:space:]]*TLS[[:space:]]'; then
  echo 'error: Android API 10 emutls probe unexpectedly contains PT_TLS' >&2
  exit 1
fi
if readelf -r "$EMUTLS_ELF" | grep -Eq 'R_ARM_TLS'; then
  echo 'error: Android API 10 emutls probe unexpectedly contains native TLS relocations' >&2
  exit 1
fi

printf '%s\n' '== Execute initialized, zeroed, and aligned __thread variables in GingerVM =='
"$ROOT/target/release/gingervm" run-elf "$EMUTLS_ROOTFS" "$EMUTLS_ELF" | tee "$EMUTLS_LOG"
grep -Fq 'Instruction set: ARM' "$EMUTLS_LOG"
grep -Fq 'Guest exit code: 0' "$EMUTLS_LOG"
printf 'Android API 10 emutls probe ELF: %s\n' "$EMUTLS_ELF"
printf 'emutls execution log: %s\n' "$EMUTLS_LOG"

printf 'Probe ELF: %s\n' "$ELF"
printf 'Execution log: %s\n' "$LOG"

printf '%s\n' '== Cross-compile static ARMv5T Thumb-1 guest =='
"$CLANG_BIN" \
  --target=armv5-linux-gnueabi \
  -march=armv5t \
  -mthumb \
  -fuse-ld="$LLD_DRIVER" \
  -nostdlib \
  -static \
  -Wl,-e,_start \
  -Wl,--build-id=none \
  -Wl,-z,noexecstack \
  -o "$THUMB_ELF" \
  "$ROOT/probes/thumbv1-static-probe.S"
file "$THUMB_ELF"
readelf -h "$THUMB_ELF" | grep -E 'Class:|Type:|Machine:|Flags:'
if readelf -l "$THUMB_ELF" | grep -q 'INTERP'; then
  echo 'error: Thumb probe unexpectedly has a dynamic interpreter' >&2
  exit 1
fi

printf '%s\n' '== Execute the genuine Thumb-1 ELF in GingerVM =='
"$ROOT/target/release/gingervm" run-elf "$THUMB_ROOTFS" "$THUMB_ELF" | tee "$THUMB_LOG"
grep -Fq 'Instruction set: Thumb' "$THUMB_LOG"
grep -Fq 'Instructions executed: 140' "$THUMB_LOG"
grep -Fq 'Brokered syscall events: 0' "$THUMB_LOG"
grep -Fq 'Guest exit code: 0' "$THUMB_LOG"
printf 'Thumb probe ELF: %s\n' "$THUMB_ELF"
printf 'Thumb execution log: %s\n' "$THUMB_LOG"

printf '%s\n' '== Cross-compile ARMv7 guest memory-management probe =='
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
  -o "$MEMORY_ELF" \
  "$ROOT/probes/armv7-memory-probe.S"
file "$MEMORY_ELF"
readelf -h "$MEMORY_ELF" | grep -E 'Class:|Type:|Machine:|Flags:'
if readelf -l "$MEMORY_ELF" | grep -q 'INTERP'; then
  echo 'error: memory probe unexpectedly has a dynamic interpreter' >&2
  exit 1
fi

MEMORY_FIXTURE="$MEMORY_ROOTFS/tmp/gingervm-mmap-fixture.bin"
MEMORY_FIXTURE_EXPECTED="$BUILD_DIR/gingervm-mmap-fixture.expected"
mkdir -p "$(dirname "$MEMORY_FIXTURE")"
python3 - "$MEMORY_FIXTURE" "$MEMORY_FIXTURE_EXPECTED" <<'PY'
import pathlib
import sys

page = 4096
fixture = b"HEAD" + b"A" * (page - 4) + b"MAP2" + b"B" * (page - 4)
for path in sys.argv[1:]:
    pathlib.Path(path).write_bytes(fixture)
PY

printf '%s\n' '== Execute the genuine ARM memory-management ELF in GingerVM =='
"$ROOT/target/release/gingervm" run-elf "$MEMORY_ROOTFS" "$MEMORY_ELF" | tee "$MEMORY_LOG"
grep -Fq 'Instruction set: ARM' "$MEMORY_LOG"
grep -Fq 'Brokered syscall events: 4' "$MEMORY_LOG"
grep -Fq 'Guest exit code: 0' "$MEMORY_LOG"
cmp "$MEMORY_FIXTURE_EXPECTED" "$MEMORY_FIXTURE"
printf '%s\n' 'File-backed MAP_PRIVATE leaves the guest rootfs source unchanged.'
printf 'Memory probe ELF: %s\n' "$MEMORY_ELF"
printf 'Memory execution log: %s\n' "$MEMORY_LOG"

printf '%s\n' '== Cross-compile relocatable ARMv7 ET_DYN PIE =='
"$CLANG_BIN" \
  --target=armv7-linux-gnueabi \
  -march=armv7-a \
  -marm \
  -fPIC \
  -nostdlib \
  -fuse-ld="$LLD_DRIVER" \
  -pie \
  -Wl,--no-dynamic-linker \
  -Wl,-e,_start \
  -Wl,--build-id=none \
  -Wl,-z,noexecstack \
  -Wl,-z,max-page-size=4096 \
  -o "$PIE_ELF" \
  "$ROOT/probes/armv7-pie-probe.S"
file "$PIE_ELF"
readelf -h "$PIE_ELF" | grep -E 'Class:|Type:|Machine:|Flags:'
readelf -r "$PIE_ELF" | grep -F 'R_ARM_RELATIVE'
if readelf -h "$PIE_ELF" | grep -Eq 'Type:[[:space:]]+EXEC([[:space:]]|$)'; then
  echo 'error: PIE probe is not ET_DYN' >&2
  exit 1
fi
if readelf -l "$PIE_ELF" | grep -q 'INTERP'; then
  echo 'error: PIE probe unexpectedly has a dynamic interpreter' >&2
  exit 1
fi

printf '%s\n' '== Execute the genuine ARM ET_DYN PIE in GingerVM =='
"$ROOT/target/release/gingervm" run-elf "$PIE_ROOTFS" "$PIE_ELF" | tee "$PIE_LOG"
grep -Fq 'Instruction set: ARM' "$PIE_LOG"
grep -Fq 'Instructions executed: 8' "$PIE_LOG"
grep -Fq 'Brokered syscall events: 0' "$PIE_LOG"
grep -Fq 'Guest exit code: 0' "$PIE_LOG"
printf 'PIE probe ELF: %s\n' "$PIE_ELF"
printf 'PIE execution log: %s\n' "$PIE_LOG"

printf '%s\n' '== Cross-compile a guest PT_INTERP linker and dynamic ARM executable =='
"$CLANG_BIN" \
  --target=armv7-linux-gnueabi \
  -march=armv7-a \
  -marm \
  -fPIC \
  -nostdlib \
  -fuse-ld="$LLD_DRIVER" \
  -shared \
  -Wl,-e,_start \
  -Wl,--build-id=none \
  -Wl,-z,max-page-size=4096 \
  -o "$INTERP_ELF" \
  "$ROOT/probes/armv7-test-linker.S"
"$CLANG_BIN" \
  --target=armv7-linux-gnueabi \
  -march=armv7-a \
  -marm \
  -nostdlib \
  -fuse-ld="$LLD_DRIVER" \
  -Wl,-e,_start \
  -Wl,--dynamic-linker=/system/bin/gingervm-test-linker \
  -Wl,--build-id=none \
  -Wl,-z,max-page-size=4096 \
  -o "$INTERP_MAIN_ELF" \
  "$ROOT/probes/armv7-interp-main.S"
file "$INTERP_ELF" "$INTERP_MAIN_ELF"
readelf -h "$INTERP_MAIN_ELF" | grep -E 'Class:|Type:|Machine:|Flags:'
readelf -l "$INTERP_MAIN_ELF" | grep -F '/system/bin/gingervm-test-linker'
cp "$INTERP_ELF" "$INTERP_ROOTFS/system/bin/gingervm-test-linker"

printf '%s\n' '== Execute the real ARM PT_INTERP handoff in GingerVM =='
"$ROOT/target/release/gingervm" run-elf "$INTERP_ROOTFS" "$INTERP_MAIN_ELF" | tee "$INTERP_LOG"
grep -Fq 'Instruction set: ARM' "$INTERP_LOG"
grep -Fq 'Instructions executed: 17' "$INTERP_LOG"
grep -Fq 'Brokered syscall events: 0' "$INTERP_LOG"
grep -Fq 'Guest exit code: 0' "$INTERP_LOG"
printf 'Dynamic main ELF: %s\n' "$INTERP_MAIN_ELF"
printf 'Guest linker ELF: %s\n' "$INTERP_ELF"
printf 'Interpreter execution log: %s\n' "$INTERP_LOG"

printf '%s\n' '== Cross-compile a real ARM app and DT_NEEDED shared library =='
"$CLANG_BIN" \
  --target=armv7-linux-gnueabi \
  -march=armv7-a \
  -marm \
  -fPIC \
  -fno-stack-protector \
  -fno-builtin \
  -O1 \
  -nostdlib \
  -fuse-ld="$LLD_DRIVER" \
  -shared \
  -Wl,-soname,libgingervm-probe.so \
  -Wl,--hash-style=sysv \
  -Wl,--build-id=none \
  -Wl,-z,max-page-size=4096 \
  -o "$DYNAMIC_LIBRARY_ELF" \
  "$ROOT/probes/armv7-shared-library.c"
"$CLANG_BIN" \
  --target=armv7-linux-gnueabi \
  -march=armv7-a \
  -marm \
  -fPIC \
  -fno-stack-protector \
  -fno-builtin \
  -O1 \
  -nostdlib \
  -fuse-ld="$LLD_DRIVER" \
  -pie \
  -Wl,--hash-style=sysv \
  -Wl,-e,_start \
  -Wl,--dynamic-linker=/system/bin/gingervm-dynamic-linker \
  -Wl,--build-id=none \
  -Wl,-z,max-page-size=4096 \
  -L"$BUILD_DIR" \
  -Wl,-rpath-link,"$BUILD_DIR" \
  -o "$DYNAMIC_MAIN_ELF" \
  "$ROOT/probes/armv7-shared-main.c" \
  -lgingervm-probe
"$CLANG_BIN" \
  --target=armv7-linux-gnueabi \
  -march=armv7-a \
  -marm \
  -fPIC \
  -nostdlib \
  -fuse-ld="$LLD_DRIVER" \
  -shared \
  -Wl,-e,_start \
  -Wl,--build-id=none \
  -Wl,-z,max-page-size=4096 \
  -o "$DYNAMIC_LINKER_ELF" \
  "$ROOT/probes/armv7-dynamic-linker.S"
file "$DYNAMIC_MAIN_ELF" "$DYNAMIC_LIBRARY_ELF" "$DYNAMIC_LINKER_ELF"
readelf -d "$DYNAMIC_MAIN_ELF" | grep -F 'libgingervm-probe.so'
readelf -r "$DYNAMIC_MAIN_ELF" | grep -F 'R_ARM_GLOB_DAT'
readelf -r "$DYNAMIC_MAIN_ELF" | grep -F 'R_ARM_JUMP_SLOT'
cp "$DYNAMIC_LIBRARY_ELF" "$DYNAMIC_ROOTFS/system/lib/libgingervm-probe.so"
cp "$DYNAMIC_LINKER_ELF" "$DYNAMIC_ROOTFS/system/bin/gingervm-dynamic-linker"

printf '%s\n' '== Resolve DT_NEEDED and ARM GOT/PLT relocations before interpreter handoff =='
"$ROOT/target/release/gingervm" run-elf "$DYNAMIC_ROOTFS" "$DYNAMIC_MAIN_ELF" | tee "$DYNAMIC_LOG"
grep -Fq 'Instruction set: ARM' "$DYNAMIC_LOG"
grep -Fq 'Brokered syscall events: 0' "$DYNAMIC_LOG"
grep -Fq 'Guest exit code: 0' "$DYNAMIC_LOG"

printf '%s\n' '== Verify Gingerbread ARM REL32 and COPY relocation behavior =='
"$CLANG_BIN" \
  --target=armv5-linux-gnueabi \
  -march=armv5t \
  -marm \
  -fPIC \
  -fno-stack-protector \
  -fno-builtin \
  -O1 \
  -nostdlib \
  -fuse-ld="$LLD_DRIVER" \
  -shared \
  -Wl,-soname,libgingervm-copy.so \
  -Wl,--hash-style=sysv \
  -Wl,--build-id=none \
  -Wl,-z,max-page-size=4096 \
  -o "$COPY_LIBRARY_ELF" \
  "$ROOT/probes/armv7-copy-library.c"
"$CLANG_BIN" \
  --target=armv5-linux-gnueabi \
  -march=armv5t \
  -marm \
  -fno-pic \
  -fno-pie \
  -fno-stack-protector \
  -fno-builtin \
  -O1 \
  -nostdlib \
  -fuse-ld="$LLD_DRIVER" \
  -Wl,-no-pie \
  -Wl,-e,_start \
  -Wl,--dynamic-linker=/system/bin/gingervm-dynamic-linker \
  -Wl,--hash-style=sysv \
  -Wl,--build-id=none \
  -Wl,-z,max-page-size=4096 \
  -L"$BUILD_DIR" \
  -Wl,-rpath-link,"$BUILD_DIR" \
  -o "$COPY_MAIN_ELF" \
  "$ROOT/probes/armv7-copy-main.c" \
  -lgingervm-copy
readelf -h "$COPY_MAIN_ELF" | grep -E 'Type:[[:space:]]+EXEC|Machine:|Flags:'
readelf -d "$COPY_MAIN_ELF" | grep -F 'libgingervm-copy.so'
readelf -r "$COPY_MAIN_ELF" | grep -F 'R_ARM_COPY'
python3 "$ROOT/probes/rewrite-arm-relocation.py" \
  "$COPY_LIBRARY_ELF" ginger_copy_value 2 3
readelf -r "$COPY_LIBRARY_ELF" | grep -F 'R_ARM_REL32'
cp "$COPY_LIBRARY_ELF" "$DYNAMIC_ROOTFS/system/lib/libgingervm-copy.so"
"$ROOT/target/release/gingervm" run-elf "$DYNAMIC_ROOTFS" "$COPY_MAIN_ELF" | tee "$COPY_LOG"
grep -Fq 'Instruction set: ARM' "$COPY_LOG"
grep -Fq 'Guest exit code: 0' "$COPY_LOG"
printf 'COPY/REL32 executable: %s\n' "$COPY_MAIN_ELF"
printf 'COPY/REL32 shared library: %s\n' "$COPY_LIBRARY_ELF"
printf 'COPY/REL32 execution log: %s\n' "$COPY_LOG"

printf 'Dynamic main ELF: %s\n' "$DYNAMIC_MAIN_ELF"
printf 'Dependency ELF: %s\n' "$DYNAMIC_LIBRARY_ELF"
printf 'Dynamic relocation execution log: %s\n' "$DYNAMIC_LOG"
