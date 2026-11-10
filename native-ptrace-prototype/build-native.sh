#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
SDK="${ANDROID_SDK_ROOT:-/home/ubuntu/android-sdk}"
NDK="${ANDROID_NDK_HOME:-$SDK/ndk/27.2.12479018}"
TOOLCHAIN="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
READELF="$TOOLCHAIN/llvm-readelf"
OUT64="$ROOT/app/src/main/jniLibs/arm64-v8a"
OUT32="$ROOT/app/src/main/jniLibs/armeabi-v7a"
GUEST_ROOT="${GINGERVM_GUEST_BASE:-$ROOT/guest-image/google-api10-android-2.3.7}"
GUEST_STAGING="$GUEST_ROOT/guest-root-staging"
SYSTEM_TREE="$GUEST_ROOT/system-tree"
ASSETS="$ROOT/app/src/main/assets"

printf '%s\n' 'Verifying the matched official Google API10 ramdisk and system image...'
bash "$ROOT/tests/verify_google_api10_guest.sh"
printf '%s\n' 'Running legacy smoke-tracer and continuous process-tree host regressions...'
bash "$ROOT/tests/run_startup_regression.sh"
printf '%s\n' 'Running software-only guest broker/path regression...'
bash "$ROOT/tests/run_init_broker_regression.sh"

if [[ ! -x "$TOOLCHAIN/clang" || ! -x "$READELF" ]]; then
  echo "Android NDK clang/readelf not found under: $TOOLCHAIN" >&2
  exit 2
fi
if [[ ! -d "$SYSTEM_TREE" || ! -d "$GUEST_STAGING" ]]; then
  echo 'Verified original API10 guest root or full system-tree is missing.' >&2
  exit 2
fi
mkdir -p "$OUT64" "$OUT32" "$ASSETS"

# Remove only stale executable outputs produced by this isolated prototype's prior revisions.
rm -f "$OUT64/libprobe_supervisor.so" "$OUT32/libprobe_guest.so"
rm -f "$OUT32/libgingervm_guest_init.so" "$OUT32/libgingervm_guest_linker.so"

cc -std=c11 -O2 -Wall -Wextra -Werror -fsyntax-only \
  "$ROOT/app/src/main/cpp/init_supervisor.c"
"$TOOLCHAIN/clang" --target=aarch64-linux-android23 \
  -O2 -std=c11 -Wall -Wextra -Werror -fPIE -pie \
  -D_FILE_OFFSET_BITS=64 -Wl,--build-id=none \
  "$ROOT/app/src/main/cpp/init_supervisor.c" \
  -o "$OUT64/libgingervm_init_supervisor.so"
cp "$GUEST_STAGING/init" "$OUT32/libgingervm_guest_init.so"
chmod 755 "$OUT64/libgingervm_init_supervisor.so" "$OUT32/libgingervm_guest_init.so"

python3 "$ROOT/tests/stage_init_assets.py" \
  "$GUEST_STAGING" "$SYSTEM_TREE" "$ASSETS" "$OUT32"

"$READELF" -h "$OUT64/libgingervm_init_supervisor.so" | grep -Eq 'Class:.*ELF64'
"$READELF" -h "$OUT64/libgingervm_init_supervisor.so" | grep -Eq 'Machine:.*AArch64'
"$READELF" -h "$OUT32/libgingervm_guest_init.so" | grep -Eq 'Class:.*ELF32'
"$READELF" -h "$OUT32/libgingervm_guest_init.so" | grep -Eq 'Machine:.*ARM'

printf '%s\n' 'Continuous ARM64 supervisor and original static init staged; complete API10 userland native payloads staged.'
printf 'ARM64 supervisor: %s\n' "$OUT64/libgingervm_init_supervisor.so"
printf 'ARM32 original init: %s\n' "$OUT32/libgingervm_guest_init.so"
printf 'ARM32 original system linker: %s\n' "$OUT32/libgingervm_guest_linker.so"
printf '%s\n' 'Standalone legacy probe ELFs are excluded from this APK.'

cd "$ROOT"
export ANDROID_HOME="$SDK"
export ANDROID_SDK_ROOT="$SDK"
chmod +x ./gradlew 2>/dev/null || true
if [[ "${GINGERVM_GRADLE_OFFLINE:-0}" == "1" ]]; then
  ./gradlew --offline assembleDebug
else
  ./gradlew assembleDebug
fi
APK="$ROOT/app/build/outputs/apk/debug/app-debug.apk"
bash "$ROOT/tests/check_native_exec_packaging.sh" \
  "$APK" "$READELF" "$GUEST_STAGING/init" "$SYSTEM_TREE"
printf '\nAPK: %s\n' "$APK"
printf 'APK bytes: %s\n' "$(stat -c '%s' "$APK")"
sha256sum "$APK"
