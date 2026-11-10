#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPO="$(cd "$ROOT/.." && pwd)"
BASE="${GINGERVM_GUEST_BASE:-$ROOT/guest-image/google-api10-android-2.3.7}"
CACHE="${GINGERVM_API10_CACHE:-$REPO/build/aosp/sdk-api10-arm}"
ARCHIVE="$CACHE/armeabi-v7a-10_r05.zip"
READELF="${READELF:-/home/ubuntu/android-sdk/ndk/27.2.12479018/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-readelf}"

[[ -x "$READELF" ]] || { echo "llvm-readelf not found: $READELF" >&2; exit 2; }
[[ -f "$ARCHIVE" ]] || { echo "official API10 archive missing: $ARCHIVE" >&2; exit 2; }
[[ ! -e "$ROOT/guest-rootfs" ]] || { echo "refusing: unexpected prototype guest-rootfs exists" >&2; exit 1; }

expect_hash() {
  local expected="$1" path="$2" actual
  actual="$(sha256sum "$path" | awk '{print $1}')"
  [[ "$actual" == "$expected" ]] || {
    echo "SHA-256 mismatch: $path ($actual != $expected)" >&2
    exit 1
  }
}

expect_hash b3c6188ca95bea7299b8325bd3bbd4f504fc85545befec979728f2ed169878df "$ARCHIVE"
expect_hash 94db377c1ee8d79dbd8bf9570d12b18fb7c14bb8829f6fe793d77c5e7f05619d "$BASE/ramdisk.img"
expect_hash e41e8698c4d138a425c1ac3324209a7a2180db324360dc64dc7937ff6e3263fd "$CACHE/system.img"

[[ -L "$BASE/system.img" ]]
[[ "$(readlink -f "$BASE/system.img")" == "$CACHE/system.img" ]]
[[ -d "$BASE/system-tree" ]]
[[ -f "$BASE/ramdisk-root/init" && -f "$BASE/ramdisk-root/init.rc" ]]
[[ -f "$BASE/ramdisk-root/sbin/adbd" ]]
[[ -L "$BASE/ramdisk-root/sbin/ueventd" ]]
[[ "$(readlink "$BASE/ramdisk-root/sbin/ueventd")" == "../init" ]]
[[ -f "$BASE/guest-root-staging/init" && -f "$BASE/guest-root-staging/init.rc" ]]
[[ -L "$BASE/guest-root-staging/system" ]]
[[ "$(readlink "$BASE/guest-root-staging/system")" == "../system-tree" ]]
[[ -e "$BASE/guest-root-staging/system/bin/app_process" ]]
[[ -e "$BASE/guest-root-staging/system/bin/linker" ]]
grep -q '^ro.build.version.release=2.3.7$' "$BASE/system-tree/build.prop"
grep -q '^ro.build.version.sdk=10$' "$BASE/system-tree/build.prop"

INIT_HEADER="$("$READELF" -h "$BASE/guest-root-staging/init")"
grep -q 'Class:.*ELF32' <<<"$INIT_HEADER"
grep -q 'Machine:.*ARM' <<<"$INIT_HEADER"
if "$READELF" -l "$BASE/guest-root-staging/init" | grep -q 'Requesting program interpreter'; then
  echo 'expected original init to remain static (PT_INTERP absent)' >&2
  exit 1
fi

APP_HEADER="$("$READELF" -h "$BASE/guest-root-staging/system/bin/app_process")"
grep -q 'Class:.*ELF32' <<<"$APP_HEADER"
grep -q 'Machine:.*ARM' <<<"$APP_HEADER"
"$READELF" -l "$BASE/guest-root-staging/system/bin/app_process" | grep -q 'Requesting program interpreter: /system/bin/linker'

printf '%s\n' 'PASS: official image hashes and isolated init/system guest-root staging verified.'
printf '%s\n' 'INFO: this checks staging only; it does not execute init or assert Android boot.'
printf '%s\n' 'INFO: no mount or host-root operation was used.'
