#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPO="$(cd "$ROOT/.." && pwd)"
BASE="${GINGERVM_GUEST_BASE:-$ROOT/guest-image/google-api10-android-2.3.7}"
CACHE="${GINGERVM_API10_CACHE:-$REPO/build/aosp/sdk-api10-arm}"
ARCHIVE_NAME='armeabi-v7a-10_r05.zip'
ARCHIVE_URL='https://dl.google.com/android/repository/sys-img/android/armeabi-v7a-10_r05.zip'
EXPECTED_ARCHIVE='b3c6188ca95bea7299b8325bd3bbd4f504fc85545befec979728f2ed169878df'

command -v curl >/dev/null || { echo 'curl is required to fetch the official Google API10 package' >&2; exit 2; }
command -v debugfs >/dev/null || { echo 'debugfs (e2fsprogs) is required for rootless system.img extraction' >&2; exit 2; }
command -v python3 >/dev/null || { echo 'python3 is required for newc CPIO extraction' >&2; exit 2; }
mkdir -p "$BASE" "$CACHE"
TMP="$(mktemp -d "$CACHE/.gingervm-api10-prepare.XXXXXX")"
STAGE="$(mktemp -d "$BASE/.gingervm-api10-stage.XXXXXX")"
cleanup() { rm -rf "$TMP" "$STAGE"; }
trap cleanup EXIT

ARCHIVE_SOURCE="${GINGERVM_API10_ARCHIVE_SOURCE:-}"
if [[ -n "$ARCHIVE_SOURCE" ]]; then
  [[ -f "$ARCHIVE_SOURCE" ]] || { echo "archive source missing: $ARCHIVE_SOURCE" >&2; exit 2; }
  cp "$ARCHIVE_SOURCE" "$TMP/$ARCHIVE_NAME"
elif [[ -f "$CACHE/$ARCHIVE_NAME" ]] && [[ "$(sha256sum "$CACHE/$ARCHIVE_NAME" | awk '{print $1}')" == "$EXPECTED_ARCHIVE" ]]; then
  cp "$CACHE/$ARCHIVE_NAME" "$TMP/$ARCHIVE_NAME"
else
  echo "Downloading official API10 SDK package: $ARCHIVE_URL"
  curl --fail --location --retry 3 --retry-all-errors --connect-timeout 30 \
    "$ARCHIVE_URL" -o "$TMP/$ARCHIVE_NAME"
fi

python3 "$ROOT/tests/extract_google_api10_images.py" \
  "$TMP/$ARCHIVE_NAME" "$TMP/images"

mv -f "$TMP/$ARCHIVE_NAME" "$CACHE/$ARCHIVE_NAME"
mv -f "$TMP/images/system.img" "$CACHE/system.img"
install -m 0644 "$TMP/images/ramdisk.img" "$BASE/ramdisk.img"
ln -sfn "$CACHE/system.img" "$BASE/system.img"

python3 "$ROOT/tests/extract_android_newc_ramdisk.py" \
  "$BASE/ramdisk.img" "$STAGE/ramdisk-root"
mkdir "$STAGE/system-tree"
debugfs -R "rdump / $STAGE/system-tree" "$CACHE/system.img" \
  >"$STAGE/debugfs.stdout" 2>"$STAGE/debugfs.stderr"

# The original ramdisk contains an empty /system directory. The staged guest root
# pairs that ramdisk with the image's extracted /system using a confined link.
cp -a "$STAGE/ramdisk-root" "$STAGE/guest-root-staging"
rm -rf "$STAGE/guest-root-staging/system"
ln -s ../system-tree "$STAGE/guest-root-staging/system"

for generated in ramdisk-root system-tree guest-root-staging; do
  rm -rf "$BASE/$generated"
  mv "$STAGE/$generated" "$BASE/$generated"
done

ARCHIVE_SHA="$(sha256sum "$CACHE/$ARCHIVE_NAME" | awk '{print $1}')"
SYSTEM_SHA="$(sha256sum "$CACHE/system.img" | awk '{print $1}')"
RAMDISK_SHA="$(sha256sum "$BASE/ramdisk.img" | awk '{print $1}')"
[[ "$ARCHIVE_SHA" == "$EXPECTED_ARCHIVE" ]]
echo "Prepared official API10 package: archive=$ARCHIVE_SHA ramdisk=$RAMDISK_SHA system=$SYSTEM_SHA"
echo 'Staging used gzip/newc parsing and unprivileged debugfs only; no host mount or root operation was performed.'
