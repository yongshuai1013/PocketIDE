#!/usr/bin/env bash
set -euo pipefail
app="${1:?usage: verify-app.sh path/to/PocketIDE.app}"
test -d "$app"
minimum=$(/usr/libexec/PlistBuddy -c 'Print :MinimumOSVersion' "$app/Info.plist")
test "$minimum" = '15.0'
executable=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$app/Info.plist")
xcrun lipo -verify_arch arm64 "$app/$executable"
if codesign -dv "$app" >/dev/null 2>&1; then
  echo 'Unexpected signature: this workflow must emit an unsigned app.' >&2
  exit 1
fi
xcrun vtool -show-build "$app/$executable"
echo 'Verified: iOS 15.0 minimum, arm64, no code signature. Not a device runtime test.'
