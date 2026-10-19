#!/usr/bin/env bash
set -euo pipefail
: "${RUNNER_TEMP:=${TMPDIR:-/tmp}/pocketide-tools}"
export RUNNER_TEMP
readonly revision=21ac9944b0ab546a07422dbed86f33dd2ebd76f8
readonly source_dir="$RUNNER_TEMP/PocketIDE-XcodeGen"
mkdir -p "$RUNNER_TEMP/xcodegen-bin"
if [[ ! -d "$source_dir/.git" ]]; then
  git clone --no-checkout https://github.com/yonaskolb/XcodeGen.git "$source_dir"
fi
git -C "$source_dir" checkout --detach "$revision"
test "$(git -C "$source_dir" rev-parse HEAD)" = "$revision"
swift build --package-path "$source_dir" --configuration release --product xcodegen
bin_dir="$(swift build --package-path "$source_dir" --configuration release --show-bin-path)"
cp "$bin_dir/xcodegen" "$RUNNER_TEMP/xcodegen-bin/xcodegen"
"$RUNNER_TEMP/xcodegen-bin/xcodegen" --version
