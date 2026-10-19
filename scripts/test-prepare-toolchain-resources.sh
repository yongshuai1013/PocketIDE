#!/usr/bin/env bash
set -euo pipefail
ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT
SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/prepare-toolchain-resources.sh"
RESOURCE_DIR="$ROOT/toolchain/ios-arm64/Toolchain"

POCKETIDE_ROOT="$ROOT" bash "$SCRIPT"
test -d "$RESOURCE_DIR"
test -z "$(find "$RESOURCE_DIR" -mindepth 1 -print -quit)"
mkdir -p "$RESOURCE_DIR/clang/include"
printf 'native-resource\n' > "$RESOURCE_DIR/clang/include/stddef.h"
POCKETIDE_ROOT="$ROOT" bash "$SCRIPT"
grep -Fx 'native-resource' "$RESOURCE_DIR/clang/include/stddef.h"
