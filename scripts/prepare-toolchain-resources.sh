#!/usr/bin/env bash
set -euo pipefail

ROOT="${POCKETIDE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
# XcodeGen/Xcode require a folder reference to exist even when it is marked
# optional. Create only the empty resource root; never replace native outputs.
mkdir -p "$ROOT/toolchain/ios-arm64/Toolchain"
