#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# Linux compatibility smoke, not the pinned 18.1.8 iOS build or a real SDK test.
LLVM_PREFIX="${LLVM_PREFIX:-/usr/lib/llvm-18}"
CXX="${CXX:-c++}"
[[ -f "$LLVM_PREFIX/lib/libclang-cpp.so.18.1" ]] || { echo 'Requires Linux LLVM/Clang/LLD 18 development packages' >&2; exit 1; }
WORK="$(mktemp -d "${TMPDIR:-/tmp}/ncb-embedded.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
"$CXX" -std=c++17 -O0 -pthread -DPOCKETIDE_EMBEDDED_LLVM=1 \
  -I Sources/NativeCompilerBridge/include -I "$LLVM_PREFIX/include" \
  Sources/NativeCompilerBridge/NativeCompilerBridge.cpp Tests/EmbeddedSmoke.cpp \
  -L "$LLVM_PREFIX/lib" -Wl,-rpath,"$LLVM_PREFIX/lib" \
  "$LLVM_PREFIX/lib/libclang-cpp.so.18.1" -llldMachO -llldCommon -lLLVM-18 -o "$WORK/host-test"
"$WORK/host-test" "$WORK"
