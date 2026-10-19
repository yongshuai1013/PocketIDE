#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
WORK="$(mktemp -d "${TMPDIR:-/tmp}/ncb-stub.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
cat > "$WORK/main.cpp" <<'CPP'
#include "NativeCompilerBridge.h"
#include <cassert>
#include <cstring>
int main() {
  auto capabilities = ncb_get_capabilities();
  assert(capabilities.abi_version == NCB_ABI_VERSION && capabilities.flags == 0);
  const char *args[] = {"clang", "-c", "input.c"};
  auto result = ncb_compile_driver_argv(3, args);
  assert(result.status != 0 && result.diagnostics.text && result.diagnostics.length);
  assert(std::strstr(result.diagnostics.text, "without embedded LLVM"));
  ncb_dispose_diagnostics(&result.diagnostics);
  ncb_dispose_diagnostics(&result.diagnostics);
  assert(!result.diagnostics.text && !result.diagnostics.length);
  result = ncb_link_lld_argv(0, nullptr);
  assert(result.status != 0);
  ncb_dispose_diagnostics(&result.diagnostics);
}
CPP
for mode in undefined disabled; do
  FLAGS=()
  if [[ "$mode" == disabled ]]; then FLAGS+=(-DPOCKETIDE_EMBEDDED_LLVM=0); fi
  "${CXX:-c++}" -std=c++17 ${FLAGS[@]+"${FLAGS[@]}"} -I Sources/NativeCompilerBridge/include \
    "$WORK/main.cpp" Sources/NativeCompilerBridge/NativeCompilerBridge.cpp -o "$WORK/test"
  "$WORK/test"
done
echo 'NativeCompilerBridge stub smoke passed (macro absent and explicitly zero)'
