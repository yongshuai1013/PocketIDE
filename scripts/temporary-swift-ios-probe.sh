#!/usr/bin/env bash
# One-time diagnostic. No SDK copies/downloads, installation, signing or device execution.
set -euo pipefail
LOG="$GITHUB_WORKSPACE/probe-logs"
ROOT="$RUNNER_TEMP/swift-ios-probe"
mkdir -p "$LOG" "$ROOT"
stage() { printf '%s\n' "$1" | tee "$LOG/stage.txt"; }
trap 'rc=$?; echo "PROBE_EXIT=$rc LAST_STAGE=$(cat "$LOG/stage.txt")"; exit "$rc"' EXIT
stage prerequisites
xcodebuild -version | grep -Fx 'Xcode 16.4'
SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
test "$(xcrun --sdk iphoneos --show-sdk-version)" = 18.5
xcrun --sdk iphoneos --show-sdk-version
xcrun clang --version
xcrun swiftc --version
# Xcode's compiler builds the pinned 6.0.3 C++ frontend sources; it is not substituted for them.
cmake --version
ninja --version
export CMAKE_POLICY_VERSION_MINIMUM=3.5
COMMON=(-G Ninja -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DCMAKE_BUILD_TYPE=Release
  -DCMAKE_C_COMPILER="$(xcrun --find clang)" -DCMAKE_CXX_COMPILER="$(xcrun --find clang++)"
  -DLLVM_ENABLE_PROJECTS=clang -DLLVM_TARGETS_TO_BUILD=AArch64
  -DLLVM_INCLUDE_TESTS=OFF -DLLVM_INCLUDE_BENCHMARKS=OFF -DLLVM_INCLUDE_EXAMPLES=OFF
  -DLLVM_ENABLE_ZLIB=OFF -DLLVM_ENABLE_ZSTD=OFF -DLLVM_ENABLE_LIBXML2=OFF
  -DLLVM_ENABLE_TERMINFO=OFF -DLLVM_ENABLE_LIBEDIT=OFF -DLLVM_ENABLE_LIBPFM=OFF
  -DLLVM_ENABLE_ASSERTIONS=OFF -DLLVM_ENABLE_BINDINGS=OFF)
IOS=(-DCMAKE_SYSTEM_NAME=iOS -DCMAKE_OSX_SYSROOT="$SDK" -DCMAKE_OSX_ARCHITECTURES=arm64
  -DCMAKE_OSX_DEPLOYMENT_TARGET=15.0 -DCMAKE_MACOSX_BUNDLE=OFF
  -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY
  -DCMAKE_EXE_LINKER_FLAGS=-Wl,-no_adhoc_codesign)
stage acquire-pinned-open-source
while read -r name repo sha; do
  printf '%s %s %s\n' "$name" "$repo" "$sha" | tee -a "$LOG/sources.txt"
  if test -f "$ROOT/$name/.pocketide-pinned-revision"; then
    test "$(cat "$ROOT/$name/.pocketide-pinned-revision")" = "$sha"
    echo "Reusing preserved pinned source: $name $sha"
    continue
  fi
  test ! -d "$ROOT/$name" || test -z "$(ls -A "$ROOT/$name")"
  mkdir -p "$ROOT/$name"
  curl --fail --location --retry 3 "https://codeload.github.com/$repo/tar.gz/$sha" | tar -xz --strip-components=1 -C "$ROOT/$name"
  printf "%s\n" "$sha" > "$ROOT/$name/.pocketide-pinned-revision"
done <<'SOURCES'
swift swiftlang/swift 6a862d2eb7128ff1f317b07e8ad1a6da939775f3
llvm-project swiftlang/llvm-project 2e6139970eda445d9c6872c0ca293088b4e63dd2
cmark swiftlang/swift-cmark 3ccff77b2dc5b96b77db3da0d68d28068593fa53
swift-syntax swiftlang/swift-syntax 0687f71944021d616d34d922343dcef086855920
SOURCES
stage temporary-ios-cmake-configuration
# Apple's UUID symbols are in libSystem. Supply a probe-only package config,
# not a change to the pinned compiler's source or CMake files.
mkdir -p "$ROOT/uuid-config" "$ROOT/syntax-wrapper"
cat > "$ROOT/uuid-config/UUIDConfig.cmake" <<CMAKE
set(UUID_FOUND TRUE)
set(UUID_INCLUDE_DIR "$SDK/usr/include")
set(UUID_INCLUDE_DIRS "$SDK/usr/include")
set(UUID_LIBRARY "")
set(UUID_LIBRARIES "")
CMAKE
# Upstream compiler integration selects shared SwiftSyntax by default.
# A FetchContent source override keeps the exact unmodified dependency static.
cat > "$ROOT/syntax-wrapper/CMakeLists.txt" <<CMAKE
cmake_minimum_required(VERSION 3.19.6)
set(BUILD_SHARED_LIBS OFF)
add_subdirectory("$ROOT/swift-syntax" "syntax")
CMAKE
stage native-tablegen-configure
cmake -S "$ROOT/llvm-project/llvm" -B "$ROOT/native" "${COMMON[@]}"
stage native-tablegen-build
cmake --build "$ROOT/native" --target llvm-tblgen clang-tblgen --parallel 3
stage ios-cmark-configure
cmake -S "$ROOT/cmark" -B "$ROOT/cmark-ios" -G Ninja "${IOS[@]}" \
  -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_TESTING=OFF -DBUILD_SHARED_LIBS=OFF
stage ios-cmark-build
cmake --build "$ROOT/cmark-ios" --target libcmark-gfm --parallel 3
mkdir -p "$ROOT/harness"
TEMP_HARNESS="$RUNNER_TEMP/probe-harness-inputs"
mkdir -p "$TEMP_HARNESS"
printf 'include("%s/cmark-ios/src/cmarkTargets.cmake")\n' "$ROOT" > "$TEMP_HARNESS/import-cmark.cmake"
cat > "$TEMP_HARNESS/CMakeLists.txt" <<'CMAKE'
if(NOT TARGET swiftFrontendTool)
  message(FATAL_ERROR "Official static swiftFrontendTool unavailable")
endif()
get_target_property(frontend_type swiftFrontendTool TYPE)
if(NOT frontend_type STREQUAL "STATIC_LIBRARY")
  message(FATAL_ERROR "swiftFrontendTool must be static")
endif()
add_executable(ios_frontend_link_probe probe.cpp)
target_include_directories(ios_frontend_link_probe PRIVATE
  "${LLVM_EXTERNAL_SWIFT_SOURCE_DIR}/include" "${CMAKE_BINARY_DIR}/tools/swift/include" ${LLVM_INCLUDE_DIRS})
target_link_libraries(ios_frontend_link_probe PRIVATE swiftFrontendTool)
# Fail closed if the dependency override did not create real static libraries.
foreach(dependency SwiftSyntax SwiftParser swiftASTGen)
  get_target_property(dependency_type ${dependency} TYPE)
  if(NOT dependency_type STREQUAL "STATIC_LIBRARY")
    message(FATAL_ERROR "${dependency} is not a static library: ${dependency_type}")
  endif()
endforeach()
# Swift static archives require Swift's iOS runtime autolink search directory.
execute_process(COMMAND xcrun --find swiftc OUTPUT_VARIABLE probe_swiftc OUTPUT_STRIP_TRAILING_WHITESPACE)
get_filename_component(probe_tool_bin "${probe_swiftc}" DIRECTORY)
target_link_directories(ios_frontend_link_probe PRIVATE "${probe_tool_bin}/../lib/swift/iphoneos")
target_link_options(ios_frontend_link_probe PRIVATE "-Wl,-rpath,/usr/lib/swift")
target_link_options(ios_frontend_link_probe PRIVATE -Wl,-no_adhoc_codesign)
CMAKE
cat > "$TEMP_HARNESS/probe.cpp" <<'CPP'
#include "swift/FrontendTool/FrontendTool.h"
#include "llvm/ADT/ArrayRef.h"
// A real call forces the static frontend and its dependency closure into the link.
// This executable is inspected only; it is never executed, signed or installed.
int main(int argc, const char **argv) {
  return swift::performFrontend(llvm::ArrayRef<const char *>(argv + 1, argc - 1),
      argv[0], reinterpret_cast<void *>(&main));
}
CPP
for item in import-cmark.cmake CMakeLists.txt probe.cpp; do
  destination="$ROOT/harness/$item"
  test "$item" != import-cmark.cmake || destination="$ROOT/$item"
  if ! cmp -s "$TEMP_HARNESS/$item" "$destination"; then cp -p "$TEMP_HARNESS/$item" "$destination"; fi
done
stage ios-frontend-configure
cmake -S "$ROOT/llvm-project/llvm" -B "$ROOT/ios" "${COMMON[@]}" "${IOS[@]}" \
  -DCMAKE_CXX_FLAGS_RELEASE='-O1 -DNDEBUG' \
  -DHAVE_LIBRT:BOOL=OFF \
  -DCMAKE_FIND_PACKAGE_PREFER_CONFIG=ON -DUUID_DIR="$ROOT/uuid-config" \
  -DCMAKE_Swift_COMPILER="$(xcrun --find swiftc)" \
  -DCMAKE_Swift_COMPILER_TARGET=arm64-apple-ios15.0 \
  -DCMAKE_Swift_FLAGS="-sdk $SDK -target arm64-apple-ios15.0" \
  -DFETCHCONTENT_SOURCE_DIR_SWIFTSYNTAX="$ROOT/syntax-wrapper" \
  -DSWIFT_PATH_TO_SWIFT_SYNTAX_SOURCE="$ROOT/swift-syntax" \
  -DBUILD_SHARED_LIBS=OFF -DLLVM_BUILD_LLVM_DYLIB=OFF -DLLVM_LINK_LLVM_DYLIB=OFF \
  -DLLVM_ENABLE_PLUGINS=OFF -DLLVM_ENABLE_FFI=OFF \
  -DLLVM_HOST_TRIPLE=arm64-apple-ios15.0 -DLLVM_DEFAULT_TARGET_TRIPLE=arm64-apple-ios15.0 \
  -DLLVM_NATIVE_TOOL_DIR="$ROOT/native/bin" \
  -DLLVM_TABLEGEN="$ROOT/native/bin/llvm-tblgen" -DCLANG_TABLEGEN="$ROOT/native/bin/clang-tblgen" \
  -DLLVM_EXTERNAL_PROJECTS='swift;iosprobe' \
  -DLLVM_EXTERNAL_SWIFT_SOURCE_DIR="$ROOT/swift" -DLLVM_EXTERNAL_IOSPROBE_SOURCE_DIR="$ROOT/harness" \
  -DCMAKE_PROJECT_LLVM_INCLUDE="$ROOT/import-cmark.cmake" \
  -DSWIFT_HOST_VARIANT_SDK=IOS -DSWIFT_HOST_VARIANT_ARCH=arm64 -DSWIFT_HOST_VARIANT=iphoneos \
  -DSWIFT_PRIMARY_VARIANT_SDK=IOS -DSWIFT_PRIMARY_VARIANT_ARCH=arm64 \
  -DSWIFT_SDKS=IOS -DSWIFT_DARWIN_SUPPORTED_ARCHS=arm64 -DSWIFT_DARWIN_DEPLOYMENT_VERSION_IOS=15.0 \
  -DSWIFT_PATH_TO_CMARK_SOURCE="$ROOT/cmark" -DSWIFT_PATH_TO_CMARK_BUILD="$ROOT/cmark-ios" \
  -DSWIFT_NATIVE_LLVM_TOOLS_PATH="$ROOT/native/bin" \
  -DSWIFT_NATIVE_SWIFT_TOOLS_PATH="$(dirname "$(xcrun --find swiftc)")" -DSWIFT_USE_LINKER:STRING= \
  -DSWIFT_BUILD_DYNAMIC_STDLIB=OFF -DSWIFT_BUILD_STATIC_STDLIB=OFF \
  -DSWIFT_BUILD_DYNAMIC_SDK_OVERLAY=OFF -DSWIFT_BUILD_STATIC_SDK_OVERLAY=OFF \
  -DSWIFT_BUILD_STDLIB_EXTRA_TOOLCHAIN_CONTENT=OFF -DSWIFT_BUILD_STDLIB_CXX_MODULE=OFF \
  -DSWIFT_BUILD_SOURCEKIT=OFF -DSWIFT_ENABLE_DISPATCH=OFF -DSWIFT_INCLUDE_TESTS=OFF -DSWIFT_INCLUDE_DOCS=OFF \
  -DSWIFT_BUILD_SWIFT_SYNTAX=ON -DSWIFT_BUILD_REGEX_PARSER_IN_COMPILER=OFF \
  -DSWIFT_ENABLE_EXPERIMENTAL_STRING_PROCESSING=OFF
stage configured-inspect-generated-link-requirements
{
  echo 'CONFIGURE_SUCCEEDED=1; this is not proof of build/runtime/device compatibility.'
  grep -E '^(CMAKE_SYSTEM_NAME|CMAKE_OSX_|CMAKE_HOST_SYSTEM|LLVM_HOST_TRIPLE|LLVM_DEFAULT_TARGET_TRIPLE|SWIFT_HOST_VARIANT|BUILD_SHARED_LIBS|LLVM_BUILD_LLVM_DYLIB|LLVM_LINK_LLVM_DYLIB|UUID_|SWIFT_BUILD_)' "$ROOT/ios/CMakeCache.txt" || true
  echo 'Generated final target link command (last command only):'
  ninja -C "$ROOT/ios" -t commands ios_frontend_link_probe | tail -1
} > "$LOG/configure-metadata.txt"
stage ios-frontend-build-plan
ninja -C "$ROOT/ios" -n ios_frontend_link_probe > "$ROOT/full-build-plan.txt"
python3 - "$ROOT/full-build-plan.txt" "$LOG/build-plan.txt" <<'PYPLAN'
from pathlib import Path
import re,sys
lines=Path(sys.argv[1]).read_text().splitlines()
steps=[x for x in lines if re.match(r'^\[\d+/\d+\]',x)]
Path(sys.argv[2]).write_text(f'DRY_RUN_STEP_COUNT={len(steps)}\n'+ '\n'.join(lines[:20])+ '\n...\n'+ '\n'.join(lines[-10:])+ '\n')
PYPLAN
stage actual-ios-frontend-compile-link
export NINJA_STATUS='[%f/%t elapsed=%es] '
ninja -C "$ROOT/ios" -j2 ios_frontend_link_probe
stage final-link-succeeded-inspect-only
{
  file "$ROOT/ios/bin/ios_frontend_link_probe"
  xcrun vtool -show-build "$ROOT/ios/bin/ios_frontend_link_probe"
  xcrun otool -L "$ROOT/ios/bin/ios_frontend_link_probe"
} > "$LOG/link-metadata.txt"
stage completed-link-no-runtime-signing-install-or-device-test
