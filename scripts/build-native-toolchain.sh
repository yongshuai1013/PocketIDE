#!/usr/bin/env bash
set -euo pipefail

# Experimental recipe: requires macOS/Xcode 16.4. Never copies the Apple SDK.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLCHAIN="$ROOT/toolchain"
BUILD_ROOT="${POCKETIDE_TOOLCHAIN_BUILD_DIR:-$ROOT/.toolchain-build}"
PREFIX="$TOOLCHAIN/ios-arm64"
LLVM_COMMIT="3b5b5c1ec4a3095ab096dd780e84d7ab81f3d7ff"
LLVM_REPO="https://github.com/llvm/llvm-project.git"
fail() { echo "error: $*" >&2; exit 1; }
[[ "$(uname -s)" == Darwin ]] || fail "This build requires macOS and Xcode; Linux cross-builds are unsupported."
xcode_version="$(xcodebuild -version)" || fail "Could not read the selected Xcode version."
[[ "$xcode_version" == "Xcode 16.4"$'\n'* ]] || fail "Select Xcode 16.4 using DEVELOPER_DIR."
command -v cmake >/dev/null || fail "cmake is required"
command -v ninja >/dev/null || fail "ninja is required"
SDKROOT="$(xcrun --sdk iphoneos --show-sdk-path)"
[[ -d "$SDKROOT" ]] || fail "iPhoneOS SDK not found in local Xcode"
# Fail closed even when a previous installation exists and this attempt fails.
cat > "$TOOLCHAIN/NativeCompiler.generated.xcconfig" <<'CONFIG'
// Disabled until the complete native toolchain passes the link check.
POCKETIDE_EMBEDDED_LLVM = 0
CLANG_CXX_LANGUAGE_STANDARD = c++17
CONFIG
SRC="$BUILD_ROOT/llvm-project"
FRESH_CLONE=0
if [[ ! -d "$SRC/.git" ]]; then
  mkdir -p "$BUILD_ROOT"
  git clone --filter=blob:none --no-checkout "$LLVM_REPO" "$SRC"
  FRESH_CLONE=1
fi
[[ "$FRESH_CLONE" == 1 || -z "$(git -C "$SRC" status --porcelain)" ]] || fail "LLVM source tree has local changes; use a clean build directory."
git -C "$SRC" fetch --depth=1 origin "$LLVM_COMMIT"
[[ "$(git -C "$SRC" rev-parse 'FETCH_HEAD^{commit}')" == "$LLVM_COMMIT" ]] || fail "Source SHA mismatch"
git -C "$SRC" checkout --detach "$LLVM_COMMIT"
JOBS="${JOBS:-4}"
HOST_BUILD="$BUILD_ROOT/host"
IOS_BUILD="$BUILD_ROOT/ios-arm64"
cmake -S "$SRC/llvm" -B "$HOST_BUILD" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_PROJECTS=clang -DLLVM_TARGETS_TO_BUILD=AArch64 \
  -DLLVM_INCLUDE_TESTS=OFF -DLLVM_INCLUDE_EXAMPLES=OFF -DLLVM_INCLUDE_BENCHMARKS=OFF \
  -DLLVM_ENABLE_TERMINFO=OFF -DLLVM_ENABLE_ZLIB=OFF -DLLVM_ENABLE_ZSTD=OFF \
  -DLLVM_ENABLE_LIBXML2=OFF -DLLVM_ENABLE_LIBEDIT=OFF -DLLVM_ENABLE_LIBPFM=OFF
cmake --build "$HOST_BUILD" --target llvm-tblgen clang-tblgen --parallel "$JOBS"
# CMake defaults executables to app bundles for iOS. LLVM's auxiliary tools
# use RUNTIME install rules, not BUNDLE rules, even when excluded from the build.
cmake -S "$SRC/llvm" -B "$IOS_BUILD" -G Ninja \
  -DCMAKE_SYSTEM_NAME=iOS -DCMAKE_OSX_SYSROOT="$SDKROOT" -DCMAKE_OSX_ARCHITECTURES=arm64 \
  -DCMAKE_MACOSX_BUNDLE=OFF \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=15.0 -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY \
  -DCMAKE_C_COMPILER="$(xcrun --find clang)" -DCMAKE_CXX_COMPILER="$(xcrun --find clang++)" \
  -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DLLVM_BUILD_LLVM_DYLIB=OFF \
  -DLLVM_LINK_LLVM_DYLIB=OFF -DLLVM_ENABLE_PIC=ON -DLLVM_ENABLE_PROJECTS='clang;lld' \
  -DLLVM_TARGETS_TO_BUILD=AArch64 -DLLVM_HOST_TRIPLE=arm64-apple-ios15.0 \
  -DLLVM_DEFAULT_TARGET_TRIPLE=arm64-apple-ios15.0 \
  -DLLVM_NATIVE_TOOL_DIR="$HOST_BUILD/bin" \
  -DLLVM_TABLEGEN="$HOST_BUILD/bin/llvm-tblgen" -DCLANG_TABLEGEN="$HOST_BUILD/bin/clang-tblgen" \
  -DLLVM_INCLUDE_TESTS=OFF -DLLVM_INCLUDE_EXAMPLES=OFF -DLLVM_INCLUDE_BENCHMARKS=OFF \
  -DLLVM_INCLUDE_UTILS=OFF -DLLVM_BUILD_TOOLS=OFF -DLLVM_ENABLE_TERMINFO=OFF \
  -DLLVM_ENABLE_ZLIB=OFF -DLLVM_ENABLE_ZSTD=OFF -DLLVM_ENABLE_LIBXML2=OFF \
  -DLLVM_ENABLE_LIBEDIT=OFF -DLLVM_ENABLE_LIBPFM=OFF -DLLVM_ENABLE_FFI=OFF \
  -DLLVM_ENABLE_PLUGINS=OFF -DLLVM_ENABLE_ASSERTIONS=OFF -DLLVM_ENABLE_RTTI=ON -DLLVM_ENABLE_EH=ON \
  -DCLANG_BUILD_TOOLS=OFF -DCLANG_INCLUDE_TESTS=OFF -DCLANG_INCLUDE_DOCS=OFF \
  -DLLD_BUILD_TOOLS=OFF -DLLD_INCLUDE_TESTS=OFF
# Build only the needed static-library dependency closure, not iOS-hosted CLI tools.
cmake --build "$IOS_BUILD" --target clangCodeGen clangFrontend clangDriver lldMachO lldCommon clang-resource-headers --parallel "$JOBS"
STAGE="$BUILD_ROOT/stage"
rm -rf "$STAGE"
mkdir -p "$STAGE/include" "$STAGE/lib" "$STAGE/Toolchain/clang/include" "$STAGE/licenses"
for dir in "$SRC/llvm/include" "$SRC/clang/include" "$SRC/lld/include" "$IOS_BUILD/include" "$IOS_BUILD/tools/clang/include"; do
  [[ -d "$dir" ]] && cp -R "$dir/." "$STAGE/include/"
done
find "$IOS_BUILD/lib" -maxdepth 1 -type f -name '*.a' -exec cp '{}' "$STAGE/lib/" \;
[[ -f "$STAGE/lib/liblldMachO.a" && -f "$STAGE/lib/libclangCodeGen.a" ]] || fail "Missing Clang/LLD libraries"
RESOURCE_HEADERS="$IOS_BUILD/lib/clang/18/include"
[[ -f "$RESOURCE_HEADERS/stddef.h" ]] || fail "Missing generated Clang resource headers"
cp -R "$RESOURCE_HEADERS/." "$STAGE/Toolchain/clang/include/"
for component in llvm clang lld; do cp "$SRC/$component/LICENSE.TXT" "$STAGE/licenses/$component-LICENSE.TXT"; done
# Check the exact bridge against the staged device headers, then force-link the full archive closure.
BRIDGE="$ROOT/Packages/NativeCompilerBridge/Sources/NativeCompilerBridge"
xcrun --sdk iphoneos clang++ -arch arm64 -isysroot "$SDKROOT" -miphoneos-version-min=15.0 \
  -std=c++17 -DPOCKETIDE_EMBEDDED_LLVM=1 -I "$STAGE/include" -I "$BRIDGE/include" \
  -c "$BRIDGE/NativeCompilerBridge.cpp" -o "$BUILD_ROOT/bridge-ios.o"
printf '#include "NativeCompilerBridge.h"\nint main(void) { return ncb_get_capabilities().flags == 0; }\n' > "$BUILD_ROOT/link-check.cpp"
LINK_FLAGS=()
while IFS= read -r lib; do LINK_FLAGS+=("-Xlinker" "-force_load" "-Xlinker" "$lib"); done < <(find "$STAGE/lib" -maxdepth 1 -name '*.a' -type f | LC_ALL=C sort)
xcrun --sdk iphoneos clang++ -arch arm64 -isysroot "$SDKROOT" -miphoneos-version-min=15.0 \
  -std=c++17 -I "$BRIDGE/include" "$BUILD_ROOT/link-check.cpp" "$BUILD_ROOT/bridge-ios.o" \
  "${LINK_FLAGS[@]}" -lc++ -Wl,-no_adhoc_codesign -o "$BUILD_ROOT/link-check-ios"
xcrun lipo "$BUILD_ROOT/link-check-ios" -verify_arch arm64
{
  printf 'LLVM_VERSION=18.1.8\nBUILTIN_HEADERS_VERSION=18.1.8\nLLVM_COMMIT=%s\nTARGET=arm64-apple-ios15.0\nXCODE=16.4\n' "$LLVM_COMMIT"
  printf 'IOS_SDK=%s\nSWIFT_FRONTEND=0\n' "$(xcrun --sdk iphoneos --show-sdk-version)"
  printf 'LIBRARIES:\n'
  find "$STAGE/lib" -maxdepth 1 -name '*.a' -type f | LC_ALL=C sort | sed "s#^$STAGE/##"
} > "$STAGE/manifest.txt"
cp "$STAGE/manifest.txt" "$STAGE/Toolchain/manifest.txt"
rm -rf "$PREFIX"
mv "$STAGE" "$PREFIX"
{
  printf '// Generated only after compiling and linking the actual bridge for iOS.\n'
  # An iphoneos-only bundle must never be passed to a simulator linker.
  printf 'POCKETIDE_EMBEDDED_LLVM = 0\nPOCKETIDE_EMBEDDED_LLVM[sdk=iphoneos*] = 1\n'
  printf 'HEADER_SEARCH_PATHS[sdk=iphoneos*] = $(inherited) "$(PROJECT_DIR)/toolchain/ios-arm64/include"\n'
  printf 'CLANG_CXX_LANGUAGE_STANDARD = c++17\nIPHONEOS_DEPLOYMENT_TARGET = 15.0\n'
  printf 'OTHER_LDFLAGS[sdk=iphoneos*] = $(inherited)'
  while IFS= read -r lib; do
    printf ' -Xlinker -force_load -Xlinker "$(PROJECT_DIR)/toolchain/ios-arm64/lib/%s"' "$(basename "$lib")"
  done < <(find "$PREFIX/lib" -maxdepth 1 -name '*.a' -type f | LC_ALL=C sort)
  printf ' -lc++\n'
} > "$TOOLCHAIN/NativeCompiler.generated.xcconfig"
echo "Clang/LLD iOS link-check passed; bundle staged at $PREFIX. Device execution is not tested."
