#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP="$ROOT/android-app"
SDK_ROOT="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-/home/ubuntu/android-sdk}}"
NDK="$SDK_ROOT/ndk/27.2.12479018"
IMAGE_DIR="$ROOT/build/aosp/sdk-api10-arm"
IMAGE_ZIP="$IMAGE_DIR/armeabi-v7a-10_r05.zip"
IMAGE_IMG="$IMAGE_DIR/system.img"
IMAGE_URL="https://dl.google.com/android/repository/sys-img/android/armeabi-v7a-10_r05.zip"
IMAGE_SHA256="b3c6188ca95bea7299b8325bd3bbd4f504fc85545befec979728f2ed169878df"
SYSTEM_ROOT="$IMAGE_DIR/system-root"
AOSP_ROOTFS="$ROOT/build/aosp/init-api10-probe/rootfs"
ASSETS="$APP/app/src/main/assets/rootfs"
JNI_DIR="$APP/app/src/main/jniLibs"
JNI_SOURCE="$APP/app/src/main/cpp/gingervm_jni.c"

for tool in cargo rustup curl unzip sha256sum debugfs; do
    command -v "$tool" >/dev/null || { echo "Missing tool: $tool" >&2; exit 1; }
done
[ -x "$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android23-clang" ] || {
    echo "Missing Android NDK 27.2.12479018 under $SDK_ROOT" >&2; exit 1;
}
[ -d "$SDK_ROOT/platforms/android-35" ] || { echo "Missing Android SDK platform 35" >&2; exit 1; }
[ -d "$SDK_ROOT/build-tools/35.0.0" ] || { echo "Missing Android Build Tools 35.0.0" >&2; exit 1; }
[ -f "$AOSP_ROOTFS/init" ] && [ -f "$AOSP_ROOTFS/init.rc" ] || {
    echo "Missing the verified AOSP init probe under $AOSP_ROOTFS; prepare probes/run-aosp-init.py first" >&2; exit 1;
}

mkdir -p "$IMAGE_DIR"
if [ ! -f "$IMAGE_ZIP" ]; then
    echo "Downloading Android SDK API 10 ARM system image..."
    curl -fL --retry 3 "$IMAGE_URL" -o "$IMAGE_ZIP"
fi
printf '%s  %s\n' "$IMAGE_SHA256" "$IMAGE_ZIP" | sha256sum -c -
if [ ! -f "$IMAGE_IMG" ]; then
    if [ -f "$IMAGE_DIR/unpacked/armeabi-v7a/system.img" ]; then
        mv "$IMAGE_DIR/unpacked/armeabi-v7a/system.img" "$IMAGE_IMG"
    else
        unzip -p "$IMAGE_ZIP" armeabi-v7a/system.img >"$IMAGE_IMG"
    fi
fi
if [ ! -f "$SYSTEM_ROOT/build.prop" ]; then
    rm -rf "$SYSTEM_ROOT"
    mkdir -p "$SYSTEM_ROOT"
    debugfs -R "rdump / $SYSTEM_ROOT" "$IMAGE_IMG" >"$IMAGE_DIR/debugfs-extract.log" 2>&1
fi
grep -Fx 'ro.build.version.release=2.3.7' "$SYSTEM_ROOT/build.prop" >/dev/null || {
    echo "The extracted Android image is not identified as Android 2.3.7" >&2; exit 1;
}
[ -f "$SYSTEM_ROOT/etc/NOTICE.html.gz" ] || { echo "Missing Android open-source NOTICE" >&2; exit 1; }

rm -rf "$ASSETS"
mkdir -p "$ASSETS/system"
cp "$AOSP_ROOTFS/init" "$ASSETS/init"
cp "$AOSP_ROOTFS/init.rc" "$ASSETS/init.rc"
cp -rL "$SYSTEM_ROOT/." "$ASSETS/system/"
cat > "$ASSETS/IMAGE_SOURCE.txt" <<EOF
Android SDK API 10 ARM EABI v7a default system image, revision 5
Source: $IMAGE_URL
Archive SHA-256: $IMAGE_SHA256
Image build.prop: Android 2.3.7, generic/sdk/generic, build 3644351
Extracted payload: system partition only (/system tree).
AOSP init source tag: android-2.3.7_r1; see android-app/README.md.
EOF

NDK_BIN="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
export ANDROID_HOME="$SDK_ROOT" ANDROID_SDK_ROOT="$SDK_ROOT"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$NDK_BIN/aarch64-linux-android23-clang"
export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER="$NDK_BIN/armv7a-linux-androideabi23-clang"

build_native() {
    local rust_target="$1"
    local abi="$2"
    local clang="$3"
    local out="$ROOT/target/$rust_target/release"
    local dest="$JNI_DIR/$abi"
    mkdir -p "$dest"
    cargo build --release --lib --target "$rust_target" --manifest-path "$ROOT/Cargo.toml"
    cp "$out/libgingervm_core.so" "$dest/libgingervm_core.so"
    "$NDK_BIN/$clang" -shared -fPIC -std=c11 -O2 \
        -I"$NDK/sysroot/usr/include" \
        "$JNI_SOURCE" -L"$dest" -Wl,--no-undefined \
        -Wl,-soname,libgingervm_jni.so -lgingervm_core \
        -o "$dest/libgingervm_jni.so"
}

build_native aarch64-linux-android arm64-v8a aarch64-linux-android23-clang
build_native armv7-linux-androideabi armeabi-v7a armv7a-linux-androideabi23-clang

if [ ! -x "$APP/gradlew" ]; then
    echo "Missing Gradle Wrapper; generate it with Gradle 8.9 before building." >&2
    exit 1
fi
(cd "$APP" && ./gradlew --no-daemon assembleDebug)

APK="$APP/app/build/outputs/apk/debug/app-debug.apk"
[ -f "$APK" ] || { echo "APK was not produced at $APK" >&2; exit 1; }
mkdir -p "$ROOT/dist"
cp "$APK" "$ROOT/dist/GingerVM-Android-2.3.7-debug.apk"
BT="$SDK_ROOT/build-tools/35.0.0"
"$BT/apksigner" verify --verbose "$ROOT/dist/GingerVM-Android-2.3.7-debug.apk"
"$BT/aapt" dump badging "$ROOT/dist/GingerVM-Android-2.3.7-debug.apk" >"$ROOT/dist/apk-badging.txt"
sed -n '1,15p' "$ROOT/dist/apk-badging.txt"
printf '\nAPK: %s\n' "$ROOT/dist/GingerVM-Android-2.3.7-debug.apk"
sha256sum "$ROOT/dist/GingerVM-Android-2.3.7-debug.apk"
ls -lh "$ROOT/dist/GingerVM-Android-2.3.7-debug.apk"
