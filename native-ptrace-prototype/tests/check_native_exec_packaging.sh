#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 4 ]]; then
  echo "usage: check_native_exec_packaging.sh <apk> <llvm-readelf> <official-init> <system-tree>" >&2
  exit 2
fi
APK="$1"
READELF="$2"
OFFICIAL_INIT="$3"
SYSTEM_TREE="$4"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

python3 - "$APK" "$OFFICIAL_INIT" "$SYSTEM_TREE" "$TMP" <<'PY'
import hashlib
import json
import os
import pathlib
import struct
import sys
import zipfile

apk = pathlib.Path(sys.argv[1])
official_init = pathlib.Path(sys.argv[2])
system_root = pathlib.Path(sys.argv[3])
tmp = pathlib.Path(sys.argv[4])
expected_init = "2d9cbb198d8367f434c5fd7bada245c9e7618dc910253190f5d4dd3d0f6d1a00"
expected_system_img = "e41e8698c4d138a425c1ac3324209a7a2180db324360dc64dc7937ff6e3263fd"
expected_ramdisk_img = "94db377c1ee8d79dbd8bf9570d12b18fb7c14bb8829f6fe793d77c5e7f05619d"

def digest(data):
    return hashlib.sha256(data).hexdigest()

def safe_source_path(relative):
    p = pathlib.PurePosixPath(relative)
    assert not p.is_absolute() and ".." not in p.parts, relative
    return system_root.joinpath(*p.parts)

def arm32_elf(data, label):
    assert len(data) >= 20 and data[:4] == b"\x7fELF", f"not ELF: {label}"
    assert data[4] == 1, f"not ELF32: {label}"
    assert struct.unpack_from("<H", data, 18)[0] == 40, f"not ARM: {label}"

def expected_patched_interpreter(data):
    assert len(data) >= 52 and data[:4] == b"\x7fELF" and data[4] == 1 and data[5] == 1
    phoff = struct.unpack_from("<I", data, 28)[0]
    phentsize = struct.unpack_from("<H", data, 42)[0]
    phnum = struct.unpack_from("<H", data, 44)[0]
    assert phentsize == 32 and 0 < phnum <= 128 and phoff + phentsize * phnum <= len(data)
    patched = bytearray(data)
    found = False
    for index in range(phnum):
        entry = phoff + index * phentsize
        p_type = struct.unpack_from("<I", data, entry)[0]
        p_offset = struct.unpack_from("<I", data, entry + 4)[0]
        p_filesz = struct.unpack_from("<I", data, entry + 16)[0]
        if p_type != 3:
            continue
        assert not found and p_filesz >= 2 and p_offset + p_filesz <= len(data)
        raw = data[p_offset:p_offset + p_filesz]
        assert raw[-1] == 0
        original_path, trailing = raw.split(b"\0", 1)
        assert original_path == b"/system/bin/linker" and not any(trailing)
        replacement = b"/proc/self/fd/198\0"
        assert len(replacement) <= p_filesz
        patched[p_offset:p_offset + p_filesz] = replacement + b"\0" * (p_filesz - len(replacement))
        found = True
    assert found
    return bytes(patched)

with zipfile.ZipFile(apk) as zf:
    names = set(zf.namelist())
    manifest_path = "assets/api10-system-manifest.json"
    manifest_hash_path = "assets/api10-system-manifest.sha256"
    assert manifest_path in names and manifest_hash_path in names
    manifest_bytes = zf.read(manifest_path)
    manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
    assert zf.read(manifest_hash_path).decode().strip() == manifest_hash
    manifest = json.loads(manifest_bytes)
    assert manifest["init_sha256"] == expected_init
    assert manifest["source_system_img_sha256"] == expected_system_img
    assert manifest["source_ramdisk_img_sha256"] == expected_ramdisk_img
    assert digest(official_init.read_bytes()) == expected_init
    actual_directories = set()
    for directory, dirnames, _ in os.walk(system_root, followlinks=False):
        current = pathlib.Path(directory)
        relative_dir = current.relative_to(system_root)
        if relative_dir.parts:
            actual_directories.add(relative_dir.as_posix())
        kept = []
        for name in dirnames:
            child = current / name
            if child.is_symlink():
                continue
            actual_directories.add((relative_dir / name).as_posix())
            kept.append(name)
        dirnames[:] = kept
    assert set(manifest["directories"]) == actual_directories, "source directory manifest mismatch"

    required = {
        "lib/arm64-v8a/libgingervm_init_supervisor.so",
        "lib/armeabi-v7a/libgingervm_guest_init.so",
        "lib/armeabi-v7a/libgingervm_guest_linker.so",
        "assets/api10-system-symlinks.json",
        "assets/api10-system-native-libraries.json",
        "assets/api10-system-native-executables.json",
        "assets/api10-init-root/init.rc",
        "assets/api10-system/build.prop",
    }
    assert required <= names, f"missing APK entries: {sorted(required - names)}"
    assert "lib/arm64-v8a/libgingervm_guest_init.so" not in names
    assert "lib/arm64-v8a/libgingervm_guest_linker.so" not in names
    assert "lib/arm64-v8a/libprobe_supervisor.so" not in names
    assert "lib/armeabi-v7a/libprobe_guest.so" not in names
    assert not any("system.img" in n.lower() for n in names), "raw system.img should not be duplicated into APK"
    assert not any(n.startswith("assets/native/") for n in names), "stale writable-files supervisor asset present"

    init_bytes = zf.read("lib/armeabi-v7a/libgingervm_guest_init.so")
    assert digest(init_bytes) == expected_init, "packaged init differs from original verified init"
    linker = zf.read("lib/armeabi-v7a/libgingervm_guest_linker.so")
    arm32_elf(linker, "system linker")
    assert digest(linker) == next(x["sha256"] for x in manifest["files"] if x["kind"] == "native-linker")

    file_rows = manifest["files"]
    assert len(file_rows) == manifest["regular_file_count"]
    assert len({row["path"] for row in file_rows}) == len(file_rows), "duplicate file paths in manifest"
    assert sum(row["size"] for row in file_rows) == manifest["regular_file_bytes"]
    file_bytes = 0
    patched_exec_count = 0
    patched_exec_bytes = 0
    asset_count = native_lib_count = native_exec_count = 0
    native_paths = {
        "lib/armeabi-v7a/libgingervm_guest_linker.so",
        "lib/armeabi-v7a/libgingervm_guest_init.so",
    }
    for row in file_rows:
        relative = row["path"]
        source = safe_source_path(relative)
        assert source.is_file() and not source.is_symlink(), f"missing regular source file: {relative}"
        source_bytes = source.read_bytes()
        assert digest(source_bytes) == row["sha256"], f"source system tree changed since manifest: {relative}"
        assert len(source_bytes) == row["size"]
        kind = row["kind"]
        if kind == "asset":
            asset_path = row.get("asset_path", relative)
            if relative.endswith(".gz"):
                assert asset_path == relative + ".aaptdata", f"unsafe AAPT gzip path: {relative}"
                assert "assets/api10-system/" + relative not in names
            else:
                assert asset_path == relative, f"unexpected asset path alias: {relative}"
            entry = "assets/api10-system/" + asset_path
            assert entry in names, f"system asset missing from APK: {relative}"
            packaged = zf.read(entry)
            asset_count += 1
        else:
            entry = "lib/armeabi-v7a/" + row["native"]
            assert entry in names, f"ABI native payload missing from APK: {entry}"
            if kind == "native-linker":
                assert entry == "lib/armeabi-v7a/libgingervm_guest_linker.so"
            else:
                assert entry not in native_paths, f"native payload name collision: {entry}"
                native_paths.add(entry)
            packaged = zf.read(entry)
            arm32_elf(packaged, entry)
            if kind == "native-library": native_lib_count += 1
            elif kind == "native-executable": native_exec_count += 1
            elif kind != "native-linker": raise AssertionError(f"unknown payload kind {kind}")
        assert digest(packaged) == row["sha256"], f"packaged bytes changed: {relative}"
        file_bytes += len(packaged)
        if kind == "native-executable" and "dynamic_native" in row:
            patched_entry = "lib/armeabi-v7a/" + row["dynamic_native"]
            assert patched_entry in names, f"patched guest-linker alias missing: {patched_entry}"
            patched = zf.read(patched_entry)
            assert patched == expected_patched_interpreter(source_bytes), f"unexpected non-interpreter modification: {relative}"
            assert digest(patched) == row["dynamic_sha256"] and len(patched) == row["dynamic_size"]
            assert row["dynamic_interpreter_original"] == "/system/bin/linker"
            assert row["dynamic_interpreter_patched"] == "/proc/self/fd/198"
            arm32_elf(patched, "patched " + relative)
            patched_exec_count += 1
            patched_exec_bytes += len(patched)

    symlink_rows = manifest["symlinks"]
    assert len(symlink_rows) == manifest["symlink_count"]
    for relative, target in symlink_rows:
        p = pathlib.PurePosixPath(relative)
        assert not p.is_absolute() and ".." not in p.parts
        assert target and "\x00" not in target
        resolved = os.path.normpath(target.lstrip("/")) if target.startswith("/") else os.path.normpath(str(p.parent / target))
        assert resolved != ".." and not resolved.startswith("../"), f"symlink escapes system image: {relative} -> {target}"
    archived_links = json.loads(zf.read("assets/api10-system-symlinks.json"))
    assert archived_links == symlink_rows
    libraries = json.loads(zf.read("assets/api10-system-native-libraries.json"))
    executables = json.loads(zf.read("assets/api10-system-native-executables.json"))
    assert len(libraries) == native_lib_count == manifest["native_library_count"]
    assert len(executables) == native_exec_count == manifest["native_executable_count"]
    assert patched_exec_count == manifest["dynamic_executable_count"]
    assert patched_exec_bytes == manifest["dynamic_executable_bytes"]
    assert sum("dynamic_native" in row for row in executables) == patched_exec_count

    assert "assets/api10-system/bin/app_process" not in names
    assert "assets/api10-system/bin/dalvikvm" not in names
    assert "assets/api10-system/lib/libc.so" not in names
    assert "assets/api10-system/etc/NOTICE.html.gz" not in names
    assert "assets/api10-system/etc/NOTICE.html.gz.aaptdata" in names
    expected_system_asset_entries = {
        "assets/api10-system/" + row.get("asset_path", row["path"])
        for row in file_rows if row["kind"] == "asset"
    }
    actual_system_asset_entries = {
        n for n in names if n.startswith("assets/api10-system/") and not n.endswith("/")
    }
    assert actual_system_asset_entries == expected_system_asset_entries, "unmanifested/missing system asset in APK"
    assert manifest["app_private_asset_bytes"] + manifest["abi_native_payload_bytes"] == manifest["regular_file_bytes"]
    assert file_bytes == manifest["regular_file_bytes"]

    # Check the one ARM64 continuous supervisor without requiring an attached device.
    for entry in ("lib/arm64-v8a/libgingervm_init_supervisor.so",):
        data = zf.read(entry)
        assert data[:4] == b"\x7fELF" and data[4] == 2
        assert struct.unpack_from("<H", data, 18)[0] == 183

    native_entries = [n for n in names if n.startswith("lib/armeabi-v7a/") and not n.endswith("/")]
    assert len(native_entries) == 2 + native_lib_count + native_exec_count + patched_exec_count, len(native_entries)
    total_files = manifest["regular_file_count"]
    print(f"Full API10 system package regression: PASS ({total_files} files, {manifest['regular_file_bytes']} bytes, {manifest['symlink_count']} confined links)")
    print(f"Verified APK payloads: {asset_count} app-private system assets; {native_lib_count} original .so libraries; {native_exec_count} original executable ELFs; {patched_exec_count} PT_INTERP-only guest-linker aliases; original init")
    print(f"Original linker and init are ARM32; official init SHA-256: {expected_init}")
    print(f"System image SHA-256: {expected_system_img}; manifest SHA-256: {manifest_hash}")
PY

if unzip -Z1 "$APK" | grep -Eiq '(^|/)[^/]+\.(keystore|jks|p12|pem|pk8|key)$'; then
  echo 'Signing material must not be packaged in the APK.' >&2
  exit 1
fi

AAPT="${AAPT:-/home/ubuntu/android-sdk/build-tools/35.0.0/aapt}"
if [[ -x "$AAPT" ]]; then
  "$AAPT" dump badging "$APK" > "$TMP/badging"
  grep -Fq "native-code: 'arm64-v8a'" "$TMP/badging"
  grep -Fq "alt-native-code: 'armeabi-v7a'" "$TMP/badging"
  grep -Fq "versionName='0.6.6'" "$TMP/badging"
fi
printf '%s\n' 'Native ABI metadata regression: PASS (arm64-v8a supervisor + armeabi-v7a original userland; extracted libraries required).'
