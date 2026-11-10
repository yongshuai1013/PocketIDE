#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import shutil
import struct
import sys
from pathlib import Path, PurePosixPath

EXPECTED_INIT_SHA256 = "2d9cbb198d8367f434c5fd7bada245c9e7618dc910253190f5d4dd3d0f6d1a00"
GUEST_LINKER_NAME = "libgingervm_guest_linker.so"
ORIGINAL_GUEST_INTERPRETER = b"/system/bin/linker"
PATCHED_GUEST_INTERPRETER = b"/proc/self/fd/198"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def is_arm32_elf(path: Path) -> bool:
    with path.open("rb") as stream:
        header = stream.read(20)
    return len(header) >= 20 and header[:4] == b"\x7fELF" and header[4] == 1 and struct.unpack_from("<H", header, 18)[0] == 40


def ensure_confined_symlink(rel: str, target: str) -> None:
    if not target or "\x00" in target:
        raise SystemExit(f"invalid symlink target for {rel!r}")
    rel_path = PurePosixPath(rel)
    if rel_path.is_absolute() or ".." in rel_path.parts:
        raise SystemExit(f"unsafe system symlink path: {rel!r}")
    if target.startswith("/"):
        resolved = os.path.normpath(target.lstrip("/"))
    else:
        resolved = os.path.normpath(str(rel_path.parent / target))
    if resolved == ".." or resolved.startswith("../"):
        raise SystemExit(f"system symlink escapes guest /system: {rel!r} -> {target!r}")


def copy_file(source: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, dest)


def copy_native(source: Path, output: Path, name: str) -> dict[str, object]:
    dest = output / name
    copy_file(source, dest)
    dest.chmod(0o755)
    return {"name": name, "sha256": sha256(source), "size": source.stat().st_size}


def elf32_arm_interp_span(data: bytes) -> tuple[int, int, bytes] | None:
    if (len(data) < 52 or data[:4] != b"\x7fELF" or data[4] != 1 or data[5] != 1 or
            struct.unpack_from("<H", data, 18)[0] != 40):
        raise ValueError("dynamic executable is not little-endian ELF32 ARM")
    phoff = struct.unpack_from("<I", data, 28)[0]
    phentsize = struct.unpack_from("<H", data, 42)[0]
    phnum = struct.unpack_from("<H", data, 44)[0]
    if phentsize != 32 or phnum == 0 or phnum > 128 or phoff + phentsize * phnum > len(data):
        raise ValueError("invalid ELF32 ARM program-header table")
    found = None
    for index in range(phnum):
        entry = phoff + index * phentsize
        p_type = struct.unpack_from("<I", data, entry)[0]
        p_offset = struct.unpack_from("<I", data, entry + 4)[0]
        p_filesz = struct.unpack_from("<I", data, entry + 16)[0]
        if p_type != 3:  # PT_INTERP
            continue
        if found is not None or p_filesz < 2 or p_offset + p_filesz > len(data):
            raise ValueError("invalid or duplicate PT_INTERP segment")
        raw = data[p_offset:p_offset + p_filesz]
        if raw[-1] != 0 or b"\0" not in raw:
            raise ValueError("PT_INTERP is not safely NUL-terminated")
        path, trailing = raw.split(b"\0", 1)
        if any(trailing):
            raise ValueError("PT_INTERP contains nonzero data after its terminator")
        if not path.startswith(b"/"):
            raise ValueError("PT_INTERP path is not absolute")
        found = (p_offset, p_filesz, path)
    return found


def patch_guest_interpreter(data: bytes) -> tuple[bytes, str | None]:
    span = elf32_arm_interp_span(data)
    if span is None:
        return data, None
    offset, filesz, original = span
    if original != ORIGINAL_GUEST_INTERPRETER:
        raise ValueError(f"unexpected API10 ELF interpreter: {original!r}")
    replacement = PATCHED_GUEST_INTERPRETER + b"\0"
    if len(replacement) > filesz:
        raise ValueError("replacement PT_INTERP does not fit original ELF segment")
    patched = bytearray(data)
    patched[offset:offset + filesz] = replacement + b"\0" * (filesz - len(replacement))
    return bytes(patched), PATCHED_GUEST_INTERPRETER.decode("ascii")


def copy_native_bytes(data: bytes, output: Path, name: str) -> dict[str, object]:
    dest = output / name
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)
    dest.chmod(0o755)
    return {"name": name, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


def main() -> int:
    if len(sys.argv) != 5:
        raise SystemExit("usage: stage_init_assets.py <guest-root-staging> <system-tree> <assets-dir> <armeabi-v7a-jniLibs-dir>")
    ramdisk = Path(sys.argv[1]).resolve()
    system = Path(sys.argv[2]).resolve()
    assets = Path(sys.argv[3]).resolve()
    native32 = Path(sys.argv[4]).resolve()
    if not ramdisk.is_dir() or not system.is_dir():
        raise SystemExit("official ramdisk staging or matching system-tree is missing")

    init = ramdisk / "init"
    init_digest = sha256(init)
    if init_digest != EXPECTED_INIT_SHA256:
        raise SystemExit(f"refusing unexpected init binary SHA-256: {init_digest}")
    build_prop = system / "build.prop"
    if not build_prop.is_file():
        raise SystemExit("matching API10 /system/build.prop is missing")
    props = build_prop.read_text(errors="replace")
    if "ro.build.version.release=2.3.7" not in props or "ro.build.version.sdk=10" not in props:
        raise SystemExit("system-tree does not identify the expected Android 2.3.7/API 10 image")
    for required in ("bin/linker", "bin/app_process", "bin/dalvikvm", "bin/servicemanager",
                     "bin/surfaceflinger", "lib/libc.so", "lib/libdvm.so", "framework/core.jar",
                     "framework/framework.jar"):
        if not (system / required).is_file():
            raise SystemExit(f"required API10 system payload is missing: {required}")
    if not is_arm32_elf(system / "bin/linker"):
        raise SystemExit("matching /system/bin/linker is not ELF32 ARM")

    guest_assets = assets / "api10-init-root"
    system_assets = assets / "api10-system"
    for generated in (guest_assets, system_assets):
        if generated.exists():
            shutil.rmtree(generated)
        generated.mkdir(parents=True)
    assets.mkdir(parents=True, exist_ok=True)
    native32.mkdir(parents=True, exist_ok=True)

    # Remove only outputs owned by this stager; keep legacy probe and supervisor files.
    for pattern in ("libgingervm_exec_*.so", GUEST_LINKER_NAME):
        for stale in native32.glob(pattern):
            stale.unlink()
    old_native_asset = assets / "native" / "gingervm-init-supervisor"
    old_native_asset.unlink(missing_ok=True)
    try:
        old_native_asset.parent.rmdir()
    except OSError:
        pass

    root_files: list[str] = []
    for child in sorted(ramdisk.iterdir()):
        if child.is_file() and not child.is_symlink():
            copy_file(child, guest_assets / child.name)
            root_files.append(child.name)
    (guest_assets / "STAGING-NOTE.txt").write_text(
        "Original Google SDK API 10 ARMv7 ramdisk files.\n"
        "The complete matching system.img userland is staged at guest /.images/system and is exposed at /system only by the software mount broker.\n"
        f"Original /init SHA-256: {init_digest}\n",
        encoding="utf-8",
    )
    (guest_assets / "ASSET-FILES.txt").write_text("\n".join(root_files) + "\n", encoding="utf-8")

    native_libraries: list[dict[str, object]] = []
    native_executables: list[dict[str, object]] = []
    symlinks: list[list[str]] = []
    system_directories: set[str] = set()
    file_manifest: list[dict[str, object]] = []
    regular_files = 0
    symlink_count = 0
    total_bytes = 0
    app_private_asset_bytes = 0
    abi_native_payload_bytes = 0
    dynamic_executable_count = 0
    dynamic_executable_bytes = 0

    for directory, dirnames, filenames in os.walk(system, followlinks=False):
        current = Path(directory)
        rel_dir = current.relative_to(system)
        if rel_dir.parts:
            system_directories.add(rel_dir.as_posix())
        kept_dirs: list[str] = []
        for name in sorted(dirnames):
            child = current / name
            rel = (rel_dir / name).as_posix()
            if child.is_symlink():
                target = os.readlink(child)
                ensure_confined_symlink(rel, target)
                symlinks.append([rel, target])
                symlink_count += 1
            else:
                kept_dirs.append(name)
                (system_assets / rel).mkdir(parents=True, exist_ok=True)
                system_directories.add(rel)
        dirnames[:] = kept_dirs

        for name in sorted(filenames):
            source = current / name
            rel = (rel_dir / name).as_posix()
            if source.is_symlink():
                target = os.readlink(source)
                ensure_confined_symlink(rel, target)
                symlinks.append([rel, target])
                symlink_count += 1
                continue
            if not source.is_file():
                continue
            size = source.stat().st_size
            digest = sha256(source)
            total_bytes += size
            regular_files += 1
            payload_kind = "asset"

            if rel == "bin/linker":
                native = copy_native(source, native32, GUEST_LINKER_NAME)
                abi_native_payload_bytes += size
                file_manifest.append({"path": rel, "kind": "native-linker", "size": size, "sha256": digest,
                                      "native": native["name"]})
                continue

            rel_path = PurePosixPath(rel)
            if rel_path.parts[0] == "lib" and len(rel_path.parts) == 2 and rel_path.name.endswith(".so"):
                if not is_arm32_elf(source):
                    raise SystemExit(f"system library is not ELF32 ARM: {rel}")
                native = copy_native(source, native32, rel_path.name)
                abi_native_payload_bytes += size
                native_libraries.append({"path": rel, "native": native["name"], "size": size, "sha256": digest})
                file_manifest.append({"path": rel, "kind": "native-library", "size": size, "sha256": digest,
                                      "native": native["name"]})
                continue

            if rel_path.parts[0] in ("bin", "xbin") and len(rel_path.parts) == 2 and (source.stat().st_mode & 0o111) and is_arm32_elf(source):
                native_name = "libgingervm_exec_" + rel.replace("/", "_") + ".so"
                copy_native(source, native32, native_name)
                abi_native_payload_bytes += size
                executable_row: dict[str, object] = {
                    "path": rel, "native": native_name, "size": size, "sha256": digest
                }
                patched, patched_interpreter = patch_guest_interpreter(source.read_bytes())
                if patched_interpreter is not None:
                    patched_name = "libgingervm_exec_patched_" + rel.replace("/", "_") + ".so"
                    patched_payload = copy_native_bytes(patched, native32, patched_name)
                    executable_row.update({
                        "dynamic_native": patched_name,
                        "dynamic_sha256": patched_payload["sha256"],
                        "dynamic_size": patched_payload["size"],
                        "dynamic_interpreter_original": ORIGINAL_GUEST_INTERPRETER.decode("ascii"),
                        "dynamic_interpreter_patched": patched_interpreter,
                    })
                    dynamic_executable_count += 1
                    dynamic_executable_bytes += int(patched_payload["size"])
                native_executables.append(executable_row)
                file_manifest.append({"path": rel, "kind": "native-executable", "size": size, "sha256": digest,
                                      "native": native_name, **{k: v for k, v in executable_row.items() if k != "path" and k != "native"}})
                continue

            # AAPT expands assets ending in .gz and drops that suffix. Preserve
            # exact source bytes under a neutral APK name; the app restores the
            # original guest path after copying the full tree.
            asset_rel = rel + ".aaptdata" if rel.endswith(".gz") else rel
            copy_file(source, system_assets / asset_rel)
            app_private_asset_bytes += size
            file_manifest.append({"path": rel, "asset_path": asset_rel, "kind": payload_kind,
                                  "size": size, "sha256": digest})

    if not symlinks or not native_libraries or not native_executables:
        raise SystemExit("system image staging unexpectedly produced an incomplete payload")

    (assets / "api10-system-symlinks.json").write_text(json.dumps(symlinks, separators=(",", ":")), encoding="utf-8")
    (assets / "api10-system-native-libraries.json").write_text(json.dumps(native_libraries, separators=(",", ":")), encoding="utf-8")
    (assets / "api10-system-native-executables.json").write_text(json.dumps(native_executables, separators=(",", ":")), encoding="utf-8")
    manifest = {
        "source": "Google Android SDK API 10 ARMv7 system.img; build.prop reports Android 2.3.7",
        "source_system_img_sha256": "e41e8698c4d138a425c1ac3324209a7a2180db324360dc64dc7937ff6e3263fd",
        "source_ramdisk_img_sha256": "94db377c1ee8d79dbd8bf9570d12b18fb7c14bb8829f6fe793d77c5e7f05619d",
        "init_sha256": init_digest,
        "regular_file_count": regular_files,
        "symlink_count": symlink_count,
        "regular_file_bytes": total_bytes,
        "app_private_asset_bytes": app_private_asset_bytes,
        "abi_native_payload_bytes": abi_native_payload_bytes,
        "native_library_count": len(native_libraries),
        "native_executable_count": len(native_executables),
        "dynamic_executable_count": dynamic_executable_count,
        "dynamic_executable_bytes": dynamic_executable_bytes,
        "directories": sorted(system_directories),
        "files": file_manifest,
        "symlinks": symlinks,
    }
    manifest_text = json.dumps(manifest, separators=(",", ":"), sort_keys=True)
    (assets / "api10-system-manifest.json").write_text(manifest_text, encoding="utf-8")
    manifest_hash = hashlib.sha256(manifest_text.encode()).hexdigest()
    (assets / "api10-system-manifest.sha256").write_text(manifest_hash + "\n", encoding="ascii")

    print(f"Staged original ramdisk files: {len(root_files)}; init SHA-256 verified.")
    print(f"Staged complete /system userland: {regular_files} regular files ({total_bytes} bytes), {symlink_count} confined symlinks.")
    print(f"App-private system assets: {app_private_asset_bytes} bytes; APK-extracted ARM32 files: {abi_native_payload_bytes} bytes.")
    print(f"APK-extracted ARM32 payloads: linker={GUEST_LINKER_NAME}, {len(native_libraries)} shared libraries, {len(native_executables)} original executables, {dynamic_executable_count} patched linker aliases ({dynamic_executable_bytes} bytes).")
    print(f"System manifest SHA-256: {manifest_hash}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
