#!/usr/bin/env python3
"""Fail-closed cache helper for bounded Swift/iOS intermediate probe artifacts."""
from __future__ import annotations
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "swift-ios-probe"
SNAP = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "swift-ios-probe-cache" / "snapshot"
PREFIX = "pocketide-swift-ios-intermediate-v1-"
WHITELIST = {"swift", "llvm-project", "cmark", "native", "cmark-ios", "ios", "harness", "import-cmark.cmake", "platform-fix.diff"}
SWIFT_REV = "6a862d2eb7128ff1f317b07e8ad1a6da939775f3"
LLVM_REV = "2e6139970eda445d9c6872c0ca293088b4e63dd2"
CMARK_REV = "3ccff77b2dc5b96b77db3da0d68d28068593fa53"
MAX_BYTES = 8 * 1024**3
MAX_FILES = 500_000
SCRIPT = Path(__file__).resolve()


def output(name: str, value: str) -> None:
    p = os.environ.get("GITHUB_OUTPUT")
    if p:
        with open(p, "a", encoding="utf-8") as f:
            f.write(f"{name}={value}\n")


def run(argv: list[str]) -> str:
    return subprocess.check_output(argv, stderr=subprocess.STDOUT, text=True).strip()


def build_script() -> Path:
    p = SCRIPT.parent / 'temporary-swift-ios-probe.sh'
    if not p.is_file():
        raise RuntimeError('probe build script not found')
    return p


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda: f.read(1024 * 1024), b""):
            h.update(b)
    return h.hexdigest()


def signature() -> str:
    script = build_script()
    fingerprint = {
        "xcodebuild": run(["xcodebuild", "-version"]),
        "sdk_version": run(["xcrun", "--sdk", "iphoneos", "--show-sdk-version"]),
        "sdk_path": run(["xcrun", "--sdk", "iphoneos", "--show-sdk-path"]),
        "clang_path": run(["xcrun", "--find", "clang"]),
        "clang_version": run(["xcrun", "clang", "--version"]),
        "cmake": run(["cmake", "--version"]), "ninja": run(["ninja", "--version"]),
        "machine": run(["uname", "-m"]),
        "macos": run(["sw_vers", "-productVersion"]),
        "root": str(ROOT), "swift_revision": SWIFT_REV, "llvm_revision": LLVM_REV,
        "cmark_revision": CMARK_REV, "build_script_sha256": sha(script),
        "cache_helper_sha256": sha(SCRIPT),
        "configuration": {"arch": "arm64", "target": "ios15", "configuration": "Release",
                          "optimization": "O1", "generator": "Ninja", "jobs": 2, "uuid_fix": True},
    }
    assert "Xcode 16.4" in fingerprint["xcodebuild"], "Xcode 16.4 required"
    assert fingerprint["sdk_version"] == "18.5", "iPhoneOS SDK 18.5 required"
    assert fingerprint["macos"].startswith("15."), "macOS 15 required"
    assert fingerprint["machine"] == "arm64", "arm64 runner required"
    # This migration changes only the iOS librt system-library link setting.
    # Recompute the previous key using CURRENT toolchain details, so incompatible
    # Xcode/CMake/SDK/root changes cannot match the saved intermediate state.
    previous_script_sha = '37f624a364068237b248cad1663d367e12f94ae5118e88061e7307fa07c1f250'
    previous_helper_sha = '214c17931b6126a88688da0d53771de239f6a80176650d6c25ad2af43013a07a'
    normalized = script.read_bytes().replace(b'  -DHAVE_LIBRT:BOOL=OFF \\\n', b'')
    assert hashlib.sha256(normalized).hexdigest() == previous_script_sha, 'unreviewed build configuration change'
    legacy = dict(fingerprint)
    legacy['build_script_sha256'] = previous_script_sha
    legacy['cache_helper_sha256'] = previous_helper_sha
    compatible = PREFIX + hashlib.sha256(json.dumps(legacy, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    output('compatible_prefix', compatible)
    env = os.environ.get('GITHUB_ENV')
    if env:
        with open(env, 'a', encoding='utf-8') as f:
            f.write(f'PROBE_COMPATIBLE_CACHE_SIGNATURE={compatible}\n')
    return PREFIX + hashlib.sha256(json.dumps(fingerprint, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def metadata(text: str) -> None:
    d = Path(os.environ.get("GITHUB_WORKSPACE", os.getcwd())) / "probe-logs"
    d.mkdir(parents=True, exist_ok=True)
    secrets = [os.environ.get(k, "") for k in ("HOME", "RUNNER_TEMP", "GITHUB_WORKSPACE")]
    for secret in sorted((x for x in secrets if x), key=len, reverse=True):
        text = text.replace(secret, "[REDACTED]")
    with (d / "cache-metadata.txt").open("a", encoding="utf-8") as f:
        f.write(text.rstrip() + "\n")


def valid_signature(sig: str) -> bool:
    return bool(re.fullmatch(re.escape(PREFIX) + r"[0-9a-f]{64}", sig))


def forbidden_name(p: Path) -> bool:
    name = p.name.lower()
    return name in {".git", ".ssh", ".aws", ".netrc", "probe-logs", "ios_frontend_link_probe"} or name.endswith((".sdk", ".app", ".xcframework"))


def marker_ok(root: Path) -> bool:
    markers = {
        "swift": ("README.md", "CMakeLists.txt"),
        "llvm-project": ("README.md", "llvm/CMakeLists.txt"),
        "cmark": ("README.md", "CMakeLists.txt"),
    }
    revisions = {"swift": SWIFT_REV, "llvm-project": LLVM_REV, "cmark": CMARK_REV}
    for top, names in markers.items():
        base = root / top
        marker = base / ".pocketide-pinned-revision"
        if not base.is_dir() or not marker.is_file() or marker.read_text().strip() != revisions[top] or not any((base / n).is_file() for n in names):
            return False
    return True


def safe_file(p: Path) -> bool:
    if p.suffix.lower() in {".a", ".dylib", ".so", ".exe"}:
        return False
    if p.name == "ios_frontend_link_probe":
        return False
    try:
        with p.open("rb") as f:
            head = f.read(4096)
    except OSError:
        return False
    if p.name == ".ninja_deps":
        return head.startswith(b"# ninjadeps\n")
    # Keep only Mach-O MH_OBJECT intermediates; discard all executables/dylibs and fat binaries.
    magics = {b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"}
    if head[:4] in magics:
        endian = "little" if head[:4] in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe") else "big"
        if len(head) < 16:
            return False
        return int.from_bytes(head[12:16], endian) == 1
    if head[:4] in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"):
        return False
    if head.startswith(b"\x7fELF"):
        return len(head) > 18 and int.from_bytes(head[16:18], "little" if head[5] == 1 else "big") == 1
    # Text/scripts and ordinary non-Mach-O build intermediates are permissible; reject unknown binaries.
    if b"\0" in head:
        return p.suffix.lower() == ".o" and head[:4] not in (b"\x7fELF",)
    return True


def ensure_empty_root() -> None:
    if ROOT.exists() and (not ROOT.is_dir() or any(ROOT.iterdir())):
        raise RuntimeError("probe root already exists and is nonempty; refusing restore")
    ROOT.mkdir(parents=True, exist_ok=True)


def restore(sig: str) -> None:
    if not os.environ.get('PROBE_CACHE_MATCHED_KEY'):
        if SNAP.exists():
            raise RuntimeError('unexpected snapshot without matched cache key')
        metadata('RESTORED=false; cache miss; fresh runner; no prior incremental state available')
        return
    manifest_path = SNAP / ".probe-cache-manifest.json"
    if not valid_signature(sig) or not manifest_path.is_file():
        raise RuntimeError("missing/invalid signature or snapshot manifest")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    saved_signature = manifest.get('signature', '')
    compatible = os.environ.get('PROBE_COMPATIBLE_CACHE_SIGNATURE', '')
    matched = os.environ.get('PROBE_CACHE_MATCHED_KEY', '')
    if saved_signature not in {sig, compatible} or not valid_signature(saved_signature) or not matched.startswith(saved_signature + '-'):
        raise RuntimeError('snapshot signature mismatch')
    if saved_signature != sig:
        metadata('COMPATIBLE_MIGRATION=iOS HAVE_LIBRT=OFF link-only correction; current toolchain and all object compile flags verified unchanged')
    ensure_empty_root()
    source = SNAP / "payload"
    if not source.is_dir() or not marker_ok(source):
        raise RuntimeError("snapshot source markers absent")
    for item in source.iterdir():
        if item.name not in WHITELIST:
            raise RuntimeError("snapshot contains unapproved root item")
    files = 0
    total = 0
    for base, dirs, names in os.walk(source, topdown=True, followlinks=False):
        b = Path(base)
        for d in list(dirs):
            p = b / d
            if p.is_symlink() or forbidden_name(p) or (d == "bin" and p.parts[-2] in {"native", "ios", "cmark-ios"}):
                raise RuntimeError("unsafe directory in snapshot")
        for n in names:
            p = b / n
            if p.is_symlink() or not p.is_file() or forbidden_name(p) or not safe_file(p):
                raise RuntimeError("unsafe file in snapshot")
            files += 1
            total += p.stat().st_size
            if files > MAX_FILES or total > MAX_BYTES:
                raise RuntimeError("snapshot file limit exceeded")
    if total + 8 * 1024**3 > shutil.disk_usage(ROOT.parent).free:
        raise RuntimeError("insufficient restore free-space floor")
    shutil.copytree(source, ROOT, dirs_exist_ok=True, copy_function=shutil.copy2, symlinks=False)
    metadata(f"RESTORED=true; requested_signature={sig}; saved_signature={saved_signature}; files={files}; bytes={total}; restored_ios_objects={len(list((ROOT / 'ios').rglob('*.o')))}")


def snapshot(sig: str) -> None:
    if not valid_signature(sig) or not ROOT.is_dir() or not marker_ok(ROOT):
        raise RuntimeError("missing/invalid signature or expected source markers")
    temp_parent = SNAP.parent
    temp_parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".snapshot-staging-", dir=temp_parent))
    payload = stage / "payload"
    payload.mkdir()
    excluded = 0
    files = 0
    total = 0
    try:
        for name in sorted(WHITELIST):
            src = ROOT / name
            if not src.exists():
                continue
            if src.is_symlink():
                excluded += 1
                continue
            if src.is_dir():
                (payload / name).mkdir()
                for base, dirs, names in os.walk(src, topdown=True, followlinks=False):
                    b = Path(base)
                    kept = []
                    for d in dirs:
                        p = b / d
                        if p.is_symlink() or forbidden_name(p) or (d == "bin" and p.parts[-2] in {"native", "ios", "cmark-ios"}):
                            excluded += 1
                        else:
                            kept.append(d)
                            dest = payload / p.relative_to(ROOT)
                            dest.mkdir(exist_ok=True)
                            shutil.copystat(p, dest, follow_symlinks=False)
                    dirs[:] = kept
                    for n in names:
                        p = b / n
                        if p.is_symlink() or not p.is_file() or forbidden_name(p) or not safe_file(p):
                            excluded += 1
                            continue
                        size = p.stat().st_size
                        files += 1; total += size
                        if files > MAX_FILES or total > MAX_BYTES:
                            raise RuntimeError("snapshot logical limit exceeded")
                        dest = payload / p.relative_to(ROOT)
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        try:
                            os.link(p, dest)
                        except OSError:
                            if size + 8 * 1024**3 > shutil.disk_usage(temp_parent).free:
                                raise RuntimeError("copy would violate free-space floor")
                            shutil.copy2(p, dest)
            elif src.is_file() and not forbidden_name(src) and safe_file(src):
                files += 1; total += src.stat().st_size
                if files > MAX_FILES or total > MAX_BYTES:
                    raise RuntimeError("snapshot logical limit exceeded")
                shutil.copy2(src, payload / name)
            else:
                excluded += 1
        if not marker_ok(payload):
            raise RuntimeError("source markers were excluded or missing")
        if shutil.disk_usage(temp_parent).free < 8 * 1024**3:
            raise RuntimeError("insufficient free disk space")
        manifest = {"signature": sig, "files": files, "bytes": total, "exclusions": excluded}
        (stage / ".probe-cache-manifest.json").write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8")
        if SNAP.exists():
            shutil.rmtree(SNAP)
        os.replace(stage, SNAP)
        metadata(f"snapshot signature={sig} files={files} bytes={total} exclusions={excluded}")
        output("safe", "true")
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in {"signature", "restore", "snapshot"}:
        print("usage: temporary-swift-ios-cache.py {signature|restore|snapshot}", file=sys.stderr); return 2
    mode = sys.argv[1]
    try:
        if mode == "signature":
            sig = signature()
            output("prefix", sig)
            output("restore_key", sig + "-" + os.environ.get("GITHUB_RUN_ID", "unknown"))
            env = os.environ.get("GITHUB_ENV")
            if env:
                with open(env, "a", encoding="utf-8") as f: f.write(f"PROBE_CACHE_SIGNATURE={sig}\n")
            metadata(f"SIGNATURE={sig}; pinned Swift={SWIFT_REV}; LLVM={LLVM_REV}; cmark={CMARK_REV}; Xcode=16.4; SDK=18.5; arm64/iOS15; config and tool versions fingerprinted")
            print(sig)
        else:
            sig = os.environ.get("PROBE_CACHE_SIGNATURE", "")
            if mode == "restore": restore(sig)
            else: snapshot(sig)
        return 0
    except Exception as e:
        # Avoid surfacing paths, command output, or potentially sensitive tool output.
        print(f"probe cache {mode} failed closed ({type(e).__name__})", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
