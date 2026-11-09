#!/usr/bin/env python3
"""Run pinned Android 2.3.7 init with one explicitly simulated property event."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOTFS = ROOT / "android-app/app/src/main/assets/rootfs"
TEST_ROOTFS = ROOT / "build/aosp/init-simulated-rootfs"
BINARY = ROOT / "target/release/gingervm"


def remove_test_rootfs(path: Path) -> None:
    if not path.exists():
        return
    for current, directories, _files in os.walk(path, topdown=True, followlinks=False):
        os.chmod(current, 0o700)
        for name in directories:
            child = Path(current) / name
            if not child.is_symlink():
                os.chmod(child, 0o700)
    shutil.rmtree(path)


def main() -> int:
    if len(sys.argv) > 2:
        raise SystemExit("usage: probes/run-aosp-init-simulated.py [packaged-rootfs]")
    source = Path(sys.argv[1]).resolve() if len(sys.argv) == 2 else SOURCE_ROOTFS
    if not (source / "init").is_file() or not (source / "system/build.prop").is_file():
        raise SystemExit(f"missing packaged init or /system/build.prop in {source}")
    if not BINARY.is_file():
        raise SystemExit("missing target/release/gingervm; run cargo build --release --bin gingervm first")

    remove_test_rootfs(TEST_ROOTFS)
    TEST_ROOTFS.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, TEST_ROOTFS, copy_function=os.link, symlinks=True)

    command = [str(BINARY), "init-simulated", str(TEST_ROOTFS)]
    result = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    print(result.stdout, end="")
    if result.returncode:
        return result.returncode
    required = (
        "SIMULATED EVENT:",
        "debug.gingervm.simulated=1",
        "AOSP init accepted the virtual connection",
        "128-byte message",
        "No hardware/uevent was generated.",
        "Guest init: WaitingForEvents",
    )
    missing = [text for text in required if text not in result.stdout]
    if missing:
        print(f"\nIntegration test failed; missing output: {missing}", file=sys.stderr)
        return 1
    print("AOSP init simulated property-event integration test: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
