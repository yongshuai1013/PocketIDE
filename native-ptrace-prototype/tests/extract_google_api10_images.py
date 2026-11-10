#!/usr/bin/env python3
"""Stream the two hash-pinned image members from Google's API10 SDK ZIP."""
from __future__ import annotations

import hashlib
import shutil
import sys
import zipfile
from pathlib import Path

EXPECTED = {
    "armeabi-v7a/ramdisk.img": (144_213, "94db377c1ee8d79dbd8bf9570d12b18fb7c14bb8829f6fe793d77c5e7f05619d"),
    "armeabi-v7a/system.img": (576_716_800, "e41e8698c4d138a425c1ac3324209a7a2180db324360dc64dc7937ff6e3263fd"),
}
EXPECTED_ARCHIVE_SHA256 = "b3c6188ca95bea7299b8325bd3bbd4f504fc85545befec979728f2ed169878df"


def digest(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            sha.update(block)
    return sha.hexdigest()


def extract(archive: Path, destination: Path) -> None:
    actual_archive = digest(archive)
    if actual_archive != EXPECTED_ARCHIVE_SHA256:
        raise ValueError(f"official archive SHA-256 mismatch: {actual_archive}")
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as zf:
        names = set(zf.namelist())
        if not set(EXPECTED) <= names:
            raise ValueError("official SDK ZIP is missing a required API10 image member")
        for member, (size_expected, sha_expected) in EXPECTED.items():
            info = zf.getinfo(member)
            if info.file_size != size_expected:
                raise ValueError(f"unexpected uncompressed size for {member}: {info.file_size}")
            output = destination / Path(member).name
            sha = hashlib.sha256()
            written = 0
            with zf.open(info) as source, output.open("wb") as target:
                while block := source.read(1024 * 1024):
                    target.write(block)
                    sha.update(block)
                    written += len(block)
            actual = sha.hexdigest()
            if written != size_expected or actual != sha_expected:
                output.unlink(missing_ok=True)
                raise ValueError(f"image member verification failed for {member}: bytes={written}, sha256={actual}")
            print(f"Verified {member}: {written} bytes, SHA-256 {actual}")


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: extract_google_api10_images.py <official-sdk.zip> <output-dir>", file=sys.stderr)
        return 2
    extract(Path(sys.argv[1]), Path(sys.argv[2]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
