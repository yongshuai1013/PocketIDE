#!/usr/bin/env python3
"""Extract a gzip-compressed Android newc CPIO ramdisk without root or cpio."""
from __future__ import annotations

import gzip
import os
import stat
import sys
from pathlib import Path, PurePosixPath

HEADER_SIZE = 110
ALIGNMENT = 4


def align(value: int) -> int:
    return (value + ALIGNMENT - 1) & ~(ALIGNMENT - 1)


def safe_target(root: Path, name: str) -> Path:
    relative = PurePosixPath(name)
    parts = [part for part in relative.parts if part not in ("", ".", "/")]
    if ".." in parts:
        raise ValueError(f"unsafe CPIO path: {name!r}")
    target = root.joinpath(*parts)
    current = root
    for part in parts[:-1]:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"CPIO path traverses an earlier symlink: {name!r}")
        current.mkdir(exist_ok=True)
        if not current.is_dir():
            raise ValueError(f"CPIO path parent is not a directory: {name!r}")
    if target != root and target.parent.is_symlink():
        raise ValueError(f"CPIO path parent is a symlink: {name!r}")
    return target


def extract(archive: Path, destination: Path) -> tuple[int, int, int]:
    compressed = archive.read_bytes()
    payload = gzip.decompress(compressed) if compressed[:2] == b"\x1f\x8b" else compressed
    if not payload.startswith((b"070701", b"070702")):
        raise ValueError("ramdisk payload is not an Android newc CPIO archive")
    destination.mkdir(parents=True, exist_ok=True)
    offset = 0
    entries = regular_files = symlinks = 0
    saw_trailer = False
    while offset + HEADER_SIZE <= len(payload):
        header = payload[offset : offset + HEADER_SIZE]
        magic = header[:6]
        if magic not in (b"070701", b"070702"):
            raise ValueError(f"invalid newc CPIO header at offset {offset}")
        fields = [int(header[6 + index * 8 : 14 + index * 8], 16) for index in range(13)]
        mode = fields[1]
        file_size = fields[6]
        name_size = fields[11]
        if name_size < 1:
            raise ValueError("invalid empty CPIO path")
        name_start = offset + HEADER_SIZE
        name_end = name_start + name_size
        if name_end > len(payload):
            raise ValueError("truncated CPIO name")
        raw_name = payload[name_start:name_end]
        if raw_name[-1] != 0 or b"\0" in raw_name[:-1]:
            raise ValueError("malformed CPIO name")
        name = raw_name[:-1].decode("utf-8", "surrogateescape")
        data_start = align(name_end)
        data_end = data_start + file_size
        if data_end > len(payload):
            raise ValueError(f"truncated CPIO content for {name!r}")
        next_offset = align(data_end)
        if name == "TRAILER!!!":
            saw_trailer = True
            break
        target = safe_target(destination, name)
        file_type = stat.S_IFMT(mode)
        permissions = mode & 0o777
        if file_type == stat.S_IFDIR:
            target.mkdir(parents=True, exist_ok=True)
            target.chmod(permissions or 0o755)
        elif file_type == stat.S_IFREG:
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("wb") as stream:
                stream.write(payload[data_start:data_end])
            target.chmod(permissions)
            regular_files += 1
        elif file_type == stat.S_IFLNK:
            target.parent.mkdir(parents=True, exist_ok=True)
            link_target = payload[data_start:data_end].decode("utf-8", "surrogateescape")
            if not link_target or "\0" in link_target:
                raise ValueError(f"invalid symlink target for {name!r}")
            target.symlink_to(link_target)
            symlinks += 1
        else:
            # Device nodes, sockets and FIFOs belong to the guest model, not the host.
            pass
        entries += 1
        offset = next_offset
    if not saw_trailer:
        raise ValueError("CPIO trailer is missing")
    return entries, regular_files, symlinks


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: extract_android_newc_ramdisk.py <ramdisk.img> <destination>", file=sys.stderr)
        return 2
    archive, destination = Path(sys.argv[1]), Path(sys.argv[2])
    entries, files, links = extract(archive, destination)
    print(f"Rootless Android CPIO extraction: {entries} entries; {files} regular files; {links} symlinks; host device nodes skipped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
