#!/usr/bin/env python3
from __future__ import annotations

import os
import pathlib
import shutil
import struct
import subprocess
import tempfile


def interpreter_span(data: bytes) -> tuple[int, int, bytes]:
    assert len(data) >= 52 and data[:4] == b"\x7fELF" and data[4] == 2 and data[5] == 1
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phentsize = struct.unpack_from("<H", data, 54)[0]
    phnum = struct.unpack_from("<H", data, 56)[0]
    assert phentsize == 56 and 0 < phnum <= 128 and phoff + phentsize * phnum <= len(data)
    found = None
    for index in range(phnum):
        entry = phoff + index * phentsize
        p_type = struct.unpack_from("<I", data, entry)[0]
        if p_type != 3:
            continue
        offset = struct.unpack_from("<Q", data, entry + 8)[0]
        size = struct.unpack_from("<Q", data, entry + 32)[0]
        raw = data[offset:offset + size]
        assert raw and raw[-1] == 0 and b"\0" in raw
        path, trailing = raw.split(b"\0", 1)
        assert not any(trailing)
        assert found is None
        found = (offset, size, path)
    assert found is not None
    return found


binary = pathlib.Path(shutil.which("true") or "/bin/true").resolve()
original = binary.read_bytes()
offset, size, loader_bytes = interpreter_span(original)
loader = pathlib.Path(os.fsdecode(loader_bytes))
assert loader.is_file(), f"host ELF interpreter is unavailable: {loader}"
replacement = b"/proc/self/fd/198\0"
assert len(replacement) <= size
patched = bytearray(original)
patched[offset:offset + size] = replacement + bytes(size - len(replacement))

with tempfile.TemporaryDirectory(prefix="gingervm-procfd-ptinterp-") as td:
    target = pathlib.Path(td) / "true-procfd"
    target.write_bytes(patched)
    target.chmod(0o755)
    try:
        os.close(198)
    except OSError:
        pass
    fd = os.open(loader, os.O_RDONLY)
    if fd != 198:
        os.dup2(fd, 198, inheritable=True)
        os.close(fd)
    else:
        os.set_inheritable(198, True)
    result = subprocess.run([str(target)], pass_fds=(198,), check=False,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert result.returncode == 0, (result.returncode, result.stdout, result.stderr)
    os.close(198)

print("procfd PT_INTERP kernel regression: PASS (dynamic ELF executed through inherited fd=198; no root/mount)")
