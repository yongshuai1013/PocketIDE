#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import pathlib
import struct

ROOT = pathlib.Path(__file__).resolve().parent.parent
MODULE_PATH = pathlib.Path(__file__).resolve().parent / "stage_init_assets.py"
spec = importlib.util.spec_from_file_location("stage_init_assets", MODULE_PATH)
assert spec and spec.loader
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)


def fixture(interpreter: bytes | None) -> bytearray:
    phnum = 1
    data = bytearray(256)
    data[:16] = b"\x7fELF" + bytes((1, 1, 1, 0, 0)) + bytes(7)
    struct.pack_into("<HHIIIIIHHHHHH", data, 16, 2, 40, 1, 0x8000, 52, 0, 0, 52, 32, phnum, 0, 0, 0)
    if interpreter is None:
        struct.pack_into("<IIIIIIII", data, 52, 1, 128, 0x8000, 0x8000, 64, 64, 5, 4096)
    else:
        raw = interpreter + b"\0"
        struct.pack_into("<IIIIIIII", data, 52, 3, 128, 0x8000, 0x8000, len(raw), len(raw), 4, 1)
        data[128:128 + len(raw)] = raw
    return data


original = bytes(fixture(b"/system/bin/linker"))
patched, interp = stage.patch_guest_interpreter(original)
assert interp == "/proc/self/fd/198"
expected = bytearray(original)
replacement = b"/proc/self/fd/198\0"
expected[128:147] = replacement + bytes(19 - len(replacement))
assert patched == bytes(expected), "patch changed ELF bytes outside PT_INTERP"
span = stage.elf32_arm_interp_span(patched)
assert span is not None and span[2] == b"/proc/self/fd/198"

static = bytes(fixture(None))
assert stage.patch_guest_interpreter(static) == (static, None)

wrong = fixture(b"/host/bin/linker")
try:
    stage.patch_guest_interpreter(bytes(wrong))
except ValueError as exc:
    assert "unexpected API10 ELF interpreter" in str(exc)
else:
    raise AssertionError("non-API10 interpreter was accepted")

print("guest PT_INTERP patch regression: PASS (only linker string changes; static ELF unchanged; unexpected interpreters rejected)")
