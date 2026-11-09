#!/usr/bin/env python3
"""Rewrite one ELF32 ARM SHT_REL relocation type for a focused runtime probe."""

import pathlib
import struct
import sys

SHT_REL = 9
ELFCLASS32 = 1
ELFDATA2LSB = 1
EM_ARM = 40


def u16(data, offset):
    return struct.unpack_from("<H", data, offset)[0]


def u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


def main():
    if len(sys.argv) != 5:
        raise SystemExit(f"usage: {sys.argv[0]} ELF SYMBOL OLD_TYPE NEW_TYPE")
    path = pathlib.Path(sys.argv[1])
    symbol_name = sys.argv[2].encode()
    old_type = int(sys.argv[3], 0)
    new_type = int(sys.argv[4], 0)
    data = bytearray(path.read_bytes())
    if data[:4] != b"\x7fELF" or data[4] != ELFCLASS32 or data[5] != ELFDATA2LSB:
        raise SystemExit("expected a little-endian ELF32 image")
    if u16(data, 18) != EM_ARM:
        raise SystemExit("expected an ARM ELF image")

    section_offset = u32(data, 32)
    section_size = u16(data, 46)
    section_count = u16(data, 48)
    string_index = u16(data, 50)
    if section_size < 40 or string_index >= section_count:
        raise SystemExit("invalid ELF section table")
    section_headers = [
        section_offset + index * section_size for index in range(section_count)
    ]
    names_header = section_headers[string_index]
    names_offset = u32(data, names_header + 16)
    names_size = u32(data, names_header + 20)
    section_names = data[names_offset : names_offset + names_size]

    matches = 0
    for header in section_headers:
        if u32(data, header + 4) != SHT_REL:
            continue
        rel_offset = u32(data, header + 16)
        rel_size = u32(data, header + 20)
        symbol_section_index = u32(data, header + 24)
        entry_size = u32(data, header + 36) or 8
        if entry_size != 8 or rel_size % entry_size:
            raise SystemExit("invalid ARM REL section")
        symbol_header = section_headers[symbol_section_index]
        string_header = section_headers[u32(data, symbol_header + 24)]
        symbols_offset = u32(data, symbol_header + 16)
        symbols_size = u32(data, symbol_header + 20)
        symbol_entry_size = u32(data, symbol_header + 36) or 16
        strings_offset = u32(data, string_header + 16)
        strings_size = u32(data, string_header + 20)
        strings = data[strings_offset : strings_offset + strings_size]
        symbol_indices = set()
        if symbol_entry_size != 16 or symbols_size % symbol_entry_size:
            raise SystemExit("invalid ELF32 dynamic symbol table")
        for index in range(symbols_size // symbol_entry_size):
            name_offset = u32(data, symbols_offset + index * symbol_entry_size)
            end = strings.find(b"\0", name_offset)
            if end >= 0 and strings[name_offset:end] == symbol_name:
                symbol_indices.add(index)
        for offset in range(rel_offset, rel_offset + rel_size, entry_size):
            info = u32(data, offset + 4)
            if info >> 8 in symbol_indices and (info & 0xFF) == old_type:
                struct.pack_into("<I", data, offset + 4, (info & ~0xFF) | new_type)
                matches += 1
    if matches != 1:
        raise SystemExit(
            f"expected exactly one {old_type} relocation for {symbol_name.decode()}, found {matches}"
        )
    path.write_bytes(data)
    print(f"rewrote one relocation for {symbol_name.decode()}: {old_type} -> {new_type}")


if __name__ == "__main__":
    main()
