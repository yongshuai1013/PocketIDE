import Foundation

extension NativeCBackend {
    /// Structural/target checks only: not a loader, signature verifier or device test.
    public static func validateMachO(at url: URL, fileType: UInt32) throws {
        func invalid(_ reason: String) -> NativeCError { .invalidArtifact("\(url.path): \(reason)") }
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: url.path) else { throw invalid("missing artifact") }
        guard attributes[.type] as? FileAttributeType == .typeRegular,
              let size = (attributes[.size] as? NSNumber)?.uint64Value, size >= 32 else {
            throw invalid("expected a regular, non-symlink file")
        }
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        let header = try handle.read(upToCount: 32) ?? Data()
        func word(_ data: Data, _ offset: Int) -> UInt32 {
            (0..<4).reduce(UInt32(0)) { $0 | (UInt32(data[offset + $1]) << (8 * $1)) }
        }
        func wide(_ data: Data, _ offset: Int) -> UInt64 {
            UInt64(word(data, offset)) | (UInt64(word(data, offset + 4)) << 32)
        }
        guard header.count == 32, word(header, 0) == 0xfeedfacf,
              word(header, 4) == 0x0100000c, word(header, 8) == 0,
              [UInt32(1), 2].contains(fileType), word(header, 12) == fileType else {
            throw invalid("expected little-endian arm64 (not arm64e), matching object/executable type")
        }
        let count = Int(word(header, 16)), bytes = Int(word(header, 20))
        guard bytes <= 16 * 1024 * 1024, UInt64(bytes) <= size - 32,
              count > 0, count <= bytes / 8 else { throw invalid("invalid load-command region") }
        let commands = try handle.read(upToCount: bytes) ?? Data()
        guard commands.count == bytes else { throw invalid("truncated load commands") }
        var cursor = 0
        var targetCommands = 0
        func rangeFits(_ offset: UInt64, _ length: UInt64) -> Bool { offset <= size && length <= size - offset }
        for _ in 0..<count {
            guard cursor <= bytes - 8 else { throw invalid("truncated command header") }
            let command = word(commands, cursor), length = Int(word(commands, cursor + 4))
            guard length >= 8, length % 8 == 0, length <= bytes - cursor else {
                throw invalid("invalid command size/alignment")
            }
            switch command {
            case 0x32: // LC_BUILD_VERSION: platform iOS, minimum exactly our deployment target.
                guard length >= 24, Int(word(commands, cursor + 20)) == (length - 24) / 8,
                      word(commands, cursor + 8) == 2,
                      word(commands, cursor + 12) == 0x000f0000,
                      word(commands, cursor + 16) == 0 || word(commands, cursor + 16) >= 0x000f0000 else {
                    throw invalid("expected iPhoneOS / iOS 15.0 build version")
                }
                targetCommands += 1
            case 0x25: // LC_VERSION_MIN_IPHONEOS (legacy LLVM output)
                guard length == 16, word(commands, cursor + 8) == 0x000f0000,
                      word(commands, cursor + 12) == 0 || word(commands, cursor + 12) >= 0x000f0000 else {
                    throw invalid("expected iOS 15.0 minimum version")
                }
                targetCommands += 1
            case 0x24, 0x2f, 0x30:
                throw invalid("non-iPhoneOS minimum-version command")
            case 0x1d:
                throw invalid("expected unsigned artifact; LC_CODE_SIGNATURE found")
            case 0x19: // LC_SEGMENT_64 and all section records must fit this command.
                guard length >= 72, Int(word(commands, cursor + 64)) == (length - 72) / 80,
                      (length - 72) % 80 == 0,
                      rangeFits(wide(commands, cursor + 40), wide(commands, cursor + 48)) else {
                    throw invalid("invalid segment/section bounds")
                }
                for section in 0..<Int(word(commands, cursor + 64)) {
                    let base = cursor + 72 + section * 80
                    let kind = word(commands, base + 64) & 0xff
                    // S_ZEROFILL, S_GB_ZEROFILL and S_THREAD_LOCAL_ZEROFILL have no file data.
                    if ![UInt32(1), 0xc, 0x12].contains(kind) {
                        guard rangeFits(UInt64(word(commands, base + 48)), wide(commands, base + 40)) else {
                            throw invalid("section data outside file")
                        }
                    }
                    guard rangeFits(UInt64(word(commands, base + 56)), UInt64(word(commands, base + 60)) * 8) else {
                        throw invalid("section relocations outside file")
                    }
                }
            case 0x2: // LC_SYMTAB
                guard length == 24,
                      rangeFits(UInt64(word(commands, cursor + 8)), UInt64(word(commands, cursor + 12)) * 16),
                      rangeFits(UInt64(word(commands, cursor + 16)), UInt64(word(commands, cursor + 20))) else {
                    throw invalid("symbol table outside file")
                }
            case 0xb: // LC_DYSYMTAB: file-backed tables, including indirect symbols.
                guard length == 80 else { throw invalid("invalid dynamic symbol command") }
                for (offset, stride) in [(32, 8), (40, 56), (48, 4), (56, 4), (64, 8), (72, 8)] {
                    guard rangeFits(UInt64(word(commands, cursor + offset)), UInt64(word(commands, cursor + offset + 4)) * UInt64(stride)) else {
                        throw invalid("dynamic symbol data outside file")
                    }
                }
            case 0x22, 0x80000022: // LC_DYLD_INFO[_ONLY]
                guard length == 48 else { throw invalid("invalid dyld info command") }
                for offset in stride(from: 8, through: 40, by: 8) {
                    guard rangeFits(UInt64(word(commands, cursor + offset)), UInt64(word(commands, cursor + offset + 4))) else {
                        throw invalid("dyld info outside file")
                    }
                }
            case 0x26, 0x29, 0x2b, 0x2e, 0x80000033, 0x80000034:
                guard length == 16, rangeFits(UInt64(word(commands, cursor + 8)), UInt64(word(commands, cursor + 12))) else {
                    throw invalid("linkedit data outside file")
                }
            case 0x80000028: // LC_MAIN
                guard length == 24, wide(commands, cursor + 8) < size else { throw invalid("invalid entry point") }
            case 0xc, 0xd, 0x18, 0x80000018, 0x8000001f, 0x80000023:
                guard length >= 24 else { throw invalid("truncated dylib command") }
                let name = Int(word(commands, cursor + 8))
                guard name >= 24, name < length, commands[(cursor + name)..<(cursor + length)].contains(0) else {
                    throw invalid("invalid dylib name bounds")
                }
            default: break // Unknown commands still receive complete envelope/bounds checking.
            }
            cursor += length
        }
        guard cursor == bytes, targetCommands == 1 else {
            throw invalid("command count/size mismatch or missing/duplicate iOS target")
        }
    }
}
