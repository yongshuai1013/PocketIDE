import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// Safely imports the deliberately narrow PocketIDE C workspace interchange format.
public enum CWorkspaceImporter {
    public static let maximumFiles = 32
    public static let maximumBytes = 2 * 1024 * 1024

    private static let format = "pocketide.c-workspace.v1"

    public enum ImportError: LocalizedError {
        case invalidWorkspace
        case invalidFile
        case fileTooLarge
        case unreadableFile

        public var errorDescription: String? {
            switch self {
            case .invalidWorkspace: return "The workspace file is invalid or unsupported."
            case .invalidFile: return "The workspace file cannot be read safely."
            case .fileTooLarge: return "The workspace file exceeds the size limit."
            case .unreadableFile: return "The workspace file could not be read."
            }
        }
    }

    /// Decode a single strict UTF-8 JSON object. The 2 MiB limit applies both to
    /// the complete JSON envelope and independently to the aggregate source text.
    public static func decode(_ data: Data) throws -> Workspace {
        guard data.count <= maximumBytes else { throw ImportError.fileTooLarge }
        guard let text = String(data: data, encoding: .utf8),
              !text.utf8.contains(0) else { throw ImportError.invalidWorkspace }
        var parser = StrictJSONParser(bytes: Array(data))
        let root = try parser.parse()
        guard case .object(let fields) = root,
              Set(fields.keys) == Set(["format", "name", "files"]),
              case .string(let formatValue)? = fields["format"], formatValue == format,
              case .string(let name)? = fields["name"], validWorkspaceName(name),
              case .array(let entries)? = fields["files"], (1...maximumFiles).contains(entries.count) else {
            throw ImportError.invalidWorkspace
        }
        var files: [SourceFile] = []
        var names = Set<String>()
        var sourceByteCount = 0
        for entry in entries {
            guard case .object(let props) = entry,
                  Set(props.keys) == Set(["name", "contents"]),
                  case .string(let filename)? = props["name"], validFilename(filename),
                  case .string(let contents)? = props["contents"],
                  !contents.utf8.contains(0) else { throw ImportError.invalidWorkspace }
            let folded = filename.lowercased()
            guard names.insert(folded).inserted else { throw ImportError.invalidWorkspace }
            sourceByteCount += contents.utf8.count
            guard sourceByteCount <= maximumBytes else { throw ImportError.fileTooLarge }
            files.append(SourceFile(name: filename, contents: contents, language: .c))
        }
        return Workspace(name: name, files: files)
    }

    /// Loads only a local `.json` regular file; every path component is opened
    /// descriptor-relative with O_NOFOLLOW. Symlink ancestors (including system
    /// aliases such as /var -> /private/var) are intentionally rejected.
    public static func load(from url: URL) throws -> Workspace {
        guard url.isFileURL, url.scheme?.lowercased() == "file",
              url.host == nil || url.host == "" || url.host?.lowercased() == "localhost",
              url.user == nil, url.password == nil, url.port == nil,
              url.query == nil, url.fragment == nil,
              url.pathExtension == "json", !url.path.hasPrefix("//") else {
            throw ImportError.invalidFile
        }
        // Validate before normalization: do not erase traversal or allow C-string truncation.
        let path = url.path
        let components = path.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
        guard path.hasPrefix("/"), !components.isEmpty,
              !path.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
              components.allSatisfy({ $0 != "." && $0 != ".." && !$0.isEmpty }) else {
            throw ImportError.invalidFile
        }
        var descriptor = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard descriptor >= 0 else { throw ImportError.unreadableFile }
        defer { _ = close(descriptor) }
        for (index, component) in components.enumerated() {
            let isFinal = index == components.count - 1
            let flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW | (isFinal ? O_NONBLOCK : O_DIRECTORY)
            let next = component.withCString { openat(descriptor, $0, flags) }
            guard next >= 0 else { throw ImportError.invalidFile }
            _ = close(descriptor)
            descriptor = next
        }
        var info = stat()
        guard fstat(descriptor, &info) == 0, (info.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG) else {
            throw ImportError.invalidFile
        }
        guard info.st_size >= 0, info.st_size <= off_t(maximumBytes) else { throw ImportError.fileTooLarge }
        var data = Data()
        data.reserveCapacity(Int(info.st_size))
        var buffer = [UInt8](repeating: 0, count: 16 * 1024)
        while true {
            let count = read(descriptor, &buffer, min(buffer.count, maximumBytes - data.count + 1))
            if count == 0 { break }
            if count < 0 {
                if errno == EINTR { continue }
                throw ImportError.unreadableFile
            }
            guard data.count + count <= maximumBytes else { throw ImportError.fileTooLarge }
            data.append(contentsOf: buffer[0..<count])
        }
        return try decode(data)
    }

    private static func validFilename(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard !bytes.isEmpty, bytes.count <= 128, bytes.last == 99,
              value.hasSuffix(".c"), value != ".", value != "..",
              !value.hasSuffix("."), !value.hasSuffix(" "),
              bytes.allSatisfy({ isASCIIAlphaNumeric($0) || $0 == 95 || $0 == 46 || $0 == 45 }),
              let first = bytes.first, isASCIIAlphaNumeric(first) || first == 95 else { return false }
        return true
    }

    private static func validWorkspaceName(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard !bytes.isEmpty, bytes.count <= 64, value != ".", value != "..",
              !value.hasSuffix("."), !value.hasSuffix(" "),
              bytes.allSatisfy({ isASCIIAlphaNumeric($0) || $0 == 95 || $0 == 46 || $0 == 45 || $0 == 32 }),
              let first = bytes.first, isASCIIAlphaNumeric(first) || first == 95 else { return false }
        return true
    }

    private static func isASCIIAlphaNumeric(_ byte: UInt8) -> Bool {
        (byte >= 65 && byte <= 90) || (byte >= 97 && byte <= 122) || (byte >= 48 && byte <= 57)
    }
}

/// Minimal RFC 8259 parser used before model construction so duplicate keys,
/// including keys spelled with escapes, cannot be hidden by Foundation decoding.
private struct StrictJSONParser {
    enum Value {
        case object([String: Value])
        case array([Value])
        case string(String)
        case other
    }
    private let bytes: [UInt8]
    private var index = 0
    init(bytes: [UInt8]) { self.bytes = bytes }

    mutating func parse() throws -> Value {
        skipWhitespace()
        let value = try parseValue(depth: 0)
        skipWhitespace()
        guard index == bytes.count else { throw CWorkspaceImporter.ImportError.invalidWorkspace }
        return value
    }

    private mutating func parseValue(depth: Int) throws -> Value {
        guard depth <= 64, index < bytes.count else { throw CWorkspaceImporter.ImportError.invalidWorkspace }
        switch bytes[index] {
        case 123: return try parseObject(depth: depth + 1)
        case 91: return try parseArray(depth: depth + 1)
        case 34: return .string(try parseString())
        case 116: try consumeLiteral(Array("true".utf8)); return .other
        case 102: try consumeLiteral(Array("false".utf8)); return .other
        case 110: try consumeLiteral(Array("null".utf8)); return .other
        case 45, 48...57: try parseNumber(); return .other
        default: throw CWorkspaceImporter.ImportError.invalidWorkspace
        }
    }

    private mutating func parseObject(depth: Int) throws -> Value {
        index += 1; skipWhitespace()
        var result: [String: Value] = [:]
        if consume(125) { return .object(result) }
        while true {
            guard index < bytes.count, bytes[index] == 34 else { throw CWorkspaceImporter.ImportError.invalidWorkspace }
            let key = try parseString()
            guard result[key] == nil else { throw CWorkspaceImporter.ImportError.invalidWorkspace }
            skipWhitespace(); guard consume(58) else { throw CWorkspaceImporter.ImportError.invalidWorkspace }; skipWhitespace()
            result[key] = try parseValue(depth: depth)
            skipWhitespace()
            if consume(125) { break }
            guard consume(44) else { throw CWorkspaceImporter.ImportError.invalidWorkspace }
            skipWhitespace()
        }
        return .object(result)
    }

    private mutating func parseArray(depth: Int) throws -> Value {
        index += 1; skipWhitespace()
        var values: [Value] = []
        if consume(93) { return .array(values) }
        while true {
            values.append(try parseValue(depth: depth))
            skipWhitespace()
            if consume(93) { break }
            guard consume(44) else { throw CWorkspaceImporter.ImportError.invalidWorkspace }
            skipWhitespace()
        }
        return .array(values)
    }

    private mutating func parseString() throws -> String {
        guard consume(34) else { throw CWorkspaceImporter.ImportError.invalidWorkspace }
        var scalars = String.UnicodeScalarView()
        var segmentStart = index
        while index < bytes.count {
            let byte = bytes[index]
            if byte == 34 {
                if segmentStart < index { try appendUTF8(bytes[segmentStart..<index], to: &scalars) }
                index += 1
                return String(scalars)
            }
            if byte == 92 {
                if segmentStart < index { try appendUTF8(bytes[segmentStart..<index], to: &scalars) }
                index += 1
                guard index < bytes.count else { throw CWorkspaceImporter.ImportError.invalidWorkspace }
                let escaped = bytes[index]; index += 1
                switch escaped {
                case 34: scalars.append("\"")
                case 92: scalars.append("\\")
                case 47: scalars.append("/")
                case 98: scalars.append("\u{8}")
                case 102: scalars.append("\u{c}")
                case 110: scalars.append("\n")
                case 114: scalars.append("\r")
                case 116: scalars.append("\t")
                case 117:
                    let first = try hexQuad()
                    let scalar: UInt32
                    if (0xD800...0xDBFF).contains(first) {
                        guard index + 2 <= bytes.count, bytes[index] == 92, bytes[index + 1] == 117 else { throw CWorkspaceImporter.ImportError.invalidWorkspace }
                        index += 2
                        let second = try hexQuad()
                        guard (0xDC00...0xDFFF).contains(second) else { throw CWorkspaceImporter.ImportError.invalidWorkspace }
                        scalar = 0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00)
                    } else {
                        guard !(0xDC00...0xDFFF).contains(first) else { throw CWorkspaceImporter.ImportError.invalidWorkspace }
                        scalar = first
                    }
                    guard let unicode = Unicode.Scalar(scalar) else { throw CWorkspaceImporter.ImportError.invalidWorkspace }
                    scalars.append(unicode)
                default: throw CWorkspaceImporter.ImportError.invalidWorkspace
                }
                segmentStart = index
            } else {
                guard byte >= 32 else { throw CWorkspaceImporter.ImportError.invalidWorkspace }
                index += 1
            }
        }
        throw CWorkspaceImporter.ImportError.invalidWorkspace
    }

    private mutating func appendUTF8(_ range: ArraySlice<UInt8>, to scalars: inout String.UnicodeScalarView) throws {
        guard let string = String(bytes: range, encoding: .utf8) else { throw CWorkspaceImporter.ImportError.invalidWorkspace }
        scalars.append(contentsOf: string.unicodeScalars)
    }

    private mutating func hexQuad() throws -> UInt32 {
        guard index + 4 <= bytes.count else { throw CWorkspaceImporter.ImportError.invalidWorkspace }
        var value: UInt32 = 0
        for byte in bytes[index..<index + 4] {
            let digit: UInt32
            switch byte {
            case 48...57: digit = UInt32(byte - 48)
            case 65...70: digit = UInt32(byte - 55)
            case 97...102: digit = UInt32(byte - 87)
            default: throw CWorkspaceImporter.ImportError.invalidWorkspace
            }
            value = value * 16 + digit
        }
        index += 4
        return value
    }

    private mutating func parseNumber() throws {
        let start = index
        _ = consume(45)
        guard index < bytes.count else { throw CWorkspaceImporter.ImportError.invalidWorkspace }
        if consume(48) {
            if index < bytes.count, isDigit(bytes[index]) { throw CWorkspaceImporter.ImportError.invalidWorkspace }
        } else {
            guard index < bytes.count, (49...57).contains(bytes[index]) else { throw CWorkspaceImporter.ImportError.invalidWorkspace }
            while index < bytes.count, isDigit(bytes[index]) { index += 1 }
        }
        if consume(46) {
            guard index < bytes.count, isDigit(bytes[index]) else { throw CWorkspaceImporter.ImportError.invalidWorkspace }
            while index < bytes.count, isDigit(bytes[index]) { index += 1 }
        }
        if index < bytes.count, bytes[index] == 101 || bytes[index] == 69 {
            index += 1
            if index < bytes.count, bytes[index] == 43 || bytes[index] == 45 { index += 1 }
            guard index < bytes.count, isDigit(bytes[index]) else { throw CWorkspaceImporter.ImportError.invalidWorkspace }
            while index < bytes.count, isDigit(bytes[index]) { index += 1 }
        }
        guard index > start else { throw CWorkspaceImporter.ImportError.invalidWorkspace }
    }

    private mutating func consumeLiteral(_ literal: [UInt8]) throws {
        guard index + literal.count <= bytes.count, Array(bytes[index..<index + literal.count]) == literal else { throw CWorkspaceImporter.ImportError.invalidWorkspace }
        index += literal.count
    }
    private mutating func consume(_ byte: UInt8) -> Bool {
        guard index < bytes.count, bytes[index] == byte else { return false }
        index += 1; return true
    }
    private mutating func skipWhitespace() {
        while index < bytes.count, bytes[index] == 32 || bytes[index] == 9 || bytes[index] == 10 || bytes[index] == 13 { index += 1 }
    }
    private func isDigit(_ byte: UInt8) -> Bool { byte >= 48 && byte <= 57 }
}
