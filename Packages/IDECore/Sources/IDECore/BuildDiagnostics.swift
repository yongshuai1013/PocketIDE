import Foundation

public enum BuildPhase: String, Codable { case compile, link }
public enum DiagnosticSeverity: String, Codable { case fatal, error, warning, note, remark, unknown }

/// File labels and messages are safe for display/export; only exact workspace identities navigate.
public struct BuildDiagnostic: Identifiable, Equatable, Codable {
    public let id: UUID
    public let file: String?
    public let line: Int?
    public let column: Int?
    public let severity: DiagnosticSeverity
    public let phase: BuildPhase
    public let message: String
    public let sourceFileID: UUID?

    public init(id: UUID = UUID(), file: String? = nil, line: Int? = nil, column: Int? = nil,
                severity: DiagnosticSeverity, phase: BuildPhase, message: String, sourceFileID: UUID? = nil) {
        self.id = id; self.file = file; self.line = line; self.column = column
        self.severity = severity; self.phase = phase; self.message = message; self.sourceFileID = sourceFileID
    }
}

/// Invocation failures retain earlier warnings/notes and a bounded, redacted raw transcript.
public struct NativeBuildFailure: Error, LocalizedError {
    public let tool: String
    public let output: String
    public let diagnostics: [BuildDiagnostic]
    public var errorDescription: String? { "\(tool) failed:\n\(output)" }
}

public struct DiagnosticRedactor {
    private let replacements: [(String, String)]

    public init(buildRoot: URL, sdkRoot: URL, resourceRoot: URL) {
        replacements = [(buildRoot, "<build>"), (sdkRoot, "<sdk>"), (resourceRoot, "<clang>")]
            .flatMap { url, label in
                [url.standardizedFileURL.path, url.resolvingSymlinksInPath().path].map { ($0, label) }
            }.sorted { $0.0.count > $1.0.count }
    }

    public func redact(_ text: String) -> String {
        var safe = text
        for (path, label) in replacements {
            // Boundary prevents a root /sdk from masking only the prefix of /sdk-private.
            let pattern = NSRegularExpression.escapedPattern(for: path) + "(?=/|[\\s:'\\\"),]|$)"
            if let regex = try? NSRegularExpression(pattern: pattern) {
                safe = regex.stringByReplacingMatches(in: safe, range: NSRange(safe.startIndex..., in: safe),
                                                      withTemplate: NSRegularExpression.escapedTemplate(for: label))
            }
        }
        return Self.redact(safe)
    }

    /// Unknown local paths may contain spaces. Conservatively hide the rest of that line rather
    /// than export a partial private directory. Known roots above keep their useful relative tail.
    public static func redact(_ text: String) -> String {
        let pattern = #"(?<![A-Za-z0-9_>/])(?:file://)?/(?!/)[^\r\n]*"#
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return text }
        return regex.stringByReplacingMatches(in: text, range: NSRange(text.startIndex..., in: text),
                                              withTemplate: "<local path redacted>")
    }
}

/// Parses stable plain-text Clang and LLD severity/location headers. All other bytes remain in
/// the bounded raw log; completely unrecognized invocations get a visible fallback record.
public struct CBuildDiagnosticParser {
    public static let maximumDiagnostics = 256
    private let root: URL
    private let files: [SourceFile]
    private let redactor: DiagnosticRedactor

    public init(buildRoot: URL, files: [SourceFile], redactor: DiagnosticRedactor) {
        root = buildRoot; self.files = files; self.redactor = redactor
    }

    public func parse(_ text: String, phase: BuildPhase, failed: Bool) -> [BuildDiagnostic] {
        let bounded = BuildRetention.boundedLog(text)
        let location = try! NSRegularExpression(pattern: #"^(.+?):([0-9]+):(?:([0-9]+):)?\s*(fatal error|error|warning|note|remark):\s*(.*)$"#)
        let driver = try! NSRegularExpression(pattern: #"^(?:(?:clang(?:-[0-9]+)?|ld64\.lld|ld\.lld|lld|ld):\s*)?(fatal error|error|warning|note|remark):\s*(.*)$"#)
        var result = [BuildDiagnostic]()
        func append(_ diagnostic: BuildDiagnostic) {
            if result.count < Self.maximumDiagnostics { result.append(diagnostic) }
            else if diagnostic.severity == .error || diagnostic.severity == .fatal {
                result[result.count - 1] = diagnostic
            }
        }
        for line in bounded.components(separatedBy: .newlines) {
            let range = NSRange(line.startIndex..., in: line)
            func capture(_ match: NSTextCheckingResult, _ index: Int) -> String? {
                guard let range = Range(match.range(at: index), in: line) else { return nil }
                return String(line[range])
            }
            func severity(_ value: String?) -> DiagnosticSeverity {
                value == "fatal error" ? .fatal : DiagnosticSeverity(rawValue: value ?? "") ?? .unknown
            }
            if let match = location.firstMatch(in: line, range: range), let path = capture(match, 1) {
                // Do not guess a workspace file from an unrelated SDK/header basename.
                let source = files.first { file in
                    path == file.name || path == "./" + file.name ||
                    path == root.appendingPathComponent(file.name).path ||
                    path == root.resolvingSymlinksInPath().appendingPathComponent(file.name).path
                }
                let row = capture(match, 2).flatMap(Int.init).flatMap { $0 > 0 ? $0 : nil }
                let col = capture(match, 3).flatMap(Int.init).flatMap { $0 > 0 ? $0 : nil }
                append(BuildDiagnostic(file: source?.name ?? redactor.redact(path), line: row, column: col,
                    severity: severity(capture(match, 4)), phase: phase,
                    message: redactor.redact(capture(match, 5) ?? ""), sourceFileID: source?.id))
            } else if let match = driver.firstMatch(in: line, range: range) {
                append(BuildDiagnostic(severity: severity(capture(match, 1)), phase: phase,
                                              message: redactor.redact(capture(match, 2) ?? "")))
            }
        }
        if result.isEmpty && (!bounded.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || failed) {
            result.append(BuildDiagnostic(severity: failed ? .error : .unknown, phase: phase,
                message: bounded.isEmpty ? "Tool failed without diagnostic output." : redactor.redact(bounded)))
        } else if failed && !result.contains(where: { $0.severity == .error || $0.severity == .fatal }) {
            if result.count == Self.maximumDiagnostics { result.removeLast() }
            result.append(BuildDiagnostic(severity: .error, phase: phase, message: "Tool exited unsuccessfully; see raw build output."))
        }
        return result
    }
}

public enum SourceSelection {
    /// Clang columns are one-based UTF-8 byte offsets, UIKit ranges are UTF-16. Clamp stale or
    /// oversized locations to a valid character boundary, never into a surrogate pair.
    public static func range(in text: String, line: Int, column: Int?) -> NSRange {
        // CRLF is a single Swift Character, so split(separator: "\n") is insufficient.
        func isNewline(_ character: Character) -> Bool { character == "\n" || character == "\r\n" || character == "\r" }
        var start = text.startIndex
        var remaining = max(line, 1) - 1
        while remaining > 0, let newline = text[start...].firstIndex(where: isNewline) {
            start = text.index(after: newline)
            remaining -= 1
        }
        let end = text[start...].firstIndex(where: isNewline) ?? text.endIndex
        var position = start
        var bytes = 0
        let target = max(column ?? 1, 1) - 1
        while position < end {
            let next = text.index(after: position)
            let width = text[position..<next].utf8.count
            if bytes + width > target { break }
            bytes += width; position = next
        }
        return NSRange(location: text[..<position].utf16.count, length: 0)
    }
}
