import Foundation
import XCTest
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif
@testable import IDECore

final class CWorkspaceImportTests: XCTestCase {
    private let format = "pocketide.c-workspace.v1"

    private func envelope(name: String = "Demo", files: [(String, String)] = [("main.c", "int main(void) {}")], format: String? = nil) -> Data {
        let object: [String: Any] = [
            "format": format ?? self.format,
            "name": name,
            "files": files.map { ["name": $0.0, "contents": $0.1] }
        ]
        return try! JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .fragmentsAllowed])
    }

    private func raw(_ body: String) -> Data { Data(body.utf8) }

    private func assertRejected(_ data: Data, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try CWorkspaceImporter.decode(data), "Expected import rejection", file: file, line: line)
    }

    private func temporaryRoot() throws -> URL {
        // Canonicalize only after creation: Foundation can leave /var aliases
        // unresolved for a nonexistent leaf on macOS. Keep the importer strict.
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let resolved = try XCTUnwrap(realpath(root.path, nil))
        defer { free(resolved) }
        return URL(fileURLWithPath: String(cString: resolved), isDirectory: true)
    }

    func testValidDecodeCreatesIndependentCFiles() throws {
        let imported = try CWorkspaceImporter.decode(envelope(name: "Hello World", files: [("main.c", "int main(void) { return 0; }"), ("util_1.c", "/* helper */")]))
        XCTAssertEqual(imported.name, "Hello World")
        XCTAssertEqual(imported.files.map(\.name), ["main.c", "util_1.c"])
        XCTAssertTrue(imported.files.allSatisfy { $0.language == .c })
        XCTAssertEqual(imported.files.map(\.contents), ["int main(void) { return 0; }", "/* helper */"])
        XCTAssertNotEqual(imported.files[0].id, imported.files[1].id)
        let second = try CWorkspaceImporter.decode(envelope())
        XCTAssertNotEqual(imported.files[0].id, second.files[0].id)
    }

    func testValidLoadAndImportDoesNotWriteToSource() throws {
        let root = try temporaryRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let source = root.appendingPathComponent("project.json")
        let bytes = envelope(name: "Loaded", files: [("main.c", "puts(\"ok\");")])
        try bytes.write(to: source)
        let before = try Data(contentsOf: source)
        let loaded = try CWorkspaceImporter.load(from: source)
        XCTAssertEqual(loaded.name, "Loaded")
        XCTAssertEqual(try Data(contentsOf: source), before)
    }

    func testFileCountBoundary() throws {
        let thirtyTwo = (0..<32).map { ("f\($0).c", "") }
        XCTAssertEqual(try CWorkspaceImporter.decode(envelope(files: thirtyTwo)).files.count, 32)
        assertRejected(envelope(files: thirtyTwo + [("extra.c", "")]))
        XCTAssertEqual(CWorkspaceImporter.maximumFiles, 32)
    }

    func testSerializedEnvelopeExactByteLimitAndOneOver() throws {
        XCTAssertEqual(CWorkspaceImporter.maximumBytes, 2 * 1024 * 1024)
        let base = envelope(files: [("x.c", "")])
        let exactContentLength = CWorkspaceImporter.maximumBytes - base.count
        XCTAssertGreaterThan(exactContentLength, 0)
        let exact = envelope(files: [("x.c", String(repeating: "a", count: exactContentLength))])
        XCTAssertEqual(exact.count, CWorkspaceImporter.maximumBytes)
        XCTAssertEqual(try CWorkspaceImporter.decode(exact).files[0].contents.utf8.count, exactContentLength)
        assertRejected(envelope(files: [("x.c", String(repeating: "a", count: exactContentLength + 1))]))
    }

    func testUTF8AccountingAndAggregateSourceLimit() throws {
        let data = envelope(name: "Cafe", files: [("main.c", "/* 🧪 */\né")])
        let result = try CWorkspaceImporter.decode(data)
        XCTAssertEqual(result.name, "Cafe")
        XCTAssertEqual(result.files[0].contents, "/* 🧪 */\né")
        XCTAssertGreaterThan(result.files[0].contents.utf8.count, result.files[0].contents.count)
        // This exceeds both budgets; UTF-8 bytes, not Swift Character count, determine the limit.
        let over = String(repeating: "é", count: CWorkspaceImporter.maximumBytes / 2 + 1)
        assertRejected(envelope(files: [("main.c", over)]))
    }

    func testRejectsZeroFiles() { assertRejected(envelope(files: [])) }

    func testRejectsWrongFormatTypesMissingAndUnknownFields() {
        assertRejected(envelope(format: "other"))
        for json in [
            #"{"format":7,"name":"x","files":[{"name":"x.c","contents":""}]}"#,
            #"{"format":"pocketide.c-workspace.v1","name":null,"files":[{"name":"x.c","contents":""}]}"#,
            #"{"format":"pocketide.c-workspace.v1","name":"x","files":"x.c"}"#,
            #"{"format":"pocketide.c-workspace.v1","files":[{"name":"x.c","contents":""}]}"#,
            #"{"format":"pocketide.c-workspace.v1","name":"x","files":[{"name":"x.c"}]}"#,
            #"{"format":"pocketide.c-workspace.v1","name":"x","files":[{"name":"x.c","contents":"","extra":1}]}"#,
            #"{"format":"pocketide.c-workspace.v1","name":"x","files":[{"name":"x.c","contents":""}],"extra":1}"#
        ] { assertRejected(raw(json)) }
    }

    func testRejectsDuplicateKeysIncludingEscapedKey() {
        assertRejected(raw(#"{"format":"pocketide.c-workspace.v1","name":"x","name":"y","files":[{"name":"x.c","contents":""}]}"#))
        assertRejected(raw(#"{"format":"pocketide.c-workspace.v1","name":"x","files":[{"name":"x.c","contents":"","con\u0074ents":"other"}]}"#))
        assertRejected(raw(#"{"format":"pocketide.c-workspace.v1","name":"x","files":[{"name":"x.c","name":"y","contents":""}]}"#))
    }

    func testRejectsDuplicateFilesIgnoringCase() {
        assertRejected(envelope(files: [("Main.c", ""), ("main.c", "")]))
    }

    func testRejectsUnsafeWorkspaceAndFileNames() {
        for name in ["", ".", "..", "bad/thing", "bad\\thing", "/absolute", "%2e%2e", "é", "a\n", "trailing.", "trailing ", "-leading"] {
            assertRejected(envelope(name: name))
        }
        for name in ["", "../x.c", "a/b.c", "a\\b.c", "/tmp/x.c", "%2e%2e.c", "é.c", "-x.c", "x.h", "x.C", "x.swift", "run.sh", "x.c.txt", "x.c\n", "x.c "] {
            assertRejected(envelope(files: [(name, "")]))
        }
    }

    func testWorkspaceAndFileNameByteLengthBoundaries() throws {
        let workspaceAtLimit = String(repeating: "a", count: 64)
        XCTAssertEqual(try CWorkspaceImporter.decode(envelope(name: workspaceAtLimit)).name, workspaceAtLimit)
        assertRejected(envelope(name: workspaceAtLimit + "a"))
        let fileAtLimit = String(repeating: "a", count: 126) + ".c"
        XCTAssertEqual(try CWorkspaceImporter.decode(envelope(files: [(fileAtLimit, "")])).files[0].name, fileAtLimit)
        assertRejected(envelope(files: [(String(repeating: "a", count: 127) + ".c", "")]))
    }

    func testRejectsNULInSource() { assertRejected(envelope(files: [("main.c", "before\0after")])) }

    func testRejectsMalformedInvalidUTF8TrailingAndNestedJSON() {
        for data in [raw("{"), raw(#"{"format":"pocketide.c-workspace.v1","name":"x","files":[{"name":"x.c","contents":""}]} trailing"#), Data([0xFF, 0xFE]), raw(#"{"format":"pocketide.c-workspace.v1","name":"x","files":[{"name":"x.c","contents":"","nested":{"a":{"b":{"c":{}}}}}]}"#)] {
            assertRejected(data)
        }
    }

    func testRejectsScriptPayloadAndNeverExecutesIt() throws {
        let root = try temporaryRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let marker = root.appendingPathComponent("executed")
        let script = "touch \(marker.path)"
        let scriptData = try JSONSerialization.data(withJSONObject: ["format": format, "name": "x", "files": [["name": "run.sh", "contents": script]]])
        assertRejected(scriptData)
        assertRejected(raw(#"{"format":"pocketide.c-workspace.v1","name":"x","files":[{"name":"main.c","contents":""}],"scripts":["touch marker"]}"#))
        XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path))
    }

    func testRejectsUnsupportedExtensionAndNonFileURLs() throws {
        let root = try temporaryRoot(); defer { try? FileManager.default.removeItem(at: root) }
        for name in ["project.JSON", "project.txt", "project.zip", "project"] {
            let url = root.appendingPathComponent(name); try envelope().write(to: url)
            XCTAssertThrowsError(try CWorkspaceImporter.load(from: url))
        }
        let doubleExtension = root.appendingPathComponent("project.c.json")
        try envelope().write(to: doubleExtension)
        XCTAssertEqual(try CWorkspaceImporter.load(from: doubleExtension).name, "Demo")
        XCTAssertThrowsError(try CWorkspaceImporter.load(from: URL(string: "https://example.com/project.json")!))
    }

    func testRejectsDirectoryAndSymlinkLeafAndParent() throws {
        let root = try temporaryRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let directory = root.appendingPathComponent("folder.json", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        XCTAssertThrowsError(try CWorkspaceImporter.load(from: directory))
        let actual = root.appendingPathComponent("actual.json"); try envelope().write(to: actual)
        let leaf = root.appendingPathComponent("link.json"); try FileManager.default.createSymbolicLink(at: leaf, withDestinationURL: actual)
        XCTAssertThrowsError(try CWorkspaceImporter.load(from: leaf))
        let realParent = root.appendingPathComponent("real", isDirectory: true)
        try FileManager.default.createDirectory(at: realParent, withIntermediateDirectories: false)
        let parentFile = realParent.appendingPathComponent("project.json"); try envelope().write(to: parentFile)
        let parentLink = root.appendingPathComponent("alias", isDirectory: true)
        try FileManager.default.createSymbolicLink(at: parentLink, withDestinationURL: realParent)
        XCTAssertThrowsError(try CWorkspaceImporter.load(from: parentLink.appendingPathComponent("project.json")))
    }

    func testRejectsFIFOWithoutBlocking() throws {
        let root = try temporaryRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let fifo = root.appendingPathComponent("pipe.json")
        XCTAssertEqual(mkfifo(fifo.path, mode_t(0o600)), 0)
        XCTAssertThrowsError(try CWorkspaceImporter.load(from: fifo))
    }

    func testFailedAssignmentIsAtomicAndDoesNotChangeSavedBytes() throws {
        let root = try temporaryRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let source = root.appendingPathComponent("bad.json")
        let badBytes = raw("not JSON"); try badBytes.write(to: source)
        let original = try CWorkspaceImporter.decode(envelope(name: "Existing", files: [("keep.c", "unchanged")]))
        var current = original
        let saved = try JSONEncoder().encode(original)
        let savedURL = root.appendingPathComponent("workspace.json")
        try saved.write(to: savedURL)
        XCTAssertThrowsError(try { current = try CWorkspaceImporter.load(from: source) }())
        XCTAssertEqual(current, original)
        XCTAssertEqual(try Data(contentsOf: savedURL), saved)
        XCTAssertEqual(try Data(contentsOf: source), badBytes)
    }

    func testLoadExactLimitAndOversizeFile() throws {
        let root = try temporaryRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let source = root.appendingPathComponent("limit.json")
        let base = envelope(files: [("main.c", "")])
        let exact = envelope(files: [("main.c", String(repeating: "a", count: CWorkspaceImporter.maximumBytes - base.count))])
        XCTAssertEqual(exact.count, CWorkspaceImporter.maximumBytes)
        try exact.write(to: source)
        XCTAssertEqual(try CWorkspaceImporter.load(from: source).files.count, 1)
        var over = exact; over.append(0x20)
        try over.write(to: source)
        XCTAssertThrowsError(try CWorkspaceImporter.load(from: source))
    }

    func testRejectsRemoteHostTraversalAndControlCharacterURLs() throws {
        let root = try temporaryRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let source = root.appendingPathComponent("project.json")
        try envelope().write(to: source)
        let local = source.absoluteString
        let urls = [
            URL(string: local.replacingOccurrences(of: "file:///", with: "file://remote.invalid/"))!,
            URL(string: root.absoluteString + "/../" + root.lastPathComponent + "/project.json")!,
            URL(string: root.absoluteString + "/%2e%2e/" + root.lastPathComponent + "/project.json")!,
            URL(string: local + "?query=1")!,
            URL(string: local + "#fragment")!,
            URL(string: local.replacingOccurrences(of: "project.json", with: "project.json%00ignored.json"))!
        ]
        for url in urls { XCTAssertThrowsError(try CWorkspaceImporter.load(from: url), "Rejected unsafe URL") }
    }

    func testStringEscapesAndMalformedJSONGrammar() throws {
        let escaped = raw(#"{"format":"pocketide.c-workspace.v1","name":"Demo","files":[{"name":"main.c","contents":"\uD83E\uDDEA\n\t\"\\\/"}]}"#)
        XCTAssertEqual(try CWorkspaceImporter.decode(escaped).files[0].contents, "🧪\n\t\"\\/")
        for value in [#""\uD800""#, #""\uDC00""#, #""\uD800\u0041""#, #""\x41""#, "01", "1.", "1e", "-", "truefalse", "[1,]", "{\"a\":1,}"] {
            assertRejected(raw("{\"format\":\"pocketide.c-workspace.v1\",\"name\":\"x\",\"files\":[{\"name\":\"x.c\",\"contents\":\(value)}]}"))
        }
        let deep = String(repeating: "[", count: 1000) + "0" + String(repeating: "]", count: 1000)
        assertRejected(raw(deep))
    }

    func testEveryFailedImportKeepsExistingWorkspaceAndSavedFile() throws {
        let root = try temporaryRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let original = Workspace.sample(language: .c)
        let saved = try JSONEncoder().encode(original)
        let savedURL = root.appendingPathComponent("workspace.json")
        try saved.write(to: savedURL)
        let invalid: [Data] = [
            raw("not json"), envelope(files: []),
            envelope(files: (0..<33).map { ("f\($0).c", "") }),
            envelope(files: [("main.c", ""), ("MAIN.c", "")]),
            envelope(files: [("../escape.c", "")]), envelope(files: [("run.sh", "touch marker")]),
            Data(repeating: 32, count: CWorkspaceImporter.maximumBytes + 1)
        ]
        let source = root.appendingPathComponent("incoming.json")
        for bytes in invalid {
            try bytes.write(to: source)
            var current = original
            XCTAssertThrowsError(try { current = try CWorkspaceImporter.load(from: source) }())
            XCTAssertEqual(current, original)
            XCTAssertEqual(try Data(contentsOf: savedURL), saved)
            XCTAssertEqual(try Data(contentsOf: source), bytes)
        }
        let outside = root.appendingPathComponent("outside.json")
        try envelope().write(to: outside)
        try FileManager.default.removeItem(at: source)
        try FileManager.default.createSymbolicLink(at: source, withDestinationURL: outside)
        var current = original
        XCTAssertThrowsError(try { current = try CWorkspaceImporter.load(from: source) }())
        XCTAssertEqual(current, original)
        XCTAssertEqual(try Data(contentsOf: savedURL), saved)
    }
}
