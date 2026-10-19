import Foundation
import XCTest
@testable import IDECore

final class BuildDiagnosticsTests: XCTestCase {
    private var root: URL!
    private var configuration: NativeCConfiguration!

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        let sdk = root.appendingPathComponent("SDK with spaces", isDirectory: true)
        let resource = root.appendingPathComponent("Clang Resources", isDirectory: true)
        for path in [sdk.appendingPathComponent("usr/include/stdio.h"), sdk.appendingPathComponent("usr/lib/libSystem.tbd"), resource.appendingPathComponent("include/stddef.h")] {
            try FileManager.default.createDirectory(at: path.deletingLastPathComponent(), withIntermediateDirectories: true)
            try Data().write(to: path)
        }
        configuration = NativeCConfiguration(sdkURL: sdk, resourceURL: resource, buildsURL: root.appendingPathComponent("Build Output", isDirectory: true), sdkVersion: "18.5")
    }

    override func tearDownWithError() throws { try FileManager.default.removeItem(at: root) }

    private func parser(files: [SourceFile] = [], buildRoot: URL? = nil) -> CBuildDiagnosticParser {
        let build = buildRoot ?? root.appendingPathComponent("build", isDirectory: true)
        let redactor = DiagnosticRedactor(buildRoot: build, sdkRoot: configuration.sdkURL, resourceRoot: configuration.resourceURL)
        return CBuildDiagnosticParser(buildRoot: build, files: files, redactor: redactor)
    }

    func testSyntaxErrorCapturesLocationSeverityAndCompilePhase() throws {
        let file = SourceFile(name: "main.c", contents: "int main(){\n nope\n}", language: .c)
        let diagnostic = try XCTUnwrap(parser(files: [file]).parse("main.c:2:7: error: use of undeclared identifier 'nope'", phase: .compile, failed: true).first)
        XCTAssertEqual(diagnostic.file, "main.c")
        XCTAssertEqual(diagnostic.line, 2)
        XCTAssertEqual(diagnostic.column, 7)
        XCTAssertEqual(diagnostic.severity, .error)
        XCTAssertEqual(diagnostic.phase, .compile)
        XCTAssertEqual(diagnostic.sourceFileID, file.id)
    }

    func testWarningInEarlierFileAndErrorInLaterFileKeepSourceIdentity() async throws {
        let a = SourceFile(name: "a.c", contents: "", language: .c)
        let b = SourceFile(name: "b.c", contents: "", language: .c)
        let p = parser(files: [a, b])
        let first = p.parse("a.c:1:2: warning: caution", phase: .compile, failed: false)
        let second = p.parse("b.c:3:4: error: broken", phase: .compile, failed: true)
        XCTAssertEqual(first.first?.severity, .warning)
        XCTAssertEqual(first.first?.sourceFileID, a.id)
        XCTAssertEqual(second.first?.severity, .error)
        XCTAssertEqual(second.first?.sourceFileID, b.id)
        let invoker = SequencedInvoker(results: [
            NativeInvocationResult(exitCode: 0, diagnostics: "a.c:1:2: warning: caution"),
            NativeInvocationResult(exitCode: 1, diagnostics: "b.c:3:4: error: broken")])
        do {
            _ = try await NativeCBackend(configuration: configuration, invoker: invoker)
                .build(workspace: Workspace(name: "multi", files: [a, b]))
            XCTFail("Expected second-file compile failure")
        } catch let failure as NativeBuildFailure {
            XCTAssertEqual(failure.diagnostics.map(\.sourceFileID), [a.id, b.id])
            XCTAssertEqual(failure.diagnostics.map(\.severity), [.warning, .error])
        }
        XCTAssertEqual(invoker.tools, [.clang, .clang])
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: configuration.buildsURL.path).count, 0)
    }

    func testLLDUndefinedSymbolIsLinkDiagnosticWithMultilineRawOutputAndNoSource() async throws {
        let output = "ld64.lld: error: undefined symbol: _missing\n>>> referenced by main.c:4\n>>>               main.o:(main)"
        let values = parser(files: [SourceFile(name: "main.c", contents: "", language: .c)]).parse(output, phase: .link, failed: true)
        let diagnostic = try XCTUnwrap(values.first)
        XCTAssertEqual(diagnostic.severity, .error)
        XCTAssertEqual(diagnostic.phase, .link)
        XCTAssertNil(diagnostic.file)
        XCTAssertNil(diagnostic.sourceFileID)
        XCTAssertTrue(diagnostic.message.contains("undefined symbol: _missing"))
        XCTAssertTrue(values.count >= 1)
        let invoker = SequencedInvoker(results: [NativeInvocationResult(exitCode: 0), NativeInvocationResult(exitCode: 1, diagnostics: output)])
        do {
            _ = try await NativeCBackend(configuration: configuration, invoker: invoker).build(workspace: .sample(language: .c))
            XCTFail("Expected undefined symbol failure")
        } catch let failure as NativeBuildFailure {
            XCTAssertTrue(failure.output.contains(">>> referenced by main.c:4"))
            XCTAssertTrue(failure.output.contains("main.o:(main)"))
            XCTAssertEqual(failure.diagnostics.first?.phase, .link)
        }
    }

    func testRetryAfterCompileAndLinkFailuresDoesNotAccumulateDiagnostics() async throws {
        let invoker = SequencedInvoker(results: [
            NativeInvocationResult(exitCode: 1, diagnostics: "main.c:1:1: error: compile failed"),
            NativeInvocationResult(exitCode: 0), NativeInvocationResult(exitCode: 1, diagnostics: "ld64.lld: error: undefined symbol: _x"),
            NativeInvocationResult(exitCode: 0), NativeInvocationResult(exitCode: 0)
        ])
        let backend = NativeCBackend(configuration: configuration, invoker: invoker)
        let workspace = Workspace(name: "retry", files: [SourceFile(name: "main.c", contents: "int main(void){return 0;}", language: .c)])
        do { _ = try await backend.build(workspace: workspace); XCTFail("Expected compile failure") }
        catch { XCTAssertTrue((error as? NativeBuildFailure)?.diagnostics.contains(where: { $0.message.contains("compile failed") }) == true) }
        do { _ = try await backend.build(workspace: workspace); XCTFail("Expected link failure") }
        catch { XCTAssertTrue((error as? NativeBuildFailure)?.diagnostics.contains(where: { $0.phase == .link }) == true) }
        let success = try await backend.build(workspace: workspace)
        XCTAssertTrue(success.diagnostics.isEmpty)
    }

    func testKnownRootsWithSpacesAndUnknownAbsolutePathsAreRedacted() {
        let redactor = DiagnosticRedactor(buildRoot: root.appendingPathComponent("build root"), sdkRoot: configuration.sdkURL, resourceRoot: configuration.resourceURL)
        let value = redactor.redact("sdk \(configuration.sdkURL.path)/usr/include/stdio.h; unknown /private/user secret/file.c")
        XCTAssertTrue(value.contains("<sdk>/usr/include/stdio.h"))
        XCTAssertTrue(value.contains("<local path redacted>"))
        XCTAssertFalse(value.contains(root.path))
        XCTAssertFalse(value.contains(configuration.sdkURL.path))
    }

    func testSuccessBuildLogAndFailureOutputAndJSONDiagnosticsDoNotLeakRoots() async throws {
        let workspace = Workspace(name: "safe", files: [SourceFile(name: "main.c", contents: "int main(void){return 0;}", language: .c)])
        let success = try await NativeCBackend(configuration: configuration, invoker: SequencedInvoker(results: [NativeInvocationResult(exitCode: 0, diagnostics: "note: \(configuration.sdkURL.path)/private.h")] )).build(workspace: workspace)
        let logURL = try XCTUnwrap(success.artifactURL).deletingLastPathComponent().appendingPathComponent("build.log")
        let saved = try String(contentsOf: logURL, encoding: .utf8)
        XCTAssertFalse(success.output.contains(root.path)); XCTAssertFalse(saved.contains(root.path))
        let failing = NativeCBackend(configuration: configuration, invoker: SequencedInvoker(results: [NativeInvocationResult(exitCode: 1, diagnostics: "main.c:1:1: error: cannot include \(configuration.sdkURL.path)/secret.h")]))
        do {
            _ = try await failing.build(workspace: workspace)
            XCTFail("Expected failure")
        } catch let error as NativeBuildFailure {
            let encoded = try String(data: JSONEncoder().encode(error.diagnostics), encoding: .utf8)
            XCTAssertFalse(error.output.contains(root.path))
            XCTAssertFalse(error.output.contains(configuration.sdkURL.path))
            XCTAssertFalse(encoded?.contains(root.path) ?? true)
            XCTAssertFalse(encoded?.contains(configuration.sdkURL.path) ?? true)
        }
    }

    func testUnknownEmptyFailureGetsVisibleFallback() throws {
        let values = parser().parse("", phase: .link, failed: true)
        XCTAssertEqual(values.count, 1)
        XCTAssertEqual(values[0].severity, .error)
        XCTAssertEqual(values[0].phase, .link)
        XCTAssertTrue(values[0].message.contains("without diagnostic output"))
    }

    func testDiagnosticLimitRetainsFinalFailureError() throws {
        let text = (0..<300).map { "clang: warning: warning \($0)" }.joined(separator: "\n") + "\nclang: error: final failure"
        let values = parser().parse(text, phase: .compile, failed: true)
        XCTAssertEqual(values.count, CBuildDiagnosticParser.maximumDiagnostics)
        XCTAssertEqual(values.last?.severity, .error)
        XCTAssertTrue(values.last?.message.contains("final failure") == true)
    }

    func testExternalHeaderWithWorkspaceBasenameNeverNavigates() throws {
        let file = SourceFile(name: "main.c", contents: "", language: .c)
        let values = parser(files: [file]).parse("/private/別人的目錄/main.c:5:9: fatal error: missing header", phase: .compile, failed: true)
        let diagnostic = try XCTUnwrap(values.first)
        XCTAssertNil(diagnostic.sourceFileID)
        XCTAssertEqual(diagnostic.severity, .fatal)
        XCTAssertEqual(diagnostic.line, 5)
        XCTAssertFalse(diagnostic.file?.contains("/private") ?? true)
        XCTAssertFalse(diagnostic.file?.contains("別人的目錄") ?? true)
    }

    func testExactAbsoluteWorkspacePathAndLocationWithoutColumn() throws {
        let file = SourceFile(name: "file with spaces.c", contents: "", language: .c)
        let build = root.appendingPathComponent("build")
        let text = "\(build.appendingPathComponent(file.name).path):7: note: declared here"
        let diagnostic = try XCTUnwrap(parser(files: [file], buildRoot: build).parse(text, phase: .compile, failed: false).first)
        XCTAssertEqual(diagnostic.sourceFileID, file.id)
        XCTAssertEqual(diagnostic.file, file.name)
        XCTAssertEqual(diagnostic.line, 7)
        XCTAssertNil(diagnostic.column)
        XCTAssertEqual(diagnostic.severity, .note)
    }

    func testUnknownFormatPreservesBoundedRawFallbackAndRedactsUnicodePaths() async throws {
        let text = "unrecognized tool output\n" + String(repeating: "內容 ", count: 30_000) + "\nfailed opening /私人 目錄/input.c"
        let invoker = SequencedInvoker(results: [NativeInvocationResult(exitCode: 1, diagnostics: text)])
        do {
            _ = try await NativeCBackend(configuration: configuration, invoker: invoker).build(workspace: .sample(language: .c))
            XCTFail("Expected unknown-format failure")
        } catch let failure as NativeBuildFailure {
            XCTAssertEqual(failure.diagnostics.first?.severity, .error)
            XCTAssertTrue(failure.output.contains("unrecognized tool output"))
            XCTAssertTrue(failure.output.contains("[build log truncated]"))
            XCTAssertFalse(failure.output.contains("私人"))
            XCTAssertFalse(failure.localizedDescription.contains("私人"))
            XCTAssertLessThanOrEqual(failure.output.utf8.count, BuildRetention.maximumLogBytes)
            XCTAssertLessThanOrEqual(try XCTUnwrap(failure.diagnostics.first).message.utf8.count, BuildRetention.maximumLogBytes)
        }
        XCTAssertFalse(NativeCError.missingResource("/私人 目錄/sdk").localizedDescription.contains("私人"))
        XCTAssertFalse(NativeCError.invalidArtifact("/私人 目錄/output").localizedDescription.contains("私人"))
    }

    func testBuildWideLimitStillKeepsLaterLinkFailure() async throws {
        let warnings = (0..<300).map { "main.c:1:1: warning: w\($0)" }.joined(separator: "\n")
        let invoker = SequencedInvoker(results: [NativeInvocationResult(exitCode: 0, diagnostics: warnings),
            NativeInvocationResult(exitCode: 1, diagnostics: "ld64.lld: error: undefined symbol: _last")])
        do {
            _ = try await NativeCBackend(configuration: configuration, invoker: invoker).build(workspace: .sample(language: .c))
            XCTFail("Expected link failure after full warning list")
        } catch let failure as NativeBuildFailure {
            XCTAssertEqual(failure.diagnostics.count, CBuildDiagnosticParser.maximumDiagnostics)
            XCTAssertEqual(failure.diagnostics.last?.phase, .link)
            XCTAssertEqual(failure.diagnostics.last?.severity, .error)
            XCTAssertTrue(failure.diagnostics.last?.message.contains("_last") == true)
        }
    }

    func testSourceSelectionHandlesUTF8CJKEmojiCombiningTabAndCRLF() {
        let text = "中🙂e\u{301}\tX\r\nnext"
        let scalarStart = SourceSelection.range(in: text, line: 1, column: 1).location
        let emojiStart = SourceSelection.range(in: text, line: 1, column: 4).location
        let afterEmoji = SourceSelection.range(in: text, line: 1, column: 8).location
        let clamped = SourceSelection.range(in: text, line: 1, column: 999).location
        let nextLine = SourceSelection.range(in: text, line: 2, column: 1).location
        XCTAssertEqual(scalarStart, 0)
        XCTAssertEqual(emojiStart, 1)
        XCTAssertEqual(afterEmoji, 3)
        XCTAssertEqual(clamped, 7)
        XCTAssertEqual(nextLine, 9)
        XCTAssertEqual(SourceSelection.range(in: text, line: 99, column: 999).location, 13)
        XCTAssertEqual(SourceSelection.range(in: "", line: Int.max, column: Int.max), NSRange(location: 0, length: 0))
        XCTAssertEqual(SourceSelection.range(in: text, line: Int.min, column: Int.min).location, 0)
        XCTAssertEqual(SourceSelection.range(in: text, line: 1, column: 5).location, 1)
        XCTAssertEqual(SourceSelection.range(in: text, line: 1, column: 11).location, 5)
        XCTAssertEqual(SourceSelection.range(in: text, line: 2, column: nil).location, 9)
    }
}

/// Explicit test double; writes the same synthetic Mach-O headers as NativeCBackendTests.
private final class SequencedInvoker: NativeCInvoker {
    var isAvailable = true
    var tools = [NativeTool]()
    private var results: [NativeInvocationResult]
    init(results: [NativeInvocationResult]) { self.results = results }
    func invoke(_ tool: NativeTool, arguments: [String]) -> NativeInvocationResult {
        tools.append(tool)
        let result = results.isEmpty ? NativeInvocationResult(exitCode: 0) : results.removeFirst()
        if result.exitCode == 0, let index = arguments.firstIndex(of: "-o") {
            do { try Self.header(fileType: tool == .clang ? 1 : 2).write(to: URL(fileURLWithPath: arguments[index + 1])) }
            catch { return NativeInvocationResult(exitCode: 1, diagnostics: error.localizedDescription) }
        }
        return result
    }
    private static func header(fileType: UInt32) -> Data {
        var data = Data()
        for word: UInt32 in [0xfeedfacf, 0x0100000c, 0, fileType, 1, 24, 0, 0, 0x32, 24, 2, 0x000f0000, 0x00120500, 0] {
            data.append(contentsOf: (0..<4).map { UInt8((word >> (8 * $0)) & 255) })
        }
        return data
    }
}
