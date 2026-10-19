import Foundation
import XCTest
@testable import IDECore

final class NativeCBackendTests: XCTestCase {
    private var root: URL!
    private var configuration: NativeCConfiguration!

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let sdk = root.appendingPathComponent("SDK with spaces")
        let resource = root.appendingPathComponent("clang")
        for path in [sdk.appendingPathComponent("usr/include/stdio.h"),
                     sdk.appendingPathComponent("usr/lib/libSystem.tbd"),
                     resource.appendingPathComponent("include/stddef.h")] {
            try FileManager.default.createDirectory(at: path.deletingLastPathComponent(), withIntermediateDirectories: true)
            try Data().write(to: path)
        }
        configuration = NativeCConfiguration(sdkURL: sdk, resourceURL: resource,
                                              buildsURL: root.appendingPathComponent("Builds"), sdkVersion: "18.5")
    }
    override func tearDownWithError() throws { try FileManager.default.removeItem(at: root) }

    func testCompileLinkAndKeepVerifiedArtifact() async throws {
        let invoker = RecordingInvoker()
        let backend = NativeCBackend(configuration: configuration, invoker: invoker)
        let result = try await backend.build(workspace: .sample(language: .c))
        let artifact = try XCTUnwrap(result.artifactURL)
        XCTAssertTrue(FileManager.default.fileExists(atPath: artifact.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: artifact.deletingLastPathComponent().appendingPathComponent("build.log").path))
        XCTAssertEqual(invoker.calls.count, 2)
        let clang = invoker.calls[0].1
        XCTAssertEqual(clang.first, "clang")
        XCTAssertEqual(clang[try XCTUnwrap(clang.firstIndex(of: "-isysroot")) + 1], configuration.sdkURL.path)
        XCTAssertTrue(clang.contains("arm64-apple-ios15.0"))
        XCTAssertTrue(invoker.calls[1].1.contains("-no_adhoc_codesign"))
        XCTAssertFalse(result.output.contains("executed successfully"))
    }

    func testMultipleSourcesAndRepeatedBuildsUseDifferentDirectories() async throws {
        let invoker = RecordingInvoker()
        let backend = NativeCBackend(configuration: configuration, invoker: invoker)
        let workspace = Workspace(name: "two", files: [
            SourceFile(name: "a.c", contents: "int f(void){return 7;}", language: .c),
            SourceFile(name: "main.c", contents: "int f(void); int main(void){return f();}", language: .c)])
        let first = try await backend.build(workspace: workspace)
        let second = try await backend.build(workspace: workspace)
        XCTAssertEqual(invoker.calls.count, 6)
        XCTAssertNotEqual(first.artifactURL, second.artifactURL)
        XCTAssertEqual(invoker.calls[2].1.filter { $0.hasSuffix(".o") }.count, 2)
    }

    func testCompileFailureDoesNotLinkAndCleansPartialBuild() async throws {
        let invoker = RecordingInvoker()
        invoker.failure = .clang
        do {
            _ = try await NativeCBackend(configuration: configuration, invoker: invoker).build(workspace: .sample(language: .c))
            XCTFail("Expected diagnostic failure")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("test compiler diagnostic"))
        }
        XCTAssertEqual(invoker.calls.count, 1)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: configuration.buildsURL.path).count, 0)
    }

    func testLinkFailureDoesNotReportSuccess() async throws {
        let invoker = RecordingInvoker()
        invoker.failure = .linker
        do {
            _ = try await NativeCBackend(configuration: configuration, invoker: invoker).build(workspace: .sample(language: .c))
            XCTFail("Expected linker failure")
        } catch { XCTAssertTrue(error.localizedDescription.contains("LLD")) }
        XCTAssertEqual(invoker.calls.count, 2)
    }

    func testSuccessExitWithoutArtifactIsRejected() async {
        let invoker = RecordingInvoker()
        invoker.writeArtifacts = false
        do {
            _ = try await NativeCBackend(configuration: configuration, invoker: invoker).build(workspace: .sample(language: .c))
            XCTFail("Expected missing object")
        } catch { XCTAssertTrue(error.localizedDescription.contains("Mach-O")) }
        XCTAssertEqual(invoker.calls.count, 1)
    }

    func testMissingSDKFailsBeforeNativeCall() async throws {
        try FileManager.default.removeItem(at: configuration.sdkURL)
        let invoker = RecordingInvoker()
        do {
            _ = try await NativeCBackend(configuration: configuration, invoker: invoker).build(workspace: .sample(language: .c))
            XCTFail("Expected missing resource")
        } catch { XCTAssertTrue(error.localizedDescription.contains("missing")) }
        XCTAssertTrue(invoker.calls.isEmpty)
    }

    func testSwiftRemainsExplicitlyUnsupported() async {
        let invoker = RecordingInvoker()
        do {
            _ = try await NativeCBackend(configuration: configuration, invoker: invoker).build(workspace: .sample(language: .swift))
            XCTFail("Expected unsupported Swift")
        } catch { XCTAssertTrue(error.localizedDescription.contains("Swift frontend")) }
        XCTAssertTrue(invoker.calls.isEmpty)
    }

    func testUnavailableToolchainDoesNotCreateBuildDirectory() async {
        let invoker = RecordingInvoker()
        invoker.isAvailable = false
        do {
            _ = try await NativeCBackend(configuration: configuration, invoker: invoker).build(workspace: .sample(language: .c))
            XCTFail("Expected missing toolchain")
        } catch { XCTAssertEqual(error as? CompilerBackendError, .toolchainNotInstalled) }
        XCTAssertFalse(FileManager.default.fileExists(atPath: configuration.buildsURL.path))
    }

    func testUnsafeFilenameNeverReachesNativeBridge() async {
        let invoker = RecordingInvoker()
        do {
            _ = try await NativeCBackend(configuration: configuration, invoker: invoker).build(workspace:
                Workspace(name: "bad", files: [SourceFile(name: "../escape.c", contents: "", language: .c)]))
            XCTFail("Expected unsafe filename")
        } catch { XCTAssertEqual(error as? BuildPlanningError, .unsafeFilename("../escape.c")) }
        XCTAssertTrue(invoker.calls.isEmpty)
    }

    func testResourceAndVersionValidation() throws {
        let invalid = NativeCConfiguration(sdkURL: configuration.sdkURL, resourceURL: configuration.resourceURL,
                                          buildsURL: configuration.buildsURL, sdkVersion: "18.5 -bad")
        XCTAssertThrowsError(try invalid.validate())
        try FileManager.default.removeItem(at: configuration.resourceURL.appendingPathComponent("include/stddef.h"))
        XCTAssertThrowsError(try configuration.validate())
    }

    func testSourceAndFileCountLimitsRejectBeforeNativeCall() async {
        let invoker = RecordingInvoker()
        let backend = NativeCBackend(configuration: configuration, invoker: invoker)
        let workspaces = [
            Workspace(name: "many", files: (0..<33).map { SourceFile(name: "f\($0).c", contents: "", language: .c) }),
            Workspace(name: "large", files: [SourceFile(name: "main.c", contents: String(repeating: "x", count: 2 * 1024 * 1024 + 1), language: .c)])
        ]
        for workspace in workspaces {
            do { _ = try await backend.build(workspace: workspace); XCTFail("Expected size limit") }
            catch { XCTAssertTrue(error.localizedDescription.contains("32 files")) }
        }
        XCTAssertTrue(invoker.calls.isEmpty)
    }

    func testInvalidOutputDirectoryFailsBeforeNativeCall() async throws {
        try Data("not a directory".utf8).write(to: configuration.buildsURL)
        let invoker = RecordingInvoker()
        do {
            _ = try await NativeCBackend(configuration: configuration, invoker: invoker).build(workspace: .sample(language: .c))
            XCTFail("Expected output directory failure")
        } catch { XCTAssertTrue(invoker.calls.isEmpty) }
    }

    func testLargeDiagnosticsAreBoundedWithoutLosingFinalStatus() async throws {
        let invoker = RecordingInvoker()
        invoker.diagnostics = String(repeating: "diagnostic ", count: 20_000)
        let result = try await NativeCBackend(configuration: configuration, invoker: invoker).build(workspace: .sample(language: .c))
        XCTAssertLessThanOrEqual(result.output.utf8.count, BuildRetention.maximumLogBytes)
        XCTAssertTrue(result.output.contains("[build log truncated]"))
        XCTAssertTrue(result.output.contains("Not signed, installed, or executed."))
        let saved = try String(contentsOf: try XCTUnwrap(result.artifactURL).deletingLastPathComponent().appendingPathComponent("build.log"), encoding: .utf8)
        XCTAssertEqual(saved, result.output)
    }

    func testSymlinkArtifactRejectedBeforeLinkAndExternalFileUntouched() async throws {
        let outside = root.appendingPathComponent("external.o")
        let data = RecordingInvoker.header(fileType: 1)
        try data.write(to: outside)
        let invoker = RecordingInvoker()
        invoker.symlinkTarget = outside
        do {
            _ = try await NativeCBackend(configuration: configuration, invoker: invoker).build(workspace: .sample(language: .c))
            XCTFail("Expected symlink rejection")
        } catch { XCTAssertTrue(error.localizedDescription.contains("escaped") || error.localizedDescription.contains("symlink")) }
        XCTAssertEqual(invoker.calls.count, 1)
        XCTAssertEqual(try Data(contentsOf: outside), data)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: configuration.buildsURL.path).count, 0)
    }

    func testMachOSanityRejectsWrongArchitectureAndFileType() throws {
        let url = root.appendingPathComponent("bad.o")
        try Data(repeating: 0, count: 32).write(to: url)
        XCTAssertThrowsError(try NativeCBackend.validateMachO(at: url, fileType: 1))
        var bytes = RecordingInvoker.header(fileType: 2)
        try bytes.write(to: url)
        XCTAssertThrowsError(try NativeCBackend.validateMachO(at: url, fileType: 1))
        bytes[4] = 7
        try bytes.write(to: url)
        XCTAssertThrowsError(try NativeCBackend.validateMachO(at: url, fileType: 2))
    }
}

/// Deliberate test double: these headers are NOT real compiler output.
private final class RecordingInvoker: NativeCInvoker {
    var isAvailable = true
    var calls = [(NativeTool, [String])]()
    var failure: NativeTool?
    var writeArtifacts = true
    var diagnostics = ""
    var symlinkTarget: URL?
    func invoke(_ tool: NativeTool, arguments: [String]) -> NativeInvocationResult {
        calls.append((tool, arguments))
        if failure == tool { return NativeInvocationResult(exitCode: 1, diagnostics: "test compiler diagnostic") }
        if writeArtifacts, let index = arguments.firstIndex(of: "-o") {
            do {
                let url = URL(fileURLWithPath: arguments[index + 1])
                if let target = symlinkTarget { try FileManager.default.createSymbolicLink(at: url, withDestinationURL: target) }
                else { try Self.header(fileType: tool == .clang ? 1 : 2).write(to: url) }
            }
            catch { return NativeInvocationResult(exitCode: 1, diagnostics: error.localizedDescription) }
        }
        return NativeInvocationResult(exitCode: 0, diagnostics: diagnostics)
    }
    static func header(fileType: UInt32) -> Data {
        var data = Data()
        for word: UInt32 in [0xfeedfacf, 0x0100000c, 0, fileType, 1, 24, 0, 0, 0x32, 24, 2, 0x000f0000, 0x00120500, 0] {
            data.append(contentsOf: (0..<4).map { UInt8((word >> (8 * $0)) & 255) })
        }
        return data
    }
}
