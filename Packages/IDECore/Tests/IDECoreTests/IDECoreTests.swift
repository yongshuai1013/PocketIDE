import Foundation
import XCTest
@testable import IDECore

final class IDECoreTests: XCTestCase {
    func testWorkspaceStoreRoundTrip() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = WorkspaceStore(directoryURL: directory)
        let workspace = Workspace(name: "Demo", files: [SourceFile(name: "main.swift", contents: "print(1)", language: .swift)])
        try store.save(workspace)
        XCTAssertEqual(try store.load(named: "Demo"), workspace)
    }

    func testStoreRejectsTraversal() throws {
        let store = WorkspaceStore(directoryURL: FileManager.default.temporaryDirectory)
        XCTAssertThrowsError(try store.load(named: "../escape")) { XCTAssertEqual($0 as? WorkspaceStoreError, .unsafeWorkspaceName) }
    }

    func testPlanRejectsUnsafeFilename() {
        let workspace = Workspace(name: "x", files: [SourceFile(name: "../main.c", contents: "", language: .c)])
        XCTAssertThrowsError(try BuildPlanner.plan(workspace: workspace)) { XCTAssertEqual($0 as? BuildPlanningError, .unsafeFilename("../main.c")) }
    }

    func testPlanRejectsOptionInjectionAndControlCharacters() {
        for name in ["-output.c", "bad\u{0}name.c", "bad\nname.c"] {
            let workspace = Workspace(name: "x", files: [SourceFile(name: name, contents: "", language: .c)])
            XCTAssertThrowsError(try BuildPlanner.plan(workspace: workspace)) { XCTAssertEqual($0 as? BuildPlanningError, .unsafeFilename(name)) }
        }
    }

    func testPlanRejectsDuplicateNames() {
        let workspace = Workspace(name: "x", files: [SourceFile(name: "same.c", contents: "", language: .c), SourceFile(name: "same.c", contents: "", language: .c)])
        XCTAssertThrowsError(try BuildPlanner.plan(workspace: workspace)) { XCTAssertEqual($0 as? BuildPlanningError, .duplicateFilename("same.c")) }
    }

    func testPlanRejectsCaseInsensitiveDuplicateNames() {
        let workspace = Workspace(name: "x", files: [SourceFile(name: "Main.c", contents: "", language: .c), SourceFile(name: "main.c", contents: "", language: .c)])
        XCTAssertThrowsError(try BuildPlanner.plan(workspace: workspace)) { XCTAssertEqual($0 as? BuildPlanningError, .duplicateFilename("main.c")) }
    }

    func testSwiftFilesCompileTogetherInOneInvocation() throws {
        let workspace = Workspace(name: "x", files: [SourceFile(name: "a.swift", contents: "", language: .swift), SourceFile(name: "b.swift", contents: "", language: .swift)])
        let plan = try BuildPlanner.plan(workspace: workspace)
        XCTAssertEqual(plan.invocations.count, 1)
        XCTAssertEqual(plan.invocations.filter { $0.executable == "swiftc" }.count, 1)
        XCTAssertEqual(plan.invocations[0].executable, "swiftc")
        XCTAssertTrue(plan.invocations[0].arguments.contains("a.swift"))
        XCTAssertTrue(plan.invocations[0].arguments.contains("b.swift"))
    }

    func testCFilesCompileSeparately() throws {
        let workspace = Workspace(name: "x", files: [SourceFile(name: "a.c", contents: "", language: .c), SourceFile(name: "b.c", contents: "", language: .c)])
        let plan = try BuildPlanner.plan(workspace: workspace)
        XCTAssertEqual(plan.invocations.filter { $0.executable == "clang" }.count, 2)
        XCTAssertEqual(plan.invocations[0].arguments[plan.invocations[0].arguments.firstIndex(of: "-c")! + 1], "a.c")
        XCTAssertEqual(plan.invocations[1].arguments[plan.invocations[1].arguments.firstIndex(of: "-c")! + 1], "b.c")
    }

    func testDeploymentTargetIsIOS15Arm64() throws {
        let plan = try BuildPlanner.plan(workspace: .sample(language: .c))
        XCTAssertEqual(plan.target.deploymentVersion, "15.0")
        XCTAssertEqual(plan.target.triple, "arm64-apple-ios15.0")
        XCTAssertTrue(plan.invocations[0].arguments.contains("-miphoneos-version-min=15.0"))
    }

    func testLinkerExecutableIsFirstArgvElement() throws {
        let plan = try BuildPlanner.plan(workspace: .sample(language: .c))
        let linker = try XCTUnwrap(plan.invocations.last)
        XCTAssertEqual(linker.argv.first, "ld64.lld")
        XCTAssertTrue(linker.arguments.contains("-syslibroot"))
        XCTAssertTrue(linker.arguments.contains("<iPhoneOS SDK>"))
        XCTAssertTrue(linker.arguments.contains("-lSystem"))
        XCTAssertEqual(linker.arguments[linker.arguments.firstIndex(of: "-platform_version")! + 3], "18.5")
    }

    func testUnavailableBackendThrowsToolchainError() async {
        do {
            _ = try await UnavailableNativeBackend().build(workspace: .sample(language: .swift))
            XCTFail("Expected missing toolchain error")
        } catch {
            XCTAssertEqual(error as? CompilerBackendError, .toolchainNotInstalled)
        }
    }

    func testRejectsMixedLanguages() {
        let workspace = Workspace(name: "x", files: [SourceFile(name: "a.c", contents: "", language: .c), SourceFile(name: "b.swift", contents: "", language: .swift)])
        XCTAssertThrowsError(try BuildPlanner.plan(workspace: workspace)) { XCTAssertEqual($0 as? BuildPlanningError, .mixedLanguagesUnsupported) }
    }

    func testRejectsWrongExtension() {
        let workspace = Workspace(name: "x", files: [SourceFile(name: "main.txt", contents: "", language: .c)])
        XCTAssertThrowsError(try BuildPlanner.plan(workspace: workspace)) { XCTAssertEqual($0 as? BuildPlanningError, .wrongExtension(file: "main.txt", expected: ".c")) }
    }

    func testRejectsNoSources() {
        XCTAssertThrowsError(try BuildPlanner.plan(workspace: Workspace(name: "empty"))) { XCTAssertEqual($0 as? BuildPlanningError, .noSources) }
    }

    func testStoreRejectsUnsafeSaveName() {
        let store = WorkspaceStore(directoryURL: FileManager.default.temporaryDirectory)
        XCTAssertThrowsError(try store.save(Workspace(name: "../oops"))) { XCTAssertEqual($0 as? WorkspaceStoreError, .unsafeWorkspaceName) }
    }

    func testStoreRejectsControlCharactersInName() {
        let store = WorkspaceStore(directoryURL: FileManager.default.temporaryDirectory)
        XCTAssertThrowsError(try store.save(Workspace(name: "bad\nname"))) { XCTAssertEqual($0 as? WorkspaceStoreError, .unsafeWorkspaceName) }
    }
}
