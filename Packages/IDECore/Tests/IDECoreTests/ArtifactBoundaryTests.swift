import Foundation
import XCTest
@testable import IDECore

final class ArtifactBoundaryTests: XCTestCase {
    private var root: URL!
    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    }
    override func tearDownWithError() throws { try FileManager.default.removeItem(at: root) }

    private func words(_ words: [UInt32]) -> Data {
        var data = Data()
        for word in words { data.append(contentsOf: (0..<4).map { UInt8((word >> (8 * $0)) & 255) }) }
        return data
    }
    private func artifact(_ commands: [UInt32] = [0x32, 24, 2, 0xf0000, 0x120500, 0], count: UInt32 = 1) -> Data {
        words([0xfeedfacf, 0x100000c, 0, 2, count, UInt32(commands.count * 4), 0, 0] + commands)
    }
    private func check(_ data: Data, valid: Bool = false) throws {
        let url = root.appendingPathComponent("a.out")
        try data.write(to: url)
        if valid { XCTAssertNoThrow(try NativeCBackend.validateMachO(at: url, fileType: 2)) }
        else { XCTAssertThrowsError(try NativeCBackend.validateMachO(at: url, fileType: 2)) }
    }
    func testValidModernAndLegacyIOS15Commands() throws {
        try check(artifact(), valid: true)
        try check(artifact([0x25, 16, 0xf0000, 0x120500]), valid: true)
    }
    func testRejectsTruncatedOversizedMisalignedAndCountMismatchedCommands() throws {
        var truncated = artifact(); truncated.removeLast(); try check(truncated)
        try check(artifact([0x32, 0xfffffff8, 2, 0xf0000, 0, 0]))
        try check(artifact([0x32, 20, 2, 0xf0000, 0, 0]))
        try check(artifact(count: 2))
        try check(artifact([0x32, 24, 2, 0xf0000, 0, 0, 0, 0]))
        try check(artifact([0x32, 24, 2, 0xf0000, 0, 1]))
        try check(artifact([], count: 0))
    }
    func testRejectsSimulatorWrongMinimumDuplicateTargetAndSignatures() throws {
        try check(artifact([0x32, 24, 7, 0xf0000, 0, 0]))
        try check(artifact([0x32, 24, 2, 0x100000, 0, 0]))
        try check(artifact([0x32, 24, 2, 0xe0000, 0, 0]))
        let target: [UInt32] = [0x32, 24, 2, 0xf0000, 0, 0]
        try check(artifact(target + target, count: 2))
        try check(artifact(target + [0x1d, 16, 0, 0], count: 2))
        var arm64e = artifact(); arm64e[8] = 2; try check(arm64e)
    }
    func testRejectsSegmentAndSymbolTableOutsideFile() throws {
        let target: [UInt32] = [0x32, 24, 2, 0xf0000, 0, 0]
        try check(artifact(target + [0x19, 72] + Array(repeating: 0, count: 14) + [1, 0], count: 2))
        try check(artifact(target + [2, 24, 0xfffffff0, 8, 0, 0], count: 2))
        var segment: [UInt32] = [0x19, 72] + Array(repeating: 0, count: 16)
        segment[12] = 0xfffffff0
        try check(artifact(target + segment, count: 2))
    }
    func testRejectsMachOSymlinkAndCanonicalEscape() throws {
        let outside = root.appendingPathComponent("outside")
        try artifact().write(to: outside)
        let directory = root.appendingPathComponent("build")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let link = directory.appendingPathComponent("linked")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: outside)
        XCTAssertThrowsError(try NativeCBackend.validateMachO(at: link, fileType: 2))
        XCTAssertThrowsError(try BuildRetention.checkChild(link, of: directory))
        XCTAssertThrowsError(try BuildRetention.checkChild(directory.appendingPathComponent("../outside"), of: directory))
        XCTAssertThrowsError(try BuildRetention.checkChild(root.appendingPathComponent("build-sibling/a"), of: directory))
        XCTAssertNoThrow(try BuildRetention.checkChild(directory.appendingPathComponent("safe.o"), of: directory))
    }
    func testLogLimitIsUTF8SafeAndHasMarker() {
        let bounded = BuildRetention.boundedLog(String(repeating: "診斷", count: 100_000))
        XCTAssertLessThanOrEqual(bounded.utf8.count, BuildRetention.maximumLogBytes)
        XCTAssertTrue(bounded.contains("[build log truncated]\n"))
        XCTAssertFalse(bounded.contains("�"))
        XCTAssertEqual(BuildRetention.boundedLog("small"), "small")
    }
    func testRetentionKeepsNewestTenAndDoesNotFollowOrDeleteForeignFiles() throws {
        let fm = FileManager.default
        var directories = [URL]()
        for index in 0..<12 {
            let dir = root.appendingPathComponent(UUID().uuidString)
            try fm.createDirectory(at: dir, withIntermediateDirectories: true)
            try Data([1]).write(to: dir.appendingPathComponent("artifact"))
            try fm.setAttributes([.modificationDate: Date(timeIntervalSince1970: Double(index))], ofItemAtPath: dir.path)
            directories.append(dir)
        }
        let foreign = root.appendingPathComponent("notes.txt"); try Data([1]).write(to: foreign)
        let link = root.appendingPathComponent(UUID().uuidString)
        try fm.createSymbolicLink(at: link, withDestinationURL: directories.last!)
        try BuildRetention.prune(root, keeping: directories.last!)
        XCTAssertFalse(fm.fileExists(atPath: directories[0].path))
        XCTAssertFalse(fm.fileExists(atPath: directories[1].path))
        XCTAssertTrue(fm.fileExists(atPath: directories[2].path))
        XCTAssertTrue(fm.fileExists(atPath: foreign.path))
        XCTAssertTrue(fm.fileExists(atPath: link.path))
    }
    func testRetentionByteLimitAndOversizedCurrentBuild() throws {
        let fm = FileManager.default
        let old = root.appendingPathComponent(UUID().uuidString)
        let current = root.appendingPathComponent(UUID().uuidString)
        for dir in [old, current] { try fm.createDirectory(at: dir, withIntermediateDirectories: true) }
        func sparse(_ url: URL, _ size: UInt64) throws {
            XCTAssertTrue(fm.createFile(atPath: url.path, contents: nil))
            let handle = try FileHandle(forWritingTo: url); defer { try? handle.close() }
            try handle.truncate(atOffset: size)
        }
        try sparse(old.appendingPathComponent("a"), BuildRetention.maximumBytes)
        try Data([1]).write(to: current.appendingPathComponent("a"))
        try BuildRetention.prune(root, keeping: current)
        XCTAssertFalse(fm.fileExists(atPath: old.path))
        try sparse(current.appendingPathComponent("huge"), BuildRetention.maximumBytes + 1)
        XCTAssertThrowsError(try BuildRetention.prune(root, keeping: current))
    }
    func testOutputRootRejectsSymlinkAndResourceOverlap() throws {
        let sdk = root.appendingPathComponent("SDK"), resource = root.appendingPathComponent("clang")
        let link = root.appendingPathComponent("Builds")
        try FileManager.default.createDirectory(at: sdk, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: sdk)
        func config(_ builds: URL) -> NativeCConfiguration {
            NativeCConfiguration(sdkURL: sdk, resourceURL: resource, buildsURL: builds, sdkVersion: "18.5")
        }
        XCTAssertThrowsError(try BuildRetention.prepare(config(link)))
        XCTAssertThrowsError(try BuildRetention.prepare(config(sdk.appendingPathComponent("builds"))))
        XCTAssertThrowsError(try BuildRetention.prepare(config(root)))
    }
}
