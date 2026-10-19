import Foundation
import XCTest
@testable import IDECore

final class ToolchainPreflightTests: XCTestCase {
    private var root: URL!
    private var config: NativeCConfiguration!
    private var manifest: URL!
    private var settings: URL!
    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let sdk = root.appendingPathComponent("Toolchain/iPhoneOS.sdk")
        let resource = root.appendingPathComponent("Toolchain/clang/18/include")
        for url in [sdk.appendingPathComponent("usr/include/stdio.h"), sdk.appendingPathComponent("usr/lib/libSystem.tbd"), resource.appendingPathComponent("stddef.h")] {
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try Data().write(to: url)
        }
        settings = sdk.appendingPathComponent("SDKSettings.plist")
        manifest = root.appendingPathComponent("Toolchain/manifest.txt")
        config = NativeCConfiguration(sdkURL: sdk, resourceURL: resource.deletingLastPathComponent(), buildsURL: root.appendingPathComponent("Builds"), sdkVersion: "18.5")
    }
    override func tearDownWithError() throws { try FileManager.default.removeItem(at: root) }
    private func writeSettings(version: String = "18.5", name: String = "iphoneos", archs: [String] = ["arm64"], min: String = "12.0", max: String = "20.0", platform: String = "iphoneos") throws {
        let dict: [String: Any] = ["Version": version, "CanonicalName": name, "SupportedTargets": ["iphoneos": ["Archs": archs, "MinimumDeploymentTarget": min, "MaximumDeploymentTarget": max]], "DefaultProperties": ["PLATFORM_NAME": platform]]
        try PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0).write(to: settings)
    }
    private func writeManifest(_ text: String) throws { try text.write(to: manifest, atomically: true, encoding: .utf8) }
    func testValidEvidenceAndHeaderVersionUsesManifestNotComments() throws {
        try writeSettings()
        try Data("/* 18.1.8 */".utf8).write(to: config.resourceURL.appendingPathComponent("include/stddef.h"))
        try writeManifest("LLVM_VERSION=18.1.8\nBUILTIN_HEADERS_VERSION=18.1.8\nTARGET=arm64-apple-ios15.0\nIOS_SDK=18.4\n")
        let result = try config.preflight().joined(separator: "\n")
        XCTAssertTrue(result.contains("Verified: manifest LLVM and builtin-header versions match"))
        XCTAssertTrue(result.contains("Unverified: toolchain SDK 18.4 differs"))
        XCTAssertFalse(result.contains("18.1.8 */"))
    }
    func testMissingSettingsAndManifestAreUnverified() throws {
        let result = try config.preflight().joined(separator: "\n")
        XCTAssertTrue(result.contains("SDKSettings.plist is absent"))
        XCTAssertTrue(result.contains("manifest not found"))
    }
    func testSDKSettingsRejectMalformedWrongPlatformAndInsufficientTarget() throws {
        try Data("not plist".utf8).write(to: settings)
        XCTAssertThrowsError(try config.preflight())
        try writeSettings(name: "iphonesimulator"); XCTAssertThrowsError(try config.preflight())
        try writeSettings(archs: ["arm64e"]); XCTAssertThrowsError(try config.preflight())
        try writeSettings(min: "16.0"); XCTAssertThrowsError(try config.preflight())
        try writeSettings(max: "14.0"); XCTAssertThrowsError(try config.preflight())
        try writeSettings(platform: "macosx"); XCTAssertThrowsError(try config.preflight())
        try writeSettings(version: "14.0"); XCTAssertThrowsError(try config.preflight())
    }
    func testDuplicateMalformedManifestAndVersionConflictReject() throws {
        try writeSettings()
        try writeManifest("LLVM_VERSION=18.1.8\nLLVM_VERSION=18.1.8\n"); XCTAssertThrowsError(try config.preflight())
        try writeManifest("LLVM_VERSION=18.1.8\nBUILTIN_HEADERS_VERSION=18.1.9\n"); XCTAssertThrowsError(try config.preflight())
    }
    func testTbdRecognizedDeviceAndKnownBadTargets() throws {
        try writeSettings()
        try Data("targets: [ arm64-ios ]\n".utf8).write(to: config.sdkURL.appendingPathComponent("usr/lib/libSystem.tbd"))
        XCTAssertTrue(try config.preflight().joined().contains("arm64-ios device support"))
        try Data("targets: [ arm64-ios-simulator ]\n".utf8).write(to: config.sdkURL.appendingPathComponent("usr/lib/libSystem.tbd"))
        XCTAssertThrowsError(try config.preflight())
        try Data("unknown format\n".utf8).write(to: config.sdkURL.appendingPathComponent("usr/lib/libSystem.tbd"))
        XCTAssertTrue(try config.preflight().joined().contains("not recognized"))
    }
    func testMultiSliceSDKAndVersionedCanonicalNameRemainSupported() throws {
        try writeSettings(name: "iphoneos18.5", archs: ["arm64", "arm64e"])
        let tbd = config.sdkURL.appendingPathComponent("usr/lib/libSystem.tbd")
        try "targets: [ arm64-ios, arm64e-ios, arm64-ios-simulator ]\n".write(to: tbd, atomically: true, encoding: .utf8)
        XCTAssertNoThrow(try config.preflight())
        try "archs: [ arm64, arm64e ]\nplatform: ios\n".write(to: tbd, atomically: true, encoding: .utf8)
        XCTAssertNoThrow(try config.preflight())
        try "targets: [ arm64e-ios ]\n".write(to: tbd, atomically: true, encoding: .utf8)
        XCTAssertThrowsError(try config.preflight())
    }

    func testMissingDeploymentMetadataIsNotReportedAsVerified() throws {
        let dict: [String: Any] = ["Version": "18.5", "CanonicalName": "iphoneos"]
        try PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0).write(to: settings)
        let result = try config.preflight().joined(separator: "\n")
        XCTAssertTrue(result.contains("Unverified: SDK iphoneos SupportedTargets"))
        try writeSettings(min: "unknown")
        XCTAssertThrowsError(try config.preflight())
        try writeSettings(name: "iphoneos17.0")
        XCTAssertThrowsError(try config.preflight())
    }

    func testKnownVersionTargetAndResourceMajorConflictsReject() throws {
        for text in ["LLVM_VERSION=bad\n", "TARGET=arm64-apple-ios16.0\n", "LLVM_VERSION=17.0.0\n", "IOS_SDK=14.0\n"] {
            try writeManifest(text)
            XCTAssertThrowsError(try config.preflight())
        }
        let old = NativeCConfiguration(sdkURL: config.sdkURL, resourceURL: config.resourceURL, buildsURL: config.buildsURL, sdkVersion: "14.0")
        XCTAssertThrowsError(try old.preflight())
    }

}
