import Foundation

public extension NativeCConfiguration {
    /// Validates installed resources and reports only compatibility supported by explicit evidence.
    func preflight() throws -> [String] {
        try validate()
        guard let configured = Self.numeric(sdkVersion), Self.atLeast(configured, [15]) else {
            throw Self.invalid("Configured SDK must be iOS 15 or newer")
        }
        var messages = ["Verified: required SDK and Clang resource headers are readable."]
        try checkSDKSettings(messages: &messages)
        try checkLibSystem(messages: &messages)
        let fm = FileManager.default
        let candidates = [resourceURL.deletingLastPathComponent().appendingPathComponent("manifest.txt"),
                          resourceURL.deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("manifest.txt")]
        let found = candidates.filter { fm.fileExists(atPath: $0.path) }
        guard !found.isEmpty else {
            return messages + ["Unverified: toolchain manifest not found; LLVM/header version and toolchain-to-SDK pairing are unknown."]
        }
        let manifests = try found.map { try Self.parseManifest(String(contentsOf: $0, encoding: .utf8)) }
        var values = [String: String]()
        for manifest in manifests {
            for (key, value) in manifest {
                if let previous = values[key], previous != value { throw Self.invalid("Multiple manifests contain conflicting values for \(key)") }
                values[key] = value
            }
        }
        let llvm = values["LLVM_VERSION"]
        let builtin = values["BUILTIN_HEADERS_VERSION"]
        for version in [llvm, builtin].compactMap({ $0 }) {
            guard Self.numeric(version) != nil else { throw Self.invalid("Manifest LLVM/header version must be numeric") }
        }
        if let llvm, let builtin {
            guard let llvmVersion = Self.numeric(llvm), let headerVersion = Self.numeric(builtin),
                  Self.compare(llvmVersion, headerVersion) == 0 else {
                throw Self.invalid("BUILTIN_HEADERS_VERSION must numerically equal LLVM_VERSION")
            }
            messages.append("Verified: manifest LLVM and builtin-header versions match (\(llvm)).")
        } else { messages.append("Unverified: LLVM_VERSION or BUILTIN_HEADERS_VERSION is absent; header/toolchain version match is unknown.") }
        if let target = values["TARGET"] {
            guard target == "arm64-apple-ios15.0" else { throw Self.invalid("Toolchain manifest target conflicts with required arm64 iOS 15.0") }
            messages.append("Verified: manifest target is arm64 iOS 15.0.")
        } else { messages.append("Unverified: manifest does not declare TARGET.") }
        if let sdk = values["IOS_SDK"] {
            guard let v = Self.numeric(sdk), Self.atLeast(v, [15]) else { throw Self.invalid("Manifest IOS_SDK is not a numeric iOS 15-or-newer version") }
            if sdk == sdkVersion { messages.append("Verified: toolchain was built with configured SDK version \(sdkVersion).") }
            else { messages.append("Unverified: toolchain SDK \(sdk) differs from configured SDK \(sdkVersion); both must be iOS 15 or newer.") }
        } else { messages.append("Unverified: manifest does not declare IOS_SDK.") }
        let major = resourceURL.lastPathComponent
        if let llvm, let m = Self.numeric(llvm), let majorVersion = UInt32(major), m.first == majorVersion {
            messages.append("Verified: Clang resource directory major \(majorVersion) matches LLVM_VERSION.")
        } else if let llvm, let m = Self.numeric(llvm), let majorVersion = UInt32(major), m.first != majorVersion {
            throw Self.invalid("Clang resource directory major conflicts with LLVM_VERSION")
        } else { messages.append("Unverified: Clang resource directory major does not establish a match with LLVM_VERSION.") }
        messages.append("Unverified: metadata declarations do not authenticate the linked LLVM binary or complete SDK/header contents.")
        return messages
    }

    private func checkSDKSettings(messages: inout [String]) throws {
        let url = sdkURL.appendingPathComponent("SDKSettings.plist")
        guard FileManager.default.fileExists(atPath: url.path) else { messages.append("Unverified: SDKSettings.plist is absent."); return }
        let data = try Data(contentsOf: url)
        guard let root = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              let version = root["Version"] as? String, let v = Self.numeric(version),
              let canonical = root["CanonicalName"] as? String else { throw Self.invalid("SDKSettings.plist is malformed or lacks required fields") }
        guard Self.atLeast(v, [15]), let configured = Self.numeric(sdkVersion), Self.atLeast(configured, [15]), Self.compare(v, configured) == 0 else { throw Self.invalid("SDKSettings Version must numerically match configured iOS 15-or-newer SDK version") }
        let suffix = canonical.hasPrefix("iphoneos") ? String(canonical.dropFirst(8)) : "invalid"
        guard suffix.isEmpty || (Self.numeric(suffix).map { Self.compare($0, v) == 0 } ?? false) else {
            throw Self.invalid("Expected CanonicalName iphoneos[version], not simulator or macOS")
        }
        if let raw = root["SupportedTargets"] {
            guard let targets = raw as? [String: Any], targets["iphoneos"] is [String: Any] else {
                throw Self.invalid("SDK SupportedTargets does not identify an iPhoneOS device target")
            }
        }
        if let targets = root["SupportedTargets"] as? [String: Any], let ios = targets["iphoneos"] as? [String: Any] {
            if let raw = ios["Archs"] {
                guard let archs = raw as? [String], archs.contains("arm64") else { throw Self.invalid("SDK iphoneos SupportedTargets lacks arm64") }
                messages.append("Verified: SDK SupportedTargets includes arm64.")
            } else { messages.append("Unverified: SDK SupportedTargets Archs is absent.") }
            for (key, minimum) in [("MinimumDeploymentTarget", true), ("MaximumDeploymentTarget", false)] {
                if let raw = ios[key] {
                    guard let text = raw as? String, let version = Self.numeric(text) else { throw Self.invalid("Malformed SDK deployment range") }
                    let relation = Self.compare(version, [15])
                    guard minimum ? relation <= 0 : relation >= 0 else { throw Self.invalid("SDK deployment range excludes iOS 15") }
                    messages.append("Verified: SDK \(key) permits iOS 15.")
                } else { messages.append("Unverified: SDK \(key) is absent.") }
            }
        } else { messages.append("Unverified: SDK iphoneos SupportedTargets architecture/deployment metadata is absent.") }
        if let props = root["DefaultProperties"] as? [String: Any], let platform = props["PLATFORM_NAME"] as? String, platform != "iphoneos" { throw Self.invalid("SDK PLATFORM_NAME is not iphoneos") }
        messages.append("Verified: SDKSettings identifies the configured iPhoneOS SDK version.")
    }

    private func checkLibSystem(messages: inout [String]) throws {
        let url = sdkURL.appendingPathComponent("usr/lib/libSystem.tbd")
        let text = (try? String(contentsOf: url, encoding: .utf8)) ?? ""
        func lists(_ key: String) -> [String] {
            let pattern = "(?m)\\b" + key + "\\s*:\\s*\\[([^\\]]*)\\]"
            guard let regex = try? NSRegularExpression(pattern: pattern) else { return [] }
            return regex.matches(in: text, range: NSRange(text.startIndex..., in: text)).flatMap { match -> [String] in
                guard let range = Range(match.range(at: 1), in: text) else { return [] }
                return text[range].split(separator: ",").map { $0.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines.union(CharacterSet(charactersIn: "\"'"))) }
            }
        }
        let targets = lists("targets")
        if !targets.isEmpty {
            guard targets.contains("arm64-ios") else { throw Self.invalid("libSystem.tbd targets do not include arm64-ios device support") }
            messages.append("Verified: libSystem.tbd declares arm64-ios device support (other slices allowed).")
            return
        }
        let archs = lists("archs")
        if !archs.isEmpty {
            guard archs.contains("arm64") else { throw Self.invalid("libSystem.tbd architectures do not include arm64") }
            let regex = try NSRegularExpression(pattern: "(?m)^\\s*platform\\s*:\\s*['\"]?(ios|macosx|iossimulator|tvos|watchos|2)\\b")
            if let match = regex.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)), let range = Range(match.range(at: 1), in: text) {
                guard ["ios", "2"].contains(String(text[range])) else { throw Self.invalid("libSystem.tbd legacy platform is not iPhoneOS") }
                messages.append("Verified: libSystem.tbd legacy fields declare arm64 iOS support.")
                return
            }
        }
        messages.append("Unverified: libSystem.tbd target fields are not recognized.")
    }

    private static func parseManifest(_ text: String) throws -> [String: String] {
        var result = [String: String]()
        for (i, lineSub) in text.split(whereSeparator: \.isNewline).enumerated() {
            let line = String(lineSub).trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty, !line.hasPrefix("#"), !line.hasPrefix("LIBRARIES:") else { continue }
            guard let eq = line.firstIndex(of: "=") else { continue }
            let key = String(line[..<eq]).trimmingCharacters(in: .whitespaces)
            let value = String(line[line.index(after: eq)...]).trimmingCharacters(in: .whitespaces)
            guard !key.isEmpty, !value.isEmpty else { throw invalid("Malformed manifest line \(i + 1)") }
            if let previous = result[key] { guard previous == value else { throw invalid("Conflicting duplicate manifest key \(key)") }; throw invalid("Duplicate manifest key \(key)") }
            result[key] = value
        }
        return result
    }
    private static func numeric(_ s: String) -> [UInt32]? {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        guard (1...3).contains(parts.count), parts.allSatisfy({ !$0.isEmpty && $0.allSatisfy(\.isNumber) }), let values = Optional(parts.compactMap { UInt32($0) }), values.count == parts.count else { return nil }
        return values
    }
    private static func compare(_ a: [UInt32], _ b: [UInt32]) -> Int {
        for i in 0..<max(a.count, b.count) { let x = i < a.count ? a[i] : 0, y = i < b.count ? b[i] : 0; if x != y { return x < y ? -1 : 1 } }; return 0
    }
    private static func atLeast(_ a: [UInt32], _ b: [UInt32]) -> Bool { compare(a, b) >= 0 }
    private static func invalid(_ message: String) -> NativeCError { .invalidConfiguration(message) }
}
