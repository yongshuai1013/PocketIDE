import Foundation
import IDECore

struct EmbeddedCInvoker: NativeCInvoker {
    var isAvailable: Bool {
        let capabilities = ncb_get_capabilities()
        let required = UInt32(NCB_CAP_COMPILE | NCB_CAP_LINK | NCB_CAP_EMBEDDED_LLVM)
        return capabilities.abi_version == NCB_ABI_VERSION && (capabilities.flags & required) == required
    }

    func invoke(_ tool: NativeTool, arguments: [String]) -> NativeInvocationResult {
        guard arguments.count <= Int(Int32.max), arguments.allSatisfy({ !$0.contains("\0") }) else {
            return NativeInvocationResult(exitCode: 1, diagnostics: "Invalid compiler argument vector")
        }
        let strings = arguments.map { strdup($0) }
        defer { strings.forEach { free($0) } }
        guard strings.allSatisfy({ $0 != nil }) else {
            return NativeInvocationResult(exitCode: 1, diagnostics: "Could not allocate compiler arguments")
        }
        let pointers: [UnsafePointer<CChar>?] = strings.map { $0.map { UnsafePointer($0) } }
        var result = pointers.withUnsafeBufferPointer { buffer in
            tool == .clang
                ? ncb_compile_driver_argv(Int32(buffer.count), buffer.baseAddress)
                : ncb_link_lld_argv(Int32(buffer.count), buffer.baseAddress)
        }
        defer { ncb_dispose_diagnostics(&result.diagnostics) }
        let text: String
        if let bytes = result.diagnostics.text {
            text = String(decoding: UnsafeBufferPointer(start: UnsafeRawPointer(bytes).assumingMemoryBound(to: UInt8.self),
                                                       count: Int(result.diagnostics.length)), as: UTF8.self)
        } else { text = "" }
        return NativeInvocationResult(exitCode: result.status, diagnostics: text)
    }
}

/// Resources must be installed locally. No SDK download, upload or redistribution.
enum EmbeddedCSetup {
    static var status: String {
        guard EmbeddedCInvoker().isAvailable else { return "Embedded Clang/LLD not linked (stub build)" }
        do {
            let evidence = try configuration().preflight()
            let unknown = evidence.filter { $0.hasPrefix("Unverified:") }.count
            return "C preflight · iOS 15 arm64 · \(unknown) unverified checks"
        } catch { return error.localizedDescription }
    }

    static func configuration() throws -> NativeCConfiguration {
        guard let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first else {
            throw NativeCError.invalidConfiguration("Documents directory is unavailable")
        }
        let base = documents.appendingPathComponent("PocketIDE", isDirectory: true)
        let sdk = base.appendingPathComponent("Toolchain/iPhoneOS.sdk", isDirectory: true)
        let settings = sdk.appendingPathComponent("SDKSettings.plist")
        guard let data = try? Data(contentsOf: settings),
              let dictionary = (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: Any],
              let version = dictionary["Version"] as? String else {
            throw NativeCError.missingResource(settings.path)
        }
        guard let name = dictionary["CanonicalName"] as? String, name.hasPrefix("iphoneos") else {
            throw NativeCError.invalidConfiguration("Expected an iPhoneOS device SDK, not a simulator or macOS SDK")
        }
        return NativeCConfiguration(sdkURL: sdk,
            resourceURL: Bundle.main.bundleURL.appendingPathComponent("Toolchain/clang", isDirectory: true),
            buildsURL: base.appendingPathComponent("Builds", isDirectory: true), sdkVersion: version)
    }

    static func backend() throws -> NativeCBackend {
        guard EmbeddedCInvoker().isAvailable else { throw CompilerBackendError.toolchainNotInstalled }
        return NativeCBackend(configuration: try configuration(), invoker: EmbeddedCInvoker())
    }
}
