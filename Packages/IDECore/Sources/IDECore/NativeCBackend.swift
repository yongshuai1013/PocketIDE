import Foundation

/// No shell or subprocess is involved. Implementations call the embedded libraries.
public enum NativeTool: Equatable { case clang, linker }

public struct NativeInvocationResult {
    public let exitCode: Int32
    public let diagnostics: String
    public init(exitCode: Int32, diagnostics: String = "") {
        self.exitCode = exitCode
        self.diagnostics = diagnostics
    }
}

public protocol NativeCInvoker {
    var isAvailable: Bool { get }
    func invoke(_ tool: NativeTool, arguments: [String]) -> NativeInvocationResult
}

public struct NativeCConfiguration {
    public let sdkURL: URL
    public let resourceURL: URL
    public let buildsURL: URL
    public let sdkVersion: String

    public init(sdkURL: URL, resourceURL: URL, buildsURL: URL, sdkVersion: String) {
        self.sdkURL = sdkURL
        self.resourceURL = resourceURL
        self.buildsURL = buildsURL
        self.sdkVersion = sdkVersion
    }

    public func validate() throws {
        for url in [sdkURL, resourceURL, buildsURL] {
            guard url.isFileURL, url.path.hasPrefix("/"), !url.path.contains("\0") else {
                throw NativeCError.invalidConfiguration("Paths must be absolute file URLs")
            }
        }
        let components = sdkVersion.split(separator: ".", omittingEmptySubsequences: false)
        guard (2...3).contains(components.count), components.allSatisfy({ !$0.isEmpty && $0.allSatisfy({ $0.isASCII && $0.isNumber }) && UInt16($0) != nil }) else {
            throw NativeCError.invalidConfiguration("SDK version must be numeric, for example 18.5")
        }
        for url in [sdkURL.appendingPathComponent("usr/include/stdio.h"),
                    sdkURL.appendingPathComponent("usr/lib/libSystem.tbd"),
                    resourceURL.appendingPathComponent("include/stddef.h")] {
            guard FileManager.default.isReadableFile(atPath: url.path) else {
                throw NativeCError.missingResource(url.path)
            }
        }
    }
}

public enum NativeCError: Error, LocalizedError {
    case swiftNotSupported
    case invalidConfiguration(String)
    case missingResource(String)
    case workspaceTooLarge
    case invocationFailed(tool: String, diagnostics: String)
    case invalidArtifact(String)

    public var errorDescription: String? {
        switch self {
        case .swiftNotSupported: return "The Swift frontend is not integrated yet. Choose a C workspace."
        case .invalidConfiguration(let reason): return "Invalid native toolchain configuration: \(reason)"
        case .missingResource(let path): return "Required SDK or Clang resource is missing: \(path)"
        case .workspaceTooLarge: return "This initial backend accepts at most 32 files and 2 MiB of source."
        case .invocationFailed(let tool, let diagnostics): return "\(tool) failed:\n\(diagnostics)"
        case .invalidArtifact(let path): return "Compiler did not produce the expected arm64 Mach-O artifact: \(path)"
        }
    }
}

/// Actor isolation keeps the blocking compiler away from the UI's main actor.
/// The native bridge must additionally serialize all callers process-wide.
public actor NativeCBackend: CompilerBackend {
    private let invoker: NativeCInvoker
    private let configuration: NativeCConfiguration

    public init(configuration: NativeCConfiguration, invoker: NativeCInvoker) {
        self.configuration = configuration
        self.invoker = invoker
    }

    public func build(workspace: Workspace) async throws -> BuildResult {
        // Validate editable filenames before creating any output or invoking native code.
        _ = try BuildPlanner.plan(workspace: workspace)
        guard workspace.files.allSatisfy({ $0.language == .c }) else { throw NativeCError.swiftNotSupported }
        guard workspace.files.count <= 32,
              workspace.files.reduce(0, { $0 + $1.contents.utf8.count }) <= 2 * 1024 * 1024 else {
            throw NativeCError.workspaceTooLarge
        }
        guard invoker.isAvailable else { throw CompilerBackendError.toolchainNotInstalled }
        try configuration.validate()
        try Task.checkCancellation()

        let fm = FileManager.default
        let root = configuration.buildsURL.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try fm.createDirectory(at: root, withIntermediateDirectories: true)
        var succeeded = false
        defer { if !succeeded { try? fm.removeItem(at: root) } }
        var log = ["In-process C build · arm64 · iOS 15.0"]
        var objects = [URL]()
        for file in workspace.files {
            try Task.checkCancellation()
            let source = root.appendingPathComponent(file.name)
            let object = root.appendingPathComponent((file.name as NSString).deletingPathExtension + ".o")
            try file.contents.write(to: source, atomically: true, encoding: .utf8)
            let args = ["clang", "-target", "arm64-apple-ios15.0", "-isysroot", configuration.sdkURL.path,
                        "-resource-dir", configuration.resourceURL.path, "-miphoneos-version-min=15.0",
                        "-std=c17", "-fno-modules", "-fno-color-diagnostics", "-c", source.path, "-o", object.path]
            let result = invoker.invoke(.clang, arguments: args)
            log.append("Compile \(file.name)\n\(result.diagnostics)")
            guard result.exitCode == 0 else {
                throw NativeCError.invocationFailed(tool: "Clang (\(file.name))", diagnostics: log.joined(separator: "\n"))
            }
            try Self.validateMachO(at: object, fileType: 1)
            objects.append(object)
        }
        try Task.checkCancellation()
        let executable = root.appendingPathComponent("PocketIDE.out")
        let args = ["ld64.lld", "-arch", "arm64", "-syslibroot", configuration.sdkURL.path,
                    "-platform_version", "ios", "15.0", configuration.sdkVersion,
                    "-no_adhoc_codesign", "-o", executable.path] + objects.map(\.path) + ["-lSystem"]
        let linked = invoker.invoke(.linker, arguments: args)
        log.append("Link PocketIDE.out\n\(linked.diagnostics)")
        guard linked.exitCode == 0 else {
            throw NativeCError.invocationFailed(tool: "LLD", diagnostics: log.joined(separator: "\n"))
        }
        try Self.validateMachO(at: executable, fileType: 2)
        log.append("Produced unsigned Mach-O: \(executable.path)\nNot signed, installed, or executed.")
        let output = log.joined(separator: "\n")
        try output.write(to: root.appendingPathComponent("build.log"), atomically: true, encoding: .utf8)
        succeeded = true
        return BuildResult(output: output, artifactURL: executable)
    }

    /// A sanity check, not a substitute for a full Mach-O parser or device validation.
    public static func validateMachO(at url: URL, fileType: UInt32) throws {
        guard let handle = try? FileHandle(forReadingFrom: url) else { throw NativeCError.invalidArtifact(url.path) }
        defer { try? handle.close() }
        let data = try handle.read(upToCount: 32) ?? Data()
        func word(_ index: Int) -> UInt32 {
            let start = index * 4
            return (0..<4).reduce(UInt32(0)) { $0 | (UInt32(data[start + $1]) << (8 * $1)) }
        }
        guard data.count == 32, word(0) == 0xfeedfacf, word(1) == 0x0100000c, word(3) == fileType else {
            throw NativeCError.invalidArtifact(url.path)
        }
    }
}
