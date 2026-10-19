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
        case .invalidConfiguration(let reason): return "Invalid native toolchain configuration: \(DiagnosticRedactor.redact(reason))"
        case .missingResource(let path): return "Required SDK or Clang resource is missing: \(DiagnosticRedactor.redact(path))"
        case .workspaceTooLarge: return "This initial backend accepts at most 32 files and 2 MiB of source."
        case .invocationFailed(let tool, let diagnostics): return "\(tool) failed:\n\(DiagnosticRedactor.redact(diagnostics))"
        case .invalidArtifact(let path): return "Compiler did not produce the expected arm64 Mach-O artifact: \(DiagnosticRedactor.redact(path))"
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
        // Retention and compilation share a process-wide critical section: another
        // backend instance must not prune an in-flight UUID directory.
        try BuildRetention.serialized { try buildSynchronously(workspace: workspace) }
    }

    private func buildSynchronously(workspace: Workspace) throws -> BuildResult {
        // Validate editable filenames before creating any output or invoking native code.
        _ = try BuildPlanner.plan(workspace: workspace)
        guard workspace.files.allSatisfy({ $0.language == .c }) else { throw NativeCError.swiftNotSupported }
        guard workspace.files.count <= 32,
              workspace.files.reduce(0, { $0 + $1.contents.utf8.count }) <= 2 * 1024 * 1024 else {
            throw NativeCError.workspaceTooLarge
        }
        guard invoker.isAvailable else { throw CompilerBackendError.toolchainNotInstalled }
        let preflight = try configuration.preflight()
        try Task.checkCancellation()

        let fm = FileManager.default
        try BuildRetention.prepare(configuration)
        let root = configuration.buildsURL.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try fm.createDirectory(at: root, withIntermediateDirectories: true)
        try BuildRetention.checkChild(root, of: configuration.buildsURL)
        var succeeded = false
        defer { if !succeeded { try? fm.removeItem(at: root) } }
        let redactor = DiagnosticRedactor(buildRoot: root, sdkRoot: configuration.sdkURL, resourceRoot: configuration.resourceURL)
        let parser = CBuildDiagnosticParser(buildRoot: root, files: workspace.files, redactor: redactor)
        var diagnostics = [BuildDiagnostic]()
        var log = BuildRetention.boundedLog(redactor.redact("In-process C build · arm64 · iOS 15.0\n" + preflight.joined(separator: "\n")))
        func appendLog(_ text: String) { log = BuildRetention.boundedLog(log + "\n" + BuildRetention.boundedLog(redactor.redact(text))) }
        func record(_ result: NativeInvocationResult, phase: BuildPhase) {
            let parsed = parser.parse(result.diagnostics, phase: phase, failed: result.exitCode != 0)
            diagnostics.append(contentsOf: parsed.prefix(max(0, CBuildDiagnosticParser.maximumDiagnostics - diagnostics.count)))
            // Even a full warning list must retain the later failure's phase/error.
            if result.exitCode != 0, let error = parsed.last(where: { $0.severity == .error || $0.severity == .fatal }),
               !diagnostics.contains(where: { $0.id == error.id }) {
                if diagnostics.count == CBuildDiagnosticParser.maximumDiagnostics { diagnostics.removeLast() }
                diagnostics.append(error)
            }
        }
        var objects = [URL]()
        for file in workspace.files {
            try Task.checkCancellation()
            let source = root.appendingPathComponent(file.name)
            let object = root.appendingPathComponent((file.name as NSString).deletingPathExtension + ".o")
            try BuildRetention.checkChild(source, of: root)
            try BuildRetention.checkChild(object, of: root)
            try file.contents.write(to: source, atomically: true, encoding: .utf8)
            let args = ["clang", "-target", "arm64-apple-ios15.0", "-isysroot", configuration.sdkURL.path,
                        "-resource-dir", configuration.resourceURL.path, "-miphoneos-version-min=15.0",
                        "-std=c17", "-fno-modules", "-fno-color-diagnostics", "-c", source.path, "-o", object.path]
            let result = invoker.invoke(.clang, arguments: args)
            appendLog("Compile \(file.name)\n\(result.diagnostics)")
            record(result, phase: .compile)
            guard result.exitCode == 0 else {
                throw NativeBuildFailure(tool: "Clang (\(file.name))", output: log, diagnostics: diagnostics)
            }
            try BuildRetention.checkChild(root, of: configuration.buildsURL)
            try BuildRetention.checkCurrentSize(root)
            try BuildRetention.checkChild(object, of: root)
            try Self.validateMachO(at: object, fileType: 1)
            objects.append(object)
        }
        try Task.checkCancellation()
        let executable = root.appendingPathComponent("PocketIDE.out")
        try BuildRetention.checkChild(executable, of: root)
        let args = ["ld64.lld", "-arch", "arm64", "-syslibroot", configuration.sdkURL.path,
                    "-platform_version", "ios", "15.0", configuration.sdkVersion,
                    "-no_adhoc_codesign", "-o", executable.path] + objects.map(\.path) + ["-lSystem"]
        let linked = invoker.invoke(.linker, arguments: args)
        appendLog("Link PocketIDE.out\n\(linked.diagnostics)")
        record(linked, phase: .link)
        guard linked.exitCode == 0 else {
            throw NativeBuildFailure(tool: "LLD", output: log, diagnostics: diagnostics)
        }
        try BuildRetention.checkChild(root, of: configuration.buildsURL)
        try BuildRetention.checkCurrentSize(root)
        try BuildRetention.checkChild(executable, of: root)
        try Self.validateMachO(at: executable, fileType: 2)
        appendLog("Produced unsigned Mach-O: \(executable.path)\nNot signed, installed, or executed.")
        let output = log
        let logURL = root.appendingPathComponent("build.log")
        try BuildRetention.checkChild(logURL, of: root)
        try output.write(to: logURL, atomically: true, encoding: .utf8)
        try BuildRetention.prune(configuration.buildsURL, keeping: root)
        succeeded = true
        return BuildResult(output: output, artifactURL: executable, diagnostics: diagnostics)
    }

}
