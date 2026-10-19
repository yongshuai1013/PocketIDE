import Foundation

public enum SourceLanguage: String, Codable, Equatable, CaseIterable {
    case c
    case swift
}

public struct SourceFile: Codable, Equatable, Identifiable {
    public var id: UUID
    public var name: String
    public var contents: String
    public var language: SourceLanguage

    public init(id: UUID = UUID(), name: String, contents: String, language: SourceLanguage) {
        self.id = id
        self.name = name
        self.contents = contents
        self.language = language
    }
}

public struct Workspace: Codable, Equatable {
    public var name: String
    public var files: [SourceFile]

    public init(name: String, files: [SourceFile] = []) {
        self.name = name
        self.files = files
    }

    public static func sample(language: SourceLanguage) -> Workspace {
        switch language {
        case .c:
            return Workspace(name: "C Sample", files: [SourceFile(name: "main.c", contents: "#include <stdio.h>\nint main(void) { puts(\"Hello, world!\"); return 0; }\n", language: .c)])
        case .swift:
            return Workspace(name: "Swift Sample", files: [SourceFile(name: "main.swift", contents: "print(\"Hello, world!\")\n", language: .swift)])
        }
    }
}

public enum WorkspaceStoreError: Error, Equatable {
    case unsafeWorkspaceName
}

/// JSON-backed workspace persistence. Workspace filenames are derived from a sanitized name.
public struct WorkspaceStore {
    public let directoryURL: URL
    private let fileManager: FileManager

    public init(directoryURL: URL? = nil, fileManager: FileManager = .default) {
        self.fileManager = fileManager
        if let directoryURL = directoryURL {
            self.directoryURL = directoryURL
        } else {
            let documents = fileManager.urls(for: .documentDirectory, in: .userDomainMask).first
                ?? fileManager.temporaryDirectory
            self.directoryURL = documents.appendingPathComponent("PocketIDE", isDirectory: true)
        }
    }

    public func save(_ workspace: Workspace) throws {
        let destination = try fileURL(for: workspace.name)
        try fileManager.createDirectory(at: directoryURL, withIntermediateDirectories: true)
        let data = try JSONEncoder().encode(workspace)
        try data.write(to: destination, options: .atomic)
    }

    public func load(named name: String) throws -> Workspace {
        let url = try fileURL(for: name)
        let data = try Data(contentsOf: url)
        return try JSONDecoder().decode(Workspace.self, from: data)
    }

    private func fileURL(for name: String) throws -> URL {
        guard !name.isEmpty,
              name != ".", name != "..",
              !name.contains("/"), !name.contains("\\"),
              !name.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
              URL(fileURLWithPath: name).lastPathComponent == name else {
            throw WorkspaceStoreError.unsafeWorkspaceName
        }
        return directoryURL.appendingPathComponent(name + ".json", isDirectory: false)
    }
}

public struct BuildTarget: Equatable, Codable {
    public let deploymentVersion: String
    public let triple: String
    public let sdkPath: String
    public let sdkVersion: String

    public init(deploymentVersion: String = "15.0", triple: String = "arm64-apple-ios15.0", sdkPath: String = "<iPhoneOS SDK>", sdkVersion: String = "18.5") {
        self.deploymentVersion = deploymentVersion
        self.triple = triple
        self.sdkPath = sdkPath
        self.sdkVersion = sdkVersion
    }

    public static let iOS15 = BuildTarget()
}

public struct BuildInvocation: Equatable {
    public let executable: String
    public let arguments: [String]

    public init(executable: String, arguments: [String]) {
        self.executable = executable
        self.arguments = arguments
    }

    /// Complete argv with executable at index zero, suitable for command display or execution.
    public var argv: [String] { [executable] + arguments }
}

public struct BuildPlan: Equatable {
    public let target: BuildTarget
    public let invocations: [BuildInvocation]

    public init(target: BuildTarget, invocations: [BuildInvocation]) {
        self.target = target
        self.invocations = invocations
    }
}

public enum BuildPlanningError: Error, Equatable {
    case noSources
    case mixedLanguagesUnsupported
    case wrongExtension(file: String, expected: String)
    case unsafeFilename(String)
    case duplicateFilename(String)
}

public enum BuildPlanner {
    public static func plan(workspace: Workspace, target: BuildTarget = .iOS15) throws -> BuildPlan {
        guard !workspace.files.isEmpty else { throw BuildPlanningError.noSources }
        var seen = Set<String>()
        for file in workspace.files {
            guard isSafeFilename(file.name) else { throw BuildPlanningError.unsafeFilename(file.name) }
            guard seen.insert(file.name.lowercased()).inserted else { throw BuildPlanningError.duplicateFilename(file.name) }
            let expected = file.language == .c ? ".c" : ".swift"
            guard file.name.hasSuffix(expected) else {
                throw BuildPlanningError.wrongExtension(file: file.name, expected: expected)
            }
        }
        guard let language = workspace.files.first?.language,
              workspace.files.allSatisfy({ $0.language == language }) else {
            throw BuildPlanningError.mixedLanguagesUnsupported
        }

        let invocations: [BuildInvocation]
        switch language {
        case .c:
            let compileInvocations = workspace.files.map { file in
                BuildInvocation(executable: "clang", arguments: ["-target", target.triple, "-isysroot", target.sdkPath, "-miphoneos-version-min=\(target.deploymentVersion)", "-c", file.name, "-o", objectName(for: file.name)])
            }
            // Keep the linker executable as argv[0]; this ordering is intentionally covered by regression tests.
            let linkInputs = workspace.files.map { objectName(for: $0.name) }
            let link = BuildInvocation(executable: "ld64.lld", arguments: ["-arch", "arm64", "-syslibroot", target.sdkPath, "-lSystem", "-platform_version", "ios", target.deploymentVersion, target.sdkVersion, "-o", "PocketIDE.out"] + linkInputs)
            invocations = compileInvocations + [link]
        case .swift:
            invocations = [BuildInvocation(executable: "swiftc", arguments: ["-target", target.triple, "-sdk", target.sdkPath, "-emit-executable"] + workspace.files.map(\.name) + ["-o", "PocketIDE.out"])]
        }
        return BuildPlan(target: target, invocations: invocations)
    }

    private static func isSafeFilename(_ name: String) -> Bool {
        guard !name.isEmpty, !name.hasPrefix("-"), name != ".", name != "..", !name.contains("/"), !name.contains("\\"),
              !name.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else { return false }
        return URL(fileURLWithPath: name).lastPathComponent == name
    }

    private static func objectName(for sourceName: String) -> String {
        let base = (sourceName as NSString).deletingPathExtension
        return base + ".o"
    }
}

public struct BuildResult: Equatable {
    public let output: String
    public let artifactURL: URL?
    public let diagnostics: [BuildDiagnostic]
    public init(output: String, artifactURL: URL? = nil, diagnostics: [BuildDiagnostic] = []) {
        self.output = output
        self.artifactURL = artifactURL
        self.diagnostics = diagnostics
    }
}

public enum CompilerBackendError: Error, Equatable, LocalizedError {
    case toolchainNotInstalled

    public var errorDescription: String? {
        switch self {
        case .toolchainNotInstalled:
            return "Native compiler toolchain is not installed in this app; building is unavailable on this platform."
        }
    }
}

public protocol CompilerBackend {
    func build(workspace: Workspace) async throws -> BuildResult
}

/// Explicitly unavailable backend: never reports fake success or launches a process on iOS.
public struct UnavailableNativeBackend: CompilerBackend {
    public init() {}
    public func build(workspace: Workspace) async throws -> BuildResult {
        throw CompilerBackendError.toolchainNotInstalled
    }
}
