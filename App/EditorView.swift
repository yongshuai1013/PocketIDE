import SwiftUI
import IDECore
import UniformTypeIdentifiers

struct DiagnosticNavigationRequest: Equatable {
    let token: UUID
    let fileID: UUID
    let line: Int
    let column: Int?
}

@MainActor
final class EditorModel: ObservableObject {
    @Published var workspace: Workspace
    @Published var selectedFileID: UUID?
    @Published var console = "Ready. C builds require embedded Clang/LLD and a locally supplied SDK. Swift is not integrated yet."
    @Published var isBuilding = false
    @Published var notice: String?
    @Published private(set) var diagnostics: [BuildDiagnostic] = []
    @Published private(set) var navigationRequest: DiagnosticNavigationRequest?
    @Published var pendingImport: Workspace?

    private let workspaceURL: URL

    init() {
        let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        workspaceURL = documents.appendingPathComponent("PocketIDE", isDirectory: true)
            .appendingPathComponent("workspace.json")
        workspace = Workspace.sample(language: .c)
        selectedFileID = workspace.files.first?.id
    }

    var selectedIndex: Int? {
        workspace.files.firstIndex(where: { $0.id == selectedFileID })
    }

    var selectedFileName: String {
        guard let index = selectedIndex else { return "No file" }
        return workspace.files[index].name
    }

    func contentBinding() -> Binding<String> {
        Binding(
            get: {
                guard let index = self.selectedIndex else { return "" }
                return self.workspace.files[index].contents
            },
            set: { value in
                guard let index = self.selectedIndex else { return }
                guard self.workspace.files[index].contents != value else { return }
                self.workspace.files[index].contents = value
                self.clearDiagnostics()
            }
        )
    }

    private func clearDiagnostics() {
        diagnostics = []
        navigationRequest = nil
    }

    func choose(_ language: SourceLanguage) {
        clearDiagnostics()
        workspace = Workspace.sample(language: language)
        selectedFileID = workspace.files.first?.id
        console = "Loaded the \(language.rawValue.uppercased()) sample.\n\(EmbeddedCSetup.status)\nSwift frontend is not integrated yet."
        notice = "Loaded \(language.rawValue.uppercased()) sample"
    }

    func save() {
        do {
            let directory = workspaceURL.deletingLastPathComponent()
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            let data = try JSONEncoder().encode(workspace)
            try data.write(to: workspaceURL, options: .atomic)
            notice = "Workspace saved locally"
            console = "Saved workspace to Documents/PocketIDE/workspace.json"
        } catch {
            notice = "Save failed: \(DiagnosticRedactor.redact(error.localizedDescription))"
            console = notice ?? "Save failed."
        }
    }

    func load() {
        clearDiagnostics()
        do {
            let data = try Data(contentsOf: workspaceURL)
            let loaded = try JSONDecoder().decode(Workspace.self, from: data)
            workspace = loaded
            selectedFileID = loaded.files.first?.id
            console = "Loaded workspace from Documents/PocketIDE/workspace.json"
            notice = "Workspace loaded"
        } catch {
            console = "Could not load local workspace: \(DiagnosticRedactor.redact(error.localizedDescription))"
            notice = "No saved workspace found or file is invalid"
        }
    }

    /// Read-only import: coordination/security scope belong to the UI; validation stays in IDECore.
    func prepareImport(_ result: Result<[URL], Error>) {
        guard !isBuilding else { return }
        pendingImport = nil
        do {
            let urls = try result.get()
            guard urls.count == 1, let url = urls.first else { throw CocoaError(.fileReadUnknown) }
            let accessed = url.startAccessingSecurityScopedResource()
            defer { if accessed { url.stopAccessingSecurityScopedResource() } }
            var coordinationError: NSError?
            var readError: Error?
            var candidate: Workspace?
            NSFileCoordinator().coordinate(readingItemAt: url, options: .withoutChanges, error: &coordinationError) { _ in
                // Validate the selected path itself; never let coordinator canonicalization hide a symlink.
                do { candidate = try CWorkspaceImporter.load(from: url) }
                catch { readError = error }
            }
            if let error = coordinationError { throw error }
            if let error = readError { throw error }
            guard let candidate = candidate else { throw CocoaError(.fileReadUnknown) }
            pendingImport = candidate
        } catch {
            notice = "Import failed: \(DiagnosticRedactor.redact(error.localizedDescription))"
        }
    }

    func confirmImport() {
        guard !isBuilding, let candidate = pendingImport else { return }
        // No persistence or compiler call: replace only after complete validation and user confirmation.
        workspace = candidate
        selectedFileID = candidate.files.first?.id
        clearDiagnostics()
        pendingImport = nil
        console = "Imported \(candidate.files.count) C files into the editor. Not saved or built; no scripts were executed."
    }

    func openDiagnostic(_ diagnostic: BuildDiagnostic) {
        guard let file = workspace.files.first(where: { $0.id == diagnostic.sourceFileID }),
              let sourceID = diagnostic.sourceFileID else { return }
        selectedFileID = sourceID
        guard let line = diagnostic.line else { return }
        navigationRequest = DiagnosticNavigationRequest(token: UUID(), fileID: file.id, line: line, column: diagnostic.column)
    }

    func build() {
        guard !isBuilding else { return }
        clearDiagnostics()
        isBuilding = true
        let snapshot = workspace
        console = "Preparing in-process C build…"
        Task {
            defer { isBuilding = false }
            do {
                guard snapshot.files.allSatisfy({ $0.language == .c }) else { throw NativeCError.swiftNotSupported }
                let backend = try EmbeddedCSetup.backend()
                let result = try await backend.build(workspace: snapshot)
                console = result.output
                if workspace == snapshot {
                    diagnostics = result.diagnostics
                } else {
                    clearDiagnostics()
                    notice = "Build finished, but diagnostics were hidden because the workspace changed during the build."
                }
            } catch let failure as NativeBuildFailure {
                console = "Build failed (\(failure.tool)):\n\(failure.output)\nNo signing, installation, or execution was performed."
                if workspace == snapshot {
                    diagnostics = failure.diagnostics
                } else {
                    clearDiagnostics()
                    notice = "Build finished, but diagnostics were hidden because the workspace changed during the build."
                }
            } catch {
                console = "Build failed or unavailable: \(DiagnosticRedactor.redact(error.localizedDescription))\nNo signing, installation, or execution was performed."
            }
        }
    }
}

struct EditorView: View {
    @StateObject private var model = EditorModel()
    @State private var isImporting = false
    @State private var isConfirmingImport = false

    var body: some View {
        NavigationView {
            VStack(spacing: 0) {
                header
                filePicker
                editor
                consolePanel
            }
            .background(Color(.systemGroupedBackground))
            .navigationBarTitle("Pocket IDE", displayMode: .inline)
            .navigationBarItems(leading: Menu {
                Button(action: { model.choose(.c) }) {
                    Label("C sample", systemImage: "chevron.left.forwardslash.chevron.right")
                }
                Button(action: { model.choose(.swift) }) {
                    Label("Swift sample", systemImage: "swift")
                }
                Divider()
                Button(action: model.load) {
                    Label("Load workspace", systemImage: "folder")
                }
                Button(action: model.save) {
                    Label("Save workspace", systemImage: "square.and.arrow.down")
                }
                Divider()
                Button(action: { isImporting = true }) {
                    Label("Import C workspace JSON…", systemImage: "square.and.arrow.down.on.square")
                }
                .disabled(model.isBuilding)
            } label: {
                Image(systemName: "ellipsis.circle").accessibilityLabel("Workspace actions")
            }, trailing: Button(action: model.build) {
                if model.isBuilding {
                    ProgressView().accessibilityLabel("Build status")
                } else {
                    Label("Build", systemImage: "hammer")
                }
            }.disabled(model.isBuilding))
            .alert(isPresented: Binding(
                get: { model.notice != nil },
                set: { if !$0 { model.notice = nil } }
            )) {
                Alert(title: Text(model.notice ?? "Pocket IDE"))
            }
        }
        .navigationViewStyle(StackNavigationViewStyle())
        .fileImporter(isPresented: $isImporting, allowedContentTypes: [.json], allowsMultipleSelection: false) { result in
            model.prepareImport(result)
            isConfirmingImport = model.pendingImport != nil
        }
        .confirmationDialog("Replace the current editor workspace?", isPresented: $isConfirmingImport, titleVisibility: .visible) {
            Button("Replace editor contents", role: .destructive, action: model.confirmImport)
            Button("Cancel", role: .cancel) { model.pendingImport = nil }
        } message: {
            Text("Import \(model.pendingImport?.name ?? "") (\(model.pendingImport?.files.count ?? 0) C files). Unsaved editor changes will be replaced. Your saved workspace is unchanged until Save. Only versioned C workspace JSON is supported: 32 files / 2 MiB maximum.")
        }
    }

    private var header: some View {
        HStack {
            VStack(alignment: .leading, spacing: 3) {
                Text(model.workspace.name).font(.headline).lineLimit(1)
                Text(EmbeddedCSetup.status).font(.caption).foregroundColor(.secondary)
            }
            Spacer()
            Circle().fill(Color.orange).frame(width: 8, height: 8).accessibilityLabel(EmbeddedCSetup.status)
        }
        .padding(.horizontal).padding(.vertical, 12)
        .background(Color(.secondarySystemGroupedBackground))
    }

    private var filePicker: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                ForEach(model.workspace.files) { file in
                    Button(action: { model.selectedFileID = file.id }) {
                        HStack(spacing: 6) {
                            Image(systemName: file.language == .swift ? "swift" : "chevron.left.forwardslash.chevron.right")
                            Text(file.name).lineLimit(1)
                        }
                        .font(.system(.caption, design: .monospaced))
                        .padding(.horizontal, 11).padding(.vertical, 8)
                        .background(model.selectedFileID == file.id ? Color.accentColor : Color(.tertiarySystemGroupedBackground))
                        .foregroundColor(model.selectedFileID == file.id ? .white : .primary)
                        .clipShape(Capsule())
                    }
                    .buttonStyle(PlainButtonStyle())
                    .accessibilityLabel("Open file \(file.name)")
                    .accessibilityAddTraits(model.selectedFileID == file.id ? .isSelected : [])
                }
            }
            .padding(.horizontal).padding(.vertical, 10)
        }
    }

    private var editor: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text(model.selectedFileName).font(.caption.weight(.semibold)).foregroundColor(.secondary)
                Spacer()
                Text("EDITABLE SOURCE").font(.system(size: 9, weight: .bold, design: .rounded)).tracking(1).foregroundColor(.secondary)
            }
            .padding(.horizontal, 14).padding(.vertical, 10)
            Divider()
            DiagnosticTextEditor(text: model.contentBinding(), fileID: model.selectedFileID, navigationRequest: model.navigationRequest)
                .accessibilityLabel("Source code editor")
                .padding(8)
            if !model.diagnostics.isEmpty {
                Divider()
                VStack(alignment: .leading, spacing: 6) {
                    Text("Diagnostics (\(model.diagnostics.count))").font(.subheadline.weight(.semibold))
                    ScrollView {
                        VStack(alignment: .leading, spacing: 6) {
                            ForEach(model.diagnostics) { diagnostic in
                                diagnosticRow(diagnostic)
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .frame(maxHeight: 112)
                }
                .padding(10)
            }
        }
        .background(Color(.secondarySystemGroupedBackground))
        .clipShape(RoundedRectangle(cornerRadius: 14))
        .padding(.horizontal, 12).padding(.bottom, 12)
    }

    private func diagnosticRow(_ diagnostic: BuildDiagnostic) -> some View {
        let sourceExists = diagnostic.sourceFileID.map { id in model.workspace.files.contains(where: { $0.id == id }) } ?? false
        let location: String = {
            guard let file = diagnostic.file else { return "Unknown file" }
            guard let line = diagnostic.line else { return file }
            if let column = diagnostic.column { return "\(file):\(line):\(column)" }
            return "\(file):\(line)"
        }()
        return Button(action: { model.openDiagnostic(diagnostic) }) {
            VStack(alignment: .leading, spacing: 3) {
                Text("\(diagnostic.phase.rawValue) · \(diagnostic.severity.rawValue) · \(location)")
                    .font(.system(.caption2, design: .monospaced)).foregroundColor(.secondary)
                Text(diagnostic.message).font(.system(.footnote, design: .monospaced)).foregroundColor(.primary)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .padding(7).background(Color(.tertiarySystemGroupedBackground)).cornerRadius(7)
        }
        .buttonStyle(PlainButtonStyle())
        .disabled(!sourceExists)
        .accessibilityHint(sourceExists ? "Open diagnostic source" : "No matching workspace source")
    }

    private var consolePanel: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Label("Build console", systemImage: "terminal").font(.subheadline.weight(.semibold))
                Spacer()
                Text(model.isBuilding ? "BUILDING" : "NO EXECUTION")
                    .font(.system(size: 9, weight: .bold)).tracking(0.8).foregroundColor(.orange)
            }
            ScrollView {
                Text(model.console).font(.system(.footnote, design: .monospaced)).foregroundColor(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading).textSelection(.enabled)
            }
            .frame(minHeight: 58, maxHeight: 88).accessibilityLabel("Build console output")
            Text("C: optional embedded Clang/LLD. Swift: pending. No signing, installation or execution.")
                .font(.caption2).foregroundColor(.secondary)
        }
        .padding(14).background(Color(.secondarySystemGroupedBackground))
    }
}
