import SwiftUI
import IDECore

@MainActor
final class EditorModel: ObservableObject {
    @Published var workspace: Workspace
    @Published var selectedFileID: UUID?
    @Published var console = "Ready. Native compiler toolchain is unavailable in this app."
    @Published var isBuilding = false
    @Published var notice: String?

    private let workspaceURL: URL

    init() {
        let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        workspaceURL = documents.appendingPathComponent("PocketIDE", isDirectory: true)
            .appendingPathComponent("workspace.json")
        workspace = Workspace.sample(language: .swift)
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
                self.workspace.files[index].contents = value
            }
        )
    }

    func choose(_ language: SourceLanguage) {
        workspace = Workspace.sample(language: language)
        selectedFileID = workspace.files.first?.id
        console = "Loaded the \(language.rawValue.uppercased()) sample. Build is unavailable without a native toolchain."
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
            notice = "Save failed: \(error.localizedDescription)"
            console = notice ?? "Save failed."
        }
    }

    func load() {
        do {
            let data = try Data(contentsOf: workspaceURL)
            let loaded = try JSONDecoder().decode(Workspace.self, from: data)
            workspace = loaded
            selectedFileID = loaded.files.first?.id
            console = "Loaded workspace from Documents/PocketIDE/workspace.json"
            notice = "Workspace loaded"
        } catch {
            console = "Could not load local workspace: \(error.localizedDescription)"
            notice = "No saved workspace found or file is invalid"
        }
    }

    func build() {
        guard !isBuilding else { return }
        isBuilding = true
        console = "Preparing build…\nNative compilation is unavailable on this device."
        Task {
            defer { isBuilding = false }
            do {
                let backend = UnavailableNativeBackend()
                let result = try await backend.build(workspace: workspace)
                console = result.output
            } catch {
                console = "Build unavailable: \(error.localizedDescription)\nNo compilation, signing, installation, or execution was performed."
            }
        }
    }
}

struct EditorView: View {
    @StateObject private var model = EditorModel()

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
    }

    private var header: some View {
        HStack {
            VStack(alignment: .leading, spacing: 3) {
                Text(model.workspace.name)
                    .font(.headline)
                    .lineLimit(1)
                Text("Local workspace · Build toolchain unavailable")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            Spacer()
            Circle()
                .fill(Color.orange)
                .frame(width: 8, height: 8)
                .accessibilityLabel("Native build unavailable")
        }
        .padding(.horizontal)
        .padding(.vertical, 12)
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
                        .padding(.horizontal, 11)
                        .padding(.vertical, 8)
                        .background(model.selectedFileID == file.id ? Color.accentColor : Color(.tertiarySystemGroupedBackground))
                        .foregroundColor(model.selectedFileID == file.id ? .white : .primary)
                        .clipShape(Capsule())
                    }
                    .buttonStyle(PlainButtonStyle())
                    .accessibilityLabel("Open file \(file.name)")
                    .accessibilityAddTraits(model.selectedFileID == file.id ? .isSelected : [])
                }
            }
            .padding(.horizontal)
            .padding(.vertical, 10)
        }
    }

    private var editor: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text(model.selectedFileName)
                    .font(.caption.weight(.semibold))
                    .foregroundColor(.secondary)
                Spacer()
                Text("EDITABLE SOURCE")
                    .font(.system(size: 9, weight: .bold, design: .rounded))
                    .tracking(1)
                    .foregroundColor(.secondary)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
            Divider()
            TextEditor(text: model.contentBinding())
                .font(.system(.body, design: .monospaced))
                .autocapitalization(.none)
                .disableAutocorrection(true)
                .accessibilityLabel("Source code editor")
                .padding(8)
        }
        .background(Color(.secondarySystemGroupedBackground))
        .clipShape(RoundedRectangle(cornerRadius: 14))
        .padding(.horizontal, 12)
        .padding(.bottom, 12)
    }

    private var consolePanel: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Label("Build console", systemImage: "terminal")
                    .font(.subheadline.weight(.semibold))
                Spacer()
                Text("NOT RUNNING")
                    .font(.system(size: 9, weight: .bold))
                    .tracking(0.8)
                    .foregroundColor(.orange)
            }
            ScrollView {
                Text(model.console)
                    .font(.system(.footnote, design: .monospaced))
                    .foregroundColor(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .textSelection(.enabled)
            }
            .frame(minHeight: 58, maxHeight: 88)
            .accessibilityLabel("Build console output")
            Text("This editor does not compile, sign, install, or run code.")
                .font(.caption2)
                .foregroundColor(.secondary)
        }
        .padding(14)
        .background(Color(.secondarySystemGroupedBackground))
    }
}

