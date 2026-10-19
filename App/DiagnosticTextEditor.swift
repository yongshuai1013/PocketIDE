import SwiftUI
import UIKit
import IDECore

struct DiagnosticTextEditor: UIViewRepresentable {
    @Binding var text: String
    let fileID: UUID?
    let navigationRequest: DiagnosticNavigationRequest?

    func makeUIView(context: Context) -> UITextView {
        let view = UITextView()
        view.delegate = context.coordinator
        view.font = UIFont.monospacedSystemFont(ofSize: UIFont.systemFontSize, weight: .regular)
        view.autocorrectionType = .no
        view.autocapitalizationType = .none
        view.smartQuotesType = .no
        view.smartDashesType = .no
        view.smartInsertDeleteType = .no
        view.alwaysBounceVertical = true
        view.backgroundColor = .clear
        view.text = text
        return view
    }

    func updateUIView(_ view: UITextView, context: Context) {
        context.coordinator.parent = self
        let fileChanged = context.coordinator.displayedFileID != fileID
        if fileChanged || view.text != text {
            let oldSelection = view.selectedRange
            view.text = text
            view.selectedRange = NSRange(location: fileChanged ? 0 : min(oldSelection.location, (text as NSString).length), length: 0)
            if fileChanged { view.setContentOffset(.zero, animated: false) }
        }
        context.coordinator.displayedFileID = fileID
        guard let request = navigationRequest,
              request.fileID == fileID,
              context.coordinator.appliedToken != request.token || context.coordinator.appliedFileID != request.fileID else { return }
        context.coordinator.appliedToken = request.token
        context.coordinator.appliedFileID = request.fileID
        let range = SourceSelection.range(in: text, line: request.line, column: request.column)
        view.selectedRange = range
        view.scrollRangeToVisible(range)
    }

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    final class Coordinator: NSObject, UITextViewDelegate {
        var parent: DiagnosticTextEditor
        var appliedToken: UUID?
        var appliedFileID: UUID?
        var displayedFileID: UUID?

        init(_ parent: DiagnosticTextEditor) { self.parent = parent }

        func textViewDidChange(_ textView: UITextView) {
            parent.text = textView.text
        }
    }
}
