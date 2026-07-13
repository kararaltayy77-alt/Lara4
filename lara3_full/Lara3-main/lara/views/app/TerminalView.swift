import SwiftUI

private struct TerminalLine: Identifiable {
    let id   = UUID()
    let text: String
    let kind: Kind
    enum Kind { case input, output, error, system }
}

struct TerminalView: View {

    @State private var input:       String = ""
    @State private var lines:       [TerminalLine] = []
    @State private var cmdHistory:  [String] = []
    @State private var histIdx:     Int = -1
    @State private var prompt:      String = "/"
    @State private var isExecuting: Bool = false   // ← prevents concurrent execution
    @FocusState private var focused: Bool

    var body: some View {
        VStack(spacing: 0) {
            outputArea
            Divider().background(Color.green.opacity(0.4))
            inputBar
        }
        .background(Color.black)
        .navigationTitle("Terminal")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar { toolbarContent }
        .onAppear {
            OmegaBootstrap.start()
            cmdHistory = TerminalHistory.shared.load()
            prompt     = OmegaFS.shared.cwd
            append("LARA Shell  —  type 'help' for full command list", .system)
            append("cwd: \(prompt)  |  ios: \(UIDevice.current.systemVersion)", .system)
            focused = true
        }
    }

    // MARK: - Output area

    private var outputArea: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 1) {
                    ForEach(lines) { line in
                        Text(line.text)
                            .font(.system(size: 12.5, design: .monospaced))
                            .foregroundColor(lineColor(line.kind))
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .textSelection(.enabled)
                            .id(line.id)
                    }
                }
                .padding(8)
            }
            .background(Color.black)
            .onChange(of: lines.count) { _ in
                withAnimation(.easeOut(duration: 0.12)) {
                    proxy.scrollTo(lines.last?.id, anchor: .bottom)
                }
            }
        }
    }

    // MARK: - Input bar

    private var inputBar: some View {
        HStack(spacing: 6) {
            Text("\(shortenedPrompt)]$")
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(isExecuting ? .yellow : .green)
                .lineLimit(1)
                .minimumScaleFactor(0.5)

            TextField("", text: $input)
                .font(.system(size: 13, design: .monospaced))
                .foregroundColor(.green)
                .tint(.green)
                .autocorrectionDisabled()
                .textInputAutocapitalization(.never)
                .focused($focused)
                .disabled(isExecuting)
                .onSubmit { run() }
                .submitLabel(.done)

            Button { histUp() } label: {
                Image(systemName: "chevron.up")
                    .foregroundColor(.green)
                    .frame(width: 28, height: 28)
            }
            .buttonStyle(.plain)
            .disabled(isExecuting)

            Button { histDown() } label: {
                Image(systemName: "chevron.down")
                    .foregroundColor(.green)
                    .frame(width: 28, height: 28)
            }
            .buttonStyle(.plain)
            .disabled(isExecuting)

            if isExecuting {
                ProgressView()
                    .progressViewStyle(.circular)
                    .scaleEffect(0.75)
                    .tint(.green)
                    .frame(width: 36, height: 28)
            } else {
                Button("↵") { run() }
                    .font(.system(size: 13, weight: .semibold, design: .monospaced))
                    .foregroundColor(.black)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 5)
                    .background(Color.green)
                    .cornerRadius(5)
            }
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 6)
        .background(Color.black)
    }

    // MARK: - Toolbar

    @ToolbarContentBuilder
    private var toolbarContent: some ToolbarContent {
        ToolbarItem(placement: .navigationBarLeading) {
            Button("Copy All") {
                let all = lines.map(\.text).joined(separator: "\n")
                UIPasteboard.general.string = all
            }
            .foregroundColor(.green)
        }
        ToolbarItem(placement: .navigationBarTrailing) {
            Button("Clear") {
                lines.removeAll()
                append("LARA Shell — cleared", .system)
            }
            .foregroundColor(.green)
            .disabled(isExecuting)
        }
    }

    // MARK: - Helpers

    private var shortenedPrompt: String {
        if prompt == "/" { return "/" }
        return prompt.split(separator: "/").last.map(String.init) ?? prompt
    }

    private func lineColor(_ kind: TerminalLine.Kind) -> Color {
        switch kind {
        case .input:  return .yellow
        case .output: return .green
        case .error:  return .red
        case .system: return Color(white: 0.55)
        }
    }

    private func append(_ text: String, _ kind: TerminalLine.Kind) {
        lines.append(TerminalLine(text: text, kind: kind))
    }

    // MARK: - Command execution

    private func run() {
        // ── Guard: prevent concurrent execution ────────────────────────────
        guard !isExecuting else {
            append("⚠ command already running — wait for it to finish", .error)
            return
        }

        let raw = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !raw.isEmpty else { return }

        // ── Validate input ────────────────────────────────────────────────
        let (valid, validErr) = CommandValidator.validate(raw)
        guard valid else {
            append("⚠ \(validErr ?? "invalid input")", .error)
            return
        }

        input   = ""
        histIdx = -1

        // save history (deduplicated)
        if cmdHistory.first != raw {
            cmdHistory.insert(raw, at: 0)
            TerminalHistory.shared.save(raw)
        }

        append("lara:\(shortenedPrompt)]$ \(raw)", .input)

        isExecuting = true
        let mgr     = laramgr.shared
        let start   = Date()

        // ── Execute on background thread ──────────────────────────────────
        DispatchQueue.global(qos: .userInitiated).async {
            let result: CommandResult

            if raw.contains(" | ") {
                result = Self.runPipeline(raw, mgr: mgr)
            } else {
                result = OmegaCore.execute(raw, context: mgr)
            }

            let duration = Date().timeIntervalSince(start)
            let firstWord = raw.split(separator: " ").first.map(String.init) ?? raw
            CommandLogger.shared.log(firstWord,
                                     status: result.isError ? "error" : "ok",
                                     duration: duration)

            // ── Return to main thread for UI updates ──────────────────────
            DispatchQueue.main.async {
                // Special pipe-clear sentinel
                if result.output == "__CLEAR__" {
                    lines.removeAll()
                    append("LARA Shell — cleared", .system)
                } else {
                    handleResult(result)
                }
                prompt      = OmegaFS.shared.cwd
                isExecuting = false
                focused     = true
            }
        }
    }

    // ── Static pipeline runner (called from background thread) ────────────
    private static func runPipeline(_ raw: String, mgr: laramgr) -> CommandResult {
        let stages = raw.components(separatedBy: " | ")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }

        guard stages.count >= 2 else {
            return OmegaCore.execute(raw, context: mgr)
        }

        var pipeInput = ""

        for (idx, stage) in stages.enumerated() {
            let result: CommandResult
            if idx == 0 {
                result = OmegaCore.execute(stage, context: mgr)
            } else {
                result = OmegaCore.executePiped(stage, stdin: pipeInput, context: mgr)
            }

            if result.isError { return result }   // propagate pipe errors immediately
            pipeInput = result.output
        }

        // Check for clear sentinel
        if pipeInput == "__CLEAR__" {
            return CommandResult(output: "__CLEAR__", isError: false)
        }

        return CommandResult(output: pipeInput, isError: false)
    }

    // ── Instance pipeline helper (kept for backwards compat) ──────────────
    private func executePipeline(_ raw: String, mgr: laramgr) {
        let result = Self.runPipeline(raw, mgr: mgr)
        if result.output == "__CLEAR__" {
            lines.removeAll()
            append("LARA Shell — cleared", .system)
        } else {
            handleResult(result)
        }
    }

    private func handleResult(_ result: CommandResult) {
        if result.output == "__CLEAR__" {
            lines.removeAll()
            append("LARA Shell — cleared", .system)
        } else if !result.output.isEmpty {
            for line in result.output.split(separator: "\n", omittingEmptySubsequences: false) {
                append(String(line), result.isError ? .error : .output)
            }
        }
    }

    // MARK: - History navigation

    private func histUp() {
        guard !cmdHistory.isEmpty else { return }
        histIdx = min(histIdx + 1, cmdHistory.count - 1)
        input   = cmdHistory[histIdx]
    }

    private func histDown() {
        if histIdx <= 0 { histIdx = -1; input = "" }
        else { histIdx -= 1; input = cmdHistory[histIdx] }
    }
}
