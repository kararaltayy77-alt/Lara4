import Foundation

// MARK: - OmegaCore
// Thread-safe command registry + crash-protected execution + timeout guard.
// Crash protection uses a dedicated Thread (not DispatchQueue.global) to avoid
// thread-pool starvation, plus an ObjC @try/@catch barrier via OmegaRunWithBarrier.

final class OmegaCore {

    typealias Handler = (String, laramgr) -> CommandResult

    // ── Registry ───────────────────────────────────────────────────────────
    private static let _lock    = NSLock()
    private static var _commands: [String: Handler] = [:]
    private static var _pipeBuffer: String? = nil

    // ── Diagnostics ────────────────────────────────────────────────────────
    private static var _crashCount   = 0
    private static var _timeoutCount = 0
    static var crashCount:   Int { _lock.withLock { _crashCount } }
    static var timeoutCount: Int { _lock.withLock { _timeoutCount } }
    static var registeredCount: Int { _lock.withLock { _commands.count } }

    static var pipeBuffer: String? {
        get { _lock.withLock { _pipeBuffer } }
        set { _lock.withLock { _pipeBuffer = newValue } }
    }

    // ── Registration ───────────────────────────────────────────────────────
    static func register(_ name: String, _ handler: @escaping Handler) {
        _lock.withLock { _commands[name] = handler }
    }

    // ── Fuzzy suggestion on not-found ──────────────────────────────────────
    private static func _suggestCommand(_ key: String) -> String? {
        let all = _lock.withLock { Array(_commands.keys) }
        // Common prefix scoring — fast, no allocation
        var best: String?
        var bestScore = 0
        for cmd in all {
            var score = 0
            for (a, b) in zip(key, cmd) {
                guard a == b else { break }
                score += 1
            }
            // Penalise length mismatch
            let diff = abs(key.count - cmd.count)
            if diff > 5 { continue }
            score -= diff / 2
            if score > bestScore && score >= 2 {
                bestScore = score
                best = cmd
            }
        }
        return best
    }

    // ── Main entry-point ───────────────────────────────────────────────────
    static func execute(_ input: String, context mgr: laramgr) -> CommandResult {
        let cmd = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cmd.isEmpty else { return .fail("empty command") }
        guard cmd.count <= 8_192 else {
            return .fail("command too long (max 8192 chars)")
        }

        let parts = cmd.split(separator: " ", maxSplits: 1).map { String($0) }
        let key   = parts[0].lowercased()
        let arg   = parts.count > 1 ? CommandValidator.sanitize(parts[1]) : ""

        guard let handler = _lock.withLock({ _commands[key] }) else {
            OmegaBus.shared.emit("shell.unknown_command", key)
            if let suggestion = _suggestCommand(key) {
                return .fail("""
\(key): command not found
  Did you mean '\(suggestion)'?  (type 'help' for full list  |  \(registeredCount) commands loaded)
""")
            }
            return .fail("\(key): command not found — type 'help' for full list  (\(registeredCount) commands loaded)")
        }

        return _safeExecute(key: key, handler: handler, arg: arg, mgr: mgr)
    }

    // ── Crash-protected execution with 30 s timeout ────────────────────────
    private static func _safeExecute(
        key: String,
        handler: @escaping Handler,
        arg: String,
        mgr: laramgr
    ) -> CommandResult {

        let sema    = DispatchSemaphore(value: 0)
        var result: CommandResult = .fail("\(key): unexpected internal error")

        let t = Thread {
            // OmegaRunWithBarrier wraps the Swift call in ObjC @try/@catch.
            // Any NSException (e.g. NSRangeException, NSInvalidArgumentException)
            // is caught here and converted to a .fail result — the app does NOT crash.
            OmegaRunWithBarrier({
                autoreleasepool {
                    result = handler(arg, mgr)
                }
            }, { exc in
                _lock.withLock { _crashCount += 1 }
                let msg = "\(key): caught \(exc.name.rawValue): \(exc.reason ?? "unknown reason")"
                result  = .fail(msg)
                CommandLogger.shared.log(key, status: "exception: \(exc.name.rawValue)", duration: 0)
                OmegaBus.shared.emit("shell.crash", [
                    "command":   key,
                    "exception": exc.name.rawValue,
                    "reason":    exc.reason ?? ""
                ])
            })
            sema.signal()
        }
        t.name             = "omega.\(key)"
        t.qualityOfService = QualityOfService.userInitiated
        t.start()

        let deadline = DispatchTime.now() + .seconds(30)
        if sema.wait(timeout: deadline) == .timedOut {
            _lock.withLock { _timeoutCount += 1 }
            CommandLogger.shared.log(key, status: "timeout", duration: 30)
            OmegaBus.shared.emit("shell.timeout", key)
            return .fail("\(key): timed out after 30 s — try a smaller range or simpler argument")
        }

        return result
    }

    // ── Piped execution ────────────────────────────────────────────────────
    static func executePiped(_ input: String, stdin: String, context mgr: laramgr) -> CommandResult {
        pipeBuffer = stdin
        defer { pipeBuffer = nil }
        return execute(input, context: mgr)
    }
}
