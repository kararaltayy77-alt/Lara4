import Foundation

// MARK: - CommandLogger
// Thread-safe ring-buffer logger for shell command history (last 500 entries).

final class CommandLogger {

    static let shared = CommandLogger()
    private init() {}

    private struct Entry {
        let timestamp: Date
        let command:   String
        let status:    String   // "ok" | "error" | "timeout"
        let duration:  Double   // seconds
    }

    private let _lock    = NSLock()
    private var _entries = [Entry]()
    private let _limit   = 500

    private lazy var _fmt: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss.SSS"
        return f
    }()

    func log(_ command: String, status: String = "", duration: Double = 0) {
        let entry = Entry(timestamp: Date(), command: command, status: status, duration: duration)
        _lock.withLock {
            _entries.append(entry)
            if _entries.count > _limit { _entries.removeFirst() }
        }
    }

    func dump(last n: Int = 100) -> String {
        let copy = _lock.withLock { _entries.suffix(n) }
        guard !copy.isEmpty else { return "(no command log entries)" }
        var out = "LARA Command Log — last \(copy.count) entries\n"
        out += String(repeating: "─", count: 50) + "\n"
        for e in copy {
            out += String(format: "[%@] %-30s [%@] %.1fms\n",
                          _fmt.string(from: e.timestamp),
                          String(e.command.prefix(30)),
                          e.status,
                          e.duration * 1_000)
        }
        return out
    }

    func clear() { _lock.withLock { _entries.removeAll() } }
}
