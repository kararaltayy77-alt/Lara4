import Foundation

// MARK: - CommandValidator
// Input validation + sanitization before commands are dispatched.

enum CommandValidator {

    // Returns (isValid, errorMessage?)
    static func validate(_ input: String) -> (Bool, String?) {
        let t = input.trimmingCharacters(in: .whitespacesAndNewlines)

        if t.isEmpty         { return (false, "empty command") }
        if t.count > 8_192   { return (false, "command too long (max 8192 chars)") }

        // Null bytes and raw carriage-returns in the command name portion are
        // almost always injection artefacts.
        let firstPart = t.split(separator: " ", maxSplits: 1).first.map(String.init) ?? t
        if firstPart.contains("\0") || firstPart.contains("\r") {
            return (false, "command contains invalid characters")
        }

        return (true, nil)
    }

    // Light sanitisation of arguments: strip embedded nulls.
    // We do NOT strip quotes or pipes here — those are handled at parse time.
    static func sanitize(_ arg: String) -> String {
        arg.replacingOccurrences(of: "\0", with: "")
    }
}

// MARK: - NSLock convenience
extension NSLock {
    @discardableResult
    func withLock<T>(_ body: () throws -> T) rethrows -> T {
        lock(); defer { unlock() }
        return try body()
    }
}
