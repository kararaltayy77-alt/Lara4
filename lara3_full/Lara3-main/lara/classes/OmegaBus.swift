import Foundation

// MARK: - OmegaBus
// Thread-safe event bus used across the shell subsystem.

final class OmegaBus {

    static let shared = OmegaBus()
    private init() {}

    typealias Handler = (String, Any?) -> Void

    private let _lock = NSLock()
    private var _listeners: [String: [Handler]] = [:]

    func on(_ event: String, _ handler: @escaping Handler) {
        _lock.withLock {
            _listeners[event, default: []].append(handler)
        }
    }

    func emit(_ event: String, _ data: Any? = nil) {
        // Copy handlers under lock, then call outside lock to avoid deadlocks.
        let handlers = _lock.withLock { _listeners[event] ?? [] }
        handlers.forEach { $0(event, data) }
    }
}
