import Foundation

final class TerminalHistory {

    static let shared = TerminalHistory()
    private let key   = "omega.history.v2"
    private let limit = 300

    func save(_ cmd: String) {
        var list = load()
        list.removeAll { $0 == cmd }
        list.insert(cmd, at: 0)
        if list.count > limit { list = Array(list.prefix(limit)) }
        UserDefaults.standard.set(list, forKey: key)
    }

    func load() -> [String] {
        UserDefaults.standard.stringArray(forKey: key) ?? []
    }

    func clear() {
        UserDefaults.standard.removeObject(forKey: key)
    }
}
