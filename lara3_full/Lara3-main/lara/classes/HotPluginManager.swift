import Foundation

final class HotPluginManager {

    static let shared = HotPluginManager()
    private init() {}

    private var plugins: [HotPlugin] = []

    func register(_ p: HotPlugin) {
        plugins.append(p)
    }

    func execute(_ cmd: String, _ arg: String, context: AppContext) -> String? {
        for p in plugins {
            if let r = p.handle(cmd, arg, context: context) {
                return r
            }
        }
        return nil
    }
}
