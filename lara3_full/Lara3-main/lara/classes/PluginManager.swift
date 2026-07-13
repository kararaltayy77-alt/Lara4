import Foundation

final class PluginManager {

    static let shared = PluginManager()

    private init() {}

    var plugins: [String: OmegaPlugin] = [:]

    func register(_ plugin: OmegaPlugin) {
        plugins[plugin.name] = plugin
    }

    func execute(_ cmd: String, arg: String, context: AppContext) -> String {
        return plugins[cmd]?.execute(arg, context: context) ?? "plugin not found"
    }
}
