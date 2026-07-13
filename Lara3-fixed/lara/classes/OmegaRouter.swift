import Foundation

final class OmegaRouter {

    static let shared = OmegaRouter()
    private init() {}

    func execute(_ input: String) -> String {
        let cmd = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cmd.isEmpty else { return "" }

        let p = cmd.split(separator: " ", maxSplits: 1).map { String($0) }
        let name = p[0].lowercased()
        let arg  = p.count > 1 ? p[1] : ""

        if let plugin = HotPluginManager.shared.execute(name, arg, context: AppContext.shared) {
            return plugin
        }

        let result = OmegaCore.execute(cmd, context: AppContext.shared.mgr)
        return result.output
    }
}
