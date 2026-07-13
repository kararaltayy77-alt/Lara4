import Foundation

// EchoPlugin: implements HotPlugin so it integrates with HotPluginManager.
// Handles: echo <text>, print <text>
final class EchoPlugin: HotPlugin {

    let id = "echo"

    func handle(_ cmd: String, _ arg: String, context: AppContext) -> String? {
        switch cmd {
        case "echo", "print":
            return arg
        case "echo-upper":
            return arg.uppercased()
        case "echo-lower":
            return arg.lowercased()
        case "echo-len":
            return "length: \(arg.count)"
        default:
            return nil
        }
    }
}
