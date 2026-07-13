import Foundation

final class StatusPlugin: HotPlugin {

    let id = "status"

    func handle(_ cmd: String, _ arg: String, context: AppContext) -> String? {
        if cmd == "sys" {
            return context.getStatus()
        }
        return nil
    }
}
