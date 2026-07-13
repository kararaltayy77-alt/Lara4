import Foundation

protocol HotPlugin {
    var id: String { get }
    func handle(_ cmd: String, _ arg: String, context: AppContext) -> String?
}
