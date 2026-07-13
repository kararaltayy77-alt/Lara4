import Foundation

protocol OmegaPlugin {
    var name: String { get }
    func execute(_ arg: String, context: AppContext) -> String
}
