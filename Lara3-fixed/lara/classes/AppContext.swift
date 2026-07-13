import Foundation

final class AppContext {

    static let shared = AppContext()
    let mgr = laramgr.shared

    private init() {
        HotPluginManager.shared.register(StatusPlugin())
        HotPluginManager.shared.register(EchoPlugin())
    }

    func getStatus() -> String {
        return """
OMEGA STATUS
dsrunning : \(mgr.dsrunning)
dsready   : \(mgr.dsready)
dsattempted: \(mgr.dsattempted)
vfsready  : \(mgr.vfsready)
sbxrunning: \(mgr.sbxrunning)
"""
    }

    func getLogs() -> String {
        mgr.log
    }

    func runSystem() -> String {
        OmegaBus.shared.emit("system.run", nil)
        mgr.run()
        return "run ok"
    }

    func triggerRespring() -> String {
        OmegaBus.shared.emit("system.respring", nil)
        mgr.showrespring = true
        return "respring ok"
    }
}
