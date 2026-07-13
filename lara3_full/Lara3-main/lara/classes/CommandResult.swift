import Foundation

struct CommandResult {
    let output: String
    let isError: Bool

    static func ok(_ text: String) -> CommandResult {
        CommandResult(output: text, isError: false)
    }

    static func fail(_ text: String) -> CommandResult {
        CommandResult(output: text, isError: true)
    }

    static func result(_ text: String) -> CommandResult {
        if text.isEmpty { return CommandResult(output: "", isError: false) }
        let lower = text.lowercased()
        let errorPrefixes = [
            "error", "rm:", "ls:", "cat:", "cd:", "cp:", "mv:", "mkdir:", "touch:",
            "stat:", "head:", "tail:", "find:", "chmod:", "write:", "chown:",
            "vls:", "vcat:", "vsize:", "voverwrite:", "vzero:",
            "kread:", "kwrite:", "kread32:", "kwrite32:", "kinfo:",
            "apps:", "app-info:", "app-data:", "app-bundle:", "app-prefs:",
            "plist:", "plist-get:", "plist-set:", "plist-del:",
            "exec:", "sysctl:", "hexdump:", "grep:", "strings:", "b64:",
            "sbx-info:", "sbx-token:", "sbx-elevate:",
            "proc-kill:", "proc-signal:", "proc-suspend:", "proc-resume:",
            "proc-info:", "proc-csflags:", "proc-cred:",
            "app-kill:", "app-container:",
            "mg-info:", "mg-get:", "mg-set:",
            "defaults:", "vwrite:", "vcopy:", "vstat:",
            "no such", "cannot", "not found", "failed", "invalid",
            "command not found"
        ]
        let isErr = errorPrefixes.contains { lower.hasPrefix($0) }
        return CommandResult(output: text, isError: isErr)
    }
}
