//
//  OmegaExtendedD.swift
//  lara — Extended shell: sandbox, trace, log filter, aliases
//
import Foundation
import Darwin

func _registerSandboxEx() {

    OmegaCore.register("sandbox") { arg, mgr in
        let a = arg.trimmingCharacters(in: .whitespaces)
        guard !a.isEmpty, let pid = _resolvePid(a) else {
            return .fail("sandbox: usage: sandbox <pid|name>")
        }
        // Try BSDINFO — blocked for most system daemons on iOS
        var bsd = proc_bsdinfo()
        let bsdOk = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bsd,
                                 Int32(MemoryLayout<proc_bsdinfo>.size)) > 0
        let name: String = {
            if bsdOk {
                var buf = [UInt8](repeating: 0, count: 33)
                withUnsafeBytes(of: bsd.pbi_name) { raw in
                    let limit = min(raw.count, 32)
                    for i in 0..<limit { guard raw[i] != 0 else { break }; buf[i] = raw[i] }
                }
                let sl = Array(buf.prefix(while: { $0 != 0 }))
                if !sl.isEmpty, let s = String(bytes: sl, encoding: .utf8) ?? String(bytes: sl, encoding: .isoLatin1) { return s }
            }
            // proc_name works even when BSDINFO is blocked
            var nb = [CChar](repeating: 0, count: 256)
            proc_name(pid, &nb, 256)
            let s = String(cString: nb)
            return s.isEmpty ? (ProcessLayer.shared.entry(for: pid)?.name ?? "(pid \(pid))") : s
        }()
        let uidgid = bsdOk ? "\(bsd.pbi_uid) / \(bsd.pbi_gid)" : "-- (PROC_PIDTBSDINFO blocked)"
        var lines = ["Sandbox info — \(name) (\(pid))",
                     "  UID/GID : \(uidgid)"]
        if mgr.sbxready {
            if let tok = mgr.sbxgettokenstring(pid: pid) {
                lines.append("  SBX tok : \(tok)")
            } else {
                lines.append("  SBX tok : (unavailable for this pid)")
            }
        } else {
            lines.append("  SBX tok : (SBX not ready — init exploit + sbx first)")
        }
        return .ok(lines.joined(separator: "\n"))
    }
}

// MARK: - Thread-safe trace state
// Bug fixed: _traceTarget / _traceActive / _traceLogs were bare file-scope
// private vars accessed from OmegaCore's dedicated Thread without any lock,
// causing data races under concurrent command execution.
// They are now encapsulated in a locked class to prevent races.

private final class TraceState {
    static let shared = TraceState()
    private init() {}
    private let lock  = NSLock()
    private var _target: Int32   = -1
    private var _active          = false
    private var _logs: [String]  = []

    var active: Bool  { lock.withLock { _active } }
    var target: Int32 { lock.withLock { _target } }

    func start(pid: Int32, name: String) {
        lock.withLock {
            _target = pid
            _active = true
            _logs   = ["[start] attached to \(name) (\(pid))"]
        }
    }

    func stop(pid: Int32) {
        lock.withLock {
            _logs.append("[stop] detached from pid \(pid)")
            _active = false
            _target = -1
        }
    }

    func dump() -> [String] { lock.withLock { _logs } }
}

// MARK: - Trace

func _registerTrace() {

    OmegaCore.register("trace") { arg, _ in
        let parts = arg.trimmingCharacters(in: .whitespaces).split(separator: " ").map { String($0) }
        switch parts.first?.lowercased() {

        case "start":
            guard parts.count >= 2 else { return .fail("trace start: usage: trace start <pid|name>") }
            guard let pid = _resolvePid(parts[1]) else { return .fail("trace: not found: \(parts[1])") }
            guard !TraceState.shared.active else {
                return .fail("trace: already tracing pid \(TraceState.shared.target) — stop first")
            }
            TraceState.shared.start(pid: pid, name: _pidName(pid))
            // PT_ATTACHEXC = 14 on Darwin/iOS
            let _ = ptrace(14, pid, nil, 0)
            return .ok("trace: attached to \(_pidName(pid)) (\(pid)) — use 'trace dump' to inspect events")

        case "stop":
            guard TraceState.shared.active else { return .fail("trace stop: not currently tracing") }
            let tracedPid = TraceState.shared.target
            // PT_DETACH = 11 on Darwin/iOS
            let _ = ptrace(11, tracedPid, nil, 0)
            TraceState.shared.stop(pid: tracedPid)
            return .ok("trace: stopped")

        case "dump":
            let logs = TraceState.shared.dump()
            return logs.isEmpty ? .ok("trace: no events captured yet") : .ok(logs.joined(separator: "\n"))

        default:
            return .fail("trace: usage: trace <start <pid|name> | stop | dump>")
        }
    }
}

// MARK: - Log filter

func _registerLogEx() {

    OmegaCore.register("log") { arg, _ in
        let sub = arg.trimmingCharacters(in: .whitespaces)
        if sub.lowercased().hasPrefix("filter ") {
            let kw = String(sub.dropFirst(7)).lowercased()
            guard !kw.isEmpty else { return .fail("log filter: keyword required") }
            let matches = globallogger.logs.filter { $0.lowercased().contains(kw) }
            return matches.isEmpty
                ? .ok("log filter: no entries matching '\(kw)'")
                : .ok(matches.prefix(200).joined(separator: "\n"))
        }
        if sub.lowercased() == "clear" { globallogger.clear(); return .ok("log: cleared") }
        return .fail("log: usage: log filter <keyword> | log clear")
    }
}

// MARK: - Aliases

func _registerAliases() {
    OmegaCore.register("entitlements") { arg, mgr in
        OmegaCore.execute("proc-entitlements " + arg, context: mgr)
    }
    OmegaCore.register("sysctl-get") { arg, mgr in
        OmegaCore.execute("sysctl " + arg, context: mgr)
    }
    OmegaCore.register("sysctl-list") { _, mgr in
        OmegaCore.execute("sysctl-all", context: mgr)
    }
}
