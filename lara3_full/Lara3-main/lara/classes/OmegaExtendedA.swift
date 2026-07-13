//
//  OmegaExtendedA.swift
//  lara — Extended shell: psx, taskinfo, threadinfo
//
import Foundation
import Darwin

// MARK: - Shared helpers (internal — used across OmegaExtended*)

func _allPIDs() -> [Int32] {
  ProcessLayer.shared.listAll().map { $0.pid }
}

func _pidName(_ pid: Int32) -> String {
  ProcessLayer.shared.entry(for: pid)?.name ?? ""
}

func _findPid(_ name: String) -> Int32? {
  ProcessLayer.shared.find(matching: name).first?.pid
}

func _resolvePid(_ s: String) -> Int32? {
  ProcessLayer.shared.resolve(s)
}

func _parseAddrE(_ s: String) -> UInt64? {
    let t = s.trimmingCharacters(in: .whitespaces)
    if t.hasPrefix("0x") || t.hasPrefix("0X") { return UInt64(t.dropFirst(2), radix: 16) }
    return UInt64(t, radix: 16) ?? UInt64(t)
}

func _col(_ widths: [Int], _ fields: [String]) -> String {
    zip(widths, fields).map { w, f in
        f.count > w ? String(f.prefix(w)) : f.padding(toLength: w, withPad: " ", startingAt: 0)
    }.joined(separator: "  ")
}

// MARK: - Registration entry point

final class OmegaExtended {
    private static var registered = false
    static func registerAll() {
        guard !registered else { return }
        registered = true
        _registerPsx()
        _registerMemory()
        _registerPorts()
        _registerProcCtl()
        _registerKernelEx()
        _registerSandboxEx()
        _registerTrace()
        _registerLogEx()
        _registerAliases()
    }
}

// MARK: - psx / taskinfo / threadinfo

func _registerPsx() {

    // psx [filter] — enhanced process list
    // Bug fixed: name was extracted via withMemoryRebound (no null-termination guarantee).
    // Now routed through ProcessLayer for consistent PID mapping + safe string decoding.
    OmegaCore.register("psx") { arg, _ in
        let filter = arg.trimmingCharacters(in: .whitespaces).lowercased()
        let meta   = ProcessLayer.shared.listAllWithMeta()
        var lines  = [_col([7,6,5,5,24], ["PID","PPID","UID","STA","NAME"]),
                      String(repeating: "-", count: 55)]
        for p in meta.entries {
            guard filter.isEmpty || p.name.lowercased().contains(filter) else { continue }
            lines.append(_col([7,6,5,5,24],
                [String(p.pid), String(p.ppid), String(p.uid),
                 p.status.rawValue, p.name]))
        }
        lines.append("  [source: \(meta.primarySource)  total=\(meta.entries.count)]")
        return .ok(lines.joined(separator: "\n"))
    }

    // taskinfo <pid|name>
    OmegaCore.register("taskinfo") { arg, _ in
        let a = arg.trimmingCharacters(in: .whitespaces)
        guard !a.isEmpty, let pid = _resolvePid(a) else {
            return .fail("usage: taskinfo <pid|name>")
        }
        // Try BSDINFO (blocked for most system daemons on iOS)
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
            // Fallback: proc_name works for most processes
            var nb = [CChar](repeating: 0, count: 256)
            proc_name(pid, &nb, 256)
            let s = String(cString: nb)
            return s.isEmpty ? (ProcessLayer.shared.entry(for: pid)?.name ?? "(pid \(pid))") : s
        }()
        var out = ["Process  : \(name) (\(pid))"]
        if bsdOk {
            out.append("PPID/UID : \(bsd.pbi_ppid) / \(bsd.pbi_uid)")
        } else {
            out.append("PPID/UID : -- (PROC_PIDTBSDINFO blocked by iOS for this process)")
        }
        var ti = proc_taskinfo()
        let tiGot = proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &ti,
                                  Int32(MemoryLayout<proc_taskinfo>.size))
        if tiGot > 0 {
            func mb(_ b: UInt64) -> String { String(format: "%.2f MB", Double(b) / 1_048_576) }
            out += [
                "Virtual  : \(mb(ti.pti_virtual_size))",
                "Resident : \(mb(ti.pti_resident_size))",
                "Footprint: \(mb(ti.pti_phys_footprint))",
                "Threads  : \(ti.pti_threadnum)",
                "Mach IPC : \(ti.pti_syscalls_mach) syscalls",
                "BSD  IPC : \(ti.pti_syscalls_unix) syscalls",
                "CPU time : \(String(format: "%.3fs", Double(ti.pti_total_user + ti.pti_total_system) / 1e9))",
            ]
        } else {
            out.append("mem/cpu  : -- (PROC_PIDTASKINFO blocked by iOS for this process)")
        }
        return .ok(out.joined(separator: "\n"))
    }

    // threadinfo <pid|name>
    OmegaCore.register("threadinfo") { arg, _ in
        let a = arg.trimmingCharacters(in: .whitespaces)
        guard !a.isEmpty, let pid = _resolvePid(a) else {
            return .fail("usage: threadinfo <pid|name>")
        }
        var ti = proc_taskinfo()
        guard proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &ti,
                           Int32(MemoryLayout<proc_taskinfo>.size)) > 0 else {
            var nb = [CChar](repeating: 0, count: 256)
            proc_name(pid, &nb, 256)
            let nm = String(cString: nb)
            return .ok("threadinfo \(pid) [\(nm.isEmpty ? "unknown" : nm)]\n  iOS blocks PROC_PIDTASKINFO for system/daemon processes\n  (thread enumeration requires task_for_pid which is restricted)")
        }
        var lines = ["Threads of \(_pidName(pid)) (\(pid)) — count: \(ti.pti_threadnum)"]
        for i in 0..<min(Int(ti.pti_threadnum), 64) {
            var th = proc_threadinfo()
            if proc_pidinfo(pid, PROC_PIDTHREADINFO, UInt64(i), &th,
                            Int32(MemoryLayout<proc_threadinfo>.size)) > 0 {
                let st: String
                switch th.pth_run_state {
                case TH_STATE_RUNNING:         st = "RUNNING "
                case TH_STATE_STOPPED:         st = "STOPPED "
                case TH_STATE_WAITING:         st = "WAITING "
                case TH_STATE_UNINTERRUPTIBLE: st = "UNINT   "
                case TH_STATE_HALTED:          st = "HALTED  "
                default:                       st = "UNKNOWN "
                }
                lines.append(String(format: "  [%02d] id=%-8u %@ pri=%-3d cpu=%.3fs",
                    i, th.pth_thread_id, st, th.pth_priority,
                    Double(th.pth_user_time + th.pth_system_time) / 1e9))
            }
        }
        return .ok(lines.joined(separator: "\n"))
    }
}
