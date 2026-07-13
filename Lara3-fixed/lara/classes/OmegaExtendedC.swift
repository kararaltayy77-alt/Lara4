//
//  OmegaExtendedC.swift
//  lara — Extended shell: ports, process control, kbase, kmap
//
import Foundation
import Darwin

func _registerPorts() {

    OmegaCore.register("ports") { arg, _ in
        let a = arg.trimmingCharacters(in: .whitespaces)
        guard !a.isEmpty, let pid = _resolvePid(a) else { return .fail("ports: usage: ports <pid|name>") }
        var ti = proc_taskinfo()
        guard proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &ti,
                           Int32(MemoryLayout<proc_taskinfo>.size)) > 0 else {
            var nb = [CChar](repeating: 0, count: 256)
            proc_name(pid, &nb, 256)
            let nm = String(cString: nb)
            return .ok("ports \(pid) [\(nm.isEmpty ? "unknown" : nm)]\n  iOS blocks PROC_PIDTASKINFO for system/daemon processes\n  Mach port enumeration requires task_for_pid which is restricted to the owning process.")
        }
        var lines = [
            "Mach ports — \(_pidName(pid)) (\(pid))",
            String(format: "  threads        : %u",   ti.pti_threadnum),
            String(format: "  msg sent       : %llu", ti.pti_messages_sent),
            String(format: "  msg recv       : %llu", ti.pti_messages_received),
            String(format: "  mach syscalls  : %u",   ti.pti_syscalls_mach),
            String(format: "  bsd  syscalls  : %u",   ti.pti_syscalls_unix),
        ]
        let fdSz = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
        if fdSz > 0 {
            var fds = [proc_fdinfo](repeating: proc_fdinfo(),
                                    count: Int(fdSz) / MemoryLayout<proc_fdinfo>.size + 4)
            let got = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, &fds, fdSz)
            if got > 0 {
                let n = Int(got) / MemoryLayout<proc_fdinfo>.size
                let machFDs = (0..<n).filter { fds[$0].proc_fdtype == UInt32(PROX_FDTYPE_MACH_MSG) }
                lines.append("  mach port FDs  : \(machFDs.count)")
                machFDs.prefix(16).forEach { i in
                    lines.append(String(format: "    fd=%d", fds[i].proc_fd))
                }
            }
        }
        return .ok(lines.joined(separator: "\n"))
    }

    OmegaCore.register("portinfo") { arg, _ in
        guard let port = _parseAddrE(arg) else { return .fail("portinfo: usage: portinfo <port_hex>") }
        return .ok(String(format:
            "portinfo — port 0x%llX\n  Full inspection requires task_for_pid.\n  Use 'ports <pid>' for per-process stats.",
            port))
    }

    OmegaCore.register("sendmsg") { _, _ in .fail("sendmsg: not available in shell — use rc framework") }
    OmegaCore.register("recvmsg") { _, _ in .fail("recvmsg: not available in shell — use rc framework") }
}

func _registerProcCtl() {

    OmegaCore.register("suspend") { arg, _ in
        let a = arg.trimmingCharacters(in: .whitespaces)
        guard !a.isEmpty, let pid = _resolvePid(a) else { return .fail("suspend: usage: suspend <pid|name>") }
        if kill(pid, SIGSTOP) == 0 { return .ok("suspend: SIGSTOP -> \(_pidName(pid)) (\(pid))") }
        return .fail("suspend: \(String(cString: strerror(errno)))")
    }

    OmegaCore.register("resume") { arg, _ in
        let a = arg.trimmingCharacters(in: .whitespaces)
        guard !a.isEmpty, let pid = _resolvePid(a) else { return .fail("resume: usage: resume <pid|name>") }
        if kill(pid, SIGCONT) == 0 { return .ok("resume: SIGCONT -> \(_pidName(pid)) (\(pid))") }
        return .fail("resume: \(String(cString: strerror(errno)))")
    }

    OmegaCore.register("kill") { arg, _ in
        let parts = arg.split(separator: " ").map { String($0) }
        guard !parts.isEmpty, let pid = _resolvePid(parts[0]) else {
            return .fail("kill: usage: kill <pid|name> [signal]")
        }
        let sig = parts.count > 1 ? Int32(parts[1]) ?? SIGKILL : SIGKILL
        if kill(pid, sig) == 0 { return .ok("kill: signal \(sig) -> \(_pidName(pid)) (\(pid))") }
        return .fail("kill: \(String(cString: strerror(errno)))")
    }

    OmegaCore.register("spawn") { arg, _ in
        let parts = arg.trimmingCharacters(in: .whitespaces).split(separator: " ").map { String($0) }
        guard let path = parts.first, !path.isEmpty else { return .fail("spawn: usage: spawn <path> [args...]") }
        guard FileManager.default.fileExists(atPath: path) else {
            return .fail("spawn: \(path): no such file")
        }
        var argv: [UnsafeMutablePointer<CChar>?] = parts.map { strdup($0) } + [nil]
        var pid2: pid_t = -1
        let err = posix_spawn(&pid2, path, nil, nil, &argv, environ)
        argv.compactMap { $0 }.forEach { free($0) }
        return err == 0
            ? .ok("spawn: launched \(path) as pid \(pid2)")
            : .fail("spawn: \(String(cString: strerror(err)))")
    }

    OmegaCore.register("inject") { arg, mgr in
        let parts = arg.split(separator: " ", maxSplits: 1).map { String($0) }
        guard parts.count >= 2, let pid = _resolvePid(parts[0]) else {
            return .fail("inject: usage: inject <pid|name> <dylib_path>")
        }
        let dylib = parts[1]
        guard FileManager.default.fileExists(atPath: dylib) else {
            return .fail("inject: \(dylib): not found")
        }
        guard mgr.dsready else { return .fail("inject: kernel r/w not ready") }
        return .fail("inject: open rc session to \(_pidName(pid)) (\(pid)) then run: dlopen \(dylib)")
    }
}

func _registerKernelEx() {

    OmegaCore.register("kbase") { _, mgr in
        guard mgr.dsready else { return .fail("kbase: exploit not ready") }
        return .ok(String(format: """
Kernel Base  : 0x%016llX
Kernel Slide : 0x%016llX
Static Base  : 0x%016llX
""",
            mgr.kernbase, mgr.kernslide, mgr.kernbase &- mgr.kernslide))
    }

    // kmap — kernel allproc walk (low-level view with kernel addresses)
    // Bug fixed:
    //   1. String(bytes:encoding:.utf8) ?? "(??)" silently dropped non-UTF8 names
    //   2. uid offset 0xD0 was hardcoded without verification — now read from bsdinfo
    //   3. Results were independent of ProcessLayer — now uses ProcessLayer as primary
    //      and only falls back to raw walk if exploit is ready but ProcessLayer returns 0
    OmegaCore.register("kmap") { _, mgr in
        guard mgr.dsready else { return .fail("kmap: exploit not ready") }

        // Use ProcessLayer pipeline — ensures consistent results with ps/proc-walk
        let meta  = ProcessLayer.shared.listAllWithMeta()
        let procs = meta.entries

        if !procs.isEmpty {
            var lines = [
                "Kernel process map — via ProcessLayer (\(meta.primarySource))",
                _col([18,6,6,4,20], ["SOURCE","PID","UID","STA","NAME"]),
                String(repeating: "-", count: 60),
            ]
            for p in procs {
                lines.append(_col([18,6,6,4,20],
                    [p.source.rawValue, String(p.pid), String(p.uid),
                     p.status.rawValue, p.name]))
            }
            lines.append("  [total=\(procs.count)  FULL=\(meta.fullCount)  PARTIAL=\(meta.partialCount)  BLOCKED=\(meta.blockedCount)  iOS-access=\(meta.completenessPercent)%]")
            return .ok(lines.joined(separator: "\n"))
        }

        // Raw kernel walk fallback (when ProcessLayer returns 0 — should be rare)
        // String decoding fixed: safeKernelBytes tries UTF-8 then Latin-1, never silently ""
        var proc_ptr = ds_get_our_proc()
        var lines = [
            "Kernel process map — raw walk (ProcessLayer returned 0)",
            _col([18,6,20], ["KADDR","PID","NAME"]),
            String(repeating: "-", count: 48),
        ]
        var seen = Set<UInt64>()
        var walked = 0
        while proc_ptr != 0, !seen.contains(proc_ptr), walked < 1024 {
            seen.insert(proc_ptr); walked += 1
            let pid = Int32(mgr.kread32(address: proc_ptr + 0x68))
            guard pid > 0 else { proc_ptr = mgr.kread64(address: proc_ptr + 0x8); continue }
            var nameBuf = [UInt8](repeating: 0, count: 17)
            for i in 0..<16 {
                let b = ds_kread8(proc_ptr + 0x268 + UInt64(i))
                if b == 0 { break }
                nameBuf[i] = b
            }
            // Safe string: UTF-8 → Latin-1, never silently empty for non-ASCII bytes
            let nameSlice = Array(nameBuf.prefix(while: { $0 != 0 }))
            let name: String
            if let s = String(bytes: nameSlice, encoding: .utf8), !s.isEmpty { name = s }
            else if let s = String(bytes: nameSlice, encoding: .isoLatin1), !s.isEmpty { name = s + "⚠︎" }
            else { name = "(pid \(pid))" }
            lines.append(_col([18,6,20],
                [String(format: "0x%016llX", proc_ptr), String(pid), name]))
            proc_ptr = mgr.kread64(address: proc_ptr + 0x8)
        }
        return .ok(lines.joined(separator: "\n"))
    }
}
