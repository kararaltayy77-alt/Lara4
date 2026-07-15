//
//  OmegaExtendedH.swift
//  lara — Kernel Object Explorer
//  fd-info, socket-info, socket-dump, socket-diff
//

import Foundation
import Darwin

// MARK: – Single Source of Truth: FD Resolution Result

private struct FdResolution {
    let pid: Int32
    let fd: Int32
    let procPtr: UInt64
    let fdPtr: UInt64
    let ofilesPtr: UInt64
    let fileprocPtr: UInt64
    let fileglobPtr: UInt64
    let fg_flag: UInt32
    let fg_data: UInt64
    let fg_ops: UInt64
    let fg_type: FgType
}

private enum FgType: Equatable {
    case socket
    case vnode
    case other(UInt32)
    case unknown
}

// MARK: – Socket Snapshot Store

private struct SocketSnapshot: Codable {
    let timestamp: Date
    let data: Data
}

private final class SocketSnapshotStore {
    static let shared = SocketSnapshotStore()
    private var snapshots: [String: SocketSnapshot] = [:]
    private let lock = NSLock()

    func save(pid: Int32, fd: Int, data: Data) {
        lock.lock(); defer { lock.unlock() }
        snapshots[String(format: "%d:%d", pid, fd)] = SocketSnapshot(timestamp: Date(), data: data)
    }
    func load(pid: Int32, fd: Int) -> (Date, Data)? {
        lock.lock(); defer { lock.unlock() }
        guard let snap = snapshots[String(format: "%d:%d", pid, fd)] else { return nil }
        return (snap.timestamp, snap.data)
    }
}

// MARK: – Kernel Read Helpers

private func _kreadPtrH(_ addr: UInt64) -> UInt64 {
    guard addr != 0, ds_isvalid(addr) else { return 0 }
    return ds_kreadptr(addr)
}

private func _kread64H(_ addr: UInt64) -> UInt64 {
    guard addr != 0, ds_isvalid(addr) else { return 0 }
    return ds_kread64(addr)
}

private func _kread32H(_ addr: UInt64) -> UInt32 {
    guard addr != 0, ds_isvalid(addr) else { return 0 }
    return ds_kread32(addr)
}

// MARK: – PID Resolution (Single Source of Truth)

private func _resolvePidH(_ s: String) -> Int32? {
    let t = s.trimmingCharacters(in: .whitespaces)
    if let n = Int32(t) { return n }
    return ProcessLayer.shared.find(matching: t.lowercased()).first?.pid
}

// MARK: – Proc Resolution (Single Source of Truth)
// Resolves PID to kernel proc pointer.
// For current process: uses ds_get_our_proc() directly (fast & reliable).
// For other processes: walks the allproc list.

private func _resolveProcPtr(pid: Int32) -> UInt64? {
    let ourProc = ds_get_our_proc()
    guard ourProc != 0 else { return nil }

    // Fast path: if this is our own process, return directly
    let procPPidOff = UInt64(off_proc_p_pid)
    let ourPid = Int32(bitPattern: ds_kread32(ourProc + procPPidOff))
    if ourPid == pid {
        return ourProc
    }

    // Slow path: walk the allproc list for other processes
    let procPListLeNextOff = UInt64(off_proc_p_list_le_next)
    var procPtr: UInt64 = 0
    var ptr = ourProc
    var seen = Set<UInt64>()
    while ptr != 0 && !seen.contains(ptr) {
        seen.insert(ptr)
        let p_pid = Int32(bitPattern: ds_kread32(ptr + procPPidOff))
        if p_pid == pid { procPtr = ptr; break }
        ptr = ds_kreadptr(ptr + procPListLeNextOff)
    }
    return procPtr != 0 ? procPtr : nil
}

// MARK: – FD Resolution (Single Source of Truth)
// Resolves (pid, fd) to full fd structure. ALL commands use this.

private func _resolveFd(pid: Int32, fd: Int32, mgr: laramgr) -> FdResolution? {
    guard mgr.dsready else { return nil }

    guard let procPtr = _resolveProcPtr(pid: pid) else { return nil }

    let procPFdOff = UInt64(off_proc_p_fd)
    let filedescFdOfilesOff = UInt64(off_filedesc_fd_ofiles)
    let fileprocFpGlobOff = UInt64(off_fileproc_fp_glob)
    let fileglobFgDataOff = UInt64(off_fileglob_fg_data)
    let vnodeVUsecountOff = UInt64(off_vnode_v_usecount)
    let vnodeVIocountOff = UInt64(off_vnode_v_iocount)

    let fdPtr = _kreadPtrH(procPtr + procPFdOff)
    guard fdPtr != 0 else { return nil }

    let ofilesPtr = _kreadPtrH(fdPtr + filedescFdOfilesOff)
    guard ofilesPtr != 0 else { return nil }

    let fileprocPtr = _kreadPtrH(ofilesPtr + UInt64(fd) * 8)
    guard fileprocPtr != 0 else { return nil }

    let fileglobPtr = _kreadPtrH(fileprocPtr + fileprocFpGlobOff)
    guard fileglobPtr != 0 else { return nil }

    let fg_flag = _kread32H(fileglobPtr + 0x10)
    let fg_data = _kreadPtrH(fileglobPtr + fileglobFgDataOff)
    let fg_ops  = _kreadPtrH(fileglobPtr + 0x28)

    let fg_type: FgType
    if fg_data != 0 {
        let so_type = _kread32H(fg_data + 0x04)
        if so_type >= 1 && so_type <= 10 {
            fg_type = .socket
        } else {
            let v_usecount = _kread32H(fg_data + vnodeVUsecountOff)
            let v_iocount  = _kread32H(fg_data + vnodeVIocountOff)
            if v_usecount > 0 && v_usecount < 0x10000 && v_iocount > 0 && v_iocount < 0x10000 {
                fg_type = .vnode
            } else {
                fg_type = .other(fg_flag)
            }
        }
    } else {
        fg_type = .unknown
    }

    return FdResolution(
        pid: pid, fd: fd,
        procPtr: procPtr, fdPtr: fdPtr, ofilesPtr: ofilesPtr,
        fileprocPtr: fileprocPtr, fileglobPtr: fileglobPtr,
        fg_flag: fg_flag, fg_data: fg_data, fg_ops: fg_ops,
        fg_type: fg_type
    )
}

// MARK: – Socket Address Resolution (Single Source of Truth)

private func _resolveSocketAddr(pid: Int32, fd: Int32, mgr: laramgr) -> UInt64? {
    guard let res = _resolveFd(pid: pid, fd: fd, mgr: mgr) else { return nil }
    guard res.fg_type == .socket, res.fg_data != 0 else { return nil }
    return res.fg_data
}

// MARK: – Address Parser

private func _parseAddrH(_ s: String) -> UInt64? {
    let t = s.trimmingCharacters(in: .whitespaces)
    let c = (t.hasPrefix("0x") || t.hasPrefix("0X")) ? String(t.dropFirst(2)) : t
    return UInt64(c, radix: 16)
}

// MARK: – fd-info

private func _fdInfo(pid: Int32, fd: Int32, mgr: laramgr) -> String? {
    guard let res = _resolveFd(pid: pid, fd: fd, mgr: mgr) else { return nil }

    let fg_typeStr: String
    switch res.fg_type {
    case .socket: fg_typeStr = "DTYPE_SOCKET"
    case .vnode: fg_typeStr = "DTYPE_VNODE"
    case .other(let flag): fg_typeStr = String(format: "DTYPE_OTHER(%u)", flag)
    case .unknown: fg_typeStr = "UNKNOWN"
    }

    var lines = [
        String(format: "PID             : %d", res.pid),
        String(format: "FD              : %d", res.fd),
        String(format: "proc            : 0x%016llx", res.procPtr),
        String(format: "fdPtr           : 0x%016llx", res.fdPtr),
        String(format: "ofilesPtr       : 0x%016llx", res.ofilesPtr),
        String(format: "fileproc        : 0x%016llx", res.fileprocPtr),
        String(format: "fileglob        : 0x%016llx", res.fileglobPtr),
        String(format: "fg_type         : %@", fg_typeStr),
        String(format: "fg_flag         : 0x%08x", res.fg_flag),
        String(format: "fg_ops          : 0x%016llx", res.fg_ops),
        String(format: "fg_data         : 0x%016llx", res.fg_data),
    ]
    if res.fg_type == .socket && res.fg_data != 0 {
        lines.append("")
        lines.append("Socket structure detected — use 'socket-info <pid> <fd>' for full decode.")
    }
    let nl = "\n"
    return lines.joined(separator: nl)
}

// MARK: – socket-info

private func _socketInfo(pid: Int32, fd: Int32, mgr: laramgr) -> String? {
    guard let socketAddr = _resolveSocketAddr(pid: pid, fd: fd, mgr: mgr), socketAddr != 0 else {
        return nil
    }
    return _socketInfoFromAddr(socketAddr: socketAddr)
}

private func _socketInfoFromAddr(socketAddr: UInt64) -> String? {
    guard socketAddr != 0, ds_isvalid(socketAddr) else { return nil }

    let socketSoProtoOff = UInt64(off_socket_so_proto)
    let socketSoUsecntOff = UInt64(off_socket_so_usecount)

    let so_type     = _kread32H(socketAddr + 0x04)
    let so_state    = _kread32H(socketAddr + 0x08)
    let so_options  = _kread32H(socketAddr + 0x10)
    let so_proto    = _kreadPtrH(socketAddr + socketSoProtoOff)
    let so_pcb      = _kreadPtrH(socketAddr + 0x80)
    let so_usecount = _kread32H(socketAddr + socketSoUsecntOff)
    let so_rcv_cc    = _kread32H(socketAddr + 0xA0)
    let so_rcv_hiwat = _kread32H(socketAddr + 0xA8)
    let so_snd_cc    = _kread32H(socketAddr + 0x120)
    let so_snd_hiwat = _kread32H(socketAddr + 0x128)

    let typeNames = [1: "SOCK_STREAM", 2: "SOCK_DGRAM", 3: "SOCK_RAW",
                     4: "SOCK_RDM", 5: "SOCK_SEQPACKET", 6: "SOCK_DCCP", 10: "SOCK_PACKET"]
    let typeStr = typeNames[Int(so_type)] ?? String(format: "UNKNOWN(%d)", so_type)

    var stateFlags: [String] = []
    if (so_state & 0x001) != 0 { stateFlags.append("SS_NOFDREF") }
    if (so_state & 0x002) != 0 { stateFlags.append("SS_ISCONNECTED") }
    if (so_state & 0x004) != 0 { stateFlags.append("SS_ISCONNECTING") }
    if (so_state & 0x008) != 0 { stateFlags.append("SS_ISDISCONNECTING") }
    if (so_state & 0x010) != 0 { stateFlags.append("SS_CANTSENDMORE") }
    if (so_state & 0x020) != 0 { stateFlags.append("SS_CANTRCVMORE") }
    if (so_state & 0x040) != 0 { stateFlags.append("SS_RCVATMARK") }
    if (so_state & 0x080) != 0 { stateFlags.append("SS_PRIV") }
    if (so_state & 0x100) != 0 { stateFlags.append("SS_NBIO") }
    if (so_state & 0x200) != 0 { stateFlags.append("SS_ASYNC") }
    if (so_state & 0x400) != 0 { stateFlags.append("SS_ISCONFIRMING") }
    if (so_state & 0x800) != 0 { stateFlags.append("SS_INCOMP") }
    if (so_state & 0x1000) != 0 { stateFlags.append("SS_COMP") }
    if (so_state & 0x2000) != 0 { stateFlags.append("SS_ISDISCONNECTED") }
    let stateStr = stateFlags.isEmpty ? "0" : stateFlags.joined(separator: " | ")

    let lines = [
        String(format: "socket          : 0x%016llx", socketAddr),
        String(format: "so_type         : %@ (%d)", typeStr, so_type),
        String(format: "so_state        : 0x%08x (%@)", so_state, stateStr),
        String(format: "so_options      : 0x%08x", so_options),
        String(format: "so_proto        : 0x%016llx", so_proto),
        String(format: "so_pcb          : 0x%016llx", so_pcb),
        String(format: "so_usecount     : %d", so_usecount),
        String(format: "so_rcv          : cc=%d hiwat=%d", so_rcv_cc, so_rcv_hiwat),
        String(format: "so_snd          : cc=%d hiwat=%d", so_snd_cc, so_snd_hiwat),
    ]
    let nl = "\n"
    return lines.joined(separator: nl)
}

// MARK: – socket-dump

private func _socketDump(pid: Int32, fd: Int32, mgr: laramgr) -> String? {
    guard let socketAddr = _resolveSocketAddr(pid: pid, fd: fd, mgr: mgr), socketAddr != 0 else {
        return nil
    }
    var lines: [String] = []
    for off in stride(from: 0, to: 0x200, by: 16) {
        var vals: [UInt64] = []
        for j in 0..<2 {
            vals.append(_kread64H(socketAddr + UInt64(off + j * 8)))
        }
        lines.append(String(format: "0x%03X: %016llx %016llx", off, vals[0], vals[1]))
    }
    let nl = "\n"
    return lines.joined(separator: nl)
}

// MARK: – Registration

func registerKernelObjectExplorer() {

    OmegaCore.register("fd-info") { arg, mgr in
        guard mgr.dsready else { return .fail("fd-info: kernel r/w not ready") }
        let parts = arg.split(separator: " ").map { String($0) }
        guard parts.count >= 2,
              let pid = _resolvePidH(parts[0]),
              let fd = Int32(parts[1]) else {
            return .fail("fd-info: usage — fd-info <pid|name> <fd>")
        }
        guard let out = _fdInfo(pid: pid, fd: fd, mgr: mgr) else {
            return .fail(String(format: "fd-info: failed to resolve fd %d for pid %d. Check: kernel r/w ready? offsets correct? process exists?", fd, pid))
        }
        return .ok(out)
    }

    OmegaCore.register("socket-info") { arg, mgr in
        guard mgr.dsready else { return .fail("socket-info: kernel r/w not ready") }
        let parts = arg.split(separator: " ").map { String($0) }
        guard parts.count >= 2,
              let pid = _resolvePidH(parts[0]),
              let fd = Int32(parts[1]) else {
            return .fail("socket-info: usage — socket-info <pid|name> <fd>")
        }
        guard let out = _socketInfo(pid: pid, fd: fd, mgr: mgr) else {
            return .fail(String(format: "socket-info: fd %d is not a socket or not found for pid %d. Use fd-info %d %d to verify fd type.", fd, pid, pid, fd))
        }
        return .ok(out)
    }

    OmegaCore.register("socket-info-addr") { arg, mgr in
        guard mgr.dsready else { return .fail("socket-info-addr: kernel r/w not ready") }
        guard let addr = _parseAddrH(arg) else {
            return .fail("socket-info-addr: usage — socket-info-addr <socket_addr_hex>")
        }
        guard let out = _socketInfoFromAddr(socketAddr: addr) else {
            return .fail(String(format: "socket-info-addr: invalid socket address 0x%llx", addr))
        }
        return .ok(out)
    }

    OmegaCore.register("socket-dump") { arg, mgr in
        guard mgr.dsready else { return .fail("socket-dump: kernel r/w not ready") }
        let parts = arg.split(separator: " ").map { String($0) }
        guard parts.count >= 2,
              let pid = _resolvePidH(parts[0]),
              let fd = Int32(parts[1]) else {
            return .fail("socket-dump: usage — socket-dump <pid|name> <fd>")
        }
        guard let out = _socketDump(pid: pid, fd: fd, mgr: mgr) else {
            return .fail(String(format: "socket-dump: fd %d is not a socket or not found for pid %d", fd, pid))
        }
        return .ok(out)
    }

    OmegaCore.register("socket-save") { arg, mgr in
        guard mgr.dsready else { return .fail("socket-save: kernel r/w not ready") }
        let parts = arg.split(separator: " ").map { String($0) }
        guard parts.count >= 2,
              let pid = _resolvePidH(parts[0]),
              let fd = Int(parts[1]) else {
            return .fail("socket-save: usage — socket-save <pid|name> <fd>")
        }
        guard let socketAddr = _resolveSocketAddr(pid: pid, fd: Int32(fd), mgr: mgr), socketAddr != 0 else {
            return .fail(String(format: "socket-save: fd %d is not a socket for pid %d", fd, pid))
        }
        var data = Data()
        for off in stride(from: 0, to: 0x200, by: 8) {
            var val = _kread64H(socketAddr + UInt64(off))
            data.append(Data(bytes: &val, count: 8))
        }
        SocketSnapshotStore.shared.save(pid: pid, fd: fd, data: data)
        return .ok(String(format: "socket-save: pid=%d fd=%d  socket@0x%llx  saved %d bytes", pid, fd, socketAddr, data.count))
    }

    OmegaCore.register("socket-diff") { arg, mgr in
        guard mgr.dsready else { return .fail("socket-diff: kernel r/w not ready") }
        let parts = arg.split(separator: " ").map { String($0) }
        guard parts.count >= 2,
              let pid = _resolvePidH(parts[0]),
              let fd = Int(parts[1]) else {
            return .fail("socket-diff: usage — socket-diff <pid|name> <fd>")
        }
        guard let (timestamp, before) = SocketSnapshotStore.shared.load(pid: pid, fd: fd) else {
            return .fail(String(format: "socket-diff: no snapshot for pid=%d fd=%d. Run 'socket-save <pid> <fd>' first.", pid, fd))
        }
        guard let socketAddr = _resolveSocketAddr(pid: pid, fd: Int32(fd), mgr: mgr), socketAddr != 0 else {
            return .fail(String(format: "socket-diff: fd %d is not a socket for pid %d", fd, pid))
        }
        var after = Data()
        for off in stride(from: 0, to: 0x200, by: 8) {
            var val = _kread64H(socketAddr + UInt64(off))
            after.append(Data(bytes: &val, count: 8))
        }
        guard before.count == after.count else {
            return .fail("socket-diff: size mismatch")
        }
        var diffs: [(Int, UInt64, UInt64)] = []
        for i in stride(from: 0, to: before.count, by: 8) {
            let b = before.withUnsafeBytes { $0.load(fromByteOffset: i, as: UInt64.self) }
            let a = after.withUnsafeBytes { $0.load(fromByteOffset: i, as: UInt64.self) }
            if b != a { diffs.append((i, b, a)) }
        }
        if diffs.isEmpty {
            return .ok("socket-diff: pid=" + String(pid) + " fd=" + String(fd) + "  no changes since " + String(describing: timestamp))
        }
        var lines = [
            String(format: "socket-diff: pid=%d fd=%d  socket@0x%llx", pid, fd, socketAddr),
            "  saved: " + String(describing: timestamp),
            String(format: "  changed offsets: %d", diffs.count),
            ""
        ]
        for (off, b, a) in diffs {
            lines.append(String(format: "Offset 0x%03X:", off))
            lines.append(String(format: "  before: 0x%016llx", b))
            lines.append(String(format: "  after : 0x%016llx", a))
            lines.append("")
        }
        let nl = "\n"
        return .ok(lines.joined(separator: nl))
    }
}
