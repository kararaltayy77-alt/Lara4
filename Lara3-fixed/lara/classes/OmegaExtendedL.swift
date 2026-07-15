//
//  OmegaExtendedL.swift
//  lara — Memory Explorer
//  kstruct, ksearch, xref
//

import Foundation
import Darwin

private func _parseAddrL(_ s: String) -> UInt64? {
    let t = s.trimmingCharacters(in: .whitespaces)
    let c = (t.hasPrefix("0x") || t.hasPrefix("0X")) ? String(t.dropFirst(2)) : t
    return UInt64(c, radix: 16)
}

private func _kreadPtrL(_ addr: UInt64) -> UInt64 {
    guard addr != 0, ds_isvalid(addr) else { return 0 }
    return ds_kreadptr(addr)
}

private func _kread64L(_ addr: UInt64) -> UInt64 {
    guard addr != 0, ds_isvalid(addr) else { return 0 }
    return ds_kread64(addr)
}

private func _kread32L(_ addr: UInt64) -> UInt32 {
    guard addr != 0, ds_isvalid(addr) else { return 0 }
    return ds_kread32(addr)
}

private func _kreadCStrL(_ addr: UInt64, max: Int = 64) -> String {
    guard addr != 0, ds_isvalid(addr) else { return "" }
    var buf = [UInt8](repeating: 0, count: max + 1)
    for i in 0..<max {
        let b = ds_kread8(addr + UInt64(i))
        if b == 0 { break }
        buf[i] = b
    }
    let data = Data(buf.prefix(while: { $0 != 0 }))
    return String(data: data, encoding: .utf8) ?? String(data: data, encoding: .ascii) ?? ""
}

// MARK: – kstruct

private func _kstruct(type: String, addr: UInt64) -> String? {
    guard addr != 0, ds_isvalid(addr) else { return nil }
    let t = type.lowercased()
    var lines = [String(format: "kstruct %@ @ 0x%016llx", type, addr), ""]

    switch t {
    case "socket":
        let fields: [(UInt64, String, String)] = [
            (0x00, "so_list.le_next", "ptr"), (0x08, "so_list.le_prev", "ptr"),
            (0x10, "so_type/family", "u32"), (0x18, "so_state", "u32"),
            (0x20, "so_pcb", "ptr"), (0x28, "so_proto", "ptr"),
            (0x30, "so_head", "ptr"), (0x38, "so_incomp", "ptr"),
            (0x40, "so_comp", "ptr"), (0x48, "so_qlen/limit", "u16"),
            (0x50, "so_options", "u32"), (0x58, "so_cred", "ptr"),
            (0x60, "so_label", "ptr"), (0x68, "so_gencnt", "u64"),
            (0x70, "so_flags", "u32"), (0x74, "so_usecount", "u32"),
            (0x78, "so_retaincnt", "u32"), (0x7C, "so_filter", "u32"),
            (0x80, "so_rcv.sb_cc", "u32"), (0x88, "so_rcv.sb_hiwat", "u32"),
            (0x90, "so_rcv.sb_mbcnt", "u32"), (0x98, "so_rcv.sb_mbmax", "u32"),
            (0xA0, "so_rcv.sb_mtx", "ptr"), (0xA8, "so_rcv.sb_tstmp", "ptr"),
            (0xB0, "so_snd.sb_cc", "u32"), (0xB8, "so_snd.sb_hiwat", "u32"),
            (0xC0, "so_snd.sb_mbcnt", "u32"), (0xC8, "so_snd.sb_mbmax", "u32"),
            (0xD0, "so_snd lowat/flags", "u32"), (0xD8, "so_snd.sb_sel", "ptr"),
            (0xE0, "so_snd.sb_mtx", "ptr"), (0xE8, "so_snd.sb_tstmp", "ptr"),
            (0xF0, "so_upcall/arg", "ptr"), (0xF8, "so_cred2", "ptr"),
            (0x100, "so_label2", "ptr"), (0x108, "so_gencnt2", "u64"),
            (0x110, "so_flags2", "u32"), (0x118, "so_usecount2", "u32"),
            (0x120, "so_retaincnt2", "u32"), (0x128, "so_filter2", "u32"),
            (0x130, "so_kern_ctl", "ptr"), (0x138, "so_acc_sas", "ptr"),
            (0x140, "so_acc_sas_sz", "u64"), (0x148, "so_ev_pcb", "ptr"),
            (0x150, "so_ev_pcbarg", "ptr"), (0x158, "so_ev_state", "u32"),
            (0x160, "so_ev_rcvpending", "u32"), (0x168, "so_traffic_mgt", "ptr"),
            (0x170, "so_netsvctype", "u32"), (0x178, "so_resv", "u64"),
            (0x180, "so_extended", "ptr"), (0x188, "so_waitq", "ptr"),
            (0x190, "so_waitq_link", "ptr"), (0x198, "so_zone", "ptr"),
        ]
        for (off, name, kind) in fields {
            let val = _kread64L(addr + off)
            if kind == "u32" {
                lines.append(String(format: "0x%03X %-24s 0x%08x  (%@)", off, name, UInt32(truncatingIfNeeded: val), kind))
            } else if kind == "u16" {
                lines.append(String(format: "0x%03X %-24s 0x%04x      (%@)", off, name, UInt16(truncatingIfNeeded: val), kind))
            } else {
                lines.append(String(format: "0x%03X %-24s 0x%016llx (%@)", off, name, val, kind))
            }
        }

    case "proc":
        let fields: [(UInt64, String, String)] = [
            (0x00, "p_list.le_next", "ptr"), (0x08, "p_list.le_prev", "ptr"),
            (0x10, "p_pid", "u32"), (0x14, "p_pgrpid", "u32"),
            (0x18, "p_task", "ptr"), (0x20, "p_pptr", "ptr"),
            (0x28, "p_pgrp", "ptr"), (0x30, "p_uid", "u32"),
            (0x34, "p_gid", "u32"), (0x38, "p_ruid", "u32"),
            (0x3C, "p_rgid", "u32"), (0x40, "p_svuid", "u32"),
            (0x44, "p_svgid", "u32"), (0x48, "p_comm", "str16"),
            (0x58, "p_name", "ptr"), (0x60, "p_fd", "ptr"),
            (0x68, "p_csflags", "u32"), (0x6C, "p_flag", "u32"),
        ]
        for (off, name, kind) in fields {
            if kind == "str16" {
                let s = _kreadCStrL(addr + off, max: 16)
                lines.append(String(format: "0x%03X %-24s %@          (%@)", off, name, s.isEmpty ? "(null)" : s, kind))
            } else if kind == "u32" {
                let val = _kread32L(addr + off)
                lines.append(String(format: "0x%03X %-24s 0x%08x  (%@)", off, name, val, kind))
            } else {
                let val = _kread64L(addr + off)
                lines.append(String(format: "0x%03X %-24s 0x%016llx (%@)", off, name, val, kind))
            }
        }

    case "task":
        let fields: [(UInt64, String, String)] = [
            (0x00, "ref_count", "u32"), (0x08, "active", "u32"),
            (0x10, "map", "ptr"), (0x18, "threads_next", "ptr"),
            (0x20, "itk_space", "ptr"), (0x28, "itk_self", "ptr"),
            (0x30, "itk_sself", "ptr"), (0x38, "itk_bootstrap", "ptr"),
            (0x40, "itk_registered", "ptr"), (0x48, "itk_host", "ptr"),
            (0x50, "itk_gssd", "ptr"), (0x58, "itk_task_access", "ptr"),
            (0x60, "itk_resume", "u32"), (0x68, "exc_guard", "u32"),
        ]
        for (off, name, kind) in fields {
            if kind == "u32" {
                let val = _kread32L(addr + off)
                lines.append(String(format: "0x%03X %-24s 0x%08x  (%@)", off, name, val, kind))
            } else {
                let val = _kread64L(addr + off)
                lines.append(String(format: "0x%03X %-24s 0x%016llx (%@)", off, name, val, kind))
            }
        }

    case "ucred":
        let fields: [(UInt64, String, String)] = [
            (0x00, "cr_ref", "u32"), (0x04, "cr_pad", "u32"),
            (0x08, "cr_uid", "u32"), (0x0C, "cr_ruid", "u32"),
            (0x10, "cr_svuid", "u32"), (0x14, "cr_ngroups", "u32"),
            (0x18, "cr_groups[0]", "u32"), (0x1C, "cr_rgid", "u32"),
            (0x20, "cr_svgid", "u32"), (0x24, "cr_gmuid", "u32"),
            (0x28, "cr_flags", "u32"), (0x30, "cr_label", "ptr"),
        ]
        for (off, name, kind) in fields {
            if kind == "u32" {
                let val = _kread32L(addr + off)
                lines.append(String(format: "0x%03X %-24s 0x%08x  (%@)", off, name, val, kind))
            } else {
                let val = _kread64L(addr + off)
                lines.append(String(format: "0x%03X %-24s 0x%016llx (%@)", off, name, val, kind))
            }
        }

    case "vnode":
        let fields: [(UInt64, String, String)] = [
            (0x00, "v_list.le_next", "ptr"), (0x08, "v_list.le_prev", "ptr"),
            (0x10, "v_mount", "ptr"), (0x18, "v_un.vu_specnext", "ptr"),
            (0x20, "v_un.vu_socket", "ptr"), (0x28, "v_un.vu_fifoinfo", "ptr"),
            (0x30, "v_type", "u32"), (0x34, "v_tag", "u32"),
            (0x38, "v_usecount", "u32"), (0x3C, "v_iocount", "u32"),
            (0x40, "v_lflag", "u32"), (0x44, "v_flag", "u32"),
            (0x48, "v_lock", "ptr"), (0x50, "v_data", "ptr"),
            (0x58, "v_parent", "ptr"), (0x60, "v_name", "ptr"),
        ]
        for (off, name, kind) in fields {
            if kind == "u32" {
                let val = _kread32L(addr + off)
                lines.append(String(format: "0x%03X %-24s 0x%08x  (%@)", off, name, val, kind))
            } else {
                let val = _kread64L(addr + off)
                lines.append(String(format: "0x%03X %-24s 0x%016llx (%@)", off, name, val, kind))
            }
        }

    case "ipc_port":
        let fields: [(UInt64, String, String)] = [
            (0x00, "ip_object.io_bits", "u32"), (0x04, "ip_object.io_references", "u32"),
            (0x08, "ip_object.io_lock_data", "ptr"), (0x10, "ip_kobject", "ptr"),
            (0x18, "ip_receiver", "ptr"), (0x20, "ip_srights", "u32"),
            (0x24, "ip_sorights", "u32"), (0x28, "ip_mscount", "u32"),
            (0x2C, "ip_tsleep", "u32"), (0x30, "ip_context", "ptr"),
        ]
        for (off, name, kind) in fields {
            if kind == "u32" {
                let val = _kread32L(addr + off)
                lines.append(String(format: "0x%03X %-24s 0x%08x  (%@)", off, name, val, kind))
            } else {
                let val = _kread64L(addr + off)
                lines.append(String(format: "0x%03X %-24s 0x%016llx (%@)", off, name, val, kind))
            }
        }

    default:
        lines.append("Unknown struct type: \(type)")
        lines.append("Supported: socket, proc, task, ucred, vnode, ipc_port")
        return lines.joined(separator: "\n")
    }
    return lines.joined(separator: "\n")
}

// MARK: – ksearch

private func _ksearch(pattern: String, start: UInt64, end: UInt64) -> String? {
    guard start != 0, end > start, ds_isvalid(start) else { return nil }
    let pat = pattern.trimmingCharacters(in: .whitespaces)
    var searchVal: UInt64?
    if pat.hasPrefix("0x") || pat.hasPrefix("0X") {
        searchVal = UInt64(pat.dropFirst(2), radix: 16)
    } else {
        searchVal = UInt64(pat, radix: 16)
    }
    guard let sv = searchVal else { return nil }

    var matches: [UInt64] = []
    var addr = start
    let chunkSize: UInt64 = 0x1000

    while addr < end && matches.count < 64 {
        guard ds_isvalid(addr) else { addr += chunkSize; continue }
        for off in stride(from: 0, to: chunkSize, by: 8) {
            let a = addr + off
            if a >= end { break }
            let val = _kread64L(a)
            if val == sv { matches.append(a); if matches.count >= 64 { break } }
        }
        addr += chunkSize
    }

    if matches.isEmpty {
        return "ksearch: no matches for 0x\(String(format: "%llx", sv)) in range 0x\(String(format: "%llx", start))–0x\(String(format: "%llx", end))"
    }
    var lines = [
        String(format: "ksearch: pattern 0x%llx", sv),
        String(format: "  range: 0x%llx – 0x%llx", start, end),
        String(format: "  matches: %d", matches.count), ""
    ]
    for m in matches { lines.append(String(format: "  0x%016llx", m)) }
    return lines.joined(separator: "\n")
}

// MARK: – xref

private func _xref(target: UInt64, start: UInt64, end: UInt64) -> String? {
    guard target != 0, start != 0, end > start else { return nil }
    var matches: [UInt64] = []
    var addr = start
    let chunkSize: UInt64 = 0x1000

    while addr < end && matches.count < 128 {
        guard ds_isvalid(addr) else { addr += chunkSize; continue }
        for off in stride(from: 0, to: chunkSize, by: 8) {
            let a = addr + off
            if a >= end { break }
            let val = _kread64L(a)
            let stripped = val & 0x0000000FFFFFFFFF
            let targetStripped = target & 0x0000000FFFFFFFFF
            if stripped == targetStripped || val == target {
                matches.append(a)
                if matches.count >= 128 { break }
            }
        }
        addr += chunkSize
    }

    if matches.isEmpty {
        return "xref: no references to 0x\(String(format: "%llx", target)) in range 0x\(String(format: "%llx", start))–0x\(String(format: "%llx", end))"
    }
    var lines = [
        String(format: "xref: target 0x%016llx", target),
        String(format: "  range: 0x%llx – 0x%llx", start, end),
        String(format: "  references: %d", matches.count), ""
    ]
    for m in matches {
        let val = _kread64L(m)
        lines.append(String(format: "  0x%016llx -> 0x%016llx", m, val))
    }
    return lines.joined(separator: "\n")
}

// MARK: – Registration

func registerMemoryExplorer() {

    OmegaCore.register("kstruct") { arg, mgr in
        guard mgr.dsready else { return .fail("kstruct: kernel r/w not ready") }
        let parts = arg.split(separator: " ").map { String($0) }
        guard parts.count >= 2 else {
            return .fail("kstruct: usage — kstruct <type> <addr_hex>\n  types: socket, proc, task, ucred, vnode, ipc_port")
        }
        guard let addr = _parseAddrL(parts[1]) else {
            return .fail("kstruct: invalid address '\(parts[1])'")
        }
        guard let out = _kstruct(type: parts[0], addr: addr) else {
            return .fail("kstruct: failed to read struct at 0x\(String(format: "%llx", addr))")
        }
        return .ok(out)
    }

    OmegaCore.register("ksearch") { arg, mgr in
        guard mgr.dsready else { return .fail("ksearch: kernel r/w not ready") }
        let parts = arg.split(separator: " ").map { String($0) }
        guard parts.count >= 1 else {
            return .fail("ksearch: usage — ksearch <pattern_hex> [start] [end]")
        }
        let pattern = parts[0]
        let kb = ds_get_kernel_base()
        let start = parts.count > 1 ? (_parseAddrL(parts[1]) ?? kb) : kb
        let end = parts.count > 2 ? (_parseAddrL(parts[2]) ?? start + 0x1000000) : start + 0x1000000
        guard let out = _ksearch(pattern: pattern, start: start, end: end) else {
            return .fail("ksearch: search failed")
        }
        return .ok(out)
    }

    OmegaCore.register("xref") { arg, mgr in
        guard mgr.dsready else { return .fail("xref: kernel r/w not ready") }
        let parts = arg.split(separator: " ").map { String($0) }
        guard parts.count >= 1 else {
            return .fail("xref: usage — xref <target_hex> [start] [end]")
        }
        guard let target = _parseAddrL(parts[0]) else {
            return .fail("xref: invalid target address")
        }
        let kb = ds_get_kernel_base()
        let start = parts.count > 1 ? (_parseAddrL(parts[1]) ?? kb) : kb
        let end = parts.count > 2 ? (_parseAddrL(parts[2]) ?? start + 0x1000000) : start + 0x1000000
        guard let out = _xref(target: target, start: start, end: end) else {
            return .fail("xref: search failed")
        }
        return .ok(out)
    }
}
