//
//  OmegaExtendedB.swift
//  lara — Extended shell: vmmap, memread, memwrite
//
import Foundation
import Darwin

func _registerMemory() {

    // vmmap <pid|name>
    OmegaCore.register("vmmap") { arg, _ in
        let a = arg.trimmingCharacters(in: .whitespaces)
        guard !a.isEmpty, let pid = _resolvePid(a) else { return .fail("usage: vmmap <pid|name>") }
        var rows = ["vmmap — \(_pidName(pid)) (\(pid))",
                    _col([20,20,10,5,25], ["START","END","SIZE","PROT","PATH"]),
                    String(repeating: "-", count: 84)]
        var addr: UInt64 = 0
        for _ in 0..<1024 {
            var ri = proc_regionwithpathinfo()
            let rsz = Int32(MemoryLayout<proc_regionwithpathinfo>.size)
            guard proc_pidinfo(pid, PROC_PIDREGIONPATHINFO, addr, &ri, rsz) > 0 else { break }
            let start = ri.prp_prinfo.pri_address
            let size  = ri.prp_prinfo.pri_size
            let end   = start + size
            let prot  = ri.prp_prinfo.pri_protection
            var ps = ""
            ps += (prot & VM_PROT_READ)    != 0 ? "r" : "-"
            ps += (prot & VM_PROT_WRITE)   != 0 ? "w" : "-"
            ps += (prot & VM_PROT_EXECUTE) != 0 ? "x" : "-"
            let path = withUnsafePointer(to: ri.prp_vip.vip_path) {
                $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXPATHLEN)) { String(cString: $0) }
            }
            func fmtSz(_ v: UInt64) -> String {
                if v < 1024 { return "\(v)B" }
                if v < 1_048_576 { return String(format: "%.1fK", Double(v)/1024) }
                return String(format: "%.1fM", Double(v)/1_048_576)
            }
            let leaf = path.isEmpty ? "(anon)" : (path as NSString).lastPathComponent
            rows.append(_col([20,20,10,5,25],
                [String(format: "0x%012llX", start),
                 String(format: "0x%012llX", end),
                 fmtSz(size), ps, leaf]))
            addr = end
        }
        if rows.count == 3 { rows.append("  (no regions — denied or unknown pid)") }
        return .ok(rows.joined(separator: "\n"))
    }

    // memread <addr_hex> <size> — kernel memory hexdump
    OmegaCore.register("memread") { arg, mgr in
        guard mgr.dsready else { return .fail("memread: kernel r/w not ready") }
        let parts = arg.split(separator: " ").map { String($0) }
        guard parts.count >= 2, let addr = _parseAddrE(parts[0]),
              let size = Int(parts[1]), size > 0, size <= 4096 else {
            return .fail("memread: usage: memread <addr_hex> <size> (max 4096 bytes)")
        }
        var lines = [String(format: "memread @ 0x%016llX  (%d bytes)", addr, size), ""]
        for off in stride(from: 0, to: size, by: 16) {
            let cnt = min(16, size - off)
            var hexS = "", ascS = ""
            for i in 0..<cnt {
                let byte = ds_kread8(addr + UInt64(off + i))
                hexS += String(format: "%02X ", byte)
                ascS += (byte >= 32 && byte < 127) ? String(UnicodeScalar(byte)) : "."
            }
            lines.append(String(format: "%08X  %-48s  %@", off, hexS, ascS))
        }
        return .ok(lines.joined(separator: "\n"))
    }

    // memwrite <addr_hex> <value_hex> — write 64-bit kernel word
    OmegaCore.register("memwrite") { arg, mgr in
        guard mgr.dsready else { return .fail("memwrite: kernel r/w not ready") }
        let parts = arg.split(separator: " ").map { String($0) }
        guard parts.count >= 2,
              let addr = _parseAddrE(parts[0]),
              let val  = _parseAddrE(parts[1]) else {
            return .fail("memwrite: usage: memwrite <addr_hex> <value_hex>")
        }
        let _ = mgr.kwrite64(address: addr, value: val)
        let verify = mgr.kread64(address: addr)
        return verify == val
            ? .ok(String(format: "memwrite: 0x%016llX <- 0x%016llX  OK", addr, val))
            : .fail(String(format: "memwrite: verify FAILED (got 0x%016llX)", verify))
    }
}
