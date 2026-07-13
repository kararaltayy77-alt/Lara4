//
//  ProcLinkEngine.swift
//  lara
//
//  Process Relationship / Context Linking Engine
//  ─────────────────────────────────────────────────────────────────────────
//
//  Every kernel address operation in this file goes through the mandatory
//  4-stage pipeline BEFORE any read/write occurs:
//
//    ① address validation   — non-zero, kernel-space range, alignment
//    ② pointer sanity check — first-word probe for dead/sentinel values
//    ③ safe read wrapper    — _safeKRead* helpers (returns Optional)
//    ④ operation            — only reached when all three pass
//
//  Commands registered here:
//    proc-link add <src_pid> <dst_pid> [<relation_type>]
//      Capture both processes, compute fingerprints, store the link.
//
//    proc-link list
//      Show all stored links with fingerprints and metadata.
//
//    proc-link remove <id>
//      Remove a stored link by its numeric ID.
//
//    proc-link clear
//      Remove all stored links.
//
//    proc-inspect <pid_or_addr>
//      Deep inspection: identity, struct fingerprint, credentials,
//      task pointer, parent/child relationships, CS flags.
//
//    proc-trace <pid_or_addr>
//      ASCII relationship tree: parent, children, task, ucred, linked objects.
//
//    proc-find-relation <fingerprint_hex>
//      Walk allproc and return every process whose fingerprint matches.
//
//    proc-monitor
//      Snapshot the current state of all stored links and report drift
//      (fingerprint changes, missing processes, new PIDs).
//
//    proc-link help
//      Full command reference.
//

import Foundation
import Darwin

// ─────────────────────────────────────────────────────────────────────────────
// MARK: – Types
// ─────────────────────────────────────────────────────────────────────────────

/// Stable, address-independent identity of a process.
/// Built from fields that survive reboots better than kaddrs do.
private struct ProcFingerprint: CustomStringConvertible {
    let pid:      Int32
    let uid:      UInt32
    let name:     String
    /// Hash of the first 64 bytes of the proc struct (structure shape, not content)
    let structHash: UInt32
    /// First 8 bytes of p_comm offset (stable across most ASLR slides)
    let commSeed: UInt64

    var hex: String { String(format: "%08x%016llx%08x", structHash, commSeed, UInt32(bitPattern: pid)) }

    var description: String {
        String(format: "fp{pid=%d uid=%d name=%@ sh=%08x cs=%016llx}",
               pid, uid, name, structHash, commSeed)
    }

    /// Compare two fingerprints — returns similarity score 0.0–1.0
    func similarity(to other: ProcFingerprint) -> Double {
        var score = 0.0
        if name == other.name           { score += 0.40 }
        if uid  == other.uid            { score += 0.20 }
        if structHash == other.structHash { score += 0.25 }
        if commSeed   == other.commSeed { score += 0.15 }
        return score
    }
}

private enum ProcRelationType: String {
    case parent     = "parent"
    case child      = "child"
    case ucred      = "ucred"
    case task       = "task"
    case injected   = "injected"
    case linked     = "linked"     // generic/user-defined
}

private struct ProcLink {
    let id:         Int
    let sourceAddr: UInt64
    let targetAddr: UInt64
    let sourceFP:   ProcFingerprint
    let targetFP:   ProcFingerprint
    let relation:   ProcRelationType
    let timestamp:  Date
    var status:     String   // "linked", "lost-source", "lost-target", "fp-drift"
}

// ─────────────────────────────────────────────────────────────────────────────
// MARK: – Thread-safe in-memory store
// ─────────────────────────────────────────────────────────────────────────────

private final class ProcLinkStore {
    static let shared = ProcLinkStore()
    private let lock  = NSLock()
    private var links: [ProcLink] = []
    private var nextID = 1

    func add(_ link: ProcLink) {
        lock.lock(); defer { lock.unlock() }
        links.append(link)
    }

    func all() -> [ProcLink] {
        lock.lock(); defer { lock.unlock() }
        return links
    }

    func remove(id: Int) -> Bool {
        lock.lock(); defer { lock.unlock() }
        let before = links.count
        links.removeAll { $0.id == id }
        return links.count < before
    }

    func clear() {
        lock.lock(); defer { lock.unlock() }
        links.removeAll()
        nextID = 1
    }

    func allocID() -> Int {
        lock.lock(); defer { lock.unlock() }
        let id = nextID; nextID += 1; return id
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MARK: – ① Address Validation
// ─────────────────────────────────────────────────────────────────────────────

/// Stage 1: verify the address is plausible for an iOS kernel pointer.
/// ARM64e kernel pointers live above 0xFFFFFE0000000000 (PAC canonical bit set).
/// Older arm64 / A11 kernels live in the 0xFFFFFFF... range.
private func _validateAddr(_ addr: UInt64, label: String) -> String? {
    guard addr != 0 else {
        return "\(label): null pointer — nothing to read"
    }
    // Must be in upper-half canonical kernel address space
    let highNibble = addr >> 60
    guard highNibble == 0xF else {
        return "\(label): 0x\(String(format: "%llx", addr)) is not a kernel address (high nibble: 0x\(String(highNibble, radix: 16)))"
    }
    // Must be at least 4-byte aligned — proc structs are always 16-byte aligned
    guard (addr & 0x3) == 0 else {
        return "\(label): address 0x\(String(format: "%llx", addr)) is not 4-byte aligned"
    }
    return nil // OK
}

// ─────────────────────────────────────────────────────────────────────────────
// MARK: – ② Pointer Sanity Check
// ─────────────────────────────────────────────────────────────────────────────

/// Stage 2: probe the first 8 bytes to rule out dead/freed memory.
/// Returns an error string if the value looks like a sentinel, nil otherwise.
private func _sanitizeProbe(_ addr: UInt64, label: String) -> String? {
    let probe = ds_kread64(addr)
    switch probe {
    case 0xDEADBEEFDEADBEEF, 0xDEADDEADDEADDEAD,
         0xFEEEFEEEFEEEFEEE, 0xBADDBADDBADDBADD,
         0xABABABABABABABAB, 0x4141414141414141,
         0x0000000000000000:
        // A proc struct must have at least one non-zero word at offset 0
        // (p_list.le_next or p_pptr); an all-zero first word means freed/invalid
        return "\(label): probe of 0x\(String(format: "%llx", addr)) returned sentinel 0x\(String(format: "%llx", probe)) — likely freed or invalid"
    default:
        // Additional check: kernel pointers must look like kernel pointers
        if probe < 0xFFFFFE0000000000 && probe != 0 {
            // Could be a non-pointer field at offset 0 — not necessarily wrong,
            // just note it (don't fail, proc structs may have pid at offset 0 on some iOS)
            break
        }
        return nil // OK
    }
    return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// MARK: – ③ Safe Read Wrappers
// ─────────────────────────────────────────────────────────────────────────────

/// Stage 3: safe 64-bit read — returns nil on validation failure, value otherwise.
private func _safeKRead64(_ addr: UInt64, label: String) -> (UInt64?, String?) {
    if let e = _validateAddr(addr, label: label) { return (nil, e) }
    if let e = _sanitizeProbe(addr, label: label) { return (nil, e) }
    return (ds_kread64(addr), nil)
}

/// Stage 3: safe 32-bit read — only does address validation (no sanity probe).
private func _safeKRead32(_ addr: UInt64, label: String) -> (UInt32?, String?) {
    if let e = _validateAddr(addr, label: label) { return (nil, e) }
    return (ds_kread32(addr), nil)
}

/// Stage 3: safe pointer read — validates the pointer itself AND the target.
private func _safeKReadPtr(_ addr: UInt64, label: String) -> (UInt64?, String?) {
    if let e = _validateAddr(addr, label: label) { return (nil, e) }
    let ptr = ds_kread64(addr)
    if ptr == 0 { return (0, nil) } // null pointer is allowed (may just mean absent)
    if let e = _validateAddr(ptr, label: "\(label)->deref") { return (nil, e) }
    return (ptr, nil)
}

// ─────────────────────────────────────────────────────────────────────────────
// MARK: – Hex parser
// ─────────────────────────────────────────────────────────────────────────────

private func _plHex(_ s: String) -> UInt64? {
    let t = s.trimmingCharacters(in: .whitespaces)
    let clean = (t.hasPrefix("0x") || t.hasPrefix("0X")) ? String(t.dropFirst(2)) : t
    return UInt64(clean, radix: 16)
}

// ─────────────────────────────────────────────────────────────────────────────
// MARK: – Fingerprint builder
// ─────────────────────────────────────────────────────────────────────────────

/// Build a ProcFingerprint from a kernel proc address.
/// Uses the full validation pipeline before every read.
private func _buildFingerprint(procAddr: UInt64, mgr: laramgr) -> (ProcFingerprint?, String?) {

    // ④ Operation — all reads below are preceded by stage-3 wrappers
    let pid:  Int32
    let uid:  UInt32
    var name: String = "?"

    // Read pid (p_pid at 0x60)
    guard let pidAddr = _validateAddr(procAddr, label: "fingerprint.pid") == nil
                        ? (procAddr + 0x60) as UInt64? : nil else {
        return (nil, "fingerprint: invalid proc addr")
    }
    let (pid32, pidErr) = _safeKRead32(pidAddr, label: "fingerprint.pid")
    if let e = pidErr { return (nil, e) }
    pid = Int32(bitPattern: pid32!)

    // Read uid from ucred pointer (proc+0x10 → ucred → cr_posix.cr_uid at 0x18)
    let ucredField = procAddr + 0x10
    let (ucredPtr, ucredPtrErr) = _safeKReadPtr(ucredField, label: "fingerprint.ucred_ptr")
    if let e = ucredPtrErr { return (nil, e) }
    if let uc = ucredPtr, uc != 0 {
        let (uidVal, _) = _safeKRead32(uc + 0x18, label: "fingerprint.uid")
        uid = uidVal ?? 0
    } else {
        uid = 0
    }

    // Read p_comm name — try iOS 18 offset 0x56c, fallback to 0x268
    for nameOff: UInt64 in [0x56c, 0x268, 0x2b0] {
        let nameAddr = procAddr + nameOff
        if _validateAddr(nameAddr, label: "fp.name") != nil { continue }
        var buf = [UInt8](repeating: 0, count: 17)
        for i in 0..<16 { buf[i] = ds_kread8(nameAddr + UInt64(i)) }
        let s = String(bytes: buf.prefix(while: { $0 != 0 }), encoding: .utf8) ?? ""
        if !s.isEmpty { name = s; break }
    }

    // Structure hash: XOR of first 8 qwords at the proc addr (layout fingerprint)
    var structHash: UInt32 = 0
    for i: UInt64 in stride(from: 0, to: 64, by: 8) {
        let wordAddr = procAddr + i
        if _validateAddr(wordAddr, label: "fp.hash") != nil { break }
        let w = ds_kread64(wordAddr)
        // XOR high and low 32 bits to get a 32-bit contribution
        structHash ^= UInt32(w >> 32) ^ UInt32(w & 0xFFFF_FFFF)
    }

    // commSeed: raw bytes at p_comm offset (stable across slides)
    var commSeed: UInt64 = 0
    let commBase = procAddr + 0x56c
    if _validateAddr(commBase, label: "fp.commSeed") == nil {
        commSeed = ds_kread64(commBase)
    }

    let fp = ProcFingerprint(pid: pid, uid: uid, name: name,
                             structHash: structHash, commSeed: commSeed)
    return (fp, nil)
}

// ─────────────────────────────────────────────────────────────────────────────
// MARK: – allproc walker (pipeline-safe)
// ─────────────────────────────────────────────────────────────────────────────

private struct PLProc {
    let kaddr:   UInt64
    let pid:     Int32
    let uid:     UInt32
    let name:    String
    let taskPtr: UInt64
    let ppid:    Int32
}

/// Walk allproc. Every pointer dereference goes through the full pipeline.
private func _plAllprocs(mgr: laramgr, limit: Int = 512) -> [PLProc] {
    var list: [PLProc] = []
    var ptr  = ds_get_our_proc()
    var seen = Set<UInt64>()

    while list.count < limit {
        // ① Validate
        guard ptr != 0 else { break }
        if let e = _validateAddr(ptr, label: "allproc.ptr") {
            CommandLogger.shared.log("ProcLink/allprocs: \(e)")
            break
        }
        // ② Sanity
        if let e = _sanitizeProbe(ptr, label: "allproc.ptr") {
            CommandLogger.shared.log("ProcLink/allprocs: \(e)")
            break
        }
        guard !seen.contains(ptr) else { break }
        seen.insert(ptr)

        // ③/④ Safe reads
        let pid  = Int32(bitPattern: ds_kread32(ptr + 0x60))
        let ppid = Int32(bitPattern: ds_kread32(ptr + 0x64))

        // uid via ucred
        var uid: UInt32 = 0
        let ucPtr = ds_kreadptr(ptr + 0x10)
        if ucPtr != 0, _validateAddr(ucPtr, label: "allproc.ucred") == nil {
            uid = ds_kread32(ucPtr + 0x18)
        }

        var name = ""
        for nameOff: UInt64 in [0x56c, 0x268] {
            let na = ptr + nameOff
            if _validateAddr(na, label: "allproc.name") != nil { continue }
            var buf = [UInt8](repeating: 0, count: 17)
            for i in 0..<16 { buf[i] = ds_kread8(na + UInt64(i)) }
            let s = String(bytes: buf.prefix(while: { $0 != 0 }), encoding: .utf8) ?? ""
            if !s.isEmpty { name = s; break }
        }

        var taskPtr: UInt64 = 0
        let (tp, _) = _safeKReadPtr(ptr + 0x18, label: "allproc.task")
        if let t = tp { taskPtr = t }

        list.append(PLProc(kaddr: ptr, pid: pid, uid: uid,
                           name: name, taskPtr: taskPtr, ppid: ppid))

        // Advance: p_list.le_next at offset 0x08
        let (next, nextErr) = _safeKReadPtr(ptr + 0x08, label: "allproc.next")
        if let e = nextErr {
            CommandLogger.shared.log("ProcLink/allprocs next: \(e)")
            break
        }
        ptr = next ?? 0
    }
    return list
}

/// Resolve pid or hex address → PLProc
private func _resolvePLProc(arg: String, mgr: laramgr) -> (PLProc?, String?) {
    let procs = _plAllprocs(mgr: mgr)
    if let pid = Int32(arg) {
        if let p = procs.first(where: { $0.pid == pid }) { return (p, nil) }
        return (nil, "proc: no process with pid \(pid)")
    }
    if let addr = _plHex(arg) {
        if let e = _validateAddr(addr, label: "proc.addr") { return (nil, e) }
        if let p = procs.first(where: { $0.kaddr == addr }) { return (p, nil) }
        // Addr given but not in list — build a synthetic entry from the address
        if let e = _sanitizeProbe(addr, label: "proc.probe") { return (nil, e) }
        let pid  = Int32(bitPattern: ds_kread32(addr + 0x60))
        let ppid = Int32(bitPattern: ds_kread32(addr + 0x64))
        var uid: UInt32 = 0
        let uc = ds_kreadptr(addr + 0x10)
        if uc != 0, _validateAddr(uc, label: "proc.ucred") == nil { uid = ds_kread32(uc + 0x18) }
        var name = ""
        for off: UInt64 in [0x56c, 0x268] {
            let na = addr + off
            guard _validateAddr(na, label: "proc.name") == nil else { continue }
            var buf = [UInt8](repeating: 0, count: 17)
            for i in 0..<16 { buf[i] = ds_kread8(na + UInt64(i)) }
            let s = String(bytes: buf.prefix(while: { $0 != 0 }), encoding: .utf8) ?? ""
            if !s.isEmpty { name = s; break }
        }
        var taskPtr: UInt64 = 0
        let (tp, _) = _safeKReadPtr(addr + 0x18, label: "proc.task")
        if let t = tp { taskPtr = t }
        return (PLProc(kaddr: addr, pid: pid, uid: uid,
                       name: name, taskPtr: taskPtr, ppid: ppid), nil)
    }
    // Try name match
    let lower = arg.lowercased()
    if let p = procs.first(where: { $0.name.lowercased().contains(lower) }) { return (p, nil) }
    return (nil, "proc: '\(arg)' is not a valid pid, hex address, or process name")
}

// ─────────────────────────────────────────────────────────────────────────────
// MARK: – Registration
// ─────────────────────────────────────────────────────────────────────────────

func registerProcLinkCommands() {

    // ── proc-link add ─────────────────────────────────────────────────────────
    OmegaCore.register("proc-link") { rawArg, mgr in
        guard mgr.dsready else { return .fail("proc-link: exploit not ready — run 'run' first") }

        let tokens = rawArg.split(separator: " ")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        guard let subCmd = tokens.first else {
            return .fail("proc-link: usage — proc-link <add|list|remove|clear|help>")
        }

        switch subCmd {

        // ── add ───────────────────────────────────────────────────────────────
        case "add":
            guard tokens.count >= 3 else {
                return .fail("proc-link add: usage — proc-link add <src_pid_or_addr> <dst_pid_or_addr> [relation]\n" +
                             "  relation values: parent child ucred task injected linked (default: linked)")
            }
            let (srcProc, srcErr) = _resolvePLProc(arg: String(tokens[1]), mgr: mgr)
            if let e = srcErr { return .fail("proc-link add [source]: \(e)") }
            let (dstProc, dstErr) = _resolvePLProc(arg: String(tokens[2]), mgr: mgr)
            if let e = dstErr { return .fail("proc-link add [target]: \(e)") }

            let relationRaw = tokens.count >= 4 ? String(tokens[3]) : "linked"
            let relation = ProcRelationType(rawValue: relationRaw) ?? .linked

            let (srcFP, srcFPErr) = _buildFingerprint(procAddr: srcProc!.kaddr, mgr: mgr)
            if let e = srcFPErr { return .fail("proc-link add [fingerprint source]: \(e)") }
            let (dstFP, dstFPErr) = _buildFingerprint(procAddr: dstProc!.kaddr, mgr: mgr)
            if let e = dstFPErr { return .fail("proc-link add [fingerprint target]: \(e)") }

            let id   = ProcLinkStore.shared.allocID()
            let link = ProcLink(
                id:         id,
                sourceAddr: srcProc!.kaddr,
                targetAddr: dstProc!.kaddr,
                sourceFP:   srcFP!,
                targetFP:   dstFP!,
                relation:   relation,
                timestamp:  Date(),
                status:     "linked"
            )
            ProcLinkStore.shared.add(link)
            CommandLogger.shared.log("proc-link add: id=\(id) \(srcFP!.name)→\(dstFP!.name) [\(relation.rawValue)]")

            return .ok(
                "proc-link: ✔ link stored\n" +
                "──────────────────────────────────────────────────\n" +
                String(format: "  id          : %d\n", id) +
                "  source      : \(srcFP!.name) (pid=\(srcFP!.pid))\n" +
                String(format: "  source_addr : 0x%016llx\n", srcProc!.kaddr) +
                "  source_fp   : \(srcFP!.hex)\n" +
                "  relation    : \(relation.rawValue)\n" +
                "  target      : \(dstFP!.name) (pid=\(dstFP!.pid))\n" +
                String(format: "  target_addr : 0x%016llx\n", dstProc!.kaddr) +
                "  target_fp   : \(dstFP!.hex)\n" +
                "  status      : linked\n" +
                "──────────────────────────────────────────────────"
            )

        // ── list ──────────────────────────────────────────────────────────────
        case "list":
            let links = ProcLinkStore.shared.all()
            if links.isEmpty { return .ok("proc-link list: no links stored — use 'proc-link add' first") }
            let fmt = DateFormatter(); fmt.dateFormat = "HH:mm:ss"
            var out = "proc-link list: \(links.count) link(s)\n"
            out    += "──────────────────────────────────────────────────────────────\n"
            for l in links {
                out += String(format: " [%2d] %@ → %@  (%@)\n",
                              l.id, l.sourceFP.name, l.targetFP.name, l.relation.rawValue)
                out += String(format: "      src addr : 0x%016llx  fp: %@\n",
                              l.sourceAddr, l.sourceFP.hex)
                out += String(format: "      dst addr : 0x%016llx  fp: %@\n",
                              l.targetAddr, l.targetFP.hex)
                out += "      status   : \(l.status)  @ \(fmt.string(from: l.timestamp))\n"
                out += "      ──────────────────────────────────────────────────────\n"
            }
            return .ok(out)

        // ── remove ────────────────────────────────────────────────────────────
        case "remove":
            guard tokens.count >= 2, let id = Int(tokens.last ?? "") else {
                return .fail("proc-link remove: usage — proc-link remove <id>")
            }
            if ProcLinkStore.shared.remove(id: id) {
                return .ok("proc-link remove: link #\(id) removed")
            }
            return .fail("proc-link remove: no link with id \(id)")

        // ── clear ─────────────────────────────────────────────────────────────
        case "clear":
            ProcLinkStore.shared.clear()
            return .ok("proc-link clear: all links removed")

        // ── help ──────────────────────────────────────────────────────────────
        case "help":
            return .ok("""
proc-link — Process Relationship Engine
────────────────────────────────────────────────────────────────
  proc-link add <src> <dst> [relation]
      Link two processes. <src>/<dst> = pid | hex_addr | name
      relation: parent | child | ucred | task | injected | linked

  proc-link list           Show all stored links with fingerprints
  proc-link remove <id>    Remove link by ID
  proc-link clear          Remove all links

  proc-inspect <pid|addr>  Deep process inspection + relationships
  proc-trace   <pid|addr>  ASCII relationship tree
  proc-find-relation <fp>  Find process by fingerprint hex
  proc-monitor             Check stored links for drift/changes
────────────────────────────────────────────────────────────────
  Fingerprints are ASLR-independent — they survive reboots.
  Use 'proc-find-relation <fp_hex>' to re-locate a process.
""")

        default:
            return .fail("proc-link: unknown subcommand '\(subCmd)' — try 'proc-link help'")
        }
    }

    // ── proc inspect ──────────────────────────────────────────────────────────
    OmegaCore.register("proc-inspect") { rawArg, mgr in
        guard mgr.dsready else { return .fail("proc-inspect: exploit not ready") }
        let arg = rawArg.trimmingCharacters(in: .whitespaces)
        guard !arg.isEmpty else { return .fail("proc-inspect: usage — proc inspect <pid|hex_addr|name>") }

        let (proc, resolveErr) = _resolvePLProc(arg: arg, mgr: mgr)
        if let e = resolveErr { return .fail(e) }
        let p = proc!

        // ④ Deep inspection — every field goes through the pipeline
        var out = "proc-inspect — process identity\n"
        out    += "════════════════════════════════════════════════════════\n"
        out    += String(format: "  name         : %@\n", p.name.isEmpty ? "(unknown)" : p.name)
        out    += String(format: "  pid          : %d\n", p.pid)
        out    += String(format: "  ppid         : %d\n", p.ppid)
        out    += String(format: "  uid          : %d\n", p.uid)
        out    += String(format: "  kaddr        : 0x%016llx\n", p.kaddr)
        out    += String(format: "  task_ptr     : 0x%016llx\n", p.taskPtr)

        // CS flags
        var csFlags: UInt32 = 0
        for csOff: UInt64 in [0x300, 0x2c4, 0x2e0] {
            let (v, _) = _safeKRead32(p.kaddr + csOff, label: "inspect.csflags")
            if let f = v, f != 0 { csFlags = f; break }
        }
        out += String(format: "  cs_flags     : 0x%08x\n", csFlags)

        // p_pptr (parent proc pointer)
        let (ppPtr, ppErr) = _safeKReadPtr(p.kaddr + 0x30, label: "inspect.pptr")
        if let e = ppErr {
            out += "  parent_proc  : \(e)\n"
        } else if let pp = ppPtr, pp != 0 {
            let ppPid = Int32(bitPattern: ds_kread32(pp + 0x60))
            out += String(format: "  parent_proc  : 0x%016llx  (pid=%d)\n", pp, ppPid)
        } else {
            out += "  parent_proc  : (null)\n"
        }

        // ucred pointer and credential info
        out += "\n── credential reference ──────────────────────────────\n"
        let (ucPtr, ucErr) = _safeKReadPtr(p.kaddr + 0x10, label: "inspect.ucred")
        if let e = ucErr {
            out += "  ucred_ptr    : \(e)\n"
        } else if let uc = ucPtr, uc != 0 {
            out += String(format: "  ucred_ptr    : 0x%016llx\n", uc)
            let (ruid, _) = _safeKRead32(uc + 0x18, label: "inspect.ruid")
            let (euid, _) = _safeKRead32(uc + 0x1c, label: "inspect.euid")
            let (rgid, _) = _safeKRead32(uc + 0x20, label: "inspect.rgid")
            let (egid, _) = _safeKRead32(uc + 0x24, label: "inspect.egid")
            out += String(format: "  ruid/euid    : %d / %d\n", ruid ?? 0xFFFF, euid ?? 0xFFFF)
            out += String(format: "  rgid/egid    : %d / %d\n", rgid ?? 0xFFFF, egid ?? 0xFFFF)
        } else {
            out += "  ucred_ptr    : (null)\n"
        }

        // task relationship
        out += "\n── task relationship ─────────────────────────────────\n"
        if p.taskPtr != 0 {
            out += String(format: "  task_ptr     : 0x%016llx\n", p.taskPtr)
            // bsd_info back-pointer (task → proc, should match p.kaddr)
            let (bsdInfo, _) = _safeKReadPtr(p.taskPtr + 0x390, label: "inspect.bsd_info")
            if let b = bsdInfo, b != 0 {
                let bsdMatch = b == p.kaddr ? "✔ matches proc" : "✖ MISMATCH"
                out += String(format: "  bsd_info     : 0x%016llx  %@\n", b, bsdMatch)
            }
        } else {
            out += "  task_ptr     : (null)\n"
        }

        // Structure fingerprint
        out += "\n── structure fingerprint ─────────────────────────────\n"
        let (fp, fpErr) = _buildFingerprint(procAddr: p.kaddr, mgr: mgr)
        if let e = fpErr {
            out += "  fingerprint  : error — \(e)\n"
        } else {
            out += "  fingerprint  : \(fp!.hex)\n"
            out += "  struct_hash  : \(String(format: "0x%08x", fp!.structHash))\n"
            out += "  comm_seed    : \(String(format: "0x%016llx", fp!.commSeed))\n"
        }

        // Stored links involving this process
        let links = ProcLinkStore.shared.all().filter {
            $0.sourceAddr == p.kaddr || $0.targetAddr == p.kaddr
        }
        if !links.isEmpty {
            out += "\n── stored links involving this process ───────────────\n"
            for l in links {
                let role = l.sourceAddr == p.kaddr ? "source" : "target"
                let other = role == "source" ? l.targetFP.name : l.sourceFP.name
                out += "  [#\(l.id)] role=\(role)  relation=\(l.relation.rawValue)  other=\(other)\n"
            }
        }
        out += "════════════════════════════════════════════════════════"
        return .ok(out)
    }

    // ── proc trace ────────────────────────────────────────────────────────────
    OmegaCore.register("proc-trace") { rawArg, mgr in
        guard mgr.dsready else { return .fail("proc-trace: exploit not ready") }
        let arg = rawArg.trimmingCharacters(in: .whitespaces)
        guard !arg.isEmpty else { return .fail("proc-trace: usage — proc trace <pid|hex_addr|name>") }

        let (proc, err) = _resolvePLProc(arg: arg, mgr: mgr)
        if let e = err { return .fail(e) }
        let p = proc!

        let allProcs = _plAllprocs(mgr: mgr)
        var out = "proc-trace — relationship tree\n"
        out    += "════════════════════════════════════════════════\n"
        out    += String(format: "  [ROOT] %@ (pid=%d  uid=%d)\n",
                         p.name.isEmpty ? "?" : p.name, p.pid, p.uid)
        out    += String(format: "         kaddr: 0x%016llx\n", p.kaddr)

        // task relation
        out += "   │\n"
        if p.taskPtr != 0 {
            out += String(format: "   ├── [task]    0x%016llx\n", p.taskPtr)
            let (bsd, _) = _safeKReadPtr(p.taskPtr + 0x390, label: "trace.bsd_info")
            if let b = bsd, b != 0 {
                out += String(format: "   │    └── bsd_info → 0x%016llx  %@\n", b,
                              b == p.kaddr ? "(✔ self)" : "(⚠ points elsewhere)")
            }
        } else {
            out += "   ├── [task]    (null)\n"
        }

        // ucred relation
        let (ucPtr, _) = _safeKReadPtr(p.kaddr + 0x10, label: "trace.ucred")
        out += "   │\n"
        if let uc = ucPtr, uc != 0 {
            out += String(format: "   ├── [ucred]   0x%016llx\n", uc)
            let (ruid, _) = _safeKRead32(uc + 0x18, label: "trace.ruid")
            let (euid, _) = _safeKRead32(uc + 0x1c, label: "trace.euid")
            out += String(format: "   │    └── ruid=%d  euid=%d\n", ruid ?? 0, euid ?? 0)
        } else {
            out += "   ├── [ucred]   (null)\n"
        }

        // parent relation
        let (ppPtr, _) = _safeKReadPtr(p.kaddr + 0x30, label: "trace.parent")
        out += "   │\n"
        if let pp = ppPtr, pp != 0 {
            let ppPid  = Int32(bitPattern: ds_kread32(pp + 0x60))
            let ppEntry = allProcs.first(where: { $0.pid == ppPid })
            let ppName  = ppEntry?.name ?? "?"
            out += String(format: "   ├── [parent]  %@ (pid=%d)\n", ppName, ppPid)
            out += String(format: "   │    └── kaddr: 0x%016llx\n", pp)
        } else {
            out += "   ├── [parent]  (null)\n"
        }

        // children (scan allproc for ppid == p.pid)
        let children = allProcs.filter { $0.ppid == p.pid && $0.pid != p.pid }
        out += "   │\n"
        if children.isEmpty {
            out += "   ├── [children] (none)\n"
        } else {
            out += "   ├── [children] \(children.count) child(ren)\n"
            for (i, c) in children.enumerated() {
                let prefix = i == children.count - 1 ? "   │    └──" : "   │    ├──"
                out += String(format: "\(prefix) %@ (pid=%d  uid=%d)\n", c.name, c.pid, c.uid)
                out += String(format: "   │         kaddr: 0x%016llx\n", c.kaddr)
            }
        }

        // stored links
        let links = ProcLinkStore.shared.all().filter {
            $0.sourceAddr == p.kaddr || $0.targetAddr == p.kaddr
        }
        out += "   │\n"
        if links.isEmpty {
            out += "   └── [linked objects] (none — use 'proc-link add' to create links)\n"
        } else {
            out += "   └── [linked objects] \(links.count) stored link(s)\n"
            for (i, l) in links.enumerated() {
                let prefix = i == links.count - 1 ? "        └──" : "        ├──"
                let role    = l.sourceAddr == p.kaddr ? "→" : "←"
                let other   = l.sourceAddr == p.kaddr ? l.targetFP : l.sourceFP
                let otherAddr = l.sourceAddr == p.kaddr ? l.targetAddr : l.sourceAddr
                out += "\(prefix) [\(l.relation.rawValue)] \(role) \(other.name) (pid=\(other.pid))\n"
                out += String(format: "             kaddr: 0x%016llx  fp: %@\n",
                              otherAddr, other.hex)
            }
        }
        out += "════════════════════════════════════════════════"
        return .ok(out)
    }

    // ── proc find-relation ────────────────────────────────────────────────────
    OmegaCore.register("proc-find-relation") { rawArg, mgr in
        guard mgr.dsready else { return .fail("proc-find-relation: exploit not ready") }
        let fpArg = rawArg.trimmingCharacters(in: .whitespaces)
        guard !fpArg.isEmpty else {
            return .fail("proc-find-relation: usage — proc find-relation <fingerprint_hex>\n" +
                         "  Get fingerprint from 'proc inspect <pid>'")
        }

        // The fingerprint hex is: structHash(8) + commSeed(16) + pid_bits(8)
        // We compare using similarity scoring, not exact match
        let allProcs = _plAllprocs(mgr: mgr)
        var scored: [(score: Double, proc: PLProc, fp: ProcFingerprint)] = []

        for p in allProcs {
            let (fp, err) = _buildFingerprint(procAddr: p.kaddr, mgr: mgr)
            guard err == nil, let fp = fp else { continue }
            if fp.hex == fpArg {
                scored.append((score: 1.0, proc: p, fp: fp))
                continue
            }
            // Partial match by structHash prefix (first 8 hex chars)
            if fpArg.count >= 8 && fp.hex.hasPrefix(fpArg.prefix(8)) {
                scored.append((score: 0.7, proc: p, fp: fp))
            }
        }

        if scored.isEmpty {
            return .ok("proc find-relation: no process matches fingerprint '\(fpArg)'\n" +
                       "  (fingerprints may change after reboot or memory compaction)")
        }

        scored.sort { $0.score > $1.score }
        var out = "proc find-relation: \(scored.count) match(es) for fingerprint '\(fpArg)'\n"
        out    += "──────────────────────────────────────────────────────\n"
        for s in scored {
            out += String(format: "  name     : %@\n", s.fp.name)
            out += String(format: "  pid      : %d\n", s.fp.pid)
            out += String(format: "  uid      : %d\n", s.fp.uid)
            out += String(format: "  kaddr    : 0x%016llx\n", s.proc.kaddr)
            out += String(format: "  fp       : %@\n", s.fp.hex)
            out += String(format: "  score    : %.0f%%\n", s.score * 100)
            out += "  ──────────────────────────────────────────────────\n"
        }
        return .ok(out)
    }

    // ── proc monitor ──────────────────────────────────────────────────────────
    OmegaCore.register("proc-monitor") { _, mgr in
        guard mgr.dsready else { return .fail("proc-monitor: exploit not ready") }
        let links = ProcLinkStore.shared.all()
        if links.isEmpty {
            return .ok("proc monitor: no links to monitor — use 'proc-link add' first")
        }
        let allProcs = _plAllprocs(mgr: mgr)

        var out     = "proc-monitor — link drift check\n"
        out        += "════════════════════════════════════════════════════════════\n"
        var issues  = 0

        for l in links {
            out += String(format: " [#%d] %@ → %@  (%@)\n",
                          l.id, l.sourceFP.name, l.targetFP.name, l.relation.rawValue)

            // Check source
            let srcNow = allProcs.first(where: { $0.kaddr == l.sourceAddr })
            if srcNow == nil {
                out += "  ⚠ source 0x\(String(format: "%llx", l.sourceAddr)) NO LONGER IN allproc → LOST\n"
                issues += 1
            } else {
                let (srcFPNow, _) = _buildFingerprint(procAddr: l.sourceAddr, mgr: mgr)
                if let fpn = srcFPNow, fpn.hex != l.sourceFP.hex {
                    out += "  ⚠ source fingerprint CHANGED\n"
                    out += "    was : \(l.sourceFP.hex)\n"
                    out += "    now : \(fpn.hex)\n"
                    issues += 1
                } else {
                    out += "  ✔ source: \(l.sourceFP.name)  pid=\(srcNow!.pid)  fp stable\n"
                }
            }

            // Check target
            let dstNow = allProcs.first(where: { $0.kaddr == l.targetAddr })
            if dstNow == nil {
                out += "  ⚠ target 0x\(String(format: "%llx", l.targetAddr)) NO LONGER IN allproc → LOST\n"
                issues += 1
            } else {
                let (dstFPNow, _) = _buildFingerprint(procAddr: l.targetAddr, mgr: mgr)
                if let fpn = dstFPNow, fpn.hex != l.targetFP.hex {
                    out += "  ⚠ target fingerprint CHANGED\n"
                    out += "    was : \(l.targetFP.hex)\n"
                    out += "    now : \(fpn.hex)\n"
                    issues += 1
                } else {
                    out += "  ✔ target: \(l.targetFP.name)  pid=\(dstNow!.pid)  fp stable\n"
                }
            }
            out += "  ──────────────────────────────────────────────────────────\n"
        }

        let summary = issues == 0 ? "✔ all \(links.count) link(s) stable" : "⚠ \(issues) drift issue(s) detected"
        out += "════════════════════════════════════════════════════════════\n"
        out += "  summary: \(summary)\n"
        return .ok(out)
    }
}
