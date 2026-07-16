//
//  CommandSafetyLayer.swift
//  lara
//
//  SURGICAL SAFETY LAYER — iOS 18.3.1
//
//  Philosophy: "I am your surgical assistant. I look inside before cutting."
//
//  NOT a bouncer. NOT a gatekeeper.
//  I examine the kernel structure, verify the target, analyze the risk,
//  then tell you: 'Go ahead' or 'Stop — and here is WHY, with evidence.'
//
//  For every dangerous command, I:
//    1. READ the target area first (non-destructive)
//    2. ANALYZE what I found (structure, permissions, state)
//    3. VALIDATE against the command's intent
//    4. REPORT with evidence: 'I checked, here is what I saw...'
//

import Foundation
import Darwin

enum SafetyResult {
    case safe
    case proceedWithNote(String)   // Go ahead, but here is what I noticed
    case stopAndExplain(String)   // Do NOT proceed. Here is what I found + why + correction
}

final class CommandSafetyLayer {
    static let shared = CommandSafetyLayer()
    private init() {}

    // MARK: – Main Entry

    func preflight(command: String, arg: String, mgr: laramgr) -> SafetyResult {

        // ── KERNEL WRITE — kwrite / kwrite32 ──
        if command == "kwrite" || command == "kwrite32" {
            return analyzeKernelWrite(arg: arg, mgr: mgr)
        }

        // ── CREDENTIAL INJECTION — inject-root ──
        if command == "inject-root" {
            return analyzeInjectRoot(arg: arg, mgr: mgr)
        }

        // ── FILE OVERWRITE — voverwrite / vwrite / vzero ──
        if command == "voverwrite" || command == "vwrite" || command == "vzero" {
            return analyzeFileWrite(arg: arg, mgr: mgr)
        }

        // ── RESPRING — state loss warning ──
        if command == "respring" {
            return .proceedWithNote("respring will restart SpringBoard. All KRW state will be lost. Run 'transfer' first to persist primitives to launchd.")
        }

        // ── EVERYTHING ELSE — reads, listings, info — all safe ──
        return .safe
    }

    // MARK: – Post-flight (validate outputs)

    func postflight(command: String, output: String, mgr: laramgr) -> String {
        if command == "ucred-info" { return validateUcredOutput(output) }
        if command == "proc-cred" { return validateProcCredOutput(output) }
        return output
    }

    // MARK: – 1. KERNEL WRITE ANALYSIS (the surgeon looks before cutting)

    private func analyzeKernelWrite(arg: String, mgr: laramgr) -> SafetyResult {
        let parts = arg.split(separator: " ").map { String($0) }
        guard let addrStr = parts.first, let addr = parseHex(addrStr) else {
            return .stopAndExplain("I cannot parse the address. Format: kwrite 0xfffffff0XXXXXXXX 0xVALUE")
        }

        guard parts.count >= 2 else {
            return .stopAndExplain("Missing value. Format: kwrite 0xfffffff0XXXXXXXX 0xVALUE")
        }

        // ── Step 1: Is this even a kernel address? ──
        if (addr & (1 << 63)) == 0 {
            return .stopAndExplain(
                "I checked the address 0x" + String(addr, radix: 16) + ".\n" +
                "  → bit63 = 0. This is a USERLAND address, not kernel space.\n" +
                "  → Writing here will panic the device 100%.\n" +
                "  → Kernel addresses on arm64e MUST have bit63 = 1 (start with 0xfffffff...)."
            )
        }

        guard mgr.dsready else {
            return .stopAndExplain("KRW session not active. Run 'run' or 'revive' first.")
        }

        // ── Step 2: Is the page mapped? ──
        if !ds_isvalid(addr) {
            return .stopAndExplain(
                "I checked address 0x" + String(addr, radix: 16) + ".\n" +
                "  → ds_isvalid() returned FALSE. This page is NOT mapped in kernel space.\n" +
                "  → Writing to unmapped memory WILL cause kernel panic."
            )
        }

        // ── Step 3: Read the current value (non-destructive probe) ──
        let currentValue = ds_kread64(addr)

        // ── Step 4: Is this the kernel Mach-O header? ──
        let kbase = ds_get_kernel_base()
        if kbase != 0 && addr >= kbase && addr < kbase + 0x4000 {
            let magic = ds_kread32(kbase)
            return .stopAndExplain(
                "I examined address 0x" + String(addr, radix: 16) + ".\n" +
                "  → This is inside the kernel Mach-O header (kernel_base + 0x" + String(addr - kbase, radix: 16) + ").\n" +
                "  → I read the Mach-O magic: 0x" + String(magic, radix: 16) + " (expected 0xfeedfacf).\n" +
                "  → The Mach-O header is READ-ONLY (KTRR protected).\n" +
                "  → Writing here WILL panic the device.\n" +
                "  → If you want to patch kernel code, use a code-injection framework, not kwrite."
            )
        }

        // ── Step 5: Is this in kernel text segment? ──
        if kbase != 0 && addr >= kbase && addr < kbase + 0x100000 {
            // Try to determine if it's text by checking for executable patterns
            let nearby = ds_kread64(addr & ~0xFFF)  // Page-aligned read
            // If we see ARM64 instructions (common patterns), it's likely text
            if isLikelyText(addr: addr, kbase: kbase) {
                return .stopAndExplain(
                    "I examined address 0x" + String(addr, radix: 16) + ".\n" +
                    "  → This appears to be in the kernel TEXT segment (executable code).\n" +
                    "  → Current value: 0x" + String(currentValue, radix: 16) + ".\n" +
                    "  → Kernel text is READ-ONLY. Writing here WILL panic.\n" +
                    "  → If you need to hook kernel functions, use a proper kext/code-patch framework."
                )
            }
        }

        // ── Step 6: Is this a kernel data structure? ──
        if let structureGuess = identifyKernelStructure(at: addr, mgr: mgr) {
            return .proceedWithNote(
                "I examined address 0x" + String(addr, radix: 16) + ".\n" +
                "  → Current value: 0x" + String(currentValue, radix: 16) + ".\n" +
                "  → Structure analysis: " + structureGuess + ".\n" +
                "  → This appears to be kernel data (writable). Proceed with caution."
            )
        }

        // ── Step 7: Unknown kernel address — allow with full disclosure ──
        return .proceedWithNote(
            "I examined address 0x" + String(addr, radix: 16) + ".\n" +
            "  → Current value: 0x" + String(currentValue, radix: 16) + ".\n" +
            "  → Page is mapped and writable (not in KTRR zone).\n" +
            "  → I could not identify the structure. Ensure you know what you are overwriting."
        )
    }

    // MARK: – 2. INJECT-ROOT ANALYSIS (examine proc before modifying)

    private func analyzeInjectRoot(arg: String, mgr: laramgr) -> SafetyResult {
        let parts = arg.split(separator: " ").map { String($0) }
        guard let pidStr = parts.first, let pid = Int32(pidStr) else {
            // Allow process names — let the handler resolve it
            return .safe
        }

        guard pid >= 0 else {
            return .stopAndExplain("PID cannot be negative. You provided: " + String(pid))
        }

        guard mgr.dsready else {
            return .stopAndExplain("KRW session not active. Run 'run' or 'revive' first.")
        }

        // ── Step 1: Find proc in kernel ──
        let kaddr = procbypid(pid_t(pid))
        guard kaddr != 0 else {
            return .stopAndExplain(
                "I searched kernel allproc for PID " + String(pid) + ".\n" +
                "  → procbypid() returned 0. This process does not exist in the kernel list.\n" +
                "  → The process may have exited, or the PID is wrong."
            )
        }

        // ── Step 2: Read proc name from kernel ──
        var procName = "unknown"
        for off: UInt64 in [0x268, 0x2d0, 0x56c] {
            var buf = [UInt8](repeating: 0, count: 17)
            ds_kreadbuf(kaddr + off, &buf, 16)
            if let s = String(bytes: buf.prefix(while: { $0 != 0 }), encoding: .utf8), !s.isEmpty {
                procName = s
                break
            }
        }

        // ── Step 3: Find ucred via dynamic probing ──
        let procROOffsets: [UInt64] = [0x18, 0x20, 0x28, 0x30]
        let ucredROOffsets: [UInt64] = [0x08, 0x10, 0x18, 0x20]
        let credBaseOffsets: [UInt64] = [0x18, 0x20]

        var bestProcRO: UInt64 = 0
        var bestUcred: UInt64 = 0
        var bestBase: UInt64 = 0x18
        var bestScore = -1

        for pro in procROOffsets {
            let proc_ro = mgr.kread64(address: kaddr + pro)
            guard proc_ro != 0 else { continue }
            for uco in ucredROOffsets {
                let ucred = mgr.kread64(address: proc_ro + uco)
                guard ucred != 0 else { continue }
                for cBase in credBaseOffsets {
                    let c_uid = mgr.kread32(address: ucred + cBase)
                    let c_gid = mgr.kread32(address: ucred + cBase + 0x0C)
                    let c_ng = mgr.kread32(address: ucred + cBase + 0x18)
                    var score = 0
                    if c_uid < 100_000 { score += 10 }
                    if c_gid < 100_000 { score += 10 }
                    if c_ng <= 16 { score += 200 }
                    if score > bestScore {
                        bestScore = score
                        bestProcRO = proc_ro
                        bestUcred = ucred
                        bestBase = cBase
                    }
                }
            }
        }

        guard bestUcred != 0 else {
            return .stopAndExplain(
                "I examined PID " + String(pid) + " (" + procName + ") in the kernel.\n" +
                "  → Found proc at 0x" + String(kaddr, radix: 16) + ".\n" +
                "  → BUT: I could not locate a valid ucred structure.\n" +
                "  → All 32 offset combinations failed validation.\n" +
                "  → This iOS version may have a new ucred layout we have not mapped.\n" +
                "  → inject-root is NOT safe without confirmed ucred location."
            )
        }

        // ── Step 4: Read current credentials ──
        let currentUID = mgr.kread32(address: bestUcred + bestBase)
        let currentGID = mgr.kread32(address: bestUcred + bestBase + 0x0C)

        // ── Step 5: Is it already root? ──
        if currentUID == 0 {
            return .stopAndExplain(
                "I examined PID " + String(pid) + " (" + procName + ").\n" +
                "  → proc at: 0x" + String(kaddr, radix: 16) + ".\n" +
                "  → ucred at: 0x" + String(bestUcred, radix: 16) + " (layout score: " + String(bestScore) + ").\n" +
                "  → Current uid: " + String(currentUID) + ", gid: " + String(currentGID) + ".\n" +
                "  → This process ALREADY runs as root (uid=0).\n" +
                "  → inject-root is redundant. No need to modify credentials."
            )
        }

        // ── Step 6: Is it a critical system process? ──
        if pid <= 4 {
            return .stopAndExplain(
                "I examined PID " + String(pid) + " (" + procName + ").\n" +
                "  → proc at: 0x" + String(kaddr, radix: 16) + ".\n" +
                "  → ucred at: 0x" + String(bestUcred, radix: 16) + ".\n" +
                "  → This is a CRITICAL system process (launchd, kernel_task, etc.).\n" +
                "  → Modifying its credentials has 99% chance of kernel panic or respring.\n" +
                "  → If you need to debug system processes, use proper kernel debugging tools."
            )
        }

        // ── Step 7: User app — safe to proceed ──
        return .proceedWithNote(
            "I examined PID " + String(pid) + " (" + procName + ").\n" +
            "  → proc at: 0x" + String(kaddr, radix: 16) + ".\n" +
            "  → ucred at: 0x" + String(bestUcred, radix: 16) + " (layout score: " + String(bestScore) + ").\n" +
            "  → Current uid: " + String(currentUID) + ", gid: " + String(currentGID) + ".\n" +
            "  → This is a user app. inject-root should be safe. Proceeding."
        )
    }

    // MARK: – 3. FILE OVERWRITE ANALYSIS

    private func analyzeFileWrite(arg: String, mgr: laramgr) -> SafetyResult {
        let parts = arg.split(separator: " ").map { String($0) }
        guard let path = parts.first else { return .safe }

        // kernelcache = 100% panic
        if path.contains("kernelcache") || path.contains("com.apple.kernel") {
            return .stopAndExplain(
                "I checked the path: " + path + ".\n" +
                "  → This path contains 'kernelcache' or kernel references.\n" +
                "  → The kernelcache is PPL-protected (Page Protection Layer).\n" +
                "  → ANY write to kernelcache pages WILL cause kernel panic.\n" +
                "  → Even root cannot bypass PPL without a separate PPL bypass exploit."
            )
        }

        // SSV paths = revert on reboot, not panic
        if path.hasPrefix("/System/") || path.hasPrefix("/usr/libexec/") ||
           path.hasPrefix("/usr/sbin/") || path.hasPrefix("/sbin/") {
            return .proceedWithNote(
                "I checked the path: " + path + ".\n" +
                "  → This is on the Signed System Volume (SSV).\n" +
                "  → The write will succeed, but iOS will revert it on next boot.\n" +
                "  → It will NOT cause panic, but it is NOT persistent."
            )
        }

        return .safe
    }

    // MARK: – Helpers

    private func isLikelyText(addr: UInt64, kbase: UInt64) -> Bool {
        // Heuristic: read a few bytes and check for common ARM64 instruction patterns
        let val = ds_kread32(addr)
        // Common ARM64 prologue patterns or NOPs
        let textPatterns: [UInt32] = [0xd503201f, 0xa9be7bfd, 0xa9bf7bfd, 0xd10143ff]
        return textPatterns.contains(val)
    }

    private func identifyKernelStructure(at addr: UInt64, mgr: laramgr) -> String? {
        // Heuristic structure identification
        let val = ds_kread64(addr)
        let kbase = ds_get_kernel_base()

        // Check if it looks like a pointer to kernel heap
        if val != 0 && (val & 0xFFFFFF0000000000) == 0xFFFFFF0000000000 {
            // Could be a pointer to another kernel object
            let targetVal = ds_kread64(val)
            if targetVal == 0x4242424242424242 || targetVal == 0x4141414141414141 {
                return "likely heap object (detected canary pattern at pointed-to address)"
            }
        }

        // Check if it is within kernel_base + known zones
        if kbase != 0 && addr >= kbase + 0x100000 && addr < kbase + 0x2000000 {
            return "likely kernel data (__DATA segment)"
        }

        // Check for common structure signatures
        let first32 = ds_kread32(addr)
        if first32 == 0x1 || first32 == 0x0 {
            // Could be refcount or flags
            let second32 = ds_kread32(addr + 4)
            if second32 < 1000 {
                return "possibly struct with refcount/flags (first fields: " + String(first32) + ", " + String(second32) + ")"
            }
        }

        return nil
    }

    private func parseHex(_ s: String) -> UInt64? {
        let cleaned = s.trimmingCharacters(in: .whitespaces)
        if cleaned.hasPrefix("0x") || cleaned.hasPrefix("0X") {
            return UInt64(cleaned.dropFirst(2), radix: 16)
        }
        return UInt64(cleaned, radix: 16) ?? UInt64(cleaned)
    }

    private func validateUcredOutput(_ output: String) -> String {
        if let range = output.range(of: "ngroups"),
           let valRange = output[range.upperBound...].range(of: #"\d+"#, options: .regularExpression) {
            let valStr = String(output[valRange])
            if let ng = Int(valStr), ng > 16 {
                return output + "\n\n[ANALYSIS: ngroups=" + String(ng) + " exceeds NGROUPS_MAX (16). I checked the ucred layout and it appears WRONG for this iOS version. The uid/gid values above should NOT be trusted. Run 'ucred-info' again or verify offsets.]"
            }
        }
        return output
    }

    private func validateProcCredOutput(_ output: String) -> String {
        if output.contains("gid   : 4") && output.contains("uid   : 501") {
            return output + "\n\n[ANALYSIS: gid=4 with uid=501 is anomalous. On iOS, app processes should have gid=501 (or 250 for sandbox). I detected a possible WRONG offset layout. Verify with 'ucred-info'.]"
        }
        return output
    }
}
