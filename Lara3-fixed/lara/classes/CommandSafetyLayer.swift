//
//  CommandSafetyLayer.swift
//  lara
//
//  SURGICAL SAFETY LAYER — iOS 18.3.1
//
//  Mission:   Validate every command before kernel dispatch,
//             cross-validate every result after execution,
//             warn before dangerous operations.
//
//  Principle: "Fail safe, not silent."
//

import Foundation
import Darwin

// MARK: – Validation Result

enum SafetyResult {
    case safe                          // All checks passed — execute freely
    case warning(String)               // Proceed but prepend warning to output
    case dangerous(String)             // High-risk — prepend WARNING block
    case blocked(String)               // Do NOT execute — return error immediately

    var shouldExecute: Bool {
        switch self {
        case .blocked: return false
        default:       return true
        }
    }
}

// MARK: – CommandSafetyLayer

final class CommandSafetyLayer {

    // ── Singleton ────────────────────────────────────────────────────────
    static let shared = CommandSafetyLayer()
    private init() {}

    // ── Known dangerous kernel address ranges (iOS 18 arm64e) ────────────
    // These are heuristic zones — PPL/KTRR protected or highly sensitive.
    private let dangerousZones: [(start: UInt64, end: UInt64, name: String)] = [
        (0xFFFFFE0000000000, 0xFFFFFFFF00000000, "PPL/KTRR protected region"),
        (0xFFFFFFF007004000, 0xFFFFFFF007800000, "kernel text (KTRR) — read-only, panic on write"),
    ]

    // ── Known system PIDs (never inject-root without explicit warning) ───
    private let criticalPIDs: Set<Int32> = [0, 1, 2, 3, 4, 11, 14, 15, 16, 17, 18, 19, 20]

    // ── Commands that require KRW health check ────────────────────────────
    private let krwCommands: Set<String> = [
        "kread", "kwrite", "kread32", "kwrite32", "kbytes", "kcstr",
        "proc-cred", "proc-info", "proc-csflags", "proc-csflags-set",
        "ucred-info", "vmmap-k", "inject-root", "cs-grant", "cs-flags",
        "task-info", "ipc-space", "port-info", "kstruct", "ksearch", "xref",
        "watch32", "watch64", "trace-write", "snapshot", "snapshot-diff",
        "proc-walk", "kalloc", "proc-entitlements", "proc-open-files",
        "proc-mem-info", "fd-info", "socket-info", "socket-dump",
    ]

    // ── Commands that write to kernel memory ──────────────────────────────
    private let writeCommands: Set<String> = [
        "kwrite", "kwrite32", "inject-root", "proc-csflags-set",
        "cs-grant", "voverwrite", "vwrite", "vzero",
    ]

    // ── Commands that target system processes ─────────────────────────────
    private let systemProcCommands: Set<String> = [
        "inject-root", "proc-kill", "proc-signal", "proc-suspend",
    ]

    // MARK: – Pre-flight Validation (called BEFORE handler)

    func preflight(command: String, arg: String, mgr: laramgr) -> SafetyResult {

        // 1. KRW health gate
        if krwCommands.contains(command) {
            let health = validateKRWHealth(mgr: mgr)
            if case .blocked(let msg) = health { return .blocked(msg) }
            if case .warning(let msg) = health { return .warning(msg) }
        }

        // 2. Address validation (kread/kwrite family)
        if ["kread", "kwrite", "kread32", "kwrite32", "kbytes", "kcstr"].contains(command) {
            return validateKernelAddressCommand(command: command, arg: arg, mgr: mgr)
        }

        // 3. PID validation (proc-* family)
        if command.hasPrefix("proc-") || ["ucred-info", "task-info", "vmmap-k",
             "inject-root", "ipc-space", "fd-info", "socket-info"].contains(command) {
            return validatePIDCommand(command: command, arg: arg, mgr: mgr)
        }

        // 4. File path validation (voverwrite, vwrite, vzero)
        if ["voverwrite", "vwrite", "vzero"].contains(command) {
            return validateFileWriteCommand(command: command, arg: arg, mgr: mgr)
        }

        // 5. General danger assessment
        return assessDanger(command: command, arg: arg, mgr: mgr)
    }

    // MARK: – Post-flight Validation (called AFTER handler)

    func postflight(command: String, output: String, mgr: laramgr) -> String {

        // 1. ucred sanity check
        if command == "ucred-info" {
            return validateUcredOutput(output)
        }

        // 2. proc-cred sanity check
        if command == "proc-cred" {
            return validateProcCredOutput(output)
        }

        // 3. kread sanity check
        if command == "kread" || command == "kread32" {
            return validateKReadOutput(output)
        }

        return output
    }

    // MARK: – KRW Health Validation

    private func validateKRWHealth(mgr: laramgr) -> SafetyResult {
        guard mgr.dsready else {
            return .blocked("\(command): KRW session not ready — run 'run' first")
        }

        // Socket health probe — lightweight read of kernel base magic
        let kbase = ds_get_kernel_base()
        guard kbase != 0 else {
            return .blocked("KRW session degraded — kernel_base is zero. Run 'revive'")
        }

        do {
            let magic = ds_kread32(kbase)
            guard magic == 0xFEEDFACF else {
                return .blocked("KRW session corrupted — kernel magic mismatch (0x\(String(magic, radix: 16))). Run 'revive'")
            }
        } catch {
            return .blocked("KRW socket disconnected — \(error). Run 'revive'")
        }

        // Thermal state check
        let thermal = ProcessInfo.processInfo.thermalState
        if thermal == .critical {
            return .warning("⚠️ CRITICAL thermal state — KRW ops may be throttled by iOS")
        } else if thermal == .serious {
            return .warning("⚠️ SERIOUS thermal state — consider cooling device")
        }

        return .safe
    }

    // MARK: – Kernel Address Validation

    private func validateKernelAddressCommand(command: String, arg: String, mgr: laramgr) -> SafetyResult {
        let parts = arg.split(separator: " ").map { String($0) }
        guard let addrStr = parts.first, let addr = parseHex(addrStr) else {
            return .blocked("\(command): invalid address format — use 0x...")
        }

        // Bit63 check (arm64e kernel addresses must have bit63 set)
        if (addr & (1 << 63)) == 0 {
            return .blocked("\(command): 0x\(String(addr, radix: 16)) is not a valid kernel address (bit63=0)")
        }

        // ds_isvalid mappedness check
        if !ds_isvalid(addr) {
            return .blocked("\(command): 0x\(String(addr, radix: 16)) is not mapped in kernel space")
        }

        // Danger zone check
        for zone in dangerousZones {
            if addr >= zone.start && addr < zone.end {
                if writeCommands.contains(command) {
                    return .blocked("\(command): address falls in \(zone.name) — WRITE WILL PANIC")
                } else {
                    return .dangerous("⚠️ WARNING: address in \(zone.name).
    Read-only recommended. Any write = kernel panic.")
                }
            }
        }

        // Alignment check for 32-bit ops
        if command == "kread32" || command == "kwrite32" {
            if addr % 4 != 0 {
                return .warning("⚠️ Address 0x\(String(addr, radix: 16)) is not 4-byte aligned — may cause unaligned access")
            }
        }

        // Write-specific checks
        if writeCommands.contains(command) {
            guard parts.count >= 2 else {
                return .blocked("\(command): missing value argument")
            }
            guard parseHex(parts[1]) != nil else {
                return .blocked("\(command): invalid value format — use 0x...")
            }
            return .dangerous("⚠️ DANGER: Writing to kernel memory at 0x\(String(addr, radix: 16)).
    This can cause kernel panic, data loss, or device boot-loop.
    Ensure you have a valid backup before proceeding.")
        }

        return .safe
    }

    // MARK: – PID Validation

    private func validatePIDCommand(command: String, arg: String, mgr: laramgr) -> SafetyResult {
        let parts = arg.split(separator: " ").map { String($0) }
        guard let pidStr = parts.first, let pid = Int32(pidStr) else {
            return .blocked("\(command): invalid PID — use numeric value")
        }

        guard pid >= 0 else {
            return .blocked("\(command): PID cannot be negative")
        }

        // Existence check via BSD API (fast, safe)
        var info = proc_bsdinfo()
        let exists = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info,
                                  Int32(MemoryLayout<proc_bsdinfo>.size)) > 0

        if !exists && !mgr.dsready {
            return .blocked("\(command): PID \(pid) does not exist and KRW unavailable for kernel fallback")
        }

        // System process warnings
        if criticalPIDs.contains(pid) || (exists && info.pbi_uid == 0 && pid <= 100) {
            if systemProcCommands.contains(command) {
                return .dangerous("⚠️ CRITICAL: PID \(pid) is a system process (\(exists ? String(cString: info.pbi_comm) : "unknown")).
    \(command) on system processes can cause kernel panic or respring.
    Proceed only if you understand the consequences.")
            }
            if command == "proc-cred" || command == "ucred-info" {
                return .warning("⚠️ PID \(pid) is a system process. Some fields may be PPL-protected.")
            }
        }

        // inject-root specific
        if command == "inject-root" {
            if pid == getpid() {
                return .dangerous("⚠️ WARNING: You are about to inject root into LARA itself (PID \(pid)).
    This is usually unnecessary — LARA already has root via sandbox escape.")
            }
            guard exists else {
                return .blocked("inject-root: PID \(pid) does not exist")
            }
            guard info.pbi_uid != 0 else {
                return .dangerous("⚠️ WARNING: PID \(pid) already runs as root.
    inject-root is redundant and may destabilize the process.")
            }
        }

        return .safe
    }

    // MARK: – File Write Validation

    private func validateFileWriteCommand(command: String, arg: String, mgr: laramgr) -> SafetyResult {
        let parts = arg.split(separator: " ").map { String($0) }
        guard let path = parts.first else {
            return .blocked("\(command): missing path argument")
        }

        // SSV (Signed System Volume) check
        if path.hasPrefix("/System/") || path.hasPrefix("/usr/libexec/") ||
           path.hasPrefix("/usr/sbin/") || path.hasPrefix("/sbin/") {
            return .dangerous("⚠️ DANGER: Path '\(path)' is on Signed System Volume (SSV).
    Writes may be reverted on reboot or cause boot-loop.
    Use voverwrite only for research with valid backup.")
        }

        // PPL-protected paths
        if path.contains("kernelcache") || path.contains("com.apple.kernel") {
            return .blocked("\(command): path contains kernelcache — PPL-protected, write WILL PANIC")
        }

        return .safe
    }

    // MARK: – General Danger Assessment

    private func assessDanger(command: String, arg: String, mgr: laramgr) -> SafetyResult {
        // respring warning
        if command == "respring" {
            return .dangerous("⚠️ WARNING: respring will restart SpringBoard.
    All unsaved KRW state will be lost.
    Run 'transfer' first if you want to persist primitives.")
        }

        // revive warning
        if command == "revive" || command == "run" {
            return .warning("⚠️ This will re-run the full kernel exploit.
    Expect 3-5 seconds of socket spraying.")
        }

        return .safe
    }

    // MARK: – Post-flight Output Validators

    private func validateUcredOutput(_ output: String) -> String {
        // Detect garbage ngroups
        if let range = output.range(of: "ngroups"),
           let valRange = output[range.upperBound...].range(of: #"\d+"#, options: .regularExpression) {
            let valStr = String(output[valRange])
            if let ng = Int(valStr), ng > 16 {
                return output + "

⚠️ SAFETY WARNING: ngroups=\(ng) exceeds NGROUPS_MAX (16).
    This indicates WRONG ucred offsets. Do NOT trust uid/gid values above.
    Run 'ucred-info' again — if persistent, offsets need update for this iOS version."
            }
        }
        return output
    }

    private func validateProcCredOutput(_ output: String) -> String {
        // Detect inconsistent gid/uid
        if output.contains("gid   : 4") && output.contains("uid   : 501") {
            return output + "

⚠️ SAFETY WARNING: gid=4 with uid=501 is SUSPICIOUS.
    On iOS, app processes should have gid=501 (or 250 for sandbox).
    gid=4 suggests WRONG offset layout. Verify with 'ucred-info'."
        }
        return output
    }

    private func validateKReadOutput(_ output: String) -> String {
        // Detect suspicious zero reads from non-zero addresses
        if output.contains("=  0x0000000000000000") {
            return output + "
  [NOTE: zero read — may indicate unmapped page or stripped PAC]"
        }
        return output
    }

    // MARK: – Helpers

    private func parseHex(_ s: String) -> UInt64? {
        let cleaned = s.trimmingCharacters(in: .whitespaces)
        if cleaned.hasPrefix("0x") || cleaned.hasPrefix("0X") {
            return UInt64(cleaned.dropFirst(2), radix: 16)
        }
        return UInt64(cleaned, radix: 16) ?? UInt64(cleaned)
    }
}
