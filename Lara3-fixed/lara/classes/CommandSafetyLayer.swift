//
//  CommandSafetyLayer.swift
//  lara
//
//  SMART SAFETY LAYER — iOS 18.3.1
//
//  Principle: "Block only what WILL crash. Let everything else flow."
//
//  Blocks (100% crash or corruption):
//    • kwrite to non-kernel address (bit63=0) → panic
//    • kwrite to KTRR/PPL zone → panic
//    • kwrite to unmapped page → panic
//    • inject-root on PID ≤ 4 (launchd/kernel_task) → panic/respring
//    • voverwrite on kernelcache → panic
//
//  Warns (dangerous but not guaranteed crash):
//    • inject-root on system daemons (PID 5-100)
//    • kwrite to any kernel address (user must know what they do)
//    • respring (loses KRW state)
//
//  Allows freely (read-only or safe):
//    • ALL read commands (kread, proc-cred, ucred-info, ps, proc-find, etc.)
//    • ALL filesystem commands (ls, cat, find, etc.)
//    • ALL info commands (kinfo, apps, device-info, etc.)
//

import Foundation
import Darwin

enum SafetyResult {
    case safe
    case warning(String)   // Proceed with warning prepended
    case blocked(String)   // STOP — will crash
}

final class CommandSafetyLayer {
    static let shared = CommandSafetyLayer()
    private init() {}

    // ── KTRR / kernel text zone (write = guaranteed panic) ──
    private let ktrrStart: UInt64 = 0xFFFFFFF007004000
    private let ktrrEnd:   UInt64 = 0xFFFFFFF007800000

    // ── PIDs that WILL crash on inject-root (99%) ──
    private let guaranteedCrashPIDs: Set<Int32> = [0, 1, 2, 3, 4]

    // ── Commands that WRITE to kernel memory ──
    private let kernelWriteCommands: Set<String> = ["kwrite", "kwrite32"]

    // ── Commands that MODIFY process credentials ──
    private let credWriteCommands: Set<String> = ["inject-root", "proc-csflags-set"]

    // ── Commands that OVERWRITE system files ──
    private let fileWriteCommands: Set<String> = ["voverwrite", "vwrite", "vzero"]

    // MARK: – Main Entry

    func preflight(command: String, arg: String, mgr: laramgr) -> SafetyResult {

        // ── 1. KERNEL WRITE COMMANDS — address validation ──
        if kernelWriteCommands.contains(command) {
            return validateKernelWrite(arg: arg, mgr: mgr)
        }

        // ── 2. CREDENTIAL WRITE — PID validation ──
        if credWriteCommands.contains(command) {
            return validateCredWrite(command: command, arg: arg, mgr: mgr)
        }

        // ── 3. FILE OVERWRITE — path validation ──
        if fileWriteCommands.contains(command) {
            return validateFileWrite(arg: arg)
        }

        // ── 4. RESPRING — state loss warning ──
        if command == "respring" {
            return .warning("respring will restart SpringBoard. All unsaved KRW state will be lost. Run 'transfer' first to persist.")
        }

        // ── 5. REVIVE / RUN — slow operation warning ──
        if command == "revive" || command == "run" {
            return .warning("This re-runs the full kernel exploit. Expect 3-5 seconds of socket spraying.")
        }

        // ── EVERYTHING ELSE — allow freely ──
        // kread, kread32, kbytes, kcstr, proc-cred, ucred-info, proc-info,
        // ps, proc-find, proc-walk, proc-tree, task-info, vmmap-k, ipc-space,
        // fd-info, socket-info, socket-dump, kinfo, apps, ls, cat, find, etc.
        return .safe
    }

    // MARK: – Post-flight (sanity checks on output)

    func postflight(command: String, output: String, mgr: laramgr) -> String {

        // Only check outputs that might be wrong due to bad offsets
        if command == "ucred-info" {
            return validateUcredOutput(output)
        }
        if command == "proc-cred" {
            return validateProcCredOutput(output)
        }

        return output
    }

    // MARK: – Kernel Write Validation (BLOCKS 100% panic scenarios)

    private func validateKernelWrite(arg: String, mgr: laramgr) -> SafetyResult {
        let parts = arg.split(separator: " ").map { String($0) }
        guard let addrStr = parts.first, let addr = parseHex(addrStr) else {
            return .blocked("kwrite: invalid address format. Use: kwrite 0xfffffff0XXXXXXXX 0xVALUE")
        }

        // 1. bit63 check — userland address = 100% panic
        if (addr & (1 << 63)) == 0 {
            return .blocked("kwrite: 0x" + String(addr, radix: 16) + " is not a kernel address (bit63=0). Writing here will panic the device.")
        }

        // 2. KTRR zone — kernel text = 100% panic
        if addr >= ktrrStart && addr < ktrrEnd {
            return .blocked("kwrite: address falls in kernel text (KTRR-protected). Write WILL cause kernel panic.")
        }

        // 3. Unmapped page — 100% panic
        if mgr.dsready && !ds_isvalid(addr) {
            return .blocked("kwrite: 0x" + String(addr, radix: 16) + " is not a mapped kernel page. Write WILL panic.")
        }

        // 4. Valid kernel address — warn but allow (user knows what they do)
        return .warning("kwrite: Writing to kernel memory at 0x" + String(addr, radix: 16) + ". Ensure you know the structure layout. Wrong value = panic.")
    }

    // MARK: – Credential Write Validation (BLOCKS 99% crash scenarios)

    private func validateCredWrite(command: String, arg: String, mgr: laramgr) -> SafetyResult {
        let parts = arg.split(separator: " ").map { String($0) }
        guard let pidStr = parts.first, let pid = Int32(pidStr) else {
            // Allow non-numeric args (e.g. process names) — let the handler deal with it
            return .safe
        }

        // PID 0-4 = kernel_task, launchd, etc. — 99% panic/respring
        if guaranteedCrashPIDs.contains(pid) {
            return .blocked(command + ": PID " + String(pid) + " is a critical system process (launchd/kernel_task). " + command + " here has 99% chance of kernel panic or respring. This is blocked for your safety.")
        }

        // PID 5-100 = system daemons — dangerous but not guaranteed crash
        if pid <= 100 {
            return .warning(command + ": PID " + String(pid) + " is a system daemon. " + command + " here may cause instability or respring. Proceed with caution.")
        }

        // PID > 100 = user apps — generally safe
        return .safe
    }

    // MARK: – File Write Validation

    private func validateFileWrite(arg: String) -> SafetyResult {
        let parts = arg.split(separator: " ").map { String($0) }
        guard let path = parts.first else { return .safe }

        // kernelcache = 100% panic
        if path.contains("kernelcache") || path.contains("com.apple.kernel") {
            return .blocked("voverwrite: path contains kernelcache — this is PPL-protected. Write WILL panic.")
        }

        // SSV paths = dangerous but not panic (just reverted on reboot)
        if path.hasPrefix("/System/") || path.hasPrefix("/usr/libexec/") ||
           path.hasPrefix("/usr/sbin/") || path.hasPrefix("/sbin/") {
            return .warning("voverwrite: '" + path + "' is on Signed System Volume (SSV). Changes will be reverted on reboot. Use only for research.")
        }

        return .safe
    }

    // MARK: – Output Validators (post-flight sanity checks)

    private func validateUcredOutput(_ output: String) -> String {
        // Detect garbage ngroups (> 16 = impossible on iOS)
        if let range = output.range(of: "ngroups"),
           let valRange = output[range.upperBound...].range(of: #"\d+"#, options: .regularExpression) {
            let valStr = String(output[valRange])
            if let ng = Int(valStr), ng > 16 {
                return output + "\n\n[NOTE: ngroups=" + String(ng) + " exceeds iOS NGROUPS_MAX (16). This indicates WRONG ucred offsets. The uid/gid values above may be incorrect. Run 'ucred-info' again or check iOS version compatibility.]"
            }
        }
        return output
    }

    private func validateProcCredOutput(_ output: String) -> String {
        // Detect suspicious gid=4 with uid=501 (wrong offset layout)
        if output.contains("gid   : 4") && output.contains("uid   : 501") {
            return output + "\n\n[NOTE: gid=4 with uid=501 is suspicious. On iOS, app processes should have gid=501 (or 250 for sandbox). gid=4 suggests WRONG offset layout. Verify with 'ucred-info'.]"
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
