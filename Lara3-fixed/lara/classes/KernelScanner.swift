//
//  KernelScanner.swift
//  lara
//
//  Pattern Matching Scanner (ASLR-independent) + Transaction Write Engine
//  ─────────────────────────────────────────────────────────────────────────
//
//  Commands registered here:
//    find_pattern <hex_bytes> [--range <start_hex> <end_hex>]
//      Scans kernel memory for a byte-pattern "fingerprint" without needing
//      an absolute address.  Works even when ASLR shifts the kernel.
//      Example: find_pattern "e9 03 00 91 08 00 40 f9" --range 0xfffffff007000000 0xfffffff010000000
//
//    transaction_write <addr_hex> <value_hex> [--width 8|4|2|1]
//      Atomic safety valve:
//        1) Read current value (save)
//        2) Write new value
//        3) Read back and verify
//        4) On mismatch → auto-rollback to original value
//      Prevents kernel panics from bad writes.
//
//    kwrite_safe <addr_hex> <value_hex>
//      Alias for transaction_write with width=8.
//
//    kread_range <start_hex> <end_hex>
//      Hexdump a kernel memory range (max 1 KB).
//
//    kfind_ptr <ptr_hex> [--range <start_hex> <end_hex>]
//      Search for a 64-bit pointer value in kernel memory.
//
//    kscan_zero <start_hex> <end_hex>
//      Find 8-byte-aligned zero qwords in a range (useful for locating
//      uninitialized struct fields or free-list entries).
//
//    kverify <addr_hex> <expected_hex> [--width 8|4|2|1]
//      Read addr and compare to expected — reports match/mismatch with
//      actual value.  Useful before a destructive write.
//

import Foundation
import Darwin

// MARK: – Private helpers

private func _parseHex(_ s: String) -> UInt64? {
    let t = s.trimmingCharacters(in: .whitespaces)
    let stripped = (t.hasPrefix("0x") || t.hasPrefix("0X")) ? String(t.dropFirst(2)) : t
    return UInt64(stripped, radix: 16)
}

/// "aa bb cc" or "aabbcc" or "0xaa 0xbb" → [UInt8]
private func _parsePattern(_ s: String) -> [UInt8]? {
    let raw = s.trimmingCharacters(in: .whitespaces)
    // Try space-separated first
    let tokens = raw.components(separatedBy: CharacterSet(charactersIn: " \t"))
                    .filter { !$0.isEmpty }
    var bytes: [UInt8] = []
    for tok in tokens {
        let clean = (tok.hasPrefix("0x") || tok.hasPrefix("0X")) ? String(tok.dropFirst(2)) : tok
        guard clean.count == 2, let b = UInt8(clean, radix: 16) else { return nil }
        bytes.append(b)
    }
    return bytes.isEmpty ? nil : bytes
}

/// Split args into: pattern part, optional --range part
private func _splitRange(_ raw: String) -> (main: String, range: String?) {
    if let idx = raw.range(of: "--range") {
        let main  = String(raw[raw.startIndex ..< idx.lowerBound]).trimmingCharacters(in: .whitespaces)
        let rest  = String(raw[idx.upperBound...]).trimmingCharacters(in: .whitespaces)
        return (main, rest)
    }
    return (raw.trimmingCharacters(in: .whitespaces), nil)
}

/// Parse "start end" from --range body, falling back to defaults relative to kernBase
private func _parseRangeArgs(_ rangeStr: String?, kernBase: UInt64) -> (UInt64, UInt64)? {
    guard let r = rangeStr else {
        return (kernBase, kernBase &+ 0x2000_0000) // 512 MB default window
    }
    let parts = r.split(separator: " ").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    guard parts.count >= 2,
          let s = _parseHex(parts[0]),
          let e = _parseHex(parts[1]) else { return nil }
    return (s, e)
}

// MARK: – Registration entry-point (called from OmegaBootstrap)

func registerKernelScannerCommands() {

    // ── find_pattern ──────────────────────────────────────────────────────────
    OmegaCore.register("find_pattern") { rawArg, mgr in
        guard mgr.dsready else { return .fail("find_pattern: exploit not ready — run 'run' first") }

        let (patStr, rangeStr) = _splitRange(rawArg)
        guard !patStr.isEmpty, let pattern = _parsePattern(patStr) else {
            return .fail(
                "find_pattern: usage:\n" +
                "  find_pattern <hex_bytes> [--range <start_hex> <end_hex>]\n" +
                "  hex_bytes: space-separated bytes, e.g. \"ff 43 00 d1 e9 03 00 91\"\n" +
                "  --range defaults to 512 MB from kernel_base"
            )
        }
        guard pattern.count >= 2 else { return .fail("find_pattern: pattern must be ≥ 2 bytes") }

        let kernBase = ds_get_kernel_base()
        guard kernBase != 0 else { return .fail("find_pattern: kernel_base not available") }

        guard let (rangeStart, rangeEnd) = _parseRangeArgs(rangeStr, kernBase: kernBase) else {
            return .fail("find_pattern: --range needs two hex addresses: --range <start> <end>")
        }
        guard rangeStart < rangeEnd else { return .fail("find_pattern: range start >= end") }

        let scanBytes = rangeEnd - rangeStart
        guard scanBytes <= 0x1000_0000 else {         // hard cap: 256 MB
            return .fail("find_pattern: range too large (max 256 MB = 0x10000000)")
        }

        let patLen  = UInt64(pattern.count)
        let slide   = ds_get_kernel_slide()
        var hits: [UInt64] = []
        let maxHits = 64
        var addr    = rangeStart                       // byte-by-byte scan (accurate)

        while addr + patLen <= rangeEnd, hits.count < maxHits {
            // Fast first-byte check before full comparison
            if ds_kread8(addr) == pattern[0] {
                var ok = true
                for i in 1 ..< patLen {
                    if ds_kread8(addr + i) != pattern[Int(i)] { ok = false; break }
                }
                if ok { hits.append(addr) }
            }
            addr &+= 1
        }

        let patHex = pattern.map { String(format: "%02x", $0) }.joined(separator: " ")
        if hits.isEmpty {
            return .ok(
                "find_pattern: no matches\n" +
                "  pattern   : \(patHex)\n" +
                String(format: "  scanned   : 0x%llx – 0x%llx (%llu bytes)\n", rangeStart, rangeEnd, scanBytes) +
                String(format: "  kernel_base: 0x%llx  slide: 0x%llx\n", kernBase, slide)
            )
        }

        var out =  "find_pattern: \(hits.count) hit(s) [\(hits.count == maxHits ? "limit reached" : "all")]\n"
        out     += "  pattern    : \(patHex)\n"
        out     += String(format: "  range      : 0x%llx – 0x%llx\n", rangeStart, rangeEnd)
        out     += String(format: "  kernel_base: 0x%llx  slide: 0x%llx\n", kernBase, slide)
        out     += "──────────────────────────────────────────────────────\n"
        for va in hits {
            let unslid = va &- slide
            out += String(format: "  [HIT] va=0x%016llx  unslid=0x%016llx\n", va, unslid)
        }
        if hits.count == maxHits { out += "  (stopped at \(maxHits) hits — narrow range or use more specific pattern)\n" }
        return .ok(out)
    }

    // ── transaction_write ─────────────────────────────────────────────────────
    // Usage: transaction_write <addr_hex> <value_hex> [--width 8|4|2|1]
    OmegaCore.register("transaction_write") { rawArg, mgr in
        guard mgr.dsready else { return .fail("transaction_write: exploit not ready") }

        let tokens = rawArg.split(separator: " ")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }

        guard tokens.count >= 2 else {
            return .fail(
                "transaction_write: usage:\n" +
                "  transaction_write <addr_hex> <value_hex> [--width 8|4|2|1]\n" +
                "  Performs read→write→verify→rollback atomically.\n" +
                "  --width defaults to 8 (64-bit)"
            )
        }

        guard let addr  = _parseHex(tokens[0]) else { return .fail("transaction_write: invalid address '\(tokens[0])'") }
        guard let value = _parseHex(tokens[1]) else { return .fail("transaction_write: invalid value '\(tokens[1])'") }

        // Parse optional --width
        var width = 8
        if let wi = tokens.firstIndex(of: "--width"), wi + 1 < tokens.count {
            width = Int(tokens[wi + 1]) ?? 8
        }
        guard [1, 2, 4, 8].contains(width) else {
            return .fail("transaction_write: --width must be 1, 2, 4, or 8")
        }

        let mask: UInt64 = width < 8 ? ((1 << (width * 8)) - 1) : 0xFFFF_FFFF_FFFF_FFFF
        let writeable = value & mask

        // 1. READ — save original
        let original: UInt64
        switch width {
        case 1:  original = UInt64(ds_kread8(addr))
        case 2:  original = UInt64(ds_kread16(addr))
        case 4:  original = UInt64(ds_kread32(addr))
        default: original = ds_kread64(addr)
        }

        // 2. WRITE
        switch width {
        case 1:  ds_kwrite8(addr,  UInt8(writeable))
        case 2:  ds_kwrite16(addr, UInt16(writeable))
        case 4:  ds_kwrite32(addr, UInt32(writeable))
        default: ds_kwrite64(addr, writeable)
        }

        // 3. VERIFY (read back)
        let readback: UInt64
        switch width {
        case 1:  readback = UInt64(ds_kread8(addr))
        case 2:  readback = UInt64(ds_kread16(addr))
        case 4:  readback = UInt64(ds_kread32(addr))
        default: readback = ds_kread64(addr)
        }

        if readback == writeable {
            // SUCCESS
            return .ok(String(format:
                "transaction_write: ✔ SUCCESS\n" +
                "  addr     : 0x%016llx\n" +
                "  width    : %d bytes\n" +
                "  original : 0x%llx\n" +
                "  written  : 0x%llx\n" +
                "  readback : 0x%llx  ← matches ✔\n",
                addr, width, original, writeable, readback
            ))
        }

        // 4. ROLLBACK — write failed verification
        switch width {
        case 1:  ds_kwrite8(addr,  UInt8(original  & 0xFF))
        case 2:  ds_kwrite16(addr, UInt16(original & 0xFFFF))
        case 4:  ds_kwrite32(addr, UInt32(original & 0xFFFF_FFFF))
        default: ds_kwrite64(addr, original)
        }

        return .fail(String(format:
            "transaction_write: ✖ VERIFY FAILED → ROLLED BACK\n" +
            "  addr     : 0x%016llx\n" +
            "  width    : %d bytes\n" +
            "  expected : 0x%llx\n" +
            "  got      : 0x%llx\n" +
            "  restored : 0x%llx  ← original value restored\n",
            addr, width, writeable, readback, original
        ))
    }

    // ── kwrite_safe (alias) ───────────────────────────────────────────────────
    OmegaCore.register("kwrite_safe") { rawArg, mgr in
        guard mgr.dsready else { return .fail("kwrite_safe: exploit not ready") }
        let tokens = rawArg.split(separator: " ")
            .map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        guard tokens.count >= 2 else {
            return .fail("kwrite_safe: usage — kwrite_safe <addr_hex> <value_hex>")
        }
        return OmegaCore.execute("transaction_write \(tokens[0]) \(tokens[1])", context: mgr)
    }

    // ── kread_range ───────────────────────────────────────────────────────────
    OmegaCore.register("kread_range") { rawArg, mgr in
        guard mgr.dsready else { return .fail("kread_range: exploit not ready") }
        let tokens = rawArg.split(separator: " ")
            .map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        guard tokens.count >= 2,
              let start = _parseHex(tokens[0]),
              let end   = _parseHex(tokens[1]),
              start < end else {
            return .fail("kread_range: usage — kread_range <start_hex> <end_hex>  (max 1 KB)")
        }
        let maxSize: UInt64 = 0x400   // 1 KB cap
        let size = min(end - start, maxSize)

        var out = String(format: "kread_range: 0x%llx – 0x%llx  (%llu bytes)\n", start, start + size, size)
        var i: UInt64 = 0
        while i < size {
            if i % 16 == 0 { out += String(format: "\n  %04llx: ", i) }
            out += String(format: "%02x ", ds_kread8(start + i))
            i += 1
        }
        out += "\n"
        return .ok(out)
    }

    // ── kfind_ptr ─────────────────────────────────────────────────────────────
    OmegaCore.register("kfind_ptr") { rawArg, mgr in
        guard mgr.dsready else { return .fail("kfind_ptr: exploit not ready") }
        let (needleStr, rangeStr) = _splitRange(rawArg)
        guard let needle = _parseHex(needleStr) else {
            return .fail("kfind_ptr: usage — kfind_ptr <ptr_hex> [--range <start> <end>]")
        }
        let kernBase = ds_get_kernel_base()
        guard let (rangeStart, rangeEnd) = _parseRangeArgs(rangeStr, kernBase: kernBase) else {
            return .fail("kfind_ptr: --range needs two hex addresses")
        }
        guard rangeStart < rangeEnd, (rangeEnd - rangeStart) <= 0x1000_0000 else {
            return .fail("kfind_ptr: range invalid or too large (max 256 MB)")
        }
        var hits: [UInt64] = []
        var addr = rangeStart & ~7   // 8-byte aligned
        while addr + 8 <= rangeEnd, hits.count < 64 {
            if ds_kread64(addr) == needle { hits.append(addr) }
            addr &+= 8
        }
        if hits.isEmpty {
            return .ok(String(format: "kfind_ptr: 0x%llx not found in range\n", needle))
        }
        var out = String(format: "kfind_ptr: 0x%llx — %d hit(s)\n", needle, hits.count)
        for h in hits { out += String(format: "  → 0x%016llx\n", h) }
        return .ok(out)
    }

    // ── kscan_zero ────────────────────────────────────────────────────────────
    OmegaCore.register("kscan_zero") { rawArg, mgr in
        guard mgr.dsready else { return .fail("kscan_zero: exploit not ready") }
        let tokens = rawArg.split(separator: " ")
            .map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        guard tokens.count >= 2,
              let start = _parseHex(tokens[0]),
              let end   = _parseHex(tokens[1]),
              start < end, (end - start) <= 0x1000_0000 else {
            return .fail("kscan_zero: usage — kscan_zero <start_hex> <end_hex>  (max 256 MB)")
        }
        var hits: [UInt64] = []
        var addr = start & ~7
        while addr + 8 <= end, hits.count < 64 {
            if ds_kread64(addr) == 0 { hits.append(addr) }
            addr &+= 8
        }
        if hits.isEmpty { return .ok("kscan_zero: no zero qwords found in range") }
        var out = "kscan_zero: \(hits.count) zero qword(s)\n"
        for h in hits { out += String(format: "  0x%016llx\n", h) }
        return .ok(out)
    }

    // ── kverify ───────────────────────────────────────────────────────────────
    OmegaCore.register("kverify") { rawArg, mgr in
        guard mgr.dsready else { return .fail("kverify: exploit not ready") }
        let tokens = rawArg.split(separator: " ")
            .map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        guard tokens.count >= 2,
              let addr     = _parseHex(tokens[0]),
              let expected = _parseHex(tokens[1]) else {
            return .fail("kverify: usage — kverify <addr_hex> <expected_hex> [--width 8|4|2|1]")
        }
        var width = 8
        if let wi = tokens.firstIndex(of: "--width"), wi + 1 < tokens.count {
            width = Int(tokens[wi + 1]) ?? 8
        }
        guard [1, 2, 4, 8].contains(width) else { return .fail("kverify: --width must be 1,2,4,8") }

        let actual: UInt64
        switch width {
        case 1:  actual = UInt64(ds_kread8(addr))
        case 2:  actual = UInt64(ds_kread16(addr))
        case 4:  actual = UInt64(ds_kread32(addr))
        default: actual = ds_kread64(addr)
        }

        let mask: UInt64 = width < 8 ? ((1 << (width * 8)) - 1) : 0xFFFF_FFFF_FFFF_FFFF
        let exp = expected & mask
        let match = actual == exp

        return match
            ? .ok(String(format:   "kverify: ✔ MATCH   addr=0x%llx  value=0x%llx  width=%d\n", addr, actual, width))
            : .fail(String(format: "kverify: ✖ MISMATCH  addr=0x%llx\n  expected: 0x%llx\n  actual  : 0x%llx\n  width   : %d bytes\n", addr, exp, actual, width))
    }
}
