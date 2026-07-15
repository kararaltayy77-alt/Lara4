//
//  OmegaExtendedM.swift
//  lara — Kernel Debugger
//  watch32, watch64, trace-write
//

import Foundation
import Darwin

private func _parseAddrM(_ s: String) -> UInt64? {
    let t = s.trimmingCharacters(in: .whitespaces)
    let c = (t.hasPrefix("0x") || t.hasPrefix("0X")) ? String(t.dropFirst(2)) : t
    return UInt64(c, radix: 16)
}

private func _parseIntervalM(_ s: String) -> UInt64? {
    let t = s.trimmingCharacters(in: .whitespaces).lowercased()
    if t.hasSuffix("ms") { return UInt64(t.dropLast(2)) }
    else if t.hasSuffix("s") { return UInt64(t.dropLast(1)).map { $0 * 1000 } }
    return UInt64(t)
}

private func _kread64M(_ addr: UInt64) -> UInt64 {
    guard addr != 0, ds_isvalid(addr) else { return 0 }
    return ds_kread64(addr)
}

private func _kread32M(_ addr: UInt64) -> UInt32 {
    guard addr != 0, ds_isvalid(addr) else { return 0 }
    return ds_kread32(addr)
}

// MARK: – watch64

private func _watch64(addr: UInt64, intervalMs: UInt64, durationMs: UInt64) -> String? {
    guard addr != 0, ds_isvalid(addr) else { return nil }
    var lines = [String(format: "watch64: 0x%016llx  interval=%llums  duration=%llums", addr, intervalMs, durationMs), ""]
    var lastVal = _kread64M(addr)
    lines.append(String(format: "initial: 0x%016llx", lastVal))
    let startTime = Date()
    var elapsed: UInt64 = 0
    while elapsed < durationMs {
        Thread.sleep(forTimeInterval: Double(intervalMs) / 1000.0)
        let val = _kread64M(addr)
        if val != lastVal {
            lines.append(String(format: "0x%016llx", lastVal))
            lines.append("↓")
            lines.append(String(format: "0x%016llx", val))
            lastVal = val
        }
        elapsed = UInt64(Date().timeIntervalSince(startTime) * 1000)
    }
    lines.append(String(format: "final: 0x%016llx  (observed for %llums)", lastVal, elapsed))
    return lines.joined(separator: "\n")
}

// MARK: – watch32

private func _watch32(addr: UInt64, intervalMs: UInt64, durationMs: UInt64) -> String? {
    guard addr != 0, ds_isvalid(addr) else { return nil }
    var lines = [String(format: "watch32: 0x%016llx  interval=%llums  duration=%llums", addr, intervalMs, durationMs), ""]
    var lastVal = _kread32M(addr)
    lines.append(String(format: "initial: 0x%08x", lastVal))
    let startTime = Date()
    var elapsed: UInt64 = 0
    while elapsed < durationMs {
        Thread.sleep(forTimeInterval: Double(intervalMs) / 1000.0)
        let val = _kread32M(addr)
        if val != lastVal {
            lines.append(String(format: "0x%08x", lastVal))
            lines.append("↓")
            lines.append(String(format: "0x%08x", val))
            lastVal = val
        }
        elapsed = UInt64(Date().timeIntervalSince(startTime) * 1000)
    }
    lines.append(String(format: "final: 0x%08x  (observed for %llums)", lastVal, elapsed))
    return lines.joined(separator: "\n")
}

// MARK: – trace-write

private func _traceWrite(addr: UInt64, durationMs: UInt64) -> String? {
    guard addr != 0, ds_isvalid(addr) else { return nil }
    var lines = [String(format: "trace-write: 0x%016llx  duration=%llums", addr, durationMs), ""]
    var lastVal = _kread64M(addr)
    lines.append(String(format: "initial: 0x%016llx", lastVal))
    lines.append("polling... (software-only, no hardware breakpoints)")
    let startTime = Date()
    var elapsed: UInt64 = 0
    var changeCount = 0
    while elapsed < durationMs {
        Thread.sleep(forTimeInterval: 0.01)
        let val = _kread64M(addr)
        if val != lastVal {
            let ts = String(format: "%.3f", Date().timeIntervalSince(startTime))
            lines.append(String(format: "[+%@s] 0x%016llx -> 0x%016llx", ts, lastVal, val))
            lastVal = val
            changeCount += 1
        }
        elapsed = UInt64(Date().timeIntervalSince(startTime) * 1000)
    }
    lines.append(String(format: "final: 0x%016llx  %d changes in %llums", lastVal, changeCount, elapsed))
    return lines.joined(separator: "\n")
}

// MARK: – Registration

func registerDebuggerCommands() {

    OmegaCore.register("watch64") { arg, mgr in
        guard mgr.dsready else { return .fail("watch64: kernel r/w not ready") }
        let parts = arg.split(separator: " ").map { String($0) }
        guard parts.count >= 1, let addr = _parseAddrM(parts[0]) else {
            return .fail("watch64: usage — watch64 <addr_hex> [interval=100ms] [duration=5000ms]")
        }
        let interval = parts.count > 1 ? (_parseIntervalM(parts[1]) ?? 100) : 100
        let duration = parts.count > 2 ? (_parseIntervalM(parts[2]) ?? 5000) : 5000
        guard let out = _watch64(addr: addr, intervalMs: interval, durationMs: duration) else {
            return .fail("watch64: invalid address or kernel r/w degraded")
        }
        return .ok(out)
    }

    OmegaCore.register("watch32") { arg, mgr in
        guard mgr.dsready else { return .fail("watch32: kernel r/w not ready") }
        let parts = arg.split(separator: " ").map { String($0) }
        guard parts.count >= 1, let addr = _parseAddrM(parts[0]) else {
            return .fail("watch32: usage — watch32 <addr_hex> [interval=100ms] [duration=5000ms]")
        }
        let interval = parts.count > 1 ? (_parseIntervalM(parts[1]) ?? 100) : 100
        let duration = parts.count > 2 ? (_parseIntervalM(parts[2]) ?? 5000) : 5000
        guard let out = _watch32(addr: addr, intervalMs: interval, durationMs: duration) else {
            return .fail("watch32: invalid address or kernel r/w degraded")
        }
        return .ok(out)
    }

    OmegaCore.register("trace-write") { arg, mgr in
        guard mgr.dsready else { return .fail("trace-write: kernel r/w not ready") }
        let parts = arg.split(separator: " ").map { String($0) }
        guard parts.count >= 1, let addr = _parseAddrM(parts[0]) else {
            return .fail("trace-write: usage — trace-write <addr_hex> [duration=5000ms]")
        }
        let duration = parts.count > 1 ? (_parseIntervalM(parts[1]) ?? 5000) : 5000
        guard let out = _traceWrite(addr: addr, durationMs: duration) else {
            return .fail("trace-write: invalid address or kernel r/w degraded")
        }
        return .ok(out)
    }
}
