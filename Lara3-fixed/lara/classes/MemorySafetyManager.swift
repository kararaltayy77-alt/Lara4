//
//  MemorySafetyManager.swift
//  lara
//
//  Comprehensive memory safety manager for kernel R/W operations.
//  Validates all kernel addresses, tracks operation health, and prevents
//  crashes from invalid memory access.
//

import Foundation
import Darwin

// MARK: ── KernelAddressValidator ─────────────────────────────────────────────
/// Validates kernel virtual addresses before access.
enum KernelAddressValidator {

    /// Minimum valid kernel virtual address (arm64 standard)
    private static let kernelVABase: UInt64 = 0xFFFFFE0000000000

    /// Maximum valid kernel virtual address
    private static let kernelVALimit: UInt64 = 0xFFFFFFFFF0000000

    /// Validates a kernel address.
    /// - Returns: true if the address appears to be a valid kernel VA
    static func isValid(_ addr: UInt64) -> Bool {
        guard addr != 0 else { return false }
        guard addr != 0xFFFFFFFFFFFFFFFF else { return false }
        // Kernel VA on arm64: high bits are 0xFFFFFF
        guard (addr >> 40) & 0xFFFFFF == 0xFFFFFF else { return false }
        return true
    }

    /// Validates a range of kernel addresses.
    static func isValidRange(_ addr: UInt64, length: UInt64) -> Bool {
        guard isValid(addr) else { return false }
        guard length > 0 else { return false }
        // Check for overflow
        let end = addr &+ length
        guard end > addr else { return false }
        guard isValid(end) else { return false }
        return true
    }

    /// Classifies a kernel address region.
    static func classify(_ addr: UInt64) -> String {
        guard isValid(addr) else { return "INVALID" }
        let kb = ds_get_kernel_base()
        if addr >= kb && addr < kb + 0x0800_0000 { return "KERNEL_TEXT" }
        if addr >= kb + 0x0800_0000 && addr < kb + 0x1800_0000 { return "KERNEL_DATA" }
        if addr >= 0xFFFF_FFFF_0000_0000 { return "KERNEL_HEAP" }
        return "KERNEL_UNKNOWN"
    }
}

// MARK: ── MemoryOperationTracker ─────────────────────────────────────────────
/// Tracks kernel memory operations for health monitoring.
final class MemoryOperationTracker {
    static let shared = MemoryOperationTracker()

    private let lock = NSLock()
    private var totalReads: UInt64 = 0
    private var totalWrites: UInt64 = 0
    private var failedReads: UInt64 = 0
    private var failedWrites: UInt64 = 0
    private var lastFailureTime: TimeInterval = 0
    private var consecutiveFailures: UInt = 0

    /// Record a successful read operation
    func recordReadSuccess() {
        lock.lock()
        totalReads += 1
        consecutiveFailures = 0
        lock.unlock()
    }

    /// Record a failed read operation
    func recordReadFailure() {
        lock.lock()
        failedReads += 1
        consecutiveFailures += 1
        lastFailureTime = Date().timeIntervalSince1970
        lock.unlock()
    }

    /// Record a successful write operation
    func recordWriteSuccess() {
        lock.lock()
        totalWrites += 1
        consecutiveFailures = 0
        lock.unlock()
    }

    /// Record a failed write operation
    func recordWriteFailure() {
        lock.lock()
        failedWrites += 1
        consecutiveFailures += 1
        lastFailureTime = Date().timeIntervalSince1970
        lock.unlock()
    }

    /// Get current health status
    var healthStatus: String {
        lock.lock()
        let reads = totalReads
        let writes = totalWrites
        let fReads = failedReads
        let fWrites = failedWrites
        let consecFails = consecutiveFailures
        lock.unlock()

        let total = reads + writes
        let failures = fReads + fWrites
        let ratio = total > 0 ? Double(failures) / Double(total) : 0.0

        if consecFails > 10 { return "CRITICAL" }
        if ratio > 0.1 { return "DEGRADED" }
        if ratio > 0.05 { return "WARNING" }
        return "HEALTHY"
    }

    /// Get statistics string
    var stats: String {
        lock.lock()
        let reads = totalReads
        let writes = totalWrites
        let fReads = failedReads
        let fWrites = failedWrites
        let consecFails = consecutiveFailures
        lock.unlock()

        return String(format:
            "Memory Ops — reads:%llu/%llu fails  writes:%llu/%llu fails  consecutive:%u  status:%@",
            reads, fReads, writes, fWrites, consecFails, healthStatus
        )
    }

    /// Check if operations should be throttled
    var shouldThrottle: Bool {
        lock.lock()
        let consecFails = consecutiveFailures
        lock.unlock()
        return consecFails > 5
    }

    /// Reset all counters
    func reset() {
        lock.lock()
        totalReads = 0
        totalWrites = 0
        failedReads = 0
        failedWrites = 0
        consecutiveFailures = 0
        lastFailureTime = 0
        lock.unlock()
    }
}

// MARK: ── SafeKRWWrapper ────────────────────────────────────────────────────
/// Wrapper around raw KRW operations with safety checks.
enum SafeKRW {

    /// Safely read 64 bits from kernel memory.
    static func read64(_ address: UInt64) -> UInt64 {
        guard KernelAddressValidator.isValid(address) else {
            MemoryOperationTracker.shared.recordReadFailure()
            return 0
        }
        guard !MemoryOperationTracker.shared.shouldThrottle else {
            usleep(1000)  // 1ms throttle
            return 0
        }
        let val = ds_kread64(address)
        if val == 0 && address != 0 {
            // Zero could be valid data OR a failed read
            // Check session health to determine
            if ds_session_health_score() < 30 {
                MemoryOperationTracker.shared.recordReadFailure()
            } else {
                MemoryOperationTracker.shared.recordReadSuccess()
            }
        } else {
            MemoryOperationTracker.shared.recordReadSuccess()
        }
        return val
    }

    /// Safely read 32 bits from kernel memory.
    static func read32(_ address: UInt64) -> UInt32 {
        guard KernelAddressValidator.isValid(address) else { return 0 }
        let val = ds_kread32(address)
        MemoryOperationTracker.shared.recordReadSuccess()
        return val
    }

    /// Safely read a pointer (with PAC stripping).
    static func readPtr(_ address: UInt64) -> UInt64 {
        let raw = read64(address)
        guard raw != 0 else { return 0 }
        // Strip PAC bits (upper 16 bits on arm64e)
        return raw & 0x0000FFFFFFFFFFFF
    }

    /// Safely write 64 bits to kernel memory.
    static func write64(_ address: UInt64, value: UInt64) {
        guard KernelAddressValidator.isValid(address) else {
            MemoryOperationTracker.shared.recordWriteFailure()
            return
        }
        ds_kwrite64(address, value)
        MemoryOperationTracker.shared.recordWriteSuccess()
    }

    /// Read a buffer from kernel memory safely.
    static func readBuffer(_ address: UInt64, length: Int) -> Data? {
        guard KernelAddressValidator.isValidRange(address, length: UInt64(length)) else {
            return nil
        }
        guard length > 0, length <= 1024 * 1024 else { return nil }  // 1MB max

        var buffer = [UInt8](repeating: 0, count: length)
        ds_kreadbuf(address, &buffer, UInt64(length))
        MemoryOperationTracker.shared.recordReadSuccess()
        return Data(buffer)
    }

    /// Read a null-terminated string from kernel memory.
    static func readString(_ address: UInt64, maxLength: Int = 256) -> String? {
        guard KernelAddressValidator.isValid(address) else { return nil }
        guard maxLength > 0, maxLength <= 4096 else { return nil }

        var bytes = [UInt8](repeating: 0, count: maxLength)
        for i in 0..<maxLength {
            bytes[i] = ds_kread8(address + UInt64(i))
            if bytes[i] == 0 { break }
        }
        MemoryOperationTracker.shared.recordReadSuccess()
        return String(bytes: bytes.prefix(while: { $0 != 0 }), encoding: .utf8)
    }
}
