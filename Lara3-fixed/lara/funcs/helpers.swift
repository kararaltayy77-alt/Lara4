//
  //  helpers.swift
  //  lara
  //
  import Darwin
  import Foundation

  func hex(_ value: UInt64) -> String {
      "0x" + String(value, radix: 16, uppercase: true)
  }

  func hex(_ value: UInt32) -> String {
      hex(UInt64(value))
  }

  func isIOS16() -> Bool {
      if #available(iOS 17.0, *) { return false }
      if #available(iOS 16.0, *) { return true }
      return false
  }

  // doubleSystemVersion() is defined in SBCustomizerHandler.swift

  /// Lists all running process IDs using proc_listallpids.
  func listAllPIDs() throws -> [Int32] {
      let count = proc_listallpids(nil, 0)
      guard count > 0 else { return [] }
      var pids = [pid_t](repeating: 0, count: Int(count) + 16)
      let result = proc_listallpids(&pids, Int32(MemoryLayout<pid_t>.stride * pids.count))
      guard result > 0 else { return [] }
      return Array(pids.prefix(Int(result))).filter { $0 > 0 }
  }
  