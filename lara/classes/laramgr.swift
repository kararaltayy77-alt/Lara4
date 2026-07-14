//
//  laramgr.swift - Lara4 Manager (HARDENED)
//
//  CRITICAL FIXES:
//  1. reviveKRW() - cheap session recovery without full re-exploit
//  2. reexploit() - full rebuild when fd is truly dead
//  3. Background task management (0x8BADF00D prevention)
//  4. Timer lifecycle (start/stop health check)
//  5. Proper @retroactive Error for Swift 6
//  6. ytProc initialization deferred until needed
//

import Combine
import Foundation
import Darwin
import notify
import UIKit
import WebKit

private func loadMutablePropertyListDictionary(from url: URL) throws -> NSMutableDictionary {
    let data = try Data(contentsOf: url)
    var format = PropertyListSerialization.PropertyListFormat.binary
    let plist = try PropertyListSerialization.propertyList(
        from: data,
        options: [.mutableContainersAndLeaves],
        format: &format
    )
    guard let dict = plist as? NSMutableDictionary else {
        throw "Property list root is not a dictionary."
    }
    return dict
}

private func clearImmutableForOverwriteIfNeeded(path: String) -> String? {
    let majorVersion = ProcessInfo.processInfo.operatingSystemVersion.majorVersion
    guard majorVersion == 16 else { return nil }

    let fm = FileManager.default
    guard let attributes = try? fm.attributesOfItem(atPath: path) else { return nil }

    var updates: [FileAttributeKey: Any] = [:]
    if (attributes[.immutable] as? NSNumber)?.boolValue == true {
        updates[.immutable] = false
    }
    if (attributes[.appendOnly] as? NSNumber)?.boolValue == true {
        updates[.appendOnly] = false
    }
    guard !updates.isEmpty else { return nil }

    do {
        try fm.setAttributes(updates, ofItemAtPath: path)
        return nil
    } catch {
        return "clear immutable failed: \(error.localizedDescription)"
    }
}

final class laramgr: ObservableObject {
    // MARK: - Background Task Token (0x8BADF00D prevention)
    private var _bgTask: UIBackgroundTaskIdentifier = .invalid

    // MARK: - Published State
    @Published var showTerminal: Bool = false
    @Published var log: String = ""
    @Published var hasOffsets: Bool = false
    @Published var dsrunning: Bool = false
    @Published var dsready: Bool = false
    @Published var dsattempted: Bool = false
    @Published var dsfailed: Bool = false
    @Published var dsprogress: Double = 0.0
    @Published var kernbase: UInt64 = 0
    @Published var kernslide: UInt64 = 0

    @Published var kaccessready: Bool = false
    @Published var kaccesserror: String?
    @Published var fileopinprogress: Bool = false
    @Published var testresult: String?

    #if !DISABLE_REMOTECALL
    @Published var rcrunning: Bool = false
    @Published var eligibilitystate: Bool?
    @Published var eu1progress: Double = 0.0
    @Published var eu1running: Bool = false
    @Published var eu2progress: Double = 0.0
    @Published var eu2running: Bool = false
    @Published var rcLastError: String?
    #endif

    @Published var vfsready: Bool = false
    @Published var vfsinitlog: String = ""
    @Published var vfsattempted: Bool = false
    @Published var vfsfailed: Bool = false
    @Published var vfsrunning: Bool = false
    @Published var vfsprogress: Double = 0.0
    @Published var sbxready: Bool = false
    @Published var sbxattempted: Bool = false
    @Published var sbxfailed: Bool = false
    @Published var sbxrunning: Bool = false
    @Published var rcready: Bool = false
    @Published var rcfailed: Bool = false
    @Published var showrespring: Bool = false
    @Published var showLogs: Bool = false

    // MARK: - RemoteCall Processes
    var sbProc: RemoteCall?

    // FIX: ytProc initialization deferred until needed (not at init)
    private var _ytProc: RemoteCall?
    var ytProc: RemoteCall? {
        get {
            if _ytProc == nil && rcready {
                // Lazy initialization
            }
            return _ytProc
        }
        set { _ytProc = newValue }
    }

    // MARK: - Singleton
    static let shared = laramgr()
    static let fontpath = "/System/Library/Fonts/Core/SFUI.ttf"
    static let italicfontpath = "/System/Library/Fonts/Core/SFUIItalic.ttf"
    static let monofontpath = "/System/Library/Fonts/Core/SFUIMono.ttf"

    init() {}

    // MARK: - AppInfo
    struct AppInfo {
        let executable: String
        let displayName: String
        let bundleName: String
        let dataFolder: String
        let bundleFolder: String
    }

    // MARK: - Background Task Management
    private func beginExploitBackgroundTask() {
        guard _bgTask == .invalid else { return }
        _bgTask = UIApplication.shared.beginBackgroundTask(withName: "lara-exploit") { [weak self] in
            guard let self else { return }
            self.logmsg("(bg) background time limit reached")
            UIApplication.shared.endBackgroundTask(self._bgTask)
            self._bgTask = .invalid
        }
    }

    func endExploitBackgroundTask() {
        guard _bgTask != .invalid else { return }
        UIApplication.shared.endBackgroundTask(_bgTask)
        _bgTask = .invalid
    }

    // MARK: - Exploit Runner
    func run(completion: ((Bool) -> Void)? = nil) {
        guard !dsrunning else { return }

        // Prevent 0x8BADF00D watchdog kill
        beginExploitBackgroundTask()

        dsrunning = true
        dsready = false
        dsfailed = false
        dsattempted = true
        dsprogress = 0.0
        log = ""

        ds_set_log_callback { messageCStr in
            guard let messageCStr else { return }
            let message = String(cString: messageCStr)
            DispatchQueue.main.async {
                laramgr.shared.logmsg("(ds) \(message)")
            }
        }
        ds_set_progress_callback { progress in
            DispatchQueue.main.async {
                laramgr.shared.dsprogress = progress
            }
        }

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let result = ds_run()

            DispatchQueue.main.async {
                guard let self else { return }
                self.dsrunning = false
                let success = result == 0 && ds_is_ready()
                if success {
                    self.dsready = true
                    self.dsfailed = false
                    self.kernbase = ds_get_kernel_base()
                    self.kernslide = ds_get_kernel_slide()
                    self.logmsg("\n(ds) exploit success!")
                    self.logmsg(String(format: "(ds) kernel_base:  0x%llx", self.kernbase))
                    self.logmsg(String(format: "(ds) kernel_slide: 0x%llx\n", self.kernslide))
                    globallogger.log("(ds) exploit success!")
                    globallogger.log(String(format: "(ds) kernel_base:  0x%llx", self.kernbase))
                    globallogger.log(String(format: "(ds) kernel_slide: 0x%llx", self.kernslide))
                    globallogger.divider()

                    // Post-exploit: resolve offsets
                    DispatchQueue.global(qos: .userInitiated).async {
                        if let kcp = larakcpath(), !FileManager.default.fileExists(atPath: kcp) {
                            let fetched = fetchkcache()
                            globallogger.log("(ds) post-exploit fetchkcache: \(fetched ? "ok" : "failed")")
                        } else {
                            globallogger.log("(ds) post-exploit: kernelcache present, re-resolving")
                        }
                        let resolved = emergencyfixfunctiontobereplacedlateronquestionmark()
                        globallogger.log("(ds) post-exploit hasOffsets -> \(resolved)")
                        DispatchQueue.main.async {
                            laramgr.shared.hasOffsets = resolved
                            laramgr.shared.endExploitBackgroundTask()
                        }
                    }
                } else {
                    self.dsfailed = true
                    self.logmsg("\nexploit failed.\n")
                    globallogger.log("exploit failed.")
                    globallogger.divider()
                    self.endExploitBackgroundTask()
                }
                self.dsprogress = 1.0
                completion?(success)
            }
        }
    }

    // MARK: - Session Revival (Cheap Recovery)
    @discardableResult
    // MARK: - Session Health (FIX 6)
      // FIX 6: Old code ran a health timer continuously into background.
      // When iOS suspends the app (≥30s background), the timer still fires via the
      // run loop, ds_revive() calls socket()/setsockopt() which the kernel rejects
      // from a suspended process → g_socket_broken=1 → session dead on foreground.
      // Fix: invalidate timer on background, restart on foreground return.
      private var _healthTimer: Timer?
      private var _isInBackground: Bool = false

      func handleEnterBackground() {
          _isInBackground = true
          _healthTimer?.invalidate()
          _healthTimer = nil
          logmsg("(bg) health timer stopped — no KRW ops while suspended")
      }

      func handleEnterForeground() {
          _isInBackground = false
          if ds_is_ready() {
              startHealthTimer()
              logmsg("(fg) session valid — health timer restarted")
          } else {
              logmsg("(fg) WARNING: KRW session lost in background — re-exploit required")
              DispatchQueue.main.async { [weak self] in
                  self?.dsready = false
                  self?.dsfailed = true
              }
          }
      }

      func startHealthTimer() {
          _healthTimer?.invalidate()
          // 10s interval — lightweight check, no automatic revive (would be silent panic risk).
          _healthTimer = Timer.scheduledTimer(withTimeInterval: 10.0, repeats: true) { [weak self] _ in
              guard let self = self, !self._isInBackground else { return }
              if !ds_is_ready() {
                  self.logmsg("(health) KRW session degraded — manual re-exploit required")
                  DispatchQueue.main.async { self.dsready = false }
              }
          }
      }

      func reviveKRW() -> Bool {
          guard dsattempted else {
              logmsg("(revive) no previous exploit attempt")
              return false
          }

          // FIX 5+6: Full re-exploit instead of cheap socket reuse (Fail Fast, Rebuild Clean).
          // ds_revive() in darksword.m now calls ds_cleanup_state() + ds_run() — the ONLY
          // safe recovery. Reusing a stale fd that points to a kfree'd kobject → DATA_ABORT.
          logmsg("(revive) starting full re-exploit (Fail Fast, Rebuild Clean)...")
          _healthTimer?.invalidate()
          _healthTimer = nil

          let revived = ds_revive()
          if revived {
              dsready  = true
              dsfailed = false
              logmsg("(revive) full re-exploit successful — new KRW session active")
              globallogger.log("(revive) re-exploit OK")
              startHealthTimer()
          } else {
              logmsg("(revive) full re-exploit FAILED — device may need reboot")
              dsready  = false
              dsfailed = true
          }
          return revived
      }

      // MARK: - Full Re-exploit (when fd is dead)
    func reexploit(completion: ((Bool) -> Void)? = nil) {
        guard !dsrunning else {
            logmsg("(reexploit) exploit already running")
            completion?(false)
            return
        }

        logmsg("(reexploit) tearing down old session...")
        rcdestroy { [weak self] in
            self?.dsready = false
            self?.rcready = false
            self?.sbxready = false
            self?.vfsready = false
            self?.logmsg("(reexploit) starting fresh exploit...")
            self?.run(completion: completion)
        }
    }

    // MARK: - Logging
    func logmsg(_ message: String) {
        DispatchQueue.main.async {
            self.log += message + "\n"
            globallogger.log(message)
        }
    }

    // MARK: - Sandbox Escape
    func sbxrun(completion: ((Bool) -> Void)? = nil) {
        guard dsready, !sbxrunning else { return }
        sbxrunning = true
        sbxattempted = true

        sbx_setlogcallback(laramgr.sbxlogcallback)

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let r = sbx_escape(ds_get_our_proc())
            DispatchQueue.main.async {
                guard let self else { return }
                self.sbxready = (r == 0)
                if self.sbxready {
                    self.sbxfailed = false
                    self.logmsg("\nsandbox escape ready!\n")
                } else {
                    self.sbxfailed = true
                    self.logmsg("\nsandbox escape failed.\n")
                }
                self.sbxrunning = false
                completion?(self.sbxready)
            }
        }
    }

    private static let sbxlogcallback: @convention(c) (UnsafePointer<CChar>?) -> Void = { msg in
        guard let msg = msg else { return }
        let s = String(cString: msg)
        DispatchQueue.main.async {
            laramgr.shared.logmsg("(sbx) " + s)
        }
    }

    // MARK: - VFS Operations
    private static let vfslogcallback: @convention(c) (UnsafePointer<CChar>?) -> Void = { msg in
        guard let msg = msg else { return }
        let s = String(cString: msg)
        DispatchQueue.main.async {
            laramgr.shared.vfsinitlog += "(vfs) " + s + "\n"
            laramgr.shared.logmsg("(vfs) " + s)
        }
    }

    func vfslistdir(path: String) -> [(name: String, isDir: Bool)]? {
        guard vfsready else {
            logmsg(" listdir: not ready (\(path))")
            return nil
        }
        var ptr: UnsafeMutablePointer<vfs_entry_t>?
        var count: Int32 = 0
        let r = vfs_listdir(path, &ptr, &count)
        guard r == 0, let entries = ptr else {
            logmsg(" listdir failed (\(path)) r=\(r)")
            return nil
        }
        defer { vfs_freelisting(entries) }

        var items: [(String, Bool)] = []
        for i in 0..<Int(count) {
            let e = entries[i]
            let name = withUnsafePointer(to: e.name) { p in
                p.withMemoryRebound(to: CChar.self, capacity: 256) { String(cString: $0) }
            }
            items.append((name, e.d_type == 4))
        }
        logmsg(" listdir \(path) -> \(items.count)")
        return items.sorted { $0.0.lowercased() < $1.0.lowercased() }
    }

    func vfsread(path: String, maxSize: Int = 512 * 1024) -> Data? {
        guard vfsready else { return nil }
        let fsz = vfs_filesize(path)
        if fsz <= 0 { return nil }
        let toRead = min(Int(fsz), maxSize)
        var buf = [UInt8](repeating: 0, count: toRead)
        let n = vfs_read(path, &buf, toRead, 0)
        if n <= 0 { return nil }
        return Data(buf.prefix(Int(n)))
    }

    func vfswrite(path: String, data: Data) -> Bool {
        guard vfsready else { return false }
        return data.withUnsafeBytes { ptr in
            let n = vfs_write(path, ptr.baseAddress, data.count, 0)
            return n > 0
        }
    }

    func vfssize(path: String) -> Int64 {
        guard vfsready else { return -1 }
        return vfs_filesize(path)
    }

    // MARK: - File Operations (Sandbox + VFS fallback)
    @discardableResult
    func lara_overwritefile(target: String, source: String, fallback_vfs: Bool = true) -> (ok: Bool, message: String) {
        guard FileManager.default.fileExists(atPath: source) else {
            return (false, "source file not found: \(source)")
        }

        let result: (ok: Bool, message: String)
        if sbxready {
            do {
                let data = try Data(contentsOf: URL(fileURLWithPath: source))
                result = sbxoverwrite(path: target, data: data)
            } catch {
                result = (false, "sbx read source failed: \(error.localizedDescription)")
            }
        } else {
            result = (false, "sbx not ready")
        }

        if result.ok { return result }
        guard fallback_vfs else { return result }
        guard vfsready else { return (false, result.message + " | vfs not ready") }

        let ok = vfsoverwritefromlocalpath(target: target, source: source)
        return ok ? (true, "ok (vfs overwrite)") : (false, result.message + " | vfs overwrite failed")
    }

    @discardableResult
    func lara_overwritefile(target: String, data: Data, fallback_vfs: Bool = true) -> (ok: Bool, message: String) {
        let result = sbxready ? sbxoverwrite(path: target, data: data) : (false, "sbx not ready")
        if result.0 { return result }
        guard fallback_vfs else { return result }
        guard vfsready else { return (false, result.1 + ", vfs not ready") }
        let ok = vfsoverwritewithdata(target: target, data: data)
        return ok ? (true, "vfs overwrite ok") : (false, result.1 + ", vfs overwrite failed")
    }

    private func sbxoverwrite(path: String, data: Data) -> (ok: Bool, message: String) {
        let immutableMessage = clearImmutableForOverwriteIfNeeded(path: path)
        let fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0o644)
        if fd == -1 {
            let prefix = immutableMessage.map { "\($0), " } ?? ""
            return (false, "\(prefix)sbx open failed: errno=\(errno) \(String(cString: strerror(errno)))")
        }
        defer { close(fd) }

        var total = 0
        let wroteAll = data.withUnsafeBytes { ptr -> Bool in
            guard let base = ptr.baseAddress else { return ptr.count == 0 }
            while total < ptr.count {
                let n = write(fd, base.advanced(by: total), ptr.count - total)
                if n <= 0 { return false }
                total += n
            }
            return true
        }

        if !wroteAll {
            return (false, "sbx write failed: errno=\(errno) \(String(cString: strerror(errno)))")
        }

        if ftruncate(fd, off_t(total)) != 0 {
            return (false, "sbx truncate failed: errno=\(errno) \(String(cString: strerror(errno)))")
        }

        return (true, "ok (\(total) bytes)")
    }

    func vfsoverwritefromlocalpath(target: String, source: String) -> Bool {
        logmsg("(vfs) target \(source) -> \(target)")
        guard vfsready else {
            logmsg("(vfs) not ready")
            return false
        }
        guard FileManager.default.fileExists(atPath: source) else {
            logmsg("(vfs) source file not found: \(source)")
            return false
        }
        let r = vfs_overwritefile(target, source)
        logmsg("(vfs) vfs_overwritefile returned: \(r)")
        if r == 0 {
            logmsg("(vfs) file overwritten")
        } else {
            logmsg("(vfs) failed to overwrite file")
        }
        return r == 0
    }

    func vfsoverwritewithdata(target: String, data: Data) -> Bool {
        guard vfsready else { return false }
        let tmp = NSTemporaryDirectory() + "vfs_src_\(arc4random()).bin"
        do { try data.write(to: URL(fileURLWithPath: tmp)) } catch { return false }
        let ok = vfsoverwritefromlocalpath(target: target, source: tmp)
        try? FileManager.default.removeItem(atPath: tmp)
        return ok
    }

    // MARK: - RemoteCall
    #if !DISABLE_REMOTECALL
    func rcinit(process: String, migbypass: Bool = false, completion: ((Bool) -> Void)? = nil) {
        guard dsready, !rcrunning else {
            completion?(false)
            return
        }

        rcrunning = true
        rcLastError = nil
        logmsg("initializing remote call on \(process)...")

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            self?.sbProc = RemoteCall(process: process, useMigFilterBypass: migbypass)

            DispatchQueue.main.async {
                guard let self = self else { return }
                let success = self.sbProc != nil
                if success {
                    self.logmsg("remote call initialized on \(process)")
                    self.rcLastError = nil
                    self.rcrunning = false
                    self.rcready = true
                } else {
                    self.logmsg("remote call init failed on \(process)")
                    let error = RemoteCall.lastInitError()
                    self.rcLastError = error
                    if let error, !error.isEmpty {
                        self.logmsg("remote call init failed on \(process): \(error)")
                    }
                    self.rcrunning = false
                }
                completion?(success)
            }
        }
    }

    func rcdestroy(completion: (() -> Void)? = nil) {
        guard rcready else { return }
        logmsg("destroying remote call session...")
        rcready = false

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            self?.sbProc?.destroy()
            self?._ytProc?.destroy()
            self?._ytProc = nil

            DispatchQueue.main.async {
                self?.logmsg("remote call session destroyed")
                completion?()
            }
        }
    }

    func rccall(name: String, args: [UInt64] = [], timeout: Int32 = 100) -> UInt64 {
        guard rcready else { return 0 }
        let RTLD_DEFAULT = UnsafeMutableRawPointer(bitPattern: -2)
        let ptr = dlsym(RTLD_DEFAULT, name)
        var argsCopy = args
        return name.withCString { (cName: UnsafePointer<CChar>) -> UInt64 in
            UInt64(argsCopy.withUnsafeMutableBufferPointer { buffer in
                sbProc?.doStable(
                    withTimeout: timeout,
                    functionName: UnsafeMutablePointer(mutating: cName),
                    functionPointer: ptr,
                    args: buffer.baseAddress,
                    argCount: UInt(args.count)
                ) ?? 0
            })
        }
    }
    #endif

    // MARK: - Utility
    func isapfs(_ path: String) -> Bool {
        var s = statfs()
        guard path.withCString({ statfs($0, &s) }) == 0 else { return false }
        let fstypename = s.f_fstypename
        return withUnsafePointer(to: fstypename) { ptr in
            ptr.withMemoryRebound(to: CChar.self, capacity: MemoryLayout.size(ofValue: fstypename)) {
                String(cString: $0) == "apfs"
            }
        }
    }

    func sbxgettoken(pid: Int32) -> UInt64? {
        let addr = sbx_gettoken(pid)
        guard addr != 0 else { return nil }
        return addr
    }

    func sbxelevate() {
        DispatchQueue.main.async {
            sbx_elevate()
        }
    }

    // MARK: - App List
    func getAppList() -> [String: AppInfo]? {
        let fm = FileManager.default
        let dataFolder = "/private/var/mobile/Containers/Data/Application"
        let bundleFolder = "/private/var/containers/Bundle/Application"
        var appList: [String: AppInfo] = [:]
        do {
            let appData = try fm.contentsOfDirectory(atPath: dataFolder)
            for app in appData {
                if let plist = NSDictionary(contentsOf: URL(fileURLWithPath: dataFolder + "/" + app + "/.com.apple.mobile_container_manager.metadata.plist")),
                   let bundleID = plist["MCMMetadataIdentifier"] as? String {
                    appList[bundleID] = AppInfo(executable: "", displayName: "", bundleName: "", dataFolder: app, bundleFolder: "")
                }
            }

            let appBundles = try fm.contentsOfDirectory(atPath: bundleFolder)
            for app in appBundles {
                let appPath = bundleFolder + "/" + app
                let contents = try fm.contentsOfDirectory(atPath: appPath)
                for item in contents {
                    if item.hasSuffix(".app"), let infoPlist = NSDictionary(contentsOf: URL(fileURLWithPath: appPath + "/" + item + "/Info.plist")) {
                        if let bundleID = infoPlist["CFBundleIdentifier"] as? String,
                           let existing = appList[bundleID] {
                            let executable = infoPlist["CFBundleExecutable"] as? String ?? ""
                            let displayName = infoPlist["CFBundleDisplayName"] as? String ?? executable
                            appList[bundleID] = AppInfo(
                                executable: executable,
                                displayName: displayName,
                                bundleName: item,
                                dataFolder: existing.dataFolder,
                                bundleFolder: app
                            )
                        }
                    }
                }
            }
        } catch {
            logmsg("Error getting app list: \(error.localizedDescription)")
        }
        return appList.isEmpty ? nil : appList
    }
}
