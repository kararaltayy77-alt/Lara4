//
//  IPAInstallerView.swift
//  lara
//
//  IPA Installer — true unsigned IPA installation.
//  Uses DarkSword kernel r/w to:
//    1. Permanently elevate the process to root (UID 0) via ucred patch.
//    2. Disable mac_proc_enforce (AMFI bypass) so ad-hoc binaries launch.
//    3. Ad-hoc sign the bundle with choma.
//  No certificate, no PC, no AltStore needed at all.
//

import SwiftUI
import UniformTypeIdentifiers
import Darwin

// MARK: - State

private enum InstallPhase: Equatable {
    case idle
    case reading
    case extracting
    case copying(file: String)
    case permissions
    case registering
    case done(name: String)
    case failed(reason: String)

    var label: String {
        switch self {
        case .idle:                  return "Ready"
        case .reading:               return "Reading IPA…"
        case .extracting:            return "Extracting…"
        case .copying(let f):        return "Copying \(f)…"
        case .permissions:           return "Setting permissions…"
        case .registering:           return "Registering with system…"
        case .done(let n):           return "Installed \(n)"
        case .failed(let r):         return "Failed: \(r)"
        }
    }

    var isWorking: Bool {
        switch self {
        case .idle, .done, .failed: return false
        default: return true
        }
    }
}

// MARK: - Installed app entry

private struct LaraInstalledApp: Identifiable {
    let id = UUID()
    let name: String
    let bundleID: String
    let bundlePath: String
    let icon: UIImage?
}

// MARK: - LSApplicationWorkspace private API bridge

private func lsRegister(bundleURL: URL) -> Bool {
    guard let cls = NSClassFromString("LSApplicationWorkspace") as? NSObject.Type else { return false }
    let ws = cls.perform(NSSelectorFromString("defaultWorkspace"))?.takeUnretainedValue() as AnyObject
    let sel = NSSelectorFromString("registerApplicationWithBundleURL:")
    if ws.responds(to: sel) {
        let result = ws.perform(sel, with: bundleURL)
        return result != nil
    }
    let sel2 = NSSelectorFromString("_LSPrivateRebuildApplicationDatabasesForSystemApps:isFull:outError:")
    _ = ws.perform(sel2)
    return false
}

// MARK: - View

struct IPAInstallerView: View {
    @EnvironmentObject private var mgr: laramgr

    @State private var showPicker      = false
    @State private var phase: InstallPhase = .idle
    @State private var loglines: [String]  = []
    @State private var installedApps: [LaraInstalledApp] = []

    private let bundleRoot = "/var/containers/Bundle/Application"
    private let dataRoot   = "/var/mobile/Containers/Data/Application"

    var body: some View {
        List {
            requirementsBanner

            Section {
                Button {
                    showPicker = true
                } label: {
                    Label("Choose IPA File", systemImage: "square.and.arrow.down")
                }
                .disabled(!mgr.dsready || !mgr.sbxready || phase.isWorking)
            } header: {
                HeaderLabel(text: "Install", icon: "plus.app")
            } footer: {
                Text("أي ملف IPA يعمل — بدون توقيع مسبق. lara ترفع صلاحيات العملية لـ root نهائياً ثم تثبّت مباشرةً.")
            }

            if phase.isWorking {
                Section {
                    HStack(spacing: 12) {
                        ProgressView()
                        Text(phase.label)
                            .foregroundColor(.secondary)
                    }
                } header: {
                    Text("Progress")
                }
            }

            if case .done(let name) = phase {
                Section {
                    PlainAlert(
                        title: "Installed!",
                        icon: "checkmark.circle.fill",
                        text: "\(name) was installed. Respring to see it on the Home Screen.",
                        color: .green
                    )
                    Button("Respring Now") { mgr.respring() }
                }
            }

            if case .failed(let reason) = phase {
                Section {
                    PlainAlert(
                        title: "Install Failed",
                        icon: "xmark.circle.fill",
                        text: reason,
                        color: .red
                    )
                }
            }

            if !loglines.isEmpty {
                Section {
                    ScrollView {
                        Text(loglines.joined(separator: "\n"))
                            .font(.system(size: 12, design: .monospaced))
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .textSelection(.enabled)
                    }
                    .frame(height: 180)

                    Button("Clear Log") { loglines.removeAll() }
                        .foregroundColor(.red)
                } header: {
                    HeaderLabel(text: "Log", icon: "terminal")
                }
            }

            if !installedApps.isEmpty {
                Section {
                    ForEach(installedApps) { app in
                        HStack(spacing: 12) {
                            if let icon = app.icon {
                                Image(uiImage: icon)
                                    .resizable()
                                    .frame(width: 40, height: 40)
                                    .clipShape(RoundedRectangle(cornerRadius: 9))
                            } else {
                                Image(systemName: "app.fill")
                                    .resizable()
                                    .frame(width: 40, height: 40)
                                    .foregroundColor(.accentColor)
                            }
                            VStack(alignment: .leading, spacing: 2) {
                                Text(app.name).font(.headline)
                                Text(app.bundleID).font(.caption).foregroundColor(.secondary)
                            }
                            Spacer()
                            Button {
                                uninstall(app)
                            } label: {
                                Image(systemName: "trash")
                                    .foregroundColor(.red)
                            }
                            .buttonStyle(.plain)
                        }
                    }
                } header: {
                    HeaderLabel(text: "Installed by lara", icon: "square.stack.3d.up")
                }
            }
        }
        .navigationTitle("IPA Installer")
        .fileImporter(
            isPresented: $showPicker,
            allowedContentTypes: [UTType(filenameExtension: "ipa") ?? .data],
            allowsMultipleSelection: false
        ) { result in
            switch result {
            case .success(let urls):
                if let url = urls.first { startInstall(url: url) }
            case .failure(let err):
                log("picker error: \(err.localizedDescription)")
            }
        }
        .onAppear { scanInstalledApps() }
    }

    // MARK: - Requirement banner

    @ViewBuilder
    private var requirementsBanner: some View {
        Section {
            if !mgr.dsready {
                PlainAlert(
                    title: "Exploit required",
                    icon: "exclamationmark.triangle.fill",
                    text: "Run the DarkSword exploit first (kernel r/w needed).",
                    color: .red
                )
            } else if !mgr.sbxready {
                PlainAlert(
                    title: "Sandbox escape required",
                    icon: "exclamationmark.triangle.fill",
                    text: "Kernel ready — run sandbox escape next.",
                    color: .orange
                )
            } else {
                PlainAlert(
                    icon: "checkmark.seal.fill",
                    text: "Kernel r/w + Sandbox escape active. Any unsigned IPA will install.",
                    color: .green
                )
            }
        } footer: {
            Text("lara patches the process ucred to root (UID 0) then installs with full privileges. No external tool needed.")
        }
    }

    // MARK: - Install pipeline

    private func startInstall(url: URL) {
        loglines.removeAll()
        phase = .reading

        let accessed = url.startAccessingSecurityScopedResource()
        defer { if accessed { url.stopAccessingSecurityScopedResource() } }

        guard let data = try? Data(contentsOf: url) else {
            fail("Cannot read IPA file.")
            return
        }

        log("read \(ByteCountFormatter.string(fromByteCount: Int64(data.count), countStyle: .file))")

        DispatchQueue.global(qos: .userInitiated).async {
            self.runInstall(data: data)
        }
    }

    private func runInstall(data: Data) {
        setPhase(.extracting)

        // ── 1. Elevate process to root (UID 0) via kernel ucred patch ─────────
        //    This gives us full write access everywhere — no more permission errors.
        var rootRC = amfi_elevate_to_root()
          if rootRC == 0 && getuid() == 0 {
              log("root elevation: OK (uid=\(getuid()))")
          } else {
              // Fallback: sbx_elevate_to_root uses ds_kwrite64 — same channel sbx_escape uses
              log("root elevation (amfi): uid=\(getuid()) — trying sbx fallback…")
              let proc = ds_get_our_proc()
              if proc != 0 { rootRC = sbx_elevate_to_root(proc) }
              if rootRC == 0 && getuid() == 0 {
                  log("root elevation (sbx fallback): OK (uid=\(getuid()))")
              } else {
                  // Last resort: setuid(0) — works if kernel cr_uid was patched but cache not flushed
                  setuid(0); setgid(0)
                  if getuid() == 0 {
                      log("root elevation (setuid): OK"); rootRC = 0
                  } else {
                      log("⚠️ root elevation failed (uid=\(getuid())) — bundle dir may fail")
                  }
              }
          }

        // ── 2. Disable AMFI mac_proc_enforce ─────────────────────────────────
        let amfiOK = amfi_disable_mac_proc_enforce()
        log("AMFI bypass: \(amfiOK ? "OK" : "warn — ensure kernelcache is loaded")")

        // ── 3. Open IPA as ZIP ────────────────────────────────────────────────
        let archive: ZipArchive
        do {
            archive = try ZipArchive(data: data)
        } catch {
            fail("ZIP parse error: \(error)")
            return
        }

        // ── 4. Find Payload/*.app ─────────────────────────────────────────────
        let payloadEntries = archive.entries.filter {
            $0.path.hasPrefix("Payload/") && !$0.path.hasPrefix("Payload/__")
        }

        guard let appEntry = payloadEntries.first(where: {
            let parts = $0.path.split(separator: "/")
            return parts.count >= 2 && parts[1].hasSuffix(".app")
        }) else {
            fail("No Payload/*.app found in IPA.")
            return
        }

        let appFolderInZip: String = {
            let parts = appEntry.path.split(separator: "/")
            return "Payload/" + parts[1]
        }()
        let appBundleName = String(appFolderInZip.split(separator: "/").last ?? "App.app")

        // ── 5. Read Info.plist ────────────────────────────────────────────────
        let infoPlistPath = appFolderInZip + "/Info.plist"
        guard let infoPlistEntry = archive[infoPlistPath],
              let infoPlistData  = try? archive.extract(infoPlistEntry),
              let infoPlist      = try? PropertyListSerialization.propertyList(
                                      from: infoPlistData, options: [], format: nil
                                  ) as? [String: Any]
        else {
            fail("Cannot read Info.plist in bundle.")
            return
        }

        let bundleID = infoPlist["CFBundleIdentifier"] as? String ?? "unknown"
        let appName  = (infoPlist["CFBundleDisplayName"] as? String)
                    ?? (infoPlist["CFBundleName"]        as? String)
                    ?? appBundleName

        log("app: \(appName) (\(bundleID))")

        // ── 6. Extract to temp ────────────────────────────────────────────────
        let tmpBase = NSTemporaryDirectory() + "lara_ipa_\(bundleID)_\(Int(Date().timeIntervalSince1970))/"
        let tmpApp  = tmpBase + appBundleName

        let fm = FileManager.default
        try? fm.removeItem(atPath: tmpBase)

        let appEntries = archive.entries.filter {
            $0.path.hasPrefix(appFolderInZip + "/") || $0.path == appFolderInZip
        }

        for entry in appEntries {
            let relative = String(entry.path.dropFirst(appFolderInZip.count + 1))
            let dest = relative.isEmpty ? tmpApp : tmpApp + "/" + relative

            if entry.isDirectory {
                try? fm.createDirectory(atPath: dest, withIntermediateDirectories: true)
            } else {
                let destDir = (dest as NSString).deletingLastPathComponent
                try? fm.createDirectory(atPath: destDir, withIntermediateDirectories: true)
                if let fileData = try? archive.extract(entry) {
                    setPhase(.copying(file: (relative as NSString).lastPathComponent))
                    fm.createFile(atPath: dest, contents: fileData)
                } else {
                    log("warn: failed to extract \(relative)")
                }
            }
        }

        log("extracted \(appEntries.count) entries to temp")

        // ── 7. Ad-hoc sign in temp location ──────────────────────────────────
        setPhase(.copying(file: "signing…"))
        let signOK = amfi_sign_app_bundle(tmpApp) == 0
        log("ad-hoc sign (temp): \(signOK ? "OK" : "partial — will retry in bundle")")

        // ── 8. Create bundle container ────────────────────────────────────────
        //    As root (after step 1) this is a plain mkdir — no permission error.
        let containerUUID = UUID().uuidString.uppercased()
        let bundleDir     = bundleRoot + "/" + containerUUID
        let appDest       = bundleDir  + "/" + appBundleName

        // Use POSIX mkdir directly — FileManager goes through extra sandbox checks
        let mkdirRC = bundleDir.withCString { Darwin.mkdir($0, 0o755) }
        if mkdirRC != 0 {
            let e = errno
            // Fallback to FileManager (may work after root elevation flushes cache)
            do {
                try fm.createDirectory(atPath: bundleDir, withIntermediateDirectories: true)
                log("created bundle dir (FileManager fallback): \(containerUUID)")
            } catch {
                fail("Cannot create bundle directory: errno=\(e) (\(String(cString: strerror(e))))")
                return
            }
        } else {
            log("created bundle dir: \(containerUUID)")
        }

        // ── 9. Copy app bundle ────────────────────────────────────────────────
        setPhase(.copying(file: appBundleName))
        do {
            try fm.copyItem(atPath: tmpApp, toPath: appDest)
            log("copied app bundle")
        } catch {
            log("copyItem failed (\(error.localizedDescription)), trying direct copy…")
            if !directCopy(src: tmpApp, dst: appDest) {
                fail("Cannot copy app bundle to container.")
                return
            }
            log("direct copy OK")
        }

        // Re-sign in final location
        if amfi_sign_app_bundle(appDest) == 0 {
            log("re-sign in bundle container: OK")
        } else {
            log("warn: re-sign in bundle container failed")
        }

        // ── 10. Write bundle metadata plist ───────────────────────────────────
        let bundleMeta = bundleDir + "/.com.apple.mobile_container_manager.metadata.plist"
        let bundleMetaDict: [String: Any] = [
            "MCMMetadataContent": [
                "com.apple.MobileContainerManager.displayIdentifier": bundleID
            ],
            "MCMMetadataIdentifier": bundleID
        ]
        if let metaData = try? PropertyListSerialization.data(
            fromPropertyList: bundleMetaDict, format: .binary, options: 0
        ) {
            fm.createFile(atPath: bundleMeta, contents: metaData)
            log("wrote bundle metadata plist")
        }

        // ── 11. Create data container ─────────────────────────────────────────
        let dataUUID = UUID().uuidString.uppercased()
        let dataDir  = dataRoot + "/" + dataUUID

        let dataSubdirs = [
            dataDir + "/Documents",
            dataDir + "/Library",
            dataDir + "/Library/Application Support",
            dataDir + "/Library/Caches",
            dataDir + "/Library/Preferences",
            dataDir + "/tmp"
        ]
        for sub in dataSubdirs {
            // POSIX mkdir first, FileManager fallback
            sub.withCString { _ = Darwin.mkdir($0, 0o755) }
            try? fm.createDirectory(atPath: sub, withIntermediateDirectories: true)
        }

        let dataMeta = dataDir + "/.com.apple.mobile_container_manager.metadata.plist"
        let dataMetaDict: [String: Any] = [
            "MCMMetadataContent": [
                "com.apple.MobileContainerManager.displayIdentifier": bundleID
            ],
            "MCMMetadataIdentifier": bundleID
        ]
        if let dataMetaData = try? PropertyListSerialization.data(
            fromPropertyList: dataMetaDict, format: .binary, options: 0
        ) {
            fm.createFile(atPath: dataMeta, contents: dataMetaData)
            log("created data container: \(dataUUID)")
        }

        // ── 12. Set ownership (501:501 = mobile, so SpringBoard can read it) ──
        setPhase(.permissions)
        let ownOK = mgr.apfsown(path: appDest, uid: 501, gid: 501)
        log("apfsown app bundle: \(ownOK ? "OK" : "warn (may still work)")")

        // ── 13. Remove validated-by-free-profile xattr ────────────────────────
        let xattrKey = "com.apple.installd.validatedByFreeProfile"
        errno = 0
        let xattrRC = removexattr(appDest, xattrKey, 0)
        if xattrRC == 0 || errno == ENOATTR {
            log("xattr bypass applied")
        } else {
            log("xattr removal: errno=\(errno) (may be fine)")
        }

        // ── 14. Register with SpringBoard ─────────────────────────────────────
        setPhase(.registering)
        let appDestURL = URL(fileURLWithPath: appDest)
        let registered = lsRegister(bundleURL: appDestURL)
        log("LSApplicationWorkspace register: \(registered ? "OK" : "fallback")")

        notify_post("com.apple.LaunchServices.Register")
        notify_post("com.apple.mobile.application_installed")
        log("posted install notifications")

        // ── 15. Load icon for list ────────────────────────────────────────────
        let icon = loadIcon(bundlePath: appDest, info: infoPlist)

        // Cleanup temp
        try? fm.removeItem(atPath: tmpBase)

        DispatchQueue.main.async {
            phase = .done(name: appName)
            let entry = LaraInstalledApp(
                name: appName, bundleID: bundleID,
                bundlePath: appDest, icon: icon
            )
            installedApps.append(entry)
            persistInstalled(entry, containerUUID: containerUUID, dataUUID: dataUUID)
            mgr.logmsg("(ipa) installed \(appName) (\(bundleID))")
        }
    }

    // MARK: - Uninstall

    private func uninstall(_ app: LaraInstalledApp) {
        let fm = FileManager.default
        let containerDir = (app.bundlePath as NSString).deletingLastPathComponent

        Alertinator.shared.alert(
            title: "Uninstall \(app.name)?",
            body: "This will delete the app bundle. Data container will remain.",
            showCancel: true,
            actionLabel: "Uninstall"
        ) {
            DispatchQueue.global(qos: .userInitiated).async {
                let ok = (try? fm.removeItem(atPath: containerDir)) != nil
                log(ok ? "removed bundle container" : "failed to remove bundle container")
                notify_post("com.apple.LaunchServices.Register")
                DispatchQueue.main.async {
                    installedApps.removeAll { $0.id == app.id }
                    removePersistedEntry(bundleID: app.bundleID)
                    phase = .idle
                }
            }
        }
    }

    // MARK: - Scan installed apps

    private func scanInstalledApps() {
        let key = "lara.ipa.installed"
        guard let list = UserDefaults.standard.array(forKey: key) as? [[String: String]] else { return }
        var found: [LaraInstalledApp] = []
        for entry in list {
            guard let path = entry["bundlePath"],
                  FileManager.default.fileExists(atPath: path) else { continue }
            let info = NSDictionary(contentsOfFile: path + "/Info.plist") as? [String: Any]
            let name = (info?["CFBundleDisplayName"] as? String)
                    ?? (info?["CFBundleName"]        as? String)
                    ?? entry["name"] ?? "Unknown"
            let bid  = info?["CFBundleIdentifier"] as? String ?? entry["bundleID"] ?? ""
            let icon = loadIcon(bundlePath: path, info: info)
            found.append(LaraInstalledApp(name: name, bundleID: bid, bundlePath: path, icon: icon))
        }
        installedApps = found
    }

    private func persistInstalled(_ app: LaraInstalledApp, containerUUID: String, dataUUID: String) {
        let key = "lara.ipa.installed"
        var list = UserDefaults.standard.array(forKey: key) as? [[String: String]] ?? []
        list.removeAll { $0["bundleID"] == app.bundleID }
        list.append([
            "name": app.name,
            "bundleID": app.bundleID,
            "bundlePath": app.bundlePath,
            "containerUUID": containerUUID,
            "dataUUID": dataUUID
        ])
        UserDefaults.standard.set(list, forKey: key)
    }

    private func removePersistedEntry(bundleID: String) {
        let key = "lara.ipa.installed"
        var list = UserDefaults.standard.array(forKey: key) as? [[String: String]] ?? []
        list.removeAll { $0["bundleID"] == bundleID }
        UserDefaults.standard.set(list, forKey: key)
    }

    // MARK: - Helpers

    /// Fast file-by-file copy using direct write() syscall.
    /// Works even when FileManager.copyItem fails due to sandbox checks.
    private func directCopy(src: String, dst: String) -> Bool {
        let fm = FileManager.default
        guard let enumerator = fm.enumerator(atPath: src) else { return false }
        dst.withCString { _ = Darwin.mkdir($0, 0o755) }
        for case let rel as String in enumerator {
            let srcFull = src + "/" + rel
            let dstFull = dst + "/" + rel
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: srcFull, isDirectory: &isDir) else { continue }
            if isDir.boolValue {
                dstFull.withCString { _ = Darwin.mkdir($0, 0o755) }
            } else {
                let dstDir = (dstFull as NSString).deletingLastPathComponent
                dstDir.withCString { _ = Darwin.mkdir($0, 0o755) }
                guard let fileData = fm.contents(atPath: srcFull) else { continue }
                let fd = open(dstFull, O_WRONLY | O_CREAT | O_TRUNC, 0o644)
                guard fd >= 0 else { continue }
                fileData.withUnsafeBytes { ptr in
                    _ = Darwin.write(fd, ptr.baseAddress, fileData.count)
                }
                close(fd)
            }
        }
        return fm.fileExists(atPath: dst)
    }

    private func loadIcon(bundlePath: String, info: [String: Any]?) -> UIImage? {
        if let icons = info?["CFBundleIcons"] as? [String: Any],
           let primary = icons["CFBundlePrimaryIcon"] as? [String: Any],
           let files = primary["CFBundleIconFiles"] as? [String] {
            for name in files.reversed() {
                let base = bundlePath + "/" + name
                if let img = UIImage(contentsOfFile: base)             { return img }
                if let img = UIImage(contentsOfFile: base + "@2x.png") { return img }
                if let img = UIImage(contentsOfFile: base + ".png")    { return img }
            }
        }
        if let name = info?["CFBundleIconFile"] as? String {
            let base = bundlePath + "/" + name
            if let img = UIImage(contentsOfFile: base)             { return img }
            if let img = UIImage(contentsOfFile: base + "@2x.png") { return img }
            if let img = UIImage(contentsOfFile: base + ".png")    { return img }
        }
        return nil
    }

    private func setPhase(_ p: InstallPhase) {
        DispatchQueue.main.async { phase = p }
    }

    private func fail(_ reason: String) {
        log("ERROR: \(reason)")
        DispatchQueue.main.async { phase = .failed(reason: reason) }
    }

    private func log(_ msg: String) {
        DispatchQueue.main.async {
            loglines.append("▸ " + msg)
        }
    }
}
