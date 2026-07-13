//
//  FontPicker.swift
//  lara
//
//  Created by ruter on 27.03.26.
//

import SwiftUI
import Darwin

struct scannedapp: Identifiable, Hashable {
    let id: String
    let name: String
    let bundleid: String
    let bundlepath: String
    let hasmobileprov: Bool
    let notbypassed: Bool
}

struct AppsView: View {
    @EnvironmentObject private var mgr: laramgr
    @AppStorage("selectedmethod") private var selectedmethod: method = .vfs
    
    @State private var scannedapps: [scannedapp] = []
    @State private var iconcache: [String: UIImage] = [:]
    @State private var scanning: Bool = false
    @State private var bypassing: Bool = false
    
    private func isbypassed(bundlepath: String) -> Bool {
        let key = "com.apple.installd.validatedByFreeProfile"

        errno = 0
        let size = getxattr(bundlepath, key, nil, 0, 0, 0)

        if size < 0 {
            let code = errno

            if code == ENOATTR {
                mgr.logmsg("(sbx) xattr not present (bypassed): \(bundlepath)")
                return true
            } else {
                let err = String(cString: strerror(code))
                mgr.logmsg("(sbx) getxattr error on \(bundlepath) | errno=\(code) | \(err)")
                return false
            }
        }

        mgr.logmsg("(sbx) xattr still present (NOT bypassed): \(bundlepath)")
        return false
    }
    
    private func sbx3apbypass() {
        guard mgr.sbxready else {
            mgr.logmsg("(sbx) sandbox escape not ready")
            return
        }

        guard !bypassing else { return }
        bypassing = true

        DispatchQueue.global(qos: .userInitiated).async {
            let fm = FileManager.default
            let roots = [
                "/private/var/containers/Bundle/Application",
                "/var/containers/Bundle/Application"
            ]

            var seen: Set<String> = []
            var processed = 0

            for root in roots {
                guard let entries = try? fm.contentsOfDirectory(atPath: root) else { continue }

                for uuid in entries {
                    let dir = root + "/" + uuid

                    var isDir: ObjCBool = false
                    guard fm.fileExists(atPath: dir, isDirectory: &isDir), isDir.boolValue else { continue }
                    guard let apps = try? fm.contentsOfDirectory(atPath: dir) else { continue }

                    for app in apps where app.hasSuffix(".app") {
                        let bundlepath = dir + "/" + app

                        let normalized = bundlepath.hasPrefix("/private/")
                            ? String(bundlepath.dropFirst(8))
                            : bundlepath

                        if seen.contains(normalized) { continue }
                        seen.insert(normalized)

                        let mp = bundlepath + "/embedded.mobileprovision"
                        guard access(mp, F_OK) == 0 else { continue }

                        let testkey = "com.apple.installd.validatedByFreeProfile"
                        
                        let success = mgr.apfsown(path: bundlepath, uid: 501, gid: 501)
                        if !success {
                            mgr.logmsg("(sbx) failed to set ownership on: \(bundlepath)")
                        } else {
                            mgr.logmsg("(sbx) set ownership on: \(bundlepath)")
                        }

                        errno = 0
                        let rc = removexattr(bundlepath, testkey, 0)
                        if rc == 0 {
                            mgr.logmsg("(sbx) removed xattr on: \(bundlepath)")
                            processed += 1
                        } else {
                            let code = errno

                            if code == ENOATTR {
                                mgr.logmsg("(sbx) xattr already missing: \(bundlepath)")
                                processed += 1
                            } else {
                                let err = String(cString: strerror(code))
                                mgr.logmsg("(sbx) removexattr failed \(bundlepath) | errno=\(code) | \(err)")
                            }
                        }

                        errno = 0
                        let size = getxattr(bundlepath, testkey, nil, 0, 0, 0)
                        if size < 0 && errno == ENOATTR {
                            mgr.logmsg("(sbx) verified removal: \(bundlepath)")
                        } else {
                            mgr.logmsg("(sbx) xattr still exists on: \(bundlepath)")
                        }
                    }
                }
            }
            
            mgr.logmsg("(sbx) processed \(processed) app(s)")

            if processed == 0 {
                mgr.logmsg("(sbx) no eligible app found for xattr test")
            }

            DispatchQueue.main.async {
                bypassing = false
                scanappssbx()
            }
        }
    }
    
    private func scanappssbx() {
        guard mgr.sbxready else {
            scannedapps = []
            iconcache = [:]
            return
        }

        guard !scanning else { return }
        scanning = true

        DispatchQueue.global(qos: .userInitiated).async {
            let fm = FileManager.default
            let roots = [
                "/private/var/containers/Bundle/Application",
                "/var/containers/Bundle/Application"
            ]

            var results: [scannedapp] = []
            var cache: [String: UIImage] = [:]
            var seen: Set<String> = []

            for root in roots {
                guard let entries = try? fm.contentsOfDirectory(atPath: root) else { continue }

                for uuid in entries {
                    let dir = root + "/" + uuid
                    
                    var isDir: ObjCBool = false
                    guard fm.fileExists(atPath: dir, isDirectory: &isDir), isDir.boolValue else { continue }
                    guard let apps = try? fm.contentsOfDirectory(atPath: dir) else { continue }

                    for app in apps where app.hasSuffix(".app") {
                        let bundlepath = dir + "/" + app
                        
                        let normalizedPath = bundlepath.hasPrefix("/private/")
                            ? String(bundlepath.dropFirst(8))
                            : bundlepath
                        
                        if seen.contains(normalizedPath) { continue }

                        let infoPath = bundlepath + "/Info.plist"
                        let info = NSDictionary(contentsOfFile: infoPath) as? [String: Any]

                        let name =
                            (info?["CFBundleDisplayName"] as? String) ??
                            (info?["CFBundleName"] as? String) ??
                            app
                        
                        let bundleid = (info?["CFBundleIdentifier"] as? String) ?? "unknown"

                        let mp = bundlepath + "/embedded.mobileprovision"
                        let hasMP = access(mp, F_OK) == 0
                        guard hasMP else { continue }

                        let validated = isbypassed(bundlepath: bundlepath)

                        seen.insert(normalizedPath)

                        if let icon = loadappicon(bundlepath: bundlepath, info: info) {
                            cache[bundlepath] = icon
                        }

                        results.append(
                            scannedapp(
                                id: bundlepath,
                                name: name,
                                bundleid: bundleid,
                                bundlepath: bundlepath,
                                hasmobileprov: hasMP,
                                notbypassed: !validated
                            )
                        )
                    }
                }
            }

            results.sort { $0.name.lowercased() < $1.name.lowercased() }

            DispatchQueue.main.async {
                scannedapps = results
                iconcache = cache
                scanning = false
            }
        }
    }
    
    // FIX: use UIImage(contentsOfFile:) instead of Bundle(path:) + UIImage(named:in:bundle:)
    // The old approach crashed on iOS when loading bundles of other apps.
    // This matches how JitView.swift and DecryptView.swift load icons safely.
    private func loadappicon(bundlepath: String, info: [String: Any]?) -> UIImage? {
        if let icons = info?["CFBundleIcons"] as? [String: Any],
           let primary = icons["CFBundlePrimaryIcon"] as? [String: Any],
           let files = primary["CFBundleIconFiles"] as? [String] {
            for name in files.reversed() {
                let base = bundlepath + "/" + name
                if let image = UIImage(contentsOfFile: base) { return image }
                if let image = UIImage(contentsOfFile: base + "@2x.png") { return image }
                if let image = UIImage(contentsOfFile: base + ".png") { return image }
            }
        }

        if let name = info?["CFBundleIconFile"] as? String {
            let base = bundlepath + "/" + name
            if let image = UIImage(contentsOfFile: base) { return image }
            if let image = UIImage(contentsOfFile: base + "@2x.png") { return image }
            if let image = UIImage(contentsOfFile: base + ".png") { return image }
        }

        return nil
    }
    
    var body: some View {
        List {
            Section {
                if scanning {
                    HStack {
                        ProgressView()
                        Text("Scanning apps...")
                            .foregroundColor(.secondary)
                    }
                } else if scannedapps.isEmpty {
                    Text("No apps found.")
                        .foregroundColor(.secondary)
                } else {
                    ForEach(scannedapps) { app in
                        HStack(spacing: 12) {
                            if let icon = iconcache[app.bundlepath] {
                                Image(uiImage: icon)
                                    .resizable()
                                    .frame(width: 40, height: 40)
                                    .clipShape(RoundedRectangle(cornerRadius: 9))
                            } else {
                                Image("unknown")
                                    .resizable()
                                    .frame(width: 40, height: 40)
                                    .clipShape(RoundedRectangle(cornerRadius: 9))
                            }

                            VStack(alignment: .leading) {
                                Text(app.name)
                                    .font(.headline)

                                Text(app.bundleid)
                                    .font(.subheadline)
                                    .foregroundColor(.secondary)
                            }
                            
                            Spacer()
                            
                            if !app.notbypassed {
                                Image(systemName: "checkmark.circle")
                                    .foregroundColor(.green)
                            }
                        }
                    }
                }
            } header: {
                Text("Sideloaded Apps")
            }

            Section {
                Button {
                    sbx3apbypass()
                } label: {
                    if bypassing {
                        HStack {
                            ProgressView()
                            Text("Bypassing...")
                        }
                    } else {
                        Text("Bypass 3 App Limit")
                    }
                }
                .disabled(bypassing || scanning)
            } footer: {
                Text("Needs to be reapplied everytime you sideload a new app.")
            }
        }
        .navigationTitle("3 App Bypass")
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button {
                    scanappssbx()
                } label: {
                    if scanning {
                        ProgressView()
                    } else {
                        Image(systemName: "arrow.clockwise")
                    }
                }
                .disabled(scanning || bypassing)
            }
        }
        .onAppear {
            scanappssbx()
        }
    }
}
