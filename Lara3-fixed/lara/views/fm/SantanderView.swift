//
//  SantanderView.swift
//  lara
//

import SwiftUI
import Combine

struct SantanderView: View {
    let startpath: String

    @AppStorage("selectedmethod") private var selectedmethod: method = .hybrid
    @ObservedObject private var mgr = laramgr.shared

    @State private var showsecret: Bool = false
    @State private var rootElevated: Bool = false

    init(startPath: String = "/") {
        self.startpath = startPath.isEmpty ? "/" : startPath
    }

    private var readsbx: Bool {
        selectedmethod != .vfs
    }

    private var writevfs: Bool {
        selectedmethod != .sbx
    }

    private var ready: Bool {
        switch selectedmethod {
        case .sbx:
            return mgr.sbxready
        case .vfs:
            return mgr.vfsready
        case .hybrid:
            return mgr.sbxready && mgr.vfsready
        }
    }

    var body: some View {
        Group {
            if ready {
                santanderroot(
                    startpath: startpath,
                    readsbx: readsbx,
                    writevfs: writevfs,
                    rootElevated: rootElevated
                )
                .onAppear {
                    if !rootElevated {
                        let rc = amfi_elevate_to_root()
                        rootElevated = (rc == 0) || amfi_is_root()
                    }
                }
            } else {
                NavigationStack {
                    VStack(spacing: 16) {
                        Image(systemName: "externaldrive.trianglebadge.exclamationmark")
                            .imageScale(.large)
                            .font(.system(size: 48))
                            .foregroundColor(.orange)
                        Text("File Manager Not Ready")
                            .font(.headline)
                        Text("Run exploit → Sandbox escape → then open File Manager again.")
                            .multilineTextAlignment(.center)
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                            .padding(.horizontal)
                    }
                }
            }
        }
    }
}

// MARK: - Root nav container

private struct santanderroot: View {
    let readsbx: Bool
    let writevfs: Bool
    let rootElevated: Bool

    @StateObject private var nav: santandernav

    init(startpath: String, readsbx: Bool, writevfs: Bool, rootElevated: Bool) {
        self.readsbx = readsbx
        self.writevfs = writevfs
        self.rootElevated = rootElevated
        _nav = StateObject(wrappedValue: santandernav(root: santanderitem(path: startpath, isdir: true)))
    }

    var body: some View {
        NavigationStack(path: $nav.stack) {
            santanderdirview(item: nav.root, readsbx: readsbx, writevfs: writevfs, rootElevated: rootElevated)
                .environmentObject(nav)
                .navigationDestination(for: santanderitem.self) { item in
                    if item.isdir {
                        santanderdirview(item: item, readsbx: readsbx, writevfs: writevfs, rootElevated: rootElevated)
                            .environmentObject(nav)
                    } else {
                        santanderfileview(item: item, readsbx: readsbx, writevfs: writevfs)
                    }
                }
        }
    }
}

// MARK: - Nav state

final class santandernav: ObservableObject {
    @Published var root: santanderitem
    @Published var stack: [santanderitem] = []

    init(root: santanderitem) {
        self.root = root
    }

    func go(_ item: santanderitem) {
        root = item
        stack.removeAll()
    }
}

extension UIViewController {
    func topMostViewController() -> UIViewController {
        if let presented = presentedViewController {
            return presented.topMostViewController()
        }
        return self
    }
}
