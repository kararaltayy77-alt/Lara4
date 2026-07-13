//
//  DirectoryView.swift
//  lara
//

import SwiftUI
import Combine
import UniformTypeIdentifiers

struct santanderitem: Identifiable, Hashable {
    let path: String
    let name: String
    let display: String
    let isApp: Bool
    let appUDID: String
    let isdir: Bool
    let type: UTType?

    var id: String { path }

    init(path: String, isdir: Bool, display: String? = nil, isApp: Bool = false, appUDID: String = "") {
        self.path = path
        self.isdir = isdir
        let name = path == "/" ? "/" : (path as NSString).lastPathComponent
        self.name = name
        self.isApp = isApp
        self.appUDID = appUDID
        self.display = display ?? name
        let ext = (path as NSString).pathExtension
        self.type = ext.isEmpty ? nil : UTType(filenameExtension: ext)
    }

    var icon: String {
        if isdir { return "folder.fill" }
        guard let type else { return "doc" }
        if type.isSubtype(of: .text) { return "doc.text" }
        if type.isSubtype(of: .image) { return "photo" }
        if type.isSubtype(of: .audio) { return "waveform" }
        if type.isSubtype(of: .movie) || type.isSubtype(of: .video) { return "play.rectangle" }
        return "doc"
    }
}

final class santanderdirmodel: ObservableObject {
    @Published var allitems: [santanderitem] = []
    @Published var shownitems: [santanderitem] = []
    @Published var emptymsg: String?
    @Published var loading = false

    let item: santanderitem
    let readsbx: Bool
    let writevfs: Bool

    var sort: santandersort = .az
    var showhidden = true
    var recsearch = false

    init(item: santanderitem, readsbx: Bool, writevfs: Bool) {
        self.item = item
        self.readsbx = readsbx
        self.writevfs = writevfs
    }

    func load(query: String = "") {
        loading = true
        let item = item
        let readsbx = readsbx
        let sort = sort
        let showhidden = showhidden
        let recsearch = recsearch

        DispatchQueue.global(qos: .userInitiated).async {
            let listing = santanderfs.listdir(item: item, readsbx: readsbx)
            let shown = santanderfs.filteritems(
                all: listing.items,
                base: item.path,
                query: query,
                showhidden: showhidden,
                recsearch: recsearch,
                sort: sort,
                readsbx: readsbx
            )
            let empty = santanderfs.emptymessage(
                shown: shown,
                all: listing.items,
                query: query,
                showhidden: showhidden,
                fallback: listing.empty
            )
            DispatchQueue.main.async {
                self.allitems = listing.items
                self.shownitems = shown
                self.emptymsg = empty
                self.loading = false
            }
        }
    }
}

struct santanderdirview: View {
    let item: santanderitem
    let readsbx: Bool
    let writevfs: Bool
    let rootElevated: Bool

    @EnvironmentObject private var nav: santandernav
    @ObservedObject private var clip = santanderclip.shared
    @AppStorage("fmRecursiveSearch") private var recsearch = false

    @StateObject private var model: santanderdirmodel
    @State private var query = ""
    @State private var showimport = false
    @State private var msg: santandermsg?
    @State private var infoitem: santanderitem?
    @State private var chmoditem: santanderitem?
    @State private var chownitem: santanderitem?
    @State private var delitem: santanderitem?
    @State private var renameitem: santanderitem?
    @State private var shownewfolder = false
    @State private var shownewfile = false
    @State private var showvfsinfo = false

    init(item: santanderitem, readsbx: Bool, writevfs: Bool, rootElevated: Bool) {
        self.item = item
        self.readsbx = readsbx
        self.writevfs = writevfs
        self.rootElevated = rootElevated
        _model = StateObject(wrappedValue: santanderdirmodel(item: item, readsbx: readsbx, writevfs: writevfs))
    }

    // As root (UID 0) we can write anywhere — no need for sbx mode restriction.
    private var canWrite: Bool { readsbx || rootElevated }

    var body: some View {
        List {
            if model.loading && model.shownitems.isEmpty {
                Section {
                    HStack {
                        Spacer()
                        ProgressView()
                        Spacer()
                    }
                }
            } else if model.shownitems.isEmpty {
                Section {
                    Text(model.emptymsg ?? "Directory is empty.")
                        .foregroundColor(.secondary)
                }
            } else {
                Section {
                    ForEach(model.shownitems) { entry in
                        Button {
                            nav.stack.append(entry)
                        } label: {
                            row(entry: entry)
                        }
                        .buttonStyle(.plain)
                        .contextMenu {
                            Button {
                                copy(entry)
                            } label: {
                                Label("Copy", systemImage: "doc.on.doc")
                            }

                            Button {
                                infoitem = entry
                            } label: {
                                Label("Get Info", systemImage: "info.circle")
                            }

                            Button {
                                share(entry)
                            } label: {
                                Label("Share", systemImage: "square.and.arrow.up")
                            }

                            Button {
                                renameitem = entry
                            } label: {
                                Label("Rename", systemImage: "pencil")
                            }
                            .disabled(!canWrite)

                            Button {
                                replace(entry)
                            } label: {
                                Label("Replace With Clipboard", systemImage: "doc.on.clipboard")
                            }
                            .disabled(clip.item == nil || (!canWrite && !writevfs))

                            Button {
                                chmoditem = entry
                            } label: {
                                Label("Chmod", systemImage: "lock.open")
                            }

                            Button {
                                chownitem = entry
                            } label: {
                                Label("Chown", systemImage: "person.crop.circle")
                            }

                            Button(role: .destructive) {
                                delitem = entry
                            } label: {
                                Label("Delete", systemImage: "trash")
                            }
                        }
                    }
                } footer: {
                    if !readsbx {
                        Text("This file manager is powered by vfs namecache lookups. It may display inaccurate information.")
                    }
                }
            }
        }
        .navigationTitle(item.path == "/" ? "/" : item.name)
        .navigationBarTitleDisplayMode(.inline)
        .searchable(text: $query, placement: .navigationBarDrawer(displayMode: .always))
        .toolbar {
            // ── root/mobile badge (top-left) ──────────────────────────────────
            ToolbarItem(placement: .topBarLeading) {
                HStack(spacing: 4) {
                    Image(systemName: rootElevated ? "checkmark.shield.fill" : "person.fill")
                        .foregroundColor(rootElevated ? .green : .orange)
                        .font(.caption)
                    Text(rootElevated ? "root" : "mobile")
                        .font(.caption2.bold())
                        .foregroundColor(rootElevated ? .green : .orange)
                }
            }

            ToolbarItemGroup(placement: .topBarTrailing) {
                if !readsbx {
                    Button { showvfsinfo = true } label: {
                        Image(systemName: "info.circle")
                    }
                }

                Menu {
                    Button {
                        showimport = true
                    } label: {
                        Label("Upload File", systemImage: "square.and.arrow.down")
                    }
                    .disabled(!canWrite)

                    Button {
                        shownewfolder = true
                    } label: {
                        Label("New Folder", systemImage: "folder.badge.plus")
                    }
                    .disabled(!canWrite)

                    Button {
                        shownewfile = true
                    } label: {
                        Label("Create File", systemImage: "doc.badge.plus")
                    }
                    .disabled(!canWrite)

                    Button {
                        paste(replace: false)
                    } label: {
                        Label("Paste", systemImage: "doc.on.clipboard")
                    }
                    .disabled(clip.item == nil || !canWrite)

                    Button {
                        paste(replace: true)
                    } label: {
                        Label("Paste (Replace)", systemImage: "doc.on.clipboard.fill")
                    }
                    .disabled(clip.item == nil || !canWrite)

                    Menu {
                        Button("Sort A-Z") {
                            model.sort = .az
                            model.load(query: query.trimmingCharacters(in: .whitespacesAndNewlines))
                        }
                        Button("Sort Z-A") {
                            model.sort = .za
                            model.load(query: query.trimmingCharacters(in: .whitespacesAndNewlines))
                        }
                    } label: {
                        Label("Sort", systemImage: "arrow.up.arrow.down")
                    }

                    Button {
                        model.showhidden.toggle()
                        model.load(query: query.trimmingCharacters(in: .whitespacesAndNewlines))
                    } label: {
                        Label(model.showhidden ? "Hide Hidden Files" : "Show Hidden Files", systemImage: "eye")
                    }

                    Divider()

                    Button {
                        nav.go(santanderitem(path: "/", isdir: true))
                    } label: {
                        Label("Go to Root /", systemImage: "externaldrive")
                    }

                    Button {
                        nav.go(santanderitem(path: "/var/containers/Bundle/Application", isdir: true))
                    } label: {
                        Label("Apps (Bundle)", systemImage: "square.stack.3d.up")
                    }

                    Button {
                        nav.go(santanderitem(path: "/var/mobile/Containers/Data/Application", isdir: true))
                    } label: {
                        Label("Apps (Data)", systemImage: "internaldrive")
                    }

                    Button {
                        nav.go(santanderitem(path: NSHomeDirectory(), isdir: true))
                    } label: {
                        Label("Go to Home", systemImage: "house")
                    }
                } label: {
                    Image(systemName: "ellipsis.circle")
                }
            }
        }
        .onAppear {
            syncsettings()
            model.load()
        }
        .onChange(of: query) { newvalue in
            syncsettings()
            model.load(query: newvalue.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        .onChange(of: recsearch) { _ in
            syncsettings()
            model.load(query: query.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        .refreshable {
            syncsettings()
            model.load(query: query.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        .fileImporter(
            isPresented: $showimport,
            allowedContentTypes: [.item],
            allowsMultipleSelection: false
        ) { result in
            switch result {
            case .success(let urls):
                guard let url = urls.first else { return }
                upload(url)
            case .failure(let err):
                msg = santandermsg(title: "Upload Failed", text: err.localizedDescription)
            }
        }
        .alert(item: $msg) { m in
            Alert(title: Text(m.title), message: Text(m.text), dismissButton: .default(Text("OK")))
        }
        .alert("Delete", isPresented: Binding(
            get: { delitem != nil },
            set: { if !$0 { delitem = nil } }
        )) {
            Button("Cancel", role: .cancel) { delitem = nil }
            Button("Delete", role: .destructive) {
                if let entry = delitem { delete(entry) }
                delitem = nil
            }
        } message: {
            Text("Delete \(delitem?.name ?? "item")?")
        }
        .sheet(item: $infoitem) { entry in
            infosheetcontent(entry: entry)
        }
        .sheet(item: $renameitem) { entry in
            santandernamesheet(
                title: "Rename",
                itemname: entry.name,
                placeholder: entry.name,
                actiontitle: "Rename"
            ) { newname in rename(entry, newname: newname) }
        }
        .sheet(item: $chmoditem) { entry in
            santanderchmodsheet(item: entry) { mode in
                santanderfs.clearImmutableIfPossible(atPath: entry.path)
                let ok = entry.path.withCString { apfs_mod($0, mode) == 0 }
                msg = santandermsg(title: "Chmod", text: ok ? "Done." : "Failed.")
            }
        }
        .sheet(item: $chownitem) { entry in
            santanderchownsheet(item: entry) { uid, gid in
                santanderfs.clearImmutableIfPossible(atPath: entry.path)
                let ok = entry.path.withCString { apfs_own($0, uid, gid) == 0 }
                msg = santandermsg(title: "Chown", text: ok ? "Done." : "Failed.")
            }
        }
        .alert("File Manager Info", isPresented: $showvfsinfo) {
            Button("OK", role: .cancel) {}
        } message: {
            Text("This browser is powered by vfs namecache lookups, not full directory enumeration. Some folders may appear empty unless entries are already cached.")
        }
        .sheet(isPresented: $shownewfolder) {
            santandernamesheet(
                title: "New Folder",
                itemname: item.name,
                placeholder: "New Folder",
                actiontitle: "Create"
            ) { name in newfolder(name: name) }
        }
        .sheet(isPresented: $shownewfile) {
            santandernewfilesheet(itemname: item.name) { name, text in
                newfile(name: name, text: text)
            }
        }
    }

    // MARK: - Helpers

    private func syncsettings() {
        model.recsearch = recsearch
    }

    @ViewBuilder
    private func row(entry: santanderitem) -> some View {
        HStack(spacing: 12) {
            Image(systemName: entry.icon)
                .foregroundColor(entry.isdir ? .accentColor : .secondary)
                .frame(width: 22)

            VStack(alignment: .leading, spacing: 2) {
                Text(entry.display)
                    .foregroundColor(entry.name.hasPrefix(".") ? .gray : .primary)
                    .lineLimit(1)
                    .truncationMode(.middle)

                if entry.isApp {
                    Text(entry.appUDID)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }

                if !query.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    Text(entry.path)
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            }

            Spacer()

            if entry.isdir {
                Image(systemName: "chevron.right")
                    .font(.caption)
                    .foregroundColor(Color(uiColor: .tertiaryLabel))
            }
        }
        .contentShape(Rectangle())
    }

    // MARK: - Actions

    private func copy(_ entry: santanderitem) {
        clip.item = santanderclipitem(path: entry.path, isdir: entry.isdir, name: entry.name)
        msg = santandermsg(title: "Copied", text: entry.name)
    }

    private func rename(_ entry: santanderitem, newname: String) {
        guard canWrite else {
            msg = santandermsg(title: "Rename Unavailable", text: "Sandbox escape or root required.")
            return
        }
        let trimmed = newname.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            msg = santandermsg(title: "Rename Failed", text: "Name cannot be empty.")
            return
        }
        guard !trimmed.contains("/") else {
            msg = santandermsg(title: "Rename Failed", text: "Name cannot contain '/'.")
            return
        }
        guard trimmed != entry.name else { return }
        let dest = ((entry.path as NSString).deletingLastPathComponent as NSString).appendingPathComponent(trimmed)
        guard !FileManager.default.fileExists(atPath: dest) else {
            msg = santandermsg(title: "Rename Failed", text: "A file with that name already exists.")
            return
        }
        do {
            santanderfs.clearImmutableIfPossible(atPath: entry.path)
            try FileManager.default.moveItem(atPath: entry.path, toPath: dest)
            model.load(query: query.trimmingCharacters(in: .whitespacesAndNewlines))
        } catch {
            msg = santandermsg(title: "Rename Failed", text: error.localizedDescription)
        }
    }

    private func newfolder(name: String) {
        guard canWrite else {
            msg = santandermsg(title: "New Folder Unavailable", text: "Sandbox escape or root required.")
            return
        }
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !trimmed.contains("/") else { return }
        let dest = (item.path as NSString).appendingPathComponent(trimmed)
        guard !FileManager.default.fileExists(atPath: dest) else {
            msg = santandermsg(title: "New Folder Failed", text: "Already exists.")
            return
        }
        // Try POSIX mkdir first (works everywhere as root), fallback to FileManager
        let rc = dest.withCString { Darwin.mkdir($0, 0o755) }
        if rc == 0 {
            model.load(query: query.trimmingCharacters(in: .whitespacesAndNewlines))
        } else {
            do {
                try FileManager.default.createDirectory(atPath: dest, withIntermediateDirectories: false)
                model.load(query: query.trimmingCharacters(in: .whitespacesAndNewlines))
            } catch {
                msg = santandermsg(title: "New Folder Failed", text: error.localizedDescription)
            }
        }
    }

    private func newfile(name: String, text: String) {
        guard canWrite else {
            msg = santandermsg(title: "Create File Unavailable", text: "Sandbox escape or root required.")
            return
        }
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !trimmed.contains("/") else { return }
        let dest = (item.path as NSString).appendingPathComponent(trimmed)
        guard !FileManager.default.fileExists(atPath: dest) else {
            msg = santandermsg(title: "Create File Failed", text: "Already exists.")
            return
        }
        let data = Data(text.utf8)
        // Try direct write (works as root), fallback to FileManager
        let fd = open(dest, O_WRONLY | O_CREAT | O_TRUNC, 0o644)
        if fd >= 0 {
            data.withUnsafeBytes { _ = Darwin.write(fd, $0.baseAddress, data.count) }
            close(fd)
            model.load(query: query.trimmingCharacters(in: .whitespacesAndNewlines))
        } else {
            do {
                try data.write(to: URL(fileURLWithPath: dest), options: .atomic)
                model.load(query: query.trimmingCharacters(in: .whitespacesAndNewlines))
            } catch {
                msg = santandermsg(title: "Create File Failed", text: error.localizedDescription)
            }
        }
    }

    private func paste(replace: Bool) {
        guard canWrite else {
            msg = santandermsg(title: "Paste Unavailable", text: "Sandbox escape or root required.")
            return
        }
        guard let clipitem = clip.item else { return }
        if clipitem.isdir && (item.path == clipitem.path || item.path.hasPrefix(clipitem.path + "/")) {
            msg = santandermsg(title: "Paste Failed", text: "Cannot paste a folder into itself.")
            return
        }
        let base = (item.path as NSString).appendingPathComponent(clipitem.name)
        let dest = replace ? base : santanderfs.uniquepath(base: base)
        do {
            if replace && FileManager.default.fileExists(atPath: dest) {
                try santanderfs.removeItemClearingImmutable(atPath: dest)
            }
            try FileManager.default.copyItem(atPath: clipitem.path, toPath: dest)
            model.load(query: query.trimmingCharacters(in: .whitespacesAndNewlines))
        } catch {
            msg = santandermsg(title: "Paste Failed", text: error.localizedDescription)
        }
    }

    private func replace(_ entry: santanderitem) {
        guard let clipitem = clip.item else { return }
        if writevfs && !entry.isdir && !clipitem.isdir {
            let ok = laramgr.shared.vfsoverwritefromlocalpath(target: entry.path, source: clipitem.path)
            if ok {
                model.load(query: query.trimmingCharacters(in: .whitespacesAndNewlines))
            } else {
                msg = santandermsg(title: "Replace Failed", text: "VFS overwrite failed.")
            }
            return
        }
        guard canWrite else {
            msg = santandermsg(title: "Replace Unavailable", text: "Sandbox escape or root required.")
            return
        }
        if clipitem.isdir && (entry.path == clipitem.path || entry.path.hasPrefix(clipitem.path + "/")) {
            msg = santandermsg(title: "Replace Failed", text: "Cannot replace with a folder into itself.")
            return
        }
        do {
            if FileManager.default.fileExists(atPath: entry.path) {
                try santanderfs.removeItemClearingImmutable(atPath: entry.path)
            }
            try FileManager.default.copyItem(atPath: clipitem.path, toPath: entry.path)
            model.load(query: query.trimmingCharacters(in: .whitespacesAndNewlines))
        } catch {
            msg = santandermsg(title: "Replace Failed", text: error.localizedDescription)
        }
    }

    private func delete(_ entry: santanderitem) {
        guard canWrite else {
            msg = santandermsg(title: "Delete Unavailable", text: "Sandbox escape or root required.")
            return
        }
        do {
            try santanderfs.removeItemClearingImmutable(atPath: entry.path)
            model.load(query: query.trimmingCharacters(in: .whitespacesAndNewlines))
        } catch {
            msg = santandermsg(title: "Delete Failed", text: error.localizedDescription)
        }
    }

    @MainActor
    private func share(_ entry: santanderitem) {
        guard !entry.isdir else {
            msg = santandermsg(title: "Share Unavailable", text: "Sharing folders is not supported.")
            return
        }
        guard FileManager.default.isReadableFile(atPath: entry.path) else {
            msg = santandermsg(title: "Share Failed", text: "File is not readable.")
            return
        }
        presentShareSheet(with: URL(fileURLWithPath: entry.path))
    }

    private func upload(_ url: URL) {
        guard canWrite else {
            msg = santandermsg(title: "Upload Unavailable", text: "Sandbox escape or root required.")
            return
        }
        guard url.startAccessingSecurityScopedResource() else {
            msg = santandermsg(title: "Upload Failed", text: "Unable to access selected file.")
            return
        }
        defer { url.stopAccessingSecurityScopedResource() }
        let base = (item.path as NSString).appendingPathComponent(url.lastPathComponent)
        let dest = santanderfs.uniquepath(base: base)
        do {
            if FileManager.default.fileExists(atPath: dest) {
                try santanderfs.removeItemClearingImmutable(atPath: dest)
            }
            try FileManager.default.copyItem(at: url, to: URL(fileURLWithPath: dest))
            model.load(query: query.trimmingCharacters(in: .whitespacesAndNewlines))
        } catch {
            msg = santandermsg(title: "Upload Failed", text: error.localizedDescription)
        }
    }
}
