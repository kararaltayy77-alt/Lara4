import Foundation

final class OmegaFS {

    static let shared = OmegaFS()
    private let fm = FileManager.default
    var cwd: String = "/"

    func resolve(_ path: String) -> String {
        if path.isEmpty { return cwd }
        if path == "~" { return NSHomeDirectory() }
        if path.hasPrefix("~/") {
            return NSHomeDirectory() + path.dropFirst(1)
        }
        if path.hasPrefix("/") {
            return URL(fileURLWithPath: path).standardized.path
        }
        return URL(fileURLWithPath: cwd).appendingPathComponent(path).standardized.path
    }

    func pwd() -> String { cwd }

    func cd(_ path: String) -> String {
        let target = resolve(path.isEmpty ? "~" : path)
        var isDir: ObjCBool = false
        guard fm.fileExists(atPath: target, isDirectory: &isDir), isDir.boolValue else {
            return "cd: \(path): No such directory"
        }
        cwd = target
        return ""
    }

    func ls(_ arg: String) -> String {
        var showHidden = false
        var longFormat = false
        var targetPath = ""

        let parts = arg.split(separator: " ").map { String($0) }
        for p in parts {
            if p.hasPrefix("-") {
                if p.contains("a") { showHidden = true }
                if p.contains("l") { longFormat = true }
            } else {
                targetPath = p
            }
        }

        let target = targetPath.isEmpty ? cwd : resolve(targetPath)
        var isDir: ObjCBool = false
        guard fm.fileExists(atPath: target, isDirectory: &isDir) else {
            return "ls: \(targetPath): No such file or directory"
        }

        if !isDir.boolValue { return target }

        let contents = (try? fm.contentsOfDirectory(atPath: target)) ?? []
        let filtered = showHidden ? contents : contents.filter { !$0.hasPrefix(".") }
        let sorted = filtered.sorted()

        if sorted.isEmpty { return "(empty)" }

        if longFormat {
            return sorted.map { name -> String in
                let full = (target as NSString).appendingPathComponent(name)
                var isD: ObjCBool = false
                fm.fileExists(atPath: full, isDirectory: &isD)
                let attrs = try? fm.attributesOfItem(atPath: full)
                let size = attrs?[.size] as? Int ?? 0
                let date = attrs?[.modificationDate] as? Date ?? Date()
                let df = DateFormatter()
                df.dateFormat = "MMM dd HH:mm"
                // Bug fixed: was hardcoding rwxr-xr-x; now reads actual POSIX permissions
                let modeVal = (attrs?[.posixPermissions] as? UInt16) ?? 0
                let typeChar = isD.boolValue ? "d" : "-"
                let permStr: String = {
                    guard modeVal != 0 else { return "rwxr-xr-x" }
                    var s = ""
                    s += (modeVal & 0o400) != 0 ? "r" : "-"
                    s += (modeVal & 0o200) != 0 ? "w" : "-"
                    s += (modeVal & 0o100) != 0 ? "x" : "-"
                    s += (modeVal & 0o040) != 0 ? "r" : "-"
                    s += (modeVal & 0o020) != 0 ? "w" : "-"
                    s += (modeVal & 0o010) != 0 ? "x" : "-"
                    s += (modeVal & 0o004) != 0 ? "r" : "-"
                    s += (modeVal & 0o002) != 0 ? "w" : "-"
                    s += (modeVal & 0o001) != 0 ? "x" : "-"
                    return s
                }()
                return "\(typeChar)\(permStr)  \(formatSize(size).padding(toLength: 6, withPad: " ", startingAt: 0))  \(df.string(from: date))  \(name)"
            }.joined(separator: "\n")
        } else {
            return sorted.joined(separator: "  ")
        }
    }

    func cat(_ arg: String) -> String {
        let path = resolve(arg.trimmingCharacters(in: .whitespaces))
        guard fm.fileExists(atPath: path) else {
            return "cat: \(arg): No such file or directory"
        }
        return (try? String(contentsOfFile: path, encoding: .utf8))
            ?? "cat: \(arg): binary or unreadable file"
    }

    func head(_ arg: String) -> String {
        var n = 10; var fileArg = ""
        let parts = arg.split(separator: " ").map { String($0) }
        var i = 0
        while i < parts.count {
            if parts[i] == "-n", i + 1 < parts.count { n = Int(parts[i+1]) ?? 10; i += 2 }
            else { fileArg = parts[i]; i += 1 }
        }
        guard !fileArg.isEmpty else { return "head: missing filename" }
        let path = resolve(fileArg)
        guard let content = try? String(contentsOfFile: path, encoding: .utf8) else {
            return "head: \(fileArg): No such file or unreadable"
        }
        return content.split(separator: "\n", omittingEmptySubsequences: false)
            .prefix(n).joined(separator: "\n")
    }

    func tail(_ arg: String) -> String {
        var n = 10; var fileArg = ""
        let parts = arg.split(separator: " ").map { String($0) }
        var i = 0
        while i < parts.count {
            if parts[i] == "-n", i + 1 < parts.count { n = Int(parts[i+1]) ?? 10; i += 2 }
            else { fileArg = parts[i]; i += 1 }
        }
        guard !fileArg.isEmpty else { return "tail: missing filename" }
        let path = resolve(fileArg)
        guard let content = try? String(contentsOfFile: path, encoding: .utf8) else {
            return "tail: \(fileArg): No such file or unreadable"
        }
        return content.split(separator: "\n", omittingEmptySubsequences: false)
            .suffix(n).joined(separator: "\n")
    }

    func write(_ file: String, _ content: String) -> String {
        let path = resolve(file)
        do {
            try content.write(toFile: path, atomically: true, encoding: .utf8)
            return ""
        } catch {
            return "write: \(error.localizedDescription)"
        }
    }

    func touch(_ arg: String) -> String {
        let path = resolve(arg.trimmingCharacters(in: .whitespaces))
        if fm.fileExists(atPath: path) {
            try? fm.setAttributes([.modificationDate: Date()], ofItemAtPath: path)
            return ""
        }
        guard fm.createFile(atPath: path, contents: nil) else {
            return "touch: cannot create \(arg)"
        }
        return ""
    }

    func rm(_ arg: String) -> String {
        var force = false; var recursive = false; var targetArg = ""
        let parts = arg.split(separator: " ").map { String($0) }
        for p in parts {
            if p.hasPrefix("-") {
                if p.contains("f") { force = true }
                if p.contains("r") || p.contains("R") { recursive = true }
            } else { targetArg = p }
        }
        let path = resolve(targetArg)
        var isDir: ObjCBool = false
        guard fm.fileExists(atPath: path, isDirectory: &isDir) else {
            return force ? "" : "rm: \(targetArg): No such file"
        }
        if isDir.boolValue && !recursive {
            return "rm: \(targetArg): is a directory — use -r"
        }
        do { try fm.removeItem(atPath: path); return "" }
        catch { return "rm: \(error.localizedDescription)" }
    }

    func mkdir(_ arg: String) -> String {
        var parents = false; var nameArg = ""
        for p in arg.split(separator: " ").map({ String($0) }) {
            if p == "-p" { parents = true } else { nameArg = p }
        }
        let path = resolve(nameArg)
        do {
            try fm.createDirectory(atPath: path, withIntermediateDirectories: parents)
            return ""
        } catch { return "mkdir: \(error.localizedDescription)" }
    }

    func cp(_ arg: String) -> String {
        let parts = arg.split(separator: " ").map { String($0) }
        guard parts.count >= 2 else { return "cp: usage: cp <src> <dst>" }
        let src = resolve(parts[0])
        var dst = resolve(parts[1])
        var isDir: ObjCBool = false
        if fm.fileExists(atPath: dst, isDirectory: &isDir), isDir.boolValue {
            dst = URL(fileURLWithPath: dst)
                .appendingPathComponent(URL(fileURLWithPath: src).lastPathComponent).path
        }
        do { try fm.copyItem(atPath: src, toPath: dst); return "" }
        catch { return "cp: \(error.localizedDescription)" }
    }

    func mv(_ arg: String) -> String {
        let parts = arg.split(separator: " ").map { String($0) }
        guard parts.count >= 2 else { return "mv: usage: mv <src> <dst>" }
        let src = resolve(parts[0])
        var dst = resolve(parts[1])
        var isDir: ObjCBool = false
        if fm.fileExists(atPath: dst, isDirectory: &isDir), isDir.boolValue {
            dst = URL(fileURLWithPath: dst)
                .appendingPathComponent(URL(fileURLWithPath: src).lastPathComponent).path
        }
        do { try fm.moveItem(atPath: src, toPath: dst); return "" }
        catch { return "mv: \(error.localizedDescription)" }
    }

    func stat(_ arg: String) -> String {
        let path = resolve(arg.trimmingCharacters(in: .whitespaces))
        guard let attrs = try? fm.attributesOfItem(atPath: path) else {
            return "stat: \(arg): No such file or directory"
        }
        var isDir: ObjCBool = false
        fm.fileExists(atPath: path, isDirectory: &isDir)
        let size = attrs[.size] as? Int ?? 0
        let created = attrs[.creationDate] as? Date ?? Date()
        let modified = attrs[.modificationDate] as? Date ?? Date()
        let df = DateFormatter(); df.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return """
  File: \(path)
  Type: \(isDir.boolValue ? "directory" : "regular file")
  Size: \(formatSize(size))
Created: \(df.string(from: created))
   Mod: \(df.string(from: modified))
"""
    }

    func find(_ arg: String) -> String {
        let parts = arg.split(separator: " ").map { String($0) }
        var searchPath = cwd
        var namePattern: String? = nil
        var i = 0
        while i < parts.count {
            if parts[i] == "-name", i + 1 < parts.count {
                namePattern = parts[i+1]; i += 2
            } else { searchPath = resolve(parts[i]); i += 1 }
        }
        var results: [String] = []
        guard let enumerator = fm.enumerator(atPath: searchPath) else {
            return "find: \(searchPath): No such directory"
        }
        for case let file as String in enumerator {
            if let pattern = namePattern {
                let name = URL(fileURLWithPath: file).lastPathComponent
                if fnmatch(pattern, name, 0) == 0 {
                    results.append((searchPath as NSString).appendingPathComponent(file))
                }
            } else {
                results.append((searchPath as NSString).appendingPathComponent(file))
            }
            if results.count >= 200 { results.append("... (limited to 200)"); break }
        }
        return results.isEmpty ? "" : results.joined(separator: "\n")
    }

    func chmod(_ arg: String) -> String {
        let parts = arg.split(separator: " ").map { String($0) }
        guard parts.count >= 2 else { return "chmod: usage: chmod <mode> <file>" }
        let path = resolve(parts[1])
        guard let mode = UInt16(parts[0], radix: 8) else { return "chmod: invalid mode" }
        guard Darwin.chmod(path, mode_t(mode)) == 0 else {
            return "chmod: \(String(cString: strerror(errno)))"
        }
        return ""
    }

    private func formatSize(_ bytes: Int) -> String {
        if bytes < 1024 { return "\(bytes)B" }
        if bytes < 1024 * 1024 { return String(format: "%.1fK", Double(bytes) / 1024) }
        return String(format: "%.1fM", Double(bytes) / (1024 * 1024))
    }
}
