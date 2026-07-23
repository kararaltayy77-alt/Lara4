//
//  RemoteBridgeManager.swift
//  LARA4 Remote Bridge v2.0
//
//  TCP Command & Control server integrated into Lara4 Shell.
//  Usage inside Lara4 shell:
//    bridge-start [port] [token]
//    bridge-stop
//

import Foundation
import Darwin

final class RemoteBridgeManager {
    static let shared = RemoteBridgeManager()

    private var listenerSocket: Int32 = -1
    private var isRunning = false
    private var clients: [Int32: DispatchSourceRead] = [:]
    private var clientBuffers: [Int32: Data] = [:]
    private let queue = DispatchQueue(label: "lara.bridge", qos: .utility)
    private var authToken: String = "L4RA-2026-SECURE"
    private weak var laramgrRef: laramgr?

    private init() {}

    // MARK: - Public API

    func start(port: UInt16 = 8765, token: String = "L4RA-2026-SECURE", mgr: laramgr) -> String {
        guard !isRunning else {
            return "[!] Bridge already running. Stop it first: bridge-stop"
        }

        self.laramgrRef = mgr
        self.authToken = token

        listenerSocket = socket(AF_INET, SOCK_STREAM, 0)
        guard listenerSocket >= 0 else {
            return "[!] Failed to create socket"
        }

        var on: Int32 = 1
        setsockopt(listenerSocket, SOL_SOCKET, SO_REUSEADDR, &on, socklen_t(MemoryLayout<Int32>.size))

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = INADDR_ANY.bigEndian

        let bindRes = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(listenerSocket, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }

        guard bindRes == 0 else {
            let err = String(cString: strerror(errno))
            close(listenerSocket); listenerSocket = -1
            return "[!] Bind failed on port \(port): \(err)"
        }

        guard listen(listenerSocket, 5) == 0 else {
            let err = String(cString: strerror(errno))
            close(listenerSocket); listenerSocket = -1
            return "[!] Listen failed: \(err)"
        }

        isRunning = true

        queue.async { [weak self] in
            self?.acceptLoop()
        }

        let ip = getDeviceIP() ?? "0.0.0.0"

        return """

        ╔══════════════════════════════════════════════════════════════════╗
        ║  LARA4 Remote Bridge v2.0 — ONLINE                               ║
        ╠══════════════════════════════════════════════════════════════════╣
        ║  Address:  \(ip):\(port)                                        ║
        ║  Token:    \(token)                                             ║
        ║  Status:   Listening for connections...                        ║
        ╠══════════════════════════════════════════════════════════════════╣
        ║  Connect from your PC/Mac:                                       ║
        ║  python3 lara_client.py \(ip) \(port)                             ║
        ╚══════════════════════════════════════════════════════════════════╝
        """
    }

    func stop() {
        isRunning = false

        for (fd, source) in clients {
            source.cancel()
            close(fd)
        }
        clients.removeAll()
        clientBuffers.removeAll()

        if listenerSocket >= 0 {
            close(listenerSocket)
            listenerSocket = -1
        }
    }

    // MARK: - Network Loop

    private func acceptLoop() {
        while isRunning {
            var clientAddr = sockaddr_in()
            var addrLen = socklen_t(MemoryLayout<sockaddr_in>.size)

            let clientFd = withUnsafeMutablePointer(to: &clientAddr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    accept(listenerSocket, $0, &addrLen)
                }
            }

            guard clientFd >= 0 else { continue }

            var flags = fcntl(clientFd, F_GETFL, 0)
            fcntl(clientFd, F_SETFL, flags | O_NONBLOCK)

            queue.async { [weak self] in
                self?.handleClient(clientFd)
            }
        }
    }

    private func handleClient(_ fd: Int32) {
        clientBuffers[fd] = Data()

        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        source.setEventHandler { [weak self] in
            self?.readFromClient(fd)
        }
        source.setCancelHandler {
            close(fd)
        }
        source.resume()
        clients[fd] = source

        let welcome = "{\"type\":\"welcome\",\"bridge\":\"LARA4\",\"version\":\"2.0\"}\n"
        _ = welcome.withCString { send(fd, $0, strlen($0), 0) }
    }

    private func readFromClient(_ fd: Int32) {
        var buf = [UInt8](repeating: 0, count: 4096)
        let n = read(fd, &buf, 4096)

        if n <= 0 {
            cleanupClient(fd)
            return
        }

        clientBuffers[fd]?.append(contentsOf: buf[0..<n])

        while let newlineIdx = clientBuffers[fd]?.firstIndex(of: 10) {
            guard let lineData = clientBuffers[fd]?[..<newlineIdx] else { break }
            clientBuffers[fd]?.removeSubrange(...newlineIdx)

            guard let line = String(data: Data(lineData), encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
                  !line.isEmpty else { continue }

            processCommand(line, fd: fd)
        }
    }

    private func cleanupClient(_ fd: Int32) {
        clients[fd]?.cancel()
        clients.removeValue(forKey: fd)
        clientBuffers.removeValue(forKey: fd)
    }

    // MARK: - Command Processing

    private func processCommand(_ jsonStr: String, fd: Int32) {
        guard let data = jsonStr.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            sendJson(["ok": false, "error": "invalid_json"], fd: fd)
            return
        }

        let token = json["auth"] as? String ?? ""
        guard token == authToken else {
            sendJson(["ok": false, "error": "auth_failed"], fd: fd)
            return
        }

        let action = json["action"] as? String ?? ""
        let payload = json["payload"] as? String ?? ""

        DispatchQueue.main.async { [weak self] in
            guard let self = self, let mgr = self.laramgrRef else {
                self?.sendJson(["ok": false, "error": "laramgr_not_available"], fd: fd)
                return
            }

            let result = self.routeCommand(action: action, payload: payload, mgr: mgr)
            self.sendJson(result, fd: fd)
        }
    }

    private func routeCommand(action: String, payload: String, mgr: laramgr) -> [String: Any] {
        switch action {

        case "shell":
            let res = OmegaCore.execute("exec", context: mgr, arg: payload)
            return convertResult(res)

        case "lara":
            let parts = payload.split(separator: " ", maxSplits: 1).map(String.init)
            let cmd = parts.first ?? ""
            let arg = parts.count > 1 ? parts[1] : ""
            let res = OmegaCore.execute(cmd, context: mgr, arg: arg)
            return convertResult(res)

        case "sysinfo":
            return [
                "ok": true,
                "hostname": runShell("hostname"),
                "whoami": runShell("whoami"),
                "pwd": FileManager.default.currentDirectoryPath,
                "uid": runShell("id"),
                "uname": runShell("uname -a")
            ]

        case "file_read":
            do {
                let content = try String(contentsOfFile: payload, encoding: .utf8)
                return ["ok": true, "content": content]
            } catch {
                return ["ok": false, "error": error.localizedDescription]
            }

        case "file_write":
            if let fileData = payload.data(using: .utf8),
               let fileJson = try? JSONSerialization.jsonObject(with: fileData) as? [String: String],
               let path = fileJson["path"],
               let content = fileJson["content"] {
                do {
                    try content.write(toFile: path, atomically: true, encoding: .utf8)
                    return ["ok": true, "bytes_written": content.count]
                } catch {
                    return ["ok": false, "error": error.localizedDescription]
                }
            }
            return ["ok": false, "error": "invalid_payload_for_file_write"]

        case "file_list":
            let path = payload.isEmpty ? "." : payload
            do {
                let entries = try FileManager.default.contentsOfDirectory(atPath: path)
                let details = entries.map { name -> [String: Any] in
                    let full = (path as NSString).appendingPathComponent(name)
                    let attrs = try? FileManager.default.attributesOfItem(atPath: full)
                    return [
                        "name": name,
                        "size": attrs?[.size] as? Int ?? 0,
                        "is_dir": (attrs?[.type] as? FileAttributeType) == .typeDirectory,
                        "mode": String(format: "%o", (attrs?[.posixPermissions] as? Int16 ?? 0)),
                        "modified": (attrs?[.modificationDate] as? Date)?.timeIntervalSince1970 ?? 0
                    ]
                }
                return ["ok": true, "path": path, "entries": details]
            } catch {
                return ["ok": false, "error": error.localizedDescription]
            }

        case "ps":
            return ["ok": true, "output": runShell("ps -eo pid,ppid,comm,args")]

        case "env":
            return ["ok": true, "env": ProcessInfo.processInfo.environment]

        case "cd":
            FileManager.default.changeCurrentDirectoryPath(payload)
            return ["ok": true, "cwd": FileManager.default.currentDirectoryPath]

        case "cwd":
            return ["ok": true, "cwd": FileManager.default.currentDirectoryPath]

        case "ping":
            return ["ok": true, "pong": true]

        case "exit":
            return ["ok": true, "msg": "goodbye"]

        default:
            return ["ok": false, "error": "unknown_action: \(action)"]
        }
    }

    private func convertResult(_ result: CommandResult) -> [String: Any] {
        switch result {
        case .ok(let msg):
            return ["ok": true, "output": msg]
        case .fail(let msg):
            return ["ok": false, "error": msg]
        case .result(let res):
            return ["ok": res.ok, "output": res.output, "isError": res.isError]
        }
    }

    private func runShell(_ cmd: String) -> String {
        let task = Process()
        task.launchPath = "/bin/sh"
        task.arguments = ["-c", cmd]
        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = pipe
        task.launch()
        task.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        return String(data: data, encoding: .utf8) ?? ""
    }

    private func sendJson(_ dict: [String: Any], fd: Int32) {
        guard let data = try? JSONSerialization.data(withJSONObject: dict) else { return }
        var sendData = data
        sendData.append(10)
        _ = sendData.withUnsafeBytes { send(fd, $0.baseAddress!, $0.count, 0) }
    }

    private func getDeviceIP() -> String? {
        var addresses: [String] = []
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0 else { return nil }
        var ptr = ifaddr
        while ptr != nil {
            let flags = Int32(ptr!.pointee.ifa_flags)
            let addr = ptr!.pointee.ifa_addr.pointee
            if (flags & (IFF_UP|IFF_RUNNING|IFF_LOOPBACK)) == (IFF_UP|IFF_RUNNING),
               addr.sa_family == UInt8(AF_INET) {
                var hostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                if getnameinfo(ptr!.pointee.ifa_addr, socklen_t(addr.sa_len),
                              &hostname, socklen_t(hostname.count),
                              nil, 0, NI_NUMERICHOST) == 0 {
                    let address = String(cString: hostname)
                    if !address.hasPrefix("127.") {
                        addresses.append(address)
                    }
                }
            }
            ptr = ptr!.pointee.ifa_next
        }
        freeifaddrs(ifaddr)
        return addresses.first
    }
}
