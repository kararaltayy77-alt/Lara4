#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════════════════╗
# ║  LARA4 REMOTE CLIENT v2.0 — External Control Terminal               ║
# ║  Run on your Mac/PC: python3 lara_client.py <device_ip>             ║
# ╚══════════════════════════════════════════════════════════════════════╝

import socket
import json
import sys
import time
import readline
import os
import threading

# ── Configuration ─────────────────────────────────────────────────────
AUTH_TOKEN = "L4RA-2026-SECURE"
DEFAULT_PORT = 8765
BUFFER_SIZE = 65536

# ── Colors ────────────────────────────────────────────────────────────
class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

def c(color, text):
    return f"{color}{text}{Colors.RESET}"

# ── LaraClient Class ──────────────────────────────────────────────────
class LaraClient:
    def __init__(self, host, port=DEFAULT_PORT):
        self.host = host
        self.port = port
        self.sock = None
        self.session_id = None
        self.connected = False
        self.history_file = os.path.expanduser("~/.lara_history")

        # Load command history
        try:
            readline.read_history_file(self.history_file)
        except:
            pass

    def connect(self):
        """Establish connection to the bridge."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10)
            self.sock.connect((self.host, self.port))

            # Read welcome message
            welcome = self._recv_json()
            if welcome and welcome.get("type") == "welcome":
                self.session_id = welcome.get("session")
                self.connected = True
                return True
            return False
        except Exception as e:
            print(c(Colors.RED, f"[!] Connection failed: {e}"))
            return False

    def disconnect(self):
        if self.sock:
            try:
                self.send_cmd("exit")
            except:
                pass
            self.sock.close()
            self.sock = None
        self.connected = False
        try:
            readline.write_history_file(self.history_file)
        except:
            pass

    def send_cmd(self, action, payload=""):
        """Send a command and return the response."""
        if not self.sock:
            return {"ok": False, "error": "not_connected"}

        data = {
            "auth": AUTH_TOKEN,
            "action": action,
            "payload": payload
        }

        try:
            self.sock.sendall((json.dumps(data) + "\n").encode())
            return self._recv_json()
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def _recv_json(self):
        """Receive a single JSON response."""
        buffer = b""
        while b"\n" not in buffer:
            chunk = self.sock.recv(BUFFER_SIZE)
            if not chunk:
                return None
            buffer += chunk
        line, _ = buffer.split(b"\n", 1)
        try:
            return json.loads(line.decode("utf-8", errors="ignore"))
        except:
            return None

    def shell(self, cmd):
        """Execute a shell command and display results."""
        resp = self.send_cmd("shell", cmd)
        if not resp:
            print(c(Colors.RED, "[!] No response from bridge"))
            return

        if resp.get("ok"):
            stdout = resp.get("stdout", "")
            stderr = resp.get("stderr", "")
            code = resp.get("code", 0)

            if stdout:
                print(stdout, end="")
            if stderr:
                print(c(Colors.YELLOW, stderr), end="")
            if code != 0 and not stdout and not stderr:
                print(c(Colors.YELLOW, f"[exit code: {code}]"))
        else:
            print(c(Colors.RED, f"[!] Error: {resp.get('error', 'unknown')}"))

    def sysinfo(self):
        """Display system information."""
        resp = self.send_cmd("sysinfo")
        if resp and resp.get("ok"):
            info = resp.get("info", {})
            print()
            print(c(Colors.CYAN, "╔══════════════════════════════════════════════════════════════╗"))
            print(c(Colors.CYAN, "║  DEVICE INFORMATION                                          ║"))
            print(c(Colors.CYAN, "╠══════════════════════════════════════════════════════════════╣"))
            for key, val in info.items():
                label = key.replace("_", " ").title()
                print(c(Colors.CYAN, f"║  {label:20s}: {str(val)[:45]:45s} ║"))
            print(c(Colors.CYAN, "╚══════════════════════════════════════════════════════════════╝"))
            print()
        else:
            print(c(Colors.RED, "[!] Failed to get system info"))

    def file_list(self, path="."):
        """List files in a directory."""
        resp = self.send_cmd("file_list", path)
        if resp and resp.get("ok"):
            entries = resp.get("entries", [])
            print(f"\n{c(Colors.BOLD, path)}:")
            print("-" * 60)
            for e in entries:
                icon = "📁" if e["is_dir"] else "📄"
                size = f"{e['size']:>10,} B" if not e["is_dir"] else "<DIR>"
                print(f"  {icon} {e['name']:<30s} {size}  {e['mode']}")
            print(f"\n  Total: {len(entries)} entries")
        else:
            print(c(Colors.RED, f"[!] {resp.get('error', 'unknown')}"))

    def interactive_mode(self):
        """Main interactive shell loop."""
        print()
        print(c(Colors.GREEN, "╔══════════════════════════════════════════════════════════════╗"))
        print(c(Colors.GREEN, "║  LARA4 REMOTE SHELL v2.0                                     ║"))
        print(c(Colors.GREEN, f"║  Connected to: {self.host}:{self.port:<25s} ║"))
        print(c(Colors.GREEN, f"║  Session:     {str(self.session_id)[:38]:38s} ║"))
        print(c(Colors.GREEN, "╠══════════════════════════════════════════════════════════════╣"))
        print(c(Colors.GREEN, "║  Commands:                                                   ║"))
        print(c(Colors.GREEN, "║    !sysinfo       Show device info                           ║"))
        print(c(Colors.GREEN, "║    !ls [path]     List directory                             ║"))
        print(c(Colors.GREEN, "║    !cd <path>     Change directory                           ║"))
        print(c(Colors.GREEN, "║    !cat <file>    Read file                                   ║"))
        print(c(Colors.GREEN, "║    !ps            List processes                             ║"))
        print(c(Colors.GREEN, "║    !env           Show environment                           ║"))
        print(c(Colors.GREEN, "║    !exit          Disconnect                                 ║"))
        print(c(Colors.GREEN, "║    <any shell>    Execute raw shell command                  ║"))
        print(c(Colors.GREEN, "╚══════════════════════════════════════════════════════════════╝"))
        print()

        while self.connected:
            try:
                prompt = c(Colors.GREEN, "lara") + c(Colors.DIM, "@") + c(Colors.CYAN, "remote") + c(Colors.RESET, " $ ")
                cmd = input(prompt).strip()

                if not cmd:
                    continue

                if cmd == "!exit":
                    break
                elif cmd == "!sysinfo":
                    self.sysinfo()
                elif cmd.startswith("!ls "):
                    self.file_list(cmd[4:].strip() or ".")
                elif cmd == "!ls":
                    self.file_list(".")
                elif cmd.startswith("!cd "):
                    path = cmd[4:].strip()
                    resp = self.send_cmd("cd", path)
                    if resp and resp.get("ok"):
                        print(c(Colors.GREEN, f"[+] CWD: {resp.get('cwd')}"))
                    else:
                        print(c(Colors.RED, f"[!] {resp.get('error', 'unknown')}"))
                elif cmd.startswith("!cat "):
                    path = cmd[5:].strip()
                    resp = self.send_cmd("file_read", path)
                    if resp and resp.get("ok"):
                        print(resp.get("content", ""))
                    else:
                        print(c(Colors.RED, f"[!] {resp.get('error', 'unknown')}"))
                elif cmd == "!ps":
                    self.shell("ps -eo pid,ppid,user,comm,args 2>/dev/null || ps -e")
                elif cmd == "!env":
                    resp = self.send_cmd("env")
                    if resp and resp.get("ok"):
                        for k, v in resp.get("env", {}).items():
                            print(f"  {k}={v}")
                else:
                    # Raw shell command
                    self.shell(cmd)

            except KeyboardInterrupt:
                print()
                continue
            except EOFError:
                break

        self.disconnect()
        print(c(Colors.YELLOW, "[*] Disconnected."))

# ── Main ──────────────────────────────────────────────────────────────
def main():
    if len(sys.argv) < 2:
        print(c(Colors.RED, "[!] Usage: python3 lara_client.py <device_ip> [port]"))
        print(c(Colors.DIM, "    Example: python3 lara_client.py 192.168.1.50"))
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT

    print(c(Colors.CYAN, f"[*] Connecting to {host}:{port}..."))

    client = LaraClient(host, port)
    if client.connect():
        print(c(Colors.GREEN, f"[+] Connected! Session: {client.session_id}"))
        client.interactive_mode()
    else:
        print(c(Colors.RED, "[!] Failed to connect. Make sure the bridge is running on the device."))
        print(c(Colors.DIM, "    On device: exec-bg python3 /tmp/lara_bridge.py"))
        sys.exit(1)

if __name__ == "__main__":
    main()
