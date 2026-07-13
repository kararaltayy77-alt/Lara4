# LARA — Complete Terminal Command Reference
### Target: iOS 18.3.1 · A12 (T8020) arm64e/PAC · iPhone11,2 (XS Max)
### Last updated: 2026-07-12

---

## HOW THE SHELL WORKS

```
Input → OmegaRouter → HotPluginManager (plugins, checked first)
                    → OmegaCore.execute() → registered handler
```

- All commands are **case-insensitive** (`PSX` = `psx`)
- Maximum input length: **8192 characters**
- Each command runs in its own thread with a **30-second timeout**
- Pipe syntax: `command1 | command2` (stdin routed via `OmegaCore.pipeBuffer`)
- `dsready` = kernel r/w ready; `vfsready` = VFS patched; `sbxready` = sandbox escaped

---

## QUICK-START SEQUENCE

```
status              # Check exploit / VFS / sandbox state
run                 # Trigger kernel exploit (DarkSword)
jb-status           # Full exploit status dump
vfs                 # Mount VFS patches (needs dsready)
sbx                 # Escape sandbox (needs dsready)
set-all-ids-zero    # uid/gid → 0 (needs dsready)
amfi-disable-globally       # Disable AMFI enforcement (needs dsready)
cs-remove-all-restrictions  # Strip CS flags (needs dsready)
monitor-root-status         # Confirm root achieved
```

---

## §1  SHELL CORE (built-ins, always available)

| Command | Usage | Description |
|---------|-------|-------------|
| `help` | `help` | Print command list |
| `help-priv` | `help-priv` | Privilege escalation commands |
| `help-ppl` | `help-ppl` | PAC/KTRR/SMR/PPL commands |
| `help-kernel` | `help-kernel` | Kernel inspection commands |
| `clear` | `clear` | Clear terminal (sends `__CLEAR__` sentinel) |
| `echo` | `echo <text>` | Print text |
| `history` | `history` | Show command history |
| `reset-history` | `reset-history` | Clear command history |
| `date` | `date` | Current date/time |
| `uname` | `uname` | Kernel version string |
| `hostname` | `hostname` | Device hostname |
| `env` | `env` | Dump environment variables |
| `whoami` | `whoami` | Current username |
| `uid` | `uid` | Print uid/euid/gid/egid |
| `bundle-id` | `bundle-id` | LARA bundle identifier |
| `boot-args` | `boot-args` | Read kern.bootargs via sysctl |
| `status` | `status` | ds/vfs/sbx/rc/offsets ready flags |
| `jb-status` | `jb-status` | Full DarkSword exploit status dump |
| `logs` | `logs` | Show DarkSword log buffer |
| `clear-logs` | `clear-logs` | Clear DarkSword log buffer |
| `cmdlog` | `cmdlog [N]` | Last N command audit entries (default 50) |
| `cmdlog-clear` | `cmdlog-clear` | Clear command audit log |

---

## §2  FILESYSTEM (OmegaFS)

| Command | Usage | Description |
|---------|-------|-------------|
| `ls` | `ls [-a] [-l] [path]` | List directory; `-a` shows hidden, `-l` long format with real permissions |
| `pwd` | `pwd` | Print working directory |
| `cd` | `cd [path]` | Change directory (`~` = home) |
| `cat` | `cat <file>` | Print file contents (UTF-8) |
| `head` | `head [-n N] <file>` | First N lines (default 10) |
| `tail` | `tail [-n N] <file>` | Last N lines (default 10) |
| `stat` | `stat <path>` | File metadata (size, perms, dates) |
| `file` | `file <path>` | Detect file type (magic bytes) |
| `find` | `find <dir> [name_pattern]` | Recursive file search |
| `du` | `du [-h] <path>` | Disk usage |
| `touch` | `touch <file>` | Create file or update mtime |
| `mkdir` | `mkdir <dir>` | Create directory |
| `rm` | `rm [-r] <path>` | Remove file or directory |
| `cp` | `cp <src> <dst>` | Copy file |
| `mv` | `mv <src> <dst>` | Move / rename |
| `chmod` | `chmod <octal> <path>` | Change permissions |
| `chown` | `chown <uid>[:<gid>] <path>` | Change owner (needs dsready) |
| `ln` | `ln [-s] <src> <dst>` | Create hard or symbolic link |
| `readlink` | `readlink <path>` | Resolve symlink |
| `write` | `write <file> <content>` | Write string to file |

---

## §3  VFS COMMANDS (require `vfsready`)

VFS commands bypass sandbox and iOS file restrictions via kernel VFS patching.

| Command | Usage | Description |
|---------|-------|-------------|
| `vls` | `vls <path>` | VFS-patched directory listing |
| `vcat` | `vcat <path>` | VFS-patched file read |
| `vsize` | `vsize <path>` | VFS-patched file size |
| `vstat` | `vstat <path>` | VFS-patched stat |
| `vhex` | `vhex <path> [offset] [len]` | Hexdump file via VFS |
| `vwrite` | `vwrite <path> <content>` | VFS-patched file write |
| `voverwrite` | `voverwrite <path> <hex_bytes>` | Overwrite raw bytes at offset |
| `vzero` | `vzero <path> <offset> <len>` | Zero-fill bytes in file |
| `vcopy` | `vcopy <src> <dst>` | VFS-patched copy |

---

## §4  PROCESS INSPECTION

### Basic (no exploit required)

| Command | Usage | Description |
|---------|-------|-------------|
| `ps` | `ps [filter]` | BSD process list via `/proc` |
| `psx` | `psx [filter]` | Enhanced process list (ProcessLayer) with PID/PPID/UID/STATUS/NAME |
| `proc-find` | `proc-find <name>` | Search processes by name substring |
| `proc-info` | `proc-info <pid\|name>` | Deep process inspection (ucred, task ptr, cs_flags, quality) |
| `proc-walk` | `proc-walk` | Walk all PIDs via ProcessLayer |
| `taskinfo` | `taskinfo <pid\|name>` | VM size, resident mem, thread count, CPU time |
| `threadinfo` | `threadinfo <pid\|name>` | Per-thread state, priority, CPU time (up to 64 threads) |
| `ports` | `ports <pid\|name>` | Mach port stats + FD list |
| `portinfo` | `portinfo <port_hex>` | Port info (limited without task_for_pid) |
| `vmmap` | `vmmap <pid\|name>` | Virtual memory map (START/END/SIZE/PROT/PATH) |
| `sandbox` | `sandbox <pid\|name>` | Sandbox token + UID/GID for process |
| `sandbox-check` | `sandbox-check <pid>` | Check sandbox enforcement state |

### Kernel-level (require `dsready`)

| Command | Usage | Description |
|---------|-------|-------------|
| `kernel-info` | `kernel-info` | iOS version, kbase, kslide, proc/task ptrs, ready flags |
| `kmap` | `kmap` | Kernel allproc walk (uses ProcessLayer, falls back to raw walk) |
| `proc-tree` | `proc-tree` | Allproc walk with kernel addresses (PID/UID/KADDR/NAME) |
| `kbase` | `kbase` | Print kernel base, slide, and static base |
| `kinfo` | `kinfo` | Kernel base + our proc/task addresses |
| `proc-cred` | `proc-cred <pid\|name>` | Read ucred fields from kernel |
| `proc-csflags` | `proc-csflags <pid\|name>` | Read CS flags via kernel walk |
| `proc-csflags-set` | `proc-csflags-set <pid> <flags_hex>` | Write CS flags via kernel |
| `proc-entitlements` | `proc-entitlements <pid\|name>` | Dump process entitlement blob |
| `proc-inspect` | `proc-inspect <pid\|name>` | Full kernel proc struct dump |
| `proc-link` | `proc-link <pid>` | Show allproc linked-list pointers |
| `proc-access` | `proc-access <pid\|name>` | Check access level to a process |
| `proc-mem-info` | `proc-mem-info <pid\|name>` | Kernel-side memory stats |
| `proc-open-files` | `proc-open-files <pid\|name>` | Open file descriptors |
| `proc-find-relation` | `proc-find-relation <pid1> <pid2>` | Parent/child relationship check |
| `proc-monitor` | `proc-monitor <pid\|name>` | Periodic status poll |
| `proc-trace` | `proc-trace <pid\|name>` | Kernel-level trace attach |
| `pivot-status` | `pivot-status` | Current privilege elevation summary |
| `kern-regions` | `kern-regions` | Interesting kernel memory regions |
| `thread-list` | `thread-list <pid>` | Thread list with kernel state |
| `kaddr-info` | `kaddr-info <addr_hex>` | Classify address (ktext/kdata/heap/user) |
| `kheap-search` | `kheap-search <4char_tag>` | Search kalloc zones by tag |
| `smr-read` | `smr-read <addr_hex>` | Read SMR (hazard-pointer) protected 64-bit pointer |

---

## §5  PROCESS CONTROL

| Command | Usage | Description |
|---------|-------|-------------|
| `suspend` | `suspend <pid\|name>` | Send SIGSTOP |
| `resume` | `resume <pid\|name>` | Send SIGCONT |
| `kill` | `kill <pid\|name> [signal]` | Send signal (default SIGKILL=9) |
| `proc-kill` | `proc-kill <pid>` | SIGKILL by numeric PID (refuses pid ≤ 1) |
| `proc-suspend` | `proc-suspend <pid>` | SIGSTOP by numeric PID |
| `proc-resume` | `proc-resume <pid>` | SIGCONT by numeric PID |
| `proc-signal` | `proc-signal <pid> <sig>` | Send named or numeric signal. Known names: HUP INT QUIT ILL TRAP ABRT KILL BUS SEGV SYS PIPE ALRM TERM STOP TSTP CONT |
| `spawn` | `spawn <path> [args...]` | posix_spawn a binary |
| `exec` | `exec <path> [args...]` | Execute binary synchronously |
| `exec-bg` | `exec-bg <path> [args...]` | Execute binary in background |
| `inject` | `inject <pid\|name> <dylib>` | Dylib injection stub (opens rc session) |
| `app-kill` | `app-kill <bundle_id\|name>` | Kill app by bundle ID |
| `app-pid` | `app-pid <bundle_id>` | Get PID for an app |
| `respring` | `respring` | Respring SpringBoard |

---

## §6  KERNEL MEMORY READ/WRITE (require `dsready`)

All addresses are in kernel virtual address space. Use hex (`0x...`).

| Command | Usage | Description |
|---------|-------|-------------|
| `kread` | `kread <addr_hex>` | Read 64-bit kernel word |
| `kread32` | `kread32 <addr_hex>` | Read 32-bit kernel word |
| `kwrite` | `kwrite <addr_hex> <val_hex>` | Write 64-bit kernel word |
| `kwrite32` | `kwrite32 <addr_hex> <val_hex>` | Write 32-bit kernel word |
| `kwrite_safe` | `kwrite_safe <addr_hex> <val_hex>` | Write with PPL-zone check |
| `kread_range` | `kread_range <addr_hex> <len>` | Read N bytes from kernel |
| `kcstr` | `kcstr <addr_hex>` | Read null-terminated C string from kernel |
| `kbytes` | `kbytes <addr_hex> <len>` | Hexdump N bytes from kernel |
| `kverify` | `kverify <addr_hex> <expected_hex>` | Read and compare (assert) |
| `kfind_ptr` | `kfind_ptr <start_hex> <val_hex> [range]` | Scan kernel for pointer value |
| `kscan_zero` | `kscan_zero <start_hex> <len>` | Scan for zero 64-bit words |
| `find_pattern` | `find_pattern <start_hex> <hex_pattern>` | Scan for byte pattern |
| `memread` | `memread <addr_hex> <size>` | Hexdump (max 4096 bytes) with ASCII column |
| `memwrite` | `memwrite <addr_hex> <val_hex>` | Write 64-bit word + verify read-back |

---

## §7  TRACE & PTRACE

| Command | Usage | Description |
|---------|-------|-------------|
| `trace start` | `trace start <pid\|name>` | Attach via PT_ATTACHEXC (ptrace) |
| `trace stop` | `trace stop` | Detach (PT_DETACH) |
| `trace dump` | `trace dump` | Show captured trace events |
| `proc-trace` | `proc-trace <pid\|name>` | Kernel-level trace |

---

## §8  LOG MANAGEMENT

| Command | Usage | Description |
|---------|-------|-------------|
| `log filter` | `log filter <keyword>` | Filter LARA log buffer by keyword (up to 200 results) |
| `log clear` | `log clear` | Clear LARA log buffer |
| `logs` | `logs` | Print full DarkSword log buffer |
| `clear-logs` | `clear-logs` | Clear DarkSword log buffer |
| `cmdlog` | `cmdlog [N]` | Last N shell command history with status + duration |
| `cmdlog-clear` | `cmdlog-clear` | Clear command audit log |

---

## §9  SANDBOX COMMANDS

### Basic (no exploit required)

| Command | Usage | Description |
|---------|-------|-------------|
| `sbx-info` | `sbx-info` | Our sandbox token + uid + bundle ID |
| `sbx-token` | `sbx-token <pid>` | Kernel address of sandbox token for PID |
| `sbx-token-str` | `sbx-token-str <pid>` | Sandbox token string for PID |
| `sbx-issue` | `sbx-issue <class> <path>` | Issue sandbox extension token. Example: `sbx-issue com.apple.security.application-groups /private/var` |
| `sbx` | `sbx` | Trigger sandbox escape (requires dsready) |
| `sbx-elevate` | `sbx-elevate` | Elevate sandbox permissions (requires sbxready) |

### Advanced (require `dsready`)

| Command | Usage | Description |
|---------|-------|-------------|
| `sandbox-rules-dump` | `sandbox-rules-dump <pid\|name>` | Dump sandbox policy text |
| `sandbox-token-elevate` | `sandbox-token-elevate [path]` | Issue root sandbox extension (default `/`) |
| `sandbox-complete-escape` | `sandbox-complete-escape` | Full sbx_escape + ucred chain |
| `sandbox-allow-all-paths` | `sandbox-allow-all-paths` | Inject read-write root extension for all paths |
| `app-sandbox-escape` | `app-sandbox-escape <bundle_id>` | Escape sandbox for a specific app |

---

## §10  APP MANAGEMENT

| Command | Usage | Description |
|---------|-------|-------------|
| `apps` | `apps [filter]` | List installed apps (bundle ID + name + version) |
| `app-info` | `app-info <bundle_id\|name>` | App metadata (bundle, container, data dir) |
| `app-data` | `app-data <bundle_id>` | App data container path |
| `app-bundle` | `app-bundle <bundle_id>` | App bundle path |
| `app-prefs` | `app-prefs <bundle_id>` | App plist preferences |
| `app-env` | `app-env <bundle_id>` | App environment variables |
| `app-entitlements` | `app-entitlements <bundle_id>` | App entitlement plist (from binary) |
| `app-version` | `app-version <bundle_id>` | App version string |
| `app-list-files` | `app-list-files <bundle_id>` | Files in app bundle |
| `app-container` | `app-container <bundle_id>` | Full container paths |
| `app-csflags` | `app-csflags <bundle_id>` | CS flags for running app |
| `app-csflags-set` | `app-csflags-set <bundle_id> <flags_hex>` | Patch CS flags for running app |

---

## §11  PLIST TOOLS

| Command | Usage | Description |
|---------|-------|-------------|
| `plist` | `plist <path>` | Print plist as text |
| `plist-get` | `plist-get <path> <key>` | Read a single key |
| `plist-set` | `plist-set <path> <key> <value>` | Write a key |
| `plist-del` | `plist-del <path> <key>` | Delete a key |
| `plist-keys` | `plist-keys <path>` | List all keys |
| `defaults` | `defaults domains` | List preference domains |
| `defaults` | `defaults read <domain> [key]` | Read preference(s) |
| `defaults` | `defaults write <domain> <key> <val>` | Write preference |
| `defaults` | `defaults delete <domain> <key>` | Delete preference key |

---

## §12  SYSCTL & DEVICE INFO

| Command | Usage | Description |
|---------|-------|-------------|
| `sysctl` | `sysctl <name>` | Read a sysctl value |
| `sysctl-all` | `sysctl-all` | Dump all readable sysctls |
| `sysctl-get` | `sysctl-get <name>` | Alias for `sysctl` |
| `sysctl-list` | `sysctl-list` | Alias for `sysctl-all` |
| `device-info` | `device-info` | Hardware model, ECID, serial, chip info |
| `disk-info` | `disk-info` | Storage capacity + free space |
| `memory-info` | `memory-info` | RAM size + pressure |
| `mg-info` | `mg-info` | MobileGestalt plist path |
| `mg-get` | `mg-get <key>` | Read MobileGestalt key |
| `mg-set` | `mg-set <key> <value>` | Write MobileGestalt key |
| `mg-keys` | `mg-keys` | List all MobileGestalt keys |
| `notif` | `notif <name>` | Post Darwin notification |
| `launchctl` | `launchctl <args>` | Run launchctl command |

---

## §13  UTILITY TOOLS

| Command | Usage | Description |
|---------|-------|-------------|
| `hexdump` | `hexdump <file>` | Hex + ASCII dump of file |
| `grep` | `grep <pattern> <file>` | Search pattern in file |
| `strings` | `strings <file>` | Extract printable strings (min 4 chars) |
| `b64` | `b64 <string>` | Base64 encode |
| `b64d` | `b64d <string>` | Base64 decode |
| `sha256` | `sha256 <file\|string>` | SHA-256 hash |
| `wc` | `wc <file>` | Word / line / byte count |
| `sort` | `sort [file]` | Sort lines (or pipe stdin) |
| `uniq` | `uniq [file]` | Remove duplicate lines |
| `entitlements` | `entitlements` | Dump LARA's own entitlements |
| `proc-entitlements` | `proc-entitlements <pid\|name>` | Dump process entitlements |

---

## §14  PRIVILEGE ESCALATION (require `dsready`)

> **WARNING:** All commands in this section write directly to kernel memory.
> Run `status` first. Never run `setuid(0)` after ucred patch on A12+.

### 14.1  Credential Patch (ucred)

iOS 18.3.1 ucred layout: cr_uid=+0x18, cr_ruid=+0x1C, cr_svuid=+0x20, cr_rgid=+0x68, cr_svgid=+0x6C, cr_gmuid=+0x24, cr_label=+0x78 (runtime), cr_label=+0x98 (tools_creds.m UC_CR_LABEL). Zone size: 0x90 bytes.

| Command | Usage | Description |
|---------|-------|-------------|
| `set-uid-zero` | `set-uid-zero` | Patch cr_uid + cr_ruid + cr_svuid → 0 |
| `set-gid-zero` | `set-gid-zero` | Patch cr_rgid + cr_svgid → 0 |
| `set-euid-zero` | `set-euid-zero` | Patch effective UID (cr_uid) → 0 |
| `set-egid-zero` | `set-egid-zero` | Patch cr_gmuid → 0 |
| `set-all-ids-zero` | `set-all-ids-zero` | All UID/GID fields → 0 atomically **(use this)** |
| `ucred-reader` | `ucred-reader [pid\|name]` | Full ucred struct dump with field names |
| `ucred-writer` | `ucred-writer <pid\|name> <offset_hex> <val_hex>` | Write 32-bit field at ucred+offset |
| `ucred-clone` | `ucred-clone <src_pid\|name> <dst_pid\|name>` | Copy credentials src→dst |
| `inject-uid-to-process` | `inject-uid-to-process <pid\|name> <uid>` | Set specific UID in target process |
| `inject-root` | `inject-root <pid\|name>` | Patch ucred uid/gid → 0 in another process |
| `copy-root-credentials` | `copy-root-credentials <src> <dst>` | Clone ucred src→dst |
| `grant-root-to-process` | `grant-root-to-process <pid\|name>` | Full ucred + CS root grant |
| `find-root-process` | `find-root-process` | Find uid=0 proc with writable ucred |
| `escalate-all-processes` | `escalate-all-processes` | Elevate trusted jailbreak daemons |
| `proc-uid-inspector` | `proc-uid-inspector [pid\|name]` | Read uid/gid/cred from kernel |
| `elevate` | `elevate` | Quick self-elevation alias |

### 14.2  Code Signing (CS flags)

| Command | Usage | Description |
|---------|-------|-------------|
| `cs-flags-dump` | `cs-flags-dump [pid\|name]` | Decode CS flags with bit names |
| `cs-flags-modify` | `cs-flags-modify <pid\|name> <set_mask> [clr_mask]` | OR/AND mask on CS flags |
| `cs-flags` | `cs-flags <pid\|name>` | Raw CS flags read |
| `cs-grant` | `cs-grant <pid\|name>` | Set CS_PLATFORM_BINARY \| CS_DEBUGGED \| CS_UNRESTRICTED |
| `cs-disable-amfi` | `cs-disable-amfi` | Disable AMFI mac_proc_enforce (kernel patch) |
| `cs-disable-library-validation` | `cs-disable-library-validation` | Clear CS_REQUIRE_LV |
| `cs-enable-get-task-allow` | `cs-enable-get-task-allow` | Set CS_GET_TASK_ALLOW |
| `cs-set-debuggable` | `cs-set-debuggable` | Set CS_DEBUGGED |
| `cs-remove-all-restrictions` | `cs-remove-all-restrictions` | Strip CS_RESTRICT + CS_ENFORCEMENT + CS_KILL |

### 14.3  AMFI & Entitlements

| Command | Usage | Description |
|---------|-------|-------------|
| `amfi-disable-globally` | `amfi-disable-globally` | Kernel-patch mac_proc_enforce = 0 |
| `amfi-bypass-signature-check` | `amfi-bypass-signature-check <pid\|name>` | Patch AMFI label for process |
| `amfi-whitelist-app` | `amfi-whitelist-app <bundle_id> [pid]` | Add to kernel trust cache |
| `amfi-status-check` | `amfi-status-check` | Full AMFI state report |
| `amfi-status` | `amfi-status` | AMFI enforcement state (compact) |
| `entitlement-reader` | `entitlement-reader [pid\|name]` | Dump entitlement flags |
| `entitlement-grant-all` | `entitlement-grant-all [pid]` | Set maximum CS flags (default = self) |

### 14.4  Security Labels

| Command | Usage | Description |
|---------|-------|-------------|
| `security-label-read` | `security-label-read <pid\|name>` | All MAC label slots |
| `security-context-elevate` | `security-context-elevate [pid]` | Set sandbox label → NULL |
| `security-policy-bypass` | `security-policy-bypass [pid]` | mac_proc_enforce + label bypass |

### 14.5  System Files (require `vfsready`)

| Command | Usage | Description |
|---------|-------|-------------|
| `system-file-read` | `system-file-read <path>` | Read protected file (shows hex if binary) |
| `system-file-write` | `system-file-write <path> <content>` | Write protected file |
| `system-binary-patch` | `system-binary-patch <path> <offset_hex> <hex_bytes>` | Patch raw bytes in binary |

### 14.6  Services & MDM

| Command | Usage | Description |
|---------|-------|-------------|
| `kill-security-processes` | `kill-security-processes` | Stop MDM/supervision daemons |
| `system-daemon-control` | `system-daemon-control <launchctl_args>` | Run launchctl with root |
| `device-management-bypass` | `device-management-bypass` | Disable MDM supervision flags |

### 14.7  Persistence & Monitoring

| Command | Usage | Description |
|---------|-------|-------------|
| `persistence-check` | `persistence-check` | Print uid / ds / vfs / sbx state |
| `process-hide` | `process-hide <pid\|name>` | Rename proc comm string (evades ps) |
| `file-hide` | `file-hide <path>` | Set UF_HIDDEN attribute |
| `audit-log-clean` | `audit-log-clean` | Session cleanup via kernel patches |
| `monitor-root-status` | `monitor-root-status` | Live privilege snapshot (uid + AMFI + vfs + sbx) |
| `detect-revocation` | `detect-revocation` | Check if root privileges were revoked |
| `execute-as-root` | `execute-as-root <cmd>` | posix_spawn cmd via `/bin/sh -c` (needs uid=0) |

---

## §15  PAC / KTRR / SMR / PPL ANALYSIS (require `dsready`)

### 15.1  PAC — Pointer Authentication

| Command | Usage | Description |
|---------|-------|-------------|
| `pac-reader` | `pac-reader <va_hex>` | Decode PAC-signed kernel pointer |
| `pac-signature-extractor` | `pac-signature-extractor <ptr_hex>` | Extract PAC tag from raw pointer |
| `pac-key-scanner` | `pac-key-scanner [start_hex] [end_hex]` | Scan kernel range for PAC-signed ptrs |
| `pac-context-analyzer` | `pac-context-analyzer <ptr_hex>` | PACDA vs PACIA analysis |
| `pac-entropy-checker` | `pac-entropy-checker <va_hex> [n]` | Measure PAC signature entropy |
| `pac-algorithm-fingerprint` | `pac-algorithm-fingerprint` | Identify PAC algorithm (QARMA) |
| `pac-strength-analyzer` | `pac-strength-analyzer` | Overall PAC protection strength score |
| `pac-coverage-mapper` | `pac-coverage-mapper` | PAC coverage map of known kernel structs |
| `pac-weak-key-detector` | `pac-weak-key-detector <va_hex> [n] [threshold]` | Check for duplicate/weak PAC tags |
| `pac-null-pointer-checker` | `pac-null-pointer-checker <va_hex>` | Find null-PAC (PACIZA) pointers |
| `pac-bypass-validator` | `pac-bypass-validator` | Confirm current PAC bypass is correct |

### 15.2  KTRR — Kernel Text Region Read-Only

| Command | Usage | Description |
|---------|-------|-------------|
| `ktrr-region-mapper` | `ktrr-region-mapper` | All KTRR-protected regions + PTE entries |
| `ktrr-boundary-finder` | `ktrr-boundary-finder` | Exact KTRR start/end virtual address |
| `ktrr-permission-checker` | `ktrr-permission-checker <addr_hex>` | AP bits + protection for address |
| `ktrr-enforcement-detector` | `ktrr-enforcement-detector` | Is KTRR hardware-enforced? |
| `ktrr-bypass-paths-finder` | `ktrr-bypass-paths-finder` | RW windows via physmap |

### 15.3  SMR — Secure Memory Region

| Command | Usage | Description |
|---------|-------|-------------|
| `smr-region-scanner` | `smr-region-scanner` | Scan allproc for SMR pointers |
| `smr-metadata-reader` | `smr-metadata-reader <ptr_hex>` | Decode SMR pointer + epoch |
| `smr-protection-level-analyzer` | `smr-protection-level-analyzer` | Epoch size + rotation policy |
| `smr-isolation-tester` | `smr-isolation-tester <ptr_hex>` | SMR boundary reachability test |

### 15.4  PPL — Page Protection Layer

| Command | Usage | Description |
|---------|-------|-------------|
| `ppl-status` | `ppl-status` | Full PPL + privilege snapshot (uid/bypass/physmap/ucred/AMFI) |
| `ppl-phase-report` | `ppl-phase-report` | OmegaPhysmap P1/P2/P3 results |
| `ppl-write-bypass` | `ppl-write-bypass <addr_hex> <u32_val_hex>` | Attempt physmap write at address |
| `ppl-signature-forge` | `ppl-signature-forge` | PAC forgery test |
| `ppl-protected-variable-read` | `ppl-protected-variable-read <addr_hex>` | Read addr + PPL zone check + read64/32/smr |
| `ppl-bypass-strategy-planner` | `ppl-bypass-strategy-planner` | Auto-recommend bypass strategy based on current state |
| `ppl-fuzzer` | `ppl-fuzzer <start_hex> [probe_len]` | Probe range for writable windows (default 128 probes) |
| `ppl-version-comparison` | `ppl-version-comparison` | PPL implementation history across iOS versions |
| `auto-ppl-breaker` | `auto-ppl-breaker` | Run best PPL bypass automatically |
| `comprehensive-ppl-tester` | `comprehensive-ppl-tester` | Full 7-check PPL test battery |

---

## §16  EXPLOIT CONTROL

| Command | Usage | Description |
|---------|-------|-------------|
| `run` | `run` | Trigger DarkSword kernel exploit |
| `vfs` | `vfs` | Initialize VFS patches (needs dsready) |
| `sbx` | `sbx` | Trigger sandbox escape (needs dsready) |
| `rc` | `rc` | Init RemoteCall on SpringBoard (needs dsready) |

---

## §17  ALIASES

| Alias | Resolves to |
|-------|-------------|
| `entitlements` | `proc-entitlements` (our own process) |
| `sysctl-get <name>` | `sysctl <name>` |
| `sysctl-list` | `sysctl-all` |

---

## §18  COMMAND NOTES & SAFETY RULES

### A12/PAC pointer rules (critical for stability)
```
Data pointers (ucred, proc_ro, cr_label, amfi_slot) → strip with XPACD (kptr_strip_data)
Code pointers (function ptrs)                        → strip with XPACI (kptr_strip_code)
Always validate with kptr_is_valid_kernel() before dereferencing
Always check 8-byte alignment before writing
```

### Do NOT do these on A12+
```
setuid(0) after ucred patch     — kernel will panic
setsockopt() writes to PPL zone — use ds_kwritezoneelement()
Write to cr_label without XPACD strip — kernel panic
```

### Typical full-chain sequence
```
run                             # 1. Exploit
jb-status                       # 2. Confirm dsready
vfs                             # 3. VFS patches
sbx                             # 4. Sandbox escape
set-all-ids-zero                # 5. uid=0
amfi-disable-globally           # 6. AMFI off
cs-remove-all-restrictions      # 7. Strip CS
sandbox-complete-escape         # 8. Full sbx chain
monitor-root-status             # 9. Verify
```

### Timeout
Every command kills itself after **30 seconds**. Long scans (`ppl-fuzzer`, `pac-key-scanner`) may need smaller ranges.

---

*Generated from source: OmegaBootstrap, OmegaCore, OmegaExtendedA–G, OmegaFS, OmegaRouter*
