# Lara4 - iOS Jailbreak Tool (Hardened Build)

Comprehensive hardening of the Lara jailbreak tool with session stability fixes, self-healing KRW primitives, and production-ready CI/CD.

## Critical Fixes Applied

### 1. Self-Healing g_socket_broken (Session Death Fix)
- **Problem:** `g_socket_broken` was a permanent latch - first transient failure killed the session forever
- **Fix:** Transient state with fail streak counter. Success decrements streak; session self-heals when streak reaches 0
- **Result:** Single transient failure no longer kills the session

### 2. Mutex Leak Fixes
- **Problem:** Multiple return paths in `early_kread` and `early_kwrite32bytes` skipped `pthread_mutex_unlock`
- **Fix:** All return paths (success, failure, exception) now properly unlock the mutex
- **Result:** No more deadlock from mutex leaks

### 3. Retry Logic in set_target_kaddr
- **Problem:** Single setsockopt failure killed the KRW primitive
- **Fix:** 6 retry attempts with 1.5ms exponential backoff
- **Result:** Transient failures are automatically retried

### 4. Cooldown After Failure
- **Problem:** Tight loops calling KRW after failure caused exception storms
- **Fix:** 250ms cooldown period after failure before KRW operations resume
- **Result:** Graceful degradation instead of crash loops

### 5. ds_is_ready() - Live Check
- **Problem:** `ds_socket_broken()` was a latch that stayed true forever
- **Fix:** `ds_is_ready()` performs live fd validation + corruption health check
- **Result:** Accurate session state without false negatives

### 6. ds_revive() - Cheap Recovery
- **Problem:** Session death required full re-exploit (slow and unreliable)
- **Fix:** `ds_revive()` attempts cheap recovery without re-running the exploit
- **Result:** Fast session recovery when fd is still alive

### 7. handlebg() Fix
- **Problem:** Background transition destroyed RemoteCall, killing long sessions
- **Fix:** Default behavior keeps RemoteCall alive; optional `destroyRemoteCallOnBackground` setting
- **Result:** Sessions survive background/foreground transitions

### 8. Timer Lifecycle
- **Problem:** Health check timer continued in background, causing crashes
- **Fix:** Timer started/stopped based on app state and dsready
- **Result:** Clean timer lifecycle with no background crashes

### 9. Bounds Checking
- **Problem:** `control_socket_idx + 1` accessed without array bounds check
- **Fix:** All array accesses validated against `socket_ports_count`
- **Result:** No buffer overruns

### 10. @try/@catch Wrappers
- **Problem:** Public KRW functions could throw exceptions without handling
- **Fix:** All public KRW functions wrapped in @try/@catch
- **Result:** Exceptions caught and handled gracefully

## Architecture

```
lara/
  kexploit/
    darksword.h          - KRW API header
    darksword.m          - UAF exploit + hardened KRW primitives
  classes/
    laramgr.swift        - Main manager (exploit, VFS, sandbox, RemoteCall)
    MemorySafetyManager.swift - Kernel address validation + operation tracking
    ProcessLayer.swift   - Process listing with quality tiers
    OmegaBootstrap.swift - Shell command processor
  views/
    app/                 - SwiftUI app views
    tweaks/              - Tweak management views
  funcs/                 - Helper functions
  lib/                   - Static libraries
  lara.swift             - App entry point
  lara-Bridging-Header.h - ObjC bridging
  Info.plist

Config/
  lara.entitlements      - Full jailbreak entitlements

.github/workflows/
  build.yml              - GitHub Actions CI/CD

codemagic.yaml           - Codemagic CI/CD
ipabuild.sh              - IPA build script
```

## Build Requirements

- macOS with Xcode (latest stable)
- ldid (`brew install ldid`)
- iOS 16.0 - 18.7.1 or 26.0 - 26.0.1 (supported versions)

## Building IPA

```bash
./ipabuild.sh           # Release build
./ipabuild.sh --debug   # Debug build
```

## CI/CD

### GitHub Actions
Automatically builds and releases IPA on every push to `main`. The nightly release is updated with the latest build.

### Codemagic
Alternative CI/CD via `codemagic.yaml` for mac_mini_m2 builds.

## Session Health

The app includes a health check timer that runs every 30 seconds:
- Health score 0-100 based on success/failure ratio
- Auto-revive attempts when health drops below 50
- Manual revive via "Revive KRW Session" button in UI

## Credits

Original Lara tool by ruter. Hardening and session stability fixes by the Lara4 team.
