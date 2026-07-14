# Session Death Fix - Technical Documentation

## Problem

After commit `6487f58` ("socket primitive hardening"), sessions that previously ran for 24+ hours started dying after ~10 minutes with:

```
remote getpid() returned: 34
destroying remote call session...
remote call session destroyed
(ds) KRW ERROR  stage: setsockopt  reason: setsockopt returned -1 (errno=22)
```

## Root Cause

1. **Permanent latch `g_socket_broken`:** First failure sets it to `true` with no recovery path
2. **Shell executes thousands of KRW ops:** Statistically one transient failure occurs within ~10 minutes
3. **Latch closes forever:** `ds_is_ready()` returns `false` permanently
4. **All privileges lost:** KRW session is effectively dead

Additional issues:
- `handlebg()` destroyed RemoteCall on background transition
- Mutex leak in `early_kread` (size>0x20 returned without unlock -> deadlock)
- Missing @try/@catch in public write functions

## Solution

### 1. Self-Healing g_socket_broken

```objc
// OLD: Permanent latch
static BOOL g_socket_broken = false;
// Set true on first failure -> never recovers

// NEW: Transient with fail streak
static _Atomic(bool)     g_socket_broken = false;
static _Atomic(uint64_t) g_fail_streak = 0;
static _Atomic(uint64_t) g_success_count = 0;

// On failure: streak++, socket_broken = true
// On success: streak--, if streak==0: socket_broken = false
```

### 2. Retry Logic

```objc
static bool set_target_kaddr(uint64_t kaddr) {
    for (int attempt = 0; attempt < 6; attempt++) {
        if (attempt > 0) usleep(1500 * attempt);
        if (setsockopt(...) == 0) return true;
    }
    return false;
}
```

### 3. Mutex Leak Fix

```objc
static void early_kread(...) {
    pthread_mutex_lock(&krwLock);
    if (size > EARLY_KRW_LENGTH) {
        pthread_mutex_unlock(&krwLock);  // WAS MISSING
        return;
    }
    // ... do work ...
    pthread_mutex_unlock(&krwLock);  // Always unlock
}
```

### 4. Cooldown

```objc
#define FAIL_COOLDOWN_US 250000  // 250ms

static bool _in_fail_cooldown(void) {
    uint64_t elapsed = _now_us() - g_last_fail_us;
    return elapsed < FAIL_COOLDOWN_US;
}

uint64_t ds_kread64(uint64_t addr) {
    if (_in_fail_cooldown()) return 0;  // Prevent storm
    // ... normal read ...
}
```

### 5. handlebg() Fix

```swift
private func handlebg() {
    // NEW: Default = keep session alive
    let destroyOnBackground = UserDefaults.standard.bool(
        forKey: "destroyRemoteCallOnBackground"
    )
    if !destroyOnBackground {
        return  // Keep session alive across background/foreground
    }
    // Old behavior only if explicitly enabled
    mgr.rcdestroy { ... }
}
```

## Result

- Transient failures no longer kill the session
- Sessions survive background transitions
- Cheap recovery via `ds_revive()` without full re-exploit
- Long-running shell sessions are stable again
