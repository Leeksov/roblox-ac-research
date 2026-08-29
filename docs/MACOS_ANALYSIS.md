# macOS RobloxPlayer — Anti-Tamper & AC Module Analysis

Analysis of the macOS arm64 RobloxPlayer binary. Key difference from iOS: **macOS has a
real AC telemetry module** that scans loaded dylibs and checks SIP status.

---

## Binary Overview

| Field | Value |
|-------|-------|
| Binary | RobloxPlayer (arm64, Apple Silicon) |
| Size | ~124 MB |
| Functions | 667,990 total (39,379 named) |
| SHA256 | `7383c15ad300950dd5309dcc432651cb9ee01284eeb34bb515a6cb2f119f473e` |

---

## 1. Native AC Module (macOS-only, absent on iOS)

A self-contained AC telemetry module at `0x10525BA44`–`0x10525DE34`, launched in a
background thread from a vtable callback.

### Call chain

```
vtable @ 0x10702ADD8
  → sub_10525DE34 (entry, 132B) — weak_ptr lock, spawn thread
    → sub_10525C090 (thread launcher, 100B) — std::thread
      → sub_10525C0FC (orchestrator, 3812B, complexity 59)
        ├─ sub_10525BA44 (dylib scanner, 424B) — _dyld_image_count + _dyld_get_image_name
        ├─ sub_10525BC28 (obfuscated dlopen, 788B) — decrypts lib+symbol, calls function
        └─ sub_102C98440 / sub_102C978D4 (telemetry senders)
```

### Dylib scanner — `sub_10525BA44` (424 bytes)

Enumerates all loaded images and collects `.dylib` paths:

```c
count = _dyld_image_count();
for (i = 0; i < count; i++) {
    if (atomic_load(cancel_flag) & 1) return;  // abort check
    name = _dyld_get_image_name(i);
    lowercase(name);
    if (ends_with(name, ".dylib"))
        vector_push(results, name);
}
```

Reports ALL loaded dylibs (not just app-bundle ones, unlike iOS Reaper which
filters by `hasPrefix:appPath`). This means **injected dylibs will appear in
the telemetry report**.

### Obfuscated dlopen — `sub_10525BC28` (788 bytes)

Decrypts library name and symbol name at runtime, then calls the resolved function:

```c
// Encrypted data on stack (bit-rotation + XOR)
encrypted_lib[25] = { 0x66, 0x52, 0x79, ... };  // 25 bytes
encrypted_sym[22] = { 0xD9, 0xB1, 0x23, ... };  // 22 bytes

// Decrypt lib name: rotate right by ((i&3)+3), XOR 0xFB
for (i = 0; i < 25; i++)
    lib[i] = (rotate_right(encrypted_lib[i], (i&3)+3)) ^ 0xFB;
// Result: "/usr/lib/libSystem.dylib"

// Decrypt symbol: rotate right by (((i+1)&3)+3), XOR 0xFE
for (i = 0; i < 22; i++)
    sym[i] = (rotate_right(encrypted_sym[i], ((i+1)&3)+3)) ^ 0xFE;
// Result: "csr_get_active_config"

// Call
handle = dlopen(lib, RTLD_NOW | RTLD_NOLOAD);  // mode = 17
func = dlsym(handle, sym);
result = func(&output);
dlclose(handle);
```

**`csr_get_active_config`** returns the System Integrity Protection (SIP) bitmask.
If SIP is disabled (bit 0 set), the system allows unsigned code injection, kernel
extensions, and other modifications. This is a strong signal of a compromised system.

### Orchestrator — `sub_10525C0FC` (3812 bytes)

Builds a JSON-like telemetry payload with **8 obfuscated field names**. Each field
name is constructed on the stack using per-byte bit-rotation + XOR, with different
rotation formulas and XOR constants per field (to prevent batch string scanning).

#### Decrypted field names

| # | Length | XOR | Decrypted name | Purpose |
|---|--------|-----|---------------|---------|
| 1 | 14 | 0xFD | `PlaySessionId` | Current play session identifier |
| 2 | 12 | 0xFD | `LastPlaceId` | Last visited place ID |
| 3 | 11 | 0xFB | *(complex rotation)* | — |
| 4 | 15 | 0xFD | *(complex rotation)* | — |
| 5 | 16 | 0xFB | *(complex rotation)* | — |
| 6 | 16 | 0xFB | *(complex rotation)* | — |
| 7 | 9 | 0xFB | `MacQAPad` | macOS QA padding/identifier |
| 8 | 12 | 0xFB | `MacQAConfig` | macOS QA configuration flags |

Fields 3–6 use more complex rotation formulas that resist simple brute-force
(the rotation shift depends on `(i&3)` through nested EOR/ADD/SUB operations
with varying constants per field).

#### Telemetry sending

After building the payload, the orchestrator calls:
- `sub_102C98440` — sends key-value telemetry with a string value
- `sub_102C978D4` — sends key-value telemetry with a structured value

Each field is sent individually with its obfuscated key, the dylib list or
SIP status as the value, and a flag parameter (always `1`).

### What this module does NOT do

- Does NOT terminate the process on detection
- Does NOT block execution or show a warning
- Does NOT compare dylib names against a blocklist locally
- Does NOT check for specific tools (frida, substrate, etc.) by name
- ALL enforcement is server-side based on received telemetry

---

## 2. Dead Code: P_TRACED Debugger Check — `sub_101932D50`

A sysctl-based debugger detection function exists but has **zero callers**:

```c
int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };
struct kinfo_proc info;
sysctl(mib, 4, &info, &size, NULL, 0);
return (info.kp_proc.p_flag & P_TRACED) != 0;  // P_TRACED = 0x800
```

This code checks if a debugger is attached via the `P_TRACED` process flag.
However, it is **completely dead** — no function calls it, no data references
point to it. It may be a leftover from development or a disabled feature.

---

## 3. No Hyperion / Byfron

Zero string matches for "Hyperion" or "Byfron". No unusual or encrypted Mach-O
sections. Hyperion is **Windows-only** and does not ship on macOS.

---

## 4. Comparison: macOS vs iOS

| Feature | iOS | macOS |
|---------|-----|-------|
| **Native AC module** | No | **Yes** — dylib scanner + SIP check |
| Dylib enumeration | No | **Yes** — reports ALL loaded .dylib files |
| SIP status check | N/A | **Yes** — obfuscated `csr_get_active_config` |
| Obfuscated strings | No | **Yes** — rotation+XOR on field names + API names |
| P_TRACED check | No | Dead code (0 callers) |
| Hyperion / Byfron | No | No |
| ptrace import | No | No |
| csops import | No | No |
| Bytecode signature verification | GF(2^128) | Blake2b/Blake3 + libsodium |
| US14116 hash challenges | Yes | Yes |
| Device attestation | App Attest | Remote Attestation |
| External AC bridge | IOSSupport ObjC | sendExtAntiCheat C++ |
| Security channel | Yes | Yes |
| Physics FPS detection | Yes | Yes |
| Reaper.framework | Yes (dead-code SDK) | No |

### Key takeaway

macOS adds a **telemetry-only AC module** that iOS lacks. It collects:
1. List of all loaded `.dylib` files (catches injected libraries)
2. SIP status (catches disabled system integrity)
3. Session context (`PlaySessionId`, `LastPlaceId`, `MacQAConfig`)

All data is sent to Roblox servers with obfuscated field names. There is no
local enforcement — the server decides whether to ban based on the telemetry.
The obfuscation (rotation+XOR with per-field varying parameters) is designed
to prevent static string scanning, not to resist dedicated reverse engineering.

---

## 5. System Import Summary

| Import | Callers | Purpose |
|--------|---------|---------|
| `sysctl` | 13 | Hardware info, Crashpad, process enumeration |
| `sysctlbyname` | 34 | CPU/memory queries, hw detection, OpenSSL |
| `task_info` | 3 | Memory monitoring (TASK_VM_INFO, TASK_BASIC_INFO) |
| `proc_pidinfo` | 1 | FD count monitoring |
| `mprotect` | 23 | Luau JIT, libsodium secure memory, OpenSSL |
| `dlopen` | 13 | Framework loading, **1 AC use** (sub_10525BC28) |
| `dlsym` | 48 | Symbol resolution, **1 AC use** (sub_10525BC28) |
| `getenv` | 34 | TMPDIR/HOME/PATH, boost, OpenSSL. **No DYLD_INSERT check** |
| `fork` | 4 | Chromium process spawning, Crashpad |
| `_dyld_image_count` | 1 | **AC module** dylib scanner |
| `_dyld_get_image_name` | 1 | **AC module** dylib scanner |
| `access`/`stat`/`lstat` | many | Filesystem infrastructure (SQLite, boost) |

**Not imported:** `ptrace`, `csops`, `sandbox_check`, `vm_protect`, `mach_vm_*`,
`SecTrustEvaluate`, `SecCodeCheckValidity`.
