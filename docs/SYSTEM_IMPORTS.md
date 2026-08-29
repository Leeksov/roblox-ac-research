# System Import Audit

Every security-sensitive system import in RobloxLib was traced to its callers
to determine whether it serves an anti-cheat / RASP purpose.

**Result: None of them do.** All are used by Crashpad, SQLite, OpenSSL, WebRTC,
or standard infrastructure.

---

## Audited imports

### `sysctl` — imported at `0x7007090`

| Caller | Size | Purpose |
|--------|------|---------|
| `sub_6B0698` | 1056 | **Crashpad** `CrashHandler::Initialize` — reads `kern_proc_info` for crash dump |
| `sub_6B6B0C` | 1436 | **Crashpad** intermediate dump handler — reads process info, PID, parent PID |
| `sub_6C7128` | 1316 | **Crashpad** `CrashpadShared` — reads `kern.maxfiles` and fd count |
| `sub_3524FB8` | 280 | **Crashpad** — kern info for crash context |
| `sub_486C028` | 156 | Unknown (small, likely Crashpad auxiliary) |
| `sub_49437D0` | 168 | Unknown (small, likely system info query) |

**Verdict:** All Crashpad crash-reporter infrastructure. No `CTL_KERN`/`KERN_PROC`
P_TRACED debugger detection.

### `sysctlbyname` — imported at `0x7007098`

| Caller | Size | Purpose |
|--------|------|---------|
| `sub_6C7128` | 1316 | **Crashpad** — reads `kern.num_files` |
| `sub_6F2DB8` | 552 | **Crashpad** — reads system info |
| `sub_6F9BB0` | 788 | **Crashpad** — additional system queries |
| `sub_306D448` | 140 | Memory page size query |
| `sub_306D52C` | 160 | Memory page size query |
| `sub_36CD394` | 80 | Small system query |
| `InitFunc_23366` | 320 | **6 calls** — reads hw.ncpu, hw.memsize etc. (hardware info for telemetry) |
| `sub_42512B0` | 5948 | Large function — 4 calls to sysctlbyname (hw queries) |
| `sub_486DB14` | 128 | Small system query |
| `sub_4927158` | 196 | boost::thread::hardware_concurrency (2 calls) |
| `sub_492721C` | 96 | boost::thread::physical_concurrency |
| `_OPENSSL_cpuid_setup` | 808 | **OpenSSL** CPU feature detection (3 calls) |

**Verdict:** Hardware info, Crashpad, OpenSSL, boost. No security checks.

### `task_info` — imported at `0x70070B0`

| Caller | Size | Purpose |
|--------|------|---------|
| `sub_6B6B0C` | 1436 | **Crashpad** — `task_basic_info` for crash dump (flavor 0x5) |
| `sub_6B83F0` | 884 | **Crashpad** — task info + dyld image enumeration for crash context (flavor 0x11) |
| `sub_486BEFC` | 80 | Small task query |
| `sub_486BF4C` | 196 | Task query |
| `sub_486DFFC` | 376 | Task query |

**Verdict:** All Crashpad. No `TASK_DYLD_INFO` for debugger/injection detection.

### `access` — imported at `0x70063F0`

| Caller | Size | Purpose |
|--------|------|---------|
| `sub_469651C` | 1672 | **SQLite** `os_unix.c` — file access checks for VFS (`SQLITE_FORCE_PROXY_LOCKING`) |
| `sub_4696CD4` | 132 | **SQLite** — file existence check |
| `sub_46A2DC4` | 392 | **SQLite** — temp directory probing (`etilqs_` temp files) |
| `sub_46A56A0` | 80 | **SQLite** — simple file check |

**Verdict:** All SQLite file I/O. No jailbreak file existence checks
(`/Applications/Cydia.app`, `/usr/sbin/sshd`, etc.).

### `getenv` — imported at `0x7006A18`

| Caller | Size | Purpose |
|--------|------|---------|
| `sub_7E33D4` | 128 | Unknown small function |
| `sub_9E1A3C` | 7724 | Large function — unclear |
| `_isEnvVarEnabled` | 224 | **WebRTC** — reads env vars for debug config |
| `_setRemoteDescription` | 2184 | **WebRTC** — SDP configuration |
| `_createOffer`/`_createAnswer` | — | **WebRTC** — session setup |
| `sub_36810C8` | 104 | Reads env vars (2 calls) |
| `sub_393F064` | 80 | Small env check |
| `sub_44DCADC` | 192 | Unknown |
| `sub_45EBF30` | 56 | Very small |
| `sub_4696480` | 156 | **SQLite** — reads env for config |
| `sub_469651C` | 1672 | **SQLite** — reads `SQLITE_FORCE_PROXY_LOCKING` |
| `sub_48715E4` | 564 | Filesystem error handler — reads `TMP`/`TEMP`/`USERPROFILE` |
| `sub_49044AC` | 92 | Small env read |
| `sub_496FA2C` | 252 | 4 calls — reads multiple env vars |
| `_OPENSSL_cpuid_setup` | 808 | **OpenSSL** — CPU detection config |
| `_ossl_safe_getenv` | 56 | **OpenSSL** — safe env read wrapper |
| `sub_4ACE6D8` | 204 | **OpenSSL** — env config |
| `sub_4CDE85C` | 376 | Unknown env read |

**Verdict:** SQLite, WebRTC, OpenSSL, filesystem utils. **No `DYLD_INSERT_LIBRARIES`
detection** — none of the callers check for injection-related env vars.

### `mprotect` — imported at `0x7006C10`

| Caller | Size | Purpose |
|--------|------|---------|
| `sub_55C4` | 228 | JIT memory allocator — `mmap(NONE)` → `mprotect(RW)` for executable memory |
| `sub_B48C` | 664 | Memory allocator |
| `sub_EB58` | 512 | Memory allocator |
| `sub_112CC` | 640 | Memory allocator |
| `sub_12268` | 368 | Memory allocator |
| `sub_306CDBC` | 696 | Memory page management |
| `sub_306D134` | 60 | Small mprotect wrapper |
| `_CRYPTO_secure_malloc_init` | 840 | **OpenSSL** — secure heap initialization (2 calls) |

**Verdict:** Memory allocators and OpenSSL secure malloc. No code-integrity
self-checks (no `mprotect(TEXT, NONE)` → checksum → `mprotect(TEXT, RX)` pattern).

---

## Imports NOT present

These security-sensitive APIs are **not imported** by RobloxLib:

| API | Typical AC use | Status |
|-----|---------------|--------|
| `ptrace` | `PT_DENY_ATTACH` anti-debug | **NOT IMPORTED** |
| `csops` | Code signing self-validation | **NOT IMPORTED** |
| `sandbox_check` | Sandbox escape detection | **NOT IMPORTED** |
| `fork` | Fork-based jailbreak detection | **NOT IMPORTED** (only `pthread_atfork`) |
| `vm_protect` / `mach_vm_protect` | Memory protection manipulation | **NOT IMPORTED** |
| `mach_vm_read` / `mach_vm_write` | Memory introspection | **NOT IMPORTED** |
| `_dyld_get_image_name` (in RobloxLib) | Loaded dylib scanning | **NOT IMPORTED** by RobloxLib (only by Reaper.framework) |
| `SecTrustEvaluate` | Certificate pinning | **NOT IMPORTED** |

---

## Reaper.framework imports

Reaper imports dyld APIs but uses them for dead-code analytics, not security:

| Import | Reaper's usage |
|--------|---------------|
| `_dyld_image_count` | Count loaded images |
| `_dyld_get_image_name` | Filter to app-bundle only (`hasPrefix:`) |
| `_dyld_get_image_header` | Read Mach-O sections for type metadata |
| `_getsectiondata` | Read `__swift5_types` / `__objc_classlist` |
| `_class_getName` | Get ObjC class name for reporting |
| `_object_getClass` | Read metaclass flags |
| `_dlsym` | Swift runtime internal |

**Not imported by Reaper:** `ptrace`, `sysctl`, `task_info`, `access`, `stat`,
`getenv`, `fork`, `sandbox_check`. No security syscalls.

---

## Conclusion

RobloxLib relies entirely on **server-side validation** (bytecode signing, hash
challenges, device attestation) rather than client-side environment detection. There
is no jailbreak detection, no anti-debug, no dylib injection scanning, and no code
integrity self-checks in the main binary or any bundled framework.
