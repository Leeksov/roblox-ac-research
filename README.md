# Roblox Anti-Cheat / RASP Research

Reverse-engineering documentation of the anti-cheat, integrity verification, and runtime
application self-protection (RASP) systems in the iOS Roblox client (RobloxLib, arm64).

All addresses and analysis refer to the current RobloxLib build unless stated otherwise.
Every function was identified via static analysis in IDA Pro and cross-referenced through
string anchors, xrefs, and call-graph traversal. System import usage was audited to confirm
no classic jailbreak/root detection or anti-debug via syscalls exists in the main binary.

---

## Key findings

- **No jailbreak detection in RobloxLib.** The binary imports `sysctl`/`sysctlbyname`/`task_info`
  but they are used exclusively by Crashpad (crash reporter), not for anti-debug or P_TRACED checks.
  No `ptrace`, `csops`, `sandbox_check`, or jailbreak file-existence checks exist.
- **No anti-debug.** No `PT_DENY_ATTACH`, no `DYLD_INSERT_LIBRARIES` env checks, no code-signing
  self-validation.
- **Reaper.framework is NOT anti-cheat.** It is [Emerge Tools](https://www.emergetools.com/) dead-code
  detection SDK. It scans ObjC/Swift types used at runtime for tree-shaking analytics. It only reads
  binaries inside the `.app` bundle (filters by `hasPrefix: appPath`), does not scan for injected
  dylibs, and does not report security events.
- **The "external anti-cheat module"** referenced by the IOSSupport ObjC bridge
  (`clientSendExtAntiCheat:`, `setExtAntiCheatJoinData:`) is **not present in the IPA**. It is either
  downloaded at runtime or the bridge is a no-op on iOS.
- **All protection is server-side or signature-based:** bytecode GF(2^128) hash verification,
  US14116 server challenge-response, DataModel patch signing (Blake2b/Blake3), device integrity
  (Apple App Attest), encryption layer thresholds, and FFlag-controlled telemetry pipelines.

---

## Structure

| Document | Contents |
|---|---|
| [`docs/DETECTION_MAP.md`](docs/DETECTION_MAP.md) | High-level architecture: all detection layers, flag setters, reporting paths |
| [`docs/BYTECODE_VERIFICATION.md`](docs/BYTECODE_VERIFICATION.md) | Bytecode signature verification: GF(2^128) Galois hash, trailer parsing, obfuscation tables |
| [`docs/REPORTING_PATHS.md`](docs/REPORTING_PATHS.md) | Network reporting: 20+ disconnect codes, exit codes, crash classification, telemetry fields |
| [`docs/DETECTION_SYSTEMS.md`](docs/DETECTION_SYSTEMS.md) | Independent systems: US14116 memcheck, external AC bridge, security channel, QoS heartbeat, device integrity, physics FPS detection |
| [`docs/FFLAGS.md`](docs/FFLAGS.md) | 40+ security-relevant FFlags with string addresses and global variables |
| [`docs/FUNCTION_INDEX.md`](docs/FUNCTION_INDEX.md) | Complete address table of 60+ identified AC/integrity functions |
| [`docs/REAPER_ANALYSIS.md`](docs/REAPER_ANALYSIS.md) | Full reverse of Reaper.framework — proves it is dead-code analytics, not anti-cheat |
| [`docs/SYSTEM_IMPORTS.md`](docs/SYSTEM_IMPORTS.md) | Audit of security-sensitive system imports (sysctl, ptrace, mprotect, etc.) |

## Methodology

1. **String anchoring** — search for known AC-related strings (`"HashMismatches"`, `"US14116"`,
   `"AntiCheat"`, `"disconnect"`, etc.) and trace to referencing functions
2. **Import audit** — enumerate all security-sensitive system imports (`sysctl`, `ptrace`, `task_info`,
   `access`, `mprotect`, `getenv`, `dlopen`) and trace every caller to determine if it serves an
   AC purpose
3. **Xref traversal** — follow call graphs from identified entry points to map complete pipelines
4. **FFlag enumeration** — search all `FFlag`/`DFFlag`/`FInt` strings and correlate with init functions
5. **Framework analysis** — reverse every non-system framework in the IPA to identify external AC modules

## Credits

Research by [@leeksov](https://github.com/leeksov).

## Disclaimer

For educational and security-research purposes only. This documents publicly observable
behavior of a shipping binary for the purpose of understanding runtime protection techniques.

## License

MIT — see [`LICENSE`](LICENSE).
