# Roblox iOS — Anti-Tamper & Integrity Verification Research

Reverse-engineering of the **anti-tamper**, integrity verification, and server-side validation
systems in the iOS Roblox client (`RobloxLib`, arm64).

> **Important distinction:** This is **not** a classic anti-cheat (no environment scanning, no
> jailbreak/root detection, no process inspection, no debugger detection). Roblox on iOS has
> **no native anti-cheat** in the binary. What it has is **anti-tamper** (bytecode signature
> verification, patch integrity) and **server-side validation** (challenge-response, physics
> hash checks, device attestation). The Lua VM itself is not an anti-cheat — Lua scripts are
> game logic written by place developers, not by Roblox's security team.

All addresses refer to the current RobloxLib build. Every function was identified via static
analysis in IDA Pro, cross-referenced through string anchors, xrefs, and call-graph traversal.

---

## Key findings

- **No anti-cheat in RobloxLib.** No jailbreak detection, no anti-debug, no injection scanning,
  no environment fingerprinting. The binary imports `sysctl`/`sysctlbyname`/`task_info` but they
  are used exclusively by **Crashpad** (crash reporter). No `ptrace`, `csops`, `sandbox_check`,
  or file-existence checks (`/Applications/Cydia.app`, etc.) exist.
- **No `DYLD_INSERT_LIBRARIES` detection.** No `getenv` caller checks for injection-related
  env vars. All `getenv` usage is SQLite, WebRTC, and OpenSSL configuration.
- **Reaper.framework is NOT anti-cheat.** It is [Emerge Tools](https://www.emergetools.com/)
  dead-code detection SDK (`com.emergetools.reaper`). Scans only app-bundle binaries for
  ObjC/Swift type usage analytics. Does not scan for injected dylibs.
- **The "external anti-cheat module"** referenced by the IOSSupport ObjC bridge
  (`clientSendExtAntiCheat:`, `setExtAntiCheatJoinData:`) is **not present in the IPA**.
  The bridge is either a no-op on iOS or the module is downloaded at runtime.
- **macOS has a native AC telemetry module** (absent on iOS). It scans all loaded `.dylib`
  files via `_dyld_image_count`/`_dyld_get_image_name` and checks SIP status via an obfuscated
  `dlopen("libSystem") + dlsym("csr_get_active_config")` call. Library/symbol names and all
  8 telemetry field names are encrypted with per-field bit-rotation + XOR. Telemetry-only — no
  local enforcement. Full analysis: [`docs/MACOS_ANALYSIS.md`](docs/MACOS_ANALYSIS.md).
- **P_TRACED debugger check exists on macOS but is dead code** — `sub_101932D50` uses
  `sysctl(KERN_PROC)` to check `kp_proc.p_flag & 0x800`, but has zero callers.
- **All other protection is anti-tamper or server-side:**
  - Bytecode signature verification (GF(2^128) Galois hash)
  - DataModel patch signing (Blake2b / Blake3)
  - US14116 server challenge-response (disconnect code 268)
  - Device integrity (Apple App Attest, disconnect codes 296–300)
  - RakNet encryption failure thresholds
  - FFlag-controlled telemetry pipelines
  - Physics/animation hash checks (server-side divergence detection)

---

## Structure

| Document | Contents |
|---|---|
| [`docs/DETECTION_MAP.md`](docs/DETECTION_MAP.md) | High-level architecture: all protection layers, flag setters, reporting paths |
| [`docs/BYTECODE_VERIFICATION.md`](docs/BYTECODE_VERIFICATION.md) | Bytecode signature verification: GF(2^128) Galois hash, trailer parsing, obfuscation tables |
| [`docs/REPORTING_PATHS.md`](docs/REPORTING_PATHS.md) | Network reporting: 20+ disconnect codes, exit codes, crash classification, telemetry fields |
| [`docs/DETECTION_SYSTEMS.md`](docs/DETECTION_SYSTEMS.md) | Independent systems: US14116 memcheck, external AC bridge, security channel, QoS heartbeat, device integrity, physics FPS detection |
| [`docs/FFLAGS.md`](docs/FFLAGS.md) | 40+ security-relevant FFlags with string addresses and global variables |
| [`docs/FUNCTION_INDEX.md`](docs/FUNCTION_INDEX.md) | Complete address table of 60+ identified integrity/validation functions |
| [`docs/REAPER_ANALYSIS.md`](docs/REAPER_ANALYSIS.md) | Full reverse of Reaper.framework — proves it is dead-code analytics, not anti-cheat |
| [`docs/SYSTEM_IMPORTS.md`](docs/SYSTEM_IMPORTS.md) | Audit of all security-sensitive system imports (sysctl, ptrace, mprotect, etc.) |
| [`docs/MACOS_ANALYSIS.md`](docs/MACOS_ANALYSIS.md) | **macOS-only:** native AC telemetry module (dylib scanner + SIP check + obfuscated strings) |

## What's NOT here (and why)

- **Lua-side anti-cheat scripts** — individual Roblox *places* (games) can include their own
  Lua anti-cheat scripts, but those are written by **place developers**, not Roblox. They run
  inside the Lua VM like any game script and are not part of the native binary. They can be
  dumped and analyzed per-place, but they are not covered here.
- **Windows/macOS anti-cheat** — Roblox on desktop uses Hyperion (Byfron), a native anti-cheat
  with kernel-level protections. This research covers **iOS only**, where no equivalent exists.

## Methodology

1. **String anchoring** — search for known integrity strings (`"HashMismatches"`, `"US14116"`,
   `"bytecode version mismatch"`, `"disconnect"`, etc.) and trace to referencing functions
2. **Import audit** — enumerate all security-sensitive system imports (`sysctl`, `ptrace`,
   `task_info`, `access`, `mprotect`, `getenv`, `dlopen`) and trace every caller
3. **Xref traversal** — follow call graphs from identified entry points to map complete pipelines
4. **FFlag enumeration** — search all `FFlag`/`DFFlag`/`FInt` strings and correlate with init functions
5. **Framework analysis** — reverse every non-system framework in the IPA (Reaper, Backtrace, Persona2)

## Credits

Research by [@leeksov](https://github.com/leeksov).

## Disclaimer

For educational and security-research purposes only. This documents publicly observable
behavior of a shipping binary for the purpose of understanding runtime protection techniques.

## License

MIT — see [`LICENSE`](LICENSE).
