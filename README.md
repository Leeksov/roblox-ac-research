# Roblox Anti-Cheat / RASP Research

Reverse-engineering documentation of the anti-cheat, integrity verification, and runtime
application self-protection (RASP) systems in the iOS Roblox client (RobloxLib, arm64).

All addresses and analysis refer to the current RobloxLib build unless stated otherwise.
Every function was identified via static analysis in IDA Pro and cross-referenced through
string anchors, xrefs, and call-graph traversal.

## Structure

| Document | Contents |
|---|---|
| [`docs/DETECTION_MAP.md`](docs/DETECTION_MAP.md) | High-level architecture: flag setters, detection globals, reporting paths, defense layers |
| [`docs/BYTECODE_VERIFICATION.md`](docs/BYTECODE_VERIFICATION.md) | Bytecode signature verification pipeline: GF(2^128) hash, trailer parsing, FFlags |
| [`docs/REPORTING_PATHS.md`](docs/REPORTING_PATHS.md) | Network reporting: disconnect codes, telemetry events, sneaky packets |
| [`docs/DETECTION_SYSTEMS.md`](docs/DETECTION_SYSTEMS.md) | Independent detection systems: US14116 memcheck, hash mismatches, physics, external AC |
| [`docs/FFLAGS.md`](docs/FFLAGS.md) | All security-relevant FFlags with addresses and globals |
| [`docs/FUNCTION_INDEX.md`](docs/FUNCTION_INDEX.md) | Complete address table of every identified AC function |

## Disclaimer

For educational and security-research purposes only. This documents publicly observable
behavior of a shipping binary for the purpose of understanding runtime protection techniques.

## License

MIT
