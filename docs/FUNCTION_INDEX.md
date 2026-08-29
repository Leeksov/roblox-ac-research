# Function Index

Complete address table of every identified anti-cheat / integrity function.

---

## Bytecode Verification Pipeline

| Address | Size | Name | Description |
|---------|------|------|-------------|
| `0x43E2CE8` | 5712 | `luau_load` | Top-level bytecode deserializer |
| `0x172CC78` | 520 | `bytecode_authenticate` | Signature verification orchestrator |
| `0x172CED0` | 640 | `parse_signature_trailer` | Extract signature from bytecode end |
| `0x172DC9C` | 524 | `verify_hash_galois` | GF(2^128) polynomial hash verification |
| `0x172DEC0` | 128 | `detect_sig_v1` | XOR magic detection for v1 signatures |
| `0x172DF40` | 92 | `detect_sig_v2` | XOR magic detection for v2 (40B trailer) |
| `0x172D888` | 728 | `version_telemetry` | Version extraction + telemetry codes 900-903 |
| `0x172D184` | 1280 | `crash_report` | Bytecode AC crash/telemetry reporter |
| `0x172D714` | 96 | `stats_increment` | Atomic counter updates |
| `0x172E080` | 148 | `init_gf_tables` | Load 99KB Galois field lookup tables |
| `0x172E27C` | 160 | `copy_gf_table_data` | Copy 8257 GF table entries |
| `0x172C7D4` | 1052 | `InitFunc_10942` | FFlag registration (prehash, sig-as-hash) |
| `0x172B53C` | 1600 | `bouncing_script_hash` | Script hash integrity tracking |

## DataModel Patch Verification

| Address | Size | Name | Description |
|---------|------|------|-------------|
| `0x2FFFDB0` | 1584 | `deserializeAndVerifyPatch` | Blake2b/Blake3 patch verification |
| `0x2FFC4DC` | 736 | `deferSignatureCheck` | Deferred 15s signature check |
| `0x300EA48` | 3800 | `postTtiSignatureVerify` | Post-TTI signature verification |
| `0x221AA8C` | 1844 | `InitFunc_15727` | Player hydration signing init |

## US14116 / Remote SysStats

| Address | Size | Name | Description |
|---------|------|------|-------------|
| `0x28F43C0` | 692 | `onRemoteSysStats` | US14116 handler, DC code 268 |
| `0x28F42A0` | 236 | `antiCheatAfterJoin` | Post-join AC dispatcher |
| `0x28F2C78` | 3500 | `cheatExploitKick` | Server-initiated cheat kick |
| `0x28F3C44` | — | `disconnectPlayer` | Sends disconnect with code |

## Hash Verification

| Address | Size | Name | Description |
|---------|------|------|-------------|
| `0x9B8D60` | 688 | `hashMismatchTelemetry` | Cache hash mismatch reporter |
| `0x3C3FB8` | 1704 | `netAssetHashVerify` | NetAsset MD5 validation |
| `0x8CAC60` | 440 | `preHashTelemetry` | Pre/post hash telemetry reporter |
| `0xDD29F8` | 1504 | `rccHashExchange` | RCC hash verification |
| `0xDD3B2C` | 316 | `exitWithoutRCCHash` | RCC hash timeout handler |
| `0x840FF4` | 3824 | `lrHashCheck_1` | LR hash check function 1 |
| `0x9AD848` | 2440 | `lrHashCheck_2` | LR hash check function 2 |
| `0x2B1D2DC` | 26336 | `lrHashCheck_3` | LR hash check (very large) |

## Physics / Animation Integrity

| Address | Size | Name | Description |
|---------|------|------|-------------|
| `0x26B7D6C` | 244 | `elevatedPhysicsFPS` | Speed hack FPS detection |
| `0x203C7A4` | 1148 | `physicsSimTelemetry` | Physics hash/misprediction telemetry |
| `0x2042F30` | 1672 | `animationHashCheck` | Animation replication hash |
| `0x204CF54` | 564 | `hashCheckProfile` | Hash check count/rate profiler |

## Security Infrastructure

| Address | Size | Name | Description |
|---------|------|------|-------------|
| `0x82229C` | 1148 | `securityKeyValidation` | Security key exchange validation |
| `0x80134C` | 96 | `securityChannelInit` | Security channel mutex init |
| `0x8EBC60` | 1196 | `gameJoinSuccess` | Join success telemetry |

## Disconnect / Exit Mappers

| Address | Size | Name | Description |
|---------|------|------|-------------|
| `0x4663E8C` | 1756 | `disconnectCodeToString` | DC code → string mapper |
| `0x48E2258` | 3132 | `exitReasonMapper` | Exit code → identifier mapper |
| `0x4880184` | 2588 | `crashClassifier` | Previous-session crash classifier |
| `0x195CE4C` | 3940 | `disconnectEnumInit` | Disconnect enum registration |
| `0x19963F0` | — | `moderationResult` | Moderation verdict enum |

## FFlag Initialization

| Address | Size | Name | Description |
|---------|------|------|-------------|
| `0x65395C` | 2048 | `InitFunc_2337` | Security alerting telemetry FFlags |
| `0x195C09C` | 728 | `InitFunc_12250` | Client-side user hashing FFlags |
| `0x4845270` | 30880 | `InitFunc_24433` | AnticheatCrash registration |
| `0x22D9F08` | — | `InitFunc_15996` | Debug bytecode verification skip |

## Global Data

| Address | Type | Purpose |
|---------|------|---------|
| `0x673ED18` | xmmword | Bytecode auth state / stats counters |
| `0x673EC90`–`0x673ECF0` | ptrs | Galois field multiplication tables |
| `0x4EA6494` | 99084 bytes | Pre-computed GF table data |
| `0x4EBE7A0`–`0x4EBE800` | tables | Obfuscation lookup tables |
| `byte_6CDAA00` | bool | Signature verification enforcement |
| `dword_6CDA9D0` | int | Min signature version |
| `dword_6CDA9B8` | int | Min bytecode size |
| `dword_6CE5EE0` | int | Physics telemetry timer interval |
| `qword_6CE9D38` | ptr | Player hydration signing key |
| `dword_6CB86C8` | int | PreHash telemetry sampling threshold |
| `byte_6CF9FC8` | bool | US14116 guard flag 1 |
| `byte_6D01768` | bool | US14116 guard flag 2 |
