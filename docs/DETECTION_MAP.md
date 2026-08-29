# Roblox AC Detection Map

High-level architecture of the anti-cheat / integrity verification systems in the current
RobloxLib build. Organized by detection layer.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        FLAG SETTERS (Detection Triggers)                │
│                                                                         │
│  Hash Compare        Bytecode Auth       Physics Telemetry              │
│  sub_9B8D60          sub_172CC78          sub_203C7A4                   │
│  HashMismatches      GF(2^128) verify    TotalHashChecks               │
│                                                                         │
│  Physics FPS         Animation Hash      NetAsset Hash                  │
│  sub_26B7D6C         sub_2042F30          sub_3C3FB8                   │
│  ElevatedPhysicsFPS  HashCheckCount       MD5 validation               │
├─────────────────────────────────────────────────────────────────────────┤
│                      REPORTING PATHS (To Server)                        │
│                                                                         │
│  Telemetry Events    Disconnect Codes     Crash Classification          │
│  cr_* fields         257 BadHash          Crash-Anticheat               │
│  sub_172D184         258 SecurityKey      AnticheatCrash                │
│                      268 HashTimeout      RBX_EXIT_ANTICHEAT            │
│                      304 AndroidAC        sub_48E2258                   │
├─────────────────────────────────────────────────────────────────────────┤
│                   INDEPENDENT DETECTION SYSTEMS                         │
│                                                                         │
│  US14116 Memcheck    Bytecode Verify      External Anti-Cheat           │
│  sub_28F43C0         sub_172CC78          IOSSupport ObjC               │
│  Server challenge    GF(2^128) hash       clientSendExtAntiCheat:       │
│  DC code 268         Galois tables         connectClientExtAntiCheatSignal:│
│                                           setExtAntiCheatJoinData:      │
│                                                                         │
│  Security Channel    Secure Heartbeat     Device Integrity              │
│  SecurityChannelJob  ClientQoSImpl        getDeviceIntegrityToken       │
│  sub_80134C          secureHeartbeat      Apple App Attest              │
│                      QOS01-QOS14          DC codes 296-300              │
├─────────────────────────────────────────────────────────────────────────┤
│                        FFLAG ENFORCEMENT                                │
│                                                                         │
│  Bytecode Hash          Integrity Processor      US14116                │
│  DisablePrehash         DisableAllAdditions       DisableDisconnect     │
│  DeferSigCheck          AnalyticsThrottle         MismatchGuard         │
│  LoadRawWithHashKey                                                     │
│                                                                         │
│  Signature Verification    External AC Telemetry                        │
│  DebugSkipPostTti...       MigrateToV2                                 │
│  DebugBypassTeamTest...    DisableLegacyMetrics                        │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Layer 1: Flag Setters (Detection Triggers)

These functions detect anomalies and set flags or send telemetry.

### Hash Mismatch Detection — `sub_9B8D60` (688 bytes)

Sends `RBX::Telemetry::RobloxTelemetryEvent` containing integrity fields:
- `HashMismatches` — count of hash verification failures
- `CacheReadFailures` — cache integrity failures
- `DeserializationFailures` / `SerializationFailures`

Mismatch count stored at input struct offset +392.

### Bytecode Authentication — `sub_172CC78` (520 bytes)

The core bytecode signature verifier. Called from `luau_load` (`sub_43E2CE8`) at
`0x43E2E58`. Returns `true` on failure, `false` on success.

**Logic:**
1. Initialize global state at `xmmword_673ED18`
2. Parse cryptographic trailer from bytecode end via `sub_172CED0`
3. Run obfuscated version check through lookup tables at `0x4EBE7C4`
4. Conditionally clear capability bit `0x40000000` at `*(*(L+48)+1232)`
5. If version > 1 or check passes, compute 8-bit flags bitmask and send telemetry
6. Final validation — returns nonzero if signature mismatches

On failure: clears VM capability bit, sends crash report via `sub_172D184`.

### Elevated Physics FPS Detection — `sub_26B7D6C` (244 bytes)

Speed hack detector. Reports at thresholds: 65, 70, 80, 90, 100 FPS.
Each threshold fires a separate counter: `ElevatedPhysicsFPSDetected_65/70/80/90/100`.

### Physics Simulation Integrity — `sub_203C7A4` (1148 bytes)

Periodic telemetry sender tracking server-client physics divergence:
- `TotalHashChecks` — physics state hash comparisons
- `TotalMispredictions` — client-server prediction mismatches
- `ResimulationCount` — forced re-simulations
- `ServerAuthorityMode` — authority model in use

Timer interval at global `dword_6CE5EE0`.

### Animation Replication Hash — `sub_2042F30` (1672 bytes)

Animation state verification. Logs `[FLog::AnimationReplication] hashCheck: ...`.
Tracks `HashCheckCount` and `HashCheckRate` counters.

### NetAsset Hash Validation — `sub_3C3FB8` (1704 bytes)

MD5 hash verification of shared network assets during deserialization.
Detects `"Duplicate hash %s in shared NetAsset dictionary"` and
`"Invalid NetAsset version"`.

---

## Layer 2: Reporting Paths

### Telemetry Event Reporter — `sub_172D184` (1280 bytes)

Bytecode signature crash/event reporter. Fields:
- `cr_sessionid`, `cr_placeid`, `cr_universeid`, `cr_userid`
- `cr_source`, `cr_size`, `cr_env`
- `cr_err`, `cr_sigver`, `cr_sigid`

### Disconnect Code Table — `sub_4663E8C` (1756 bytes)

Maps integer codes to disconnect reason strings. Security-relevant codes:

| Code | Reason | Trigger |
|------|--------|---------|
| 257 | `DisconnectBadhash` | Hash verification failure |
| 258 | `DisconnectSecurityKeyMismatch` | Key exchange failure |
| 263 | `DisconnectIllegalTeleport` | Teleport exploit |
| 268 | `DisconnectHashTimeout` | US14116 hash timeout |
| 273 | `DisconnectNewSecurityKeyMismatch` | Updated key failure |
| 279 | `DisconnectBySecurityPolicy` | Policy violation |
| 296 | `DisconnectRemoteAttestationUnsupported` | Device attestation |
| 297 | `DisconnectRemoteAttestationGeneralFailure` | Attestation error |
| 298 | `DisconnectRemoteAttestationTimeout` | Attestation timeout |
| 299 | `DisconnectRemoteAttestationOSOutOfDate` | OS too old |
| 300 | `DisconnectRemoteAttestationBootValidationFailure` | Boot validation |
| 304 | `DisconnectAndroidAnticheatKick` | Android AC (also applies to iOS) |

### Crash Classification — `sub_4880184` (2588 bytes)

Classifies previous-session crashes. Categories include:
- `Crash-Anticheat` — AC-triggered crash
- `AnticheatCrash` — registered in `InitFunc_24433` (30880 bytes)
- `Inferred-OOM`, `Inferred-Uncategorized`

### Exit Reason Mapper — `sub_48E2258` (3132 bytes)

Maps exit codes to identifiers including:
- `RBX_EXIT_ANTICHEAT`
- `RBX_EXIT_QOS01` through `RBX_EXIT_QOS14` (security heartbeat failures)
- `RBX_ERROR_BADHASH`, `RBX_ERROR_SECURITY_KEY_MISMATCH`
- `RBX_ERROR_NETWORK_SECURITY_FAILURE`

---

## Layer 3: Independent Detection Systems

### US14116 Remote SysStats — `sub_28F43C0` (692 bytes)

Server challenge-response system. The server sends system stats challenges;
the client must respond correctly.

**Logic:**
1. Receives stats via `onRemoteSysStats` callback
2. Checks FFlags at `byte_6CF9FC8` and `byte_6D01768`
3. If stats entry not found in client list, or check flags pass:
   calls `sub_28F3C44(replicator, playerId, 268)` → disconnect code 268

Log: `"Players::onRemoteSysStats disconnect"`, `"[FLog::US14116] onRemoteSysStats: %s"`

### External Anti-Cheat Module (iOS)

ObjC-bridged external AC system. Three entry points on the `IOSSupport` class:
- `clientSendExtAntiCheat:` — sends AC data payload
- `connectClientExtAntiCheatSignal:` — connects the signal handler
- `setExtAntiCheatJoinData:` — sets join-time AC data

Data type: `RBX::Security::ExternalAntiCheatData` via
`rbx::signal<void(vector<uint8_t>, shared_ptr<ExternalAntiCheatData>, int64_t, ...)>`

Post-join gate at `sub_28F42A0` (236 bytes): fires `"AntiCheat-AfterJoin"` counter,
checks flag at replicator+2237.

### Security Channel — `sub_80134C` (96 bytes)

Dedicated network channel for anti-tamper communication:
- `SecurityChannelMutex` at `0x55CEE79`
- `SecurityChannelSequenceNumberMutex` at `0x55CEE8E`
- `RBX::Network::SecurityChannelJob` — background job
- `RBX::Network::ServerSecurityCheckJob` — server-side validation

### Secure Heartbeat — `ClientQoSImpl`

Periodic security heartbeat under `RBX::Security` namespace:
- `RBX::Security::ClientQoSImpl::secureHeartbeat`
- `RBX::Security::ClientQoSImplIos` — iOS-specific
- `RBX::Security::ClientQoSContext` — context data
- Failure triggers exit codes `RBX_EXIT_QOS01` through `RBX_EXIT_QOS14`

### Device Integrity (Apple App Attest)

Apple device attestation integration:
- `RBX::AccountProtocolCore::getDeviceIntegrityToken`
- `RBX::AccountProtocolCore::deviceIntegrityAvailable`
- Reflection: `GetDeviceIntegrityToken`, `GetDeviceIntegrityTokenYield`
- FFlag: `EnableAsyncDeviceIntegrityTokenRetreival`
- Failure → disconnect codes 296–300

### Cheat/Exploit Kick Handler — `sub_28F2C78` (3500 bytes)

Server-initiated kick processor. Formats `"AbuserID:{};{}"` strings,
processes script edits. Contains the `"Cheating/Exploiting;"` disconnect message.

### Security Key Exchange — `sub_82229C` (1148 bytes)

Validates security keys during connection. References:
- `SecurityKeyRejected` at `0x55D14F1`
- `ConnectSecuritykeyMismatch` counter
- Failure → disconnect codes 258 or 273

### Encryption Layer

RakNet packet encryption with automatic disconnect on repeated failures:
- `DecryptionFailDisconnectThreshold` — FFlag controlling max failures before DC
- `EncryptionFailThreshold` — encryption error threshold
- `LibcatDecryptionFailed`, `RakNetDecryptionFailure` counters

---

## Layer 4: Signature Verification (DataModel Patches)

### Patch Verification — `sub_2FFFDB0` (1584 bytes)

`DataModelPatchConfigurer` deserialization + verification. Supports both
**Blake2b** and **Blake3** hash algorithms.

Events: `deserialize_patch_begin/end`, `verify_patch_begin/end`.

### Deferred Signature Check — `sub_2FFC4DC` (736 bytes)

Postponed verification with **15-second timeout**. Skipped during homepage
interaction (`isHomePageInteractive` check at offset 152).

### Post-TTI Verification — `sub_300EA48` (3800 bytes)

Post-Time-To-Interactive signature check. Controlled by
`DebugSkipPostTtiSignatureVerification` FFlag.

### Player Hydration Signing — `InitFunc_15727` at `0x221AA8C` (1844 bytes)

Hardcoded signing key: `"8Nu7Er7LsbQpihVC+ijfEbbRFzj+Kikw9McFEZdFSt4="`
Counters: `PlayerHydrationSignatureVerifySuccessCounter/FailureCounter`.
Key stored at `qword_6CE9D38`.

---

## Layer 5: Telemetry & Counters

### PreHash Telemetry — `sub_8CAC60` (440 bytes)

Reports bytecode connection hash statistics with sampling:
- `postEnLength`, `postHash`, `preEnLength`, `preHash`
- `cap`, `verMin`, `verMax`, `numSff`
- Counter: `debugLuaConnIssue`
- Sampling: `hash(result) % 10000 < threshold` (global `dword_6CB86C8`)

### Bouncing Script Detection — `sub_172B53C` (1600 bytes)

Tracks script hash integrity: `BouncingScriptHashes`, `BouncingScriptPermyriad`,
`ScriptHash` counters.

### Client-Side User Hashing — `InitFunc_12250` at `0x195C09C`

FFlag: `ClientSideUserHashing` at `0x56A9792`.
Throttle: `ClientSideUserHashingTelemetryThrottleHundredthsPercent`.

### LR Hash Miss Telemetry

Lightweight replication hash verification:
- `LrHashCheck` / `LrHashFail` counters
- FFlag: `ReportLrHashMissTelemetryForRbxTransport`
- Functions: `sub_840FF4` (3824 bytes), `sub_9AD848` (2440 bytes),
  `sub_2B1D2DC` (26336 bytes — very large)

### RCC Hash Exchange — `sub_DD29F8` (1504 bytes)

Roblox Cloud Compute hash verification:
- `RCCHashReceived`, `RCCHashTimeout`, `ExitWithoutRCCHash` counters
- Hash source tracking: `"None"`, `"Fallback"`, `"RCC"`

---

## Layer 6: Challenge / Moderation

### Generic Challenge Service — `RBX::GenericChallengeService`

HTTP challenge headers: `rblx-challenge-id`, `rblx-challenge-metadata`, `rblx-challenge-type`.
Events: `ChallengeRequiredEvent`, `ChallengeCompletedEvent`, `ChallengeAbandonedEvent`,
`ChallengeInvalidatedEvent`, `ChallengeLoadedEvent`.
FFlag: `EnableGenericChallengeResponseHandling`.

### Moderation Result — `sub_19963F0`

Enum values: `ViolationDetected` (0), `Borderline` (1), `NoViolationDetected` (2).

### RUPP Token System

`RBX::Rupp::ClientRuppGenerator`, `ServerRuppGenerator`, `RuppTokenProcessor`.
Token validation during connection; failure causes disconnect.
Counter: `ClientRuppDeserializationError`.
