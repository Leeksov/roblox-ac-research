# Independent Detection Systems

Detailed analysis of each detection system: US14116, external anti-cheat,
security channel, device integrity, physics integrity, and hash verification.

---

## 1. US14116 — Remote SysStats / Memory Check

### Core handler — `sub_28F43C0` (692 bytes)

Server sends system stats challenges; client must respond correctly.

**Logic:**
```c
// Log the incoming stats
NSLog("[FLog::US14116] onRemoteSysStats: %s", stats_string);

// Check FFlags
if (byte_6CF9FC8 || byte_6D01768) {
    // If stats entry not found in client list → mismatch
    if (!find_in_client_list(stats))
        sub_28F3C44(replicator, playerId, 268);  // disconnect code 268
    // Log: "Players::onRemoteSysStats disconnect"
}

// Display stats telemetry
NSLog("[FLog::US14116] Sending display stats: %lld | %s | %s",
      value, key1, key2);
```

**Disconnect code 268** = `DisconnectHashTimeout`. The server expects
specific values from client memory; mismatches indicate tampering.

### AfterJoin gate — `sub_28F42A0` (236 bytes)

Post-join dispatcher:
1. Fires `"AntiCheat-AfterJoin"` telemetry event via `sub_43F2BB4`
2. Checks `*(byte*)(replicator + 2237)` — server flag for AC enabled
3. If AC enabled and callback at `*(qword*)(replicator + 2168)` exists:
   invokes external AC path
4. Otherwise: falls through to US14116 handler `sub_28F43C0`

---

## 2. External Anti-Cheat Module (iOS)

### Architecture

ObjC-bridged system on the `IOSSupport` class with three entry points:

| Selector | Purpose |
|----------|---------|
| `clientSendExtAntiCheat:` | Sends AC data payload to server |
| `connectClientExtAntiCheatSignal:` | Connects the C++ signal to ObjC bridge |
| `setExtAntiCheatJoinData:` | Sets join-time AC initialization data |

### Signal type

```cpp
rbx::signal<void(
    vector<uint8_t>,                         // payload
    shared_ptr<RBX::Security::ExternalAntiCheatData>,  // metadata
    int64_t,                                 // timestamp or ID
    const char*,                             // context string 1
    const char*,                             // context string 2
    size_t                                   // data size
)>
```

### Telemetry FFlags

| FFlag | Global | Purpose |
|-------|--------|---------|
| `MigrateExternalAntiCheatModuleTelemetryToV2` | `byte_6CB3198` | Migrate to v2 telemetry |
| `DisableExternalAntiCheatModuleLegacyTelemetryMetrics` | `byte_6CB31B0` | Kill legacy metrics |

### Exit codes

- `RBX_EXIT_ANTICHEAT` at `0x58E824C` — exit handler in `sub_48E2258`
- `Crash-Anticheat` at `0x5888B03` — crash classifier in `sub_4880184`
- `AnticheatCrash` at `0x58BC506` — init in `InitFunc_24433`
- `DisconnectAndroidAnticheatKick` (code 304) — also used on iOS

---

## 3. Security Key Exchange — `sub_82229C` (1148 bytes)

Validates cryptographic keys during connection establishment.

**References:**
- `SecurityKeyRejected` at `0x55D14F1`
- `ConnectSecuritykeyMismatch` counter at `0x58A1AD0`
- `DisconnectSecurityKeyMismatch` (code 258)
- `DisconnectNewSecurityKeyMismatch` (code 273)
- `RBX_ERROR_SECURITY_KEY_MISMATCH`
- `RBX_ERROR_NEW_SECURITY_KEY_MISMATCH`

---

## 4. Security Channel

Dedicated network channel for anti-tamper communication.

### Components

| Component | Address | Description |
|-----------|---------|-------------|
| `SecurityChannelMutex` | `0x55CEE79` | Channel mutex |
| `SecurityChannelSequenceNumberMutex` | `0x55CEE8E` | Sequence number mutex |
| `RBX::Network::SecurityChannelJob` | RTTI `0x4DB0C8D` | Background job |
| `RBX::Network::ServerSecurityCheckJob` | RTTI `0x4DB0EDC` | Server validation |

Init function: `sub_80134C` (96 bytes).

---

## 5. Secure Heartbeat (ClientQoS)

Periodic security heartbeat under `RBX::Security` namespace.

### Classes

| Class | RTTI | Description |
|-------|------|-------------|
| `RBX::Security::ClientQoSImpl` | `0x4D8F5F0` | Base implementation |
| `RBX::Security::ClientQoSImplIos` | `0x4D8F938` | iOS-specific |
| `RBX::Security::ClientQoSContext` | `0x4D8F813` | Context data |
| `RBX::Network::DeserializedClientQoSItem` | `0x4DB0D41` | Deserialized payload |

### secureHeartbeat method — RTTI `0x4D8F836`

Runs periodically. Failure triggers exit codes:
- `RBX_EXIT_QOS01` through `RBX_EXIT_QOS14` (14 distinct failure categories)

FFlag: `EnablePlatformQoSEmergency` at `0x55ADFBD` — emergency shutdown on QoS failure.

---

## 6. Device Integrity (Apple App Attest)

Apple device attestation for hardware-level trust verification.

### API surface

| Method | RTTI | Purpose |
|--------|------|---------|
| `getDeviceIntegrityToken` | `0x4DEF5DD` | Request attestation token |
| `getDeviceIntegrityTokenYield` | `0x4DEF71D` | Yielding variant |
| `deviceIntegrityAvailable` | `0x4DEF8D9` | Check availability |

Reflection names: `GetDeviceIntegrityToken`, `GetDeviceIntegrityTokenYield`,
`DeviceIntegrityAvailable`.

FFlag: `EnableAsyncDeviceIntegrityTokenRetreival` at `0x562DEEA`.

### Disconnect codes on failure

| Code | Reason |
|------|--------|
| 296 | `DisconnectRemoteAttestationUnsupported` |
| 297 | `DisconnectRemoteAttestationGeneralFailure` |
| 298 | `DisconnectRemoteAttestationTimeout` |
| 299 | `DisconnectRemoteAttestationOSOutOfDate` |
| 300 | `DisconnectRemoteAttestationBootValidationFailure` |

---

## 7. Physics Integrity Detection

### Elevated FPS Detection — `sub_26B7D6C` (244 bytes)

Speed hack detector. Reports at multiple thresholds:

| Threshold | Counter string |
|-----------|---------------|
| 65 | `ElevatedPhysicsFPSDetected_65` |
| 70 | `ElevatedPhysicsFPSDetected_70` |
| 80 | `ElevatedPhysicsFPSDetected_80` |
| 90 | `ElevatedPhysicsFPSDetected_90` |
| 100 | `ElevatedPhysicsFPSDetected_100` |
| — | `ElevatedPhysicsFPSDetected_SetMinimum` |

Reports to `"Game"` category via `sub_18EACBC`.

### Physics Simulation Telemetry — `sub_203C7A4` (1148 bytes)

Periodic integrity check tracking server-client divergence:

| Field | Description |
|-------|-------------|
| `TotalHashChecks` | Physics state hash comparisons |
| `TotalMispredictions` | Client-server prediction mismatches |
| `WorldStepsSimulatedThisEvent` | Steps in this reporting interval |
| `ResimulationCount` | Forced re-simulations |
| `ServerAuthorityMode` | Physics authority model |

Timer interval: `dword_6CE5EE0`.

### Animation Hash — `sub_2042F30` (1672 bytes)

Animation replication hash verification:
- Log: `[FLog::AnimationReplication] hashCheck: ...`
- Counters: `HashCheckCount`, `HashCheckRate`
- Physics counters: `MispredictCount`, `MispredictRate`, `FixedStepCount`
  from `sub_204CF54` (564 bytes)

---

## 8. Hash Verification Systems

### NetAsset Hash — `sub_3C3FB8` (1704 bytes)

MD5 hash validation of shared network assets:
- `"NetAsset Hash mismatch"` at `0x558DB51`
- `"Duplicate hash %s in shared NetAsset dictionary"` — duplicate detection
- `"Invalid NetAsset version"` — version validation

### Cache Hash Telemetry — `sub_9B8D60` (688 bytes)

Reports cache integrity metrics:
- `HashMismatches` — hash failures (offset +392)
- `CacheReadFailures` — cache read errors
- `DeserializationFailures` / `SerializationFailures`

### LR Hash Verification

Lightweight replication hash checks:
- `LrHashCheck` / `LrHashFail` counters
- Functions: `sub_840FF4` (3824B), `sub_9AD848` (2440B), `sub_2B1D2DC` (26336B)
- FFlag: `ReportLrHashMissTelemetryForRbxTransport`

### RCC Hash Exchange — `sub_DD29F8` (1504 bytes)

Roblox Cloud Compute hash verification:
- `RCCHashReceived` / `RCCHashTimeout` / `ExitWithoutRCCHash`
- Hash source tracking: `"None"`, `"Fallback"`, `"RCC"`
- Exit handler: `sub_DD3B2C` (316 bytes)

### Bouncing Script Detection — `sub_172B53C` (1600 bytes)

Script hash integrity: `BouncingScriptHashes`, `BouncingScriptPermyriad`, `ScriptHash`.

---

## 9. Cheat/Exploit Kick Handler — `sub_28F2C78` (3500 bytes)

Server-initiated kick for detected cheating. Cyclomatic complexity 110.

**Logic:**
- Processes script edits
- Formats `"AbuserID:{};{}"` strings
- Disconnect message: `"Cheating/Exploiting;"`
- Referenced from vtable at `0x6215288`

---

## 10. Encryption Layer

RakNet packet encryption monitoring:

| Component | Address | Purpose |
|-----------|---------|---------|
| `DecryptionFailDisconnectThreshold` | `0x57821DC` | FFlag: max failures before DC |
| `EncryptionFailThreshold` | `0x57821FE` | FFlag: encryption error threshold |
| `RakNetDecryptionFailure` | `0x5782014` | Counter |
| `LibcatDecryptionFailed` | `0x578359B` | Counter |
| `BitStreamReadBitsOverflowCheck` | `0x577E3EF` | FFlag: bounds check |

---

## 11. Additional Detection FFlags

| FFlag | Address | Purpose |
|-------|---------|---------|
| `ImprovedProximityPromptCheatDetection` | `0x57043D4` | Proximity prompt exploit detection |
| `PatchTeleportExploit` | `0x5725EF4` | Teleport exploit mitigation |
| `ClientSideUserHashing` | `0x56A9792` | Client-side user identity hashing |
| `StreamingIntegrityMode` | `0x55F3122` | Streaming data integrity enforcement |
| `VoiceChatEnableApiSecurityCheck` | `0x55B95BD` | Voice chat security validation |
| `RCCShouldUseObfuscatedByteCodeInTeamTestSignal` | `0x55EE924` | Obfuscated bytecode in team test |
