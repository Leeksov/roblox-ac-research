# Security-Relevant FFlags

All FFlags identified that control anti-cheat, integrity verification,
telemetry, and security behavior. Grouped by subsystem.

---

## Bytecode Verification

| FFlag | String address | Global | Init func | Purpose |
|-------|---------------|--------|-----------|---------|
| `RbxmBytecodeDisablePrehash` | `0x568BCFD` | `byte_6CDA8B0` | `0x172CA24` | Disable pre-hashing in RBXM files |
| `LoadBytecodeWithSignatureAsHashKey` | `0x568BD18` | `byte_6CDA8C8` | `0x172CA58` | Use signature as hash key |
| `RemoveBytecodeCopyOnLoad` | `0x568BD38` | `byte_6CDA8E0` | — | Skip bytecode buffer copy on load |
| `DebugSkipLoadAssetWithBytecodeVerification` | `0x56F850C` | `byte_6CED8F0` | `0x22D9F08` | **Skip ALL bytecode verification** |
| `LoadAssetWithBytecodeAsyncEnabled` | — | `byte_6CED8D8` | — | Async bytecode loading |

## Signature Verification (DataModel)

| FFlag | String address | Init func | Purpose |
|-------|---------------|-----------|---------|
| `DebugSkipPostTtiSignatureVerification` | `0x579DA5B` | `0x300EA48` | Skip post-TTI patch verification |
| `DebugBypassTeamTestSignatureVerification` | `0x559AD8C` | `0x4C65D0` | Skip team-test signature check |
| `RCCShouldUseObfuscatedByteCodeInTeamTestSignal` | `0x55EE924` | — | Obfuscate bytecode in team test |

## External Anti-Cheat

| FFlag | String address | Global | Purpose |
|-------|---------------|--------|---------|
| `MigrateExternalAntiCheatModuleTelemetryToV2` | `0x55B48B9` | `byte_6CB3198` | Migrate AC telemetry to v2 |
| `DisableExternalAntiCheatModuleLegacyTelemetryMetrics` | `0x55B48E5` | `byte_6CB31B0` | Kill legacy AC metrics |

## Security Alerting Telemetry

| FFlag | String address | Global | Purpose |
|-------|---------------|--------|---------|
| `MigrateGameEngineSecurityAlertingTelemetryToV2` | — | `byte_6CB3078` | Migrate security alerts |
| `DisableGameEngineSecurityAlertingLegacyTelemetryMetrics` | — | `byte_6CB3090` | Kill legacy security metrics |
| `MigrateGameEngineRccAlertingTelemetryToV2` | — | `byte_6CB3108` | Migrate RCC alerts |
| `DisableGameEngineRccAlertingLegacyTelemetryMetrics` | — | `byte_6CB3120` | Kill legacy RCC metrics |

## Integrity Checked Processor

| FFlag | String address | Init func | Purpose |
|-------|---------------|-----------|---------|
| `IntegrityCheckedProcessorDisableAllAdditions` | `0x56CE16E` | `0x1F9089C` | Disable integrity-checked telemetry pipeline |

## Encryption / Network

| FFlag | String address | Purpose |
|-------|---------------|---------|
| `DecryptionFailDisconnectThreshold` | `0x57821DC` | Max decryption failures before disconnect |
| `EncryptionFailThreshold` | `0x57821FE` | Encryption error threshold |
| `RakNetEncryptionFailureReportHundredthsPercent` | `0x578202C` | Sampling rate for failure reports |
| `BitStreamReadBitsOverflowCheck` | `0x577E3EF` | BitStream bounds checking |

## Disconnect / Reporting

| FFlag | String address | Purpose |
|-------|---------------|---------|
| `DisconnectOnISRSendThrowReportSecs` | `0x55D7570` | Timeout before DC on ISR send throw |
| `DisconnectOnISRSendThrowThrottle` | `0x55D7593` | Throttle for ISR send throw |
| `DebugEnableSendItemLimitDisconnect` | `0x55E2651` | Debug: send item limit DC |
| `EnableSendItemLimitDisconnect` | `0x55E268B` | Production: send item limit DC |
| `DisconnectReasonDiagThrottlePercent` | `0x55E611B` | DC reason telemetry sampling |
| `StopReportingDisconnectReasonToOldCounters` | `0x55E64C8` | Counter migration |
| `ReportDisconnectTelemetryForRbxTransport` | `0x55E673B` | RbxTransport DC telemetry |
| `ReportLrHashMissTelemetryForRbxTransport` | `0x55E6712` | LR hash miss telemetry |

## Device Integrity

| FFlag | String address | Purpose |
|-------|---------------|---------|
| `EnableAsyncDeviceIntegrityTokenRetreival` | `0x562DEEA` | Async device attestation |

## QoS / Heartbeat

| FFlag | String address | Purpose |
|-------|---------------|---------|
| `EnablePlatformQoSEmergency` | `0x55ADFBD` | QoS emergency shutdown |

## Exploit Detection

| FFlag | String address | Init func | Purpose |
|-------|---------------|-----------|---------|
| `ImprovedProximityPromptCheatDetection` | `0x57043D4` | `0x23D35E0` | Proximity prompt exploit detection |
| `PatchTeleportExploit` | `0x5725EF4` | `0x25BB164` | Teleport exploit mitigation |
| `ClientSideUserHashing` | `0x56A9792` | `0x195C09C` | Client-side user identity hash |
| `ClientSideUserHashingTelemetryThrottleHundredthsPercent` | `0x56A975A` | — | Throttle for hash telemetry |

## Challenge / Moderation

| FFlag | String address | Purpose |
|-------|---------------|---------|
| `EnableGenericChallengeResponseHandling` | `0x55972FD` | Challenge/captcha system |
| `VoiceChatEnableApiSecurityCheck` | `0x55B95BD` | Voice chat security check |

## Streaming

| FFlag | String address | Purpose |
|-------|---------------|---------|
| `StreamingIntegrityMode` | `0x55F3122` | Streaming data integrity mode |
| `ServerStreamingIntegrityMode` | `0x55ECBDE` | Server-side integrity mode |
