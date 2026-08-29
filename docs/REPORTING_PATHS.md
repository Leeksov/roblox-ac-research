# Reporting Paths & Disconnect Codes

How detection results are communicated to Roblox servers and how the client
is terminated when violations are detected.

---

## 1. Disconnect Code Table — `sub_4663E8C` (1756 bytes)

Master disconnect-reason-to-string mapper. Takes integer code, returns string.

### Security-relevant disconnect codes

| Code | String | Trigger |
|------|--------|---------|
| 257 | `DisconnectBadhash` | Hash verification failure |
| 258 | `DisconnectSecurityKeyMismatch` | Security key exchange failure |
| 259 | `DisconnectProtocolMismatch` | Protocol version mismatch |
| 263 | `DisconnectIllegalTeleport` | Teleport exploit detected |
| 264 | `DisconnectDuplicatePlayer` | Duplicate player connection |
| 265 | `DisconnectDuplicateTicket` | Duplicate auth ticket |
| 266 | `DisconnectTimeout` | Connection timeout |
| 268 | `DisconnectHashTimeout` | US14116 hash check timeout |
| 269 | `DisconnectLuaKick` | Script-level kick |
| 270 | `DisconnectOnRemoteSysStats` | Remote SysStats check failure |
| 273 | `DisconnectNewSecurityKeyMismatch` | Updated security key failure |
| 274 | `DisconnectEvicted` | Player evicted |
| 279 | `DisconnectBySecurityPolicy` | Security policy violation |
| 296 | `DisconnectRemoteAttestationUnsupported` | Device attestation unsupported |
| 297 | `DisconnectRemoteAttestationGeneralFailure` | Attestation error |
| 298 | `DisconnectRemoteAttestationTimeout` | Attestation timeout |
| 299 | `DisconnectRemoteAttestationOSOutOfDate` | OS too old for attestation |
| 300 | `DisconnectRemoteAttestationBootValidationFailure` | Boot validation failure |
| 304 | `DisconnectAndroidAnticheatKick` | Anti-cheat module kick |

---

## 2. Exit/Error Code Mapper — `sub_48E2258` (3132 bytes)

Maps exit codes to telemetry identifiers. Security-relevant:

| Identifier | String address | Description |
|------------|---------------|-------------|
| `RBX_ERROR_BADHASH` | `0x58E7932` | Hash verification failure |
| `RBX_ERROR_SECURITY_KEY_MISMATCH` | `0x58E7944` | Key exchange failure |
| `RBX_ERROR_NEW_SECURITY_KEY_MISMATCH` | `0x58E7ABB` | Updated key failure |
| `RBX_ERROR_HASH_TIMEOUT` | `0x58E7A75` | Hash check timeout |
| `RBX_ERROR_BY_SECURITY_POLICY` | `0x58E7B92` | Policy violation |
| `RBX_ERROR_NETWORK_SECURITY_FAILURE` | `0x58E7DB4` | Network security error |
| `RBX_ERROR_NETWORK_MISBEHAVIOR` | `0x58E7D96` | Network behavior anomaly |
| `RBX_ERROR_NETWORK_INTERNAL_FAILURE` | `0x58E7D5D` | Network internal error |
| `RBX_EXIT_ANTICHEAT` | `0x58E824C` | Anti-cheat triggered exit |
| `RBX_EXIT_QOS01`–`RBX_EXIT_QOS14` | `0x58E82A9`–`0x58E82F4` | Security heartbeat failures |

---

## 3. Crash Classification — `sub_4880184` (2588 bytes)

Previous-session crash classifier. Security categories:

- `Crash-Anticheat` at `0x5888B03` — anti-cheat triggered crash
- `AnticheatCrash` at `0x58BC506` — registered in `InitFunc_24433` (30880 bytes)
- `Inferred-OOM`, `Inferred-Uncategorized` — non-security fallbacks

---

## 4. Bytecode Signature Telemetry — `sub_172D184` (1280 bytes)

Fires on every bytecode signature verification. Reports:

| Field | Description |
|-------|-------------|
| `cr_sessionid` | Session ID |
| `cr_placeid` | Place ID |
| `cr_universeid` | Universe ID |
| `cr_userid` | User ID |
| `cr_source` | Bytecode source |
| `cr_size` | Bytecode size |
| `cr_env` | Environment |
| `cr_err` | Verification error code |
| `cr_sigver` | Signature version |
| `cr_sigid` | Signature ID |

---

## 5. Version/Signature Telemetry — `sub_172D888` (728 bytes)

Sends counters during signature version detection:

| Telemetry code | Meaning |
|---------------|---------|
| 900 | No signature found |
| 901 | Negative version (invalid) |
| 902 | Version 0 detected |
| 903 | Version > 0 detected |

Fields: `"placeid"`, `"version"`, `"code"`, `"decrcc"`, `"declocal"`.

---

## 6. PreHash Telemetry — `sub_8CAC60` (440 bytes)

Bytecode connection hash statistics. Sampled: `hash(result) % 10000 < threshold`.

| Field | Description |
|-------|-------------|
| `gameid` | Game identifier |
| `postEnLength` | Post-encryption bytecode length |
| `postHash` | Post-encryption hash |
| `preEnLength` | Pre-encryption bytecode length |
| `preHash` | Pre-encryption hash |
| `cap` | Capability flags |
| `verMin` / `verMax` | Version range (byte) |
| `numSff` | Number of SFF entries (u16) |

Counter: `debugLuaConnIssue`. Sampling threshold at `dword_6CB86C8`.

---

## 7. Encryption Failure Reporting

RakNet packet-level encryption monitoring:

| FFlag/Counter | Address | Purpose |
|---------------|---------|---------|
| `DecryptionFailDisconnectThreshold` | `0x57821DC` | Max failures before DC |
| `EncryptionFailThreshold` | `0x57821FE` | Encryption error threshold |
| `RakNetDecryptionFailure` | `0x5782014` | Decryption failure counter |
| `RakNetEncryptionFailureReportHundredthsPercent` | `0x578202C` | Sampling rate |
| `LibcatDecryptionFailed` | `0x578359B` | Libcat-specific failure |
| `DecryptionFailed` | `0x57835B2` | Generic decryption failure |

---

## 8. Security Alerting Telemetry Migration

FFlags controlling telemetry pipeline migration (from `InitFunc_2337` at `0x65395C`):

| FFlag | Global | Purpose |
|-------|--------|---------|
| `MigrateGameEngineSecurityAlertingTelemetryToV2` | `byte_6CB3078` | Migrate security alerts to v2 |
| `DisableGameEngineSecurityAlertingLegacyTelemetryMetrics` | `byte_6CB3090` | Kill legacy metrics |
| `MigrateGameEngineRccAlertingTelemetryToV2` | `byte_6CB3108` | Migrate RCC alerts |
| `DisableGameEngineRccAlertingLegacyTelemetryMetrics` | `byte_6CB3120` | Kill legacy RCC metrics |
| `MigrateExternalAntiCheatModuleTelemetryToV2` | `byte_6CB3198` | Migrate external AC |
| `DisableExternalAntiCheatModuleLegacyTelemetryMetrics` | `byte_6CB31B0` | Kill legacy AC metrics |

---

## 9. Generic Challenge Service

HTTP-based challenge/captcha system:

- Class: `RBX::GenericChallengeService`
- Headers: `rblx-challenge-id`, `rblx-challenge-metadata`, `rblx-challenge-type`
- Events: `ChallengeRequiredEvent`, `ChallengeCompletedEvent`, `ChallengeAbandonedEvent`,
  `ChallengeInvalidatedEvent`, `ChallengeLoadedEvent`
- FFlag: `EnableGenericChallengeResponseHandling` at `0x55972FD`

---

## 10. RUPP Token System

Connection-time token exchange:

- `RBX::Rupp::ClientRuppGenerator` — client token generator
- `RBX::Rupp::ServerRuppGenerator` — server token generator
- `RBX::Rupp::RuppTokenProcessor` — validation
- `RBX::Rupp::TokenTlv` — TLV wire format
- Counter: `ClientRuppDeserializationError` at `0x577F277`

---

## 11. Moderation Result Categories — `sub_19963F0`

Server-side moderation verdict enum:

| Value | Category |
|-------|----------|
| 0 | `ViolationDetected` |
| 1 | `Borderline` |
| 2 | `NoViolationDetected` |
