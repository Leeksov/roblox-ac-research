# Bytecode Signature Verification Pipeline

The bytecode authentication system verifies the cryptographic integrity of Luau bytecode
before execution. It uses a GF(2^128) polynomial hash with pre-computed multiplication
tables embedded in the binary.

---

## Call Chain

```
luau_load (sub_43E2CE8, 5712B)
  └─ bytecode_authenticate (sub_172CC78, 520B)         @ call site 0x43E2E58
       ├─ ensure_global_init (sub_172CEA0)
       ├─ parse_signature_trailer (sub_172CED0, 640B)
       │    ├─ detect_sig_v1 (sub_172DEC0, 128B)       — XOR magic 0xC432/0x6A
       │    ├─ detect_sig_v2 (sub_172DF40, 92B)        — XOR magic 0x94A9D232
       │    ├─ version_telemetry (sub_172D888, 728B)    — codes 900-903
       │    └─ verify_hash_galois (sub_172DC9C, 524B)   — GF(2^128) core
       ├─ telemetry_report (sub_172D184, 1280B)         — cr_* crash fields
       └─ stats_increment (sub_172D714, 96B)            — atomic counters
```

---

## 1. bytecode_authenticate — `sub_172CC78` (520 bytes)

The top-level orchestrator. Called from `luau_load` with the bytecode buffer.
Returns `true` (nonzero) on verification **failure**, `false` on success.

### Decompiled logic

```c
// 1. One-time init of global state
sub_172CEA0(a1);  // initializes xmmword_673ED18

// 2. Parse cryptographic trailer from bytecode end
int version = sub_172CED0(&xmmword_673ED18, bytecode, size, &trailer_info);

// 3. Obfuscated version check via multi-stage lookup
//    T1 @ 0x4EBE7C4 (10 bytes, index permutation)
//    T2 @ 0x4EBE7CE (10 bytes, second permutation)
//    T3 @ 0x4EBE7D8 (10 DWORDs, value table)
v8 = T3[ T2[ T1[(int)version] ] % 10 ] / 7 - 157;

// 4. Conditionally clear capability bit on the lua_State
//    *(*(L+48) + 1232) &= ~0x40000000
//    L+48 = global_State; offset 1232 (0x4D0) = capability flags
if (-991146299 * (v8 / 0xA9) >= 0x13B13B14)
    *(DWORD*)(*(QWORD*)(a1 + 48) + 0x4D0) &= ~0x40000000u;

// 5. Build 8-bit flags bitmask from divisor table
//    Divisors @ 0x4EBE7A0: {0xD, 0xA9, 0x895, 0x6F91, 0x5AA5D, ...}
uint8_t flags = 0;
for (int i = 0; i < 8; i++)
    flags |= ((-991146299 * (v8 / divisors[i]) > 0x13B13B13) << i);

// 6. Send telemetry with computed flags
sub_172D184(context, bytecode, &trailer_info, version, flags);

// 7. Final pass/fail via another obfuscated comparison
bool failed = (v8 / 0x895 - 13 * v14) != 0;
sub_172D714(&xmmword_673ED18, version, failed);  // stats
return failed;
```

### Key constants

| Address | Data | Purpose |
|---------|------|---------|
| `0x4EBE7C4` | `09 09 01 00 02 05 02 00 05 02` | Index permutation T1 |
| `0x4EBE7CE` | `08 03 04 09 01 05 02 07 00 06` | Index permutation T2 |
| `0x4EBE7D8` | 10 DWORDs: `0x44FD, 0x405E, 0x0945, ...` | Value table T3 |
| `0x4EBE7A0` | 8 DWORDs: `0xD, 0xA9, 0x895, 0x6F91, ...` | Exponential divisors |
| `0x4EBE800` | 10 QWORDs: `4, 8, 8, 16, 20, 24, 28, 32, 36, 40` | Stats struct offsets |

The magic constant `-991146299` (`0xC4EC4EC5` unsigned) is a compiler-generated
multiplication constant for division-by-constant optimization.

### Capability bit clear

At `0x172CD78`, the function clears bit 30 (`0x40000000`) from:
```
*(DWORD*)(*(QWORD*)(lua_State + 48) + 1232)
```
- `lua_State + 48` → `global_State*` (in Roblox's layout, offset 0x30)
- `global_State + 1232` (`0x4D0`) → execution permission/capability flags

This **removes a specific VM capability** when the bytecode's signature status
meets certain conditions — part of the anti-tamper system that adjusts runtime
permissions based on bytecode authenticity.

---

## 2. parse_signature_trailer — `sub_172CED0` (640 bytes)

Extracts the cryptographic signature from the END of the bytecode buffer.

### Trailer formats

| Version | Trailer size | Key offset | Magic check |
|---------|-------------|------------|-------------|
| 0 | 40 bytes | +4 | `0x94A9D232` (XOR of two DWORDs) |
| 1 | 24 bytes | +16 | `0xC432` / `0x6A` (XOR of individual bytes) |
| 2 | — | — | Unsupported (returns 5) |

### Logic

```c
if (bytecode_size < 0x118)  return error;  // need ≥280 bytes

int version = detect_version(bytecode, size);  // tries v1 then v2
if (version < 0)    return 3;   // negative = invalid
if (version > max)  return 4;   // exceeds dword_6CDA9E8
if (version > 1)    return 5;   // unsupported future version

// XOR-decode 4 bytes of the signing key
trailer_start = size - (version == 0 ? 40 : 24);
key_offset    = version == 0 ? 4 : 16;
decoded_key   = XOR(bytecode[trailer_start + key_offset], bytecode[trailer_start]);

// Minimum bytecode size check (256–1024 range, config at dword_6CDA9B8)
if (trailer_start < clamp(dword_6CDA9B8, 256, 1024))  return error;

// Extract 24 bytes of signing info
memcpy(output + 8, bytecode + trailer_start, 24);

// Version 1: check magic signature ID 0x74110D70
if (version >= 1 && output->sig_id != 0x74110D70)  return 9;

// Compute hash of bytecode body (everything before trailer)
hash = compute_hash(bytecode, trailer_start, 32);

// Dispatch verification
if (version == 1 && byte_6CDAA00 == 1)
    return verify_hash_galois(hash, decoded_key, sig_data);
else
    return 0;  // verification disabled by config
```

### Configuration globals

| Address | Type | Purpose |
|---------|------|---------|
| `byte_6CDAA00` | bool | Signature verification enforcement toggle (1 = enforce) |
| `dword_6CDA9D0` | int | Minimum signature version required |
| `dword_6CDA9B8` | int | Minimum bytecode size (clamped 256–1024) |
| `dword_6CDA9E8` | int | Maximum supported signature version |

---

## 3. verify_hash_galois — `sub_172DC9C` (524 bytes)

The core cryptographic verification using **Galois Field GF(2^128)** polynomial hashing.

### Pre-computed tables

On first call, loads 99,084 bytes of GF lookup tables from embedded data at `0x4EA6494`
into globals at `0x673EC90`–`0x673ECF0` (three table pointers). Tables hold 8,257 entries
of 12-byte data for the field multiplication.

Total table storage: 132,112 bytes (`0x20410`) required for verification.

### Algorithm

```c
// Initialize: load pre-computed GF tables (one-time)
if (!initialized)
    init_gf_tables(&tables_673EC90, &data_4EA6494, 99084);

// Need 0x20410 bytes of table data
if (table_end - table_start < 0x20410)  return 7;  // tables not ready

// Start with initial state from table
int8x16_t hash = *(int8x16_t*)table_start;

// Phase 1: Simple XOR with two sub-tables per key byte
for each byte b in 16-byte key:
    if (b != 0)
        hash ^= table1[offset + b] ^ table2[offset + b];

// Phase 2: Extended Galois multiplication with cross-byte interactions
for (i = 0..15):
    if (key[i] != 0):
        for (j = 0..7):
            if (bit j of key[i] is set) && (i != 0):
                for (k = 0..i-1):
                    if (key[k] != 0):
                        hash ^= table3[complex_index(j, i, k, key[k])];

// Final comparison: 12 bytes (8 + 4), big-endian
computed_hi = bswap64(hash.u64[0]);
expected_hi = bswap64(*(uint64*)(decoded_sig + 4));
computed_lo = bswap32(hash.u32[2]);
expected_lo = bswap32(*(uint32*)(decoded_sig + 12));

return (computed_hi == expected_hi && computed_lo == expected_lo) ? 0 : 7;
```

Return 0 = hash matches (pass). Return 7 = hash mismatch (fail).

---

## 4. Version detection functions

### detect_sig_v1 — `sub_172DEC0` (128 bytes)

```c
if (size < 24 || *data == 0)  return -1;
// XOR last 24 bytes with last 4 bytes, check for magic
if (((data[size-24] ^ data[size-4]) | ...) ^ 0xC432 | ... ^ 0x6A) != 0)
    return -1;
return data[size-21] ^ data[size-1];  // extracted version
```

### detect_sig_v2 — `sub_172DF40` (92 bytes)

```c
if (size < 40 || *data == 0)  return -1;
decoded = XOR(*(DWORD*)(data + size - 40), *(DWORD*)(data + size - 32));
return (decoded == 0x94A9D232) ? 0 : -1;
```

---

## 5. Telemetry reporter — `sub_172D184` (1280 bytes)

Fires when signature verification completes. Crash-report fields:

| Field | Description |
|-------|-------------|
| `cr_sessionid` | Session identifier |
| `cr_placeid` | Place ID |
| `cr_universeid` | Universe ID |
| `cr_userid` | User ID |
| `cr_source` | Bytecode source identifier |
| `cr_size` | Bytecode size |
| `cr_env` | Environment |
| `cr_err` | Error code from verification |
| `cr_sigver` | Signature version detected |
| `cr_sigid` | Signature ID from trailer |

---

## 6. Stats counters — `sub_172D714` (96 bytes)

Atomic increments on global structure at `xmmword_673ED18`:

- Always: increment `result[0]` (total attempts)
- If failed: increment `result[3]` (failure count)
- Per-version: increment at `T_offsets[version]` if `(0x3FB >> version) & 1`
  - Bitmask `0x3FB = 0b1111111011` → counters for versions 0,1,3,4,5,6,7,8,9 (not 2)

---

## 7. Related FFlags

| FFlag | Global | Init func | Purpose |
|-------|--------|-----------|---------|
| `RbxmBytecodeDisablePrehash` | `byte_6CDA8B0` | `0x172CA24` | Disable pre-hashing in RBXM |
| `LoadBytecodeWithSignatureAsHashKey` | `byte_6CDA8C8` | `0x172CA58` | Use signature as hash key |
| `RemoveBytecodeCopyOnLoad` | `byte_6CDA8E0` | — | Skip bytecode copy |
| `DebugSkipLoadAssetWithBytecodeVerification` | `byte_6CED8F0` | `0x22D9F08` | **Skip ALL verification** |
| `DebugSkipPostTtiSignatureVerification` | — | `0x300EA48` | Skip post-TTI verify |
| `DebugBypassTeamTestSignatureVerification` | — | `0x4C65D0` | Skip team-test verify |

---

## 8. Patch-level verification (DataModel)

Separate from bytecode auth, the DataModel patch system verifies game
updates using Blake2b or Blake3:

| Function | Size | Purpose |
|----------|------|---------|
| `sub_2FFFDB0` | 1584B | `deserializeAndVerifyPatch` — main entry |
| `sub_2FFC4DC` | 736B | `deferSignatureCheck` — 15s deferred verify |
| `sub_300EA48` | 3800B | Post-TTI signature verification |

Player hydration uses a hardcoded key:
`8Nu7Er7LsbQpihVC+ijfEbbRFzj+Kikw9McFEZdFSt4=` (stored at `qword_6CE9D38`).
