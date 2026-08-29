# Reaper.framework — Full Reverse

**Verdict: NOT anti-cheat.** Reaper is the [Emerge Tools](https://www.emergetools.com/) dead-code
detection SDK (`com.emergetools.reaper`). It collects which ObjC/Swift types are actually
instantiated at runtime and reports them via a callback — used for tree-shaking analytics,
not security.

---

## Binary info

| Field | Value |
|-------|-------|
| Path | `Frameworks/Reaper.framework/Reaper` |
| Size | 107,856 bytes |
| Arch | arm64 |
| Bundle ID | `reaper-ios.Reaper` |
| Min iOS | 13.0 |
| SDK | iPhoneOS 26.2 (Xcode 26.3) |

## Classes

| Class | Purpose |
|-------|---------|
| `EMGReaper` | Main ObjC singleton — lifecycle, scan, report |
| `NameFinder` | Swift helper — resolves type metadata pointers to demangled names |

---

## Function-by-function analysis

### `+[EMGReaper sharedInstance]`

Standard `dispatch_once` singleton. Stores instance at static `sSharedInstance`.

### `-[EMGReaper startWithHandler:]`

Entry point. Called once via `dispatch_once`.

**Logic:**
1. Check iOS version via `NSProcessInfo.operatingSystemVersion`
2. Only proceeds if iOS **15–18** (version check: `sub x8, version, #15; cmp x8, #4` + `cmp version, #26`)
3. If outside range → early return (no scanning on older/newer iOS)
4. Store the handler callback block
5. Create serial dispatch queue `"com.emergetools.reaper"` with QoS `.background`
6. Create `NSMutableSet` for deduplication (`_usedTypesReported`)
7. Register for `UIApplicationDidEnterBackgroundNotification` → `-didEnterBackground`
8. Register for `UIApplicationWillTerminateNotification` → `-willTerminate`

### `-[EMGReaper didEnterBackground]`

Triggers `-enqueueUploadReport`.

### `-[EMGReaper enqueueUploadReport]`

Dispatches `-uploadReport` asynchronously on the background queue.

### `-[EMGReaper uploadReport]` (main scan function)

**Logic:**
```
1. count = _dyld_image_count()
2. appPath = NSBundle.mainBundle.executableURL
                     .URLByDeletingLastPathComponent.path
3. allTypes = NSMutableArray()
4. for i in 0..<count:
     name = _dyld_get_image_name(i)          // e.g. "/path/to/Roblox.app/Roblox"
     nameStr = [NSString stringWithUTF8String:name]
     if [nameStr hasPrefix:appPath]:          // ← ONLY scans app-bundle binaries
       header = _dyld_get_image_header(i)
       types = [self usedTypesInBinary:header]
       [allTypes addObjectsFromArray:types]
5. newTypes = filter(allTypes, not in _usedTypesReported)
6. if newTypes.count > 0:
     [_usedTypesReported addObjectsFromArray:newTypes]
     handler(newTypes)                        // callback to Roblox
```

**Key detail:** The `hasPrefix:appPath` filter means Reaper **only scans binaries inside
the .app bundle** (Roblox, RobloxLib, Reaper itself, Backtrace, Persona2). It does **not**
scan system frameworks, injected dylibs, or tweaks. This confirms it is not an injection
detector.

### `-[EMGReaper usedTypesInBinary:]` (type collector)

Combines ObjC and Swift type scanning for a single mach_header.

**Logic:**
```
1. result = [self usedSwiftTypesInBinary:header]  // Swift types first
2. section = get_objc_section(header, "__objc_classlist", &size)
3. for each class pointer in section:
     metaclass = object_getClass(cls)
     // Skip Swift-bridged classes (bit 5 of metaclass RO flags)
     if metaclass.ro_data.flags & 0x20: continue
     // Check class is "realized" (actually loaded, not just declared)
     if !(cls.data & 0x3): continue
     // Check type descriptor: kind mask 0x10030080, must be 0x10000
     descriptor = cls + 0x40
     if (descriptor.kind & 0x10030080) != 0x10000: continue
     // Check singleton has been used
     kind = descriptor.kind & 0x1F
     if kind - 0x10 <= 2:  // class/struct/enum
       offset = lookup_table[kind - 0x10]
       if !(descriptor + offset).value: continue
     // Get class name
     name = class_getName(cls)
     [result addObject:[NSString stringWithUTF8String:name]]
4. return result
```

### `-[EMGReaper usedSwiftTypesInBinary:]` (Swift type scanner)

**Logic:**
```
1. section = getsectiondata(header, "__TEXT", "__swift5_types", &size)
2. for each 4-byte relative pointer in section:
     descriptor = resolve_relative_pointer(ptr)
     kind = descriptor.flags & 0x1F
     // Only struct (0x11) and class (0x12)
     if kind - 0x11 > 1: continue
     // Check context descriptor flags
     if (descriptor.flags & 0x10030080) != 0x10000: continue
     // Check singleton has been instantiated
     accessor = descriptor.accessFunction
     if !accessor.pointee: continue
     // Resolve name
     metadata = call accessor()
     name = [NameFinder getNameWithPtr:metadata qualified:true]
     name = removeUnknownContext(name)  // strip "(unknown context at $...)"
     [result addObject:name]
3. return result
```

### `NameFinder.getName(ptr:qualified:)` (Swift)

Swift static method. Takes a metadata pointer and returns the demangled Swift type name.
Uses `swift_getTypeContextDescriptor` and `swift_getObjCClassMetadata` internally.

### `removeUnknownContext()` (C++)

Strips `(unknown context at $XXXX)` patterns from demangled names using
`NSRegularExpression` with pattern `\.\(unknown context at \$[0-9a-fA-F]+\)\.`.

### `get_objc_section()` (C++)

Wrapper around `getsectiondata()` that reads Mach-O section data from a `mach_header_64`.

### `is_swift_singleton_used()` / `is_swift_singleton_attributable()` (C++)

Check whether a Swift type descriptor's singleton metadata has been instantiated.

---

## System imports used

| Import | Purpose |
|--------|---------|
| `_dyld_image_count` | Count loaded images |
| `_dyld_get_image_name` | Get image path (for `hasPrefix` filter) |
| `_dyld_get_image_header` | Get mach_header for section reading |
| `_dyld_register_func_for_add_image` | NOT called by Reaper — present in Swift runtime only |
| `_getsectiondata` | Read `__swift5_types` and `__objc_classlist` sections |
| `_dlsym` | Swift runtime internal use only |
| `_class_getName` | Get ObjC class name string |
| `_object_getClass` | Get metaclass for flag checking |
| `_memcmp` | String comparison |

**Not imported:** `ptrace`, `sysctl`, `task_info`, `access`, `stat`, `getenv`, `fork`,
`sandbox_check`, `csops`. No security-sensitive syscalls whatsoever.

---

## Instance variables

| Ivar | Type | Purpose |
|------|------|---------|
| `_queue` | `NSObject<OS_dispatch_queue>` | Background serial queue |
| `_usedTypesReported` | `NSMutableSet` | Deduplication set |
| `_handleTypes` | block | Callback for reporting new types |

---

## Conclusion

Reaper scans only app-bundle binaries, collects instantiated ObjC/Swift type names,
deduplicates across background-entry events, and reports deltas via a callback. It is
a performance/size optimization tool, not a security module. The `hasPrefix:appPath`
filter explicitly excludes injected dylibs from scanning.
