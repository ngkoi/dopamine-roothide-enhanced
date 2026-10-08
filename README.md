# dopahide-enhanced

An enhanced, high-performance edition of **Dopamine (Roothide)** for iOS 15.0 - 16.7.x (arm64 & arm64e).

`dopahide-enhanced` resolves the latency, micro-stutters, and UI frame drops historically associated with Roothide's app stealth trade-offs, delivering the smooth responsiveness of vanilla Rootless Dopamine while preserving **100% of Roothide's stealth and jailbreak detection bypass capabilities**.

---

## ⚡ Performance Optimizations

### 1. In-Process PID & Blacklist Caching
- **The Problem:** In standard Roothide, system services (`lsd`, `cfprefsd`, `SpringBoard`) queried `launchd` synchronously over XPC on virtually every app launch, preference read, and URL query via `jbclient_blacklist_check_pid`.
- **The Fix:** Implemented a thread-safe, 256-slot atomic PID cache (`cached_blacklist_check_pid()`) backed by kernel `proc_get_pidversion()` verification. Cache hits are instantaneous and require zero IPC.

### 2. Elimination of High-Frequency Plist & Flash I/O
- **The Problem:** `RootHideConfig.plist` and app bundle `Info.plist` files were read and parsed from disk repeatedly during process checks, URL scheme queries, and bundle lookups.
- **The Fix:** Introduced `mtime`-validated in-memory caching for `RootHideConfig.plist` and an `NSCache` for bundle identifier lookups, completely eliminating repetitive disk reads and XML deserialization on hot paths.

### 3. Regex & Path Matching Overhaul in `cfprefsd`
- **The Problem:** `cfprefsd` recompiled an `NSRegularExpression` (`^(/private)?/var/(\w+)/Library/Preferences/`) on every preference access across the entire operating system, while allocating a 20-item `NSArray` for exclusion lookups.
- **The Fix:** Replaced runtime regex compilation with zero-allocation C-string path prefix parsing (`isPreferencesPath()`) and migrated exclusion lists to a static, pre-hashed `NSSet` ($O(1)$ lookup).

### 4. Fast-Path Spawn Kernel Patching
- **The Problem:** On every process spawn, `launchdhook` suspended the child and made a synchronous IPC round-trip to `jailbreakd` (`JBD_MSG_SPAWN_PATCH_CHILD`) simply to set code-signing flags in the kernel.
- **The Fix:** When full dyld patching is not required, `launchdhook` directly applies `proc_patch_csflags()` using launchd's existing kernel primitives, bypassing the IPC round-trip and context switch.

### 5. Stripped Verbose Logging in Release Daemons
- **The Problem:** Core system daemons (`lsd`, `cfprefsd`, `SpringBoard`) produced dozens of synchronous `NSLog()` calls to syslog on every operation even in production builds.
- **The Fix:** Guarded all logging under `#ifdef DEBUG`, completely stripping log evaluation from release binaries and saving significant CPU cycles.

---

## 🛠️ Building dopahide-enhanced

### Option A: GitHub Actions (Recommended)
1. Fork this repository.
2. Go to the **Actions** tab.
3. Select **"*** build dopahide-enhanced tipa ***"** and click **Run workflow**.
4. Once completed, download the artifact `dopahide-enhanced-<version>.tipa`.

### Option B: Local Build (macOS)
Refer to [.github/workflows/roothide.yml](.github/workflows/roothide.yml) for setup dependencies (Theos, Procursus toolchain, trustcache, libarchive).
```bash
make -j$(sysctl -n hw.physicalcpu)
```

---

## 👥 Credits
- **opa334** - Dopamine
- **roothideDev** - Roothide architecture & jailbreak stealth bypass
- **évelyne** - ElleKit
- **ngkhoi** - `dopahide-enhanced` performance architecture & optimizations
- See [Credits.plist](Application/Dopamine/UI/Settings/Credits.plist) for full contributor list.


