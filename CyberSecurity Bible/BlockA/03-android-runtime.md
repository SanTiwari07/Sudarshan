# 03 - Android Runtime (ART)

> **Chapter ID:** `CH03` · **Block:** A (Foundations) · **Status:** Stable
> **Tags:** `#art` `#dalvik` `#dex2oat` `#classloader` `#reflection` `#dynamic-code-loading` `#jni` `#hidden-api`
> **Last Updated:** 2026-08-05 · **Version:** 1.0.0
> **Prerequisites:** [Ch 01](01-android-internals.md), [Ch 02](../apk/02-apk-architecture.md)

---

## Table of Contents

1. [Why the runtime is an attack surface](#1-why-the-runtime-is-an-attack-surface)
2. [Dalvik → ART: the history that still matters](#2-dalvik--art-the-history-that-still-matters)
3. [Compilation: dex2oat, JIT, AOT, and profiles](#3-compilation-dex2oat-jit-aot-and-profiles)
4. [The compiled artifacts: .oat, .vdex, .art](#4-the-compiled-artifacts-oat-vdex-art)
5. [Class loading](#5-class-loading)
6. [Dynamic code loading - the technique that breaks static analysis](#6-dynamic-code-loading--the-technique-that-breaks-static-analysis)
7. [Reflection](#7-reflection)
8. [Non-SDK (hidden API) restrictions](#8-non-sdk-hidden-api-restrictions)
9. [JNI and native code](#9-jni-and-native-code)
10. [Garbage collection and memory (briefly, and why you care)](#10-garbage-collection-and-memory-briefly-and-why-you-care)
11. [Detection logic for SUDARSHAN](#11-detection-logic-for-sudarshan)
12. [Limitations, edge cases, false positives](#12-limitations-edge-cases-false-positives)
13. [Engineering tips](#13-engineering-tips)
14. [Judge Insights](#14-judge-insights)
15. [Interview Insights](#15-interview-insights)
16. [Cross-references](#16-cross-references)
17. [References](#17-references)

---

## 1. Why the runtime is an attack surface

Static analysis assumes the code you can see is the code that runs. **The runtime is where
that assumption dies.**

Three runtime capabilities, all legitimate, all abused:

1. **Class loaders** can load DEX from a file, an asset, or a byte array in memory.
2. **Reflection** can call any method by name string, defeating call-graph analysis.
3. **JNI** can execute arbitrary native code that no Java decompiler will ever show you.

Chain them and you get the standard evasion pipeline:

```
  Decompiled Java shows:            What actually happens:

  Class.forName(decrypt(x))    ──►  loads a class whose name is
     .getMethod(decrypt(y))         computed at runtime from an
     .invoke(...)                   AES-decrypted string
                                          │
  ...nothing else visible                 ▼
                                    InMemoryDexClassLoader over a
                                    payload decrypted from assets/
                                          │
                                          ▼
                                    Full banking-trojan capability
                                    that never touched classes.dex
```

If you cannot explain that diagram to a judge, you cannot explain why static analysis alone
is insufficient - which is the central architectural argument for SUDARSHAN's fused
pipeline. → [Ch 23](../sudarshan/23-detection-pipeline.md)

---

## 2. Dalvik → ART: the history that still matters

### WHAT changed

| | Dalvik (Android 1.0–4.4) | ART (Android 5.0+, API 21) |
|---|---|---|
| Execution | Interpret + **JIT** (from 2.2) | **AOT** at install (5.0–6.0) → **hybrid JIT+AOT** (7.0+) |
| Compile time | At runtime, every run | At install / in background / profile-guided |
| Artifact | `.odex` (optimised DEX) | `.oat` + `.vdex` + `.art` |
| Startup | Slower (JIT warm-up) | Faster (pre-compiled hot paths) |
| Battery/CPU | Recompiles constantly | Compile once, reuse |
| Install time | Fast | Slow on 5.0/6.0 (full AOT) - fixed in 7.0 |

Both are **register-based** VMs executing **DEX bytecode** - this is the key difference
from the JVM, which is stack-based. That's why you can't run a `.class` file on Android and
why `d8` exists.

### WHY the change happened

Dalvik's JIT meant every app paid a warm-up cost on every launch, forever. ART's original
answer (Android 5.0) was: compile everything to native code at install time. That worked
but made installs and OTA updates brutally slow - a full system update recompiled every app
on the device, sometimes for 20+ minutes.

Android 7.0 (Nougat) introduced the **hybrid** model that still stands: install fast with
no compilation, interpret and JIT at first, *profile* which methods are actually hot, then
AOT-compile only those in the background when the device is idle and charging. Best of both.

### WHY you still care about Dalvik

- Legacy samples and old research reference `.odex` files and Dalvik-era behaviour.
- The DEX format itself hasn't fundamentally changed - everything you learn about DEX
  applies across both.
- **Deprecated but still seen:** documentation and tools referring to `dexopt` in the
  Dalvik sense (producing `.odex`) versus the modern `dex2oat`. Know which era a source
  is from.

> **⚙️ Engineering Note:** From **Android 12 (API 31)**, ART is a **Mainline module**
> (`com.android.art`), updatable via Google Play system updates independently of the OS.
> Practical consequence: two devices reporting the same Android version can have different
> ART versions and subtly different behaviour. Record the ART module version in your
> dynamic-analysis environment metadata, or your results aren't reproducible.

---

## 3. Compilation: dex2oat, JIT, AOT, and profiles

### The pipeline

```
  APK installed
      │
      ▼
  PackageManagerService requests dexopt
      │
      ▼
  dex2oat runs with a COMPILER FILTER
      │
      ├── verify              → verify only, no compiled code (fast install)
      ├── quicken (legacy)    → bytecode quickening
      ├── speed-profile       → AOT-compile methods in the profile  ★ default
      ├── speed               → AOT-compile everything
      └── everything          → including debug info
      │
      ▼
  App runs: interpreter → JIT compiles hot methods
      │
      ▼
  Profile written to /data/misc/profiles/cur/0/<pkg>/primary.prof
      │
      ▼
  Background dexopt job (idle + charging) recompiles with speed-profile
      │
      ▼
  Faster subsequent launches
```

### Commands

```bash
# Force compilation of a package (analysis / repro)
$ adb shell cmd package compile -m speed -f com.example.app

# Reset to as-installed state
$ adb shell cmd package compile --reset com.example.app

# What compiler filter is currently applied?
$ adb shell dumpsys package com.example.app | grep -A5 "Dexopt state"

# Where the artifacts live
$ adb shell ls -la /data/app/*/com.example.app*/oat/arm64/
```

### WHY an analyst cares

1. **Compiled artifacts are a forensic source.** If an APK has been deleted but `oat/`
   artifacts remain, you may still recover code. → [Ch 17](../digital-forensics/17-digital-forensics.md)
2. **Profiles reveal what actually executed.** `primary.prof` lists methods the runtime
   observed as hot. On a compromised device, that's behavioural evidence: it tells you which
   methods ran, not merely which exist. This is an underused forensic artifact.
3. **Compilation state affects hooking.** Frida's Java hooking works against ART's method
   structures; heavily AOT-compiled and inlined methods can behave differently under
   instrumentation. If a hook silently fails, forcing `--reset` or `-m verify` and retrying
   is a standard troubleshooting step. → [Ch 12](../dynamic-analysis/12-dynamic-analysis.md)

> **⚙️ Engineering Note:** Inlining is the usual culprit when a Frida hook "doesn't fire."
> The method exists, but the caller has an inlined copy and never dispatches to it. Hook the
> caller, or de-optimise. This costs analysts hours if they don't know it.

---

## 4. The compiled artifacts: .oat, .vdex, .art

| File | Contains | Analyst use |
|---|---|---|
| **`.vdex`** | The **verified DEX** - essentially the original DEX plus verification metadata (quickening info) | **You can extract DEX from a `.vdex`.** This is how you recover code from an installed app whose APK you can't get, and one route around some packers. |
| **`.oat`** | ELF containing AOT-compiled native code plus a reference to the DEX | Native code corresponding to Java methods |
| **`.art`** | Pre-initialised heap image for faster startup | Rarely directly useful |

Located at `/data/app/<pkg>-<rand>/oat/<isa>/base.{odex,vdex,art}` (the compiled file keeps
the `.odex` extension for historical reasons even under ART).

```bash
# Pull artifacts (root)
$ adb shell su -c 'ls /data/app/*/com.suspect*/oat/arm64/'
$ adb pull /data/app/~~x/com.suspect-y/oat/arm64/base.vdex

# Extract DEX from vdex - vdexExtractor (community tool) or:
$ python3 -m androguard ...       # some versions handle vdex
# Alternatively use `oatdump` on device (AOSP tool, often present on userdebug builds)
$ adb shell oatdump --oat-file=/data/app/.../oat/arm64/base.odex | head -50
```

> **⚙️ Engineering Note - the anti-packer play:** Many commercial packers keep the real DEX
> encrypted in `assets/` and only decrypt into memory at runtime. But if the app has been
> *installed and run*, portions may have been materialised and compiled. Combined with
> memory dumping ([Ch 12](../dynamic-analysis/12-dynamic-analysis.md)), the runtime is often
> the easiest path to the real code. **The runtime must eventually see plaintext bytecode to
> execute it. That is the fundamental weakness of every packer.**

---

## 5. Class loading

### The hierarchy

```
        BootClassLoader           ← android.*, java.*  (the framework)
              ▲
              │  parent
        PathClassLoader           ← YOUR app's classes.dex  (default)
              ▲
              │  parent
        DexClassLoader            ← additional DEX you load yourself
```

Android uses **parent-first delegation**: a loader asks its parent before loading a class
itself. That's why you can't override `java.lang.String` - `BootClassLoader` answers first.

### The loader types

| Loader | Loads from | Notes |
|---|---|---|
| `PathClassLoader` | APK/DEX already on the filesystem | The app's default loader |
| `DexClassLoader` | A DEX/JAR/APK path you specify, with an optimised-output dir | **Historic dynamic-loading workhorse** |
| `InMemoryDexClassLoader` | A `ByteBuffer` - **never touches disk** | API 26+. The modern evasion favourite. |
| `BaseDexClassLoader` | Base class of the above | Hooking target for analysis |

### Why `InMemoryDexClassLoader` changed the game

Before API 26, dynamically loaded DEX had to be written to disk, which meant:
- A file existed that a scanner could find.
- A file existed that forensics could recover.
- The `optimizedDirectory` parameter created an artifact.

With `InMemoryDexClassLoader`, the payload can go **network → decrypt → ByteBuffer →
execute**, never touching storage. Nothing to scan on disk. Nothing to recover afterwards
except from memory.

```java
// The shape you're looking for in decompiled code
ByteBuffer buf = ByteBuffer.wrap(decryptedPayloadBytes);
ClassLoader cl = new InMemoryDexClassLoader(buf, getClassLoader());
Class<?> c = cl.loadClass("com.hidden.Payload");
c.getMethod("run", Context.class).invoke(c.newInstance(), this);
```

> **⚙️ Engineering Note:** When you see **any** of `DexClassLoader`,
> `InMemoryDexClassLoader`, `PathClassLoader` constructed with a non-default path, or
> `dalvik.system.DexFile`, stop and trace where the bytes come from. This is one of the
> highest-value static signals in Android analysis - far more meaningful than any single
> permission.

---

## 6. Dynamic code loading - the technique that breaks static analysis

### WHAT / WHY it exists legitimately

Real, non-malicious uses:
- **Plugin architectures** and modular apps
- **A/B testing** and feature flags shipping code
- **Play Feature Delivery** (dynamic feature modules) - Google's *supported* mechanism
- **Game engines** and scripting layers
- **Hot-fix frameworks** (very common in the Chinese app ecosystem: Tinker, Sophix, Qzone)

### WHY attackers love it

| Benefit to attacker | Consequence for defenders |
|---|---|
| Store review sees a clean app | Play review, MobSF, and AV all pass it |
| Payload delivered post-install | The APK you analyse ≠ the code that ran |
| Payload can be per-victim / per-region | Sandbox may receive a benign payload |
| Payload can be pulled after the campaign | Sample never recoverable |
| Defeats hash-based blocking | The dropper hash stays constant and clean |

**Anatsa is the canonical case study.** ThreatFabric and Zscaler ThreatLabz documented
droppers on Google Play - one reached the **#4 spot in Play's Top Free Tools category by
June 29, 2025**, roughly six weeks after a clean May 7, 2025 release, before shipping the
malicious update. Notably, Zscaler ThreatLabz (August 2025) reported Anatsa **moved away
from loading remote DEX toward directly installing the payload**, streamlining delivery.
That evolution matters: it means "no dynamic loading detected" does **not** mean "no
staged payload."

### Google's progressive restrictions

| Android | Restriction | Effect |
|---|---|---|
| 8.0 (API 26) | `optimizedDirectory` for `DexClassLoader` deprecated; writable-then-executable DEX discouraged | Nudge away from world-writable payload dirs |
| 10 (API 29) | **Writable + executable DEX blocked** in many paths; `W^X` enforcement for app code | Can't just drop a DEX in a writable dir and run it |
| 11 (API 30) | Further app-storage restrictions | Fewer viable drop locations |
| 14 (API 34) | Dynamic code loading from **world-writable** files blocked; files must be marked read-only | Documented in Android 14 behaviour changes - a genuine hardening step |

> **🚨 Misconception:** "Android 14 blocked dynamic code loading." It did **not**. It blocked
> loading code from *world-writable* files. An app can still load DEX from its own private,
> read-only storage or from memory. Overstating this in a report or a demo will get you
> corrected by anyone who reads the release notes.

### Detection strategies

**Static** - find the loader construction and trace the byte source:

```bash
# after apktool
$ grep -rn "InMemoryDexClassLoader\|DexClassLoader\|dalvik/system/DexFile" work/smali*/
# in jadx search, look for these plus the decryption routine feeding them
```

**Dynamic** - hook the loaders and dump what they load. This is the reliable method:

```javascript
// Frida - dump every DEX handed to a class loader
Java.perform(function () {
  var IMDCL = Java.use('dalvik.system.InMemoryDexClassLoader');
  IMDCL.$init.overload('java.nio.ByteBuffer', 'java.lang.ClassLoader')
    .implementation = function (buf, parent) {
      console.log('[!] InMemoryDexClassLoader, size=' + buf.remaining());
      // dump buf to file for offline analysis
      return this.$init(buf, parent);
    };

  var DCL = Java.use('dalvik.system.DexClassLoader');
  DCL.$init.overload('java.lang.String','java.lang.String','java.lang.String','java.lang.ClassLoader')
    .implementation = function (dexPath, odex, libPath, parent) {
      console.log('[!] DexClassLoader path=' + dexPath);
      return this.$init(dexPath, odex, libPath, parent);
    };
});
```

Full Frida treatment in [Ch 12](../dynamic-analysis/12-dynamic-analysis.md).

> **⚙️ Engineering Note:** This hook is the single highest-return Frida script in Android
> malware analysis. It defeats a large fraction of packers *and* unpacks staged payloads,
> because as established in §4, **the runtime must see plaintext DEX to run it.**

---

## 7. Reflection

### WHAT / WHY

Reflection lets code inspect and invoke classes, methods, and fields by **name at runtime**.
It exists for frameworks (dependency injection, serialisation, ORMs), for backward
compatibility (`if (Build.VERSION.SDK_INT >= X) { call new API reflectively }`), and for
testing.

### WHY attackers use it

Static call-graph analysis follows *direct* invocations. Reflection replaces a direct call
with a string lookup:

```java
// Visible to a call-graph analyser:
smsManager.sendTextMessage(dest, null, body, null, null);

// Invisible to a call-graph analyser:
Class<?> c = Class.forName(dec("YW5kcm9pZC50ZWxlcGhvbnkuU21zTWFuYWdlcg=="));
Method m = c.getMethod(dec("c2VuZFRleHRNZXNzYWdl"), String.class, String.class,
                       String.class, PendingIntent.class, PendingIntent.class);
m.invoke(c.getMethod("getDefault").invoke(null), dest, null, body, null, null);
```

The second form has **no static edge** to `sendTextMessage`. Your call graph is now wrong.
Combined with string encryption ([Ch 10](../reverse-engineering/10-reverse-engineering.md)),
even the target name is unreadable statically.

### Detection

**Static signals** (all weak individually, meaningful in combination):
- Heavy use of `Class.forName`, `getMethod`, `getDeclaredMethod`, `invoke`, `setAccessible(true)`
- Reflection targets built from decrypted/Base64 strings rather than literals
- **Reflection into `android.os.ServiceManager`** or other non-SDK classes → §8, a genuine
  red flag
- Reflection density far above baseline for the app's size

**Dynamic** - hook `Method.invoke` and log every resolved target:

```javascript
Java.perform(function () {
  var M = Java.use('java.lang.reflect.Method');
  M.invoke.overload('java.lang.Object', '[Ljava.lang.Object;')
    .implementation = function (obj, args) {
      console.log('[refl] ' + this.getDeclaringClass().getName() + '.' + this.getName());
      return this.invoke(obj, args);
    };
});
```

This reconstructs the *real* call graph - the one static analysis couldn't build.

> **🚨 Misconception:** "Reflection means malware." Absolutely not. Retrofit, Gson, Jackson,
> Dagger, Room, and every compatibility shim in AndroidX use reflection heavily. It is a
> weighted contextual signal - reflection whose *target string is decrypted at runtime* is
> the meaningful variant, not reflection per se.

---

## 8. Non-SDK (hidden API) restrictions

### WHAT

Android's framework contains far more classes and methods than the public SDK exposes.
Historically apps reflected into these "hidden APIs" freely. From **Android 9 (API 28)**,
Google restricts this.

Lists:

| List | Behaviour |
|---|---|
| **SDK** (allowlist) | Public, supported |
| **blocked** | Access denied - `NoSuchMethodError` / `NoSuchFieldException` |
| **max-target-X** (conditionally blocked) | Allowed only if the app's `targetSdkVersion` ≤ X. Tightens as targetSdk rises. |
| **unsupported** (formerly greylist) | Allowed for now, warned in logcat |

### WHY it exists

Non-SDK APIs change without notice; apps depending on them broke on every OS upgrade. Also,
many hidden APIs are privileged surface that shouldn't be app-reachable at all.

### WHY it matters for detection

**Malware wants hidden APIs** - to enumerate packages, manipulate windows, reach telephony
internals, or hide itself. So malware needs bypasses. The known families of bypass:

1. **Keeping `targetSdkVersion` low** to stay under `max-target-X` gates. This is one of
   several reasons low targetSdk is a malware signal - and precisely why Android 14 (API 34)
   introduced a **hard install block for apps targeting below API 23**, and Android 15 raised
   it to API 24. → [Ch 04](../security/04-android-security-model.md)
2. **Double reflection** - reflecting into `Class.getDeclaredMethod` itself, so the
   *caller* of the restricted lookup appears to be framework code rather than app code.
   This works because the enforcement checks the caller's class loader.
3. **JNI / native access** to bypass the Java-layer enforcement.
4. **`setHiddenApiExemptions`** via `VMRuntime` - reflectively disabling the restriction.

```bash
# Watch for hidden-API access in logcat during detonation
$ adb logcat | grep -i "Accessing hidden"
# Example line:
# Accessing hidden method Landroid/os/ServiceManager;->getService(...)
#   (unsupported, reflection, denied)
```

> **⚙️ Engineering Note:** `adb logcat | grep "Accessing hidden"` during dynamic analysis is
> a cheap, high-signal detection. Legitimate apps trip it occasionally (old SDKs, compat
> shims). Malware trips it *deliberately and repeatedly*, often right after startup. Log the
> count and the specific APIs - the API list tells you the intent.

---

## 9. JNI and native code

### HOW loading works

```java
System.loadLibrary("native");        // loads lib/<abi>/libnative.so
```

```
  System.loadLibrary("native")
        │
        ▼
  Runtime resolves lib/<abi>/libnative.so (from APK if extractNativeLibs=false)
        │
        ▼
  dlopen()  ──►  ELF loaded, constructors (.init_array) RUN  ★
        │
        ▼
  JNI_OnLoad(JavaVM*, void*) called  ★
        │
        ├── typically: RegisterNatives() to bind Java methods to C functions
        └── packers: DECRYPT AND LOAD THE REAL DEX HERE
        │
        ▼
  native methods callable from Java
```

Two ★ points matter enormously:

- **`.init_array` constructors run before `JNI_OnLoad`.** Some anti-analysis code lives
  there specifically because analysts breakpoint on `JNI_OnLoad` and miss it.
- **`JNI_OnLoad` is where packers unpack.** Start Ghidra here.

### Why attackers move logic native

| Motivation | Effect on you |
|---|---|
| No Java decompiler output | `jadx` shows an empty stub method |
| Harder, slower reversing | ARM64 disassembly vs readable Java |
| Bypass Java-layer hidden-API enforcement | §8 |
| Anti-Frida / anti-debug checks in native | Detection of `frida-server`, `ptrace` checks, `/proc/self/maps` scanning |
| String/crypto material harder to grep | Constants computed rather than stored |

Documented examples: **Klopatra** (Cleafy, Aug 2025) shifted logic from Java to native and
used the commercial **Virbox** protector; **GodFather** variants migrated to native code
(Cyble). Both are cited in [Ch 14](../banking-malware/14-banking-malware.md).

### `RegisterNatives` - the mapping you need

Instead of relying on name-mangled `Java_com_pkg_Class_method` symbols, code can call
`RegisterNatives()` at runtime to bind arbitrary C functions to Java method signatures.
Result: `nm -D` shows nothing useful. To recover the mapping, hook `RegisterNatives`:

```javascript
// Frida: recover dynamically registered JNI bindings
Interceptor.attach(Module.findExportByName(null, "art::JNI::RegisterNatives") || ptr(0), {
  // (symbol name varies by ART version; jnitrace automates this)
});
```

In practice use **`jnitrace`** rather than hand-rolling this. → [Ch 12](../dynamic-analysis/12-dynamic-analysis.md)

---

## 10. Garbage collection and memory (briefly, and why you care)

ART uses a **concurrent copying (CC)** collector by default on modern versions, with
generational optimisations. You do not need GC internals for malware analysis. You need two
practical facts:

1. **Objects move.** A copying collector relocates objects, which is why naive memory
   scanning for a decrypted key can miss it, and why Frida's `Java.choose()` (which
   enumerates live instances of a class on the heap) is the better tool.

   ```javascript
   // Find live instances - beats raw memory scanning
   Java.perform(function () {
     Java.choose('com.suspect.CryptoUtil', {
       onMatch: function (inst) { console.log('key=' + inst.mKey.value); },
       onComplete: function () {}
     });
   });
   ```

2. **Heap dumps are evidence.** `am dumpheap` produces an HPROF you can analyse offline for
   decrypted strings, C2 URLs, and keys.

   ```bash
   $ adb shell am dumpheap com.suspect /data/local/tmp/heap.hprof
   $ adb pull /data/local/tmp/heap.hprof
   # convert for standard tools:
   $ hprof-conv heap.hprof heap-std.hprof
   ```

> **⚙️ Engineering Note:** Heap dumping after the malware has contacted C2 frequently yields
> the plaintext C2 URL, the AES key, and the target-app list - even when all three are
> encrypted in the APK. Time your dump: **after network activity, before the app clears
> state.** → [Ch 26](../sudarshan/26-ioc-extraction.md)

---

## 11. Detection logic for SUDARSHAN

### Static signals from this chapter

| Signal | Weight | Notes |
|---|---|---|
| `InMemoryDexClassLoader` present | **High** | Modern staged-payload pattern; rare in ordinary apps |
| `DexClassLoader` with non-app path | **High** | Classic dynamic loading |
| Class loader fed by decrypted bytes (crypto call → loader) | **Very High** | The combination is what matters |
| `Class.forName` on a decrypted/Base64 string | High | Hidden call target |
| Reflection into `ServiceManager` / non-SDK classes | High | Hidden-API bypass intent |
| `setHiddenApiExemptions` reference | **Very High** | Explicit restriction bypass |
| Reflection density >> baseline | Low-Medium | Contextual only |
| Native-to-Java code ratio skewed native | Medium | Combine with packer fingerprint |
| `RegisterNatives` usage with no exported `Java_*` symbols | Medium | Deliberate symbol hiding |
| Low `targetSdkVersion` (< 26, and especially < 23) | Medium-High | Gate evasion; also install-blocked on A14/A15 |

### Dynamic signals (higher confidence)

| Instrumentation | Yields |
|---|---|
| Hook `DexClassLoader` / `InMemoryDexClassLoader` | **Dump the real payload** - then re-run the full static pipeline on the dumped DEX |
| Hook `Method.invoke` | Reconstructed real call graph |
| `logcat \| grep "Accessing hidden"` | Hidden-API bypass attempts + which APIs |
| `jnitrace` | JNI call trace, `RegisterNatives` map |
| `am dumpheap` post-C2 | Plaintext C2, keys, target list |
| Compare pre/post `pm list packages` | Dropper installed a second app |

### The recursive-analysis requirement

> **⚙️ Architecture decision for SUDARSHAN:** When dynamic analysis dumps a DEX from a class
> loader hook, that DEX **must be fed back into the static pipeline as a new artifact**,
> linked to the parent sample. This recursion is not optional - for staged malware, the
> child artifact is where all the real capability lives, and treating it as "just a log
> line" throws away the entire finding.
>
> ```
> sample.apk ──static──► [clean-looking]
>      │
>      └──dynamic──► classloader hook ──► payload.dex  ★ NEW ARTIFACT
>                                              │
>                                              └──static──► [banking trojan capability]
>                                                              │
>                                                              └──► score attaches to
>                                                                   the PARENT sample
> ```
>
> Design this into the intake and artifact-graph model from day one.
> → [Ch 24](../sudarshan/24-threat-intake.md), [Ch 25](../sudarshan/25-investigation-engine.md)

---

## 12. Limitations, edge cases, false positives

### False positives

| Signal | Legitimate users |
|---|---|
| Reflection | Gson, Retrofit, Dagger, Room, every AndroidX compat shim |
| `DexClassLoader` | Plugin frameworks, hot-fix SDKs (Tinker, Sophix), Play Feature Delivery adjacents, some ad SDKs |
| Native libraries | Games, codecs, ML (TensorFlow Lite), DRM (Widevine), crypto libs |
| Hidden-API access | Apps supporting old devices; OEM-specific integrations |
| Low targetSdk | Genuinely abandoned but benign apps (though these are now install-blocked) |

### False negatives

- Payload delivered only to specific geographies/devices - your sandbox gets nothing.
- Time-delayed activation (dormant for days).
- Payload requires C2 that is offline at analysis time → **the sample looks benign**. Record
  "C2 unreachable" as an explicit analysis-quality flag, don't silently score it clean.
- Anatsa-style direct install of the payload instead of DEX loading - no loader hook fires.

### Edge cases

- **ART Mainline version differences** across devices reporting the same OS version.
- **Multidex** - hook must handle multiple DEX per loader.
- **`InMemoryDexClassLoader` with a `ByteBuffer[]`** overload (API 29+) - hook both overloads
  or you miss half the samples.
- Apps that detect Frida and behave benignly - hence static+dynamic fusion.

### Performance

Forced AOT compilation (`-m speed`) of a large app costs seconds to minutes of CPU. Don't do
it by default in a throughput-sensitive pipeline; do it when troubleshooting hook failures.

---

## 13. Engineering tips

1. **Hook class loaders first, always.** It's the highest-yield single instrumentation in
   Android analysis.
2. **Feed dumped DEX back through static analysis.** Recursion is mandatory.
3. **`grep "Accessing hidden"` in logcat** during every detonation - free signal.
4. **Use `Java.choose()` over raw memory scanning** because the collector moves objects.
5. **Heap-dump after C2 contact.** Best time to catch plaintext.
6. **Start native reversing at `JNI_OnLoad`, but check `.init_array` first.**
7. **Record the ART Mainline version** in analysis metadata for reproducibility.
8. **If a hook doesn't fire, suspect inlining** before suspecting your script.

---

## 14. Judge Insights

**What judges ask:** *"If the malware downloads its payload after installation, how can you
possibly detect it?"*

**Perfect answer:** We don't rely on the shipped code being the running code. Statically we
look for the *machinery* of staged delivery - class loaders like `InMemoryDexClassLoader`,
reflection driven by decrypted strings, hidden-API bypasses, and a native/Java code balance
that suggests hidden logic. Then dynamically we hook the class loaders and **dump the
payload the moment the runtime materialises it**, because the runtime has to see plaintext
bytecode to execute it - that's an unavoidable property of ART, not a bug we're exploiting.
The dumped payload is then fed back through the full static pipeline as a linked child
artifact, and its findings attach to the parent sample.

**Common mistake:** Claiming "our AI detects unknown payloads." Judges with security
backgrounds will ask how, and you'll have nothing. The class-loader-hook answer is concrete,
technically correct, and demonstrably works.

**Follow-ups to expect:**
- *"What if the C2 is offline when you detonate?"* → We flag analysis quality explicitly.
  A sample whose C2 didn't answer is not scored as clean; it's scored as inconclusive with
  a re-detonation schedule. Honesty here impresses more than bluffing.
- *"What if it detects your sandbox?"* → Real devices over emulators, plus static signals
  that don't depend on execution. Fusion. → [Ch 12](../dynamic-analysis/12-dynamic-analysis.md)
- *"Didn't Android 14 stop dynamic code loading?"* → **No** - it blocked loading from
  world-writable files. Knowing this precisely is a strong signal of depth.

**Fact that impresses:** ART has been a **Mainline module updatable via Google Play since
Android 12**, so two devices reporting the same Android version can run different ART
builds. Any dynamic analysis claiming reproducibility without pinning the ART version is
overclaiming.

---

## 15. Interview Insights

**Q: "Dalvik vs ART?"**
Register-based VM in both; the difference is compilation strategy. Dalvik: interpret + JIT.
ART 5.0: full AOT at install (slow installs, slow OTAs). ART 7.0+: hybrid - install fast,
JIT, profile hot methods, background AOT with `speed-profile`. Mention the Nougat pivot; it
shows you know *why*, not just *what*.

**Q: "How does an app load code that wasn't in the APK?"**
`DexClassLoader` from a file, or `InMemoryDexClassLoader` from a `ByteBuffer` (API 26+) with
no disk artifact. Then the security angle: this is why static analysis alone is insufficient,
and why Android 14 restricted loading from world-writable files.

**Q: "What is `.vdex` and why would you care?"**
Verified DEX plus verification metadata. You care because you can extract DEX from it - useful when you have an installed app but not its APK, and sometimes a route around packers.

**Q: "Reflection is used everywhere legitimately. How do you use it as a signal?"**
The right answer names the *combination*: reflection whose target is a runtime-decrypted
string, reflection into non-SDK classes like `ServiceManager`, and reflection paired with a
class loader. Reflection alone is noise.

**Q: "How would you defeat a packer?"**
The runtime must eventually see plaintext DEX. Hook the class loaders, dump at that moment,
and/or dump the heap. Add: `.init_array` and `JNI_OnLoad` for native unpacking stubs.

**Beginner mistakes:**
- Believing decompiled Java is the complete program.
- Treating reflection as inherently malicious.
- Saying "Android 14 banned dynamic code loading."
- Not knowing why a Frida hook silently failed (inlining).
- Forgetting to re-analyse dumped payloads.

---

## 16. Cross-references

**Upstream:**
- [← Ch 01 Android Internals](01-android-internals.md) - Zygote, process model
- [← Ch 02 APK Architecture](../apk/02-apk-architecture.md) - where DEX and `.so` live

**Downstream:**
- [→ Ch 04 Android Security Model](../security/04-android-security-model.md) - targetSdk gates, install blocks
- [→ Ch 08 APK File Format](../apk/08-apk-file-format.md) - DEX internals in bytes
- [→ Ch 10 Reverse Engineering](../reverse-engineering/10-reverse-engineering.md) - packers, obfuscation, native RE
- [→ Ch 11 Static Analysis](../static-analysis/11-static-analysis.md) - automating the static signals
- [→ Ch 12 Dynamic Analysis](../dynamic-analysis/12-dynamic-analysis.md) - Frida hooks, jnitrace, heap dumps
- [→ Ch 13 Android Malware](../malware/13-android-malware.md) - dropper technique in context
- [→ Ch 25 Investigation Engine](../sudarshan/25-investigation-engine.md) - recursive artifact analysis

**Related concept chain:** Reflection → Dynamic Code Loading → Frida → Runtime Hooking →
ART → Obfuscation → Packers.

---

## 17. References

1. AOSP - *Android Runtime (ART) and Dalvik*. https://source.android.com/docs/core/runtime
2. AOSP - *Configuring ART / compiler filters*. https://source.android.com/docs/core/runtime/configure
3. Android Developers - *Restrictions on non-SDK interfaces*. https://developer.android.com/guide/app-compatibility/restrictions-non-sdk-interfaces
4. Android Developers - *Behavior changes: Android 14* (dynamic code loading restrictions). https://developer.android.com/about/versions/14/behavior-changes-all
5. Android Developers - `InMemoryDexClassLoader`, `DexClassLoader` reference. https://developer.android.com/reference/dalvik/system/InMemoryDexClassLoader
6. Android Developers - *JNI tips*. https://developer.android.com/training/articles/perf-jni
7. Android Developers - *ART as a Mainline module* / Google Play system updates. https://source.android.com/docs/core/ota/modular-system/art
8. ThreatFabric - Anatsa Google Play dropper campaign (July 2025).
9. Zscaler ThreatLabz - *Anatsa's Latest Updates* (August 2025) - shift from remote DEX loading to direct install.
10. Cleafy Labs - *Klopatra* (August 2025) - Java→native migration, Virbox protector.
11. Cyble Research and Intelligence Labs - GodFather variant native-code migration.
12. Frida documentation - Java API (`Java.use`, `Java.choose`, `Java.perform`). https://frida.re/docs/javascript-api/
13. `jnitrace` project - JNI API tracing for Android.
14. MITRE ATT&CK for Mobile - T1407 (Download New Code at Runtime), T1406 (Obfuscated Files or Information). https://attack.mitre.org/matrices/mobile/

### Further reading
- AOSP `art/` source tree - `runtime/class_linker.cc`, `dex2oat/`
- `vdexExtractor` - community tool for DEX recovery from `.vdex`
- OWASP MASTG - MASVS-RESILIENCE test cases (anti-tampering, anti-hooking)

---

*Previous: [← Ch 02 APK Architecture](../apk/02-apk-architecture.md) · Next: [Ch 04 Android Security Model →](../security/04-android-security-model.md)*
