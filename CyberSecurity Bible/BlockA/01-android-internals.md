# 01 - Android Internals

> **Chapter ID:** `CH01` · **Block:** A (Foundations) · **Status:** Stable
> **Tags:** `#android` `#internals` `#binder` `#zygote` `#ipc` `#components` `#aosp`
> **Last Updated:** 2026-08-05 · **Version:** 1.0.0
> **Prerequisites:** [Ch 00 Introduction](../00-introduction.md)

---

## Table of Contents

1. [Why an analyst must know internals](#1-why-an-analyst-must-know-internals)
2. [The Android stack](#2-the-android-stack)
3. [Boot: from power button to launcher](#3-boot-from-power-button-to-launcher)
4. [Zygote: the process factory](#4-zygote-the-process-factory)
5. [system_server and the service model](#5-system_server-and-the-service-model)
6. [Binder IPC](#6-binder-ipc)
7. [The four components](#7-the-four-components)
8. [Intents and the exported surface](#8-intents-and-the-exported-surface)
9. [Storage: from wild west to scoped](#9-storage-from-wild-west-to-scoped)
10. [Detection logic for SUDARSHAN](#10-detection-logic-for-sudarshan)
11. [Limitations, edge cases, false positives](#11-limitations-edge-cases-false-positives)
12. [Engineering tips](#12-engineering-tips)
13. [Judge Insights](#13-judge-insights)
14. [Interview Insights](#14-interview-insights)
15. [Cross-references](#15-cross-references)
16. [References](#16-references)

---

## 1. Why an analyst must know internals

You can go a long way in APK analysis without knowing how Android boots. You will hit a
wall fast, and it will look like this:

- You see `android.os.ServiceManager` called by reflection and you don't know why that's
  a red flag.
- Malware registers a receiver for `BOOT_COMPLETED` and you don't understand why that
  guarantees persistence.
- You see a component with `android:exported="true"` and no permission and can't explain
  the actual risk to a bank's fraud lead.
- A dropper spawns its payload in a *separate process* and your Frida hooks silently miss
  everything, and you spend two hours wondering why.

Every one of those is an internals question. This chapter is the map.

> **⚙️ Engineering Note:** The single most useful mental model is this - **Android is a
> Linux system where the interesting security boundaries are not Linux boundaries.**
> Linux gives you UIDs and processes. Android adds Binder, permissions, components, and
> the framework. Attackers live in the gap between the two models.

---

## 2. The Android stack

### WHAT

Android is a layered stack. Bottom to top:

```
┌────────────────────────────────────────────────────────────┐
│  APPS         System apps · User apps (your APK lives here) │
├────────────────────────────────────────────────────────────┤
│  JAVA API FRAMEWORK                                         │
│  ActivityManager · PackageManager · NotificationManager     │
│  WindowManager · ContentProviders · View System · Resources │
├────────────────────────────────────────────────────────────┤
│  NATIVE LIBS              │  ANDROID RUNTIME (ART)          │
│  Bionic libc · OpenSSL    │  Core libraries                 │
│  SQLite · libc++ · Skia   │  dex2oat · JIT · GC             │
│  Media framework          │  (see Ch 03)                    │
├────────────────────────────────────────────────────────────┤
│  HARDWARE ABSTRACTION LAYER (HAL)                           │
│  Camera · Audio · Sensors · Bluetooth · Wi-Fi · Keymaster   │
├────────────────────────────────────────────────────────────┤
│  LINUX KERNEL                                               │
│  Drivers · Power mgmt · Binder driver · Low Memory Killer   │
│  SELinux (LSM) · seccomp-bpf · Namespaces · cgroups         │
└────────────────────────────────────────────────────────────┘
```

*(Source: Android Developers, "Platform Architecture.")*

### WHY it exists this way

Three forces shaped it:

1. **Hardware fragmentation.** Thousands of device models with different cameras,
   sensors, and modems. The HAL exists so the framework can be written once. This is why
   Project Treble (Android 8) mattered - it decoupled the vendor implementation from the
   framework so OS updates stopped requiring full vendor rebuilds.
2. **App portability.** Apps ship as bytecode (DEX), not native code, so the same APK
   runs on ARM and x86. This is also why *native* libraries (`lib/arm64-v8a/*.so`) need
   per-ABI builds - and why malware often ships several ABI variants.
3. **Isolation.** The Linux kernel supplies process and UID isolation for free. Android
   builds its permission model on top.

### WHY malware authors care about each layer

| Layer | What the adversary wants from it |
|---|---|
| Kernel | Root exploits (rare now, but privilege escalation is the jackpot) |
| HAL | Camera/mic/sensor access - mostly reached via framework APIs, not directly |
| Native libs | **Hiding logic.** Moving code from Java to native `.so` defeats `jadx`. Klopatra and GodFather both did this (Cleafy 2025; Cyble). |
| ART | Dynamic code loading, reflection, hooking evasion → [Ch 03](03-android-runtime.md) |
| Framework | The actual attack surface: Accessibility, WindowManager overlays, NotificationListener, SMS |
| Apps | The target: banking apps whose UI is overlaid and whose sessions are hijacked |

> **⚙️ Engineering Note:** When you see a large `.so` in `lib/` and a suspiciously thin
> `classes.dex`, the logic has been pushed native. That is a **weighted signal**, not a
> verdict - game engines, ML SDKs, and DRM libraries do this legitimately. But combined
> with a commercial packer fingerprint (Virbox, Jiagu, Bangcle) it becomes strong.

---

## 3. Boot: from power button to launcher

### HOW

```
Power on
   │
   ▼
Boot ROM  ──►  Bootloader
   │              │  verifies boot chain (Android Verified Boot → Ch 04)
   ▼              ▼
Linux kernel starts
   │  mounts rootfs, starts drivers, brings up Binder driver
   ▼
init (PID 1)   ── parses /system/etc/init/*.rc
   │
   ├──► ueventd, logd, servicemanager, vold, healthd ...
   │
   ├──► Zygote (app_process)
   │        │  preloads framework classes + resources
   │        │
   │        └──► forks system_server
   │                 │  starts ~100 system services:
   │                 │  ActivityManagerService, PackageManagerService,
   │                 │  WindowManagerService, PowerManagerService ...
   │                 │
   │                 └──► PackageManagerService scans /system/app,
   │                      /data/app; reads packages.xml; registers apps
   │
   ▼
Launcher (Home) starts  ──►  BOOT_COMPLETED broadcast sent
```

### WHY this matters to an analyst

The **`BOOT_COMPLETED` broadcast** is the single most abused persistence mechanism on
Android. An app that declares:

```xml
<receiver android:name=".BootReceiver" android:enabled="true" android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.BOOT_COMPLETED"/>
    </intent-filter>
</receiver>
```

...with `<uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED"/>`
will be woken on every reboot. Every persistent banking trojan does this. It maps to
**MITRE ATT&CK Mobile T1624 - Event Triggered Execution**.

> **🚨 Misconception:** "Rebooting the phone will kill the malware." It will not. It is
> often the *first* thing the malware wants, because reboot restores it to a clean
> baseline state where its receivers re-register and its foreground service restarts.

### WHERE the artifacts live

For forensics ([→ Ch 17](../digital-forensics/17-digital-forensics.md)):

| Artifact | Path | Why you care |
|---|---|---|
| Package registry | `/data/system/packages.xml` | Install source, granted permissions, signer cert |
| Package list | `/data/system/packages.list` | UID ↔ package mapping |
| App sandboxes | `/data/data/<pkg>/` | The app's private data |
| App APKs | `/data/app/<pkg>-<random>/base.apk` | The installed artifact itself |

---

## 4. Zygote: the process factory

### WHAT

**Zygote** is a process started at boot that has already loaded and initialised the core
framework classes and resources. Every app process on the device is created by **forking
Zygote** - never by a fresh `exec`.

```
                    ┌─────────────────┐
                    │     Zygote      │
                    │  (preloaded:    │
                    │   framework     │
                    │   classes, ART  │
                    │   heap, JNI)    │
                    └────────┬────────┘
                             │ fork()
        ┌────────────┬───────┼───────┬────────────┐
        ▼            ▼       ▼       ▼            ▼
  system_server  com.bank  com.chat  launcher   com.malware
   (uid 1000)   (uid 10123)(uid 10087)         (uid 10241)
```

### WHY it exists

Two reasons, both about cost:

1. **Startup latency.** Loading and verifying the entire framework class set on every app
   launch would take seconds. Zygote pays that cost once, at boot.
2. **Memory.** `fork()` gives **copy-on-write** semantics. Every app process shares the
   same physical pages for framework classes and resources until it writes to them. On a
   device with 40 running apps this saves hundreds of megabytes.

### HOW a launch works

```
User taps app icon
   │
   ▼
Launcher → ActivityManagerService (via Binder)
   │
   ▼
AMS: "is there a process for uid 10241?"  ── no ──►  request Zygote fork
   │                                                       │
   │                                                       ▼
   │                                       Zygote fork() → child
   │                                                       │
   │                              child: setuid(10241), set SELinux context,
   │                              apply seccomp filter, drop capabilities
   │                                                       │
   │                                                       ▼
   │                              ActivityThread.main() → bind to AMS
   ▼                                                       │
AMS schedules Activity launch ◄─────────────────────────────┘
```

The security-critical moment is the child's setup: **UID assignment, SELinux domain
transition, and seccomp filter installation all happen after the fork and before any app
code runs.** This is why an app cannot escape its sandbox by exploiting startup ordering - by the time `onCreate()` executes, the box is already closed.

### WHY attackers care

**Multi-process malware.** An app can declare components in a separate process:

```xml
<service android:name=".PayloadService" android:process=":worker"/>
```

That gets a *separate* forked process, sharing the same UID and data directory but with
its own address space. Consequences for you:

- **Frida hooks attached to the main process see nothing.** You must attach to the right
  PID or spawn-gate. → [Ch 12](../dynamic-analysis/12-dynamic-analysis.md)
- **`ps` on device shows `com.example:worker` as a distinct row.** Look for it.
- Some malware uses a watchdog process pair: each restarts the other if killed. This is
  an anti-removal technique, related to **T1629.001 (Prevent Application Removal)**.

```bash
# See every process for a package, including sub-processes
$ adb shell ps -A | grep com.suspect
u0_a241  8123  1  ... com.suspect
u0_a241  8199  1  ... com.suspect:worker      # <-- second process
```

> **⚙️ Engineering Note:** SUDARSHAN's dynamic sandbox must enumerate *all* processes
> belonging to the target UID, not just the one matching the package name exactly. A
> surprising amount of published dynamic analysis misses payloads for exactly this reason.

### LIMITATIONS

Zygote's `fork()` model means every app inherits the same preloaded class set. This has
one notable security consequence: **address space layout is partially shared across
apps** because they descend from the same parent. Android mitigates this by re-randomising
where it can, but it's a known structural weakness discussed in AOSP security docs.

---

## 5. system_server and the service model

### WHAT

`system_server` is a single, enormous, privileged process (UID 1000, `system`) that hosts
most Android system services as threads. Key residents:

| Service | Responsibility | Analyst relevance |
|---|---|---|
| `ActivityManagerService` (AMS) | Process/component lifecycle, broadcasts | Launch tracing, `dumpsys activity` |
| `PackageManagerService` (PMS) | Install/uninstall, permissions, signatures | The core of [Ch 09](../apk/09-package-manager.md) |
| `WindowManagerService` (WMS) | Windows, z-order, overlays | **Overlay attacks live here** |
| `AccessibilityManagerService` | a11y service registration and event dispatch | **The hinge of banking malware** |
| `NotificationManagerService` | Notifications, listener binding | OTP theft via notification access |
| `TelephonyRegistry` / SMS stack | SMS delivery | OTP interception |
| `PowerManagerService` | Wakelocks, doze | Persistence and battery-drain artifacts |

### WHY it's one process

Historical and practical: these services need to coordinate constantly and share state,
and Binder calls between them would be expensive. The cost is that `system_server` is a
huge, high-value target - a memory corruption bug there is effectively system compromise.
Google Project Zero has published repeatedly on this attack surface.

### HOW to interrogate it (your daily commands)

```bash
# What accessibility services are enabled RIGHT NOW? (gold for triage)
$ adb shell settings get secure enabled_accessibility_services

# Full accessibility state, including which app bound which service
$ adb shell dumpsys accessibility

# Which apps hold overlay permission?
$ adb shell dumpsys window | grep -i overlay
$ adb shell appops get <package> SYSTEM_ALERT_WINDOW

# Who has notification listener access? (OTP theft vector)
$ adb shell settings get secure enabled_notification_listeners

# Package details: install source, permissions, signature
$ adb shell dumpsys package com.suspect

# What is on screen right now / which activity is focused
$ adb shell dumpsys activity activities | grep mResumedActivity
```

> **🏛️ Enterprise Insight:** Those first and last commands are the fastest triage you can
> run on a customer's compromised handset. `enabled_accessibility_services` returning an
> unfamiliar package is, in practice, the highest-yield single check in Android banking
> fraud triage. A bank's incident-response runbook should have it on line one.
> → [Ch 20](../incident-response/20-incident-response.md)

---

## 6. Binder IPC

### WHAT

**Binder** is Android's primary inter-process communication mechanism. Practically every
interesting thing an app does - starting an activity, sending an SMS, taking a photo,
querying installed packages - is a Binder transaction to a system service.

It is implemented as a kernel driver exposed at `/dev/binder` (plus `/dev/hwbinder` and
`/dev/vndbinder` after Project Treble split vendor and framework domains).

### WHY not use standard Linux IPC?

Android could have used sockets, pipes, or System V IPC. Binder was chosen because it
gives three things they don't, all at once:

1. **Identity.** The kernel driver reliably tells the receiver the **calling UID and PID**
   (`Binder.getCallingUid()`). It cannot be spoofed by the caller. *This is the foundation
   of the entire Android permission model* - when you call `sendTextMessage()`, the SMS
   service asks the kernel "who is actually calling?" and checks whether that UID holds
   `SEND_SMS`.
2. **Object references, not just bytes.** Binder can pass a reference to a remote object
   across processes and the kernel maintains the mapping. Sockets pass bytes; you'd have
   to build all of that.
3. **Efficiency.** A single copy (into the receiver's mmap'd buffer) rather than the two
   copies a socket would need.

> **⚙️ Engineering Note:** Internalise this: **`Binder.getCallingUid()` is why Android
> permissions work.** Permission checks are not enforced in your app's process - they're
> enforced in the *service's* process, using kernel-supplied caller identity. That's why
> you cannot bypass a permission check by patching the client-side SDK. You can patch
> your own copy of `checkSelfPermission()` all day; the SMS service still asks the kernel.

### HOW a transaction flows

```
  App process                Kernel                System service process
  ───────────                ──────                ──────────────────────
  Proxy object
  (e.g. ISms$Stub$Proxy)
      │
      │ writes into a Parcel:
      │   interface token, args
      ▼
  transact(code, data, reply, flags)
      │
      ├──────────► /dev/binder driver
      │              │
      │              │ records caller uid/pid
      │              │ copies Parcel into target's mmap buffer
      │              │ wakes a thread in target's binder threadpool
      │              ▼
      │            onTransact(code, data, reply, flags)
      │              │
      │              │ Stub demarshals args
      │              ▼
      │            Service method executes
      │              │  ── enforces permission using
      │              │     Binder.getCallingUid() ──► "does uid 10241
      │              │     hold SEND_SMS?"
      │              ▼
      │            writes result into reply Parcel
      ◄──────────────┘
  returns to caller
```

### The Parcel and its hazards

A `Parcel` is a flat, ordered buffer. Serialisation and deserialisation must agree
exactly on ordering and types. Historically this has been a rich bug class:

- **Parcel mismatch / "bundle mismatch" bugs**, where an object serialises to a different
  size than it deserialises to, allowing an attacker to smuggle extra data past a
  security check. Several launcher/settings privilege-escalation bugs have used this shape.
- **Binder transaction size limit (~1 MB per process, shared)** - exceeding it throws
  `TransactionTooLargeException`. Malware sometimes triggers this deliberately to crash
  security tooling, and analysts hit it accidentally when dumping large data over Binder.

### WHY attackers care

Attackers rarely attack Binder itself; they **use** it, because everything goes through it.
What matters for detection:

- **Binder is the observation point for behavioural analysis.** If you can see the
  transactions, you see what the app is really doing, regardless of what the decompiled
  Java suggests. This is what makes dynamic analysis hard to defeat.
- **Reflection into hidden Binder interfaces** (`android.os.ServiceManager.getService()`)
  is a classic technique for reaching non-SDK APIs. Since Android 9 there are non-SDK
  interface restrictions ([→ Ch 03](03-android-runtime.md), [→ Ch 04](../security/04-android-security-model.md)),
  and malware routinely tries to bypass them. Seeing `ServiceManager` reached by
  reflection in a decompile is a genuine red flag worth scoring.

```bash
# Observe binder activity (rooted / debug builds)
$ adb shell dumpsys binder_calls_stats
$ adb shell cat /sys/kernel/debug/binder/stats     # requires root + debugfs
```

---

## 7. The four components

### WHAT and WHY

Android apps aren't a `main()` function. They're a bag of **components** the system can
start independently. This exists so the system can compose functionality across apps
(share sheet, default handlers, widgets) and reclaim memory aggressively.

| Component | Purpose | Lifecycle entry | Malware use |
|---|---|---|---|
| **Activity** | A screen | `onCreate` → `onStart` → `onResume` | Phishing/overlay screens; fake login UIs |
| **Service** | Background work | `onCreate` → `onStartCommand` / `onBind` | Persistence, C2 polling, VNC streaming |
| **BroadcastReceiver** | React to events | `onReceive` | `BOOT_COMPLETED` persistence, SMS interception |
| **ContentProvider** | Structured data sharing | `onCreate`, then query/insert/... | Data theft target; also a leak surface |

### The Activity lifecycle (know this cold)

```
    onCreate() ──► onStart() ──► onResume() ──► [RUNNING]
                      ▲              ▲               │
                      │              │          onPause()
                      │              │               │
                      │         onRestart()     onStop()
                      │              ▲               │
                      └──────────────┘          onDestroy()
```

Why an analyst cares: overlay malware typically hooks the *foreground app change* event
(via Accessibility) rather than any activity callback of its own, then launches its own
Activity or adds a `TYPE_APPLICATION_OVERLAY` window on top. So when tracing, don't just
look at the malware's activities - look at what it does when *another* app resumes.

### Services and the foreground-service tightening

Background execution has been progressively restricted:

| Android | Change | Effect on malware |
|---|---|---|
| 8 (API 26) | Background execution limits; implicit broadcast restrictions | Forced malware toward foreground services with visible notifications |
| 9 (API 28) | `FOREGROUND_SERVICE` permission required | Trivial to obtain, but now declared in manifest - a static signal |
| 12 (API 31) | Cannot start foreground services from background (mostly) | Pushed persistence toward `BOOT_COMPLETED` + a11y-driven restart |
| 13 (API 33) | `POST_NOTIFICATIONS` runtime permission | Malware must ask for notification permission - visible to the user |
| 14 (API 34) | **Foreground service types mandatory** (`android:foregroundServiceType`) | Declared types are now a static-analysis signal; `mediaProjection` type is a screen-capture tell |

> **⚙️ Engineering Note:** `android:foregroundServiceType="mediaProjection"` in a manifest
> is a strong signal worth scoring. Combined with an accessibility service declaration,
> it's a near-textbook screen-capture/VNC configuration. Screen recording via
> `MediaProjection` is documented in SpyNote and used across the Hidden-VNC families
> (Vultur, Klopatra, BingoMod).

### ContentProviders - the underrated surface

A `ContentProvider` exposes data at a `content://` URI. If exported without permission, any
app on the device can read it. Two failure modes matter:

1. **Leaky providers in legitimate apps** - a banking app that exports a provider with
   session tokens is a direct target. This maps to OWASP **MASVS-STORAGE** and **MASVS-PLATFORM**.
2. **Path traversal in providers** (`openFile` implementations that don't canonicalise
   paths) - allows arbitrary file read from the app sandbox.

```bash
# Enumerate exported providers of an installed app
$ adb shell dumpsys package com.target | grep -A5 "Provider"
# Try reading one (authorised testing only)
$ adb shell content query --uri content://com.target.provider/items
```

---

## 8. Intents and the exported surface

### WHAT

An **Intent** is a message object describing an operation. Two kinds:

- **Explicit** - names the target component (`setClassName("com.bank","com.bank.Login")`).
- **Implicit** - describes an action; the system resolves candidates by intent filter
  (`ACTION_VIEW` with a `https://` URI).

### WHY the exported flag is the whole story

A component is reachable by other apps if `android:exported="true"`. Before Android 12,
declaring *any* `<intent-filter>` made a component exported **by default**. From
**Android 12 (API 31)**, apps targeting 31+ must declare `android:exported` explicitly for
any component with an intent filter, or the app fails to install. This was a major
hardening step and it means:

> **⚙️ Engineering Note:** When you decompile an app targeting API < 31 and see a receiver
> with an intent filter and no explicit `exported` attribute - **it is exported.** Do not
> assume it's private. This is a frequent analysis error and a frequent real vulnerability
> in older banking apps.

### The attack shapes

| Attack | Mechanism | Defence |
|---|---|---|
| **Intent redirection / "Intent forwarding"** | Exported component takes an Intent from an extra and `startActivity()`s it, letting a caller reach internal components | Validate/sanitise nested intents; don't forward attacker-controlled intents |
| **Implicit intent hijack** | Malware registers a matching filter and intercepts an implicit intent carrying sensitive data | Use explicit intents for sensitive payloads |
| **Pending intent hijack** | Mutable `PendingIntent` handed to another app is rewritten | Android 12+ mandates `FLAG_IMMUTABLE` or `FLAG_MUTABLE` explicitly |
| **Task hijacking / StrandHogg** | Malicious activity inserts itself into another app's task via `taskAffinity` + `singleTask`, so the user sees the phishing screen expecting the real app | Set `taskAffinity=""`, `launchMode` care; Android 11+ mitigations |
| **Tapjacking** | Overlay window absorbs or passes through touches to trick the user | `setFilterTouchesWhenObscured(true)`; Android 12 blocks most overlay-obscured touches |

> **🚨 Misconception:** "Tapjacking and overlay attacks are the same thing." Related, not
> identical. **Tapjacking** tricks the user into touching something they can't see.
> **Overlay phishing** draws a convincing fake UI on top of a real app to harvest
> credentials. Banking malware overwhelmingly uses the second. → [Ch 13](../malware/13-android-malware.md)

### Deep links and app links

- **Deep link** - an implicit intent with a custom scheme (`myapp://pay?to=...`). Any app
  can claim the scheme. Not verifiable.
- **App Link** - an `https://` link verified against `/.well-known/assetlinks.json` on the
  developer's domain, tying the link to the app's **signing certificate**. This is
  verifiable, and it's a nice concrete demonstration of why signer identity matters
  ([→ Ch 06](../security/06-certificates.md)).

---

## 9. Storage: from wild west to scoped

### The evolution

| Era | Model | Problem |
|---|---|---|
| ≤ Android 9 | `READ/WRITE_EXTERNAL_STORAGE` gave broad access to shared storage | One granted permission → read every app's files on SD card, all photos, all downloads |
| Android 10 (API 29) | **Scoped storage** introduced (opt-out via `requestLegacyExternalStorage`) | Transition pain |
| Android 11 (API 30) | Scoped storage **enforced**; `MANAGE_EXTERNAL_STORAGE` created as a special, Play-restricted permission | Malware now asks for `MANAGE_EXTERNAL_STORAGE` - which is itself a signal |
| Android 13 (API 33) | Granular media permissions: `READ_MEDIA_IMAGES` / `_VIDEO` / `_AUDIO` | Finer-grained, better user signal |
| Android 14 (API 34) | Partial photo/video access (user picks specific items) | Reduces blast radius further |

### The storage map

```
/data/data/<package>/            ← private sandbox, UID-owned, mode 700
    ├── databases/               ← SQLite (+ -wal, -shm files!)
    ├── shared_prefs/            ← XML key-value (tokens often live here)
    ├── files/                   ← app files
    ├── cache/
    └── code_cache/              ← compiled artifacts, DEX cache

/data/app/<pkg>-<random>/base.apk   ← the installed APK
/sdcard/ (a.k.a. /storage/emulated/0)  ← shared storage, scoped since A10
```

> **⚙️ Engineering Note - the WAL trap:** SQLite databases in modern Android use
> Write-Ahead Logging. **If you copy only `foo.db` and not `foo.db-wal`, you lose the most
> recent transactions** - which are exactly the ones you care about in a fraud
> investigation. Always acquire the `-wal` and `-shm` siblings. This single mistake
> invalidates a shocking amount of amateur mobile forensics.
> → [Ch 17](../digital-forensics/17-digital-forensics.md)

> **🚨 Misconception:** "Data in `/data/data` is encrypted so I can't read it." With
> File-Based Encryption the data is encrypted *at rest*; on a running, unlocked device with
> root, it is readable. Encryption protects against device theft, not against a rooted
> live device or a privileged process.

---

## 10. Detection logic for SUDARSHAN

What this chapter contributes to the pipeline ([→ Ch 23](../sudarshan/23-detection-pipeline.md)):

### Static signals extractable from the manifest

| Signal | Weight | Rationale |
|---|---|---|
| `BOOT_COMPLETED` receiver + `RECEIVE_BOOT_COMPLETED` | Low alone | Ubiquitous; only meaningful in a cluster (T1624) |
| Accessibility service declaration (`android.accessibilityservice.AccessibilityService`) | **High** | The hinge technique (T1453) |
| `android:foregroundServiceType="mediaProjection"` | **Medium-High** | Screen capture / VNC configuration |
| Notification listener service declaration | Medium-High | OTP theft path |
| Exported component with intent filter, no permission, targetSdk < 31 | Medium | Real attack surface; also common in sloppy legit apps |
| Multiple `android:process` values | Low-Medium | Watchdog/anti-removal pattern; also normal for big apps |
| `MANAGE_EXTERNAL_STORAGE` | Medium | Rare and heavily Play-restricted in legitimate apps |
| Thin DEX + large native `.so` | Medium | Logic pushed native to defeat decompilers |

### Composite rule (illustrative)

```yaml
rule: android_odf_capability_cluster
description: >
  Capability cluster characteristic of on-device-fraud banking trojans.
  Not a verdict; raises for analyst review.
severity: high
confidence: medium          # static-only; confirm dynamically
logic:
  all_of:
    - manifest.declares_accessibility_service == true
  at_least_2_of:
    - permissions contains SYSTEM_ALERT_WINDOW
    - permissions contains REQUEST_INSTALL_PACKAGES
    - manifest.declares_notification_listener == true
    - permissions contains any [RECEIVE_SMS, READ_SMS]
    - manifest.foreground_service_types contains mediaProjection
mitre:
  - T1453    # Abuse Accessibility Features
  - T1417.001 # Keylogging
  - T1638    # Adversary-in-the-Middle
  - T1624    # Event Triggered Execution
```

Note the explicit separation of `severity` and `confidence` - a core SUDARSHAN principle
from [Ch 00 §2](../00-introduction.md#2-what-sudarshan-is), developed fully in
[Ch 27 Risk Scoring](../sudarshan/27-risk-scoring.md).

### Dynamic signals

- Enumerate **all** PIDs for the target UID before hooking (§4).
- Watch for a new package appearing in `packages.list` post-detonation (dropper behaviour).
- Snapshot `settings get secure enabled_accessibility_services` before and after.
- Log Binder transactions to `AccessibilityManagerService`, `WindowManagerService`,
  and the SMS stack.

---

## 11. Limitations, edge cases, false positives

### False positives you will generate

| Signal | Legitimate apps that trip it |
|---|---|
| Accessibility service | Password managers (autofill), screen readers, TalkBack alternatives, automation tools (Tasker), remote-support apps |
| `SYSTEM_ALERT_WINDOW` | Chat head bubbles (Messenger), floating players, screen recorders, blue-light filters |
| Notification listener | Smartwatch companions, notification managers, Android Auto helpers |
| `MediaProjection` | Screen recorders, casting apps, remote support (TeamViewer, AnyDesk) |
| Multiple processes | Every large app (browsers, super-apps, anything with a WebView renderer process) |
| Native-heavy code | Games, ML SDKs, video codecs, DRM |

**This is exactly why the cluster matters.** A password manager has accessibility. It does
*not* also have `REQUEST_INSTALL_PACKAGES`, SMS read, a mediaProjection foreground service,
and a dynamically loaded DEX from a remote host.

### False negatives you will suffer

- **Manifest lies.** Capabilities can be added at runtime via dynamically loaded code.
  A dropper's manifest is deliberately boring. → [Ch 03](03-android-runtime.md), [Ch 09](../apk/09-package-manager.md)
- **Native payloads.** If the logic is in `.so`, manifest analysis tells you nothing.
- **Staged delivery.** The Play-hosted dropper is genuinely clean at review time; the
  payload arrives weeks later (Anatsa's pattern).

### Edge cases

- **Work profiles / Android for Work** - the same package can exist twice with different
  UIDs (`u0_a123` vs `u10_a123`). Forensic tooling must handle multi-user.
- **Instant Apps** - run without full installation; different lifecycle assumptions.
- **Split APKs / App Bundles** - the "app" is several APK files; `base.apk` alone is not
  the whole app. → [Ch 02](../apk/02-apk-architecture.md)

### Performance considerations

Manifest parsing is cheap (milliseconds). Full decompilation is expensive (seconds to
minutes). **Design the pipeline so cheap manifest signals gate expensive stages** - this is
the core throughput argument of [Ch 23](../sudarshan/23-detection-pipeline.md).

---

## 12. Engineering tips

1. **Learn `dumpsys` subcommands, not GUI tools.** `dumpsys package`, `dumpsys activity`,
   `dumpsys accessibility`, `dumpsys window`, `dumpsys notification` will answer 80% of
   live-device triage questions.
2. **Always check for sub-processes** before concluding a dynamic run found nothing.
3. **`adb shell pm list packages -f -i`** gives you package → APK path → **installer
   package**. Installer attribution is one of the most under-used signals in the field.
   → [Ch 09](../apk/09-package-manager.md)
4. **Snapshot state before and after detonation.** Diffs are worth more than absolutes.
5. **When decompiled Java doesn't explain observed behaviour, suspect native code or
   dynamic loading** before suspecting your tools.

---

## 13. Judge Insights

**What judges ask:** *"Why does understanding Android internals matter for a malware
platform? Isn't this just a file-scanning problem?"*

**Perfect answer:** Because the malicious behaviour isn't in the file - it's in how the
file uses the platform. An APK's bytes are inert. The damage happens when an Accessibility
Service starts receiving events from `AccessibilityManagerService`, when a
`TYPE_APPLICATION_OVERLAY` window is added through `WindowManagerService`, when
`BOOT_COMPLETED` re-arms persistence. If you don't model the platform, you're doing
file-format matching, and file-format matching is what packers exist to defeat.

**Common mistake:** Describing Android as "just Linux." It gets you a follow-up you won't
survive. The interesting security boundaries - permissions, components, Binder identity - are Android constructs layered *above* Linux, and the reason Android permissions are
enforceable at all is that the Binder driver supplies unspoofable caller UID.

**Follow-up questions to expect:**
- *"How does Android actually enforce a permission?"* → In the service process, via
  `Binder.getCallingUid()`, not in the calling app. §6.
- *"Why is Zygote a security-relevant design?"* → UID assignment, SELinux transition, and
  seccomp installation all occur post-fork, pre-app-code. §4.
- *"How does malware survive reboot?"* → `BOOT_COMPLETED` receiver; MITRE T1624. §3.

**Fact that impresses:** From Android 12, apps targeting API 31+ **fail to install** if a
component has an intent filter without an explicit `android:exported`. So when analysing
an older app, an intent-filtered component with no `exported` attribute *is exported* - a real and frequently-missed vulnerability in legacy banking apps.

---

## 14. Interview Insights

**Q: "Explain Binder and why Android uses it instead of sockets."**
Senior answer covers all three drivers: unspoofable caller identity from the kernel
(foundation of permission enforcement), remote object references (not just byte streams),
and single-copy efficiency via the receiver's mmap'd buffer. Beginners describe it as
"Android's IPC" and stop - that answer scores zero.

**Q: "What is Zygote and why does it exist?"**
Startup latency + copy-on-write memory sharing. Bonus points for noting that the child's
UID assignment, SELinux domain transition, and seccomp filter all happen after fork and
before app code runs.

**Q: "An app declares a BroadcastReceiver with an intent filter but no exported attribute.
Is it exported?"**
Correct answer: *it depends on targetSdk.* Below API 31, yes - declaring an intent filter
makes it exported by default. At API 31+, the app wouldn't install without an explicit
declaration. This question separates people who have read the docs from people who have
read blog posts.

**Q: "How would you find what an app is doing on a live device without decompiling it?"**
`dumpsys` family, `logcat`, `ps -A` for sub-processes, `settings get secure
enabled_accessibility_services`, `appops get`, network capture. The interviewer wants to
see you reach for observation before reverse engineering.

**Beginner mistakes:**
- Confusing Android *version* with *API level*.
- Saying "the app checks the permission" - no, the *service* checks the caller's permission.
- Assuming one package = one process.
- Forgetting `-wal` files when pulling SQLite databases.

---

## 15. Cross-references

**Upstream (read first):**
- [← Ch 00 Introduction](../00-introduction.md) - conventions, Master Lifecycle

**Downstream (this enables):**
- [→ Ch 02 APK Architecture](../apk/02-apk-architecture.md) - what gets installed
- [→ Ch 03 Android Runtime](03-android-runtime.md) - how the forked process executes code
- [→ Ch 04 Android Security Model](../security/04-android-security-model.md) - the sandbox Zygote sets up
- [→ Ch 09 Package Manager](../apk/09-package-manager.md) - PMS in depth
- [→ Ch 13 Android Malware](../malware/13-android-malware.md) - a11y, overlay, tapjacking in full
- [→ Ch 17 Digital Forensics](../digital-forensics/17-digital-forensics.md) - the artifact paths in §3 and §9

**Related concepts:** Binder → permission enforcement → `Binder.getCallingUid()` →
service-side checks → reflection into `ServiceManager` → non-SDK restrictions → Ch 03/04.

---

## 16. References

1. Android Developers - *Platform Architecture*. https://developer.android.com/guide/platform
2. AOSP - *Binder / AIDL* documentation. https://source.android.com/docs/core/architecture/hidl/binder-ipc
3. AOSP - *Application Sandbox*. https://source.android.com/docs/security/app-sandbox
4. Android Developers - *App startup and the Zygote process* (Platform docs).
5. Android Developers - *Behavior changes: Apps targeting Android 12* (explicit `android:exported`). https://developer.android.com/about/versions/12/behavior-changes-12
6. Android Developers - *Storage updates in Android 11* (scoped storage). https://developer.android.com/about/versions/11/privacy/storage
7. Android Developers - *Foreground service types are required (Android 14)*. https://developer.android.com/about/versions/14/changes/fgs-types-required
8. MITRE ATT&CK for Mobile - T1624 Event Triggered Execution; T1453 Abuse Accessibility Features. https://attack.mitre.org/matrices/mobile/
9. Cleafy Labs - *Klopatra* analysis (2025) - Java→native code migration.
10. Cyble Research and Intelligence Labs - GodFather variant analysis - native code migration.
11. Google Project Zero - Android research archive. https://googleprojectzero.blogspot.com/

### Further reading
- *Android Internals: A Confectioner's Cookbook*, Jonathan Levin
- AOSP source: `frameworks/base/services/core/java/com/android/server/`
- OWASP MASTG - platform interaction test cases (MASVS-PLATFORM)

---

*Previous: [← Ch 00 Introduction](../00-introduction.md) · Next: [Ch 02 APK Architecture →](../apk/02-apk-architecture.md)*
