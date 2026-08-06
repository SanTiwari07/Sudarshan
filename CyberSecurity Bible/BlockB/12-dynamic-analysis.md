# 12 — Dynamic Analysis

> **Chapter ID:** `CH12` · **Block:** B (Analysis Craft) · **Status:** Stable
> **Tags:** `#dynamic-analysis` `#frida` `#objection` `#detonation` `#sandbox-evasion` `#network-capture` `#memory-forensics`
> **Last Updated:** 2026-08-05 · **Version:** 1.0.0
> **Prerequisites:** [Ch 03](../android/03-android-runtime.md), [Ch 10](../reverse-engineering/10-reverse-engineering.md), [Ch 11](../static-analysis/11-static-analysis.md)

> **⚖️ Scope note.** Everything here is for **authorised laboratory analysis of malware
> samples** on hardware you own, under proper legal authority and chain of custody. The
> instrumentation techniques described (hooking, TLS interception, pinning bypass) are the
> standard toolkit of defensive malware analysis and mobile app security testing. Applying
> them to software or devices you are not authorised to test is a different activity with
> different legal consequences.

---

## Table of Contents

1. [Why dynamic analysis exists](#1-why-dynamic-analysis-exists)
2. [The lab](#2-the-lab)
3. [Detonation methodology](#3-detonation-methodology)
4. [Frida](#4-frida)
5. [The essential hook library](#5-the-essential-hook-library)
6. [objection and other instrumentation](#6-objection-and-other-instrumentation)
7. [Network analysis](#7-network-analysis)
8. [Memory analysis](#8-memory-analysis)
9. [Sandbox evasion](#9-sandbox-evasion)
10. [Sandboxes and services](#10-sandboxes-and-services)
11. [Detection logic for SUDARSHAN](#11-detection-logic-for-sudarshan)
12. [Limitations, edge cases, false positives](#12-limitations-edge-cases-false-positives)
13. [Engineering tips](#13-engineering-tips)
14. [Judge Insights](#14-judge-insights)
15. [Interview Insights](#15-interview-insights)
16. [Cross-references](#16-cross-references)
17. [References](#17-references)

---

## 1. Why dynamic analysis exists

Static analysis reads the code. Dynamic analysis watches the code **run**. The gap between
those two is where modern Android malware lives.

| Static cannot see | Dynamic reveals |
|---|---|
| Payload fetched after install (droppers) | The fetch, and the payload itself |
| Packed/encrypted code | Plaintext DEX at the moment of loading |
| Reflection targets | The actual resolved method |
| Encrypted strings | Decrypted plaintext at `Cipher.doFinal` |
| C2 endpoints and protocol | Live traffic |
| Native logic | Behaviour, without reading assembly |
| Conditional triggers | Which conditions fired |

But dynamic has an equal and opposite blindness:

| Dynamic cannot see | Static reveals |
|---|---|
| Code paths that didn't execute | All code paths |
| Behaviour gated on geography/time/C2 | The gate itself |
| Anything, if the sample detects the sandbox | The detection logic |
| Anything, if C2 is offline | The embedded C2 config |

> **⚙️ Engineering Note — the thesis of Block B:** neither technique is sufficient, and their
> blind spots are **complementary rather than overlapping**. Static is blind to what wasn't
> shipped; dynamic is blind to what didn't run. A platform built on one of them has a
> structural, unfixable gap. **Fusion is not a nice-to-have; it is the product.**
> → [Ch 23](../sudarshan/23-detection-pipeline.md), [Ch 32](../appendix/32-common-misconceptions.md)

---

## 2. The lab

### Real devices vs emulators

| | Emulator (AVD, Genymotion) | Real device |
|---|---|---|
| Cost | Free | Hardware per lane |
| Scale | Easy parallelism | Limited, physical |
| Snapshot/restore | Instant | Slow (reflash/factory reset) |
| **Detection** | **Trivially detected** | Hard to detect |
| Native ARM code | Needs ARM translation or ARM host | Native |
| Sensors, telephony, SIM | Simulated, obviously fake | Real |
| Verdict | Good for triage volume | **Required for evasive samples** |

> **⚙️ Engineering Note:** The pragmatic architecture is **both**. Emulator lanes for volume
> triage where cost dominates; a smaller pool of real devices for samples that showed nothing
> in the emulator or that statically contained emulator-detection logic. Routing a sample to
> the real-device pool *because the emulator run was silent* is a design decision worth making
> explicit — silence is a signal, not a result.

### Rooting and Magisk

Frida's server mode needs root. **Magisk** is the standard: systemless root with a **DenyList**
that hides root from selected apps. Note that Magisk hiding and malware anti-root detection are
in a continuous arms race — expect to maintain this.

```bash
$ adb shell su -c 'magisk --denylist add com.suspect.app'
```

### Environment metadata — record it or your results aren't reproducible

```yaml
lab_environment:
  device_model: "Pixel 6a"
  android_version: "14"
  api_level: 34
  build_fingerprint: "google/bluejay/..."
  art_module_version: "..."        # Mainline, varies independently → Ch 03
  conscrypt_version: "..."         # Mainline TLS → Ch 05
  root: "Magisk 27.0"
  frida_version: "16.x"
  selinux: "Enforcing"
  network_egress: "controlled, logged"
  sim_present: true
  locale: "en-IN"
  timezone: "Asia/Kolkata"
```

> **⚙️ Engineering Note:** ART and Conscrypt are **Mainline modules** updated through Google
> Play independently of the OS version ([Ch 03 §2](../android/03-android-runtime.md#2-dalvik--art-the-history-that-still-matters),
> [Ch 05 §2](../security/05-android-cryptography.md#2-the-android-crypto-stack)). Two devices
> both reporting "Android 14" can behave differently. If a finding can't be reproduced six
> months later, an unrecorded module version is a common reason.
>
> Also: set **locale and timezone to the target region**. Geofenced samples — ERMAC excludes
> CIS nations; many campaigns activate only in specific countries — will simply not run
> otherwise, and you'll record a false negative.

### Network containment

You must let the sample reach C2 to learn anything, and you must not let it cause harm.

```
   Sample device ──► logged proxy ──► filtered egress ──► internet
                          │
                          ├── full PCAP capture
                          ├── DNS logging
                          ├── TLS interception (lab CA)
                          └── blocklist: SMS gateways, payment endpoints,
                                         known victim infrastructure
```

Rate-limit outbound, block premium-SMS and payment paths, and never detonate on a network
that can reach production systems.

---

## 3. Detonation methodology

Reproducibility comes from doing the same thing every time.

```
┌──────────────────────────────────────────────────────────────┐
│ 1. SNAPSHOT (pre-state)                                      │
│    pm list packages -3 -i                                    │
│    settings get secure enabled_accessibility_services        │
│    settings get secure enabled_notification_listeners        │
│    cmd appops get --all                                      │
│    dumpsys device_policy                                     │
└───────────────────────────┬──────────────────────────────────┘
                            ▼
┌──────────────────────────────────────────────────────────────┐
│ 2. INSTRUMENT BEFORE LAUNCH                                  │
│    frida -U -f com.suspect -l hooks.js --pause               │
│    ★ spawn-gate: hooks must be live before Application       │
│      .onCreate, or you miss the unpacking                    │
└───────────────────────────┬──────────────────────────────────┘
                            ▼
┌──────────────────────────────────────────────────────────────┐
│ 3. INSTALL + LAUNCH                                          │
│    record install source; start logcat and PCAP              │
└───────────────────────────┬──────────────────────────────────┘
                            ▼
┌──────────────────────────────────────────────────────────────┐
│ 4. STIMULATE                                                 │
│    grant permissions if the scenario calls for it            │
│    open a decoy banking app · send an SMS · reboot           │
│    wait (many samples idle for minutes)                      │
└───────────────────────────┬──────────────────────────────────┘
                            ▼
┌──────────────────────────────────────────────────────────────┐
│ 5. COLLECT                                                   │
│    dumped DEX · PCAP + TLS keys · logcat · heap dump         │
│    screenshots · file system diff                            │
└───────────────────────────┬──────────────────────────────────┘
                            ▼
┌──────────────────────────────────────────────────────────────┐
│ 6. SNAPSHOT (post-state) and DIFF        ★ THE PAYOFF        │
│    new packages?  → dropper confirmed  → Ch 09               │
│    new a11y services? new appops? new device admin?          │
└───────────────────────────┬──────────────────────────────────┘
                            ▼
┌──────────────────────────────────────────────────────────────┐
│ 7. RECURSE on every dumped/installed artifact  → Ch 03 §11    │
└──────────────────────────────────────────────────────────────┘
```

### The stimulation problem

Malware waits for the user. An unstimulated detonation frequently records nothing.

| Stimulus | Triggers |
|---|---|
| Grant accessibility | The entire capability chain |
| Open a decoy banking app | Overlay injection, foreground-app detection |
| Send an inbound SMS | OTP interception path |
| Post a notification | Notification-listener theft |
| Reboot | `BOOT_COMPLETED` persistence ([Ch 01 §3](../android/01-android-internals.md#3-boot-from-power-button-to-launcher)) |
| Idle 10–30 min | Time-delayed activation |
| Screen lock/unlock | Lock-state-gated behaviour |

> **⚙️ Engineering Note:** Install a set of **decoy apps** whose package names match common
> banking targets. Overlay malware enumerates installed packages and only acts when a target is
> present — a clean device gives it nothing to attack, and you record a false negative. Build
> the decoy set from the target lists your Tier 2 static analysis extracts
> ([Ch 11 §5](../static-analysis/11-static-analysis.md#5-tier-2--resource-and-asset-mining)).
> That's a nice closed loop: static tells dynamic what environment to fake.

---

## 4. Frida

### Architecture

```
   HOST                                    DEVICE
   ────                                    ──────
   frida CLI / Python  ──USB/TCP──►  frida-server (root)
   your agent (JS)                        │ injects
                                          ▼
                                    target app process
                                    ┌──────────────────┐
                                    │ Frida agent      │
                                    │ (GumJS runtime)  │
                                    │  Java.* bridge   │
                                    │  Interceptor     │
                                    │  Memory / Module │
                                    └──────────────────┘
```

Two deployment modes:

| Mode | Requires root | Use |
|---|---|---|
| **frida-server** | Yes | Standard lab; can spawn and attach to anything |
| **frida-gadget** | No — inject the `.so` into the APK and re-sign | Non-rooted devices; changes the signer ([Ch 07](../security/07-apk-signing.md)) |

### Setup

```bash
$ pip install frida-tools
# push a matching frida-server build for the device ABI
$ adb push frida-server-16.x-android-arm64 /data/local/tmp/fs
$ adb shell "chmod 755 /data/local/tmp/fs && su -c '/data/local/tmp/fs &'"

$ frida-ps -U                                  # list processes
$ frida -U -f com.suspect -l hooks.js --pause  # ★ spawn + pause + hook
$ frida -U -n com.suspect -l hooks.js          # attach to running
```

> **⚙️ Engineering Note — always spawn, never attach, for malware.** `-f ... --pause` gets
> your hooks in place before `Application.onCreate` runs. Attaching to an already-running
> process means the packer already unpacked, the C2 config was already decrypted, and you
> missed all of it. This single flag is the difference between a productive session and an
> empty one.

### Core API

```javascript
Java.perform(function () {
  const Cls = Java.use('com.example.Target');          // class handle

  // hook a method (specify overload when ambiguous)
  Cls.method.overload('java.lang.String').implementation = function (arg) {
    console.log('[hook] arg=' + arg);
    const ret = this.method(arg);                       // call original
    console.log('[hook] ret=' + ret);
    return ret;
  };

  Java.choose('com.example.Target', {                   // live heap instances
    onMatch: function (inst) { console.log(inst.someField.value); },
    onComplete: function () {}
  });
});

// native interception
Interceptor.attach(Module.findExportByName('libc.so', 'open'), {
  onEnter(args) { this.path = args[0].readCString(); },
  onLeave(ret)  { console.log('open(' + this.path + ') = ' + ret); }
});
```

> **⚙️ Engineering Note — when a hook silently doesn't fire**, in order of likelihood:
> (1) **inlining** — the caller has an inlined copy and never dispatches
> ([Ch 03 §3](../android/03-android-runtime.md#3-compilation-dex2oat-jit-aot-and-profiles));
> (2) wrong **overload**; (3) the code runs in a **different process**
> ([Ch 01 §4](../android/01-android-internals.md#4-zygote-the-process-factory)); (4) the class
> is loaded by a **different class loader** and isn't visible to `Java.use` yet; (5) the app
> detected Frida. Check in that order — most people jump to (5) and waste hours.

---

## 5. The essential hook library

These five hooks cover the majority of Android banking malware behaviour. Together they are
SUDARSHAN's standard instrumentation payload.

### 1. Class loaders — dump every payload

The highest-value hook in Android analysis. Defeats packers *and* catches staged payloads.
Full version in [Ch 10 §9](../reverse-engineering/10-reverse-engineering.md#9-unpacking-strategy).

```javascript
Java.perform(function () {
  const IM = Java.use('dalvik.system.InMemoryDexClassLoader');
  // BOTH overloads — missing the array form loses many samples
  IM.$init.overload('java.nio.ByteBuffer','java.lang.ClassLoader')
    .implementation = function (b, p) {
      console.log('[DEX] in-memory, size=' + b.remaining()); dumpBuffer(b);
      return this.$init(b, p);
    };
  IM.$init.overload('[Ljava.nio.ByteBuffer;','java.lang.ClassLoader')
    .implementation = function (bs, p) {
      console.log('[DEX] in-memory array n=' + bs.length);
      for (let i = 0; i < bs.length; i++) dumpBuffer(bs[i]);
      return this.$init(bs, p);
    };
  const DCL = Java.use('dalvik.system.DexClassLoader');
  DCL.$init.overload('java.lang.String','java.lang.String','java.lang.String','java.lang.ClassLoader')
    .implementation = function (a,b,c,d) {
      console.log('[DEX] file path=' + a);
      return this.$init(a,b,c,d);
    };
});
```

### 2. Crypto — recover keys and plaintext

```javascript
Java.perform(function () {
  const Cipher = Java.use('javax.crypto.Cipher');
  Cipher.doFinal.overload('[B').implementation = function (input) {
    const out = this.doFinal(input);
    console.log('[crypto] ' + this.getAlgorithm() + ' ' + input.length + '->' + out.length);
    try { console.log('  plain: ' + Java.use('java.lang.String').$new(out)); } catch (e) {}
    return out;
  };
  const SKS = Java.use('javax.crypto.spec.SecretKeySpec');
  SKS.$init.overload('[B','java.lang.String').implementation = function (k, alg) {
    console.log('[key] ' + alg + ' = ' + hex(k));   // ★ correlation pivot → Ch 05 §10
    return this.$init(k, alg);
  };
});
```

### 3. Reflection — rebuild the real call graph

```javascript
Java.perform(function () {
  const M = Java.use('java.lang.reflect.Method');
  M.invoke.overload('java.lang.Object','[Ljava.lang.Object;')
    .implementation = function (obj, args) {
      console.log('[refl] ' + this.getDeclaringClass().getName() + '.' + this.getName());
      return this.invoke(obj, args);
    };
});
```

### 4. Network — see endpoints regardless of TLS

```javascript
Java.perform(function () {
  const URL = Java.use('java.net.URL');
  URL.$init.overload('java.lang.String').implementation = function (s) {
    console.log('[net] URL ' + s);
    return this.$init(s);
  };
  try {
    const RB = Java.use('okhttp3.Request$Builder');
    RB.url.overload('java.lang.String').implementation = function (u) {
      console.log('[net] okhttp ' + u); return this.url(u);
    };
  } catch (e) {}
  try {
    const WS = Java.use('java.net.Socket');
    WS.connect.overload('java.net.SocketAddress','int').implementation = function (a, t) {
      console.log('[net] socket ' + a); return this.connect(a, t);
    };
  } catch (e) {}
});
```

### 5. Capability APIs — observe the attack directly

```javascript
Java.perform(function () {
  // overlay window creation
  const WM = Java.use('android.view.WindowManagerImpl');
  WM.addView.implementation = function (v, p) {
    console.log('[OVERLAY] addView type=' + p.type.value);   // 2038 = TYPE_APPLICATION_OVERLAY
    return this.addView(v, p);
  };
  // accessibility events — foreground app tracking
  const AS = Java.use('android.accessibilityservice.AccessibilityService');
  AS.onAccessibilityEvent.implementation = function (e) {
    console.log('[A11Y] pkg=' + e.getPackageName() + ' type=' + e.getEventType());
    return this.onAccessibilityEvent(e);
  };
  // SMS exfil
  const SM = Java.use('android.telephony.SmsManager');
  SM.sendTextMessage.implementation = function (d, s, t, a, b) {
    console.log('[SMS] to=' + d + ' body=' + t);
    return this.sendTextMessage(d, s, t, a, b);
  };
});
```

> **⚙️ Engineering Note:** Hook `WindowManagerImpl.addView` and log `params.type`. A value of
> **2038** (`TYPE_APPLICATION_OVERLAY`) appearing while a *different* app is in the foreground
> is close to direct evidence of an overlay attack — it's the technique itself, observed live,
> not inferred from a permission. That log line is one of the most convincing artifacts you can
> put in an investigation report. → [Ch 29](../sudarshan/29-investigation-reports.md)

---

## 6. objection and other instrumentation

**objection** wraps Frida in a task-oriented REPL — fast for interactive work.

```bash
$ objection -g com.suspect explore
com.suspect on (Pixel 6a: 14) [usb] # android hooking list activities
                                    # android hooking watch class com.suspect.Api
                                    # android sslpinning disable
                                    # android root disable
                                    # memory list modules
                                    # android heap search instances com.suspect.Config
```

| Tool | Role |
|---|---|
| **objection** | Interactive Frida wrapper; quick recon |
| **LSPosed** (Xposed successor) | Persistent system-wide hooking via modules; survives reboot |
| **Magisk** | Systemless root + DenyList |
| **jnitrace** | JNI API tracing, recovers `RegisterNatives` → [Ch 10 §10](../reverse-engineering/10-reverse-engineering.md#10-native-reverse-engineering) |
| **strace / ltrace** | Syscall/library tracing (root) |
| **`am` / `dumpsys` / `logcat`** | Native observation, no instrumentation → [Ch 01 §5](../android/01-android-internals.md#5-system_server-and-the-service-model) |

> **⚙️ Engineering Note:** Do the **uninstrumented** observation pass first — `logcat`,
> `dumpsys`, package diffing, PCAP. It's free, it can't be detected by anti-Frida checks, and
> on a surprising number of samples it answers the question. Reach for Frida when passive
> observation stops being enough, not reflexively.

---

## 7. Network analysis

### The layered picture

```
   App code
      │  ← Frida hooks here see plaintext + URLs regardless of TLS
      ▼
   TLS (Conscrypt/BoringSSL)
      │  ← pinning enforced here
      ▼
   Socket
      │  ← mitmproxy/Burp intercept here (needs trusted CA + no pinning)
      ▼
   Network
      │  ← PCAP here always works; payload encrypted unless intercepted
```

**Three vantage points, three reliabilities.** Application-layer hooks are the most robust:
they see the data before encryption and after decryption, and pinning is irrelevant to them.

### The Android 7 obstacle

From **Android 7.0 (API 24)**, apps don't trust user-added CAs unless
`network_security_config` opts in ([Ch 05 §7](../security/05-android-cryptography.md#7-tls-pinning-and-the-trust-store)).
Lab options, in increasing intrusiveness:

1. **Application-layer Frida hooks** — no CA needed at all. Preferred.
2. **Install the lab CA into the *system* store** (rooted device, Magisk module) — works for
   apps that don't pin.
3. **Patch `network_security_config` and re-sign** — changes the signer, alters the sample.
4. **Runtime pinning bypass** — `objection`'s `android sslpinning disable`, or targeted hooks.

```bash
$ mitmproxy --mode transparent --showhost -w capture.flow
$ adb shell settings put global http_proxy 10.0.0.5:8080
$ tcpdump -i any -w capture.pcap                 # on device, or upstream tap
```

### What to extract

| Artifact | Value |
|---|---|
| DNS queries | C2 domains, DGA behaviour (Octo2 uses a DGA) |
| IPs + ports + JA3/JA4 fingerprints | Infrastructure pivots → [Ch 15](../malware/15-malware-infrastructure.md) |
| HTTP paths, headers, User-Agent | Protocol fingerprint; often family-distinctive |
| POST bodies (decrypted) | Exfiltrated data, victim identifiers |
| WebSocket / MQTT frames | Antidot uses socket.io; Copybara and DroidBot use MQTT |
| Telegram / Firebase endpoints | Dead-drop C2 (Medusa; Indian UPI campaigns use FCM) |

> **⚙️ Engineering Note — an adversary's weak crypto is your detection.** ToxicPanda uses
> **AES-ECB** for C2 (Cleafy, October 2024). ECB is deterministic, so identical plaintext
> blocks produce identical ciphertext blocks — you can fingerprint and sometimes structure the
> traffic **without the key**. Always record ciphertext block patterns, not just "encrypted
> traffic observed." → [Ch 05 §9](../security/05-android-cryptography.md#9-how-malware-uses-cryptography)

---

## 8. Memory analysis

The runtime holds plaintext that the file never does.

```bash
# Heap dump — best timed AFTER first C2 contact, BEFORE state is cleared
$ adb shell am dumpheap com.suspect /data/local/tmp/heap.hprof
$ adb pull /data/local/tmp/heap.hprof
$ hprof-conv heap.hprof heap-std.hprof         # convert for standard tools
$ strings -n 8 heap-std.hprof | grep -Ei 'https?://|api_key|bot[0-9]{8,}:'
```

```javascript
// Live object inspection beats raw scanning — the GC moves objects (Ch 03 §10)
Java.perform(function () {
  Java.choose('com.suspect.Config', {
    onMatch: function (i) { console.log('c2=' + i.c2Url.value + ' key=' + i.aesKey.value); },
    onComplete: function () {}
  });
});
```

Also: **DEX carving from memory** for packers that never touch a Java class loader — see
[Ch 10 §9](../reverse-engineering/10-reverse-engineering.md#9-unpacking-strategy).

> **⚙️ Engineering Note:** Timing is everything. Dump too early and the C2 config is still
> encrypted; too late and the sample may have zeroed its buffers. Trigger the dump **on the
> first outbound connection** — a network-event-driven dump is far more reliable than a
> fixed timer.

---

## 9. Sandbox evasion

### The techniques

| Check | Signal | Countermeasure |
|---|---|---|
| **Emulator** | `Build.FINGERPRINT` contains `generic`, `ro.kernel.qemu`, `/dev/qemu_pipe`, missing sensors, default IMEI | **Real devices** |
| **Root** | `su` paths, Magisk packages, `ro.debuggable` | Magisk DenyList; hook checks |
| **Frida** | Port 27042, `frida-server` in process list, `/proc/self/maps` string scan, named pipes | Rename server, non-default port, gadget |
| **Debugger** | `Debug.isDebuggerConnected()`, `TracerPid` in `/proc/self/status` | Hook; patch `TracerPid` |
| **Analysis apps** | Enumerates installed AV/RE tools | Clean device image |
| **Geofencing** | Locale, SIM MCC/MNC, IP geolocation. **ERMAC excludes CIS nations.** | Set locale/timezone/SIM to target region |
| **Time bomb** | Delay hours/days before acting | Long-running lanes; time acceleration |
| **C2 gating** | No behaviour unless C2 responds with a command | **Flag inconclusive** — see below |
| **User interaction** | Requires taps/swipes to proceed | UI automation, decoy apps |
| **Sensor plausibility** | Flat accelerometer = emulator | Real device, or synthetic sensor data |

### The C2-gating problem — and the rule that follows

Many samples do nothing without a live C2. If the panel is down, seized, or geo-filtering you,
your detonation records a benign-looking run.

> **⚙️ Engineering Note — the most important operational rule in this chapter:**
> **"C2 unreachable" must produce an `inconclusive` verdict, never `clean`.**
>
> ```yaml
> analysis_quality:
>   c2_contacted: false
>   c2_endpoints_attempted: ["hxxps://dksu[.]top/api"]
>   behaviour_observed: minimal
>   verdict: inconclusive          # NOT clean
>   confidence_ceiling: 0.3
>   requeue: {after: 24h, max_attempts: 5}
> ```
>
> A platform that reports "low risk" for a sample it couldn't provoke is worse than one that
> says "unable to assess" — because a bank will act on the first. Requeue and re-detonate; C2
> infrastructure comes back.

### Evasion detection as a signal

Every check the sample performs is **code you can observe**. An app that scans for
`frida-server`, checks `TracerPid`, enumerates Magisk packages, and reads
`Build.FINGERPRINT` has revealed a great deal about its intent. Log evasion attempts as a
first-class finding.

> **🚨 Misconception:** "Anti-analysis present → malware." Every serious banking app ships
> RASP with these exact checks; root and emulator detection are industry-standard hardening
> ([Ch 10 §11](../reverse-engineering/10-reverse-engineering.md#11-anti-analysis-and-how-it-fails)).
> The signal is anti-analysis **plus** a malicious capability cluster **plus** an unknown
> signer — never anti-analysis alone.

---

## 10. Sandboxes and services

| Service | Notes |
|---|---|
| **MobSF dynamic analyser** | Integrated with its static side; Frida-based; convenient, less configurable → [Ch 11 §8](../static-analysis/11-static-analysis.md#8-mobsf) |
| **CAPE Sandbox** | Mature open-source sandbox, strongest on Windows; Android support is secondary |
| **Cuckoo (legacy)** | Largely superseded; still referenced in older literature |
| **Joe Sandbox** | Commercial, strong Android support and reporting |
| **Hatching Triage** | Commercial, high throughput |
| **VirusTotal / Google Threat Intelligence** | Multi-engine + behavioural reports + Retrohunt/LiveHunt |
| **Hybrid Analysis** | Free tier, Falcon Sandbox backend |

### On VirusTotal specifically

> **🚨 Misconception:** "VirusTotal is an antivirus." It is a **multi-engine aggregator**. Its
> detection count is not a verdict:
>
> - **Low count ≠ clean.** Zero-day droppers routinely score 0–2/70 on first upload. Anatsa's
>   Play droppers were undetected at the time they were reaching top-10 chart positions.
> - **High count ≠ confirmed banking trojan.** Engines copy each other's labels, and generic
>   heuristics inflate counts on packed-but-benign apps.
> - **Engine labels are inconsistent.** The same sample gets six family names from six vendors,
>   reflecting the naming divergence discussed throughout Block C.
>
> Use VT for **enrichment and corroboration** — first-seen date, submission geography,
> behavioural report, related samples, Retrohunt — not as the verdict.
> → [Ch 16](../threat-intelligence/16-threat-intelligence.md), [Ch 32](../appendix/32-common-misconceptions.md)

---

## 11. Detection logic for SUDARSHAN

### The dynamic analysis record

```yaml
dynamic_analysis:
  environment: { ... }              # §2 — mandatory for reproducibility

  behaviour:
    a11y_service_enabled: bool
    a11y_events_observed: int
    a11y_target_packages: []        # ★ which apps it watched for
    overlay_windows_created:
      - {type: 2038, foreground_pkg: "com.decoy.bank", ts: "..."}   # ★ the attack, observed
    gestures_dispatched: int         # canPerformGestures in action
    sms_read: int
    sms_sent: [{dest, body_hash}]
    notifications_read: int
    screen_capture_started: bool
    device_admin_requested: bool
    packages_installed: []           # ★ dropper confirmation → Ch 09

  artifacts_dumped:
    dex: [{sha256, size, source: "InMemoryDexClassLoader"}]   # → RECURSE
    apk: [{sha256, package}]                                   # → RECURSE
    keys: [{algorithm, hex}]                                   # → correlation pivot
    heap_strings_of_interest: []

  network:
    dns: []
    endpoints: [{ip, port, sni, ja3}]
    http: [{method, url, ua, body_len}]
    protocol: "https|websocket|mqtt|telegram|firebase"
    c2_contacted: bool
    c2_responded: bool
    encryption_observed: "AES-ECB|AES-CBC|none|unknown"

  evasion_attempts:
    emulator_checks: int
    root_checks: int
    frida_checks: int
    debugger_checks: int
    geo_checks: int

  analysis_quality:
    stimulated: []                  # which stimuli were applied
    runtime_seconds: int
    hooks_fired: int
    c2_contacted: bool
    verdict_eligible: bool          # false if C2 unreachable
    confidence_ceiling: float
```

### High-confidence dynamic rules

| Rule | Logic | Severity | Confidence |
|---|---|---|---|
| **Overlay attack observed** | `addView(type=2038)` while a different package is foreground | Critical | **High** |
| **Dropper confirmed** | New package appeared post-detonation | Critical | **High** |
| **Payload dumped** | DEX recovered from class loader; child artifact malicious | Critical | High |
| **OTP exfiltration** | SMS body read → outbound network within N seconds | Critical | High |
| **Gesture injection** | `dispatchGesture` / `performGlobalAction` on another app | High | High |
| **Screen capture** | `MediaProjection.createVirtualDisplay` started | High | Medium-High |
| **Anti-uninstall** | Device admin activated + a11y intercepting Settings | High | High |
| **C2 established** | Outbound to a known-malicious endpoint | High | High |
| **Evasion cluster** | ≥3 distinct evasion check types | Medium | Medium |

> **⚙️ Engineering Note:** Dynamic findings are **behavioural evidence**, which is
> qualitatively stronger than static capability. "The app declared `SYSTEM_ALERT_WINDOW`" is a
> capability claim; "the app created a `TYPE_APPLICATION_OVERLAY` window at 14:32:07 while
> `com.decoy.bank` was foreground" is an observed attack with a timestamp. **Weight dynamic
> confirmations well above static indications** in the score, and quote them verbatim in
> reports. → [Ch 27](../sudarshan/27-risk-scoring.md), [Ch 29](../sudarshan/29-investigation-reports.md)

---

## 12. Limitations, edge cases, false positives

### Limitations

- **Coverage**: you only see executed paths.
- **Time**: 5–15 minutes per sample; the pipeline bottleneck.
- **Detectability**: evasive samples behave differently under observation.
- **C2 dependence**: dead infrastructure produces silent runs.
- **Environment sensitivity**: geofencing, decoy apps, SIM presence all change outcomes.

### False positives

| Observation | Innocent cause |
|---|---|
| Overlay window created | Chat bubbles, floating players, screen recorders |
| Accessibility events | Password managers, TalkBack, automation tools |
| Screen capture | Screen recorders, casting, remote support |
| Network to unknown hosts | Analytics, ads, CDNs, crash reporting |
| Anti-debug / anti-root checks | **Standard banking-app RASP** |
| Package installation | App stores, MDM agents, updaters |

**Context is the discriminator**: an overlay over the app's *own* activity is normal; an
overlay over a *different* app's activity, triggered by accessibility-detected foreground
change, is the attack.

### False negatives

- Sample detected the sandbox.
- C2 offline (**must be `inconclusive`**).
- Geofenced away from the lab's apparent location.
- Time-delayed beyond the run window.
- Required user interaction not simulated.
- No decoy target apps installed.

### Performance

| Stage | Cost |
|---|---|
| Device provisioning / restore | 30 s – 5 min |
| Instrumented run | 5–15 min |
| Artifact collection | 30 s |
| **Recursive child analysis** | + full pipeline per artifact |

Parallelism is bounded by device count. This is why static gating
([Ch 11 §2](../static-analysis/11-static-analysis.md#2-the-tiered-pipeline)) matters
economically.

---

## 13. Engineering tips

1. **Spawn with `--pause`, never attach.** Hooks must precede `Application.onCreate`.
2. **Diff pre/post state.** New packages, new a11y services, new appops — the payoff step.
3. **Install decoy banking apps** built from statically-extracted target lists.
4. **Set locale, timezone, and SIM region to the target geography.**
5. **Hook both `InMemoryDexClassLoader` overloads.**
6. **Trigger heap dumps on first outbound connection**, not on a timer.
7. **Record ART and Conscrypt Mainline versions** or lose reproducibility.
8. **Do a passive observation pass first** — logcat, dumpsys, PCAP are undetectable.
9. **When a hook doesn't fire**, check inlining → overload → process → class loader → Frida
   detection, in that order.
10. **`C2 unreachable` = inconclusive + requeue.** Never clean.
11. **Recurse on every dumped artifact.**
12. **Record ciphertext block patterns** — ECB is fingerprintable without the key.

---

## 14. Judge Insights

**What judges ask:** *"How do you know the malware isn't just detecting your sandbox and
playing dead?"*

**Perfect answer:** We assume it might be, and we design for that assumption three ways.
First, we don't rely on dynamic analysis alone — the static layer sees the evasion logic
itself, so an app that checks for `frida-server`, reads `TracerPid`, and enumerates Magisk
packages has told us something meaningful even if it then does nothing. Second, we run real
devices rather than emulators for anything that showed evasion checks statically, and we set
locale, timezone, and SIM region to the target geography, because families like ERMAC
geofence — it excludes CIS nations, and many campaigns only activate in specific countries.
Third, and most importantly, when a sample doesn't exhibit behaviour we record **inconclusive**,
not **clean**, with a confidence ceiling and an automatic requeue. A platform that reports low
risk for something it couldn't provoke is actively dangerous to a bank, because they'll act on
it. Silence is a signal to investigate, not a result.

**Common mistakes:**
- "Our sandbox is undetectable." Nobody's is. Claiming it invites a demolition.
- Reporting a silent detonation as clean.
- Using emulators for everything and not knowing why samples show nothing.

**Follow-ups to expect:**
- *"What if the C2 is offline?"* → Inconclusive, confidence ceiling 0.3, requeue every 24 hours
  up to five attempts. Infrastructure comes back; we catch it then.
- *"What's the single most valuable hook?"* → The class-loader hook. The runtime must see
  plaintext DEX to execute it — that's a property of ART, not a bug — so hooking
  `InMemoryDexClassLoader` and `DexClassLoader` dumps the real payload for both packers and
  droppers. Then we recurse on the dump.
- *"How is this better than VirusTotal's behavioural report?"* → VT gives one generic run. We
  stimulate specifically: decoy banking apps drawn from the sample's own extracted target list,
  simulated inbound SMS, reboot for `BOOT_COMPLETED`, and region-matched locale. Overlay
  malware does nothing on a device with no targets installed.

**Fact that impresses:** ToxicPanda encrypts its C2 traffic with **AES-ECB** (Cleafy, October
2024). Because ECB is deterministic, identical plaintext blocks produce identical ciphertext
blocks — so the traffic is fingerprintable **without ever recovering the key**. The adversary's
weak crypto choice becomes a network detection opportunity. It's a nice demonstration that
"encrypted" and "opaque" aren't the same thing.

---

## 15. Interview Insights

**Q: "Static or dynamic analysis — which is more important?"**
A trap. Correct answer: neither, because their blind spots are complementary. Static can't see
a dropper's payload or packed code; dynamic can't see paths that didn't execute or behaviour
gated on geography, time, or C2. Give a concrete example of each and say the fusion is the
product.

**Q: "How does Frida work?"**
`frida-server` runs with root on the device and injects an agent containing the GumJS runtime
into the target process. The `Java.*` bridge interacts with ART to replace method
implementations; `Interceptor` hooks native functions. Gadget mode injects the library into the
APK instead, for non-rooted devices — at the cost of re-signing, which changes the signer.

**Q: "You hook a method and nothing happens. Debug it."**
Inlining first (ART inlined the callee — hook the caller or de-optimise), then wrong overload,
then wrong process (`android:process` sub-processes), then the class was loaded by a different
class loader, then Frida detection. Naming inlining first marks real experience.

**Q: "How do you intercept HTTPS from an Android app?"**
Since Android 7 (API 24), user CAs aren't trusted by default; the app must opt in via
`network_security_config`. Options in a lab: application-layer Frida hooks (best — no CA
needed, pinning irrelevant), system CA store install on a rooted device, patching the network
security config and re-signing, or runtime pinning bypass. Note which ones modify the sample.

**Q: "The sample did nothing when you ran it. What do you conclude?"**
Not "clean." Possible causes: sandbox detection, geofencing, time delay, C2 offline, no target
apps installed, no user interaction simulated. Record inconclusive with a confidence ceiling and
requeue. This question is a direct test of analytical honesty.

**Q: "What's the difference between VirusTotal and an antivirus?"**
VT is a multi-engine aggregator, not an AV. Low counts are common for fresh droppers; high
counts are inflated by engines copying labels and by generic heuristics on packed apps. Use it
for enrichment — first-seen, submission geography, related samples, Retrohunt — never as the
verdict.

**Beginner mistakes:**
- Attaching instead of spawning.
- Forgetting to diff pre/post state.
- Detonating on a device with no decoy apps.
- Treating a silent run as a clean verdict.
- Believing anti-debug proves malice.

---

## 16. Cross-references

**Upstream:**
- [← Ch 03 Android Runtime](../android/03-android-runtime.md) — class loaders, reflection, heap
- [← Ch 10 Reverse Engineering](../reverse-engineering/10-reverse-engineering.md) — unpacking ladder, native RE
- [← Ch 11 Static Analysis](../static-analysis/11-static-analysis.md) — the escalation gate that sends samples here

**Downstream:**
- [→ Ch 13 Android Malware](../malware/13-android-malware.md) — the behaviours you'll observe
- [→ Ch 14 Banking Malware](../banking-malware/14-banking-malware.md) — family-specific behaviour
- [→ Ch 15 Malware Infrastructure](../malware/15-malware-infrastructure.md) — C2 observed here
- [→ Ch 17 Digital Forensics](../digital-forensics/17-digital-forensics.md) — device-side artifacts
- [→ Ch 25 Investigation Engine](../sudarshan/25-investigation-engine.md) — recursive artifact handling
- [→ Ch 26 IOC Extraction](../sudarshan/26-ioc-extraction.md) — network and key IOCs
- [→ Ch 27 Risk Scoring](../sudarshan/27-risk-scoring.md) — weighting behavioural evidence

**Related chain:** Static gate → detonation → class-loader dump → recursion → C2 capture →
IOC extraction → campaign correlation.

---

## 17. References

1. Frida documentation — JavaScript API and Android guides. https://frida.re/docs/android/
2. objection — runtime mobile exploration toolkit. https://github.com/sensepost/objection
3. `jnitrace` — JNI API tracing. https://github.com/chame1eon/jnitrace
4. Magisk documentation — systemless root and DenyList. https://topjohnwu.github.io/Magisk/
5. LSPosed — Xposed framework successor. https://github.com/LSPosed/LSPosed
6. mitmproxy documentation. https://docs.mitmproxy.org/
7. Android Developers — *Network security configuration*. https://developer.android.com/privacy-and-security/security-config
8. Android Developers — `am dumpheap` / Android Studio Memory Profiler documentation.
9. MobSF — dynamic analyser documentation. https://mobsf.github.io/docs/
10. CAPE Sandbox. https://github.com/kevoreilly/CAPEv2
11. VirusTotal documentation — Retrohunt, LiveHunt, behavioural reports. https://docs.virustotal.com/
12. Cleafy Labs — *ToxicPanda* (October 2024) — AES-ECB C2, hardcoded domains.
13. Cleafy Labs — *Klopatra* (August 2025) — Hidden VNC, Virbox, native migration.
14. ThreatFabric — *Octo2* (September 2024) — DGA-based C2, anti-analysis improvements.
15. ThreatFabric — ERMAC analyses — CIS-nation geofencing.
16. Cyble Research and Intelligence Labs — *Antidot* (May 16, 2024) — socket.io WebSocket C2.
17. OWASP MASTG — dynamic analysis and MASVS-RESILIENCE test cases. https://mas.owasp.org/MASTG/

### Further reading
- Frida CodeShare — community hook scripts
- OWASP MASTG — Android anti-reversing defences chapter
- Google Project Zero — Android exploitation and instrumentation research

---

*Previous: [← Ch 11 Static Analysis](../static-analysis/11-static-analysis.md) · Next: Ch 13 Android Malware (Block C) →*

---

## ✅ Block B complete

Chapters 10–12 cover the analysis craft: manual reverse engineering, automated static analysis
at scale, and instrumented dynamic analysis. The recurring thesis — **static and dynamic have
complementary blind spots, so fusion is mandatory** — is the architectural foundation of
[Ch 23 Detection Pipeline](../sudarshan/23-detection-pipeline.md).

**Block C (Chapters 13–16)** turns to the adversary: the techniques, the banking malware
families, their infrastructure, and the threat-intelligence frameworks that organise all of it.
