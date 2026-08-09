# 02 - APK Architecture

> **Chapter ID:** `CH02` · **Block:** A (Foundations) · **Status:** Stable
> **Tags:** `#apk` `#manifest` `#aab` `#splits` `#build-pipeline` `#static-analysis`
> **Last Updated:** 2026-08-05 · **Version:** 1.0.0
> **Prerequisites:** [Ch 00](../00-introduction.md), [Ch 01](../android/01-android-internals.md)

---

## Table of Contents

1. [What an APK actually is](#1-what-an-apk-actually-is)
2. [The anatomy](#2-the-anatomy)
3. [The build pipeline](#3-the-build-pipeline)
4. [AndroidManifest.xml - the app's declaration of intent](#4-androidmanifestxml--the-apps-declaration-of-intent)
5. [Resources and resources.arsc](#5-resources-and-resourcesarsc)
6. [Native libraries](#6-native-libraries)
7. [App Bundles, split APKs, and why "the APK" is a lie](#7-app-bundles-split-apks-and-why-the-apk-is-a-lie)
8. [Package name vs Application ID vs identity](#8-package-name-vs-application-id-vs-identity)
9. [First-contact triage workflow](#9-first-contact-triage-workflow)
10. [Detection logic for SUDARSHAN](#10-detection-logic-for-sudarshan)
11. [Limitations, edge cases, false positives](#11-limitations-edge-cases-false-positives)
12. [Engineering tips](#12-engineering-tips)
13. [Judge Insights](#13-judge-insights)
14. [Interview Insights](#14-interview-insights)
15. [Cross-references](#15-cross-references)
16. [References](#16-references)

---

## 1. What an APK actually is

### WHAT

An **APK (Android Package)** is a ZIP archive with a specific internal layout and a
signature block, containing everything needed to install and run an app: compiled
bytecode, resources, native libraries, assets, and a manifest.

That's it. It's a ZIP. You can literally do this:

```bash
$ unzip -l suspicious.apk
Archive:  suspicious.apk
  Length      Date    Time    Name
---------  ---------- -----   ----
     8412  1981-01-01 01:01   AndroidManifest.xml
  2841520  1981-01-01 01:01   classes.dex
   918304  1981-01-01 01:01   classes2.dex
   445120  1981-01-01 01:01   resources.arsc
  1204288  1981-01-01 01:01   lib/arm64-v8a/libnative.so
      ...
      921  1981-01-01 01:01   META-INF/MANIFEST.MF
      874  1981-01-01 01:01   META-INF/CERT.SF
     1179  1981-01-01 01:01   META-INF/CERT.RSA
```

> **⚙️ Engineering Note:** Those `1981-01-01` timestamps are not a bug. Modern Android
> build tooling normalises ZIP entry timestamps to make builds reproducible. **If you see
> *real* varied timestamps in an APK, it was likely repackaged by hand or by a tool like
> `apktool b` - a genuine repackaging signal.** It's weak on its own (many legitimate
> pipelines re-zip), but it's free to compute and worth recording.

### WHY the format is what it is

ZIP was chosen because it's ubiquitous, streamable, supports per-entry compression, and
allows random access to individual entries without decompressing the whole archive.
Android needs the last property badly - the runtime memory-maps `classes.dex` and
`resources.arsc` directly out of the APK rather than extracting them.

This has a direct consequence you must internalise:

> **`classes.dex` and `resources.arsc` are stored *uncompressed and aligned*** (4-byte
> alignment historically; 16 KB page alignment for native libs on newer devices) so they
> can be `mmap`'d in place. That's what `zipalign` does. It's not an optimisation nicety - > it's a runtime requirement.

### The three things an APK simultaneously is

This trips people up, so be explicit:

| View | It is a... | Who uses this view |
|---|---|---|
| Storage | ZIP archive | `unzip`, `7z`, your file manager |
| Distribution | Signed package with an identity | PackageInstaller, Play Store ([Ch 07](../security/07-apk-signing.md)) |
| Runtime | Memory-mapped container of DEX + resources | ART, ResourceManager ([Ch 03](../android/03-android-runtime.md)) |

> **🚨 Misconception:** "An APK is a compiled binary." No. It's a container. The *bytecode*
> inside is compiled (DEX), but the APK itself is an archive. This matters because it means
> you can inspect and modify parts of it without touching others - which is exactly what
> repackaging attacks do, and exactly what signature scheme v2+ was built to prevent.

---

## 2. The anatomy

```
suspicious.apk  (ZIP container)
│
├── AndroidManifest.xml          ← BINARY XML (AXML), not text. → Ch 08
│                                   Declares: package, permissions, components,
│                                   targetSdk, exported flags, service types
│
├── classes.dex                  ← Dalvik bytecode, all app Java/Kotlin code
├── classes2.dex                 ← multidex overflow (64K method-ref limit)
├── classes3.dex                    ...
│
├── resources.arsc               ← compiled resource TABLE (strings, ids, configs)
│
├── res/                         ← compiled resources
│   ├── drawable-*/              ← images per density
│   ├── layout/                  ← compiled binary XML layouts
│   ├── values/
│   └── xml/                     ← ★ accessibility_service_config.xml lives here
│                                   ★ network_security_config.xml lives here
│
├── assets/                      ← RAW files, NOT compiled, NOT in resources.arsc
│                                   ★ favourite hiding place for payloads
│
├── lib/                         ← native shared objects, per ABI
│   ├── arm64-v8a/libfoo.so
│   ├── armeabi-v7a/libfoo.so
│   ├── x86_64/libfoo.so
│   └── ...
│
├── META-INF/                    ← signature material (v1 / JAR signing) → Ch 07
│   ├── MANIFEST.MF              ← digest of every file
│   ├── CERT.SF                  ← digest of MANIFEST.MF entries
│   ├── CERT.RSA                 ← PKCS#7: signature + certificate chain
│   └── (com/android/build/gradle/app-metadata.properties, etc.)
│
├── kotlin/                      ← Kotlin metadata (presence = written in Kotlin)
├── DebugProbesKt.bin            ← coroutines debug artifact
│
└── [APK Signing Block]          ← v2/v3/v3.1 signatures - NOT a ZIP entry.
                                    Sits between file data and Central Directory. → Ch 07/08
```

### Where analysts should look first, in order

| Priority | Location | Why |
|---|---|---|
| 1 | `AndroidManifest.xml` | Capabilities, entry points, targetSdk, exported surface. Cheapest, highest yield. |
| 2 | `res/xml/*accessibility*` | If an a11y service is declared, its config tells you what it can capture |
| 3 | Signer certificate | Identity - the durable pivot for campaign correlation ([Ch 06](../security/06-certificates.md)) |
| 4 | `assets/` | Uncompiled payloads, encrypted DEX, config blobs, overlay HTML |
| 5 | `lib/*.so` | Packer fingerprints, native logic |
| 6 | `classes*.dex` | The actual code (expensive to analyse - gate this stage) |
| 7 | `res/xml/network_security_config.xml` | Cleartext allowances, custom CA trust |

> **⚙️ Engineering Note - the `assets/` blind spot:** `assets/` is a raw passthrough
> directory. Nothing validates it, nothing compiles it, and many static analysers
> under-inspect it. Encrypted second-stage DEX, `.jar` payloads, overlay HTML templates,
> and C2 config have all been found there across families. Klopatra fetched overlay HTML
> from C2, but plenty of families ship it in `assets/`. **Always enumerate and entropy-scan
> `assets/`.**

### Quick entropy triage

```bash
# High-entropy files in assets = likely encrypted/packed payload
$ mkdir -p /tmp/x && unzip -q suspicious.apk -d /tmp/x
$ find /tmp/x/assets -type f -exec sh -c \
    'echo -n "$1  "; ent "$1" 2>/dev/null | head -1' _ {} \;

# Poor man's version: file type + size
$ file /tmp/x/assets/*
$ ls -laS /tmp/x/assets/ | head
```

A `.dat`/`.bin`/`.png` file in `assets/` whose `file` output says "data" and whose entropy
is ~7.9 bits/byte is encrypted or compressed content. If the app has no obvious reason to
carry one, that's a lead.

---

## 3. The build pipeline

### HOW an APK comes to exist

Understanding the forward direction makes reversing it obvious.

```
  Java / Kotlin source          res/ resources         AndroidManifest.xml (text)
        │                            │                          │
        ▼                            ▼                          ▼
   javac / kotlinc              AAPT2 compile             AAPT2 (merge + compile)
        │                            │                          │
        ▼                            ▼                          ▼
    .class files              compiled .flat res         binary AXML
        │                            │                          │
        ▼                            └──────────┬───────────────┘
   R8 / ProGuard                                ▼
   (shrink, optimise,                    AAPT2 link
    obfuscate)                                  │
        │                                       ▼
        ▼                              resources.arsc + res/
   D8 (dex compiler)                            │
        │                                       │
        ▼                                       │
   classes.dex, classes2.dex ...                │
        │                                       │
        └──────────────┬────────────────────────┘
                       ▼
                  package into ZIP
                       │
                       ▼
                   zipalign  ← align uncompressed entries for mmap
                       │
                       ▼
                  apksigner  ← v1/v2/v3/v4 signatures → Ch 07
                       │
                       ▼
                  final .apk
```

### WHY each stage matters to you

| Stage | Forward purpose | Reverse-engineering consequence |
|---|---|---|
| **kotlinc/javac** | Source → JVM bytecode | Kotlin leaves `kotlin/` metadata + `Intrinsics` calls; useful fingerprint |
| **R8/ProGuard** | Shrink + obfuscate | Class/method names become `a`, `b`, `c`. Legit and universal. → [Ch 10](../reverse-engineering/10-reverse-engineering.md) |
| **D8** | JVM bytecode → DEX (register-based) | This is why you decompile *DEX*, not `.class` |
| **AAPT2** | Compile + link resources | Produces AXML and `resources.arsc`; why the manifest isn't readable text |
| **zipalign** | Align uncompressed entries | Misalignment = repackaged carelessly (weak signal) |
| **apksigner** | Sign | The identity anchor. Everything in Ch 06/07 |

> **⚙️ Engineering Note:** Order matters and it's exam-worthy: **zipalign BEFORE apksigner
> for v2+.** Because v2 signs the whole file, aligning afterwards would invalidate the
> signature. (Modern `apksigner` can align during signing with `--align-file-size`, but the
> classic Gradle pipeline is align-then-sign.) If someone tells you they zipaligned a signed
> APK and it still verifies, they either used v1-only or re-signed.

### Repackaging: the reverse pipeline

This is what an attacker (and you, in a lab) does:

```
target.apk
    │
    ▼  apktool d target.apk -o work/
work/  (smali/, res/, AndroidManifest.xml as TEXT, assets/, lib/)
    │
    ▼  edit smali / manifest / resources
    │
    ▼  apktool b work/ -o repacked.apk
repacked.apk  ← UNSIGNED, and v2/v3 signature is destroyed
    │
    ▼  zipalign -p -f 4 repacked.apk aligned.apk
    ▼  apksigner sign --ks lab.keystore aligned.apk
signed-repacked.apk  ← different signer cert → different identity
```

**The critical security fact:** repackaging always changes the signer, because the attacker
doesn't have the original private key. So the repacked app has a **different certificate
fingerprint** and Android will refuse to install it as an *update* over the genuine app
(`INSTALL_FAILED_UPDATE_INCOMPATIBLE`). It must be installed fresh - which is why fake
banking apps are distributed via smishing to users who don't have the real app, or which
masquerade under a different package name entirely.

> **🏛️ Enterprise Insight:** This is the practical basis of a bank's cheapest, most
> effective mobile-fraud control: **maintain an allowlist of your own apps' signer
> certificate SHA-256 fingerprints**, and alert on any APK claiming your package name with
> a different signer. It costs nothing to compute and catches every repackaged clone.
> → [Ch 06 §6](../security/06-certificates.md), [Ch 28](../sudarshan/28-campaign-correlation.md)

---

## 4. AndroidManifest.xml - the app's declaration of intent

### WHY it's the highest-value file

Every capability an app can use at runtime must (with important exceptions) be declared
here. It is the app telling the OS what it intends to do. For triage, that's gold: you
get a capability profile in milliseconds without decompiling anything.

### The security-relevant attributes, annotated

```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.app">                     <!-- ① -->

    <uses-sdk android:minSdkVersion="21"
              android:targetSdkVersion="34"/>       <!-- ② -->

    <uses-permission android:name="android.permission.BIND_ACCESSIBILITY_SERVICE"/>
    <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>
    <uses-permission android:name="android.permission.REQUEST_INSTALL_PACKAGES"/>
    <uses-permission android:name="android.permission.RECEIVE_SMS"/>
    <uses-permission android:name="android.permission.QUERY_ALL_PACKAGES"/>  <!-- ③ -->

    <application
        android:allowBackup="true"                  <!-- ④ -->
        android:debuggable="false"                  <!-- ⑤ -->
        android:usesCleartextTraffic="true"         <!-- ⑥ -->
        android:networkSecurityConfig="@xml/network_security_config"
        android:extractNativeLibs="false">

        <activity android:name=".MainActivity"
                  android:exported="true">          <!-- ⑦ -->
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>

        <service android:name=".A11yService"
                 android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE"
                 android:exported="true">           <!-- ⑧ THE BIG ONE -->
            <intent-filter>
                <action android:name="android.accessibilityservice.AccessibilityService"/>
            </intent-filter>
            <meta-data android:name="android.accessibilityservice"
                       android:resource="@xml/accessibility_config"/>
        </service>

        <service android:name=".CaptureService"
                 android:foregroundServiceType="mediaProjection"/>  <!-- ⑨ -->

        <receiver android:name=".BootReceiver" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED"/>
            </intent-filter>
        </receiver>                                  <!-- ⑩ -->
    </application>
</manifest>
```

| # | Attribute | Why you care |
|---|---|---|
| ① | `package` | **Not identity.** Attacker-chosen. See §8. |
| ② | `targetSdkVersion` | Gates behaviour. Low targetSdk = evasion attempt. Android 14 blocks < API 23, Android 15 blocks < API 24. → [Ch 04](../security/04-android-security-model.md) |
| ③ | `QUERY_ALL_PACKAGES` | Lets the app enumerate every installed package - how overlay malware knows *which* banking apps you have. Play-restricted; rare in legit apps. **Strong signal.** |
| ④ | `allowBackup="true"` | Data extractable via backup; a data-leak finding (OWASP MASVS-STORAGE) |
| ⑤ | `debuggable="true"` | In a production app: critical finding. Lets anyone attach a debugger and read memory. |
| ⑥ | `usesCleartextTraffic="true"` | Plaintext HTTP allowed. Combined with a permissive `network_security_config`, an MITM finding |
| ⑦ | `exported` | The external attack surface (see [Ch 01 §8](../android/01-android-internals.md#8-intents-and-the-exported-surface)) |
| ⑧ | Accessibility service | **The hinge.** MITRE T1453. Read the linked `@xml/accessibility_config` immediately. |
| ⑨ | `foregroundServiceType="mediaProjection"` | Screen capture. Mandatory declaration since Android 14. |
| ⑩ | `BOOT_COMPLETED` | Persistence. MITRE T1624. |

### The accessibility config - read it, always

When you find an a11y service, the `@xml/accessibility_config` resource tells you what it
actually asked for:

```xml
<accessibility-service
    xmlns:android="http://schemas.android.com/apk/res/android"
    android:accessibilityEventTypes="typeAllMask"
    android:accessibilityFeedbackType="feedbackGeneric"
    android:canRetrieveWindowContent="true"
    android:canPerformGestures="true"
    android:notificationTimeout="100"
    android:packageNames=""/>
```

Decoded:

| Attribute | Benign use | Abuse implication |
|---|---|---|
| `typeAllMask` | Rare | Wants **every** event on the device |
| `canRetrieveWindowContent="true"` | Screen readers need it | **Can read text from any app's screen** - including your banking balance and typed credentials |
| `canPerformGestures="true"` | Switch access, motor assistance | **Can inject taps and swipes** - this is what auto-grants permissions and drives ATS transfers |
| `packageNames` absent/empty | Broad utilities | Not scoped to specific apps → targets everything |
| `notificationTimeout="0-100"` | Responsive UI | Wants events with minimal delay - real-time capture |

> **⚖️ Judge Tip:** Being able to read an `accessibility-service` config out loud and
> explain exactly which line enables credential theft (`canRetrieveWindowContent`) and
> which enables automated transfer (`canPerformGestures`) is one of the most impressive
> 30 seconds you can spend in a demo. It is concrete, it's in the artifact, and it maps
> directly to fraud outcomes.

### What the manifest does NOT tell you

- Runtime permissions are **requested**, not granted, at install (Android 6+). Declaration
  ≠ possession. Check `dumpsys package` on a live device for actual grants.
- Code loaded dynamically can use capabilities the manifest declares but the static code
  never touches - and *cannot* use undeclared permissions. (Permissions are a hard ceiling;
  dynamic loading can't exceed the manifest.)
- Native code behaviour is invisible here.

> **🚨 Misconception:** "The manifest is the complete capability list." It's the *ceiling*,
> not the actual usage. A dropper declares almost nothing and downloads a payload that has
> its own manifest and its own install. → [Ch 09](09-package-manager.md)

---

## 5. Resources and resources.arsc

### WHAT

`resources.arsc` is a compiled binary table mapping resource IDs (`0x7f0a0012`) to values,
with *configuration qualifiers* (language, density, orientation, API level). `res/`
contains the actual files, also compiled where applicable (layouts become binary XML).

### WHY it exists

Because a device must select the right string for the user's locale and the right drawable
for the screen density **at runtime, fast, without parsing XML**. A pre-compiled lookup
table does that.

### Why analysts care

1. **Strings live here, not only in DEX.** Overlay HTML, phishing text, target bank names,
   and C2 URLs are frequently stored as string resources. If you only grep the DEX, you
   miss them.

   ```bash
   # dump all strings and resources
   $ aapt2 dump strings suspicious.apk
   $ aapt2 dump resources suspicious.apk | less
   # or after apktool, just grep the decoded XML
   $ apktool d suspicious.apk -o work/ && grep -ri "http" work/res/values/
   ```

2. **Localisation reveals targeting.** An APK with `values-tr/`, `values-es/`, and
   `values-it/` and nothing else is telling you its victim geography. Antidot was
   documented (Cyble, May 2024) with German, French, Spanish, Russian, Portuguese,
   Romanian, and English overlay support - the resource set *is* the target list.

3. **`resources.arsc` manipulation is an evasion technique.** Malformed or non-standard
   resource tables have been used to crash or confuse parsers (including `apktool` and some
   AV engines) while Android itself tolerates them. If `apktool` fails but the app installs
   and runs, suspect deliberate anti-analysis. → [Ch 10](../reverse-engineering/10-reverse-engineering.md)

> **⚙️ Engineering Note:** Since Android 11, `resources.arsc` **must be stored uncompressed
> and 4-byte aligned** or installation fails (`INSTALL_PARSE_FAILED_RESOURCES_ARSC_COMPRESSED`).
> A useful side effect: an APK with a compressed `resources.arsc` was built for, or repacked
> targeting, older Android. That's a dating signal.

---

## 6. Native libraries

### WHAT and WHY

`lib/<abi>/*.so` holds ELF shared objects loaded via `System.loadLibrary()`. Reasons apps
use native code: performance (codecs, games, ML), reuse of existing C/C++ libraries,
and - relevantly - **hiding logic from decompilers**.

Common ABIs: `arm64-v8a` (dominant), `armeabi-v7a` (legacy 32-bit), `x86`/`x86_64`
(emulators, some Chromebooks).

### Analyst signals

| Observation | Meaning |
|---|---|
| Only `x86`/`x86_64`, no ARM | Built for emulators - unusual for real-world distribution; sometimes a test build or analysis bait |
| Only `arm64-v8a` | Modern, real-device targeting (most current malware) |
| `libjiagu.so`, `libDexHelper.so`, `libshella*.so`, `libtprt.so` | **Commercial packer fingerprints** (360 Jiagu, Bangcle/SecNeo, Virbox, Tencent) → [Ch 10](../reverse-engineering/10-reverse-engineering.md) |
| Huge `.so` + tiny `classes.dex` | Logic pushed native. Klopatra (Cleafy, Aug 2025) and GodFather variants (Cyble) both did this. |
| `.so` with high-entropy sections | Packed/encrypted native payload |
| `android:extractNativeLibs="false"` | Libraries loaded from inside the APK (page-aligned); standard modern practice |

```bash
# Identify libraries and look for packer names
$ unzip -l app.apk | grep '\.so$'
# Inspect an ELF
$ file work/lib/arm64-v8a/libnative.so
$ readelf -d work/lib/arm64-v8a/libnative.so | head -20
$ strings -n 8 work/lib/arm64-v8a/libnative.so | grep -Ei 'http|\.com|/api/|token'
# Find the JNI entry point
$ nm -D work/lib/arm64-v8a/libnative.so | grep -i 'JNI_OnLoad\|Java_'
```

> **⚙️ Engineering Note:** `JNI_OnLoad` is the first native code that runs when the library
> loads. Packers do their unpacking there. When you open a native library in Ghidra, start
> at `JNI_OnLoad` - not at `main`, which doesn't exist in a shared object.

---

## 7. App Bundles, split APKs, and why "the APK" is a lie

### WHAT changed

Since August 2021, new apps on Google Play must be published as **Android App Bundles
(AAB)**, not APKs. An AAB is a *publishing* format; Google Play generates and signs
per-device APKs from it.

```
Developer uploads:   app.aab   (signed with the UPLOAD key)
                        │
                        ▼
              Google Play Console
                        │
                        ├── validates, strips upload signature
                        │
                        ▼
              Play App Signing re-signs with the APP SIGNING key
                        │
                        ▼
      Generates split APKs per device configuration:
          base.apk
          split_config.arm64_v8a.apk
          split_config.xxhdpi.apk
          split_config.en.apk
                        │
                        ▼
              Delivered to device, installed as ONE logical app
```

### WHY this matters enormously for analysis

**A device's installed app may be several APK files.** If you pull only `base.apk`, you may
be missing native libraries, resources, and even code (dynamic feature modules).

```bash
# List ALL apk paths for a package - note the multiple lines
$ adb shell pm path com.example.app
package:/data/app/~~aBc/com.example.app-XyZ/base.apk
package:/data/app/~~aBc/com.example.app-XyZ/split_config.arm64_v8a.apk
package:/data/app/~~aBc/com.example.app-XyZ/split_config.xxhdpi.apk

# Pull them all
$ adb shell pm path com.example.app | sed 's/package://' | \
    while read p; do adb pull "$p"; done
```

The bundled distribution format is **XAPK / APKS / APKM** (third-party store containers
holding base + splits). MobSF supports these; plain `jadx` on a single split will not.

### Consequences

| Consequence | Detail |
|---|---|
| **Signer confusion** | With Play App Signing, the *upload* key ≠ the *app signing* key. The certificate you see on a Play-downloaded APK is Google's re-signature, not the developer's upload cert. |
| **Incomplete analysis** | Analysing `base.apk` alone can miss the payload entirely |
| **Hash instability** | Different devices get different APK sets → different hashes for the *same* app version. Another nail in "hash == identity". → [Ch 32](../appendix/32-common-misconceptions.md) |
| **Third-party store repacking** | XAPK files from mirror sites are frequently the malware delivery vehicle |

> **🚨 Misconception:** "I downloaded the app from Play, so the certificate I see is the
> developer's." With Play App Signing (mandatory for AAB), you're seeing the key Google
> holds and signs with. This is fine - it's still a stable identity for *that app on Play*
> - but you must not describe it as "the developer's signing key" in a report.

---

## 8. Package name vs Application ID vs identity

This section exists because these three get conflated constantly, and the conflation causes
real analytical failures. It is the seed of [Ch 32](../appendix/32-common-misconceptions.md).

| Concept | What it is | Who controls it | Is it identity? |
|---|---|---|---|
| **Package name** | The `package` attribute in the manifest; also the Java root package historically | The developer - or **any attacker who types it** | ❌ No |
| **Application ID** | Gradle's `applicationId`; what actually ends up as the installed package identifier | The developer's build config | ❌ No |
| **Signer certificate** | The X.509 cert whose private key signed the APK | Only whoever holds the private key | ✅ **Yes** |
| **File hash (SHA-256)** | Digest of these exact bytes | Anyone (change one byte → new hash) | ❌ Identifies an *artifact*, not an app |

### Why they diverge

Historically, the manifest `package` served double duty: it was both the app's unique
identifier *and* the base package for the generated `R` class. Gradle separated these:
`applicationId` sets the installed identifier, while the manifest `package` sets the code
namespace. Modern AGP (7.3+) prefers `namespace` in `build.gradle` and deprecates the
manifest `package` attribute for that purpose.

Practical outcome: build variants (`com.bank.app`, `com.bank.app.debug`,
`com.bank.app.staging`) share code but install side by side.

### Why this matters for malware

**Package names are free.** Crocodilus masqueraded as Google Chrome using the package
`quizzical.washbowl.calamity` (ThreatFabric, March 2025) - arbitrary, meaningless, chosen
to be unmemorable. Anatsa rotates package names between campaigns as a matter of routine.
Conversely, malware often *impersonates* legitimate package names to appear on allowlists.

> **⚖️ Judge Tip:** If a judge asks how you identify malware families, and you say
> "package names," you have lost the room. The answer is **signer certificate fingerprint,
> code similarity, and infrastructure overlap** - with package name recorded as a
> *campaign* attribute, useful for clustering but never for identity.

### The correct identity hierarchy

```
Most durable ──────────────────────────────────────► Most volatile

  Signer cert     Code similarity     C2 infra      Package     File
  SHA-256         (TLSH/SSDEEP,       (domains,     name        hash
  fingerprint      call graphs)        IPs)
     │                  │                  │           │          │
  survives          survives           rotates      trivially   changes
  recompiles        obfuscation        weekly       changed     every build
  and rebuilds      tweaks
```

Use the left side for **identity and attribution**. Use the right side for **IOCs and
blocking**. Confusing the two is how you end up blocking a hash that the adversary changed
an hour ago. → [Ch 16](../threat-intelligence/16-threat-intelligence.md), [Ch 26](../sudarshan/26-ioc-extraction.md)

---

## 9. First-contact triage workflow

Ten minutes, no decompiler. This is what SUDARSHAN's fast path automates.

```
        ┌─────────────────────────────────┐
        │  APK arrives                    │
        └────────────────┬────────────────┘
                         ▼
        ┌─────────────────────────────────┐
        │ 1. Hash it (SHA-256)            │  identity of the ARTIFACT
        └────────────────┬────────────────┘
                         ▼
        ┌─────────────────────────────────┐
        │ 2. Verify signature, get signer │  identity of the APP  → Ch 07
        │    apksigner verify --print-certs│
        └────────────────┬────────────────┘
                         ▼
        ┌─────────────────────────────────┐
        │ 3. Dump manifest                │  capability profile
        │    aapt2 dump badging / apktool │
        └────────────────┬────────────────┘
                         ▼
              ┌──────────┴──────────┐
              │ a11y service?       │──yes──► read res/xml a11y config
              │ overlay perm?       │         → HIGH PRIORITY QUEUE
              │ REQUEST_INSTALL?    │
              │ SMS / notif access? │
              └──────────┬──────────┘
                         │ no strong cluster
                         ▼
        ┌─────────────────────────────────┐
        │ 4. Enumerate assets/ + lib/     │  payloads, packers
        └────────────────┬────────────────┘
                         ▼
        ┌─────────────────────────────────┐
        │ 5. Strings + resources sweep    │  URLs, bank package names
        └────────────────┬────────────────┘
                         ▼
        ┌─────────────────────────────────┐
        │ 6. TI enrichment (VT/GTI, TI DB)│  → Ch 16, Ch 30
        └────────────────┬────────────────┘
                         ▼
              Decide: deep static ([Ch 11]) / detonate ([Ch 12]) / close
```

### The commands, in order

```bash
# 1
$ sha256sum suspicious.apk

# 2  ← signer identity, the durable pivot
$ apksigner verify --verbose --print-certs suspicious.apk

# 3  ← capability profile in one shot
$ aapt2 dump badging suspicious.apk
$ aapt2 dump permissions suspicious.apk
# full manifest as readable XML:
$ apktool d -s suspicious.apk -o work/     # -s = skip dex, much faster
$ cat work/AndroidManifest.xml

# 4
$ unzip -l suspicious.apk | grep -E 'assets/|\.so$'

# 5
$ grep -rEi 'https?://|\.onion|api_key|bot[0-9]{8,}:' work/res/ work/assets/ 2>/dev/null

# bonus: which apps does it look for? (overlay target list)
$ grep -rEo 'com\.[a-z0-9_]+\.[a-z0-9_.]+' work/res/values/ | sort -u | head -50
```

> **⚙️ Engineering Note:** `apktool d -s` (skip sources) is the single best speed trick in
> triage. Decoding resources and the manifest takes ~1–3 seconds; decoding smali on a large
> app can take minutes. Get your capability profile first, then decide whether the DEX is
> worth the wall-clock.

---

## 10. Detection logic for SUDARSHAN

### Intake normalisation (→ [Ch 24](../sudarshan/24-threat-intake.md))

1. Accept `.apk`, `.xapk`, `.apks`, `.apkm`, `.aab`. **Explode container formats and
   analyse the full split set**, not just `base.apk`.
2. Compute SHA-256, SHA-1, MD5 (for TI-feed compatibility), and **TLSH/SSDEEP** fuzzy
   hashes for similarity clustering ([Ch 28](../sudarshan/28-campaign-correlation.md)).
3. Extract and store the **signer certificate SHA-256 fingerprint** as a first-class
   indexed field. This is the primary correlation key.

### Cheap-signal gate (runs in < 2 seconds)

```
manifest_parse()  ──►  capability_vector
                        ├── declares_a11y_service
                        ├── a11y_can_retrieve_window_content
                        ├── a11y_can_perform_gestures
                        ├── has_overlay_permission
                        ├── has_request_install_packages
                        ├── has_query_all_packages
                        ├── has_sms_read_or_receive
                        ├── declares_notification_listener
                        ├── fgs_types[]
                        ├── target_sdk
                        ├── exported_unprotected_components[]
                        └── native_lib_ratio, packer_fingerprint
```

If `declares_a11y_service AND (can_retrieve_window_content OR can_perform_gestures)`
AND at least two other cluster members → escalate to full static + dynamic. Otherwise
proceed on the normal queue. This gating is the throughput argument of
[Ch 23](../sudarshan/23-detection-pipeline.md).

### Signals unique to this chapter

| Signal | Extraction | Notes |
|---|---|---|
| Signer fingerprint | `apksigner`/Androguard | **Primary identity.** Index it. |
| Signer ≠ known-good for claimed package | TI DB lookup | Catches every repackaged clone of a bank's own app |
| Non-normalised ZIP timestamps | ZIP central directory | Weak repackaging signal |
| Compressed `resources.arsc` | ZIP entry method | Built/repacked for pre-Android-11 |
| `assets/` high-entropy blobs | entropy scan | Encrypted stage-2 candidate |
| Packer library name in `lib/` | filename match | Virbox/Jiagu/Bangcle/SecNeo |
| Locale resource set | `res/values-*/` enumeration | **Victim geography inference** |
| Referenced bank package names in resources | regex over decoded resources | **Overlay target list** - extremely high value |

> **🏛️ Enterprise Insight:** That last one is the killer feature for a bank. If SUDARSHAN
> extracts the malware's target list and the client bank's package name is on it, that
> converts an abstract "this is malware" into "**this campaign is targeting *you*, here are
> the exact app IDs it hunts for**." That's the finding a CISO forwards upward.

---

## 11. Limitations, edge cases, false positives

### Limitations of manifest-first analysis

- Declaration ≠ usage ≠ grant. Three different things.
- Droppers deliberately have boring manifests. The payload's manifest is the interesting
  one, and it isn't in the file you have. → [Ch 09](09-package-manager.md)
- Dynamic feature modules can carry code delivered later.
- Manifest merging (library manifests merged at build time) means a permission may be
  present because a third-party SDK requested it, not because the app author wanted it.

### Edge cases

| Case | Handling |
|---|---|
| **Multidex** | Analyse `classes.dex` through `classesN.dex`. Tools that only read the first are wrong. |
| **XAPK/APKS** | Explode before analysis |
| **Instant Apps** | Different packaging assumptions |
| **APK with no `classes.dex`** | Legal (pure-native or resource-only splits). Not inherently malicious. |
| **Zip anomalies** | Duplicate entries, oversized fields, and mismatched local/central headers are classic parser-confusion tricks. Prefer strict parsers and *record* the anomaly rather than silently tolerating it. → [Ch 08](08-apk-file-format.md) |
| **Very large APKs (>200 MB)** | Games; watch for pipeline timeouts |

### False positives

| Trigger | Innocent explanation |
|---|---|
| Obfuscated code | R8 is on by default in release builds. **Nearly all Play apps are obfuscated.** |
| Native libraries | Games, ML, codecs, DRM |
| `QUERY_ALL_PACKAGES` | Launchers, antivirus, app managers, backup tools legitimately need it |
| `REQUEST_INSTALL_PACKAGES` | App stores, updaters, MDM agents |
| Many locales | Genuinely international apps |
| High-entropy assets | Compressed model files, encrypted DRM content, packed game assets |

### False negatives

- Payload downloaded post-install (Anatsa's model).
- Logic entirely in native code.
- Behaviour gated on geography, time, or C2 command - nothing static reveals it.

---

## 12. Engineering tips

1. **Always `apktool d -s` first.** Manifest and resources in seconds; decide on DEX after.
2. **Never analyse only `base.apk`** if splits exist.
3. **Index the signer fingerprint, not the file hash**, as your primary key.
4. **Grep resources, not just DEX.** Strings hide in `resources.arsc`.
5. **Enumerate `assets/` every single time.** It's the most under-inspected directory.
6. **Record ZIP structural anomalies** rather than letting your parser normalise them away - the anomaly is itself intelligence.
7. **Extract the locale set and the referenced package list.** Cheap, and they answer
   "who is being targeted?" which is the question the bank actually has.

---

## 13. Judge Insights

**What judges ask:** *"How do you know two APKs are the same malware family if the hashes
are different?"*

**Perfect answer:** Hashes identify a file, not an app or a family - change one byte and
the hash changes, which adversaries do routinely (Anatsa rotates package names and install
hashes between campaigns). We correlate on durable properties: the **signer certificate
SHA-256 fingerprint** (survives recompilation; the attacker keeps their key because they
need it to push updates), **code similarity** via fuzzy hashing and call-graph comparison
(survives cosmetic obfuscation), **shared C2 infrastructure**, and **resource artifacts**
like the overlay target list. Package name and file hash are recorded as campaign
attributes and blocking IOCs, never as identity.

**Common mistake:** Saying "we compare hashes." It's the fastest way to signal that you
haven't handled real samples.

**Follow-ups to expect:**
- *"What if they rotate signing keys too?"* → Then key rotation itself becomes the signal,
  and we fall back to code similarity and infrastructure. Also: v3 key rotation carries a
  **proof-of-rotation lineage** that links old key to new - which is a gift for
  attribution. → [Ch 07](../security/07-apk-signing.md)
- *"Why not just use VirusTotal?"* → VT gives engine verdicts, not capability or targeting.
  It also won't tell the bank that its own package name is in the overlay target list.
- *"How fast is your triage?"* → Manifest-level capability profile in under two seconds;
  that gates the expensive stages.

**Fact that impresses:** Google Play has required App Bundles for new apps since August
2021, which means **the same app version has different file hashes on different devices**,
because Play generates per-configuration split APKs. Anyone still treating file hash as app
identity is broken by design, not just by adversaries.

---

## 14. Interview Insights

**Q: "What's inside an APK?"**
Don't just list directories. Structure it: manifest (declaration of capability), DEX
(code), `resources.arsc` + `res/` (compiled resources), `assets/` (raw passthrough),
`lib/` (native ELF per ABI), `META-INF/` (v1 signature material), and the **APK Signing
Block**, which is *not* a ZIP entry and sits before the central directory. Mentioning the
signing block unprompted marks you as someone who has actually looked at the bytes.

**Q: "Difference between package name and application ID?"**
Manifest `package` was historically both the identifier and the code namespace; Gradle's
`applicationId` sets the installed identifier while `namespace` sets the code namespace.
Then add the security point: **neither is an identity claim.** Identity is the signer
certificate.

**Q: "Why is `classes.dex` stored uncompressed?"**
So ART can memory-map it directly from the APK without extraction. Same reason
`resources.arsc` is uncompressed and aligned - and since Android 11, a compressed
`resources.arsc` causes install failure.

**Q: "You're handed an APK. First five minutes?"**
Hash → verify signature and capture signer cert → dump manifest and permissions → check for
accessibility service and read its config → enumerate `assets/` and `lib/`. Note explicitly
that you do *not* start with the decompiler, and say why (cost, and packers may defeat it).

**Q: "What does zipalign do and when do you run it?"**
Aligns uncompressed entries so they can be mmap'd. Run it **before** signing with v2+,
because v2 signs the whole file.

**Beginner mistakes:**
- Reading `AndroidManifest.xml` with `cat` and being confused by binary garbage - it's AXML.
- Analysing `base.apk` and missing splits.
- Treating declared permissions as granted permissions.
- Calling obfuscation malicious.
- Ignoring `assets/`.

---

## 15. Cross-references

**Upstream:**
- [← Ch 01 Android Internals](../android/01-android-internals.md) - components, exported surface

**Downstream:**
- [→ Ch 03 Android Runtime](../android/03-android-runtime.md) - how DEX becomes executing code
- [→ Ch 06 Certificates](../security/06-certificates.md) - the signer identity introduced in §8
- [→ Ch 07 APK Signing](../security/07-apk-signing.md) - the signing block, v1–v4
- [→ Ch 08 APK File Format](08-apk-file-format.md) - byte-level ZIP/AXML/DEX structure
- [→ Ch 09 Package Manager](09-package-manager.md) - how this file gets installed
- [→ Ch 10 Reverse Engineering](../reverse-engineering/10-reverse-engineering.md) - packers, obfuscation
- [→ Ch 11 Static Analysis](../static-analysis/11-static-analysis.md) - automating §9
- [→ Ch 32 Common Misconceptions](../appendix/32-common-misconceptions.md) - §8 in full

**Related concepts:** APK → manifest → accessibility config → overlay target list →
campaign correlation → Ch 28.

---

## 16. References

1. Android Developers - *Application Fundamentals* / *App Manifest Overview*. https://developer.android.com/guide/topics/manifest/manifest-intro
2. Android Developers - *Android App Bundle*. https://developer.android.com/guide/app-bundle
3. Android Developers - *Configure the app module / applicationId vs package name*. https://developer.android.com/build/configure-app-module
4. Android Developers - *AccessibilityService configuration reference*. https://developer.android.com/reference/android/accessibilityservice/AccessibilityService
5. Android Developers - *zipalign* and *apksigner* build-tool docs. https://developer.android.com/tools/zipalign
6. Android Developers - *Behavior changes: Android 11* (uncompressed `resources.arsc`). https://developer.android.com/about/versions/11/behavior-changes-all
7. Android Developers - *Foreground service types* (Android 14). https://developer.android.com/about/versions/14/changes/fgs-types-required
8. ThreatFabric - *Crocodilus* analysis (March 29, 2025) - package masquerading.
9. Zscaler ThreatLabz - *Anatsa's Latest Updates* (August 2025) - package/hash rotation.
10. Cyble Research and Intelligence Labs - *Antidot* analysis (May 16, 2024) - multi-locale overlay targeting.
11. Cleafy Labs - *Klopatra* (August 2025) - Virbox packing, native-code migration.
12. MITRE ATT&CK for Mobile - T1453, T1624, T1417.001. https://attack.mitre.org/matrices/mobile/
13. OWASP MASTG - *Android Platform APIs* and *Data Storage* test cases. https://mas.owasp.org/MASTG/

### Further reading
- AOSP `frameworks/base/tools/aapt2/` - resource compiler source
- Google Play Console documentation - Play App Signing
- MobSF static analyser source - reference implementation of manifest capability extraction

---

*Previous: [← Ch 01 Android Internals](../android/01-android-internals.md) · Next: [Ch 03 Android Runtime →](../android/03-android-runtime.md)*
