# 09 — Package Manager

> **Chapter ID:** `CH09` · **Block:** A (Foundations) · **Status:** Stable
> **Tags:** `#package-manager` `#pms` `#packageinstaller` `#sessions` `#droppers` `#install-pipeline` `#sideloading`
> **Last Updated:** 2026-08-05 · **Version:** 1.0.0
> **Prerequisites:** [Ch 04](../security/04-android-security-model.md), [Ch 07](../security/07-apk-signing.md), [Ch 08](08-apk-file-format.md)

---

## Table of Contents

1. [The battlefield](#1-the-battlefield)
2. [The cast: who installs what](#2-the-cast-who-installs-what)
3. [The full install pipeline](#3-the-full-install-pipeline)
4. [Session-based installs](#4-session-based-installs)
5. [Installer attribution — the underused signal](#5-installer-attribution--the-underused-signal)
6. [Install sources and the sideloading boundary](#6-install-sources-and-the-sideloading-boundary)
7. [Droppers: the technique in full](#7-droppers-the-technique-in-full)
8. [Uninstall, and resisting it](#8-uninstall-and-resisting-it)
9. [`packages.xml` — the forensic goldmine](#9-packagesxml--the-forensic-goldmine)
10. [Detection logic for SUDARSHAN](#10-detection-logic-for-sudarshan)
11. [Limitations, edge cases, false positives](#11-limitations-edge-cases-false-positives)
12. [Engineering tips](#12-engineering-tips)
13. [Judge Insights](#13-judge-insights)
14. [Interview Insights](#14-interview-insights)
15. [Cross-references](#15-cross-references)
16. [References](#16-references)

---

## 1. The battlefield

Everything in Block A converges here. The APK format ([Ch 02](02-apk-architecture.md),
[Ch 08](08-apk-file-format.md)), the signature ([Ch 07](../security/07-apk-signing.md)), the
certificate identity ([Ch 06](../security/06-certificates.md)), the sandbox and permission
gates ([Ch 04](../security/04-android-security-model.md)) — all of it is consumed by one
subsystem at one moment: **install time**.

And that moment is where the adversary spends most of their engineering effort. Recall from
[Ch 00 §3](../00-introduction.md#3-the-threat-landscape-in-one-page): Google Play Protect
identified **more than 13 million new malicious apps from outside Google Play in 2024**,
versus 2.36 million policy-violating apps blocked *inside* Play. Banking malware overwhelmingly
arrives through the install pipeline's side door.

> **⚙️ Engineering Note:** If you remember one thing from this chapter: **the question "who
> installed this app?" is nearly as valuable as "what does this app do?"** — and it is far
> cheaper to answer. Installer attribution is the most under-used signal in mobile security
> operations.

---

## 2. The cast: who installs what

| Component | Where it runs | Role |
|---|---|---|
| **PackageManagerService (PMS)** | `system_server`, UID 1000 | The authority. Parses, verifies, assigns UID, grants permissions, writes `packages.xml`. |
| **PackageInstaller (system app)** | Its own process | The **UI** — the "Do you want to install this app?" dialog |
| **`PackageInstaller` API** | In the calling app | The **programmatic** interface (`Session`, `SessionParams`) |
| **`installd`** | Native daemon, root | Creates data directories, runs `dex2oat`, deletes data on uninstall |
| **Play Store / Play Services** | Privileged | Holds `INSTALL_PACKAGES`; installs without the confirmation dialog |
| **`pm` / `cmd package`** | Shell | ADB-side install/uninstall |

### The permission split that governs everything

| Permission | Level | Who has it | What it means |
|---|---|---|---|
| `INSTALL_PACKAGES` | `signature\|privileged` | Play Store, system updaters, some OEM/carrier apps | Install **silently**, no user dialog |
| `REQUEST_INSTALL_PACKAGES` | `normal`-ish (per-app toggle since Android 8) | Any app that asks | **Request** an install — user still sees the dialog |

> **🚨 Misconception:** "`REQUEST_INSTALL_PACKAGES` lets malware install apps silently." It
> does **not**. It lets the app *launch the installer UI*. The user still taps Install.
>
> That correction matters — but do not over-correct into complacency. The malware's answer is
> to first obtain **Accessibility**, and then use `canPerformGestures` to *tap the Install
> button itself* ([Ch 04 §5](../security/04-android-security-model.md#5-the-special-permissions-that-matter)).
> The dialog appears and is dismissed faster than a user can read it. Consent theatre.
>
> **So: user confirmation is a real control, and accessibility abuse is precisely what
> collapses it.** Both halves of that sentence are true and both matter.

### Android 8 changed the model

Pre-Android 8, "Unknown Sources" was a **single global toggle**: on or off for the whole
device. From **Android 8.0 (API 26)** it became **per-app**: each app that wants to trigger
installs must be individually permitted under *Install unknown apps*. Better, but it also
normalised the flow — users now grant it to whichever app asks, in context, which feels
reasonable and usually isn't.

---

## 3. The full install pipeline

This is the diagram promised in [Ch 00 §4](../00-introduction.md#4-the-master-lifecycle),
expanded.

```
  APK obtained (Play / browser / dropper / adb / third-party store)
        │
        ▼
 ┌──────────────────────────────────────────────────────────────┐
 │ 1. SESSION CREATED                                           │
 │    PackageInstaller.Session, or legacy ACTION_VIEW intent    │
 │    ★ INSTALLER PACKAGE RECORDED HERE                         │
 └──────────────────────┬───────────────────────────────────────┘
                        ▼
 ┌──────────────────────────────────────────────────────────────┐
 │ 2. PARSE                                                     │
 │    ZIP structure → AXML manifest → package name, versionCode,│
 │    minSdk/targetSdk, permissions, components   → Ch 08        │
 │    FAIL: INSTALL_PARSE_FAILED_*                              │
 └──────────────────────┬───────────────────────────────────────┘
                        ▼
 ┌──────────────────────────────────────────────────────────────┐
 │ 3. targetSdk GATE                            → Ch 04 §6      │
 │    Android 14+: targetSdk < 23 → INSTALL_FAILED_DEPRECATED_  │
 │                                  SDK_VERSION                 │
 │    Android 15+: floor raised to targetSdk 24                 │
 │    (Android 16 did NOT raise it further)                     │
 └──────────────────────┬───────────────────────────────────────┘
                        ▼
 ┌──────────────────────────────────────────────────────────────┐
 │ 4. SIGNATURE VERIFICATION                    → Ch 07         │
 │    v3.1 → v3 → v2 → v1 (v1-only REJECTED on API 30+)         │
 │    FAIL: INSTALL_PARSE_FAILED_NO_CERTIFICATES /              │
 │          INSTALL_FAILED_INVALID_APK                          │
 └──────────────────────┬───────────────────────────────────────┘
                        ▼
 ┌──────────────────────────────────────────────────────────────┐
 │ 5. SIGNER IDENTITY / TOFU CHECK              → Ch 06         │
 │    Existing package? signer must match (or v3 lineage)       │
 │    FAIL: INSTALL_FAILED_UPDATE_INCOMPATIBLE                  │
 │    Also: versionCode downgrade → INSTALL_FAILED_VERSION_     │
 │          DOWNGRADE                                           │
 └──────────────────────┬───────────────────────────────────────┘
                        ▼
 ┌──────────────────────────────────────────────────────────────┐
 │ 6. USER CONFIRMATION (unless INSTALL_PACKAGES holder)        │
 │    ★ the step accessibility abuse defeats                    │
 └──────────────────────┬───────────────────────────────────────┘
                        ▼
 ┌──────────────────────────────────────────────────────────────┐
 │ 7. PLAY PROTECT SCAN                         → Ch 04 §8      │
 │    Real-time scan of never-before-seen apps;                 │
 │    install-blocking in pilot markets                         │
 └──────────────────────┬───────────────────────────────────────┘
                        ▼
 ┌──────────────────────────────────────────────────────────────┐
 │ 8. COMMIT                                                    │
 │    UID assigned · /data/data/<pkg> created (mode 700)        │
 │    SELinux label applied · APK staged to /data/app/...       │
 └──────────────────────┬───────────────────────────────────────┘
                        ▼
 ┌──────────────────────────────────────────────────────────────┐
 │ 9. PERMISSIONS                               → Ch 04 §4      │
 │    normal: auto-granted · dangerous: deferred to runtime     │
 │    signature: granted iff same signer                        │
 │    special/appop: user must visit Settings                   │
 └──────────────────────┬───────────────────────────────────────┘
                        ▼
 ┌──────────────────────────────────────────────────────────────┐
 │ 10. DEXOPT                                   → Ch 03         │
 │     dex2oat with a compiler filter → .oat/.vdex/.art         │
 └──────────────────────┬───────────────────────────────────────┘
                        ▼
 ┌──────────────────────────────────────────────────────────────┐
 │ 11. REGISTER + BROADCAST                                     │
 │     packages.xml updated (★ signer cert recorded)            │
 │     ACTION_PACKAGE_ADDED broadcast                           │
 └──────────────────────┬───────────────────────────────────────┘
                        ▼
                    App installed
```

### Failure codes worth memorising

| Code | Meaning | Why you'd see it |
|---|---|---|
| `INSTALL_FAILED_UPDATE_INCOMPATIBLE` | Signer mismatch | **Repackaged clone** trying to update a genuine app |
| `INSTALL_FAILED_DEPRECATED_SDK_VERSION` | targetSdk below the floor | Android 14+/15+ gate ([Ch 04 §6](../security/04-android-security-model.md#6-version-gates-the-arms-race-dated)) |
| `INSTALL_PARSE_FAILED_NO_CERTIFICATES` | Unsigned or broken signature | Corrupt, or `apktool b` output you forgot to sign |
| `INSTALL_PARSE_FAILED_RESOURCES_ARSC_COMPRESSED` | Compressed `resources.arsc` | Pre-Android-11 build on Android 11+ |
| `INSTALL_FAILED_VERSION_DOWNGRADE` | Lower `versionCode` | Downgrade attack attempt, or a testing mistake |
| `INSTALL_FAILED_INVALID_APK` | Structural failure | Malformed archive ([Ch 08](08-apk-file-format.md)) |
| `INSTALL_FAILED_TEST_ONLY` | `android:testOnly="true"` | Debug build; use `pm install -t` |

---

## 4. Session-based installs

### WHAT

The modern API. Instead of handing the system a file path, the app opens a **session**,
streams the APK (or multiple split APKs) into it, then commits.

```java
PackageInstaller installer = context.getPackageManager().getPackageInstaller();
PackageInstaller.SessionParams params =
    new PackageInstaller.SessionParams(SessionParams.MODE_FULL_INSTALL);

int sessionId = installer.createSession(params);
try (PackageInstaller.Session session = installer.openSession(sessionId)) {
    try (OutputStream out = session.openWrite("base.apk", 0, apkSize)) {
        // stream APK bytes in
    }
    session.commit(pendingIntent.getIntentSender());   // user prompt appears
}
```

### WHY it exists

Three real needs, none of them malicious:

1. **Split APKs.** An App Bundle install is `base.apk` + several `split_config.*.apk`, which
   must be installed **atomically as one unit** ([Ch 02 §7](02-apk-architecture.md#7-app-bundles-split-apks-and-why-the-apk-is-a-lie)).
   A file-path API cannot express that.
2. **Streaming.** Install can begin before download completes (and with v4 signatures,
   *execution* can begin before download completes — [Ch 07 §7](../security/07-apk-signing.md#7-v4--incremental--streaming-install)).
3. **Third-party app stores.** F-Droid, Amazon Appstore, Samsung Galaxy Store, and enterprise
   MDM agents all need a first-class install API.

### WHY it became a security problem

Because Android had to distinguish "a real app store" from "a browser handing off a file" —
and it chose **which API you used** as the proxy.

From **Android 15 (API 35)**, Restricted Settings are extended: apps installed by browsers,
messaging apps, or file managers are denied Accessibility and Notification Listener access.
Apps installed via the **session-based API** — i.e. by something behaving like a store — are
exempt.

So the adversary's move is obvious and cheap: **use the session-based API.**

```
     Legacy dropper                     Modern dropper
     ─────────────                      ──────────────
  Intent.ACTION_VIEW on the APK      PackageInstaller.Session
           │                                  │
           ▼                                  ▼
  Installer attributed to a          Installer attributed to the
  browser / file manager             dropper itself, which "looks
           │                          like a store"
           ▼                                  │
  Restricted Settings APPLIES               ▼
  → accessibility toggle blocked     Restricted Settings does NOT apply
           │                                  │
           ▼                                  ▼
       attack stalls              user enables Accessibility → full DTO
```

ThreatFabric documented exactly this bypass in **Octo2** (September 2024) and **Crocodilus**
(March 29, 2025). Octo2's first stage used **Zombinder**, presenting a decoy app that asks the
user to install an "additional plugin" — the actual payload.

> **🔬 Research Gap:** There is no published, robust way for the platform to distinguish a
> legitimate third-party store from a dropper impersonating one, absent a trust anchor
> (allowlisted store signers, attestation of the installer, or a store-registration scheme).
> This is the most likely target for the next Android hardening iteration, and it is why
> **SUDARSHAN treats installer identity — not merely install *method* — as a first-class
> signal today.** → [Ch 31](../appendix/31-future-research.md)

---

## 5. Installer attribution — the underused signal

### WHAT

Android records **which package initiated the install** and exposes it.

```bash
# List packages with their installer  (-i), APK path (-f), third-party only (-3)
$ adb shell pm list packages -f -i -3
package:/data/app/~~aB/com.bank.example-Xy/base.apk=com.bank.example
  installer=com.android.vending                    ← Google Play ✅

package:/data/app/~~cD/com.suspect.app-Zw/base.apk=com.suspect.app
  installer=com.fake.pdfreader                     ← ☠️ installed by another app

# Modern, richer API surface
$ adb shell cmd package list packages -i --show-versioncode
$ adb shell dumpsys package com.suspect.app | grep -E 'installerPackageName|installInitiator|installOriginator|firstInstallTime|lastUpdateTime'
```

Programmatically, `PackageManager.getInstallSourceInfo()` (API 30+) distinguishes three roles:

| Field | Meaning |
|---|---|
| `getInstallingPackageName()` | Who performed the install |
| `getInitiatingPackageName()` | Who started the flow |
| `getOriginatingPackageName()` | Where the APK came from (often null) |

### Reading installer values

| Installer package | Interpretation |
|---|---|
| `com.android.vending` | Google Play ✅ |
| `null` | ADB / `pm install` / raw sideload |
| `com.google.android.packageinstaller` / `com.android.packageinstaller` | System installer UI (from a file/browser hand-off) |
| `com.amazon.venezia`, `org.fdroid.fdroid`, `com.sec.android.app.samsungapps` | Legitimate third-party stores |
| **An unrelated third-party app** | **This is the finding.** A PDF reader that installed a banking app is a dropper. |

> **🏛️ Enterprise Insight:** For a bank running an MTD/MDM integration, a single query answers
> the highest-value question in mobile fraud triage:
>
> > *"Which apps on this customer's device were installed by another third-party app, and does
> > any of them hold Accessibility?"*
>
> Two cheap lookups, one join. That combination — **non-store installer + accessibility
> enabled** — is close to a definition of the current Android banking-malware playbook. It
> requires no root, no decompilation, and no ML. Ship it early.
> → [Ch 19](../soc/19-enterprise-soc-operations.md), [Ch 20](../incident-response/20-incident-response.md)

### Limitations

- The installer field is **advisory metadata**, not a security boundary. A privileged
  installer can set it.
- It is not tamper-evident.
- `null` covers both ADB installs and some sideload paths — not automatically suspicious on a
  developer's device, quite suspicious on a customer's.

---

## 6. Install sources and the sideloading boundary

### The spectrum

```
  MOST controlled ◄──────────────────────────────────────► LEAST controlled

  Google Play    3rd-party store   MDM/enterprise   Browser    Dropper    ADB
  ───────────    ───────────────   ──────────────   ───────    ───────    ───
  Review +       Store-dependent   Org-controlled   User       Malicious  Physical
  Play Protect   review                             decides    app        access
  + signing      + session API                      alone      + session  required
                                                               API
```

### Where droppers sit in that picture

The uncomfortable structural point: **a dropper occupies the same technical category as a
legitimate third-party store.** Both use the session-based install API. Both ask the user to
permit installs. Both then install another app.

What distinguishes them is **not the mechanism** but:
- the **identity of the installer** (signer, reputation, prevalence),
- the **relationship** between the installer's stated purpose and what it installs (a PDF
  reader has no business installing anything),
- the **capability profile** of what gets installed
  ([Ch 04 §11](../security/04-android-security-model.md#11-detection-logic-for-sudarshan)),
- and the **temporal pattern** (install → immediately request accessibility).

That list is exactly SUDARSHAN's detection surface for this chapter.

### The Indian context

India is one of Google's untrusted-APK install-blocking pilot markets, and the Google
Security Blog reports those pilots (Brazil, Hong Kong, India, Kenya, Nigeria, Philippines,
South Africa, Thailand, Vietnam) **"shielded 10 million devices from over 36 million risky
installation attempts, encompassing over 200,000 unique apps."** Google also launched an
enhanced fraud-protection pilot in India on **October 3, 2024**.

Meanwhile the local fraud pattern is well documented: McAfee's analysis of the **"PM Surya
Ghar: Muft Bijli Yojana"** campaign describes government-scheme-themed lures with APKs hosted
on GitHub, Firebase Cloud Messaging as C2, ₹1 "UPI-Lite" credential harvesting, and smishing
self-propagation. CYFIRMA documented droppers impersonating Indian banking apps using cloud
services for C2.

> **🏛️ Enterprise Insight:** For an Indian bank, the install-source question has a
> locally-specific shape: **WhatsApp-delivered APKs**. Files arriving via messaging are
> installed with the messenger as initiator, which — post-Android 15 — falls under Restricted
> Settings, which is precisely why campaigns have moved to dropper-plus-session-API delivery.
> Customer education framed as "never install an APK sent on WhatsApp" is necessary and no
> longer sufficient. → [Ch 14](../banking-malware/14-banking-malware.md)

---

## 7. Droppers: the technique in full

### WHY droppers exist

A dropper solves the adversary's hardest problem: **distribution through a reviewed channel.**

```
  Direct approach                      Dropper approach
  ───────────────                      ────────────────
  Submit trojan to Play                Submit a genuinely clean utility to Play
        │                                    │
        ▼                                    ▼
  Static + dynamic review              Passes review — because it IS clean
        │                                    │
        ▼                                    ▼
      REJECTED                          Published, gains installs, gains ratings
                                             │
                                             ▼
                                       Update (or C2 command) turns on the
                                       payload-fetch behaviour
                                             │
                                             ▼
                                       Payload installed via session API
                                             │
                                             ▼
                                       Accessibility requested → DTO
```

**The dropper is clean at review time. That is not an evasion of review; it is a defeat of the
concept of point-in-time review.**

### The canonical case: Anatsa

The best-documented example, with dates:

- ThreatFabric (July 2025): the dropper **"Hybrid Cars Simulator, Drift & Racing"**
  (`com.stellarastra.maintainer.astracontrol_managerreadercleaner`) **reached the #4 spot in
  Google Play's Top Free – Tools category by June 29, 2025**, then shipped a malicious update
  roughly **six weeks after its clean May 7, 2025 release**. This was Anatsa's third major
  US/Canada campaign.
- Zscaler ThreatLabz (August 2025): Anatsa's target scope expanded to **more than 831
  financial institutions** globally, adding **more than 150 new banking and cryptocurrency
  applications** (up from ~650), including Germany and South Korea. ThreatLabz also documented
  Anatsa **moving away from remote DEX loading toward directly installing the payload** —
  streamlining delivery and reducing detectable runtime behaviour.
- Earlier Anatsa/TeaBot dropper campaigns used PDF readers, QR scanners, and file managers;
  one file-manager campaign reached **220,000+ installs**.

> **⚙️ Engineering Note:** That ThreatLabz finding matters operationally. **"No dynamic code
> loading observed" does not mean "no staged payload."** Anatsa dropped the class-loader
> technique in favour of plain installation. If your detection only hooks class loaders
> ([Ch 03 §6](../android/03-android-runtime.md#6-dynamic-code-loading--the-technique-that-breaks-static-analysis)),
> you will miss it. You must **also** diff the installed-package list before and after
> detonation.

### The dropper capability profile

What a dropper looks like statically — deliberately unremarkable:

| Attribute | Dropper | Payload |
|---|---|---|
| Permissions | Few. `INTERNET`, `REQUEST_INSTALL_PACKAGES`, maybe `QUERY_ALL_PACKAGES` | The full banking-trojan cluster |
| Accessibility service | **Usually absent** | Present |
| Obfuscation | Light — it needs to look normal | Heavy |
| Functionality | Genuinely works (a real PDF reader) | Overlay, keylog, VNC, ATS |
| Play presence | Often yes | Never |
| Review outcome | Passes | Never submitted |

> **🚨 Misconception:** "Static analysis of the APK will reveal the malware." For a dropper,
> **the APK you have is not the malware.** The malicious code is not present at analysis time.
> This is the single strongest argument for the fused static + dynamic + intel pipeline that
> [Ch 23](../sudarshan/23-detection-pipeline.md) specifies, and it is worth stating plainly
> in demos.

### Dropper-as-a-Service and Zombinder

Droppers are rented. **Zombinder** is the best-known service: it binds a malicious payload to
a legitimate-looking application, producing a first-stage that asks the user to install an
"additional plugin." ThreatFabric documented Zombinder distributing **Octo2**, and it has also
been observed distributing **Chameleon** alongside **Hook**.

This service model means **the dropper and the payload often come from different actors** —
which has a direct consequence for attribution: dropper infrastructure clusters may not map
cleanly onto payload-family clusters. Record them as separate nodes in the investigation graph.
→ [Ch 15](../malware/15-malware-infrastructure.md), [Ch 28](../sudarshan/28-campaign-correlation.md)

### The full dropper kill chain

```
 1. Distribution   Play Store listing / smishing link / fake Play page / Meta ad
        ▼
 2. Install        User installs a clean, functional utility
        ▼
 3. Dormancy       Days to weeks. May geofence or check for analysis environment.
        ▼
 4. Trigger        App update, or C2 command
        ▼
 5. Fetch          Payload downloaded (or already bundled in assets/, encrypted)
        ▼
 6. Install        ★ PackageInstaller SESSION  → escapes Restricted Settings
        ▼
 7. User taps      "Install" — or accessibility taps it, if already obtained
        ▼
 8. Payload runs   Requests Accessibility with a plausible pretext
        ▼
 9. Escalation     canPerformGestures auto-grants everything else
        ▼
10. Fraud          Overlay + keylog + OTP intercept + VNC → ODF/DTO  → Ch 14
```

**Detection opportunities exist at 2, 5, 6, 8, and 9** — and SUDARSHAN should instrument all
five, because each alone is evadable.

---

## 8. Uninstall, and resisting it

### The normal path

```
User → Settings/launcher → uninstall
        │
        ▼
PMS: ACTION_PACKAGE_REMOVED broadcast
        │
        ▼
installd: delete /data/data/<pkg>, /data/app/<pkg>, oat artifacts
        │
        ▼
UID retired (not immediately reused)
```

`adb shell pm uninstall -k --user 0 <pkg>` removes for the current user while keeping data —
useful in labs, and also the mechanism behind "uninstall for this user" on shipped devices.

### How malware resists removal

Mapped to **MITRE ATT&CK Mobile T1629.001 — Impair Defenses: Prevent Application Removal**.

| Technique | Mechanism | Counter |
|---|---|---|
| **Device Admin activation** | A device-admin app can't be uninstalled until admin is revoked | Revoke in Settings → Security → Device admin apps, then uninstall |
| **Accessibility interception** | Detects the uninstall/Settings screen and navigates away, or taps Cancel | **Safe Mode** (third-party apps and their a11y services disabled) |
| **Overlay obstruction** | Draws over the uninstall dialog | Safe Mode |
| **Watchdog process pair** | Two processes restart each other ([Ch 01 §4](../android/01-android-internals.md#4-zygote-the-process-factory)) | Safe Mode / ADB |
| **Icon hiding** | No launcher entry, so the user can't find it | `pm list packages -3`; Settings → Apps |
| **Device wipe on detection** | Factory reset to destroy evidence — documented in **BRATA** (Cleafy) and **BingoMod** (Cleafy, July 31, 2024) | Acquire forensic image **before** attempting removal |

> **⚙️ Engineering Note — the IR sequencing rule:** because BRATA and BingoMod wipe the device
> when they detect removal attempts or analysis, **forensic acquisition must precede
> remediation**. Get the image, then clean. A responder who uninstalls first may destroy the
> only evidence of how the fraud occurred — and with it, the bank's ability to reconstruct
> the transaction chain. Put this in the runbook in bold.
> → [Ch 17](../digital-forensics/17-digital-forensics.md), [Ch 20](../incident-response/20-incident-response.md)

### The reliable removal path

```
1. FORENSIC ACQUISITION FIRST (device is powered on and unlocked — keep it AFU → Ch 05 §6)
2. Reboot into Safe Mode (disables third-party apps and their accessibility services)
3. Settings → Security → Device admin apps → revoke
4. Settings → Apps → uninstall
   (or, with USB debugging: adb shell pm uninstall --user 0 <pkg>)
5. Verify: pm list packages -3 -i ; check enabled_accessibility_services
6. Bank side: force credential reset, review recent transactions, check for mule transfers
```

---

## 9. `packages.xml` — the forensic goldmine

`/data/system/packages.xml` is PMS's persistent state. It is one of the highest-value artifacts
on an Android device.

```xml
<package name="com.suspect.app"
         codePath="/data/app/~~aBc/com.suspect.app-XyZ"
         nativeLibraryPath="..."
         publicFlags="..." privateFlags="..."
         ft="18f2a1b3c00"          <!-- first install time (hex ms) -->
         it="18f2a1b3c00"          <!-- install time -->
         ut="18f3c9d4e11"          <!-- last update time -->
         version="12"
         installer="com.fake.pdfreader"        <!-- ★ INSTALLER ATTRIBUTION -->
         userId="10241">                        <!-- ★ UID -->
  <sigs count="1">
    <cert index="7" key="308203..."/>          <!-- ★ SIGNER CERTIFICATE (DER) -->
  </sigs>
  <perms>
    <item name="android.permission.INTERNET" granted="true" flags="0"/>
    <item name="android.permission.RECEIVE_SMS" granted="true" flags="..."/>
  </perms>
</package>
```

### What each field gives you

| Field | Investigative value |
|---|---|
| `installer` | **Who dropped it** — §5 |
| `<cert>` | **Signer identity**, even if the APK is gone — [Ch 06](../security/06-certificates.md) |
| `ft` / `it` / `ut` | **Timeline**. Correlate install time against the fraudulent transaction time. |
| `userId` | Map to `/data/data` ownership and to process listings |
| `<perms granted="...">` | **Actually granted** permissions, not merely declared |
| `codePath` | Where the APK lives — pull it |

Companion artifacts:

| File | Contents |
|---|---|
| `/data/system/packages.list` | `package uid debuggable dataDir seinfo ...` — quick UID mapping |
| `/data/system/users/0/settings_secure.xml` | `enabled_accessibility_services`, `enabled_notification_listeners` ★ |
| `/data/system/users/0/package-restrictions.xml` | Per-user enable/disable state |
| `/data/system/device_policies.xml` | Device admin registrations |
| `/data/system/appops.xml` | Special permission grants (`SYSTEM_ALERT_WINDOW`, ...) |

> **⚙️ Engineering Note:** The combination of **`packages.xml`** (installer + install time +
> signer) and **`settings_secure.xml`** (`enabled_accessibility_services`) reconstructs the
> attack timeline from a single logical acquisition — no memory forensics required. That pair
> should be the first thing any Android fraud-response script pulls.
> → [Ch 17](../digital-forensics/17-digital-forensics.md)

---

## 10. Detection logic for SUDARSHAN

### Static signals (from the APK)

| Signal | Weight | Notes |
|---|---|---|
| `REQUEST_INSTALL_PACKAGES` declared | Medium | Necessary for a dropper; also legitimate for stores/updaters |
| `PackageInstaller.Session` API usage in code | **Medium-High** | Store-like behaviour in a non-store app |
| `REQUEST_INSTALL_PACKAGES` + `QUERY_ALL_PACKAGES` + minimal other permissions | **High** | **Classic dropper profile** |
| Stated purpose ⟂ install capability | High | A PDF reader / cleaner / QR scanner that can install apps |
| Encrypted high-entropy blob in `assets/` + install capability | **High** | Bundled payload |
| URL fetch → file write → session install chain | **Very High** | Full dropper machinery |
| `targetSdk` below the platform floor | Medium-High | Install-blocked on A14/A15 ([Ch 04 §6](../security/04-android-security-model.md#6-version-gates-the-arms-race-dated)) |

### Dynamic signals (detonation) — **mandatory**

```yaml
detonation_checks:
  pre:
    - snapshot: pm list packages -3 -i
    - snapshot: settings get secure enabled_accessibility_services
    - snapshot: settings get secure enabled_notification_listeners
    - snapshot: cmd appops get --all
  during:
    - monitor: PackageInstaller session creation
    - monitor: ACTION_PACKAGE_ADDED broadcasts
    - monitor: network fetches of files with APK/DEX magic
    - hook: class loaders                      # → Ch 03
    - log: "avc: denied", "Accessing hidden"   # → Ch 03, Ch 04
  post:
    - diff: installed package list   ★ NEW PACKAGE = DROPPER CONFIRMED
    - diff: accessibility services enabled
    - diff: appops grants
    - collect: any newly installed APK → RECURSIVE ANALYSIS as a child artifact
```

> **⚙️ Engineering Note — the two mandatory diffs.** From [Ch 03](../android/03-android-runtime.md)
> you already hook class loaders to catch in-memory payloads. From this chapter you must
> **also diff the installed-package list**, because Anatsa moved to direct installation and
> class-loader hooks won't fire. **Two different staging mechanisms, two different detections,
> both required.** Missing either one produces a confident false negative — the worst kind.

### Device-side signals (MTD / agent integration)

| Query | Detection |
|---|---|
| `pm list packages -3 -i` | Any app whose installer is another third-party app |
| Join with `enabled_accessibility_services` | **Non-store installer + accessibility = the playbook** |
| `getInstallSourceInfo()` on the bank's own app | Detect a repackaged clone installed from a non-Play source |
| Install time vs first fraudulent transaction | Timeline correlation |

### The high-precision composite rule

```yaml
rule: dropper_installed_payload_with_accessibility
description: >
  A third-party app installed another app, which then obtained an
  Accessibility Service. This is the dominant Android banking malware
  pattern (Anatsa, Octo2, Crocodilus, Hook).
severity: critical
confidence: high
logic:
  all_of:
    - installed_app.installer NOT IN [known_stores, null_adb_on_dev_device]
    - installed_app.installer IS third_party_app
    - installed_app HAS enabled_accessibility_service
mitre: [T1453, T1626.001, T1629.001, T1638]
response: immediate_analyst_review + customer_session_hold
```

---

## 11. Limitations, edge cases, false positives

### False positives

| Trigger | Legitimate cause |
|---|---|
| Non-Play installer | F-Droid, Amazon Appstore, Samsung Galaxy Store, Huawei AppGallery, Xiaomi GetApps |
| `REQUEST_INSTALL_PACKAGES` | Every app store, every self-updater, every MDM agent |
| App installed by another app | Enterprise MDM deploying managed apps; OEM suites; game launchers |
| `installer = null` | ADB installs on a developer's own device |
| Session API usage | Any legitimate store or updater |
| Device admin | Every corporate MDM enrolment |

> **🚨 Misconception:** "Sideloaded = malicious." Sideloading is legal, common, and in some
> markets normal — F-Droid users, enterprise-managed devices, regions with limited Play
> availability, and privacy-conscious users all sideload routinely. **The signal is the
> installer's identity and the installed app's capability profile, not the install method.**
> A tool that flags all sideloading is unusable in India, where third-party stores and direct
> APK distribution are mainstream.

### False negatives

- Dropper never activates in the sandbox (geofenced, time-delayed, C2 offline). **Flag as
  inconclusive, never clean.**
- Payload delivered by a *later app update* rather than by an install (the Anatsa Play
  pattern) — the sample you have genuinely contains nothing.
- Legitimate-looking installer chain (compromised or malicious app on an allowlist).
- Installer field spoofed by a privileged installer.

### Edge cases

| Case | Handling |
|---|---|
| **Split APK sessions** | One session, many APKs. Treat as one logical install. |
| **Work profile installs** | Managed profile, different user ID — expected for enterprise |
| **Instant Apps** | Run without a conventional install; different artifact trail |
| **Pre-installed apps** | Not "installed" in this sense; supply-chain compromise is a separate problem class |
| **Multi-user devices** | Package present for one user, not another |
| **Rollback (Android 10+)** | Managed rollbacks exist; not a downgrade attack |

### Performance

Package-list and installer queries are milliseconds. Detonation with pre/post diffing costs
minutes of wall-clock per sample and is the pipeline's throughput bottleneck — which is
exactly why the cheap static gate from [Ch 02](02-apk-architecture.md) and
[Ch 08](08-apk-file-format.md) decides *what* gets detonated.
→ [Ch 23](../sudarshan/23-detection-pipeline.md)

---

## 12. Engineering tips

1. **`pm list packages -f -i -3` is the single highest-value triage command.** Learn it.
2. **Diff the package list before and after every detonation.** Non-negotiable.
3. **Recursively analyse any newly installed APK** as a linked child artifact
   ([Ch 03 §11](../android/03-android-runtime.md#11-detection-logic-for-sudarshan)).
4. **Join installer attribution with accessibility state.** That join *is* the detection.
5. **Never flag sideloading alone.** Flag the installer identity + capability cluster.
6. **Acquire forensics before remediation** — BRATA and BingoMod wipe on detection.
7. **Parse `packages.xml` for installer, signer, and timestamps** — it survives APK deletion.
8. **Record the failure code** when an install fails; `INSTALL_FAILED_UPDATE_INCOMPATIBLE` is
   a repackaging finding, not a nuisance.
9. **Treat "C2 unreachable" as inconclusive**, and schedule re-detonation.

---

## 13. Judge Insights

**What judges ask:** *"If the malware was on the Google Play Store, doesn't that mean Google's
review failed?"*

**Perfect answer:** Not exactly — it means point-in-time review has a structural limit. The
app Google reviewed was genuinely clean; it was a working utility with no malicious code.
Anatsa's dropper reached the **#4 spot in Play's Top Free Tools category by June 29, 2025**
and only turned malicious in an update roughly six weeks after its clean May 7 release. You
cannot statically detect a payload that doesn't exist yet. Google's answer is continuous
scanning — Play Protect scans about 200 billion apps daily and found over 13 million malicious
apps outside Play in 2024 — but the window between a malicious update and its detection is
exactly where fraud happens, and the bank carries that loss. That's the gap SUDARSHAN closes:
we analyse what a bank's customers actually have installed, we ask who installed it, and we
detonate to see what it *does*, not just what it ships with.

**Common mistakes:**
- "Google should just review better." Shows you haven't understood the staging problem.
- Claiming static analysis alone would catch it. For a dropper, the malware is not in the file.
- Saying `REQUEST_INSTALL_PACKAGES` allows silent installs. It doesn't — but accessibility
  tapping the button does, and that nuance is what a good judge is listening for.

**Follow-ups to expect:**
- *"So how do YOU detect a clean dropper?"* → Capability profile (install capability that
  doesn't match stated purpose), installer attribution on the device, detonation with
  package-list diffing, and threat-intel correlation on the signer and infrastructure. Layered
  — no single one is sufficient, and I'd rather say that than overclaim.
- *"Didn't Android 13 and 15 fix this?"* → They raised the cost. Android 13 added Restricted
  Settings; Android 15 blocked accessibility for apps not installed via the session-based
  install API. Malware answered by adopting the session-based API to look like a legitimate
  store — ThreatFabric documented Octo2 and Crocodilus doing exactly this. It's an arms race,
  not a fix.
- *"What's the one signal you'd keep if you could only have one?"* → Installer attribution
  joined with accessibility state. Two cheap queries, no root, no ML, and together they
  describe the dominant attack.

**Fact that impresses:** Zscaler ThreatLabz reported in August 2025 that Anatsa **stopped
using remote DEX loading and now directly installs its payload**. That's operationally
important, not trivia: any detection built only on class-loader hooks would silently miss
current Anatsa. It's why we diff the installed-package list *and* hook class loaders — two
staging mechanisms, two detections.

---

## 14. Interview Insights

**Q: "Walk me through what happens when you install an APK."**
The Block A capstone question. Use §3: session created (installer recorded) → parse manifest →
targetSdk gate → signature verification (v3.1→v3→v2→v1) → signer TOFU check → user
confirmation → Play Protect scan → commit (UID, sandbox, SELinux label) → permission grants →
dexopt → register in `packages.xml` + broadcast. Naming the failure codes at each gate is what
separates a strong answer from an adequate one.

**Q: "Difference between `INSTALL_PACKAGES` and `REQUEST_INSTALL_PACKAGES`?"**
`INSTALL_PACKAGES` is `signature|privileged` — Play Store and system updaters — and installs
silently. `REQUEST_INSTALL_PACKAGES` is available to ordinary apps and only launches the
installer UI; the user still confirms. Then the nuance: malware defeats that confirmation by
first obtaining Accessibility and tapping the button itself.

**Q: "What's a dropper and why is it effective?"**
An app that is genuinely clean at review time and later installs the real payload. Effective
because it defeats point-in-time review rather than evading it. Cite Anatsa reaching #4 in
Play's Top Free Tools in June 2025.

**Q: "How would you find out where an app came from?"**
`pm list packages -f -i`, `dumpsys package <pkg>` for `installerPackageName` /
`installInitiator`, `getInstallSourceInfo()` at API 30+, or `packages.xml` forensically. Add
the caveat: advisory metadata, not a security boundary.

**Q: "An app can't be uninstalled. What's happening?"**
Device admin active, an accessibility service intercepting the uninstall flow, or an overlay
obstructing the dialog. Boot to Safe Mode, revoke device admin, then uninstall — **but acquire
forensics first**, because BRATA and BingoMod wipe the device on detection.

**Q: "Why did Android 15 tie accessibility restrictions to the install API?"**
Because it needed a proxy for "installed by a real app store" versus "handed over by a browser
or messenger." Session-based install was that proxy. Droppers then adopted the session API.

**Beginner mistakes:**
- Thinking `REQUEST_INSTALL_PACKAGES` means silent installation.
- Treating all sideloading as malicious.
- Uninstalling before acquiring evidence.
- Analysing the dropper and concluding the sample is benign.
- Forgetting to diff the package list after detonation.

---

## 15. Cross-references

**Upstream:**
- [← Ch 04 Android Security Model](../security/04-android-security-model.md) — Restricted Settings, targetSdk gates, Play Protect
- [← Ch 06 Certificates](../security/06-certificates.md) — TOFU, signer identity
- [← Ch 07 APK Signing](../security/07-apk-signing.md) — verification step 4
- [← Ch 08 APK File Format](08-apk-file-format.md) — the parse step

**Downstream:**
- [→ Ch 11 Static Analysis](../static-analysis/11-static-analysis.md) — dropper capability profiling
- [→ Ch 12 Dynamic Analysis](../dynamic-analysis/12-dynamic-analysis.md) — detonation and package diffing
- [→ Ch 13 Android Malware](../malware/13-android-malware.md) — accessibility abuse, anti-removal
- [→ Ch 14 Banking Malware](../banking-malware/14-banking-malware.md) — Anatsa, Octo2, Crocodilus campaigns
- [→ Ch 15 Malware Infrastructure](../malware/15-malware-infrastructure.md) — Zombinder, DaaS
- [→ Ch 17 Digital Forensics](../digital-forensics/17-digital-forensics.md) — `packages.xml`, acquisition-before-remediation
- [→ Ch 20 Incident Response](../incident-response/20-incident-response.md) — the removal runbook

**Related chain:** Dropper → session install → Restricted Settings bypass → accessibility →
permission auto-grant → overlay → OTP theft → ODF.

---

## 16. References

1. Android Developers — `PackageInstaller` / `PackageInstaller.Session` reference. https://developer.android.com/reference/android/content/pm/PackageInstaller
2. Android Developers — `PackageManager.getInstallSourceInfo()` reference (API 30+).
3. Android Developers — *Behavior changes: all apps (Android 14)* — `INSTALL_FAILED_DEPRECATED_SDK_VERSION`. https://developer.android.com/about/versions/14/behavior-changes-all
4. Android Developers — *Behavior changes (Android 15)* — Restricted Settings and the session-install distinction. https://developer.android.com/about/versions/15/behavior-changes-all
5. Android Developers — *Install unknown apps* / per-app unknown sources (Android 8.0+).
6. AOSP — `PackageManagerService` and `installd` source. https://source.android.com/
7. Google Security Blog — *How we kept the Google Play & Android app ecosystems safe in 2024* — 13 M sideloaded malicious apps; install-blocking pilot figures. https://security.googleblog.com/
8. ThreatFabric — Anatsa Google Play dropper campaign, "Hybrid Cars Simulator, Drift & Racing" (July 2025).
9. Zscaler ThreatLabz — *Anatsa's Latest Updates* (August 2025) — 831 institutions; shift from remote DEX loading to direct install.
10. ThreatFabric — *Octo2* (September 2024) — Zombinder first stage, Android 13+ restriction bypass.
11. ThreatFabric — *Crocodilus* (March 29, 2025) — dropper bypassing Android 13+ restrictions.
12. Cleafy Labs — *BRATA* evolution analyses (2021–2022) — factory-reset kill switch.
13. Cleafy Labs — *BingoMod* (published July 31, 2024) — device wipe after fraud.
14. McAfee — "PM Surya Ghar: Muft Bijli Yojana" India campaign analysis — GitHub-hosted APKs, Firebase C2, UPI credential harvesting.
15. CYFIRMA — droppers impersonating Indian banking apps using cloud services as C2.
16. MITRE ATT&CK for Mobile — T1629.001 (Prevent Application Removal), T1626.001 (Device Administrator Permissions), T1453, T1638. https://attack.mitre.org/matrices/mobile/

### Further reading
- AOSP `frameworks/base/services/core/java/com/android/server/pm/`
- Android Developers — *Play Feature Delivery* (legitimate dynamic modules)
- OWASP MASTG — app installation and update integrity test cases

---

*Previous: [← Ch 08 APK File Format](08-apk-file-format.md) · Next: Ch 10 Reverse Engineering (Block B) →*

---

## ✅ Block A complete

Chapters 00–09 establish the foundation: the platform, the package, the runtime, the security
model, and the install pipeline. **Block B (Chapters 10–12)** turns to the analysis craft —
reverse engineering, static analysis, and dynamic analysis — building directly on the format
knowledge from [Ch 08](08-apk-file-format.md) and the runtime behaviour from
[Ch 03](../android/03-android-runtime.md).
