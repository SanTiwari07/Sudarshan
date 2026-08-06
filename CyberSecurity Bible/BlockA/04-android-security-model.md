# 04 — Android Security Model

> **Chapter ID:** `CH04` · **Block:** A (Foundations) · **Status:** Stable
> **Tags:** `#security-model` `#sandbox` `#selinux` `#permissions` `#play-protect` `#play-integrity` `#verified-boot` `#version-gates`
> **Last Updated:** 2026-08-05 · **Version:** 1.0.0
> **Prerequisites:** [Ch 01](../android/01-android-internals.md), [Ch 03](../android/03-android-runtime.md)

---

## Table of Contents

1. [The model in one picture](#1-the-model-in-one-picture)
2. [Layer 1 — The application sandbox](#2-layer-1--the-application-sandbox)
3. [Layer 2 — SELinux and seccomp](#3-layer-2--selinux-and-seccomp)
4. [Layer 3 — Permissions](#4-layer-3--permissions)
5. [The special permissions that matter](#5-the-special-permissions-that-matter)
6. [Version gates: the arms race, dated](#6-version-gates-the-arms-race-dated)
7. [Verified Boot and the hardware root of trust](#7-verified-boot-and-the-hardware-root-of-trust)
8. [Play Protect](#8-play-protect)
9. [Play Integrity API](#9-play-integrity-api)
10. [Where the model fails](#10-where-the-model-fails)
11. [Detection logic for SUDARSHAN](#11-detection-logic-for-sudarshan)
12. [Limitations, edge cases, false positives](#12-limitations-edge-cases-false-positives)
13. [Engineering tips](#13-engineering-tips)
14. [Judge Insights](#14-judge-insights)
15. [Interview Insights](#15-interview-insights)
16. [Cross-references](#16-cross-references)
17. [References](#17-references)

---

## 1. The model in one picture

Android security is **defence in depth with a specific ordering**. Each layer assumes the
ones below it may fail.

```
┌───────────────────────────────────────────────────────────────────┐
│  6. ECOSYSTEM     Play review · Play Protect · developer bans     │  ← policy
├───────────────────────────────────────────────────────────────────┤
│  5. ATTESTATION   Play Integrity API · key attestation           │  ← "is this
├───────────────────────────────────────────────────────────────────┤     device sane?"
│  4. PERMISSIONS   install-time · runtime · special · appops       │  ← user consent
├───────────────────────────────────────────────────────────────────┤
│  3. SIGNING       v1–v4 signatures · signer identity              │  ← "who made this?"
├───────────────────────────────────────────────────────────────────┤
│  2. MAC           SELinux domains · seccomp-bpf syscall filter    │  ← kernel policy
├───────────────────────────────────────────────────────────────────┤
│  1. DAC           UID/GID sandbox · file permissions · namespaces │  ← Linux
├───────────────────────────────────────────────────────────────────┤
│  0. BOOT          Verified Boot (AVB) · dm-verity · TEE/StrongBox │  ← root of trust
└───────────────────────────────────────────────────────────────────┘
```

> **⚙️ Engineering Note — the single most important sentence in this chapter:**
> **Banking malware defeats none of these layers.** It does not exploit the kernel. It does
> not bypass SELinux. It does not forge signatures. It gets the *user* to grant it
> Accessibility, and then operates entirely within the rules. The security model is working
> as designed; the model just never promised to protect a user from their own consent.
>
> Internalise this, because it explains why "the platform will fix it" is wrong, and why a
> bank needs SUDARSHAN regardless of how good Android gets.

---

## 2. Layer 1 — The application sandbox

### WHAT

Every installed app gets a **unique Linux UID** (typically 10000+, shown as `u0_a123`).
Its private directory `/data/data/<pkg>` is owned by that UID with mode `700`. Standard
Linux DAC then does the work: app A literally cannot `open()` app B's files.

```bash
$ adb shell ls -ld /data/data/com.example.app
drwx------ 4 u0_a241 u0_a241 4096 2026-08-05 10:12 /data/data/com.example.app

$ adb shell cat /data/system/packages.list | grep com.example
com.example.app 10241 0 /data/user/0/com.example.app default:targetSdkVersion=34 none 0
#               ^UID
```

### WHY UID-per-app rather than user-per-app

Because Linux's isolation primitives were already there, were battle-tested, and were
enforced by the kernel rather than by a userspace framework that could be bypassed. Reusing
DAC was the pragmatic and correct choice.

### The lifecycle of a sandbox

```
Install ──► PMS assigns UID  ──► creates /data/data/<pkg> mode 700
                                   assigns SELinux label
                                        │
Launch  ──► Zygote fork ──► setuid(UID) ──► SELinux domain transition
                                       ──► seccomp filter installed
                                        │
                                        ▼
                                   app code runs (box already closed)
Uninstall ──► UID retired, data directory removed
```

UIDs are **not immediately reused** after uninstall, which prevents a new app from
inheriting a predecessor's leftover file access.

### `sharedUserId` — deprecated, still seen

Historically two apps signed by the **same certificate** could declare
`android:sharedUserId` and share a UID and data directory. This was used legitimately by
OEM app suites, and abusively by malware families shipping cooperating components.

**Deprecated as of Android 10 (API 29)**, and migrating away is non-trivial once shipped
(you cannot change it without breaking updates). If you see `sharedUserId` in a modern
sample, note it — it is unusual, it implies same-signer multi-app design, and it is worth
investigating as a multi-component malware pattern.

> **🚨 Misconception:** "The sandbox stops malware from stealing my banking data." It stops
> malware from *reading the banking app's files*. It does absolutely nothing about a
> malicious Accessibility Service reading the balance **off the screen** or an overlay
> harvesting the password **as you type it**. The sandbox protects data at rest between
> apps; banking malware attacks data in use, at the UI layer, with the user's consent.
> This distinction is the heart of [Ch 13](../malware/13-android-malware.md).

---

## 3. Layer 2 — SELinux and seccomp

### SELinux on Android

**Discretionary Access Control (DAC)** — the UID model above — is discretionary: the owner
of a file can change its permissions. **Mandatory Access Control (MAC)** is not: the policy
is fixed at build time and even root cannot violate it.

Timeline:

| Android | SELinux state |
|---|---|
| 4.3 | Introduced, **permissive** (log only) |
| 4.4 | Enforcing for a few domains |
| 5.0 | **Fully enforcing** for all domains |
| 8.0 | Treble: split `vndbinder`, vendor/system policy separation |

Everything is labelled with a security context:

```bash
$ adb shell ls -Z /data/data/com.example.app
u:object_r:app_data_file:s0:c241,c256

$ adb shell ps -Z | grep com.example
u:r:untrusted_app:s0:c241,c256  u0_a241  8123  ...
#      ^domain                            ^categories = per-app MLS isolation
```

Key domains: `untrusted_app` (normal apps), `platform_app`, `system_app`, `priv_app`,
`system_server`, `init`, `su` (only on userdebug/eng builds).

> **⚙️ Engineering Note:** The `:c241,c256` categories are **per-app MLS categories**. They
> are why two `untrusted_app` processes, despite sharing a domain, still cannot touch each
> other's files even if DAC were somehow misconfigured. SELinux and DAC are belt and braces,
> deliberately.

### Why it matters to you

1. **Root exploits must also defeat SELinux.** Getting `uid=0` on modern Android is
   insufficient; you land in a constrained domain. This is a large part of why kernel-level
   Android malware is rare and banking malware went the social-engineering route instead.
2. **Your analysis tooling is constrained too.** Frida's `frida-server` needs to run in a
   permissive-enough context; on production builds this generally requires Magisk. Expect to
   fight SELinux during lab setup, and know that `setenforce 0` on a rooted device changes
   the environment the malware observes (some samples check).
3. **Denials are evidence.** `avc: denied` lines in logcat during detonation tell you what
   the malware *tried* to do and was refused.

```bash
$ adb logcat | grep -i "avc: denied"
$ adb shell dmesg | grep avc      # requires root
$ adb shell getenforce            # Enforcing | Permissive
```

### seccomp-bpf

Since Android 8, app processes get a **syscall allowlist** installed post-fork. It blocks
syscalls apps have no business making, shrinking the kernel attack surface. You rarely
interact with it directly, but it's why some native exploit code that works on generic
Linux fails on Android.

---

## 4. Layer 3 — Permissions

### The evolution

| Era | Model | Problem it caused |
|---|---|---|
| ≤ Android 5.1 (API 22) | **Install-time**: accept all or don't install | Users accepted everything. Meaningless consent. |
| Android 6.0 (API 23) | **Runtime permissions** for dangerous groups | Users can deny/revoke; apps must handle refusal |
| Android 10 (API 29) | "Only while using the app" for location | Reduced background tracking |
| Android 11 (API 30) | **One-time permissions**; **auto-reset** of unused app permissions | Dormant malware loses grants |
| Android 12 (API 31) | Approximate location option; mic/camera indicators + kill switches | Visible surveillance |
| Android 13 (API 33) | `POST_NOTIFICATIONS` runtime permission; granular media permissions | Notification spam and OTP-phish surface reduced |
| Android 14 (API 34) | Partial photo/video access | Least-privilege media |

### Protection levels

| Level | Granting | Examples |
|---|---|---|
| `normal` | Automatic at install | `INTERNET`, `VIBRATE`, `RECEIVE_BOOT_COMPLETED` |
| `dangerous` | Runtime prompt | `READ_SMS`, `CAMERA`, `RECORD_AUDIO`, `READ_CONTACTS` |
| `signature` | Only if the requester is signed with the **same certificate** as the definer | Inter-app private APIs; OEM suites |
| `signature|privileged` | System-partition privileged apps | `INSTALL_PACKAGES` |
| **appop / special** | Dedicated Settings screen, not a normal prompt | `SYSTEM_ALERT_WINDOW`, `MANAGE_EXTERNAL_STORAGE`, accessibility binding, notification listener |

> **⚙️ Engineering Note:** `signature`-level permissions are the clearest illustration in the
> whole platform of why **the certificate is identity**. Android grants these based purely on
> "were these two APKs signed by the same key?" Not the package name. Not the developer name
> in the cert (which is self-asserted and meaningless). The **key**. → [Ch 06](06-certificates.md)

### `INTERNET` is `normal` — and that surprises people

`android.permission.INTERNET` is protection level `normal`, auto-granted at install with no
prompt. Every app can talk to the network. This is the reason "the app has internet access"
is never a finding, and why C2 detection must be behavioural.

### The killer detail: declaration ≠ grant

```bash
# What the app DECLARED (from the APK):
$ aapt2 dump permissions app.apk

# What the app was actually GRANTED (from the device):
$ adb shell dumpsys package com.suspect | sed -n '/runtime permissions:/,/^$/p'
    android.permission.READ_SMS: granted=true
    android.permission.RECORD_AUDIO: granted=false

# Special permissions live in appops, not the permission list:
$ adb shell cmd appops get com.suspect
$ adb shell cmd appops get com.suspect SYSTEM_ALERT_WINDOW
```

Three different questions, three different commands. Static analysis answers the first
only. → [Ch 11](../static-analysis/11-static-analysis.md)

---

## 5. The special permissions that matter

These are the ones banking malware needs. Learn them cold — this table is the backbone of
SUDARSHAN's capability scoring.

| Permission / capability | What it enables | Legit users | Malware use | MITRE |
|---|---|---|---|---|
| **`BIND_ACCESSIBILITY_SERVICE`** | Read screen content, inject taps/gestures, observe every UI event | Screen readers, password managers, automation, remote support | **The hinge.** Auto-grant other permissions, keylog, drive ATS transfers, detect foreground app | **T1453**, T1417.001 |
| **`SYSTEM_ALERT_WINDOW`** | Draw windows over other apps | Chat bubbles, floating players, screen dimmers | **Overlay phishing** — fake login on top of the real bank app | T1417.002 |
| **`REQUEST_INSTALL_PACKAGES`** | Prompt to install another APK | App stores, updaters, MDM | **Dropper installs the payload** | T1401-adjacent |
| **`QUERY_ALL_PACKAGES`** | Enumerate every installed package | Launchers, AV, backup, app managers | **Discover which banking apps you have**, then fetch matching overlays | T1418 |
| **`RECEIVE_SMS` / `READ_SMS`** | Read incoming/stored SMS | SMS apps, OTP autofill | **OTP interception** | T1636.004, T1638 |
| **Notification Listener** (`BIND_NOTIFICATION_LISTENER_SERVICE`) | Read every notification's content | Smartwatches, notification managers | **OTP theft without SMS permission**; dismiss security alerts | T1517 |
| **`MediaProjection`** (fgs type) | Capture the screen | Screen recorders, casting, remote support | **Hidden VNC**, credential capture | T1513 |
| **Device Admin / `BIND_DEVICE_ADMIN`** | Lock, wipe, enforce policy | MDM/EMM | **Anti-uninstall**, remote wipe after fraud (BRATA, BingoMod) | T1626.001, **T1629.001** |
| **`MANAGE_EXTERNAL_STORAGE`** | Broad file access | File managers, backup | Bulk data theft | T1420 |
| **`FOREGROUND_SERVICE`** + types | Persistent background execution | Music, fitness, navigation | Persistence | T1541 |

### Why accessibility is uniquely dangerous

Because it is **both a read and a write primitive over every app's UI**:

```
  canRetrieveWindowContent = READ  ─► sees your balance, your typed password,
                                       your OTP, which app is in the foreground

  canPerformGestures       = WRITE ─► taps "Allow" on permission dialogs,
                                       taps "Transfer", types account numbers,
                                       dismisses security warnings
```

Read + write over the UI of every app is, functionally, **remote control of the device
within the user's own authenticated sessions.** That's why On-Device Fraud defeats device
fingerprinting, geolocation checks, and IP reputation: the transaction genuinely originates
from the customer's device and session.

> **🏛️ Enterprise Insight:** When explaining this to a bank's fraud team, the framing that
> lands is: *"This is not a stolen password. This is a stranger sitting inside your
> customer's already-unlocked banking session, using their phone, from their home Wi-Fi."*
> Every legacy fraud control that asks "is this really the customer's device?" answers yes.
> → [Ch 14](../banking-malware/14-banking-malware.md), [Ch 20](../incident-response/20-incident-response.md)

---

## 6. Version gates: the arms race, dated

This is the section people get wrong most often, so every claim here carries its version and
API level. It is also directly relevant to why droppers behave as they do.

### The API level ↔ version map (memorise the recent rows)

| Android | API | Codename/notes |
|---|---|---|
| 6.0 | 23 | Runtime permissions |
| 7.0 | 24 | v2 signing; user CAs untrusted by default |
| 8.0 | 26 | Background limits; `InMemoryDexClassLoader` |
| 9 | 28 | v3 signing; non-SDK restrictions |
| 10 | 29 | Scoped storage; `sharedUserId` deprecated |
| 11 | 30 | v4 signing; scoped storage enforced; uncompressed `resources.arsc` |
| 12 | 31 | Explicit `android:exported`; ART Mainline |
| 13 | 33 | **Restricted Settings**; `POST_NOTIFICATIONS` |
| 14 | 34 | **Min targetSdk install block (< API 23)**; FGS types mandatory |
| 15 | 35 | **Min targetSdk raised to API 24**; Restricted Settings extended |
| 16 | 36 | Min installable targetSdk **not** raised beyond 24 |

### Android 13 (API 33) — Restricted Settings

**What it does:** If an app was installed from a source Android considers "sideloaded," the
user cannot simply toggle on Accessibility or Notification Listener access for it. Settings
shows a dialog explaining the setting is restricted for that app; enabling requires an extra
deliberate path.

**Why it exists:** Directly targeted at exactly the banking-malware playbook — the "please
enable Accessibility" step.

**How malware answered:** By not being "sideloaded" in the technical sense — see Android 15.

### Android 14 (API 34) — the minimum targetSdk install block

**What it does:** Apps targeting **below API 23 (Android 6.0)** cannot be installed at all.
The installer returns `INSTALL_FAILED_DEPRECATED_SDK_VERSION`. This applies regardless of
install source. The only escape is an explicit ADB flag:

```bash
$ adb install --bypass-low-target-sdk-block old-app.apk
```

**Why it exists:** AOSP's stated rationale is that malware deliberately targets old API
levels — commonly targetSdk 22 — specifically to opt out of the runtime permission model
introduced in API 23, so that permissions are granted wholesale at install time with no
runtime prompts.

> **⚖️ Judge Tip:** This is a beautiful, concrete example of the platform closing an evasion
> technique, and it's specific enough to prove you've read primary sources. "Android 14
> blocks installation of apps targeting below API 23, returning
> `INSTALL_FAILED_DEPRECATED_SDK_VERSION`, because malware was targeting API 22 to escape
> runtime permissions" is a sentence that ends the doubt about whether you know the platform.

### Android 15 (API 35) — the session-install distinction

Two changes:

1. Minimum installable `targetSdkVersion` raised to **API 24 (Android 7.0)**.
2. **Restricted Settings extended.** Apps installed by browsers, messaging apps, or file
   managers — i.e. anything **not** using the purpose-built **session-based install API** —
   are denied Accessibility and Notification Listener access. Third-party app stores that
   *do* use the session-based API are exempt, because Android needs legitimate alternative
   stores to work.

**And that exemption is the hole.** Malware droppers adopted the session-based install API
to present themselves as legitimate store-like installers, escaping the restriction.
ThreatFabric documented Octo2 and Crocodilus droppers specifically bypassing Android 13+
restrictions this way; **Zombinder** was observed as Octo2's first stage, presenting a decoy
that asks the user to install an "additional plugin."

```
   Old dropper                        Modern dropper
   ───────────                        ──────────────
   Intent ACTION_VIEW on APK          PackageInstaller.Session
        │                                  │
        ▼                                  ▼
   "installed from a browser"        "installed by an installer app"
        │                                  │
        ▼                                  ▼
   Restricted Settings BLOCKS         Restricted Settings does NOT apply
   accessibility toggle                     │
                                            ▼
                                     User enables Accessibility
                                            │
                                            ▼
                                     Full device takeover
```

> **🔬 Research Gap:** The session-based-install exemption is a genuine, currently-open
> weakness in the sideloading security boundary. There is no published, robust way for the
> platform to distinguish "legitimate third-party app store" from "dropper pretending to be
> one" without a trust anchor. Watch this space; it is the most likely area for the next
> Android hardening change, and SUDARSHAN should treat *installer package identity* as a
> first-class signal today. → [Ch 09](../apk/09-package-manager.md), [Ch 31](../appendix/31-future-research.md)

### Android 16 (API 36)

Notably did **not** raise the minimum installable targetSdk beyond API 24. Don't claim it
did.

---

## 7. Verified Boot and the hardware root of trust

### WHAT

**Android Verified Boot (AVB)** establishes a chain of cryptographic verification from
immutable hardware up through the OS:

```
  Hardware root of trust (fused key)
        │  verifies
        ▼
  Bootloader
        │  verifies (signature over vbmeta)
        ▼
  vbmeta / boot / system images
        │  dm-verity: per-block hash tree verified ON READ
        ▼
  Running system — any modified block is detected at access time
```

**Rollback protection** prevents flashing an older, vulnerable image by tracking a version
counter in tamper-evident storage.

**Boot states** are surfaced to the user and to attestation:

| State | Meaning |
|---|---|
| **GREEN** | Locked bootloader, verified with the OEM key |
| **YELLOW** | Locked, verified with a **user-supplied** key (custom ROM, locked) |
| **ORANGE** | **Unlocked** bootloader — no verification |
| **RED** | Verification failed — device won't boot normally |

### WHY it matters to a bank

A rooted or unlocked device breaks the assumption that the OS is enforcing anything.
Detecting boot state is therefore a genuine risk input — but see the misconception below.

> **🚨 Misconception:** "Root detection = malware detection." Completely different questions.
> A rooted device is a *risk posture* signal about the device. It says nothing about whether
> a specific APK is malicious. Meanwhile most real banking-malware victims are on
> **stock, locked, unrooted devices** — the malware never needed root. Conversely, developers,
> researchers, and enthusiasts root their own devices routinely. Treating root as malware
> gives you a huge false-positive population and misses the actual threat.
> → [Ch 32](../appendix/32-common-misconceptions.md)

TEE, StrongBox, Keystore, and key attestation are covered in [Ch 05](05-android-cryptography.md).

---

## 8. Play Protect

### WHAT

Google Play Protect is the on-device and cloud-backed malware defence built into Google
Play Services. It covers:

- **Pre-publication scanning** of apps submitted to Play
- **On-device scanning** of installed apps, including sideloaded ones
- **Real-time scanning** of never-before-seen apps at install time
- **Live threat detection** (behavioural, on-device ML, rolled out on newer Pixel/Samsung)
- **Untrusted-APK install blocking** in pilot markets

### The numbers (Google Security Blog, reviewing 2024)

- **~200 billion apps scanned daily.**
- **2.36 million** policy-violating apps blocked from Play (2023: 2.28 M; 2022: 1.43 M).
- **158,000** developer accounts banned.
- Prevented **1.3 million** apps from getting excessive/unnecessary permissions.
- **"In 2024, Google Play Protect's real-time scanning identified more than 13 million new
  malicious apps from outside Google Play."**
- **AI assisted 92% of human reviews** of harmful apps.
- **"More than 91% of app installs on Google Play now use the latest security features of
  Android 13 or newer."**
- Untrusted-APK install-blocking pilots (Brazil, Hong Kong, India, Kenya, Nigeria,
  Philippines, South Africa, Thailand, Vietnam) **"shielded 10 million devices from over
  36 million risky installation attempts, encompassing over 200,000 unique apps."**
- Google launched an enhanced fraud-protection pilot **in India on October 3, 2024.**

### Reading those numbers correctly

The 13 million figure is the important one. **Play Protect finds roughly 5–6× more malware
outside Google Play than the 2.36 million it blocks inside it.** Sideloading is where
banking malware lives. That is the whole justification for a bank-side detection platform.

> **🚨 Misconception:** "Play Protect catches everything." It is a strong layer and it is not
> complete. Anatsa droppers have repeatedly reached Google Play — one reaching **#4 in Top
> Free Tools** (ThreatFabric, June 2025) — because they are genuinely clean at review time
> and turn malicious via a later update. Static review cannot detect a payload that doesn't
> exist yet. Play Protect is a layer; the bank still carries the fraud loss.

---

## 9. Play Integrity API

### WHAT

An API that lets an app ask Google for a signed verdict about the integrity of the device,
the app binary, the user's account, and (optionally) the app's licensing.

**It replaced SafetyNet Attestation.** Hard dates: **SafetyNet Attestation was fully shut
down on January 31, 2025**, and the migration transition ended **May 20, 2025**, breaking
apps that hadn't migrated.

### The verdicts

| Field | Values / meaning |
|---|---|
| `deviceIntegrity` | `MEETS_BASIC_INTEGRITY`, `MEETS_DEVICE_INTEGRITY`, `MEETS_STRONG_INTEGRITY` |
| `appIntegrity` | `PLAY_RECOGNIZED` (unmodified, Play-distributed), `UNRECOGNIZED_VERSION`, `UNEVALUATED` |
| `accountDetails` | `LICENSED` / `UNLICENSED` — legitimate Play install for this account |
| `environmentDetails` | e.g. app-access risk, Play Protect verdict (where available) |

Notable specifics:

- From **Android 13+**, `MEETS_STRONG_INTEGRITY` requires the device to have received a
  security update within roughly the **last 12 months**.
- **May 2025 changes** require hardware-backed signals, making rooted devices and custom ROMs
  substantially harder to pass.
- Attestation logic runs inside the **DroidGuard** environment (obfuscated, remotely
  updatable), which is why bypasses are an ongoing cat-and-mouse rather than a one-time break.

### The single most important implementation rule

> **⚙️ Engineering Note:** **Verify the verdict server-side.** The API returns a signed token;
> the app must send it to the app's backend, which decrypts/verifies it with Google. Checking
> the verdict on-device and branching on the result is trivially patchable — hook the boolean,
> return `true`, done. The most common real-world failure of SafetyNet was exactly this
> client-side-only pattern. Banks repeat this mistake constantly; it is worth an explicit
> check in any mobile app security review. → [Ch 12](../dynamic-analysis/12-dynamic-analysis.md)

### Where it helps and where it doesn't

**Helps:** detecting emulators, modified app binaries, unlicensed installs, and rooted
devices.

**Does not help:** the actual banking-malware scenario. A victim's phone running Anatsa is a
**stock, locked, unmodified device passing STRONG_INTEGRITY with a genuine Play-installed
banking app**. Integrity attestation asks "is this device and app genuine?" The answer is
yes. The problem is that a malicious Accessibility Service is driving the genuine app.

> **⚖️ Judge Tip:** If a judge suggests Play Integrity solves mobile banking fraud, this is
> your moment. "Play Integrity answers 'is the device compromised or the app modified?' In
> the dominant fraud scenario — On-Device Fraud via Accessibility abuse — the device is
> stock, the bank app is unmodified and Play-installed, and integrity checks pass cleanly.
> That's precisely why detection has to happen at the *behaviour and third-party-app* layer,
> which is what SUDARSHAN does."

---

## 10. Where the model fails

An honest inventory. Each row is a design input for SUDARSHAN.

| Gap | Why the model doesn't cover it | Consequence |
|---|---|---|
| **User consent is the weakest link** | Permissions are a consent model; a convinced user grants anything | Accessibility abuse works within the rules |
| **Accessibility is over-powerful by necessity** | Genuine accessibility needs full screen read + input injection | No way to narrow it without breaking real users |
| **Session-install exemption** | Legitimate third-party stores must work | Droppers impersonate stores (§6) |
| **Store review is point-in-time** | Can't detect a payload that doesn't exist yet | Clean-then-update droppers (Anatsa) |
| **Signature ≠ trustworthiness** | Self-signed certs; anyone can generate a key | Identity is stable, not *good* → [Ch 06](06-certificates.md) |
| **Notification access ≈ SMS access** | Notifications legitimately need to be readable | OTP theft without SMS permission |
| **Integrity attestation is device-scoped** | Asks about the device/app, not about *other* apps | Blind to the malicious third app (§9) |
| **Sideloading must remain possible** | Open platform commitment, regulatory pressure | 13 M malicious apps found outside Play in 2024 |

> **🔬 Research Gap:** There is no good published solution to *scoped* accessibility — a way
> for a user to grant an app screen-reading for its own purposes without granting it read
> access to a banking app's UI. Proposals exist (per-app a11y scoping, sensitive-window
> flags, `FLAG_SECURE` extensions) but nothing shipped and general. This is arguably the most
> valuable open problem in Android security today. → [Ch 31](../appendix/31-future-research.md)

---

## 11. Detection logic for SUDARSHAN

### The capability scoring core

This chapter supplies SUDARSHAN's primary static feature set. The design rule from
[Ch 00](../00-introduction.md): **cluster, never single-signal**, and **separate severity
from confidence**.

```yaml
# Capability weights — illustrative, calibrate against a real corpus (see Ch 27)
capabilities:
  accessibility_service_declared:        { weight: 30, requires_context: true }
  a11y_can_retrieve_window_content:      { weight: 15 }
  a11y_can_perform_gestures:             { weight: 20 }
  a11y_no_package_scope:                 { weight: 10 }   # packageNames empty
  system_alert_window:                   { weight: 15 }
  request_install_packages:              { weight: 15 }
  query_all_packages:                    { weight: 12 }
  sms_read_or_receive:                   { weight: 12 }
  notification_listener_declared:        { weight: 12 }
  media_projection_fgs_type:             { weight: 12 }
  device_admin_declared:                 { weight: 10 }
  manage_external_storage:               { weight: 8 }
  target_sdk_below_26:                   { weight: 10 }
  target_sdk_below_23:                   { weight: 20 }   # install-blocked on A14+
  shared_user_id_present:                { weight: 5 }

gating_rule:
  # No score is emitted from permissions ALONE.
  # A single capability, however scary, is a "review" flag at most.
  escalate_when:
    - accessibility_service_declared AND (can_retrieve_window_content OR can_perform_gestures)
    - AND count(other_cluster_members) >= 2
```

### Runtime/device-side signals (for MTD or agent integration)

| Check | Command / API | Meaning |
|---|---|---|
| Enabled a11y services | `settings get secure enabled_accessibility_services` | **Highest-yield single triage check** |
| Notification listeners | `settings get secure enabled_notification_listeners` | OTP theft path |
| Overlay grants | `cmd appops get <pkg> SYSTEM_ALERT_WINDOW` | Overlay capability |
| Device admins | `dumpsys device_policy` | Anti-uninstall |
| Install source | `pm list packages -i` | Session-install / dropper attribution → [Ch 09](../apk/09-package-manager.md) |
| Boot state | Play Integrity / `getprop ro.boot.verifiedbootstate` | Device risk posture (**not** malware) |
| SELinux denials | `logcat \| grep "avc: denied"` | What the sample tried and failed to do |
| Hidden-API access | `logcat \| grep "Accessing hidden"` | Non-SDK bypass attempts → [Ch 03](../android/03-android-runtime.md) |

> **🏛️ Enterprise Insight:** For a bank integrating SUDARSHAN signals into its own mobile
> app SDK, the two highest-value, lowest-friction checks are (1) is any accessibility service
> enabled that isn't on a known-good allowlist, and (2) is an overlay window present while
> our login/transaction screen is foreground. Both are cheap, both map directly to the
> dominant attack, and neither requires root. Pair with `FLAG_SECURE` on sensitive screens
> and overlay-obscured touch filtering. → [Ch 20](../incident-response/20-incident-response.md)

---

## 12. Limitations, edge cases, false positives

### False positives

| Signal | Legitimate population |
|---|---|
| Accessibility service | Password managers, TalkBack alternatives, Tasker/automation, remote support (TeamViewer, AnyDesk), accessibility utilities |
| `SYSTEM_ALERT_WINDOW` | Messenger chat heads, floating video, screen dimmers, recorders |
| `REQUEST_INSTALL_PACKAGES` | F-Droid, Amazon Appstore, Samsung Galaxy Store, MDM agents, updaters |
| `QUERY_ALL_PACKAGES` | Launchers, antivirus, backup, parental controls, app managers |
| Notification listener | Wear OS companions, Android Auto helpers, notification history apps |
| Device admin | Every legitimate MDM/EMM agent |
| Rooted device | Developers, researchers, privacy enthusiasts |
| Low targetSdk | Abandoned-but-benign apps |

**A password manager legitimately has accessibility.** It does not also have
`REQUEST_INSTALL_PACKAGES`, SMS read, `QUERY_ALL_PACKAGES`, a `mediaProjection` foreground
service, and a dynamically loaded DEX. **The cluster is the signal.**

### False negatives

- Capabilities acquired via a dynamically loaded payload the static manifest doesn't show.
- Dropper manifests are deliberately minimal.
- Native-implemented behaviour.
- Region/time-gated activation.

### Edge cases

- **Work profiles / multi-user**: same package, different UIDs (`u0_a123`, `u10_a123`).
  Forensic and telemetry tooling must be multi-user aware.
- **Preinstalled/system apps** hold permissions no third-party app could obtain; don't score
  them on the same scale. Supply-chain-compromised preinstalls are a real and separate
  problem class.
- **`signature`-level permissions** granted to a same-signer sibling app — legitimate, but
  worth mapping.
- **OEM permission divergence** (Chinese OEM ROMs with custom autostart managers) changes
  observed behaviour in dynamic analysis.

### Performance

Permission and manifest extraction is milliseconds. Device-side checks are cheap. There is
no throughput reason not to compute every signal in this chapter on every sample.

---

## 13. Engineering tips

1. **Never score a permission in isolation.** Write this on the wall.
2. **Distinguish declared / granted / appop-granted.** Three commands, three answers.
3. **`settings get secure enabled_accessibility_services` is your first triage command** on
   any suspect device.
4. **Version-gate every claim.** "Android blocks X" is almost always wrong without an API
   level attached.
5. **Check for client-side-only integrity verification** in any bank app you review — it's
   the most common real finding.
6. **Log `avc: denied` and `Accessing hidden`** during every detonation. Free intelligence.
7. **Treat root/emulator detection as device posture, never as malware verdict.**

---

## 14. Judge Insights

**What judges ask:** *"Android has sandboxing, SELinux, signature verification, Play Protect,
and hardware attestation. Why is mobile banking fraud still growing 67% year over year?"*

**Perfect answer:** Because banking malware doesn't break any of those layers. It doesn't
exploit the kernel, doesn't defeat SELinux, doesn't forge signatures, and typically doesn't
need root. It asks the user to enable an Accessibility Service — a legitimate API — and then
operates entirely within the rules. `canRetrieveWindowContent` gives it read access to every
app's screen and `canPerformGestures` gives it write access to every app's input. Read plus
write over the UI is functionally remote control inside the victim's own authenticated
session, which is why it's called On-Device Fraud: the transaction comes from the real
device, real IP, real session. Every control that asks "is this really the customer?"
answers yes. The security model was never designed to protect a user from their own consent,
which is exactly the gap a bank-side detection platform has to fill.

**Common mistakes:**
- Saying "Android is insecure." It isn't; that answer reads as uninformed.
- Claiming malware "roots the phone." Modern banking malware overwhelmingly doesn't need to.
- Saying "Play Integrity would stop this." It wouldn't — the device and bank app are genuine.

**Follow-ups to expect:**
- *"Why doesn't Google just restrict Accessibility more?"* → They have, repeatedly (Android
  13 Restricted Settings, Android 15 session-install distinction), but genuine accessibility
  users need full screen-read and input-injection, and there's no shipped mechanism for
  scoped accessibility. It's an open research problem.
- *"How did malware get past Android 13's restrictions?"* → By adopting the **session-based
  install API**, which exempts legitimate third-party stores. ThreatFabric documented Octo2
  and Crocodilus droppers doing exactly this.
- *"Doesn't the sandbox protect banking data?"* → It protects data *at rest between apps*.
  Banking malware attacks data *in use*, at the UI layer.

**Fact that impresses:** Android 14 hard-blocks installation of apps targeting below API 23,
returning `INSTALL_FAILED_DEPRECATED_SDK_VERSION`, specifically because malware targeted
API 22 to opt out of the runtime permission model. Android 15 raised that floor to API 24;
Android 16 did not raise it further.

---

## 15. Interview Insights

**Q: "Explain the Android security model."**
Answer in layers, bottom-up: Verified Boot → DAC (UID sandbox) → MAC (SELinux + seccomp) →
signing/identity → permissions → attestation → ecosystem policy. Then add the analyst's
insight: *most real Android malware defeats none of these; it uses consent.* That last
sentence is what distinguishes a memorised answer from an understood one.

**Q: "How does Android enforce permissions?"**
Not in the calling app. In the *service*, using `Binder.getCallingUid()` — kernel-supplied
and unspoofable. That's why patching your own client-side `checkSelfPermission()` achieves
nothing. → [Ch 01 §6](../android/01-android-internals.md#6-binder-ipc)

**Q: "What's the difference between install-time, runtime, and special permissions?"**
Install-time (`normal`) auto-granted, e.g. `INTERNET`. Runtime (`dangerous`) prompted at use,
since API 23. Special/appop permissions require a dedicated Settings screen —
`SYSTEM_ALERT_WINDOW`, accessibility binding, notification listener, `MANAGE_EXTERNAL_STORAGE`
— and these are the ones banking malware needs.

**Q: "Is a rooted device compromised?"**
No — it's a device whose owner unlocked it, which is a *risk posture* signal, not a malware
verdict. Most banking-malware victims run stock, locked, unrooted devices. Conflating the two
produces false positives and misses real threats.

**Q: "SafetyNet or Play Integrity?"**
Play Integrity. SafetyNet Attestation was fully shut down on January 31, 2025, with the
migration transition ending May 20, 2025. And the key implementation point: **verify the
token server-side**, because client-side verdict checks are trivially patched.

**Beginner mistakes:**
- Version-free claims ("Android blocks that now").
- Confusing declared with granted permissions.
- Assuming the sandbox protects against screen-reading attacks.
- Believing Play Protect is comprehensive.

---

## 16. Cross-references

**Upstream:**
- [← Ch 01 Android Internals](../android/01-android-internals.md) — Binder, UID assignment
- [← Ch 03 Android Runtime](../android/03-android-runtime.md) — targetSdk gates, hidden APIs

**Downstream:**
- [→ Ch 05 Android Cryptography](05-android-cryptography.md) — Keystore, TEE, attestation detail
- [→ Ch 06 Certificates](06-certificates.md) — why signature permissions prove cert = identity
- [→ Ch 09 Package Manager](../apk/09-package-manager.md) — session installs and the A15 gap
- [→ Ch 13 Android Malware](../malware/13-android-malware.md) — accessibility abuse in full
- [→ Ch 14 Banking Malware](../banking-malware/14-banking-malware.md) — ODF/DTO mechanics
- [→ Ch 27 Risk Scoring](../sudarshan/27-risk-scoring.md) — calibrating the weights in §11
- [→ Ch 32 Common Misconceptions](../appendix/32-common-misconceptions.md) — root, permissions, Play Protect

**Related chain:** Permission → Accessibility → Overlay → OTP theft → ODF → fraud loss.

---

## 17. References

1. AOSP — *Android Security Overview*. https://source.android.com/docs/security
2. AOSP — *Application Sandbox*. https://source.android.com/docs/security/app-sandbox
3. AOSP — *Security-Enhanced Linux in Android*. https://source.android.com/docs/security/features/selinux
4. AOSP — *Verified Boot*. https://source.android.com/docs/security/features/verifiedboot
5. Android Developers — *Permissions on Android*. https://developer.android.com/guide/topics/permissions/overview
6. Android Developers — *Behavior changes: all apps (Android 14)* — minimum installable targetSdk. https://developer.android.com/about/versions/14/behavior-changes-all
7. Android Developers — *Behavior changes (Android 15)* — Restricted Settings and targetSdk floor. https://developer.android.com/about/versions/15/behavior-changes-all
8. Android Developers — *Play Integrity API* documentation. https://developer.android.com/google/play/integrity
9. Google Security Blog — *How we kept the Google Play & Android app ecosystems safe in 2024*. https://security.googleblog.com/
10. Google — SafetyNet Attestation deprecation and shutdown timeline (fully shut down Jan 31, 2025; transition ended May 20, 2025).
11. ThreatFabric — *Octo2* analysis (September 2024) — Zombinder first stage, Android 13+ restriction bypass.
12. ThreatFabric — *Crocodilus* analysis (March 29, 2025) — dropper bypassing Android 13+ restrictions.
13. MITRE ATT&CK for Mobile — T1453, T1417.001, T1626.001, T1629.001, T1517, T1513, T1638. https://attack.mitre.org/matrices/mobile/
14. OWASP MASVS v2.1.0 — MASVS-PLATFORM, MASVS-RESILIENCE. https://mas.owasp.org/MASVS/
15. NIST SP 800-124 Rev. 2 — *Guidelines for Managing the Security of Mobile Devices*.

### Further reading
- AOSP `system/sepolicy/` — the actual SELinux policy source
- OWASP MASTG — platform and resilience test cases
- Google Project Zero — Android privilege-escalation research archive

---

*Previous: [← Ch 03 Android Runtime](../android/03-android-runtime.md) · Next: [Ch 05 Android Cryptography →](05-android-cryptography.md)*
