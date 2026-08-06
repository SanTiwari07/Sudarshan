# 17 — Digital Forensics

> **Chapter ID:** `CH17` · **Block:** D (Operations) · **Status:** Stable
> **Tags:** `#forensics` `#acquisition` `#bfu-afu` `#artifacts` `#chain-of-custody` `#aleapp` `#cert-in` `#dpdp`
> **Last Updated:** 2026-08-05 · **Version:** 1.0.0
> **Prerequisites:** [Ch 01](../android/01-android-internals.md), [Ch 05](../security/05-android-cryptography.md), [Ch 09](../apk/09-package-manager.md)

---

## Table of Contents

1. [Why forensics, when you already have the APK](#1-why-forensics-when-you-already-have-the-apk)
2. [The golden rules](#2-the-golden-rules)
3. [BFU vs AFU — the variable that decides everything](#3-bfu-vs-afu--the-variable-that-decides-everything)
4. [Acquisition tiers](#4-acquisition-tiers)
5. [The artifact map](#5-the-artifact-map)
6. [Reconstructing the attack timeline](#6-reconstructing-the-attack-timeline)
7. [Tools](#7-tools)
8. [Anti-forensics](#8-anti-forensics)
9. [Chain of custody and legal context](#9-chain-of-custody-and-legal-context)
10. [Detection logic for SUDARSHAN](#10-detection-logic-for-sudarshan)
11. [Limitations, edge cases, false positives](#11-limitations-edge-cases-false-positives)
12. [Engineering tips](#12-engineering-tips)
13. [Judge Insights](#13-judge-insights)
14. [Interview Insights](#14-interview-insights)
15. [Cross-references](#15-cross-references)
16. [References](#16-references)

---

## 1. Why forensics, when you already have the APK

Malware analysis answers *"what does this software do?"* Forensics answers a different and
often more urgent set of questions:

| Question | Only forensics answers it |
|---|---|
| **When** was it installed? | `packages.xml` timestamps |
| **Who** installed it? | Installer attribution |
| **Was accessibility actually enabled**, and when? | `settings_secure.xml` |
| **What did it actually access** on *this* device? | App sandbox, usage stats |
| **Did the fraud happen before or after** infection? | Timeline correlation |
| **Are there other compromised apps?** | Full package inventory |
| **Can this stand up in court / with a regulator?** | Chain of custody |

> **🏛️ Enterprise Insight:** For a bank, the decisive forensic output is usually a **single
> timestamp**: the moment the malicious app was installed, compared against the disputed
> transaction. That comparison drives the liability determination, the customer conversation,
> and the regulatory filing. An analysis that proves an APK is Anatsa but cannot establish
> *when it landed on this customer's phone* leaves the most consequential question open.

### Where forensics sits

```
  SUSPECTED FRAUD
        │
        ├──► SAMPLE ANALYSIS  (Ch 10–12)  "what is this software?"
        │
        └──► DEVICE FORENSICS (this chapter) "what happened on THIS device?"
                    │
                    ▼
             TIMELINE + EVIDENCE
                    │
                    ▼
        INCIDENT RESPONSE (Ch 20) + regulatory reporting
```

---

## 2. The golden rules

Six rules. Violating any of them can destroy the case.

```
 1. ACQUIRE BEFORE YOU REMEDIATE.
    BRATA and BingoMod WIPE the device on detection of removal attempts.
    Uninstall first and you may destroy the only evidence.   → Ch 13 §8

 2. KEEP THE DEVICE POWERED ON AND UNLOCKED (AFU).
    Powering off drops it to BFU and can render data unrecoverable.  → §3

 3. ISOLATE THE NETWORK — but do not power off.
    Airplane mode / Faraday bag. Prevents remote wipe and further exfil.

 4. HASH EVERYTHING, IMMEDIATELY.
    SHA-256 at acquisition; re-verify at every handoff.

 5. WORK ON COPIES. NEVER ON THE ORIGINAL.

 6. DOCUMENT EVERY ACTION WITH TIME, OPERATOR, AND TOOL VERSION.
    "I ran adb" is not documentation. Command, timestamp, output hash is.
```

> **⚙️ Engineering Note — rules 1 and 3 are in tension, and rule 3 wins.** You need the network
> off to prevent a remote wipe command reaching the device, and you need the device *on* to keep
> CE keys in memory. Airplane mode or a Faraday bag achieves both. Pulling the battery achieves
> neither and loses you the AFU state.

---

## 3. BFU vs AFU — the variable that decides everything

From [Ch 05 §6](../security/05-android-cryptography.md#6-disk-encryption-fde--fbe): **File-Based
Encryption** splits storage into two classes.

| Class | Key availability | Contents |
|---|---|---|
| **DE** (Device Encrypted) | Available at boot | Alarms, dialer, accessibility services, minimal system state |
| **CE** (Credential Encrypted) | **Only after first unlock** | Essentially all app data |

```
   POWER ON
       │
       ▼
   ┌──────────────────────────────────────────┐
   │ BFU — Before First Unlock                │
   │  • DE storage readable                   │
   │  • CE data CRYPTOGRAPHICALLY INACCESSIBLE│
   │  • App sandboxes: unreadable             │
   │  → very limited forensic yield           │
   └───────────────────┬──────────────────────┘
                       │ user unlocks
                       ▼
   ┌──────────────────────────────────────────┐
   │ AFU — After First Unlock                 │
   │  • CE keys resident in memory            │
   │  • App data readable (with root/tooling) │
   │  → FULL forensic yield                   │
   └──────────────────────────────────────────┘
                       │ power off
                       ▼
                  back to BFU  ☠️
```

> **⚙️ Engineering Note — this belongs on page one of any device-seizure runbook.** If a device
> arrives powered on and unlocked, **keep it that way**: disable auto-lock, keep it charged,
> isolate the network, and acquire immediately. A responder who "safely powers it down for
> transport" has, in one action, potentially converted a recoverable case into an unrecoverable
> one. This is the most consequential and most commonly violated rule in mobile forensics.

---

## 4. Acquisition tiers

| Tier | What you get | Access needed | Forensic soundness |
|---|---|---|---|
| **Manual** | Photographs of screens | Unlocked device | Low — but zero-risk and fast |
| **Logical** | Backups, ADB-accessible data, `bugreport` | USB debugging | Medium |
| **File system** | `/data` tree | **Root** or exploit/vendor tooling | High |
| **Physical** | Bit-for-bit image | Bootloader/chip-level access | Highest — rarely achievable on modern devices |

### Reality check on modern devices

Full **physical** acquisition of a current, locked, FBE Android device is generally **not
achievable** without vendor-grade tooling (Cellebrite, MSAB, Magnet) and often not even then,
depending on chipset and patch level. Most real bank-fraud casework runs on **logical +
file-system acquisition of an AFU device with the customer's consent**.

### Logical acquisition — the practical commands

```bash
# ---- 0. document the device and the moment -------------------------------
$ date -u; adb shell getprop ro.product.model; adb shell getprop ro.build.fingerprint
$ adb shell getprop ro.build.version.release; adb shell getprop ro.build.version.security_patch

# ---- 1. THE HIGH-VALUE TRIO (run these first) -----------------------------
$ adb shell settings get secure enabled_accessibility_services      # ★★★
$ adb shell settings get secure enabled_notification_listeners      # ★★
$ adb shell pm list packages -f -i -3                                # ★★★ installer attribution

# ---- 2. broad state capture ----------------------------------------------
$ adb shell dumpsys package        > dumpsys_package.txt
$ adb shell dumpsys accessibility  > dumpsys_accessibility.txt
$ adb shell dumpsys device_policy  > dumpsys_device_policy.txt
$ adb shell dumpsys notification   > dumpsys_notification.txt
$ adb shell dumpsys usagestats     > dumpsys_usagestats.txt
$ adb shell cmd appops get --all   > appops.txt
$ adb shell dumpsys window         > dumpsys_window.txt

# ---- 3. full bug report (large, comprehensive) ---------------------------
$ adb bugreport bugreport_$(date -u +%Y%m%dT%H%M%SZ).zip

# ---- 4. logs -------------------------------------------------------------
$ adb logcat -d -b all > logcat_all.txt

# ---- 5. pull the suspect APK(s) — ALL splits -----------------------------
$ adb shell pm path com.suspect | sed 's/package://' | while read p; do adb pull "$p"; done

# ---- 6. hash everything NOW ----------------------------------------------
$ sha256sum * > acquisition_manifest.sha256
```

> **⚙️ Engineering Note:** `adb backup` is **deprecated** and unreliable on modern Android —
> many apps set `allowBackup="false"` and Android 12+ restricts it further. Don't build a
> workflow on it. Use `bugreport`, `dumpsys`, and direct pulls, and file-system acquisition
> where root or tooling permits.

---

## 5. The artifact map

### The core artifacts, ranked by value for banking-malware casework

| # | Artifact | Path | Yields |
|---|---|---|---|
| 1 | **Accessibility state** | `/data/system/users/0/settings_secure.xml` | **Which services were enabled** ★★★ |
| 2 | **Package registry** | `/data/system/packages.xml` | **Installer, install time, signer cert, granted perms** ★★★ |
| 3 | Package list | `/data/system/packages.list` | UID ↔ package mapping |
| 4 | AppOps | `/data/system/appops.xml` | `SYSTEM_ALERT_WINDOW` and other special grants |
| 5 | Device policy | `/data/system/device_policies.xml` | Device admin registrations |
| 6 | Usage stats | `/data/system/usagestats/` | **Which apps ran, and when** ★★ |
| 7 | Notification log | `dumpsys notification` | Notification history |
| 8 | App sandboxes | `/data/data/<pkg>/` | Databases, prefs, cached exfil |
| 9 | Installed APKs | `/data/app/<pkg>-<rand>/` | The artifact itself |
| 10 | ART artifacts | `/data/app/.../oat/` | **`.vdex` → recoverable DEX** ([Ch 03 §4](../android/03-android-runtime.md#4-the-compiled-artifacts-oat-vdex-art)) |
| 11 | Profiles | `/data/misc/profiles/cur/0/<pkg>/primary.prof` | **Which methods actually executed** ★ |
| 12 | Wi-Fi / network | `/data/misc/wifi/`, connectivity logs | Location inference |

### `packages.xml` — the single richest artifact

```xml
<package name="com.suspect.app"
         codePath="/data/app/~~aBc/com.suspect.app-XyZ"
         ft="18f2a1b3c00"      <!-- ★ first install time (hex ms since epoch) -->
         it="18f2a1b3c00"      <!-- install time -->
         ut="18f3c9d4e11"      <!-- last update time -->
         version="12"
         installer="com.fake.pdfreader"    <!-- ★★★ WHO INSTALLED IT -->
         userId="10241">
  <sigs count="1">
    <cert index="7" key="308203..."/>      <!-- ★★ SIGNER CERT, DER-encoded -->
  </sigs>
  <perms>
    <item name="android.permission.RECEIVE_SMS" granted="true" flags="..."/>
  </perms>
</package>
```

```python
# Convert the hex timestamps — analysts get this wrong constantly
from datetime import datetime, timezone
ms = int("18f2a1b3c00", 16)
print(datetime.fromtimestamp(ms/1000, tz=timezone.utc).isoformat())
```

> **⚙️ Engineering Note:** The `<cert>` element persists the signer certificate **even after the
> APK is deleted**. So if the malware self-removed, `packages.xml` (or its backup at
> `packages-backup.xml`) may still prove which signer was installed and when. Also always check
> `/data/system/packages-backup.xml` — it sometimes retains an earlier state the live file no
> longer shows. → [Ch 06](../security/06-certificates.md)

### The accessibility artifact

```xml
<!-- /data/system/users/0/settings_secure.xml -->
<setting id="..." name="enabled_accessibility_services"
         value="com.suspect.app/com.suspect.A11yService" package="android" />
<setting id="..." name="accessibility_enabled" value="1" package="android" />
```

**This is the proof of compromise mechanism.** Combined with the install time from
`packages.xml`, it establishes when the device became controllable.

### Usage stats — the underused timeline source

`/data/system/usagestats/` records app foreground events with timestamps. For an ODF case this
lets you show: *malware installed at T, accessibility enabled at T+2min, banking app foregrounded
at T+14min, transaction at T+15min.* That is a narrative a fraud team and a regulator can both
follow.

```bash
$ adb shell dumpsys usagestats | head -100
```

---

## 6. Reconstructing the attack timeline

The deliverable. Everything above serves this.

```
 ┌────────────────────────────────────────────────────────────────────┐
 │  ANDROID BANKING FRAUD — RECONSTRUCTED TIMELINE                    │
 ├──────────────┬─────────────────────────────────────────────────────┤
 │ T-3d 14:02   │ Dropper "PDF Reader Pro" installed                  │
 │              │   source: packages.xml ft= · installer=com.android. │
 │              │           packageinstaller (browser hand-off)       │
 ├──────────────┼─────────────────────────────────────────────────────┤
 │ T-3d 14:05   │ Payload "System Service" installed                  │
 │              │   installer = com.fake.pdfreader  ★ DROPPER PROVEN  │
 ├──────────────┼─────────────────────────────────────────────────────┤
 │ T-3d 14:06   │ Accessibility service enabled                       │
 │              │   source: settings_secure.xml                       │
 ├──────────────┼─────────────────────────────────────────────────────┤
 │ T-3d 14:06   │ SYSTEM_ALERT_WINDOW granted (appops.xml)            │
 │ T-3d 14:07   │ RECEIVE_SMS granted (packages.xml perms)            │
 │              │   ★ 60 seconds apart → SELF-ESCALATION, not a user  │
 ├──────────────┼─────────────────────────────────────────────────────┤
 │ T-0  09:31   │ Banking app foregrounded (usagestats)               │
 │ T-0  09:32   │ Overlay window created (logcat, if still resident)  │
 │ T-0  09:34   │ ★ DISPUTED TRANSACTION (bank records)               │
 │ T-0  09:34   │ Inbound SMS — OTP (bank records; device SMS absent) │
 └──────────────┴─────────────────────────────────────────────────────┘
```

> **⚙️ Engineering Note — the strongest single forensic argument.** Look at the permission grant
> timestamps. Three dangerous permissions granted within **60 seconds**, immediately after an
> accessibility service was enabled, is **not** a pattern a human produces — a person navigating
> permission dialogs takes longer and rarely grants a full cluster consecutively. That timing
> signature is machine-driven self-escalation
> ([Ch 13 §3](../malware/13-android-malware.md#3-accessibility-service-abuse--the-hinge)), and it
> is compelling, explainable evidence for a fraud committee that the customer did not knowingly
> authorise the capability.

### Correlating with bank-side data

| Device artifact | Bank artifact | Establishes |
|---|---|---|
| Install time | First anomalous login | Infection preceded fraud |
| a11y enable time | Session start | Control mechanism was live |
| usagestats foreground | Transaction timestamp | App was open at the time |
| Missing SMS on device | OTP send record | **OTP intercepted and deleted** |
| Device ID / IP | Session logs | Same device, same IP → ODF signature |

---

## 7. Tools

| Tool | Type | Use |
|---|---|---|
| **ALEAPP** | Open source | **Android Logs Events And Protobuf Parser** — parses the artifacts in §5 into an HTML/timeline report. Start here. |
| **Autopsy** + Sleuth Kit | Open source | File-system forensics, timeline, keyword search |
| **Cellebrite UFED / Physical Analyzer** | Commercial | Widest device support, exploit-based acquisition |
| **MSAB XRY** | Commercial | Strong logical/physical acquisition |
| **Magnet AXIOM** | Commercial | Artifact parsing + timeline, strong reporting |
| **adb + dumpsys** | Built-in | Fast triage; scriptable |
| **SQLite tooling** (`sqlite3`, DB Browser) | Open source | App databases — **remember WAL** |
| **libimobiledevice** | Open source | iOS equivalent (out of scope) |

> **⚙️ Engineering Note — the WAL trap, again.** SQLite on modern Android uses Write-Ahead
> Logging. Copying only `foo.db` and not `foo.db-wal` and `foo.db-shm` **loses the most recent
> transactions** — precisely the ones covering the fraud window. This single mistake invalidates
> a large amount of amateur mobile forensics. Always acquire the sibling files, and check them
> before concluding a table is empty.
> → [Ch 01 §9](../android/01-android-internals.md#9-storage-from-wild-west-to-scoped)

### A minimal open-source workflow

```bash
# 1. acquire (AFU device, consented, network-isolated)
$ ./acquire.sh                       # the §4 command set, logged and hashed

# 2. parse with ALEAPP
$ python3 aleapp.py -t fs -i ./extraction/ -o ./report/

# 3. targeted checks
$ grep -A5 'enabled_accessibility_services' extraction/data/system/users/0/settings_secure.xml
$ python3 parse_packages_xml.py extraction/data/system/packages.xml --sort-by first_install

# 4. build the timeline
$ python3 build_timeline.py --packages packages.json --usagestats usagestats.json \
                            --settings settings.json --out timeline.csv
```

---

## 8. Anti-forensics

| Technique | Effect | Counter |
|---|---|---|
| **Device wipe** (BRATA, BingoMod) | Total evidence loss | **Acquire before remediation**; network isolate |
| Self-uninstall on command | APK gone | `packages.xml` / `packages-backup.xml` retain signer + timestamps |
| Log clearing | `logcat` cleared | Persistent artifacts survive; logcat is volatile anyway |
| Icon hiding | Victim can't find it | `pm list packages -3` |
| Encrypted local storage | App data unreadable | Memory analysis; key recovery ([Ch 12 §8](../dynamic-analysis/12-dynamic-analysis.md#8-memory-analysis)) |
| Timestamp manipulation | Misleading times | Cross-check multiple independent sources |
| Remote kill command | Triggered when C2 sees analysis | **Network isolate immediately** |

> **⚙️ Engineering Note:** The counter to nearly every row is the same: **isolate the network
> first, acquire second, remediate third.** Sequence is the whole discipline. Most mobile
> anti-forensics assumes the device stays online — cut that and most of it fails.

---

## 9. Chain of custody and legal context

### The record

Every transfer, every action, logged:

```
 EVIDENCE ITEM: Samsung SM-A536E, IMEI 3xxxxxxxxxxxxxx
 ─────────────────────────────────────────────────────────────────
 2026-08-05 09:14 UTC  Received from customer, powered ON, UNLOCKED
                       Airplane mode enabled. Operator: A. Sharma
 2026-08-05 09:16 UTC  Photographed; state documented
 2026-08-05 09:22 UTC  Logical acquisition begun (adb, platform-tools 35.0.2)
 2026-08-05 09:58 UTC  Acquisition complete.
                       SHA-256 (manifest): 7c2f...a91b
 2026-08-05 10:05 UTC  Working copy created; original image write-protected
 2026-08-05 10:30 UTC  Analysis begun on COPY. Operator: R. Nair
```

Requirements: **integrity** (hashes, verified at each handoff), **continuity** (no unexplained
gaps), **repeatability** (tool + version recorded so another examiner can reproduce),
**documentation** (contemporaneous, not reconstructed).

### The Indian legal and regulatory frame

| Instrument | Relevance |
|---|---|
| **IT Act 2000** (with amendments) | Computer-related offences; electronic evidence |
| **Bharatiya Sakshya Adhiniyam 2023** (replacing the Indian Evidence Act) | Admissibility of electronic records; certification requirements for computer-generated evidence |
| **CERT-In Directions, April 28 2022** | **6-hour incident reporting**; log retention obligations |
| **RBI Cyber Security Framework for Banks** | Bank incident handling, reporting, and controls |
| **DPDP Act 2023** | **Constrains what victim data may be collected, stored, and processed** |

> **🏛️ Enterprise Insight — the DPDP constraint is a design constraint, not a footnote.** A
> forensic image of a customer's phone contains their photos, messages, contacts, and health
> data — almost none of which is relevant to the fraud investigation. Under DPDP principles of
> purpose limitation and data minimisation, SUDARSHAN should **scope acquisition to the artifacts
> in §5**, not take a full image by default, and should apply retention limits and access
> controls to whatever it does hold. Build targeted collection profiles rather than
> "acquire everything and filter later." → [Ch 20](../incident-response/20-incident-response.md)

> **⚙️ Engineering Note:** The certification requirements for electronic evidence under the
> Bharatiya Sakshya Adhiniyam matter operationally — a technically perfect acquisition that
> lacks the required certification may be inadmissible. **Involve legal counsel in designing the
> acquisition workflow**, not after an incident. This is not a detail an engineering team can
> resolve alone, and this document is not legal advice.

---

## 10. Detection logic for SUDARSHAN

### The forensic record

```yaml
device_forensics:
  device: {model, android_version, api_level, security_patch, build_fingerprint}
  acquisition:
    method: logical | filesystem | physical
    state_at_seizure: AFU | BFU              # ★ determines yield
    operator: "..."
    started_utc: "..."
    completed_utc: "..."
    manifest_sha256: "..."
    tool_versions: {adb: "35.0.2", aleapp: "3.x"}
    scope: targeted_artifacts | full_image   # ★ DPDP: prefer targeted
  findings:
    suspicious_packages:
      - package: "com.suspect.app"
        first_install_utc: "..."
        installer: "com.fake.pdfreader"      # ★ dropper attribution
        signer_sha256: "..."                 # ★ → Ch 06 identity
        granted_permissions: [...]
        permission_grant_burst: true         # ★ self-escalation signature
        accessibility_enabled: true
        accessibility_enabled_utc: "..."
        device_admin: false
        icon_hidden: true
    timeline: [{ts_utc, event, source_artifact, confidence}]
    correlation_with_bank_records:
      infection_preceded_fraud: true
      time_delta_to_first_fraud: "3d 19h 32m"
  integrity:
    chain_of_custody_ref: "COC-2026-0805-014"
    all_hashes_verified: true
```

### High-value detection rules

| Rule | Evidence | Strength |
|---|---|---|
| **Third-party app installed another app** | `packages.xml` `installer=` | **Very strong** — dropper proof |
| **Accessibility enabled for a non-store app** | `settings_secure.xml` + installer | **Very strong** |
| **Permission grant burst < 2 min after a11y enable** | `packages.xml` grant flags + timestamps | **Very strong** — self-escalation |
| Signer not in the bank's canonical registry for its package | `<cert>` vs registry | **Deterministic** ([Ch 06](../security/06-certificates.md)) |
| App with no launcher entry | Package + component analysis | Strong |
| Device admin held by a non-MDM app | `device_policies.xml` | Strong |
| Banking app foregrounded immediately before disputed txn | `usagestats` | Supporting |
| SMS absent on device but sent per bank records | Bank + device comparison | **Strong — interception evidence** |

> **🏛️ Enterprise Insight:** The top three rules together produce a finding a fraud committee
> can act on without any malware analysis at all: *"an app installed by another third-party app
> obtained accessibility, then self-granted four permissions in ninety seconds, three days
> before the disputed transaction."* That is faster to produce than a full sample analysis and,
> for the liability question, frequently sufficient. Ship the forensic triage path as a
> **first-class product surface**, not an appendix to sample analysis.

---

## 11. Limitations, edge cases, false positives

### Limitations

- **BFU devices yield very little.** Often the case is effectively closed at seizure.
- **Root or vendor tooling is usually required** for file-system access.
- **Locked bootloader + current patch level** blocks most physical acquisition.
- **Timestamps can be manipulated** — corroborate across independent artifacts.
- **Consent and legal authority are prerequisites**, not formalities.

### False positives

| Observation | Innocent explanation |
|---|---|
| App installed by another app | MDM deployment, legitimate store, OEM suite, game launcher |
| Accessibility enabled | Password manager, TalkBack, automation, remote support |
| Device admin | Corporate MDM enrolment |
| Overlay permission | Chat heads, screen recorder, blue-light filter |
| Icon not in launcher | Some legitimate system/companion apps have no launcher entry |
| Rapid permission grants | A user tapping through quickly — **check the interval distribution**, not just the count |

> **🚨 Misconception:** "Accessibility was enabled, therefore the customer was compromised."
> Perhaps they use a password manager. The forensic finding is the **combination**: non-store
> installer + accessibility + permission-grant burst + capability cluster in the APK + temporal
> proximity to the fraud. Any one of those alone is a lead, not a conclusion.

### Edge cases

| Case | Handling |
|---|---|
| Multi-user / work profile | Artifacts exist per user (`users/0/`, `users/10/`) — check all |
| Factory reset after fraud | Very limited yield; cloud backups may help (separate legal basis) |
| Device already wiped by malware | Bank-side records and network telemetry become primary |
| Customer-owned device, no consent | **Stop.** Legal basis first. |
| Cloud-synced evidence | Different legal process entirely |

---

## 12. Engineering tips

1. **Acquire before remediation. Always.** Wipe-capable families exist.
2. **Keep the device AFU.** Never power it off "for transport."
3. **Isolate the network immediately** — airplane mode or Faraday.
4. **Run the high-value trio first**: `enabled_accessibility_services`,
   `enabled_notification_listeners`, `pm list packages -f -i -3`.
5. **Parse `packages.xml` hex timestamps correctly** — a very common error.
6. **Check `packages-backup.xml`** for prior state.
7. **Pull SQLite `-wal` and `-shm` siblings.**
8. **Look for the permission-grant burst** — the self-escalation signature.
9. **Scope acquisition to relevant artifacts** — DPDP data minimisation.
10. **Hash at acquisition and verify at every handoff.**
11. **Record tool versions**, or your work isn't reproducible.
12. **Involve legal counsel in workflow design**, not after the incident.

---

## 13. Judge Insights

**What judges ask:** *"How do you prove the customer didn't just authorise the transaction
themselves?"*

**Perfect answer:** Through timeline reconstruction from device artifacts, and the strongest
single piece is the permission-grant timing. `packages.xml` gives us install time and installer
attribution; `settings_secure.xml` tells us exactly when the accessibility service was enabled;
appops and the permission flags give us grant times. In a typical ODF case you see a dropper
install, then a payload installed *by that dropper* — which `packages.xml` proves via the
`installer=` field — then accessibility enabled, then three or four dangerous permissions
granted within about sixty seconds. A human navigating permission dialogs doesn't produce that
pattern; that timing signature is machine-driven self-escalation via `canPerformGestures`. Line
that up against the bank's transaction timestamp and you have a narrative a fraud committee and
a regulator can both follow — and it doesn't require any malware analysis at all, which means
it's fast.

**Common mistakes:**
- Leading with sample analysis. The bank's question is about *this device and this transaction*.
- Saying you'd "image the phone." On a modern locked FBE device that's usually not achievable,
  and under DPDP a full image of a customer's phone is disproportionate.
- Not knowing the BFU/AFU distinction.

**Follow-ups to expect:**
- *"What if the malware wiped the device?"* → It's a documented capability — BRATA and BingoMod
  both do it — which is exactly why the runbook is isolate, acquire, *then* remediate. If it
  already wiped, we fall back to bank-side session records and network telemetry.
- *"Is this admissible?"* → That depends on chain of custody and on the certification
  requirements for electronic evidence under the Bharatiya Sakshya Adhiniyam. We design the
  acquisition workflow with legal counsel rather than retrofitting it, and we hash at
  acquisition and verify at every handoff.
- *"What about the customer's privacy?"* → We use targeted collection profiles, not full images.
  Under DPDP purpose limitation and data minimisation, we collect the package registry,
  accessibility state, appops, and usage stats — not photos, messages, or health data.

**Fact that impresses:** File-Based Encryption means a phone that gets powered off drops from
AFU to BFU, and Credential Encrypted storage — essentially all app data — becomes
cryptographically inaccessible until the next unlock. So a well-meaning responder who powers a
seized device down for transport can single-handedly convert a recoverable case into an
unrecoverable one. It's the highest-consequence, most-violated rule in mobile forensics.

---

## 14. Interview Insights

**Q: "What's the first thing you do with a suspected compromised Android device?"**
Isolate the network without powering off — airplane mode or a Faraday bag — because wipe-capable
malware exists and because powering off drops you from AFU to BFU. Then document the state,
then acquire, then remediate. Sequence is the answer.

**Q: "Explain BFU vs AFU."**
Before First Unlock: only Device Encrypted storage is readable; Credential Encrypted data — the
app sandboxes — is cryptographically inaccessible. After First Unlock: CE keys are in memory and
app data is readable with root or vendor tooling. Powering off returns the device to BFU.

**Q: "Which single Android artifact would you want most?"**
`/data/system/packages.xml`. It gives install time, **installer attribution**, the signer
certificate — which survives APK deletion — and granted permissions. Runner-up:
`settings_secure.xml` for `enabled_accessibility_services`.

**Q: "How do you show the user didn't grant permissions themselves?"**
Grant-timestamp clustering. Multiple dangerous permissions granted within seconds of each other,
immediately after an accessibility service was enabled, is the signature of `canPerformGestures`
tapping the dialogs. Humans produce a different interval distribution.

**Q: "You pulled an app's SQLite database and it's empty. What did you miss?"**
The `-wal` file. Write-Ahead Logging means recent transactions live there until checkpointed.
Always pull `-wal` and `-shm` alongside the `.db`.

**Q: "Can you do a physical acquisition of a modern Android phone?"**
Usually not, on a current locked device with an up-to-date patch level, without commercial
exploit-based tooling — and often not even then. Most real casework is logical plus file-system
acquisition of a consented AFU device.

**Beginner mistakes:**
- Powering the device off.
- Uninstalling the malware before acquiring.
- Missing `-wal` files.
- Misreading `packages.xml` hex timestamps.
- Taking a full image when targeted collection is both sufficient and legally safer.

---

## 15. Cross-references

**Upstream:**
- [← Ch 05 Android Cryptography](../security/05-android-cryptography.md) — FBE, BFU/AFU
- [← Ch 09 Package Manager](../apk/09-package-manager.md) — `packages.xml`, installer attribution
- [← Ch 13 Android Malware](../malware/13-android-malware.md) — anti-removal, wipe capability

**Downstream:**
- [→ Ch 18 Mobile Threat Hunting](../soc/18-mobile-threat-hunting.md) — artifacts as hunt telemetry
- [→ Ch 19 Enterprise SOC](../soc/19-enterprise-soc-operations.md) — device telemetry at scale
- [→ Ch 20 Incident Response](../incident-response/20-incident-response.md) — the runbook this feeds
- [→ Ch 25 Investigation Engine](../sudarshan/25-investigation-engine.md) — evidence linking
- [→ Ch 29 Investigation Reports](../sudarshan/29-investigation-reports.md) — timeline as deliverable

**Related chain:** Seizure → isolation → AFU acquisition → artifact parsing → timeline →
bank correlation → liability determination → regulatory filing.

---

## 16. References

1. NIST SP 800-101 Rev. 1 — *Guidelines on Mobile Device Forensics*.
2. NIST SP 800-86 — *Guide to Integrating Forensic Techniques into Incident Response*.
3. AOSP — *File-Based Encryption*. https://source.android.com/docs/security/features/encryption/file-based
4. Android Developers — `adb` and `dumpsys` documentation. https://developer.android.com/tools/adb
5. ALEAPP — Android Logs Events And Protobuf Parser. https://github.com/abrignoni/ALEAPP
6. Autopsy / The Sleuth Kit. https://www.autopsy.com/
7. Magnet Forensics AXIOM; Cellebrite UFED; MSAB XRY — vendor documentation.
8. SQLite — Write-Ahead Logging. https://www.sqlite.org/wal.html
9. Cleafy Labs — *BRATA* (2021–2022) — factory-reset kill switch.
10. Cleafy Labs — *BingoMod* (July 31, 2024) — device wipe after fraud.
11. CERT-In — Directions of April 28, 2022 (6-hour incident reporting, log retention).
12. Reserve Bank of India — Cyber Security Framework for Banks.
13. Digital Personal Data Protection Act, 2023 (India).
14. Bharatiya Sakshya Adhiniyam, 2023 (India) — electronic evidence.
15. Information Technology Act, 2000 (India).

### Further reading
- Brigs / Alexis Brignoni — mobile forensics artifact research blog
- SANS FOR585 — Advanced Smartphone Forensics course materials
- AOSP `frameworks/base/services/core/java/com/android/server/pm/` — `packages.xml` writer

---

*Previous: [← Ch 16 Threat Intelligence](../threat-intelligence/16-threat-intelligence.md) · Next: [Ch 18 Mobile Threat Hunting →](../soc/18-mobile-threat-hunting.md)*
