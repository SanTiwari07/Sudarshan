# 36 - Glossary

> **Chapter ID:** `CH36` · **Block:** F (Reference) · **Status:** Stable
> **Tags:** `#glossary` `#terminology` `#acronyms` `#reference`
> **Last Updated:** 2026-08-05 · **Version:** 1.0.0

> Terms are defined as this knowledge base uses them, with the chapter that treats each in depth.
> **★** marks terms whose precise meaning is frequently confused - see
> [Ch 32](32-common-misconceptions.md).

---

## A

**AAB (Android App Bundle)** - Google Play's publishing format. Play generates and signs per-device
**split APKs** from it. Mandatory for new Play apps since August 2021. → [Ch 02 §7](../apk/02-apk-architecture.md#7-app-bundles-split-apks-and-why-the-apk-is-a-lie)

**aapt2** - Android Asset Packaging Tool. Compiles and links resources; also the closest thing to
Android's own parser for dumping manifests. → [Ch 08](../apk/08-apk-file-format.md)

**★ Accessibility Service** - Android API granting an app the ability to read screen content
(`canRetrieveWindowContent`) and inject input (`canPerformGestures`) across **all** apps. Exists for
assistive technology; is the hinge of essentially all Android banking malware. MITRE **T1453**.
→ [Ch 13 §3](../malware/13-android-malware.md#3-accessibility-service-abuse--the-hinge)

**AFU (After First Unlock)** - Device state in which Credential Encrypted keys are resident in
memory and app data is readable. Contrast **BFU**. Powering off a device drops it from AFU to BFU.
→ [Ch 17 §3](../digital-forensics/17-digital-forensics.md#3-bfu-vs-afu--the-variable-that-decides-everything)

**Androguard** - Python framework for APK/DEX analysis; the scriptable backbone of automated static
pipelines. → [Ch 10 §6](../reverse-engineering/10-reverse-engineering.md#6-androguard--scriptable-analysis)

**APK (Android Package)** - A ZIP archive containing an app's manifest, DEX bytecode, resources,
native libraries, and signature material. → [Ch 02](../apk/02-apk-architecture.md)

**APK Signing Block** - Container for v2/v3/v3.1 signatures, sitting between file data and the ZIP
central directory. **Not a ZIP entry.** Ends with the magic `APK Sig Block 42`.
→ [Ch 07 §4](../security/07-apk-signing.md#4-the-apk-signing-block)

**apksigner** - Android build tool for signing and verifying APKs (v1–v4). Supersedes `jarsigner`,
which only handles v1.

**apktool** - Decodes an APK to readable resources and smali, and can rebuild. Use `-s` to skip
smali for fast triage. → [Ch 10 §3](../reverse-engineering/10-reverse-engineering.md#3-apktool--resources-and-smali)

**Application ID** - Gradle's `applicationId`; the installed package identifier. **Not** the same as
the manifest `package` attribute (which sets the code namespace), and **not** an identity claim.
→ [Ch 02 §8](../apk/02-apk-architecture.md#8-package-name-vs-application-id-vs-identity)

**ART (Android Runtime)** - The managed runtime executing DEX bytecode; hybrid JIT/AOT since Android
7.0. A **Mainline module** since Android 12, updatable via Play independently of the OS version.
→ [Ch 03](../android/03-android-runtime.md)

**ATS (Automated Transfer System)** - A scripted, per-bank transfer engine running on the victim's
device via accessibility. Contrast **Hidden VNC**, which uses a live operator.
→ [Ch 14 §3](../banking-malware/14-banking-malware.md#3-ats--automated-transfer-systems)

**Attestation (Key Attestation)** - Hardware-backed X.509 chain proving a Keystore key's properties,
the device boot state, and **the calling app's signing certificate digest**.
→ [Ch 05 §5](../security/05-android-cryptography.md#5-key-attestation)

**AVB (Android Verified Boot)** - Cryptographic verification chain from hardware root of trust
through the OS, with dm-verity and rollback protection. → [Ch 04 §7](../security/04-android-security-model.md#7-verified-boot-and-the-hardware-root-of-trust)

**AXML** - Android's compiled binary XML format. `AndroidManifest.xml` and compiled layouts use it;
`cat` produces garbage. → [Ch 08 §4](../apk/08-apk-file-format.md#4-binary-xml-axml)

---

## B

**BFU (Before First Unlock)** - Device state in which only Device Encrypted storage is readable;
app data is cryptographically inaccessible. → [Ch 17 §3](../digital-forensics/17-digital-forensics.md#3-bfu-vs-afu--the-variable-that-decides-everything)

**Binder** - Android's primary IPC mechanism, implemented as a kernel driver. Supplies unspoofable
caller UID via `Binder.getCallingUid()`, which is the foundation of permission enforcement.
→ [Ch 01 §6](../android/01-android-internals.md#6-binder-ipc)

---

## C

**★ Certificate (signing certificate)** - Self-signed X.509 binding a public key to a self-asserted
Subject. Its **fingerprint** is the app's identity; its Subject text is unverified and must never be
used for attribution. → [Ch 06](../security/06-certificates.md)

**CE (Credential Encrypted) storage** - File-Based Encryption class available only after first
unlock. Holds essentially all app data.

**Cluster gate** - SUDARSHAN's rule that no single capability signal can produce a high score; a
core accessibility capability plus ≥2 supporting capabilities is required.
→ [Ch 27 §5](../sudarshan/27-risk-scoring.md#5-cluster-gating)

**Confidence ceiling** - A cap on verdict confidence imposed by analysis quality (packed and
un-unpacked, C2 unreachable, decompilation failed). Caps confidence, **never** lowers severity.
→ [Ch 27 §6](../sudarshan/27-risk-scoring.md#6-the-confidence-ceiling)

**Concept drift** - Degradation of a trained model as the threat and benign populations evolve. The
defining failure mode of ML for Android malware. → [Ch 21 §4](../ai-malware-analysis/21-ai-assisted-malware-analysis.md#4-concept-drift--the-defining-failure-mode)

**Conscrypt** - Android's TLS provider; a **Mainline module**, so TLS behaviour can differ between
devices reporting the same OS version.

---

## D

**DaaS (Dropper-as-a-Service)** - Criminal service binding a payload to a decoy app. **Zombinder** is
the best-known; it has delivered Octo2, Chameleon, and Hook - three different payload families.
→ [Ch 15 §8](../malware/15-malware-infrastructure.md#8-dropper-as-a-service-and-zombinder)

**DE (Device Encrypted) storage** - FBE class available at boot, before unlock. Enables Direct Boot.

**Detection-as-code** - Managing detection rules like software: version control, tests, review,
backtesting, ownership, and review cadence. → [Ch 19 §7](../soc/19-enterprise-soc-operations.md#7-detection-engineering)

**DEX (Dalvik Executable)** - Android's bytecode format. Register-based (unlike the stack-based JVM).
Header is 0x70 bytes with an Adler-32 checksum and SHA-1 signature. → [Ch 08 §6](../apk/08-apk-file-format.md#6-dex-format)

**dex2oat** - ART's ahead-of-time compiler, producing `.oat`, `.vdex`, and `.art` artifacts.

**DGA (Domain Generation Algorithm)** - Algorithmic C2 domain generation for resilience. Reversing
one enables *predictive* blocking. Octo2 introduced one in September 2024.
→ [Ch 15 §5](../malware/15-malware-infrastructure.md#5-resilience-techniques)

**Dropper** - An app that is genuinely clean at review time and later installs the real payload.
Defeats point-in-time review rather than evading it. → [Ch 09 §7](../apk/09-package-manager.md#7-droppers-the-technique-in-full)

**DTO (Device Takeover)** - See **ODF**.

---

## E–F

**Evidence ledger** - Immutable, append-only record binding every finding to an artifact pointer
(file and line, or log offset and timestamp). → [Ch 25 §4](../sudarshan/25-investigation-engine.md#4-the-evidence-ledger)

**FBE (File-Based Encryption)** - Per-file encryption with CE and DE classes; required from Android
10. Enables Direct Boot and creates the BFU/AFU distinction.

**FLAG_SECURE** - Window flag preventing screenshots and screen capture of a sensitive screen. An
**opt-in** control the *bank* must implement.

**Frida** - Dynamic instrumentation toolkit. `frida-server` (rooted) or `frida-gadget` (injected).
The class-loader hook is the highest-yield technique in Android malware analysis.
→ [Ch 12 §4](../dynamic-analysis/12-dynamic-analysis.md#4-frida)

---

## H–J

**Hard-negative corpus** - Deliberately difficult benign samples used for calibration: password
managers, remote-support apps, MDM agents, and **the client bank's own production app**.
→ [Ch 27 §10](../sudarshan/27-risk-scoring.md#10-the-hard-negative-corpus)

**★ Hash** - Digest of exact file bytes. Identifies **an artifact**, not an app. Changes on any byte
change; Play split APKs give one app version many hashes.

**Hidden VNC** - Remote screen viewing plus input injection, giving a live operator control of the
victim's device. Vultur (2021) pioneered it as an alternative to overlays.
→ [Ch 13 §6](../malware/13-android-malware.md#6-screen-capture-and-hidden-vnc)

**InMemoryDexClassLoader** - API 26+ class loader accepting a `ByteBuffer`, so a payload can go
network → decrypt → execute with **no disk artifact**. Hook **both** overloads.
→ [Ch 03 §5](../android/03-android-runtime.md#5-class-loading)

**Installer attribution** - The package that initiated an install, exposed via `pm list packages -i`
and `getInstallSourceInfo()`. One of the most under-used signals in mobile security.
→ [Ch 09 §5](../apk/09-package-manager.md#5-installer-attribution--the-underused-signal)

**IOC (Indicator of Compromise)** - An observable used to recognise a threat. Must carry type,
confidence, severity, source, TTL, and **action class**. → [Ch 26](../sudarshan/26-ioc-extraction.md)

**jadx** - DEX-to-Java decompiler; the primary reading tool. When its output looks impossible,
switch to the smali view - smali is ground truth.

**Janus (CVE-2017-13156)** - Attack exploiting a file being simultaneously a valid ZIP and a valid
DEX. Affected Android 5.0–8.0, **v1-only** APKs; patched December 2017; structurally impossible
under v2. → [Ch 07 §9](../security/07-apk-signing.md#9-the-three-classic-attacks)

**JNI_OnLoad** - First JNI entry point when a native library loads; where packers unpack. Note
`.init_array` constructors run **before** it.

---

## K–M

**Keystore (Android Keystore)** - System service generating and storing keys such that key material
is never exposed to the app. Protects against **extraction**, not **use**.
→ [Ch 05 §3](../security/05-android-cryptography.md#3-android-keystore)

**Mainline module** - A system component updatable via Google Play independently of the OS. ART and
Conscrypt are Mainline - record their versions or dynamic analysis isn't reproducible.

**MaaS (Malware-as-a-Service)** - Rental model where a developer sells builder and panel access to
affiliates. Detection consequence: shared code, **divergent signers and infrastructure**.
→ [Ch 15 §7](../malware/15-malware-infrastructure.md#7-malware-as-a-service)

**MASVS / MASTG** - OWASP Mobile Application Security Verification Standard (v2.1.0, January 2024;
8 categories, 24 controls) and its Testing Guide.

**MediaProjection** - Screen-capture API. Since Android 14, requires
`android:foregroundServiceType="mediaProjection"` - which makes it a static signal.

**MITRE ATT&CK for Mobile** - Catalogue of adversary tactics and techniques. Key IDs: **T1453**
(accessibility abuse), T1417.001/.002, T1516, T1513, T1517, T1636.004, T1638, T1626.001,
**T1629.001**, T1624. → [Ch 16 §3](../threat-intelligence/16-threat-intelligence.md#3-mitre-attck-for-mobile)

**MobSF** - Open-source mobile security framework. Measures **security hygiene, not maliciousness** - its score must not be read as a malware verdict. → [Ch 11 §8](../static-analysis/11-static-analysis.md#8-mobsf)

**MTD (Mobile Threat Defence)** - On-device detection for **managed** devices. Cannot reach a bank's
customer population. → [Ch 19 §5](../soc/19-enterprise-soc-operations.md#5-mobile-specific-tooling-mtd-mdm-uem)

**Mule chain** - Tiered network of accounts through which stolen funds are dispersed, typically
within minutes under real-time rails. → [Ch 15 §10](../malware/15-malware-infrastructure.md#10-the-money-side-mule-chains)

**MUTF-8 (Modified UTF-8)** - DEX string encoding; null as `0xC0 0x80`, supplementary characters as
surrogate pairs. Standard UTF-8 decoders corrupt both cases.

---

## N–P

**Notification Listener** - `NotificationListenerService`; reads the content of every notification.
Functionally equivalent to SMS-read for OTP theft and far less scrutinised - **weight it
comparably**.

**★ ODF (On-Device Fraud)** - Fraud initiated from the victim's own device inside their own
authenticated session. Device fingerprinting, geolocation, and integrity attestation all pass.
→ [Ch 14 §2](../banking-malware/14-banking-malware.md#2-on-device-fraud-and-device-takeover)

**Overlay attack** - A window drawn over another app, styled to look like its real UI, harvesting
input. `TYPE_APPLICATION_OVERLAY` is type **2038**. Distinct from **tapjacking** (which deceives
touch) and **task hijacking** (which deceives navigation).

**★ Package name** - The `package` attribute; a **string anyone can type**. A campaign attribute,
never an identity.

**PackageInstaller / Session API** - Modern install API required for split APKs. Android 15 uses it
as the proxy for "a real app store" when gating accessibility - which droppers exploit by adopting
it. → [Ch 09 §4](../apk/09-package-manager.md#4-session-based-installs)

**packages.xml** - `/data/system/packages.xml`; the richest Android forensic artifact - installer
attribution, install timestamps, **signer certificate**, and granted permissions. Survives APK
deletion. → [Ch 17 §5](../digital-forensics/17-digital-forensics.md#5-the-artifact-map)

**Play Integrity API** - Google's device/app/account integrity verdicts. Replaced SafetyNet
Attestation (**shut down January 31, 2025**). **Must be verified server-side.** Blind to
third-party-app behaviour. → [Ch 04 §9](../security/04-android-security-model.md#9-play-integrity-api)

**Pyramid of Pain** - Bianco's model ranking indicators by adversary cost: hashes (minutes) → IPs
(hours) → domains (days) → artifacts (weeks) → tools → **TTPs (months)**.
→ [Ch 16 §7](../threat-intelligence/16-threat-intelligence.md#7-the-pyramid-of-pain)

---

## R–S

**RASP (Runtime Application Self-Protection)** - In-app hardening: root/emulator detection,
anti-debug, anti-hooking, integrity checks. **Standard in banking apps** - never a malware
indicator.

**Recursion (artifact recursion)** - SUDARSHAN principle **P6**: dumped or installed child artifacts
re-enter the full pipeline, and their verdicts propagate **upward** to the parent.
→ [Ch 25 §3](../sudarshan/25-investigation-engine.md#3-recursion)

**Restricted Settings** - Android 13+ mechanism blocking accessibility and notification-listener
toggles for apps installed outside a store-like flow; extended in Android 15 to key on the
**session install API**.

**Retro-hunt** - Replaying new rules across the historical corpus, recomputing verdicts, and
notifying original submitters when a verdict changes. Makes verdicts **provisional, not final**.
→ [Ch 18 §6](../soc/18-mobile-threat-hunting.md#6-hunting-the-sample-corpus)

**Safe Mode** - Boot mode disabling all third-party apps and their accessibility services. Defeats
uninstall interception, overlay obstruction, and watchdog pairs in one step. The key remediation
step. → [Ch 20 §10](../incident-response/20-incident-response.md#10-the-device-remediation-runbook)

**SELinux** - Mandatory Access Control on Android, fully enforcing since Android 5.0. Even root
cannot violate policy. Per-app MLS categories isolate `untrusted_app` processes from each other.

**★ Signature (APK)** - Cryptographic proof that the APK's bytes were not modified after signing.
New with every build. Distinct from the **certificate** (who signed) and the **hash** (which file).

**Signer fingerprint** - SHA-256 of the DER-encoded signing certificate. **SUDARSHAN's primary
identity key** and the most durable correlation pivot.

**Sinkhole** - Malicious infrastructure taken over by researchers or law enforcement. A hit
indicates a **previously infected device beaconing**, not an active adversary connection - it
inverts the meaning of the indicator. → [Ch 26 §7](../sudarshan/26-ioc-extraction.md#7-sinkholes-and-re-registration)

**smali / baksmali** - Assembler and disassembler for DEX bytecode. Register-based: `v` locals, `p`
parameters, `p0` is `this`.

**Sweep** - Searching the customer base and corpus for the same signer, package, or code cluster.
Converts a single-sample incident into estate-wide containment.
→ [Ch 25 §7](../sudarshan/25-investigation-engine.md#7-the-sweep)

---

## T–Z

**Tapjacking** - Deceiving *touch*: an overlay absorbs or passes through taps so the user activates
something invisible. Distinct from overlay phishing, which deceives *display*.

**Task hijacking (StrandHogg)** - Abusing `taskAffinity`/`launchMode` so a malicious activity
inserts itself into another app's task, deceiving *navigation*.

**targetSdkVersion** - Declares which behaviour changes an app opts into. Android 14 blocks
installing apps targeting below API 23; Android 15 raised the floor to API 24; Android 16 did not
raise it further.

**TEE (Trusted Execution Environment)** - Secure mode of the main SoC (ARM TrustZone) hosting
Keystore operations. Contrast **StrongBox**, a discrete physical security chip (API 28+).

**TLSH (Trend Micro Locality Sensitive Hash)** - Fuzzy hash producing a numeric distance. Hash the
**DEX**, not the whole APK - whole-APK hashes are dominated by resources that vary per campaign.
Distance < 50 ≈ same family.

**TOFU (Trust On First Use)** - Android's app-identity model: the signer recorded at first install
must match on every update, or installation fails with
`INSTALL_FAILED_UPDATE_INCOMPATIBLE`. Verifies *sameness*, not trustworthiness.
→ [Ch 06 §4](../security/06-certificates.md#4-trust-on-first-use--androids-actual-model)

**TLP (Traffic Light Protocol)** - Sharing classification: RED (named recipients), AMBER (+STRICT),
GREEN (community), CLEAR (public). Bank-derived indicators are typically AMBER+STRICT.

**TTP (Tactics, Techniques, Procedures)** - Adversary behaviour patterns. The **top** of the Pyramid
of Pain and where SUDARSHAN deliberately weights detection.

**vdex** - ART artifact containing verified DEX. **DEX can be extracted from it**, which makes it a
recovery route when the APK is unavailable.

**Zip-Slip** - Archive path-traversal (`../` in an entry name) that writes outside the extraction
directory. In this context, plausibly an attack aimed at the analysis platform itself.
→ [Ch 24 §4](../sudarshan/24-threat-intake.md#4-safe-extraction)

**Zombinder** - Dropper-as-a-Service binding payloads to decoy apps; documented delivering **Octo2,
Chameleon, and Hook**. Because one service serves multiple actors, shared delivery infrastructure
must **link, not merge**, campaign clusters.

**Zygote** - The preloaded process forked to create every app process. UID assignment, SELinux
domain transition, and seccomp filter installation all occur post-fork, before any app code runs.
→ [Ch 01 §4](../android/01-android-internals.md#4-zygote-the-process-factory)

---

## Acronym quick index

| | | | |
|---|---|---|---|
| **AAB** App Bundle | **AFU** After First Unlock | **API** Application Programming Interface / API level | **APK** Android Package |
| **ART** Android Runtime | **ATS** Automated Transfer System | **AVB** Android Verified Boot | **AXML** Android binary XML |
| **BFU** Before First Unlock | **C2** Command and Control | **CE** Credential Encrypted | **DaaS** Dropper-as-a-Service |
| **DE** Device Encrypted | **DEX** Dalvik Executable | **DGA** Domain Generation Algorithm | **DPDP** Digital Personal Data Protection Act |
| **DTO** Device Takeover | **FBE** File-Based Encryption | **FGS** Foreground Service | **IOC** Indicator of Compromise |
| **JNI** Java Native Interface | **MaaS** Malware-as-a-Service | **MASVS** Mobile App Security Verification Standard | **MDM** Mobile Device Management |
| **MTD** Mobile Threat Defence | **ODF** On-Device Fraud | **RASP** Runtime App Self-Protection | **RLS** Row-Level Security |
| **SPKI** Subject Public Key Info | **STIX** Structured Threat Information eXpression | **TEE** Trusted Execution Environment | **TLP** Traffic Light Protocol |
| **TLSH** Trend Micro Locality Sensitive Hash | **TOFU** Trust On First Use | **TTP** Tactics, Techniques, Procedures | **UPI** Unified Payments Interface |

---

*Previous: [← Ch 35 Interview Preparation](35-interview-preparation.md) · Next: [Ch 37 References →](37-references.md)*
