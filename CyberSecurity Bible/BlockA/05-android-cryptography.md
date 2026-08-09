# 05 - Android Cryptography

> **Chapter ID:** `CH05` · **Block:** A (Foundations) · **Status:** Stable
> **Tags:** `#cryptography` `#keystore` `#strongbox` `#tee` `#key-attestation` `#pinning` `#crypto-misuse`
> **Last Updated:** 2026-08-05 · **Version:** 1.0.0
> **Prerequisites:** [Ch 04](04-android-security-model.md)

---

## Table of Contents

1. [Why crypto is two chapters, not one](#1-why-crypto-is-two-chapters-not-one)
2. [The Android crypto stack](#2-the-android-crypto-stack)
3. [Android Keystore](#3-android-keystore)
4. [TEE and StrongBox](#4-tee-and-strongbox)
5. [Key attestation](#5-key-attestation)
6. [Disk encryption: FDE → FBE](#6-disk-encryption-fde--fbe)
7. [TLS, pinning, and the trust store](#7-tls-pinning-and-the-trust-store)
8. [Crypto misuse - what you will actually find](#8-crypto-misuse--what-you-will-actually-find)
9. [How malware uses cryptography](#9-how-malware-uses-cryptography)
10. [Detection logic for SUDARSHAN](#10-detection-logic-for-sudarshan)
11. [Limitations, edge cases, false positives](#11-limitations-edge-cases-false-positives)
12. [Engineering tips](#12-engineering-tips)
13. [Judge Insights](#13-judge-insights)
14. [Interview Insights](#14-interview-insights)
15. [Cross-references](#15-cross-references)
16. [References](#16-references)

---

## 1. Why crypto is two chapters, not one

Cryptography shows up twice in this knowledge base and the split confuses people, so let's
be explicit:

| Chapter | Question it answers |
|---|---|
| **05 (this one)** | How do *apps* use cryptography, how does the platform protect keys, and how does malware abuse crypto? |
| **[06 Certificates](06-certificates.md)** | What is an X.509 certificate and how does Android use it as **identity**? |
| **[07 APK Signing](07-apk-signing.md)** | How is that identity **bound to an APK**, and what attacks broke that binding? |

This chapter is the app-and-platform view. The next two are the package-identity view.

---

## 2. The Android crypto stack

```
┌────────────────────────────────────────────────────────────┐
│  App code:  Cipher · MessageDigest · Mac · KeyGenerator    │
│             SecretKeyFactory · SecureRandom · SSLContext   │
├────────────────────────────────────────────────────────────┤
│  JCA providers (java.security.Provider)                    │
│    AndroidKeyStore  ← keys never leave secure hardware     │
│    AndroidOpenSSL / Conscrypt  ← software crypto + TLS     │
├────────────────────────────────────────────────────────────┤
│  Conscrypt (Mainline module - updatable via Play)          │
│  BoringSSL                                                 │
├────────────────────────────────────────────────────────────┤
│  Keymaster / KeyMint HAL                                   │
├────────────────────────────────────────────────────────────┤
│  TEE (TrustZone) · StrongBox (discrete secure element)     │
└────────────────────────────────────────────────────────────┘
```

Two things worth knowing:

- **Conscrypt is a Mainline module.** TLS behaviour and cipher-suite support can be updated
  through Google Play system updates without an OS upgrade. Same reproducibility caveat as
  ART in [Ch 03](../android/03-android-runtime.md): record module versions in your analysis
  environment metadata.
- **Bouncy Castle is bundled but crippled.** Android ships a trimmed Bouncy Castle. Apps
  frequently bundle **Spongy Castle** or a full BC to get algorithms Android's copy lacks.
  Seeing a bundled BC/SC in an APK is normal, not suspicious - but it does tell you the app
  is doing non-trivial crypto, which is worth a look.

---

## 3. Android Keystore

### WHAT

A system service that generates and stores cryptographic keys such that **the key material
is never exposed to the app process**. The app gets a *handle*. Operations (`sign`,
`decrypt`) are performed by the system - and, on capable hardware, inside the TEE.

### WHY it exists

Before Keystore, an app's secret key was a byte array in the app's heap. Any memory
disclosure, any heap dump, any root compromise, and the key was gone forever. Keystore's
promise: even a fully compromised app process cannot **extract** the key. It can *use* the
key while it's running, but it cannot steal it.

That distinction - **use vs. extract** - is the entire security value, and it's also the
limitation. Remember it for §13.

### HOW

```java
KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
        "bank_signing_key",
        KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
    .setDigests(KeyProperties.DIGEST_SHA256)
    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
    .setUserAuthenticationRequired(true)                 // ① biometric/PIN gate
    .setUserAuthenticationParameters(30, KeyProperties.AUTH_BIOMETRIC_STRONG)
    .setInvalidatedByBiometricEnrollment(true)           // ② new fingerprint → key dies
    .setIsStrongBoxBacked(true)                          // ③ discrete SE if available
    .setAttestationChallenge(serverNonce)                // ④ prove it to the server
    .build();

KeyPairGenerator kpg = KeyPairGenerator.getInstance(
        KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
kpg.initialize(spec);
KeyPair kp = kpg.generateKeyPair();
```

| # | Property | Why a bank app should set it |
|---|---|---|
| ① | `setUserAuthenticationRequired(true)` | Key usable only after biometric/PIN auth. **This is the single most important control against Accessibility-driven fraud** - see below. |
| ② | `setInvalidatedByBiometricEnrollment(true)` | If an attacker enrols their own fingerprint, the key is destroyed rather than reused |
| ③ | `setIsStrongBoxBacked(true)` | Discrete secure element, resistant to physical and side-channel attack |
| ④ | `setAttestationChallenge(...)` | Server can cryptographically verify key properties (§5) |

> **🏛️ Enterprise Insight - the control that actually helps:** A key bound with
> `setUserAuthenticationRequired(true)` and a **short** `setUserAuthenticationValidityDuration`
> (or, better, per-operation auth) forces a fresh biometric prompt at transaction time. An
> Accessibility-driven attacker can tap buttons and read the screen, but **cannot present a
> fingerprint.** This is one of the few platform primitives that meaningfully raises the cost
> of On-Device Fraud.
>
> **The caveat that matters:** ThreatFabric documented **Chameleon** (December 2023)
> defeating this by using accessibility to **force a fallback from biometric to PIN**, then
> capturing the PIN via keylogging and replaying it. So: require *strong* biometric class,
> avoid silent PIN fallback for high-value transactions, and treat a biometric→PIN downgrade
> as a fraud signal. → [Ch 14](../banking-malware/14-banking-malware.md)

### Key material, and where it lives

| Backing | Where the key is | Extractable by root? |
|---|---|---|
| Software-only keystore (very old / emulated) | Encrypted blob in `/data/misc/keystore` | Potentially yes |
| **TEE-backed** | Inside TrustZone; only a wrapped blob is stored | No |
| **StrongBox** | Inside a discrete secure element | No |

```bash
# Is a device StrongBox-capable?
$ adb shell pm list features | grep -i strongbox
feature:android.hardware.strongbox_keystore
```

---

## 4. TEE and StrongBox

### TEE (Trusted Execution Environment)

A secure world running alongside the normal OS on the same application processor, isolated
by ARM **TrustZone**. Runs a small trusted OS (Trusty, QSEE, Kinibi). Handles Keystore
operations, biometric template matching, DRM, and Verified Boot state.

**Threat model it covers:** a fully compromised Android OS - including root - cannot read
TEE-held key material.
**Threat model it does not cover:** vulnerabilities *in* the TEE itself. Trustlet
vulnerabilities have been repeatedly found and published (notably by Project Zero and
various academic teams), and a TEE compromise is catastrophic because it undermines
everything above it.

### StrongBox

Introduced in **Android 9 (API 28)**. A *separate physical* security chip (its own CPU, RAM,
and secure storage) with tamper resistance and side-channel countermeasures - think embedded
secure element rather than a secure mode of the main CPU. Titan M / Titan M2 in Pixels are
the best-known examples.

| | TEE | StrongBox |
|---|---|---|
| Hardware | Secure mode of the main SoC | Discrete chip |
| Isolation | Logical (TrustZone) | Physical |
| Side-channel resistance | Limited | Designed for it |
| Availability | Nearly universal | Flagship-tier, not guaranteed |
| Performance | Faster | Slower (constrained chip) |

> **⚙️ Engineering Note:** `setIsStrongBoxBacked(true)` throws
> `StrongBoxUnavailableException` on devices without it. **Always catch it and fall back to
> TEE.** A surprising number of production banking apps crash on mid-range devices because
> they didn't. It's a good thing to check for in an app security review.

---

## 5. Key attestation

### WHAT

The device produces an **X.509 certificate chain** for a Keystore key, chaining up to a
Google-owned root, where the leaf certificate contains an extension describing the key's
properties and the device's state.

```
  Google Hardware Attestation Root
            │
            ▼
     Intermediate(s)
            │
            ▼
   Device attestation certificate
            │
            ▼
   Leaf: YOUR key's certificate
         └── attestation extension:
               • security level: SOFTWARE / TRUSTED_ENVIRONMENT / STRONGBOX
               • verified boot state (GREEN/YELLOW/ORANGE) + boot key hash
               • OS version and patch level
               • whether user auth is required, and which auth type
               • the challenge you supplied (anti-replay)
               • the attesting app's package name and SIGNING CERT DIGEST ★
```

### WHY it's powerful

Because the server can verify **cryptographically, not by asking the client**, that:

- The key genuinely lives in hardware (`TRUSTED_ENVIRONMENT` or `STRONGBOX`).
- The device booted with a locked bootloader and verified boot GREEN.
- The key requires user authentication.
- **The app requesting it has a specific signing certificate.**

That last line matters enormously and links directly to [Ch 06](06-certificates.md): the
attestation record binds the key to the **signer identity** of the app, not to its package
name. A repackaged clone of a banking app cannot produce an attestation naming the genuine
bank's signing certificate.

### Attestation vs Play Integrity - don't confuse them

| | Key Attestation | Play Integrity API |
|---|---|---|
| Provided by | Device hardware + Google PKI | Google Play Services (DroidGuard) |
| Answers | "Is this *key* hardware-backed, and what is the device/app state?" | "Is this device/app/account genuine per Google?" |
| Needs Play Services | No | **Yes** |
| Offline | Possible (chain verification) | No |
| Best for | Binding a credential to a device | Anti-abuse, anti-emulator, licensing |

Banks typically want **both**: attestation to bind the customer credential to real hardware,
Play Integrity to catch modified apps and emulator farms.

> **🚨 Misconception:** "Key attestation proves the device isn't infected." No. It proves the
> key is hardware-backed and the boot state is clean. A stock, GREEN-boot, StrongBox-equipped
> device running Anatsa passes attestation perfectly. Attestation answers a device-integrity
> question; banking malware is a *third-party-app-behaviour* problem. Same limitation as
> Play Integrity in [Ch 04 §9](04-android-security-model.md#9-play-integrity-api).

---

## 6. Disk encryption: FDE → FBE

| Model | Android | How it works |
|---|---|---|
| **FDE** (Full Disk Encryption) | 5.0–9, deprecated | One key for the whole userdata partition; nothing accessible until first unlock |
| **FBE** (File-Based Encryption) | 7.0+, **required from Android 10** | Per-file keys in two classes: **Credential Encrypted (CE)** - available only after first unlock; **Device Encrypted (DE)** - available at boot |

FBE enables **Direct Boot**: alarms, calls, and accessibility services can work before the
user unlocks, because DE storage is available.

### Forensic consequence

| Device state | What's readable |
|---|---|
| **BFU** (Before First Unlock) | DE storage only. CE data is cryptographically inaccessible. |
| **AFU** (After First Unlock) | CE keys are in memory; with root, app data is readable |

> **⚙️ Engineering Note:** BFU vs AFU is the **single most important variable in mobile
> forensic acquisition**. If a seized device is powered on and unlocked at least once, keep
> it that way - powering it off drops it to BFU and can render the evidence unrecoverable
> without vendor tooling. This belongs on the first page of any device-seizure runbook.
> → [Ch 17](../digital-forensics/17-digital-forensics.md)

> **🚨 Misconception:** "The data is encrypted so malware can't read it." Encryption is at
> rest. On a running, unlocked device, the app's own data is transparently decrypted for it
> - and screen content is plaintext by definition. FBE protects against device theft, not
> against a live Accessibility Service.

---

## 7. TLS, pinning, and the trust store

### The Android 7 change that shapes all analysis

**From Android 7.0 (API 24), apps do not trust user-installed CA certificates by default.**
Only the system trust store is used unless the app explicitly opts in via
`network_security_config`.

This is why MITM-ing an app is harder than it used to be, and why every mobile analysis
tutorial has a section on it.

```xml
<!-- res/xml/network_security_config.xml -->
<network-security-config>
    <!-- Debug-only: trust user CAs. NEVER ship this in release. -->
    <debug-overrides>
        <trust-anchors>
            <certificates src="user"/>
        </trust-anchors>
    </debug-overrides>

    <domain-config cleartextTrafficPermitted="false">
        <domain includeSubdomains="true">api.bank.example</domain>
        <pin-set expiration="2027-01-01">
            <pin digest="SHA-256">AAAA...=</pin>   <!-- leaf/intermediate SPKI -->
            <pin digest="SHA-256">BBBB...=</pin>   <!-- BACKUP pin, mandatory -->
        </pin-set>
    </domain-config>
</network-security-config>
```

### Certificate pinning

**WHAT:** the app refuses connections unless the server's certificate (or its public key)
matches a pinned value, ignoring the OS trust store.

**WHY:** defends against a rogue or compromised CA, and against an attacker who convinced
the user to install a CA.

**Approaches:** declarative `network_security_config` `<pin-set>` (recommended - Google
verifies it, and it's harder to accidentally break), OkHttp `CertificatePinner`, or a custom
`TrustManager` (most error-prone).

> **⚙️ Engineering Note:** **Always ship a backup pin** and set an expiration. Pinning to a
> single leaf certificate with no backup is how apps brick themselves at certificate
> renewal - this has taken real banking apps offline. Pin the **SPKI (public key)**, not the
> certificate, so renewal with the same key doesn't break clients.

### Pinning from the analyst's side

Pinning blocks your traffic interception. In an **authorised lab**, standard approaches:
patch the `network_security_config` and re-sign the APK, or hook the trust-manager path at
runtime with Frida/objection. Full treatment, with the caveat that this is
lab-and-authorised-testing-only, in [Ch 12](../dynamic-analysis/12-dynamic-analysis.md).

The important conceptual point for this chapter: **pinning is a resilience control
(OWASP MASVS-RESILIENCE / MASVS-NETWORK), not an authentication control.** It raises the
cost of interception. It does not stop a device-resident attacker who reads the plaintext
before it ever reaches TLS - which is precisely what Accessibility-based malware does. This
is why "we pin our certificates" is not an answer to banking-trojan fraud.

---

## 8. Crypto misuse - what you will actually find

When SUDARSHAN analyses a *legitimate* banking app (a common enterprise use case: vetting
your own and your vendors' apps), these are the findings that actually appear. They map to
**OWASP MASVS-CRYPTO** and the MASTG test cases.

| Finding | Why it's wrong | Detection |
|---|---|---|
| **`AES/ECB/*`** | ECB leaks plaintext structure - identical blocks encrypt identically | String `"AES/ECB"` or `Cipher.getInstance("AES")` (ECB is the default!) |
| **Hardcoded keys / IVs** | Key in the APK = no key | Byte arrays / strings feeding `SecretKeySpec` / `IvParameterSpec` |
| **Static IV with CBC** | Destroys semantic security | Constant `IvParameterSpec` |
| **`ECB` by omission** | `Cipher.getInstance("AES")` silently means `AES/ECB/PKCS5Padding` | Look for the bare algorithm string |
| **MD5 / SHA-1 for security** | Collision-broken | `MessageDigest.getInstance("MD5")` in an auth/integrity path |
| **`new Random()` for secrets** | Not cryptographically secure; predictable | `java.util.Random` instead of `SecureRandom` |
| **`SecureRandom.setSeed()`** | Can reduce entropy | Explicit seeding |
| **Custom crypto** | Always wrong | XOR loops, home-rolled "encryption" |
| **Key derived from device ID** | IMEI/ANDROID_ID are not secrets | Key material from `Settings.Secure.ANDROID_ID` |
| **Password → key without KDF** | No PBKDF2/scrypt/Argon2 = trivially brute-forced | `SecretKeySpec(password.getBytes(), "AES")` |
| **Trust-all `TrustManager`** | Disables TLS verification entirely | Empty `checkServerTrusted()` |
| **`setHostnameVerifier(ALLOW_ALL)`** | Accepts any hostname | Literal constant |

> **⚙️ Engineering Note - the most common real finding:** `Cipher.getInstance("AES")` with
> no mode specified. Developers assume a sane default. The JCA default on Android is
> **ECB**. This appears in production financial apps with depressing regularity. Grep for it
> in every app review; it's a one-line finding with a one-line fix (`AES/GCM/NoPadding`).

```bash
# quick crypto-misuse sweep after apktool
$ grep -rn "AES/ECB\|getInstance(\"AES\")\|MD5\|SHA-1\|java/util/Random\|ALLOW_ALL" work/smali*/ | head -40
```

---

## 9. How malware uses cryptography

Malware is a *heavy* crypto user - not to protect users, but to protect itself.

### The four uses

**1. String encryption (anti-static-analysis).**
C2 URLs, target package lists, and API names are stored encrypted and decrypted at runtime.
Anatsa has been documented performing **runtime DES decryption** of its strings (vendor
analyses, 2024–2025). This is why grepping an APK for `http` often yields nothing while the
sample clearly talks to a C2.

**2. Payload encryption (anti-detection).**
The stage-2 DEX in `assets/` is AES-encrypted, decrypted in memory, then handed to
`InMemoryDexClassLoader` ([Ch 03 §6](../android/03-android-runtime.md#6-dynamic-code-loading--the-technique-that-breaks-static-analysis)).
Signature-based detection sees only high-entropy data.

**3. C2 channel encryption (anti-network-detection).**
Documented, family-specific examples:

| Family | C2 crypto | Source |
|---|---|---|
| **ERMAC** (3.0 leak) | **AES-CBC** | Hunt.io, Aug 2025 (open directory at `141.164.62[.]236:443`) |
| **ToxicPanda** | **AES-ECB**, hardcoded domains `dksu[.]top`, `mixcom[.]one` | Cleafy, Oct 2024 |
| **Klopatra** | Base64-encoded JSON payloads over C2; overlay HTML fetched from C2 | Cleafy, Aug 2025 |
| **Antidot** | WebSocket (socket.io) C2 at `46[.]228.205.159:5055` | Cyble, May 2024 |

> **⚙️ Engineering Note:** **AES-ECB in malware is a gift.** ECB is deterministic, so
> identical plaintext blocks produce identical ciphertext blocks - you can fingerprint
> traffic and sometimes recover structure without the key. When you see ECB in a C2 protocol,
> that's a strong, cheap network-detection opportunity (and a nice detail to mention to
> judges, because it shows you understand *why* the mode choice matters, not just that it's
> "insecure").

**4. Attacking the victim's crypto.**
Crocodilus (ThreatFabric, March 2025) includes a **crypto-wallet seed-phrase parser** - using accessibility to read seed phrases off the screen during wallet setup or recovery.
No cryptanalysis needed; it reads the secret as the user views it. A perfect illustration
that strong cryptography is irrelevant when the endpoint is owned.

### Analyst workflow: recovering encrypted strings

Static decryption is possible but slow (find the routine, reimplement it). The reliable
path is dynamic:

```javascript
// Frida - log every Cipher operation and its plaintext
Java.perform(function () {
  var Cipher = Java.use('javax.crypto.Cipher');
  Cipher.doFinal.overload('[B').implementation = function (input) {
    var out = this.doFinal(input);
    console.log('[crypto] alg=' + this.getAlgorithm() +
                ' in=' + input.length + ' out=' + out.length);
    try { console.log('  plaintext: ' + Java.use('java.lang.String').$new(out)); }
    catch (e) {}
    return out;
  };

  // Catch hardcoded keys at construction
  var SKS = Java.use('javax.crypto.spec.SecretKeySpec');
  SKS.$init.overload('[B', 'java.lang.String').implementation = function (k, a) {
    console.log('[key] alg=' + a + ' key=' + bytesToHex(k));
    return this.$init(k, a);
  };
});
```

This one script routinely yields the C2 URL, the AES key, and the overlay target list from
samples where static analysis produced nothing. Combine with a post-C2 heap dump
([Ch 03 §10](../android/03-android-runtime.md#10-garbage-collection-and-memory-briefly-and-why-you-care)).

---

## 10. Detection logic for SUDARSHAN

### For malware analysis

| Signal | Weight | Notes |
|---|---|---|
| Crypto routine output feeding a **class loader** | **Very High** | The packed-payload pattern |
| Crypto output feeding `Class.forName` / `getMethod` | **High** | Encrypted reflection targets |
| High-entropy blobs in `assets/` + AES usage in code | **High** | Stage-2 payload |
| **AES-ECB** in a network path | Medium | Weak crypto + fingerprintable traffic |
| Hardcoded key material | Medium | Extract it - it becomes an **IOC and a correlation key** |
| Custom/rolled crypto | Medium | Unusual outside malware and bad apps |
| Base64 + XOR string obfuscation | Low-Medium | Very common; note but don't over-weight |

> **🏛️ Enterprise Insight:** Extracted **hardcoded keys are excellent campaign-correlation
> pivots.** Adversaries reuse keys across builds far more readily than they reuse domains or
> hashes, because rotating a key means rebuilding the panel. Index recovered key material
> alongside signer fingerprints in the TI database.
> → [Ch 28](../sudarshan/28-campaign-correlation.md), [Ch 30](../threat-intelligence/30-threat-intelligence-database.md)

### For vetting the bank's own (and vendors') apps

Map findings directly to **OWASP MASVS-CRYPTO** and MASTG test IDs so the report is
audit-ready:

```yaml
finding:
  id: CRYPTO-001
  title: "ECB mode used for transaction payload encryption"
  masvs: MASVS-CRYPTO-1
  severity: high
  evidence:
    file: com/bank/net/PayloadCrypto.smali
    line: 142
    snippet: 'const-string v0, "AES/ECB/PKCS5Padding"'
  remediation: "Use AES/GCM/NoPadding with a unique 96-bit IV per operation."
```

Also check, specifically for banking clients:
- Is Keystore used at all, or are secrets in `SharedPreferences`?
- `setUserAuthenticationRequired(true)` on transaction-signing keys?
- Is Play Integrity / attestation verified **server-side**? ([Ch 04 §9](04-android-security-model.md#9-play-integrity-api))
- Is there a silent biometric→PIN fallback? (Chameleon's technique)
- Backup pin present and pin expiration set?

---

## 11. Limitations, edge cases, false positives

### Limitations of static crypto analysis

- Obfuscation renames the classes but **not** the JCA algorithm strings - which is why
  grepping for `"AES/ECB"` still works surprisingly often. Sophisticated samples build the
  string at runtime, defeating this.
- Native crypto (OpenSSL/BoringSSL called via JNI) is invisible to Java-level analysis.
- Hooking `Cipher` misses native and hand-rolled implementations.

### False positives

| Signal | Innocent cause |
|---|---|
| Heavy AES usage | Any app with local encryption, DRM, offline sync, or an encrypted database (SQLCipher) |
| Bundled Bouncy/Spongy Castle | Extremely common in fintech |
| Base64 everywhere | Standard encoding, not encryption |
| High-entropy assets | Compressed models, DRM content, packed game assets |
| Certificate pinning + anti-hooking | **Legitimate banking apps do this deliberately.** Pinning and RASP are *good* practice - do not score a bank's own hardened app as suspicious for defending itself. |

> **⚙️ Engineering Note:** That last row causes real embarrassment. Run SUDARSHAN against a
> major bank's genuine app and a naive scorer will flag pinning, obfuscation, root detection,
> anti-debug, and native code - i.e. it will call the most-hardened app on the device
> malicious. **Legitimate hardening and malicious anti-analysis look similar statically.**
> The discriminator is *what the app does with its capabilities*, plus signer reputation.
> → [Ch 27](../sudarshan/27-risk-scoring.md), [Ch 32](../appendix/32-common-misconceptions.md)

### False negatives

- Crypto implemented natively.
- Keys derived at runtime from C2-delivered material (nothing hardcoded to find).
- Sample that never decrypts because C2 was unreachable - flag as *inconclusive*, not clean.

---

## 12. Engineering tips

1. **Hook `Cipher.doFinal` and `SecretKeySpec.<init>` on every detonation.** Highest-yield
   crypto instrumentation, by a wide margin.
2. **Grep for `getInstance("AES")` with no mode** - it means ECB, and it's a real finding.
3. **Extract and index hardcoded keys** as correlation pivots, not just as findings.
4. **Never conflate encryption at rest with protection from a live device-resident attacker.**
5. **For bank app reviews, check for silent biometric→PIN fallback** - Chameleon's technique.
6. **Preserve device state (AFU) during seizure.** BFU can be unrecoverable.
7. **Record Conscrypt and ART Mainline versions** in analysis metadata.

---

## 13. Judge Insights

**What judges ask:** *"If the banking app uses hardware-backed keys, biometrics, and
certificate pinning, how does the malware still succeed?"*

**Perfect answer:** Because none of those controls are defeated - they're bypassed at a
different layer. Keystore guarantees the key can be *used* but not *extracted*; malware
doesn't need to extract it, it needs the app to use it, which it triggers by driving the UI
through Accessibility. Certificate pinning protects data in transit; the malware reads the
plaintext on screen before TLS ever happens. Hardware attestation proves the device is
genuine and the boot state is clean - and it is, because the victim's phone is stock and
unrooted. The one control that genuinely raises cost is a Keystore key bound with
`setUserAuthenticationRequired(true)` and per-operation biometric auth, because an
accessibility attacker can tap buttons but cannot present a fingerprint. Even there,
ThreatFabric documented **Chameleon** in December 2023 forcing a biometric-to-PIN fallback
and capturing the PIN by keylogging - so we also treat a biometric downgrade as a fraud
signal.

**Common mistakes:**
- Saying "the encryption was broken." It essentially never is. Say *bypassed*, and say where.
- Recommending pinning as a fix for banking-trojan fraud. Wrong layer.
- Not knowing that `Cipher.getInstance("AES")` defaults to ECB.

**Follow-ups to expect:**
- *"So what SHOULD a bank do?"* → Per-operation user authentication on transaction-signing
  keys; server-side verification of Play Integrity and key attestation; `FLAG_SECURE` on
  sensitive screens; overlay-obscured touch filtering; detect enabled accessibility services
  outside a known-good allowlist; treat biometric→PIN downgrade as risk.
- *"Isn't hardware-backed crypto the answer?"* → It's necessary and insufficient. It protects
  the key, not the session.

**Fact that impresses:** ToxicPanda uses **AES-ECB** for its C2 (Cleafy, October 2024).
Because ECB is deterministic, identical plaintext blocks produce identical ciphertext - which makes the traffic *fingerprintable without the key*. The adversary's weak crypto is a
defender's detection opportunity. That's a genuinely interesting, non-obvious point.

---

## 14. Interview Insights

**Q: "What does Android Keystore actually protect against?"**
Key *extraction*, not key *misuse*. A compromised app process can ask the system to sign or
decrypt with the key while the process runs, but cannot read the key material out. That
distinction is the whole answer; candidates who miss it usually also miss why banking malware
works.

**Q: "TEE vs StrongBox?"**
TEE = secure mode of the main SoC via TrustZone, logical isolation, near-universal.
StrongBox (API 28+) = discrete physical security chip, tamper-resistant, side-channel
hardened, not present on all devices - always handle `StrongBoxUnavailableException`.

**Q: "What's wrong with `Cipher.getInstance("AES")`?"**
It silently selects **ECB** mode. ECB is deterministic, so identical plaintext blocks yield
identical ciphertext, leaking structure. Use `AES/GCM/NoPadding` with a unique IV.

**Q: "Why can't you MITM a modern Android app easily?"**
Since Android 7.0 (API 24), user-installed CAs aren't trusted by default; the app must opt in
via `network_security_config`. Plus many apps pin. In an authorised lab you patch the network
security config and re-sign, or hook the trust path at runtime.

**Q: "Certificate pinning - leaf or public key, and why a backup pin?"**
Pin the **SPKI (public key)**, so certificate renewal with the same key doesn't break
clients. Always include a **backup pin** and an expiration, or you risk bricking the app at
renewal.

**Q: "What's the difference between key attestation and Play Integrity?"**
Attestation is hardware + Google PKI, verifiable offline, proves key properties, boot state,
and the **calling app's signing certificate digest**. Play Integrity is a Google Play Services
verdict about device/app/account genuineness, requires Play Services, and must be verified
server-side.

**Beginner mistakes:**
- "The data is encrypted so it's safe" - from what, in which state?
- Confusing encoding (Base64) with encryption.
- Thinking pinning defends against on-device malware.
- Forgetting that FBE means BFU/AFU determines what forensics can recover.

---

## 15. Cross-references

**Upstream:**
- [← Ch 04 Android Security Model](04-android-security-model.md) - where crypto sits in the layers

**Downstream:**
- [→ Ch 06 Certificates](06-certificates.md) - X.509 and identity
- [→ Ch 07 APK Signing](07-apk-signing.md) - binding identity to the package
- [→ Ch 10 Reverse Engineering](../reverse-engineering/10-reverse-engineering.md) - string encryption, packers
- [→ Ch 12 Dynamic Analysis](../dynamic-analysis/12-dynamic-analysis.md) - Frida crypto hooks, pinning bypass in lab
- [→ Ch 14 Banking Malware](../banking-malware/14-banking-malware.md) - Chameleon biometric bypass, Crocodilus seed theft
- [→ Ch 17 Digital Forensics](../digital-forensics/17-digital-forensics.md) - FBE, BFU/AFU
- [→ Ch 26 IOC Extraction](../sudarshan/26-ioc-extraction.md) - keys as pivots

**Related chain:** String encryption → dynamic code loading → class loader hook → payload
dump → recursive analysis.

---

## 16. References

1. Android Developers - *Android Keystore system*. https://developer.android.com/privacy-and-security/keystore
2. Android Developers - *Hardware-backed Keystore & StrongBox*. https://source.android.com/docs/security/features/keystore
3. Android Developers - *Verifying hardware-backed key pairs with key attestation*. https://developer.android.com/privacy-and-security/security-key-attestation
4. AOSP - *File-Based Encryption*. https://source.android.com/docs/security/features/encryption/file-based
5. Android Developers - *Network security configuration*. https://developer.android.com/privacy-and-security/security-config
6. Android Developers - *Security with HTTPS and SSL* / certificate pinning guidance.
7. AOSP - *Trusty TEE*. https://source.android.com/docs/security/features/trusty
8. OWASP MASVS v2.1.0 - MASVS-CRYPTO, MASVS-NETWORK, MASVS-RESILIENCE. https://mas.owasp.org/MASVS/
9. OWASP MASTG - cryptography and network communication test cases. https://mas.owasp.org/MASTG/
10. ThreatFabric - *Chameleon* biometric-bypass analysis (December 2023).
11. ThreatFabric - *Crocodilus* (March 29, 2025) - crypto-wallet seed-phrase parser.
12. Cleafy Labs - *ToxicPanda* (October 2024) - AES-ECB C2, `dksu[.]top`, `mixcom[.]one`.
13. Cleafy Labs - *Klopatra* (August 2025) - Base64 JSON C2, C2-delivered overlay HTML.
14. Hunt.io - *ERMAC 3.0 source code leak* (published August 2025) - AES-CBC C2.
15. Cyble Research and Intelligence Labs - *Antidot* (May 16, 2024) - socket.io WebSocket C2.
16. Frida JavaScript API documentation. https://frida.re/docs/javascript-api/

### Further reading
- NIST SP 800-38 series - block cipher modes of operation
- Google Project Zero - TrustZone/TEE vulnerability research
- Conscrypt project documentation (Mainline TLS provider)

---

*Previous: [← Ch 04 Android Security Model](04-android-security-model.md) · Next: [Ch 06 Certificates →](06-certificates.md)*
