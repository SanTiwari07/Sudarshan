# 06 - Certificates

> **Chapter ID:** `CH06` · **Block:** A (Foundations) · **Status:** Stable
> **Tags:** `#certificates` `#x509` `#identity` `#fingerprint` `#trust-on-first-use` `#play-app-signing` `#correlation`
> **Last Updated:** 2026-08-05 · **Version:** 1.0.0
> **Prerequisites:** [Ch 02](../apk/02-apk-architecture.md), [Ch 05](05-android-cryptography.md)

---

## Table of Contents

1. [The one idea that matters](#1-the-one-idea-that-matters)
2. [X.509 in ninety seconds](#2-x509-in-ninety-seconds)
3. [Why Android certificates are self-signed](#3-why-android-certificates-are-self-signed)
4. [Trust On First Use - Android's actual model](#4-trust-on-first-use--androids-actual-model)
5. [Fingerprints: the thing you actually use](#5-fingerprints-the-thing-you-actually-use)
6. [Where the certificate is enforced](#6-where-the-certificate-is-enforced)
7. [Key rotation and lineage](#7-key-rotation-and-lineage)
8. [Play App Signing: whose certificate are you looking at?](#8-play-app-signing-whose-certificate-are-you-looking-at)
9. [Certificate ≠ Signature ≠ Hash](#9-certificate--signature--hash)
10. [Certificates as a correlation pivot](#10-certificates-as-a-correlation-pivot)
11. [Detection logic for SUDARSHAN](#11-detection-logic-for-sudarshan)
12. [Limitations, edge cases, false positives](#12-limitations-edge-cases-false-positives)
13. [Engineering tips](#13-engineering-tips)
14. [Judge Insights](#14-judge-insights)
15. [Interview Insights](#15-interview-insights)
16. [Cross-references](#16-cross-references)
17. [References](#17-references)

---

## 1. The one idea that matters

> **On Android, the signing certificate is the app's identity. The package name is not.
> The file hash is not. The developer name inside the certificate is not.**

Everything else in this chapter is elaboration. If you take one thing from Block A into
your daily work, take this - it prevents more analytical errors than any other single fact
in Android security.

Why it's true, in one line: **the package name is a string anyone can type; the certificate
requires a private key you either have or don't.**

---

## 2. X.509 in ninety seconds

An X.509 certificate binds a **public key** to a **subject** (an identity claim), signed by
an **issuer**.

```
Certificate
├── Version, Serial Number
├── Signature Algorithm        (e.g. SHA256withRSA)
├── Issuer                     ← who signed this certificate
├── Validity                   ← notBefore / notAfter
├── Subject                    ← who this certificate claims to be
│     CN=Bank App, O=Example Bank, C=IN
├── Subject Public Key Info    ← THE PUBLIC KEY  ★
├── Extensions                 (keyUsage, basicConstraints, SANs, ...)
└── Signature                  ← issuer's signature over all of the above
```

In the web PKI, a Certificate Authority vouches for the Subject: you trust
`api.bank.example` because a CA you trust signed a certificate saying that hostname holds
that public key.

**Android app signing does not work like that at all.**

---

## 3. Why Android certificates are self-signed

### WHAT

In an Android APK, `Issuer == Subject`. The certificate is signed by its own private key.
No CA is involved, ever. Anyone can generate one in ten seconds:

```bash
$ keytool -genkeypair -v -keystore my.keystore -alias mykey \
    -keyalg RSA -keysize 4096 -validity 10000 \
    -dname "CN=Google Inc, O=Google, C=US"      # ← yes, you can type anything
```

That certificate will claim to be Google. Android will accept it. It will install fine.

### WHY Google chose this

A CA model would mean:
- Every Android developer paying a CA, creating a barrier for hobbyists and open source.
- Google (or CAs) becoming a gatekeeper for whether an app can *exist* - politically and
  practically undesirable for an open platform.
- CA compromise becoming an ecosystem-wide app-signing compromise.

Instead Android chose a model where the certificate does not assert *who you are in the
world*; it asserts *that this app is from the same source as the last version of this app*.

> **🚨 Misconception:** "The certificate tells you who developed the app." It tells you
> **what the signer typed into the `-dname` field.** The Subject fields (CN, O, OU, L, ST, C)
> are **completely self-asserted and unverified**. Malware routinely puts plausible-looking
> organisation names in there. Never report a certificate Subject as an attribution claim - > report it as an *artifact*, useful for clustering, worthless as proof.

### What the Subject IS good for

Despite being unverified, Subject strings are useful:

- **Correlation.** Adversaries are lazy. A distinctive `CN=Rachel`, a typo, or a specific
  `O=` value recurring across samples clusters a campaign.
- **Default detection.** `CN=Android Debug, O=Android, C=US` is the **Android debug
  certificate**. An app in the wild signed with the debug key was built by someone who ran a
  debug build - sloppy, and a genuine signal.
- **Anomaly detection.** A certificate claiming a well-known bank's `O=` value whose
  fingerprint doesn't match that bank's known signer is, by definition, an impersonation
  attempt.

---

## 4. Trust On First Use - Android's actual model

### HOW it works

```
  First install of com.example.app
        │
        ▼
  Android records the signer certificate for that package name
  (stored in /data/system/packages.xml)
        │
        ▼
  ═══════════════════════════════════════════════════════
        │
  Update arrives claiming to be com.example.app
        │
        ▼
  Does its signer match the recorded one?
        │
   ┌────┴────┐
   │         │
  YES       NO
   │         │
   ▼         ▼
 Update   INSTALL_FAILED_UPDATE_INCOMPATIBLE
 allowed  (must uninstall first - losing all data)
```

This is **Trust On First Use (TOFU)**. Android never asks "is this signer trustworthy?" It
asks "is this the *same* signer as before?"

### WHY this is powerful

- Guarantees **update integrity**: nobody can push a malicious update to your app without
  your private key.
- Enables `signature`-level permissions: two apps by the same signer can share private APIs
  ([Ch 04 §4](04-android-security-model.md#4-layer-3--permissions)).
- Makes **repackaging detectable**: a modified clone necessarily has a different signer.

### WHY it's insufficient

TOFU protects continuity, not initial trust. If the *first* app you install under a package
name is malicious, TOFU faithfully protects the malware's ability to update itself. This is
exactly the situation with smishing-delivered fake banking apps: the victim doesn't have
the real app, so there's no prior signer to conflict with.

> **⚙️ Engineering Note:** You can see the recorded signer in the package database:
> ```bash
> $ adb shell dumpsys package com.example.app | grep -A2 "signatures"
> $ adb shell cat /data/system/packages.xml | grep -A5 'package name="com.example.app"'
> ```
> The `<cert index="N" key="308...."/>` element holds the DER-encoded certificate. This is
> a first-class forensic artifact: it tells you what signer the device accepted, even if the
> APK has since been deleted. → [Ch 17](../digital-forensics/17-digital-forensics.md)

---

## 5. Fingerprints: the thing you actually use

A **fingerprint** is a hash of the DER-encoded certificate. It's how you refer to a signer
in practice - compact, comparable, and greppable.

```bash
# The canonical command. Learn it.
$ apksigner verify --verbose --print-certs app.apk

Verifies
Verified using v1 scheme (JAR signing): false
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): true
Number of signers: 1
Signer #1 certificate DN: CN=Example Bank, O=Example Bank Ltd, C=IN
Signer #1 certificate SHA-256 digest: 3a1f...b92c
Signer #1 certificate SHA-1 digest:   9de4...11af
Signer #1 certificate MD5 digest:     c0ff...eeee
Signer #1 key algorithm: RSA
Signer #1 key size (bits): 4096
Signer #1 public key SHA-256 digest: 7b02...aa31        ← SPKI digest
```

Alternatives:

```bash
# keytool on the extracted cert
$ unzip -p app.apk META-INF/CERT.RSA | keytool -printcert
# Androguard (scriptable - what SUDARSHAN should use)
$ python3 -c "
from androguard.core.bytecodes.apk import APK
a = APK('app.apk')
for c in a.get_certificates():
    print(c.sha256_fingerprint, c.subject.native)
"
```

### Which digest to use

| Digest | Use it? | Why |
|---|---|---|
| **SHA-256 of the certificate** | ✅ **Primary** | Collision-resistant; the field to index |
| SHA-256 of the public key (SPKI) | ✅ Secondary | Survives certificate re-encoding; useful for rotation tracking |
| SHA-1 | ⚠️ Compatibility only | Broken for collisions; still the format Google APIs (Maps, Firebase) ask for |
| MD5 | ❌ | Legacy only |

> **⚙️ Engineering Note:** Google's own developer console still asks for **SHA-1** signing
> certificate fingerprints when configuring Maps or Firebase. That's a legacy interface, not
> an endorsement. For security decisions, use SHA-256. If a tool or a report gives you only
> a SHA-1 signer fingerprint, treat it as an identifier to *match*, never as a security
> guarantee.

---

## 6. Where the certificate is enforced

Concrete places where Android makes a decision based on the signer, not the package name:

| Mechanism | Certificate's role |
|---|---|
| **App updates** | Must match the recorded signer (TOFU, §4) |
| **`signature`-level permissions** | Granted only to same-signer apps |
| **`sharedUserId`** (deprecated) | Requires identical signer |
| **App Links** | `assetlinks.json` names the app's signing-cert SHA-256 fingerprint |
| **Key attestation** | Attestation record includes the calling app's signing-cert digest ([Ch 05 §5](05-android-cryptography.md#5-key-attestation)) |
| **`PackageManager.checkSignatures()`** | Compares two packages' signers |
| **`signingInfo` / `GET_SIGNING_CERTIFICATES`** | Runtime self- or peer-verification |
| **Google Play** | Uploads must be signed with the registered key |
| **MDM/EMM allowlists** | Enterprise policy pins app identity to signer |

### The App Links example, spelled out

```json
// https://bank.example/.well-known/assetlinks.json
[{
  "relation": ["delegate_permission/common.handle_all_urls"],
  "target": {
    "namespace": "android_app",
    "package_name": "com.bank.example",
    "sha256_cert_fingerprints": ["3A:1F:...:B9:2C"]     ← the identity anchor
  }
}]
```

A repackaged clone with the same `package_name` but a different signer **cannot** claim the
bank's HTTPS links. The package name alone is insufficient; the fingerprint is what makes it
verifiable. This is the cleanest available proof that Android treats the certificate - not
the package name - as identity.

---

## 7. Key rotation and lineage

### The problem

Under TOFU, if you lose your signing key you lose the ability to update your app, forever.
If your key is compromised, you cannot move to a new one without forcing every user to
uninstall and reinstall. Before Android 9 this was genuinely unsolvable.

### The solution: v3 proof-of-rotation

**APK Signature Scheme v3 (Android 9, API 28)** introduced a **signing certificate lineage**.
The APK carries a chain in which each old key signs the next key, proving the rotation was
authorised by the previous key holder.

```
   Key A  ──signs──►  Key B  ──signs──►  Key C
   (2019)             (2022)             (2025)
     │                  │                  │
     └──────────────────┴──────────────────┘
                proof-of-rotation lineage
             carried inside the APK's v3 block

  Old device (< API 28): verifies with Key A (v2 block)
  New device (API 28+):  verifies with Key C, sees the lineage back to A
```

Each lineage node also carries flags describing what the old certificate is still trusted
for (e.g. still valid for `signature` permissions and `sharedUserId`, or not).

From **Android 13 (API 33)**, `PackageManager.checkSignatures()` recognises proof-of-rotation
and returns the **newest** signing certificate - so same-signer checks keep working across a
rotation.

**v3.1** (Android 13 era) refines this: it lets a developer target rotation at newer SDK
versions while continuing to present the older key to older platforms, which fixes some
awkward compatibility cases v3 alone couldn't express.

### Why this is a gift to analysts

> **⚖️ Judge Tip:** Key rotation is usually discussed as a developer feature. The
> counter-intuitive security point worth making: **proof-of-rotation lineage is an
> attribution windfall.** If an adversary rotates keys, the lineage cryptographically links
> the old identity to the new one - the adversary hands you the correlation you would
> otherwise have to infer. Any campaign-correlation engine should parse v3 lineage and treat
> every key in the chain as the *same actor*.

---

## 8. Play App Signing: whose certificate are you looking at?

Since new apps must publish as App Bundles ([Ch 02 §7](../apk/02-apk-architecture.md#7-app-bundles-split-apks-and-why-the-apk-is-a-lie)),
**Play App Signing** is effectively mandatory for new Play apps.

```
  Developer's UPLOAD key ──signs──► app.aab
                                      │
                                      ▼
                              Google Play Console
                                verifies upload signature,
                                then STRIPS it
                                      │
                                      ▼
                    Google's held APP SIGNING key ──signs──► generated APKs
                                      │
                                      ▼
                                   device
```

### Consequences you must get right

1. **The certificate on a Play-downloaded APK is the app signing key held by Google**, not
   the developer's upload key. Both are real; they're different keys with different roles.
2. **It is still a valid, stable identity** for that app on Play - TOFU works, App Links
   work, attestation works.
3. **You must not describe it as "the developer's key"** in a report. Say "the app signing
   certificate (Play App Signing)".
4. An APK for the same app obtained from a third-party mirror may be signed differently
   (re-signed by the mirror, or an older pre-bundle build). **Different signer ≠ automatically
   malicious**, but it does mean "not the Play-distributed artifact," which is itself
   important for a bank.

> **🏛️ Enterprise Insight:** For a bank's own apps, maintain a **canonical signer registry**:
> package name → expected app signing certificate SHA-256 (plus any lineage predecessors).
> Then any sample claiming your package with a different fingerprint is an impersonation
> candidate, full stop - no ML required, no false positives from obfuscation or permissions.
> This is the cheapest high-precision detection a bank can deploy, and SUDARSHAN should
> ship it as a first-class feature. → [Ch 28](../sudarshan/28-campaign-correlation.md)

---

## 9. Certificate ≠ Signature ≠ Hash

The three-way confusion, resolved. This table is worth memorising verbatim; it is asked in
interviews constantly and it is the seed of several entries in
[Ch 32](../appendix/32-common-misconceptions.md).

| | **Certificate** | **Signature** | **Hash** |
|---|---|---|---|
| **What it is** | Public key + self-asserted identity claim | Cryptographic proof produced with the private key over the APK's contents | Digest of exact file bytes |
| **Answers** | *Who signed this?* | *Was this modified since signing?* | *Is this the exact same file?* |
| **Stable across rebuilds?** | ✅ Yes (same key) | ❌ New signature each build | ❌ Changes on any byte change |
| **Forgeable without the key?** | You can make a *lookalike* cert, but not the same fingerprint | ❌ No | ✅ Trivially - that's the point |
| **Use for** | **Identity, attribution, correlation** | **Integrity verification** | **IOC, blocklist, dedup** |
| **Lifetime as an indicator** | Months to years | Per-build | Hours to days |

```
An analogy that survives scrutiny:

  Certificate  ≈  the passport (who you claim to be, and a key only you hold)
  Signature    ≈  a wax seal on this specific envelope (proves untampered)
  Hash         ≈  the envelope's exact weight (identifies this envelope, nothing more)
```

> **🚨 Misconception:** "Same hash = same app; different hash = different app." Both halves
> are wrong in practice. Same hash does mean same file (useful!). But **different hash
> absolutely does not mean different app** - Play generates per-device split APKs, so the
> same app version legitimately has many hashes. And adversaries change a byte to defeat
> hash blocklists as routine hygiene; Zscaler ThreatLabz documented Anatsa rotating package
> names and install hashes between campaigns.

---

## 10. Certificates as a correlation pivot

### Why the signer is the best pivot available

Rank the pivots by how expensive they are for the adversary to change:

```
 EXPENSIVE to change ◄─────────────────────────────► CHEAP to change

  Signing key         Code structure      C2 domain     Package     File
  (breaks their       (requires real      (register     name        hash
   own update path,    rework)             a new one)   (type it)   (1 byte)
   costs them
   installed base)
```

The signing key sits at the expensive end for a specific structural reason: **the adversary
needs it to update their own installed victims.** Rotating it means abandoning that base or
carrying a v3 lineage that links old to new. Either way you win.

### What correlation looks like in practice

```
   Sample A (SHA-256 aaa…)  ┐
   Sample B (SHA-256 bbb…)  ├─► same signer fingerprint 3a1f…b92c
   Sample C (SHA-256 ccc…)  ┘         │
                                      ▼
                        ONE campaign / one actor's build key
                                      │
                        ┌─────────────┴──────────────┐
                        ▼                            ▼
              Union of their C2 domains    Union of target bank lists
                        │                            │
                        ▼                            ▼
                  Block at network            Notify affected banks
```

Supporting pivots when the signer differs (each covered later):
- **Code similarity** - TLSH/SSDEEP fuzzy hashes, call-graph comparison → [Ch 28](../sudarshan/28-campaign-correlation.md)
- **Packer fingerprint** - Virbox / Jiagu / Bangcle native library names → [Ch 10](../reverse-engineering/10-reverse-engineering.md)
- **Infrastructure overlap** - shared IPs/domains, e.g. ERMAC's `141.164.62[.]236` (Hunt.io, Aug 2025)
- **Hardcoded key reuse** → [Ch 05 §10](05-android-cryptography.md#10-detection-logic-for-sudarshan)
- **Resource artifacts** - overlay HTML, target package lists, locale sets

### Real-world caveat

Sophisticated MaaS operations generate a **fresh key per build** precisely to break this
pivot. When that happens, signer correlation yields clusters of one and you must fall back
to code and infrastructure similarity. **Record that fact** - "unique signer per sample" is
itself an operational-sophistication indicator worth reporting.

---

## 11. Detection logic for SUDARSHAN

### Mandatory intake behaviour

```yaml
on_sample_intake:
  extract:
    - signer_cert_sha256          # PRIMARY IDENTITY KEY - indexed, required
    - signer_spki_sha256          # survives re-encoding
    - signer_subject_dn           # artifact only, never attribution
    - signer_issuer_dn
    - signer_validity_not_before / not_after
    - signer_key_algorithm, key_size
    - signature_schemes_verified  # v1/v2/v3/v3.1/v4 → Ch 07
    - v3_rotation_lineage[]       # ALL keys in the chain
    - number_of_signers
  index:
    primary_key: signer_cert_sha256
    also: v3_rotation_lineage[*]   # every lineage member maps to the same actor node
```

### Rules

| Rule | Logic | Severity | Confidence |
|---|---|---|---|
| **Impersonation of a protected package** | `package ∈ bank_registry AND signer_sha256 ∉ registry[package].allowed` | **Critical** | **High** - deterministic, no ML |
| **Android debug certificate** | Subject == `CN=Android Debug, O=Android, C=US` | Medium | High |
| **Known-malicious signer** | signer ∈ TI database malicious signers | High | High |
| **Signer seen only on flagged samples** | cluster purity == 100% malicious, n ≥ 3 | Medium-High | Medium |
| **Absurd validity** | `notAfter - notBefore > 100 years` or `notBefore` in the future | Low | Medium - common in malware, also in careless legit builds |
| **Weak key** | RSA < 2048 bits | Low | High (as a hygiene finding) |
| **Multiple signers** | `number_of_signers > 1` | Low | Informational - legitimate but unusual |
| **Fresh signer per sample across a family** | code-similar samples, all distinct signers | Informational | - flag as *operational sophistication* |

> **⚙️ Engineering Note:** The impersonation rule is the highest-precision detection in the
> entire SUDARSHAN design. It has essentially **zero false positives** when the registry is
> correct, requires no behavioural analysis, and runs in milliseconds. Build it first. It is
> also the easiest thing to demo convincingly: show a genuine bank APK and a clone side by
> side, same package name, different fingerprint, instant verdict with cryptographic
> justification.

### Certificate as a graph node

In the investigation graph ([Ch 25](../sudarshan/25-investigation-engine.md)), the signer
certificate should be a **first-class node**, not an attribute of the sample:

```
        ┌──────────────┐
        │  SIGNER CERT │◄──── the durable identity node
        │  3a1f…b92c   │
        └──────┬───────┘
       ┌───────┼────────┐
       ▼       ▼        ▼
   sample A  sample B  sample C
       │       │        │
       ▼       ▼        ▼
     C2 x    C2 x     C2 y     ← infrastructure links
       └───────┴────────┘
              │
              ▼
      CAMPAIGN cluster
```

---

## 12. Limitations, edge cases, false positives

### Limitations

- **The certificate proves continuity, not goodness.** A consistently-signed app from a
  consistent malware author verifies perfectly. Identity ≠ trustworthiness.
- **Subject fields are unverified.** Never attribute from them.
- **Per-build key generation** defeats signer correlation (§10).
- **Play App Signing** means the visible cert is Google's, not the developer's (§8).

### Edge cases

| Case | Handling |
|---|---|
| **Multiple signers** | Legal. All must verify. Record all fingerprints. |
| **v3 lineage present** | Map *every* key in the lineage to the same actor node |
| **v1-only APK** | Different verification semantics and Janus exposure → [Ch 07](07-apk-signing.md) |
| **Split APKs** | All splits share the signer; verify each anyway |
| **Expired certificate** | Android does **not** check expiry at install for app signing certs - an expired cert still installs. Surprises people. |
| **Same cert, different package names** | Common and legitimate (one developer, many apps). Also a malware-family fingerprint. Cluster, don't accuse. |
| **Debug certificate** | Suspicious in the wild, but also seen in genuine sideloaded internal/test builds |

### False positives

| Trigger | Innocent explanation |
|---|---|
| Signer differs from Play version | App obtained from a third-party mirror, or a pre-App-Bundle build, or a regional variant |
| Long certificate validity | Google's own guidance is to use a long validity (e.g. 25+ years) so the key outlives the app |
| Self-signed | **Every** Android app signing cert is self-signed. Never a finding on its own. |
| One signer, many packages | Normal for any developer with a portfolio |

> **🚨 Misconception:** "Self-signed certificate = suspicious." On the web, maybe. On
> Android, **it's the only kind there is**. Flagging it marks your tool as unaware of the
> platform. (This one genuinely appears in low-quality scanner output.)

---

## 13. Engineering tips

1. **Index `signer_cert_sha256` as your primary identity key.** Not the file hash.
2. **Parse and expand v3 lineage** - collapse all lineage keys into one actor node.
3. **Build the bank's canonical signer registry on day one.** Cheapest high-precision win.
4. **Report Subject DN as an artifact, never as attribution.** Write the caveat into the
   report template so analysts can't forget.
5. **Prefer SHA-256; keep SHA-1 only for interop** with Google console tooling.
6. **Don't flag self-signed or long validity.** Both are normal.
7. **Verify every split**, not just `base.apk`.
8. **Record "unique signer per sample"** as a sophistication indicator when correlation fails.

---

## 14. Judge Insights

**What judges ask:** *"How do you know this fake banking app isn't the real one?"*

**Perfect answer:** The package name matches, but the signing certificate doesn't. Android
identity is the signer, not the package name - a package name is a string anyone can type,
whereas the certificate requires a private key the bank has never released. We maintain a
registry of each client bank's app signing certificate SHA-256 fingerprints, so this check
is deterministic and cryptographic: the clone claims `com.bank.example` but its fingerprint
isn't in the registry, which means it cannot have been built by the bank. It also can't
update over the genuine app - Android would reject it with
`INSTALL_FAILED_UPDATE_INCOMPATIBLE` - and it can't claim the bank's verified App Links,
because `assetlinks.json` pins the fingerprint.

**Common mistakes:**
- "We check the developer name in the certificate." Self-asserted and unverified. Anyone can
  put `O=Google` in a certificate.
- "We compare hashes." Adversaries change one byte routinely; Play itself produces multiple
  hashes per version.
- Flagging self-signed certificates. Every Android app cert is self-signed.

**Follow-ups to expect:**
- *"What if they steal the bank's signing key?"* → Catastrophic, and the reason Play App
  Signing (Google-held keys, HSM-protected) plus v3 key rotation exist. Rotation lets a bank
  move to a new key with cryptographic proof-of-rotation rather than forcing reinstalls.
- *"What if the attacker uses a different package name?"* → Then it's not impersonating our
  registry entry, and we fall back to capability clustering and code/infrastructure
  similarity. Different detection, and we're explicit about which one fired.
- *"Can two apps share a certificate legitimately?"* → Yes - one developer's portfolio, and
  it's required for `signature` permissions and (deprecated) `sharedUserId`.

**Fact that impresses:** APK Signature Scheme **v3 carries a proof-of-rotation lineage**, so
when an adversary rotates signing keys they hand you a cryptographic link between their old
and new identity. Key rotation is normally framed as a developer convenience; framing it as
an attribution windfall shows you've thought past the documentation.

---

## 15. Interview Insights

**Q: "Certificate vs signature vs hash?"**
Use §9's table. Certificate = who signed (identity, durable). Signature = proof of integrity
for these bytes (per-build). Hash = identifies this exact file (volatile, adversary-controlled).
Then the punchline: **identity is the certificate; the hash is only an IOC.**

**Q: "Why are Android signing certificates self-signed?"**
No CA gatekeeping, no cost barrier, no ecosystem-wide CA-compromise risk. The model is Trust
On First Use - Android verifies *sameness across updates*, not real-world identity.

**Q: "What happens if I try to update an app with a different signing key?"**
`INSTALL_FAILED_UPDATE_INCOMPATIBLE`. The user must uninstall first, losing app data. Unless
v3 proof-of-rotation lineage links the keys.

**Q: "How does an app prove its identity to a server?"**
Not by package name (spoofable) and not by a client-side self-check (patchable). Use **key
attestation** - the attestation record includes the calling app's signing certificate digest
and is verified server-side against Google's PKI - optionally alongside Play Integrity's
`appIntegrity` verdict. → [Ch 05 §5](05-android-cryptography.md#5-key-attestation)

**Q: "You have two APKs with different hashes. Same app?"**
Maybe. Check the signer fingerprint and version. Different hashes are expected for the same
app version across devices because Play generates per-configuration split APKs from an App
Bundle.

**Beginner mistakes:**
- Treating the certificate Subject as verified identity.
- Flagging self-signed certs.
- Using the file hash as app identity.
- Not knowing Android doesn't enforce app-signing-cert expiry at install.

---

## 16. Cross-references

**Upstream:**
- [← Ch 02 APK Architecture](../apk/02-apk-architecture.md) - package name vs application ID
- [← Ch 05 Android Cryptography](05-android-cryptography.md) - key attestation, Keystore

**Downstream:**
- [→ Ch 07 APK Signing](07-apk-signing.md) - how the cert is bound to the APK; v1–v4; Janus
- [→ Ch 09 Package Manager](../apk/09-package-manager.md) - where TOFU is enforced
- [→ Ch 17 Digital Forensics](../digital-forensics/17-digital-forensics.md) - `packages.xml` cert artifacts
- [→ Ch 26 IOC Extraction](../sudarshan/26-ioc-extraction.md) - signer as an indicator
- [→ Ch 28 Campaign Correlation](../sudarshan/28-campaign-correlation.md) - the pivot in §10
- [→ Ch 32 Common Misconceptions](../appendix/32-common-misconceptions.md) - §9 in full

**Related chain:** Certificate → signature → APK signing → TOFU → update integrity →
campaign correlation.

---

## 17. References

1. AOSP - *Application Signing*. https://source.android.com/docs/security/features/apksigning
2. Android Developers - *Sign your app*. https://developer.android.com/studio/publish/app-signing
3. Android Developers - *APK signature scheme v3 / key rotation*. https://source.android.com/docs/security/features/apksigning/v3
4. Android Developers - *Verify Android App Links* (`assetlinks.json`). https://developer.android.com/training/app-links/verify-android-applinks
5. Android Developers - `PackageManager.checkSignatures()` / `SigningInfo` reference.
6. Google Play Console Help - *Play App Signing*. https://support.google.com/googleplay/android-developer/answer/9842756
7. RFC 5280 - *Internet X.509 Public Key Infrastructure Certificate and CRL Profile*.
8. Android Developers - `apksigner` documentation. https://developer.android.com/tools/apksigner
9. Androguard documentation - certificate extraction API. https://androguard.readthedocs.io/
10. Zscaler ThreatLabz - *Anatsa's Latest Updates* (August 2025) - package name and hash rotation.
11. Hunt.io - *ERMAC 3.0 source code leak* (August 2025) - shared infrastructure pivots.
12. OWASP MASTG - code signing and integrity test cases. https://mas.owasp.org/MASTG/

### Further reading
- AOSP `tools/apksig/` - the reference signing/verification implementation
- Android Developers - *Use Play App Signing* migration guidance
- MITRE ATT&CK for Mobile - T1408 (Artifact/asset analysis context)

---

*Previous: [← Ch 05 Android Cryptography](05-android-cryptography.md) · Next: [Ch 07 APK Signing →](07-apk-signing.md)*
