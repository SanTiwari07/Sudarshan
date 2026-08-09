# 07 - APK Signing

> **Chapter ID:** `CH07` · **Block:** A (Foundations) · **Status:** Stable
> **Tags:** `#apk-signing` `#v1` `#v2` `#v3` `#v4` `#janus` `#master-key` `#fake-id` `#signing-block`
> **Last Updated:** 2026-08-05 · **Version:** 1.0.0
> **Prerequisites:** [Ch 02](../apk/02-apk-architecture.md), [Ch 06](06-certificates.md)

---

## Table of Contents

1. [The problem signing solves](#1-the-problem-signing-solves)
2. [The scheme matrix](#2-the-scheme-matrix)
3. [v1 - JAR signing](#3-v1--jar-signing)
4. [The APK Signing Block](#4-the-apk-signing-block)
5. [v2 - whole-file signing](#5-v2--whole-file-signing)
6. [v3 and v3.1 - key rotation](#6-v3-and-v31--key-rotation)
7. [v4 - incremental / streaming install](#7-v4--incremental--streaming-install)
8. [How verification actually runs](#8-how-verification-actually-runs)
9. [The three classic attacks](#9-the-three-classic-attacks)
10. [Working with signatures: commands](#10-working-with-signatures-commands)
11. [Detection logic for SUDARSHAN](#11-detection-logic-for-sudarshan)
12. [Limitations, edge cases, false positives](#12-limitations-edge-cases-false-positives)
13. [Engineering tips](#13-engineering-tips)
14. [Judge Insights](#14-judge-insights)
15. [Interview Insights](#15-interview-insights)
16. [Cross-references](#16-cross-references)
17. [References](#17-references)

---

## 1. The problem signing solves

Three questions, answered by three properties:

| Question | Property | Mechanism |
|---|---|---|
| Was this APK modified after the developer built it? | **Integrity** | Digest over contents, signed |
| Is this update from the same source as the installed version? | **Continuity** | Signer comparison (TOFU, [Ch 06 §4](06-certificates.md#4-trust-on-first-use--androids-actual-model)) |
| Can two apps trust each other? | **Same-origin** | `signature` permissions, `sharedUserId` |

Note what is *not* on this list: **trustworthiness**. Signing tells you the APK is unmodified
and from a consistent source. It says nothing about whether that source is benign. Every
banking trojan in [Ch 14](../banking-malware/14-banking-malware.md) is correctly signed.

**Every APK must be signed.** An unsigned APK cannot be installed, full stop.

---

## 2. The scheme matrix

The table to memorise. Every row's Android version is the version that *introduced
verification support*.

| Scheme | Android (API) | What it covers | Stored where | Key property |
|---|---|---|---|---|
| **v1 (JAR)** | All versions | Individual **ZIP entries** | `META-INF/` files | Doesn't protect ZIP metadata; slow; extensible-but-weak |
| **v2** | 7.0 (24) | **The entire file** | APK Signing Block, ID `0x7109871a` | Any byte change breaks it; fast verification |
| **v3** | 9 (28) | Entire file + **rotation lineage** | APK Signing Block, ID `0xf05368c0` | Key rotation with proof-of-rotation |
| **v3.1** | 13 (33) era | As v3, SDK-targeted rotation | APK Signing Block, ID `0x1b93ad61` | Rotate for new SDKs, keep old key for old devices |
| **v4** | 11 (30) | **Merkle hash tree** over the file | **Separate file** `<name>.apk.idsig` | Enables incremental/streaming install; requires v2 or v3 alongside |

### The rules that follow from it

- **Since Android 11 (API 30), APKs must be signed with v2 or higher.** v1 may be added
  *in addition* for backward compatibility with pre-Nougat devices - but v1-only will not
  install.
- **v4 is never alone.** It complements v2/v3; it does not replace them.
- **Higher schemes win.** If v3 is present and verifies, Android uses it and doesn't need v1.

```
        Android version support
        ────────────────────────────────────────────────────────►
  API:  21    24        28        30        33
        │     │         │         │         │
  v1    ██████████████████████████████████████████  (all, but v1-only blocked ≥30)
  v2          ████████████████████████████████████
  v3                    ██████████████████████████
  v3.1                                      ██████
  v4                              ██████████████████
```

---

## 3. v1 - JAR signing

### WHAT

Inherited directly from Java's JAR signing. Three files in `META-INF/`:

```
META-INF/MANIFEST.MF     ← SHA-256 digest of EACH file in the archive
META-INF/CERT.SF         ← SHA-256 digest of each MANIFEST.MF ENTRY (+ whole-manifest digest)
META-INF/CERT.RSA        ← PKCS#7 blob: signature over CERT.SF + the certificate chain
```

```
MANIFEST.MF
   Name: classes.dex
   SHA-256-Digest: qX7f...=          ← digest of the file's CONTENT
   Name: res/layout/main.xml
   SHA-256-Digest: 8bK2...=
        │
        ▼  digested per-entry
CERT.SF
   SHA-256-Digest-Manifest: aa11...=
   Name: classes.dex
   SHA-256-Digest: Lm09...=          ← digest of the MANIFEST.MF *stanza*
        │
        ▼  signed
CERT.RSA  (PKCS#7 signature + certificate)
```

### The structural weaknesses

This design has three problems that all trace to one root cause: **it signs file *contents*,
not the *archive***.

1. **ZIP metadata is unprotected.** Filenames, ordering, extra fields, comments, and the
   central directory itself are outside the signature.
2. **Files not listed in `MANIFEST.MF` are unprotected.** An attacker can *add* files.
3. **Verification is slow** - every entry must be decompressed and digested. On a large APK
   this is measurable, and it happens on every install and every boot verification pass.

Consequences #1 and #2 produced Master Key and Janus (§9).

> **⚙️ Engineering Note:** The filenames `CERT.SF` / `CERT.RSA` are conventional, not
> mandatory - the base name can be anything (`ANDROID.SF`, `A.RSA`), and the extension may be
> `.RSA`, `.DSA`, or `.EC` depending on key type. Parsers that hardcode `CERT.RSA` miss
> samples. Match on `META-INF/*.{RSA,DSA,EC}` instead. This bites people writing their own
> extractors.

---

## 4. The APK Signing Block

Everything from v2 onward lives here. Understanding its position in the file is what makes
v2's guarantee obvious.

### ZIP layout, before and after

```
   Classic ZIP                        APK with Signing Block
   ───────────                        ──────────────────────
  ┌──────────────────┐               ┌──────────────────────┐
  │ ① Local file     │               │ ① Local file         │
  │    headers +     │               │    headers + data    │
  │    file data     │               │                      │
  ├──────────────────┤               ├──────────────────────┤
  │                  │               │ ★ APK SIGNING BLOCK  │  ← inserted here
  │                  │               │   (NOT a ZIP entry)  │
  ├──────────────────┤               ├──────────────────────┤
  │ ② Central        │               │ ② Central directory  │
  │    directory     │               │                      │
  ├──────────────────┤               ├──────────────────────┤
  │ ③ End of Central │               │ ③ EOCD               │
  │    Directory     │               │                      │
  └──────────────────┘               └──────────────────────┘
```

### Block structure

```
┌────────────────────────────────────────────────────┐
│ size of block (uint64, excluding this field)       │
├────────────────────────────────────────────────────┤
│ ID-value pairs:                                    │
│   ┌──────────────────────────────────────────┐     │
│   │ length (uint64) │ ID (uint32) │ value ... │     │
│   └──────────────────────────────────────────┘     │
│   0x7109871a → v2 signature block                  │
│   0xf05368c0 → v3 signature block                  │
│   0x1b93ad61 → v3.1 signature block                │
│   0x42726577 → "Brew" - Google Play metadata       │
│   (other IDs: vendor/dependency metadata)          │
├────────────────────────────────────────────────────┤
│ size of block (repeated, uint64)                   │
├────────────────────────────────────────────────────┤
│ magic: "APK Sig Block 42" (16 bytes)               │
└────────────────────────────────────────────────────┘
```

> **⚙️ Engineering Note:** The magic string **`APK Sig Block 42`** is a Hitchhiker's Guide
> reference and a genuinely useful forensic marker - grep for it to locate the block in a
> raw file, or to confirm a signing block exists in a truncated/damaged sample. Unknown
> ID-value pairs are **ignored by verifiers but still covered by the signature**, which is
> how Google Play stuffs its own metadata (`0x42726577`) in without breaking anything. Those
> extra pairs are also worth recording: their presence and content can fingerprint the build
> or distribution pipeline. → [Ch 28](../sudarshan/28-campaign-correlation.md)

---

## 5. v2 - whole-file signing

### HOW it works

The APK is split into **1 MiB chunks** across three regions, each chunk digested, then a
top-level digest computed over all chunk digests, then signed.

```
  Regions covered by the v2 digest:
  ┌──────────────────┐
  │ ① file data      │  ✅ covered
  ├──────────────────┤
  │   SIGNING BLOCK  │  ⛔ excluded (obviously - it holds the signature)
  ├──────────────────┤
  │ ② central dir    │  ✅ covered
  ├──────────────────┤
  │ ③ EOCD           │  ✅ covered (with the CD-offset field normalised)
  └──────────────────┘

  chunk₀ chunk₁ chunk₂ … chunkₙ
    │      │      │        │
   H(0xa5‖chunk) each          ← 0xa5 prefix domain-separates chunk digests
    │      │      │        │
    └──────┴──────┴────────┘
              │
       H(0x5a ‖ count ‖ all chunk digests)   ← 0x5a prefix for the root
              │
              ▼
        signed with the private key
```

The `0xa5` / `0x5a` byte prefixes are **domain separation** - they ensure a chunk digest can
never be confused with the root digest. A small detail that shows the design was done
carefully.

### WHY this fixes v1's problems

| v1 problem | v2 answer |
|---|---|
| ZIP metadata unprotected | Central directory and EOCD are inside the digest |
| Extra files can be added | Adding *anything* changes bytes → digest breaks |
| Slow verification | Chunked digest, parallelisable, no per-entry decompression |
| Structural ambiguity (Janus) | The whole file is covered, so prepending is impossible |

### The consequence you must internalise

> **After v2 signing, you cannot change a single byte of the APK without invalidating the
> signature.** This includes: `zipalign`, adding a file, removing a file, re-compressing,
> editing the manifest, changing a resource, or touching ZIP comments.
>
> Practical rule: **align first, sign last.**

That is also why repackaging always requires re-signing with the attacker's own key, and
therefore always changes the signer fingerprint ([Ch 06](06-certificates.md)).

---

## 6. v3 and v3.1 - key rotation

v3 is v2's structure plus two additions:

1. **Supported SDK range** (`minSdkVersion` / `maxSdkVersion`) inside the signer block, so
   different signers can apply on different platform versions.
2. **Proof-of-rotation** - a lineage where each old key signs the next.

```
  proof-of-rotation lineage inside the v3 block:

   ┌──────┐  signs   ┌──────┐  signs   ┌──────┐
   │ Key A│─────────►│ Key B│─────────►│ Key C│  ← current signer
   └──────┘          └──────┘          └──────┘
      │                 │                 │
      └── each node carries FLAGS: is the old cert still
          trusted for signature-permissions? for sharedUserId?
```

**Android 13 (API 33)** made `PackageManager.checkSignatures()` rotation-aware, returning
the newest certificate - so same-signer checks survive a rotation.

**v3.1** exists because v3 rotation applied everywhere, which broke compatibility in some
cases (notably where a platform version couldn't handle the rotated key). v3.1 lets you
target rotation at specific SDK versions while the v3 block continues serving older
platforms. `apksigner` exposes this via `--rotation-min-sdk-version`.

> **⚖️ Judge Tip:** Restating the point from [Ch 06 §7](06-certificates.md#7-key-rotation-and-lineage)
> because it is genuinely a differentiator: **v3 lineage is an attribution gift.** An
> adversary who rotates keys publishes a cryptographic link between their old and new
> identity, inside the APK. SUDARSHAN parses the lineage and collapses every key in the chain
> into a single actor node.

---

## 7. v4 - incremental / streaming install

### WHAT

v4 computes a **Merkle hash tree** over the APK (the `fs-verity` structure) and stores the
signature in a **separate file**: `base.apk.idsig`.

### WHY

To enable **Incremental Install** (Android 11+): start running an app before it has finished
downloading. This matters for large games and for `adb install --incremental` in development.
Verification happens **per page, on demand**, as blocks are read - which requires a tree
structure, not a single whole-file digest.

```
                 root hash  ← signed (this is the tiny .idsig)
                /         \
            H(01)          H(23)
           /     \        /     \
        H(0)   H(1)    H(2)   H(3)
         │      │       │      │
      block0 block1  block2 block3     ← verified individually, on read
```

### Practical notes

- **Requires a v2 or v3 signature to also be present.** v4 alone is invalid.
- The `.idsig` is a **separate file** - so it can be lost in transit. If you receive an APK
  without its `.idsig`, v4 simply doesn't apply; v2/v3 still verifies.
- Same Merkle-tree concept as **fs-verity** and **dm-verity**
  ([Ch 04 §7](04-android-security-model.md#7-verified-boot-and-the-hardware-root-of-trust)) - verify-on-read rather than verify-once-upfront.

```bash
$ apksigner sign --ks lab.keystore --v4-signing-enabled true app.apk
$ ls
app.apk  app.apk.idsig
$ adb install --incremental app.apk
```

---

## 8. How verification actually runs

### The order (this is exam material)

```
  PackageInstaller receives APK
            │
            ▼
  Is there an APK Signing Block?
            │
     ┌──────┴───────┐
    YES             NO
     │               │
     ▼               ▼
  v3.1 present? ──► verify, DONE (ignore v3/v2/v1)
     │ no
     ▼
  v3 present?   ──► verify, DONE (ignore v2/v1)
     │ no
     ▼
  v2 present?   ──► verify, DONE (ignore v1)
     │ no
     ▼
  ┌──────────────────────────────────┐
  │ fall back to v1 (META-INF)       │◄─── also the NO branch above
  │  • API ≥ 30: v1-only is REJECTED │
  └──────────────────────────────────┘
            │
            ▼
  Compare signer against installed package's recorded signer (TOFU)
            │
            ▼
  Install / INSTALL_FAILED_UPDATE_INCOMPATIBLE
```

### The subtle, important rule

> **⚙️ Engineering Note:** **If v2/v3 verifies, v1 is not checked at all.** This is why v2+
> structurally kills Janus: the attack depends on v1 being the verification path. It also
> means an APK can carry a *broken or attacker-supplied* v1 signature and still install
> perfectly on modern Android - which is a genuine analysis trap. **Always record which
> schemes verified, not just "signature valid."** `apksigner verify --verbose` prints exactly
> this, and SUDARSHAN should store all five booleans.

Related detail: v2+ verification also enforces **stripping protection** - the v1
`MANIFEST.MF` records that a v2 signature was present, so an attacker cannot simply delete
the signing block and downgrade the APK to v1-only verification on an older device.

---

## 9. The three classic attacks

These three are the "why" behind the entire v2+ design. Every serious Android security
interview touches at least one.

### 9.1 Master Key - Android bug 8219321 (2013)

**The trick:** ZIP files can contain **duplicate filenames**. Android's verifier (Java-based)
processed one instance while the installer (C++-based) extracted the other.

```
  archive:
    classes.dex   ← instance A: original, benign     → VERIFIER reads this ✅
    classes.dex   ← instance B: malicious            → INSTALLER extracts this ☠️
```

**Impact:** modify any app without breaking its v1 signature. Affected essentially all
devices at the time (~99%).

**Root cause:** two parsers disagreeing about the same file. A textbook **parser
differential** vulnerability.

**Fixed:** verifier and installer reconciled; v2 makes it structurally impossible.

### 9.2 Fake ID - CVE-2014-3153-era disclosure (2014)

**The trick:** Android's certificate-chain handling didn't properly verify that each
certificate in a chain was actually signed by its claimed issuer. An app could present a
chain claiming to descend from a privileged certificate (e.g. Adobe's, which had special
webview plugin privileges) without possessing the corresponding key.

**Impact:** privilege escalation by impersonating a privileged signer.

**Root cause:** validating the *claim* of a chain rather than the *cryptography* of it.

**Lesson for you:** this is the concrete proof of the [Ch 06](06-certificates.md) point - certificate *fields* are claims; only the cryptographic chain is evidence.

### 9.3 Janus - CVE-2017-13156 (2017)

The most important one, because it's the most elegant and the most-asked.

**The trick:** a file can be **simultaneously a valid APK (ZIP) and a valid DEX**.

- **ZIP** is parsed from the **end** (locate EOCD, then the central directory). Bytes
  *before* the first local file header are ignored.
- **DEX** is parsed from the **beginning** (magic `dex\n035\0` at offset 0).

So: prepend a malicious DEX to a legitimate APK. ZIP parsers skip the prefix and see the
original, correctly-v1-signed archive. The Dalvik/ART loader, handed the same file, reads it
from offset 0 and sees the attacker's DEX.

```
  ┌────────────────────────────────────────────────┐
  │ malicious DEX  (magic at offset 0)             │ ← ART reads THIS
  ├────────────────────────────────────────────────┤
  │ original APK, untouched:                       │
  │   local headers + data                         │ ← ZIP verifier reads THIS
  │   META-INF/ (v1 signature - STILL VALID) ✅    │
  │   central directory                            │
  │   EOCD                                         │
  └────────────────────────────────────────────────┘
```

**Impact:** replace the code of an installed app **while keeping its v1 signature valid** - so the malicious version installs as a legitimate *update*, inheriting the original app's
package name, its granted permissions, and its data.

**Scope:** Android **5.0 through 8.0**, and **only v1-only APKs**. Reported to Google
**July 31, 2017**; patched in the **December 2017** Android Security Bulletin. Roughly 74%
of devices were affected at disclosure.

**Why v2+ kills it:** v2's digest covers the *entire file*, including any prepended bytes.
Prepend anything and the signature fails immediately.

> **⚖️ Judge Tip:** Janus is the single best story for explaining why v2 exists. The one-line
> version: *"A file can be a valid ZIP and a valid DEX at the same time, because ZIP is
> parsed from the end and DEX from the beginning - so you could prepend malicious code and
> the v1 signature still verified. v2 signs the whole file, so the prefix breaks it. That's
> CVE-2017-13156, patched December 2017, and it only ever affected v1-only APKs."* Precise,
> memorable, and demonstrably from primary sources.

### The pattern across all three

All three are **parser differentials or claim-vs-proof confusion**:

| Attack | Two parties who disagreed |
|---|---|
| Master Key | Verifier vs installer, on duplicate ZIP entries |
| Fake ID | Certificate *claim* vs certificate *cryptography* |
| Janus | ZIP parser (from the end) vs DEX parser (from the start) |

> **🔬 Research Gap / design lesson:** Format ambiguity is the recurring root cause. Any time
> your platform lets two components interpret the same bytes differently, you have a latent
> vulnerability. SUDARSHAN should therefore **record ZIP structural anomalies rather than
> normalising them away** - duplicate entries, mismatched local vs central headers,
> prepended data, oversized extra fields. The anomaly is intelligence.
> → [Ch 08](../apk/08-apk-file-format.md)

---

## 10. Working with signatures: commands

### Verify and inspect

```bash
# The one command to know
$ apksigner verify --verbose --print-certs app.apk

# Just tell me pass/fail, quietly
$ apksigner verify app.apk && echo OK

# Verify as a specific platform version would
$ apksigner verify --min-sdk-version 24 --max-sdk-version 34 app.apk

# Locate the signing block in raw bytes
$ grep -abo "APK Sig Block 42" app.apk

# Extract the v1 certificate directly
$ unzip -p app.apk META-INF/CERT.RSA | openssl pkcs7 -inform DER -print_certs -text | head -30

# Which schemes are present? (Androguard, scriptable)
$ python3 -c "
from androguard.core.bytecodes.apk import APK
a = APK('app.apk')
print('v1', a.is_signed_v1(), 'v2', a.is_signed_v2(), 'v3', a.is_signed_v3())
"
```

### Sign (lab use, authorised testing only)

```bash
$ keytool -genkeypair -v -keystore lab.keystore -alias lab \
    -keyalg RSA -keysize 4096 -validity 10000

# ALIGN FIRST
$ zipalign -p -f 4 unsigned.apk aligned.apk

# THEN SIGN
$ apksigner sign --ks lab.keystore --ks-key-alias lab \
    --v1-signing-enabled true \
    --v2-signing-enabled true \
    --v3-signing-enabled true \
    --out signed.apk aligned.apk

$ apksigner verify --verbose --print-certs signed.apk
```

### Rotate keys

```bash
$ apksigner rotate --out lineage.bin \
    --old-signer --ks old.keystore --ks-key-alias oldkey \
    --new-signer --ks new.keystore --ks-key-alias newkey

$ apksigner sign --ks new.keystore --ks-key-alias newkey \
    --lineage lineage.bin \
    --rotation-min-sdk-version 33 \
    app.apk
```

---

## 11. Detection logic for SUDARSHAN

### Fields to extract on every sample (mandatory)

```yaml
signing:
  verified_v1: bool
  verified_v2: bool
  verified_v3: bool
  verified_v31: bool
  verified_v4: bool          # only if .idsig accompanied the sample
  verification_errors: []
  signers:
    - cert_sha256            # PRIMARY IDENTITY → Ch 06
      spki_sha256
      subject_dn, issuer_dn
      not_before, not_after
      key_algorithm, key_size
  rotation_lineage: [cert_sha256, ...]   # oldest → newest
  signing_block_ids: [0x7109871a, 0xf05368c0, 0x42726577, ...]
  zip_anomalies:
    duplicate_entries: []
    prepended_bytes: int
    local_vs_central_mismatch: bool
    compressed_resources_arsc: bool
```

### Rules

| Rule | Logic | Severity | Confidence | Note |
|---|---|---|---|---|
| **Signature invalid** | any scheme present but failing | High | High | Tampered or corrupt |
| **v1-only APK** | `v1 && !v2 && !v3` | Medium | High | Won't install on API 30+; **Janus-relevant on legacy**; strongly suggests old or deliberately-legacy build |
| **Janus indicator** | DEX magic at offset 0 **and** valid ZIP structure | **Critical** | **High** | Deterministic byte check - cheap and definitive |
| **Duplicate ZIP entries** | central directory has repeated names | High | High | Master-Key-class; also parser-confusion evasion |
| **Prepended data before first local header** | offset of first LFH > 0 | High | High | Janus-class |
| **Local vs central header mismatch** | sizes/CRCs disagree | Medium-High | Medium | Parser-confusion evasion |
| **Signer not in bank registry for a protected package** | see [Ch 06 §11](06-certificates.md#11-detection-logic-for-sudarshan) | **Critical** | **High** | Impersonation |
| **Rotation lineage present** | v3 lineage non-empty | Informational | - | **Expand to actor node**; attribution gain |
| **Unusual signing-block IDs** | IDs outside the known set | Informational | - | Build-pipeline fingerprint |
| **Debug certificate** | `CN=Android Debug` | Medium | High | Sloppy build in the wild |

> **⚙️ Engineering Note - the Janus check is nearly free.** Read the first 8 bytes; if they
> match a DEX magic (`dex\n035\0`, `dex\n037\0`, `dex\n038\0`, `dex\n039\0`) *and* the file
> also parses as a ZIP, you have a Janus-format file. It costs microseconds and it is
> deterministic. Any sample matching this in 2026 is either a museum piece, a deliberate
> test, or an attack aimed at unpatched legacy devices - all three are worth an alert. Put it
> in the intake stage.

### What the scheme profile tells you

| Profile | Interpretation |
|---|---|
| v1 only | Pre-2016 build, or deliberately targeting legacy devices. Cannot install on API 30+. |
| v1 + v2 | Typical 2016–2018 build, or wide-compatibility build |
| v1 + v2 + v3 | Modern standard |
| v2 + v3, no v1 | Modern, minSdk ≥ 24 - very common now |
| v3.1 present | Recent build using SDK-targeted rotation |
| v4 `.idsig` present | Delivered via a channel supporting incremental install |

This profile is a **build-pipeline fingerprint** and a useful weak correlation signal across
samples in a family.

---

## 12. Limitations, edge cases, false positives

### Limitations

- **Signing proves integrity and continuity, not intent.** All malware in this document is
  correctly signed.
- **v4 signatures travel separately** - absence of `.idsig` means nothing about the sample.
- **Play App Signing** means the visible signer is Google's key, not the developer's
  ([Ch 06 §8](06-certificates.md#8-play-app-signing-whose-certificate-are-you-looking-at)).

### Edge cases

| Case | Handling |
|---|---|
| **Multiple signers** | All must verify; record every fingerprint |
| **Expired certificate** | Android does **not** enforce app-signing-cert expiry at install. Not a finding on its own. |
| **v1 signature present but invalid, v2 valid** | **Installs fine.** Record it - an invalid-but-present v1 is anomalous and worth noting. |
| **Split APKs** | Each split is independently signed; all must match the base's signer |
| **APKs > 4 GB / ZIP64** | Rare but legal; ensure your parser handles ZIP64 |
| **`apktool b` output** | Unsigned and v2-invalidated by construction - expected in a lab, not a finding |

### False positives

| Trigger | Innocent cause |
|---|---|
| v1-only | Genuinely old app, or one built for pre-Nougat compatibility |
| Long/odd validity | Google's own guidance is a very long validity period |
| Unknown signing-block IDs | Google Play metadata, dependency metadata, vendor tooling |
| Different signer than the Play build | Third-party mirror or an older non-bundle build |
| Failed signature on a lab-rebuilt sample | You rebuilt it |

> **🚨 Misconception:** "The signature failed, so it's malware." A failed signature means
> *modified or corrupt*. That could be malware, a truncated download, a badly-repacked
> mirror, or your own tooling. Report the **specific** failure (which scheme, which check)
> and its implication - don't collapse it into a verdict.

---

## 13. Engineering tips

1. **Record all five scheme booleans**, not a single "signature valid."
2. **Run the Janus byte check at intake.** Microseconds, deterministic.
3. **Preserve and report ZIP structural anomalies** rather than normalising them.
4. **Match `META-INF/*.{RSA,DSA,EC}`**, not hardcoded `CERT.RSA`.
5. **Align before signing.** v2 signs the whole file.
6. **Expand v3 lineage into your actor graph.**
7. **Use `apksigner`, not `jarsigner`**, for anything modern - `jarsigner` only does v1.
8. **Verify with explicit `--min-sdk-version`** when you care about how a *specific* platform
   version would behave.
9. **Store signing-block IDs** as a build-pipeline fingerprint.

---

## 14. Judge Insights

**What judges ask:** *"Why does Android have four different signature schemes? Isn't one
enough?"*

**Perfect answer:** Each one exists because the previous one had a specific, exploited
weakness. v1 was inherited from JAR signing and signs individual ZIP *entries*, not the
archive - so ZIP metadata and unlisted files were unprotected. That produced Master Key in
2013, where duplicate ZIP filenames let the verifier and the installer read different files,
and Janus in 2017 - CVE-2017-13156 - where you could prepend a malicious DEX to a
correctly-signed APK, because ZIP is parsed from the end and DEX from the beginning, so both
parsers saw a valid file. v2, in Android 7, signs the entire file including the central
directory, which makes both attacks structurally impossible. v3, in Android 9, added key
rotation with a cryptographic proof-of-rotation lineage, solving the "lost or compromised
signing key ends your app" problem. v4, in Android 11, added a Merkle hash tree in a separate
`.idsig` file so an app can be verified page-by-page while it's still downloading - incremental install.

**Common mistakes:**
- "Newer schemes are just faster." They fix specific vulnerabilities.
- Not knowing Janus only affected **v1-only** APKs - the qualifier matters and shows you read
  the advisory rather than a summary.
- Saying v4 replaced v3. It complements it; v4 alone is invalid.

**Follow-ups to expect:**
- *"So can old attacks still work?"* → Only against v1-only APKs on Android 5.0–8.0. Since
  API 30, v1-only won't even install. But we still run the check - it's microseconds and
  legacy devices exist, especially in the emerging markets where a lot of banking fraud
  concentrates.
- *"How does v2 stop Janus specifically?"* → The digest covers the whole file, so prepended
  bytes break it immediately.
- *"What if an attacker strips the v2 block to force v1 verification?"* → v2+ includes
  stripping protection: the v1 manifest records that a v2 signature existed, so downgrade is
  detected.

**Fact that impresses:** The APK Signing Block ends with the magic string
**`APK Sig Block 42`** - a Hitchhiker's Guide reference - and unknown ID-value pairs inside
it are ignored by verifiers but still covered by the signature, which is how Google Play
injects its own metadata under ID `0x42726577` ("Brew") without breaking anything. Those
extra pairs make a usable build-pipeline fingerprint.

---

## 15. Interview Insights

**Q: "Walk me through APK signature schemes v1 to v4."**
Structure it as problem → solution, as in §14. Include the API level each was introduced at
(24, 28, 30), the fact that v1-only is rejected from API 30, and that v4 requires v2/v3
alongside.

**Q: "Explain Janus."**
A file can be a valid ZIP and a valid DEX simultaneously - ZIP is parsed from the end, DEX
from offset 0. Prepend a malicious DEX to a v1-signed APK: the signature verifier sees the
untouched archive and passes; ART loads the prepended DEX. CVE-2017-13156, Android 5.0–8.0,
v1-only, patched December 2017, structurally impossible under v2.

**Q: "Where is the v2 signature stored?"**
In the **APK Signing Block**, which is *not* a ZIP entry - it sits between the last file data
and the central directory, and ends with the magic `APK Sig Block 42`. v2 is ID `0x7109871a`,
v3 is `0xf05368c0`.

**Q: "If v2 verifies, is v1 checked?"**
No. Higher schemes take precedence. This is why v2+ kills Janus, and it's also why an APK can
carry a broken v1 signature and still install cleanly on modern Android.

**Q: "Why must you zipalign before signing?"**
Because v2+ signs the whole file - aligning afterwards changes bytes and invalidates the
signature.

**Q: "What's the difference between `jarsigner` and `apksigner`?"**
`jarsigner` only produces v1 (JAR) signatures. `apksigner` supports v1–v4, key rotation, and
per-SDK verification. Use `apksigner`.

**Beginner mistakes:**
- Saying "the signature proves the app is safe."
- Not knowing the signing block isn't a ZIP entry.
- Signing then aligning.
- Believing Janus still works on modern devices.
- Using `jarsigner` for a modern build.

---

## 16. Cross-references

**Upstream:**
- [← Ch 02 APK Architecture](../apk/02-apk-architecture.md) - build pipeline, repackaging
- [← Ch 06 Certificates](06-certificates.md) - signer identity, fingerprints, TOFU

**Downstream:**
- [→ Ch 08 APK File Format](../apk/08-apk-file-format.md) - the ZIP/DEX byte structures the attacks abuse
- [→ Ch 09 Package Manager](../apk/09-package-manager.md) - where verification runs in the install pipeline
- [→ Ch 11 Static Analysis](../static-analysis/11-static-analysis.md) - automating §11
- [→ Ch 28 Campaign Correlation](../sudarshan/28-campaign-correlation.md) - signer and build-pipeline fingerprints
- [→ Ch 32 Common Misconceptions](../appendix/32-common-misconceptions.md) - certificate ≠ signature ≠ hash

**Related chain:** APK → signing block → v2 digest → whole-file integrity → repackaging
detection → signer correlation.

---

## 17. References

1. AOSP - *Application Signing* (v1/v2/v3/v4 overview). https://source.android.com/docs/security/features/apksigning
2. AOSP - *APK Signature Scheme v2*. https://source.android.com/docs/security/features/apksigning/v2
3. AOSP - *APK Signature Scheme v3*. https://source.android.com/docs/security/features/apksigning/v3
4. AOSP - *APK Signature Scheme v4*. https://source.android.com/docs/security/features/apksigning/v4
5. Android Developers - `apksigner` reference. https://developer.android.com/tools/apksigner
6. Android Developers - `zipalign` reference. https://developer.android.com/tools/zipalign
7. Android Security Bulletin - **December 2017** (CVE-2017-13156, Janus). https://source.android.com/docs/security/bulletin/2017-12-01
8. Guardsquare - Janus vulnerability disclosure and analysis (2017).
9. Trend Micro - Janus vulnerability technical analysis (2017).
10. Bluebox Security - *Master Key* vulnerability (Android bug 8219321) disclosure (2013).
11. Bluebox Security - *Fake ID* vulnerability disclosure (2014).
12. AOSP `tools/apksig/` - reference implementation of signing and verification.
13. Androguard documentation - signature scheme detection APIs. https://androguard.readthedocs.io/
14. Android Developers - *Incremental install* / `adb install --incremental`.

### Further reading
- ZIP APPNOTE (PKWARE) - the underlying archive format specification
- fs-verity documentation (Linux kernel) - the Merkle-tree mechanism behind v4
- OWASP MASTG - code signing verification test cases

---

*Previous: [← Ch 06 Certificates](06-certificates.md) · Next: [Ch 08 APK File Format →](../apk/08-apk-file-format.md)*
