# 24 — Threat Intake

> **Chapter ID:** `CH24` · **Block:** E · **Status:** Stable
> **Tags:** `#intake` `#normalisation` `#safe-extraction` `#dedup` `#sandbox` `#custody` `#zip-slip`
> **Last Updated:** 2026-08-05 · **Version:** 1.0.0
> **Prerequisites:** [Ch 08](../apk/08-apk-file-format.md), [Ch 22](22-building-sudarshan.md), [Ch 23](23-detection-pipeline.md)

---

## Table of Contents

1. [Intake's job — and what it must not do](#1-intakes-job--and-what-it-must-not-do)
2. [Sources and trust levels](#2-sources-and-trust-levels)
3. [Format handling](#3-format-handling)
4. [Safe extraction](#4-safe-extraction)
5. [Identity and hashing](#5-identity-and-hashing)
6. [Deduplication](#6-deduplication)
7. [The artifact record](#7-the-artifact-record)
8. [Priority assignment](#8-priority-assignment)
9. [Sample custody](#9-sample-custody)
10. [The intake API](#10-the-intake-api)
11. [Limitations and edge cases](#11-limitations-and-edge-cases)
12. [Engineering tips](#12-engineering-tips)
13. [Judge Insights](#13-judge-insights)
14. [Interview Insights](#14-interview-insights)
15. [Cross-references](#15-cross-references)
16. [References](#16-references)

---

## 1. Intake's job — and what it must not do

**Job:** turn whatever arrives into a canonical, safely-stored, uniquely-identified artifact
record that the pipeline can process.

**Must not:** analyse it. The moment intake starts interpreting content, it needs the same
sandboxing, the same parsers, and the same failure handling as the analysis tiers — and the
separation that keeps hostile input away from the orchestrator collapses.

```
   ARRIVES                INTAKE                       HANDS OFF
   ───────                ──────                       ─────────
   .apk .xapk .aab   ──►  identify format         ──►  artifact record
   .apks .apkm            explode containers            + object-store ref
   URL, hash, or          hash (SHA-256/1/MD5,          + priority
   device pull            TLSH)                         + tenant + custody
                          extract signer                       │
                          dedup                                ▼
                          assign priority              detection pipeline
                          store under custody               (Ch 23)
```

> **⚙️ Engineering Note — the one rule that matters most in this chapter:** **intake parses
> attacker-controlled bytes.** `unzip`, ZIP parsers, and signature readers have all had
> vulnerabilities. Every parsing step runs in an **ephemeral, network-restricted sandbox with
> resource caps**, never in the API process. If an attacker can crash or exploit your intake,
> they have compromised the platform before analysis even begins.
> → [Ch 22 §9](22-building-sudarshan.md#9-operating-and-safety-constraints)

---

## 2. Sources and trust levels

| Source | Trust | Priority | Notes |
|---|---|---|---|
| **Bank fraud team** (victim device) | High | URGENT/HIGH | Real incident; may carry customer context |
| **SOC / SOAR API** | High | Per request | Automated escalation |
| **Device forensic acquisition** | High | HIGH | Chain of custody applies ([Ch 17](../digital-forensics/17-digital-forensics.md)) |
| **App-store monitoring** | Medium | NORMAL | Impersonation hunting |
| **TI feed / partner** | Medium | BULK | Volume; variable quality |
| **Public repositories** (MalwareBazaar etc.) | Medium | BULK | Corpus enrichment |
| **Anonymous / unauthenticated** | **Low** | BULK, rate-limited | ★ Poisoning risk |

> **⚙️ Engineering Note — provenance is a security control, not metadata.** Two reasons.
> **Poisoning:** unvetted submissions must never feed training data
> ([Ch 21 §6](../ai-malware-analysis/21-ai-assisted-malware-analysis.md#6-adversarial-machine-learning)).
> **Reachback:** when a verdict changes on retro-hunt, you must know who to notify
> ([Ch 18 §6](../soc/18-mobile-threat-hunting.md#6-hunting-the-sample-corpus)). Record source,
> submitter, tenant, and timestamp on every artifact — immutably.

---

## 3. Format handling

| Input | Action |
|---|---|
| `.apk` | Direct artifact |
| **`.xapk` / `.apks` / `.apkm`** | **Explode**; base + splits become one logical analysis unit |
| `.aab` | Publishing format; note it, extract what's analysable |
| `.dex` (bare) | Artifact — commonly a dumped payload ([Ch 12 §5](../dynamic-analysis/12-dynamic-analysis.md#5-the-essential-hook-library)) |
| `.so` | Native library artifact |
| `.zip` / `.7z` / `.rar` | Container — explode, then classify members |
| URL | Fetch **in the sandbox**, with egress logging |
| Hash only | TI DB lookup; no analysis without bytes |
| Non-Android | Reject with a clear reason |

### The split-APK rule

```
  base.apk + split_config.arm64_v8a.apk + split_config.xxhdpi.apk
        │
        ▼
  ONE logical artifact (an "artifact set")
  — signer verified on every member
  — capability vector computed across the union
  — analysing base.apk alone is a KNOWN FALSE-NEGATIVE MODE
```

> **🚨 Misconception:** "The APK is the app." Since App Bundles became mandatory for new Play
> apps in August 2021, an installed app is frequently several APK files, and the code you care
> about may live in a split
> ([Ch 02 §7](../apk/02-apk-architecture.md#7-app-bundles-split-apks-and-why-the-apk-is-a-lie)).
> Intake must model an **artifact set**, not a file.

---

## 4. Safe extraction

Everything from [Ch 08 §3](../apk/08-apk-file-format.md#3-zip-anomalies-and-parser-differentials),
enforced.

```python
import os, zipfile

MAX_ENTRY_BYTES  = 500 * 1024 * 1024
MAX_TOTAL_BYTES  = 2 * 1024 * 1024 * 1024
MAX_ENTRIES      = 50_000
MAX_RATIO        = 200          # compression-bomb guard

def safe_extract(path, dest):
    dest = os.path.realpath(dest)
    total = 0
    anomalies = {"traversal": [], "duplicates": [], "oversized": []}
    with zipfile.ZipFile(path) as z:
        infos = z.infolist()
        if len(infos) > MAX_ENTRIES:
            raise IntakeError("entry_count_exceeded")
        names = [i.filename for i in infos]
        anomalies["duplicates"] = [n for n in set(names) if names.count(n) > 1]
        for info in infos:
            # ★ Zip-Slip: canonicalise and verify containment
            target = os.path.realpath(os.path.join(dest, info.filename))
            if not target.startswith(dest + os.sep):
                anomalies["traversal"].append(info.filename)
                continue                       # RECORD, don't extract
            if info.file_size > MAX_ENTRY_BYTES:
                anomalies["oversized"].append(info.filename); continue
            if info.compress_size and info.file_size / max(info.compress_size,1) > MAX_RATIO:
                anomalies["oversized"].append(info.filename); continue
            total += info.file_size
            if total > MAX_TOTAL_BYTES:
                raise IntakeError("total_size_exceeded")
            z.extract(info, dest)
    return anomalies          # ★ anomalies are FINDINGS, not just guardrails
```

### Anomalies are intelligence

```
   ❌ tolerant extractor: silently "fixes" duplicates and traversal
        → the most important fact about the sample is destroyed

   ✅ strict extractor: refuses, and RECORDS what it refused
        → duplicate entries      → Master-Key-class parser differential
        → path traversal          → Zip-Slip targeting the analysis platform
        → prepended bytes         → Janus check  (Ch 07 §9)
        → extreme ratio           → zip bomb
```

> **⚙️ Engineering Note:** A path-traversal entry in a submitted APK is not just a malformed
> archive — it is plausibly **an attack aimed at your analysis pipeline**. Record it, alert on
> it, and treat repeated occurrences from one source as a signal about that source.

### Sandbox profile

```yaml
extraction_sandbox:
  runtime: ephemeral_container
  filesystem: read_only_except_scratch
  network: none                         # ★ extraction never needs network
  cpu_limit: 2
  memory_limit: 4Gi
  timeout: 60s
  user: non_root
  seccomp: restricted
  destroyed_after_each_artifact: true
```

---

## 5. Identity and hashing

```yaml
identity:
  sha256: "..."          # ★ canonical artifact ID
  sha1: "..."            # feed compatibility
  md5: "..."             # legacy feed compatibility
  tlsh_file: "..."       # fuzzy — whole file
  tlsh_dex: "..."        # ★ fuzzy — DEX only; tracks CODE lineage
  ssdeep: "..."          # legacy fuzzy
  size_bytes: 0
  signer_cert_sha256: "..."     # ★★ PRIMARY IDENTITY (P5)
  signer_spki_sha256: "..."
  signature_schemes: {v1: bool, v2: bool, v3: bool, v31: bool, v4: bool}
  rotation_lineage: []          # v3 proof-of-rotation → Ch 07 §6
```

Two identity concepts, deliberately distinct:

| | Artifact identity | App identity |
|---|---|---|
| Field | `sha256` | `signer_cert_sha256` |
| Answers | "Is this the same file?" | "Is this the same publisher?" |
| Stability | Changes every build | Survives rebuilds |
| Use | Dedup, IOC (short TTL) | **Correlation, impersonation detection** |

> **⚙️ Engineering Note:** Hash the **DEX separately** for TLSH. Whole-APK fuzzy hashes are
> dominated by resources and assets, which differ per campaign (different overlays, different
> icons) even when the code is identical. **DEX-level TLSH tracks code lineage**, which is what
> family clustering actually needs ([Ch 11 §10](../static-analysis/11-static-analysis.md#10-similarity-hashing)).

---

## 6. Deduplication

```
  incoming artifact
        │
        ▼
  SHA-256 seen before?
        │
   ┌────┴─────┐
  yes         no ──► new artifact → full pipeline
   │
   ▼
  Is the cached verdict still valid?
    ruleset_version == current?
    tool_versions == current?
    TTL not expired?
        │
   ┌────┴─────┐
  yes         no
   │           │
   ▼           ▼
 return    ★ RE-ANALYSE (rules changed since)
 cached        │
 verdict       ▼
   │      update cached verdict
   │      → if it CHANGED, notify prior submitters  (Ch 18 §6)
   ▼
  record the new submission event against the SAME artifact
  (different tenant, different time, different context)
```

> **⚙️ Engineering Note — dedup must not lose the submission event.** The same SHA-256 submitted
> by three different banks on three different days is **one artifact and three submissions**, and
> the three submissions are exactly what tells you a campaign is multi-institution. Model them as
> separate entities: `artifact` (immutable, hash-keyed) and `submission` (append-only, with
> tenant, source, timestamp, and context).

---

## 7. The artifact record

```yaml
artifact:
  id: "art_01J8..."
  sha256: "..."
  identity: { ... }                     # §5
  format:
    type: apk | dex | so | aab | container
    artifact_set_id: "set_..."          # splits grouped
    members: [{name, sha256, role: base|split_config|...}]
  storage:
    object_key: "samples/ab/cd/<sha256>"
    encrypted: true
    size_bytes: 0
  provenance:                            # ★ immutable
    first_seen_utc: "..."
    submissions:                         # append-only
      - {tenant, source, submitter, ts_utc, context, priority_requested}
  lineage:                               # ★ recursion (P6)
    parent_artifact_id: null
    derivation: null | dumped_from_classloader | installed_by | extracted_from_container
    depth: 0
  intake_findings:                       # ★ anomalies as findings
    zip_anomalies: {duplicates: [], traversal: [], prepended_bytes: 0}
    janus_shape: false                   # DEX magic at offset 0 + valid ZIP
    extraction_errors: []
  custody:
    tenant_id: "..."
    classification: malicious_sample
    retention_until: "..."
    chain_of_custody_ref: null           # set when forensically acquired
  priority: urgent | high | normal | bulk
  state: queued | analysing | complete | failed
```

---

## 8. Priority assignment

```yaml
priority_rules:
  urgent:                                # SLA 10s first result → Ch 23 §4
    - source == fraud_team AND context.active_fraud == true
    - source == soc_api AND requested_priority == urgent
  high:
    - source == device_forensics
    - identity.signer_cert_sha256 IN ti.malicious_signers     # ★ known-bad signer
    - claimed_package IN client_registry AND signer NOT IN canonical_signers[package]
      # ★ impersonation — detectable AT INTAKE, before any analysis
  normal:
    - source IN [app_store_monitoring, manual_submission]
  bulk:
    - source IN [ti_feed, public_repo, corpus_backfill]
    - source == anonymous          # + rate limiting
```

> **⚙️ Engineering Note — the impersonation check runs at intake, not in analysis.** Extracting
> the signer certificate takes milliseconds and requires no decompilation. If the artifact claims
> a protected package name with a non-canonical signer, that is a **critical finding available
> before the sample enters the pipeline at all**
> ([Ch 06 §11](../security/06-certificates.md#11-detection-logic-for-sudarshan)). Emit it
> immediately and escalate priority. It is the fastest high-confidence detection in the system.

---

## 9. Sample custody

Handling live malware carries obligations.

| Control | Implementation |
|---|---|
| **Encryption at rest** | Per-tenant keys; object store encrypted |
| **Access logging** | Every read logged with actor and purpose |
| **No accidental execution** | Stored without executable permissions; never on a general-purpose host |
| **Password-protected export** | Standard `infected` convention for any analyst download |
| **Retention** | Policy-driven; deletion honoured across replicas |
| **Tenant isolation** | Bank A cannot read bank B's samples — hard boundary |
| **Chain of custody** | Preserved when forensically acquired ([Ch 17 §9](../digital-forensics/17-digital-forensics.md#9-chain-of-custody-and-legal-context)) |
| **Legal/export** | Malware handling and cross-border transfer reviewed with counsel |

> **🏛️ Enterprise Insight:** A bank's own security team will audit this before deployment.
> Storing live banking trojans on infrastructure the bank contracts for is a governance question
> as much as a technical one. Have documented answers on encryption, retention, access control,
> tenant isolation, and deletion **before** the first procurement conversation — not during it.

---

## 10. The intake API

```http
POST /api/v1/artifacts
Authorization: Bearer <tenant_token>
Content-Type: multipart/form-data

file=@suspicious.apk
priority=urgent
context={"case_id":"INC-2026-0805-014","active_fraud":true,
         "customer_ref":"<pseudonymised>","device_ref":"<pseudonymised>"}
```

```json
{
  "artifact_id": "art_01J8...",
  "sha256": "...",
  "state": "queued",
  "deduplicated": false,
  "priority": "urgent",
  "immediate_findings": [
    {
      "rule": "SIGNER_IMPERSONATION",
      "severity": "critical",
      "confidence": "high",
      "detail": "claims com.clientbank.app; signer 9f2a…c104 not in canonical registry",
      "evidence": {"field": "signer_cert_sha256", "expected": ["3a1f…b92c"]}
    }
  ],
  "stream_url": "/api/v1/artifacts/art_01J8.../events",
  "eta_first_result_seconds": 10
}
```

> **⚙️ Engineering Note:** `immediate_findings` on the intake response is deliberate. The signer
> impersonation check and the Janus byte check both complete in milliseconds; returning them
> synchronously means the caller can act **before the analysis has started**. In an active fraud
> case those milliseconds are worth having.

> **🏛️ Enterprise Insight:** Note `customer_ref` is pseudonymised. Intake should accept a
> tenant-side reference token, not customer PII — SUDARSHAN doesn't need to know who the customer
> is to analyse the APK, and not holding the identifier is the cleanest DPDP posture
> ([Ch 17 §9](../digital-forensics/17-digital-forensics.md#9-chain-of-custody-and-legal-context)).

---

## 11. Limitations and edge cases

| Case | Handling |
|---|---|
| Corrupt/truncated file | Reject with a specific reason; record — truncation can be deliberate |
| Password-protected archive | Accept a password parameter; otherwise reject clearly |
| Nested containers | Explode with a depth cap (3); record depth |
| Same file, different splits | Artifact set identity is the ordered member hash set |
| Very old APK (v1-only) | Accept; note it won't install on API 30+ ([Ch 07 §2](../security/07-apk-signing.md#2-the-scheme-matrix)) |
| Legitimate app submitted | Analyse normally; a benign verdict is a valid, useful outcome |
| Submission spam | Rate limits per tenant/source; anonymous heavily throttled |
| Cross-border transfer | Data-residency constraints may require regional processing |

> **🚨 Misconception:** "Intake is plumbing." Intake is where **identity, provenance, custody,
> and the fastest detection in the system** are established. Get the artifact/submission
> distinction wrong, or the signer extraction wrong, and every downstream capability —
> correlation, retro-hunt notification, impersonation detection — is degraded. It is the highest
> leverage-per-line code in the platform.

---

## 12. Engineering tips

1. **Never parse untrusted input outside the sandbox.**
2. **Record extraction anomalies as findings**, not as warnings.
3. **Model artifact sets**, not files — splits are one logical unit.
4. **Separate `artifact` from `submission`.** Dedup must not lose the event.
5. **Extract the signer at intake** and run the impersonation check immediately.
6. **TLSH the DEX separately** from the whole file.
7. **Version cached verdicts** with ruleset and tool versions; re-run when stale.
8. **Notify prior submitters when a verdict changes.**
9. **Accept pseudonymised customer references**, never PII.
10. **Have the custody story documented before procurement.**

---

## 13. Judge Insights

**What judges ask:** *"What's actually hard about accepting a file upload?"*

**Perfect answer:** Three things, and they're all security-critical. First, intake parses
attacker-controlled bytes — `unzip` and ZIP parsers have real vulnerabilities, so every parsing
step runs in an ephemeral, network-isolated sandbox with resource caps. A submitted APK with a
path-traversal entry name isn't just malformed; it's plausibly Zip-Slip aimed at our own
platform, so we record it as a finding rather than silently normalising it away. Second, identity
— the file hash identifies a file, but the *app* identity is the signer certificate, and getting
that distinction wrong breaks correlation, impersonation detection, and retro-hunt notification
downstream. Third, and this is the one people miss, the fastest detection in the whole system
runs here: extracting the signer takes milliseconds, so if a sample claims a client bank's
package name with a certificate outside their canonical registry, we return a critical finding
**synchronously on the upload response**, before analysis has even started.

**Common mistakes:**
- Treating intake as plumbing. It establishes identity, provenance, custody, and the fastest
  detection.
- Using a tolerant extractor that "helpfully" fixes anomalies — destroying the most important
  fact about the sample.
- Deduplicating by hash and losing the submission event, which is what reveals multi-bank
  campaigns.

**Follow-ups to expect:**
- *"What if the same file is submitted twice?"* → One artifact, two submissions. We return the
  cached verdict but record the new submission, because the same sample arriving from three banks
  is exactly the signal that a campaign is multi-institution. And if the ruleset has changed since
  the cached verdict, we re-analyse rather than serve a stale answer.
- *"How do you handle split APKs?"* → As one logical artifact set. Analysing `base.apk` alone is
  a known false-negative mode, because since App Bundles became mandatory in 2021 the interesting
  code may live in a split.
- *"Where do you store live malware?"* → Encrypted per-tenant, access-logged, never on an
  executable path, with retention policy and hard tenant isolation. A bank's own security team
  audits this before deployment, so we have the answers documented before procurement.

**Fact that impresses:** Extraction anomalies are intelligence, not just guardrails. Duplicate ZIP
entries are the Master Key class of parser differential; a DEX magic at offset zero on a valid ZIP
is the Janus shape; a `../` in an entry name is Zip-Slip aimed at the analysis platform itself. A
tolerant extractor silently discards all three — which is why we use a strict one and record what
it refused.

---

## 14. Interview Insights

**Q: "How would you safely extract an untrusted archive?"**
Canonicalise every target path and verify containment (Zip-Slip), cap per-entry size, total size,
entry count, and compression ratio (zip bombs), run in an ephemeral non-root sandbox with no
network, and **record anomalies rather than silently correcting them**.

**Q: "How do you deduplicate samples?"**
By SHA-256, but keep `artifact` and `submission` as separate entities so repeat submissions are
retained. Also version cached verdicts by ruleset and tool version, and re-analyse when stale.

**Q: "Why hash the DEX separately?"**
Whole-APK fuzzy hashes are dominated by resources and assets, which vary per campaign. DEX-level
TLSH tracks code lineage, which is what family clustering needs.

**Q: "What's the fastest detection you can do?"**
Extract the signer certificate — milliseconds, no decompilation — and compare against a canonical
registry of expected signers per protected package name. Deterministic, near-zero false positives,
and available on the upload response.

**Q: "What could go wrong accepting files from many banks?"**
Poisoning of training data from unvetted sources, tenant data leakage, submission spam, and
malware custody obligations. Provenance is a security control, not metadata.

**Beginner mistakes:**
- Extracting outside a sandbox.
- Using a tolerant parser and losing anomalies.
- Conflating file hash with app identity.
- Treating split APKs as independent files.
- Caching verdicts without a ruleset version.

---

## 15. Cross-references

**Upstream:** [Ch 08 §3](../apk/08-apk-file-format.md#3-zip-anomalies-and-parser-differentials) ·
[Ch 06](../security/06-certificates.md) · [Ch 22 §9](22-building-sudarshan.md#9-operating-and-safety-constraints) ·
[Ch 23 §4](23-detection-pipeline.md#4-priority-lanes-and-slas)

**Downstream:** [Ch 25](25-investigation-engine.md) · [Ch 27](27-risk-scoring.md) ·
[Ch 30](../threat-intelligence/30-threat-intelligence-database.md)

---

## 16. References

1. Snyk — *Zip Slip* archive path-traversal research.
2. PKWARE — *.ZIP File Format Specification* (APPNOTE.TXT).
3. AOSP — *Application Signing*. https://source.android.com/docs/security/features/apksigning
4. TLSH — Trend Micro Locality Sensitive Hash. https://github.com/trendmicro/tlsh
5. Android Developers — *Android App Bundle* and split APKs. https://developer.android.com/guide/app-bundle
6. Digital Personal Data Protection Act, 2023 (India) — data minimisation.
7. MalwareBazaar / abuse.ch — sample-sharing conventions (password-protected export).

---

*Previous: [← Ch 23 Detection Pipeline](23-detection-pipeline.md) · Next: [Ch 25 Investigation Engine →](25-investigation-engine.md)*
