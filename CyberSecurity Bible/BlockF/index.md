# SUDARSHAN Engineering Knowledge Base

> **The definitive internal engineering documentation for SUDARSHAN - an AI-powered
> enterprise Android malware investigation platform for banks.**

> **Version:** 1.5.0 · **Last Updated:** 2026-08-05 · **Status:** ✅ **ALL 38 CHAPTERS COMPLETE** (00–37)

---

## Start here

| If you are… | Read this path |
|---|---|
| **New to the team** | [Ch 00 Introduction](00-introduction.md) → Block A in order → Block B → Block E |
| **Holding an APK right now** | [Ch 33 Cheat Sheets](appendix/33-cheat-sheets.md) → [Ch 11](static-analysis/11-static-analysis.md) → [Ch 12](dynamic-analysis/12-dynamic-analysis.md) |
| **Presenting to judges** | [Ch 32 Misconceptions](appendix/32-common-misconceptions.md) → [Ch 34 Judge Prep](appendix/34-judge-preparation.md) → Quick Revision Guide |
| **Interviewing** | [Ch 35 Interview Prep](appendix/35-interview-preparation.md) + the *Interview Insights* section at the end of every chapter |
| **Designing the platform** | [Ch 22 Building SUDARSHAN](sudarshan/22-building-sudarshan.md) → Ch 23–30 |

---

## The Master Lifecycle

Every chapter plugs into this spine. See [Ch 00 §4](00-introduction.md#4-the-master-lifecycle)
for the full version.

```
 APK → Download → PackageInstaller → Signature Verification → Certificate Validation
   → Installation → Permissions → ART Runtime → Execution → Malicious Behaviour
 ══════════════════════════ investigation begins ═════════════════════════════
   → Static Analysis → Dynamic Analysis → Threat Intelligence → IOC Extraction
   → Risk Scoring → Investigation Report → SOC Response → Incident Response
```

---

## Chapter index

### Block A - Foundations ✅ **Complete**

| # | Chapter | Purpose | Tags |
|---|---|---|---|
| 00 | [Introduction](00-introduction.md) | Conventions, Master Lifecycle, Ten Perspectives | `#introduction` `#conventions` |
| 01 | [Android Internals](android/01-android-internals.md) | Stack, Zygote, Binder, components, storage | `#internals` `#binder` `#zygote` |
| 02 | [APK Architecture](apk/02-apk-architecture.md) | Anatomy, build pipeline, bundles, identity | `#apk` `#manifest` `#aab` |
| 03 | [Android Runtime](android/03-android-runtime.md) | ART, dexopt, class loaders, reflection, JNI | `#art` `#dynamic-code-loading` |
| 04 | [Android Security Model](security/04-android-security-model.md) | Sandbox, SELinux, permissions, version gates | `#security-model` `#permissions` |
| 05 | [Android Cryptography](security/05-android-cryptography.md) | Keystore, TEE/StrongBox, attestation, pinning | `#keystore` `#crypto-misuse` |
| 06 | [Certificates](security/06-certificates.md) | X.509, TOFU, fingerprints, identity | `#certificates` `#identity` |
| 07 | [APK Signing](security/07-apk-signing.md) | v1–v4, rotation, Janus / Master Key / Fake ID | `#apk-signing` `#janus` |
| 08 | [APK File Format](apk/08-apk-file-format.md) | ZIP, AXML, `resources.arsc`, DEX at byte level | `#file-format` `#dex` |
| 09 | [Package Manager](apk/09-package-manager.md) | Install pipeline, sessions, droppers | `#package-manager` `#droppers` |

### Block B - Analysis Craft ✅ **Complete**

| # | Chapter | Purpose | Tags |
|---|---|---|---|
| 10 | [Reverse Engineering](reverse-engineering/10-reverse-engineering.md) | apktool, jadx, smali, packers, unpacking, native RE | `#jadx` `#smali` `#packers` |
| 11 | [Static Analysis](static-analysis/11-static-analysis.md) | Tiered pipeline, MobSF, YARA, capability extraction | `#mobsf` `#yara` `#pipeline` |
| 12 | [Dynamic Analysis](dynamic-analysis/12-dynamic-analysis.md) | Frida, detonation, evasion, network + memory | `#frida` `#detonation` `#evasion` |

### Block C - The Adversary ✅ **Complete**

| # | Chapter | Purpose | Tags |
|---|---|---|---|
| 13 | [Android Malware](malware/13-android-malware.md) | a11y abuse, overlays, OTP theft, VNC, anti-removal | `#accessibility-abuse` `#overlay` |
| 14 | [Banking Malware](banking-malware/14-banking-malware.md) | ODF/DTO, 25+ family profiles, lineages, India/UPI | `#odf` `#families` `#upi` |
| 15 | [Malware Infrastructure](malware/15-malware-infrastructure.md) | C2, MaaS, Zombinder, pivoting, mule chains | `#c2` `#maas` `#pivoting` |
| 16 | [Threat Intelligence](threat-intelligence/16-threat-intelligence.md) | ATT&CK Mobile, Pyramid of Pain, STIX, attribution | `#mitre` `#stix` `#attribution` |

### Block D - Operations ✅ **Complete**

| # | Chapter | Purpose | Tags |
|---|---|---|---|
| 17 | [Digital Forensics](digital-forensics/17-digital-forensics.md) | Acquisition, BFU/AFU, artifacts, timeline, custody | `#forensics` `#bfu-afu` |
| 18 | [Mobile Threat Hunting](soc/18-mobile-threat-hunting.md) | PEAK/TaHiTI, hunt playbooks, retro-hunting | `#threat-hunting` `#peak` |
| 19 | [Enterprise SOC Operations](soc/19-enterprise-soc-operations.md) | Tiers, SIEM/SOAR, MTD, detection engineering | `#soc` `#detection-engineering` |
| 20 | [Incident Response](incident-response/20-incident-response.md) | Two-track IR, remediation runbook, CERT-In | `#incident-response` `#picerl` |
| 21 | [AI-assisted Analysis](ai-malware-analysis/21-ai-assisted-malware-analysis.md) | ML, drift, LLM triage, explainability | `#ml` `#llm` `#explainability` |

### Block E - Building SUDARSHAN ✅ **Complete**

| # | Chapter | Purpose | Tags |
|---|---|---|---|
| 22 | [Building SUDARSHAN](sudarshan/22-building-sudarshan.md) | Principles P1–P9, architecture, non-goals, staging | `#architecture` `#principles` |
| 23 | [Detection Pipeline](sudarshan/23-detection-pipeline.md) | Tiering, gating, SLAs, partial results | `#pipeline` `#sla` |
| 24 | [Threat Intake](sudarshan/24-threat-intake.md) | Safe extraction, dedup, artifact records | `#intake` `#sandbox` |
| 25 | [Investigation Engine](sudarshan/25-investigation-engine.md) | Artifact graph, recursion, evidence ledger, sweep | `#graph` `#recursion` |
| 26 | [IOC Extraction](sudarshan/26-ioc-extraction.md) | Typed indicators, TTLs, action classes | `#ioc` `#ttl` |
| 27 | [Risk Scoring](sudarshan/27-risk-scoring.md) | Two axes, cluster gate, confidence ceiling | `#scoring` `#calibration` |
| 28 | [Campaign Correlation](sudarshan/28-campaign-correlation.md) | Pivot hierarchy, clustering, leaked-source problem | `#correlation` `#clustering` |
| 29 | [Investigation Reports](sudarshan/29-investigation-reports.md) | Five audiences, evidence linking, regulatory pack | `#reporting` `#regulatory` |
| 30 | [Threat Intelligence Database](threat-intelligence/30-threat-intelligence-database.md) | Schema, aliases, provenance, retro-hunt | `#ti-database` `#retro-hunt` |

### Block F - Reference ✅ **Complete**

| # | Chapter | Purpose | Tags |
|---|---|---|---|
| 31 | [Future Research](appendix/31-future-research.md) | 22 consolidated open problems, ranked by tractability | `#research-gaps` |
| 32 | [Common Misconceptions](appendix/32-common-misconceptions.md) | 29 misconceptions with **origins** and consequences | `#misconceptions` |
| 33 | [Cheat Sheets](appendix/33-cheat-sheets.md) | Commands, tables, runbooks, numbers | `#cheatsheet` |
| 34 | [Judge Preparation](appendix/34-judge-preparation.md) | Demo choreography, archetypes, recovery | `#judges` `#demo` |
| 35 | [Interview Preparation](appendix/35-interview-preparation.md) | Role tracks, frameworks, 48h revision plan | `#interview` |
| 36 | [Glossary](appendix/36-glossary.md) | Terms and acronyms, cross-referenced | `#glossary` |
| 37 | [References](appendix/37-references.md) | Consolidated bibliography + source-quality caveats | `#references` |

---

## Directory structure

```
/docs
  index.md                    ← you are here
  README.md
  00-introduction.md
  /android      01-android-internals.md · 03-android-runtime.md
  /apk          02-apk-architecture.md · 08-apk-file-format.md · 09-package-manager.md
  /security     04-android-security-model.md · 05-android-cryptography.md
                06-certificates.md · 07-apk-signing.md
  /reverse-engineering   10-reverse-engineering.md
  /static-analysis       11-static-analysis.md
  /dynamic-analysis      12-dynamic-analysis.md
  /malware               13-android-malware.md · 15-malware-infrastructure.md
  /banking-malware       14-banking-malware.md
  /threat-intelligence   16-threat-intelligence.md · 30-* (Block E)
  /digital-forensics     17-digital-forensics.md
  /soc                   18-mobile-threat-hunting.md · 19-enterprise-soc-operations.md
  /incident-response     20-incident-response.md
  /ai-malware-analysis   21-ai-assisted-malware-analysis.md
  /sudarshan             22-building-sudarshan.md … 29-investigation-reports.md
  /appendix              31-future-research.md … 37-references.md

/knowledge-cards         one concept per file, <3 min read each
```

---

## Concept map - Block A

```
                      ┌─────────────────┐
                      │  Ch 01 Internals│
                      │  Zygote · Binder│
                      └────────┬────────┘
                               │
          ┌────────────────────┼────────────────────┐
          ▼                    ▼                    ▼
  ┌───────────────┐   ┌─────────────────┐   ┌──────────────┐
  │ Ch 02 APK     │   │ Ch 03 Runtime   │   │ Ch 04 Security│
  │ Architecture  │   │ ART · loaders   │   │ Model         │
  └───┬───────┬───┘   └────────┬────────┘   └───┬──────┬────┘
      │       │                │                │      │
      ▼       ▼                ▼                ▼      ▼
 ┌────────┐ ┌──────────┐  (dynamic code   ┌────────┐ ┌──────────┐
 │ Ch 08  │ │ Ch 06    │   loading breaks │ Ch 05  │ │ version  │
 │ Format │ │ Certs    │   static analysis)│ Crypto │ │ gates    │
 └───┬────┘ └────┬─────┘                  └────────┘ └────┬─────┘
     │           │                                        │
     └─────┬─────┘                                        │
           ▼                                              │
     ┌──────────┐                                         │
     │ Ch 07    │                                         │
     │ Signing  │                                         │
     └────┬─────┘                                         │
          │                                               │
          └────────────────┬──────────────────────────────┘
                           ▼
                  ┌────────────────┐
                  │ Ch 09 Package  │  ← everything converges at install
                  │ Manager        │
                  └────────────────┘
```

---

## Concept map - Block B

```
        ┌──────────────────────────────────────────────┐
        │  Ch 11 STATIC ANALYSIS  (100% of samples)    │
        │  Tier 0 structural → Tier 1 capability       │
        │  → Tier 2 resources → Tier 3 code            │
        └───────────────────┬──────────────────────────┘
                            │ escalation gate
                 ┌──────────┴──────────┐
                 ▼                     ▼
   ┌──────────────────────┐  ┌────────────────────────┐
   │ Ch 12 DYNAMIC (~5%)  │  │ Ch 10 REVERSE ENG (<1%)│
   │ detonate · hook ·    │◄─┤ unpack · native RE ·   │
   │ dump · capture C2    │  │ understand logic       │
   └──────────┬───────────┘  └───────────┬────────────┘
              │                          │
              │  dumped DEX / installed  │  YARA rules,
              │  APK → RECURSE ──────────┘  API patterns,
              │                             MITRE mappings
              ▼                                  │
        back into Ch 11 ◄────────────────────────┘
        (the loop that makes the platform compound)
```

**The Block B thesis:** static is blind to what wasn't shipped; dynamic is blind to what didn't
run. Their blind spots are complementary, so fusion is mandatory - see
[Ch 12 §1](dynamic-analysis/12-dynamic-analysis.md#1-why-dynamic-analysis-exists).

---

## Concept map - Block C

```
   DELIVERY ──► DROPPER ──► ★ ACCESSIBILITY ──► self-escalation
   (Ch 15)      (Ch 09)        (Ch 13)              │
                                                     ▼
                          ┌──────────┬──────────┬──────────┐
                          ▼          ▼          ▼          ▼
                       OVERLAY   KEYLOG    OTP THEFT   HIDDEN VNC
                          └──────────┴──────────┴──────────┘
                                        │
                                        ▼
                            ODF / DTO  ──► ATS or live operator
                                (Ch 14)         │
                                                ▼
                                       MULE CHAINS (Ch 15)
                                                │
   ═══════════════════ defender side ═══════════╪═════════════════
                                                ▼
                        INFRASTRUCTURE PIVOTING (Ch 15)
                        signer › key › code › protocol › domain › IP › hash
                                                │
                                                ▼
                        THREAT INTELLIGENCE (Ch 16)
                        ATT&CK mapping · Pyramid of Pain · IOC TTLs
                                                │
                                ┌───────────────┼───────────────┐
                                ▼               ▼               ▼
                           TACTICAL       OPERATIONAL      STRATEGIC
                           (SIEM/MTD)     (SOC/fraud)      (CISO/board)
```

**The Block C thesis:** accessibility abuse is the hinge of the entire playbook, and detection
should target the **top of the Pyramid of Pain** - behaviour and capability clusters - because
hashes and IPs cost the adversary nothing to change.

---

## Concept map - Block D

```
   VICTIM DEVICE                          SAMPLE CORPUS + TELEMETRY
        │                                          │
        ▼                                          ▼
  ┌──────────────┐                        ┌──────────────────┐
  │ Ch 17        │                        │ Ch 18            │
  │ FORENSICS    │                        │ THREAT HUNTING   │
  │ isolate →    │                        │ hypothesis →     │
  │ acquire →    │                        │ hunt → RULE      │
  │ TIMELINE     │                        └────────┬─────────┘
  └──────┬───────┘                                 │
         │                                         ▼
         │                              ┌──────────────────────┐
         │                              │ Ch 19 SOC            │
         │                              │ SIEM/SOAR · triage · │
         │                              │ detection engineering│
         │                              └────────┬─────────────┘
         └────────────────┬───────────────────────┘
                          ▼
              ┌───────────────────────────┐
              │ Ch 20 INCIDENT RESPONSE   │
              │ TRACK 1: contain (minutes)│  ★ money clock
              │ TRACK 2: investigate (hrs)│
              └───────────┬───────────────┘
                          │
                          ▼
              ┌───────────────────────────┐
              │ Ch 21 AI ASSISTANCE       │
              │ deterministic = VERDICT   │
              │ ML = priority · LLM = prose│
              └───────────────────────────┘
```

**The Block D thesis:** containment runs on a *minutes* clock while investigation runs on an
*hours* clock, so they must be **two parallel tracks with different confidence bars** - and the
verdict must stay deterministic and evidence-linked, because a bank has to defend it to a
regulator.

---

## Concept map - Block E

```
   SOURCES ──► ① INTAKE (Ch 24) ──► ② PIPELINE (Ch 23) ──► ③ ENGINE (Ch 25)
               safe extraction      T0→T5 gated by cost      artifact graph
               signer @ intake ★    partial streaming        RECURSION ★
                                                             evidence ledger
                                            │
                        ┌───────────────────┼───────────────────┐
                        ▼                   ▼                   ▼
                 ④ IOC (Ch 26)      ⑤ CORRELATION (28)   ⑥ TI DB (Ch 30)
                 typed + TTL'd      pivot hierarchy       provenance
                 action classes     leaked-source flag    retro-hunt ★
                        └───────────────────┼───────────────────┘
                                            ▼
                                  ⑦ SCORING (Ch 27)
                                  severity × confidence
                                  cluster gate · CEILING ★
                                            │
                                            ▼
                                  ⑧ REPORTS (Ch 29)
                        SOC · fraud ops · CISO · regulatory · customer
```

**The Block E thesis:** every verdict is **evidence-linked and reproducible**, and the system
**refuses to claim cleanliness on samples it could not analyse**. Those two properties (P3 + P4)
are what make the output usable by a regulated institution.

---

## Conventions

Defined fully in [Ch 00 §6](00-introduction.md#6-conventions-used-everywhere).

| Callout | Meaning |
|---|---|
| ⚙️ **Engineering Note** | Practical detail that will bite you in code |
| 🏛️ **Enterprise Insight** | Why a bank, regulator, or SOC lead cares |
| ⚖️ **Judge Tip** | What impresses in demo Q&A |
| 🚨 **Misconception** | A widely believed wrong thing |
| 🔬 **Research Gap** | Genuinely unsolved - don't claim we solved it |

**Version-gated claims** are always written as *"Android 14 (API 34)+"*, never "modern
Android." **Malware family names** carry the naming vendor on first use per chapter, because
vendor naming diverges.

---

## Versioning

Each file carries `Version: MAJOR.MINOR.PATCH` and `Last Updated`. Bump MINOR when adding a
section, PATCH for corrections, MAJOR on structural change. **Threat-intel content ages
fastest** - anything in Blocks C and D older than 12 months should be re-verified before use.

---

*See also: [README](README.md) · [Knowledge Cards](../knowledge-cards/)*
