# 22 - Building SUDARSHAN

> **Chapter ID:** `CH22` · **Block:** E (Building SUDARSHAN) · **Status:** Stable
> **Tags:** `#architecture` `#principles` `#roadmap` `#non-goals` `#staging` `#design`
> **Last Updated:** 2026-08-05 · **Version:** 1.0.0
> **Prerequisites:** Blocks A–D

---

## Table of Contents

1. [The problem statement](#1-the-problem-statement)
2. [The nine design principles](#2-the-nine-design-principles)
3. [System architecture](#3-system-architecture)
4. [Component responsibilities](#4-component-responsibilities)
5. [The data model](#5-the-data-model)
6. [Technology choices](#6-technology-choices)
7. [Non-goals](#7-non-goals)
8. [Staging roadmap](#8-staging-roadmap)
9. [Operating and safety constraints](#9-operating-and-safety-constraints)
10. [Limitations and honest positioning](#10-limitations-and-honest-positioning)
11. [Engineering tips](#11-engineering-tips)
12. [Judge Insights](#12-judge-insights)
13. [Interview Insights](#13-interview-insights)
14. [Cross-references](#14-cross-references)
15. [References](#15-references)

---

## 1. The problem statement

Written precisely, because a vague problem statement produces a vague product.

> A bank's fraud team receives an Android APK - pulled from a victim's device, flagged by a
> threat feed, or found impersonating the bank's own app. They must answer, **inside the fraud
> response window**:
>
> 1. Is it malicious, and how confident are we?
> 2. What does it do to *our* customers?
> 3. **Is our bank specifically targeted?**
> 4. Is this part of a campaign we've seen?
> 5. Which of our customers have it installed?
> 6. What do we do in the next thirty minutes?
> 7. Can we defend every one of those answers to a regulator?

Today that takes a human analyst hours, isn't reproducible, doesn't scale, and produces a
document nobody can audit six months later.

### The constraints that shape everything

| Constraint | Source | Consequence |
|---|---|---|
| **Funds disperse in minutes** | [Ch 15 §10](../malware/15-malware-infrastructure.md#10-the-money-side-mule-chains) | SLAs measured in minutes, partial results streamed |
| **Verdicts must be explainable** | [Ch 21 §10](../ai-malware-analysis/21-ai-assisted-malware-analysis.md#10-explainability-for-regulated-banks) | Deterministic scoring, evidence pointers |
| **Static alone is blind; dynamic alone is blind** | [Ch 12 §1](../dynamic-analysis/12-dynamic-analysis.md#1-why-dynamic-analysis-exists) | Fusion is mandatory |
| **Analysis cost spans 4 orders of magnitude** | [Ch 11 §2](../static-analysis/11-static-analysis.md#2-the-tiered-pipeline) | Tiered gating |
| **The SOC and fraud ops are different teams** | [Ch 19 §8](../soc/19-enterprise-soc-operations.md#8-the-bank-soc--fraud-ops-relationship) | Dual-audience output, shared case ID |
| **Customer data is regulated (DPDP)** | [Ch 17 §9](../digital-forensics/17-digital-forensics.md#9-chain-of-custody-and-legal-context) | Data minimisation by design |
| **CERT-In: 6 hours from noticing** | [Ch 20 §11](../incident-response/20-incident-response.md#11-regulatory-reporting) | Immutable detection timestamps |

---

## 2. The nine design principles

Each one is a conclusion from Blocks A–D, not a preference.

### P1 - No single signal is a verdict
Not a permission, not obfuscation, not a VirusTotal count, not root detection. Scoring operates
on **capability clusters** with corroboration.
*Source: [Ch 04 §11](../security/04-android-security-model.md#11-detection-logic-for-sudarshan), [Ch 32](../appendix/32-common-misconceptions.md)*

### P2 - Confidence and severity are separate axes
"Definitely bad" and "possibly very bad" are different rows in a queue and warrant different
actions.
*Source: [Ch 16 §8](../threat-intelligence/16-threat-intelligence.md#8-iocs-types-quality-lifecycle)*

### P3 - Every point of score traces to an artifact
File path, line number, log offset, timestamp. A regulator can verify it; a model score cannot.
*Source: [Ch 21 §10](../ai-malware-analysis/21-ai-assisted-malware-analysis.md#10-explainability-for-regulated-banks)*

### P4 - Analysis quality caps confidence
Packed and un-unpacked, or C2 unreachable, means **inconclusive** - never clean. Inability to
analyse is an escalation trigger, not a silent pass.
*Source: [Ch 10 §13](../reverse-engineering/10-reverse-engineering.md#13-detection-logic-for-sudarshan), [Ch 12 §9](../dynamic-analysis/12-dynamic-analysis.md#9-sandbox-evasion)*

### P5 - Identity is the signer, never the package name or hash
Signer certificate SHA-256 is the primary index. Hashes are IOCs with short TTLs.
*Source: [Ch 06 §9](../security/06-certificates.md#9-certificate--signature--hash)*

### P6 - Recursion is mandatory
Any dumped DEX or installed APK becomes a **linked child artifact** re-entering the full
pipeline. Findings attach to the parent.
*Source: [Ch 03 §11](../android/03-android-runtime.md#11-detection-logic-for-sudarshan), [Ch 09 §10](../apk/09-package-manager.md#10-detection-logic-for-sudarshan)*

### P7 - Detect at the top of the Pyramid of Pain
Weight TTPs and capability clusters above domains and hashes. Extract all levels; expire by type.
*Source: [Ch 16 §7](../threat-intelligence/16-threat-intelligence.md#7-the-pyramid-of-pain)*

### P8 - Two clocks, two tracks
Containment tolerates medium confidence in minutes; investigation requires high confidence over
hours. Stream partial results.
*Source: [Ch 20 §3](../incident-response/20-incident-response.md#3-the-response-clock)*

### P9 - AI accelerates; deterministic rules decide
ML orders the queue and links campaigns. LLMs summarise and draft. Neither produces a verdict or
triggers containment.
*Source: [Ch 21 §1](../ai-malware-analysis/21-ai-assisted-malware-analysis.md#1-where-ai-actually-helps)*

> **⚖️ Judge Tip:** If asked "what's your differentiator," the answer is not a feature - it is
> **P3 + P4 together**: every verdict is evidence-linked and reproducible, *and* the system
> refuses to claim cleanliness on samples it could not actually analyse. Most scanners fail both.
> Those two properties are what make the output usable by a regulated institution.

---

## 3. System architecture

```
┌───────────────────────────────────────────────────────────────────────────┐
│  SOURCES                                                                  │
│  bank fraud team · SOC/SOAR API · TI feeds · app-store monitoring ·        │
│  customer device forensics (Ch 17) · partner banks                        │
└──────────────────────────────────┬────────────────────────────────────────┘
                                   ▼
┌───────────────────────────────────────────────────────────────────────────┐
│  ① INTAKE  (Ch 24)                                                        │
│  container explode · safe extraction · dedup · hashing · signer extraction │
│  · priority assignment · artifact-graph node creation                     │
└──────────────────────────────────┬────────────────────────────────────────┘
                                   ▼
┌───────────────────────────────────────────────────────────────────────────┐
│  ② DETECTION PIPELINE  (Ch 23)                                            │
│  ┌──────────┬──────────┬──────────┬──────────┬──────────┬──────────┐      │
│  │ T0       │ T1       │ T2       │ T3       │ T4       │ T5       │      │
│  │structural│capability│resources │  code    │ dynamic  │human RE  │      │
│  │  ~10ms   │  ~50ms   │ ~500ms   │ ~10-120s │ 5-15 min │  hours   │      │
│  │  100%    │  100%    │  100%    │  ~20%    │   ~5%    │   <1%    │      │
│  └──────────┴──────────┴──────────┴──────────┴──────────┴──────────┘      │
│         each tier gates the next · partial results streamed               │
└──────────────────────────────────┬────────────────────────────────────────┘
                                   ▼
┌───────────────────────────────────────────────────────────────────────────┐
│  ③ INVESTIGATION ENGINE  (Ch 25)                                          │
│  artifact graph · recursion · evidence ledger · case management · sweep    │
└────────────┬──────────────────────────────────────────┬───────────────────┘
             ▼                                          ▼
┌──────────────────────────┐              ┌──────────────────────────────────┐
│ ④ IOC EXTRACTION (Ch 26) │              │ ⑤ CAMPAIGN CORRELATION (Ch 28)   │
│ typed · TTL'd · exported │◄────────────►│ pivot graph · similarity · actors│
└────────────┬─────────────┘              └────────────────┬─────────────────┘
             │                                             │
             ▼                                             ▼
┌───────────────────────────────────────────────────────────────────────────┐
│  ⑥ THREAT INTELLIGENCE DATABASE  (Ch 30)                                  │
│  families + aliases · signers · infrastructure · rules · retro-hunt        │
└──────────────────────────────────┬────────────────────────────────────────┘
                                   ▼
┌───────────────────────────────────────────────────────────────────────────┐
│  ⑦ RISK SCORING  (Ch 27)                                                  │
│  deterministic rules · severity × confidence · analysis-quality ceiling    │
└──────────────────────────────────┬────────────────────────────────────────┘
                                   ▼
┌───────────────────────────────────────────────────────────────────────────┐
│  ⑧ INVESTIGATION REPORTS  (Ch 29)                                         │
│  SOC view · fraud-ops view · CISO view · regulatory pack · customer facts  │
└──────────────────────────────────┬────────────────────────────────────────┘
                                   ▼
        SIEM / SOAR  ·  Fraud Ops  ·  TIP  ·  Compliance  ·  Analysts
```

---

## 4. Component responsibilities

| # | Component | Owns | Must not |
|---|---|---|---|
| ① | **Intake** | Normalisation, dedup, safe extraction, priority | Analyse content |
| ② | **Detection Pipeline** | Tiered analysis, gating, partial emission | Decide business actions |
| ③ | **Investigation Engine** | Artifact graph, recursion, evidence ledger, cases | Produce prose |
| ④ | **IOC Extraction** | Typed indicators with TTLs and provenance | Auto-block |
| ⑤ | **Campaign Correlation** | Pivots, clustering, actor/family linkage | Assert actor attribution |
| ⑥ | **TI Database** | Families, aliases, signers, infra, rules, history | Be the source of verdicts |
| ⑦ | **Risk Scoring** | Deterministic score, severity/confidence, ceiling | Use ML output as input to the verdict |
| ⑧ | **Reporting** | Multi-audience rendering, regulatory pack | Assert regulatory reportability |

> **⚙️ Engineering Note:** The "must not" column is as important as the "owns" column. Two
> failures kill this class of product: **intake that starts analysing** (couples everything and
> makes safe sandboxing impossible), and **reporting that asserts legal conclusions** (a
> compliance decision the platform is not entitled to make →
> [Ch 20 §11](../incident-response/20-incident-response.md#11-regulatory-reporting)). Write the
> boundaries into the service contracts, not just the docs.

---

## 5. The data model

Five first-class entities. Everything else hangs off them.

```
  ┌────────────┐        signed_by         ┌────────────┐
  │  ARTIFACT  │─────────────────────────►│   SIGNER   │ ★ primary identity (P5)
  │  (APK/DEX) │                          │  cert_sha256│
  └─────┬──────┘                          └──────┬──────┘
        │ derived_from (recursion, P6)           │ attributed_to
        │                                        ▼
        │                                 ┌────────────┐
        │      exhibits                   │  CAMPAIGN  │
        ├────────────────►┌───────────┐   │  / FAMILY  │
        │                 │ CAPABILITY│   └─────┬──────┘
        │                 └───────────┘         │ uses
        │ contacts                              ▼
        └────────────────►┌──────────────────────────┐
                          │      INFRASTRUCTURE      │
                          │  domain · IP · key · TLS │
                          └──────────────────────────┘
                                      │
        ┌─────────────────────────────┴──────────────┐
        ▼                                            ▼
  ┌───────────┐                              ┌──────────────┐
  │ EVIDENCE  │  every claim → artifact ptr  │     CASE     │
  │  (P3)     │◄─────────────────────────────│ shared w/ SOC│
  └───────────┘                              │ + fraud ops  │
                                             └──────────────┘
```

### Why a graph, not a table

Investigation is **traversal**: signer → sibling samples → shared key → affiliate samples → C2 →
sibling domains → other banks' submissions → union of target lists
([Ch 15 §11](../malware/15-malware-infrastructure.md#11-pivoting-infrastructure-as-an-investigative-graph)).
A relational schema can express this, but the queries are joins-of-joins and the model doesn't
communicate intent. A property graph makes the pivot the primitive.

> **⚙️ Engineering Note:** Store the graph in a graph database (or a relational store with an
> explicit edge table) **and** keep a columnar analytical store for corpus-wide queries and
> hunting ([Ch 18 §5](../soc/18-mobile-threat-hunting.md#5-hunt-playbooks)). Trying to serve both
> access patterns from one engine is a common early mistake - graph traversal and
> aggregate-over-millions have genuinely different requirements.

---

## 6. Technology choices

Illustrative, with the reasoning that matters more than the specific pick.

| Layer | Choice | Why |
|---|---|---|
| Intake / API | Python (FastAPI) or Go | Ecosystem fit with analysis tooling |
| Static analysis | **Androguard**, `apktool`, `jadx`, `aapt2`, `apksigner` | [Ch 10](../reverse-engineering/10-reverse-engineering.md), [Ch 11](../static-analysis/11-static-analysis.md) |
| Pattern matching | **YARA-X** | Faster, memory-safe rewrite |
| Similarity | **TLSH** (+ SSDEEP for feed compat) | DEX-level lineage |
| Dynamic | **Real devices** + emulator lanes, **Frida** | [Ch 12 §2](../dynamic-analysis/12-dynamic-analysis.md#2-the-lab) |
| Orchestration | Durable workflow engine (Temporal/Airflow-class) | Long-running, retryable, auditable |
| Queue | Kafka / NATS | Priority lanes for the urgent path |
| Object store | S3-compatible, **encrypted, access-logged** | Malicious sample custody |
| Graph | Neo4j / JanusGraph, or Postgres + edge tables | Pivoting |
| Analytics | ClickHouse / BigQuery-class | Corpus hunting |
| Search | OpenSearch | Strings, resources, reports |
| Rules | Git-versioned (**detection-as-code**) | [Ch 19 §7](../soc/19-enterprise-soc-operations.md#7-detection-engineering) |
| LLM | API-based, grounded, cited | [Ch 21 §7](../ai-malware-analysis/21-ai-assisted-malware-analysis.md#7-llms-in-malware-analysis) |

> **⚙️ Engineering Note - the one non-negotiable:** **analysis tooling parses attacker-controlled
> input.** `apktool`, `jadx`, `unzip`, image parsers, and MobSF have all had parser
> vulnerabilities; MobSF v4.4.6 (March 2026) patched a SQL injection in its SQLite viewer. Every
> parsing and detonation stage runs in an **isolated, ephemeral, network-restricted sandbox**,
> never on the orchestrator. This is not defence in depth; it is the baseline.
> → [Ch 24](24-threat-intake.md)

---

## 7. Non-goals

Stating these explicitly prevents scope drift and, in a pitch, signals maturity.

| Non-goal | Why | Instead |
|---|---|---|
| **Be a SIEM** | Banks have one; displacing it is a multi-year procurement fight | Integrate via API ([Ch 19 §6](../soc/19-enterprise-soc-operations.md#6-where-sudarshan-plugs-in)) |
| **Be an antivirus** | Different product, different distribution, different economics | Investigation platform |
| **Run on customer devices** | Cannot enrol customer phones; privacy exposure | Analyse samples; consume bank-app SDK telemetry |
| **Autonomous containment** | Real-world consequences on customer accounts | Recommend; the bank's SOAR acts on pre-authorised rules |
| **Actor / nation-state attribution** | Requires capabilities no commercial platform has | Family and campaign only, with stated confidence |
| **Assert regulatory reportability** | A compliance decision | Supply facts, flag "potentially reportable" |
| **Collect full app inventories** | DPDP data minimisation | Accessibility + notification-listener package names only |
| **Replace reverse engineers** | Novel logic needs humans | Make each analyst cover far more |
| **iOS parity at launch** | Different platform, different threat model, different tooling | Android-first, deliberately |

> **⚖️ Judge Tip:** Volunteering non-goals is disproportionately persuasive. Saying *"we are not
> a SIEM, we do not do actor attribution, and we do not assert regulatory reportability because
> that's a compliance call"* signals that you understand the domain's boundaries. Teams that
> claim everything are assumed to have thought about nothing.

---

## 8. Staging roadmap

### Stage 1 - Deterministic core (0–3 months)

**Goal: a defensible verdict on a single APK, fast.**

| Ship | Chapter |
|---|---|
| Intake + safe extraction + dedup | [Ch 24](24-threat-intake.md) |
| T0 structural checks (Janus, dup entries, DEX checksums) | [Ch 08 §10](../apk/08-apk-file-format.md#10-detection-logic-for-sudarshan) |
| Signer extraction + **canonical registry impersonation rule** | [Ch 06 §11](../security/06-certificates.md#11-detection-logic-for-sudarshan) |
| T1 capability vector incl. **accessibility config parsing** | [Ch 11 §4](../static-analysis/11-static-analysis.md#4-tier-1--manifest-and-capability-extraction) |
| T2 resource mining → **overlay target list** | [Ch 11 §5](../static-analysis/11-static-analysis.md#5-tier-2--resource-and-asset-mining) |
| Deterministic scoring with severity/confidence + ceiling | [Ch 27](27-risk-scoring.md) |
| Evidence ledger | [Ch 25](25-investigation-engine.md) |
| Basic report | [Ch 29](29-investigation-reports.md) |

**Acceptance:** given a client bank's package registry, correctly and instantly flag any
impersonating APK with cryptographic justification; produce a capability profile in under 2
seconds; never emit "clean" for an unanalysable sample.

### Stage 2 - Fusion and intelligence (3–9 months)

| Ship | Chapter |
|---|---|
| T3 code analysis, API chains, YARA-X | [Ch 11 §6](../static-analysis/11-static-analysis.md#6-tier-3--code-analysis) |
| T4 dynamic detonation, real devices, standard hook set | [Ch 12](../dynamic-analysis/12-dynamic-analysis.md) |
| **Recursive child-artifact analysis** | [Ch 25](25-investigation-engine.md) |
| IOC extraction with typed TTLs | [Ch 26](26-ioc-extraction.md) |
| TI database + external enrichment | [Ch 30](../threat-intelligence/30-threat-intelligence-database.md) |
| MITRE ATT&CK mapping on every rule | [Ch 16 §3](../threat-intelligence/16-threat-intelligence.md#3-mitre-attck-for-mobile) |
| SOC/SOAR API + partial-result streaming | [Ch 19 §6](../soc/19-enterprise-soc-operations.md#6-where-sudarshan-plugs-in) |

### Stage 3 - Campaign scale and operations (9–18 months)

| Ship | Chapter |
|---|---|
| Campaign correlation graph + similarity | [Ch 28](28-campaign-correlation.md) |
| **Customer-base sweep by signer** | [Ch 20 §6](../incident-response/20-incident-response.md#6-phase-3--containment) |
| Retro-hunt + verdict-change notification | [Ch 18 §6](../soc/18-mobile-threat-hunting.md#6-hunting-the-sample-corpus) |
| Hunting workbench + hypothesis backlog | [Ch 18](../soc/18-mobile-threat-hunting.md) |
| LLM summarisation + report drafting (grounded) | [Ch 21 §7](../ai-malware-analysis/21-ai-assisted-malware-analysis.md#7-llms-in-malware-analysis) |
| Regulatory pack generation | [Ch 20 §11](../incident-response/20-incident-response.md#11-regulatory-reporting) |
| Multi-tenant, cross-bank correlation (consent-gated) | [Ch 28](28-campaign-correlation.md) |

### Sequencing rationale

```
  Stage 1 = the thing that works on day one and can be demoed truthfully
            (signer impersonation is deterministic, instant, ~zero FP)
        ▼
  Stage 2 = the thing that makes it a malware platform rather than a checker
        ▼
  Stage 3 = the thing that makes one bank's submission protect four banks
            ★ this is where the compounding value lives
```

> **🏛️ Enterprise Insight:** Stage 1's impersonation rule is deliberately first. It is
> deterministic, requires no ML, has essentially zero false positives when the registry is
> correct, and demos in thirty seconds - genuine APK and clone side by side, same package name,
> different fingerprint, instant verdict with cryptographic justification. **Ship the credible
> thing first**; it buys the runway to build the hard parts.

---

## 9. Operating and safety constraints

| Constraint | Implementation |
|---|---|
| **Malicious sample custody** | Encrypted at rest, access-logged, never executed outside the sandbox, retention policy, no accidental redistribution |
| **Sandbox isolation** | Ephemeral, network-restricted egress, no path to production or the orchestrator |
| **Detonation egress control** | Logged proxy; block premium-SMS and payment paths; rate-limit |
| **Customer data (DPDP)** | Targeted collection profiles; purpose limitation; retention limits; access audit |
| **Multi-tenancy** | Hard tenant isolation; cross-bank correlation only on aggregate, consented indicators |
| **Auditability** | Every query, verdict, and verdict change logged immutably |
| **Reproducibility** | Rule versions, tool versions, ART/Conscrypt module versions, model versions recorded per analysis |
| **Detection timestamp** | Immutable - starts the CERT-In clock |

> **⚙️ Engineering Note - cross-tenant correlation is the hardest design problem in the product.**
> The value proposition is that one bank's submission protects others
> ([Ch 15 §11](../malware/15-malware-infrastructure.md#11-pivoting-infrastructure-as-an-investigative-graph)),
> but bank A must never see bank B's customer or submission data. The workable design shares
> **indicators and family/campaign linkage** (signer fingerprints, C2, code-similarity clusters)
> while keeping **submissions, customer cohorts, and impact data tenant-private** - with the
> sharing consented contractually. Get this wrong and the product is either useless or unsellable.

---

## 10. Limitations and honest positioning

| We cannot | Because |
|---|---|
| Detect a payload that doesn't exist yet | Droppers ([Ch 09 §7](../apk/09-package-manager.md#7-droppers-the-technique-in-full)) |
| Guarantee unpacking | Some packers resist; hence the confidence ceiling (P4) |
| See devices we have no telemetry from | No agent on customer phones |
| Recover funds | Bank and law-enforcement function |
| Attribute to an actor | [Ch 16 §10](../threat-intelligence/16-threat-intelligence.md#10-attribution-and-its-limits) |
| Prevent infection | We detect and inform; prevention is platform + user + bank app hardening |
| Be certain when C2 is offline | Inconclusive + requeue |

> **🚨 Misconception (internal, and worth stating):** "The platform stops mobile banking fraud."
> It **shortens the time from infection to informed response**, and it converts single-sample
> analysis into campaign-scale intelligence. Those are large, defensible claims. Claiming
> prevention invites a demonstration that it doesn't, and there will always be a sample it
> misses.

---

## 11. Engineering tips

1. **Build the signer registry and impersonation rule first.** Highest precision, lowest cost.
2. **Design the artifact graph with recursion from day one** - retrofitting P6 is painful.
3. **Make analysis quality a first-class field**, not a log line.
4. **Separate the graph store from the analytics store.**
5. **Never parse untrusted input outside the sandbox.**
6. **Stream partial results** - the money clock doesn't wait for certainty.
7. **Version everything** - rules, tools, models, ART/Conscrypt.
8. **Write the "must not" boundaries into service contracts.**
9. **Solve tenant isolation before multi-tenant correlation**, not after.
10. **Keep non-goals visible in the repo**, not just in a slide.

---

## 12. Judge Insights

**What judges ask:** *"Why does this need to exist? Couldn't a bank just use MobSF and
VirusTotal?"*

**Perfect answer:** They could, and they'd get two things neither tool provides. MobSF scores app
**security hygiene** - a hardened banking app with pinning and obfuscation grades badly while a
dropper with three permissions grades well, because the payload isn't there yet. VirusTotal is a
multi-engine aggregator, and Anatsa's droppers reached the top of Play's Tools chart essentially
undetected. What a bank actually needs is the answer to "is *our* package name in this malware's
overlay target list, which of our customers have it installed, and what do we do in the next
thirty minutes" - with every claim traceable to a file and a line so we can defend the decision
to RBI six months later. That's an investigation platform, not a scanner, and it's built around
three constraints those tools weren't designed for: a minutes-long fraud window, mandatory
explainability, and the fact that static and dynamic analysis have complementary blind spots so
neither alone is sufficient.

**Common mistakes:**
- Claiming to prevent fraud. Claim to compress time-to-informed-response - provable and large.
- Not having non-goals. It reads as not having thought about scope.
- Positioning against a SIEM. Banks have one and won't replace it.

**Follow-ups to expect:**
- *"What ships first?"* → The signer impersonation check. Deterministic, instant, essentially
  zero false positives, and it demos in thirty seconds - genuine bank APK versus clone, same
  package name, different certificate fingerprint. Credible thing first.
- *"How is this defensible to a regulator?"* → Every point of score traces to an artifact, and the
  system structurally refuses to report "clean" on a sample it couldn't actually analyse. Those
  two properties together are the differentiator.
- *"What's the hardest engineering problem?"* → Cross-tenant correlation. The value is that one
  bank's submission protects four, but bank A can never see bank B's data. We share indicators
  and campaign linkage; submissions and customer impact stay tenant-private.

**Fact that impresses:** The most valuable single output isn't the verdict - it's the extracted
**overlay target list**. It converts "this is malware" into "this campaign specifically hunts for
`com.yourbank.app` alongside 46 other Indian financial apps," and it costs under a second to
produce from resource strings. That's the finding a CISO forwards upward within the hour.

---

## 13. Interview Insights

**Q: "Design a malware analysis platform. Where do you start?"**
Constraints before components: the response clock, explainability requirements, the cost gradient
across analysis techniques, and the complementary blind spots of static and dynamic. Then a tiered
pipeline gating expensive stages, a graph data model because investigation is traversal, and a
deterministic scoring layer with evidence pointers.

**Q: "Why a graph database?"**
Because investigation is pivoting: signer → sibling samples → shared key → affiliates → C2 →
sibling domains → other victims. Relational can express it, but as joins-of-joins. Keep a separate
columnar store for corpus-wide analytics - different access patterns.

**Q: "How do you make the verdict explainable?"**
Deterministic rules produce the score; every point traces to an artifact - file, line, timestamp.
ML orders the queue; LLMs narrate. Nothing model-derived enters the verdict, so the decision is
reproducible even after models change.

**Q: "What would you deliberately not build?"**
SIEM replacement, antivirus, on-device agent for customers, autonomous containment, actor
attribution, regulatory reportability assertions, full app-inventory collection. Each with a
one-line reason. Volunteering scope discipline is a strong signal.

**Q: "How do you handle multi-tenancy for banks that compete?"**
Share indicators and campaign linkage; keep submissions and customer impact tenant-private; gate
sharing contractually. Solve isolation before building correlation, not after.

**Beginner mistakes:**
- Starting with components instead of constraints.
- Letting intake do analysis.
- Retrofitting recursion.
- Treating analysis quality as a log line.
- Building correlation before tenant isolation.

---

## 14. Cross-references

**Upstream:** All of Blocks A–D. Principles P1–P9 each cite their source chapter in §2.

**Downstream:**
- [→ Ch 23 Detection Pipeline](23-detection-pipeline.md) · [→ Ch 24 Threat Intake](24-threat-intake.md)
- [→ Ch 25 Investigation Engine](25-investigation-engine.md) · [→ Ch 26 IOC Extraction](26-ioc-extraction.md)
- [→ Ch 27 Risk Scoring](27-risk-scoring.md) · [→ Ch 28 Campaign Correlation](28-campaign-correlation.md)
- [→ Ch 29 Investigation Reports](29-investigation-reports.md) · [→ Ch 30 TI Database](../threat-intelligence/30-threat-intelligence-database.md)

---

## 15. References

1. NIST SP 800-163 Rev. 1 - *Vetting the Security of Mobile Applications*.
2. NIST SP 800-61 Rev. 2 - *Computer Security Incident Handling Guide*.
3. OWASP MASVS v2.1.0 / MASTG. https://mas.owasp.org/
4. MITRE ATT&CK for Mobile. https://attack.mitre.org/matrices/mobile/
5. MobSF documentation and release notes (v4.4.x). https://mobsf.github.io/docs/
6. Androguard, YARA-X, TLSH, Frida - tooling documentation.
7. Digital Personal Data Protection Act, 2023 (India).
8. CERT-In Directions, April 28, 2022.
9. Reserve Bank of India - Cyber Security Framework for Banks.

---

*Previous: [← Ch 21 AI-assisted Malware Analysis](../ai-malware-analysis/21-ai-assisted-malware-analysis.md) · Next: [Ch 23 Detection Pipeline →](23-detection-pipeline.md)*
