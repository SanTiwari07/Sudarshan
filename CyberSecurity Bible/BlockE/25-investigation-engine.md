# 25 - Investigation Engine

> **Chapter ID:** `CH25` · **Block:** E · **Status:** Stable
> **Tags:** `#investigation` `#artifact-graph` `#recursion` `#evidence-ledger` `#case-management` `#sweep`
> **Last Updated:** 2026-08-05 · **Version:** 1.0.0
> **Prerequisites:** [Ch 23](23-detection-pipeline.md), [Ch 24](24-threat-intake.md)

---

## Table of Contents

1. [What the engine is for](#1-what-the-engine-is-for)
2. [The artifact graph](#2-the-artifact-graph)
3. [Recursion](#3-recursion)
4. [The evidence ledger](#4-the-evidence-ledger)
5. [Score propagation](#5-score-propagation)
6. [Cases](#6-cases)
7. [The sweep](#7-the-sweep)
8. [Reproducibility](#8-reproducibility)
9. [Analyst interaction](#9-analyst-interaction)
10. [Limitations and edge cases](#10-limitations-and-edge-cases)
11. [Engineering tips](#11-engineering-tips)
12. [Judge Insights](#12-judge-insights)
13. [Interview Insights](#13-interview-insights)
14. [Cross-references](#14-cross-references)
15. [References](#15-references)

---

## 1. What the engine is for

The detection pipeline ([Ch 23](23-detection-pipeline.md)) analyses *artifacts*. The investigation
engine assembles those analyses into **an investigation** - a connected, evidenced, reproducible
account of what happened and who it affects.

```
   PIPELINE                      INVESTIGATION ENGINE
   ────────                      ────────────────────
   analyses one artifact    ──►  relates artifacts to each other (graph)
   emits findings           ──►  binds every finding to evidence (ledger)
   discovers child files    ──►  recurses and propagates scores
   produces a verdict       ──►  assembles a case, sweeps the estate
```

Four responsibilities:

| # | Responsibility | Principle |
|---|---|---|
| 1 | **Artifact graph** - nodes and relationships | P5 identity |
| 2 | **Recursion** - child artifacts re-enter the pipeline | **P6** |
| 3 | **Evidence ledger** - every claim → an artifact pointer | **P3** |
| 4 | **Cases and sweep** - from one sample to estate-wide impact | P8 |

---

## 2. The artifact graph

### Node types

| Node | Key | Notes |
|---|---|---|
| **Artifact** | `sha256` | APK, DEX, `.so`, container member |
| **Signer** | `cert_sha256` | ★ Primary identity (P5) |
| **Capability** | canonical name | a11y, overlay, sms_intercept… |
| **Infrastructure** | typed value | domain, IP, key, TLS cert, panel path |
| **Family / Campaign** | id | With aliases → [Ch 30](../threat-intelligence/30-threat-intelligence-database.md) |
| **Target** | package name | ★ Which apps the sample hunts for |
| **Case** | id | Shared with SOC + fraud ops |
| **Evidence** | id | Immutable claim record |
| **Submission** | id | Tenant, source, time ([Ch 24 §6](24-threat-intake.md#6-deduplication)) |

### Edge types

```
  artifact  ──signed_by──►         signer
  artifact  ──derived_from──►      artifact         ★ recursion (P6)
  artifact  ──installed──►         artifact         ★ dropper relationship
  artifact  ──exhibits──►          capability
  artifact  ──contacts──►          infrastructure
  artifact  ──targets──►           target
  artifact  ──similar_to──►        artifact  {tlsh_distance}
  artifact  ──member_of──►         family
  signer    ──attributed_to──►     campaign
  infra     ──co_hosted_with──►    infra
  finding   ──supported_by──►      evidence
  case      ──contains──►          artifact | finding | customer_cohort
  submission ──of──►               artifact
```

### Why the graph earns its complexity

A single question demonstrates it:

> *"A customer's phone had app X. What else do we know?"*

```
  app X ──signed_by──► signer S ──┬──► 4 other samples in the corpus
                                   │
                                   └──► campaign C
                                             │
        app X ──contacts──► C2 domain D ──┬──► IP 1.2.3.4 ──► 6 sibling domains
                                           │                       │
                                           │                       ▼
                                           │            2 other tenants' submissions
                                           │
        app X ──targets──► [com.bankA, com.bankB, com.bankC, …47 more]
                                           │
                                           ▼
                          ★ THREE client banks are targeted, not one
```

That traversal - not the individual verdict - is the product.
→ [Ch 15 §11](../malware/15-malware-infrastructure.md#11-pivoting-infrastructure-as-an-investigative-graph)

---

## 3. Recursion

**P6.** Any artifact discovered *during* analysis becomes a first-class artifact that re-enters
the pipeline.

### Sources of child artifacts

| Source | Discovery point | Chapter |
|---|---|---|
| **Class-loader dump** | Frida hook on `InMemoryDexClassLoader` / `DexClassLoader` | [Ch 12 §5](../dynamic-analysis/12-dynamic-analysis.md#5-the-essential-hook-library) |
| **Installed package** | Post-detonation `pm list packages` diff | [Ch 09 §10](../apk/09-package-manager.md#10-detection-logic-for-sudarshan) |
| **Memory-carved DEX** | Scan for DEX magic in process memory | [Ch 10 §9](../reverse-engineering/10-reverse-engineering.md#9-unpacking-strategy) |
| **Decrypted asset** | Crypto hook output | [Ch 05 §9](../security/05-android-cryptography.md#9-how-malware-uses-cryptography) |
| **Downloaded file** | Network capture with APK/DEX magic | [Ch 12 §7](../dynamic-analysis/12-dynamic-analysis.md#7-network-analysis) |
| **Container member** | Intake explosion | [Ch 24 §3](24-threat-intake.md#3-format-handling) |

### The canonical case

```
  dropper.apk                       static verdict: CLEAN-looking
     │                              (3 permissions, no a11y, functional PDF reader)
     │  T4 detonation
     ▼
  package-list diff → new package appeared
     │
     ▼
  payload.apk  ★ NEW ARTIFACT, derived_from: dropper.apk, derivation: installed_by
     │
     │  full pipeline re-runs on payload.apk
     ▼
  static verdict: MALICIOUS
    a11y + canPerformGestures + overlay + SMS + notification listener
    targets 831 financial institutions
     │
     ▼
  ★ SCORE PROPAGATES UP: dropper.apk is now CRITICAL
    reason: "installed a malicious payload (child artifact <sha256>)"
```

> **⚙️ Engineering Note - without propagation, recursion is pointless.** A system that analyses
> the payload but leaves the dropper scored "clean" has produced a correct analysis and a wrong
> answer, because the dropper is what the bank's customers actually installed and what the store
> is distributing. **The parent must inherit a verdict from its children**, with the child cited
> as the evidence.

### Safeguards

```yaml
recursion:
  max_depth: 3
  max_children_per_artifact: 20
  cycle_detection: by_sha256          # child == ancestor → stop, record
  cap_hit_is_a_finding: true          # ★ hitting the cap is itself unusual
  child_priority: inherit_from_parent
  child_completion_triggers_parent_rescore: true    # ★
```

---

## 4. The evidence ledger

**P3.** Every finding is bound to an immutable evidence record with a pointer an auditor can
follow.

```yaml
evidence:
  id: "ev_01J8..."
  artifact_id: "art_01J8..."
  analysis_id: "AN-2026-0805-0042"
  tier: T1 | T2 | T3 | T4 | intake | correlation
  claim: "Accessibility service declares canPerformGestures"
  kind: static | dynamic | structural | intel | correlation
  pointer:
    type: file_offset | file_path | log_line | network_flow | db_record
    file: "res/xml/accessibility_config.xml"
    line: 6
    excerpt: 'android:canPerformGestures="true"'
  observed_at_utc: "2026-08-05T09:14:31Z"
  produced_by:
    tool: "androguard"
    version: "4.1.2"
    rule_id: "CAP-A11Y-002"
    ruleset_version: "2026.08.01"
  immutable: true
```

### Static vs dynamic evidence

```
  STATIC EVIDENCE                     DYNAMIC EVIDENCE
  ───────────────                     ────────────────
  "declares canPerformGestures"       "created TYPE_APPLICATION_OVERLAY (2038)
   → a CAPABILITY claim                 over com.decoy.bank at 14:32:07"
                                       → an OBSERVED ACT with a timestamp
        │                                        │
        ▼                                        ▼
   weight: high                          weight: VERY HIGH
   confidence: medium                    confidence: high
```

> **⚙️ Engineering Note:** Dynamic evidence is qualitatively stronger and should be weighted and
> *quoted* accordingly. "The app declared an overlay permission" is a capability claim; "the app
> drew a full-screen overlay over a banking app at 14:32:07, log line 4821" is an observed attack.
> The second is what a fraud committee and a regulator find persuasive.
> → [Ch 29](29-investigation-reports.md)

### Why immutability matters

A verdict may be revisited months later in a liability dispute. The evidence that supported it
must be exactly what it was, and the ledger must show **who or what changed anything, when**.
Evidence is append-only; corrections are new records that supersede, never edits.

---

## 5. Score propagation

```
                 ┌──────────────────┐
                 │ dropper.apk      │  base score: 25 (low)
                 │                  │  ← propagated: 95 (critical)
                 └────────┬─────────┘
                          │ installed_by
                          ▼
                 ┌──────────────────┐
                 │ payload.apk      │  score: 95 (critical)
                 └────────┬─────────┘
                          │ derived_from (classloader dump)
                          ▼
                 ┌──────────────────┐
                 │ stage3.dex       │  score: 90
                 └──────────────────┘
```

### The rules

```yaml
propagation:
  upward:                       # child → parent
    rule: parent_score = max(parent_base_score, max(child_scores))
    reason_recorded: "delivered malicious child artifact <sha256>"
    applies_to: [installed_by, derived_from]
  lateral:                      # via shared signer
    rule: >
      If signer S is confirmed malicious on any artifact, all artifacts
      signed by S are RE-EVALUATED (not auto-scored) and flagged for review.
    reason: signer identity is durable, but a signer could be compromised
  never:
    - propagate DOWNWARD (a malicious parent doesn't make a benign
      bundled library malicious)
    - propagate across mere similarity without review
```

> **⚙️ Engineering Note - do not propagate downward.** A malicious APK may bundle a perfectly
> ordinary open-source library. Marking that library malicious because of its container is how a
> platform ends up flagging OkHttp. Upward propagation reflects *delivery responsibility*;
> downward propagation reflects nothing.

---

## 6. Cases

A **case** is the unit the humans work in, and it must be shared across the organisational seam
([Ch 19 §8](../soc/19-enterprise-soc-operations.md#8-the-bank-soc--fraud-ops-relationship)).

```yaml
case:
  id: "CASE-2026-0805-014"          # ★ shared with SOC and fraud ops
  tenant_id: "..."
  opened_utc: "..."                  # ★ immutable - CERT-In clock (Ch 20 §11)
  opened_by: automated | analyst | soc_api
  state: open | contained | investigating | closed
  severity / confidence: ...
  artifacts: [art_..., art_...]      # incl. children
  family: {name, aliases, basis, confidence}
  campaign_id: "..."
  affected:
    client_packages_targeted: ["com.clientbank.app"]
    customer_cohort_size: 340        # ★ from the sweep
    devices: [pseudonymised refs]
  actions:
    - {ts, action: session_hold, scope: cohort, actor: soar, authorised_by: rule_TIER2}
  evidence_refs: [ev_..., ev_...]
  timeline: [...]                     # from Ch 17 §6 where device forensics exist
  regulatory:
    detected_at_utc: "..."           # ★ immutable
    potentially_reportable: true     # ★ flag only - never assert (Ch 20 §11)
```

### Case creation triggers

| Trigger | Severity |
|---|---|
| Signer impersonation of a protected package | Critical |
| Client package in a sample's target list | Critical |
| Dropper chain + accessibility on a customer device | Critical |
| Known-malicious signer with customers affected | High |
| Novel family candidate | High (analyst) |
| Analyst manual creation | - |

---

## 7. The sweep

The highest-leverage action in the platform: converting one sample into estate-wide containment
([Ch 20 §6](../incident-response/20-incident-response.md#6-phase-3--containment)).

```
   ONE confirmed malicious artifact
            │
            ▼
   ┌────────────────────────────────────────────────┐
   │ SWEEP by, in order of precision:               │
   │  1. signer_cert_sha256      ★ most durable     │
   │  2. package_name            (campaign attr)    │
   │  3. tlsh_dex distance < 50  (code lineage)     │
   │  4. shared C2 infrastructure                   │
   │  5. shared hardcoded key                       │
   └───────────────┬────────────────────────────────┘
                   ▼
   ┌────────────────────────────────────────────────┐
   │ ACROSS:                                        │
   │  • the sample corpus  → other samples          │
   │  • bank app SDK telemetry → affected customers │
   │  • prior submissions  → other tenants (consent)│
   └───────────────┬────────────────────────────────┘
                   ▼
        affected_cohort + graduated response  (Ch 20 §6)
```

### Precision by pivot

| Pivot | Precision | Use for |
|---|---|---|
| Signer | Very high | **Containment action** |
| Hardcoded key | High | Containment/review |
| TLSH < 50 | Medium-high | Review |
| Package name | Medium | Review (attacker-chosen) |
| C2 domain | Medium | Review (shared hosting) |

> **⚙️ Engineering Note:** Match the pivot's precision to the action's cost
> ([Ch 20 §13](../incident-response/20-incident-response.md#13-limitations-edge-cases-false-positives)).
> A signer match justifies an automated session hold; a TLSH-similarity match justifies enhanced
> monitoring and analyst review, not a customer-visible action. One global threshold across all
> pivots is the wrong design.

---

## 8. Reproducibility

Every analysis records what produced it, so a verdict can be reproduced or explained months later.

```yaml
reproducibility:
  ruleset_version: "2026.08.01"
  tool_versions: {androguard: "4.1.2", jadx: "1.5.0", apktool: "2.9.3",
                  yara_x: "0.8.0", frida: "16.4.2"}
  device_environment:                     # T4 only
    model, android_version, api_level, build_fingerprint
    art_module_version, conscrypt_version     # ★ Mainline → Ch 12 §2
    locale, timezone, sim_present
  model_versions: {code_summariser: "...", clustering: "..."}   # ★ Ch 21
  analysis_started_utc / completed_utc
  stimuli_applied: [grant_a11y, open_decoy_bank, inbound_sms, reboot]
```

> **⚙️ Engineering Note:** ART and Conscrypt are **Mainline modules updated via Google Play
> independently of the OS version** ([Ch 03 §2](../android/03-android-runtime.md#2-dalvik--art-the-history-that-still-matters)).
> Two devices reporting "Android 14" can behave differently. Recording only the Android version is
> the most common reason a dynamic finding can't be reproduced six months later.

---

## 9. Analyst interaction

The engine must accept human input **without contaminating the deterministic record**.

| Analyst action | Effect |
|---|---|
| Add a note | Stored, attributed, timestamped; **not evidence** |
| Mark a finding as a false positive | Recorded as an *adjudication*; feeds rule tuning; base finding preserved |
| Override the verdict | Allowed, **requires a reason**, recorded as a separate layer |
| Add evidence (manual RE) | New evidence record, `produced_by: analyst` |
| Link artifacts manually | New edge with `created_by: analyst`, `basis:` required |
| Request T5 escalation | Priority change |

```yaml
verdict:
  automated: {value: "malicious", score: 95, confidence: 0.92, ruleset: "2026.08.01"}
  adjudicated:                       # ★ separate layer, never overwrites
    value: "malicious"
    by: "analyst@bank"
    at_utc: "..."
    reason: "confirmed Anatsa via manual RE; C2 protocol matches"
    evidence_added: [ev_...]
```

> **⚙️ Engineering Note:** Keep automated and adjudicated verdicts as **separate layers**. If an
> analyst overwrites the automated verdict in place, you lose the ability to measure the platform's
> accuracy - and analyst adjudications are the highest-quality labels you have for tuning
> ([Ch 21 §3](../ai-malware-analysis/21-ai-assisted-malware-analysis.md#3-datasets-and-their-limitations)).
> Preserve both, always.

---

## 10. Limitations and edge cases

| Case | Handling |
|---|---|
| Graph growth | Prune expired infrastructure edges; keep signer and artifact nodes indefinitely |
| Recursion cap hit | Record as a finding; escalate to T5 |
| Contradictory findings (static clean, dynamic malicious) | Dynamic wins; both retained; contradiction is itself notable |
| Analyst disagrees with the engine | Adjudication layer; feeds tuning |
| Cross-tenant edges | Only via shared indicators; **never** expose the other tenant's submissions |
| Legitimate app scored malicious | Adjudication + rule tuning + regression test added |
| Sample deleted (retention) | Graph node and findings persist; bytes removed |

> **🚨 Misconception:** "The verdict is the output." The **case** is the output - verdict plus
> evidence plus affected cohort plus recommended actions plus a reproducible record. A verdict
> alone doesn't tell a bank whose sessions to hold or what to tell a regulator.

---

## 11. Engineering tips

1. **Design the graph with recursion from day one.** Retrofitting P6 is very expensive.
2. **Propagate upward only.** Never downward.
3. **Evidence is immutable and append-only.** Corrections supersede, never edit.
4. **Weight dynamic evidence above static** and quote it verbatim in reports.
5. **Match sweep-pivot precision to action cost.**
6. **Record ART and Conscrypt Mainline versions**, not just the Android version.
7. **Keep automated and adjudicated verdicts as separate layers.**
8. **Make the recursion cap a finding**, not a silent truncation.
9. **Share the case ID with SOC and fraud ops** from the start.
10. **Persist graph nodes even after sample bytes are deleted.**

---

## 12. Judge Insights

**What judges ask:** *"You analysed a dropper and it looked clean. Doesn't that mean you missed
it?"*

**Perfect answer:** It would, if the analysis stopped there. The dropper is genuinely clean - Anatsa's Play droppers were working utilities with no malicious code, which is exactly why store
review passed them. So during detonation we diff the installed-package list before and after, and
when a new package appears we treat it as a **new artifact with a `derived_from` edge**, re-run
the entire pipeline on it, and then **propagate the child's verdict back up to the parent**. The
dropper's final score is critical, with the reason recorded as "delivered malicious child
artifact," and the child cited as the evidence. Without that upward propagation you'd have a
correct analysis and a wrong answer - because the dropper is what customers actually installed and
what the store is still distributing.

**Common mistakes:**
- Analysing the payload and leaving the dropper scored clean.
- Propagating scores downward, which flags every bundled open-source library.
- Treating the verdict as the deliverable rather than the case.

**Follow-ups to expect:**
- *"What stops infinite recursion?"* → Depth cap of three, a per-artifact child cap, and cycle
  detection by hash. And hitting the cap is recorded as a finding and escalated to a human, because
  it's unusual enough to be interesting.
- *"How do you go from one sample to protecting the whole customer base?"* → The sweep. We pivot on
  signer certificate first because it's the most durable identity, then hardcoded keys, then
  DEX-level code similarity, then shared C2. And we match pivot precision to action cost - a signer
  match justifies an automated session hold; a similarity match justifies review, not a
  customer-visible action.
- *"Can an analyst override you?"* → Yes, with a required reason, recorded as a separate
  adjudication layer that never overwrites the automated verdict. That preserves our ability to
  measure accuracy, and analyst adjudications are the best training labels we have.

**Fact that impresses:** Dynamic evidence is qualitatively different from static and we treat it
that way. "The app declares `SYSTEM_ALERT_WINDOW`" is a capability claim. "The app created a
`TYPE_APPLICATION_OVERLAY` window over `com.decoy.bank` at 14:32:07, detonation log line 4821" is
an observed attack with a timestamp and a pointer. The second is what persuades a fraud committee,
so we weight it higher and quote it verbatim in the report.

---

## 13. Interview Insights

**Q: "Why model this as a graph?"**
Because investigation is traversal: signer → sibling samples → shared key → affiliates → C2 →
sibling domains → other tenants' submissions → union of target lists. Relational can express it, as
joins-of-joins, but the graph makes the pivot the primitive.

**Q: "A dropper installs a payload. How does your system handle it?"**
The payload becomes a new artifact with a `derived_from`/`installed_by` edge, re-enters the full
pipeline, and its verdict propagates **upward** to the parent with the reason recorded. Depth cap,
child cap, and hash-based cycle detection prevent runaway recursion.

**Q: "How do you make a verdict auditable?"**
An immutable, append-only evidence ledger where every finding cites a pointer - file and line, log
offset, or network flow - plus recorded rule, tool, model, and device-environment versions so the
analysis is reproducible.

**Q: "Should a malicious app make its bundled libraries malicious?"**
No. Propagate upward only. Downward propagation flags every open-source dependency and destroys
precision.

**Q: "How do you handle analyst disagreement?"**
A separate adjudication layer with a required reason. Never overwrite the automated verdict - you'd lose accuracy measurement and your best labels.

**Beginner mistakes:**
- Not propagating child verdicts.
- Mutable evidence records.
- One sweep threshold for all pivots and all actions.
- Recording only the Android version for dynamic reproducibility.

---

## 14. Cross-references

**Upstream:** [Ch 23](23-detection-pipeline.md) · [Ch 24](24-threat-intake.md) ·
[Ch 03 §11](../android/03-android-runtime.md#11-detection-logic-for-sudarshan) ·
[Ch 09 §10](../apk/09-package-manager.md#10-detection-logic-for-sudarshan)

**Downstream:** [Ch 26](26-ioc-extraction.md) · [Ch 27](27-risk-scoring.md) ·
[Ch 28](28-campaign-correlation.md) · [Ch 29](29-investigation-reports.md)

---

## 15. References

1. Caltagirone, Pendergast, Betz - *The Diamond Model of Intrusion Analysis* (2013).
2. OASIS - STIX 2.1 relationship model. https://oasis-open.github.io/cti-documentation/
3. NIST SP 800-86 - forensic integration with incident response.
4. Zscaler ThreatLabz - *Anatsa's Latest Updates* (August 2025) - direct payload installation.
5. ThreatFabric - Anatsa Play dropper campaign (July 2025).
6. TLSH - similarity hashing. https://github.com/trendmicro/tlsh

---

*Previous: [← Ch 24 Threat Intake](24-threat-intake.md) · Next: [Ch 26 IOC Extraction →](26-ioc-extraction.md)*
