# 18 - Mobile Threat Hunting

> **Chapter ID:** `CH18` · **Block:** D (Operations) · **Status:** Stable
> **Tags:** `#threat-hunting` `#peak` `#tahiti` `#hypothesis-driven` `#telemetry` `#hunt-playbooks`
> **Last Updated:** 2026-08-05 · **Version:** 1.0.0
> **Prerequisites:** [Ch 16](../threat-intelligence/16-threat-intelligence.md), [Ch 17](../digital-forensics/17-digital-forensics.md)

---

## Table of Contents

1. [Hunting vs alerting](#1-hunting-vs-alerting)
2. [The frameworks](#2-the-frameworks)
3. [Telemetry: what you can actually hunt in](#3-telemetry-what-you-can-actually-hunt-in)
4. [Building a hypothesis](#4-building-a-hypothesis)
5. [Hunt playbooks](#5-hunt-playbooks)
6. [Hunting the sample corpus](#6-hunting-the-sample-corpus)
7. [From hunt to detection](#7-from-hunt-to-detection)
8. [Measuring a hunt programme](#8-measuring-a-hunt-programme)
9. [Detection logic for SUDARSHAN](#9-detection-logic-for-sudarshan)
10. [Limitations, edge cases, false positives](#10-limitations-edge-cases-false-positives)
11. [Engineering tips](#11-engineering-tips)
12. [Judge Insights](#12-judge-insights)
13. [Interview Insights](#13-interview-insights)
14. [Cross-references](#14-cross-references)
15. [References](#15-references)

---

## 1. Hunting vs alerting

**Alerting** answers *"did something we already know about happen?"* **Hunting** answers
*"is something we don't have a rule for happening right now?"*

| | Alerting | Hunting |
|---|---|---|
| Trigger | A rule fires | A human forms a hypothesis |
| Assumes | The threat is known | **The threat may be unknown** |
| Output | An alert | A finding **and, ideally, a new rule** |
| Failure mode | Misses novelty | Consumes time on dead ends |
| Cadence | Continuous | Scheduled, iterative |

```
        ┌────────────────────────────────────────────────┐
        │  KNOWN THREATS       →  detection rules fire   │
        ├────────────────────────────────────────────────┤
        │  KNOWN-UNKNOWN       →  ★ HUNTING              │
        │  (we suspect a TTP but have no rule)           │
        ├────────────────────────────────────────────────┤
        │  UNKNOWN-UNKNOWN     →  ★ HUNTING + anomaly    │
        │  (we don't know what to look for)              │
        └────────────────────────────────────────────────┘
```

> **⚙️ Engineering Note - the defining property of a mature hunt programme:** **every hunt ends
> with an artifact.** Either a new detection rule, a tuning change, a telemetry gap logged, or a
> documented negative result. A hunt that ends with "we looked, seemed fine" and produces nothing
> is unrepeatable and unmeasurable. This is the same compounding principle as
> [Ch 10 §12](../reverse-engineering/10-reverse-engineering.md#12-the-re-workflow-end-to-end):
> knowledge that isn't encoded dies with the analyst.

### Why mobile hunting is different

| Difference | Consequence |
|---|---|
| **No EDR agent on most consumer devices** | You hunt in *bank-app telemetry* and *sample corpora*, not in endpoint logs |
| The device isn't yours | No process trees, no file writes, no registry equivalent |
| The customer base is huge and heterogeneous | Scale is enormous; baselines are noisy |
| The victim is a customer, not an employee | **Privacy and DPDP constraints bind hard** ([Ch 17 §9](../digital-forensics/17-digital-forensics.md#9-chain-of-custody-and-legal-context)) |
| The attack is UI-layer | Traditional network/host indicators are thin |

> **🏛️ Enterprise Insight:** This reshapes the whole discipline. For a bank, mobile threat
> hunting is mostly **hunting in three places**: (1) telemetry the bank's own app collects from
> consented devices, (2) the sample corpus SUDARSHAN has accumulated, and (3) fraud-transaction
> patterns. It is *not* endpoint hunting, and importing an EDR-shaped hunt programme wholesale
> will produce a plan you cannot execute.

---

## 2. The frameworks

### PEAK

Splunk's **PEAK** framework - *Prepare, Execute, Act with Knowledge* - with three hunt types:

| Hunt type | Driven by | Example |
|---|---|---|
| **Hypothesis-driven** | An analyst's specific theory | "Accessibility-abusing apps are present on devices that later saw ODF" |
| **Baseline (exploratory)** | Understanding normal | "What accessibility services are enabled across our customer base?" |
| **Model-assisted (M-ATH)** | ML/statistics surfacing outliers | "Cluster apps by permission profile; inspect the outliers" |

```
  PREPARE                EXECUTE                 ACT
  ───────                ───────                 ───
  • topic + scope        • gather data           • document findings
  • hypothesis           • analyse               • ★ create detections
  • data sources         • pivot                 • note telemetry gaps
  • timebox              • validate/refute       • feed back to Prepare
```

### TaHiTI

**Targeted Hunting integrating Threat Intelligence** - a three-phase model emphasising that
hunts should be **intel-driven**, with a documented hypothesis backlog:

```
  INITIATE  →  HUNT  →  FINALIZE
  (trigger:     (investigate,  (document, create
   TI report,    pivot,         detections, update
   incident,     refine)        the backlog)
   crown jewel)
```

TaHiTI's most useful contribution is the **hypothesis backlog** - a ranked, persistent queue of
hunt ideas, so hunting is a managed programme rather than whatever the analyst thought of on
Tuesday.

> **⚙️ Engineering Note:** Use **TaHiTI for programme structure** (backlog, prioritisation,
> intel triggers) and **PEAK for the individual hunt** (prepare/execute/act, hunt typing). They
> are complementary, not competing, and picking one dogmatically is a common way to end up with
> either a well-run programme that produces nothing or good hunts that nobody can prioritise.

---

## 3. Telemetry: what you can actually hunt in

Be realistic about sources before designing hunts against data you don't have.

| Source | Availability | Hunt value |
|---|---|---|
| **Bank app SDK telemetry** | If the bank instruments its app | ★★★ a11y services enabled, overlay detected, root/emulator, device attributes |
| **SUDARSHAN sample corpus** | Always | ★★★ retro-hunting across every APK ever submitted |
| **Fraud/transaction data** | Bank-side | ★★★ the outcome signal to correlate against |
| **MTD / MDM telemetry** | Enterprise devices only | ★★ full app inventory on managed fleets |
| **Network / DNS logs** | Bank infrastructure | ★★ C2 contact from bank-network devices |
| **Threat intel feeds** | External | ★★ hunt triggers |
| **App store monitoring** | Public | ★★ impersonation, fake listings |
| **Customer-reported devices** | Case-by-case | ★ deep but low volume ([Ch 17](../digital-forensics/17-digital-forensics.md)) |

### The bank-app SDK - the highest-leverage investment

If a bank instruments its own app with a lightweight security SDK, these signals become
huntable across the entire customer base:

```yaml
# Minimal, privacy-respecting telemetry set
device_signals:
  accessibility_services_enabled: [package_names]     # ★ THE signal
  notification_listeners_enabled: [package_names]     # ★
  overlay_detected_during_session: bool               # ★
  screen_capture_active: bool
  installer_of_our_app: string                        # repackaging detection
  our_app_signer_matches_expected: bool               # ★ clone detection
  device_integrity_verdict: enum                      # Play Integrity, server-verified
  root_indicators: bool                               # posture, NOT malware
  developer_options_enabled: bool
# deliberately NOT collected: contacts, messages, photos, location,
# full app inventory (DPDP data minimisation → Ch 17 §9)
```

> **🏛️ Enterprise Insight:** Note what's absent. Collecting the **full installed-app list** from
> every customer device would be enormously useful for hunting and is a **privacy and DPDP
> problem** - it reveals health apps, dating apps, religious and political affiliations. The
> defensible design collects *the accessibility and notification-listener package names* (a small,
> directly security-relevant set) rather than the whole inventory. That constraint is a
> feature: it forces precision and it is the position you want to defend to a regulator.

---

## 4. Building a hypothesis

A good hypothesis is **specific, falsifiable, and tied to available data**.

| Bad | Good |
|---|---|
| "Look for banking malware" | "Devices with an enabled accessibility service not on our known-good list, that transacted in the last 30 days, show elevated fraud rates" |
| "Check for anomalies" | "Apps in our corpus declaring a11y + overlay + `REQUEST_INSTALL_PACKAGES` with signers seen fewer than 5 times are disproportionately malicious" |
| "Is Anatsa here?" | "Anatsa droppers are Play-distributed utilities; our corpus should contain Play-sourced utility apps whose signer also signs a known-malicious payload" |

### The template

```yaml
hunt:
  id: HUNT-2026-042
  title: "Accessibility services preceding ODF-pattern transactions"
  trigger: {type: threat_intel, ref: "Zscaler ThreatLabz Anatsa, Aug 2025"}
  hypothesis: >
    Customer devices reporting an enabled accessibility service outside our
    known-good allowlist show a materially higher rate of ODF-pattern
    transactions than the baseline population.
  attack_technique: [T1453, T1516]
  data_sources: [bank_app_sdk_telemetry, transaction_records]
  scope: {population: "active mobile customers", window: "last 90 days"}
  timebox: "3 analyst-days"
  success_criteria: >
    Either a statistically meaningful association (→ build a detection),
    or a documented negative with the confidence interval stated.
  privacy_review: "completed - a11y package names only, no full inventory"
```

> **⚙️ Engineering Note:** The `privacy_review` field is not bureaucratic decoration. In a bank
> under DPDP, a hunt that requires data you are not permitted to collect is a hunt that cannot
> run - and discovering that *after* three days of work is wasted effort. Make it part of the
> template so it's answered in Prepare, not Execute.

---

## 5. Hunt playbooks

Five concrete, runnable hunts. Each maps to techniques from
[Ch 13](../malware/13-android-malware.md).

### HUNT-1 - Unauthorised accessibility services (★ highest value)

**Hypothesis:** Devices with a non-allowlisted accessibility service are at elevated ODF risk.

```sql
-- bank app SDK telemetry
WITH a11y AS (
  SELECT device_id, customer_id, a11y_package, reported_at
  FROM device_signals, UNNEST(accessibility_services_enabled) AS a11y_package
  WHERE reported_at >= CURRENT_DATE - 90
)
SELECT a.a11y_package,
       COUNT(DISTINCT a.device_id)                                  AS devices,
       COUNT(DISTINCT f.txn_id)                                     AS fraud_txns,
       COUNT(DISTINCT f.txn_id)*1.0/COUNT(DISTINCT a.device_id)     AS fraud_rate
FROM a11y a
LEFT JOIN fraud_transactions f
       ON f.customer_id = a.customer_id
      AND f.txn_time BETWEEN a.reported_at AND a.reported_at + INTERVAL '90 days'
WHERE a.a11y_package NOT IN (SELECT package FROM a11y_allowlist)
GROUP BY 1
HAVING COUNT(DISTINCT a.device_id) >= 5
ORDER BY fraud_rate DESC;
```

**Expected noise:** password managers, TalkBack alternatives, automation tools, remote support.
**Build the allowlist first** - otherwise the hunt returns the legitimate population and buries
the signal.

**Outcome:** any package with a materially elevated fraud rate → pull a sample, analyse
([Ch 11](../static-analysis/11-static-analysis.md)), and if malicious, build a detection.

### HUNT-2 - Clone / repackaged bank app

**Hypothesis:** Apps claiming our package name with a signer outside our canonical registry are
impersonation attempts.

```sql
SELECT s.sha256, s.package_name, s.signer_sha256,
       s.first_seen, s.source_channel
FROM samples s
JOIN protected_packages p ON p.package_name = s.package_name
WHERE s.signer_sha256 NOT IN (
    SELECT signer_sha256 FROM canonical_signers WHERE package_name = p.package_name)
ORDER BY s.first_seen DESC;
```

**Precision: essentially 100%** when the registry is correct - this is the deterministic rule
from [Ch 06 §11](../security/06-certificates.md#11-detection-logic-for-sudarshan). Run it
continuously, not as a hunt, once validated.

### HUNT-3 - Dropper chains in the corpus

**Hypothesis:** Apps that install other apps, where the installer's stated purpose is unrelated,
are droppers.

```sql
SELECT d.installer_package, d.installer_category,
       COUNT(DISTINCT d.installed_package) AS n_installed,
       ARRAY_AGG(DISTINCT d.installed_package) AS payloads
FROM device_install_edges d
WHERE d.installer_package NOT IN (SELECT package FROM known_app_stores)
  AND d.installer_category IN ('utility','tools','productivity','photography')
GROUP BY 1,2
HAVING COUNT(DISTINCT d.installed_package) >= 1
ORDER BY n_installed DESC;
```

**Rationale:** a PDF reader or QR scanner has no legitimate reason to install applications
([Ch 09 §7](../apk/09-package-manager.md#7-droppers-the-technique-in-full)).

### HUNT-4 - Our package name in someone's target list

**Hypothesis:** Samples in the corpus reference our client banks' package names in resources.

```sql
SELECT s.sha256, s.family, s.first_seen,
       ARRAY_AGG(t.target_package) AS our_packages_targeted
FROM samples s
JOIN sample_target_packages t ON t.sha256 = s.sha256
WHERE t.target_package IN (SELECT package_name FROM client_bank_packages)
GROUP BY 1,2,3
ORDER BY s.first_seen DESC;
```

**This is the hunt that produces the escalation email.** It converts corpus data into
*"campaign X is targeting you."* → [Ch 11 §5](../static-analysis/11-static-analysis.md#5-tier-2--resource-and-asset-mining)

### HUNT-5 - Rare-signer capability clusters

**Hypothesis:** Apps with the ODF capability cluster whose signer appears rarely are
disproportionately malicious (established publishers sign many apps; throwaway keys sign few).

```sql
WITH signer_prevalence AS (
  SELECT signer_sha256, COUNT(*) AS n_samples,
         MIN(first_seen) AS signer_first_seen
  FROM samples GROUP BY 1)
SELECT s.sha256, s.package_name, s.signer_sha256, sp.n_samples
FROM samples s
JOIN signer_prevalence sp USING (signer_sha256)
WHERE s.cap_a11y_service
  AND (s.cap_a11y_retrieve_content OR s.cap_a11y_gestures)
  AND (s.cap_overlay::int + s.cap_request_install::int +
       s.cap_sms::int + s.cap_notif_listener::int) >= 2
  AND sp.n_samples <= 3
  AND s.verdict IS NULL                      -- not yet triaged
ORDER BY s.first_seen DESC;
```

---

## 6. Hunting the sample corpus

The corpus is a hunting ground most teams under-use. When new intelligence arrives, **hunt
backwards**.

### Retro-hunting

```
  New intel arrives (e.g. ERMAC 3.0 protocol details, Aug 2025)
            │
            ▼
  Write a YARA/behavioural rule from it
            │
            ▼
  Run it across EVERY sample ever submitted
            │
            ▼
  Findings in samples previously scored "clean" or "inconclusive"
            │
            ▼
  ★ Re-score, and notify the banks that submitted them
```

> **⚙️ Engineering Note - retro-hunting is a product requirement, not a nice-to-have.** A sample
> scored *inconclusive* in March because its C2 was offline
> ([Ch 12 §9](../dynamic-analysis/12-dynamic-analysis.md#9-sandbox-evasion)) should be
> automatically re-evaluated when new intel lands. Build (1) full-corpus rule replay, (2)
> automatic re-scoring, and (3) **notification of the original submitter when a verdict
> changes.** That last one is what makes a bank trust the platform: it means a "clean" answer is
> provisional and revisable, not final and wrong.

VirusTotal/GTI offer the same idea externally as **Retrohunt** and **LiveHunt**
([Ch 11 §9](../static-analysis/11-static-analysis.md#9-yara)).

### Corpus baselining

Before you can spot outliers, know what normal looks like:

| Baseline question | Use |
|---|---|
| Distribution of permission counts | Outlier detection |
| Prevalence of each capability | How rare is `QUERY_ALL_PACKAGES` really? |
| Signer prevalence distribution | HUNT-5 threshold calibration |
| Packer prevalence | Is Virbox rare or common in our corpus? |
| Locale-set distribution | What targeting is normal for our region? |

---

## 7. From hunt to detection

The mandatory final step.

```
  HUNT FINDING
       │
       ▼
  Is it reliably repeatable?  ──no──► document as a lead; note telemetry gap
       │ yes
       ▼
  Can it be expressed as a rule?  ──no──► document; consider new telemetry
       │ yes
       ▼
  Write the rule (Sigma / YARA / SQL / platform rule)
       │
       ▼
  Backtest against historical data - measure the FP rate
       │
       ▼
  FP rate acceptable?  ──no──► tune, add cluster conditions, or shelve
       │ yes
       ▼
  Deploy · map to ATT&CK · assign an owner · schedule review
       │
       ▼
  ★ Update the hypothesis backlog with what you learned
```

### A Sigma rule from HUNT-1

```yaml
title: Non-Allowlisted Accessibility Service on Customer Device
id: 8f2c1a30-4b7e-4e21-9c55-0a1b2c3d4e5f
status: experimental
description: >
  A device reports an enabled accessibility service that is not on the
  known-good allowlist. Primary indicator of Android banking malware
  device-takeover capability. NOT a verdict on its own.
references:
  - docs/malware/13-android-malware.md
author: SUDARSHAN Detection Engineering
date: 2026/08/05
tags:
  - attack.collection
  - attack.t1453
logsource:
  product: mobile
  service: bank_app_sdk
detection:
  selection:
    event_type: 'device_signals'
    accessibility_services_enabled|exists: true
  filter_allowlist:
    accessibility_services_enabled|contains:
      - 'com.google.android.marvin.talkback'
      - 'com.microsoft.appmanager'
      # ... maintained allowlist
  condition: selection and not filter_allowlist
falsepositives:
  - Password managers using autofill via accessibility
  - Screen readers and assistive utilities
  - Automation apps (Tasker, MacroDroid)
  - Remote support tools (TeamViewer, AnyDesk)
level: medium
fields:
  - customer_id
  - device_id
  - accessibility_services_enabled
```

> **⚙️ Engineering Note:** `level: medium`, not `high` - and the `falsepositives` block is
> populated honestly. A rule that fires on every password-manager user and is labelled `high`
> will be muted by the SOC within a week, and then it protects nobody. **Calibrated severity is
> what keeps a rule alive.** → [Ch 19](../soc/19-enterprise-soc-operations.md)

---

## 8. Measuring a hunt programme

| Metric | Measures | Caution |
|---|---|---|
| **Detections created per hunt** | Output that persists | ★ The best single metric |
| Telemetry gaps identified | Where you're blind | Valuable negative result |
| Hypotheses tested / backlog burn-down | Programme health | |
| Time-to-hypothesis-resolution | Efficiency | |
| Findings escalated to IR | Direct impact | Low counts are normal and fine |
| Corpus retro-hunt verdict changes | Value of new intel | ★ Underrated |
| **"Threats found"** | - | ⚠️ **Bad primary metric** - incentivises finding things |

> **⚙️ Engineering Note:** Measuring a hunt team on "threats found" creates pressure to
> manufacture findings and to avoid hunting where nothing is likely. Measure on **detections
> created, telemetry gaps closed, and hypotheses resolved** - a well-documented negative result
> that proves a technique isn't present in your environment is a genuine success and should be
> recorded as one.

---

## 9. Detection logic for SUDARSHAN

### What the platform must provide to hunters

```yaml
hunting_capabilities:
  corpus_search:
    - by_capability_vector          # any combination of capability flags
    - by_signer                     # → Ch 06
    - by_target_package             # ★ "who targets our clients?"
    - by_c2_infrastructure          # → Ch 15
    - by_similarity                 # DEX TLSH distance
    - by_locale_set                 # geographic targeting
    - full_text over strings/resources
  retro_hunt:
    - replay_yara_across_corpus: true
    - replay_behavioural_rules: true
    - auto_rescore_on_new_intel: true          # ★
    - notify_original_submitter_on_change: true # ★★
  baselines:
    - capability_prevalence
    - signer_prevalence
    - packer_prevalence
  export:
    - to_sigma
    - to_yara
    - to_stix
  audit:
    - every_query_logged            # DPDP / access accountability
```

### The hypothesis backlog as a first-class object

```yaml
hypothesis_backlog:
  - id: HUNT-2026-051
    title: "Session-install droppers among Play-sourced utilities"
    priority: high
    trigger: {type: threat_intel, ref: "ThreatFabric Anatsa, Jul 2025"}
    status: queued
    data_available: true
    privacy_cleared: true
    estimated_effort: "2d"
```

> **🏛️ Enterprise Insight:** Expose the backlog to the client bank's security team. Hunting is
> one of the few security activities where a client can meaningfully contribute hypotheses - > they know their own fraud patterns, their customer demographics, and which of their flows are
> unusual. A shared backlog turns SUDARSHAN from a tool into a joint programme, and it surfaces
> hypotheses a vendor would never think of.

---

## 10. Limitations, edge cases, false positives

### Limitations

- **Telemetry is the ceiling.** No SDK in the bank app means no population-scale hunting; you
  are limited to the corpus and fraud data.
- **Privacy constraints are real and binding.** Some valuable hunts are simply not permissible.
- **Consumer devices have no EDR.** Endpoint-hunting techniques don't transfer.
- **Hunting doesn't scale linearly.** It is analyst-bounded by design.
- **Negative results are common** and should be expected, not treated as failure.

### False positives

Every hunt in §5 has a substantial legitimate population:

| Hunt | Dominant noise source |
|---|---|
| HUNT-1 a11y | Password managers, screen readers, automation, remote support |
| HUNT-3 droppers | MDM agents, legitimate stores, OEM suites |
| HUNT-4 target lists | Aggregators, comparison apps, payment SDKs, MDM catalogues |
| HUNT-5 rare signers | Small indie developers; new legitimate publishers |

**HUNT-2 (clone detection) is the exception** - near-zero false positives, because it's a
cryptographic identity check rather than a behavioural heuristic.

> **🚨 Misconception:** "A hunt that returns lots of results found lots of threats." Usually it
> found your baseline. If HUNT-1 returns 40% of your customer base, you're looking at the
> legitimate accessibility-using population and your allowlist isn't built yet. **Build baselines
> before hunting**, or you'll spend your time rediscovering normality.

### Edge cases

| Case | Handling |
|---|---|
| Enterprise-managed devices | MDM legitimately installs apps and holds device admin - separate population |
| Shared/family devices | One device, multiple customers - attribution is ambiguous |
| Regional norms | Third-party stores and sideloading are mainstream in some markets - calibrate per geography |
| Accessibility users | **Never treat as suspicious by default.** Genuine assistive-technology users exist and deserve service. |

> **🏛️ Enterprise Insight:** That last row deserves emphasis. Some customers use accessibility
> services because they need them. A bank whose fraud controls flag disabled customers as
> suspicious has created an accessibility and discrimination problem, not just a false-positive
> problem. **Build the allowlist properly, and never auto-restrict on accessibility alone.**

---

## 11. Engineering tips

1. **Build baselines before hunting.** Otherwise you rediscover normal.
2. **Build the accessibility allowlist first** - it's the precondition for HUNT-1.
3. **Every hunt ends with an artifact** - rule, tuning change, or documented gap.
4. **Run privacy review in Prepare**, not after three days of work.
5. **Retro-hunt on every new intel drop**, and notify submitters when verdicts change.
6. **Backtest before deploying**; measure the FP rate honestly.
7. **Set rule severity conservatively.** Over-severe rules get muted.
8. **Don't measure hunters on "threats found."**
9. **Keep a persistent, prioritised hypothesis backlog** (TaHiTI).
10. **Share the backlog with the client bank.**
11. **Never treat accessibility use as inherently suspicious.**

---

## 12. Judge Insights

**What judges ask:** *"You can't put an agent on customers' phones. So what is there to hunt in?"*

**Perfect answer:** Three places, and none of them is endpoint telemetry. First, the sample
corpus - every APK ever submitted, which we retro-hunt whenever new intelligence lands, so a
sample scored inconclusive in March because its C2 was offline gets automatically re-scored in
August and the submitting bank gets notified that the verdict changed. Second, telemetry the
bank's own app collects from consented devices - deliberately minimal: which accessibility
services and notification listeners are enabled, whether an overlay was present during a
session, whether our own app's signer matches what we published. Not the full app inventory,
because that reveals health, dating, and religious apps and fails DPDP data minimisation. Third,
the fraud transaction data itself, which is the outcome signal we correlate against. The highest
value hunt is joining the first and second: which apps holding accessibility on our customers'
devices also appear in our corpus with an ODF capability cluster.

**Common mistakes:**
- Describing an EDR-shaped hunt programme. Consumer phones have no agent, and the plan won't
  execute.
- Proposing to collect the full installed-app list. It's the obvious idea and it's a privacy
  failure.
- Treating "we found threats" as the success metric.

**Follow-ups to expect:**
- *"What's your best hunt?"* → Clone detection: samples claiming a client bank's package name
  with a signer outside their canonical registry. Near-zero false positives because it's a
  cryptographic identity check, not a heuristic. Once validated it stops being a hunt and becomes
  a continuous detection.
- *"How do you avoid flagging disabled customers?"* → Build the accessibility allowlist properly
  and never auto-restrict on accessibility alone. A bank that flags assistive-technology users as
  fraud risks has created a discrimination problem, not a detection.
- *"What if a hunt finds nothing?"* → That's a legitimate outcome and we record it as one - a
  documented negative that a technique isn't present in this environment has real value.
  Measuring hunters on "threats found" just incentivises manufacturing findings.

**Fact that impresses:** Retro-hunting changes the meaning of a verdict. Because a sample can be
inconclusive purely because its C2 was down at detonation time, "clean" in our platform is
provisional - we replay every new rule across the entire historical corpus and notify the
original submitter when a verdict flips. Most scanners treat a verdict as final; treating it as
revisable is what makes the answer trustworthy.

---

## 13. Interview Insights

**Q: "Difference between threat hunting and alerting?"**
Alerting answers "did a known thing happen?" Hunting answers "is an unknown thing happening?"
Hunting is human-initiated and hypothesis-driven, and its real output is **new detections**, not
individual findings.

**Q: "Walk me through a hunt."**
Use the template: trigger (intel report), a specific falsifiable hypothesis, mapped ATT&CK
techniques, data sources, scope and timebox, success criteria including what a negative result
looks like. Then execute, then - crucially - convert the finding into a rule, backtest it, and
update the backlog.

**Q: "What frameworks do you know?"**
PEAK (Prepare/Execute/Act, with hypothesis-driven, baseline, and model-assisted hunt types) and
TaHiTI (Initiate/Hunt/Finalize, intel-driven, with a hypothesis backlog). Good answer: use TaHiTI
for programme structure and PEAK for the individual hunt.

**Q: "How is mobile hunting different?"**
No EDR agent on consumer devices, so no process trees or file-write telemetry. You hunt in app
SDK telemetry, the sample corpus, and fraud data. Privacy constraints bind much harder because
the subject is a customer, not an employee.

**Q: "Your hunt returned 40% of the customer base. What now?"**
You found the baseline, not a threat. Build the allowlist and the prevalence baseline first, then
re-run. This question tests whether you've actually run a hunt or only read about them.

**Q: "How do you measure hunting?"**
Detections created, telemetry gaps identified, hypotheses resolved, retro-hunt verdict changes.
Explicitly *not* "threats found," which incentivises manufacturing findings and avoiding hunts
where nothing is likely.

**Beginner mistakes:**
- Vague hypotheses that can't be falsified.
- Hunting before baselining.
- Ending a hunt without producing a rule.
- Ignoring privacy constraints until execution.
- Proposing full app-inventory collection.

---

## 14. Cross-references

**Upstream:**
- [← Ch 16 Threat Intelligence](../threat-intelligence/16-threat-intelligence.md) - intel as hunt trigger; ATT&CK mapping
- [← Ch 17 Digital Forensics](../digital-forensics/17-digital-forensics.md) - device artifacts as telemetry

**Downstream:**
- [→ Ch 19 Enterprise SOC](19-enterprise-soc-operations.md) - where hunt-derived rules live
- [→ Ch 20 Incident Response](../incident-response/20-incident-response.md) - escalation path
- [→ Ch 21 AI-assisted Analysis](../ai-malware-analysis/21-ai-assisted-malware-analysis.md) - model-assisted hunting
- [→ Ch 28 Campaign Correlation](../sudarshan/28-campaign-correlation.md) - corpus pivoting
- [→ Ch 30 TI Database](../threat-intelligence/30-threat-intelligence-database.md) - retro-hunt infrastructure

**Related chain:** Intel trigger → hypothesis → corpus/telemetry hunt → finding → detection rule
→ SOC → IR.

---

## 15. References

1. Splunk - **PEAK** Threat Hunting Framework. https://www.splunk.com/en_us/blog/security/peak-threat-hunting-framework.html
2. Betaalvereniging Nederland / DCC-NL - **TaHiTI**: Targeted Hunting integrating Threat Intelligence.
3. Sqrrl / David Bianco - *A Framework for Cyber Threat Hunting*; the Hunting Maturity Model.
4. MITRE ATT&CK for Mobile - technique mapping for hunt hypotheses. https://attack.mitre.org/matrices/mobile/
5. SigmaHQ - Sigma generic detection rule format. https://github.com/SigmaHQ/sigma
6. VirusTotal - Retrohunt and LiveHunt documentation. https://docs.virustotal.com/
7. Digital Personal Data Protection Act, 2023 (India) - purpose limitation, data minimisation.
8. Zscaler ThreatLabz - *Anatsa's Latest Updates* (August 2025) - example hunt trigger.
9. Hunt.io - ERMAC 3.0 source leak (August 2025) - example retro-hunt trigger.
10. NIST SP 800-137 - *Information Security Continuous Monitoring*.

### Further reading
- ThreatHunting Project - open hunt procedure library
- Splunk Security Research - hunt content examples
- OWASP MASVS - MASVS-PRIVACY controls relevant to telemetry design

---

*Previous: [← Ch 17 Digital Forensics](../digital-forensics/17-digital-forensics.md) · Next: [Ch 19 Enterprise SOC Operations →](19-enterprise-soc-operations.md)*
