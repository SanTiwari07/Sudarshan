# 19 — Enterprise SOC Operations

> **Chapter ID:** `CH19` · **Block:** D (Operations) · **Status:** Stable
> **Tags:** `#soc` `#siem` `#soar` `#mtd` `#mdm` `#detection-engineering` `#sigma` `#alert-fatigue` `#triage`
> **Last Updated:** 2026-08-05 · **Version:** 1.0.0
> **Prerequisites:** [Ch 16](../threat-intelligence/16-threat-intelligence.md), [Ch 18](18-mobile-threat-hunting.md)

---

## Table of Contents

1. [What a SOC actually is](#1-what-a-soc-actually-is)
2. [Tiers and the triage funnel](#2-tiers-and-the-triage-funnel)
3. [Alert fatigue — the real enemy](#3-alert-fatigue--the-real-enemy)
4. [The technology stack](#4-the-technology-stack)
5. [Mobile-specific tooling: MTD, MDM, UEM](#5-mobile-specific-tooling-mtd-mdm-uem)
6. [Where SUDARSHAN plugs in](#6-where-sudarshan-plugs-in)
7. [Detection engineering](#7-detection-engineering)
8. [The bank SOC ↔ fraud ops relationship](#8-the-bank-soc--fraud-ops-relationship)
9. [Metrics that matter](#9-metrics-that-matter)
10. [Detection logic for SUDARSHAN](#10-detection-logic-for-sudarshan)
11. [Limitations, edge cases, false positives](#11-limitations-edge-cases-false-positives)
12. [Engineering tips](#12-engineering-tips)
13. [Judge Insights](#13-judge-insights)
14. [Interview Insights](#14-interview-insights)
15. [Cross-references](#15-cross-references)
16. [References](#16-references)

---

## 1. What a SOC actually is

A **Security Operations Centre** is the function that turns telemetry into decisions,
continuously. Not a room, not a tool — a **process with people and an SLA**.

For a bank, the mobile-fraud slice of the SOC has a defining property that most SOC literature
doesn't address:

> **The clock is not "mean time to detect." The clock is "before the money is gone."**

Under real-time rails — UPI in India especially — funds disperse through mule chains within
minutes ([Ch 15 §10](../malware/15-malware-infrastructure.md#10-the-money-side-mule-chains)).
A 4-hour MTTD is a normal SOC metric and a **total failure** in mobile banking fraud.

```
   Fraud initiated (T+0)
        │
        ├── T+0–2 min    funds reach tier-1 mule       ← window closes
        ├── T+2–10 min   fan-out to tier-2/3
        ├── T+10–60 min  cash-out / crypto / cross-border
        └── T+1h+        recovery probability ≈ 0
```

> **🏛️ Enterprise Insight:** Every SLA in Block E should be designed against that timeline, not
> against generic SOC benchmarks. A correct answer delivered in four hours is *correct and
> useless*. This is the single most important framing difference between a general SOC and a
> bank's mobile-fraud SOC, and it is worth stating explicitly to any stakeholder.

---

## 2. Tiers and the triage funnel

### The classic model

| Tier | Role | Typical time per item |
|---|---|---|
| **T1 — Triage** | Validate, enrich, close obvious FPs, escalate | 2–10 min |
| **T2 — Investigation** | Scope, correlate, determine impact | 30 min – hours |
| **T3 — Hunt / IR / Detection Engineering** | Novel threats, rule development, incident lead | Hours – days |

### The funnel, with realistic numbers

```
   10,000,000  telemetry events / day
        │  correlation + rules
        ▼
        3,000  alerts / day
        │  automation + enrichment (SOAR)   ← ★ where SUDARSHAN sits
        ▼
          200  T1 triage items
        │
        ▼
           25  T2 investigations
        │
        ▼
            3  T3 incidents / escalations
```

The ratios matter more than the absolutes. **If your automation layer doesn't cut alerts by an
order of magnitude, T1 drowns and quality collapses.**

### The T1 mobile-fraud triage decision tree

```
  ALERT: suspicious app on customer device
        │
        ▼
  Is the app on the known-good allowlist? ──yes──► CLOSE (benign)
        │ no
        ▼
  Is the signer in the known-malicious TI DB? ──yes──► ESCALATE T2 (high conf)
        │ no
        ▼
  Does it hold accessibility AND ≥2 cluster capabilities?
        │                                    │
       yes                                  no
        │                                    ▼
        │                          Any fraud signal on this customer?
        │                                ┌───┴───┐
        │                              yes      no
        │                               │        ▼
        │                               │    CLOSE (monitor)
        ▼                               ▼
  Was it installed by another    ESCALATE T2
  third-party app?
    ┌───┴───┐
   yes      no
    │        ▼
    │   ESCALATE T2 (medium)
    ▼
  ★ ESCALATE T2 — HIGH PRIORITY
    (dropper chain + a11y = the playbook)
    → hold sessions pending review
```

> **⚙️ Engineering Note:** Every branch of that tree is answerable from data SUDARSHAN already
> produces — allowlist, signer TI lookup, capability vector, installer attribution. **That means
> the tree can be automated end to end**, with T1 reviewing the *escalations* rather than
> performing the walk. Automating triage logic that a human would perform identically is the
> highest-ROI SOAR work available. → [Ch 25](../sudarshan/25-investigation-engine.md)

---

## 3. Alert fatigue — the real enemy

More SOCs fail from noise than from missing detections.

### The mechanism

```
  Rule deployed with poor precision
        │
        ▼
  High false-positive volume
        │
        ▼
  Analysts learn "this alert is usually nothing"
        │
        ▼
  Alert is closed reflexively, or muted
        │
        ▼
  ★ The one true positive is closed with the rest
        │
        ▼
  Breach — and the detection technically "worked"
```

### The countermeasures

| Countermeasure | Practice |
|---|---|
| **Tune before deploying** | Backtest against historical data; measure FP rate ([Ch 18 §7](18-mobile-threat-hunting.md#7-from-hunt-to-detection)) |
| **Calibrate severity honestly** | A rule that fires on every password-manager user is not `high` |
| **Enrich before presenting** | An alert with signer reputation, capability vector, and installer attribution attached takes 30 seconds to triage, not 10 minutes |
| **Cluster, don't alert per event** | One case per campaign, not one alert per device |
| **Retire rules** | Track per-rule FP rate; kill rules above threshold |
| **Own every rule** | Unowned rules rot |

> **⚙️ Engineering Note — the single biggest lever is enrichment, not filtering.** An alert that
> arrives with the answer attached ("app X, signer not in registry, a11y + overlay + SMS,
> installed by app Y which is itself unknown, 340 other customers affected") is triaged in
> seconds. The same alert as a bare package name takes ten minutes and gets deprioritised.
> **SUDARSHAN's job is to make alerts self-explanatory**, and that's a more valuable
> contribution than raising detection recall.

> **🚨 Misconception:** "More detections = better security." More *un-tuned* detections =
> worse security, because they consume the attention that would have caught the real one. Six
> well-tuned, owned, ATT&CK-mapped rules beat six hundred imported feed rules.

---

## 4. The technology stack

```
 ┌──────────────────────────────────────────────────────────────────┐
 │ SOURCES                                                          │
 │  bank app SDK · MTD · MDM/UEM · network/DNS · transaction系统    │
 │  · SUDARSHAN analysis results · external TI feeds                │
 └────────────────────────────┬─────────────────────────────────────┘
                              ▼
 ┌──────────────────────────────────────────────────────────────────┐
 │ SIEM — collection, normalisation, correlation, retention         │
 │  Splunk · Elastic · Sentinel · QRadar · Chronicle                │
 └────────────────────────────┬─────────────────────────────────────┘
                              ▼
 ┌──────────────────────────────────────────────────────────────────┐
 │ SOAR — enrichment, automated triage, case management, response   │
 │  ★ where the §2 decision tree runs                               │
 └────────────────────────────┬─────────────────────────────────────┘
                              ▼
 ┌──────────────────────────────────────────────────────────────────┐
 │ ANALYSTS  T1 → T2 → T3                                           │
 └──────────────────────────────────────────────────────────────────┘
```

| Component | Purpose | Mobile-fraud relevance |
|---|---|---|
| **SIEM** | Aggregate, normalise, correlate, retain | Retention matters for CERT-In log obligations |
| **SOAR** | Automate enrichment and response | Runs the triage tree; executes session holds |
| **TIP** | Threat intel management | Feeds signer/C2 lookups ([Ch 30](../threat-intelligence/30-threat-intelligence-database.md)) |
| **Case management** | Investigation record | Chain of custody, regulatory evidence |
| **EDR** | Endpoint detection | **Corporate endpoints only — not customer phones** |
| **MTD** | Mobile threat defence | See §5 |

> **⚙️ Engineering Note:** SUDARSHAN is an **enrichment and analysis service**, not a SIEM
> replacement. Design the integration as: SIEM/SOAR calls SUDARSHAN's API with a sample or a
> package identifier; SUDARSHAN returns a structured verdict with evidence; SOAR renders it into
> the case. Trying to *be* the SOC console is a common product mistake — banks already have one,
> and displacing it is a multi-year procurement fight you don't need.

---

## 5. Mobile-specific tooling: MTD, MDM, UEM

| Category | What it does | Applies to |
|---|---|---|
| **MDM / EMM / UEM** | Device enrolment, policy, app allow/blocklists, remote wipe | **Managed** devices (employees, corporate) |
| **MTD** (Mobile Threat Defence) | On-device malware/network/phishing detection | Managed devices, or consumer if the bank ships an SDK |
| **In-app security SDK** | Signals from within the bank's own app | ★ **Customer devices — the only scalable option** |

Vendors in this space include Zimperium (z9/MTD) and Lookout on the MTD side, and Appdome,
Promon, Guardsquare, Verimatrix, and Build38 on the in-app hardening/RASP side.

### The critical distinction for a bank

```
  EMPLOYEE DEVICE                       CUSTOMER DEVICE
  ───────────────                       ───────────────
  MDM enrolled                          NOT enrolled, never will be
  MTD agent installed                   No agent possible
  Full app inventory visible            Only what our SDK reports
  Policy enforceable                    Only advisory
  Remote wipe available                 Not available
        │                                      │
        ▼                                      ▼
  Classic mobile security             ★ THE ACTUAL PROBLEM
```

> **🏛️ Enterprise Insight:** Most mobile-security vendor material addresses the left column
> because that's the enterprise-IT budget. **The bank's fraud losses come from the right
> column.** A bank cannot MDM-enrol its customers. The only scalable telemetry is what the
> bank's own app can observe about its own environment — which is exactly the minimal signal set
> in [Ch 18 §3](18-mobile-threat-hunting.md#3-telemetry-what-you-can-actually-hunt-in), and it is
> why in-app SDK instrumentation is the highest-leverage investment a bank can make.

---

## 6. Where SUDARSHAN plugs in

```
                          ┌─────────────────────┐
   APK from any source ──►│  SUDARSHAN          │
   (customer device,      │  intake → analysis  │
    fraud team, TI feed,  │  → scoring → report │
    app store monitoring) └──────────┬──────────┘
                                     │ API
        ┌────────────────────────────┼────────────────────────────┐
        ▼                            ▼                            ▼
 ┌──────────────┐            ┌──────────────┐            ┌──────────────┐
 │ SIEM / SOAR  │            │ FRAUD OPS    │            │ TI PLATFORM  │
 │ • alert      │            │ • session    │            │ • IOCs       │
 │   enrichment │            │   hold       │            │ • campaign   │
 │ • auto-triage│            │ • customer   │            │   tracking   │
 │ • case data  │            │   contact    │            │ • retro-hunt │
 └──────────────┘            └──────────────┘            └──────────────┘
```

### The integration contract

```yaml
# SOAR → SUDARSHAN
POST /api/v1/analyze
  {sample_sha256 | apk_upload | package_name+signer, priority: urgent|normal}

# SUDARSHAN → SOAR (structured, self-explanatory)
{
  "verdict": "malicious",
  "severity": "critical",
  "confidence": 0.92,
  "confidence_ceiling_reason": null,        # ★ honest when analysis was limited
  "family": {"name": "Anatsa", "aliases": ["TeaBot"], "basis": "code_similarity+c2"},
  "capabilities": ["accessibility","overlay","sms_intercept","dropper"],
  "mitre": ["T1453","T1417.001","T1636.004","T1629.001"],
  "client_impact": {
    "client_packages_targeted": ["com.clientbank.app"],   # ★ escalation trigger
    "affected_customers_estimate": 340
  },
  "evidence": [
    {"type":"static","claim":"accessibility service with canPerformGestures",
     "artifact":"res/xml/a11y_config.xml"},
    {"type":"dynamic","claim":"overlay window type 2038 over com.decoy.bank",
     "artifact":"detonation_log.json#L4821","timestamp":"..."}
  ],
  "recommended_actions": ["hold_sessions","force_credential_reset",
                          "review_transactions_since_install"],
  "report_url": "https://.../investigations/INV-2026-0805-014"
}
```

> **⚙️ Engineering Note:** The `evidence` array is the difference between an alert an analyst
> trusts and one they don't. Every claim links to a specific artifact — a file path, a log line,
> a timestamp — so a T2 analyst (or an auditor six months later) can verify it rather than
> trusting a score. **Never emit a claim without a pointer to its evidence.**
> → [Ch 29](../sudarshan/29-investigation-reports.md)

---

## 7. Detection engineering

### Detection-as-code

Rules are software. Treat them accordingly.

```
  repo/detections/
    ├── android/
    │   ├── a11y_non_allowlisted.yml        (Sigma)
    │   ├── clone_signer_mismatch.yml
    │   ├── dropper_chain.yml
    │   └── odf_capability_cluster.yml
    ├── yara/
    │   ├── family_anatsa.yar
    │   └── capability_overlay.yar
    └── tests/
        ├── true_positives/                  ← known-malicious samples
        └── false_positives/                 ← known-benign that MUST NOT fire
```

Pipeline: **PR → lint → unit tests (TP fire / FP don't) → backtest against historical data →
review → deploy → monitor FP rate → periodic review.**

### The rule contract

Every rule carries:

```yaml
metadata:
  id: <uuid>
  owner: "detection-eng@bank"        # ★ unowned rules rot
  created: 2026-08-05
  last_reviewed: 2026-08-05
  review_cadence: 90d
  attack_technique: [T1453]
  attack_version: "v17"              # ★ pin it → Ch 16 §3
  severity: medium                   # ★ calibrated, not aspirational
  confidence: medium
  expected_fp_rate: "<2% of alerts"
  known_false_positives: [...]        # ★ populated honestly
  data_source: bank_app_sdk
  linked_docs: "docs/malware/13-android-malware.md#3"
```

### ATT&CK coverage as a management artifact

Mapping every rule to a technique gives you a heatmap that shows **gaps, not just coverage** —
and the honest version from [Ch 16 §3](../threat-intelligence/16-threat-intelligence.md#3-mitre-attck-for-mobile)
is the one to publish internally.

> **⚙️ Engineering Note:** Beware coverage theatre. "We cover 47 techniques" is meaningless if
> the rules are untuned and muted. Measure **effective coverage**: techniques covered by rules
> that are (a) deployed, (b) owned, (c) reviewed within the cadence, and (d) below their FP
> threshold. That number is always smaller and always more useful.

---

## 8. The bank SOC ↔ fraud ops relationship

These are usually **different teams with different tooling, different vocabulary, and different
reporting lines** — and mobile banking malware sits exactly on the seam.

| | SOC | Fraud Operations |
|---|---|---|
| Owns | Infrastructure, endpoints, detection | Transactions, customer accounts |
| Tooling | SIEM, SOAR, EDR | Fraud engine, case management, rules |
| Vocabulary | ATT&CK, IOCs, TTPs | Chargebacks, mule accounts, velocity rules |
| Clock | Minutes–hours | **Seconds–minutes** |
| Sees | The malware | The money |

```
         ┌──────────────────────────────────────────┐
         │  ANDROID BANKING MALWARE                 │
         │  lives on a customer device (neither     │
         │  team's traditional turf) and produces   │
         │  a fraudulent transaction (fraud ops)    │
         │  via a malicious app (SOC)               │
         └────────────────┬─────────────────────────┘
                          │
         ┌────────────────┴─────────────────┐
         ▼                                  ▼
     SOC sees: "malicious app"       Fraud sees: "anomalous txn
     but not the transaction          from a KNOWN device"
                          │
                          ▼
              ★ NEITHER HAS THE FULL PICTURE
```

> **🏛️ Enterprise Insight:** This organisational seam is where SUDARSHAN creates the most
> value — and it is a **process problem before it is a technology problem**. The platform's
> output must be legible to both audiences: MITRE-mapped technical evidence for the SOC, and
> customer/session/transaction impact for fraud ops, generated from the same investigation.
> Practically: agree a **joint escalation path and a shared case ID** before deployment, or the
> best analysis in the world will sit in one team's queue while the other team declines the
> chargeback. → [Ch 20](../incident-response/20-incident-response.md), [Ch 29](../sudarshan/29-investigation-reports.md)

---

## 9. Metrics that matter

| Metric | Why | Caution |
|---|---|---|
| **Time from detection to session hold** | ★ The money clock | The metric that matters most |
| Mean time to triage (MTTT) | T1 throughput | Watch quality alongside |
| Mean time to respond (MTTR) | End-to-end | |
| **False-positive rate per rule** | Alert fatigue driver | ★ Track per rule, not aggregate |
| Alert-to-incident ratio | Signal quality | |
| Effective ATT&CK coverage | Real gaps | Not raw technique count |
| Auto-closed alert % | Automation value | |
| **Recovered funds / prevented loss** | Business outcome | ★ The number the board cares about |
| Alerts per analyst per shift | Burnout indicator | |
| Rules past review cadence | Decay indicator | ★ Underused |

> **⚙️ Engineering Note:** "Alerts handled per analyst" is a **throughput** metric that
> deteriorates quality when used as a target — analysts close faster, not better. Pair it with
> alert-to-incident ratio and per-rule FP rate, and be explicit internally that it's a capacity
> planning number, not a performance one.

---

## 10. Detection logic for SUDARSHAN

### SOC-facing requirements

```yaml
soc_integration:
  api:
    submit_sample: {sla_normal: "15 min", sla_urgent: "3 min"}   # ★ money clock
    lookup_by_package_signer: {sla: "<1 s"}                       # cached verdicts
    bulk_lookup: supported
  output:
    format: [json, stix2.1, sigma, csv]
    self_explanatory: true          # evidence array with artifact pointers
    severity_and_confidence: separate
    confidence_ceiling_reason: exposed
  automation_hooks:
    on_critical: [notify_soc, notify_fraud_ops, create_case]
    on_client_package_targeted: [escalate_immediately]   # ★
  case_management:
    shared_case_id_with_fraud_ops: true    # ★ the §8 seam
    chain_of_custody_retained: true        # → Ch 17
  audit:
    every_query_and_verdict_logged: true
    verdict_changes_notify_submitter: true # → Ch 18 §6 retro-hunt
```

### The triage automation SUDARSHAN should ship

Encode the §2 decision tree as a callable service so the SOC gets a *decision*, not data:

```yaml
POST /api/v1/triage
  {package_name, signer_sha256, installer_package, a11y_enabled, customer_has_fraud_signal}
→
  {
    "decision": "escalate_t2_high",
    "reasons": [
      "signer not in canonical registry for claimed package",
      "installed by third-party app com.fake.pdfreader (not a known store)",
      "accessibility service enabled",
      "capability cluster: a11y + overlay + sms"
    ],
    "recommended_immediate_action": "hold_sessions",
    "auto_closable": false
  }
```

---

## 11. Limitations, edge cases, false positives

### Limitations

- **No agent on customer devices.** Telemetry is limited to what the bank's app reports.
- **SOC ≠ fraud ops.** Organisational integration is a prerequisite, not an afterthought.
- **Automation can't replace judgement** on ambiguous cases — and shouldn't be claimed to.
- **Privacy constraints bind** what can be collected and correlated
  ([Ch 17 §9](../digital-forensics/17-digital-forensics.md#9-chain-of-custody-and-legal-context)).

### False positives at SOC scale

At millions of customers, even a 0.1% FP rate is thousands of alerts. The mitigations:

1. **Allowlists first** (accessibility, known stores, MDM agents).
2. **Cluster into cases** — one case per campaign, not per device.
3. **Auto-close the confidently benign**, with the reason logged.
4. **Route by confidence**, not just severity.

> **🚨 Misconception:** "We can't auto-close alerts — what if we're wrong?" You are already
> effectively auto-closing them, just manually and at random, because a drowning T1 queue gets
> triaged by whatever is on top. **Deliberate, logged, reviewable auto-closure is strictly safer
> than implicit neglect** — and it's auditable, which implicit neglect is not.

### Edge cases

| Case | Handling |
|---|---|
| Customer using genuine assistive tech | Allowlist; **never auto-restrict on a11y alone** ([Ch 18 §10](18-mobile-threat-hunting.md#10-limitations-edge-cases-false-positives)) |
| Shared family device | Attribution ambiguous — widen the review |
| Enterprise-managed customer device | MDM legitimately installs and holds admin |
| Bank's own app on an MDM-managed fleet | Different baseline entirely |
| VIP / high-value customer | Separate escalation path — usually required by policy |

---

## 12. Engineering tips

1. **Design SLAs against the money clock**, not generic MTTD benchmarks.
2. **Enrich alerts so they explain themselves.** Bigger lever than more detections.
3. **Automate the triage tree** — every branch is answerable from existing data.
4. **Track FP rate per rule and retire the worst.**
5. **Own every rule; set a review cadence; act on it.**
6. **Calibrate severity honestly** — over-severe rules get muted.
7. **Measure *effective* ATT&CK coverage**, not raw technique count.
8. **Agree a shared case ID with fraud ops before deployment.**
9. **Integrate with the SIEM; don't try to replace it.**
10. **Log auto-closures with reasons** — auditable beats implicit.
11. **Ship both outputs from one investigation**: technical for SOC, impact for fraud ops.

---

## 13. Judge Insights

**What judges ask:** *"Banks already have a SOC and a fraud team. Where do you actually fit?"*

**Perfect answer:** Precisely on the seam between them, which is where this threat class lives.
The SOC sees "a malicious app" but has no visibility into the transaction. Fraud ops sees "an
anomalous transaction from a known, trusted device" — and under On-Device Fraud, every
device-centric control they have says the customer is legitimate, because it is the customer's
phone. Neither team has the full picture, and the malware sits on a customer device that is
neither team's traditional turf. We produce one investigation with two renderings: MITRE-mapped
technical evidence with artifact pointers for the SOC, and customer, session, and transaction
impact for fraud ops — under a shared case ID. And every SLA is designed against the money
clock, not against generic SOC benchmarks, because under UPI the funds are through a mule chain
in minutes. A correct verdict in four hours is correct and useless.

**Common mistakes:**
- Positioning as a SIEM replacement. Banks have one; displacing it is a procurement fight you
  don't need and don't win.
- Claiming to eliminate analyst work. Claim to make each alert triageable in seconds instead of
  minutes — that's credible and measurable.
- Ignoring the SOC/fraud-ops organisational split, which is a process problem before it's a
  technology one.

**Follow-ups to expect:**
- *"How do you avoid adding to alert fatigue?"* → Enrichment over volume. An alert arriving with
  signer reputation, capability vector, installer attribution, and affected-customer count is
  triaged in seconds. We also cluster into one case per campaign rather than one alert per
  device, and we track false-positive rate per rule and retire the worst.
- *"Can you auto-close alerts?"* → Yes, deliberately and with logged reasons. The alternative
  isn't careful review — a drowning T1 queue is already auto-closing implicitly and at random.
  Deliberate closure is auditable; neglect isn't.
- *"What's your MTTD?"* → Wrong metric for this problem. The one that matters is time from
  detection to session hold, because that's what's measured against fund dispersal.

**Fact that impresses:** Most mobile security tooling — MDM, MTD, EDR — assumes a *managed*
device. A bank cannot enrol its customers' phones in MDM, so all of it addresses the employee
population while the fraud losses come from the customer population. The only scalable telemetry
on a customer device is what the bank's own app can observe about its own environment, which is
why in-app SDK instrumentation is the highest-leverage security investment a retail bank can
make — and why it must be scoped to accessibility and overlay signals rather than the full app
inventory, for DPDP reasons.

---

## 14. Interview Insights

**Q: "Walk me through SOC tiers."**
T1 triages and closes obvious false positives (minutes per item); T2 investigates, scopes, and
determines impact (30 min to hours); T3 hunts, engineers detections, and leads incidents (hours
to days). Then add the ratio point: if automation doesn't cut alerts by an order of magnitude
before T1, quality collapses.

**Q: "What's alert fatigue and how do you fix it?"**
Analysts learn a noisy alert is usually nothing, close it reflexively, and eventually close the
true positive with the rest. Fixes: tune and backtest before deploying, calibrate severity
honestly, enrich so alerts self-explain, cluster into cases, track FP rate per rule, retire bad
rules, and assign an owner to every rule.

**Q: "Difference between SIEM and SOAR?"**
SIEM collects, normalises, correlates, and retains. SOAR automates enrichment, triage, and
response, and manages cases. SIEM tells you something happened; SOAR does something about it.

**Q: "What is MTD and why can't a bank use it for customers?"**
Mobile Threat Defence is on-device detection for **managed** devices. Banks can't enrol customer
phones in MDM, so MTD doesn't reach them. The scalable alternative is an in-app security SDK in
the bank's own app.

**Q: "How do you measure a SOC?"**
Time to containment (for banking fraud: time to session hold), per-rule false-positive rate,
alert-to-incident ratio, effective ATT&CK coverage, and business outcome — prevented loss. Flag
that "alerts handled per analyst" is a capacity metric that degrades quality if used as a target.

**Q: "Detection-as-code — what does that mean in practice?"**
Rules live in version control with tests: true-positive samples that must fire and benign samples
that must not. PR review, backtest against historical data, deploy, then monitor FP rate with a
review cadence and a named owner.

**Beginner mistakes:**
- Equating more detections with better security.
- Deploying rules without backtesting.
- Setting every rule to `high`.
- Ignoring rule ownership and review.
- Treating SOC and fraud ops as one audience.

---

## 15. Cross-references

**Upstream:**
- [← Ch 16 Threat Intelligence](../threat-intelligence/16-threat-intelligence.md) — ATT&CK mapping, IOC quality
- [← Ch 17 Digital Forensics](../digital-forensics/17-digital-forensics.md) — evidence and custody
- [← Ch 18 Mobile Threat Hunting](18-mobile-threat-hunting.md) — where new rules come from

**Downstream:**
- [→ Ch 20 Incident Response](../incident-response/20-incident-response.md) — what happens after escalation
- [→ Ch 21 AI-assisted Analysis](../ai-malware-analysis/21-ai-assisted-malware-analysis.md) — automating triage
- [→ Ch 23 Detection Pipeline](../sudarshan/23-detection-pipeline.md) — SLAs and throughput
- [→ Ch 25 Investigation Engine](../sudarshan/25-investigation-engine.md) — evidence arrays
- [→ Ch 29 Investigation Reports](../sudarshan/29-investigation-reports.md) — dual-audience output

**Related chain:** Telemetry → SIEM → SOAR enrichment (SUDARSHAN) → automated triage → T1/T2 →
fraud ops session hold → IR.

---

## 16. References

1. NIST SP 800-61 Rev. 2 — *Computer Security Incident Handling Guide*.
2. NIST SP 800-137 — *Information Security Continuous Monitoring*.
3. MITRE ATT&CK for Mobile — coverage mapping. https://attack.mitre.org/matrices/mobile/
4. SigmaHQ — Sigma rule format and rule repository. https://github.com/SigmaHQ/sigma
5. Splunk — PEAK framework and detection engineering practice.
6. Zimperium — MTD product documentation and *Banking Heist Report* (March 19, 2026).
7. Lookout — mobile threat defence documentation.
8. Appdome, Promon, Guardsquare, Verimatrix, Build38 — in-app protection/RASP vendor documentation.
9. Reserve Bank of India — Cyber Security Framework for Banks (incident reporting, SOC expectations).
10. CERT-In — Directions of April 28, 2022 (6-hour reporting, log retention).
11. FIRST — CSIRT Services Framework.

### Further reading
- MITRE — *11 Strategies of a World-Class Cybersecurity Operations Center*
- Detection Engineering community resources (Detection Engineering Weekly, DeTT&CT)
- OWASP MASVS — MASVS-RESILIENCE controls relevant to in-app SDK design

---

*Previous: [← Ch 18 Mobile Threat Hunting](18-mobile-threat-hunting.md) · Next: [Ch 20 Incident Response →](../incident-response/20-incident-response.md)*
