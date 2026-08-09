# 27 - Risk Scoring

> **Chapter ID:** `CH27` · **Block:** E · **Status:** Stable
> **Tags:** `#risk-scoring` `#calibration` `#confidence` `#severity` `#explainability` `#false-positives`
> **Last Updated:** 2026-08-05 · **Version:** 1.0.0
> **Prerequisites:** [Ch 04](../security/04-android-security-model.md), [Ch 21](../ai-malware-analysis/21-ai-assisted-malware-analysis.md), [Ch 25](25-investigation-engine.md)

---

## Table of Contents

1. [What a score is for](#1-what-a-score-is-for)
2. [Two axes, not one](#2-two-axes-not-one)
3. [The scoring model](#3-the-scoring-model)
4. [Signal weights](#4-signal-weights)
5. [Cluster gating](#5-cluster-gating)
6. [The confidence ceiling](#6-the-confidence-ceiling)
7. [Deterministic overrides](#7-deterministic-overrides)
8. [Explainability](#8-explainability)
9. [Calibration](#9-calibration)
10. [The hard-negative corpus](#10-the-hard-negative-corpus)
11. [Limitations and false positives](#11-limitations-and-false-positives)
12. [Engineering tips](#12-engineering-tips)
13. [Judge Insights](#13-judge-insights)
14. [Interview Insights](#14-interview-insights)
15. [Cross-references](#15-cross-references)
16. [References](#16-references)

---

## 1. What a score is for

A score exists to **order a queue and trigger an action**. It is not a truth value.

```
   ❌ "This app is 87% malware."
        → meaningless; malware isn't a continuous property

   ✅ "Severity: critical. Confidence: 0.92. Recommended action:
       hold sessions for the 340 affected customers.
       Basis: 6 findings, each with an evidence pointer."
        → orders the queue, triggers an action, survives audit
```

The three things a score must support:

| Requirement | Consequence |
|---|---|
| **Ordering** - which sample does an analyst look at first? | Comparable across samples |
| **Action triggering** - should SOAR hold sessions? | Thresholds mapped to actions |
| **Defence** - can we justify this to RBI in nine months? | Deterministic + evidence-linked (**P3**) |

---

## 2. Two axes, not one

**P2.** Collapsing severity and confidence into one number destroys information the consumer
needs.

```
                        CONFIDENCE  (how sure are we?)
                    low                          high
              ┌──────────────────────┬──────────────────────┐
       crit   │ INVESTIGATE URGENTLY │ ★ ACT NOW            │
              │ could be very bad,   │ contain, notify,     │
  SEVERITY    │ we don't know yet    │ sweep                │
  (how bad    ├──────────────────────┼──────────────────────┤
   if true?)  │ MONITOR              │ CLOSE / TRACK        │
       low    │ low value, low       │ confirmed benign or  │
              │ certainty            │ confirmed low-impact │
              └──────────────────────┴──────────────────────┘
```

### Why the top-left quadrant is the important one

*Critical severity, low confidence* is the state a packed, un-unpacked, C2-offline sample lands
in ([Ch 23 §7](23-detection-pipeline.md#7-failure-handling)). A single-number score would render
it as "medium" and it would sit in a queue. Two axes render it as **"potentially catastrophic,
we cannot yet tell - escalate"**, which is the correct handling.

> **⚙️ Engineering Note:** This is the operational face of **P4**. A system that cannot express
> "very bad if true, unknown" will always understate the samples that most resist analysis - which
> are, by design, the ones the adversary most wants you to under-prioritise.

---

## 3. The scoring model

```
  ┌──────────────────────────────────────────────────────────────┐
  │ 1. DETERMINISTIC OVERRIDES        → fixed verdict, exit early │
  │    impersonation · Janus · known-bad signer                   │
  ├──────────────────────────────────────────────────────────────┤
  │ 2. CLUSTER GATE                   → no cluster, no high score │
  │    a11y core + ≥2 supporting capabilities                     │
  ├──────────────────────────────────────────────────────────────┤
  │ 3. WEIGHTED SIGNAL SUM            → base severity              │
  │    capability + structural + intel + behavioural              │
  ├──────────────────────────────────────────────────────────────┤
  │ 4. EVIDENCE-STRENGTH MULTIPLIER   → confidence                 │
  │    dynamic-confirmed > static-inferred                        │
  ├──────────────────────────────────────────────────────────────┤
  │ 5. ★ ANALYSIS-QUALITY CEILING     → caps confidence            │
  │    packed/unopened · C2 down · decompile failed               │
  ├──────────────────────────────────────────────────────────────┤
  │ 6. CONTEXT ADJUSTMENT             → client impact              │
  │    client package targeted · customers affected               │
  └──────────────────────────────────────────────────────────────┘
                              ▼
                (severity, confidence, action, evidence[])
```

### Reference implementation

```python
def score(analysis) -> Verdict:
    ev = []

    # ── 1. deterministic overrides ─────────────────────────────
    for rule in DETERMINISTIC_RULES:                 # §7
        if rule.matches(analysis):
            return Verdict(severity=rule.severity,
                           confidence=rule.confidence,
                           evidence=[rule.evidence(analysis)],
                           basis="deterministic")

    # ── 2. cluster gate ────────────────────────────────────────
    cluster = evaluate_cluster(analysis)             # §5
    if not cluster.satisfied:
        cap = SEVERITY_MEDIUM                        # ★ no cluster → no critical

    # ── 3. weighted sum ────────────────────────────────────────
    base = 0
    for sig in analysis.signals:
        w = WEIGHTS[sig.name]
        base += w
        ev.append(sig.evidence)

    # ── 4. evidence strength → confidence ──────────────────────
    conf = confidence_from_evidence(analysis)        # dynamic > static

    # ── 5. ★ analysis-quality ceiling ──────────────────────────
    ceiling, reason = quality_ceiling(analysis)      # §6
    conf = min(conf, ceiling)

    # ── 6. context ─────────────────────────────────────────────
    ctx = client_impact(analysis)                    # target list ∩ client packages

    return Verdict(
        severity=bucket(min(base, cap if not cluster.satisfied else 100)),
        confidence=conf,
        confidence_ceiling=ceiling,
        ceiling_reason=reason,
        client_impact=ctx,
        evidence=ev,
        ruleset_version=RULESET_VERSION,
    )
```

---

## 4. Signal weights

Illustrative starting values - **calibrate against a real corpus** (§9).

### Capability signals ([Ch 04 §11](../security/04-android-security-model.md#11-detection-logic-for-sudarshan))

| Signal | Weight | Note |
|---|---|---|
| a11y service declared | 20 | Gate member, not standalone |
| `canRetrieveWindowContent` | 15 | Read primitive |
| `canPerformGestures` | 20 | Write primitive |
| a11y unscoped (`packageNames` empty) | 10 | |
| `SYSTEM_ALERT_WINDOW` | 15 | |
| `REQUEST_INSTALL_PACKAGES` | 15 | |
| Notification listener | **12** | ★ Weight comparably to SMS |
| SMS read/receive | 12 | |
| `mediaProjection` FGS type | 12 | |
| `QUERY_ALL_PACKAGES` | 10 | |
| Device admin | 10 | |
| targetSdk < 23 | 20 | Install-blocked on A14+ |

### Structural signals ([Ch 08 §10](../apk/08-apk-file-format.md#10-detection-logic-for-sudarshan))

| Signal | Weight |
|---|---|
| DEX checksum/SHA-1 mismatch | 25 |
| Duplicate ZIP entries | 25 |
| Header ↔ `map_list` mismatch | 20 |
| Zip-Slip entry name | 25 |
| Packer fingerprint | 10 |
| Parser fallback required | 10 |

### Behavioural signals (T4 - highest weight)

| Signal | Weight |
|---|---|
| **Overlay over a different app observed** | **40** |
| **New package installed post-detonation** | **40** |
| Gesture injection into another app | 35 |
| SMS/notification read → outbound network | 35 |
| C2 contact with known-bad infrastructure | 35 |
| Child artifact dumped and malicious | 40 (via propagation) |
| `MediaProjection` started | 20 |
| ≥3 distinct evasion check types | 15 |

### Intelligence signals

| Signal | Weight |
|---|---|
| Signer in known-malicious set | override (§7) |
| TLSH within 50 of known malware | 30 |
| Shared hardcoded key with known malware | 30 |
| C2 in known-malicious infrastructure | 35 |

> **⚙️ Engineering Note:** Behavioural weights exceed capability weights by design. *"Declares
> overlay permission"* is a claim about what an app *could* do; *"drew a `TYPE_APPLICATION_OVERLAY`
> over `com.decoy.bank` at 14:32:07"* is the attack, observed
> ([Ch 25 §4](25-investigation-engine.md#4-the-evidence-ledger)). The weight ratio should reflect
> that difference, and the report should quote the dynamic evidence verbatim.

---

## 5. Cluster gating

**P1 made operational.** No single signal produces a high score.

```yaml
cluster_gate:
  core:                                   # at least one REQUIRED
    - a11y_service AND (can_retrieve_window_content OR can_perform_gestures)
  supporting:                             # at least TWO required
    - overlay_permission
    - request_install_packages
    - sms_read_or_receive
    - notification_listener
    - media_projection_fgs
    - device_admin
    - query_all_packages
  effect_if_unsatisfied:
    severity_cap: medium                  # ★ cannot reach high/critical
    note: "no capability cluster; individual signals are not a verdict"
  exemptions:                             # deterministic rules bypass the gate
    - signer_impersonation
    - structural_janus
    - known_malicious_signer
    - behavioural_overlay_observed        # ★ observation beats gating
```

### Why the gate exists

| Without the gate | With the gate |
|---|---|
| Password manager (a11y) → high score | Capped at medium; no supporting cluster |
| Screen recorder (mediaProjection) → high | Capped |
| App store (`REQUEST_INSTALL_PACKAGES`) → high | Capped |
| Chat app (overlay) → high | Capped |
| **Banking trojan** (all five) → high | **High - correctly** |

> **🚨 Misconception:** "Sum the permissions and threshold it." That model flags every large,
> legitimate app and misses every dropper. Droppers declare almost nothing
> ([Ch 09 §7](../apk/09-package-manager.md#7-droppers-the-technique-in-full)); super-apps declare
> everything. **The cluster's shape matters, not the count.**

---

## 6. The confidence ceiling

**P4.** The single most important safety property in the scoring model.

```yaml
confidence_ceilings:
  packed_and_not_unpacked:      {ceiling: 0.50, reason: "code not readable"}
  decompilation_failed:         {ceiling: 0.55, reason: "code analysis incomplete"}
  c2_unreachable:               {ceiling: 0.30, reason: "behaviour not observable"}   # ★
  dynamic_timeout:              {ceiling: 0.60, reason: "detonation incomplete"}
  no_dynamic_analysis_run:      {ceiling: 0.75, reason: "static only"}
  evasion_detected_no_behaviour:{ceiling: 0.40, reason: "sample likely detected sandbox"}
  ti_enrichment_unavailable:    {ceiling: 0.85, reason: "degraded enrichment"}
  splits_incomplete:            {ceiling: 0.65, reason: "not all split APKs available"}

rule: effective_confidence = min(computed_confidence, min(applicable_ceilings))
```

### The asymmetry that makes it safe

```
   Ceiling on a MALICIOUS sample:  we say "critical, confidence 0.5"
        → escalates for review. Cost: analyst time. ✅

   NO ceiling on an UNANALYSABLE sample: we say "low risk, confidence 0.9"
        → bank acts on it. Cost: undetected fraud. ☠️
```

> **⚙️ Engineering Note:** The ceiling **never raises** a score and **never lowers severity** - it
> only caps *confidence*. A packed sample with a critical capability cluster stays critical
> severity; we simply admit we're less sure. That combination - high severity, capped confidence - > lands in the top-left quadrant of §2 and routes to investigation rather than to closure. That
> is exactly the behaviour you want.

---

## 7. Deterministic overrides

Rules so precise they bypass the weighted model entirely.

| Rule | Verdict | Confidence | Basis |
|---|---|---|---|
| **Signer impersonation** - claims a protected package, signer not in canonical registry | Critical | **1.0** | Cryptographic ([Ch 06 §11](../security/06-certificates.md#11-detection-logic-for-sudarshan)) |
| **Janus shape** - DEX magic at offset 0 on a valid ZIP | Critical | 0.95 | Deterministic byte check |
| **Known-malicious signer** in the TI database | Critical | 0.95 | Identity match |
| **Duplicate ZIP entries** | High | 0.9 | Structural |
| **DEX checksum mismatch** | High | 0.9 | Recomputed |
| **Child artifact confirmed malicious** | Critical | inherit | Propagation ([Ch 25 §5](25-investigation-engine.md#5-score-propagation)) |
| **Overlay over another app observed** | Critical | 0.95 | Behavioural observation |

> **⚖️ Judge Tip:** Deterministic overrides are the strongest demo material in the platform. Two
> APKs, same package name, different certificate fingerprint, instant critical verdict with a
> cryptographic justification and no model involved. It takes thirty seconds and it makes the
> explainability argument concretely rather than abstractly.

---

## 8. Explainability

**P3.** Every point of score traces to an artifact.

```json
{
  "verdict": "malicious",
  "severity": "critical",
  "severity_score": 142,
  "confidence": 0.92,
  "confidence_ceiling": 1.0,
  "ceiling_reason": null,
  "ruleset_version": "2026.08.01",
  "basis": "weighted_cluster",
  "contributions": [
    {"signal":"a11y_can_perform_gestures","weight":20,
     "evidence":{"file":"res/xml/a11y_config.xml","line":6,
                 "excerpt":"android:canPerformGestures=\"true\""}},
    {"signal":"overlay_permission","weight":15,
     "evidence":{"file":"AndroidManifest.xml","line":14}},
    {"signal":"overlay_observed_over_other_app","weight":40,
     "evidence":{"log":"detonation.json","line":4821,
                 "detail":"addView type=2038 while com.decoy.bank foreground",
                 "ts":"2026-08-05T14:32:07Z"}},
    {"signal":"new_package_installed","weight":40,
     "evidence":{"log":"detonation.json","line":5102,
                 "child_artifact":"art_01J8..."}},
    {"signal":"tlsh_similarity_known_family","weight":30,
     "evidence":{"family":"Anatsa","tlsh_distance":31,
                 "reference_sha256":"..."}}
  ],
  "cluster_gate": {"satisfied": true, "core":"a11y_gestures",
                   "supporting":["overlay","request_install","sms"]},
  "client_impact": {"packages_targeted":["com.clientbank.app"],
                    "customers_affected_estimate":340},
  "recommended_actions":["hold_sessions","force_credential_reset",
                         "review_transactions_since_install"]
}
```

> **⚙️ Engineering Note:** The `contributions` array **is** the explanation - no separate
> "explanation module" is needed or wanted. Generating a natural-language rationale from this
> structure is a rendering task ([Ch 29](29-investigation-reports.md)); the *authoritative*
> explanation is the structured record, because that is what an auditor can verify line by line.

---

## 9. Calibration

Weights are hypotheses. Calibrate them or they are guesses with decimal places.

```
  1. Build a labelled corpus
       positives: analyst-adjudicated malicious   (Ch 25 §9)
       negatives: ★ the HARD-NEGATIVE corpus      (§10)
  2. Score every sample with the current ruleset
  3. Plot the severity distribution per class
  4. Choose thresholds against a target FP rate at each action level
  5. Measure precision/recall per rule and per weight
  6. Adjust; add regression tests
  7. Re-run on EVERY ruleset change
```

### Thresholds mapped to actions

| Severity | Score | Action | Target FP rate |
|---|---|---|---|
| Critical | ≥ 120 | Auto-escalate; recommend containment | **< 1%** |
| High | 80–119 | Analyst review within SLA | < 5% |
| Medium | 40–79 | Queue; monitor | < 20% |
| Low | < 40 | Log only | - |

> **⚙️ Engineering Note:** Set the FP target **by action cost**, not globally
> ([Ch 20 §13](../incident-response/20-incident-response.md#13-limitations-edge-cases-false-positives)).
> Critical triggers customer-visible containment, so it needs sub-1% precision. Medium triggers a
> queue entry, so 20% is tolerable. A single global threshold either drowns analysts or misses
> threats - there is no setting at which one number serves both.

### Regression testing

```yaml
scoring_tests:
  must_be_critical:
    - {sha256: "...", note: "confirmed Anatsa"}
    - {sha256: "...", note: "signer impersonation of client bank"}
  must_not_exceed_medium:                 # ★ the hard negatives
    - {sha256: "...", note: "1Password - a11y autofill"}
    - {sha256: "...", note: "TeamViewer - a11y + screen capture + input"}
    - {sha256: "...", note: "client bank's own app - pinning, RASP, obfuscation"}
    - {sha256: "...", note: "F-Droid - REQUEST_INSTALL_PACKAGES"}
    - {sha256: "...", note: "MDM agent - device admin + install"}
  run_on: every_ruleset_change
```

---

## 10. The hard-negative corpus

The most important dataset in the product, and the one teams skip.

| Category | Why it's hard | Examples |
|---|---|---|
| **Password managers** | a11y + autofill | 1Password, Bitwarden |
| **Remote support** | a11y + MediaProjection + input injection - **the Hidden VNC profile** | TeamViewer, AnyDesk |
| **Screen readers / assistive** | a11y with full capability | TalkBack alternatives |
| **Automation** | a11y + gestures | Tasker, MacroDroid |
| **App stores** | `REQUEST_INSTALL_PACKAGES` + session install | F-Droid, Amazon Appstore |
| **MDM agents** | device admin + install + broad permissions | Intune, Workspace ONE |
| **★ Client banks' own apps** | pinning, obfuscation, packing, root/emulator detection | The client's production APK |
| **Regional super-apps** | Very broad permissions are normal | Market-specific |
| **Screen recorders** | MediaProjection + overlay | |
| **Launchers / AV / backup** | `QUERY_ALL_PACKAGES` | |

> **🏛️ Enterprise Insight:** Include **the client bank's own production app** in the hard-negative
> corpus, and test against it before every release. A scorer that flags the most-hardened app on
> the device as the most suspicious one is a specific, embarrassing, and entirely predictable
> failure ([Ch 05 §11](../security/05-android-cryptography.md#11-limitations-edge-cases-false-positives)).
> It also happens to be the first thing a prospective client will try.

---

## 11. Limitations and false positives

### Structural limitations

- **Weights are judgement**, informed by evidence but not derived from it.
- **The corpus is small** relative to the app ecosystem.
- **Drift**: legitimate app behaviour evolves; weights need periodic review.
- **Adversaries can probe** the scoring boundary if scores are exposed raw.

> **⚙️ Engineering Note:** Do not expose raw scores or per-signal weights on a public API. An
> adversary with score feedback can perform boundary probing and tune samples to land just below
> a threshold - a model-extraction attack against a rule system
> ([Ch 21 §6](../ai-malware-analysis/21-ai-assisted-malware-analysis.md#6-adversarial-machine-learning)).
> Expose severity buckets and evidence to authenticated tenants; keep the arithmetic internal.

### Known false positives

| Trigger | Innocent population | Mitigation |
|---|---|---|
| a11y capability | Password managers, assistive tech | Cluster gate + signer allowlist |
| Remote support profile | TeamViewer, AnyDesk | Signer reputation + prevalence |
| Packer | Banks, games, DRM | Weight low; context |
| Obfuscation | Nearly all Play apps | **Not scored** |
| Root/emulator detection | Banking RASP | **Not scored as malicious** |
| Broad permissions | Super-apps | Regional calibration |

### Known false negatives

| Cause | Handling |
|---|---|
| Dropper (payload absent) | Recursion + installer attribution ([Ch 25 §3](25-investigation-engine.md#3-recursion)) |
| Novel family, no intel | Cluster gate still fires on capability |
| Native-only logic | T5 escalation |
| C2 gated | **Inconclusive + requeue**, never clean |

---

## 12. Engineering tips

1. **Two axes always.** Never collapse severity and confidence.
2. **Cluster gate before weighted sum.** No cluster, no critical.
3. **Behavioural weights > capability weights.** Observation beats declaration.
4. **Ceilings cap confidence only** - never severity, never upward.
5. **Deterministic overrides bypass everything** and carry near-1.0 confidence.
6. **The `contributions` array is the explanation.** No separate module.
7. **Version every verdict** with the ruleset that produced it.
8. **Set FP targets by action cost**, not globally.
9. **Build and maintain the hard-negative corpus**, including the client's own app.
10. **Regression-test scoring on every ruleset change.**
11. **Don't expose raw scores externally.**
12. **Never score obfuscation, root detection, or emulator detection as malicious.**

---

## 13. Judge Insights

**What judges ask:** *"How do you know your risk score is right?"*

**Perfect answer:** We don't treat it as a truth value - it exists to order a queue and trigger an
action, and it's built so both are defensible. Three properties. First, two axes: severity and
confidence stay separate, because "potentially catastrophic but we can't yet tell" is a real and
important state that a single number renders as "medium" and buries. Second, cluster gating: no
single signal can produce a high score, so a password manager with an accessibility service caps
at medium while a sample with accessibility plus overlay plus install capability plus SMS access
reaches critical. Third, and most importantly, a **confidence ceiling** - if the sample was packed
and we couldn't unpack it, or its C2 was offline, confidence is capped and the verdict is
inconclusive, never clean. And we calibrate against a hard-negative corpus that deliberately
includes password managers, TeamViewer, MDM agents, and the client bank's own production app,
because a scorer that flags the most-hardened app on the device is a predictable and embarrassing
failure.

**Common mistakes:**
- Presenting a single 0–100 number as the output.
- Summing permissions. It flags every super-app and misses every dropper.
- Scoring obfuscation or root detection as malicious - that's the client's own banking app.

**Follow-ups to expect:**
- *"What's your false positive rate?"* → It depends on the action, deliberately. Critical triggers
  customer-visible containment so we target under 1%; medium just queues, so 20% is tolerable. A
  single global threshold either drowns analysts or misses threats.
- *"Could an attacker tune a sample to score just under your threshold?"* → Yes, which is why we
  don't expose raw scores or weights externally - that's boundary probing, a model-extraction
  attack against a rule system. Tenants see severity buckets and evidence, not the arithmetic.
- *"Why not use ML for the score?"* → Because a bank has to explain a held session to a regulator
  nine months later. "The model said 0.87" fails; "the accessibility config declares
  `canPerformGestures` at line 6, and the app drew an overlay over a banking app at 14:32:07,
  detonation log line 4821" survives. ML orders the queue; rules decide.

**Fact that impresses:** The confidence ceiling is deliberately asymmetric - it caps confidence but
never lowers severity. So a packed sample we couldn't open stays *critical severity with 0.5
confidence*, which routes it to investigation rather than closure. The alternative design, where
inability to analyse quietly produces a low score, means the samples that most resist analysis are
the ones the system most under-prioritises - which is exactly what a packer is for.

---

## 14. Interview Insights

**Q: "Design a risk score for mobile malware."**
Two axes; cluster gating so no single signal dominates; weighted signals with behavioural above
capability; an analysis-quality ceiling on confidence; deterministic overrides for cryptographic
certainties; and evidence pointers on every contribution.

**Q: "Why separate severity and confidence?"**
Because "critical but uncertain" and "certainly minor" are different situations demanding different
actions, and a single number renders both as "medium." The critical-low-confidence quadrant is
where unanalysable samples land, and it must escalate.

**Q: "An app has ten dangerous permissions. High risk?"**
Not necessarily - super-apps and MDM agents legitimately do, and droppers declare almost nothing.
The cluster *shape* matters, not the count.

**Q: "How do you make a score explainable?"**
Deterministic rules with a contributions array: signal, weight, and an evidence pointer to a file
and line or a log offset. Plus the ruleset version, so the verdict is reproducible after rules
change.

**Q: "How would you calibrate it?"**
Labelled corpus with a deliberately hard negative set, score everything, choose thresholds against
per-action FP targets, measure per-rule precision, and regression-test on every ruleset change.

**Q: "What goes in your negative corpus?"**
Password managers, remote-support apps, screen readers, automation tools, app stores, MDM agents,
regional super-apps - and the client bank's own production app, which is obfuscated, pinned, and
root-detecting.

**Beginner mistakes:**
- One number.
- Permission counting.
- No confidence ceiling.
- Negative corpus of ordinary apps only.
- Exposing raw scores publicly.

---

## 15. Cross-references

**Upstream:** [Ch 04 §11](../security/04-android-security-model.md#11-detection-logic-for-sudarshan) ·
[Ch 10 §13](../reverse-engineering/10-reverse-engineering.md#13-detection-logic-for-sudarshan) ·
[Ch 25](25-investigation-engine.md) · [Ch 21 §10](../ai-malware-analysis/21-ai-assisted-malware-analysis.md#10-explainability-for-regulated-banks)

**Downstream:** [Ch 29](29-investigation-reports.md) · [Ch 32](../appendix/32-common-misconceptions.md)

---

## 16. References

1. NIST SP 800-30 Rev. 1 - *Guide for Conducting Risk Assessments*.
2. FIRST - CVSS specification (severity/exploitability separation as a design precedent).
3. MITRE ATT&CK for Mobile. https://attack.mitre.org/matrices/mobile/
4. OWASP MASVS v2.1.0. https://mas.owasp.org/MASVS/
5. MobSF scoring methodology (as a contrast case - hygiene, not maliciousness). https://mobsf.github.io/docs/
6. Pendlebury et al. - *TESSERACT* (USENIX Security 2019) - evaluation bias.
7. Reserve Bank of India - model risk and explainability expectations in financial services.

---

*Previous: [← Ch 26 IOC Extraction](26-ioc-extraction.md) · Next: [Ch 28 Campaign Correlation →](28-campaign-correlation.md)*
