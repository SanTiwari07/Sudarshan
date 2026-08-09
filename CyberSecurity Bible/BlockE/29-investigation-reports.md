# 29 - Investigation Reports

> **Chapter ID:** `CH29` · **Block:** E · **Status:** Stable
> **Tags:** `#reporting` `#multi-audience` `#evidence` `#regulatory` `#customer-comms` `#auditability`
> **Last Updated:** 2026-08-05 · **Version:** 1.0.0
> **Prerequisites:** [Ch 19](../soc/19-enterprise-soc-operations.md), [Ch 20](../incident-response/20-incident-response.md), [Ch 25](25-investigation-engine.md), [Ch 27](27-risk-scoring.md)

---

## Table of Contents

1. [The report is the product](#1-the-report-is-the-product)
2. [Five audiences, one investigation](#2-five-audiences-one-investigation)
3. [The SOC view](#3-the-soc-view)
4. [The fraud-ops view](#4-the-fraud-ops-view)
5. [The CISO view](#5-the-ciso-view)
6. [The regulatory pack](#6-the-regulatory-pack)
7. [Customer communication facts](#7-customer-communication-facts)
8. [Evidence linking](#8-evidence-linking)
9. [Language discipline](#9-language-discipline)
10. [Generation and review](#10-generation-and-review)
11. [Limitations and edge cases](#11-limitations-and-edge-cases)
12. [Engineering tips](#12-engineering-tips)
13. [Judge Insights](#13-judge-insights)
14. [Interview Insights](#14-interview-insights)
15. [Cross-references](#15-cross-references)
16. [References](#16-references)

---

## 1. The report is the product

Everything upstream - intake, analysis, scoring, correlation - exists to produce **an artifact a
human acts on**. If the report doesn't change what someone does in the next thirty minutes, the
analysis was academic.

```
   Analysis quality   ×   Report quality   =   Actual value
        high                   low                 ≈ 0
```

### The three tests

| Test | Question |
|---|---|
| **Actionability** | Does a reader know what to do differently after reading it? |
| **Defensibility** | Can every claim be verified nine months later? |
| **Legibility** | Does the intended audience understand it without translation? |

> **⚙️ Engineering Note:** The third test is where most security reporting fails. A MITRE-mapped
> technical writeup is unreadable to a fraud-operations manager; a customer-impact summary is
> useless to a detection engineer. **One investigation, multiple renderings** - generated from the
> same structured record, never written twice.

---

## 2. Five audiences, one investigation

```
                    ┌────────────────────────────┐
                    │  STRUCTURED INVESTIGATION  │
                    │  verdict · evidence · IOCs │
                    │  campaign · impact         │
                    └─────────────┬──────────────┘
        ┌─────────────┬───────────┼───────────┬─────────────┐
        ▼             ▼           ▼           ▼             ▼
   ┌─────────┐  ┌──────────┐ ┌────────┐ ┌──────────┐ ┌───────────┐
   │  SOC    │  │ FRAUD OPS│ │ CISO   │ │REGULATORY│ │ CUSTOMER  │
   │ analyst │  │ manager  │ │ board  │ │ pack     │ │ comms     │
   ├─────────┤  ├──────────┤ ├────────┤ ├──────────┤ ├───────────┤
   │technical│  │ customer │ │business│ │  facts + │ │ plain     │
   │ evidence│  │  impact  │ │  risk  │ │timestamps│ │ language  │
   │ ATT&CK  │  │ actions  │ │ trend  │ │ no legal │ │ no blame  │
   │ IOCs    │  │ cohort   │ │ posture│ │conclusion│ │ actionable│
   └─────────┘  └──────────┘ └────────┘ └──────────┘ └───────────┘
```

| Audience | Cares about | Timeframe | Format |
|---|---|---|---|
| **SOC analyst** | Technical evidence, ATT&CK, IOCs, detections | Minutes | Structured + JSON |
| **Fraud ops** | Which customers, what actions, what transactions | **Minutes** | Cohort + action list |
| **CISO / board** | Exposure, trend, posture, what changed | Weekly/monthly | Narrative + figures |
| **Compliance / regulator** | Facts, timestamps, scope | Hours (**6h CERT-In**) | Structured pack |
| **Customer** | What happened, what to do | Hours | Plain language |

---

## 3. The SOC view

```markdown
# INV-2026-0805-014 - Anatsa (TeaBot) - CRITICAL

**Verdict** malicious · **Severity** critical · **Confidence** 0.92
**Ruleset** 2026.08.01 · **Analysis** AN-2026-0805-0042

## Summary
APK submitted from a customer device following a disputed UPI transfer. Confirmed
Anatsa (ThreatFabric; TeaBot per Cleafy) via DEX code similarity (TLSH 31) and C2
overlap. Delivered by a dropper installed from a non-store source. Targets 831
financial institutions including **com.clientbank.app**.

## Capabilities  (MITRE ATT&CK Mobile)
| Capability | Technique | Evidence |
|---|---|---|
| Accessibility abuse | T1453 | res/xml/a11y_config.xml:6 `canPerformGestures="true"` |
| Overlay phishing | T1417.002 | detonation.json:4821 - addView type=2038 over com.decoy.bank @14:32:07 |
| Keylogging | T1417.001 | smali/com/x/A11y.smali:212 - node text capture |
| SMS interception | T1636.004 | AndroidManifest.xml:22 + detonation.json:5044 |
| Anti-removal | T1629.001 | device_policies diff - admin activated post-install |

## Attack chain
dropper (com.fake.pdfreader) → session-install → payload → accessibility
→ self-escalation (4 permissions in 62s) → package enumeration → overlay → OTP intercept

## Indicators
| Type | Value | Confidence | Action | TTL |
|---|---|---|---|---|
| signer_cert_sha256 | 9f2a…c104 | high | **block** | none |
| domain | `dksu[.]top` | high | alert | 90d |
| aes_key | 3f8a…(32B) | high | enrich | 365d |
| sha256 | a6f6…b116 | high | block | 30d |

## Detections available
- Sigma: `android_a11y_non_allowlisted.yml`
- YARA: `family_anatsa_2026.yar`
- Sweep: signer 9f2a…c104 → **340 customer devices**

## Analysis quality
static ✅ · dynamic ✅ · unpacked ✅ · C2 reached ✅ · **ceiling: none**
```

---

## 4. The fraud-ops view

Same investigation. Different language, different first line.

```markdown
# CASE-2026-0805-014 - Mobile banking malware - ACTION REQUIRED

## What this means for us
A malicious app on customer devices can **read the screen and control the phone**,
which lets an attacker operate our app inside the customer's own logged-in session.
Transactions will appear to come from the customer's genuine device and IP.
**Device fingerprinting, geolocation, and app-integrity checks will all pass.**

## Who is affected
| | |
|---|---|
| Customers with this app installed | **340** |
| Confirmed fraudulent transactions | 12 |
| Total exposure | ₹48,20,000 |
| Earliest infection observed | 2026-08-02 09:14 IST |

## Immediate actions
1. ☐ **Hold mobile sessions** - 340 customers (pre-authorised Tier 2)
2. ☐ **Freeze beneficiary accounts** - 4 in-house *(requires Tier 3 sign-off)*
3. ☐ **Review transactions** since each customer's infection time
4. ☐ **Contact customers by phone** - not via the app
5. ☐ **Do not instruct uninstall yet** - device evidence first (see runbook)

## What NOT to rely on
- ❌ OTP - intercepted from SMS *and* notifications
- ❌ Authenticator app - the code is read off the screen
- ❌ Push approval - the malware taps "Approve"
- ✅ **Per-transaction biometric** - the one control that still holds
  *(caveat: watch for biometric→PIN downgrade)*

## Recovery window
Funds typically disperse through mule chains within minutes of transfer.
Beneficiary freezes are only effective very early. Set customer expectations
accordingly - do not promise recovery.
```

> **🏛️ Enterprise Insight:** The *"What NOT to rely on"* section is the highest-value block in
> this view. Fraud teams' mental models are built on classic account-takeover, where OTP and
> device fingerprinting work. **Explicitly listing the controls that fail under On-Device Fraud**
> - and the one that still holds - changes decisions faster than any amount of technical detail.

---

## 5. The CISO view

```markdown
# Mobile Banking Malware - Monthly Exposure Brief, August 2026

## Position
Three active campaigns target our customers. Anatsa is the most significant:
it reaches customers through **Google Play droppers** - apps that are genuinely
clean at review and turn malicious weeks later - so "only install from Play"
is no longer sufficient guidance.

## Figures
| Metric | This month | Change |
|---|---|---|
| Samples analysed naming our packages | 47 | ▲ 12 |
| Customers with confirmed malware | 340 | ▲ 210 |
| Exposure prevented (holds before transfer) | ₹1,92,00,000 | ▲ |
| Loss realised | ₹48,20,000 | ▼ |
| Median detection → session hold | 4 min | ▼ 11 min |

## Context
Industry: Zimperium (March 2026) tracked 34 families targeting 1,243 institutions
across 90 countries; Android malware-driven fraudulent transactions rose 67% YoY.
India: UPI fraud rose ~85% YoY to 13.42 lakh cases / ₹1,087 crore in FY2023-24
(Lok Sabha, disclosed November 2024).

## Decisions requested
1. **In-app accessibility detection** - engineering effort, highest single ROI
2. **Per-transaction biometric** above ₹50,000 - product decision
3. **`FLAG_SECURE`** on login and transaction screens - one-line change, not yet shipped
```

> **⚙️ Engineering Note:** Lead with **what changed**, not what is. A CISO brief that restates the
> threat landscape monthly gets skimmed; one that says "this control is no longer sufficient and
> here are three decisions" gets read. And note that all three requests are things **the bank
> controls** - that's what makes the brief actionable rather than alarming.

---

## 6. The regulatory pack

```yaml
regulatory_pack:
  incident_id: "INC-2026-0805-014"
  institution: "<bank>"

  # ★ starts the CERT-In 6-hour clock - immutable
  detected_at_utc: "2026-08-05T09:14:22Z"
  detection_method: "automated analysis of customer-submitted APK"
  detection_system: "SUDARSHAN v2.4.1, ruleset 2026.08.01"

  incident_type: "mobile banking malware - on-device fraud"
  malware:
    family: "Anatsa"
    aliases: ["TeaBot"]
    attribution_basis: "code similarity + C2 overlap"
    attribution_confidence: "high (family) / medium (campaign) / low (actor)"
    source: "ThreatFabric; Cleafy"

  scope:
    customers_with_malware: 340
    confirmed_fraudulent_transactions: 12
    total_exposure: {currency: "INR", amount: 4820000}
    earliest_infection_utc: "2026-08-02T03:44:00Z"

  attack_vector: "dropper-delivered payload; accessibility service abuse"
  mitre_techniques: ["T1453","T1417.001","T1417.002","T1636.004","T1629.001"]

  personal_data_potentially_accessed:      # ★ DPDP input
    - "authentication credentials"
    - "one-time passwords"
    - "on-screen account information"

  containment:
    first_action_utc: "2026-08-05T09:18:40Z"
    actions: [session_hold, beneficiary_freeze, credential_reset]
    completed_utc: "2026-08-05T09:41:00Z"

  indicators: {...}
  evidence_refs: ["ev_...", "ev_..."]
  chain_of_custody_ref: "COC-2026-0805-014"

  # ★★ THE BOUNDARY
  compliance_assessment_required: true
  reportability_determination: "NOT MADE BY THIS SYSTEM - refer to compliance/legal"
```

> **⚙️ Engineering Note:** That last field is deliberate and non-negotiable
> ([Ch 20 §11](../incident-response/20-incident-response.md#11-regulatory-reporting)). SUDARSHAN
> supplies **facts with timestamps and evidence pointers** and flags *potentially reportable*. It
> must never assert that an incident is reportable under CERT-In, RBI, or DPDP - that is a legal
> determination, and a platform that makes it is both overstepping and creating liability. Encode
> the boundary in the schema so it cannot be quietly crossed by a future feature.

---

## 7. Customer communication facts

SUDARSHAN supplies **facts**; the bank's communications team writes the message.

```yaml
customer_comms_facts:
  what_happened: >
    An application on the customer's device was able to view screen contents and
    control the device, allowing an unauthorised party to operate the banking app
    within the customer's own session.
  when_infected: "2026-08-02 09:14 IST"
  app_name_shown_to_user: "PDF Reader Pro"
  app_installed_from: "a link, not Google Play"
  what_we_did: [session_hold, credential_reset_required, transactions_under_review]
  what_customer_must_do:
    - "Do not uninstall the app yet - our team needs to check the device first"
    - "Do not enter your PIN or password on the device until we confirm it is clean"
    - "Call us on <number>; do not use links in messages"
  recovery_expectation: >
    We have frozen the receiving account and filed with the cybercrime portal.
    Recovery is not guaranteed.
  prevention_guidance:
    - "Never install apps from links in messages"
    - "★ No bank, government scheme, or genuine app requires you to enable
       Accessibility permissions"
```

> **🏛️ Enterprise Insight:** Two things make this section unusually important. First, **honesty
> about recovery** - "we will get your money back" generates complaints and regulatory attention
> when it fails; the honest version is defensible. Second, the accessibility line is the single
> most protective sentence a bank can put in customer education, because it targets the actual
> attack step rather than the delivery channel - which keeps working even as delivery shifts from
> WhatsApp APKs to Play droppers
> ([Ch 14 §8](../banking-malware/14-banking-malware.md#8-india-and-the-upi-fraud-ecosystem)).

---

## 8. Evidence linking

**P3.** Every claim in every view resolves to an artifact.

```markdown
The app can inject taps into other applications.^[ev_01J8A3]

  [ev_01J8A3] res/xml/accessibility_config.xml, line 6
              android:canPerformGestures="true"
              extracted by androguard 4.1.2, rule CAP-A11Y-002,
              ruleset 2026.08.01, at 2026-08-05T09:14:31Z
```

### Rendering rules by audience

| Audience | Evidence rendering |
|---|---|
| SOC | Inline pointers, expandable to raw artifacts |
| Fraud ops | Footnote references; raw detail on demand |
| CISO | Summary only; full report linked |
| Regulatory | **Full pointers mandatory** |
| Customer | **None** - plain language only |

> **⚙️ Engineering Note:** Never strip evidence from the *record* to simplify a *view*. The
> customer-facing message has no citations, but the underlying investigation still carries every
> pointer - because that same incident may be re-examined in a liability dispute where the
> customer's account of events is contested.

---

## 9. Language discipline

### Estimative language

| Phrase | Means | Use when |
|---|---|---|
| "We assess with high confidence" | Multiple strong independent evidence types | Signer + code + C2 agree |
| "We assess with moderate confidence" | Some strong evidence, gaps remain | Code similarity only |
| "We assess with low confidence" | Circumstantial or single-source | Language artifacts, timing |
| "Consistent with" | Compatible - **not proof** | Similarity without confirmation |
| "It is possible that" | Speculation, labelled | Hypotheses |

### Prohibited constructions

| ❌ Don't write | ✅ Write instead |
|---|---|
| "This is definitely Anatsa" | "We assess with high confidence this is Anatsa (basis: signer match, TLSH 31, shared C2)" |
| "Turkish authors" | "Turkish-language artifacts present; note these are spoofable and a known false-flag technique" |
| "This incident is reportable under CERT-In" | "Potentially reportable - refer to compliance" |
| "The customer's device was hacked" | "An application on the device obtained accessibility permissions" |
| "We will recover the funds" | "We have frozen the beneficiary account; recovery is not guaranteed" |
| "VirusTotal shows 42/70" | "42 of 70 engines flagged the sample; engine labels are inconsistent and are corroborating context, not a verdict" |

> **⚙️ Engineering Note:** Build these as **lint rules on generated reports**. An LLM drafting
> prose ([Ch 21 §7](../ai-malware-analysis/21-ai-assisted-malware-analysis.md#7-llms-in-malware-analysis))
> will reach for confident phrasing because it reads better. A post-generation check that flags
> "definitely," "proves," "hacked," and unqualified nationality claims catches the drift
> mechanically instead of relying on reviewer discipline.

---

## 10. Generation and review

```
  Structured investigation record  (Ch 25)
        │
        ▼
  Deterministic rendering ──► SOC view, regulatory pack, IOC exports
        │                     (templated - no LLM, fully reproducible)
        ▼
  LLM narration  ──────────► prose summaries for fraud-ops / CISO views
        │                     ★ grounded: every claim must cite an evidence id
        │                     ★ labelled as AI-generated
        ▼
  Lint (§9)  ──────────────► prohibited-construction check
        │
        ▼
  Human review  ───────────► REQUIRED for: regulatory pack,
        │                     customer comms, any external distribution
        ▼
  Publish, versioned + immutable
```

| View | LLM-drafted? | Human review |
|---|---|---|
| SOC view | Summary only | Optional |
| Fraud-ops view | Yes | **Required** |
| CISO view | Yes | **Required** |
| Regulatory pack | **No - templated** | **Required** |
| Customer comms facts | **No - templated** | **Required** |
| IOC exports | No | No |

> **⚙️ Engineering Note:** The regulatory pack and customer-facing facts are **deterministically
> templated, never LLM-generated**. Both may be quoted in a legal or regulatory proceeding, and
> non-determinism is disqualifying there - the same investigation must render identically every
> time. Use the LLM where prose quality matters and stakes are internal; use templates where
> reproducibility is the requirement.

---

## 11. Limitations and edge cases

| Case | Handling |
|---|---|
| Inconclusive verdict | Report it as inconclusive with the ceiling reason ([Ch 27 §6](27-risk-scoring.md#6-the-confidence-ceiling)) - never omit |
| Verdict changes on retro-hunt | Issue a **revision**, notify prior recipients ([Ch 18 §6](../soc/18-mobile-threat-hunting.md#6-hunting-the-sample-corpus)) |
| Cross-tenant campaign | Share counts; redact institution identities ([Ch 28 §8](28-campaign-correlation.md#8-cross-tenant-correlation)) |
| Analyst disagrees | Both automated and adjudicated verdicts appear |
| Legitimate app scored high | Report the finding, the adjudication, and the tuning action |
| Report requested mid-analysis | Emit partial with `state: partial` and ETA |

> **🚨 Misconception:** "Reports are documentation." Reports are **decisions in a readable
> wrapper**. If a fraud manager cannot tell from the first screen which customers to hold and
> which controls have failed, the report has failed regardless of how thorough the analysis was.

---

## 12. Engineering tips

1. **One investigation, multiple renderings.** Never write the same finding twice.
2. **Lead each view with what that audience must decide.**
3. **Template the regulatory pack and customer facts.** No LLM.
4. **Ground every LLM claim to an evidence id**, and lint the output.
5. **Never assert regulatory reportability.**
6. **Include the "controls that fail" section** in the fraud-ops view.
7. **Be honest about recovery probability.**
8. **Version reports immutably; issue revisions** rather than edits.
9. **Notify prior recipients when a verdict changes.**
10. **Report inconclusive verdicts prominently**, with the reason.
11. **Redact institution identities in shared views.**
12. **Keep full evidence in the record even when a view omits it.**

---

## 13. Judge Insights

**What judges ask:** *"You've analysed the malware. What does the bank actually receive?"*

**Perfect answer:** Five renderings of one investigation, because the audiences need genuinely
different things. The SOC analyst gets MITRE-mapped technical evidence with pointers to specific
files, lines, and detonation log offsets, plus ready IOCs and Sigma rules. Fraud operations gets a
different first line entirely: which 340 customers are affected, what actions to take, and - the
section they value most - **which of their existing controls have failed**, because OTP,
authenticator apps, and push approval all break under on-device fraud while per-transaction
biometric still holds. The CISO gets what changed and three decisions they can actually make. The
regulatory pack is deterministically templated with immutable timestamps, because the CERT-In clock
runs from detection - and it explicitly does *not* assert reportability, since that's a compliance
determination we're not entitled to make. And the customer-facing facts are plain language with no
blame, honest about recovery not being guaranteed.

**Common mistakes:**
- One report for everyone. The fraud manager can't read the ATT&CK matrix and the analyst can't
  act on the customer summary.
- Asserting legal conclusions. Flagging "potentially reportable" is the correct boundary.
- Promising fund recovery.

**Follow-ups to expect:**
- *"Is the report AI-generated?"* → Partly and deliberately not everywhere. Prose summaries for the
  fraud-ops and CISO views are LLM-drafted, grounded so every claim cites an evidence id, linted
  for prohibited constructions, and human-reviewed. The regulatory pack and customer-facing facts
  are **templated, not generated** - they may be quoted in a proceeding, and non-determinism is
  disqualifying there.
- *"What if you're wrong and the verdict changes later?"* → We issue a versioned revision and
  notify prior recipients, because retro-hunting means a verdict is provisional rather than final.
  A sample marked inconclusive because its C2 was offline gets re-evaluated when new intelligence
  lands.
- *"How does a regulator verify your claims?"* → Every claim resolves to an evidence record with a
  file path and line, or a log offset and timestamp, plus the rule, tool, and ruleset versions that
  produced it. They can check it rather than trust it.

**Fact that impresses:** The most valuable single block in the whole report isn't the verdict - it's the fraud-ops "what NOT to rely on" list. Fraud teams' mental models come from classic account
takeover, where OTP and device fingerprinting work. Explicitly stating that OTP is intercepted from
both SMS and notifications, that authenticator codes are read off the screen, that push approval is
tapped by the malware, and that per-transaction biometric is the one control still standing changes
decisions faster than any amount of technical evidence.

---

## 14. Interview Insights

**Q: "Who reads a malware report and what do they need?"**
Five audiences: SOC (technical evidence, ATT&CK, IOCs), fraud ops (customer cohort, actions,
failed controls), CISO (exposure, trend, decisions), compliance (facts and timestamps), customer
(plain language). One structured investigation, multiple renderings.

**Q: "How do you make findings defensible?"**
Every claim carries an evidence pointer - file and line, or log offset and timestamp - plus the
rule, tool, and ruleset versions. Reports are immutably versioned, and corrections are revisions
rather than edits.

**Q: "Would you use an LLM to write the report?"**
For internal prose views, yes - grounded with mandatory evidence citations, linted for overconfident
language, and human-reviewed. Not for the regulatory pack or customer-facing facts, which are
templated because they may be quoted in a proceeding and must render identically every time.

**Q: "Should the report say whether the incident is reportable?"**
No. Supply facts, timestamps, scope, and the personal-data categories potentially accessed, and
flag "potentially reportable - refer to compliance." Reportability is a legal determination.

**Q: "How do you write about attribution?"**
Estimative language with a stated basis: "we assess with high confidence, basis signer match plus
TLSH 31 plus shared C2." Never "definitely." And language artifacts get an explicit spoofability
caveat.

**Beginner mistakes:**
- One report for all audiences.
- Overconfident phrasing.
- Omitting inconclusive results.
- Promising recovery.
- Stripping evidence from the record rather than from the view.

---

## 15. Cross-references

**Upstream:** [Ch 25](25-investigation-engine.md) · [Ch 27](27-risk-scoring.md) ·
[Ch 28](28-campaign-correlation.md) · [Ch 20 §11](../incident-response/20-incident-response.md#11-regulatory-reporting)

**Downstream:** [Ch 30](../threat-intelligence/30-threat-intelligence-database.md) ·
[Ch 34](../appendix/34-judge-preparation.md)

---

## 16. References

1. NIST SP 800-61 Rev. 2 - incident documentation and reporting.
2. CERT-In - Directions of April 28, 2022 (6-hour reporting).
3. Reserve Bank of India - Cyber Security Framework for Banks; customer protection framework.
4. Digital Personal Data Protection Act, 2023 (India).
5. FIRST - Traffic Light Protocol 2.0. https://www.first.org/tlp/
6. OASIS - STIX 2.1 (structured export). https://oasis-open.github.io/cti-documentation/
7. Zimperium zLabs - *Banking Heist Report* (March 19, 2026).
8. Lok Sabha, Ministry of Finance - UPI fraud statistics (disclosed November 25, 2024).
9. ODNI / Sherman Kent - analytic confidence and estimative language standards.

---

*Previous: [← Ch 28 Campaign Correlation](28-campaign-correlation.md) · Next: [Ch 30 Threat Intelligence Database →](../threat-intelligence/30-threat-intelligence-database.md)*
