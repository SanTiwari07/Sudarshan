# 31 - Future Research

> **Chapter ID:** `CH31` · **Block:** F (Reference) · **Status:** Living document
> **Tags:** `#research-gaps` `#open-problems` `#roadmap` `#unsolved`
> **Last Updated:** 2026-08-05 · **Version:** 1.0.0
> **Prerequisites:** Blocks A–E

---

## Table of Contents

1. [How to read this chapter](#1-how-to-read-this-chapter)
2. [Platform-level open problems](#2-platform-level-open-problems)
3. [Analysis and tooling gaps](#3-analysis-and-tooling-gaps)
4. [Detection and ML gaps](#4-detection-and-ml-gaps)
5. [Operational and organisational gaps](#5-operational-and-organisational-gaps)
6. [India-specific gaps](#6-india-specific-gaps)
7. [Emerging threat classes](#7-emerging-threat-classes)
8. [What SUDARSHAN could contribute](#8-what-sudarshan-could-contribute)
9. [Judge Insights](#9-judge-insights)
10. [Interview Insights](#10-interview-insights)
11. [Cross-references](#11-cross-references)
12. [References](#12-references)

---

## 1. How to read this chapter

Every 🔬 **Research Gap** callout scattered through Blocks A–E is consolidated here, plus problems
that only become visible once the whole picture is assembled.

**Two rules for using it:**

1. **These are genuinely unsolved.** Do not claim SUDARSHAN solves them. Claiming to have solved
   scoped accessibility or robust ML drift resistance will be caught by anyone who works in the
   field, and it costs more credibility than the claim gains.
2. **Naming a gap precisely is itself a contribution.** In a demo or an interview, "here is the
   part nobody has solved, and here is how we degrade gracefully around it" is a stronger position
   than pretending completeness.

| Symbol | Meaning |
|---|---|
| 🔴 | **Fundamental** - no known good solution |
| 🟠 | **Hard** - partial solutions exist, none general |
| 🟡 | **Tractable** - solvable with effort, nobody has done it well |

---

## 2. Platform-level open problems

### 🔴 GAP-1 - Scoped accessibility

**The problem.** `AccessibilityService` grants read (`canRetrieveWindowContent`) and write
(`canPerformGestures`) over **every app's UI**. Assistive technology genuinely needs both. There is
no shipped mechanism to grant a screen reader what it needs while denying a banking app's UI to a
third party.

**Why it's hard.** Any restriction that excludes banking apps from accessibility either breaks
accessibility for banking (a discrimination problem) or creates a bypassable allowlist.

**Partial approaches, none general:** per-app a11y scoping (`packageNames`) is advisory and
attacker-controlled; `FLAG_SECURE` blocks screenshots but not node-text reading; sensitive-window
flags exist as proposals.

> **This is arguably the single most valuable unsolved problem in Android security today.** Every
> family in [Ch 14](../banking-malware/14-banking-malware.md) depends on it.
> *Source: [Ch 04 §10](../security/04-android-security-model.md#10-where-the-model-fails)*

### 🔴 GAP-2 - Distinguishing a legitimate app store from a dropper

**The problem.** Android 15 ties accessibility eligibility to whether an app was installed via the
**session-based install API** - the proxy for "a real app store." Droppers adopted the same API.
ThreatFabric documented Octo2 and Crocodilus doing exactly this.

**Why it's hard.** Both use identical platform mechanics. Distinguishing them needs a trust anchor:
allowlisted store signers, installer attestation, or a store-registration scheme - each with
ecosystem-politics costs.

**Most likely target for the next Android hardening iteration.**
*Source: [Ch 09 §4](../apk/09-package-manager.md#4-session-based-installs), [Ch 15 §8](../malware/15-malware-infrastructure.md#8-dropper-as-a-service-and-zombinder)*

### 🟠 GAP-3 - Point-in-time review cannot see future payloads

**The problem.** Anatsa's droppers were genuinely clean at Play review and turned malicious weeks
later - one reaching **#4 in Play's Top Free Tools by June 29, 2025** after a clean May 7 release.

**Why it's hard.** You cannot statically detect code that does not yet exist. Continuous scanning
helps (Play Protect scans ~200 billion apps daily) but the window between malicious update and
detection is where fraud happens.

**Open direction:** update-diff risk scoring - treating a *behavioural delta* between versions as a
first-class signal rather than re-scoring each version independently.

### 🟠 GAP-4 - Consumer devices have no security agent

MDM/MTD assume managed devices. Banks cannot enrol customer phones. The only scalable telemetry is
what the bank's own app observes about its environment - a narrow, privacy-constrained window.
*Source: [Ch 19 §5](../soc/19-enterprise-soc-operations.md#5-mobile-specific-tooling-mtd-mdm-uem)*

---

## 3. Analysis and tooling gaps

### 🟡 GAP-5 - No Android format-confusion corpus

There is no maintained, canonical set of test APKs exercising each parser-differential class
(duplicate ZIP entries, LFH/CD mismatch, prepended DEX, malformed AXML, non-standard ULEB128) with
known-correct expected parses - the equivalent of what exists for PE and PDF.

**Why it matters:** without it, every analysis platform's structural parsers are untested against
deliberate malformation, and regressions are invisible.

**Tractable.** A well-scoped, publishable contribution.
*Source: [Ch 08 §9](../apk/08-apk-file-format.md#9-format-level-anti-analysis)*

### 🟠 GAP-6 - Unpacking commercially-protected samples at scale

Klopatra (Cleafy, Aug 2025) used **Virbox** plus Java→native migration; GodFather variants migrated
to native code (Cyble). Class-loader hooking defeats many packers because the runtime must
materialise plaintext DEX - but native-loading protectors that never touch a Java class loader
resist it.

**Open direction:** generalised memory-carving heuristics, ART-instrumentation-based dumping, and
automated `JNI_OnLoad` unpacker analysis.
*Source: [Ch 10 §9](../reverse-engineering/10-reverse-engineering.md#9-unpacking-strategy)*

### 🟠 GAP-7 - Static taint analysis at production throughput

FlowDroid is excellent research and too slow, memory-hungry, and fragile on obfuscated code,
reflection, native calls, and Binder-mediated inter-component flow to sit in a high-throughput
pipeline. Everyone falls back to pattern-based flow rules.

**Open direction:** incremental/partial taint analysis with explicit unsoundness budgets, and
reflection resolution informed by dynamic traces.
*Source: [Ch 11 §7](../static-analysis/11-static-analysis.md#7-taint-analysis)*

### 🟡 GAP-8 - SDK-attributed permissions

Manifest merging means an app's permission set includes everything its third-party SDKs request. An
ad SDK requesting `QUERY_ALL_PACKAGES` makes the *app* look like it enumerates packages.

**Why it matters:** a real, under-addressed accuracy problem in mobile static analysis, and a
recurring false-positive source.

**Open direction:** SDK fingerprinting plus provenance attribution per declared permission.
*Source: [Ch 11 §13](../static-analysis/11-static-analysis.md#13-limitations-edge-cases-false-positives)*

### 🟠 GAP-9 - Cross-platform framework blind spots

React Native logic lives in `assets/index.android.bundle`; Flutter in `libapp.so` as compiled Dart;
Cordova in `assets/www/`. Analysts decompile the DEX, find framework glue, and conclude "nothing
here." Tooling maturity for these is far behind DEX analysis.
*Source: [Ch 10 §14](../reverse-engineering/10-reverse-engineering.md#14-limitations-edge-cases-false-positives)*

---

## 4. Detection and ML gaps

### 🔴 GAP-10 - Concept drift in Android malware classifiers

Models degrade continuously as families evolve monthly, platform gates change behaviour, and the
*benign* population drifts too. Retraining needs a continuous labelled stream, which is the hard
part.

**Compounding problem:** labels usually derive from VirusTotal thresholds, so models learn to
predict **VT consensus, not maliciousness** - including its blind spots. Anatsa's droppers were
essentially undetected while topping Play charts.

**Open direction:** analyst-adjudicated label pipelines, drift-aware architectures, and stable
platform-fact features that don't drift.
*Source: [Ch 21 §3–4](../ai-malware-analysis/21-ai-assisted-malware-analysis.md#3-datasets-and-their-limitations)*

### 🟠 GAP-11 - No current public benchmark

Drebin (2010–2012) pre-dates runtime permissions, accessibility abuse, and On-Device Fraud entirely.
AndroZoo provides scale with VT-derived labels. MalRadar is curated but small.

**What's missing:** a dated, adjudicated, temporally-split benchmark reflecting the 2024–2026
landscape, with a **deliberate hard-negative set** (password managers, remote-support apps, MDM
agents, hardened banking apps).
*Source: [Ch 21 §3](../ai-malware-analysis/21-ai-assisted-malware-analysis.md#3-datasets-and-their-limitations), [Ch 27 §10](../sudarshan/27-risk-scoring.md#10-the-hard-negative-corpus)*

### 🟠 GAP-12 - Behavioural biometrics against ODF

Under On-Device Fraud the device, IP, and session are genuine, so behavioural biometrics is often
the **only** remaining signal - and it is imperfect. ATS scripts can be tuned to human-like timing;
a live VNC operator produces genuinely human input.

**Open direction:** detecting the artefacts of `dispatchGesture` specifically - absent touch-pressure
variance, unnaturally precise coordinates, impossible gesture velocities - rather than modelling
"the user."
*Source: [Ch 14 §2](../banking-malware/14-banking-malware.md#2-on-device-fraud-and-device-takeover)*

### 🟡 GAP-13 - Prompt injection via sample content

Feeding decompiled strings and resource text to an LLM creates an injection surface: an adversary
can plant content crafted to read as instructions. Mitigations exist (structural separation,
never letting output mutate verdicts) but there is no rigorous evaluation of injection resistance in
security-analysis LLM pipelines.
*Source: [Ch 21 §7](../ai-malware-analysis/21-ai-assisted-malware-analysis.md#7-llms-in-malware-analysis)*

---

## 5. Operational and organisational gaps

### 🟠 GAP-14 - The SOC ↔ fraud-ops seam

Mobile banking malware sits precisely between two teams with different tooling, vocabulary,
reporting lines, and clocks. **This is a process problem before it is a technology problem**, and it
is under-researched relative to its impact.

**Open direction:** published joint-escalation reference models and shared-case-ID patterns for
retail banks.
*Source: [Ch 19 §8](../soc/19-enterprise-soc-operations.md#8-the-bank-soc--fraud-ops-relationship)*

### 🟠 GAP-15 - Fund recovery under real-time rails

Under UPI, settlement is immediate and irreversible; funds fan out through mule tiers within
minutes. Beneficiary freezes work only very early.

**Open direction:** cross-institution real-time mule-signal sharing, and automated beneficiary
holds triggered by device-compromise signals rather than only by transaction anomalies.
*Source: [Ch 15 §10](../malware/15-malware-infrastructure.md#10-the-money-side-mule-chains), [Ch 20 §8](../incident-response/20-incident-response.md#8-phase-5--recovery)*

### 🟡 GAP-16 - Multi-tenant correlation without disclosure

Sharing indicators across banks while keeping submissions, cohorts, and *the fact that a specific
institution is targeted* private is solvable in principle but has no published reference design for
financial-sector threat sharing under DPDP-style constraints.
*Source: [Ch 28 §8](../sudarshan/28-campaign-correlation.md#8-cross-tenant-correlation)*

---

## 6. India-specific gaps

### 🟠 GAP-17 - UPI-specific fraud telemetry

UPI's properties - real-time settlement, PIN-based authorisation, VPA addressing, multiple apps per
user - create a fraud model that global research under-covers. Most published Android
banking-malware research is Europe- and US-centric.
*Source: [Ch 14 §8](../banking-malware/14-banking-malware.md#8-india-and-the-upi-fraud-ecosystem)*

### 🟠 GAP-18 - Vendor visibility bias toward India

Cleafy sees Italy and Spain; ThreatFabric Western Europe and the US; Group-IB Southeast Asia; Cyble
and CYFIRMA more of India. **"Not seen in India" frequently means "no vendor with Indian visibility
has published."**

**Open direction:** India-focused telemetry and publication - a gap a platform serving Indian banks
is uniquely positioned to close.
*Source: [Ch 16 §11](../threat-intelligence/16-threat-intelligence.md#11-sources-and-how-to-weigh-them), [Ch 30 §5](../threat-intelligence/30-threat-intelligence-database.md#5-provenance)*

### 🟡 GAP-19 - Vernacular customer education

The single most protective message - *"no bank, government scheme, or genuine app requires you to
enable Accessibility"* - needs to work across India's language landscape and varying technical
literacy. Effectiveness of vernacular security messaging is largely unmeasured.

---

## 7. Emerging threat classes

### 🟠 GAP-20 - Biometric-data harvesting for synthetic identity

Group-IB documented **GoldPickaxe** (Feb 15, 2024) as the first iOS trojan harvesting
facial-recognition data and ID documents for AI face-swap to defeat bank biometric verification.

**Why it's a distinct class:** this is not credential theft. Detection tooling - including Block E's
design - models capability clusters aimed at *session hijacking*, not at *biometric enrolment
material capture*. It needs its own detection thinking.
*Source: [Ch 14 §7](../banking-malware/14-banking-malware.md#7-notable-specialists)*

### 🟡 GAP-21 - NFC relay fraud

Copybara has been documented performing NFC-relay card fraud (Cleafy). Relay attacks against
contactless payment via a compromised phone are an under-modelled vector in mobile malware
detection.

### 🟡 GAP-22 - Crypto seed-phrase theft as a distinct objective

Crocodilus (ThreatFabric, Mar 29, 2025) includes a wallet **seed-phrase parser**. The victim asset
is not a session but an irrecoverable secret - no freeze, no reversal, no recovery window. Response
playbooks built around session holds do not apply.

---

## 8. What SUDARSHAN could contribute

Gaps this platform is unusually well-positioned to close, ordered by tractability.

| Gap | Contribution | Effort |
|---|---|---|
| **GAP-5** format-confusion corpus | Publish a test-case set from observed malformations | Low |
| **GAP-11** current benchmark | Publish a dated, adjudicated, temporally-split dataset with hard negatives | Medium |
| **GAP-18** India visibility | Publish India-focused campaign research from real bank submissions | Medium |
| **GAP-8** SDK attribution | SDK fingerprinting + per-permission provenance | Medium |
| **GAP-14** SOC/fraud seam | Publish a joint-escalation reference model | Low |
| **GAP-16** multi-tenant sharing | Publish the tenant-isolation + shared-indicator design | Low |
| **GAP-12** ODF behavioural signals | Characterise `dispatchGesture` artefacts from detonation data | Medium |

> **🏛️ Enterprise Insight:** Publishing research is not a distraction from building the product - > it is how a security platform earns the credibility that procurement actually runs on. The
> format-confusion corpus and a current, honestly-labelled benchmark are both **low-effort,
> high-visibility, genuinely useful** contributions that no vendor currently provides.

---

## 9. Judge Insights

**What judges ask:** *"What can't your platform do?"*

**Perfect answer:** Several things, and I'd rather name them precisely than imply completeness. The
fundamental one is scoped accessibility - there is no way, on Android today, to give a screen reader
the screen access it genuinely needs while denying a third party access to a banking app's UI. Every
family we detect depends on that gap, and we detect the *consequences* rather than closing the gap.
Second, we cannot detect a payload that does not yet exist: Anatsa's dropper reached number four in
Play's Top Free Tools before turning malicious weeks later, and point-in-time review is
structurally blind to that - we handle it with installer attribution and detonation-time package
diffing, not by pretending we can see the future. Third, ML drift is unsolved in this domain, partly
because the standard labelling method teaches models to predict VirusTotal consensus rather than
maliciousness. That's why our verdict layer is deterministic rules rather than a classifier.

**Common mistakes:**
- Claiming completeness. Every experienced person in the room knows accessibility abuse is unsolved.
- Listing gaps without saying how you degrade around them. The gap plus the mitigation is the
  credible answer.

**Follow-ups to expect:**
- *"So what would you research if you had time?"* → A current, honestly-labelled, temporally-split
  benchmark with a deliberate hard-negative set - password managers, remote-support apps, MDM
  agents, hardened banking apps. Drebin is from 2010 to 2012 and pre-dates accessibility abuse
  entirely, so the field is still benchmarking against a threat model that no longer exists.
- *"Is there anything genuinely new emerging?"* → Biometric-data harvesting. Group-IB's GoldPickaxe
  in February 2024 was the first documented iOS trojan collecting facial-recognition data and ID
  documents for AI face-swap against bank verification. It's structurally different from credential
  theft, and our capability-cluster model doesn't cover it yet.

**Fact that impresses:** There is no maintained public corpus of Android format-confusion test cases - no equivalent of what exists for PE or PDF. Every analysis platform's structural parsers are
therefore untested against deliberate malformation. It's a low-effort, genuinely useful contribution
that nobody has made.

---

## 10. Interview Insights

**Q: "What's the hardest unsolved problem in Android security?"**
Scoped accessibility. The API grants read and write over every app's UI, assistive technology needs
both, and there is no shipped way to separate legitimate from malicious use. Google has restricted
it repeatedly - Android 13 Restricted Settings, Android 15's session-install tie - and each time
malware adapted rather than being blocked.

**Q: "Why is ML for malware detection still hard?"**
Concept drift plus label quality. Families evolve monthly, the benign population drifts too, and the
usual labelling method - VirusTotal engine thresholds - teaches models to predict VT consensus
including its blind spots. Plus the adversary is adaptive, which most ML domains don't face.

**Q: "What would you fix in the Android platform if you could?"**
The session-install exemption. Android 15 uses "was it installed via the session API" as the proxy
for "a real app store," and droppers simply adopted the API. Distinguishing them needs a trust
anchor - allowlisted store signers or installer attestation - which is an ecosystem-politics problem
as much as a technical one.

**Q: "Name a gap you could actually close."**
A public Android format-confusion test corpus, or a current adjudicated benchmark with hard
negatives. Both are tractable, both are useful, and neither exists.

**Beginner mistakes:**
- Claiming a research area is solved because a paper exists.
- Not distinguishing fundamental gaps from engineering gaps.
- Citing Drebin results as if they reflect current performance.

---

## 11. Cross-references

Gap sources: [Ch 04](../security/04-android-security-model.md) · [Ch 08](../apk/08-apk-file-format.md) ·
[Ch 09](../apk/09-package-manager.md) · [Ch 10](../reverse-engineering/10-reverse-engineering.md) ·
[Ch 11](../static-analysis/11-static-analysis.md) · [Ch 14](../banking-malware/14-banking-malware.md) ·
[Ch 15](../malware/15-malware-infrastructure.md) · [Ch 16](../threat-intelligence/16-threat-intelligence.md) ·
[Ch 19](../soc/19-enterprise-soc-operations.md) · [Ch 20](../incident-response/20-incident-response.md) ·
[Ch 21](../ai-malware-analysis/21-ai-assisted-malware-analysis.md) · [Ch 27](../sudarshan/27-risk-scoring.md) ·
[Ch 28](../sudarshan/28-campaign-correlation.md)

---

## 12. References

1. Android Developers - `AccessibilityService`; Android 13/14/15 behaviour changes.
2. ThreatFabric - Anatsa Play dropper campaign (July 2025); Octo2 (September 2024); Crocodilus (March 29, 2025).
3. Zscaler ThreatLabz - *Anatsa's Latest Updates* (August 2025).
4. Cleafy Labs - *Klopatra* (August 2025); *Copybara* (NFC relay).
5. Cyble - GodFather native-code migration.
6. Group-IB - *GoldPickaxe* (February 15, 2024) - biometric-data harvesting.
7. Arp et al. - *DREBIN* (NDSS 2014). Allix et al. - *AndroZoo* (MSR 2016). *MalRadar*.
8. Pendlebury et al. - *TESSERACT* (USENIX Security 2019). Jordaney et al. - *Transcend* (USENIX Security 2017).
9. FlowDroid - static taint analysis for Android.
10. OWASP Top 10 for LLM Applications - prompt injection.
11. Google Security Blog - Play Protect scale figures (2024 review).
12. Lok Sabha / I4C - India UPI fraud statistics (2024).

---

*Previous: [← Ch 30 Threat Intelligence Database](../threat-intelligence/30-threat-intelligence-database.md) · Next: [Ch 32 Common Misconceptions →](32-common-misconceptions.md)*
