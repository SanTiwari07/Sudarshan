# 20 - Incident Response

> **Chapter ID:** `CH20` · **Block:** D (Operations) · **Status:** Stable
> **Tags:** `#incident-response` `#nist-800-61` `#picerl` `#playbook` `#cert-in` `#rbi` `#mule-chains` `#containment`
> **Last Updated:** 2026-08-05 · **Version:** 1.0.0
> **Prerequisites:** [Ch 17](../digital-forensics/17-digital-forensics.md), [Ch 19](../soc/19-enterprise-soc-operations.md)

---

## Table of Contents

1. [The frameworks](#1-the-frameworks)
2. [What makes mobile banking fraud IR different](#2-what-makes-mobile-banking-fraud-ir-different)
3. [The response clock](#3-the-response-clock)
4. [Phase 1 - Preparation](#4-phase-1--preparation)
5. [Phase 2 - Detection and Analysis](#5-phase-2--detection-and-analysis)
6. [Phase 3 - Containment](#6-phase-3--containment)
7. [Phase 4 - Eradication](#7-phase-4--eradication)
8. [Phase 5 - Recovery](#8-phase-5--recovery)
9. [Phase 6 - Post-Incident](#9-phase-6--post-incident)
10. [The device remediation runbook](#10-the-device-remediation-runbook)
11. [Regulatory reporting](#11-regulatory-reporting)
12. [Detection logic for SUDARSHAN](#12-detection-logic-for-sudarshan)
13. [Limitations, edge cases, false positives](#13-limitations-edge-cases-false-positives)
14. [Engineering tips](#14-engineering-tips)
15. [Judge Insights](#15-judge-insights)
16. [Interview Insights](#16-interview-insights)
17. [Cross-references](#17-cross-references)
18. [References](#18-references)

---

## 1. The frameworks

### NIST SP 800-61 (four phases)

```
  ┌──────────────┐   ┌──────────────────────┐   ┌─────────────────────┐   ┌──────────────┐
  │ PREPARATION  │──►│ DETECTION & ANALYSIS │──►│ CONTAINMENT,        │──►│ POST-INCIDENT│
  │              │   │                      │   │ ERADICATION,        │   │ ACTIVITY     │
  │              │◄──┴──────────────────────┴───┤ RECOVERY            │◄──┤              │
  └──────────────┘         (iterative)          └─────────────────────┘   └──────────────┘
```

### SANS PICERL (six steps)

**P**reparation → **I**dentification → **C**ontainment → **E**radication → **R**ecovery →
**L**essons Learned.

They are the same model at different granularities. This chapter uses PICERL's six steps because
containment, eradication, and recovery have genuinely distinct mechanics in mobile banking fraud.

> **⚙️ Engineering Note:** The frameworks are correct and generic. **Their weakness for this
> problem is that they assume you control the endpoint.** In mobile banking fraud you control
> the *account* and the *app*, not the device - the device belongs to a customer who may be
> uncooperative, non-technical, or in a different time zone. Every playbook below is written
> around that constraint, which is what makes it different from a standard IR playbook.

---

## 2. What makes mobile banking fraud IR different

| Dimension | Classic IR | Mobile banking fraud IR |
|---|---|---|
| Asset owner | The organisation | **The customer** |
| Endpoint control | Full (EDR, remote wipe) | **None** |
| Containment target | The host | **The account and session** |
| Time budget | Hours–days | **Minutes** ([§3](#3-the-response-clock)) |
| Evidence | Org-owned logs | Customer device + bank records |
| Legal basis | Employment/AUP | **Consent required** |
| Loss | Data, downtime | **Money, and often the bank's liability** |
| Regulator | Sometimes | **Frequently - CERT-In, RBI** |
| "Eradication" | Remove malware | Remove malware **+ recover funds + reset trust** |

```
   ┌────────────────────────────────────────────────────────────┐
   │  YOU CONTROL              │  YOU DO NOT CONTROL            │
   ├───────────────────────────┼────────────────────────────────┤
   │  the account              │  the device                    │
   │  the session              │  the customer's actions         │
   │  the transaction rails    │  the malware's C2               │
   │  your own app             │  what else is installed         │
   │  credentials              │  whether they cooperate         │
   └───────────────────────────┴────────────────────────────────┘
            ▲                                    ▲
     containment happens HERE         forensics needs consent HERE
```

> **🏛️ Enterprise Insight:** This table is the single most useful thing to put in front of a
> bank's IR lead when designing the playbook. **Containment is account-side and immediate;
> device remediation is customer-side, slower, and consent-dependent.** Teams that conflate the
> two end up waiting for device access before stopping the bleeding. Stop the money first.

---

## 3. The response clock

```
  T+0        Fraudulent transfer initiated on the victim's device
   │
   ├─ T+0–2m    Funds reach tier-1 mule           ★ RECOVERY WINDOW
   │            ── containment must happen HERE
   │
   ├─ T+2–10m   Fan-out to tier-2/3 mules
   │
   ├─ T+10–60m  Cash-out / crypto / cross-border
   │
   ├─ T+1h      Recovery probability ≈ 0
   │
   ├─ T+6h      ★ CERT-In reporting deadline (if reportable)
   │
   └─ T+days    Customer dispute, liability determination, regulatory filing
```

Under real-time rails - **UPI in India especially** - settlement is immediate and irreversible
([Ch 14 §8](../banking-malware/14-banking-malware.md#8-india-and-the-upi-fraud-ecosystem)).

> **⚙️ Engineering Note - the two-track principle.** Because the money clock (minutes) and the
> investigation clock (hours) are incompatible, IR must run **two tracks in parallel**:
>
> ```
>  TRACK 1 - CONTAIN (minutes, automated, low-confidence-tolerant)
>    hold session · block transaction · freeze beneficiary · notify customer
>
>  TRACK 2 - INVESTIGATE (hours, analytical, high-confidence-required)
>    sample analysis · device forensics · campaign correlation · reporting
> ```
>
> Track 1 must be **allowed to act on medium confidence**, because the cost of a wrongly held
> session (customer inconvenience, reversible in minutes) is orders of magnitude below the cost
> of a completed fraud (irrecoverable). Track 2 sets the record straight afterwards. Designing
> both tracks to the same confidence bar is the most common and most expensive IR design error
> in this domain.

---

## 4. Phase 1 - Preparation

Everything that must exist **before** an incident.

| Item | Detail |
|---|---|
| **Playbooks** | This chapter's §10 runbook, rehearsed |
| **Joint SOC/fraud escalation path** | Shared case ID, agreed thresholds ([Ch 19 §8](../soc/19-enterprise-soc-operations.md#8-the-bank-soc--fraud-ops-relationship)) |
| **Canonical signer registry** | Package → expected signer SHA-256 ([Ch 06](../security/06-certificates.md)) |
| **Accessibility allowlist** | Known-good a11y services ([Ch 18](../soc/18-mobile-threat-hunting.md)) |
| **Session-hold capability** | Technical ability to freeze a session in seconds |
| **Beneficiary-freeze capability** | Ability to hold outbound to a suspect account |
| **Consented forensic workflow** | Legal-reviewed, DPDP-scoped ([Ch 17 §9](../digital-forensics/17-digital-forensics.md#9-chain-of-custody-and-legal-context)) |
| **Customer comms templates** | Pre-approved, in local languages |
| **Regulator contacts and templates** | CERT-In, RBI |
| **SUDARSHAN integration** | API, SLAs, auto-escalation hooks |
| **Tabletop exercises** | Rehearsed, with fraud ops present |

> **🏛️ Enterprise Insight:** The item banks most often lack is a **rehearsed joint exercise with
> fraud ops in the room**. The technology usually works; the handoff usually doesn't. Run a
> tabletop where the SOC detects an ODF-capable app on 300 customer devices at 2am and see who
> has authority to hold sessions. The answer is frequently "nobody, until morning," which is the
> finding that matters.

---

## 5. Phase 2 - Detection and Analysis

### Entry points

```
  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
  │ Customer reports │  │ Fraud engine     │  │ SUDARSHAN /      │
  │ unauthorised txn │  │ anomaly          │  │ hunt finding     │
  └────────┬─────────┘  └────────┬─────────┘  └────────┬─────────┘
           └─────────────────────┼─────────────────────┘
                                 ▼
                    ┌────────────────────────┐
                    │ TRIAGE (Ch 19 §2 tree) │
                    └────────────┬───────────┘
                                 ▼
                 ┌───────────────┴───────────────┐
                 ▼                               ▼
        TRACK 1: CONTAIN NOW           TRACK 2: INVESTIGATE
```

### The ODF signature - what confirms it

| Evidence | Source |
|---|---|
| Transaction from a **known** device and IP | Bank session logs |
| Device passed integrity/attestation | Play Integrity ([Ch 04](../security/04-android-security-model.md)) |
| Non-allowlisted accessibility service enabled | App SDK / device forensics |
| App installed by another third-party app | `packages.xml` ([Ch 17 §5](../digital-forensics/17-digital-forensics.md#5-the-artifact-map)) |
| Permission-grant burst < 2 min after a11y enable | `packages.xml` timestamps |
| OTP sent per bank records but **absent on device** | Correlation |
| Install time **precedes** the fraud | Timeline ([Ch 17 §6](../digital-forensics/17-digital-forensics.md#6-reconstructing-the-attack-timeline)) |

> **⚙️ Engineering Note:** *"Every device-centric control passed, and yet the transaction is
> disputed"* is itself the ODF signature. Under classic credential theft you'd see a new device,
> a new IP, or a failed step-up. **Clean device signals plus a disputed transaction should raise
> suspicion of ODF, not lower it.** That inversion is counter-intuitive to fraud engines tuned
> on classic ATO patterns, and it's worth explicitly encoding as a rule.

---

## 6. Phase 3 - Containment

**Track 1. Minutes. Automated where possible.**

```
  IMMEDIATE (seconds–minutes)
   ├── Hold the active session(s) for the affected customer
   ├── Block pending/queued transactions
   ├── Freeze the beneficiary account (if within the institution)
   ├── Flag the beneficiary to the receiving bank / NPCI channel
   ├── Suspend mobile-channel transactions for that customer
   └── Notify the customer via a SEPARATE channel (call, not the app)

  SHORT-TERM (minutes–hour)
   ├── Sweep: which other customers have this package/signer installed?
   ├── Apply the same holds to that cohort - proportionately
   ├── Block C2 infrastructure at the bank's network egress
   └── Push IOCs to SIEM/MTD/TIP

  DEVICE-SIDE (customer-dependent, slower)
   └── ★ ISOLATE, DO NOT REMEDIATE YET  → §10
```

> **⚙️ Engineering Note - the sweep is the highest-value containment action.** One confirmed
> infection tells you a package name and a signer fingerprint. Sweeping the customer base for
> that signer converts a single-customer incident into a campaign-scale containment. It is also
> where SUDARSHAN's corpus and the bank's telemetry combine most usefully:
> **one submission protects thousands.**

### Proportionality

Holding sessions for 340 customers is disruptive. Calibrate:

| Confidence | Cohort action |
|---|---|
| Confirmed malicious (signer in TI DB, dynamic-confirmed) | Hold all, notify all |
| High confidence, no dynamic confirmation yet | Hold high-value; enhanced monitoring for the rest |
| Medium (capability cluster, unknown signer) | Enhanced monitoring; step-up auth on transactions |
| Low | Monitor; no customer-visible action |

> **🏛️ Enterprise Insight:** Get this graduated response agreed and signed off **in advance**,
> in Preparation. Deciding proportionality during an incident, at speed, without pre-agreed
> authority, is how banks end up either over-reacting (thousands of angry customers) or
> under-reacting (waiting for certainty while funds disperse). Pre-authorised tiers remove the
> decision from the critical path.

---

## 7. Phase 4 - Eradication

### Account side

```
  ├── Force credential reset (password, MPIN, UPI PIN)
  ├── Invalidate ALL sessions and device bindings
  ├── Re-enrol the device only AFTER device remediation is verified
  ├── Revoke and reissue any compromised payment instruments
  └── Review and reverse where possible: all transactions since infection time
```

> **⚙️ Engineering Note - sequencing trap.** Resetting credentials **while the malware is still
> resident and accessibility is still enabled** simply hands the attacker the new credentials - > they can read the reset flow off the screen and tap through it. **Device remediation must
> precede credential reset**, or the reset must be performed out-of-band on a different device.
> This is a genuine, commonly-made error.

### Device side

Full runbook in §10. The ordering rule, restated because it is the most important thing in this
chapter after the two-track principle:

```
  ISOLATE  →  ACQUIRE  →  REMEDIATE
     (network)   (forensics)   (removal)
```

Never remediate first. **BRATA and BingoMod wipe the device** when they detect removal attempts
(Cleafy), destroying the evidence that determines liability
([Ch 13 §8](../malware/13-android-malware.md#8-device-admin-abuse-and-anti-removal)).

---

## 8. Phase 5 - Recovery

| Action | Notes |
|---|---|
| Verify device is clean | `pm list packages -3`, `enabled_accessibility_services` re-checked |
| Re-enrol device binding | Only after verification |
| Restore transaction capability | Graduated - low limits first |
| Enhanced monitoring | 30–90 days on the affected customer |
| Fund recovery | Beneficiary freeze, inter-bank recall, law enforcement |
| Customer communication | Clear, non-blaming, with prevention guidance |

### Fund recovery reality

Be honest with the customer and internally: **recovery probability drops steeply with time**.
Within the first minutes, a beneficiary freeze can work. After the funds have fanned out through
tiers of mules and been cashed out, recovery is largely a law-enforcement matter with low success
rates. In India this routes through the **National Cybercrime Reporting Portal / helpline 1930**
and the I4C ecosystem.

> **🏛️ Enterprise Insight:** Set expectations honestly in customer communications. Overpromising
> recovery generates complaints and regulatory attention when it fails. "We have frozen the
> receiving account and filed with the cybercrime portal; recovery is not guaranteed" is a
> defensible statement. "We will get your money back" usually isn't.

---

## 9. Phase 6 - Post-Incident

### The lessons-learned review

Questions worth answering honestly:

1. How long from infection to detection? What would have shortened it?
2. Was the detection automated or customer-reported? (Customer-reported = a detection gap.)
3. Did containment happen inside the money clock? If not, where was the delay - technical or
   authority?
4. Did SOC and fraud ops coordinate cleanly, or was there a handoff gap?
5. What new detection came out of this? ([Ch 18 §7](../soc/18-mobile-threat-hunting.md#7-from-hunt-to-detection))
6. Was any telemetry missing that would have helped?
7. Did the customer comms work?

> **⚙️ Engineering Note:** The most valuable and most skipped output is **a new detection rule
> and a retro-hunt**. Every real incident should produce: (a) a rule that would have caught it
> earlier, (b) a corpus retro-hunt for the same signer/family, and (c) a customer-base sweep.
> Without those three, you have handled an incident rather than improved.

---

## 10. The device remediation runbook

The operational core of this chapter. Print it.

```
╔══════════════════════════════════════════════════════════════════════╗
║  ANDROID BANKING MALWARE - DEVICE REMEDIATION RUNBOOK                ║
╠══════════════════════════════════════════════════════════════════════╣
║ STEP 0 - DO NOT power off. DO NOT uninstall yet.                     ║
║   Rationale: powering off drops AFU→BFU (Ch 05 §6, Ch 17 §3).        ║
║              Uninstall may trigger wipe (BRATA, BingoMod).           ║
╠══════════════════════════════════════════════════════════════════════╣
║ STEP 1 - ISOLATE                                                     ║
║   Airplane mode ON (or Faraday bag).                                 ║
║   Prevents remote wipe command and further exfiltration.             ║
╠══════════════════════════════════════════════════════════════════════╣
║ STEP 2 - CONTAIN (account side, in parallel - Track 1)               ║
║   Session hold · block transactions · freeze beneficiary.            ║
╠══════════════════════════════════════════════════════════════════════╣
║ STEP 3 - ACQUIRE (with consent, DPDP-scoped)                         ║
║   settings get secure enabled_accessibility_services                 ║
║   settings get secure enabled_notification_listeners                 ║
║   pm list packages -f -i -3                                          ║
║   dumpsys package / device_policy / usagestats / notification        ║
║   appops get --all                                                   ║
║   pull all APK paths (including splits)                              ║
║   adb bugreport ; hash everything                          (Ch 17 §4)║
╠══════════════════════════════════════════════════════════════════════╣
║ STEP 4 - SUBMIT to SUDARSHAN                                          ║
║   Sample → analysis; signer → TI lookup; targets → client impact.    ║
╠══════════════════════════════════════════════════════════════════════╣
║ STEP 5 - SWEEP the customer base for the same package/signer.        ║
║   ★ Converts one incident into campaign-scale containment.           ║
╠══════════════════════════════════════════════════════════════════════╣
║ STEP 6 - REMEDIATE the device                                        ║
║   6a. Boot into SAFE MODE                                            ║
║       → disables ALL third-party apps and their a11y services,       ║
║         defeating anti-uninstall, overlay obstruction, watchdogs.    ║
║   6b. Settings → Security → Device admin apps → REVOKE               ║
║   6c. Settings → Apps → uninstall the malicious package(s)           ║
║       (or: adb shell pm uninstall --user 0 <pkg>)                    ║
║   6d. Disable any remaining unknown accessibility services           ║
║   6e. Reboot normally                                                ║
╠══════════════════════════════════════════════════════════════════════╣
║ STEP 7 - VERIFY                                                      ║
║   pm list packages -3 -i        (is it gone? anything else odd?)     ║
║   settings get secure enabled_accessibility_services   (empty/known?)║
║   dumpsys device_policy         (no rogue admin?)                    ║
╠══════════════════════════════════════════════════════════════════════╣
║ STEP 8 - ERADICATE (account side) - ONLY AFTER STEP 7 PASSES         ║
║   Force credential reset (password, MPIN, UPI PIN)                   ║
║   Invalidate all sessions and device bindings; re-enrol              ║
║   ⚠ Resetting BEFORE the device is clean hands the attacker          ║
║     the new credentials.                                             ║
╠══════════════════════════════════════════════════════════════════════╣
║ STEP 9 - RECOVER                                                     ║
║   Graduated limits · 30–90d enhanced monitoring · fund recovery ·    ║
║   customer guidance.                                                 ║
╠══════════════════════════════════════════════════════════════════════╣
║ STEP 10 - POST-INCIDENT                                              ║
║   New detection rule · corpus retro-hunt · lessons learned ·         ║
║   regulatory filing if applicable.                                   ║
╚══════════════════════════════════════════════════════════════════════╝

  IF THE DEVICE CANNOT BE CLEANED (rooted, persistent, uncooperative):
    → factory reset, and DO NOT restore from a backup taken after infection
    → re-enrol as a new device with fresh credentials
```

> **⚙️ Engineering Note - why Safe Mode is the key step.** Safe Mode disables all third-party
> apps, which simultaneously defeats accessibility-based uninstall interception, overlay
> obstruction of the uninstall dialog, and watchdog process pairs
> ([Ch 13 §8](../malware/13-android-malware.md#8-device-admin-abuse-and-anti-removal)). It turns
> a frustrating removal into a routine one. Most consumer-facing removal advice omits it, which
> is why customers report "I tried to uninstall and it wouldn't let me."

---

## 11. Regulatory reporting

### India

| Obligation | Body | Timing |
|---|---|---|
| Cyber incident reporting | **CERT-In** (Directions, April 28 2022) | **Within 6 hours** of noticing a reportable incident |
| Log retention | CERT-In | 180 days, within India |
| Cyber-security incident reporting | **RBI** (Cyber Security Framework for Banks) | Per framework timelines |
| Customer fraud reporting | RBI customer-protection framework | Per circular timelines |
| Personal data breach | **DPDP Act 2023** | Notification obligations to the Data Protection Board and affected principals |
| Cybercrime complaint | National Cybercrime Reporting Portal / **1930** | ASAP - affects fund recovery |

> **⚙️ Engineering Note:** The **6-hour CERT-In clock** runs from *noticing*, which means your
> detection timestamp is legally significant. Log it precisely and immutably. A dispute about
> when the bank "noticed" an incident is a dispute you want documentation to settle. Build
> detection-time recording into the platform, not into a spreadsheet.

> **🏛️ Enterprise Insight:** Reportability determination is a **legal and compliance decision**,
> not an engineering one. SUDARSHAN's role is to supply the facts - what, when detected, how
> many customers, what data was accessible - with timestamps and evidence pointers, and to flag
> *"potentially reportable - refer to compliance"*. It should never assert reportability itself.
> Encode that boundary in the product. This document is not legal advice.

### The reporting pack

```yaml
regulatory_pack:
  incident_id: INC-2026-0805-014
  detected_at_utc: "2026-08-05T09:14:22Z"      # ★ starts the 6h clock
  detection_source: "SUDARSHAN automated triage"
  incident_type: "mobile banking malware / on-device fraud"
  affected_customers: 340
  confirmed_fraudulent_transactions: 12
  total_exposure_inr: 4820000
  malware: {family: "Anatsa", aliases: ["TeaBot"], source: "ThreatFabric"}
  attack_vector: "dropper-installed payload, accessibility abuse"
  mitre: [T1453, T1417.001, T1636.004, T1629.001]
  iocs: {signer_sha256: [...], c2: [...], packages: [...]}
  containment_actions: [...]
  containment_completed_at_utc: "..."
  personal_data_accessible: ["credentials","otp","screen_contents"]  # DPDP input
  compliance_review_required: true              # ★ never self-assert reportability
```

---

## 12. Detection logic for SUDARSHAN

### IR-facing capabilities

```yaml
ir_support:
  urgent_analysis:
    sla: "3 minutes"                       # ★ money clock
    partial_results_streamed: true         # don't wait for full analysis
  sweep:
    by_signer_sha256: true                 # ★ highest-value containment action
    by_package_name: true
    by_code_similarity: true
    returns: affected_customer_cohort
  timeline:
    reconstruct_from_device_artifacts: true # → Ch 17 §6
    correlate_with_bank_transactions: true
  case:
    shared_id_with_soc_and_fraud_ops: true
    chain_of_custody_retained: true
    immutable_detection_timestamp: true     # ★ CERT-In clock
  outputs:
    containment_recommendations: true
    regulatory_pack: true
    customer_comms_facts: true
  post_incident:
    auto_generate_detection_candidate: true
    trigger_corpus_retro_hunt: true         # → Ch 18 §6
```

### Partial results matter

```
  T+0:00  sample submitted
  T+0:05  ★ structural + manifest done → capability cluster known
          → EMIT PARTIAL: "high-risk capability cluster, recommend session hold"
  T+0:45  static code analysis done → family candidate
          → EMIT PARTIAL: "consistent with Anatsa"
  T+8:00  dynamic detonation done → C2, target list, confirmation
          → EMIT FINAL: full verdict + client impact + IOCs
```

> **⚙️ Engineering Note:** **Stream partial results.** Waiting eight minutes to say anything
> wastes six minutes of the recovery window. The Tier-1 capability signals
> ([Ch 11 §2](../static-analysis/11-static-analysis.md#2-the-tiered-pipeline)) are available in
> seconds and are sufficient for a *medium-confidence containment* decision under the two-track
> principle. Design the API to emit progressively, with confidence rising as evidence
> accumulates.

---

## 13. Limitations, edge cases, false positives

### Limitations

- **You cannot force device remediation.** The customer may refuse or be unable.
- **Fund recovery is largely outside your control** after the first minutes.
- **Consent gates forensics.** No consent, no device evidence.
- **Cross-border mule chains** exceed any single bank's reach.
- **Customer capability varies** - Safe Mode instructions are not universally followable.

### False positives - the cost of over-containment

| Action | Cost if wrong |
|---|---|
| Session hold | Customer inconvenience - **reversible in minutes** |
| Credential reset | Moderate friction |
| Transaction block | Failed legitimate payment - **material** |
| Beneficiary freeze | **Affects a third party who may be innocent** |
| Customer-base sweep | Mass disruption if the indicator is wrong |

> **⚙️ Engineering Note:** These costs are **asymmetric and the asymmetry favours acting**. A
> wrongly held session costs a phone call; a completed ODF transfer is irrecoverable. That
> justifies Track 1 acting on medium confidence - **but the asymmetry does not extend to
> beneficiary freezes**, which affect an uninvolved third party's access to their own funds and
> deserve a higher bar. Encode different confidence thresholds per action type rather than one
> global threshold.

### Edge cases

| Case | Handling |
|---|---|
| Customer refuses forensics | Proceed with account-side containment only; document the refusal |
| Device already wiped by malware | Bank-side records become primary evidence |
| Customer is the fraudster (first-party fraud) | Different investigation entirely - don't assume victimhood |
| Shared/family device | Multiple customers potentially affected |
| Customer abroad / unreachable | Precautionary holds; extended monitoring |
| Legitimate accessibility user | **Never restrict on a11y alone** ([Ch 18 §10](../soc/18-mobile-threat-hunting.md#10-limitations-edge-cases-false-positives)) |

---

## 14. Engineering tips

1. **Run two tracks in parallel** - contain in minutes, investigate in hours.
2. **Different confidence thresholds per action.** Session hold ≠ beneficiary freeze.
3. **Isolate → acquire → remediate.** Never reorder.
4. **Safe Mode is the key remediation step.** Most advice omits it.
5. **Remediate the device before resetting credentials**, or reset out-of-band.
6. **Sweep by signer** - the highest-leverage containment action.
7. **Stream partial analysis results.** Don't hoard certainty while money moves.
8. **Record the detection timestamp immutably** - the CERT-In clock starts there.
9. **Never self-assert regulatory reportability.** Supply facts; flag for compliance.
10. **Pre-authorise graduated response tiers** so proportionality isn't decided at 2am.
11. **Every incident produces a rule and a retro-hunt.**
12. **Be honest about fund recovery** in customer communications.

---

## 15. Judge Insights

**What judges ask:** *"Walk me through what happens the moment you detect a compromised
customer."*

**Perfect answer:** Two tracks in parallel, because the money clock and the investigation clock
are incompatible. Track one is containment, in minutes and largely automated: hold the session,
block pending transactions, freeze the beneficiary if it's in-house, and - the highest-leverage
action - sweep the entire customer base for the same signer certificate, which turns a
single-customer incident into campaign-scale containment. Track two is investigation over hours:
sample analysis, consented device forensics, timeline reconstruction, campaign correlation.
Critically, track one is allowed to act on *medium* confidence, because a wrongly held session
costs a phone call and is reversible in minutes, whereas a completed on-device-fraud transfer is
irrecoverable - under UPI the funds are through a mule chain in minutes. We also stream partial
analysis results, so a capability-cluster finding available at five seconds can trigger a
containment decision rather than waiting eight minutes for the full detonation.

**Common mistakes:**
- Waiting for high confidence before containing. The asymmetry justifies acting early.
- Uninstalling the malware first. BRATA and BingoMod wipe on detection - you destroy the evidence
  that determines liability.
- Resetting credentials while the malware is still resident and accessibility is still enabled - you've just handed the attacker the new credentials.

**Follow-ups to expect:**
- *"What if you're wrong and you've frozen a real customer?"* → Session holds are reversible in
  minutes and we treat that cost as acceptable. But we use different confidence thresholds per
  action - a beneficiary freeze affects an uninvolved third party's access to their own money, so
  it needs a higher bar than a session hold. One global threshold is the wrong design.
- *"You can't control the customer's phone. So what can you actually do?"* → Containment is
  account-side and immediate - session, transaction, beneficiary. Device remediation is
  customer-side, consent-dependent, and slower. The mistake teams make is waiting for device
  access before stopping the bleeding.
- *"What about the regulator?"* → In India, CERT-In requires reporting within six hours of
  *noticing*, so our detection timestamp is legally significant and recorded immutably. But we
  supply facts and flag "potentially reportable" - we never assert reportability ourselves,
  because that's a compliance decision.

**Fact that impresses:** Safe Mode is the single most effective device-remediation step and
almost no consumer-facing advice mentions it. It disables all third-party apps and therefore
their accessibility services simultaneously, which defeats uninstall interception, overlay
obstruction of the uninstall dialog, and watchdog process pairs in one action. It's why customers
report "it wouldn't let me uninstall it" - they were fighting an accessibility service that Safe
Mode would have switched off.

---

## 16. Interview Insights

**Q: "Describe the incident response lifecycle."**
NIST SP 800-61's four phases or SANS PICERL's six. Then add the domain point: these frameworks
assume you control the endpoint, and in mobile banking fraud you control the account and the app
but not the device - which is what reshapes the playbook.

**Q: "A customer reports an unauthorised UPI transfer. First actions?"**
Two tracks. Immediately: hold the session, block pending transactions, freeze the beneficiary,
contact the customer on a separate channel. In parallel: begin investigation. And do **not** tell
them to uninstall the app yet - isolate the device with airplane mode, acquire evidence, then
remediate.

**Q: "Why not just tell the customer to factory reset?"**
It destroys the evidence that determines liability and regulatory position, and if they restore
from a post-infection backup they may reinfect. Factory reset is the fallback when the device
can't be cleaned - not the first move.

**Q: "The malware is still on the phone and you reset the password. What happens?"**
The attacker reads the new password off the screen via accessibility and can tap through the
reset flow. **Device remediation must precede credential reset**, or the reset must happen
out-of-band on a different device.

**Q: "How do you contain when you don't control the endpoint?"**
Account-side: session hold, transaction block, beneficiary freeze, channel suspension, sweep by
signer across the customer base. Endpoint control isn't a prerequisite for containment - it's a
prerequisite for eradication.

**Q: "What's your reporting obligation in India?"**
CERT-In directions of April 2022: report within six hours of noticing a reportable cyber
incident, plus 180-day log retention within India. RBI's cyber security framework applies to
banks, and DPDP 2023 adds personal-data breach obligations. Add that reportability determination
is a compliance call, not an engineering one.

**Beginner mistakes:**
- Sequencing remediation before acquisition.
- Applying one confidence threshold to all containment actions.
- Resetting credentials on a still-infected device.
- Forgetting the customer-base sweep.
- Promising fund recovery.

---

## 17. Cross-references

**Upstream:**
- [← Ch 17 Digital Forensics](../digital-forensics/17-digital-forensics.md) - acquisition, timeline, legal
- [← Ch 19 Enterprise SOC](../soc/19-enterprise-soc-operations.md) - triage, escalation, the SOC/fraud seam
- [← Ch 13 Android Malware](../malware/13-android-malware.md) - anti-removal, wipe capability

**Downstream:**
- [→ Ch 21 AI-assisted Analysis](../ai-malware-analysis/21-ai-assisted-malware-analysis.md) - automating IR support
- [→ Ch 23 Detection Pipeline](../sudarshan/23-detection-pipeline.md) - urgent-path SLAs, partial results
- [→ Ch 25 Investigation Engine](../sudarshan/25-investigation-engine.md) - case model, sweep
- [→ Ch 29 Investigation Reports](../sudarshan/29-investigation-reports.md) - regulatory pack, customer comms facts

**Related chain:** Detection → parallel contain/investigate → isolate → acquire → sweep →
remediate → eradicate → recover → rule + retro-hunt.

---

## 18. References

1. NIST SP 800-61 Rev. 2 - *Computer Security Incident Handling Guide*.
2. NIST SP 800-86 - *Guide to Integrating Forensic Techniques into Incident Response*.
3. SANS - PICERL incident handling process.
4. CERT-In - Directions of April 28, 2022 (6-hour incident reporting; 180-day log retention).
5. Reserve Bank of India - Cyber Security Framework for Banks; customer protection framework on unauthorised electronic banking transactions.
6. Digital Personal Data Protection Act, 2023 (India) - breach notification obligations.
7. Indian Cyber Crime Coordination Centre (I4C) - National Cybercrime Reporting Portal; helpline 1930.
8. Cleafy Labs - *BRATA* (2021–2022) - factory-reset kill switch.
9. Cleafy Labs - *BingoMod* (July 31, 2024) - device wipe after fraud.
10. ThreatFabric - Anatsa, Octo2, Crocodilus analyses - attack chain reference.
11. MITRE ATT&CK for Mobile - T1453, T1629.001, T1626.001. https://attack.mitre.org/matrices/mobile/
12. FIRST - CSIRT Services Framework.

### Further reading
- NPCI circulars on UPI fraud handling and beneficiary freezes
- ENISA - incident response maturity guidance
- OWASP MASVS - MASVS-AUTH controls relevant to out-of-band credential reset

---

*Previous: [← Ch 19 Enterprise SOC Operations](../soc/19-enterprise-soc-operations.md) · Next: [Ch 21 AI-assisted Malware Analysis →](../ai-malware-analysis/21-ai-assisted-malware-analysis.md)*
