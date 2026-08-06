# 16 — Threat Intelligence

> **Chapter ID:** `CH16` · **Block:** C (The Adversary) · **Status:** Stable
> **Tags:** `#threat-intelligence` `#mitre-attack` `#d3fend` `#diamond-model` `#pyramid-of-pain` `#stix` `#taxii` `#misp` `#attribution`
> **Last Updated:** 2026-08-05 · **Version:** 1.0.0
> **Prerequisites:** [Ch 14](../banking-malware/14-banking-malware.md), [Ch 15](../malware/15-malware-infrastructure.md)

---

## Table of Contents

1. [What threat intelligence actually is](#1-what-threat-intelligence-actually-is)
2. [The three tiers](#2-the-three-tiers)
3. [MITRE ATT&CK for Mobile](#3-mitre-attck-for-mobile)
4. [MITRE D3FEND](#4-mitre-d3fend)
5. [The Diamond Model](#5-the-diamond-model)
6. [The Cyber Kill Chain, adapted](#6-the-cyber-kill-chain-adapted)
7. [The Pyramid of Pain](#7-the-pyramid-of-pain)
8. [IOCs: types, quality, lifecycle](#8-iocs-types-quality-lifecycle)
9. [Sharing standards: STIX, TAXII, MISP, OpenCTI](#9-sharing-standards-stix-taxii-misp-opencti)
10. [Attribution and its limits](#10-attribution-and-its-limits)
11. [Sources and how to weigh them](#11-sources-and-how-to-weigh-them)
12. [Detection logic for SUDARSHAN](#12-detection-logic-for-sudarshan)
13. [Limitations, edge cases, false positives](#13-limitations-edge-cases-false-positives)
14. [Engineering tips](#14-engineering-tips)
15. [Judge Insights](#15-judge-insights)
16. [Interview Insights](#16-interview-insights)
17. [Cross-references](#17-cross-references)
18. [References](#18-references)

---

## 1. What threat intelligence actually is

> **Threat intelligence is information that changes a decision.**

That definition is doing real work. A list of ten thousand malicious hashes is **data**. A
statement that *"Anatsa's current campaign targets 831 financial institutions including three of
your client banks, delivered via Play droppers, so your Play-install allowlist assumption is
wrong"* is **intelligence** — it changes what someone does.

### The distinction, made concrete

| | Data | Information | Intelligence |
|---|---|---|---|
| Example | `3a1f…b92c` | "That hash is Anatsa" | "Anatsa is on Play, targets your bank, and your allowlist assumption fails" |
| Answers | — | What is it? | **What do I do?** |
| Consumer | Machine | Analyst | **Decision-maker** |
| Perishability | High | Medium | Lower — drives strategy |

> **⚙️ Engineering Note:** Most "threat intel platforms" are data platforms with a feed
> subscription. The test for SUDARSHAN: **does the output change a bank's action in the next
> hour?** If a report ends with "this file is malicious," it failed. If it ends with "hold
> sessions for these 340 devices, reset these credentials, review transactions since this
> timestamp, and assess CERT-In reportability," it succeeded.
> → [Ch 29](../sudarshan/29-investigation-reports.md)

---

## 2. The three tiers

```
 ┌──────────────────────────────────────────────────────────────┐
 │ STRATEGIC        audience: CISO, board, regulator            │
 │                  horizon: quarters–years                      │
 │                  e.g. "Android banking fraud +67% YoY;        │
 │                        UPI fraud +85% in India"               │
 ├──────────────────────────────────────────────────────────────┤
 │ OPERATIONAL      audience: SOC lead, fraud ops, IR            │
 │                  horizon: weeks–months                        │
 │                  e.g. "Anatsa uses Play droppers that go      │
 │                        malicious ~6 weeks post-release"       │
 ├──────────────────────────────────────────────────────────────┤
 │ TACTICAL         audience: detection engineer, SOC analyst    │
 │                  horizon: hours–weeks                         │
 │                  e.g. IOCs, YARA rules, Sigma rules,          │
 │                        C2 domains, signer fingerprints         │
 └──────────────────────────────────────────────────────────────┘
```

**All three must come from the same investigation.** A platform that only emits tactical IOCs
cannot answer the board's question; a platform that only emits strategic narrative cannot feed
a SIEM. SUDARSHAN's report generator produces all three views from one analysis
([Ch 29](../sudarshan/29-investigation-reports.md)).

---

## 3. MITRE ATT&CK for Mobile

### WHAT

A curated, community-maintained knowledge base of adversary **tactics** (the *why*) and
**techniques** (the *how*), observed in the real world. ATT&CK for Mobile is the Android/iOS
matrix.

```
  TACTIC (the goal)          →   TECHNIQUE (the method)      →  SUB-TECHNIQUE
  Credential Access              Input Capture (T1417)          Keylogging (T1417.001)
                                                                GUI Input Capture (T1417.002)
```

### WHY it matters more than it looks

1. **Shared vocabulary.** ThreatFabric, Cleafy, Cyble, Zimperium, your SOC, and your client
   bank all mean the same thing by "T1453."
2. **Coverage measurement.** Map your detections to techniques and your **gaps become visible**.
   You cannot manage coverage you cannot see.
3. **Behaviour outlives infrastructure.** Techniques sit at the top of the Pyramid of Pain (§7).
4. **It's the lingua franca of vendor reports** — which is most of [Ch 14](../banking-malware/14-banking-malware.md).

### The techniques that matter for Android banking malware

| Tactic | Technique | ID | Seen in |
|---|---|---|---|
| Initial Access | Deliver Malicious App via Other Means | T1476* | Smishing, fake Play pages |
| Execution | Native Code | T1575 | Klopatra, GodFather |
| Persistence | Event Triggered Execution | T1624 | `BOOT_COMPLETED` |
| Persistence | Foreground Persistence | T1541 | Foreground services |
| Privilege Escalation | **Abuse Elevation Control: Device Admin** | **T1626.001** | BRATA, BingoMod |
| Defense Evasion | **Prevent Application Removal** | **T1629.001** | Most families |
| Defense Evasion | Obfuscated Files or Information | T1406 | Packers → [Ch 10](../reverse-engineering/10-reverse-engineering.md) |
| Defense Evasion | Download New Code at Runtime | T1407 | Staging → [Ch 03](../android/03-android-runtime.md) |
| Defense Evasion | User Evasion | T1618 | Icon hiding, black overlay |
| Discovery | Software Discovery | T1418 | `QUERY_ALL_PACKAGES` |
| **Collection** | **Abuse Accessibility Features** | **T1453** | ★ The hinge — nearly every family |
| Collection | Input Capture: Keylogging | T1417.001 | a11y node text |
| Collection | Input Capture: GUI Input Capture | T1417.002 | Overlays |
| Collection | Screen Capture | T1513 | Hidden VNC |
| Collection | Access Notifications | T1517 | OTP theft |
| Collection | Protected User Data: SMS | T1636.004 | OTP theft |
| Impact | Input Injection | T1516 | `dispatchGesture`, ATS |
| Credential Access | Adversary-in-the-Middle | T1638 | OTP interception |
| Command and Control | Encrypted Channel / Web Service | T1521 / T1481 | AES C2, Telegram dead drops |

*Technique IDs are revised across ATT&CK versions — **pin the ATT&CK version** in your mappings.

MITRE also now publishes **detection strategies** (e.g. `DET0697` for accessibility abuse),
which are worth reading as a sanity check against your own rule coverage.

> **⚙️ Engineering Note:** Map every detection rule to a technique ID **at authoring time**, and
> record the ATT&CK version. Retro-mapping is tedious and inaccurate, and unversioned mappings
> silently rot when MITRE renumbers. The payoff is a free coverage heatmap for the SOC
> ([Ch 19](../soc/19-enterprise-soc-operations.md)) and instant alignment with every vendor
> report you cite.

### Coverage heatmap — the honest version

```
  TACTIC              SUDARSHAN COVERAGE
  ──────              ──────────────────
  Initial Access      ▓▓▓░░  partial — we see the sample, not the delivery
  Execution           ▓▓▓▓░  static + dynamic
  Persistence         ▓▓▓▓▓  manifest + runtime
  Priv. Escalation    ▓▓▓▓▓  a11y + device admin
  Defense Evasion     ▓▓▓░░  packers detected; native logic partial
  Discovery           ▓▓▓▓▓  package enumeration
  Collection          ▓▓▓▓▓  ★ strongest — the core capability cluster
  C2                  ▓▓▓▓░  dynamic; blind if C2 offline
  Exfiltration        ▓▓▓▓░  network capture
  Impact              ▓▓▓░░  ATS/VNC observed; fraud outcome is bank-side
```

Publishing your own gaps internally is what stops a coverage claim from drifting into a coverage
myth.

---

## 4. MITRE D3FEND

ATT&CK catalogues **offense**. **D3FEND** catalogues **defense** — a taxonomy of defensive
techniques (Harden, Detect, Isolate, Deceive, Evict) with mappings back to ATT&CK.

| D3FEND tactic | SUDARSHAN / bank example |
|---|---|
| **Harden** | `FLAG_SECURE` on transaction screens; Keystore key with `setUserAuthenticationRequired` |
| **Detect** | Accessibility-service allowlist checks; overlay detection; capability-cluster scoring |
| **Isolate** | MDM app allowlisting; session hold on suspected devices |
| **Deceive** | Decoy apps in the analysis lab ([Ch 12 §3](../dynamic-analysis/12-dynamic-analysis.md#3-detonation-methodology)) |
| **Evict** | Safe Mode removal runbook ([Ch 13 §8](../malware/13-android-malware.md#8-device-admin-abuse-and-anti-removal)) |

> **⚙️ Engineering Note:** D3FEND is less mature and less used than ATT&CK, and that's fine —
> its practical value is as a **checklist against one-sidedness**. Teams over-invest in Detect
> and under-invest in Harden and Evict. If your D3FEND mapping is all Detect, your recommendation
> section is probably missing the cheap wins the bank actually controls.

---

## 5. The Diamond Model

Every intrusion has four vertices; **pivoting means moving between them.**

```
              ADVERSARY
             (DukeEugene,
              "Architect")
                  ▲
                  │
   INFRASTRUCTURE ─┼─ CAPABILITY
   (C2, hosting,   │   (Anatsa, Octo2,
    Zombinder)     │    ATS scripts)
                  ▼
               VICTIM
        (bank customers, banks)
```

### Worked example — Octo2

| Vertex | Value |
|---|---|
| Adversary | Actor **"Architect"** (ThreatFabric), original Octo author |
| Capability | Octo2 — RAT, DGA, anti-analysis, Android 13+ bypass |
| Infrastructure | DGA-generated C2; Zombinder as delivery |
| Victim | Bank customers in Europe, US, Canada, Middle East, Singapore, Australia |

The model's value: **any vertex leads to the others.** A C2 domain (infrastructure) leads to
other samples (capability), which lead to other victims, which may lead back to the adversary.
That is the formal statement of the pivot graph in
[Ch 15 §11](../malware/15-malware-infrastructure.md#11-pivoting-infrastructure-as-an-investigative-graph).

---

## 6. The Cyber Kill Chain, adapted

Lockheed Martin's chain was written for network intrusions. The Android banking-fraud analogue:

| Classic stage | Android banking equivalent | Defensive opportunity |
|---|---|---|
| Reconnaissance | Target-bank list selection; victim geography | Monitor for your package name in samples |
| Weaponisation | Build via MaaS builder; bind via Zombinder | TI on builders/services |
| Delivery | Smishing, fake Play page, Play dropper, Meta ad | Takedowns; customer education |
| Exploitation | **User enables Accessibility** | ★ Restricted Settings; in-app a11y detection |
| Installation | Session-based install of payload | Installer attribution ([Ch 09](../apk/09-package-manager.md)) |
| C2 | Establish channel | Network detection; DGA pre-blocking |
| **Actions on Objectives** | ATS / VNC transfer → mule chain | Transaction controls; session hold |

> **⚙️ Engineering Note:** The **Exploitation** row is where this chain differs most from the
> classic model — there is no software exploit. The "exploitation" is a **user decision**, which
> is why the strongest single mitigation is behavioural education (*"no legitimate app requires
> you to enable Accessibility"*) rather than a technical control. Uncomfortable, but true, and
> worth saying plainly to a bank rather than implying technology alone closes it.

---

## 7. The Pyramid of Pain

David Bianco's model: how much pain does it cause the adversary when you detect and block a
given indicator type?

```
                    ▲  MOST PAIN
                   ╱ ╲
                  ╱TTPs╲          months  ← behaviour: a11y cluster, ATS,
                 ╱───────╲                    overlay-on-foreground-change
                ╱  Tools  ╲       weeks   ← packers, ATS engines, Zombinder
               ╱───────────╲
              ╱  Network /  ╲     days–   ← C2 domains, hosting, protocol
             ╱  Host Artifacts╲   weeks
            ╱──────────────────╲
           ╱   Domain Names     ╲ days    ← rotates
          ╱──────────────────────╲
         ╱      IP Addresses      ╲ hours ← rotates faster
        ╱──────────────────────────╲
       ╱        Hash Values         ╲ mins ← trivially changed
      ╱──────────────────────────────╲
                LEAST PAIN
```

### The strategic consequence

**Most detection programmes invert this pyramid** — they consume hash and IP feeds because those
are cheap and abundant, and they detect the things that cost the adversary nothing.

SUDARSHAN's design deliberately weights the top:

| Layer | SUDARSHAN's implementation |
|---|---|
| **TTPs** | Capability-cluster rules; overlay-on-foreground-change; a11y self-escalation ([Ch 13](../malware/13-android-malware.md)) |
| **Tools** | Packer fingerprints, ATS engines, delivery services ([Ch 10](../reverse-engineering/10-reverse-engineering.md)) |
| **Artifacts** | Protocol + encryption mode, panel paths, hardcoded keys ([Ch 15](../malware/15-malware-infrastructure.md)) |
| Domains/IPs | Extracted and expired by TTL |
| Hashes | Extracted, deduplicated, expired fast |

> **⚖️ Judge Tip:** The Pyramid of Pain is the cleanest framing for *why* SUDARSHAN is built the
> way it is. One sentence: *"We deliberately detect at the top of the pyramid — behaviour and
> capability clusters — because a hash costs the adversary a minute to change and a working
> attack pattern costs them months to redesign."* It reframes the whole platform from
> "another scanner" to "a detection strategy."

**Note the honest caveat:** hashes and IPs still matter operationally — they're what a SIEM can
block *today*. The point is weighting and expiry, not abandonment.

---

## 8. IOCs: types, quality, lifecycle

### Types, with Android specifics

| Type | Example | Durability | Note |
|---|---|---|---|
| **Signer cert SHA-256** | `3a1f…b92c` | **Indefinite** | ★ Android's identity primitive ([Ch 06](../security/06-certificates.md)) |
| Hardcoded crypto key | AES key bytes | Months | ★ Under-used pivot |
| DGA generator | Algorithm | Indefinite | Predictive |
| Code similarity (DEX TLSH) | Hash + distance | Months | Survives obfuscation |
| C2 domain | `dksu[.]top` | Days–weeks | |
| IP address | `46[.]228.205.159` | Days | Shared-hosting risk |
| TLS cert / JA3-JA4 | Fingerprint | Weeks | |
| Package name | `quizzical.washbowl.calamity` | Days | Campaign attribute, **not identity** |
| File hash | SHA-256 | Hours–days | Per-build |
| Behavioural string | `is_chameleon`, `TRU9MMRHBCRO` | Months | ★ Distinctive and durable |

### Quality dimensions

Every indicator should carry:

```yaml
indicator:
  value: "dksu[.]top"
  type: domain
  confidence: high          # how sure are we it's malicious?
  severity: high            # how bad if it fires?
  source: "Cleafy ToxicPanda, Oct 2024"
  first_seen: 2024-10-25
  last_seen: 2026-07-14
  ttl: 90d
  context: "ToxicPanda C2, AES-ECB protocol"
  false_positive_notes: "verify not sinkholed or re-registered"
  tlp: "TLP:AMBER"
```

**Confidence and severity are separate axes** — the same principle as the risk score
([Ch 27](../sudarshan/27-risk-scoring.md)). A high-severity indicator you're unsure about is a
*review* item, not a *block* item.

### Lifecycle and decay

```
  Discovered ──► Validated ──► Distributed ──► Active ──► Decaying ──► Expired
                     │                                        │           │
              context added                            re-verify    archive, don't
              confidence set                           periodically  auto-block
```

> **⚙️ Engineering Note — expiry is a correctness requirement.** Domains get re-registered
> legitimately; IPs get recycled; hosts get sinkholed by researchers and law enforcement. An
> IOC database that only grows becomes a **false-positive engine**, and eventually it blocks
> something a customer needs. Worse, sinkholed infrastructure means *contact with a known-bad IP*
> may indicate a researcher, not a compromise. Build expiry and re-verification in from day one.
> → [Ch 26](../sudarshan/26-ioc-extraction.md), [Ch 30](../threat-intelligence/30-threat-intelligence-database.md)

### TLP — Traffic Light Protocol

| Level | Sharing |
|---|---|
| **TLP:RED** | Named recipients only |
| **TLP:AMBER** | Recipient's organisation, need-to-know (**+STRICT** = that org only) |
| **TLP:GREEN** | Community |
| **TLP:CLEAR** | Public |

Bank-derived indicators are frequently **AMBER+STRICT** — customer-linked data cannot be shared
freely, and in India the **DPDP Act 2023** constrains this directly
([Ch 14 §8](../banking-malware/14-banking-malware.md#8-india-and-the-upi-fraud-ecosystem)).

---

## 9. Sharing standards: STIX, TAXII, MISP, OpenCTI

| Standard/tool | What it is |
|---|---|
| **STIX 2.1** | JSON data model for threat intel — objects (Indicator, Malware, Campaign, Threat-Actor, Infrastructure) plus relationships |
| **TAXII 2.1** | Transport protocol for exchanging STIX |
| **MISP** | Open-source sharing platform; event-based; large community feed ecosystem |
| **OpenCTI** | Open-source knowledge-graph platform; STIX-native; strong for relationship modelling |

### A STIX 2.1 sketch

```json
{
  "type": "bundle", "id": "bundle--...",
  "objects": [
    { "type": "malware", "id": "malware--...", "name": "Anatsa",
      "aliases": ["TeaBot", "Toddler"], "is_family": true,
      "malware_types": ["trojan"] },
    { "type": "indicator", "id": "indicator--...",
      "pattern_type": "stix",
      "pattern": "[file:hashes.'SHA-256' = '3a1f...b92c']",
      "valid_from": "2026-07-01T00:00:00Z",
      "valid_until": "2026-10-01T00:00:00Z" },
    { "type": "relationship", "relationship_type": "indicates",
      "source_ref": "indicator--...", "target_ref": "malware--..." },
    { "type": "attack-pattern", "id": "attack-pattern--...",
      "name": "Abuse Accessibility Features",
      "external_references": [
        {"source_name": "mitre-attack", "external_id": "T1453"}] }
  ]
}
```

> **⚙️ Engineering Note:** Note `aliases` on the malware object — that is where the naming
> divergence from [Ch 14 §9](../banking-malware/14-banking-malware.md#9-naming-divergence) gets
> modelled properly. Store aliases **with the naming vendor and first-report date**, not as bare
> strings, or correlation fragments the first time two vendors disagree.
>
> Also note `valid_until` — STIX has expiry built in. **Use it.**

### The interoperability reality

STIX/TAXII adoption is real but uneven. Many feeds are still CSV or plain text; many vendor
reports are prose PDFs. **Build a normaliser**, not an assumption of STIX everywhere. Budget
engineering time for ingesting messy sources; it is not a solved problem.

---

## 10. Attribution and its limits

### The levels

```
  Malware family   →   Campaign   →   Operator/group   →   Country/state
  ──────────────       ────────       ──────────────       ─────────────
  achievable           achievable     hard                 very hard
  by code +            by infra +     needs sustained      needs intelligence
  signer               targeting      tracking + intel     capabilities
                                                            you don't have
```

**Where SUDARSHAN should operate: the first two.** Family and campaign attribution are
technically grounded and defensible. Operator attribution needs sustained tracking; state
attribution needs capabilities no commercial platform has.

### Evidence strength

| Evidence | Strength | Caveat |
|---|---|---|
| Signer certificate match | **Strong** | MaaS affiliates use different keys |
| Code similarity (DEX-level) | **Strong** | **Leaked source weakens it** — post-leak, similarity indicates lineage, not actor |
| Shared C2 infrastructure | Strong | Shared hosting; delivery services serve many actors |
| Hardcoded key reuse | Strong | |
| Protocol + command set | Medium-Strong | |
| Panel name / path structure | Medium | |
| Target list overlap | Medium | Many actors target the same banks |
| Package naming style | Weak | |
| **Language artifacts** | **Weak** | ★ Spoofable; **known false-flag technique** |
| **Timezone / build times** | **Weak** | Spoofable |
| **CIS geofencing** | **Weak** | Circumstantial only |
| VirusTotal engine labels | **Very weak** | Engines copy each other; labels are inconsistent |

> **🚨 Misconception:** "Turkish comments in the code mean Turkish authors." Language artifacts,
> build timezones, and CIS geofencing are **weak circumstantial indicators, deliberately
> spoofable, and a documented false-flag technique.** Vendors report them because they are
> observations. Report them the same way — as observations with hedged language ("consistent
> with," "assessed as"), never as conclusions. Cleafy assessed Klopatra's operators as
> Turkish-speaking and ThreatFabric assessed Crocodilus's author similarly; note the verb —
> *assessed*, not *proved*.

### The leaked-source problem

This is the specific attribution trap in this domain. After **Cerberus (~Aug 2020)**, **SpyNote/
CypherRat (GitHub, Oct 2022)**, **Octo (2024)**, and **ERMAC 3.0 (Hunt.io, pub. Aug 2025)** all
leaked, code similarity to those families indicates **shared lineage, not shared operator**.

> **⚙️ Engineering Note:** Encode a **post-leak flag** on family nodes in the TI database. When
> a family's source is public, automatically **downgrade the confidence of code-similarity-based
> actor attribution** for that lineage, and lean on infrastructure and signer instead. This is a
> small schema decision that prevents a whole class of confidently wrong reports.
> → [Ch 30](../threat-intelligence/30-threat-intelligence-database.md)

### Analytic language discipline

Use estimative language and mean it:

| Phrase | Confidence |
|---|---|
| "We assess with high confidence" | Multiple strong, independent evidence types |
| "We assess with moderate confidence" | Some strong evidence, gaps remain |
| "We assess with low confidence" | Circumstantial or single-source |
| "It is possible that" | Speculation — label it |
| "Consistent with" | Compatible, **not** proof |

---

## 11. Sources and how to weigh them

| Source type | Examples | Strength | Weakness |
|---|---|---|---|
| **Primary vendor research** | ThreatFabric, Cleafy, Group-IB, Cyble, Zimperium, NCC Group, Zscaler, Hunt.io, CTM360 | First-hand telemetry, technical depth | Vendor visibility bias; marketing framing |
| **Platform reports** | Google Security Blog, Play Protect data | Enormous scale | Google's view only |
| **Multi-engine platforms** | VirusTotal / Google Threat Intelligence | Breadth, retrohunt | **Aggregator, not verdict** |
| **Government/CERT** | CERT-In, I4C, national CERTs | Authoritative, local | Slower, less technical |
| **Community** | MISP feeds, abuse.ch, OTX | Fast, free | Variable quality |
| **Secondary press** | BleepingComputer, The Hacker News, SecurityWeek | Timely | Derivative — **cite the primary** |

### The rules

1. **Cite the primary source**, not the article about it.
2. **Attach vendor + date to every claim** ([Ch 14](../banking-malware/14-banking-malware.md)).
3. **Treat telemetry figures as that vendor's visibility**, not global truth.
4. **Distinguish observation from prediction** — ThreatFabric's "Octo2 will become more
   widespread" is a forecast.
5. **Flag single-vendor claims** as such.

> **⚙️ Engineering Note:** Vendor visibility bias is real and systematic. Cleafy sees Italy and
> Spain clearly; ThreatFabric has strong Western European and US coverage; Cyble and CYFIRMA see
> more of India; Group-IB sees more of Southeast Asia. **A family "not seen in India" may simply
> mean no vendor with Indian visibility has published on it.** For an India-focused platform,
> that gap is a reason to build your own telemetry, not a reason to assume safety.

---

## 12. Detection logic for SUDARSHAN

### The intelligence record

```yaml
threat_intel:
  family:
    name: "Anatsa"
    aliases: [{name: "TeaBot", vendor: "Cleafy"}, {name: "Toddler", vendor: "-"}]
    lineage: []                      # empty — no known parent
    source_leaked: false             # ★ gates attribution confidence
    first_reported: {date: "2021-01", vendor: "Cleafy"}
  attribution:
    family_confidence: high
    campaign_confidence: medium
    actor_confidence: low            # ★ be honest
    basis: [signer_match, code_similarity, c2_overlap]
    caveats: ["MaaS: affiliates use distinct signers"]
  mitre:
    attack_version: "v17"            # ★ pin it
    techniques: [T1453, T1417.001, T1417.002, T1636.004, T1638, T1629.001, T1624]
  indicators:
    - {value: ..., type: ..., confidence: ..., ttl: ..., tlp: "AMBER"}
  pyramid_coverage:
    ttp_rules: 6
    tool_signatures: 2
    artifacts: 4
    domains: 12
    hashes: 340
  sources:
    - {vendor: "Zscaler ThreatLabz", date: "2025-08", claim: "831 institutions", type: telemetry}
    - {vendor: "ThreatFabric", date: "2025-07", claim: "Play dropper #4 Top Free Tools", type: observation}
```

### Enrichment pipeline

```
  Sample analysed ([Ch 11](../static-analysis/11-static-analysis.md), [Ch 12](../dynamic-analysis/12-dynamic-analysis.md))
        │
        ▼
  Extract indicators ([Ch 26](../sudarshan/26-ioc-extraction.md))
        │
        ▼
  ┌─────────────────────────────────────────────┐
  │ ENRICH                                       │
  │  • internal TI DB (prior samples, campaigns) │
  │  • VirusTotal / GTI (context, NOT verdict)   │
  │  • MISP / OpenCTI feeds                      │
  │  • passive DNS, WHOIS, certificate transparency│
  │  • vendor reporting corpus                    │
  └────────────────────┬─────────────────────────┘
                       ▼
  Correlate → campaign cluster ([Ch 28](../sudarshan/28-campaign-correlation.md))
                       │
                       ▼
  Map to ATT&CK · assign confidence · set TTLs
                       │
                       ▼
  ┌──────────────┬──────────────┬──────────────┐
  │ TACTICAL     │ OPERATIONAL  │ STRATEGIC    │
  │ IOCs, rules  │ SOC briefing │ CISO summary │
  │ → SIEM/MTD   │ → fraud ops  │ → board/reg  │
  └──────────────┴──────────────┴──────────────┘
```

### Rules

| Rule | Severity | Confidence |
|---|---|---|
| Signer matches known-malicious signer in TI DB | Critical | High |
| C2 matches active known-malicious infrastructure | Critical | High |
| Hardcoded key matches a known family | High | High |
| DEX TLSH within threshold of a known family | High | Medium-High |
| Behavioural string matches a family fingerprint | High | Medium-High |
| Hash matches a known sample | High | High (but **low value** — top of pipeline, bottom of pyramid) |
| Indicator expired / possibly sinkholed | — | **Suppress; require re-verification** |

---

## 13. Limitations, edge cases, false positives

### Limitations

- **Intelligence is always retrospective.** It describes what was seen. Novel campaigns have no
  intel by definition — which is why TTP-level detection matters more than feeds.
- **Vendor visibility bias** shapes what "the landscape" looks like.
- **Attribution beyond family/campaign is out of reach** for a commercial platform.
- **Feeds vary wildly in quality**; unvetted ingestion imports someone else's false positives.

### False positives

| Trigger | Innocent cause |
|---|---|
| Hash in a low-quality feed | Mislabelled, or a shared legitimate library |
| IP in a feed | Shared hosting, CDN, recycled address |
| Domain in a feed | Re-registered legitimately, or sinkholed |
| Code similarity to a leaked family | Unrelated actor reusing public source |
| Target-list overlap | Many actors target the same major banks |
| High VT count | Engine label copying; generic heuristics on packed-but-benign apps |

> **🚨 Misconception:** "It's in a threat feed, so it's malicious." Feed quality varies by orders
> of magnitude. Ingest with **provenance, confidence, and TTL attached**, and never
> auto-block from an unvetted source. One bad feed entry blocking a customer's bank domain is a
> production incident, not a detection.

### Edge cases

| Case | Handling |
|---|---|
| **Sinkholed C2** | Contact indicates a researcher/LE host, **not** active compromise — suppress or reclassify |
| Re-registered domain | Expire and re-verify before acting |
| Family renamed by a vendor | Alias modelling handles it |
| Post-leak lineage | Downgrade actor-attribution confidence automatically |
| Conflicting vendor claims | Record both, cite both, state the disagreement |

---

## 14. Engineering tips

1. **Map rules to ATT&CK at authoring time, and pin the ATT&CK version.**
2. **Weight the top of the Pyramid of Pain** — TTPs and tools over hashes and IPs.
3. **Every indicator carries confidence, severity, source, TTL, and TLP.**
4. **Expire indicators.** Growth-only databases become false-positive engines.
5. **Model family aliases with the naming vendor**, never as bare strings.
6. **Flag leaked-source families** and auto-downgrade actor attribution for them.
7. **Cite primary sources**, not the press coverage of them.
8. **Separate observation from prediction** when quoting vendor reports.
9. **Use estimative language** — "assessed with moderate confidence," not "is."
10. **Never attribute from language artifacts or VT labels.**
11. **Produce all three tiers** — tactical, operational, strategic — from one investigation.
12. **Account for vendor visibility bias**, especially for India-focused coverage.

---

## 15. Judge Insights

**What judges ask:** *"Aren't you just reselling threat feeds?"*

**Perfect answer:** No — and the Pyramid of Pain explains why. Most detection programmes consume
hash and IP feeds because they're cheap and abundant, which means they detect exactly the things
that cost an adversary nothing: a hash takes a minute to change, an IP takes hours. We
deliberately detect at the top of the pyramid — behaviour and capability clusters like
accessibility abuse driving an overlay on a foreground-app change, which costs the adversary
months to redesign because it *is* the attack. Feeds are one enrichment input, ingested with
provenance, confidence, and a TTL, never auto-blocked. And critically we *produce* intelligence
rather than only consuming it: from a bank's own submissions we build campaign clusters, extract
target lists, and generate ATT&CK-mapped detections that no external feed contains, because no
external feed has visibility into that bank's customer base.

**Common mistakes:**
- Presenting an IOC count as a capability metric. Three hundred and forty hashes is not better
  than six good TTP rules.
- Auto-blocking from unvetted feeds.
- Claiming actor-level attribution.

**Follow-ups to expect:**
- *"How do you avoid stale indicators?"* → Type-based TTLs, periodic re-verification, and
  explicit handling of sinkholed infrastructure — contact with a sinkholed host indicates a
  researcher, not a compromise. Expiry is a correctness requirement, not housekeeping.
- *"Can you tell us who's behind it?"* → Family and campaign, yes, with stated confidence.
  Operator, rarely. Nation-state, no — and anyone claiming otherwise from an APK is overselling.
  Also, after source leaks like Cerberus, Octo, SpyNote, and ERMAC 3.0, code similarity indicates
  **lineage, not actor**, so we automatically downgrade actor confidence for leaked families.
- *"Why MITRE mapping?"* → Shared vocabulary with every vendor report and the client's SOC, plus
  a coverage heatmap that makes our own gaps visible. We publish those gaps internally.

**Fact that impresses:** Vendor visibility bias is systematic and under-discussed. Cleafy sees
Italy and Spain clearly, ThreatFabric sees Western Europe and the US, Group-IB sees Southeast
Asia, Cyble and CYFIRMA see more of India. So *"this family hasn't been seen in India"* often
just means no vendor with Indian visibility has published on it. For an India-focused platform
that's an argument for building our own telemetry, not a reason to assume safety.

---

## 16. Interview Insights

**Q: "What's the difference between data, information, and intelligence?"**
Data is a hash. Information is "that hash is Anatsa." Intelligence is "Anatsa targets your bank,
arrives via Play droppers, so your Play-install allowlist assumption fails — here's what to
change." **Intelligence changes a decision.**

**Q: "Explain the Pyramid of Pain."**
Bianco's model ranking indicator types by the pain caused to the adversary: hashes (minutes) →
IPs (hours) → domains (days) → artifacts (weeks) → tools (weeks–months) → TTPs (months). The
strategic point: most programmes invert it, consuming cheap indicators that cost the adversary
nothing.

**Q: "Why map detections to MITRE ATT&CK?"**
Shared vocabulary across vendors and teams, measurable coverage with visible gaps, and behaviour
sits at the top of the pyramid. Add the practical bit: map at authoring time and **pin the ATT&CK
version**, because technique IDs get revised.

**Q: "How confident can you be in attribution?"**
Family and campaign: reasonably, from signer, code similarity, and infrastructure. Operator: hard,
needs sustained tracking. Nation-state: not from an APK. Then the key caveat — leaked source
(Cerberus, SpyNote, Octo, ERMAC 3.0) means code similarity shows lineage rather than actor, and
language artifacts and timezones are spoofable false-flag material.

**Q: "What are STIX and TAXII?"**
STIX 2.1 is the JSON data model — Indicator, Malware, Campaign, Infrastructure objects plus
relationships. TAXII 2.1 is the transport protocol. Add realism: adoption is uneven, many feeds
are still CSV or prose PDFs, so build a normaliser.

**Q: "An IP is in your threat feed and a customer connected to it. Compromised?"**
Not necessarily. Check whether it's shared hosting, whether the address was recycled, and
critically whether it's been **sinkholed** — contact with a sinkholed host means a researcher or
law enforcement operates it, not that the customer is compromised. Verify before acting.

**Beginner mistakes:**
- Equating feed volume with capability.
- Auto-blocking from unvetted feeds.
- Attributing from VT labels or language artifacts.
- Never expiring indicators.
- Treating vendor telemetry as global ground truth.

---

## 17. Cross-references

**Upstream:**
- [← Ch 13 Android Malware](../malware/13-android-malware.md) — the techniques being mapped
- [← Ch 14 Banking Malware](../banking-malware/14-banking-malware.md) — families, aliases, naming divergence
- [← Ch 15 Malware Infrastructure](../malware/15-malware-infrastructure.md) — the pivot graph

**Downstream:**
- [→ Ch 18 Mobile Threat Hunting](../soc/18-mobile-threat-hunting.md) — intel-driven hunting
- [→ Ch 19 Enterprise SOC](../soc/19-enterprise-soc-operations.md) — ATT&CK coverage, detection engineering
- [→ Ch 26 IOC Extraction](../sudarshan/26-ioc-extraction.md) — indicator typing and TTLs
- [→ Ch 28 Campaign Correlation](../sudarshan/28-campaign-correlation.md) — Diamond Model in practice
- [→ Ch 29 Investigation Reports](../sudarshan/29-investigation-reports.md) — the three tiers as output
- [→ Ch 30 TI Database](../threat-intelligence/30-threat-intelligence-database.md) — schema, aliases, leak flags

**Related chain:** Sample → indicators → enrichment → correlation → ATT&CK mapping →
tactical/operational/strategic output.

---

## 18. References

1. MITRE ATT&CK for Mobile. https://attack.mitre.org/matrices/mobile/
2. MITRE ATT&CK — detection strategies (e.g. DET0697, Abuse Accessibility Features).
3. MITRE D3FEND. https://d3fend.mitre.org/
4. Caltagirone, Pendergast, Betz — *The Diamond Model of Intrusion Analysis* (2013).
5. Lockheed Martin — *Cyber Kill Chain*.
6. David Bianco — *The Pyramid of Pain* (2013).
7. OASIS — STIX 2.1 and TAXII 2.1 specifications. https://oasis-open.github.io/cti-documentation/
8. MISP — Open Source Threat Intelligence Platform. https://www.misp-project.org/
9. OpenCTI. https://www.filigran.io/en/products/opencti/
10. FIRST — Traffic Light Protocol (TLP) 2.0. https://www.first.org/tlp/
11. Google Security Blog — *How we kept the Google Play & Android app ecosystems safe in 2024*.
12. Zimperium zLabs — *Banking Heist Report* (March 19, 2026).
13. Zscaler ThreatLabz — *Anatsa's Latest Updates* (August 2025).
14. ThreatFabric — Octo2 (September 2024), Crocodilus (March 29, 2025), Chameleon (December 2023).
15. Cleafy Labs — ToxicPanda (October 2024), Klopatra (August 2025), BingoMod (July 31, 2024).
16. Hunt.io — ERMAC 3.0 source leak (published August 2025).
17. CERT-In — Directions of April 28, 2022 (incident reporting).
18. NIST SP 800-150 — *Guide to Cyber Threat Information Sharing*.

### Further reading
- Sherman Kent / ODNI — estimative language and analytic confidence standards
- abuse.ch projects (MalwareBazaar, URLhaus, ThreatFox)
- Certificate Transparency logs as an infrastructure-discovery source

---

*Previous: [← Ch 15 Malware Infrastructure](../malware/15-malware-infrastructure.md) · Next: Ch 17 Digital Forensics (Block D) →*

---

## ✅ Block C complete

Chapters 13–16 cover the adversary: the technique playbook, the banking-malware families and
their lineages, the infrastructure and criminal supply chain behind them, and the
threat-intelligence frameworks that organise all of it.

**Block D (Chapters 17–21)** turns to operations — digital forensics, mobile threat hunting,
enterprise SOC, incident response, and AI-assisted analysis — where this knowledge becomes a
response inside the fraud window.
