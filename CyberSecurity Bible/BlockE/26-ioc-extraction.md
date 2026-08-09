# 26 - IOC Extraction

> **Chapter ID:** `CH26` · **Block:** E · **Status:** Stable
> **Tags:** `#ioc` `#indicators` `#ttl` `#stix` `#pyramid-of-pain` `#expiry` `#export`
> **Last Updated:** 2026-08-05 · **Version:** 1.0.0
> **Prerequisites:** [Ch 16](../threat-intelligence/16-threat-intelligence.md), [Ch 25](25-investigation-engine.md)

---

## Table of Contents

1. [What an IOC is for](#1-what-an-ioc-is-for)
2. [The indicator taxonomy](#2-the-indicator-taxonomy)
3. [Extraction by source](#3-extraction-by-source)
4. [The indicator record](#4-the-indicator-record)
5. [Confidence, severity, and action class](#5-confidence-severity-and-action-class)
6. [TTLs and expiry](#6-ttls-and-expiry)
7. [Sinkholes and re-registration](#7-sinkholes-and-re-registration)
8. [Export formats](#8-export-formats)
9. [Sharing and TLP](#9-sharing-and-tlp)
10. [Limitations and false positives](#10-limitations-and-false-positives)
11. [Engineering tips](#11-engineering-tips)
12. [Judge Insights](#12-judge-insights)
13. [Interview Insights](#13-interview-insights)
14. [Cross-references](#14-cross-references)
15. [References](#15-references)

---

## 1. What an IOC is for

An indicator exists to let **someone else, somewhere else, recognise the same threat.**

That framing constrains the design: an indicator is only useful if it is (a) **specific** enough
not to fire on benign traffic, (b) **durable** enough to still be true when it arrives, and (c)
**actionable** by the system consuming it.

```
   SUDARSHAN analysis                    CONSUMER
   ──────────────────                    ────────
   sample → findings   ──► indicator ──► SIEM rule / MTD block /
                                          firewall / TIP / partner bank
                             │
                             ▼
                    must carry: type, value, confidence,
                    severity, source, TTL, TLP, context
```

> **⚙️ Engineering Note - the failure mode is volume without discipline.** A platform that emits
> ten thousand hashes per day and no context has produced data, not intelligence
> ([Ch 16 §1](../threat-intelligence/16-threat-intelligence.md#1-what-threat-intelligence-actually-is)).
> Every indicator must carry provenance and an expiry, or the consuming blocklist eventually
> blocks something a customer needs.

---

## 2. The indicator taxonomy

Ordered by **durability**, which is the Pyramid of Pain applied to output
([Ch 16 §7](../threat-intelligence/16-threat-intelligence.md#7-the-pyramid-of-pain)).

| Indicator | Type | Durability | Default TTL | Notes |
|---|---|---|---|---|
| **Signer cert SHA-256** | `x509-certificate:hashes` | **Indefinite** | none | ★ App identity (P5) |
| **DGA generator** | custom | Indefinite | none | Predictive - enumerate future domains |
| **Behavioural rule (TTP)** | Sigma / custom | Indefinite | none | Top of the pyramid |
| **YARA rule** | yara | Months–years | none | Family/capability |
| **Hardcoded crypto key** | custom | Months | 365 d | ★ Under-used pivot |
| **DEX TLSH** | custom | Months | 180 d | Code lineage |
| **Behavioural string** | artifact | Months | 180 d | e.g. `is_chameleon`, `TRU9MMRHBCRO` |
| **Panel path / URI pattern** | url-pattern | Weeks–months | 120 d | e.g. `/api/gate.php` |
| **TLS cert SHA-256** | x509 | Weeks | 180 d | Infrastructure pivot |
| **JA3 / JA4** | custom | Weeks | 180 d | Client fingerprint |
| **C2 domain** | `domain-name` | Days–weeks | 90 d | Rotates |
| **Package name** | custom | Days | 60 d | ⚠ Campaign attribute, **not identity** |
| **IP address** | `ipv4-addr` | Days | 14 d | ⚠ Shared hosting risk |
| **File hash (SHA-256)** | `file:hashes` | Hours–days | 30 d | Per-build; bottom of the pyramid |

### The two special cases

**Target package list.** Not a classical IOC - you don't block on it - but it is the single most
business-relevant output ([Ch 11 §5](../static-analysis/11-static-analysis.md#5-tier-2--resource-and-asset-mining)).
Emit it as a distinct object type: *"this sample hunts for these apps."*

**Accessibility service class name.** Detectable on-device from bank-app SDK telemetry
([Ch 18 §3](../soc/18-mobile-threat-hunting.md#3-telemetry-what-you-can-actually-hunt-in)), which
makes it directly actionable by the bank in a way a C2 domain is not.

---

## 3. Extraction by source

| Source tier | Indicators produced |
|---|---|
| **Intake** ([Ch 24](24-threat-intake.md)) | file hashes, TLSH, **signer cert**, signature schemes |
| **T0 structural** | Janus shape, duplicate entries, DEX checksum mismatch (as *findings*, not blockable IOCs) |
| **T1 capability** | a11y service class name, declared components, targetSdk |
| **T2 resources** | URLs, **target package list**, locale set, packer fingerprint, asset hashes |
| **T3 code** | strings, embedded URLs, YARA hits, API-chain patterns, hardcoded keys (static) |
| **T4 dynamic** | ★ **C2 endpoints, resolved DNS, JA3/JA4, protocol + encryption mode, decrypted keys, panel paths, dumped child hashes** |
| **Correlation** | campaign linkage, actor node, similarity clusters |

> **⚙️ Engineering Note - dynamic extraction is where the good indicators come from.** Statically
> you get what the author left in plaintext. Dynamically you get what the runtime had to
> materialise: the decrypted C2, the AES key, the real target list. That asymmetry is another
> argument for the fused pipeline - and it means indicator *quality* correlates with how far up
> the tier ladder a sample went.

### Concrete extraction points

```python
# T4 - the highest-yield hooks (Ch 12 §5)
#   Cipher.doFinal          → decrypted C2 URLs, config, target lists
#   SecretKeySpec.<init>    → ★ hardcoded keys (durable pivot)
#   URL.<init> / OkHttp     → endpoints regardless of TLS
#   ClassLoader ctors       → child artifact hashes (recursion, Ch 25 §3)
#   pm list packages diff   → installed child package
# Network capture           → DNS, IP, SNI, JA3/JA4, ciphertext block patterns
```

---

## 4. The indicator record

```yaml
indicator:
  id: "ind_01J8..."
  type: domain-name
  value: "dksu[.]top"                   # ★ defanged in human-readable output
  value_raw: "dksu.top"                 # machine-consumable
  confidence: high                       # how sure it is malicious
  severity: high                         # how bad if it fires
  action_class: block | alert | enrich_only   # ★ see §5
  first_seen_utc: "2024-10-25T00:00:00Z"
  last_seen_utc: "2026-07-14T00:00:00Z"
  valid_until_utc: "2026-10-12T00:00:00Z"     # ★ TTL
  source:
    internal: {artifact_ids: [...], analysis_ids: [...], tier: T4}
    external: {vendor: "Cleafy", report: "ToxicPanda", published: "2024-10"}
  context:
    family: "ToxicPanda"
    campaign_id: "camp_..."
    protocol: "https"
    encryption: "AES-ECB"
    mitre: ["T1521"]
  false_positive_notes: "verify not sinkholed or re-registered before blocking"
  tlp: "TLP:AMBER"
  tenant_visibility: shared | tenant_private     # ★ multi-tenant
```

> **⚙️ Engineering Note:** Defang in every human-readable surface (`dksu[.]top`,
> `hxxps://`) and keep a raw field for machines. An analyst who accidentally clicks a live C2
> link in a report has just contacted the adversary's infrastructure from the bank's network.
> This is a small convention that prevents a real, recurring incident.

---

## 5. Confidence, severity, and action class

Three axes, not one - because a consumer's action should depend on all three.

```
                 CONFIDENCE
                 low        high
              ┌──────────┬──────────┐
       high   │ ALERT    │  BLOCK   │
  SEVERITY    │ (review) │          │
              ├──────────┼──────────┤
       low    │ ENRICH   │  ALERT   │
              │  ONLY    │          │
              └──────────┴──────────┘
```

| Action class | Meaning | Example |
|---|---|---|
| **block** | Safe to enforce automatically | Signer of a confirmed impersonating clone |
| **alert** | Raise for review; don't enforce | C2 domain with medium confidence |
| **enrich_only** | Context only; never fires an alert | Package name; shared-hosting IP |

> **⚙️ Engineering Note - never emit a bare list.** If SUDARSHAN hands a bank a flat CSV of
> domains and the bank blocks them all, one re-registered domain takes down a legitimate service
> and trust in the feed is gone permanently. **The action class is the contract** that says which
> indicators are safe to enforce, and it should be conservative by default.

---

## 6. TTLs and expiry

```yaml
default_ttls:
  signer_cert_sha256: none          # identity - never expires
  dga_generator:      none          # predictive
  behavioural_rule:   none          # TTP
  yara_rule:          none
  hardcoded_key:      365d
  tlsh_dex:           180d
  behavioural_string: 180d
  tls_cert_sha256:    180d
  ja3_ja4:            180d
  panel_path:         120d
  domain:             90d
  package_name:       60d
  ip_address:         14d           # ★ shortest - rotates and gets recycled
  file_hash:          30d
```

### The expiry lifecycle

```
  ACTIVE ──► approaching expiry ──► RE-VERIFY
                                        │
                            ┌───────────┴───────────┐
                        still bad                 not bad
                            │                       │
                            ▼                       ▼
                      extend TTL              EXPIRE (archive)
                                                    │
                                                    ▼
                                     retained for HISTORY and correlation,
                                     removed from ENFORCEMENT feeds
```

> **⚙️ Engineering Note - expiry is a correctness requirement, not housekeeping
> ([Ch 16 §8](../threat-intelligence/16-threat-intelligence.md#8-iocs-types-quality-lifecycle)).**
> Domains get re-registered by legitimate businesses; IPs get recycled by hosting providers. An
> indicator database that only grows becomes a false-positive engine, and the first time it blocks
> a customer's payment gateway the bank stops consuming the feed. **Expire from enforcement;
> retain for history.** Those are different stores with different rules.

---

## 7. Sinkholes and re-registration

Two cases that invert the meaning of a hit.

| Case | What a hit actually means |
|---|---|
| **Sinkholed domain** | The host is now operated by a researcher or law enforcement. Contact means a *previously infected* device is beaconing - useful signal, but **not** active adversary infrastructure. |
| **Re-registered domain** | A legitimate business now owns it. Contact means **nothing**. |
| **Recycled IP** | A different tenant now uses it. Contact means nothing. |
| **CDN-fronted C2** | The IP is the CDN's. Blocking it blocks the CDN. |

```yaml
indicator_status:
  active: true
  sinkholed: false          # ★ set on detection; changes interpretation
  reregistered: false
  shared_hosting: false     # ★ suppress IP-based enforcement
  last_verified_utc: "..."
```

> **⚙️ Engineering Note:** A sinkhole hit is genuinely valuable - it identifies still-infected
> devices - but it must be **reclassified, not treated as compromise-in-progress**. Reporting a
> sinkhole contact as an active C2 connection produces an incident response to an event that
> already ended, and it burns analyst time. Track sinkhole status explicitly.

---

## 8. Export formats

| Format | Consumer | Notes |
|---|---|---|
| **STIX 2.1** | TIP, partner sharing | Canonical; carries relationships and `valid_until` |
| **MISP event** | MISP instances | Community sharing |
| **Sigma** | SIEM | Behavioural detections |
| **YARA** | File scanning, retro-hunt | Family/capability rules |
| **CSV / JSON** | Ad-hoc, firewall imports | ⚠ Loses context - mark `action_class` prominently |
| **OpenIOC** | Legacy tooling | On request |

### A STIX 2.1 fragment

```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--...",
  "created": "2026-08-05T09:20:00Z",
  "valid_from": "2026-08-05T09:20:00Z",
  "valid_until": "2026-11-03T09:20:00Z",
  "confidence": 85,
  "pattern_type": "stix",
  "pattern": "[domain-name:value = 'dksu.top']",
  "labels": ["malicious-activity"],
  "external_references": [
    {"source_name": "Cleafy", "description": "ToxicPanda (October 2024)"}
  ],
  "object_marking_refs": ["marking-definition--<TLP:AMBER>"]
}
```

Plus the relationship that makes it intelligence rather than a string:

```json
{"type":"relationship","relationship_type":"indicates",
 "source_ref":"indicator--...","target_ref":"malware--<ToxicPanda>"}
```

> **⚙️ Engineering Note:** Always emit the **relationship objects**, not just indicators. An
> indicator without a link to the malware, campaign, and attack-pattern it belongs to is a string
> in a list. The relationships are what let the consumer answer "why am I blocking this?" - > which is the question that arises the moment something breaks.

---

## 9. Sharing and TLP

| TLP | Sharing | Typical SUDARSHAN use |
|---|---|---|
| **TLP:RED** | Named recipients only | Customer-linked findings |
| **TLP:AMBER(+STRICT)** | Recipient org / need-to-know | Most bank-derived indicators |
| **TLP:GREEN** | Community | Family-level infrastructure |
| **TLP:CLEAR** | Public | Published research |

### Multi-tenant sharing

```
  TENANT-PRIVATE (never crosses)        SHAREABLE (with consent)
  ──────────────────────────────        ────────────────────────
  submissions                            signer certificate hashes
  customer cohorts                       C2 domains / IPs
  case details                           YARA and Sigma rules
  device references                      family and campaign linkage
  transaction data                       TLSH clusters
  target lists naming the tenant         ⚠ generic target lists only
```

> **🏛️ Enterprise Insight:** The last row is subtle and important. A target list is shareable
> intelligence *in general*, but a statement that *"this campaign targets Bank A"* is
> **Bank A's information about being attacked**, and disclosing it to Bank B without consent is a
> confidentiality breach and a commercial betrayal. Share the indicator; redact the
> tenant-identifying impact. Get this wrong once and the multi-tenant model is finished.
> → [Ch 22 §9](22-building-sudarshan.md#9-operating-and-safety-constraints)

---

## 10. Limitations and false positives

| Indicator | False-positive cause |
|---|---|
| IP address | Shared hosting, CDN, recycled allocation |
| Domain | Re-registered, sinkholed, parked |
| File hash | None (exact match) - but near-zero recall on active campaigns |
| Package name | Attacker-chosen; may collide with legitimate apps |
| TLSH similarity | Shared libraries; leaked source reused by unrelated actors |
| YARA capability rule | Legitimate apps with the same capability |
| JA3/JA4 | Shared HTTP client libraries |
| Panel path | Generic paths like `/api/` |

### Recall vs precision by indicator

```
  file hash      precision ████████████  recall ▏          (exact, but stale instantly)
  signer cert    precision ███████████   recall ██████     (★ best balance)
  domain         precision ████████      recall ███
  TLSH cluster   precision ██████        recall ████████
  TTP rule       precision █████         recall ██████████  (★ broadest, noisiest)
```

> **🚨 Misconception:** "More IOCs means better coverage." Coverage comes from the **top of the
> pyramid** - behavioural rules and durable identity - not from hash volume. A thousand hashes
> from last month's campaign is a large number and near-zero recall against this month's builds.

---

## 11. Engineering tips

1. **Emit an `action_class` on every indicator.** Never hand over a bare list.
2. **Defang in all human-readable output.** Analysts click links.
3. **TTL by type**, and expire from enforcement while retaining history.
4. **Track sinkhole and shared-hosting status** - they invert or void a hit.
5. **Extract hardcoded keys as indicators**, not just as crypto findings.
6. **Emit the target package list** as a distinct object - it's the business-relevant output.
7. **Always emit STIX relationships**, not orphan indicators.
8. **Redact tenant-identifying impact** before cross-tenant sharing.
9. **Prefer domain and certificate pivots over IP pivots.**
10. **Measure per-indicator-type false-positive rates** and adjust TTLs accordingly.

---

## 12. Judge Insights

**What judges ask:** *"You extract IOCs - so does everyone. What's different?"*

**Perfect answer:** Three things. First, we type indicators by **durability and expire them
accordingly** - a signer certificate never expires because it's an identity, a hardcoded AES key
gets a year, a domain gets ninety days, an IP gets fourteen. An indicator database that only grows
becomes a false-positive engine, and the first time it blocks a customer's payment gateway the
bank stops consuming it. Second, every indicator carries an **action class** - block, alert, or
enrich-only - so we're explicit about which are safe to enforce automatically. Handing a bank a
flat CSV of domains is how you take down a legitimate service. Third, we extract the indicators
most people don't: **hardcoded crypto keys**, which are far more durable than domains because
rotating one means rebuilding the panel, and the **target package list**, which isn't blockable at
all but tells the bank whether it's specifically being hunted.

**Common mistakes:**
- Volume as a metric. A thousand hashes from last month is a big number and near-zero recall.
- No expiry. Recycled IPs and re-registered domains become false positives.
- Treating a sinkhole hit as an active compromise.

**Follow-ups to expect:**
- *"What's the most valuable indicator you extract?"* → Signer certificate hash, because it's the
  durable app identity and it survives rebuilds - the adversary keeps their key because they need
  it to update their own installed base. After that, hardcoded keys, for the same economic reason.
- *"How do you avoid blocking legitimate infrastructure?"* → Action classes, shared-hosting flags
  that suppress IP enforcement, sinkhole tracking, and TTLs with re-verification. And we prefer
  domain and certificate pivots over IP pivots, because one IP can host thousands of unrelated
  sites.
- *"How do you share across banks without leaking?"* → Indicators and campaign linkage are
  shareable with consent; submissions, customer cohorts, and any statement that names a specific
  bank as targeted stay tenant-private. "This campaign targets Bank A" is Bank A's information
  about being attacked, not ours to distribute.

**Fact that impresses:** Hardcoded encryption keys sit *above* domains and well above hashes on
the durability scale, and almost nobody extracts them as indicators - they get filed as "crypto
hygiene findings." Adversaries rotate domains weekly and rebuild binaries daily, but rotating a
key means rebuilding the panel and re-flashing the installed base, so keys persist for months. A
`SecretKeySpec` hook during detonation makes them essentially free to collect.

---

## 13. Interview Insights

**Q: "Why is hash-based blocking ineffective?"**
A hash identifies one build. Anatsa rotates package names and install hashes between campaigns, so
by the time a hash is distributed it's stale. Frame it with the Pyramid of Pain - hashes cost the
adversary minutes, domains days, TTPs months.

**Q: "What makes a good IOC?"**
Specific enough not to fire on benign traffic, durable enough to still be true on arrival, and
actionable by the consumer. Plus provenance, confidence, severity, TTL, and TLP - an indicator
without context is a string.

**Q: "An IP in your feed is contacted by a customer. Compromised?"**
Check shared hosting, whether the address was recycled, and critically whether the destination is
**sinkholed** - a sinkhole hit identifies a previously infected device beaconing, not an active
adversary connection. Different response entirely.

**Q: "How long should indicators live?"**
By type: signer certificates and behavioural rules indefinitely, keys around a year, domains
ninety days, IPs about two weeks, hashes thirty. Expire from enforcement, retain for history and
correlation - two different stores.

**Q: "What's an under-used indicator type?"**
Hardcoded crypto keys. High durability, cheap to extract dynamically, and they link samples with
*different* signers, which is exactly how you spot MaaS affiliates.

**Beginner mistakes:**
- Measuring IOC output by volume.
- No expiry policy.
- Exporting bare lists without action classes.
- Not defanging in reports.
- Blocking on IPs without checking shared hosting.

---

## 14. Cross-references

**Upstream:** [Ch 16 §7–8](../threat-intelligence/16-threat-intelligence.md#7-the-pyramid-of-pain) ·
[Ch 12 §5](../dynamic-analysis/12-dynamic-analysis.md#5-the-essential-hook-library) ·
[Ch 25](25-investigation-engine.md)

**Downstream:** [Ch 28](28-campaign-correlation.md) · [Ch 29](29-investigation-reports.md) ·
[Ch 30](../threat-intelligence/30-threat-intelligence-database.md)

---

## 15. References

1. OASIS - STIX 2.1 / TAXII 2.1. https://oasis-open.github.io/cti-documentation/
2. FIRST - Traffic Light Protocol 2.0. https://www.first.org/tlp/
3. David Bianco - *The Pyramid of Pain* (2013).
4. MISP - indicator and event model. https://www.misp-project.org/
5. SigmaHQ - Sigma rule format. https://github.com/SigmaHQ/sigma
6. Cleafy Labs - *ToxicPanda* (October 2024) - `dksu[.]top`, `mixcom[.]one`, AES-ECB.
7. Cleafy Labs - *Klopatra* (August 2025) - `adsservices.uk`, `adsservice2.org`.
8. Cyble - *Antidot* (May 16, 2024) - `46[.]228.205.159:5055`.
9. Hunt.io - ERMAC 3.0 leak (August 2025) - `141.164.62[.]236`.
10. ThreatFabric - *Crocodilus* (March 29, 2025) - command `TRU9MMRHBCRO`.

---

*Previous: [← Ch 25 Investigation Engine](25-investigation-engine.md) · Next: [Ch 27 Risk Scoring →](27-risk-scoring.md)*
