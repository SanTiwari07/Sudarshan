# 28 - Campaign Correlation

> **Chapter ID:** `CH28` · **Block:** E · **Status:** Stable
> **Tags:** `#correlation` `#campaign` `#clustering` `#tlsh` `#pivoting` `#attribution` `#multi-tenant`
> **Last Updated:** 2026-08-05 · **Version:** 1.0.0
> **Prerequisites:** [Ch 15](../malware/15-malware-infrastructure.md), [Ch 25](25-investigation-engine.md), [Ch 26](26-ioc-extraction.md)

---

## Table of Contents

1. [Why correlation is the product](#1-why-correlation-is-the-product)
2. [The pivot hierarchy](#2-the-pivot-hierarchy)
3. [Code similarity](#3-code-similarity)
4. [Infrastructure correlation](#4-infrastructure-correlation)
5. [The clustering algorithm](#5-the-clustering-algorithm)
6. [Campaign and actor modelling](#6-campaign-and-actor-modelling)
7. [The leaked-source problem](#7-the-leaked-source-problem)
8. [Cross-tenant correlation](#8-cross-tenant-correlation)
9. [The correlation output](#9-the-correlation-output)
10. [Limitations and false positives](#10-limitations-and-false-positives)
11. [Engineering tips](#11-engineering-tips)
12. [Judge Insights](#12-judge-insights)
13. [Interview Insights](#13-interview-insights)
14. [Cross-references](#14-cross-references)
15. [References](#15-references)

---

## 1. Why correlation is the product

A verdict on one sample is a commodity. **Turning one sample into campaign-scale intelligence is
not.**

```
   WITHOUT CORRELATION              WITH CORRELATION
   ───────────────────              ────────────────
   "This APK is malicious."         "This APK belongs to a campaign of 47 samples
                                     sharing one signing key and three C2 hosts.
                                     It has been submitted by two other banks.
                                     The campaign's combined target list names
                                     four of our client banks. Here are the 340
                                     customers with it installed."
        │                                      │
        ▼                                      ▼
   an antivirus answer               an intelligence answer
```

> **🏛️ Enterprise Insight:** This is the mechanism by which the platform's value **compounds**.
> Every bank's submission enriches the graph, which improves every other bank's answer. It is also
> the hardest thing to build correctly, because it collides directly with tenant confidentiality
> (§8). Get the sharing model right and the product has a moat; get it wrong and it's unsellable.

---

## 2. The pivot hierarchy

From [Ch 15 §11](../malware/15-malware-infrastructure.md#11-pivoting-infrastructure-as-an-investigative-graph),
formalised with the operational consequence attached.

| Rank | Pivot | Durability | Precision | Safe to auto-act on? |
|---|---|---|---|---|
| 1 | **Signer certificate SHA-256** | Indefinite | Very high | ✅ Yes |
| 2 | **v3 rotation lineage** | Indefinite | Very high | ✅ Yes |
| 3 | **Hardcoded crypto key** | Months | High | ✅ Yes (review) |
| 4 | **DEX TLSH similarity** | Months | Medium-high | ⚠ Review only |
| 5 | **Protocol + command set** | Months | Medium-high | ⚠ Review |
| 6 | **Behavioural string** | Months | Medium-high | ⚠ Review |
| 7 | **Panel path structure** | Weeks–months | Medium | ⚠ Review |
| 8 | **TLS cert / JA3-JA4** | Weeks | Medium | ⚠ Review |
| 9 | **C2 domain** | Days–weeks | Medium | ⚠ Review |
| 10 | **Target list overlap** | Weeks | Low-medium | ℹ Context |
| 11 | **Package name** | Days | Low | ℹ Context |
| 12 | **IP address** | Days | **Low** (shared hosting) | ❌ No |
| 13 | **File hash** | Hours | Exact but no recall | ℹ Dedup only |

### The rule that follows

> **⚙️ Engineering Note:** **Match the pivot's precision to the action's cost**
> ([Ch 25 §7](25-investigation-engine.md#7-the-sweep)). A signer match justifies an automated
> session hold. A TLSH-similarity match justifies analyst review and enhanced monitoring, not a
> customer-visible action. An IP match justifies nothing on its own, because one address can host
> thousands of unrelated sites. Teams that apply one global confidence threshold across all pivot
> types generate either useless caution or damaging over-action.

### Why the signer sits at the top

Economics, not cryptography. The adversary **needs their signing key** to push updates to their
own installed base ([Ch 06 §4](../security/06-certificates.md#4-trust-on-first-use--androids-actual-model)).
Rotating it means abandoning those victims - or carrying a **v3 proof-of-rotation lineage** that
cryptographically links old key to new, which hands you the correlation for free
([Ch 07 §6](../security/07-apk-signing.md#6-v3-and-v31--key-rotation)).

---

## 3. Code similarity

### DEX-level TLSH, not whole-APK

```
   WHOLE-APK TLSH                    DEX-ONLY TLSH
   ──────────────                    ─────────────
   dominated by resources,           tracks the CODE
   assets, icons, overlays                 │
        │                                  ▼
        ▼                          same family, different
   same family, different          campaign → still close
   campaign → looks distant        ★ correct behaviour
```

| Distance | Interpretation |
|---|---|
| 0 | Identical DEX |
| 1–30 | Same build lineage, minor changes |
| **31–50** | **Same family** - the working threshold |
| 51–100 | Possibly related; review |
| > 150 | Unrelated |

### Complementary similarity measures

| Measure | What it captures | Robust to |
|---|---|---|
| **DEX TLSH** | Byte-level code similarity | Renaming, minor edits |
| **API-set hash** | Sorted sensitive-API set | Reordering, obfuscation |
| **Manifest hash** | Normalised permission + component set | Code changes |
| **Call-graph similarity** | Structure | Identifier renaming |
| **Resource-set hash** | Overlay assets, target list | Code rewrites |
| **String-set Jaccard** | Shared literals | Partial rewrites |

> **⚙️ Engineering Note:** Use **multiple measures and require agreement**. TLSH alone produces
> false clusters when two unrelated apps share a large common library (the same Flutter or React
> Native runtime, for example, can dominate a DEX). Requiring TLSH proximity *plus* API-set
> overlap *plus* one of manifest/resource similarity substantially cuts that noise, at negligible
> compute cost.

---

## 4. Infrastructure correlation

```
   sample A ──contacts──► c2-a.example ──resolves──► 1.2.3.4
                                                        │
                              ┌─────────────────────────┤
                              ▼                         ▼
                        c2-b.example            c2-c.example
                              │                         │
                              ▼                         ▼
                         sample B                  sample C
                       (tenant 2)                (tenant 3)
                              │
                              ▼
                    ★ ONE campaign, THREE banks
```

| Signal | Strength | Caveat |
|---|---|---|
| Same domain | Medium | Could be a sinkhole ([Ch 26 §7](26-ioc-extraction.md#7-sinkholes-and-re-registration)) |
| Same IP | **Low** | Shared hosting |
| Same TLS certificate | Medium-high | Reuse across hosts is deliberate |
| Same ASN + registration burst | Medium | Bulk registration pattern |
| Same registrar + nameservers + timing | Medium | Operator habit |
| **Same hardcoded key** | **High** | Rotating means rebuilding the panel |
| Same protocol + command set | Medium-high | Rewriting both ends is expensive |
| Same panel path structure | Medium | e.g. Copybara's "JOKER RAT" (Cleafy) |
| **DGA from the same generator** | **Very high** | Algorithmic identity |

> **⚙️ Engineering Note:** DGA-derived correlation is the strongest infrastructure pivot available
> and it is *predictive* - reverse the generator once (a T5 human task,
> [Ch 10](../reverse-engineering/10-reverse-engineering.md)) and you can enumerate the campaign's
> future domains, pre-block them, and recognise any sample using the same generator. Octo2
> introduced a DGA in September 2024 specifically to raise blocking cost (ThreatFabric); reversing
> it inverts that advantage permanently.

---

## 5. The clustering algorithm

```
  ┌──────────────────────────────────────────────────────────────┐
  │ PHASE 1 - DETERMINISTIC (high precision, auto-merge)          │
  │   union-find over:                                            │
  │     • identical signer_cert_sha256                            │
  │     • v3 rotation lineage membership                          │
  │     • identical hardcoded key                                 │
  │   → hard clusters                                             │
  ├──────────────────────────────────────────────────────────────┤
  │ PHASE 2 - SIMILARITY (medium precision, propose)              │
  │   for each pair of hard clusters:                             │
  │     score = w1·tlsh_proximity + w2·api_overlap                │
  │           + w3·manifest_similarity + w4·resource_overlap       │
  │   merge if score > MERGE_THRESHOLD                            │
  │   flag for review if BETWEEN review and merge thresholds      │
  ├──────────────────────────────────────────────────────────────┤
  │ PHASE 3 - INFRASTRUCTURE (link, don't merge)                  │
  │   add campaign-level edges for shared C2, TLS, DGA, protocol  │
  │   ★ links do NOT merge clusters - different actors share       │
  │     delivery services (Zombinder)                             │
  ├──────────────────────────────────────────────────────────────┤
  │ PHASE 4 - HUMAN ADJUDICATION                                  │
  │   analyst confirms / splits / merges; recorded as adjudication │
  └──────────────────────────────────────────────────────────────┘
```

### Why phase 3 links rather than merges

**Zombinder** delivered **Octo2**, **Chameleon**, and **Hook** - three different payload families
through one delivery service (ThreatFabric). Merging on shared delivery infrastructure would fuse
three unrelated actors into one phantom campaign.

> **⚙️ Engineering Note:** Model the criminal supply chain as it actually is
> ([Ch 15 §2](../malware/15-malware-infrastructure.md#2-the-criminal-supply-chain)): **dropper
> actor, payload actor, and cash-out actor are frequently different parties.** Shared
> infrastructure is a *relationship*, not an identity. This single modelling decision prevents a
> large class of confidently wrong attribution.

---

## 6. Campaign and actor modelling

```yaml
campaign:
  id: "camp_01J8..."
  name: "Anatsa NA Q2-2025"
  family: {id: "fam_anatsa", aliases: [{name: "TeaBot", vendor: "Cleafy"}]}
  artifacts: [art_..., ...]
  signers: [cert_sha256, ...]
  infrastructure: {c2: [...], keys: [...], protocol: "https", dga: null}
  delivery: {service: "Zombinder", confidence: medium}     # ★ separate node
  targeting:
    packages: [...]                        # union across the campaign
    client_packages_hit: ["com.clientbank.app"]
    regions: ["US","CA","DE","KR"]         # from locale sets
  timeline: {first_seen, last_seen, sample_count}
  tenants_affected: [t1, t2, t3]           # ★ count exposed; identities gated
  confidence:
    family: high
    campaign: medium
    actor: low                             # ★ be honest
  basis: [signer_match, tlsh_cluster, c2_overlap]
  caveats: ["MaaS - affiliates use distinct signers"]
```

### The MaaS vs private-operation signature

| Observation | Interpretation |
|---|---|
| Many signers + high code similarity + divergent C2 | **MaaS with multiple affiliates** |
| Few signers + coherent infrastructure | **Private operation** |
| One signer per sample, code-similar | **Sophisticated MaaS** - per-build key generation |

Cleafy assessed **Klopatra** as a private botnet partly on this shape (August 2025); ERMAC's
~$5,000/month rental model (ESET, May 2022) is the MaaS archetype.

> **⚙️ Engineering Note:** Report this shape explicitly. It tells the bank whether they face **one
> adversary or a marketplace** - which changes the expected trajectory. A private operation may be
> disrupted by a single takedown; a MaaS ecosystem will produce a new affiliate next week.

---

## 7. The leaked-source problem

The specific attribution trap in this domain.

```
   Cerberus source leaked (~Aug 2020)
        └──► Alien, ERMAC, Phoenix   ← code-similar, DIFFERENT actors
   ERMAC 3.0 source leaked (Hunt.io, pub. Aug 2025)
   Octo source leaked (2024)
   SpyNote/CypherRat source public on GitHub (Oct 2022)
```

After a leak, **code similarity indicates lineage, not actor**.

```yaml
family:
  id: "fam_ermac"
  source_leaked: true                     # ★ schema flag
  leak_date: "2025-08"
  leak_reference: "Hunt.io ERMAC 3.0"
  correlation_policy:
    code_similarity_actor_confidence: downgrade_to_low   # ★ automatic
    prefer_pivots: [signer, infrastructure, hardcoded_key]
```

> **⚙️ Engineering Note:** Make `source_leaked` a first-class field that **automatically
> downgrades** actor-attribution confidence for anything in that lineage. It is a two-line schema
> decision that prevents an entire class of confidently wrong reports - and post-leak windows are
> exactly when variant volume spikes and analysts are busiest.
> → [Ch 30](../threat-intelligence/30-threat-intelligence-database.md)

### Attribution ceiling

| Level | Achievable? | Basis |
|---|---|---|
| **Family** | ✅ Yes | Code + signer + protocol |
| **Campaign** | ✅ Yes | Infrastructure + targeting + timing |
| **Operator/group** | ⚠ Rarely | Sustained tracking; usually vendor-sourced |
| **Nation-state** | ❌ No | Out of scope ([Ch 16 §10](../threat-intelligence/16-threat-intelligence.md#10-attribution-and-its-limits)) |

**Never attribute from** language artifacts, build timezones, or CIS geofencing - spoofable and a
documented false-flag technique.

---

## 8. Cross-tenant correlation

The hardest design problem in the product
([Ch 22 §9](22-building-sudarshan.md#9-operating-and-safety-constraints)).

### The tension

```
   VALUE                                RISK
   ─────                                ────
   Bank A's submission should            Bank A must never see Bank B's
   protect Banks B, C, D                 submissions, customers, or the
        │                                fact that B was targeted
        ▼                                       │
   requires shared correlation                  ▼
                                        requires hard isolation
```

### The workable split

| Shared (with contractual consent) | Tenant-private (never crosses) |
|---|---|
| Signer certificate hashes | Submissions and submitters |
| C2 domains, IPs, TLS certs | Customer cohorts and device references |
| Hardcoded keys | Case details and transaction data |
| YARA / Sigma rules | **The fact that a specific tenant is targeted** |
| Family and campaign linkage | Tenant-identifying target-list entries |
| TLSH cluster membership | |
| **Aggregate counts** ("3 institutions affected") | **Institution identities** |

```yaml
correlation_result:
  campaign_id: "camp_..."
  # visible to ALL tenants in the campaign
  shared:
    sample_count: 47
    signers: [...]
    c2: [...]
    institutions_affected_count: 4          # ★ count only
  # visible ONLY to the requesting tenant
  tenant_scoped:
    your_packages_targeted: ["com.clientbank.app"]
    your_customers_affected: 340
    your_submissions_in_campaign: [art_...]
```

> **🏛️ Enterprise Insight:** *"Four institutions are affected"* is shareable and genuinely useful
> - it tells each bank the campaign is sectoral rather than personal. *"Bank B is affected"* is
> **Bank B's information about being attacked**, and disclosing it without consent is a
> confidentiality breach and a commercial betrayal. Aggregate counts, never identities. This
> boundary must be in the contract and enforced in the query layer, not left to convention.

---

## 9. The correlation output

```json
{
  "artifact_id": "art_01J8...",
  "campaign": {
    "id": "camp_01J8...",
    "name": "Anatsa NA Q2-2025",
    "family": {"name": "Anatsa", "aliases": ["TeaBot"], "vendor": "ThreatFabric"},
    "sample_count": 47,
    "first_seen": "2025-05-07",
    "last_seen": "2026-08-01"
  },
  "clustering_basis": [
    {"pivot":"signer_cert_sha256","matched":12,"precision":"very_high"},
    {"pivot":"hardcoded_key","matched":31,"precision":"high",
     "note":"different signers → MaaS affiliates"},
    {"pivot":"tlsh_dex","matched":47,"threshold":50,"precision":"medium_high"}
  ],
  "infrastructure_links": [
    {"type":"c2_domain","shared_with_samples":18},
    {"type":"delivery_service","value":"Zombinder","note":"LINK not MERGE"}
  ],
  "operation_shape": "maas_multiple_affiliates",
  "confidence": {"family":"high","campaign":"medium","actor":"low"},
  "caveats": ["family source not leaked","affiliate signers differ"],
  "shared_view": {"institutions_affected_count": 4},
  "tenant_view": {
    "your_packages_targeted": ["com.clientbank.app"],
    "your_customers_affected": 340
  }
}
```

---

## 10. Limitations and false positives

### False clusters

| Cause | Mitigation |
|---|---|
| Shared large framework (Flutter, React Native, Unity) dominating TLSH | Require multi-measure agreement (§3) |
| Leaked source reused by unrelated actors | `source_leaked` flag (§7) |
| Shared delivery service | Link, don't merge (§5) |
| Shared hosting IP | Never merge on IP alone |
| Common commercial packer | Packer is a tool, not an identity |
| Target-list overlap | Many actors target the same major banks |

### Missed clusters

| Cause | Mitigation |
|---|---|
| Per-build signing keys | Fall back to code + infrastructure; **record as a sophistication indicator** |
| Full rewrite between campaigns | Infrastructure and protocol pivots |
| Distinct infrastructure per affiliate | Code similarity |
| Sparse corpus | Time; cross-tenant sharing |

> **🚨 Misconception:** "Same C2 means same actor." Shared hosting, bulletproof providers with many
> customers, and delivery services (Zombinder) all put unrelated actors on shared infrastructure.
> Infrastructure overlap is a **link**, and links are hypotheses - merging on them is how you
> invent a campaign that doesn't exist.

---

## 11. Engineering tips

1. **Rank pivots by durability and match precision to action cost.**
2. **TLSH the DEX, not the APK.**
3. **Require multi-measure agreement** before auto-merging clusters.
4. **Link on infrastructure; merge only on identity-grade pivots.**
5. **Model dropper and payload as separate actors** with a delivery relationship.
6. **Flag leaked-source families** and auto-downgrade actor confidence.
7. **Index hardcoded keys** - they catch affiliates whose signers differ.
8. **Parse and expand v3 rotation lineage** into one actor node.
9. **Report the operation shape** (MaaS vs private) - it changes expectations.
10. **Share counts, never institution identities**, across tenants.
11. **Record "unique signer per sample"** as a sophistication indicator, not a failure.
12. **Keep human adjudication in the loop** and store it separately.

---

## 12. Judge Insights

**What judges ask:** *"How does analysing one bank's APK help another bank?"*

**Perfect answer:** Through the correlation graph, and the design point is that we share
*indicators and linkage* without ever sharing *submissions or identities*. From one sample we
extract the signer certificate, any hardcoded keys, the C2 endpoints, and a DEX-level fuzzy hash.
The signer links to sibling samples; a shared AES key links to samples with *different* signers,
which tells us we're looking at MaaS affiliates rather than one operator; the C2 resolves to a host
with sibling domains that appear in other tenants' submissions. Then we union the target lists
across the cluster. So each bank sees "this campaign spans 47 samples and four institutions, and
these are *your* packages targeted and *your* customers affected" - the count is shared, the
identities are not. "Bank B is targeted" is Bank B's information about being attacked, not ours to
distribute, and that boundary is enforced in the query layer, not by convention.

**Common mistakes:**
- Merging clusters on shared infrastructure. Zombinder delivered Octo2, Chameleon, and Hook - three different actors through one service.
- Attributing to an operator from code similarity after a source leak.
- Applying one confidence threshold across all pivot types.

**Follow-ups to expect:**
- *"What if they use a different signing key per sample?"* → Then signer correlation produces
  clusters of one, and we fall back to code similarity, hardcoded keys, and infrastructure. But we
  also *record* the per-build key generation, because it's itself an operational-sophistication
  indicator worth telling the bank about.
- *"How confident is your attribution?"* → Family and campaign, reasonably. Operator, rarely.
  Nation-state, no. And after the Cerberus, Octo, SpyNote, and ERMAC 3.0 leaks, code similarity
  indicates lineage rather than actor, so we carry a `source_leaked` flag that automatically
  downgrades actor confidence for those families.
- *"Could you accidentally cluster two unrelated apps?"* → Yes, if you use TLSH alone - a shared
  Flutter or React Native runtime can dominate a DEX. We require agreement across TLSH, API-set
  overlap, and manifest or resource similarity before auto-merging.

**Fact that impresses:** Hardcoded encryption keys are a better correlation pivot than C2 domains,
and almost nobody indexes them. Adversaries rotate domains weekly and rebuild binaries daily, but
rotating a key means rebuilding the panel and re-flashing the installed base - so keys persist for
months. More usefully, a shared key across samples with *different signing certificates* is a
direct fingerprint of a MaaS operation with multiple affiliates.

---

## 13. Interview Insights

**Q: "How do you group malware samples into families?"**
Deterministic pivots first - signer certificate, v3 rotation lineage, hardcoded keys - union-find
into hard clusters. Then similarity with multi-measure agreement (DEX TLSH plus API-set plus
manifest/resource). Then infrastructure as *links*, not merges. Then human adjudication.

**Q: "Why DEX-level fuzzy hashing rather than whole-file?"**
Whole-APK hashes are dominated by resources and assets, which vary per campaign even when the code
is identical. DEX-level tracks code lineage, which is what family clustering needs.

**Q: "Two samples share a C2. Same actor?"**
Not necessarily. Shared hosting, bulletproof providers with many customers, and delivery services
like Zombinder - which distributed Octo2, Chameleon, and Hook - all place unrelated actors on
common infrastructure. Link, don't merge.

**Q: "Malware source code leaked. What does that do to your attribution?"**
Code similarity now indicates lineage rather than actor. We flag the family as leaked and
automatically downgrade actor-attribution confidence, leaning on signer and infrastructure instead.

**Q: "How would you correlate across customers who compete with each other?"**
Share indicators and campaign linkage; keep submissions, customer cohorts, and institution
identities tenant-private. Expose aggregate counts. Enforce it in the query layer and put it in
the contract.

**Beginner mistakes:**
- Merging on IP or shared infrastructure.
- Single-measure clustering.
- Attributing to actors post-leak.
- Treating per-build keys as a correlation failure rather than a finding.

---

## 14. Cross-references

**Upstream:** [Ch 06 §10](../security/06-certificates.md#10-certificates-as-a-correlation-pivot) ·
[Ch 14 §4](../banking-malware/14-banking-malware.md#4-the-lineage-map) ·
[Ch 15 §11](../malware/15-malware-infrastructure.md#11-pivoting-infrastructure-as-an-investigative-graph) ·
[Ch 26](26-ioc-extraction.md)

**Downstream:** [Ch 29](29-investigation-reports.md) ·
[Ch 30](../threat-intelligence/30-threat-intelligence-database.md)

---

## 15. References

1. Caltagirone, Pendergast, Betz - *The Diamond Model of Intrusion Analysis* (2013).
2. TLSH - Trend Micro Locality Sensitive Hash. https://github.com/trendmicro/tlsh
3. ThreatFabric - *Octo2* (September 2024) - DGA; Zombinder as first stage.
4. ThreatFabric - Zombinder distributing Chameleon alongside Hook.
5. Hunt.io - ERMAC 3.0 source leak (published August 2025).
6. ESET - ERMAC v2 MaaS pricing (~$5,000/month, May 2022).
7. Cleafy Labs - *Klopatra* (August 2025) - private-botnet assessment.
8. Cleafy Labs - *Copybara* - "JOKER RAT" panel naming.
9. AOSP - APK Signature Scheme v3 proof-of-rotation. https://source.android.com/docs/security/features/apksigning/v3
10. OASIS - STIX 2.1 campaign, intrusion-set, and relationship objects.

---

*Previous: [← Ch 27 Risk Scoring](27-risk-scoring.md) · Next: [Ch 29 Investigation Reports →](29-investigation-reports.md)*
