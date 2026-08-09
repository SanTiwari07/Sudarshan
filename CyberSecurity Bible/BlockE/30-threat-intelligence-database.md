# 30 - Threat Intelligence Database

> **Chapter ID:** `CH30` · **Block:** E · **Status:** Stable
> **Tags:** `#ti-database` `#schema` `#aliases` `#feeds` `#retro-hunt` `#provenance` `#multi-tenant`
> **Last Updated:** 2026-08-05 · **Version:** 1.0.0
> **Prerequisites:** [Ch 16](16-threat-intelligence.md), [Ch 26](../sudarshan/26-ioc-extraction.md), [Ch 28](../sudarshan/28-campaign-correlation.md)

---

## Table of Contents

1. [What the database is for](#1-what-the-database-is-for)
2. [The schema](#2-the-schema)
3. [Family and alias modelling](#3-family-and-alias-modelling)
4. [The leaked-source flag](#4-the-leaked-source-flag)
5. [Provenance](#5-provenance)
6. [Feed ingestion](#6-feed-ingestion)
7. [Retro-hunt infrastructure](#7-retro-hunt-infrastructure)
8. [Rule storage](#8-rule-storage)
9. [Multi-tenant partitioning](#9-multi-tenant-partitioning)
10. [Decay and hygiene](#10-decay-and-hygiene)
11. [Limitations and edge cases](#11-limitations-and-edge-cases)
12. [Engineering tips](#12-engineering-tips)
13. [Judge Insights](#13-judge-insights)
14. [Interview Insights](#14-interview-insights)
15. [Cross-references](#15-cross-references)
16. [References](#16-references)

---

## 1. What the database is for

Four jobs, and the fourth is the one that makes the platform compound.

| Job | Consumer |
|---|---|
| **Enrichment** - is this signer/hash/domain known? | Detection pipeline ([Ch 23](../sudarshan/23-detection-pipeline.md)) |
| **Correlation memory** - what does this connect to? | Campaign correlation ([Ch 28](../sudarshan/28-campaign-correlation.md)) |
| **Rule store** - what do we detect and how? | Detection engineering ([Ch 19 §7](../soc/19-enterprise-soc-operations.md#7-detection-engineering)) |
| **★ Retro-hunt substrate** - re-evaluate the past when the present changes | Hunting ([Ch 18 §6](../soc/18-mobile-threat-hunting.md#6-hunting-the-sample-corpus)) |

```
   Every analysis WRITES to the DB          Every analysis READS from it
        │                                            │
        ▼                                            ▼
   the corpus grows                    each new sample is answered
        │                              with everything learned before
        ▼                                            │
   ★ new intel triggers RETRO-HUNT ─────────────────┘
     over the whole corpus, changing past verdicts
```

> **⚙️ Engineering Note:** Design for the retro-hunt from the start. It is the property that turns
> a scanner into an intelligence platform: **a verdict is provisional, not final.** A sample marked
> inconclusive in March because its C2 was offline should be automatically re-evaluated in August
> when new rules land - and the original submitter notified. Retrofitting that requires storing
> things you didn't keep.

---

## 2. The schema

```
 ┌──────────────┐   aliases    ┌──────────────┐
 │   FAMILY     │◄─────────────│    ALIAS     │  {name, vendor, first_reported}
 │ source_leaked│              └──────────────┘
 └──────┬───────┘
        │ member_of
        ▼
 ┌──────────────┐  signed_by   ┌──────────────┐  attributed_to  ┌──────────────┐
 │   ARTIFACT   │─────────────►│    SIGNER    │────────────────►│   CAMPAIGN   │
 │  sha256 (PK) │              │ cert_sha256  │                 │              │
 └──┬────┬──────┘              └──────────────┘                 └──────┬───────┘
    │    │ derived_from (recursion)                                     │ uses
    │    └──────────────► ARTIFACT                                      ▼
    │ exhibits                                              ┌──────────────────┐
    ├──────────────► CAPABILITY                             │  INFRASTRUCTURE  │
    │ targets                                               │ domain·ip·key·   │
    ├──────────────► TARGET_PACKAGE  ★                      │ tls·ja3·panel    │
    │ contacts                                              └──────────────────┘
    └──────────────► INFRASTRUCTURE
                            │
 ┌──────────────┐           │        ┌──────────────┐      ┌──────────────┐
 │  INDICATOR   │───────────┘        │     RULE     │      │  SUBMISSION  │
 │ ttl·conf·tlp │                    │ yara·sigma   │      │ tenant·source│
 └──────────────┘                    │ ruleset_ver  │      └──────────────┘
                                     └──────────────┘
 ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
 │   EVIDENCE   │   │   VERDICT    │   │   SOURCE     │
 │  immutable   │   │ automated +  │   │ vendor·date· │
 │              │   │ adjudicated  │   │ report·tlp   │
 └──────────────┘   └──────────────┘   └──────────────┘
```

### Core tables

```sql
CREATE TABLE artifact (
  sha256            TEXT PRIMARY KEY,
  size_bytes        BIGINT,
  tlsh_file         TEXT,
  tlsh_dex          TEXT,              -- ★ code lineage (Ch 24 §5)
  signer_cert_sha256 TEXT REFERENCES signer(cert_sha256),
  package_name      TEXT,              -- campaign attribute, NOT identity
  first_seen_utc    TIMESTAMPTZ,
  artifact_set_id   TEXT,              -- splits grouped
  parent_sha256     TEXT REFERENCES artifact(sha256),   -- ★ recursion
  derivation        TEXT,              -- installed_by | classloader_dump | ...
  depth             INT DEFAULT 0
);

CREATE TABLE signer (                  -- ★ PRIMARY IDENTITY (P5)
  cert_sha256       TEXT PRIMARY KEY,
  spki_sha256       TEXT,
  subject_dn        TEXT,              -- artifact only, NEVER attribution
  not_before, not_after TIMESTAMPTZ,
  key_algorithm     TEXT, key_size INT,
  is_debug_cert     BOOLEAN,
  reputation        TEXT,              -- unknown | benign | malicious
  sample_count      INT,               -- prevalence → Ch 18 HUNT-5
  rotation_lineage_id TEXT             -- ★ v3 proof-of-rotation
);

CREATE TABLE indicator (
  id                TEXT PRIMARY KEY,
  type              TEXT, value_raw TEXT, value_defanged TEXT,
  confidence, severity, action_class TEXT,   -- ★ block|alert|enrich_only
  first_seen_utc, last_seen_utc, valid_until_utc TIMESTAMPTZ,  -- ★ TTL
  sinkholed         BOOLEAN DEFAULT FALSE,   -- ★ inverts meaning (Ch 26 §7)
  shared_hosting    BOOLEAN DEFAULT FALSE,
  tlp               TEXT,
  tenant_visibility TEXT                     -- shared | tenant_private
);
CREATE INDEX ON indicator (type, value_raw) WHERE valid_until_utc > now();
```

> **⚙️ Engineering Note:** Two indexing decisions carry disproportionate weight. **`signer_cert_sha256`
> must be indexed and fast** - it is the hottest lookup in the system and the fastest path to a
> high-confidence verdict ([Ch 23 §2](../sudarshan/23-detection-pipeline.md#2-the-tiers)). And the
> partial index on live indicators (`WHERE valid_until_utc > now()`) keeps expired entries out of
> the enforcement path without deleting them from history - expiry and retention are different
> concerns and need different mechanics.

---

## 3. Family and alias modelling

Vendor naming diverges, and flat strings fragment correlation the first time two vendors disagree
([Ch 14 §9](../banking-malware/14-banking-malware.md#9-naming-divergence)).

```sql
CREATE TABLE family (
  id                TEXT PRIMARY KEY,       -- "fam_anatsa"
  canonical_name    TEXT,                   -- our chosen label
  first_reported    DATE,
  first_reported_by TEXT,
  lineage_parent_id TEXT REFERENCES family(id),   -- ★ Exobot → Octo → Octo2
  source_leaked     BOOLEAN DEFAULT FALSE,  -- ★ §4
  leak_date         DATE,
  leak_reference    TEXT,
  operation_shape   TEXT                    -- maas | private | unknown
);

CREATE TABLE family_alias (
  family_id         TEXT REFERENCES family(id),
  alias             TEXT,
  naming_vendor     TEXT,                   -- ★ WHO calls it this
  first_reported    DATE,
  is_collision      BOOLEAN DEFAULT FALSE,  -- ★ e.g. "Medusa"
  collision_note    TEXT,
  PRIMARY KEY (family_id, alias, naming_vendor)
);
```

### Seed data

```sql
INSERT INTO family_alias VALUES
 ('fam_anatsa','TeaBot','Cleafy','2021-01', false, NULL),
 ('fam_anatsa','Toddler',NULL,NULL,false,NULL),
 ('fam_octo','Coper',NULL,NULL,false,NULL),
 ('fam_medusa_android','Medusa','Cleafy','2024-06', TRUE,
  'COLLISION: distinct from the Medusa ransomware gang and the Mirai-based Medusa DDoS botnet'),
 ('fam_spynote','CypherRat',NULL,'2021-08',false,NULL);
```

> **⚙️ Engineering Note - surface the collision flag in the UI and in reports.** "Medusa" refers
> to three unrelated things, and a report that says "Medusa" without qualification is a
> credibility loss that costs nothing to avoid. Make `is_collision` force a qualifier at render
> time rather than relying on the analyst remembering.

### Lineage as data

```sql
-- Exobot(2016) → Octo/Coper(2021) → Octo2(2024)
-- Cerberus(2019) → {Alien, ERMAC, Phoenix};  ERMAC → Hook
INSERT INTO family (id, canonical_name, lineage_parent_id, source_leaked, leak_date) VALUES
 ('fam_cerberus','Cerberus', NULL,          TRUE, '2020-08'),
 ('fam_alien',   'Alien',    'fam_cerberus',FALSE, NULL),
 ('fam_ermac',   'ERMAC',    'fam_cerberus',TRUE, '2025-08'),
 ('fam_hook',    'Hook',     'fam_ermac',   FALSE, NULL);
```

Storing lineage as data means a new sample matching ERMAC code can be automatically reported as
*"ERMAC lineage - note source leaked August 2025, so this indicates lineage rather than actor."*

---

## 4. The leaked-source flag

The two-line schema decision that prevents an entire class of wrong reports
([Ch 28 §7](../sudarshan/28-campaign-correlation.md#7-the-leaked-source-problem)).

```yaml
correlation_policy:
  when: family.source_leaked == true
  then:
    code_similarity_actor_confidence: low       # ★ automatic downgrade
    preferred_pivots: [signer, infrastructure, hardcoded_key]
    report_caveat: >
      Source code for this family was leaked ({leak_date}, {leak_reference}).
      Code similarity indicates shared lineage, not necessarily a shared operator.
```

Known leaks to seed:

| Family | Leaked | Reference |
|---|---|---|
| **Cerberus** | ~Aug 2020 | Seeded Alien, ERMAC, Phoenix |
| **SpyNote / CypherRat** | Oct 2022 | Source made public on GitHub |
| **Octo** | 2024 | Prompted Octo2 by the original author |
| **ERMAC 3.0** | Pub. Aug 2025 | Hunt.io - open directory `141.164.62[.]236:443` |

> **⚙️ Engineering Note:** Post-leak windows are exactly when variant volume spikes and analysts
> are most overloaded - which is precisely when an automatic confidence downgrade is most valuable
> and least likely to be applied by hand. Make it a database property, not a checklist item.

---

## 5. Provenance

Every fact carries its source. This is what makes the corpus auditable and what lets you weight
conflicting claims.

```sql
CREATE TABLE source (
  id              TEXT PRIMARY KEY,
  kind            TEXT,   -- internal_analysis | vendor_report | feed | analyst | government
  vendor          TEXT,   -- ThreatFabric | Cleafy | Cyble | Zimperium | Hunt.io ...
  published_date  DATE,   -- ★ recency
  title, url      TEXT,
  reliability     TEXT,   -- high | medium | low
  claim_type      TEXT,   -- ★ observation | telemetry | prediction | assessment
  tlp             TEXT
);
```

### Why `claim_type` matters

| Type | Example | Treatment |
|---|---|---|
| **observation** | "Dropper reached #4 in Play Top Free Tools by June 29, 2025" | Fact |
| **telemetry** | "1,500+ infected devices; Italy 56.8%" | **That vendor's visibility**, not global truth |
| **prediction** | "Octo2 infections expected to become more widespread" | ★ **Never quote as fact** |
| **assessment** | "Operators assessed as Turkish-speaking" | Hedged; note spoofability |

> **⚙️ Engineering Note:** Separating observation from prediction at ingest time is a small schema
> field that prevents a recurring reporting error. Vendor blogs mix all four freely; if you store
> them undifferentiated, a forecast becomes a fact by the time it reaches a bank's report.
> → [Ch 16 §11](16-threat-intelligence.md#11-sources-and-how-to-weigh-them)

### Vendor visibility bias

```sql
-- record it, and surface it in coverage gaps
INSERT INTO vendor_coverage VALUES
 ('Cleafy',      ARRAY['IT','ES','PT','FR']),
 ('ThreatFabric',ARRAY['EU','US','CA']),
 ('Group-IB',    ARRAY['SEA','VN','TH']),
 ('Cyble',       ARRAY['IN','GLOBAL']),
 ('CYFIRMA',     ARRAY['IN']);
```

> **🏛️ Enterprise Insight:** *"This family hasn't been seen in India"* frequently means *"no vendor
> with Indian visibility has published on it."* For an India-focused platform, modelling vendor
> coverage explicitly turns that from a blind spot into a stated caveat - and into an argument for
> the bank's own telemetry.

---

## 6. Feed ingestion

```
   External feed (STIX / MISP / CSV / vendor PDF)
        │
        ▼
   NORMALISE ──► indicator + source records
        │
        ▼
   ASSESS: reliability, claim_type, TTL, action_class
        │
        ▼
   ★ QUARANTINE: never auto-block, never auto-train
        │
        ▼
   Cross-check against internal corpus
        │
   ┌────┴────────────┐
  confirmed        unconfirmed
   │                 │
   ▼                 ▼
 promote to      enrich_only
 alert/block
```

| Feed type | Default treatment |
|---|---|
| Named vendor report | reliability high; `enrich_only` until corroborated |
| Government / CERT | reliability high; alert |
| Commercial feed | reliability medium; alert |
| Community (MISP, abuse.ch) | reliability medium; `enrich_only` |
| Unvetted / public | reliability low; `enrich_only`, **never training data** |

> **⚙️ Engineering Note:** Two hard rules. **Never auto-block from an external feed** - one bad
> entry blocking a customer's payment gateway ends the bank's trust in the platform permanently.
> **Never auto-train on unvetted data** - that is the poisoning vector
> ([Ch 21 §6](../ai-malware-analysis/21-ai-assisted-malware-analysis.md#6-adversarial-machine-learning)).
> Both failures are quiet until they are catastrophic.

---

## 7. Retro-hunt infrastructure

The capability that makes verdicts revisable.

```
  TRIGGER: new rule · new intel · verdict change · leaked panel source
        │
        ▼
  Select corpus scope (all / family / time window / previously-inconclusive)
        │
        ▼
  Replay: YARA over stored DEX · behavioural rules over stored analyses
          · indicator match over stored network captures
        │
        ▼
  For each hit: recompute the verdict with the CURRENT ruleset
        │
   ┌────┴─────────────┐
  unchanged        ★ CHANGED
   │                  │
   ▼                  ▼
 log            issue a report revision (Ch 29 §11)
                  + NOTIFY the original submitter
                  + re-run the customer sweep (Ch 25 §7)
```

### What must be stored to make this possible

```yaml
retained_for_retrohunt:
  artifact_bytes: true                  # subject to retention policy
  extracted_dex: true                   # ★ YARA replay target
  capability_vectors: true              # cheap behavioural replay
  network_captures: true                # indicator matching
  detonation_logs: true
  verdict_history: true                 # ★ every verdict, with ruleset_version
  submission_records: true              # ★ WHO to notify
```

> **⚙️ Engineering Note:** `submission_records` is the one teams forget, and without it the whole
> mechanism is decorative. If a verdict changes and you cannot identify who received the original
> answer, you have improved your database and not helped anyone. Store tenant, submitter, and
> delivery reference on every report issued.

### Priority: previously-inconclusive samples

```sql
-- the highest-value retro-hunt population
SELECT a.sha256, v.ceiling_reason, s.tenant_id
FROM artifact a
JOIN verdict v ON v.sha256 = a.sha256
JOIN submission s ON s.sha256 = a.sha256
WHERE v.verdict = 'inconclusive'
  AND v.ceiling_reason IN ('c2_unreachable','packed_not_unpacked')
  AND v.ruleset_version < :current_ruleset
ORDER BY a.first_seen_utc DESC;
```

---

## 8. Rule storage

Detection-as-code ([Ch 19 §7](../soc/19-enterprise-soc-operations.md#7-detection-engineering)),
with the database holding operational state that Git cannot.

```sql
CREATE TABLE rule (
  id                TEXT PRIMARY KEY,
  kind              TEXT,        -- yara | sigma | structural | capability | correlation
  name, body        TEXT,
  ruleset_version   TEXT,
  attack_techniques TEXT[],
  attack_version    TEXT,        -- ★ pin it (Ch 16 §3)
  severity, confidence TEXT,
  owner             TEXT,        -- ★ unowned rules rot
  created, last_reviewed DATE,
  review_cadence_days INT DEFAULT 90,
  enabled           BOOLEAN,
  -- ★ operational health
  fire_count_30d    INT,
  fp_count_30d      INT,
  fp_rate_30d       NUMERIC GENERATED ALWAYS AS
                      (CASE WHEN fire_count_30d>0
                            THEN fp_count_30d::numeric/fire_count_30d END) STORED
);

CREATE VIEW rules_needing_attention AS
SELECT id, name, owner, fp_rate_30d, last_reviewed
FROM rule
WHERE enabled
  AND (fp_rate_30d > 0.20
       OR last_reviewed < now() - (review_cadence_days || ' days')::interval);
```

> **⚙️ Engineering Note:** Git holds the rule *text*; the database holds its **operational
> health** - fire rate, false-positive rate, last review, owner. A rule library nobody prunes
> becomes a rule library nobody trusts, and then one nobody reads
> ([Ch 19 §3](../soc/19-enterprise-soc-operations.md#3-alert-fatigue--the-real-enemy)). The
> `rules_needing_attention` view should be a standing agenda item, not a query someone
> occasionally remembers to run.

---

## 9. Multi-tenant partitioning

```sql
CREATE TABLE submission (
  id            TEXT PRIMARY KEY,
  sha256        TEXT REFERENCES artifact(sha256),
  tenant_id     TEXT NOT NULL,          -- ★ RLS boundary
  source, submitter, context_ref TEXT,  -- ★ pseudonymised, never PII
  submitted_utc TIMESTAMPTZ
);
ALTER TABLE submission ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON submission
  USING (tenant_id = current_setting('app.tenant_id'));
```

| Shared across tenants | Tenant-private |
|---|---|
| `artifact`, `signer`, `family`, `campaign` | `submission` |
| `indicator` where `tenant_visibility='shared'` | `customer_cohort` |
| `rule` | `case` |
| Aggregate counts | **Institution identities** |

```sql
-- ★ shareable: the count
SELECT count(DISTINCT tenant_id) AS institutions_affected
FROM submission WHERE sha256 IN (SELECT sha256 FROM campaign_artifact WHERE campaign_id=$1);

-- ❌ NEVER exposed cross-tenant: which institutions
```

> **🏛️ Enterprise Insight:** Enforce this in the **query layer with row-level security**, not by
> convention in application code. A single ORM query written without a tenant filter is a
> confidentiality breach and, in a multi-bank product, an existential one. RLS makes the safe path
> the default path.
> → [Ch 28 §8](../sudarshan/28-campaign-correlation.md#8-cross-tenant-correlation)

---

## 10. Decay and hygiene

```sql
-- expire from ENFORCEMENT; retain for HISTORY  (Ch 26 §6)
UPDATE indicator SET action_class='enrich_only'
WHERE valid_until_utc < now() AND action_class IN ('block','alert');

-- re-verification queue
CREATE VIEW indicators_needing_verification AS
SELECT id, type, value_defanged, valid_until_utc
FROM indicator
WHERE valid_until_utc BETWEEN now() AND now() + interval '14 days'
  AND action_class IN ('block','alert')
ORDER BY severity DESC;
```

| Hygiene task | Cadence |
|---|---|
| Indicator re-verification | Rolling, before expiry |
| Sinkhole status refresh | Weekly |
| Rule review (`rules_needing_attention`) | Weekly |
| Family alias reconciliation | On each vendor report ingest |
| Signer reputation recompute | Nightly |
| Retro-hunt on inconclusive corpus | On every ruleset release |
| Feed reliability reassessment | Quarterly |

> **⚙️ Engineering Note:** **Expiry ≠ deletion.** An expired indicator stops firing but remains
> available for historical correlation - "this domain was this family's C2 in 2025" is still true
> and still useful for clustering, even though blocking it today would be wrong. Two states, one
> record.

---

## 11. Limitations and edge cases

| Case | Handling |
|---|---|
| Vendors disagree on family assignment | Store both with their sources; surface the disagreement |
| A family is renamed | New alias with vendor and date; canonical name unchanged |
| Alias collision (**Medusa**) | `is_collision` flag forces a qualifier at render |
| Sample retained past its retention policy | Delete bytes; **keep graph node, findings, and verdicts** |
| Corpus growth | Partition by time; archive cold artifacts; keep indices hot |
| Feed contradicts internal analysis | Internal analysis wins; record the conflict |
| Tenant offboards | Delete submissions and cohorts; **shared indicators persist if consented** |

> **🚨 Misconception:** "The TI database is a big list of bad things." It is a **graph with
> provenance, confidence, and time**. Without provenance you cannot weight conflicting claims;
> without expiry you accumulate false positives; without submission records you cannot notify
> anyone when a verdict changes. A flat blocklist has none of those properties and none of the
> value.

---

## 12. Engineering tips

1. **Index `signer_cert_sha256` hard.** Hottest lookup, fastest verdict path.
2. **Model aliases with the naming vendor**, never as bare strings.
3. **Flag collisions** (Medusa) and force a qualifier at render.
4. **Store lineage as data**, so leaked-source policy applies automatically.
5. **Record `claim_type`** - observation vs telemetry vs prediction vs assessment.
6. **Model vendor coverage** to expose visibility bias.
7. **Never auto-block from feeds; never auto-train on unvetted data.**
8. **Store submission records** - retro-hunt notification is impossible without them.
9. **Keep rule operational health in the DB**, rule text in Git.
10. **Expire from enforcement; retain for history.**
11. **Enforce tenant isolation with RLS**, not convention.
12. **Prioritise the previously-inconclusive corpus** on every ruleset release.

---

## 13. Judge Insights

**What judges ask:** *"So it's a threat intelligence database. What makes yours different from a
blocklist?"*

**Perfect answer:** Three properties a blocklist doesn't have. First, **provenance on every fact** - not just "this domain is bad" but which vendor said it, when they published, and critically what
*kind* of claim it is. Vendor reports mix observations, their own telemetry, and predictions
freely; if you store those undifferentiated, ThreatFabric's forecast that Octo2 would spread
becomes a stated fact by the time it reaches a bank's report. Second, **time** - every indicator
has a type-based TTL, and we expire from enforcement while retaining for history, because domains
get re-registered and IPs get recycled. A database that only grows becomes a false-positive engine.
Third, and this is the one that matters most, it's **retro-hunt substrate**: when new intelligence
lands we replay rules across the entire stored corpus, recompute verdicts with the current ruleset,
and notify the original submitter when a verdict changes. That makes a "clean" answer provisional
rather than final - which is the honest position, since a sample can look clean purely because its
C2 was offline that day.

**Common mistakes:**
- Storing family names as flat strings. The first vendor disagreement fragments your correlation.
- Auto-blocking from feeds. One bad entry taking down a payment gateway ends the relationship.
- Not storing submission records, which makes verdict-change notification impossible.

**Follow-ups to expect:**
- *"How do you handle vendors calling the same malware different names?"* → Aliases are first-class
  rows carrying the naming vendor and first-reported date, and we flag known collisions - "Medusa" is an Android banker, a ransomware gang, and a DDoS botnet, so the flag forces a
  qualifier at render time rather than relying on the analyst remembering.
- *"What happens when malware source code leaks?"* → We carry a `source_leaked` flag on the family
  that automatically downgrades actor-attribution confidence for that whole lineage. After the
  Cerberus, Octo, SpyNote, and ERMAC 3.0 leaks, code similarity indicates lineage rather than
  operator - and post-leak windows are exactly when variant volume spikes and analysts are least
  likely to apply that caveat by hand.
- *"How do you keep banks' data separate?"* → Row-level security in the query layer, not
  application convention. Artifacts, signers, families, and consented indicators are shared;
  submissions, customer cohorts, and cases are tenant-private. Cross-tenant views expose counts - "four institutions affected" - never identities.

**Fact that impresses:** We model **vendor visibility bias** explicitly. Cleafy sees Italy and
Spain clearly, ThreatFabric Western Europe and the US, Group-IB Southeast Asia, Cyble and CYFIRMA
more of India. So "this family hasn't been seen in India" often just means no vendor with Indian
visibility has published on it. Storing coverage per vendor turns that from a silent blind spot
into a stated caveat - and into the argument for building the bank's own telemetry.

---

## 14. Interview Insights

**Q: "Design a threat intelligence database."**
Entities: artifact, signer (primary identity), family with aliases, campaign, infrastructure,
indicator, rule, evidence, submission, source. Properties that matter: provenance with claim type,
TTLs with expiry-from-enforcement, tenant partitioning, and retro-hunt retention.

**Q: "Two vendors name the same malware differently. How do you model it?"**
Aliases as rows with `naming_vendor` and `first_reported`, plus a collision flag for genuinely
ambiguous names. Never a flat string - that fragments correlation the first time vendors disagree.

**Q: "What's a retro-hunt and what must you store to support one?"**
Replaying new rules across the historical corpus and recomputing verdicts. You need the extracted
DEX for YARA replay, capability vectors, network captures, verdict history with ruleset versions,
and - the one people forget - **submission records**, so you know who to notify when a verdict
changes.

**Q: "Should you auto-block indicators from a feed?"**
No. Feed quality varies by orders of magnitude, and one bad entry blocking a legitimate service is
a production incident. Ingest with provenance, confidence, and TTL; promote to blocking only after
internal corroboration.

**Q: "How do you stop a shared database leaking between competing customers?"**
Row-level security enforced in the query layer. Share artifacts, signers, families, and consented
indicators; keep submissions, cohorts, and cases private; expose aggregate counts rather than
institution identities.

**Beginner mistakes:**
- Flat family-name strings.
- No expiry policy.
- Deleting expired indicators instead of demoting them.
- Tenant isolation by application convention.
- Not storing who submitted what.

---

## 15. Cross-references

**Upstream:** [Ch 16](16-threat-intelligence.md) ·
[Ch 26](../sudarshan/26-ioc-extraction.md) · [Ch 28](../sudarshan/28-campaign-correlation.md)

**Downstream:** [Ch 18 §6](../soc/18-mobile-threat-hunting.md#6-hunting-the-sample-corpus) ·
[Ch 29 §11](../sudarshan/29-investigation-reports.md#11-limitations-and-edge-cases) ·
[Ch 31](../appendix/31-future-research.md)

---

## 16. References

1. OASIS - STIX 2.1 / TAXII 2.1. https://oasis-open.github.io/cti-documentation/
2. MISP - data model and feed formats. https://www.misp-project.org/
3. OpenCTI - knowledge-graph model. https://www.filigran.io/en/products/opencti/
4. FIRST - Traffic Light Protocol 2.0. https://www.first.org/tlp/
5. NIST SP 800-150 - *Guide to Cyber Threat Information Sharing*.
6. Hunt.io - ERMAC 3.0 source leak (published August 2025).
7. ThreatFabric, Cleafy, Cyble, Group-IB, Zimperium, CYFIRMA - vendor reporting corpus (see [Ch 14](../banking-malware/14-banking-malware.md) references).
8. MITRE ATT&CK for Mobile - technique versioning. https://attack.mitre.org/matrices/mobile/
9. Digital Personal Data Protection Act, 2023 (India) - retention and minimisation.

---

*Previous: [← Ch 29 Investigation Reports](../sudarshan/29-investigation-reports.md) · Next: Ch 31 Future Research (Block F) →*

---

## ✅ Block E complete

Chapters 22–30 specify SUDARSHAN: principles derived from Blocks A–D, a tiered pipeline gated by
cost, safe intake, a recursive investigation graph with an immutable evidence ledger, typed and
expiring indicators, two-axis deterministic scoring with a confidence ceiling, campaign correlation
with honest attribution limits, multi-audience reporting, and the intelligence database that makes
verdicts revisable.

**Block F (Chapters 31–37)** closes the knowledge base: research gaps, the full misconception
catalogue, cheat sheets, judge and interview preparation, glossary, and consolidated references.
