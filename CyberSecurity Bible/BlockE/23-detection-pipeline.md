# 23 — Detection Pipeline

> **Chapter ID:** `CH23` · **Block:** E · **Status:** Stable
> **Tags:** `#pipeline` `#tiering` `#gating` `#sla` `#orchestration` `#throughput` `#partial-results`
> **Last Updated:** 2026-08-05 · **Version:** 1.0.0
> **Prerequisites:** [Ch 11](../static-analysis/11-static-analysis.md), [Ch 12](../dynamic-analysis/12-dynamic-analysis.md), [Ch 22](22-building-sudarshan.md)

---

## Table of Contents

1. [The economics that dictate the design](#1-the-economics-that-dictate-the-design)
2. [The tiers](#2-the-tiers)
3. [Gating](#3-gating)
4. [Priority lanes and SLAs](#4-priority-lanes-and-slas)
5. [Partial result streaming](#5-partial-result-streaming)
6. [Orchestration](#6-orchestration)
7. [Failure handling](#7-failure-handling)
8. [Capacity and throughput](#8-capacity-and-throughput)
9. [Observability](#9-observability)
10. [Limitations and edge cases](#10-limitations-and-edge-cases)
11. [Engineering tips](#11-engineering-tips)
12. [Judge Insights](#12-judge-insights)
13. [Interview Insights](#13-interview-insights)
14. [Cross-references](#14-cross-references)
15. [References](#15-references)

---

## 1. The economics that dictate the design

One fact drives everything: **analysis cost varies by four orders of magnitude.**

```
   T0 structural    ~10 ms      ┐
   T1 capability    ~50 ms      │  ~1,000× cheaper than T3
   T2 resources     ~500 ms     ┘
   T3 code          ~10–120 s
   T4 dynamic       ~5–15 min   ┐  ~10,000× more expensive than T1
   T5 human RE      hours       ┘
```

If every sample ran every tier, a 10,000-sample day would need roughly **2,000 device-hours** of
detonation. Nobody has that. So the pipeline's job is not to analyse — it is to **decide what
deserves analysis**.

```
        cheap tiers                       expensive tiers
   ┌──────────────────────┐         ┌──────────────────────┐
   │ run on 100%          │ ──gate─►│ run on the few %     │
   │ produce the triage   │         │ that earned it       │
   │ decision             │         │                      │
   └──────────────────────┘         └──────────────────────┘
```

> **⚙️ Engineering Note — the gating asymmetry.** A gate that wrongly *escalates* costs compute.
> A gate that wrongly *declines* to escalate produces a false negative on a sample nobody will
> look at again. **These costs are not symmetric**, so gates must be biased toward escalation and
> every gate decision must be recorded so it can be audited and tuned later
> ([P4, Ch 22 §2](22-building-sudarshan.md#2-the-nine-design-principles)).

---

## 2. The tiers

| Tier | Does | Cost (p95) | Coverage | Source |
|---|---|---|---|---|
| **T0 Structural** | ZIP/DEX/ELF integrity, Janus check, dup entries, checksums, signing schemes | 50 ms | 100% | [Ch 08 §10](../apk/08-apk-file-format.md#10-detection-logic-for-sudarshan) |
| **T1 Capability** | Manifest, permissions, **a11y config**, components, targetSdk, signer | 200 ms | 100% | [Ch 11 §4](../static-analysis/11-static-analysis.md#4-tier-1--manifest-and-capability-extraction) |
| **T2 Resources** | Locales, **target package list**, URLs, entropy scan of `assets/`, packer fingerprint | 1 s | 100% | [Ch 11 §5](../static-analysis/11-static-analysis.md#5-tier-2--resource-and-asset-mining) |
| **T3 Code** | Decompile, API chains, call graph, YARA-X, TLSH | 120 s | ~20% | [Ch 11 §6](../static-analysis/11-static-analysis.md#6-tier-3--code-analysis) |
| **T4 Dynamic** | Detonate, hook, dump, capture C2, pre/post diff | 15 min | ~5% | [Ch 12 §3](../dynamic-analysis/12-dynamic-analysis.md#3-detonation-methodology) |
| **T5 Human RE** | Novel logic, unpacking, DGA reversal | hours | <1% | [Ch 10](../reverse-engineering/10-reverse-engineering.md) |

### The enrichment tier that runs alongside

**TE — Intelligence enrichment** (~200 ms, 100%): signer lookup in the TI database, hash lookup,
known-infrastructure match. Runs concurrently with T0–T2 because it's I/O-bound and can
short-circuit everything.

```
        ┌─────────────────────────────────────────┐
        │  T0 ─► T1 ─► T2   (sequential, CPU)     │
        │   ╲                                     │
        │    ╲   TE  (parallel, I/O — TI lookups) │
        │     ╲   │                               │
        │      ▼  ▼                               │
        │      merged signal set → gate           │
        └─────────────────────────────────────────┘
```

> **⚙️ Engineering Note:** A known-malicious signer hit in TE can produce a **high-confidence
> verdict in under 300 ms** without any code analysis at all — because signer identity is durable
> ([Ch 06 §10](../security/06-certificates.md#10-certificates-as-a-correlation-pivot)). That's the
> fastest path in the whole system, and it's why TE runs in parallel rather than after static.

---

## 3. Gating

### The escalation rules

```yaml
# T2 → T3 (code analysis)
escalate_to_t3_when:
  any_of:
    # the ODF capability cluster  → Ch 04 §11, Ch 13
    - all_of:
        - capability.a11y_service_declared
        - any_of: [a11y.can_retrieve_window_content, a11y.can_perform_gestures]
        - at_least_2_of:
            [capability.overlay, capability.request_install, capability.sms,
             capability.notification_listener, capability.media_projection_fgs]
    # staging machinery
    - capability.request_install AND resources.high_entropy_assets
    - resources.packer_fingerprint != null
    # targeting
    - resources.referenced_packages ∩ client_bank_packages != ∅      # ★
    # structural
    - structural.dex_magic_at_offset_0            # Janus
    - structural.duplicate_zip_entries
    - structural.dex_checksum_mismatch
    # identity
    - signer NOT IN canonical_registry[claimed_package]              # ★ impersonation
    - signer IN ti.malicious_signers
    # similarity
    - tlsh_dex within 50 of a known-malicious sample
    # ★ inability to analyse is itself an escalation trigger
    - structural.packed AND NOT static.unpacked

# T3 → T4 (dynamic detonation)
escalate_to_t4_when:
  any_of:
    - code.api_chain_matched IN [crypto_to_classloader, sms_read_to_network,
                                 pkg_enum_to_overlay, a11y_to_gesture]
    - yara.hit WHERE severity >= high
    - static.verdict == inconclusive          # ★ must observe at runtime
    - static.packed AND NOT static.unpacked   # ★
    - t3.decompilation_failed                 # ★
    - priority == urgent                      # bypass gating on the fraud path

# T4 → T5 (human)
escalate_to_t5_when:
  any_of:
    - dynamic.unpack_failed AND static.packed
    - correlation.no_family_match AND score >= critical    # novel family candidate
    - infrastructure.dga_suspected AND NOT dga_generator_known
    - analyst_requested
```

### The three "inability" triggers

Note that **three separate gates escalate on failure to analyse**, not on positive findings:
packed-and-unopened, decompilation failure, and static-inconclusive. This is
[P4](22-building-sudarshan.md#2-the-nine-design-principles) made operational.

> **⚙️ Engineering Note:** The natural instinct is to route unanalysable samples to a "failed"
> queue that nobody reads. **Resist it.** Samples that resist analysis are disproportionately
> likely to be the ones that matter — that's the entire purpose of a packer. Route failure to
> *more* analysis, and if it still fails, route it to a human with the reason attached.

---

## 4. Priority lanes and SLAs

Two clocks ([Ch 20 §3](../incident-response/20-incident-response.md#3-the-response-clock)) mean
two lanes.

| Lane | Trigger | SLA to first result | SLA to final | Behaviour |
|---|---|---|---|---|
| **URGENT** | Active fraud, IR request, SOC escalation | **10 s** | **3 min** | Bypasses gating; dedicated device; partial streaming |
| **HIGH** | Client package targeted; known-bad signer | 30 s | 15 min | Priority queue |
| **NORMAL** | Routine submission | 2 min | 60 min | Standard gating |
| **BULK** | Feed ingestion, corpus backfill | — | 24 h | T0–T2 only unless gated up |

```
   URGENT ──────────────────────────► [dedicated device pool]
   HIGH   ────────────┐
   NORMAL ──────────┐ │             [shared device pool]
   BULK   ────────┐ │ │
                  ▼ ▼ ▼
              weighted fair queue with URGENT preemption
```

> **⚙️ Engineering Note:** Reserve a **dedicated detonation device** (or two) for the urgent lane
> that is never used for bulk work. Under load, a shared pool means an urgent sample queues
> behind a 15-minute bulk detonation — which is the exact failure the SLA exists to prevent.
> The cost of an idle device is trivial compared to a missed fraud window.

---

## 5. Partial result streaming

Waiting for completeness wastes the recovery window.

```
  T+0.00s   submitted
  T+0.30s   ★ TE: signer known-malicious?  → EMIT verdict (confidence 0.9)
  T+0.05s   T0 complete → structural anomalies
  T+0.25s   T1 complete → capability cluster
            ★ EMIT PARTIAL: "high-risk cluster; recommend session hold"
                            confidence 0.6, severity critical
  T+1.20s   T2 complete → target list, packer, locales
            ★ EMIT PARTIAL: "targets com.clientbank.app" ← escalation trigger
  T+45s     T3 complete → family candidate, YARA hits
            ★ EMIT PARTIAL: "consistent with Anatsa (code similarity)"
  T+9m      T4 complete → C2, dumped payload, observed overlay
            ★ EMIT FINAL: confidence 0.95, full IOC set, client impact
  T+9m+     recursion on dumped child artifacts → may raise the parent score
```

### The contract

```json
{
  "analysis_id": "AN-2026-0805-0042",
  "state": "partial",
  "sequence": 3,
  "verdict": "likely_malicious",
  "severity": "critical",
  "confidence": 0.60,
  "confidence_ceiling": 0.75,
  "ceiling_reason": "dynamic analysis pending",
  "actionable_now": ["recommend_session_hold"],
  "findings_so_far": [ ... ],
  "next_stage_eta_seconds": 480
}
```

> **⚙️ Engineering Note:** `confidence_ceiling` and `ceiling_reason` must appear on **every**
> partial. A consumer must be able to distinguish "0.6 because the evidence is weak" from "0.6
> because we haven't finished yet." Those imply different actions — the second warrants waiting
> or provisionally containing; the first warrants deprioritising.

---

## 6. Orchestration

### Why a durable workflow engine

Analyses are long-running (minutes to hours with recursion), must survive worker restarts, need
retries with backoff, and must be **auditable after the fact**. A durable workflow engine
(Temporal-class) gives all four; a bare queue plus cron does not.

```
  Workflow: analyze_artifact(artifact_id, priority)
    ├── activity: intake_normalise          (idempotent, retry×3)
    ├── parallel:
    │     ├── activity: tier0_structural    (sandboxed, timeout 5s)
    │     └── activity: ti_enrich            (retry×5, backoff)
    ├── activity: tier1_capability          (sandboxed, timeout 10s)
    ├── activity: tier2_resources           (sandboxed, timeout 30s)
    ├── emit_partial()
    ├── decision: gate_t3?
    │     └── activity: tier3_code          (sandboxed, timeout 300s)
    ├── emit_partial()
    ├── decision: gate_t4?
    │     └── activity: tier4_dynamic       (device lease, timeout 20m)
    ├── ★ for each child_artifact:
    │     └── child_workflow: analyze_artifact(child_id)   ← RECURSION (P6)
    ├── activity: score
    ├── activity: correlate
    └── activity: report
```

### Recursion safeguards

```yaml
recursion:
  max_depth: 3                  # dropper → payload → stage3 is realistic; deeper is a loop
  max_children_per_artifact: 20
  cycle_detection: by_sha256    # a child identical to an ancestor = stop
  child_priority: inherit_from_parent
  parent_score_updates_on_child_completion: true   # ★
```

> **⚙️ Engineering Note:** Without depth limits and cycle detection, a malformed or deliberately
> crafted sample can produce unbounded recursion — a self-referential DEX, or a payload that
> re-emits its parent. Cap depth at 3, detect cycles by hash, and **make the cap a recorded
> finding** rather than a silent truncation, because hitting it is itself unusual.

---

## 7. Failure handling

| Failure | Response | Score effect |
|---|---|---|
| Parser crash (T0–T2) | Fall back to tolerant parser; **record the divergence** | Anomaly signal ([Ch 08 §9](../apk/08-apk-file-format.md#9-format-level-anti-analysis)) |
| Decompilation failure (T3) | Escalate to T4 | Confidence ceiling applied |
| Unpacking failure | Escalate to T4, then T5 | **Ceiling ≤ 0.5; never "clean"** |
| Device unavailable (T4) | Queue with backoff; alert if sustained | Ceiling; requeue |
| **C2 unreachable** | Verdict `inconclusive`; **requeue 24h ×5** | **Ceiling 0.3** |
| Detonation timeout | Partial dynamic results retained | Ceiling |
| Sandbox escape attempt detected | **Halt, quarantine, alert** | Critical finding |
| TI enrichment unavailable | Proceed without; flag degraded | Minor ceiling |

> **⚙️ Engineering Note — every failure path must produce a *recorded* outcome, never silence.**
> The dangerous state is an analysis that quietly ends with no verdict and no ticket. Enumerate
> the failure modes, assign each an outcome, and monitor their rates — a rising unpack-failure
> rate is an early signal that a new packer has entered the ecosystem.

---

## 8. Capacity and throughput

### The bottleneck is always T4

```
  T0–T2:  CPU-bound, horizontally scalable, ~cents per 1,000 samples
  T3:     CPU + memory, scalable, minutes of CPU
  T4:     ★ DEVICE-BOUND — fixed pool, 15 min per sample
  T5:     ★ HUMAN-BOUND — the scarcest resource
```

### Sizing

```
  Given:
    S      = samples/day
    g4     = fraction escalated to T4        (target ~5%)
    t4     = minutes per detonation           (~15, incl. provisioning)
    u      = target device utilisation        (~0.6, leaves urgent headroom)

  devices = (S × g4 × t4) / (60 × 24 × u)

  Example: S=10,000, g4=0.05, t4=15, u=0.6
         = (10,000 × 0.05 × 15) / (1440 × 0.6)
         = 7,500 / 864 ≈ 9 devices  (+ 2 reserved for the urgent lane)
```

> **⚙️ Engineering Note:** `g4` is the lever with the most leverage in the entire system. Moving
> the T4 escalation rate from 5% to 10% doubles the hardware bill. **That is why T1's capability
> extraction quality matters so much** — better cheap gating directly reduces expensive
> detonation. Invest in the accessibility-config parser before buying devices.

---

## 9. Observability

| Metric | Why | Alert on |
|---|---|---|
| p50/p95/p99 latency per tier | SLA compliance | p95 > SLA |
| Escalation rate per gate | Cost control | g4 drift > ±50% |
| Device pool utilisation | Capacity | > 0.8 sustained |
| Urgent-lane queue depth | ★ Fraud-window risk | > 0 for > 30 s |
| Unpack failure rate | New packer detection | Week-over-week increase |
| C2-unreachable rate | Infrastructure health / evasion | Sudden change |
| Parser fallback rate | Anti-analysis prevalence | Increase |
| Verdict distribution | Drift / calibration | Shift |
| Recursion depth histogram | Staged-malware prevalence | — |
| Rule fire rate + FP rate | [Ch 19 §7](../soc/19-enterprise-soc-operations.md#7-detection-engineering) | FP > threshold |

> **⚙️ Engineering Note:** *Unpack failure rate* and *parser fallback rate* are the two
> underrated ones. Both are **leading indicators of adversary tooling change** — a week-over-week
> rise in unpack failures usually means a new commercial protector has entered circulation, as
> happened with Virbox in Klopatra (Cleafy, Aug 2025). Treat them as intelligence, not just ops
> metrics.

---

## 10. Limitations and edge cases

| Case | Handling |
|---|---|
| Very large APK (> 500 MB) | Stream; extended timeouts; size caps on extraction |
| XAPK/APKS/split sets | One logical analysis over the full set ([Ch 02 §7](../apk/02-apk-architecture.md#7-app-bundles-split-apks-and-why-the-apk-is-a-lie)) |
| Zip bomb | Total-decompressed and entry-count caps ([Ch 08 §3](../apk/08-apk-file-format.md#3-zip-anomalies-and-parser-differentials)) |
| Duplicate submission | Dedup by SHA-256; return cached verdict; **re-run if rules changed since** |
| Rules updated | Cached verdicts carry `ruleset_version`; stale ones flagged for retro-run |
| Sample with no DEX | Legal; analyse what exists |
| Non-Android file submitted | Reject at intake with a clear reason |

> **⚙️ Engineering Note — cache invalidation on ruleset change is easy to get wrong.** A verdict
> is only valid for the ruleset that produced it. Store `ruleset_version` and `tool_versions` on
> every verdict; when rules update, mark affected verdicts stale and feed them into the
> retro-hunt queue ([Ch 18 §6](../soc/18-mobile-threat-hunting.md#6-hunting-the-sample-corpus))
> rather than silently serving an outdated answer.

---

## 11. Engineering tips

1. **Bias gates toward escalation** and record every gate decision.
2. **Escalate on inability to analyse**, not only on positive findings.
3. **Run TI enrichment in parallel** — a signer hit can end the analysis in 300 ms.
4. **Reserve dedicated devices for the urgent lane.**
5. **Stream partials with `confidence_ceiling` and `ceiling_reason` on every one.**
6. **Use a durable workflow engine.** Retries, restarts, and audit come free.
7. **Cap recursion depth, detect cycles by hash, and record when the cap is hit.**
8. **Every failure path produces a recorded outcome.**
9. **Watch `g4` — it sets the hardware bill.**
10. **Treat unpack-failure and parser-fallback rates as intelligence.**
11. **Version verdicts with the ruleset and tool versions that produced them.**

---

## 12. Judge Insights

**What judges ask:** *"How does this scale? You can't detonate every APK."*

**Perfect answer:** No, and we don't try — the design assumption is that analysis cost varies by
four orders of magnitude, from about ten milliseconds for structural checks to fifteen minutes
for detonation. So the cheap tiers run on 100% of samples and their only job is to decide what
deserves the expensive ones. Structural checks, capability extraction, and resource mining run in
about a second and a half combined, and threat-intel enrichment runs in parallel — a known-bad
signer can produce a high-confidence verdict in under 300 milliseconds without any code analysis.
Roughly 20% reaches code analysis and about 5% reaches detonation, which for ten thousand samples
a day is around nine devices plus two reserved for the urgent lane. And critically the gates are
biased toward escalation, because a gate that wrongly declines produces a false negative nobody
revisits, whereas a gate that wrongly escalates just costs compute.

**Common mistakes:**
- Claiming full dynamic analysis on everything. It's arithmetically impossible and judges can do
  the multiplication.
- Not knowing the escalation rate. It's the number that sets your hardware cost.
- Treating unanalysable samples as a failure queue.

**Follow-ups to expect:**
- *"What happens when a sample can't be unpacked?"* → It escalates. Three separate gates trigger
  on inability to analyse rather than on findings, because the samples that resist analysis are
  disproportionately the ones that matter — that's what packers are for. If it still fails, a
  human gets it with the reason attached, and the verdict carries a confidence ceiling so we
  never report "clean" on something we couldn't read.
- *"How fast for an active fraud case?"* → There's a dedicated urgent lane with reserved devices
  that bypasses gating: first actionable result in ten seconds, final in three minutes. And we
  stream partial results, so a capability-cluster finding at 250 milliseconds can trigger a
  session hold rather than waiting nine minutes for the detonation.
- *"What's your biggest cost lever?"* → The T4 escalation rate. Moving it from 5% to 10% doubles
  the device fleet, which is why we invest in better cheap-tier gating — specifically the
  accessibility config parser — before buying hardware.

**Fact that impresses:** Rising unpack-failure and parser-fallback rates are leading indicators
of adversary tooling change, not just ops noise. A week-over-week rise in unpack failures usually
means a new commercial protector has entered circulation — which is exactly what Virbox adoption
in Klopatra looked like in August 2025. We alert on those metrics as intelligence.

---

## 13. Interview Insights

**Q: "Design a scalable malware analysis pipeline."**
Lead with the cost gradient, then tiering with gating, then the numbers: coverage per tier and
the device-count formula. Then the two subtleties that show depth — gates biased toward
escalation because the error costs are asymmetric, and escalation on *inability to analyse*.

**Q: "What's your bottleneck?"**
Dynamic analysis, because it's device-bound and roughly 15 minutes per sample. Then human RE,
which is the scarcest resource. Everything cheap is horizontally scalable.

**Q: "Why stream partial results?"**
Because containment and investigation run on different clocks. A capability-cluster finding
available in 250 ms is enough for a medium-confidence session hold, and waiting nine minutes for
full certainty wastes the fund-recovery window.

**Q: "How do you handle a sample that times out?"**
Retain partial results, apply a confidence ceiling with the reason recorded, requeue where
appropriate, and never emit a clean verdict. Every failure path produces a recorded outcome —
silence is the dangerous state.

**Q: "Why a workflow engine rather than a queue?"**
Long-running analyses with recursion, survival across worker restarts, typed retries with
backoff, and an auditable execution history. A queue plus cron gives you none of the last one,
and audit is a regulatory requirement here.

**Beginner mistakes:**
- Running everything on everything.
- Symmetric gate tuning.
- Unbounded recursion.
- Caching verdicts without a ruleset version.
- Sharing the detonation pool between bulk and urgent work.

---

## 14. Cross-references

**Upstream:** [Ch 11](../static-analysis/11-static-analysis.md) (tiers) ·
[Ch 12](../dynamic-analysis/12-dynamic-analysis.md) (detonation) ·
[Ch 20 §3](../incident-response/20-incident-response.md#3-the-response-clock) (clocks) ·
[Ch 22](22-building-sudarshan.md) (principles)

**Downstream:** [Ch 24](24-threat-intake.md) · [Ch 25](25-investigation-engine.md) ·
[Ch 27](27-risk-scoring.md) · [Ch 29](29-investigation-reports.md)

---

## 15. References

1. OWASP MASTG — static and dynamic analysis workflow. https://mas.owasp.org/MASTG/
2. MobSF — pipeline architecture reference. https://mobsf.github.io/docs/
3. Temporal / durable workflow execution documentation.
4. Cleafy Labs — *Klopatra* (August 2025) — Virbox adoption as a tooling-shift example.
5. NIST SP 800-163 Rev. 1 — *Vetting the Security of Mobile Applications*.

---

*Previous: [← Ch 22 Building SUDARSHAN](22-building-sudarshan.md) · Next: [Ch 24 Threat Intake →](24-threat-intake.md)*
