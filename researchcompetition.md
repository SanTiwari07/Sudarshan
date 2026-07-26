# Sudarshan — Global Research & Competitive Intelligence

**Baseline:** `82fc55b` · **Date:** 2026-07-27 · **Supersedes** the `74535e2` edition.

---

## Scope Statement — read before using this document

The brief asks for a sweep of ~50 named sources. **That was not achievable and I did not fake it.**
What this contains:

- **Targeted literature searches**, cited with live URLs.
- **Direct comparison against tools I can characterise from the codebase itself** (MobSF,
  Androguard, APKTool, JADX, Frida — all dependencies of this project, so their roles are
  established by evidence).
- **New this edition: measured detection results** on a 17-sample labelled corpus, which converts
  several previously speculative claims into measured ones.
- **Explicit confidence labels on every claim.**

What it does **not** contain: community-discussion synthesis (Reddit/Discord/HN), per-project
screenshots, verified accuracy benchmarks for named commercial products, or patent prior-art
searches. Those were requested; they are marked **[NOT PERFORMED]** rather than invented.

**Confidence key:** 🟢 verified from primary source or this codebase · 🟡 cited secondary source ·
🔴 inference, treat as hypothesis.

---

## 1. What Sudarshan Actually Is — updated

| Dimension | Implementation | Evidence |
|---|---|---|
| Code organisation | One shared package (`sudarshan_core`) consumed by gateway + engine; layering CI-enforced | 🟢 `00_Project_Map §3` |
| Static analysis | Androguard primary; APKTool 2.10.0 + JADX 1.5.1 enrichment; MobSF optional | 🟢 |
| **Concealment detection** | **NEW** — nested APK/DEX or max-entropy blob disproportionate to `classes.dex` | 🟢 `apk_analyzer.py` |
| **Accessibility detection** | **FIXED** — reads `<service>` guard permission + intent-filter + raw manifest, not `<uses-permission>` | 🟢 |
| Dynamic analysis | Frida 17.16.4 on a real AVD over ADB TCP; monkey + AI-driven UI exploration; **SELinux preflight** | 🟢 `frida_sandbox.py` |
| Network capture | mitmproxy sidecar → HAR → ingest | 🟢 |
| Scoring | 5-axis STEI, BFCI, FRS — **now with axis exclusion, renormalisation, and a visibility floor** | 🟢 `risk_engine.py` |
| Threat intel | VirusTotal, OTX, AbuseIPDB with 24 h SQLite cache | 🟢 |
| AI layer | RAG-grounded LLM (Ollama/Gemini); agentic planner/perception/tool-executor loop | 🟢 |
| Prompt-injection defence | Single-choke-point sanitizer, 179 lines of adversarial tests | 🟢 |
| Output | STIX 2.1, IOC CSV, MITRE ATT&CK mapping, fraud-workflow reconstruction | 🟢 |
| Domain specialisation | Indian banking — `targets_indian_banks`, CERT-In in the RAG corpus | 🟢 |

**One-line positioning:** a hybrid static+dynamic Android analyser with an *explicit, auditable*
fraud-risk formula that refuses to over-claim, an agentic LLM investigation layer, and Indian-banking
grounding.

---

## 2. Landscape

### 2.1 The open-source baseline — MobSF

MobSF is the reference open-source mobile analysis framework: automated static + dynamic analysis
for Android/iOS/Windows, partly built on Androguard, with REST APIs and CI/CD integration
(🟡 — [MobSF GitHub](https://github.com/MobSF/Mobile-Security-Framework-MobSF),
[docs](https://mobsf.github.io/docs/)).

**Sudarshan's relationship is "optional upstream", not "competitor"** — `services/mobsf_client.py`
calls MobSF when `MOBSF_HOST` is set and falls back to Androguard otherwise (🟢). This should be
stated openly rather than positioned against.

| Dimension | MobSF | Sudarshan |
|---|---|---|
| Static breadth | Broad, mature, multi-platform | Narrower; Android-only |
| Dynamic | Instrumented testing, runtime + network (🟡) | Frida + AI exploration + mitmproxy |
| Risk output | Security findings + AppSec score | **Fraud-specific weighted formula with explicit provenance** |
| LLM layer | Not core | **Agentic investigation loop** |
| Domain tuning | Generic | **Indian banking** |
| Maturity | Years of production use | Prototype |

### 2.2 Academic — LLMs for malware analysis

Active 2024-2026 area — validates the direction while narrowing the novelty window (🟡):

- **MalParse / semantic categorisation** — hierarchical summarisation with GPT-4o-mini, reported
  77% benign-vs-malicious accuracy ([arXiv:2501.04848](https://arxiv.org/abs/2501.04848)).
  *Their figure, not verified here.*
- **Beyond Classification** — argues the field should move past binary labels toward fine-grained
  **behaviour auditing** ([arXiv:2509.14335](https://arxiv.org/pdf/2509.14335)). **This is
  Sudarshan's fraud-workflow thesis** — strong external validation.
- **AppPoet** — multi-view prompt engineering ([ResearchGate](https://www.researchgate.net/publication/385148039)).
- **LLM for Software Security survey** — names *dataset bias, evolving threats, and lack of
  explainability* as the open problems ([arXiv:2504.07137](https://arxiv.org/pdf/2504.07137)).

### 2.3 Academic — datasets and drift

- **Drebin** — canonical explainable-detection feature set (🟡 [paper](https://www.researchgate.net/publication/264785935)).
  Sudarshan's static flags occupy the same space (🔴 inference).
- **AndroZoo** — millions of APKs since 2010 (🟡).
- **LAMDA (2025)** — >1M APKs, 1,380 families, 2013-2025, Drebin-derived features, built for
  **concept drift** with SHAP-based explanation drift
  ([LAMDA](https://iqsec-lab.github.io/LAMDA/), [repo](https://github.com/IQSeC-Lab/LAMDA)).

**Still the most actionable finding in this document** — a free, purpose-built instrument for the
validation Sudarshan has now begun at small scale (§3).

### 2.4 Industry — evasion is the decisive constraint

Accessibility-service abuse and overlay attacks remain the defining Android banking-trojan
techniques (🟡 — [Cyble/OverlayPhantom](https://cyble.com/blog/overlayphantom-android-banking-trojan/),
[CYFIRMA/BankBot-YNRK](https://www.cyfirma.com/research/investigation-report-android-bankbot-ynrk-mobile-banking-trojan/),
[8kSec/Xenomorph](https://8ksec.io/mobile-malware-analysis-part-6-xenomorph/)).

**This validates the BFCI weighting** — accessibility 0.35 and overlay 0.20 are the two highest
weights, matching the two techniques industry independently identifies as primary. The *ordering*
is well-founded; the *magnitudes* remain uncalibrated.

**And it is now the measured bottleneck.** The literature on sandbox evasion is directly on point:
Android sandboxes built on emulators or hooking frameworks carry fingerprints usable for evasion,
and **HOOK-FRIDA-FILE detection is more widespread in packed samples than non-packed ones**
(🟡 — [Ruggia et al., AsiaCCS'24, "Unmasking the Veiled: A Comprehensive Analysis of Android Evasive
Malware"](https://s3.eurecom.fr/docs/asiaccs24_ruggia.pdf);
[ACM](https://dl.acm.org/doi/pdf/10.1145/3634737.3637658)). Frida can be detected via ptrace,
pthread injection, spawn and attach signatures (🟡 —
[Appdome anti-Frida](https://www.appdome.com/mobile-malware-prevention/anti-frida-dbi-detection/),
[HackTricks](https://hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/android-anti-instrumentation-and-ssl-pinning-bypass.html)).
Research-grade responses exist — e.g. Phantom-Frida renames SELinux labels such as `frida_file` to
defeat hook detectors (🟡).

Sudarshan uses **stock frida-server 17.16.4 on a standard AVD** — among the most detectable
configurations possible (🟢). That prediction from the previous edition was borne out: see §3.

---

## 3. Measured Results — new this edition

Corpus: 8 real banking trojans, 4 legitimate apps, 4 OWASP crackmes, 1 vulnerable app
(`audit/DETECTION_VALIDATION.md`). All figures 🟢 measured.

**Before:** every sample scored "Safe"; **Anubis scored *below* Amaze File Manager**.

**After** fixing five defects (dead accessibility check; unavailable axes scored as benign; no
dropper detection; permissions never reaching the PR axis; an empty sandbox run diluting static
evidence):

```
malware flagged      : 8/8   (missed 0)
non-malware flagged  : 0/9   false positives
precision 1.00   recall 1.00
malware FRS 14.0–50.9   benign FRS 9.2–25.9
```

**This partially closes G1** — the previous edition's largest gap ("weights asserted; no labelled
corpus, no precision/recall anywhere in the repo"). 17 samples is a demonstration, not evidence at
scale; the honest next step is LAMDA.

**Dynamic analysis remains the weak half, and the literature explains why.** After fixing the
SELinux blocker (Enforcing denies the ptrace Frida needs, so every attach failed —
`PermissionDeniedError`), instrumentation went **0/8 → 5/8**. But across all eight samples the
accessibility, SMS, overlay and network BFCI components are **0.0**. Two causes, both measured:

1. **The sandbox never enables the accessibility service.** `permission_orchestrator.py:86` writes
   a hardcoded `.AccessibilityService` class; Cerberus's real one is `.zWPzgfI`. Android silently
   ignores a non-existent component. 🟢
2. **Packed droppers have no launchable entry point.** Cerberus and Drinik declare no launcher
   activity and their main activity class lives in the packed payload. 🟢 — consistent with the
   AsiaCCS'24 finding that evasion concentrates in packed samples.

---

## 4. Gap Analysis — updated

| # | Gap | Status | Impact | Effort |
|---|---|---|---|---|
| **G1** | No empirical validation | **PARTIAL** — 17 samples, P/R 1.00; needs LAMDA | Critical | Medium |
| **G2** | Anti-evasion | **OPEN, now quantified** — 5/8 instrument, 0/8 show fraud behaviour | **Critical** | High |
| **G2a** | Accessibility never enabled | **OPEN** — hardcoded class name; ~3 h fix | **Critical** | Low |
| **G2b** | Packed droppers unlaunchable | **OPEN** — needs receiver/service triggering | High | Medium |
| G3 | Concept drift | OPEN — no temporal evaluation | High | Medium |
| G4 | Scale corpus | OPEN — `batch_runner.py` exists; corpus is 17 | High | Medium |
| G5 | YARA depth | OPEN — `yara-python` absent from the engine image | Medium | Low |
| G6 | Multi-platform | OPEN — Android only | Medium | High |
| G7 | Family attribution | OPEN — returned "Unknown" for all 8 trojans | Medium | Medium |
| G8 | Production hardening | **IMPROVED** — 3 CRITICALs closed; root containers remain | Blocker | Low–Med |

**G2a is the single highest-leverage item in the project.** It is a ~3-hour fix that unblocks the
0.35-weighted BFCI component, which is the difference between a static analyser and a genuine
behavioural sandbox.

---

## 5. Where Sudarshan Is Genuinely Differentiated

1. **Explicit, auditable scoring that refuses to over-claim.** Axes without evidence are *excluded
   and named* (`axes_excluded`), not scored as benign; a concealed payload cannot be certified
   "Safe"; `analysis_completeness` distinguishes "nothing found" from "never computed". The
   literature names *lack of explainability* as an open problem (🟡 arXiv:2504.07137); this is a
   structurally sound answer, and for regulated banking forensics it is a feature rather than a
   limitation. 🟢
2. **Fraud *workflow* reconstruction, not classification** — aligns with the "Beyond
   Classification" direction (🟡 arXiv:2509.14335).
3. **Serious prompt-injection engineering.** `sanitizer.py` treats the analysed app as an adversary
   against the analysis system. **I found no comparable published treatment in a malware-analysis
   context** in the searches performed — 🔴 absence-of-evidence, not evidence-of-absence. If it
   survives a proper literature review, it is the most publishable thing here.
4. **Indian banking domain grounding** — a real moat for BOI-type deployments.
5. **Determinism testing** with a committed baseline, treated as a deliberate reviewed act to
   regenerate. Rare in comparable open-source tools. 🔴

---

## 6. Innovation & Research Opportunities

| # | Opportunity | Why credible here | Confidence |
|---|---|---|---|
| **I1** | **Adversarial robustness of LLM-driven malware analysis** — formalise the threat model where the *analysed app attacks the analyser* | `sanitizer.py` + `test_prompt_injection.py` are a working implementation and harness; ~70% written in code | 🟡 strong |
| **I2** | **Calibrating explicit fraud weights against LAMDA** — publish P/R over temporal splits | Closes G1 and G3; LAMDA is free and purpose-built; the 17-sample harness already exists | 🟢 feasible |
| **I3** | **Evidence-completeness as a first-class output** — `axes_excluded` + visibility floor + `analysis_completeness` as a reporting standard for forensic tools | Implemented and measured; I found no comparable treatment in the tools surveyed | 🔴 |
| **I4** | Agentic exploration vs monkey coverage — measure behavioural coverage of the LLM planner against random fuzzing | `benchmark.py`, `test_goal_progression.py` and both explorer modes exist | 🟡 |
| **I5** | Regional fraud-pattern corpus (Indian banking) as a published dataset | Grounding exists; corpus does not | 🔴 |

**Patent opportunities: [NOT PERFORMED].** No prior-art search was conducted. Nothing here should
be read as a novelty assertion for patent purposes.

---

## 7. Adversarial Review

**A SOC analyst — "what's my false-positive rate?"** → **Now answerable at small scale:** 0/9 on the
labelled corpus. Caveat it honestly as 17 samples.

**A malware researcher — "Cerberus detects Frida and does nothing. What do you show me?"** →
Measured: `EVENTS_CAPTURED`, BFCI 5.0, accessibility 0.0. And critically, the engine now **excludes**
that inconclusive run rather than letting it dilute the static verdict — a run that observed nothing
no longer makes malware look safer. That is a better answer than the previous edition could give,
but G2 remains the honest weak point.

**A Google security engineer — "why not MobSF plus a script?"** → The scoring model, workflow
reconstruction, and evidence-provenance output. Not static breadth. Lead with the former.

**A DARPA reviewer — "what is the novel contribution?"** → I1. The scoring formula is engineering
until calibrated (I2).

**A VC — "what stops adoption?"** → Previously three CRITICAL security findings; those are closed
and verified. Now: containers run malware as root, CI is gitignored so no clone is protected, and
the dynamic sandbox does not yet observe fraud behaviour. All are days of work, not months.

**A BOI judge — "does it work?"** → Static: demonstrably, 8/8 with zero false positives on a
labelled corpus. Dynamic: instrumentation works on 5/8 samples but observes no fraud behaviour yet.
Say both.

---

## 8. Where This Project Ranks

**Today:** a well-engineered prototype with two areas of genuinely excellent design
(prompt-injection defence; explicit, provenance-carrying scoring), **now with small-scale empirical
validation** — which most comparable hobby/hackathon projects never produce. It is not competitive
with MobSF on static breadth and should not try. Confidence 🟢 (direct measurement).

**After closing G2a + publishing CI + hardening containers (~1 week):** a credible internal SOC tool
whose dynamic half actually functions. Confidence 🟡.

**After G1-at-scale (LAMDA) + G2 (anti-evasion):** genuinely differentiated, and I1/I2 become
publishable. Confidence 🔴 — depends on results that do not exist yet.

**Highest-value next action:** not a feature — the ~3-hour accessibility-class fix (G2a). It
unblocks the highest-weighted behavioural signal in the entire scoring model.

---

## Sources

- [MobSF — GitHub](https://github.com/MobSF/Mobile-Security-Framework-MobSF) · [docs](https://mobsf.github.io/docs/)
- [Exploring LLMs for Semantic Analysis and Categorization of Android Malware — arXiv:2501.04848](https://arxiv.org/abs/2501.04848)
- [Beyond Classification: Evaluating LLMs for Fine-Grained Automatic Malware Behavior Auditing — arXiv:2509.14335](https://arxiv.org/pdf/2509.14335)
- [LLM for Software Security: Code Analysis, Malware Analysis, Reverse Engineering — arXiv:2504.07137](https://arxiv.org/pdf/2504.07137)
- [AppPoet: LLM-based Android malware detection via multi-view prompt engineering](https://www.researchgate.net/publication/385148039_AppPoet_Large_language_model_based_android_malware_detection_via_multi-view_prompt_engineering)
- [LAMDA: A Longitudinal Android Malware Benchmark for Concept Drift](https://iqsec-lab.github.io/LAMDA/) · [repo](https://github.com/IQSeC-Lab/LAMDA)
- [DREBIN: Effective and Explainable Detection of Android Malware in Your Pocket](https://www.researchgate.net/publication/264785935_DREBIN_Effective_and_Explainable_Detection_of_Android_Malware_in_Your_Pocket)
- [Unmasking the Veiled: A Comprehensive Analysis of Android Evasive Malware (AsiaCCS'24)](https://s3.eurecom.fr/docs/asiaccs24_ruggia.pdf) · [ACM](https://dl.acm.org/doi/pdf/10.1145/3634737.3637658)
- [Evading Android Runtime Analysis via Sandbox Detection (ASIACCS'14)](https://dl.acm.org/doi/10.1145/2590296.2590325)
- [Appdome — anti-Frida DBI detection](https://www.appdome.com/mobile-malware-prevention/anti-frida-dbi-detection/)
- [HackTricks — Android anti-instrumentation and SSL pinning bypass](https://hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/android-anti-instrumentation-and-ssl-pinning-bypass.html)
- [Cyble — OverlayPhantom Android banking trojan](https://cyble.com/blog/overlayphantom-android-banking-trojan/)
- [CYFIRMA — Android/BankBot-YNRK investigation report](https://www.cyfirma.com/research/investigation-report-android-bankbot-ynrk-mobile-banking-trojan/)
- [8kSec — Xenomorph trojan analysis](https://8ksec.io/mobile-malware-analysis-part-6-xenomorph/)
