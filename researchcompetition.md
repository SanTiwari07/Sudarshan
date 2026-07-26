# Sudarshan — Global Research & Competitive Intelligence

**Date:** 2026-07-26 · **Baseline:** commit `74535e2`

---

## Scope Statement — read before using this document

The brief asked for a sweep of ~50 named sources (Scholar, IEEE, ACM, USENIX, BlackHat, DEF CON,
Reddit, Discord, HN, vendor blogs, …). **That was not achievable and I did not fake it.** What this
document contains:

- **4 targeted literature/landscape searches**, cited below with live URLs.
- **Direct comparison against tools I can characterise from the codebase itself** (MobSF,
  Androguard, APKTool, JADX, Frida — all are dependencies of this project, so their roles are
  established by evidence, not recollection).
- **Explicit confidence labels on every claim.**

What this document does **not** contain: community-discussion synthesis (Reddit/Discord/HN),
per-project screenshots, verified accuracy benchmarks for named commercial products, or patent
searches. Those were requested; I could not perform them to a standard that would survive scrutiny,
so they are marked **[NOT PERFORMED]** rather than invented. Any number in this document that I did
not personally verify is labelled.

**Confidence key:** 🟢 verified from primary source or this codebase · 🟡 from a cited secondary
source · 🔴 inference, treat as hypothesis.

---

## 1. What Sudarshan Actually Is

Established from the codebase, not from marketing text (🟢):

| Dimension | Implementation | Evidence |
|---|---|---|
| Static analysis | Androguard primary; APKTool 2.10.0 + JADX 1.5.1 enrichment; MobSF optional | `analysis-engine/Dockerfile`, `main.py:116-145` |
| Dynamic analysis | Frida 17.16.4 on a real AVD over ADB TCP; monkey + AI-driven UI exploration | `frida_sandbox.py`, `agentic_explorer.py` |
| Network capture | mitmproxy sidecar → HAR → ingest | `docker-compose.yml:85-97`, `network_capture.py` |
| Scoring | **Explicit weighted formulas**: 5-axis STEI (CT .60/BT .20/PR .10/OB .05/IR .05); BFCI (accessibility .35/SMS .25/overlay .20/banking .10/network .05/persistence .05); FRS = .25 STEI + .35 BFCI + .20 correlation + .20 banking-impact | `risk_engine.py`, `bfci_scorer.py`, live `/` response |
| Threat intel | VirusTotal, OTX, AbuseIPDB with 24h SQLite cache | `threat_correlator.py`, `database.py:58-70` |
| AI layer | RAG-grounded LLM (Ollama local or Gemini); **agentic** planner/perception/tool-executor loop driving the device | `ai/`, `rag/`, `engines/agentic/` |
| Prompt-injection defence | Dedicated sanitizer as a single choke point, 179 lines of adversarial tests | `sanitizer.py`, `test_prompt_injection.py` |
| Output | STIX 2.1, IOC CSV, MITRE ATT&CK mapping, fraud-workflow reconstruction | `report.py`, `mitre_mapper.py`, `workflow_reconstructor.py` |
| Domain specialisation | **Indian banking fraud** — `targets_indian_banks` flag, CERT-In guidance in the RAG corpus | `apk_analyzer.py`, `knowledge_base.py` |

**The one-line positioning:** a hybrid static+dynamic Android analyser with an *explicit, auditable*
fraud-risk formula, an agentic LLM investigation layer, and Indian-banking domain grounding.

---

## 2. Landscape

### 2.1 The open-source baseline — MobSF

MobSF is the reference open-source mobile analysis framework: automated static + dynamic analysis
for Android/iOS/Windows, built partly on Androguard, with REST APIs and CI/CD integration
(🟡 — [MobSF GitHub](https://github.com/MobSF/Mobile-Security-Framework-MobSF),
[MobSF docs](https://mobsf.github.io/docs/)).

**Sudarshan's relationship to MobSF is not "competitor" — it is "optional upstream."**
`services/mobsf_client.py` calls MobSF when `MOBSF_HOST` is set and falls back to Androguard
otherwise (🟢). This is a genuinely sensible architectural choice and should be stated openly rather
than positioned against MobSF.

| Dimension | MobSF | Sudarshan |
|---|---|---|
| Static breadth | Broad, mature, multi-platform | Narrower; Android-only |
| Dynamic | Instrumented testing, runtime + network analysis (🟡) | Frida + AI-driven exploration + mitmproxy |
| Risk output | Security findings + AppSec score | **Fraud-specific weighted formula (STEI/BFCI/FRS)** |
| LLM layer | Not core | **Agentic investigation loop** |
| Domain tuning | Generic | **Indian banking** |
| Maturity | Years of production use, large community | Prototype (this audit) |

**Honest read:** Sudarshan does not beat MobSF at static analysis and should not try. Its
differentiation is downstream — scoring, fraud-workflow reconstruction, and investigation.

### 2.2 Academic — LLMs for malware analysis

This is an active 2024-2026 area, which both validates the direction and means the novelty window
is narrowing (🟡):

- **MalParse / semantic categorisation** — hierarchical-tiered summarisation with GPT-4o-mini,
  reported **77% categorisation accuracy** benign-vs-malicious
  ([arXiv:2501.04848](https://arxiv.org/abs/2501.04848)). *That figure is the paper's, not verified
  by me.*
- **Beyond Classification** — argues the field should move past binary labels toward fine-grained
  **behaviour auditing** ([arXiv:2509.14335](https://arxiv.org/pdf/2509.14335)). **This is precisely
  Sudarshan's fraud-workflow-reconstruction thesis** — strong external validation of the direction.
- **AppPoet** — multi-view prompt engineering for LLM-based Android detection
  ([ResearchGate](https://www.researchgate.net/publication/385148039)).
- **LLM for Software Security survey** — notes a context-driven framework addressing *dataset bias,
  evolving threats, and lack of explainability* ([arXiv:2504.07137](https://arxiv.org/pdf/2504.07137)).

### 2.3 Academic — datasets and the drift problem

- **Drebin** — the canonical explainable-detection feature set: manifest features (hardware,
  permissions, components, intents) plus disassembled-code features (restricted/suspicious API calls,
  network addresses) (🟡 — [Drebin paper](https://www.researchgate.net/publication/264785935)).
  **Sudarshan's static flags occupy the same feature space** (🔴 inference from
  `apk_analyzer.py` flag names).
- **AndroZoo** — millions of APKs since 2010; the standard sourcing corpus (🟡).
- **LAMDA (2025)** — >1M APKs, 1,380 families, 2013-2025, Drebin-derived features, built for
  **concept-drift** study with SHAP-based explanation drift
  ([LAMDA](https://iqsec-lab.github.io/LAMDA/), [repo](https://github.com/IQSeC-Lab/LAMDA)).

**This is the most actionable finding in this document.** LAMDA is a ready-made, free instrument for
the exact validation Sudarshan currently lacks (§3, Gap-1).

### 2.4 Industry — the threat Sudarshan targets is real and current

Accessibility-service abuse and overlay attacks are the defining Android banking-trojan techniques,
confirmed by multiple 2025-2026 vendor reports on OverlayPhantom and BankBot-YNRK
(🟡 — [Cyble](https://cyble.com/blog/overlayphantom-android-banking-trojan/),
[CYFIRMA](https://www.cyfirma.com/research/investigation-report-android-bankbot-ynrk-mobile-banking-trojan/),
[8kSec / Xenomorph](https://8ksec.io/mobile-malware-analysis-part-6-xenomorph/)).

**This directly validates the BFCI weighting.** Sudarshan assigns accessibility 0.35 and overlay
0.20 — the two highest weights — to the two techniques the industry independently identifies as
primary. The *ordering* of the weights is well-founded. Their *magnitudes* remain uncalibrated (§3).

**Counter-signal:** the same sources note malware increasingly **detects analysis environments** and
suppresses behaviour — checking for ADB, Magisk, and Frida specifically (🟡, Appdome). Sudarshan
uses **stock Frida 17.16.4 with a default frida-server on a standard AVD**, which is among the most
detectable configurations possible (🟢 from `requirements.txt`, `entrypoint.sh`). There is an
`anti_analysis_detector.py` (53 lines) but it *detects* evasion rather than *defeating* it (🔴 —
not deep-reviewed). **This is the biggest technical threat to the dynamic-analysis value
proposition.**

---

## 3. Gap Analysis

| # | Gap | Their approach | Sudarshan today | Impact | Effort |
|---|---|---|---|---|---|
| **G1** | **No empirical validation** | Drebin/LAMDA/AndroZoo benchmarking with published metrics | Weights asserted; **no labelled corpus, no precision/recall anywhere in the repo** (🟢 grepped) | **Critical** | Medium |
| **G2** | Anti-evasion | Hardened/stealth instrumentation | Stock Frida, default frida-server, standard AVD | **Critical** | High |
| **G3** | Concept drift | LAMDA temporal splits, drift-aware retraining | No temporal evaluation; static weights | High | Medium |
| **G4** | Scale corpus | AndroZoo millions | `batch_runner.py` (65L) + one committed sample | High | Medium |
| **G5** | YARA/signature depth | Curated rule corpora | `yara_scanner.py` (106L); **`yara-python` missing from engine deps** (🟢) | Medium | Low |
| **G6** | Multi-platform | MobSF: Android/iOS/Windows | Android only | Medium | High |
| **G7** | Family attribution | Clustering, YARA families | `classification_engine.py`; returned `"Unknown"` in the live run (🟢) | Medium | Medium |
| **G8** | Production hardening | Mature auth/RBAC/multi-tenancy | See `06_Security_Audit.md` — 3 CRITICAL | **Blocker for adoption** | Low–Medium |

---

## 4. Where Sudarshan Is Genuinely Differentiated

Claims I can defend from the codebase (🟢) plus the literature (🟡):

1. **Explicit, auditable scoring.** STEI/BFCI/FRS are inspectable weighted formulas, not a model
   output. Most ML detectors give a probability with no defensible chain. For **regulated banking
   forensics — where a decision may need to be justified to an auditor or a court — this is a
   feature, not a limitation.** The literature's stated concern is precisely "lack of
   explainability" (🟡 arXiv:2504.07137). Sudarshan's answer is structurally sound.
2. **Fraud *workflow* reconstruction, not classification.** `workflow_reconstructor.py` produces an
   ordered, timestamped, evidence-linked attack chain. This aligns exactly with the "Beyond
   Classification / behaviour auditing" research direction (🟡 arXiv:2509.14335) — Sudarshan is
   on the right side of where the field is moving.
3. **Serious prompt-injection engineering.** `sanitizer.py` treats the analysed app as an adversary
   *against the analysis system itself* — fence-neutralisation, bidi stripping, NFKC, bounded
   output, total-function contract, 179 lines of adversarial tests. **I found no comparable
   published treatment of prompt injection in a malware-analysis context** in the searches
   performed (🔴 absence-of-evidence, not evidence-of-absence — the searches were limited).
   *If that holds under a proper literature review, it is the most publishable thing here.*
4. **Indian banking domain grounding.** CERT-In guidance in the RAG corpus, Indian bank package
   detection. Global tools are generic; regional fraud specificity is a real moat for BOI-type
   deployments.
5. **Determinism testing.** `test_determinism_replay.py` + a committed `determinism_baseline.json`.
   Reproducibility is an evidentiary requirement in forensics and is rarely tested in comparable
   open-source tools (🔴).

---

## 5. Innovation & Research Opportunities

Ranked by (defensibility × feasibility given the current codebase):

| # | Opportunity | Why it is credible here | Confidence |
|---|---|---|---|
| **I1** | **Adversarial robustness of LLM-driven malware analysis** — formalise the threat model where the *analysed app attacks the analyser* via UI labels, notifications, logcat | `sanitizer.py` + `test_prompt_injection.py` are already a working implementation and a test harness. This is a paper that is 70% written in code already. | 🟡 strong |
| **I2** | **Calibrating explicit fraud weights against LAMDA** — publish precision/recall for STEI/BFCI/FRS over temporal splits | Closes G1 and G3 simultaneously; LAMDA is free and purpose-built | 🟢 feasible |
| **I3** | **Agentic exploration vs monkey coverage** — measure behavioural coverage of the LLM planner against random fuzzing | `benchmark.py`, `test_goal_progression.py`, and both explorer modes already exist | 🟡 |
| **I4** | **Evidence-linked workflow reconstruction as a forensic artefact** — stage→hook→timestamp provenance chain | `workflow_reconstructor.py` + `evidence_store.py` + `audit_log.py` | 🟡 |
| **I5** | Regional fraud-pattern corpus (Indian banking) as a published dataset | Domain grounding exists; corpus does not | 🔴 |

**Patent opportunities: [NOT PERFORMED].** No prior-art search was conducted. Nothing in this
document should be read as a novelty assertion for patent purposes.

---

## 6. Adversarial Review — the questions that will be asked

**A SOC analyst:** *"What's my false-positive rate?"* → **Unanswerable today.** G1. This is the
first question any evaluator asks and the project has no answer.

**A malware researcher:** *"Xenomorph detects Frida and does nothing. What do you show me?"* →
An `INSTRUMENTATION_FAILED` dynamic result and a static-only score (🟢 — this is exactly what the
live run produced with no emulator). G2 is the honest weak point.

**A Google security engineer:** *"Why not MobSF plus a script?"* → Defensible answer: the fraud
scoring model, workflow reconstruction, and agentic investigation. Not defensible: static-analysis
breadth. Lead with the former.

**A DARPA reviewer:** *"What is the novel contribution?"* → I1 (adversarial robustness of LLM
malware analysis) is the strongest. The scoring formula is engineering, not research, until it is
calibrated (I2).

**A VC:** *"What stops adoption?"* → `06_Security_Audit.md`. Three CRITICAL findings including
unauthenticated admin escalation. **No bank will deploy this until those are closed** — and they are
mostly hours of work, not weeks. This is the cheapest possible unblock.

**A BOI judge:** *"Does it work?"* → Yes, demonstrably — I ran a real APK end-to-end in 9.1s with
correct package identification, obfuscation scoring (0.82), and a full FRS breakdown. The static
pipeline is real and working. The dynamic pipeline was not demonstrable without an emulator.

---

## 7. Where This Project Ranks

**Today:** a well-engineered **prototype** with unusually thoughtful design in two specific places
(prompt-injection defence; explicit auditable scoring) and unusually weak production hygiene
(3 CRITICAL security findings, no CI, 41% duplicated code). It is **not** competitive with MobSF on
analysis breadth and **is not trying to be**. Confidence: 🟢 high — this is from direct measurement.

**After closing the security findings + CI (≈1-2 weeks):** a credible internal SOC tool for a single
bank. Confidence: 🟡.

**After G1 (empirical validation on LAMDA) + G2 (anti-evasion):** genuinely differentiated, and I1/I2
become publishable. Confidence: 🔴 — depends on results that do not exist yet.

**The single highest-value next action is not a feature.** It is running the existing 302 tests in
CI and closing S1/S2/S6, which together cost roughly one day and move the project from
"not deployable" to "deployable internally."

---

## Sources

- [MobSF — GitHub](https://github.com/MobSF/Mobile-Security-Framework-MobSF) · [MobSF docs](https://mobsf.github.io/docs/) · [mobsf.org](https://mobsf.org/)
- [Exploring LLMs for Semantic Analysis and Categorization of Android Malware — arXiv:2501.04848](https://arxiv.org/abs/2501.04848)
- [Beyond Classification: Evaluating LLMs for Fine-Grained Automatic Malware Behavior Auditing — arXiv:2509.14335](https://arxiv.org/pdf/2509.14335)
- [LLM for Software Security: Code Analysis, Malware Analysis, Reverse Engineering — arXiv:2504.07137](https://arxiv.org/pdf/2504.07137)
- [AppPoet: LLM-based Android malware detection via multi-view prompt engineering](https://www.researchgate.net/publication/385148039_AppPoet_Large_language_model_based_android_malware_detection_via_multi-view_prompt_engineering)
- [LAMDA: A Longitudinal Android Malware Benchmark for Concept Drift](https://iqsec-lab.github.io/LAMDA/) · [LAMDA repo](https://github.com/IQSeC-Lab/LAMDA)
- [DREBIN: Effective and Explainable Detection of Android Malware in Your Pocket](https://www.researchgate.net/publication/264785935_DREBIN_Effective_and_Explainable_Detection_of_Android_Malware_in_Your_Pocket)
- [Cyble — OverlayPhantom Android banking trojan](https://cyble.com/blog/overlayphantom-android-banking-trojan/)
- [CYFIRMA — Android/BankBot-YNRK investigation report](https://www.cyfirma.com/research/investigation-report-android-bankbot-ynrk-mobile-banking-trojan/)
- [8kSec — Xenomorph trojan analysis](https://8ksec.io/mobile-malware-analysis-part-6-xenomorph/)
- [Appdome — protecting banking apps against mobile banking trojans](https://www.appdome.com/dev-sec-blog/how-to-protect-banking-apps-against-mobile-banking-trojans-2022/)
