# Sudarshan — Global Research & Competitive Intelligence

**Baseline:** `e7496bc` · **Date:** 2026-07-31 · **Supersedes** the `82fc55b` edition.

---

## Scope statement — read before using this document

The brief asks for a sweep of roughly fifty named sources across academia, industry, open source and community discussion. **That was not achievable in one pass and I did not fake it.**

What this contains:

- **Targeted literature searches** performed for this edition, cited with live URLs.
- **Direct comparison against tools characterisable from the codebase itself** — MobSF, Androguard, APKTool, JADX, Frida are all dependencies of this project, so their roles are established by evidence rather than by claim.
- **Explicit confidence labels on every claim.**

What it does **not** contain, and which the brief asked for:

- **[NOT PERFORMED]** Community-discussion synthesis — Reddit, X, LinkedIn, Discord, Quora, Hacker News, Lobsters, Dev.to, Hashnode, YouTube talks, conference slides.
- **[NOT PERFORMED]** Per-project screenshots.
- **[NOT PERFORMED]** Verified accuracy benchmarks for named commercial products. Vendor-published figures are not independently reproducible and are not repeated here as fact.
- **[NOT PERFORMED]** Patent prior-art search. Nothing below is a novelty assertion for patent purposes.
- **[NOT PERFORMED]** Structured Step-5 profiles (authors, repository, stack, metrics, screenshots) for every discovered project. The searches surfaced titles and abstracts; I did not read most of the papers in full and will not summarise what I have not read.

**A second, larger caveat specific to this edition.** The previous edition contained *measured* detection results from a 17-sample labelled corpus. **No corpus was run for this edition.** Every detection figure quoted below is inherited from `audit/_superseded_82fc55b/DETECTION_VALIDATION.md`, and §3 explains why one class of those figures now needs re-measuring.

**Confidence key:** 🟢 verified from primary source or from this codebase · 🟡 cited secondary source, not independently reproduced · 🔴 inference or absence-of-evidence — treat as hypothesis.

---

## 1. What Sudarshan actually is — updated for `e7496bc`

| Dimension | Implementation | Δ since `82fc55b` | Conf. |
|---|---|---|---|
| Code organisation | One shared package (`sudarshan_core`) consumed by gateway + engine | Layering **no longer holds** — 4 upward imports into `app.routes` | 🟢 |
| Service topology | Gateway delegates to a hardened analysis-engine container | **Delegation now live** — previously dead | 🟢 |
| Static analysis | Androguard primary; APKTool 2.10.0 + JADX 1.5.1; MobSF optional | unchanged | 🟢 |
| Concealment detection | Nested APK/DEX or max-entropy blob disproportionate to `classes.dex` | unchanged | 🟢 |
| Accessibility detection | `<service>` guard permission + intent-filter + raw manifest | unchanged | 🟢 |
| **Accessibility *enablement*** | **Real service class extracted from the manifest and forwarded to the tool executor** | **G2a CLOSED** | 🟢 |
| Dynamic analysis | Frida 17.16.4 on a real AVD over ADB TCP; monkey + agentic UI exploration; SELinux preflight; 5-step launch ladder | ladder is new | 🟢 |
| Network capture | mitmproxy sidecar → HAR → ingest | unchanged | 🟢 |
| Scoring | 5-axis STEI + BFCI + FRS, with axis exclusion, renormalisation, visibility floor | unchanged | 🟢 |
| Threat intel | VirusTotal, OTX, AbuseIPDB | **the 24 h SQLite cache is never called** | 🟢 |
| AI layer | RAG-grounded **Gemini only**; agentic planner / perception / tool-executor loop | Ollama removed | 🟢 |
| Prompt-injection defence | Single-choke-point sanitizer, 20 adversarial tests | **not wired to either production LLM path** | 🟢 |
| Output | STIX 2.1, IOC CSV, MITRE mapping, fraud-workflow reconstruction | STIX IDs are malformed | 🟢 |
| Domain specialisation | Indian banking — `targets_indian_banks`, CERT-In in the RAG corpus | bank matching is naked substring | 🟢 |

**One-line positioning:** a hybrid static+dynamic Android analyser with an explicit, auditable fraud-risk formula that refuses to over-claim, an agentic LLM investigation layer, and Indian-banking grounding.

---

## 2. Landscape

### 2.1 The open-source baseline — MobSF

MobSF remains the reference open-source mobile analysis framework: automated static and dynamic analysis for Android/iOS/Windows, partly built on Androguard, with REST APIs and CI/CD integration (🟡 — [GitHub](https://github.com/MobSF/Mobile-Security-Framework-MobSF), [docs](https://mobsf.github.io/docs/)).

**Sudarshan's relationship is "optional upstream", not "competitor"** — `services/mobsf_client.py` calls MobSF when `MOBSF_HOST` is set and falls back to Androguard otherwise (🟢). State this openly rather than positioning against it.

| Dimension | MobSF | Sudarshan |
|---|---|---|
| Static breadth | Broad, mature, multi-platform | Narrower; Android only |
| Dynamic | Instrumented testing, runtime + network (🟡) | Frida + agentic exploration + mitmproxy |
| Risk output | Security findings + AppSec score | **Fraud-specific weighted formula with explicit provenance** |
| LLM layer | Not core | **Agentic investigation loop + RAG narrative** |
| Domain tuning | Generic | **Indian banking** |
| Maturity | Years of production use | Prototype |

### 2.2 Agentic LLM UI exploration — the novelty window has narrowed

This is the most important landscape change since the previous edition. Searching specifically for agentic LLM approaches to mobile UI exploration and malware analysis in 2025–2026 returns a crowded field (🟡, titles and abstracts only — most not read in full):

- **MARD — A Multi-Agent Framework for Robust Android Malware Detection** ([arXiv:2604.25264](https://arxiv.org/pdf/2604.25264))
- **MANA — Towards Efficient Mobile Ad Detection via Multimodal Agentic UI Navigation** ([arXiv:2603.20351](https://arxiv.org/pdf/2603.20351))
- **From UI to Code: Mobile Ads Detection via LLM-Unified Static-Dynamic Analysis** ([arXiv:2604.03561](https://arxiv.org/pdf/2604.03561)) — this one explicitly names **Guardian** and **AutoDroid** as prior work demonstrating LLM-driven mobile UI understanding and exploration planning.
- **Identifying Adversary Tactics and Techniques in Malware Binaries with an LLM Agent** ([arXiv:2602.06325](https://arxiv.org/pdf/2602.06325))
- **Beyond Classification: Evaluating LLMs for Fine-Grained Automatic Malware Behavior Auditing** ([arXiv:2509.14335](https://arxiv.org/pdf/2509.14335))
- **LLM-Generated Samples for Android Malware Detection** ([arXiv:2510.02391](https://arxiv.org/pdf/2510.02391), also [MDPI](https://www.mdpi.com/2673-6470/6/1/5))

**Implication for positioning.** "Agentic UI exploration of an APK under instrumentation" is no longer differentiating on its own — Guardian and AutoDroid established the technique, and MANA and MARD apply it in adjacent security contexts. What remains distinctive in Sudarshan is the *pairing* of that loop with a deterministic scoring engine the LLM is structurally forbidden from influencing (`gemini_rag.py:16-17`, 🟢). Lead with the separation of concerns, not with "we use an agent".

### 2.3 Academic — LLMs for malware analysis

- **MalParse / semantic categorisation** — hierarchical summarisation with GPT-4o-mini, reported 77 % benign-vs-malicious accuracy ([arXiv:2501.04848](https://arxiv.org/abs/2501.04848)). *Their figure, not verified here.* 🟡
- **Beyond Classification** argues the field should move past binary labels toward fine-grained **behaviour auditing** ([arXiv:2509.14335](https://arxiv.org/pdf/2509.14335)). **This is Sudarshan's fraud-workflow thesis** and remains its strongest external validation. 🟡
- **AppPoet** — multi-view prompt engineering ([ResearchGate](https://www.researchgate.net/publication/385148039_AppPoet_Large_language_model_based_android_malware_detection_via_multi-view_prompt_engineering)). 🟡
- **LLM for Software Security survey** names *dataset bias, evolving threats and lack of explainability* as the open problems ([arXiv:2504.07137](https://arxiv.org/pdf/2504.07137)). 🟡

### 2.4 Academic — datasets and drift

- **Drebin** — canonical explainable-detection feature set ([paper](https://www.researchgate.net/publication/264785935_DREBIN_Effective_and_Explainable_Detection_of_Android_Malware_in_Your_Pocket)). Sudarshan's static flags occupy the same space (🔴 inference).
- **AndroZoo** — millions of APKs since 2010. 🟡
- **LAMDA (2025)** — >1 M APKs, 1 380 families, 2013–2025, Drebin-derived features, built for **concept drift** with SHAP-based explanation drift ([site](https://iqsec-lab.github.io/LAMDA/), [repo](https://github.com/IQSeC-Lab/LAMDA)). 🟡

**Still the single most actionable finding in this document.** A free, purpose-built instrument for the validation Sudarshan has only begun at 17-sample scale.

### 2.5 Industry — the threat model Sudarshan is built for is current

Accessibility-service abuse plus overlay phishing remains *the* defining Android banking-trojan technique. **OverlayPhantom** (2025–26) is the clearest current example: it targets 180+ apps across 10 countries, abuses the Accessibility Service for persistent device control, renders counterfeit HTML phishing pages in a WebView over the legitimate banking app, exposes 30+ remote commands, and performs near-real-time screen streaming via `MediaProjection` (🟡 — [Cyble](https://cyble.com/blog/overlayphantom-android-banking-trojan/), [Cybersecurity News](https://cybersecuritynews.com/android-banking-trojan-overlayphantom/), [The Cyber Express](https://thecyberexpress.com/overlayphantom-android-banking-trojan/), [Gurucul](https://gurucul.com/latest-threats/overlayphantom-the-android-banking-trojan-hiding-in-plain-sight/)).

India-specific: McAfee documents Android banking trojans masquerading as utility and banking apps targeting Indian users (🟡 — [McAfee Labs](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/a-new-android-banking-trojan-masquerades-as-utility-and-banking-apps-in-india/)). One 2026 landscape summary reports Rewardsteal-family trojans posing as reward and loyalty apps at 88–94 % prevalence among attacked Indian users (🟡 — [Vervali](https://www.vervali.com/blog/android-malware-statistics-2026-threat-landscape-ios-comparison-and-detection-trends/); single secondary source, methodology not examined — treat the number with caution).

**No source found in these searches directly links a named 2026 trojan family to UPI specifically.** Sudarshan's UPI/NPCI package list (`apk_analyzer.py:15-21`) is a reasonable prior, not a corroborated targeting profile. 🔴

**This validates the BFCI *ordering*.** Accessibility 0.35 and overlay 0.20 are the two highest weights and match the two techniques industry independently identifies as primary. The *magnitudes* remain uncalibrated — see §5 G1.

### 2.6 Industry — evasion is still the decisive constraint, and now quantified

The AsiaCCS'24 evasion study is the key source, and the numbers are sharper than the previous edition recorded (🟡 — [Ruggia et al., *Unmasking the Veiled*](https://s3.eurecom.fr/docs/asiaccs24_ruggia.pdf), [ACM](https://dl.acm.org/doi/pdf/10.1145/3634737.3637658)):

- **HOOK-FRIDA-FILE detection appears in >60 % of packed samples versus ~25 % of non-packed malware.**
- **Jiagu-packed apps implement 56 of 97 identified evasion techniques.**

Frida is detectable via ptrace state, pthread injection, spawn and attach signatures, named pipes and port fingerprints (🟡 — [Appdome](https://www.appdome.com/mobile-malware-prevention/anti-frida-dbi-detection/), [Approov](https://approov.io/knowledge/frida-detection-prevention), [HackTricks](https://hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/android-anti-instrumentation-and-ssl-pinning-bypass.html)).

**New and directly actionable:** *To Unpack or Not to Unpack — Living with Packers to Enable Dynamic Analysis of Android Apps* (Sept 2025) presents **Purifire**, an eBPF-based runtime evasion engine that neutralises anti-analysis checks *without being detected*, driven by declarative "Defined Evasion Rules" specifically to let tools like Frida operate on packed apps (🟡 — [arXiv:2509.16340](https://arxiv.org/html/2509.16340v1)). This is the closest published answer to Sudarshan's G2, and it is more tractable than the Phantom-Frida SELinux-relabelling approach cited previously.

**Sudarshan's current configuration is among the most detectable possible** — stock `frida-server` on a standard AVD, with `setenforce 0` applied (🟢). `start.ps1` does one useful thing here: it renames the server binary to `sudarshan_agent_srv` and moves it to port 27055 instead of the default 27042 (🟢). That defeats the two laziest checks and none of the sophisticated ones.

### 2.7 The prompt-injection literature has caught up — and it changes a claim in the previous edition

The previous edition stated: *"I found no comparable published treatment [of prompt-injection defence] in a malware-analysis context."* That claim needs narrowing in two directions.

**The defence techniques are now well-documented general practice**, not novel (🟡):
- [OWASP — LLM Prompt Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html)
- [*Prompt Injection Attacks in LLMs and AI Agent Systems: A Comprehensive Review*](https://www.mdpi.com/2078-2489/17/1/54)
- [*Assessing Automated Prompt Injection Attacks in Agentic Environments*](https://arxiv.org/pdf/2606.10525)
- [*Prompt Flow Integrity to Prevent Privilege Escalation in LLM Agents*](https://arxiv.org/pdf/2503.15547)
- [Unit 42 — *Fooling AI Agents: Web-Based Indirect Prompt Injection Observed in the Wild*](https://unit42.paloaltonetworks.com/ai-agent-prompt-injection/)

Two findings from that body of work bear directly on Sudarshan:

1. **The root cause is the absence of separation between prompt and data** — the model decides its next action from the entire preceding context, so untrusted data is interpretable as instruction. One review reports **17 of 18 tested LLMs (94.4 %) vulnerable to direct prompt injection** (🟡). Delimiter-based fencing, which is what `planner.py` implements, is a mitigation, not a solution.
2. **The stronger published pattern is dual-LLM privilege separation** — a privileged model holds the tools but never reads untrusted content, and a quarantined model reads untrusted content but cannot act, passing only structured summaries upward (🟡). Sudarshan's architecture is *already close to this*: the deterministic engine holds the verdict and the LLM only explains. Naming and formalising that as privilege separation is a stronger claim than "we sanitise".

**And the sharper correction: the defence is not actually wired to the paths that need it.** `sanitizer.py` is imported by exactly two files, both in the agentic explorer. `gemini_client.py` and `gemini_rag.py` — the surfaces producing the analyst narrative, the customer advisory and the CERT-In recommendations — do not import it, and `gemini_rag.py` inserts APK-controlled activity names, MobSF finding text and hardcoded strings into the prompt with no fence at all (🟢 — `audit/06_Security_Audit.md` S16).

So the previous edition's "most publishable thing here" is presently a well-built component that is not connected to the attack surface it was written for. That is a half-day fix, and until it is made, the claim should not be published.

---

## 3. Measured results — inherited, with one class now in doubt

Corpus: 8 real banking trojans, 4 legitimate apps, 4 OWASP crackmes, 1 deliberately vulnerable app. **All figures below are inherited from the `82fc55b` edition. Nothing was re-measured for this edition.** 🟡

```
malware flagged      : 8/8   (missed 0)
non-malware flagged  : 0/9   false positives
precision 1.00   recall 1.00
malware FRS 14.0–50.9   benign FRS 9.2–25.9
```

**Static detection figures should still stand**, since `risk_engine.py` and `apk_analyzer.py` are materially unchanged (🟢 by diff inspection).

**Dynamic figures now need re-measuring, for two reasons:**

1. **G2a is closed.** `permission_orchestrator.extract_accessibility_service_class` is now called at `frida_sandbox.py:1537-1547` and the real manifest-declared class is forwarded through `AgenticExplorer` to `ToolExecutor` (🟢). The previous edition's finding — that a hardcoded `.AccessibilityService` string meant Android silently ignored the enablement command — no longer applies. **The 0.0 accessibility BFCI component across all eight trojans should be re-run.** This was the highest-leverage item in the previous edition and it has been done.
2. **A new confound was found.** When an APK fails to install, `apk_repair.py:251-268` builds a synthetic manifest that **grants `BIND_ACCESSIBILITY_SERVICE`, `READ_SMS`, `RECEIVE_SMS`, `SEND_SMS` and `SYSTEM_ALERT_WINDOW`** — the five highest-weighted signals in the model — plus `debuggable="true"`, and that derivative is what gets installed and instrumented (🟢). Any dynamic result from a repaired sample is a measurement of an artifact we modified, not of the sample. Teabot was specifically noted in the previous edition as failing install, so it is likely affected.

**Until the repair path is fixed, dynamic results from repaired derivatives are not admissible evidence** and should be excluded from any published figure.

---

## 4. Comparison matrix

| Feature | Their approach | Sudarshan | Gap | Difficulty | Impact | Can implement? |
|---|---|---|---|---|---|---|
| Static breadth | MobSF: multi-platform, mature 🟡 | Android only, Androguard+APKTool+JADX 🟢 | Wide | High | Low — not the differentiator | Don't. Integrate MobSF |
| Behaviour auditing over classification | *Beyond Classification* proposes it 🟡 | `workflow_reconstructor` implements it 🟢 | **Ahead** | — | High | Already done |
| Agentic UI exploration | Guardian, AutoDroid, MANA, MARD 🟡 | `agentic_explorer` + planner 🟢 | **Parity** — no longer novel | — | Medium | Reposition, don't rebuild |
| Anti-evasion | Purifire (eBPF, undetected) 🟡; Phantom-Frida 🟡 | Stock frida-server, renamed binary + port 🟢 | **Wide — the decisive gap** | High | **Critical** | Study Purifire's rule model |
| Concept-drift evaluation | LAMDA: 1 M APKs, 2013–2025 🟡 | 17 samples, single point in time 🟡 | Wide | Medium | Critical | **Yes — LAMDA is free** |
| Explainable scoring | Drebin-lineage; survey names explainability as open 🟡 | Explicit weights + `axes_excluded` + visibility floor 🟢 | **Ahead** | — | High | Already done; needs calibration |
| Prompt-injection defence | OWASP cheat sheet; dual-LLM privilege separation 🟡 | Excellent sanitizer, **unwired** 🟢 | **Behind own design** | Low | **Critical** | Half a day |
| Family attribution | VT/OTX labels; Drebin families 🟡 | 7 hardcoded rules, returned "Unknown" for 8/8 trojans 🟢 | Wide | Medium | Medium | Yes |
| Multi-platform | MobSF: iOS + Windows 🟡 | Android only 🟢 | Wide | High | Low for BOI | Don't |
| Production hardening | Commercial: SaaS, RBAC, audit 🔴 | Root containers, no CI, no backup 🟢 | Wide | Low | Blocker | Yes — days |

---

## 5. Gap analysis

| # | Gap | Status Δ | Impact | Effort |
|---|---|---|---|---|
| **G1** | No empirical validation at scale | PARTIAL — 17 samples, and dynamic half now in doubt (§3) | Critical | Medium |
| **G2** | Anti-evasion | **OPEN, now with a published answer to study (Purifire)** | **Critical** | High |
| ~~G2a~~ | ~~Accessibility never enabled~~ | **CLOSED** — real class extracted and forwarded | — | — |
| **G2b** | Packed droppers unlaunchable | **PARTIAL** — a 5-step launch ladder now tries `am start`, monkey, exported activities, BOOT_COMPLETED/PACKAGE_ADDED broadcasts and deep links | High | Medium |
| **G2c** | **NEW — repair path fabricates permissions on the analysed artifact** | **OPEN** | **Critical (evidentiary)** | Low |
| **G2d** | **NEW — sanitizer unwired from production LLM paths** | **OPEN** | **Critical** | Low |
| G3 | Concept drift | OPEN — no temporal evaluation | High | Medium |
| G4 | Scale corpus | OPEN — `batch_runner.py` exists but has no caller | High | Medium |
| G5 | YARA depth | **STILL OPEN** — `yara-python` is now in the engine image, but `frida_sandbox.py:1583` points at a relative `yara_rules/` directory that **does not exist anywhere in the repo**, so scanning is almost certainly a no-op | Medium | Low |
| G6 | Multi-platform | OPEN — Android only. Recommend not closing | Medium | High |
| G7 | Family attribution | OPEN — 7 rules with no stated provenance, feeding 20 % of the FRS | Medium | Medium |
| G8 | Production hardening | Mixed — delegation fixed; root containers, unpublished CI, no backup, tracked credentials | Blocker | Low–Med |

**G2c and G2d are the two highest-leverage items in the project**, and both are under a day of work. G2d is a wiring change to code that is already written and tested. G2c is restricting one hardcoded XML block to the permissions the original sample declared.

---

## 6. Where Sudarshan is genuinely differentiated

1. **Explicit, auditable scoring that refuses to over-claim.** Axes without evidence are *excluded and named* (`axes_excluded`), not scored as benign; a concealed payload cannot be certified "Safe" without a dynamic run; `analysis_completeness` distinguishes "nothing found" from "never computed". The survey literature names *lack of explainability* as an open problem ([arXiv:2504.07137](https://arxiv.org/pdf/2504.07137) 🟡); this is a structurally sound answer, and for regulated banking forensics it is a feature rather than a limitation. 🟢
2. **Fraud *workflow* reconstruction rather than classification** — directly aligned with the *Beyond Classification* direction. 🟡
3. **Architectural privilege separation between the LLM and the verdict.** The deterministic engine decides; the LLM only explains, and is structurally unable to alter a score. The prompt-injection literature's strongest recommended pattern is exactly this shape (🟡). Sudarshan arrived at it for architectural reasons and has not claimed it as a security property — it should, once G2d is closed. 🟢
4. **Indian banking domain grounding** — a real moat for BOI-type deployments, though the bank-package matching is a naked substring and the UPI targeting profile is a prior, not a corroborated observation. 🟢/🔴
5. **Determinism testing** with a committed baseline treated as a deliberately reviewed act to regenerate. Rare in comparable open-source tools. 🔴

**Dropped from the previous edition's list:** "serious prompt-injection engineering" as a *differentiator*. The component is excellent; it is not connected (§2.7). It returns to this list the day G2d closes.

---

## 7. Innovation and research opportunities

| # | Opportunity | Why credible here | Conf. |
|---|---|---|---|
| **I1** | **Adversarial robustness of LLM-driven malware analysis** — formalise the threat model in which the *analysed artifact attacks the analyser*, and evaluate delimiter fencing versus the dual-LLM privilege-separation pattern on real APK-derived content | `sanitizer.py` + `test_prompt_injection.py` are a working implementation and harness; the general defence literature exists but I found no evaluation *in a malware-analysis setting where the sample is the adversary* | 🟡 — narrowed from the previous edition |
| **I2** | **Calibrating explicit fraud weights against LAMDA**, published over temporal splits | Closes G1 and G3; LAMDA is free and purpose-built; the small-scale harness already exists | 🟢 feasible |
| **I3** | **Evidence-completeness as a first-class output** — `axes_excluded` + visibility floor + `analysis_completeness` proposed as a reporting standard for forensic tooling | Implemented and measured; I found no comparable treatment in the tools surveyed | 🔴 absence-of-evidence |
| **I4** | **Agentic exploration versus monkey coverage** — measure behavioural coverage of the LLM planner against random fuzzing on the same corpus | `benchmark.py`, `test_goal_progression.py` and both explorer modes exist. **Now more valuable, not less**: MANA/MARD/Guardian/AutoDroid establish the technique, so a rigorous *comparison* is the contribution | 🟡 |
| **I5** | **Instrumentation-integrity accounting** — quantify how often dynamic findings derive from repaired or modified artifacts, and propose a provenance standard for sandbox evidence | G2c makes this concrete and this project has both the `APKProvenance` model and the failure mode | 🟡 — **new this edition** |
| **I6** | Regional fraud-pattern corpus (Indian banking) published as a dataset | Grounding exists; corpus does not | 🔴 |

**Patent opportunities: [NOT PERFORMED].** No prior-art search was conducted.

---

## 8. Adversarial review

**A SOC analyst — "what's my false-positive rate?"** → 0/9 on a 17-sample corpus, static half. Say the number *and* the sample size. The dynamic half needs re-measuring (§3).

**A malware researcher — "Cerberus detects Frida and does nothing. What do you show me?"** → An honest inconclusive verdict: the engine excludes a run that observed nothing rather than letting it dilute strong static evidence, and says so in `dynamic_conclusive` and `axes_excluded`. That is a better answer than most sandboxes give. But you are running stock frida-server on a standard AVD against a corpus where >60 % of packed samples check for exactly that, so expect to give this answer often.

**A reverse engineer — "your dynamic finding says SMS interception. Show me the manifest."** → **This is currently the hardest question to answer.** If the sample went through the repair path, the manifest you would show is one Sudarshan wrote, containing `READ_SMS` it may have added (§3, G2c). Fix that before demonstrating dynamic results.

**A Google security engineer — "why not MobSF plus a script?"** → The scoring model, the workflow reconstruction, and the evidence-provenance output. Not static breadth. Lead with the first three.

**A DARPA reviewer — "what is the novel contribution?"** → I1 and I5, and neither is publishable today: I1 because the defence is not wired in, I5 because the failure it describes is currently live. The scoring formula is engineering until calibrated (I2).

**A red-team lead — "can I make your report say the app is safe?"** → Today, plausibly yes — not by changing the score, which is deterministic and out of the LLM's reach, but by injecting into the narrative through an activity class name or a hardcoded string (§2.7). That is the single best demo an adversary could give against this project, and it is a half-day fix.

**A VC — "what stops adoption?"** → Containers run malware as root; CI is gitignored so no clone is protected; two tracked files publish a JWT signing key and an admin password; there is no backup capability. All are days of work, not months — but a bank's procurement will find every one of them.

**A BOI judge — "does it work?"** → Static: demonstrably, on a small labelled corpus, with zero false positives. Dynamic: instrumentation works, the accessibility blocker is fixed, and the results need re-running. Say both, and say the sample size.

---

## 9. Where this project ranks

**Today:** a well-engineered prototype with two areas of genuinely excellent design — explicit provenance-carrying scoring, and a sanitizer that is better than most shipped commercial LLM systems — plus small-scale empirical validation that most comparable projects never produce. The delegation fix since the last edition was substantial and correct. It is held back by four things that are all cheap to fix and one that is not: the sanitizer is unwired, the repair path fabricates permissions, credentials are in tracked files, CI is unpublished — and the sandbox is highly detectable. Confidence 🟡 (code-verified; nothing re-measured this edition).

**After closing G2c + G2d + publishing CI + hardening containers (~1 week):** a credible internal SOC tool whose evidence chain holds up to a reverse engineer's questions. Confidence 🟡.

**After G1-at-scale (LAMDA) + G2 (anti-evasion, informed by Purifire):** genuinely differentiated, and I1/I2/I5 become publishable. Confidence 🔴 — depends on results that do not exist yet.

**Highest-value next action:** not a feature. Wire `sanitize()` into `gemini_client.py` and `gemini_rag.py` (half a day), and restrict the synthetic repair manifest to the original's declared permissions (half a day). Those two changes convert the project's two best ideas from claims into properties.

---

## Sources

**Open source and tooling**
- [MobSF — GitHub](https://github.com/MobSF/Mobile-Security-Framework-MobSF) · [docs](https://mobsf.github.io/docs/)

**Agentic LLM and mobile UI exploration**
- [MARD: A Multi-Agent Framework for Robust Android Malware Detection — arXiv:2604.25264](https://arxiv.org/pdf/2604.25264)
- [MANA: Towards Efficient Mobile Ad Detection via Multimodal Agentic UI Navigation — arXiv:2603.20351](https://arxiv.org/pdf/2603.20351)
- [From UI to Code: Mobile Ads Detection via LLM-Unified Static-Dynamic Analysis — arXiv:2604.03561](https://arxiv.org/pdf/2604.03561)
- [Identifying Adversary Tactics and Techniques in Malware Binaries with an LLM Agent — arXiv:2602.06325](https://arxiv.org/pdf/2602.06325)

**LLMs for malware analysis**
- [Exploring LLMs for Semantic Analysis and Categorization of Android Malware — arXiv:2501.04848](https://arxiv.org/abs/2501.04848)
- [Beyond Classification: Evaluating LLMs for Fine-Grained Automatic Malware Behavior Auditing — arXiv:2509.14335](https://arxiv.org/pdf/2509.14335)
- [LLM for Software Security: Code Analysis, Malware Analysis, Reverse Engineering — arXiv:2504.07137](https://arxiv.org/pdf/2504.07137)
- [LLM-Generated Samples for Android Malware Detection — arXiv:2510.02391](https://arxiv.org/pdf/2510.02391) · [MDPI](https://www.mdpi.com/2673-6470/6/1/5)
- [AppPoet: LLM-based Android malware detection via multi-view prompt engineering](https://www.researchgate.net/publication/385148039_AppPoet_Large_language_model_based_android_malware_detection_via_multi-view_prompt_engineering)

**Datasets and drift**
- [LAMDA: A Longitudinal Android Malware Benchmark for Concept Drift](https://iqsec-lab.github.io/LAMDA/) · [repo](https://github.com/IQSeC-Lab/LAMDA)
- [DREBIN: Effective and Explainable Detection of Android Malware in Your Pocket](https://www.researchgate.net/publication/264785935_DREBIN_Effective_and_Explainable_Detection_of_Android_Malware_in_Your_Pocket)

**Evasion and anti-instrumentation**
- [Unmasking the Veiled: A Comprehensive Analysis of Android Evasive Malware (AsiaCCS'24)](https://s3.eurecom.fr/docs/asiaccs24_ruggia.pdf) · [ACM](https://dl.acm.org/doi/pdf/10.1145/3634737.3637658)
- [To Unpack or Not to Unpack: Living with Packers to Enable Dynamic Analysis of Android Apps — arXiv:2509.16340](https://arxiv.org/html/2509.16340v1)
- [Evading Android Runtime Analysis via Sandbox Detection (ASIACCS'14)](https://dl.acm.org/doi/10.1145/2590296.2590325)
- [Appdome — anti-Frida DBI detection](https://www.appdome.com/mobile-malware-prevention/anti-frida-dbi-detection/)
- [Approov — Frida detection and prevention](https://approov.io/knowledge/frida-detection-prevention)
- [HackTricks — Android anti-instrumentation and SSL pinning bypass](https://hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/android-anti-instrumentation-and-ssl-pinning-bypass.html)
- [Fortinet — Defeating an Android packer with Frida](https://www.fortinet.com/blog/threat-research/defeating-an-android-packer-with-frida)

**Prompt injection**
- [OWASP — LLM Prompt Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html)
- [Prompt Injection Attacks in LLMs and AI Agent Systems: A Comprehensive Review — MDPI Information 17(1):54](https://www.mdpi.com/2078-2489/17/1/54)
- [Assessing Automated Prompt Injection Attacks in Agentic Environments — arXiv:2606.10525](https://arxiv.org/pdf/2606.10525)
- [Prompt Flow Integrity to Prevent Privilege Escalation in LLM Agents — arXiv:2503.15547](https://arxiv.org/pdf/2503.15547)
- [Unit 42 — Fooling AI Agents: Web-Based Indirect Prompt Injection Observed in the Wild](https://unit42.paloaltonetworks.com/ai-agent-prompt-injection/)

**Threat landscape**
- [Cyble — OverlayPhantom Android banking trojan](https://cyble.com/blog/overlayphantom-android-banking-trojan/)
- [Cybersecurity News — OverlayPhantom abuses Accessibility Service](https://cybersecuritynews.com/android-banking-trojan-overlayphantom/)
- [The Cyber Express — OverlayPhantom targets 180 apps](https://thecyberexpress.com/overlayphantom-android-banking-trojan/)
- [Gurucul — OverlayPhantom analysis](https://gurucul.com/latest-threats/overlayphantom-the-android-banking-trojan-hiding-in-plain-sight/)
- [McAfee Labs — Android banking trojan masquerading as utility and banking apps in India](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/a-new-android-banking-trojan-masquerades-as-utility-and-banking-apps-in-india/)
- [CYFIRMA — Android/BankBot-YNRK investigation report](https://www.cyfirma.com/research/investigation-report-android-bankbot-ynrk-mobile-banking-trojan/)
- [8kSec — Xenomorph trojan analysis](https://8ksec.io/mobile-malware-analysis-part-6-xenomorph/)
- [Vervali — Android malware statistics 2026](https://www.vervali.com/blog/android-malware-statistics-2026-threat-landscape-ios-comparison-and-detection-trends/)
