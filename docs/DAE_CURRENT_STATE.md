# Dynamic Analysis Engine — Honest Current-State Assessment

**Audience:** the Sudarshan team.
**Purpose:** an evidence-based answer to "where do we actually stand?" before we commit to the
Dynamic Analysis Engine (DAE) review roadmap.
**Method:** every claim below was produced by reading the source or executing the system, not by
reading our own documentation. Where documentation and reality disagree, reality is recorded.

---

## The one-paragraph version

**The foundation is better than we think. The measurement layer is worse than we think.**

Our architecture, determinism guarantees, test discipline and goal-directed exploration design are
genuinely solid — several of them are things commercial sandboxes get wrong. But the dynamic
engine has been producing **BFCI = 0.0 on every sample**, because the Frida hooks install and then
never fire. And even when they do fire, BFCI is computed by *counting distinct hook names*, which
is not behavioural analysis. Our static analysis works. Our dynamic analysis, as of today, does
not measure anything.

Nobody was careless. The failure modes here were **silent by design** — that is the real lesson.

---

## Part 1 — What is genuinely good

This is not padding. These are things reviewers would credit us for.

**1. The determinism invariant actually holds.**
AI controls exploration; only deterministic evidence feeds the score. This is enforced structurally,
not by convention: the risk engine is the sole writer of the verdict, inputs are validated and
clamped at the trust boundary, and the LLM narrative runs strictly downstream. We proved it — a
baseline captured before a ~3,600-line refactor still matches byte-for-byte, and a regression test
asserts that LLM-authored fields merged into the dynamic payload cannot move the score.

Most products in this category cannot make that claim. It is our strongest asset.

**2. Framework-level hooking is already our default.**
The DAE review lists this as recommendation R9.3 — anchor on stable Android surfaces rather than
app-specific hooks. We already do: `AccessibilityService`, `WindowManager`, `SmsManager`,
`DexClassLoader`, `KeyStore`, `OkHttp`. That item is largely already satisfied.

**3. The explorer is already a hybrid, and already read-only.**
`AgenticExplorer` pairs an LLM planner with a fully deterministic fallback, a 15-stage fraud goal
DAG, screen-hash state abstraction and loop detection. Critically, it **cannot mutate
instrumentation or the score** — which is exactly the constraint R3.2 demands. We got the hard part
right by accident of good design.

**4. Test discipline is real.**
285 passing tests, including 64 dedicated to prompt-injection resistance and 9 pinning the verdict
to a recorded baseline.

**5. Structured evidence records exist.**
`EvidenceRecord` already carries class, method, args, return value, thread, timestamp, stack trace,
severity and screenshot reference. The review calls Layer 5 "the best layer" of our design. It's
roughly 60% built.

**6. Fraud-goal-directed exploration is a genuine idea.**
Almost every sandbox maximises *code coverage*. We maximise progress toward *fraud outcomes*.
That is closer to a research contribution than anything else we have.

---

## Part 2 — What is actually broken

### 2.1 The dynamic engine measures nothing

| Observation | Result |
|---|---|
| Hook script loads | ✅ `ready` message received |
| Hooks install | ✅ zero `hook_error` after fixes |
| Hooks **fire** | ❌ **0 events**, including spawn-and-resume |
| BFCI | **0.0 on every sample, every run** |
| `evidence.json` | **0 records flushed** |

**Every dynamic result we have ever produced is an empty set.** A 0.0 BFCI is currently
indistinguishable from "this app is clean."

**Root cause chain, in order of discovery:**

1. **Frida 17 removed the built-in `Java` global.** Our hook script uses the classic `Java.perform`
   API. On Frida 17 the script loads, spins in `waitForJava()` forever, installs nothing, and
   **reports no error**. `requirements.txt` pinned no version, so any fresh install landed on 17.x.
   → Fixed: the script is now bundled with `frida-java-bridge` via `frida-compile`.

2. **We cannot simply downgrade.** Our AVD is a 16 KB page-size image
   (`google_apis_ps16k`, `getconf PAGESIZE → 16384`). frida-server 16.x **cannot even link**:
   `CANNOT LINK EXECUTABLE: empty/missing DT_HASH/DT_GNU_HASH`. 16 KB support only arrived in 17.x.
   We are pinned between two hard constraints.

3. **Attaching by package name can never work.** Frida reports running Android apps by their
   *display label* (`InsecureBankv2`), not their package (`com.android.insecurebankv2`). Our code
   called `attach(package_name)`, retried 15 times × 2 s, burned **30 seconds of a 30-second
   window**, then fell through.
   → Fixed: resolve the PID via `pidof`, then `attach(pid)`. Now succeeds on attempt 1.

4. **Three hooks had ambiguous overloads** (`performAction`, `sendTextMessage`, `lockNow`) and
   silently failed to install. Invisible for the life of the script, because nothing was running.
   → Fixed.

5. **Hooks still do not fire.** Remaining cause not yet isolated; ART method inlining is the
   leading hypothesis (`Java.deoptimizeEverything()` is untested).

### 2.2 BFCI is hook-name counting, not behavioural analysis

From `frida_sandbox.py:314-346`:

```
_score_component = min(unique_hook_names / max_events, 1.0) × 100
BFCI = Σ (weight × component)
```

Per-category caps: accessibility 3, sms 2, overlay 2, banking 3, network 10, persistence 2.

**Consequences we should be honest about:**

- Three unrelated accessibility hooks firing once each score **identically** to a real
  account-takeover chain.
- There is no notion of sequence, causality, time bounding, or workflow.
- Two accessibility events cap the component at 66% regardless of what they were.
- The score cannot distinguish "app read one SMS" from "app intercepted an OTP and exfiltrated it."

This is what the DAE review means by "counting API calls." It is the weakest part of the design,
and it is weak *by construction*, not by bug.

### 2.3 There is no correlation engine

We have no event graph, no causal linkage, no temporal windows, no taint tracking.
`mitre_mapper.py` is per-event tag lookup — it is not correlation. The only combination step is the
risk engine summing independent axes.

Our own pitch describes turning Accessibility + Overlay + SMS + Network into a single fraud
workflow. **That mechanism does not exist in the codebase.**

### 2.4 The goal DAG stalls, so most fraud categories are never evaluated

Stage 5 ("Login Flow") requires two hooks, is **not skippable**, and gates stages 6, 7, 8 and 10.

| Never evaluated on any sample |
|---|
| SMS / OTP Interception |
| Banking Application Detection |
| Network / C2 Communication |
| Dynamic Code Loading |

Two stopping conditions (SC1 "all goals complete" and SC2 "no new evidence") are gated on
`all_done()`, which can therefore never be true. Only the action budget, time budget and crash
detection can end a run.

### 2.5 Documentation describes hooks that do not exist

Our internal write-ups list `ClipboardManager`, `TelephonyManager`, SMS `BroadcastReceiver`s,
`Class.forName`, `Method.invoke`, `getInstalledPackages`, `getRunningAppProcesses`,
`PathClassLoader` and SSL-pinning hooks.

**None of these exist.** The real inventory is 19 hooks (21 including two added recently).

This matters beyond tidiness: if we present that list to a bank or a judge and someone opens the
file, we lose credibility on everything else we've said.

### 2.6 Other verified defects

| Defect | Location | Effect |
|---|---|---|
| Executor rejects valid coordinates | `tool_executor.py:275` | Uses hardcoded `SCREEN_HEIGHT` 1920; on our 1080×2400 device the bottom 480 px is rejected *after* the planner accepted it |
| `ToolExecutor.screen_size` unused | — | The fix it represents is inert; only a test calls it |
| `mark_failed` never called | — | The goal-retry branch is dead code |
| Legacy explorer prompt unsanitized | `ui_explorer.py:233` | Zero sanitize calls, no fence — an injection surface in the rollback path |
| `cred_note` unsanitized | `agent_memory.py:358` | LLM-supplied `field_hint` lands in the region the planner labels *trusted* |
| `explorer_error` unreachable | `agentic_explorer.py:457` | A catch-all upstream means agent crashes never surface in results |
| Device resolution caches failures | `device_properties.py` | One transient adb failure pins 1080×1920 process-wide, no TTL |
| Vision is a dead path | — | Screenshots captured; **no image ever reaches the model** |
| No device hygiene | — | The emulator is reused dirty between samples — cross-sample contamination |

---

## Part 3 — Why this happened (the actual lesson)

Not carelessness. **Every one of these failures was silent.**

- Frida 17 broke the hook script and *printed no error*.
- Attach-by-name failed 15 times per run and looked like a slow app.
- Three hooks failed to install and the message went nowhere, because nothing was running.
- `gemini-1.5-flash` was retired and returns **404** — every LLM call was failing into the
  deterministic fallback, silently, and the system looked like it was working.
- BFCI 0.0 renders as "SAFE" in the UI. A total instrumentation failure is presented to the analyst
  as a **clean verdict**.

That last point is the most important sentence in this document.

**The single highest-value change we can make is not a feature. It is a canary:** a synthetic
event asserted at script load, so that a run with no instrumentation *fails loudly* instead of
reporting "Safe."

---

## Part 4 — What blocks the DAE roadmap

The review's roadmap is sound. Four things block it, and only one is our fault.

**1. We have no malware corpus.** Our test samples are `InsecureBankv2` (a deliberately-vulnerable
*training* app) and `UnCrackable-Level1`. We have no Anatsa, Klopatra, Octo, Hook, Crocodilus or
Drinik. **Every proceed-gate in the roadmap depends on them.** Acquiring and detonating live
banking trojans is a legal, licensing and containment decision, not an engineering one.

**2. The eBPF telemetry floor is not implementable on our setup.** The review's Critical #1 (R1.1)
needs a kernel exposing eBPF/tracepoints — realistically Cuttlefish over KVM, or an ARM device.
We run a **standard Android Studio AVD (QEMU/ranchu, goldfish lineage)** with a stock kernel.
That is infrastructure we'd need to provision.

**3. Frida is currently our only collection path, and it is dead.** The roadmap treats Frida as
"optional enrichment" to be superseded by the eBPF floor. With the floor blocked by (2), that
framing doesn't hold for us yet.

**4. Scope.** The checklist is ~30 items. R1.1, R2.1 (fake C2), R4.1 (behaviour graph), R6.4
(virtualization), R9.2 (rule DSL) and R8.2 (ML attribution) are each multi-week efforts on their
own.

---

## Part 5 — Honest scorecard

Scored twice, because conflating them is how we got here.

| Dimension | The design | What's actually running |
|---|---:|---:|
| Architecture | 8 | 7 |
| Scalability | 6 | 6 |
| Practicality | 6 | 4 |
| Maintainability | 6 | 5 |
| Research value | 8 | 7 |
| Innovation | 6 | 5 |
| Malware analysis effectiveness | 6 | **3** |
| Frida usage | 7 | **4** |
| Explainability | 8 | 7 |
| Enterprise readiness | 5 | **3** |

A separate 17-requirement audit of the agentic pipeline scored **82%** (11 Full, 6 Partial).
Notably, an adversarial re-check **overturned two grades the first pass had marked complete** —
self-assessment is not reliable, and we should assume that applies to us generally.

---

## Part 6 — What I'd do next, in order

Not the roadmap order. The order that makes the roadmap *measurable*.

1. **Make hooks fire.** Probably a one-line experiment. Blocks literally everything.
2. **Add a canary hook.** A zeroed run must fail loudly, never render as "Safe."
3. **Versioned event schema + collection/detection split** (R9.1 + Layer 5). Pure refactor, no new
   infrastructure, and it's the prerequisite for every later item.
4. **Golden-trace harness** (R9.4) using synthetic fixtures, so the machinery exists before real
   samples arrive.
5. **Correlation + workflow reconstruction** (R4.1/R4.2/R5.1). Needs no new infrastructure, and
   replaces hook-counting with the thing that actually constitutes fraud intelligence.
6. **Scaffold the eBPF collector** behind the schema; real implementation pending hardware.

Steps 1–5 are all achievable on the hardware we already have.

---

## Part 7 — The uncomfortable summary

We have roughly **20 subsystems** — YARA memory scanning, MITRE mapping, three threat-intel
integrations, IOC collection, screenshot management, a replay engine, a permission orchestrator,
network capture, anti-analysis detection, two LLM paths, hybrid Monkey mode, JWT auth, a React
dashboard — standing on a dynamic engine that **emits zero events**.

That ratio is the diagnosis. We built breadth to look complete while the depth that makes it real
was broken and silent.

**We are not as far along as the demo suggests. We are also not starting over.** The static
pipeline works, the determinism guarantee is real and rare, and the exploration design is sound.
What's missing is that the dynamic engine has never actually measured anything, and until it does,
no claim we make about detection quality is testable.

One working dynamic engine with a stated false-positive rate is worth more to a bank than twenty
subsystems and a 0.0 score.

---

*Compiled from direct source inspection and live execution against a Pixel_6 AVD
(x86_64, android-37.1, 16 KB pages, frida 17.16.4). Reproducible from the current repository state.*
