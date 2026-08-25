# Dynamic Analysis 2.0 — dumb victim, smart investigator, strict sandbox

Status key used throughout: **[VERIFIED]** = reproduced in this repo,
**[IMPLEMENTED]** = code exists and is unit-tested but has not run against a
live emulator in this cycle, **[GAP]** = known missing.

This document records what changed in this cycle and, just as importantly, what
did not. Nothing below claims live validation, because no emulator run was
performed in this cycle.

---

## 1. Root cause of shallow exploration

Two defects, both in `shared/sudarshan_core/engines/agentic/exploration_engine.py`.
Both were found by running the shipped tests, not by reading the code.

### 1.1 The affirmative "boost" was a demotion **[VERIFIED]**

`ActionPrioritizer.rank_actions()` ended with:

```python
affirmative.priority = min(100, affirmative.priority + 15)
```

`score_action()` is an open-ended ranking signal, not a 0–100 scale. Security-
relevant call-to-actions accumulate large bonuses, so the clearer an action read
as *Install / Allow / Accept*, the higher it scored — and the harder this clamp
knocked it down.

Measured on the shipped fixture:

| action | raw score | after "boost" |
| --- | ---: | ---: |
| `Install update` | **159** | **100** |
| `Help` | 124 | 124 |

So the naive victim clicked **Help** instead of **Install**. This is the
mechanism behind the reported "New Update Available → [INSTALL] → scanner
stops" symptom: the update branch was never entered.

**Fix:** the boost adds (`_AFFIRMATIVE_BOOST = 15`) and never clamps.

### 1.2 `get_next_action()` teleported between states **[VERIFIED]**

When the current state had no unexplored actions, the engine looked up any other
state that did and returned *that state's* action:

```python
pending = self._pending_state_id()
if pending and pending != sid:
    self._current_state_id = pending
    return self.get_next_action(pending, memory)   # a tap for another screen
```

The device was still on the old screen. The returned tap named a control that
was not present, so it could not match, `record_action()` never resolved it, and
the same action was selected again — forever.

Measured on the mock app: **20 of 30 actions** were spent tapping `Continue` on
a Settings screen with no Continue button, and the update branch was never
reached.

**Fix:** `_navigate_toward()` emits a bounded `press_back` toward the pending
state and clears `_current_state_id` so the next `observe()` re-identifies where
we actually landed. An action is only ever returned for the screen we are on.

**Effect on the shipped mock app:**

| | before | after |
| --- | --- | --- |
| screens reached | 4 of 8 | **8 of 8** |
| workflows discovered | none | `update_flow`, `vpn_flow`, `external_apk_flow` |
| wasted actions | 20 / 30 | 0 |

---

## 2. Secondary payloads — §19 / §20 **[IMPLEMENTED]**

### The gap

`ExplorationGraph.record_secondary_apk()` existed and had tests. **Nothing in
the production path ever called it** — the only callers were in
`tests/unit/test_deep_exploration.py`. There were also no Frida hooks for
downloads or install requests. A dropper could fetch a payload, write it to
storage and ask Android to install it, and the run reported nothing.

An API with no producer is worse than a missing feature: it looks like coverage.

### What was added

**Frida agent** (`frida_hooks/banking_trojan.js`) — three new hooks:

| hook | what it observes |
| --- | --- |
| `FileOutputStream.apkWrite` | an APK being written to storage |
| `DownloadManager.enqueue` | a background download being queued |
| `Intent.installPackageRequest` | an install being *requested* of Android |

`DownloadManager.enqueue` deliberately does **not** report a URL. The
destination lives in a private field of `Request` and is not reliably readable
across API levels; the URL is recovered from the network hooks, which do see it.

**Producer** (`engines/agentic/secondary_payload.py`) — `SecondaryPayloadTracker`
consumes those events, and on request pulls the artifact through the sandbox
provider's own adb, hashes it (SHA-256, chunked), and reads the child package
name via androguard.

**Wiring** — fed from `AgenticExplorer._on_frida_event`, so it sees the whole
runtime stream rather than whatever the agent loop happens to drain. Preserved
in `flush_artifacts()`, written to `secondary_apks.json`, surfaced in
`get_reports()["secondary_apks"]`.

### The status ladder

```
DETECTED -> DOWNLOADED -> HASHED -> INSTALL_REQUESTED -> INSTALLED -> ANALYZED
                                                          BLOCKED (terminal)
```

Promotion is monotonic; `BLOCKED` cannot be promoted out of. `install_requested`
and `install_confirmed` are kept as **separate booleans** rather than folded
into the status, so a report can say "requested but not confirmed" without the
reader inferring it from an enum. This is the §34 distinction that matters most:
*installation requested* and *malware installed* are different claims, and only
one of them is usually supported.

### Safety

* Never installs, launches, or deletes anything — only `stat` and `pull`.
* Uses the sandbox provider's adb; never opens its own path to the device.
* Bounded: 8 payloads per run, 200 MB per artifact. An oversized file is
  `BLOCKED` **without** being pulled — pulling it would be the DoS.
* A failed pull records a note and leaves the payload at the rung it reached.
  It never fabricates a hash.

---

## 3. Gemini fallback telemetry **[VERIFIED]**

`fallback_used` was derived from `tried_fallback`, which is only set when the
fallback sits at index > 0. While the primary is in cooldown it is filtered out
of `_ordered_slots()` entirely, so the fallback becomes index 0 — and the whole
cooldown window was recorded as normal primary traffic. Now: the fallback served
it and a primary is configured, therefore `fallback_used` is true.

---

## 4. Boundary screens stay explorable **[VERIFIED]**

`test_external_in_separate_graph` asserted the package installer is routed to
the external (non-explorable) graph. That would leave `Install` / `Cancel`
unclickable, so the victim could never follow an install flow and the entire
secondary-APK chain would be unreachable — contradicting both §1 and
`test_deep_exploration.py`, which requires clicking "Install application".

The implementation was right and the test was stale. Ownership decides
*recording*; whether a boundary screen is interactive decides *explorability*.
The test was replaced with two that pin the real split:

* package installer / permission / settings dialogs → stay in the main graph
* an unrelated third-party app → `EXT-` external graph, recorded not explored

---

## 5. UI — progressive disclosure

The technical view rendered **41 `SocCard` panels in one scroll, every one
expanded by default** (`useState(true)`). Everything was on screen, so nothing
was.

| change | file |
| --- | --- |
| Four tabs: Summary / Static details / Behaviour & code / Network & relations | `pages/TechnicalView.tsx`, `components/investigation/AnalysisTabs.tsx` |
| Capability tags, separating **observed** from **declared** | `components/investigation/BehaviorTags.tsx` |
| Blast-radius relations graph (inline SVG, no new dependency) | `components/investigation/RelationsGraph.tsx` |
| Numeric activity tiles | `components/investigation/ActivitySummary.tsx` |
| Secondary payload panel, requested vs confirmed shown separately | `components/investigation/SecondaryApkPanel.tsx` |
| Severity accent on cards (was: identical grey boxes) | `components/ui/Card.tsx` |
| Tables > 5 rows start collapsed | `useRowAccordion` in `TechnicalView.tsx` |

Two honesty rules are enforced in the UI layer:

* A behaviour tag names a **capability**, never a verdict. `reads-sms` means the
  capability is present; whether an OTP was intercepted is a finding with
  evidence behind it.
* Runtime-observed and manifest-declared render differently (solid vs dashed
  outline). In the relations graph, statically extracted hosts are hollow and
  dashed; hosts actually contacted are filled. When the ring is truncated,
  observed nodes are kept first.

---

## 6. Configuration

| variable | default | meaning |
| --- | --- | --- |
| `SUDARSHAN_CONTENT_SETTLE_SECONDS` | `1.5` | in-content settle after `wait_for_idle()` |
| `SUDARSHAN_AGENT_ACTION_BUDGET` | `120` | total actions per run |
| `INVESTIGATION_MAX_ACTIONS_PER_GOAL` | `4` | actions one stage may spend |
| `FRIDA_ANALYSIS_DURATION` | `300` | seconds the sample is exercised |

**Note:** `.env.example` documents `SUDARSHAN_AGENT_ACTION_BUDGET=60`, but the
code default moved to `120` when the budget was relocated into
`ExplorationBudget`. A machine whose `.env` does not set these three values gets
the code defaults, not the documented ones.

---

## 7. What is NOT established

Stated plainly, because a green suite invites the opposite assumption.

* **No live emulator run was performed in this cycle.** Every result above is
  from unit tests and the shipped mock app. The exploration fix is verified
  against `MockRTOApp`, not against a real APK.
* **The three new Frida hooks have never fired on a real device.** They are
  written against the documented Android APIs and the agent's existing hook
  pattern, and a test asserts the Python side listens for exactly the names the
  agent emits — but "the hook installs and fires on Android 17" is unverified.
* **No secondary APK has been preserved end-to-end.** `preserve()` is tested
  against an injected fake adb. The androguard identification path in
  particular has not run on a real child APK.
* **`confirm_installed()` has no caller.** Promotion to `INSTALLED` requires
  someone to check the device's package list after an install request; that
  producer does not exist yet. Today no payload can reach `INSTALLED`, which is
  the safe direction to be wrong in, but it is a gap.
* **`ANALYZED` is unreachable.** Recursive child analysis (§20) is not
  implemented; a preserved child is hashed and identified, not analyzed.
* **Frontend: 18 pre-existing failures** in `src/test/AuthFlowMatrix.test.tsx`,
  untouched by this cycle. `vitest` and `@testing-library` were not installed in
  `node_modules` before this cycle, so those tests had never run here.
* **4 pre-existing backend failures** remain (`test_baselines_api`, 3 ×
  `test_pdf_generator`). The PDF three assert a page layout the generator no
  longer produces; diagnosing that is out of this cycle's scope and they are
  *not* the `FRSBarMeter` TypeError previously recorded — that error no longer
  occurs.
