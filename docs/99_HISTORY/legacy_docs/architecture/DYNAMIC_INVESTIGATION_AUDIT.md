# Dynamic Analysis Investigation Flow — Phase 1 Audit

Status: **Phase 1 complete. No production code modified in this phase.**

Every claim below was verified by reading the code or by a live run on
`emulator-5554` (Android 17 / API 37, x86_64) during this session. Anything not
verified is marked **NOT VERIFIED**.

---

## 1. Root cause

> **The static→dynamic bridge does not exist. The Dynamic Analysis Engine never
> learns what the APK declared.**

Three facts, each checked in the source:

1. `run_frida_analysis(apk_path: str, package_name: Optional[str] = None)`
   — [frida_sandbox.py:3062](../../shared/sudarshan_core/engines/frida_sandbox.py#L3062).
   There is **no parameter for static findings**, and none of its 10 call sites
   (`backend/app/routes/upload.py:752`, `analysis-engine/app/main.py:414`,
   `validation/runner.py:151`, …) passes any.

2. `FridaSandbox` has **no** `static_findings`, `declared_permissions`, or
   equivalent attribute. `grep -n "static_findings\|declared_permissions" frida_sandbox.py`
   returns nothing.

3. `AgenticExplorer.__init__` **accepts** `static_findings`
   ([agentic_explorer.py:149](../../shared/sudarshan_core/engines/agentic_explorer.py#L149))
   and forwards it into every `Observation`
   ([perception.py:332](../../shared/sudarshan_core/engines/agentic/perception.py#L332)) —
   but the construction site at
   [frida_sandbox.py:2902](../../shared/sudarshan_core/engines/frida_sandbox.py#L2902)
   **does not pass it**. So `self.static_findings` is `{}` on every real run.

The plumbing is built from the explorer downward and fed nothing from above.

This single gap is why the brief's items 5, 6, 7, 8, 10 and 11 are unfixable
today. The engine cannot compare declared vs. requested vs. granted permissions
because **it never receives the declared set**. It cannot build an expected
capability profile because it does not know the app's label, category, or
components. It cannot plan which branches matter because it has no static
signal to branch on.

Everything else in the brief is downstream of this.

### Secondary root cause

The investigation has **no state**. `AgenticExplorer.start()` is a flat
`while` loop: observe → plan → act → settle → repeat, bounded only by action
budget, time budget and Frida silence. There is no notion of "which stage of the
investigation am I in", so:

* permission handling is not a stage — it is whatever the planner happens to pick;
* there is nothing to branch on, so a calculator and a banking trojan get the
  identical treatment;
* nothing decides that an action *should* have been verified.

---

## 2. Current architecture (as built)

```
upload.py / main.py
      └─> run_frida_analysis(apk_path, package_name)          ← static findings stop here
              └─> FridaSandbox.run()
                    ├─ install → verify → resolve activity → launch ladder (5 steps)
                    ├─ attach Frida → canary → 66 hooks
                    ├─ RuntimeEventBus ──> EvidenceStore ──> evidence.json
                    │                 └──> AntiAnalysisDetector
                    │                 └──> ThreatCorrelatorListener
                    │                 └──> ScreenshotManager (conditional capture)
                    ├─ PermissionOrchestrator (pre-grants, blind)
                    ├─ AgenticExplorer.start(duration)
                    │     while budget:
                    │       PerceptionPipeline.observe()   5 levels, vision-gated
                    │       GoalTracker.next_priority_goal()   15 fraud goals
                    │       AgentPlanner.decide()          Gemini → FallbackPlanner
                    │       ToolExecutor.execute()         21-tool registry
                    │       (no verification)
                    ├─ WorkflowReconstructor.reconstruct()
                    ├─ visual_evidence.linker  ──> visual_evidence.json
                    └─ BFCI → risk_engine.calculate_risk_score()
```

### What already exists and works

Verified live this session unless noted.

| Component | State | Evidence |
| --- | --- | --- |
| Frida attach / 66 hooks / canary | works | live run, `script_loaded_v4_frida17` |
| RuntimeEventBus → EvidenceStore | works | `EVID-001` emitted and persisted live |
| ScreenshotManager + manifest | works | 19 screenshots + `manifest.json` flushed live |
| **VisualEvidenceRecord** | **already exists, richer than the brief's §19** | `visual_evidence/models.py`, 6 test files |
| visual_evidence linker | works | "Updated evidence.json screenshot links" live |
| **Action allowlist (§12)** | **already exists** | `TOOL_REGISTRY`, 21 tools; dispatcher rejects unregistered names |
| Prompt-injection sanitizer | exists | `agentic/sanitizer.py`, wired in perception |
| Dynamic status semantics (§25) | **works correctly** | failed runs reported `INSTRUMENTATION_FAILED`, never "clean" |
| Screen classifier | exists | `screen_classifier.py`, 7 types incl. OTP / accessibility / permission |
| WorldModel | exists | tracks login/OTP/overlay/permission screen hashes |
| GoalTracker | exists | 15 fraud goals, Frida-event driven |
| WorkflowReconstructor | exists | deterministic stage rules |
| Loop detection | exists but weak | see gap L1 |
| Crash recovery | exists but broken | see gap C1 |

**§12, §17, §19, §20, §23, §24 and §25 are substantially already implemented.**
Per rule §36 these must be extended, not rebuilt.

---

## 3. Gaps, with evidence

### G1 — Static findings never reach the dynamic engine (**root cause**)
Described above. Blocks §7, §8, §9, and all branch selection.

### G2 — No expected-capability model
`grep -rn "expected_for_app\|expected_capabilit\|UNEXPECTED_PERMISSION\|capability_profile"`
returns **zero hits** repo-wide. Nothing in the codebase models what an app
*should* need. §8 is entirely unimplemented.

### G3 — Permission handling is blind granting, not investigation
`PermissionOrchestrator` ([permission_orchestrator.py:134](../../shared/sudarshan_core/engines/permission_orchestrator.py#L134))
offers `grant_accessibility`, `grant_overlay`, `grant_device_admin`,
`grant_all_standard_permissions`. It:
* grants **before** launch (`Pre-granted 12 declared permission(s)` in the live log),
  which means the runtime permission dialog **never appears** — so the dialog
  the brief wants screenshotted is suppressed by our own code;
* writes a local `permissions.json` action log but **publishes no RuntimeEvent
  and creates no EvidenceRecord** (`Flushed 0 actions` live);
* never distinguishes declared / requested / granted;
* `grant_overlay` checks `"Error" not in out` — a string check, not a state query.

### G4 — No action verification layer (§6)
No `ActionVerification`/`verify_action` exists. `ToolResult.success` means "the
ADB command returned 0", not "the intended state change happened". A `click_text`
that hits nothing still reports success.
(`execution_assertions.py` is a different concern — whether the *sample* was
exercised, not whether an *action* worked.)

### G5 — Accessibility flow does not follow the analyst workflow (§10)
`grant_accessibility` opens Settings, dumps UI **only to compute an unused
`visible_in_ui` boolean**, then writes `settings put secure
enabled_accessibility_services` and returns `True` **unconditionally**
(`success = True` is hardcoded — [line ~245](../../shared/sudarshan_core/engines/permission_orchestrator.py#L245)).
It never verifies the service is enabled, and takes no screenshots. The brief's
`find_accessibility_service` / `verify_accessibility_enabled` do not exist.

### G6 — Loop detection detects but does not escalate
Observed live: `Loop detected on screen 29d4d7 - triggering backtrack action (1/2)`
fired **8+ times with the counter never advancing past 1/2**. Backtrack resets
the counter instead of escalating.

### G7 — Crash recovery was dead code (partially fixed this session)
`self.main_activity` was read at
[agentic_explorer.py:437](../../shared/sudarshan_core/engines/agentic_explorer.py#L437)
but **never assigned** → `AttributeError` swallowed by the surrounding
`except Exception`. And it dispatched `{"tool": "am_start"}`, which is **not in
TOOL_REGISTRY and has no handler** — so relaunch could never have worked.
*Both fixed earlier this session; the crash **classification** taxonomy of §15
remains unimplemented.*

### G8 — No investigation state machine (§4)
`investigation_controller.py` does not exist. The 17 states in §4 have no
counterpart. `GoalTracker`'s 15 goals are Frida-event-driven, not stage-driven,
and cannot express "we are in PERMISSION_ANALYSIS, only these actions are legal".

### G9 — No progress tracking (§13)
`CoverageTracker` counts screens/buttons/permissions but produces no
per-action progress signal, so nothing can tell a useful action from a wasted one.

### G10 — Screenshots lack investigation context
`ScreenshotRecord` has `stage`, but it is the DAE pipeline stage, not an
investigation state, and captions are generic — live output was
`"Screen state after explorer action - click_text:Search contacts"`, which
answers "what did I click", not §17's "what does this screenshot prove".

### G11 — Baseline vs instrumented comparison absent (§16)
No uninstrumented baseline run exists, so
`POTENTIAL_INSTRUMENTATION_SENSITIVE_BEHAVIOR` cannot be derived.

---

## 4. Files to change

| File | Change | Risk |
| --- | --- | --- |
| `frida_sandbox.py` | add `static_findings` param to `run_frida_analysis`; store on sandbox; pass to `AgenticExplorer`; **stop blind pre-granting** (make it a controller decision) | **HIGH** — 10 call sites; param must default to `None` |
| `agentic_explorer.py` | drive loop from controller; verify actions; record progress | HIGH — core loop |
| `permission_orchestrator.py` | emit RuntimeEvents; verify grants; real accessibility verification | MED |
| `screenshot_manager.py` | add investigation `stage` + `claim` linkage | LOW — additive |
| `tool_registry.py` / `tool_executor.py` | add `open_settings`, `enable_accessibility`, `enable_overlay`, `restart_app`, `wait` | LOW — additive |
| `planner.py` | accept candidate-action allowlist from controller | MED |
| `backend/app/routes/upload.py`, `analysis-engine/app/main.py` | pass static findings through | LOW |

## 5. Files to create

| File | Purpose |
| --- | --- |
| `engines/investigation_controller.py` | state machine + goal lifecycle (§4, §5) |
| `engines/permission_investigator.py` | declared vs requested vs granted (§7) |
| `engines/capability_profile.py` | expected-capability model (§8) |
| `engines/agentic/action_verifier.py` | deterministic verification (§6) |

## 6. Files NOT to change, and why

| File | Why |
| --- | --- |
| `risk_engine.py`, `bfci_scorer.py` | §21 — verdict semantics must not move |
| `event_bus.py`, `evidence_store.py` | §23 — schema reuse; additive fields only |
| `workflow_reconstructor.py` | §24 — already deterministic and correct |
| `visual_evidence/*` | §19 already implemented and richer than the brief; extend via linker inputs only |
| `frida_hooks/banking_trojan.js` | §22 — audit found no missing event; do not add hooks to solve orchestration |
| `yara_rules/*`, `yara_scanner.py` | out of scope |

---

## 7. Risks

1. **`run_frida_analysis` signature change** touches 10 call sites including two
   web services. Mitigate: keyword-only param defaulting to `None`; behaviour
   identical when omitted.
2. **Removing blind pre-granting changes BFCI inputs.** Today permissions are
   granted before launch; if the controller grants them reactively instead,
   samples may behave differently and scores may shift. Mitigate: keep
   pre-granting as the default, add reactive handling behind a flag, and
   measure both on the corpus before switching.
3. **The Gemini planner is currently unavailable** — the configured API key
   returns `401 UNAUTHENTICATED` and `.env` pins `gemini-3.6-flash` while
   `.env.example` says `gemini-2.5-flash`. All live measurements this session
   therefore exercised `FallbackPlanner` only. Controller work must not assume a
   working LLM.
4. **Screenshot counts will drop** once captures become milestone-driven (§18
   wants 5–15/run; live runs produced 19 mostly-generic ones). Report/PDF tests
   asserting counts may need updating.

---

## 8. Implementation plan

| Phase | Deliverable | Gate |
| --- | --- | --- |
| 2 | `capability_profile.py` + `permission_investigator.py` + the static bridge (G1, G2) | unit tests; corpus static run unchanged |
| 3 | `action_verifier.py` (G4) | unit tests |
| 4 | `investigation_controller.py` state machine (G8) | unit tests |
| 5 | Wire controller into `AgenticExplorer`; progress tracking (G9) | existing explorer tests still green |
| 6 | Permission + accessibility flows with verification and screenshots (G3, G5) | live run |
| 7 | Loop escalation + crash classification (G6, G7) | unit + live |
| 8 | Screenshot milestones + claim linkage (G10) | live run, 5–15 shots |
| 9 | Report/dashboard timeline (§31) | live run |
| 10 | Full regression | 497 unit + 1032 backend green |
| 11 | Live validation on 4 sample categories (§28) | recorded results |

**Phase 2 is ordered first because G1 blocks everything else.** Building the
controller before the static bridge would give it nothing to branch on.

---

## 9. Current test baseline (measured)

```
tests/unit                    497 passed, 12 skipped
tests/unit + backend/tests   1032 passed, 12 skipped, 5 failed
```

The 5 failures are **pre-existing and unrelated**, verified by reverting the
working-tree changes and reproducing them:
* 3 × `test_pdf_generator.py` — reproduce on HEAD
* `test_boundaries.py::test_invalid_env_override_is_ignored` — fails only
  because a real emulator is attached (`get_screen_size` returns the live
  1080×2400 instead of the 1080×1920 fallback)
* `test_baselines_api.py::test_admin_can_list_and_refresh`

## 10. Not verified

* Gemini-driven planning end-to-end — **NOT VERIFIED**, API key returns 401.
* Accessibility enable flow on API 37 — **NOT VERIFIED**; InsecureBankv2
  declares no accessibility service, so the path was never exercised live.
* Overlay / device-admin grants — **NOT VERIFIED** on this device.
* Banking-trojan live behaviour — **NOT VERIFIED**; no trojan has been detonated
  on the emulator in this session.
