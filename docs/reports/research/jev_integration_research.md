# Jev Integration Research: SUDARSHAN Agentic Explorer

This document explores whether TypeSafe Jev (a specialized LLM for UI navigation) can replace or supplement Gemini as the fast decision-making model within SUDARSHAN's `AgenticExplorer`.

## A. Research Findings
TypeSafe Jev is a "System One" decision model built for UI automation and statement evaluation, rather than text generation. It operates by taking a system state (like an accessibility tree) and a predefined array of candidate actions, and outputting a strongly-typed choice (a specific action ID) alongside confidence scores. By omitting prose generation and utilizing constrained decoding or a parallel diffusion pass, Jev achieves extremely low latency (often 200–500ms) compared to general-purpose LLMs like Gemini or GPT-4.

Sources:
- TypeSafe AI / Jev documentation (Tom's Hardware, ExplainX.ai, Daily.dev).
- Open-source implementations: `jev-mobile`, `Mobilerun`, `Droidrun` (GitHub).
- Automation patterns: Browser Use, Jev Ultrafast architectures (MarkTechPost, ScriptByAI).

## B. Existing Jev Architecture
1. **Perception**: A snapshot of the Android UI tree is captured.
2. **Candidate Generation**: The UI tree is flattened into a deterministic array of actionable elements (e.g., `[{"id": 1, "type": "TAP", "bounds": "..."}]`).
3. **Inference**: Jev receives the goal, the UI context, and the exact candidate array. It returns a strongly-typed selection (`Choice` primitive) matching an ID from the array, plus a confidence `Score`.
4. **Execution**: A native driver intercepts the choice, maps the ID back to the physical UI coordinates, and executes it.
5. **Verification**: A post-action snapshot evaluates if the system state changed as intended.

## C. SUDARSHAN Current Architecture
SUDARSHAN currently utilizes a complex pipeline centered around Gemini and deterministic graph exploration:
1. **Perception**: `PerceptionPipeline` extracts UI XML (`uiautomator dump`), Frida events, and conditionally takes screenshots (Vision/Level 5) if the XML is poorly labeled.
2. **Graph/Memory**: `ScreenGraphBuilder` tracks visited states. `ExplorationEngine` constructs `ActionItem` candidate lists for the current screen.
3. **Planner**: `AgentPlanner` invokes Gemini 2.0 Flash to pick an action. A deterministic `FallbackPlanner` operates when Gemini fails or is bypassed. `ActionDispatcher` routes the semantic intent.
4. **Execution**: `ToolExecutor` executes ADB commands (e.g., `tap`, `type_text`, `scroll`).
5. **Verification**: `DeviceStateProbe` verifies state changes to confirm action success before advancing the loop.

## D. Architecture Comparison

| Feature | Current SUDARSHAN (Gemini + Graph) | Proposed Jev Integration |
| :--- | :--- | :--- |
| **Model Type** | System 2 (General reasoning, slower) | System 1 (Reflexive, typed JSON, fast) |
| **Latency** | 7-15s per iteration (due to reasoning tokens) | < 1s expected |
| **Output** | Free-form JSON parsed dynamically | Guaranteed schema-validated `Choice` |
| **Candidate Action Scope** | Gemini can propose open-ended tools, filtered by `select_canonical_action` | Jev ONLY selects from a bounded list provided by `ExplorationEngine` |
| **Security / Containment** | Planner can technically hallucinate arbitrary inputs | Structurally contained to predefined allowed actions |

## E. Integration Architecture
SUDARSHAN already separates UI parsing (`ExplorationEngine`/`PerceptionPipeline`) from execution (`ToolExecutor`). Integrating Jev does not require an architectural rewrite.

**The Pipeline:**
1. `PerceptionPipeline` observes the screen.
2. `ExplorationEngine` generates a deterministic list of `ActionItem`s (e.g., all clickable nodes, text fields).
3. The **Jev Adapter** formatting layer serializes these `ActionItem`s into the Jev input schema.
4. **Jev Inference** evaluates the array against the `Goal` and returns a `choice_id`.
5. The **Jev Adapter** maps `choice_id` back to the original `ActionItem`.
6. `ActionDispatcher` and `ToolExecutor` execute the action normally via ADB.
7. `ActionVerifier` confirms the result.

## F. Required Adapter Layer
We need a new module: `sudarshan_core/engines/agentic/jev_planner.py`.
This class will implement the same interface as `AgentPlanner` (`async def decide(...)`).

It requires:
- `_serialize_candidates(obs: Observation, engine: ExplorationEngine) -> List[Dict]`
- `_invoke_jev_api(...) -> Dict`
- `_deserialize_choice(...) -> Dict[str, Any]` (matching SUDARSHAN's `ToolExecutor` format).

## G. Candidate-Action Schema
SUDARSHAN's `ActionItem` maps cleanly to Jev candidates:
```json
[
  {"id": "n0", "type": "TAP", "label": "Login", "role": "submit"},
  {"id": "n1", "type": "INPUT_TEXT", "label": "Username", "field_kind": "username"},
  {"id": "sys_back", "type": "BACK", "label": "Device Back Button"}
]
```

## H. Jev Input Schema
```json
{
  "system_goal": "GOAL_TRIGGER_LOGIN",
  "screen_context": "com.example.bank/LoginActivity",
  "candidates": [ /* Array from G */ ],
  "previous_action_failed": false
}
```

## I. Jev Output Schema
```json
{
  "selected_id": "n1",
  "input_text_value": "testuser",  // Only populated if type == INPUT_TEXT
  "confidence": 0.92
}
```

## J. Action Validation Design
SUDARSHAN's `ActionDispatcher` remains the authority. When Jev returns `n1`, the adapter retrieves the full `ActionItem` for `n1` from the current graph node. It ensures `n1` is a statically identified UI node. The executor then runs `_tool_tap` using the stored `ActionItem.center_x, center_y`. Jev never supplies raw coordinates.

## K. Verification Design
Unchanged. SUDARSHAN's existing `ActionVerifier` (using `DeviceStateProbe`) captures the before/after DOM and Activity. If Jev clicks a dummy button, `verify_action()` returns `VerificationOutcome.FAILED`.

## L. Failure/Retry Design
Unchanged. If `ActionVerifier` returns `FAILED`, the `ExplorationEngine` marks that `ActionItem` as `failed: True`. On the next iteration, the Jev Adapter will either omit that `ActionItem` from the candidate list or append a tag `[PREVIOUSLY_FAILED]`, forcing Jev to choose an alternative.

## M. Security Considerations
Jev is exceptionally safe for malware analysis. Because it only evaluates a pre-populated list of candidates, it cannot hallucinate shell commands. If SUDARSHAN does not provide `INSTALL_APK` in the candidate list, Jev physically cannot invoke it. All sandbox containment boundaries remain intact.

## N. Malware-Analysis-Specific Limitations
Jev is primarily trained on standard UI patterns. Malware often uses heavily obfuscated, custom-drawn, or deeply nested WebViews (e.g., phishing overlays) that do not expose clean accessibility trees.
When `LABELED_NODE_FRACTION_THRESHOLD` triggers SUDARSHAN's Level 5 Perception (Vision), Jev's standard tree-based selection will fail.

## O. Experimental Methodology
We can implement `JevPlanner` alongside `AgentPlanner`. We will introduce an environment variable `SUDARSHAN_PLANNER_MODE=jev`.
We will run identical malware samples from `VIDE` through both modes.

## P. Benchmark Design
We will evaluate using SUDARSHAN's existing `BenchmarkCollector`.
1. Run Corpus A with `GEMINI_MODEL=gemini-2.5-flash`.
2. Run Corpus A with `SUDARSHAN_PLANNER_MODE=jev`.

## Q. Metrics to measure
1. **Decision Latency**: Measured in `_agent_loop` per iteration (target: <1s vs 12s).
2. **Exploration Depth**: Max graph depth reached (`coverage_metrics()`).
3. **Goal Completion Rate**: How often `FraudGoal` sequences finish.
4. **Boundary Hits**: Does Jev accidentally trigger `SAFETY_BOUNDARY_REACHED` more often?

## R. Expected Bottlenecks
- **Vision Fallback**: Jev cannot see images. If the UI is obfuscated XML, Jev will fail where Gemini (multimodal) might succeed via screenshot analysis.
- **Complex Text Generation**: If a malware sample asks for a complex contextual reply (e.g., a specific captcha format), Jev's typed inputs might be too rigid.

## S. What should remain Gemini/LLM-based
- **Vision-based Perception (Level 5)**: When XML fails, Gemini's screenshot analysis is mandatory.
- **Goal Replanning**: High-level strategic pivots (e.g., determining the semantic meaning of an unknown screen) might still require Gemini if Jev's confidence is low.
- **Field Taxonomy (`field_classifier.py`)**: Resolving complex `field_type` values still benefits from LLM reasoning.

## T. What should be delegated to Jev
- **Standard UI Navigation**: Clicking tabs, dismissing alerts, pressing back, accepting permissions, standard form filling.
- **High-frequency Graph Traversal**: Rapidly mapping out the valid UI branches before invoking Gemini for the "hard" screens.

## U. What should remain deterministic
- **The Graph Engine** (`ExplorationEngine`): Tracking visited nodes, loop detection, and backtracking rules.
- **Execution** (`ToolExecutor`): Firing ADB commands.
- **Verification** (`ActionVerifier`): Proving state changes.
- **Verdict/Scoring** (`RiskEngine`): AI must NEVER score the malware.

## V. Whether a prototype should be built
**Yes.** The architecture separation in SUDARSHAN makes this a clean integration. The potential latency reduction (12s -> 1s per step) would dramatically increase the number of UI states SUDARSHAN can search within its strict 300s sandbox timeout.

## W. Exact Implementation Phases
1. **Phase 1: Adapter Skeleton**: Create `jev_planner.py` implementing `AgentPlanner` interface.
2. **Phase 2: Serialization**: Build translation logic to map `ExplorationEngine`'s `ActionItem` list into Jev's JSON array format.
3. **Phase 3: Execution Mapping**: Ensure Jev's `Choice` cleanly maps back to `ActionDispatcher`.
4. **Phase 4: Confidence Gating**: Implement logic to fallback to Gemini if Jev `confidence < 0.8`.
5. **Phase 5: Evaluation**: Run against `banking-baseline-corpus` and compare `BenchmarkCollector` metrics.
