# SUDARSHAN Limitations

This document captures the known limitations and environment constraints of the Sudarshan Hybrid Dynamic Analysis Engine at the conclusion of Phase 7.

## 1. Frida Environment Limitation
- **What:** Live Frida runtime events are currently blocked.
- **Why:** The test Android emulator environment lacks root access and the `frida-server` daemon. 
- **Impact:** Dynamic instrumentation features (like Accessibility abuse detection) cannot fire events natively in the live pipeline. The engine relies solely on UI exploration and logcat/dumpsys bounds.
- **Current Mitigation:** Pipeline logic is 100% verified using offline mock events in `verify_runtime_pipeline.py`.
- **Future Work:** Deploy Sudarshan onto a rooted Corellium emulator or a physical rooted device running `frida-server`.

## 2. Hosted Jev Dependency
- **What:** Jev integration relies on an external hosted API (`api.typesafe.ai`).
- **Why:** The fast multimodal capabilities of Jev are delivered as SaaS.
- **Impact:** Analysis stops or relies entirely on the Gemini/deterministic fallbacks if network connectivity drops, the endpoint is down, or API credit is exhausted.
- **Current Mitigation:** `HybridPlanner` handles `JEV_NETWORK_ERROR` and `JEV_MISSING_CREDENTIALS` by gracefully cascading to `AgentPlanner` (Gemini) or the deterministic fallback graph.
- **Future Work:** Cache responses aggressively or implement a local Jev-lite model if data residency rules prohibit SaaS.

## 3. Difficult / Unlabelled UI
- **What:** Certain UI components lack uiautomator tree nodes or content descriptions (e.g. WebViews, custom React Native canvas layers, heavily obfuscated obfuscators).
- **Why:** Android accessibility services cannot extract semantic meaning from raw canvas draws.
- **Impact:** Jev may reject these inputs due to poor candidate extraction, leading to incomplete form fields.
- **Current Mitigation:** The system detects non-standard inputs (like WebViews) and sets the `vision_reason` flag, skipping Jev entirely to use Gemini's screenshot-vision capabilities to infer coordinate bounds.
- **Future Work:** Train Jev specifically on raw coordinate extraction from pixel bounding, bypassing uiautomator dependencies.

## 4. Emulator/Device Detection (Anti-Analysis)
- **What:** Sophisticated malware can detect the Android Emulator.
- **Why:** Checking for `qemu`, `goldfish`, battery status, sensor count, and build properties is standard malware behavior.
- **Impact:** Malware may refuse to unpack its payload, displaying a benign UI. Sudarshan might classify it as low-risk (false negative).
- **Current Mitigation:** Sudarshan detects the detection (via `test_anti_evasion_api.py`) and reports that the app is evasive, flagging the analysis as potentially incomplete.
- **Future Work:** Integrate advanced sandbox cloaking (e.g., hiding Magisk, spoofing properties).
