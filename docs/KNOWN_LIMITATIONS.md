# SUDARSHAN — Known Limitations & Operational Boundaries

> **Authoritative Technical Limitations Catalog**  
> **Source Repository**: `SanTiwari07/Sudarshan`  
> **Last Verified Against Active Codebase**: 2026-08-25  

This document catalogs the known technical limitations, environmental constraints, and operational boundaries of the **SUDARSHAN** platform as it exists today.

---

## 1. Dynamic Analysis & Sandbox Limitations

### 1.1 Inconclusive Dynamic Runs & Dormant Malware
* **Affected Component**: Dynamic Sandbox (`shared/sudarshan_core/engines/frida_sandbox.py`), Risk Engine (`shared/sudarshan_core/engines/risk_engine.py`).
* **Current Behavior**: Evasive banking trojans (e.g., Anubis, Cerberus, Octo) frequently employ sleep timers, sensor checks, or wait for specific C2 activation commands before unpacking secondary payloads. During a 300-second analysis window, the sandbox may capture 0 weighted behavioral events.
* **Engine Response**: The system detects that the run was inconclusive (`dynamic_conclusive=False`), excludes the dynamic axis weight (0.35), renormalizes the remaining axes, and triggers the **Visibility Floor** or **Execution Assertion Matrix Floor** (`verdict="INCOMPLETE_EXERCISE"`), preventing an unobserved sample from falsely receiving a "Safe" rating.
* **Impact**: Full dynamic confirmation of stage-2 payload execution requires manual interactive triggering or longer execution windows.
* **Workaround**: Analysts can raise `FRIDA_ANALYSIS_DURATION` (e.g., to 600s) or utilize the investigation suggestions to manually inject triggers.

### 1.2 Single-Device Serial Concurrency Lock
* **Affected Component**: Frida Sandbox Controller (`shared/sudarshan_core/engines/frida_sandbox.py`, line 256 `_DEVICE_LOCKS`).
* **Current Behavior**: The system enforces an in-process asynchronous lock per device serial (`_DEVICE_LOCKS[serial]`). If multiple concurrent analyses target the same emulator/device, they are executed serially.
* **Impact**: High-concurrency analysis against a single Android emulator results in job queuing.
* **Workaround**: Deploy multiple emulator instances and configure device pools, or use the Enterprise Batch Scanner which automatically serializes batch jobs.

### 1.3 Pregrant Runtime Permissions Trade-off
* **Affected Component**: Permission Orchestrator (`shared/sudarshan_core/engines/permission_orchestrator.py`), Sandbox Config (`.env.example: SUDARSHAN_PREGRANT_PERMISSIONS=1`).
* **Current Behavior**: By default (`SUDARSHAN_PREGRANT_PERMISSIONS=1`), runtime permissions declared in the manifest are granted via `pm grant` prior to launching the application. This is necessary because legacy targetSdk apps cold-start into `ReviewPermissionsActivity`, which blocks process launching.
* **Impact**: Because permissions are already granted, Android does not display runtime permission request dialogs during exploration. The explorer cannot observe the interactive permission request event at runtime.
* **Workaround**: Set `SUDARSHAN_PREGRANT_PERMISSIONS=0` in `.env` if explicit UI observation of permission grant dialogs is required.

### 1.4 Frida 17 Java Global Deprecation
* **Affected Component**: Frida Hooks (`shared/sudarshan_core/engines/frida_hooks/`).
* **Current Behavior**: Frida 17+ removed the global `Java` object. Raw uncompiled `.js` hook files fail with `ReferenceError: 'Java' is not defined`.
* **Remediation**: The dynamic controller strictly loads the pre-compiled CommonJS bundle `banking_trojan.bundle.js` (compiled with `frida-java-bridge`). Loading the raw `.js` script is blocked.

---

## 2. Network & Container Topology Boundaries

### 2.1 Genymotion vs. Docker Host-Only Networking
* **Affected Component**: Sandbox Provider (`shared/sudarshan_core/sandbox/genymotion.py`), Docker Compose (`docker-compose.yml`).
* **Current Behavior**: On Windows/macOS, Docker Desktop proxies `host.docker.internal` to host loopback (`127.0.0.1`), whereas Genymotion Desktop runs VMs on VirtualBox host-only adapters (e.g., `192.168.56.101`). Setting `ADB_HOST=host.docker.internal` fails for Genymotion.
* **Remediation**: The sandbox auto-detect provider (`auto.py`) resolves Genymotion VM IPs directly from `adb devices -l`.

### 2.2 Microservice Internal Job State Persistence
* **Affected Component**: Analysis Engine Microservice (`analysis-engine/app/main.py`, line 183 `JOBS`).
* **Current Behavior**: The async job dictionary (`JOBS`) inside `analysis-engine` is held in process memory with a TTL eviction policy (`JOB_RETENTION_SECONDS=3600`, `MAX_RETAINED_JOBS=200`).
* **Impact**: If the `analysis-engine` container restarts while an async job is running, in-flight microservice jobs are lost. The gateway handles this by maintaining persistent records in `analysis_jobs` in SQLite.
* **Workaround**: Microservice is pinned to `--workers 1` in `entrypoint.sh` to prevent multi-worker 404s.

---

## 3. AI & LLM Provider Boundaries

### 3.1 Thinking Model Token Consumption
* **Affected Component**: Gemini Provider (`shared/sudarshan_core/ai/gemini_provider.py`), Agent Planner (`shared/sudarshan_core/engines/agentic/planner.py`).
* **Current Behavior**: When using Gemini 3.x Flash thinking models (`gemini-3.6-flash`), the model allocates internal tokens to reasoning before outputting JSON. Setting `max_output_tokens=512` truncates the response mid-stream.
* **Remediation**: The system enforces `SUDARSHAN_AGENT_MAX_OUTPUT_TOKENS=2048` in `.env.example` and automatically strips incompatible `thinking_config` knobs when failing over to `gemini-2.5-flash`.

### 3.2 External Threat Intelligence API Rate Limits
* **Affected Component**: Threat Correlator (`shared/sudarshan_core/services/threat_correlator.py`).
* **Current Behavior**: Free public tier API keys for VirusTotal impose a strict quota of 4 requests/minute.
* **Remediation**: SUDARSHAN implements a 24-hour persistent TTL cache in SQLite (`ioc_cache`). Duplicate queries across samples within 24 hours are served instantly from cache without consuming API quotas.

---

## 4. Decompilation & Binary Recovery Limits

### 4.1 Packed / Native-Only Binaries
* **Affected Component**: Static Pipeline (`shared/sudarshan_core/analyzers/apk_analyzer.py`, `jadx_engine.py`).
* **Current Behavior**: Samples that ship all malicious logic in compiled native libraries (`.so`) or use commercial packers (SecNeo, Qihoo, Bangcle) produce stub Java decompilation in JADX.
* **Engine Response**: The static analyzer flags native library loading (`System.loadLibrary`), scores high string entropy, flags `has_concealed_payload`, and relies on dynamic behavioral hooks to observe runtime activities.
