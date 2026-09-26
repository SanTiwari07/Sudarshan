# Frida sandbox setup

How to prepare the Android guest and `frida-server` so SUDARSHAN's dynamic analysis can run.

Verified against the active codebase on **2026-08-27**.

- Full operations guide: [`../docs/06_OPERATIONS/HOW_TO_RUN.md`](../docs/06_OPERATIONS/HOW_TO_RUN.md)
- Engine design: [`../docs/02_ANALYSIS/DYNAMIC_ANALYSIS.md`](../docs/02_ANALYSIS/DYNAMIC_ANALYSIS.md)
- Backend service notes: [`README.md`](README.md)

The Android guest runs on the **host**, never inside a container. The analysis engine reaches it through the host ADB server.

---

## Prerequisites

| Requirement | Where it comes from | Notes |
| :--- | :--- | :--- |
| `frida` and `frida-tools` (Python) | Pinned in `backend/requirements.txt` and `analysis-engine/requirements.txt` | `frida==17.16.4`, `frida-tools==14.10.4`; installed in both images |
| `adb` | Installed in both Dockerfiles | The backend image pulls Google's platform-tools directly |
| Rooted Android guest | Your host machine | Genymotion Desktop or Android Studio AVD; Android 10/11, x86_64 |
| `frida-server` on the guest | Downloaded on first use | Must be **exactly** 17.16.4 to match the host package |

### Why the version is pinned

Two constraints collide:

- **Frida 17 removed the built-in `Java` global.** The Android bridge became an external module, so a classic `Java.perform` script fails with `ReferenceError: 'Java' is not defined`. Hook scripts must be bundled with `frida-java-bridge` via `frida-compile`, which is why the controller loads `banking_trojan.bundle.js` and not the raw `.js` source.
- **Frida 16 cannot link on a 16 KB page-size device** (`empty/missing DT_HASH/DT_GNU_HASH`), which rules it out for the `google_apis_ps16k` image this project targets.

17 is therefore mandatory, and host and guest versions must match exactly.

---

## Quick path

After the one-time guest setup below, the whole platform starts with:

```powershell
.\start.ps1 -Detach
```

`start.ps1` restarts the ADB server, elevates `adbd` to root, kills any stale `frida-server` and starts a fresh instance, then brings up Compose.

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned   # first run only, if Windows blocks the script
```

---

## Guest setup

### Genymotion Desktop (default)

1. Create and start a rooted x86_64 device (Android 10 or 11). Genymotion images are rooted by default.
2. Confirm the endpoint:

   ```powershell
   adb devices -l
   # 192.168.56.101:5555   device   product:vbox86p ...
   ```

3. Genymotion already exposes a TCP endpoint, so `adb tcpip` is not needed. It is also blocked by the ADB gateway policy (`shared/sudarshan_core/security/adb_gateway.py`) and cannot be issued from analysis code.

### Android Studio AVD

1. **Virtual Device Manager → Create Device → Pixel 6 → Next.**
2. Choose a system image **without Google Play** — Play images cannot be rooted. For 16 KB page alignment, use API 33/34 x86_64 `google_apis_ps16k`.
3. Start it, then:

   ```powershell
   adb root
   adb shell whoami       # must print: root
   adb shell setenforce 0
   adb shell getenforce   # Permissive
   ```

### Deploy `frida-server`

Automated, and the recommended path:

```powershell
python scripts/setup_dynamic_analysis.py --serial <DEVICE_SERIAL>
```

It accepts `--serial`, `--avd`, `--push-server` / `--no-push-server` and `--skip-start`.

The analysis engine can also fetch the ABI-matched binary itself into `FRIDA_SERVER_DIR` (default `/opt/frida-cache`, bind-mounted from the host `./tools`), so it is downloaded once per machine rather than once per image build. `tools/` is gitignored because the binary is roughly 106 MB, over GitHub's file limit.

Manual equivalent:

```powershell
# Download frida-server-17.16.4-android-x86_64.xz from
# https://github.com/frida/frida/releases/tag/17.16.4 and extract it
adb root
adb push frida-server-17.16.4-android-x86_64 /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
adb shell "nohup /data/local/tmp/frida-server -l 127.0.0.1:27055 > /dev/null 2>&1 &"
frida-ps -D <DEVICE_SERIAL>
```

Port 27055 is the project default (`FRIDA_PORT` / `SUDARSHAN_FRIDA_PORT`), not Frida's stock 27042. `FRIDA_LISTEN_HOST` defaults to `127.0.0.1` and should not be widened.

---

## Configuration

```env
SANDBOX_PROVIDER=auto            # auto | genymotion | android_avd | physical
DEVICE_SERIAL=                   # pin when more than one device is attached
ADB_SERVER_SOCKET=tcp:host.docker.internal:5037
ADB_HOST=                        # leave empty on Docker Desktop
ADB_PORT=5555
FRIDA_PORT=27055
FRIDA_VERSION=17.16.4
FRIDA_SERVER_DIR=/opt/frida-cache
FRIDA_LISTEN_HOST=127.0.0.1
ROOT_REQUIRED=true
AUTO_CONNECT=true
FRIDA_ANALYSIS_DURATION=240      # exploration window, seconds
```

Leave `ADB_HOST` empty on Docker Desktop for Windows and macOS. Genymotion VMs live on a VirtualBox host-only adapter that `host.docker.internal` cannot reach; the auto-detect provider resolves the endpoint from `adb devices -l` instead.

---

## Verification

```bash
# From the host, checks the whole chain including inside the engine container
python scripts/preflight.py --container
```

```http
GET http://localhost:8000/api/v1/sandbox/status
Authorization: Bearer <token>
```

A healthy response reports the resolved provider, device serial, ADB reachability, the Frida version and whether the hook bundle is present. Preflight is the better diagnostic: it names the specific failing link rather than reporting the sandbox as simply unavailable.

---

## Instrumentation flow

```text
APK uploaded
     │
     ▼
Static analysis (Androguard, APKTool, JADX, optional MobSF)
     │
     ▼
Investigation manifest  -  the minimal hook profile this sample needs
     │
     ▼
[FRIDA SANDBOX]
  ├─ Install via ADB, pre-grant manifest permissions
  ├─ Five-step launch ladder; the successful rung is recorded as launch_method_used
  ├─ Resolve the exact PID and require a stability window before attaching
  ├─ ART deoptimization, then install hooks and verify them
  ├─ Load banking_trojan.bundle.js (compiled with frida-java-bridge)
  └─ AgenticExplorer drives a 15-stage fraud goal graph while events stream in
     │
     ▼
Evidence store  →  BFCI v2  →  deterministic risk engine  →  case
```

### BFCI v2 weights

Seven categories, summing to 1.0. `code_execution` carries 0.10; the six original categories are scaled by 0.90 so their relative ordering is unchanged from the validated model.

| Category | Weight | Event cap |
| :--- | ---: | ---: |
| Accessibility abuse | 0.315 | 3 |
| SMS / OTP interception | 0.225 | 2 |
| Overlay phishing | 0.180 | 2 |
| Banking app interaction | 0.090 | 3 |
| Network / C2 | 0.045 | 10 |
| Persistence | 0.045 | 2 |
| Code execution | 0.100 | 2 |

Each component is volume-aware on a logarithmic scale — `min(ln(1+N) / ln(1+cap), 1) × 100` — so one event is not equivalent to many. When a defined fraud sequence completes within 30 seconds, BFCI is multiplied by 1.25 and capped at 100.

Then:

```
FRS = 0.25·STEI + 0.35·Dynamic + 0.20·Correlation + 0.20·BankingImpact
```

renormalised over whichever axes have data. Full derivation: [`../docs/03_RISK/RISK_ENGINE.md`](../docs/03_RISK/RISK_ENGINE.md).

---

## Files

| File | Purpose |
| :--- | :--- |
| `shared/sudarshan_core/engines/frida_sandbox.py` | Sandbox controller: ADB, launch ladder, PID resolution, attach, hooks, event collection |
| `shared/sudarshan_core/engines/frida_hooks/banking_trojan.bundle.js` | Compiled agent bundle; the only script Frida 17 will load |
| `shared/sudarshan_core/engines/frida_hooks/banking_trojan.js` | Authoring source for the bundle, compiled with `frida-compile` |
| `shared/sudarshan_core/engines/dae_pipeline.py` | 16-state pipeline machine with logged transitions |
| `shared/sudarshan_core/engines/agentic_explorer.py` | Exploration loop driving the goal graph |
| `shared/sudarshan_core/engines/risk_engine.py` | Sole verdict authority — STEI, FRS, floors |
| `shared/sudarshan_core/sandbox/` | `SandboxProvider` implementations and the device channel |
| `shared/sudarshan_core/security/adb_gateway.py` | The single choke point for ADB execution |
| `scripts/setup_dynamic_analysis.py` | One-command guest preparation |
| `scripts/preflight.py` | Environment and toolchain verification |
| `start.ps1` | Windows platform bootstrap |

---

## Graceful degradation

When the emulator or `frida-server` is unreachable, the platform completes the analysis static-only. It does not fail the request, and it does not quietly score the missing evidence as clean:

- `dynamic_available` is false and the 0.35 dynamic axis is **excluded** from the FRS.
- The remaining live axes are renormalised over their own sum. With correlation also unavailable, that leaves STEI at `0.25 / 0.45 = 0.556` and banking impact at `0.20 / 0.45 = 0.444`.
- `axes_used` and `axes_excluded` are returned on the case so the renormalisation is auditable.
- If the resulting band would be `Safe` and the sample shows a concealed payload or strong static capability, a safety floor raises the band to `Suspicious` without changing the score.

A run that produced no observation is reported as a run that produced no observation, never as a clean result.
