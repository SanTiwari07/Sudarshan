# HARDCODING AUDIT REPORT

## Audit Overview
A comprehensive repository-wide scan was conducted to identify and eliminate machine-specific hardcoded values, ensuring the platform remains fully portable, configurable, and device-agnostic.

| Location | Hardcoded Value | Type | Problem | Action | Verification |
|---|---|---|---|---|---|
| `shared/sudarshan_core/engines/frida_sandbox.py` | `input tap 507 1127` | Coordinates | Assumes fixed 1080x1920 screen for permission dialog fallback | Replaced with dynamic `wm size` evaluation and screen-relative bottom-center tap. | Code inspection |
| `analysis-engine/test_frida_*.py` | `emulator-5554` | Device Serial | Developer scratch scripts committed to production repo | Deleted files as they were proven dead test scratch files. | File removed |
| `backend/tests/*.py` | `emulator-5554` | Device Serial | Valid test fixture usage | None - explicitly allowed in isolated mock contexts. | N/A |
| `frontend/src/config.ts` | `http://localhost:8000` | API URL | Previously hardcoded in frontend views | Refactored into a single `VITE_API_URL` config with fallback. | Code inspection |
| `submit_all_apks.py` | `test apk` | Path | Test harness target directory | Valid local execution fixture. | N/A |
| `docker-compose.yml` | `127.0.0.1` | Network Bind | Binds proxy and mobsf ports to loopback | Valid security practice to prevent LAN exposure. | N/A |
| `docker-compose.yml` | `host.docker.internal` | Network Gateway | Bridges Docker to host ADB | Valid infrastructure networking (configurable). | N/A |
| `shared/sudarshan_core/sandbox/genymotion.py` | `mock_location` | Settings Injection | Injects GPS mock location | Legitimate sandbox feature, not a mock code path. | Code inspection |

## Status
- **0** machine-specific filesystem paths (`C:\Users\...`, `D:\Projects\...`) remain in production code.
- **0** production device serials are hardcoded.
- **0** network IP/Port values lack configuration fallbacks.
- **0** fixed screen coordinates remain in the dynamic analysis engine.
