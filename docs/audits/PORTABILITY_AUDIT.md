# Portability Audit Report

This report identifies machine-specific assumptions across the SUDARSHAN repository, evaluating occurrences of local paths, developer identities, IP addresses, URL endpoints, and environment configurations.

## 1. Local Filesystem Paths

### Windows Drive Paths
- `c:\Projects\Sudarshan\frontend\src` (in `frontend\update_surfaces.py`): Hardcoded source directory. **Classification: Local development default.**
- `d:\Projects\Sudarshan BOI\artifacts_qa\...` (in `scripts\inspect_pdf.py`): Hardcoded QA path on D: drive. **Classification: Hardcoded application dependency / Local test configuration.**
- `d:\Projects\Sudarshan BOI\backend` / `d:\Projects\Sudarshan BOI\shared` / `d:\Projects\Sudarshan BOI\backend\sudarshan.db` (in `scripts\reset_admin_password.py`): Hardcoded system path. **Classification: Local test configuration.**
- `d:/Sudarshan/shared`, `d:/Sudarshan/backend`, `d:/Sudarshan/tests/apks/VIDE_testapks` (in `backend\test_vide_all.py`): Hardcoded system path for tests. **Classification: Local test configuration.**
- `C:\Program Files\Docker\Docker\resources\bin\docker.exe` and `C:\Windows\py.exe` (in `start.ps1`): Hardcoded execution paths. **Classification: Local development default.**

### Absolute `file:///` URIs
- `../sudarshan_artifacts/screenshots/...` (in `artifacts\screenshots_artifact.md`): Artifact references using absolute local URIs. **Classification: Local development artifact.**
- `file:///d:/Projects/Sudarshan%20BOI/...` (in `CHANGELOG.md` and `docs\reports\audits\DOCUMENTATION_AUDIT_REPORT.md`): References to prior documentation drift fixes. **Classification: Documentation example / Historical artifact.**
- `file:///etc/passwd` (in `backend\tests\test_discovery_security.py`): **Classification: Test configuration.**

## 2. Unix / Docker / Target Paths

### Docker Container Bind Mounts \u0026 Caches
- `/opt/sudarshan-core`: Mount target for the shared library across images. **Classification: Production/Test configuration.**
- `/opt/sudarshan-scripts`: Mount target for operational scripts in `docker-compose.yml`. **Classification: Production/Test configuration.**
- `/opt/frida-cache`: Bind-mounted host cache for the downloaded Frida server binary. **Classification: Production/Test configuration.**
- `/opt/VIDE`: Mount target for visual evidence data in `docker-compose.yml`. **Classification: Production/Test configuration.**
- `/corpus`: Labelled corpus directory `SUDARSHAN_LABELLED_CORPUS_DIR=/corpus`. **Classification: Local development default / Test configuration.**
- `/opt/platform-tools`: Target for ADB platform tools extraction in `backend/Dockerfile`. **Classification: Production configuration.**

### Hardcoded Android / External Paths
- `/opt/genymobile/genymotion/tools/adb` (in `shared\sudarshan_core\sandbox\genymotion.py`): Fallback path to Genymotion's adb. **Classification: Hardcoded application dependency.**
- `/data/local/tmp/frida-server` (in `analysis-engine\restart_frida_no_l.py`, `analysis-engine\restart_frida.py`, `backend\test_dyn.py`, `README.md`): Target path for Frida server on the Android guest. **Classification: Hardcoded application dependency.**

## 3. Developer Identities \u0026 Machine Specifics

### Usernames \u0026 User Paths
- `C:\Users\sansk\...` (in `scripts\health_check.py` and test fixture logs e.g. `tests\fixtures\apks\validation_runs\...`): Path reflecting previous developer ("Sanskar") environment. **Classification: Documentation example / Test artifacts.**
- `C:\Users\SHAMBHAVI PATIL\AppData\...` (in `artifacts\logs\engine_log_Safe_gemini.txt`): Current developer's Windows path found in execution logs. **Classification: Test artifacts.**
- `SanTiwari07` (in `CONTRIBUTING.md`, `CHANGELOG.md`, `scripts\migrate-to-new-github-repo.ps1`): GitHub handle for the repository origin. **Classification: Production configuration / Documentation.**

## 4. IP Addresses \u0026 Endpoints

### Localhost / Development Ports
- `http://localhost:8001`: Analysis engine default URL. **Classification: Local development default.**
- `http://localhost:5173`, `http://127.0.0.1:5173`: Vite frontend CORS origins. **Classification: Local development default.**
- `127.0.0.1:27055`: Frida server listen host/port (defaults in backend/README_FRIDA.md). **Classification: Local development default / Hardcoded application dependency.**
- `127.0.0.1:27042`: Hardcoded Frida target in `analysis-engine\restart_frida.py`. **Classification: Local development default.**
- `postgresql://sudarshan:sudarshan@localhost:5432/sudarshan` (in `backend\test_transaction.py`, `backend\test_postgres_regression.py`): Database URL. **Classification: Test configuration.**
- `host.docker.internal:5037`: Docker-to-host bridge for the ADB server. **Classification: Local development default / Docker environment configuration.**

### RFC1918 / Private Network IPs
- `192.168.56.101`: Example / Default Genymotion guest IP on VirtualBox host-only adapter (e.g. `192.168.56.101:5555`). Found in incident reports, `test_blocker_fixes.py`, and documentation. **Classification: Documentation example / Test configuration.**
- `192.168.1.1`, `192.168.1.100`, `172.16.0.5`, `10.0.0.1` (in `backend\tests\test_discovery_security.py` and `backend\tests\case_study_fixtures.py`): IPs used to validate security blockage of private/local address space. **Classification: Test configuration.**
- `10.0.2.16` (in `artifacts\logs\step_A_logcat.txt`): Android emulator's NAT IP in logs. **Classification: Test artifacts.**
- `10.9.9.9`, `10.0.0.5` (in `backend\tests\test_persistence_layer.py`): Login IP blocks tested. **Classification: Test configuration.**

## 5. Artifacts and Emulators
- `emulator-5554`: Standard AVD emulator string. **Classification: Documentation example / Hardcoded application dependency for test execution.**

---
**Summary Statement:**
The repository exhibits a significant number of machine-specific paths primarily localized to Python scripts under `scripts/`, `backend/tests/`, and hardcoded `d:\Projects\Sudarshan BOI\` or `c:\Projects\Sudarshan\` variables. Test fixtures and log artifacts preserve paths containing developer usernames (`sansk`, `SHAMBHAVI PATIL`). Docker and architectural mounts (`/opt/...`) form the production layout baseline.
