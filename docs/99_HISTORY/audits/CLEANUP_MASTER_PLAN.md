# CLEANUP MASTER PLAN

This master plan synthesizes findings from all phase 0 audits (Architecture, Duplicate Code, Legacy Code, Tests, Documentation, Portability, and Security). Each identified candidate is categorized. Nothing uncertain is deleted.

## 1. MOVES (Phase 2 - SAFE Structural Moves)

- **Test Fixtures & Artifacts**
  - **MOVE** `tests/apks/validation_runs/*` -> `tests/fixtures/validation_runs/`
  - **MOVE** `artifacts/*` to a dedicated top-level ignored artifacts dir (already present, but need to clean tracked files).
  - **MOVE** generated `.db`, `.sqlite`, `.json` logs -> `artifacts/` (or delete if purely temporary).
  
- **Documentation & Reports**
  - **MOVE** `docs/reports/historical/*` -> `docs/audits/historical/`
  - **MOVE** `docs/architecture/DYNAMIC_ANALYSIS_2.0.md` -> `docs/audits/historical/`
  - **MOVE** `docs/reports/reports/FINAL_ARCHITECTURE.md` -> `docs/audits/historical/`
  - **MOVE** obsolete test logs to `artifacts/` or `tests/fixtures/`.

- **Scratch Files & Scripts**
  - **MOVE** standalone root-level scratch files (if any remain) -> `scripts/` or `tests/regression/`

## 2. RENAMES (Phase 3 - VIDE Rename)

- **RENAME** `banking-baseline-corpus-main/` -> `VIDE/`
- **UPDATE** all imports, scripts, docker-compose, and test paths referencing `banking-baseline-corpus-main`.

## 3. PORTABILITY & SECRETS (Phases 4 & 10)

- **Centralized Configuration:** Move all hardcoded variables into `backend/app/core/config.py` or `.env`.
- **Remove Absolute Paths:**
  - Update `scripts/inspect_pdf.py` (remove `d:\Projects\Sudarshan BOI\...`)
  - Update `scripts/reset_admin_password.py`
  - Update `backend/test_vide_all.py`
  - Update `frontend/update_surfaces.py`
- **Update Passwords in Tests:** Strip hardcoded DB credentials/JWT secrets in `backend/tests/*.py` and use dummy variables or load from environment.
- **Remove Usernames:** Purge `C:\Users\sansk\...` from fixtures or logs.
- **Docs:** Replace all `file:///` local links with relative paths (`../...`).

## 4. DUPLICATES (Phase 5)

- `scripts/write_stage_b.py` vs `scripts/write_summary.py` -> **REQUIRES REVIEW**
- `convert_qmark_to_dollar` -> **REQUIRES REVIEW** (Consolidate into `shared/`)

## 5. LEGACY & DEAD CODE (Phase 6)

- `shared/sudarshan_core/engines/analysis_history.py` (Deprecated Shim) -> **DELETE** (Remove dynamic import in `frida_sandbox.py`)
- `shared/sudarshan_core/engines/frida_hooks/_bisect_variant.js` (Abandoned) -> **DELETE**
- `scripts/test_jev_mock_live.py` (Abandoned Prototype) -> **DELETE**
- `scripts/migrate-to-new-github-repo.ps1` -> **DELETE**

## 6. TESTS (Phase 7)

- `tests/dynamic/`, `tests/sandbox/`, `tests/security/`, `tests/regression/`, `tests/vide/` -> **REQUIRES REVIEW** (Empty/obsolete directories - delete if safe).
- **CONVERT** `scripts/test_phase6_e2e.py`, `scripts/test_frida_stages.py`, `scripts/test_mobsf_api.py` -> **MOVE** to `tests/integration/`
- **FIX** failing backend and frontend tests before concluding.

## 7. DOCUMENTATION (Phase 8)

- **MERGE/DELETE:** `docs/ARCHITECTURE.md` -> **DELETE** (Duplicate of `CURRENT_ARCHITECTURE.md`)
- **MERGE/DELETE:** `docs/architecture/DYNAMIC_ANALYSIS_CURRENT_STATE.md` -> **DELETE** (Overlaps with 04 and CURRENT)
- **DELETE/HISTORICAL:** `docs/FEATURE.md` -> **DELETE** (Superseded by `FEATURE_STATUS.md`)
- **HISTORICAL:** `docs/SUDARSHAN_MASTER.md` -> **DELETE** (Broken template)

## 8. DELETION SAFETY MATRIX

Will be generated prior to executing any actual deletion.

