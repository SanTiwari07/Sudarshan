# Scripts — operational and validation tooling

Hand-run tooling: environment bootstrap, health and preflight checks, database administration, and the harnesses that regenerate the evaluation artifacts. None of these run automatically — there is no CI workflow in this repository — and none of them are part of the pytest suite.

- Platform overview: [`../README.md`](../README.md)
- Operations guide: [`../docs/getting-started/HOW_TO_RUN.md`](../docs/getting-started/HOW_TO_RUN.md)

The directory is mounted read-only into the backend container at `/opt/sudarshan-scripts`, so operator tools can be run inside the running stack.

---

## Environment and sandbox

| Script | Purpose |
| :--- | :--- |
| `preflight.py` | Host-side preflight wrapper. Verifies ADB, device, root, frida-server, ports and containment policy. `--container` also checks inside the analysis engine; `--strict` treats warnings as failures; `--json` emits machine-readable output |
| `bootstrap_sandbox.py` | Emulator-agnostic sandbox bootstrap. Detects Genymotion or AVD, pushes and starts the matching `frida-server` |
| `setup_dynamic_analysis.py` | First-time dynamic analysis setup |
| `health_check.py` | Platform health check across startup validation subsystems; writes `health_check_result.json` |
| `quick_health.py` | Short backend liveness probe |

```bash
python scripts/preflight.py --container
python scripts/bootstrap_sandbox.py
```

---

## Database and accounts

| Script | Purpose |
| :--- | :--- |
| `db_admin.py` | Database operator tool — backup, restore, and `adopt` an existing database file into the managed volume |
| `reset_admin_password.py` | Reset the admin password in the backend SQLite database |
| `list_users.py` | List user accounts |

```bash
# Move a pre-volume database into the managed location
docker compose run --rm backend \
  python /opt/sudarshan-scripts/db_admin.py adopt /app/sudarshan.db
```

---

## Corpus and detection validation

The labelled corpus contains live banking trojans, is gitignored, and is never present in CI. Point these at it with `SUDARSHAN_LABELLED_CORPUS_DIR` or `--corpus-dir`.

| Script | Purpose |
| :--- | :--- |
| `validate_corpus.py` | Static-only detection validation. Regenerates [`../docs/evaluation/CORPUS_STATIC_VALIDATION.md`](../docs/evaluation/CORPUS_STATIC_VALIDATION.md) and its JSON artifact. `--check` fails if results moved; `--only <category>` scopes the run |
| `fetch_validation_corpus.py` | Fetches the open-source validation APKs listed in `tests/apks/corpus.manifest.json` |
| `virustotal_crosscheck.py` | Scores the labelled corpus with the static engine and cross-checks against VirusTotal. `--rate` bounds requests per minute |
| `validate_static_only_frs.py` | Verifies the static-only FRS values asserted in `docs/evaluation/CASE_STUDIES.md`, including that `correlation_result=None` and `{"available": False}` produce identical axis exclusion |
| `validate_yara_rules.py` | Measures the YARA rule set against the labelled corpus (`--rules`, `--corpus`) |

`validate_corpus.py` exit codes are deliberately distinct: `0` ran and invariants hold, `1` ran and something regressed, `2` could not run because the corpus or Androguard is absent. "Not run" must never be read as "passed".

```bash
docker run --rm \
  -v "$PWD/shared:/opt/sudarshan-core" -v "$PWD/scripts:/scripts" \
  -v "/path/to/corpus:/corpus:ro" \
  -e PYTHONPATH=/opt/sudarshan-core -e SUDARSHAN_LABELLED_CORPUS_DIR=/corpus \
  --entrypoint python sudarshan-analysis-engine:latest /scripts/validate_corpus.py
```

---

## Pipeline verification

Live end-to-end checks. These need a running stack and, where noted, an attached emulator.

| Script | Purpose |
| :--- | :--- |
| `test_e2e_pipeline.py` | Uploads a real APK through the backend and verifies the returned case |
| `verify_runtime_pipeline.py` | Dynamic pipeline self-test across the runtime stages, from ADB connectivity through evidence collection |
| `e2e_live_cert.py` | One-shot live device certification: Frida run, correlation and risk scoring |
| `validate_real_drinik_e2e.py` | Full pipeline run against a real Drinik sample |
| `verify_url_ingestion.py` | Exercises URL discovery and candidate ingestion |
| `test_mobsf_api.py` | MobSF API integration probe; writes `mobsf_test_report.json` |
| `test_gemini_api_fallback.py` | Exercises Gemini primary/fallback failover behaviour |
| `apk_ingest.py` | Computes an APK's SHA-256 case id and writes `ingestion_record.json` |

---

## VIDE and visual evidence

| Script | Purpose |
| :--- | :--- |
| `verify_vide_corpus.py` | Runs VIDE against the built baseline APKs and asserts the engine contract |
| `regenerate_fingerprints.py` | Regenerates `exactStrings` in a baseline's `fingerprints.json` |
| `live_vide_webview_verify.py` | Live WebView verification against Genymotion with InsecureBankv2 and the VIDE probe |
| `frida_vide_webview_trigger.js`, `vide_live_probe.js`, `vide_live_probe.bundle.js` | Frida agent sources and the compiled probe bundle used by the WebView verification |
| `e2e_visual_evidence_validate.py` | End-to-end visual evidence validation through the running API |
| `verify_vide_webview_device.md` | Device-side procedure for the WebView verification |

Only the `.bundle.js` files are loadable by Frida 17 — the plain `.js` sources are authoring inputs for `frida-compile`.

---

## Reporting QA

| Script | Purpose |
| :--- | :--- |
| `qa_pdf_visual.py` | Visual QA pass over generated PDF reports |
| `inspect_pdf.py` | Dumps PDF internals for debugging a generated report |

---

## Repository maintenance

| Script | Purpose |
| :--- | :--- |
| `enable-githooks.ps1` | Points `core.hooksPath` at `.githooks/` |
| `strip-cursor-from-git-history.ps1`, `git-filter-repo-strip-cursor.py`, `verify-no-cursor-git.ps1` | Remove and verify absence of Cursor Agent attribution in history. The `.githooks/pre-push` hook blocks pushes that would reintroduce it |
| `refresh-github-contributors.ps1` | Refreshes the contributor list |
| `migrate-to-new-github-repo.ps1` | Repository migration helper |

---

## Committed artifacts

Several JSON and HTML files in this directory are **outputs** of the scripts above, kept as reference snapshots rather than inputs: `health_check_result.json`, `pipeline_test_result.json`, `mobsf_test_report.json`, `static_only_frs_validation.json`, `live_vide_run_output.json`, `insecurebankv2_dual_degraded_report.html`. They record a specific historical run and are not regenerated automatically. `corpus_expectations.json` is an input — the expected results `validate_corpus.py --check` diffs against.

---

## Running scripts

Most scripts need `sudarshan_core` importable and, for anything touching Androguard or the toolchain, the analysis-engine image:

```bash
# Host, with the shared package on the path
PYTHONPATH="$PWD/shared" python scripts/health_check.py

# Inside the running backend
docker compose exec backend python /opt/sudarshan-scripts/list_users.py

# Inside the analysis engine, for toolchain-dependent work
docker compose exec analysis-engine python /scripts/validate_corpus.py
```

On Windows use `python`; the Microsoft Store stub does not carry the dependencies, and `start.ps1` skips it when locating an interpreter.
