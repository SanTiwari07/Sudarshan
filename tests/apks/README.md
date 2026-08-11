# Sudarshan Dynamic Validation APK Corpus

APK binaries are **not committed** (licensing and size). The runner uses `corpus.manifest.json` to locate samples.

## Populate the corpus

### Automatic fetch (known OSS URLs)

```powershell
$env:PYTHONPATH = "backend;shared"
backend\.venv\Scripts\python.exe scripts\fetch_validation_corpus.py
```

### Manual placement

Copy APKs into `tests/apks/categories/` using filenames from the manifest, for example:

| Category | Suggested file | Source |
|----------|----------------|--------|
| Banking / DVBA | `insecurebankv2.apk` | [Android-InsecureBankv2](https://github.com/dineshshetty/Android-InsecureBankv2) |
| GoatDroid | `owasp_goatdroid.apk` | OWASP GoatDroid project |
| DIVA | `accessibility_demo.apk` | Payatu DIVA |
| WebView | `webview_demo.apk` | Any WebView codelab APK |

Entries marked `"optional": true` are skipped when missing. Required entries must exist before declaring production stability.

### Drinik (banking malware — manual only)

Malware samples are **never fetched automatically**. For the Drinik E2E milestone:

1. Obtain a researcher-controlled Drinik APK in an isolated lab.
2. Place at `tests/apks/categories/drinik.apk` **or** set `DRINIK_APK_PATH`.
3. Ingest and validate:

```powershell
$env:PYTHONPATH = "backend;shared"
backend\.venv\Scripts\python.exe scripts\apk_ingest.py --drinik
backend\.venv\Scripts\python.exe scripts\validate_real_drinik_e2e.py
backend\.venv\Scripts\python.exe scripts\validate_real_drinik_e2e.py --dynamic  # requires ADB+emulator
```

Fixtures in `backend/tests/case_study_fixtures.py` are for static regression only — not proof of live dynamic analysis.

## Run validation

```powershell
$env:PYTHONPATH = "backend;shared"
$env:JWT_SECRET_KEY = "validation"
python validate_dynamic_pipeline.py
```

Reports are written under `tests/apks/validation_runs/<timestamp>/`.
