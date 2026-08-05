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

## Run validation

```powershell
$env:PYTHONPATH = "backend;shared"
$env:JWT_SECRET_KEY = "validation"
python validate_dynamic_pipeline.py
```

Reports are written under `tests/apks/validation_runs/<timestamp>/`.
