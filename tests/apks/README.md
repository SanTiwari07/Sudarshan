# Dynamic validation corpus

Sample inventory for the dynamic pipeline validation runs.

Verified against `corpus.manifest.json` and `scripts/fetch_validation_corpus.py` on **2026-08-27**.

- Test suite overview: [`../README.md`](../README.md)
- Validation protocols: [`../../docs/VALIDATION.md`](../../docs/VALIDATION.md)

---

## Contents

```text
tests/apks/
├── corpus.manifest.json     Sample inventory the runner resolves against
├── categories/              APK binaries (not committed)
├── VIDE_testapks/           Ten built VIDE baseline APKs (BASE-01-SBI … BASE-10-UNION)
├── validation_runs/         Timestamped run reports
└── sudarshan_artifacts/     Per-run artifact output
```

**APK binaries are not committed** — licensing and size. `corpus.manifest.json` is the inventory the runner resolves against; each entry gives a `relative_path` under this directory and, where a legitimate source exists, a `fetch_url`.

---

## Populating the corpus

### Automatic fetch

Downloads the entries that carry a `fetch_url`:

```bash
PYTHONPATH="backend:shared" python scripts/fetch_validation_corpus.py
```

```powershell
$env:PYTHONPATH = "backend;shared"
python scripts\fetch_validation_corpus.py
```

Only `insecurebankv2` currently carries a fetch URL; everything else is placed by hand.

### Manual placement

Copy APKs into `tests/apks/categories/` under the exact `relative_path` from the manifest.

| Sample id | Category | Optional | Suggested source |
| :--- | :--- | :--- | :--- |
| `insecurebankv2` | `banking_demo` | **required** | [Android-InsecureBankv2](https://github.com/dineshshetty/Android-InsecureBankv2) |
| `insecurebankv2_dvb` | `damn_vulnerable_bank` | optional | Damn Vulnerable Bank APK, or alias InsecureBankv2 for smoke tests |
| `goatdroid` | `owasp_goatdroid` | optional | OWASP GoatDroid |
| `accessibility_demo` | `accessibility_demo` | optional | Payatu DIVA or any accessibility-service demo |
| `webview_demo` | `webview_demo` | optional | Any WebView codelab APK |
| `overlay_demo` | `overlay_demo` | optional | Any `SYSTEM_ALERT_WINDOW` demo |
| `sms_demo` | `sms_permission_demo` | optional | Any SMS-permission demo |
| `runtime_permissions` / `no_runtime_permissions` | permission behaviour | optional | Permission-request demos, with and without runtime prompts |
| `hello_world` | `hello_world` | optional | AOSP HelloActivity or any minimal launcher APK |
| `splash`, `multi_activity`, `no_launcher`, `crash_on_launch` | launch-path edge cases | optional | Exercise the launch ladder and crash classifier |
| `obfuscated` | `obfuscated_apk` | optional | Any ProGuard/R8-obfuscated build |
| `drinik` | `banking_malware` | optional, manual only | See below |

Entries marked `"optional": true` are skipped when the file is absent. Sixteen samples are listed; only `insecurebankv2` is required.

### Drinik and other malware

Malware is **never fetched automatically**. For the Drinik end-to-end milestone:

1. Obtain a researcher-controlled sample and handle it in an isolated lab.
2. Place it at `tests/apks/categories/drinik.apk`, or set `DRINIK_APK_PATH`.
3. Ingest and validate:

   ```bash
   PYTHONPATH="backend:shared" python scripts/apk_ingest.py --drinik
   PYTHONPATH="backend:shared" python scripts/validate_real_drinik_e2e.py
   PYTHONPATH="backend:shared" python scripts/validate_real_drinik_e2e.py --dynamic   # needs ADB and an emulator
   ```

The fixtures in `backend/tests/case_study_fixtures.py` are static regression data. They are not evidence that live dynamic analysis worked, and should never be cited as such.

---

## VIDE baseline APKs

`VIDE_testapks/` holds ten built baseline applications — `BASE-01-SBI` through `BASE-10-UNION` — used by `scripts/verify_vide_corpus.py` and the VIDE attribution tests.

> All ten currently produce identical fingerprints, and their palettes collide at ΔE 0. Only the bank name distinguishes one from another, so attribution against this set rests almost entirely on the string axis. Treat detection results from it as meaningful and attribution results as provisional. See [KNOWN_LIMITATIONS.md §5.3](../../docs/KNOWN_LIMITATIONS.md).

---

## Running validation

```bash
PYTHONPATH="backend:shared" JWT_SECRET_KEY=validation \
  python validate_dynamic_pipeline.py            # [--fetch] [--stress 10,20] [--recovery]
```

| Flag | Effect |
| :--- | :--- |
| `--fetch` | Fetch fetchable manifest entries before running |
| `--stress 10,20` | Run the stress harness at the given concurrency levels |
| `--recovery` | Run the failure-recovery harness |

The runner continues past individual failures and writes reports to `tests/apks/validation_runs/<timestamp>/`.

A live sandbox is required — a rooted emulator with a matching `frida-server`. Without one every sample degrades to static-only, which is a valid result for the pipeline but not a validation of the dynamic path.

---

## Relationship to the labelled malware corpus

This corpus is **not** the labelled corpus behind the published detection figures. That one lives outside the repository, is resolved through `SUDARSHAN_LABELLED_CORPUS_DIR`, holds live banking trojans, and is driven by `scripts/validate_corpus.py` — see [`../../docs/evaluation/CORPUS_STATIC_VALIDATION.md`](../../docs/evaluation/CORPUS_STATIC_VALIDATION.md).

This corpus exercises the **pipeline**: launch paths, permission behaviour, WebView handling, crash recovery, exploration coverage. That one measures **detection accuracy**. Do not report a result from one as a result from the other.
