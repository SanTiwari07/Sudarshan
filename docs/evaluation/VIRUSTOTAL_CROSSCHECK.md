# VirusTotal cross-check

Benchmarks Sudarshan's verdict against VirusTotal on the labelled corpus, one
sample at a time.

## What this is and is not

This is a **pipeline check**, not a scoreboard. Sudarshan's FRS and VT's
detection ratio are produced by unrelated methods and are not expected to
correlate numerically — a 70/100 FRS does not mean "70% of engines agree". What
must hold is that the two systems reach the same coarse conclusion an analyst
acts on: malicious, or not.

So the useful output is not the agreement percentage. It is the
**disagreements list**: every sample where Sudarshan and VT reached opposite
conclusions is a lead pointing at a specific gap in the static or dynamic
engine.

## Running it

```bash
python scripts/virustotal_crosscheck.py --json out.json
```

Requires `VIRUSTOTAL_API_KEY` in the environment or `.env`. Pacing comes from
`VIRUSTOTAL_RATE_LIMIT_PER_MIN` (default 4, the public-key quota); override per
run with `--rate`. A public key needs roughly `samples / 4` minutes.

The corpus is located by `validation/labelled_corpus.py` — explicit `--corpus`
argument, then `SUDARSHAN_LABELLED_CORPUS_DIR`, then the in-repo defaults. It is
gitignored, so a fresh clone has to supply it.

## Hashes only — never uploads

The harness looks up SHA-256 digests. It never submits a sample file.
Submitting a file to VT publishes it to every VT Enterprise subscriber, and
that is the operator's decision to make, not a validation script's. A sample VT
has never seen simply comes back `NOT_FOUND`.

## How the two verdicts are compared

**Sudarshan side.** `Safe` maps to benign; `Suspicious`, `High Risk` and
`Critical` all map to malware. `Suspicious` counts as a malicious call on
purpose — that band is frequently the result of a *floor* in the risk engine
refusing to certify a sample as safe (concealed payload, active evasion, strong
static capability with no refuting dynamic evidence). Treating a
refusal-to-certify as a clean verdict would erase exactly the signal the floors
exist to preserve.

**VirusTotal side**, from `last_analysis_stats`:

| Condition | Verdict | Scored? |
| --- | --- | --- |
| `malicious >= VT_MALICIOUS_VENDOR_THRESHOLD` (5) | `malware` | yes |
| `0 < malicious < 5` | `low_detection` | no |
| `malicious == 0`, engines did report | `benign` | yes |
| HTTP 404, or no completed analyses | `not_found` | no |
| transport failure, 429, unparseable body | `error` | no |

Two decisions are load-bearing:

* **A vendor threshold, not `malicious > 0`.** Single-vendor hits on Android
  APKs are dominated by heuristic adware/PUP flags that fire on ad SDKs present
  in plenty of legitimate apps. A 2/70 hit is genuinely ambiguous, so it gets
  its own bucket instead of being forced into either answer.

* **`not_found` is not benign.** A 404 means VT has no opinion. Folding that
  into the benign bucket would let unknown samples silently count as agreement.
  Non-comparable rows are excluded from the confusion matrix and reported as
  coverage instead — the same discipline `static_scoring` applies to axes it
  cannot run. If nothing was comparable, the agreement rate is reported as
  `n/a`, never as 100%.

The denominator counts only engines that actually returned a verdict
(`malicious + suspicious + undetected + harmless`); `timeout` and
`type-unsupported` are non-answers and are excluded.

## Reading the confusion matrix

| Cell | Meaning |
| --- | --- |
| `both_malware` | agreement on a detection |
| `both_benign` | agreement on a clean sample |
| `sudarshan_only_malware` | VT says benign — investigate as a **possible false positive** |
| `vt_only_malware` | VT says malware — investigate as a **possible miss** |

`vt_only_malware` rows are the highest-value output. Each one is a sample the
industry detects and Sudarshan does not.

## Family names

VT's family label is taken only from `popular_threat_classification.
suggested_threat_label`. It is never reconstructed from `names` — the
uploader-supplied filename list. `threat_correlator.py` documents what happened
the last time that fallback existed: a clean file manager with 0/75 detections
was assigned the "family" `Amaze File Manager 3.11.2 (Android 5.0+).apk`, which
then raised its score through the classification multiplier. Absence of a
classification is not a classification.

## Tests

`tests/unit/test_virustotal_crosscheck.py` covers the parsing and bucketing
rules against a fake client. No network, no API key required.
