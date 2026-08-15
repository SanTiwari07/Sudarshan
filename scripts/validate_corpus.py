#!/usr/bin/env python3
"""
Static-only detection validation against the labelled malware corpus.

`audit/DETECTION_VALIDATION.md` reports 8/8 malware caught and 0/9 false
positives across 17 labelled samples. Those numbers were measured once, by
hand, in July 2026 and written into prose. Nothing could regenerate them, so
nobody could tell whether they were still true - and by the time this script
was written they were not: the analyser has since learned to spot
`addJavascriptInterface`, which moves several samples.

This makes the table a build artifact. Run it, diff it, commit it.

    python scripts/validate_corpus.py                 # score and write artifacts
    python scripts/validate_corpus.py --check         # fail if results moved
    python scripts/validate_corpus.py --only Malware  # subset

Requires androguard, which is installed in the analysis-engine image but not
on a typical host:

    docker run --rm \\
      -v "$PWD/shared:/opt/sudarshan-core" -v "$PWD/scripts:/scripts" \\
      -v "$PWD/test apk/test apk:/corpus:ro" \\
      -e PYTHONPATH=/opt/sudarshan-core -e SUDARSHAN_LABELLED_CORPUS_DIR=/corpus \\
      --entrypoint python sudarshanboi-analysis-engine:latest /scripts/validate_corpus.py

Exit codes
    0  ran; invariants (and --check expectations) hold
    1  ran; something regressed
    2  could NOT run - corpus absent or androguard missing

2 is kept distinct from 1 on purpose. The corpus is gitignored and holds live
banking trojans, so this can never run in CI; "not run" must never be mistaken
for "passed", nor reported as a failure on a machine that legitimately has no
malware.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SHARED = _REPO_ROOT / "shared"
if str(_SHARED) not in sys.path:
    sys.path.insert(0, str(_SHARED))

from sudarshan_core.validation.labelled_corpus import (  # noqa: E402
    CATEGORY_LABELS,
    LabelledSample,
    corpus_search_order,
    find_labelled_corpus_root,
    load_labelled_samples,
)

EXIT_OK, EXIT_REGRESSION, EXIT_CANNOT_RUN = 0, 1, 2

SCHEMA_VERSION = "1.0.0"

# Ordered worst-last, so "at least this band" is an index comparison.
BAND_ORDER = ["Safe", "Suspicious", "High Risk", "Critical"]

DEFAULT_JSON_OUT = _REPO_ROOT / "docs" / "evaluation" / "corpus_static_validation.json"
DEFAULT_MD_OUT = _REPO_ROOT / "docs" / "evaluation" / "CORPUS_STATIC_VALIDATION.md"
EXPECTATIONS = _REPO_ROOT / "scripts" / "corpus_expectations.json"

# The decision rule, stated once and carried into both artifacts.
#
# Deliberately a BAND comparison, not an FRS threshold. On this corpus the score
# ranges overlap - benign reaches 25.95 while the lowest-scoring trojan sits
# below that - so no numeric cut separates the classes. Separation comes from
# the visibility floor (risk_engine.py:1070), which moves a concealed dropper
# out of "Safe" without changing its number. A tuned numeric threshold would
# report a separation that does not exist.
FLAGGED_RULE = "risk_band != 'Safe'  (i.e. Suspicious, High Risk or Critical)"
FLAGGED_RATIONALE = (
    "risk_band is the product's own deploy gate: 'Safe' yields "
    "'MONITOR - Approved for deployment' while 'Suspicious' yields 'QUARANTINE - "
    "Do not approve' (risk_engine.py:_get_recommended_action). The band boundary "
    "is the decision a consumer acts on, so it is what precision/recall should "
    "measure."
)


# ─── helpers ──────────────────────────────────────────────────────────────────

def _band_at_least(band: str, minimum: str) -> bool:
    try:
        return BAND_ORDER.index(band) >= BAND_ORDER.index(minimum)
    except ValueError:
        return False


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _git_commit() -> Optional[str]:
    """
    Commit the results were produced at.

    Falls back to SUDARSHAN_GIT_COMMIT because the usual execution environment
    is a container that has the source bind-mounted but no git binary and no
    .git directory - where shelling out silently yields "unknown" and the
    artifact loses the one field that ties it to a revision.
    """
    import os

    env_commit = (os.environ.get("SUDARSHAN_GIT_COMMIT") or "").strip()
    if env_commit:
        return env_commit
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=_REPO_ROOT, capture_output=True, text=True, timeout=5,
        )
        return out.stdout.strip() or None
    except Exception:
        return None


def _androguard_version() -> str:
    try:
        import androguard
        return getattr(androguard, "__version__", "unknown")
    except Exception:
        return "unavailable"


# ─── scoring ──────────────────────────────────────────────────────────────────

def _score_one(sample: LabelledSample) -> Dict[str, Any]:
    """Score one sample and flatten it into a JSON-serialisable record."""
    from sudarshan_core.validation.static_scoring import score_apk_static

    result = score_apk_static(sample.path)
    breakdown = result.breakdown
    flags = result.flags

    band = result.band
    stei_axes = breakdown.get("stei_axes") or {}

    record: Dict[str, Any] = {
        "display_name": sample.display_name,
        "file_name": sample.file_name,
        "category": sample.category,
        "label": sample.label,
        "sha256": _sha256(sample.path),
        "size_bytes": sample.path.stat().st_size,

        "package_name": result.package_name,
        "family_classification": result.family,
        "matched_rule": result.matched_rule,
        "ai_confidence": result.ai_confidence,

        "frs": round(result.frs, 2),
        "band": band,
        "verdict": result.risk.get("verdict"),
        "confidence": round(result.confidence, 2),
        "recommended_action": result.risk.get("recommended_action"),
        "flagged": band != "Safe",

        "stei": breakdown.get("stei"),
        "stei_axes": {k: stei_axes.get(k) for k in sorted(stei_axes)},
        "axes_used": breakdown.get("axes_used"),
        "axes_excluded": sorted(breakdown.get("axes_excluded") or []),

        "floors": {
            key: bool(breakdown.get(f"verdict_floored_for_{key}"))
            for key in ("visibility", "evasion", "static_evidence", "incomplete_exercise")
        },

        # Sorted here, not in the engine: list order comes from DEX string-pool
        # iteration, which is stable per androguard version but not across them.
        # Sorting in the engine would change production behaviour.
        "permission_count": len(result.permissions),
        "permissions": sorted(result.permissions),
        "dangerous_apis_found": sorted(flags.get("dangerous_apis_found") or []),
        "indian_bank_packages_found": sorted(flags.get("indian_bank_packages_found") or []),

        "has_accessibility_abuse": bool(flags.get("has_accessibility_abuse")),
        "has_sms_read_write": bool(flags.get("has_sms_read_write")),
        "has_system_alert_window": bool(flags.get("has_system_alert_window")),
        "targets_indian_banks": bool(flags.get("targets_indian_banks")),
        "has_concealed_payload": bool(flags.get("has_concealed_payload")),
        "obfuscation_score": flags.get("obfuscation_score"),
    }

    record["invariants"] = _check_invariants(record)
    return record


def _check_invariants(record: Dict[str, Any]) -> Dict[str, bool]:
    """
    Properties that must hold for every static-only row.

    These catch a silently-changed pipeline far earlier than a score diff would:
    if the dynamic axis starts contributing to a static-only run, the number
    moves for a reason that has nothing to do with detection quality.
    """
    axes_used = record.get("axes_used") or {}
    excluded = set(record.get("axes_excluded") or [])
    weight_sum = sum(float(v) for v in axes_used.values()) if axes_used else 0.0

    return {
        "dynamic_and_correlation_excluded": {"dynamic", "correlation"}.issubset(excluded),
        "weights_sum_to_one": abs(weight_sum - 1.0) < 0.01,
        "band_is_known": record.get("band") in BAND_ORDER,
        "frs_within_range": 0.0 <= float(record.get("frs") or -1) <= 100.0,
        "confidence_within_range": 0.0 <= float(record.get("confidence") or -1) <= 100.0,
    }


# ─── aggregation ──────────────────────────────────────────────────────────────

def _matrix(records: List[Dict[str, Any]], minimum_band: str) -> Dict[str, Any]:
    tp = sum(1 for r in records if r["label"] == "malware" and _band_at_least(r["band"], minimum_band))
    fn = sum(1 for r in records if r["label"] == "malware" and not _band_at_least(r["band"], minimum_band))
    fp = sum(1 for r in records if r["label"] == "benign" and _band_at_least(r["band"], minimum_band))
    tn = sum(1 for r in records if r["label"] == "benign" and not _band_at_least(r["band"], minimum_band))

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    return {
        "rule": f"band >= {minimum_band}",
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "specificity": round(tn / (tn + fp), 4) if (tn + fp) else 0.0,
        "accuracy": round((tp + tn) / len(records), 4) if records else 0.0,
    }


def _aggregate(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    malware = [r["frs"] for r in records if r["label"] == "malware"]
    benign = [r["frs"] for r in records if r["label"] == "benign"]

    max_benign = max(benign) if benign else 0.0
    min_malware = min(malware) if malware else 0.0
    separable = bool(malware and benign and min_malware > max_benign)

    floors_fired: Dict[str, List[str]] = {}
    for key in ("visibility", "evasion", "static_evidence", "incomplete_exercise"):
        floors_fired[key] = sorted(
            r["display_name"] for r in records if r["floors"].get(key)
        )

    concealed_malware = sum(1 for r in records if r["label"] == "malware" and r["has_concealed_payload"])
    concealed_benign = sum(1 for r in records if r["label"] == "benign" and r["has_concealed_payload"])

    return {
        "sample_count": len(records),
        "malware_count": len(malware),
        "benign_count": len(benign),

        "primary": _matrix(records, "Suspicious"),
        # Recorded because it is the machine-checked form of the doc's honest
        # limitation: static-only analysis has a ceiling, and asserting a
        # scarier band from a manifest alone would be overclaiming.
        "secondary_high_risk": _matrix(records, "High Risk"),

        "score_ranges": {
            "malware_frs": [round(min(malware), 2), round(max(malware), 2)] if malware else None,
            "benign_frs": [round(min(benign), 2), round(max(benign), 2)] if benign else None,
            "max_benign_frs": round(max_benign, 2),
            "min_malware_frs": round(min_malware, 2),
            "score_separable": separable,
            "separation_source": (
                "numeric FRS (ranges do not overlap)" if separable
                else "risk_band floors, not numeric FRS (ranges overlap)"
            ),
        },

        "floors_fired": floors_fired,
        "concealment": {
            "malware": f"{concealed_malware}/{len(malware)}",
            "benign": f"{concealed_benign}/{len(benign)}",
        },
        "family_classification": {
            r["display_name"]: r["family_classification"] for r in records
        },
    }


def _results_digest(records: List[Dict[str, Any]], aggregate: Dict[str, Any]) -> str:
    """
    Hash of results only - the `run` block (timestamps, host) is excluded.

    Makes "did anything actually change?" a one-line comparison instead of an
    eyeball diff over 17 rows.
    """
    payload = json.dumps({"samples": records, "aggregate": aggregate}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ─── rendering ────────────────────────────────────────────────────────────────

def _render_markdown(doc: Dict[str, Any]) -> str:
    agg = doc["aggregate"]
    primary = agg["primary"]
    ranges = agg["score_ranges"]
    run = doc["run"]

    lines: List[str] = [
        "<!-- GENERATED by scripts/validate_corpus.py - do not edit; regenerate to change. -->",
        "",
        "# Detection validation - labelled corpus (static-only)",
        "",
        f"**Generated:** {run['generated_at']}  ",
        f"**Commit:** `{run.get('git_commit') or 'unknown'}`  ",
        f"**androguard:** {run['androguard_version']}  ",
        f"**Results digest:** `{doc['results_digest'][:16]}`",
        "",
        "Regenerate with `python scripts/validate_corpus.py` (needs the corpus and androguard;",
        "see the module docstring for the container invocation). Narrative and root-cause",
        "analysis live in `audit/DETECTION_VALIDATION.md` - this file holds only measurements.",
        "",
        "## Configuration",
        "",
        "| Axis | State |",
        "| :--- | :--- |",
        "| Dynamic instrumentation | not run |",
        "| Threat correlation | unavailable (no API keys) |",
        "| VIDE visual diff | not run |",
        "",
        "Absent axes are **excluded and the remaining weights renormalised**, not scored as",
        "zero. Scoring an absent axis as zero is what pinned 25% of every score at 0 before",
        "the fix recorded as Bug 2 in `audit/DETECTION_VALIDATION.md`.",
        "",
        "## Decision rule",
        "",
        f"```\nflagged := {FLAGGED_RULE}\n```",
        "",
        FLAGGED_RATIONALE,
        "",
    ]

    if not ranges["score_separable"]:
        lines += [
            f"**The score ranges overlap** - benign reaches {ranges['max_benign_frs']} while the "
            f"lowest-scoring trojan sits at {ranges['min_malware_frs']}. No numeric FRS threshold "
            "separates these classes; separation comes from the band floors. Any single cut-off "
            "quoted as a detection threshold would be a fiction.",
            "",
        ]

    lines += [
        "Positive class = `Malware/`. Negative = `Safe/` + `MAS Crackmes/` + `Vulnerable/`.",
        "InsecureBankv2 is counted **benign**: it is deliberately *insecure*, not *malicious*,",
        "and scoring it as malware would inflate recall by rewarding a flag on a training app.",
        "",
        "## Results",
        "",
        "| Label | Sample | FRS | Band | Conf | STEI | Family | Concealed | Floor |",
        "| :--- | :--- | ---: | :--- | ---: | ---: | :--- | :---: | :--- |",
    ]

    for r in doc["samples"]:
        floors = [k for k, v in r["floors"].items() if v]
        lines.append(
            "| {label} | {name} | {frs} | {band} | {conf} | {stei} | {family} | {concealed} | {floor} |".format(
                label=r["label"],
                name=r["display_name"],
                frs=f"{r['frs']:.2f}",
                band=r["band"],
                conf=f"{r['confidence']:.1f}",
                stei=f"{r['stei']:.2f}" if isinstance(r["stei"], (int, float)) else "-",
                family=r["family_classification"],
                concealed="yes" if r["has_concealed_payload"] else "-",
                floor=", ".join(floors) if floors else "-",
            )
        )

    lines += [
        "",
        "## Aggregate",
        "",
        "```",
        f"rule                 : {primary['rule']}",
        f"malware flagged      : {primary['tp']}/{agg['malware_count']}   (missed {primary['fn']})",
        f"non-malware flagged  : {primary['fp']}/{agg['benign_count']}   false positives",
        f"precision {primary['precision']:.2f}   recall {primary['recall']:.2f}   f1 {primary['f1']:.2f}",
        f"malware FRS {ranges['malware_frs'][0]}-{ranges['malware_frs'][1]}   "
        f"benign FRS {ranges['benign_frs'][0]}-{ranges['benign_frs'][1]}",
        f"concealed payload    : malware {agg['concealment']['malware']}, benign {agg['concealment']['benign']}",
        "```",
        "",
        "### At a stricter bar",
        "",
        "The same corpus measured at `band >= High Risk`:",
        "",
        "```",
        f"tp {agg['secondary_high_risk']['tp']}   fn {agg['secondary_high_risk']['fn']}   "
        f"fp {agg['secondary_high_risk']['fp']}   recall {agg['secondary_high_risk']['recall']:.2f}",
        "```",
        "",
        "Reported because static-only analysis has a ceiling. Reaching the higher bands",
        "requires the excluded axes - dynamic instrumentation and threat correlation.",
        "",
        "## Limitations",
        "",
        f"1. **{agg['sample_count']} samples is a small corpus.** These figures are measured on this",
        "   set, not proven at scale.",
        "2. **The dynamic axis is untested here.** Every run is static-only, so the axis carrying",
        "   the largest weight in a full analysis contributes nothing to these numbers.",
        "3. **Concealment is not malice.** Commercial packers exist. The concealed-payload signal",
        "   drives \"do not certify as safe\" and lowers confidence; it never asserts \"malicious\".",
        "4. **Family labels are behavioural patterns, not attribution.** `classification_engine.py`",
        "   matches flag combinations, so a sample can be labelled with the name of the family whose",
        "   pattern it matches rather than its own.",
        "",
    ]
    return "\n".join(lines) + "\n"


# ─── expectations ─────────────────────────────────────────────────────────────

def _compare_expectations(records: List[Dict[str, Any]], tolerance: float) -> List[str]:
    if not EXPECTATIONS.is_file():
        return [f"no expectations file at {EXPECTATIONS.relative_to(_REPO_ROOT)} - run without --check first"]

    expected = {e["sha256"]: e for e in json.loads(EXPECTATIONS.read_text(encoding="utf-8"))["samples"]}
    drift: List[str] = []

    for r in records:
        want = expected.get(r["sha256"])
        if want is None:
            drift.append(f"{r['display_name']}: sha256 {r['sha256'][:12]} not in expectations (new or replaced sample)")
            continue
        if abs(float(want["frs"]) - r["frs"]) > tolerance:
            drift.append(f"{r['display_name']}: FRS {want['frs']} -> {r['frs']} (tolerance {tolerance})")
        if want["band"] != r["band"]:
            drift.append(f"{r['display_name']}: band {want['band']} -> {r['band']}")

    seen = {r["sha256"] for r in records}
    for sha, want in expected.items():
        if sha not in seen:
            drift.append(f"{want['display_name']}: expected but not scored (missing from corpus)")

    return drift


# ─── main ─────────────────────────────────────────────────────────────────────

def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus-dir", type=Path, default=None)
    ap.add_argument("--json-out", type=Path, default=DEFAULT_JSON_OUT)
    ap.add_argument("--md-out", type=Path, default=DEFAULT_MD_OUT)
    ap.add_argument("--check", action="store_true", help="compare against scripts/corpus_expectations.json")
    ap.add_argument("--tolerance", type=float, default=0.5, help="allowed FRS drift under --check")
    ap.add_argument("--only", default=None, help="comma-separated categories, e.g. Malware,Safe")
    ap.add_argument("--sample", default=None, help="score a single sample by display name")
    ap.add_argument("--write-expectations", action="store_true", help="(re)write the expectations baseline")
    ap.add_argument("--no-write", action="store_true", help="print only; write nothing")
    ap.add_argument("--require-corpus", action="store_true", help="treat a missing corpus as failure, not skip")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    if _androguard_version() == "unavailable":
        print("androguard is not importable - cannot analyse APKs.", file=sys.stderr)
        print("Run inside the analysis-engine image; see this script's docstring.", file=sys.stderr)
        return EXIT_REGRESSION if args.require_corpus else EXIT_CANNOT_RUN

    root = find_labelled_corpus_root(args.corpus_dir)
    if root is None:
        print("Labelled corpus not found. Searched, in order:", file=sys.stderr)
        for candidate in corpus_search_order(args.corpus_dir):
            print(f"  - {candidate}", file=sys.stderr)
        print(
            "\nThe corpus is gitignored (live malware), so a fresh clone has none.\n"
            "Point at it with SUDARSHAN_LABELLED_CORPUS_DIR or --corpus-dir.",
            file=sys.stderr,
        )
        return EXIT_REGRESSION if args.require_corpus else EXIT_CANNOT_RUN

    samples = load_labelled_samples(root)
    if args.only:
        wanted = {c.strip() for c in args.only.split(",")}
        unknown = wanted - set(CATEGORY_LABELS)
        if unknown:
            print(f"Unknown categories: {sorted(unknown)}. Known: {sorted(CATEGORY_LABELS)}", file=sys.stderr)
            return EXIT_REGRESSION
        samples = [s for s in samples if s.category in wanted]
    if args.sample:
        samples = [s for s in samples if s.display_name == args.sample]

    if not samples:
        print("No samples matched the given filters.", file=sys.stderr)
        return EXIT_REGRESSION if args.require_corpus else EXIT_CANNOT_RUN

    print(f"Corpus: {root}  ({len(samples)} samples)", file=sys.stderr)

    records: List[Dict[str, Any]] = []
    for sample in samples:
        if args.verbose:
            print(f"  scoring {sample.category}/{sample.file_name} ...", file=sys.stderr)
        try:
            records.append(_score_one(sample))
        except Exception as exc:
            print(f"  FAILED {sample.file_name}: {type(exc).__name__}: {exc}", file=sys.stderr)
            return EXIT_REGRESSION

    aggregate = _aggregate(records)
    doc = {
        "schema_version": SCHEMA_VERSION,
        "run": {
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "git_commit": _git_commit(),
            "androguard_version": _androguard_version(),
            "python": platform.python_version(),
            "corpus_root": str(root),
        },
        "decision_rule": {
            "flagged": FLAGGED_RULE,
            "rationale": FLAGGED_RATIONALE,
            "positive_class": "Malware/",
            "negative_classes": ["Safe/", "MAS Crackmes/", "Vulnerable/"],
            "vulnerable_counted_as": "benign (deliberately insecure is not malicious)",
        },
        "config": {
            "dynamic": "not_run",
            "correlation": "unavailable",
            "vide": "not_run",
            "axes_excluded_expected": ["correlation", "dynamic"],
        },
        "samples": records,
        "aggregate": aggregate,
    }
    doc["results_digest"] = _results_digest(records, aggregate)

    # Invariants are non-negotiable: a violated one means the pipeline changed
    # shape, and the scores are not comparable to anything.
    violations = [
        f"{r['display_name']}: {name}"
        for r in records
        for name, ok in r["invariants"].items()
        if not ok
    ]

    primary = aggregate["primary"]
    print(
        f"\n{primary['tp']}/{aggregate['malware_count']} malware flagged, "
        f"{primary['fp']}/{aggregate['benign_count']} false positives, "
        f"precision {primary['precision']:.2f} recall {primary['recall']:.2f}",
        file=sys.stderr,
    )
    print(f"digest {doc['results_digest'][:16]}", file=sys.stderr)

    if not args.no_write:
        for path, payload in (
            (args.json_out, json.dumps(doc, indent=2, sort_keys=False) + "\n"),
            (args.md_out, _render_markdown(doc)),
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(payload, encoding="utf-8")
            print(f"wrote {path}", file=sys.stderr)

    if args.write_expectations and not args.no_write:
        EXPECTATIONS.write_text(
            json.dumps(
                {
                    "_comment": (
                        "Baseline for scripts/validate_corpus.py --check. The APKs are "
                        "gitignored, so this file is what lets someone without the malware "
                        "verify that the published results still hold."
                    ),
                    "androguard_version": doc["run"]["androguard_version"],
                    "generated_at": doc["run"]["generated_at"],
                    "results_digest": doc["results_digest"],
                    "samples": [
                        {
                            "display_name": r["display_name"],
                            "sha256": r["sha256"],
                            "label": r["label"],
                            "frs": r["frs"],
                            "band": r["band"],
                            "confidence": r["confidence"],
                        }
                        for r in records
                    ],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"wrote {EXPECTATIONS}", file=sys.stderr)

    drift = _compare_expectations(records, args.tolerance) if args.check else []

    if violations:
        print("\nINVARIANT VIOLATIONS:", file=sys.stderr)
        for v in violations:
            print(f"  - {v}", file=sys.stderr)
    if drift:
        print("\nDRIFT vs expectations:", file=sys.stderr)
        for d in drift:
            print(f"  - {d}", file=sys.stderr)

    return EXIT_REGRESSION if (violations or drift) else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
