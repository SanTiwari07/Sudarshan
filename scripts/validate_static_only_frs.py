#!/usr/bin/env python3
"""
Validate static-only FRS scores against CASE_STUDIES.md claims.

Step 0 verifies that correlation_result=None and {"available": False} produce
identical axis exclusion before any case-study assertions run.

Usage:
    PYTHONPATH=backend;shared python scripts/validate_static_only_frs.py
    PYTHONPATH=backend;shared python scripts/validate_static_only_frs.py -v
    PYTHONPATH=backend;shared python scripts/validate_static_only_frs.py --expect-band drinik=Critical
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
ARTIFACT_PATH = REPO_ROOT / "scripts" / "static_only_frs_validation.json"

# Fixtures live under backend/tests (not on default PYTHONPATH).
sys.path.insert(0, str(REPO_ROOT / "backend" / "tests"))

# Repo root on sys.path via PYTHONPATH=backend;shared
from sudarshan_core.engines.classification_engine import classify_family
from sudarshan_core.engines.risk_engine import calculate_risk_score
from sudarshan_core.models.schemas import StaticAnalysisFlags

from case_study_fixtures import (  # type: ignore[import-not-found]
    CORRELATION_UNAVAILABLE,
    case_study_scenarios,
    engine_band_to_case_study_label,
)

# Expected renormalized weights when only STEI + banking_impact are live.
EXPECTED_TWO_AXIS_WEIGHTS = {"stei": 0.556, "banking_impact": 0.444}


def _verify_correlation_sentinels(verbose: bool) -> Tuple[bool, str]:
    """
    Step 0: confirm None and {"available": False} hit the same code path.
    """
    probe = StaticAnalysisFlags(
        has_accessibility_abuse=True,
        has_sms_read_write=True,
        targets_indian_banks=True,
    )
    perms = ["android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.RECEIVE_SMS"]

    def _snapshot(corr: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        r = calculate_risk_score(
            probe,
            ai_confidence=1.0,
            dynamic_result=None,
            correlation_result=corr,
            family="Unknown",
            all_permissions=perms,
        )
        b = r["frs_breakdown"]
        return {
            "axes_excluded": b["axes_excluded"],
            "axes_used": b["axes_used"],
            "base_score": r["base_score"],
            "final_risk_score": r["final_risk_score"],
            "risk_band": r["risk_band"],
        }

    none_snap = _snapshot(None)
    false_snap = _snapshot({"available": False})

    keys = ["axes_excluded", "axes_used", "base_score", "final_risk_score", "risk_band"]
    mismatches = [k for k in keys if none_snap[k] != false_snap[k]]

    if verbose:
        print("=== Step 0: correlation_result sentinel equivalence ===")
        for k in keys:
            match = none_snap[k] == false_snap[k]
            print(f"  {k}: None={none_snap[k]!r}  available=False={false_snap[k]!r}  MATCH={match}")
        print(f"  ALL_IDENTICAL={not mismatches}\n")

    if mismatches:
        return False, f"Sentinel mismatch on fields: {mismatches}"
    return True, "None and {'available': False} produce identical axis exclusion"


def _recompute_base_score(breakdown: Dict[str, Any]) -> float:
    return sum(w * breakdown[axis] for axis, w in breakdown["axes_used"].items())


def _evaluate_scenario(scenario: Dict[str, Any]) -> Dict[str, Any]:
    flags: StaticAnalysisFlags = scenario["flags"]
    family, family_rule = classify_family(flags)

    result = calculate_risk_score(
        flags,
        ai_confidence=1.0,
        dynamic_result=None,
        correlation_result=CORRELATION_UNAVAILABLE,
        family=family,
        all_permissions=scenario["permissions"],
    )
    b = result["frs_breakdown"]
    stei_axes = b.get("stei_axes") or {}

    recomputed = _recompute_base_score(b)
    weight_sum = sum(b["axes_used"].values())

    return {
        "id": scenario["id"],
        "label": scenario["label"],
        "classifier_family": family,
        "classifier_rule": family_rule,
        "case_study_claimed_frs": scenario["case_study_claimed_frs"],
        "case_study_claimed_band": scenario["case_study_claimed_band"],
        "stei": b["stei"],
        "stei_axes": stei_axes,
        "banking_impact": b["banking_impact"],
        "correlation": b["correlation"],
        "dynamic": b["dynamic"],
        "axes_used": b["axes_used"],
        "axes_excluded": b["axes_excluded"],
        "formula_used": b["formula_used"],
        "dynamic_available": b["dynamic_available"],
        "base_score": result["base_score"],
        "final_risk_score": result["final_risk_score"],
        "risk_band": result["risk_band"],
        "case_study_band_equiv": engine_band_to_case_study_label(result["risk_band"]),
        "recomputed_base_score": round(recomputed, 2),
        "weight_sum": round(weight_sum, 3),
        "invariants": {
            "axes_excluded_static_only": b["axes_excluded"] == ["dynamic", "correlation"],
            "two_axis_weights": all(
                abs(b["axes_used"].get(k, 0) - v) < 0.001 for k, v in EXPECTED_TWO_AXIS_WEIGHTS.items()
            ),
            "weights_sum_to_one": abs(weight_sum - 1.0) < 0.01,
            "base_score_matches_components": abs(result["base_score"] - recomputed) < 0.11,
        },
        "band_matches_case_study": result["risk_band"].lower().replace(" ", "_") in {
            scenario["case_study_claimed_band"].lower().replace(" ", "_"),
            engine_band_to_case_study_label(result["risk_band"]).lower(),
        },
    }


def _print_table(rows: List[Dict[str, Any]], verbose: bool) -> None:
    print("=== Static-only FRS validation (correlation unavailable) ===\n")

    header = (
        f"{'ID':<16} {'Classifier':<12} {'STEI':>7} {'Banking':>8} "
        f"{'Base':>7} {'Final':>7} {'Band':<12} {'Claimed':<10} {'Match'}"
    )
    print(header)
    print("-" * len(header))

    for row in rows:
        claimed = row["case_study_claimed_band"]
        match = "YES" if row["band_matches_case_study"] else "NO"
        print(
            f"{row['id']:<16} {row['classifier_family']:<12} "
            f"{row['stei']:>7.2f} {row['banking_impact']:>8.2f} "
            f"{row['base_score']:>7.2f} {row['final_risk_score']:>7.2f} "
            f"{row['risk_band']:<12} {claimed:<10} {match}"
        )

    print()
    for row in rows:
        print(f"--- {row['label']} ({row['id']}) ---")
        print(f"  Classifier: {row['classifier_family']} — {row['classifier_rule']}")
        ax = row["stei_axes"]
        if ax:
            print(
                f"  STEI axes: CT={ax.get('ct', 0):.1f} BT={ax.get('bt', 0):.1f} "
                f"PR={ax.get('pr', 0):.1f} OB={ax.get('ob', 0):.1f} IR={ax.get('ir', 0):.1f}"
            )
        print(f"  axes_used: {row['axes_used']}")
        print(f"  axes_excluded: {row['axes_excluded']}")
        inv = row["invariants"]
        print(
            f"  invariants: static_only={inv['axes_excluded_static_only']} "
            f"weights_0.556_0.444={inv['two_axis_weights']} "
            f"sum=1={inv['weights_sum_to_one']} "
            f"base_recompute={inv['base_score_matches_components']}"
        )
        if row["id"] == "drinik" and row["classifier_family"] != "Drinik":
            print(
                f"  *** CLASSIFIER ALERT: Drinik-shaped flags classified as "
                f"{row['classifier_family']!r}, not 'Drinik' — demo headline risk ***"
            )
        print()

    if verbose:
        print("Full JSON written to:", ARTIFACT_PATH)


def _parse_expect_bands(values: List[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for item in values:
        if "=" not in item:
            raise ValueError(f"Expected id=Band, got: {item!r}")
        sid, band = item.split("=", 1)
        out[sid.strip().lower()] = band.strip()
    return out


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Validate static-only FRS case-study bands")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print step 0 detail and artifact path")
    parser.add_argument(
        "--expect-band",
        action="append",
        default=[],
        metavar="ID=BAND",
        help="Fail if scenario id does not produce this risk_band (e.g. drinik=Critical)",
    )
    parser.add_argument(
        "--no-write",
        action="store_true",
        help="Skip writing static_only_frs_validation.json",
    )
    args = parser.parse_args(argv)

    ok, msg = _verify_correlation_sentinels(args.verbose)
    if not ok:
        print(f"FATAL step 0: {msg}", file=sys.stderr)
        return 2
    if args.verbose:
        print(f"Step 0 OK: {msg}\n")

    rows = [_evaluate_scenario(s) for s in case_study_scenarios()]

    artifact = {
        "step0_correlation_sentinel_check": msg,
        "correlation_sentinel_used": CORRELATION_UNAVAILABLE,
        "scenarios": rows,
    }

    if not args.no_write:
        ARTIFACT_PATH.write_text(json.dumps(artifact, indent=2), encoding="utf-8")

    _print_table(rows, args.verbose)

    failures: List[str] = []
    for row in rows:
        if not all(row["invariants"].values()):
            failures.append(f"{row['id']}: engine invariant failed — {row['invariants']}")
        if row["id"] == "drinik" and row["classifier_family"] != "Drinik":
            failures.append(
                f"drinik: classifier returned {row['classifier_family']!r} "
                f"(rule: {row['classifier_rule']}) — case study headline says Drinik"
            )

    expect = _parse_expect_bands(args.expect_band)
    for row in rows:
        expected = expect.get(row["id"])
        if expected and row["risk_band"].lower() != expected.lower():
            failures.append(
                f"{row['id']}: expected band {expected!r}, got {row['risk_band']!r}"
            )

    if failures:
        print("FAILURES:")
        for f in failures:
            print(f"  - {f}")
        return 1

    print("All invariants passed. Review band vs case-study Match column above for demo narrative.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
