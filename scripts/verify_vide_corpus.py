#!/usr/bin/env python3
"""
Run VIDE against the 10 built baseline APKs and assert the engine contract.

Two things are verified, and they are different questions:

**Attribution self-consistency.** Every baseline APK must be attributed to its
*own* baseline entry. This is a check on the extraction pipeline: if
``BASE-02-HDFC.apk`` does not read as HDFC, the static extractor is losing the
signal that real detection depends on.

**Result contract.** ``safe_run_vide_analysis`` must return a structured result
carrying a ``findings`` list, a ``matched_baseline``, a ``similarity_score``
and a non-empty ``extracted_profile``. Downstream - the risk engine, the report
generator, the API - consumes those keys, so a run that silently returns
without them is a failure even when the attribution happens to be right.

A third case exercises ``CH06-SIGNER-IMPERSONATION`` end to end by re-running
one APK under an official bank package name it is not signed for.

The corpus apps are Capacitor builds, so their UI lives in ``assets/public``
(HTML + a JS bundle + a CSS token file), not ``res/layout``. The APK is a zip,
so this runs without apktool.

Usage:
    python scripts/verify_vide_corpus.py [--json]
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "shared"))

from sudarshan_core.engines.vide.baseline_store import get_baselines  # noqa: E402
from sudarshan_core.engines.vide.corpus_loader import find_corpus_root  # noqa: E402
from sudarshan_core.engines.vide.pipeline import safe_run_vide_analysis  # noqa: E402

# Only the parts VIDE reads. Extracting 445 entries per APK wastes time.
_WANTED_PREFIXES = ("assets/", "res/layout")

# A package one of the protected institutions owns, used for the CH06 case.
_IMPERSONATED_PACKAGE = "com.sbi.lotus"


def corpus_apk_dir() -> Path | None:
    root = find_corpus_root()
    if root is None:
        return None
    apk_dir = root / "built_apks"
    return apk_dir if apk_dir.is_dir() else None


def extract_apk(apk_path: Path, dest: Path) -> None:
    with zipfile.ZipFile(apk_path) as archive:
        for name in archive.namelist():
            if not name.startswith(_WANTED_PREFIXES):
                continue
            # Zip entries are attacker-controlled paths in the general case.
            target = (dest / name).resolve()
            if not str(target).startswith(str(dest.resolve())):
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                with archive.open(name) as src, open(target, "wb") as out:
                    shutil.copyfileobj(src, out)
            except (OSError, zipfile.BadZipFile):
                continue


def _run(apk_path: Path, baselines: List[Any], **kwargs: Any) -> Dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="vide-verify-") as tmp:
        decode_dir = Path(tmp)
        extract_apk(apk_path, decode_dir)
        return safe_run_vide_analysis(
            decode_dir=decode_dir,
            baselines=baselines,
            **kwargs,
        )


def contract_failures(result: Dict[str, Any]) -> List[str]:
    """Which parts of the documented result contract this run did not honour."""
    problems: List[str] = []

    if result.get("status") != "OK":
        problems.append(f"status={result.get('status')} ({result.get('error') or '-'})")
    if not isinstance(result.get("findings"), list):
        problems.append("findings missing")
    if "matched_baseline" not in result:
        problems.append("matched_baseline missing")
    if not isinstance(result.get("similarity_score"), (int, float)):
        problems.append("similarity_score missing")

    profile = result.get("extracted_profile") or {}
    if not profile.get("strings"):
        problems.append("extracted_profile.strings empty")
    if not profile.get("colors"):
        problems.append("extracted_profile.colors empty")

    return problems


def verify_one(apk_path: Path, baselines: List[Any]) -> Dict[str, Any]:
    expected = apk_path.stem  # e.g. BASE-02-HDFC
    result = _run(apk_path, baselines, package_name="", certificate={})

    corpus = result.get("corpus_compare") or {}
    ranked = corpus.get("ranked") or []
    top = ranked[0] if ranked else {}
    summary = result.get("suspect_profile_summary") or {}
    profile = result.get("extracted_profile") or {}
    matched = result.get("matched_baseline") or {}

    return {
        "apk": apk_path.name,
        "expected": expected,
        "attributed": top.get("institution_id", ""),
        "correct": top.get("institution_id") == expected,
        "detected": bool(corpus.get("detected")),
        "confidence": top.get("confidence", 0.0),
        "scores": top.get("scores", {}),
        "ambiguous": bool((corpus.get("attribution") or {}).get("ambiguous")),
        "signatures": corpus.get("suspect_signatures") or [],
        "strings": summary.get("string_count", 0),
        "ast_nodes": summary.get("ast_node_count", 0),
        "matched_baseline": matched.get("institution_id", ""),
        "similarity_score": result.get("similarity_score", 0.0),
        "finding_rules": [f.get("rule_id") for f in (result.get("findings") or [])],
        "profile_strings": len(profile.get("strings") or []),
        "profile_colors": len(profile.get("colors") or []),
        "contract_problems": contract_failures(result),
    }


def verify_signer_impersonation(apk_path: Path, baselines: List[Any]) -> Dict[str, Any]:
    """
    CH06 end to end: a corpus APK re-labelled with a real bank's package name.

    The built APKs are signed with a debug keystore under their own test
    package, so claiming ``com.sbi.lotus`` is exactly the impersonation the
    rule exists to catch.
    """
    result = _run(
        apk_path,
        baselines,
        package_name=_IMPERSONATED_PACKAGE,
        certificate={
            "certificate_sha256": "de" * 32,
            "subject": "CN=Android Debug, O=Android, C=US",
        },
    )
    signer = result.get("signer_impersonation") or {}
    rules = [f.get("rule_id") for f in (result.get("findings") or [])]
    return {
        "apk": apk_path.name,
        "package_name": _IMPERSONATED_PACKAGE,
        "detected": bool(signer.get("detected")),
        "institution_id": signer.get("institution_id", ""),
        "debug_signed": bool(signer.get("debug_signed")),
        "finding_rules": rules,
        "correct": bool(signer.get("detected"))
        and "CH06-SIGNER-IMPERSONATION" in rules,
        "evidence_lines": signer.get("evidence_lines") or [],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    args = parser.parse_args()

    apk_dir = corpus_apk_dir()
    if apk_dir is None:
        print(
            "Baseline corpus not found. Set BANKING_BASELINE_CORPUS_DIR, or place "
            "the corpus at <repo>/banking-baseline-corpus.",
            file=sys.stderr,
        )
        return 2

    apks = sorted(apk_dir.glob("*.apk"))
    if not apks:
        print(f"No APKs in {apk_dir}", file=sys.stderr)
        return 2

    baselines = get_baselines()
    results = [verify_one(apk, baselines) for apk in apks]
    signer_case = verify_signer_impersonation(apks[0], baselines)

    if args.json:
        print(json.dumps({"attribution": results, "signer": signer_case}, indent=2))
    else:
        print(f"{'APK':22} {'attributed':15} {'ok':4} {'conf':6} "
              f"{'str':5} {'struct':7} {'color':6} {'strings':8} {'colors':7} "
              f"{'rules':14} {'contract'}")
        print("-" * 128)
        for r in results:
            s = r["scores"] or {}
            print(
                f"{r['apk']:22} {r['attributed'] or '-':15} "
                f"{'PASS' if r['correct'] else 'FAIL':4} "
                f"{r['confidence']:.3f}  "
                f"{s.get('string_containment', 0):.2f}  "
                f"{s.get('structural', 0):.2f}    "
                f"{s.get('color', 0):.2f}   "
                f"{r['profile_strings']:<8} {r['profile_colors']:<7} "
                f"{','.join(r['finding_rules']) or '-':14} "
                f"{'OK' if not r['contract_problems'] else '; '.join(r['contract_problems'])}"
            )

        print(
            f"\nCH06 impersonation case: {signer_case['apk']} declared as "
            f"{signer_case['package_name']} -> "
            f"{'PASS' if signer_case['correct'] else 'FAIL'} "
            f"(institution {signer_case['institution_id'] or '-'}, "
            f"debug-signed {signer_case['debug_signed']})"
        )
        for line in signer_case["evidence_lines"]:
            print(f"    {line}")

    correct = sum(1 for r in results if r["correct"])
    contract_ok = sum(1 for r in results if not r["contract_problems"])
    print(f"\nAttribution accuracy: {correct}/{len(results)} "
          f"({100.0 * correct / len(results):.0f}%)")
    if correct < len(results):
        # Near-universally the cause on a fresh corpus checkout: the shipped
        # fingerprints are authored from the design specification, while the
        # React builds render different labels ("Available Balance", not
        # "Account Balance"). The string axis carries 40% of the confidence
        # score, so that drift alone can flip an attribution.
        print(
            "  Hint: if this is a fresh corpus checkout, its exactStrings are\n"
            "  spec-authored and drift from what the built APKs render. Run\n"
            "  `python scripts/regenerate_fingerprints.py --write` to rebuild\n"
            "  them from the shipped artifacts, then re-run this check."
        )
    print(f"Result contract:      {contract_ok}/{len(results)} "
          f"({100.0 * contract_ok / len(results):.0f}%)")
    print(f"CH06 signer rule:     {'PASS' if signer_case['correct'] else 'FAIL'}")

    ok = (
        correct == len(results)
        and contract_ok == len(results)
        and signer_case["correct"]
    )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
