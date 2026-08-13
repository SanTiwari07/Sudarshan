#!/usr/bin/env python3
"""
Run VIDE extraction against the 10 built baseline APKs and report accuracy.

This is the verification pass from the VIDE plan: every baseline APK should be
attributed to its *own* baseline entry. It is a self-consistency check on the
extraction pipeline - if BASE-02-HDFC.apk does not read as HDFC, the static
extractor is losing the signal that real detection depends on.

The corpus apps are Capacitor builds, so their UI lives in ``assets/public``
(HTML + a CSS token file), not ``res/layout``. The APK is a zip, so this runs
without apktool.

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
from sudarshan_core.engines.vide.pipeline import run_vide_analysis  # noqa: E402

APK_DIR = REPO_ROOT / "apk_details" / "built_apks"

# Only the parts VIDE reads. Extracting 445 entries per APK wastes time.
_WANTED_PREFIXES = ("assets/", "res/layout")


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


def verify_one(apk_path: Path, baselines: List[Any]) -> Dict[str, Any]:
    expected = apk_path.stem  # e.g. BASE-02-HDFC
    with tempfile.TemporaryDirectory(prefix="vide-verify-") as tmp:
        decode_dir = Path(tmp)
        extract_apk(apk_path, decode_dir)
        result = run_vide_analysis(
            decode_dir=decode_dir,
            package_name="",
            certificate={},
            baselines=baselines,
        )

    corpus = result.get("corpus_compare") or {}
    ranked = corpus.get("ranked") or []
    top = ranked[0] if ranked else {}
    summary = result.get("suspect_profile_summary") or {}

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
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    args = parser.parse_args()

    if not APK_DIR.is_dir():
        print(f"APK directory not found: {APK_DIR}", file=sys.stderr)
        return 2

    apks = sorted(APK_DIR.glob("*.apk"))
    if not apks:
        print(f"No APKs in {APK_DIR}", file=sys.stderr)
        return 2

    baselines = get_baselines()
    results = [verify_one(apk, baselines) for apk in apks]

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(f"{'APK':22} {'attributed':15} {'ok':4} {'conf':6} "
              f"{'str':5} {'struct':7} {'color':6} {'strings':8} {'ast'}")
        print("-" * 96)
        for r in results:
            s = r["scores"] or {}
            print(
                f"{r['apk']:22} {r['attributed'] or '-':15} "
                f"{'PASS' if r['correct'] else 'FAIL':4} "
                f"{r['confidence']:.3f}  "
                f"{s.get('string_containment', 0):.2f}  "
                f"{s.get('structural', 0):.2f}    "
                f"{s.get('color', 0):.2f}   "
                f"{r['strings']:<8} {r['ast_nodes']}"
            )

    correct = sum(1 for r in results if r["correct"])
    print(f"\nAttribution accuracy: {correct}/{len(results)} "
          f"({100.0 * correct / len(results):.0f}%)")
    return 0 if correct == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
