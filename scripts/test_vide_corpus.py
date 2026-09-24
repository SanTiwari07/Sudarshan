import argparse
import hashlib
import json
import logging
import os
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "shared"))

from androguard.core.apk import APK
from sudarshan_core.engines.vide.baseline_store import get_baselines
from sudarshan_core.engines.vide.pipeline import safe_run_vide_analysis
import sudarshan_core.engines.frida_sandbox as fs

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Only the parts VIDE reads for static
_WANTED_PREFIXES = ("assets/", "res/layout")

def extract_apk_static(apk_path: Path, dest: Path) -> None:
    with zipfile.ZipFile(apk_path) as archive:
        for name in archive.namelist():
            if not name.startswith(_WANTED_PREFIXES):
                continue
            target = (dest / name).resolve()
            if not str(target).startswith(str(dest.resolve())):
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                with archive.open(name) as src, open(target, "wb") as out:
                    shutil.copyfileobj(src, out)
            except (OSError, zipfile.BadZipFile):
                continue

def analyze_apk(apk_path: Path, baselines) -> Dict[str, Any]:
    logger.info(f"Processing {apk_path.name}")
    
    sha256 = hashlib.sha256(apk_path.read_bytes()).hexdigest()
    
    try:
        a = APK(str(apk_path))
        package_name = a.get_package()
        version_name = a.get_androidversion_name()
        version_code = a.get_androidversion_code()
        app_label = a.get_app_name()
        certs = a.get_certificates()
        cert_sha256 = certs[0].sha256_fingerprint.replace(" ", "").lower() if certs else ""
    except Exception as e:
        logger.error(f"Failed to parse {apk_path.name} with Androguard: {e}")
        return {"filename": apk_path.name, "status": "FAIL", "errors": [str(e)]}

    certificate_dict = {
        "certificate_sha256": cert_sha256,
        "is_signed": bool(cert_sha256)
    }

    # Extract for static analysis
    with tempfile.TemporaryDirectory(prefix="vide-corpus-") as tmp:
        decode_dir = Path(tmp)
        extract_apk_static(apk_path, decode_dir)
        
        # Run Dynamic Analysis
        logger.info(f"Running dynamic analysis for {apk_path.name}")
        try:
            import asyncio
            dynamic_result = asyncio.run(fs.run_frida_analysis(str(apk_path), package_name=package_name))
        except Exception as e:
            logger.error(f"Dynamic analysis failed for {apk_path.name}: {e}")
            dynamic_result = {}

        # Run Static + Merge
        logger.info(f"Running static analysis & VIDE comparison for {apk_path.name}")
        try:
            vide_result = safe_run_vide_analysis(
                decode_dir=decode_dir,
                dynamic_result=dynamic_result,
                package_name=package_name,
                certificate=certificate_dict,
                baselines=baselines,
                apktool_available=False
            )
        except Exception as e:
            logger.error(f"VIDE pipeline failed for {apk_path.name}: {e}")
            return {"filename": apk_path.name, "status": "FAIL", "errors": [str(e)]}

    # Compute expected identity
    name_upper = apk_path.name.upper()
    expected_identity = ""
    for inst in ["SBI", "HDFC", "ICICI", "AXIS", "BOB", "PNB", "BOI", "KOTAK", "INDUS", "UNION"]:
        if inst in name_upper:
            expected_identity = inst
            break

    matched_baseline = vide_result.get("matched_baseline") or {}
    top_baseline = matched_baseline.get("display_name", "")
    
    status = "PASS" if vide_result.get("status") == "OK" else "FAIL"

    return {
        "filename": apk_path.name,
        "sha256": sha256,
        "package": package_name,
        "version_name": version_name,
        "version_code": version_code,
        "app_label": app_label,
        "certificate_sha256": cert_sha256,
        "expected_identity": expected_identity,
        "ground_truth_available": bool(expected_identity),
        "static_profile": {
            "strings": vide_result.get("suspect_profile_summary", {}).get("string_count", 0),
            "views": vide_result.get("suspect_profile_summary", {}).get("view_node_count", 0),
            "colors": len(vide_result.get("extracted_profile", {}).get("colors", [])),
            "html": len(vide_result.get("extracted_profile", {}).get("asset_hashes", [])) # rough proxy
        },
        "dynamic": {
            "frida_attached": bool(dynamic_result),
            "runtime_events": len(dynamic_result.get("frida_events", {}).get("banking", [])) + len(dynamic_result.get("frida_events", {}).get("network", [])),
            "webview_events": len(dynamic_result.get("vide_webview_html", []))
        },
        "vide": {
            "top_baseline": top_baseline,
            "string_similarity": vide_result.get("vide_compare", {}).get("scores", {}).get("string_jaccard", 0.0),
            "tree_similarity": vide_result.get("vide_compare", {}).get("scores", {}).get("tree_similarity", 0.0),
            "color_similarity": vide_result.get("vide_compare", {}).get("scores", {}).get("color_match", 0.0),
            "combined_confidence": vide_result.get("vide_compare", {}).get("confidence", 0.0),
            "detected": vide_result.get("vide_compare", {}).get("detected", False)
        },
        "risk": {
            "visual_signal": vide_result.get("visual_impersonation_tier_label", ""),
            "critical_escalation": vide_result.get("critical_visual_cluster", False)
        },
        "status": status,
        "errors": [vide_result.get("error")] if vide_result.get("error") else [],
        "warnings": []
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", default=str(REPO_ROOT / "test apk"), help="Directory containing APKs")
    parser.add_argument("--out", default=str(REPO_ROOT / "reports" / "vide_corpus_results.json"), help="Output JSON")
    args = parser.parse_args()

    target_dir = Path(args.dir)
    apks = list(target_dir.glob("*.apk"))
    logger.info(f"Found {len(apks)} APKs in {target_dir}")

    baselines = get_baselines()
    logger.info(f"Loaded {len(baselines)} baselines")

    results = []
    
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    
    for apk in apks:
        res = analyze_apk(apk, baselines)
        results.append(res)
        
        with open(args.out, "w") as f:
            json.dump(results, f, indent=2)

if __name__ == "__main__":
    main()
