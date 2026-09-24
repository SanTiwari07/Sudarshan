import json
import logging
from pathlib import Path
import sys
import tempfile
import zipfile
import shutil

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "shared"))

from sudarshan_core.engines.vide.baseline_store import get_baselines
from sudarshan_core.engines.vide.ui_profile import UIProfile
from sudarshan_core.engines.vide.layout_extractor import extract_from_decode_dir
from sudarshan_core.engines.vide.pipeline import extract_html_from_assets, extract_styles_from_assets, extract_js_bundles, profile_from_html, profile_from_style_blob, profile_from_js_bundle, _merge_profiles, build_suspect_ast
from sudarshan_core.engines.vide.compare import compare_profiles, DETECTION_THRESHOLD
from sudarshan_core.engines.vide.fuzzy import label_weights

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def extract_apk_static(apk_path: Path, dest: Path) -> None:
    _WANTED_PREFIXES = ("assets/", "res/layout")
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

def build_profile(apk_path: Path) -> UIProfile:
    suspect = UIProfile(source="empty")
    with tempfile.TemporaryDirectory(prefix="vide-matrix-") as tmp:
        decode_dir = Path(tmp)
        extract_apk_static(apk_path, decode_dir)
        
        static_prof = extract_from_decode_dir(decode_dir)
        suspect = _merge_profiles(suspect, static_prof)
        for html in extract_html_from_assets(decode_dir):
            suspect = _merge_profiles(suspect, profile_from_html(html, "assets_html"))
        for blob in extract_styles_from_assets(decode_dir):
            suspect = _merge_profiles(suspect, profile_from_style_blob(blob))
        for bundle in extract_js_bundles(decode_dir):
            suspect = _merge_profiles(suspect, profile_from_js_bundle(bundle))
            
    return suspect

def main():
    target_dir = REPO_ROOT / "test apk"
    apks = list(target_dir.glob("*.apk"))
    baselines = get_baselines()
    
    # Pre-calculate label weights over baselines
    weights = label_weights([bl.profile.strings for bl in baselines])
    
    matrix = []
    for apk in apks:
        logger.info(f"Building profile for {apk.name}")
        prof = build_profile(apk)
        
        for bl in baselines:
            # We don't have package name or cert for these, we just want raw visual similarity
            res = compare_profiles(prof, bl, package_name="", signer_sha256="", string_weights=weights)
            matrix.append({
                "source_apk": apk.name,
                "candidate_baseline": bl.display_name,
                "string_score": res.string_jaccard,
                "tree_score": res.tree_similarity,
                "color_score": res.color_match,
                "combined_score": res.confidence,
                "detected": res.detected,
                "over_threshold": res.confidence >= DETECTION_THRESHOLD
            })

    out_file = REPO_ROOT / "reports" / "vide_corpus_matrix.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, 'w') as f:
        json.dump(matrix, f, indent=2)
    logger.info(f"Matrix saved to {out_file}")

if __name__ == '__main__':
    main()
