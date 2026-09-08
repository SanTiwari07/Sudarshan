import sys
import os
from pathlib import Path

sys.path.insert(0, "d:/Sudarshan/shared")
sys.path.insert(0, "d:/Sudarshan/backend")

from sudarshan_core.engines.apktool_engine import ApktoolEngine
from sudarshan_core.engines.vide.pipeline import safe_run_vide_analysis
from sudarshan_core.engines.vide.ui_profile import UIProfile

test_dir = Path("d:/Sudarshan/tests/apks/VIDE_testapks")
engine = ApktoolEngine()

print('Testing all VIDE test APKs against banking-baseline-corpus...', flush=True)

for apk in sorted(test_dir.glob('*.apk')):
    print(f'Decoding {apk.name}...', end=' ', flush=True)
    res = engine.analyze(apk)
    prof = UIProfile(
        source=res.ui_profile.get('source', ''),
        strings=res.ui_profile.get('strings', []),
        view_sequence=res.ui_profile.get('view_sequence', []),
        colors=res.ui_profile.get('colors', []),
        asset_hashes=res.ui_profile.get('asset_hashes', []),
    )
    vide_res = safe_run_vide_analysis(suspect_profile=prof, package_name='com.test.suspect')
    mb = vide_res.get('matched_baseline') or {}
    detected = vide_res.get('visual_impersonation_detected')
    score = vide_res.get('similarity_score', 0.0)
    inst = vide_res.get('visual_impersonation_institution') or mb.get('display_name', 'None')
    inst_id = mb.get('institution_id', 'None')
    expected_id = apk.stem
    match_status = 'PASS' if expected_id == inst_id else 'FAIL'
    print(f'[{match_status}] -> Matched: {inst_id} ({inst}) Score: {score:.4f} Detected: {detected}', flush=True)

print('All APK tests completed.', flush=True)
