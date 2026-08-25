"""End-to-end attribution over the ten reference bank APKs.

This is the check that the unit tests around it cannot make: every other VIDE
test feeds the comparer a hand-written profile, so it verifies the scoring rules
and not the extraction they run on. Here the profile comes out of a real APK,
which is the only way a regression in the extractors - or a baseline whose
palette drifts from the app it stands for - shows up before a live scan.

Skipped when the APKs are not present, so a slim checkout still runs the suite.
"""

import shutil
import tempfile
import zipfile
from pathlib import Path

import pytest

from sudarshan_core.engines.vide.baseline_store import get_baselines
from sudarshan_core.engines.vide.pipeline import safe_run_vide_analysis

APK_DIR = Path(__file__).resolve().parents[2] / "tests" / "apks" / "VIDE_testapks"

#: APK -> the institution its UI belongs to.
EXPECTED = {
    "BASE-01-SBI": "demo_sbi_yono",
    "BASE-02-HDFC": "demo_hdfc_mobile",
    "BASE-03-ICICI": "demo_icici_imobile",
    "BASE-04-AXIS": "demo_axis_mobile",
    "BASE-05-BOB": "demo_bob_world",
    "BASE-06-PNB": "demo_pnb_one",
    "BASE-07-BOI": "demo_boi_mobile",
    "BASE-08-KOTAK": "demo_kotak_811",
    "BASE-09-INDUS": "demo_indus_mobile",
    "BASE-10-UNION": "demo_union_vyom",
}

# Empty, and kept so a future miss is recorded here with its wrong answer rather
# than the expectation being quietly deleted. BASE-01-SBI lived here until its
# baseline was given the palette its reference app actually renders.
KNOWN_MISATTRIBUTED: dict[str, str] = {}

requires_apks = pytest.mark.skipif(
    not APK_DIR.is_dir() or not any(APK_DIR.glob("*.apk")),
    reason="reference bank APKs not present",
)


def _analyse(apk: Path):
    decode_dir = Path(tempfile.mkdtemp(prefix="vide-apk-"))
    try:
        with zipfile.ZipFile(apk) as archive:
            for name in archive.namelist():
                if not name.startswith(("assets/", "res/layout")):
                    continue
                target = (decode_dir / name).resolve()
                if not str(target).startswith(str(decode_dir.resolve())):
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(name) as src, open(target, "wb") as out:
                    shutil.copyfileobj(src, out)
        return safe_run_vide_analysis(
            decode_dir=decode_dir,
            package_name="com.evil.clone",
            certificate={"certificate_sha256": "de" * 32},
        )
    finally:
        shutil.rmtree(decode_dir, ignore_errors=True)


@requires_apks
@pytest.mark.parametrize("stem", sorted(EXPECTED))
def test_reference_apk_is_attributed_to_its_own_bank(stem):
    apk = APK_DIR / f"{stem}.apk"
    if not apk.is_file():
        pytest.skip(f"{apk.name} not present")

    result = _analyse(apk)
    compare = result["vide_compare"]

    assert compare["detected"] is True, f"{stem} was not detected at all"

    attributed = compare["institution_id"]
    if stem in KNOWN_MISATTRIBUTED:
        assert attributed == KNOWN_MISATTRIBUTED[stem], (
            f"{stem} now attributes to {attributed!r}. If that is the correct "
            f"bank, drop it from KNOWN_MISATTRIBUTED."
        )
        return

    assert attributed == EXPECTED[stem]


@requires_apks
def test_every_reference_apk_yields_a_usable_profile():
    """Extraction, not scoring: an empty profile makes attribution meaningless."""
    for stem in sorted(EXPECTED):
        apk = APK_DIR / f"{stem}.apk"
        if not apk.is_file():
            continue
        profile = _analyse(apk)["extracted_profile"]
        assert profile["strings"], f"{stem} extracted no strings"
        assert profile["colors"], f"{stem} extracted no colours"


@requires_apks
def test_the_baseline_set_covers_every_reference_apk():
    """A baseline must declare which reference app it stands for."""
    declared = {
        (b.baseline_id or "").upper() for b in get_baselines() if b.baseline_id
    }
    missing = sorted(s for s in EXPECTED if s.upper() not in declared)
    assert not missing, f"no baseline declares baseline_id for: {missing}"
