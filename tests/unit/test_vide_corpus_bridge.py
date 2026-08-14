"""Corpus -> engine schema bridge, corpus root resolution, official packages."""

import json

import pytest

from sudarshan_core.engines.vide.baseline_store import (
    SOURCE_CORPUS,
    convert_corpus_fingerprint_to_baseline,
    load_corpus_baselines,
)
from sudarshan_core.engines.vide.corpus_loader import find_corpus_root, parse_design_md
from sudarshan_core.engines.vide.official_packages import (
    OFFICIAL_PACKAGES,
    all_official_packages,
    baseline_id_for_package,
    packages_for,
)

META = {
    "baselineId": "BASE-07-BOI",
    "appName": "BOI Mobile",
    "bank": "Bank of India",
    "corpusVersion": "1.0",
    "screens": ["SPLASH", "LOGIN", "MPIN"],
}

FINGERPRINTS = {
    "bank": "Bank of India",
    "screens": [
        {
            "screenId": "BOI-LOGIN",
            "structuralSignature": "AUTH_FORM_VERTICAL_PRIMARY_CTA",
            "regionOrder": ["HEADER", "PRIMARY_CONTENT", "FOOTER_CTA"],
            "exactStrings": ["Password", "Mobile Number / User ID", "Proceed"],
            "brandTokens": {"colorPrimary": "#005A9C", "colorSecondary": "#F26522"},
        },
        {
            "screenId": "BOI-MPIN",
            "structuralSignature": "PINPAD_NUMERIC_ENTRY",
            "regionOrder": ["HEADER", "PIN_INPUT", "NUMERIC_KEYPAD"],
            # "Password" repeats across screens and must not be duplicated.
            "exactStrings": ["Forgot MPIN?", "Password"],
            "brandTokens": {"colorPrimary": "#005A9C", "colorSecondary": "#F26522"},
        },
    ],
}


# ── schema bridge ──────────────────────────────────────────────────────────


def test_identity_fields_are_mapped():
    bl = convert_corpus_fingerprint_to_baseline(META, FINGERPRINTS)
    assert bl.institution_id == "BASE-07-BOI"
    assert bl.app_name == "BOI Mobile"
    assert bl.display_name == "BOI Mobile"
    assert bl.bank == "Bank of India"
    assert bl.source == SOURCE_CORPUS


def test_exact_strings_across_screens_become_profile_strings():
    bl = convert_corpus_fingerprint_to_baseline(META, FINGERPRINTS)
    assert "Mobile Number / User ID" in bl.profile.strings
    assert "Forgot MPIN?" in bl.profile.strings
    # De-duplicated across screens, order preserved for readable evidence.
    assert bl.profile.strings.count("Password") == 1
    assert bl.profile.strings[0] == "Password"


def test_brand_tokens_become_the_color_palette():
    bl = convert_corpus_fingerprint_to_baseline(META, FINGERPRINTS)
    assert bl.profile.color_palette == ["#005a9c", "#f26522"]
    # color_palette is an alias of colors, not a copy.
    assert bl.profile.color_palette is bl.profile.colors


def test_region_order_becomes_the_view_sequence():
    bl = convert_corpus_fingerprint_to_baseline(META, FINGERPRINTS)
    assert bl.profile.view_sequence[:3] == ["HEADER", "PRIMARY_CONTENT", "FOOTER_CTA"]


def test_screens_are_preserved_for_structural_comparison():
    bl = convert_corpus_fingerprint_to_baseline(META, FINGERPRINTS)
    assert [s.screen_id for s in bl.screens] == ["BOI-LOGIN", "BOI-MPIN"]
    assert bl.screens[1].structural_signature == "PINPAD_NUMERIC_ENTRY"


def test_official_packages_come_from_code_not_the_corpus():
    """The corpus apps are prototypes under test package names."""
    bl = convert_corpus_fingerprint_to_baseline(META, FINGERPRINTS)
    assert "com.boi.mobile" in bl.package_names
    assert bl.package_names[0] == "com.boi.mobile"


def test_design_referenced_packages_are_merged_after_official_ones():
    design = parse_design_md(
        "# APP IDENTITY\n- Google Play `com.boi.ua.android` VERIFIED\n"
    )
    bl = convert_corpus_fingerprint_to_baseline(META, FINGERPRINTS, design=design)
    assert bl.package_names[0] == "com.boi.mobile"
    assert "com.boi.ua.android" in bl.package_names


def test_converter_tolerates_a_bare_fingerprints_file():
    bl = convert_corpus_fingerprint_to_baseline({"baselineId": "BASE-01-SBI"}, {})
    assert bl.institution_id == "BASE-01-SBI"
    # Falls back to the registered display name when meta carries no appName.
    assert bl.display_name == "YONO SBI"
    assert bl.profile.strings == []


def test_bom_prefixed_json_is_readable(tmp_path):
    """The corpus producer writes UTF-8 with a BOM."""
    path = tmp_path / "app.meta.json"
    path.write_text(json.dumps(META), encoding="utf-8-sig")
    from sudarshan_core.engines.vide.corpus_loader import read_corpus_json

    assert read_corpus_json(path)["baselineId"] == "BASE-07-BOI"


# ── official package registry ──────────────────────────────────────────────


def test_all_ten_institutions_are_registered():
    assert len(OFFICIAL_PACKAGES) == 10
    assert set(OFFICIAL_PACKAGES) == {
        "BASE-01-SBI", "BASE-02-HDFC", "BASE-03-ICICI", "BASE-04-AXIS",
        "BASE-05-BOB", "BASE-06-PNB", "BASE-07-BOI", "BASE-08-KOTAK",
        "BASE-09-INDUS", "BASE-10-UNION",
    }


@pytest.mark.parametrize(
    "baseline_id,package",
    [
        ("BASE-01-SBI", "com.sbi.lotus"),
        ("BASE-02-HDFC", "com.snapwork.hdfc"),
        ("BASE-03-ICICI", "com.csam.icici.bank.imobile"),
        ("BASE-04-AXIS", "com.axis.mobile"),
        ("BASE-05-BOB", "com.mconnect"),
        ("BASE-06-PNB", "com.pnb.pnbone"),
        ("BASE-07-BOI", "com.boi.mobile"),
        ("BASE-08-KOTAK", "com.msf.k8"),
        ("BASE-09-INDUS", "com.indusind.indusmobile"),
        ("BASE-10-UNION", "com.infrasofttech.uboi"),
    ],
)
def test_prd_package_names(baseline_id, package):
    assert package in packages_for(baseline_id)
    assert baseline_id_for_package(package) == baseline_id


def test_package_lookup_is_case_insensitive_and_safe():
    assert baseline_id_for_package("COM.BOI.MOBILE") == "BASE-07-BOI"
    assert baseline_id_for_package("com.unknown.app") == ""
    assert baseline_id_for_package("") == ""
    assert packages_for("NOT-A-BASELINE") == []


def test_no_package_is_claimed_by_two_institutions():
    packages = all_official_packages()
    assert len(packages) == len(set(packages))


# ── corpus root resolution ─────────────────────────────────────────────────


def _make_corpus(root):
    root.mkdir(parents=True, exist_ok=True)
    (root / "baselines_index.json").write_text(
        json.dumps({"corpusVersion": "1.0", "baselines": []}), encoding="utf-8-sig"
    )
    return root


def test_explicit_path_wins(tmp_path):
    corpus = _make_corpus(tmp_path / "explicit")
    assert find_corpus_root(corpus) == corpus


def test_documented_env_var_is_honoured(tmp_path, monkeypatch):
    corpus = _make_corpus(tmp_path / "corpus")
    monkeypatch.setenv("BANKING_BASELINE_CORPUS_DIR", str(corpus))
    assert find_corpus_root() == corpus


def test_legacy_env_var_still_works(tmp_path, monkeypatch):
    corpus = _make_corpus(tmp_path / "legacy")
    monkeypatch.delenv("BANKING_BASELINE_CORPUS_DIR", raising=False)
    monkeypatch.setenv("VIDE_CORPUS_DIR", str(corpus))
    assert find_corpus_root() == corpus


def test_stale_env_var_falls_through_instead_of_disabling_the_corpus(
    tmp_path, monkeypatch
):
    """A candidate only counts if it actually carries baselines_index.json."""
    real = _make_corpus(tmp_path / "real")
    monkeypatch.setenv("BANKING_BASELINE_CORPUS_DIR", str(tmp_path / "deleted"))
    monkeypatch.setenv("VIDE_CORPUS_DIR", str(real))
    assert find_corpus_root() == real


def test_missing_corpus_yields_no_baselines_rather_than_raising(tmp_path, monkeypatch):
    monkeypatch.setenv("BANKING_BASELINE_CORPUS_DIR", str(tmp_path / "nope"))
    monkeypatch.setenv("VIDE_CORPUS_DIR", str(tmp_path / "also-nope"))
    monkeypatch.setattr(
        "sudarshan_core.engines.vide.corpus_loader._DEFAULT_CORPUS_DIRS",
        (tmp_path / "neither",),
    )
    assert find_corpus_root() is None
    assert load_corpus_baselines() == []
