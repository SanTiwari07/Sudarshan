"""VIDE compare must be bitwise-stable across repeated runs."""

from sudarshan_core.engines.vide.baseline_store import InstitutionBaseline
from sudarshan_core.engines.vide.compare import compare_profiles
from sudarshan_core.engines.vide.ui_profile import UIProfile


def _baseline() -> InstitutionBaseline:
    return InstitutionBaseline.from_json(
        {
            "institution_id": "demo_sbi",
            "display_name": "SBI Demo",
            "package_names": ["com.sbi.lotus"],
            "profile": {
                "strings": ["Enter UPI PIN", "MPIN", "YONO", "Login"],
                "view_sequence": ["LinearLayout", "TextInputEditText", "MaterialButton"],
                "colors": ["#1a237e"],
            },
        }
    )


def test_compare_profiles_is_deterministic():
    suspect = UIProfile(
        source="test",
        strings=["Enter UPI PIN", "MPIN", "YONO", "Forgot Password"],
        view_sequence=["LinearLayout", "TextInputEditText", "MaterialButton", "TextView"],
        colors=["#1a237e", "#ffffff"],
    )
    bl = _baseline()
    runs = [compare_profiles(suspect, bl).to_dict() for _ in range(5)]
    first = runs[0]
    for r in runs[1:]:
        assert r == first
    assert first["rule_id"] == "VIDE-F001"
    assert first["detected"] is True
