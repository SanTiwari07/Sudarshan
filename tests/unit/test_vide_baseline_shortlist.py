"""VIDE baseline shortlist — no arbitrary bank fallback."""

from sudarshan_core.engines.vide.baseline_store import InstitutionBaseline, shortlist_baselines
from sudarshan_core.engines.vide.ui_profile import UIProfile


def _sbi() -> InstitutionBaseline:
    return InstitutionBaseline.from_json(
        {
            "institution_id": "demo_sbi",
            "display_name": "SBI Demo",
            "package_names": ["com.sbi.lotus"],
            "profile": {
                "strings": ["Enter UPI PIN", "MPIN", "YONO", "Login"],
                "view_sequence": ["LinearLayout", "Button"],
                "colors": ["#1a237e"],
            },
        }
    )


def _hdfc() -> InstitutionBaseline:
    return InstitutionBaseline.from_json(
        {
            "institution_id": "demo_hdfc",
            "display_name": "HDFC Demo",
            "package_names": ["com.hdfc"],
            "profile": {
                "strings": ["HDFC Bank", "NetBanking", "Customer ID"],
                "view_sequence": ["FrameLayout", "EditText"],
                "colors": ["#004c8f"],
            },
        }
    )


def test_shortlist_finds_relevant_candidate():
    suspect = UIProfile(
        source="test",
        strings=["Enter UPI PIN", "YONO", "Forgot Password"],
        view_sequence=["LinearLayout"],
    )
    out = shortlist_baselines(suspect, [_sbi(), _hdfc()])
    assert len(out) >= 1
    assert out[0].institution_id == "demo_sbi"


def test_unrelated_app_returns_empty_shortlist():
    suspect = UIProfile(
        source="test",
        strings=["Settings", "Wi-Fi", "Bluetooth"],
        view_sequence=["ScrollView"],
    )
    assert shortlist_baselines(suspect, [_sbi(), _hdfc()]) == []


def test_multiple_candidates_ranked_deterministically():
    suspect = UIProfile(
        source="test",
        strings=["Enter UPI PIN", "MPIN", "HDFC Bank", "NetBanking"],
        view_sequence=["LinearLayout"],
    )
    first = shortlist_baselines(suspect, [_sbi(), _hdfc()])
    second = shortlist_baselines(suspect, [_sbi(), _hdfc()])
    assert [b.institution_id for b in first] == [b.institution_id for b in second]
    assert len(first) == 2


def test_empty_profile_returns_no_candidates():
    suspect = UIProfile(source="empty")
    assert shortlist_baselines(suspect, [_sbi()]) == []
