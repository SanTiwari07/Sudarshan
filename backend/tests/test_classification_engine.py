"""Family classifier rule priority and Drinik/Xenomorph disambiguation."""

from sudarshan_core.engines.classification_engine import classify_family
from sudarshan_core.models.schemas import StaticAnalysisFlags

from case_study_fixtures import drinik_flags, xenomorph_flags


def test_drinik_shaped_flags_classify_as_drinik_not_xenomorph():
    """Drinik rule (banking + DexClassLoader) must win over broader Xenomorph rule."""
    family, rule = classify_family(drinik_flags())
    assert family == "Drinik"
    assert "DexClassLoader" in rule or "Dynamic Code Loading" in rule


def test_xenomorph_pattern_without_dex_class_loader():
    """Accessibility + SMS + banking without DexClassLoader stays Xenomorph."""
    flags = StaticAnalysisFlags(
        has_accessibility_abuse=True,
        has_sms_read_write=True,
        targets_indian_banks=True,
        dangerous_apis_found=[],
    )
    family, _ = classify_family(flags)
    assert family == "Xenomorph"


def test_xenomorph_fixture_classifies_as_hydra_without_sms():
    """Case-study Xenomorph fixture omits SMS to avoid Drinik overlap → Hydra."""
    family, rule = classify_family(xenomorph_flags())
    assert family == "Hydra"
    assert "System Alert Window" in rule
