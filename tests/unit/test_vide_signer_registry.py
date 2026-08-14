"""CH06-SIGNER-IMPERSONATION: who is allowed to claim a bank's package name."""

import json

import pytest

from sudarshan_core.engines.vide.official_packages import all_official_packages
from sudarshan_core.engines.vide.signer_registry import (
    check_signer_impersonation,
    extract_signer_sha256,
    is_debug_signed,
    load_signer_registry,
    load_signer_registry_metadata,
)

RELEASE_CERT = {"certificate_sha256": "ab" * 32}
DEBUG_CERT = {
    "certificate_sha256": "cd" * 32,
    "subject": "CN=Android Debug, O=Android, C=US",
}


# ── shipped registry ───────────────────────────────────────────────────────


def test_every_protected_package_is_registered():
    """The PRD's ten institutions must all be enforceable."""
    registry = load_signer_registry()
    missing = [p for p in all_official_packages() if p not in registry]
    assert missing == []


def test_registry_metadata_names_the_institution():
    meta = load_signer_registry_metadata()
    assert meta["com.boi.mobile"]["baseline_id"] == "BASE-07-BOI"
    assert meta["com.boi.mobile"]["bank"] == "Bank of India"


def test_schema_metadata_keys_are_not_read_as_packages():
    registry = load_signer_registry()
    assert not any(key.startswith("_") for key in registry)


# ── the rule ───────────────────────────────────────────────────────────────


def test_official_package_with_unknown_signer_is_impersonation():
    result = check_signer_impersonation("com.sbi.lotus", RELEASE_CERT)
    assert result.detected is True
    assert result.rule_id == "CH06-SIGNER-IMPERSONATION"
    assert result.institution_id == "BASE-01-SBI"
    assert any("claims the identity" in line for line in result.evidence_lines)


def test_unregistered_package_is_not_impersonation():
    assert check_signer_impersonation("com.random.notes", RELEASE_CERT).detected is False


def test_allowlisted_signer_is_not_impersonation():
    result = check_signer_impersonation(
        "com.sbi.lotus",
        {"certificate_sha256": "aa" * 32},
        registry={"com.sbi.lotus": ["aa" * 32]},
        metadata={},
    )
    assert result.detected is False
    assert result.evidence_lines == []


def test_packages_with_no_provisioned_signer_still_enforce_the_rule():
    """An empty allowlist is a decision, not missing data.

    The loader used to drop these entries, which silently disabled CH06 for
    exactly the packages whose canonical signer is unknown - the case where the
    claim cannot be checked any other way.
    """
    registry = {"com.axis.mobile": []}
    result = check_signer_impersonation("com.axis.mobile", RELEASE_CERT, registry=registry)
    assert result.detected is True
    assert any("cannot be verified" in line for line in result.evidence_lines)


def test_empty_allowlists_survive_loading(tmp_path):
    path = tmp_path / "registry.json"
    path.write_text(
        json.dumps({"packages": {"com.x.y": {"allowed_signers_sha256": []}}}),
        encoding="utf-8",
    )
    assert load_signer_registry(path) == {"com.x.y": []}


def test_legacy_flat_registry_layout_is_still_read(tmp_path):
    path = tmp_path / "registry.json"
    path.write_text(
        json.dumps({"com.x.y": {"allowed_signers_sha256": ["ef" * 32]}}),
        encoding="utf-8",
    )
    assert load_signer_registry(path) == {"com.x.y": ["ef" * 32]}


def test_malformed_fingerprints_are_discarded_not_trusted(tmp_path):
    path = tmp_path / "registry.json"
    path.write_text(
        json.dumps({"packages": {"com.x.y": {"allowed_signers_sha256": ["nope", "12ab"]}}}),
        encoding="utf-8",
    )
    assert load_signer_registry(path) == {"com.x.y": []}


def test_missing_signer_is_reported_as_undetermined_not_as_a_finding():
    result = check_signer_impersonation("com.axis.mobile", {})
    assert result.detected is False
    assert any("undetermined" in line for line in result.evidence_lines)


def test_debug_signed_apk_is_conclusive_without_a_fingerprint():
    result = check_signer_impersonation(
        "com.axis.mobile", {"subject": "CN=Android Debug, O=Android, C=US"}
    )
    assert result.detected is True
    assert result.debug_signed is True


# ── certificate parsing ────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "certificate",
    [
        {"certificate_sha256": "AB" * 32},
        {"sha256": "ab:" * 31 + "ab"},
        {"certificate_analysis": {"certificate_findings": {"sha256": "ab" * 32}}},
    ],
)
def test_signer_fingerprint_is_extracted_from_mobsf_shapes(certificate):
    assert extract_signer_sha256(certificate) == "ab" * 32


def test_short_or_absent_fingerprints_yield_empty():
    assert extract_signer_sha256({}) == ""
    assert extract_signer_sha256({"certificate_sha256": "abcd"}) == ""


def test_debug_detection_across_certificate_shapes():
    assert is_debug_signed(DEBUG_CERT) is True
    assert is_debug_signed({"certificate_analysis": {"subject": "CN=Android Debug"}}) is True
    assert is_debug_signed({"apk_is_debuggable": True}) is True
    assert is_debug_signed({"subject": "CN=State Bank of India, O=SBI"}) is False
    assert is_debug_signed({}) is False
