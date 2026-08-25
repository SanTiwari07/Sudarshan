"""
Scoring a sample that hides its own evidence.

Measured on the labelled corpus with the real analyzer, before this change:

    Anubis  (banking trojan, payload concealed)  STEI  9.20  CT  0  FRS 14.0 Safe
    NewPipe (video player, nothing concealed)    STEI 24.64  CT 25  FRS 22.6 Safe

The benign app scored HIGHER than the banking trojan. NewPipe honestly declares
SYSTEM_ALERT_WINDOW for picture-in-picture and ships real endpoints, so it earns
CT and IR points. Anubis declares four permissions and ships its real code as a
nested APK, so it earns zeros.

CT and BT are read from the manifest and string pool. When the payload is
concealed those sources describe a stub, so a 0 means "we could not see", not
"there is nothing" - and the metric inverts for exactly the class of sample it
exists to catch. These tests pin the correction: a blind axis is excluded and
the rest renormalised, never scored as an acquittal.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

from sudarshan_core.engines.risk_engine import _calculate_stei  # noqa: E402

#: Anubis, as the real analyzer reports it.
CONCEALED_TROJAN = {
    "has_accessibility_abuse": False,
    "has_sms_read_write": False,
    "has_system_alert_window": False,
    "targets_indian_banks": False,
    "has_concealed_payload": True,
    "concealment_evidence": ["Nested APK concealed at 'x.temp' (3537 KB)"],
    "obfuscation_score": 0.7989,
    "has_reflection": True,
    "dangerous_apis_found": [],
    "hardcoded_urls_ips": ["a.test", "b.test", "c.test", "d.test", "e.test"],
}

PERMS = [
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.REQUEST_INSTALL_PACKAGES",
]


def _stei(flags, perms=PERMS):
    score, axes, evidence, _ = _calculate_stei(flags, perms)
    return score, axes, evidence


# ── the inversion ────────────────────────────────────────────────────────────

def test_a_concealed_sample_does_not_score_its_blind_axes_as_zero():
    score, axes, _ = _stei(CONCEALED_TROJAN)
    # Old behaviour: 0.60*0 + 0.20*0 + 0.10*20 + 0.05*94 + 0.05*50 = 9.20
    assert score > 9.20
    assert axes["excluded"] == ["ct", "bt"]


def test_the_renormalised_score_is_the_measured_axes_only():
    """
    PR 20, OB 94, IR 50 at weights 0.10/0.05/0.05 renormalised over 0.20
    -> 0.5*20 + 0.25*94 + 0.25*50 = 46.0. Nothing is invented.
    """
    score, _, _ = _stei(CONCEALED_TROJAN)
    assert score == pytest.approx(46.0, abs=0.01)


def test_a_sample_that_hides_nothing_is_untouched():
    """The change must not move any sample whose evidence is visible."""
    visible = dict(CONCEALED_TROJAN, has_concealed_payload=False)
    score, axes, _ = _stei(visible)
    assert axes["excluded"] == []
    # Full formula, every axis scored: 0.60*0 + 0.20*0 + 0.10*20 + 0.05*34
    # + 0.05*50. OB is 34 rather than 94 here because the +60 concealment
    # contribution is exactly what this variant removes.
    assert score == pytest.approx(6.20, abs=0.01)


def test_a_concealed_trojan_now_outranks_an_honest_benign_app():
    """
    The property that was inverted. NewPipe's real flags: it declares
    SYSTEM_ALERT_WINDOW (CT 25) and ships many endpoints (IR 100).
    """
    benign = {
        "has_accessibility_abuse": False,
        "has_sms_read_write": False,
        "has_system_alert_window": True,
        "has_concealed_payload": False,
        "obfuscation_score": 0.52,
        "has_reflection": True,
        "dangerous_apis_found": [],
        "hardcoded_urls_ips": [f"h{i}.test" for i in range(12)],
    }
    trojan_score, _, _ = _stei(CONCEALED_TROJAN)
    benign_score, _, _ = _stei(benign, ["android.permission.INTERNET"])
    assert trojan_score > benign_score


# ── the exclusion is deliberately narrow ─────────────────────────────────────

def test_an_axis_that_still_carries_evidence_is_never_dropped():
    """
    A concealed sample that ALSO declares accessibility has told us something
    real. Dropping CT there would discard evidence we actually have.
    """
    partial = dict(CONCEALED_TROJAN, has_accessibility_abuse=True)
    _, axes, _ = _stei(partial)
    assert "ct" not in axes["excluded"]
    assert axes["ct"] == 40.0


def test_only_visibility_dependent_axes_are_ever_excluded():
    """PR, OB and IR are measured directly and must always be scored."""
    _, axes, _ = _stei(CONCEALED_TROJAN)
    for axis in ("pr", "ob", "ir"):
        assert axis not in axes["excluded"]


def test_concealment_alone_is_worth_something_but_not_everything():
    """
    A sample whose ONLY finding is a concealed payload. CT/BT are blind, PR and
    IR are genuinely zero, and OB carries the +60 concealment contribution.
    Renormalised that is 0.25*60 = 15.0.

    Under the old weighting the same sample scored 0.05*60 = 3.0 - concealment,
    the one thing actually established about it, was worth three points. 15 is
    not a verdict; it is the honest weight of the only measured axis.
    """
    blank = {"has_concealed_payload": True}
    score, axes, _ = _stei(blank, [])
    assert axes["excluded"] == ["ct", "bt"]
    assert score == pytest.approx(15.0, abs=0.01)


def test_a_sample_with_no_findings_at_all_scores_zero():
    """Nothing concealed and nothing found must still be 0, not a floor."""
    score, axes, _ = _stei({}, [])
    assert score == 0.0
    assert axes["excluded"] == []


# ── the reader must be able to reconstruct the arithmetic ────────────────────

def test_the_exclusion_is_explained_in_the_evidence():
    """CT 0.0 printed beside a STEI of 46 is unreadable without this."""
    _, _, evidence = _stei(CONCEALED_TROJAN)
    text = " ".join(evidence)
    assert "could not be measured" in text
    assert "concealed" in text
    assert "excluded rather than scored as zero" in text


def test_the_breakdown_reports_which_axes_were_excluded():
    from sudarshan_core.engines.risk_engine import calculate_risk_score

    out = calculate_risk_score(CONCEALED_TROJAN, all_permissions=PERMS)
    assert out["frs_breakdown"]["stei_axes_excluded"] == ["ct", "bt"]


def test_a_visible_sample_reports_no_exclusions():
    from sudarshan_core.engines.risk_engine import calculate_risk_score

    visible = dict(CONCEALED_TROJAN, has_concealed_payload=False)
    out = calculate_risk_score(visible, all_permissions=PERMS)
    assert out["frs_breakdown"]["stei_axes_excluded"] == []
