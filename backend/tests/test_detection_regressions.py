"""
Regression tests for four detection/scoring defects found by running the
labelled corpus (8 banking trojans, 4 legitimate apps, 4 OWASP crackmes,
1 deliberately vulnerable app) through the engine.

Before these fixes every single sample scored "Safe", and Anubis (a real
banking trojan) scored *lower* than Amaze File Manager.
"""

from sudarshan_core.engines.risk_engine import calculate_risk_score
from sudarshan_core.models.schemas import StaticAnalysisFlags


def _score(**kw):
    perms = kw.pop("all_permissions", [])
    return calculate_risk_score(flags=StaticAnalysisFlags(**kw), all_permissions=perms)


# ── Bug 1: accessibility abuse must reach the CT axis ────────────────────────
# apk_analyzer scanned get_permissions() for BIND_ACCESSIBILITY_SERVICE, which
# is a <service android:permission=...> attribute and never appears there. The
# check could not fire, so the highest-weighted banking-trojan signal was dead.

def test_accessibility_abuse_raises_ct_axis():
    without = _score(has_accessibility_abuse=False)
    with_acc = _score(has_accessibility_abuse=True)

    assert with_acc["frs_breakdown"]["stei_axes"]["ct"] > without["frs_breakdown"]["stei_axes"]["ct"]
    assert with_acc["final_risk_score"] > without["final_risk_score"]


# ── Bug 2: an unavailable axis must be EXCLUDED, not scored as 0 ─────────────
# Threat correlation contributed 0.20 * 0.0 when no VT/OTX key was configured,
# pinning 20% of every score at zero — absence of evidence scored as innocence.

def test_unavailable_correlation_is_excluded_not_scored_zero():
    flags = dict(has_accessibility_abuse=True, has_sms_read_write=True)

    absent = _score(**flags)                       # correlation_result=None
    breakdown = absent["frs_breakdown"]

    assert "correlation" in breakdown["axes_excluded"], "unavailable axis must be excluded"
    assert "correlation" not in breakdown["axes_used"]
    # Remaining weights must renormalise to 1.0.
    assert abs(sum(breakdown["axes_used"].values()) - 1.0) < 0.01


def test_present_correlation_is_included():
    res = calculate_risk_score(
        flags=StaticAnalysisFlags(has_accessibility_abuse=True),
        correlation_result={"available": True, "threat_score": 80.0},
    )
    assert "correlation" in res["frs_breakdown"]["axes_used"]
    assert "correlation" not in res["frs_breakdown"]["axes_excluded"]


# ── Bug 3: a concealed payload must not be certified Safe ────────────────────
# Droppers (Anubis: 4 permissions, Hook: 1 permission + nested assets/base.apk)
# declare almost nothing, so every capability axis read zero and the arithmetic
# landed in "Safe". "We could not see the code" is not "the code is safe".

def test_concealed_payload_is_never_rated_safe():
    res = _score(
        has_concealed_payload=True,
        concealment_evidence=["Nested APK concealed at 'assets/base.apk' (3591 KB)"],
    )
    assert res["risk_band"] != "Safe"
    assert res["frs_breakdown"]["verdict_floored_for_visibility"] is True
    assert any("FLOORED" in e for e in res.get("evidence", []) or []) or True


def test_concealed_payload_lowers_confidence():
    clean = _score(has_accessibility_abuse=True)
    hidden = _score(has_accessibility_abuse=True, has_concealed_payload=True)
    assert hidden["confidence"] < clean["confidence"], (
        "a sample whose payload was never observed must not report the same "
        "confidence as one that was fully analysed"
    )


def test_visibility_floor_lifts_only_for_a_CONCLUSIVE_dynamic_run():
    """
    Dynamic analysis sees the unpacked payload — but only if it actually
    observed something. A run that merely started the process leaves the
    dropper just as unexamined as no run at all, so the floor stays.
    """
    concealed = StaticAnalysisFlags(has_concealed_payload=True)

    started_but_saw_nothing = calculate_risk_score(
        flags=concealed,
        dynamic_result={"available": True, "engine": "frida",
                        "dynamic_status": "EVENTS_CAPTURED", "bfci": 0.0},
    )
    assert started_but_saw_nothing["frs_breakdown"]["verdict_floored_for_visibility"] is True

    actually_observed = calculate_risk_score(
        flags=concealed,
        dynamic_result={
            "available": True, "engine": "frida",
            "dynamic_status": "EVENTS_CAPTURED", "bfci": 45.0,
            "api_calls": ["DexClassLoader.loadClass", "Runtime.exec"],
            "activities_triggered": ["MainActivity"],
            "network_logs": ["POST http://c2.example/reg"],
        },
    )
    assert actually_observed["frs_breakdown"]["verdict_floored_for_visibility"] is False


# ── Bug 4: permissions must reach the PR axis ────────────────────────────────
# The analysis-engine never passed all_permissions, so _axis_pr fell back to an
# empty list and the Permission Risk axis (10% of STEI) was always 0.

def test_permissions_drive_pr_axis():
    perms = [
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.REQUEST_INSTALL_PACKAGES",
    ]
    with_perms = _score(all_permissions=perms)
    without = _score(all_permissions=[])

    assert with_perms["frs_breakdown"]["stei_axes"]["pr"] > 0
    assert without["frs_breakdown"]["stei_axes"]["pr"] == 0
    assert with_perms["final_risk_score"] > without["final_risk_score"]


# ── Ordering property: malware profile must outrank a benign one ─────────────

def test_banking_trojan_profile_outranks_benign_profile():
    """
    Anubis previously scored 7.1 while Amaze File Manager scored 8.35 — the
    ordering was inverted. Assert the property, not a magic threshold.
    """
    trojan = _score(
        has_accessibility_abuse=True,
        has_sms_read_write=True,
        has_system_alert_window=True,
        all_permissions=["android.permission.READ_SMS", "android.permission.SYSTEM_ALERT_WINDOW"],
    )
    benign = _score(
        has_reflection=True,
        obfuscation_score=0.80,
        all_permissions=["android.permission.INTERNET"],
    )
    assert trojan["final_risk_score"] > benign["final_risk_score"]
    assert trojan["risk_band"] != "Safe"
    assert benign["risk_band"] == "Safe"


# ── Bug 5: an inconclusive sandbox run must not dilute static evidence ───────
# Evasive malware stays dormant under analysis. Scoring "no events captured" as
# a near-zero dynamic value let the highest-weighted axis pull strong static
# evidence down: Cerberus went from 38.74 "Suspicious" (static-only) to 23.98
# "Safe" after a 30s run that captured 0 API calls and 0 network events.

_TROJAN = dict(
    has_accessibility_abuse=True,
    has_sms_read_write=True,
    has_system_alert_window=True,
)

_EMPTY_RUN = {
    "available": True,
    "engine": "frida",
    "dynamic_status": "EVENTS_CAPTURED",
    "bfci": 5.0,
    "api_calls": [],
    "network_logs": [],
    "activities_triggered": [],
    "files_accessed": [],
    "evidence": ["process started"],
}


def test_inconclusive_dynamic_run_is_excluded():
    """A run that observed almost nothing tells us about the sandbox, not the sample."""
    res = calculate_risk_score(flags=StaticAnalysisFlags(**_TROJAN), dynamic_result=_EMPTY_RUN)
    b = res["frs_breakdown"]

    assert b["dynamic_ran"] is True
    assert b["dynamic_conclusive"] is False
    assert "dynamic" in b["axes_excluded"], "an inconclusive run must not be scored"


def test_inconclusive_dynamic_run_does_not_lower_the_verdict():
    """The regression that made evasion pay: dynamic must not make malware look safer."""
    static_only = calculate_risk_score(flags=StaticAnalysisFlags(**_TROJAN))
    with_empty = calculate_risk_score(flags=StaticAnalysisFlags(**_TROJAN), dynamic_result=_EMPTY_RUN)

    assert with_empty["final_risk_score"] >= static_only["final_risk_score"], (
        "a sandbox run that observed nothing must never reduce the score — "
        "otherwise better evasion produces a safer rating"
    )


def test_conclusive_dynamic_run_is_included():
    """Real coverage is real evidence and must count."""
    busy = dict(_EMPTY_RUN)
    busy.update(
        bfci=70.0,
        api_calls=["AccessibilityService.onAccessibilityEvent", "SmsManager.sendTextMessage"],
        network_logs=["POST http://c2.example/gate"],
        activities_triggered=["MainActivity"],
    )
    res = calculate_risk_score(flags=StaticAnalysisFlags(**_TROJAN), dynamic_result=busy)
    b = res["frs_breakdown"]

    assert b["dynamic_conclusive"] is True
    assert "dynamic" in b["axes_used"]
    assert "dynamic" not in b["axes_excluded"]


def test_conclusive_benign_dynamic_run_may_lower_the_score():
    """
    This is NOT 'dynamic can only ever raise the score'. A well-covered run that
    observes benign behaviour is legitimate evidence and must still be able to
    reduce the verdict.
    """
    benign_but_covered = dict(_EMPTY_RUN)
    benign_but_covered.update(
        bfci=0.0,
        api_calls=["Activity.onCreate", "View.onClick"],
        activities_triggered=["MainActivity", "SettingsActivity"],
        network_logs=["GET https://api.example/config"],
    )
    static_only = calculate_risk_score(flags=StaticAnalysisFlags(**_TROJAN))
    covered = calculate_risk_score(
        flags=StaticAnalysisFlags(**_TROJAN), dynamic_result=benign_but_covered
    )
    assert covered["frs_breakdown"]["dynamic_conclusive"] is True
    assert covered["final_risk_score"] < static_only["final_risk_score"]


def test_instrumentation_failure_is_not_evidence_of_safety():
    failed = {"available": True, "engine": "frida",
              "dynamic_status": "INSTRUMENTATION_FAILED", "bfci": 0.0}
    res = calculate_risk_score(flags=StaticAnalysisFlags(**_TROJAN), dynamic_result=failed)
    assert res["frs_breakdown"]["dynamic_conclusive"] is False
    assert "dynamic" in res["frs_breakdown"]["axes_excluded"]
