"""
The static->dynamic bridge.

The regression these lock down: `AgenticExplorer` has always accepted
`static_findings` and `PerceptionPipeline` has always forwarded it into every
`Observation`, but `frida_sandbox` never supplied it. The parameter existed, the
plumbing existed, and it carried `{}` on every real run - so the dynamic engine
could not compare declared permissions against what the app requested at
runtime, because it was never told what was declared.

These tests assert the wiring at each hop rather than the behaviour built on top
of it, because the wiring is what silently broke.
"""

from __future__ import annotations

import inspect
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

from sudarshan_core.engines.agentic_explorer import AgenticExplorer  # noqa: E402
from sudarshan_core.engines.capability_profile import AppCategory  # noqa: E402

P = "android.permission."


# ── the signature hops ───────────────────────────────────────────────────────

def test_run_frida_analysis_accepts_static_findings():
    from sudarshan_core.engines.frida_sandbox import run_frida_analysis

    params = inspect.signature(run_frida_analysis).parameters
    assert "static_findings" in params


def test_static_findings_is_keyword_only_and_optional():
    """
    10 call sites exist, two of them web services. A positional or required
    parameter would break every one of them.
    """
    from sudarshan_core.engines.frida_sandbox import run_frida_analysis

    param = inspect.signature(run_frida_analysis).parameters["static_findings"]
    assert param.kind is inspect.Parameter.KEYWORD_ONLY
    assert param.default is None


def test_the_session_stores_static_findings():
    from sudarshan_core.engines.frida_sandbox import FridaSession

    session = FridaSession(
        "test-device", "com.example.calculator",
        static_findings={"permissions": [P + "CAMERA"]},
    )
    assert session.static_findings == {"permissions": [P + "CAMERA"]}


def test_the_session_defaults_to_an_empty_mapping():
    """A caller with no static pass must still be able to run dynamic analysis."""
    from sudarshan_core.engines.frida_sandbox import FridaSession

    assert FridaSession("test-device", "com.example.app").static_findings == {}


def test_the_session_copies_rather_than_aliases():
    """Mutating the caller's dict must not reach into a running session."""
    from sudarshan_core.engines.frida_sandbox import FridaSession

    supplied = {"permissions": [P + "CAMERA"]}
    session = FridaSession("test-device", "com.example.app", static_findings=supplied)
    supplied["permissions"] = []
    assert session.static_findings["permissions"] == [P + "CAMERA"]


def test_the_explorer_construction_site_passes_static_findings():
    """
    The hop that was actually missing.

    Asserted against the source of frida_sandbox rather than by running the
    pipeline, because reaching that line needs a device, Frida and an APK.
    """
    from sudarshan_core.engines import frida_sandbox

    source = Path(frida_sandbox.__file__).read_text(encoding="utf-8", errors="replace")
    start = source.index("AgenticExplorer(")
    # Balance the parentheses: nested calls such as `adb_path=_find_adb()` mean
    # the first ")" is not the end of the argument list.
    depth = 0
    for offset in range(start, len(source)):
        if source[offset] == "(":
            depth += 1
        elif source[offset] == ")":
            depth -= 1
            if depth == 0:
                break
    call = source[start:offset + 1]
    assert "static_findings=self.static_findings" in call


def test_every_hop_between_the_entry_point_and_the_session_carries_it():
    """
    The hop a signature test cannot see.

    `run_frida_analysis` does not build the FridaSession itself - it delegates
    to `_run_device_session`, a separate module-level function. The first
    version of this bridge added the parameter to the entry point and used it
    at the construction site, and both source-level assertions passed, but the
    name was not in scope in between. The live run failed with
    `NameError: name 'static_findings' is not defined` after the static pass
    had already succeeded.

    So: assert the intermediate function accepts and defaults it too.
    """
    from sudarshan_core.engines import frida_sandbox

    params = inspect.signature(frida_sandbox._run_device_session).parameters
    assert "static_findings" in params, (
        "the function that actually constructs FridaSession must accept it"
    )
    assert params["static_findings"].default is None


# ── what the explorer does with them ─────────────────────────────────────────

def _explorer(**static):
    return AgenticExplorer(
        device_serial="test-device",
        package_name="com.example.calculator",
        static_findings=static or None,
    )


def test_declared_permissions_seed_the_investigator():
    exp = _explorer(permissions=[P + "CAMERA", P + "READ_SMS"], app_label="Calculator")
    records = {r.permission for r in exp.permissions.records()}
    assert records == {P + "CAMERA", P + "READ_SMS"}
    assert all(r.declared for r in exp.permissions.records())


def test_the_app_label_reaches_the_capability_profile():
    exp = _explorer(permissions=[P + "CAMERA"], app_label="Calculator")
    assert exp.permissions.profile.category is AppCategory.CALCULATOR


def test_the_brief_s_calculator_case_now_reaches_a_finding():
    """
    End-to-end for the worked example, at the layer that was disconnected:
    a calculator declaring CAMERA and SMS produces unexpected-permission
    findings instead of an empty static_findings dict.
    """
    exp = _explorer(
        permissions=[P + "CAMERA", P + "READ_SMS", P + "INTERNET"],
        app_label="Calculator",
    )
    exp.permissions.classify_all()
    unexpected = {r.permission for r in exp.permissions.unexpected()}
    assert unexpected == {P + "CAMERA", P + "READ_SMS"}


def test_an_explorer_with_no_static_findings_still_constructs():
    """Validation harnesses and recovery re-runs supply nothing."""
    exp = AgenticExplorer(device_serial="test-device", package_name="com.example.app")
    assert exp.static_findings == {}
    assert exp.permissions.records() == []
    assert exp.permissions.profile.category is AppCategory.UNKNOWN


def test_malformed_static_findings_do_not_break_construction():
    """Upstream shape drift must not take the dynamic engine down with it."""
    exp = AgenticExplorer(
        device_serial="test-device",
        package_name="com.example.app",
        static_findings={"permissions": None, "app_label": None},
    )
    assert exp.permissions.records() == []


# ── the production call sites feed it ────────────────────────────────────────

@pytest.mark.parametrize("relative", [
    "backend/app/routes/upload.py",
    "analysis-engine/app/main.py",
])
def test_the_service_call_sites_supply_static_findings(relative):
    """
    Both services compute the permission list already; the bridge is only
    useful if they actually hand it over.
    """
    source = (_ROOT / relative).read_text(encoding="utf-8", errors="replace")
    start = source.index("run_frida_analysis(")
    call = source[start:start + 600]
    assert "static_findings=" in call


# ── the app label, which is a claim rather than metadata ─────────────────────

def test_androguard_output_carries_the_app_label():
    from sudarshan_core.models.schemas import AndroguardOutput, StaticAnalysisFlags

    out = AndroguardOutput(
        package_name="com.x", permissions=[], flags=StaticAnalysisFlags(),
        app_label="Calculator",
    )
    assert out.app_label == "Calculator"


def test_app_label_defaults_to_empty_for_existing_construction_sites():
    from sudarshan_core.models.schemas import AndroguardOutput, StaticAnalysisFlags

    out = AndroguardOutput(
        package_name="com.x", permissions=[], flags=StaticAnalysisFlags()
    )
    assert out.app_label == ""


@pytest.mark.parametrize("relative", [
    "backend/app/routes/upload.py",
    "analysis-engine/app/main.py",
])
def test_the_service_call_sites_supply_the_app_label(relative):
    source = (_ROOT / relative).read_text(encoding="utf-8", errors="replace")
    start = source.index("run_frida_analysis(")
    assert "app_label" in source[start:start + 900]


def test_a_disguised_label_is_judged_against_what_it_claims_to_be():
    """
    Measured on the corpus: Octo ships as "Google Chrome". Judging its
    permissions against a browser is what produces the finding - a browser has
    no business reading SMS - so the disguise creates the finding rather than
    hiding it.
    """
    from sudarshan_core.engines.permission_investigator import investigate_permissions

    inv = investigate_permissions(
        package_name="com.hmxuxgdngpi.bkqrlzkuwzuj",
        app_label="Google Chrome",
        declared=[P + "READ_SMS", P + "SEND_SMS", P + "INTERNET"],
    )
    unexpected = {r.permission for r in inv.unexpected()}
    assert P + "READ_SMS" in unexpected
    assert P + "SEND_SMS" in unexpected
    # A browser legitimately needs the network, so that must not be flagged.
    assert P + "INTERNET" not in unexpected
