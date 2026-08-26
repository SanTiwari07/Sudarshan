"""
Boot-image deoptimization must not ANR the sample it is meant to observe.

`Java.deoptimizeBootImage()` makes hooks on INLINED system classes reliable.
It also leaves the device crawling for ~30s on API 34+ (measured on an API 37
x86_64 emulator). Android's ANR watchdog fires well inside that window, so the
system draws "<app> isn't responding" over the sample before the walk has taken
an action. Measured on the e-challan sample: four consecutive ANRs, exploration
stopping after 4 actions on 1 screen, and no runtime behaviour captured at all.

`deoptimizeEverything` was already gated at the same API level for the same
reason; this pins the gate on its sibling, and pins the one host-side knob that
can turn it back on.
"""

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

_HOOKS = _ROOT / "shared" / "sudarshan_core" / "engines" / "frida_hooks"
_SOURCE = _HOOKS / "banking_trojan.js"
_BUNDLE = _HOOKS / "banking_trojan.bundle.js"


@pytest.fixture(scope="module")
def source() -> str:
    return _SOURCE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def bundle() -> str:
    return _BUNDLE.read_text(encoding="utf-8")


def test_the_boot_image_deopt_is_gated_in_the_source(source):
    assert "deoptimizeBootImage_skipped_api34_plus" in source


def test_the_gate_reached_the_compiled_bundle(bundle):
    """
    The device runs the BUNDLE. A gate that exists only in the source is a fix
    that never runs.
    """
    assert "deoptimizeBootImage_skipped_api34_plus" in bundle


def test_the_agent_default_is_not_to_deoptimize(bundle):
    from sudarshan_core.engines.frida_sandbox import _AGENT_DEOPT_TOKEN

    assert _AGENT_DEOPT_TOKEN in bundle


# ─── The host-side knob ──────────────────────────────────────────────────────

def test_the_default_leaves_the_agent_untouched(monkeypatch, bundle):
    from sudarshan_core.engines.frida_sandbox import _apply_agent_config

    monkeypatch.delenv("SUDARSHAN_DEOPT_BOOT_IMAGE", raising=False)
    assert _apply_agent_config(bundle) == bundle


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on"])
def test_an_operator_can_force_boot_image_deopt_back_on(monkeypatch, value):
    from sudarshan_core.engines.frida_sandbox import (
        _AGENT_DEOPT_TOKEN,
        _apply_agent_config,
    )

    monkeypatch.setenv("SUDARSHAN_DEOPT_BOOT_IMAGE", value)
    out = _apply_agent_config(f"// head\n{_AGENT_DEOPT_TOKEN}\n// tail\n")
    assert "var DEOPT_BOOT_IMAGE_FORCED = true;" in out
    assert _AGENT_DEOPT_TOKEN not in out


@pytest.mark.parametrize("value", ["0", "false", "no", "off", "", "maybe"])
def test_anything_that_is_not_an_affirmative_leaves_it_off(monkeypatch, value):
    from sudarshan_core.engines.frida_sandbox import (
        _AGENT_DEOPT_TOKEN,
        _apply_agent_config,
    )

    monkeypatch.setenv("SUDARSHAN_DEOPT_BOOT_IMAGE", value)
    src = f"// head\n{_AGENT_DEOPT_TOKEN}\n"
    assert _apply_agent_config(src) == src


def test_the_substitution_can_only_ever_write_a_boolean(monkeypatch):
    """
    This is a string substitution into a script that runs inside the sample's
    process, so the value space must not be able to express anything but true
    or false. The env var selects between two hardcoded literals; its own text
    is never interpolated.
    """
    from sudarshan_core.engines.frida_sandbox import (
        _AGENT_DEOPT_TOKEN,
        _apply_agent_config,
    )

    monkeypatch.setenv(
        "SUDARSHAN_DEOPT_BOOT_IMAGE", "true; send({evil:1}); //",
    )
    out = _apply_agent_config(f"{_AGENT_DEOPT_TOKEN}\n")
    assert "evil" not in out
    # Not an affirmative token, so it stays off.
    assert "var DEOPT_BOOT_IMAGE_FORCED = false;" in out


def test_a_missing_slot_is_reported_and_not_fatal(monkeypatch):
    from sudarshan_core.engines.frida_sandbox import _apply_agent_config

    monkeypatch.setenv("SUDARSHAN_DEOPT_BOOT_IMAGE", "1")
    assert _apply_agent_config("// no slot here\n") == "// no slot here\n"
