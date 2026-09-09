"""
A signal every app emits cannot be evidence about one app.

`AccessibilityManager.sendAccessibilityEvent` is dispatched by Android whenever
a view announces a UI change, so every app with an interface fires it. It was
emitted under the `accessibility` category, which carries the heaviest BFCI
weight (0.35) and a cap of 2-3 events - so ONE dispatch scored 50/100 for the
component.

Measured live on the emulator, 300-second runs:

    Anubis  (banking trojan)  fired it once  -> BFCI 17.5, accessibility 50.0
    NewPipe (video player)    fired it once  -> BFCI 17.5, accessibility 50.0

The heaviest-weighted axis could not tell a banking trojan from a video player.

bfci_scorer's own note states the rule: "A scored category that also catches
ordinary application behaviour is not a weak signal - it is a constant, and it
inflates every verdict equally."
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

_HOOKS = _ROOT / "shared" / "sudarshan_core" / "engines" / "frida_hooks"
UBIQUITOUS = "AccessibilityManager.sendAccessibilityEvent"


#: The bundle is GENERATED, so its string quoting belongs to the compiler and
#: has changed between frida-compile versions. Accepting either quote keeps
#: this asserting what the agent EMITS rather than how it is formatted.
_Q = r"['\"]"


def _emit_category_for(hook: str, text: str) -> str:
    """The category the agent emits `hook` under."""
    match = re.search(rf"hook: {_Q}{re.escape(hook)}{_Q}", text)
    assert match is not None, f"'{hook}' does not appear in the agent at all"
    before = text[: match.start()]
    return re.findall(rf"emit\({_Q}([a-z_]+){_Q}", before)[-1]


def test_the_ubiquitous_hook_is_not_in_a_scored_category():
    from sudarshan_core.engines.bfci_scorer import BFCI_WEIGHTS

    js = (_HOOKS / "banking_trojan.js").read_text(encoding="utf-8", errors="replace")
    category = _emit_category_for(UBIQUITOUS, js)
    assert category not in BFCI_WEIGHTS, (
        f"{UBIQUITOUS} fires on any UI change; scoring it makes every app "
        f"look identical on the {category} axis"
    )


def test_the_compiled_bundle_agrees():
    """The bundle is what runs; source alone proves nothing about a live run."""
    from sudarshan_core.engines.bfci_scorer import BFCI_WEIGHTS

    bundle = (_HOOKS / "banking_trojan.bundle.js").read_text(
        encoding="utf-8", errors="replace"
    )
    assert _emit_category_for(UBIQUITOUS, bundle) not in BFCI_WEIGHTS


def test_real_accessibility_abuse_is_still_scored():
    """
    Removing the constant must not blind the accessibility axis. These require
    the app to own a service or drive the screen - none fire incidentally.
    """
    from sudarshan_core.engines.bfci_scorer import BFCI_WEIGHTS

    js = (_HOOKS / "banking_trojan.js").read_text(encoding="utf-8", errors="replace")
    for hook in (
        "AccessibilityNodeInfo.getText",
        "AccessibilityNodeInfo.performAction",
        "AccessibilityService.dispatchGesture",
    ):
        assert _emit_category_for(hook, js) == "accessibility"
    assert "accessibility" in BFCI_WEIGHTS


def test_one_ubiquitous_event_no_longer_scores_the_heaviest_axis():
    """
    The measured symptom: a single dispatch produced accessibility 50.0.
    Scored through the real scorer, that category must now read zero.
    """
    from sudarshan_core.engines.bfci_scorer import calculate_bfci_v2

    result = calculate_bfci_v2({"app_telemetry": [
        {"hook": UBIQUITOUS, "timestamp_ms": 1000},
    ]})
    bfci = result[0] if isinstance(result, tuple) else result
    components = result[1] if isinstance(result, tuple) and len(result) > 1 else {}
    assert float(bfci) == 0.0
    if isinstance(components, dict):
        assert float(components.get("accessibility", 0.0)) == 0.0


def test_a_real_abuse_event_still_scores():
    from sudarshan_core.engines.bfci_scorer import calculate_bfci_v2

    result = calculate_bfci_v2({"accessibility": [
        {"hook": "AccessibilityNodeInfo.getText", "timestamp_ms": 1000},
    ]})
    bfci = result[0] if isinstance(result, tuple) else result
    assert float(bfci) > 0.0
