"""
Shell execution and payload deployment are worth points.

Observed live: Drinik, a labelled banking trojan, called
`ProcessBuilder.start` and native `execve("/bin/sh")` in a 300-second run and
scored **BFCI 0.0**. Those events landed in `dangerous_apis`, which carries no
weight, so an Android app spawning a shell contributed nothing to the fraud
score.

The bucket could not simply be weighted, because it was mixed:

    PathClassLoader.<init>   every app loads its own APK through it
    System.loadLibrary       any app with native code triggers it
    DexClassLoader / InMemoryDexClassLoader / Runtime.exec /
    ProcessBuilder.start / libc.execve / FileOutputStream.apkWrite

Weighting that set would have repeated the sendAccessibilityEvent mistake: a
constant every app produces, inflating every verdict equally. The genuine
execution hooks were split into `code_execution`; the two ubiquitous ones
stayed behind, unscored.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

from sudarshan_core.engines.bfci_scorer import (  # noqa: E402
    BFCI_WEIGHTS,
    CODE_EXECUTION_WEIGHT,
    UNSCORED_CATEGORIES,
    _BASE_WEIGHTS,
    _CATEGORY_CAPS,
    calculate_bfci_v2,
)

_HOOKS = _ROOT / "shared" / "sudarshan_core" / "engines" / "frida_hooks"

#: Hooks an ordinary app does not reach.
EXECUTION_HOOKS = (
    "DexClassLoader.<init>",
    "InMemoryDexClassLoader.<init>",
    "Runtime.exec",
    "ProcessBuilder.start",
    "libc.execve",
    "FileOutputStream.apkWrite",
)

#: Hooks every app - or every app with native code - triggers.
UBIQUITOUS_HOOKS = (
    "PathClassLoader.<init>",
    "System.loadLibrary",
)


#: The bundle is GENERATED, so its string quoting belongs to the compiler and
#: has changed between frida-compile versions - the committed bundle used
#: single quotes, a rebuild emits double. Accepting either keeps this asserting
#: what the agent EMITS rather than how the bundler happened to format it.
_Q = r"['\"]"


def _category_of(hook: str, text: str) -> str:
    match = re.search(rf"hook: {_Q}{re.escape(hook)}{_Q}", text)
    assert match is not None, f"'{hook}' does not appear in the agent at all"
    head = text[: match.start()]
    emitted = re.findall(rf"emit\({_Q}([a-z_]+){_Q}", head)
    category = re.findall(rf"category: {_Q}([a-z_]+){_Q}", head)
    # The native hooks use a raw send() with an explicit category field.
    if category and (
        not emitted
        or head.rfind(category[-1]) > head.rfind("emit(")
    ):
        return category[-1]
    return emitted[-1]


# ── the weight model stays coherent ──────────────────────────────────────────

def test_the_weights_still_sum_to_one():
    """raw_bfci is sum(weight * component) with no normalisation."""
    assert sum(BFCI_WEIGHTS.values()) == pytest.approx(1.0, abs=1e-6)


def test_the_existing_axes_keep_their_relative_ordering():
    """
    Adding an axis is a claim about what was MISSING, not a reason to re-rank
    what was already validated. Every original axis loses the same share.
    """
    for name, base in _BASE_WEIGHTS.items():
        assert BFCI_WEIGHTS[name] == pytest.approx(
            base * (1.0 - CODE_EXECUTION_WEIGHT), abs=1e-6
        )
    order_before = sorted(_BASE_WEIGHTS, key=lambda k: -_BASE_WEIGHTS[k])
    order_after = sorted(_BASE_WEIGHTS, key=lambda k: -BFCI_WEIGHTS[k])
    assert order_before == order_after


def test_the_new_axis_has_a_volume_cap():
    """Without a cap the component score cannot reach 100."""
    assert _CATEGORY_CAPS.get("code_execution")


def test_dangerous_apis_remains_unscored():
    """
    It is also the fallback bucket for unrecognised categories, so weighting it
    would let an unknown hook inflate the fraud score.
    """
    assert "dangerous_apis" in UNSCORED_CATEGORIES
    assert "dangerous_apis" not in BFCI_WEIGHTS


# ── the split itself ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("hook", EXECUTION_HOOKS)
def test_execution_hooks_are_scored(hook):
    js = (_HOOKS / "banking_trojan.js").read_text(encoding="utf-8", errors="replace")
    assert _category_of(hook, js) == "code_execution"


@pytest.mark.parametrize("hook", UBIQUITOUS_HOOKS)
def test_ubiquitous_hooks_are_not_scored(hook):
    """
    PathClassLoader is how every Android app loads its own APK, and
    System.loadLibrary fires for any app shipping native code. Scoring either
    would make every app look identical on this axis.
    """
    js = (_HOOKS / "banking_trojan.js").read_text(encoding="utf-8", errors="replace")
    assert _category_of(hook, js) not in BFCI_WEIGHTS


def test_the_compiled_bundle_carries_the_split():
    """The bundle is what runs on the device."""
    bundle = (_HOOKS / "banking_trojan.bundle.js").read_text(
        encoding="utf-8", errors="replace"
    )
    for hook in EXECUTION_HOOKS:
        assert _category_of(hook, bundle) == "code_execution"
    for hook in UBIQUITOUS_HOOKS:
        assert _category_of(hook, bundle) not in BFCI_WEIGHTS


def test_the_sandbox_registers_the_bucket():
    """An unregistered category falls through to dangerous_apis and is lost."""
    from sudarshan_core.engines import frida_sandbox

    source = Path(frida_sandbox.__file__).read_text(encoding="utf-8", errors="replace")
    assert '"code_execution": []' in source


# ── the measured case ────────────────────────────────────────────────────────

def test_the_drinik_shell_execution_now_scores():
    """ProcessBuilder.start + execve('/bin/sh'), exactly as observed."""
    bfci, components, _, _ = calculate_bfci_v2({"code_execution": [
        {"hook": "ProcessBuilder.start", "timestamp_ms": 1000},
        {"hook": "libc.execve", "timestamp_ms": 1200},
    ]})
    assert bfci > 0.0
    assert components["code_execution"] == 100.0


def test_a_benign_app_loading_its_own_code_still_scores_zero():
    """The false positive this split exists to prevent."""
    bfci, _, _, _ = calculate_bfci_v2({"dangerous_apis": [
        {"hook": "PathClassLoader.<init>", "timestamp_ms": 1000},
        {"hook": "System.loadLibrary", "timestamp_ms": 1100},
    ]})
    assert bfci == 0.0


def test_one_execution_event_is_already_meaningful():
    """An app that spawns one shell has demonstrated the capability."""
    bfci, _, _, _ = calculate_bfci_v2({"code_execution": [
        {"hook": "Runtime.exec", "timestamp_ms": 1000},
    ]})
    assert bfci > 0.0


def test_the_goal_graph_agrees_with_the_new_category():
    """
    Stage 10 completes on dynamic code loading. Its completion category has to
    follow the hooks, or the goal can never complete.
    """
    from sudarshan_core.engines.agentic.goal_tracker import GoalTracker

    goals = {g.stage: g for g in GoalTracker()._goals}
    stage10 = goals[10]
    assert "code_execution" in stage10.completion_categories
    for ubiquitous in UBIQUITOUS_HOOKS:
        assert ubiquitous not in stage10.frida_hooks
