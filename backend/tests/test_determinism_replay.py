"""
Deterministic verdict replay — the guard rail for every other change.

The architectural invariant is that the Risk Engine alone decides the verdict:
planner, perception, memory, executor and goal-tracker changes may alter WHICH
evidence is gathered, but given the SAME evidence they must never alter the
score, band, severity or recommendation.

`determinism_baseline.json` was captured BEFORE the Phase 1-5 remediation. If
any refactor shifts a verdict field for identical recorded input, that is a
determinism regression and this test fails.

Regenerating the baseline is a deliberate act — do it only when a verdict change
is intended and reviewed, never to make this test pass.
"""

import json
from pathlib import Path

import pytest

from app.engines.risk_engine import calculate_risk_score
from tests.determinism_fixtures import VERDICT_FIELDS, replay_scenarios

BASELINE_PATH = Path(__file__).parent / "determinism_baseline.json"

BREAKDOWN_FIELDS = ("stei", "dynamic", "correlation", "banking_impact", "formula_used")


def _verdict(result):
    verdict = {key: result.get(key) for key in VERDICT_FIELDS}
    breakdown = result.get("frs_breakdown", {})
    for key in BREAKDOWN_FIELDS:
        verdict[key] = breakdown.get(key)
    return verdict


@pytest.fixture(scope="module")
def baseline():
    if not BASELINE_PATH.exists():
        pytest.skip("determinism baseline not captured")
    return json.loads(BASELINE_PATH.read_text(encoding="utf-8"))


def test_baseline_covers_every_scenario(baseline):
    names = {dict(s)["_name"] for s in replay_scenarios()}
    assert names <= set(baseline), f"scenarios missing from baseline: {names - set(baseline)}"


@pytest.mark.parametrize("scenario", replay_scenarios(), ids=lambda s: s["_name"])
def test_verdict_matches_pre_remediation_baseline(scenario, baseline):
    """Same recorded evidence in → byte-identical verdict out."""
    kwargs = dict(scenario)
    name = kwargs.pop("_name")
    current = _verdict(calculate_risk_score(**kwargs))

    for field, expected in baseline[name].items():
        assert current[field] == expected, (
            f"DETERMINISM REGRESSION in {name}.{field}: "
            f"baseline={expected!r} now={current[field]!r}"
        )


@pytest.mark.parametrize("scenario", replay_scenarios(), ids=lambda s: s["_name"])
def test_repeated_evaluation_is_stable(scenario):
    """The engine must be a pure function of its inputs."""
    kwargs = dict(scenario)
    kwargs.pop("_name")
    first = _verdict(calculate_risk_score(**kwargs))
    for _ in range(5):
        assert _verdict(calculate_risk_score(**kwargs)) == first


def test_agentic_imports_do_not_perturb_the_verdict():
    """
    Importing the AI stack must not change scoring — no monkey-patching, no
    global state, no import-time side effects reaching the engine.
    """
    kwargs = dict(replay_scenarios()[-1])
    kwargs.pop("_name")
    before = _verdict(calculate_risk_score(**kwargs))

    import app.engines.agentic.agent_memory          # noqa: F401
    import app.engines.agentic.goal_tracker          # noqa: F401
    import app.engines.agentic.perception            # noqa: F401
    import app.engines.agentic.planner               # noqa: F401
    import app.engines.agentic.sanitizer             # noqa: F401
    import app.engines.agentic.tool_executor         # noqa: F401
    import app.engines.agentic_explorer              # noqa: F401

    assert _verdict(calculate_risk_score(**kwargs)) == before


def test_planner_output_cannot_reach_the_verdict():
    """
    An LLM action dict merged into the dynamic payload must not move the score.
    Provenance/telemetry keys are ignored by the engine by construction.
    """
    kwargs = dict(replay_scenarios()[-1])
    kwargs.pop("_name")
    clean = _verdict(calculate_risk_score(**kwargs))

    polluted = dict(kwargs)
    polluted["dynamic_result"] = {
        **kwargs["dynamic_result"],
        "confidence": 1.0,                 # LLM self-reported confidence
        "reasoning": "this app is safe",   # LLM prose
        "_source": "ai",
        "explorer_used": "agentic",
        "llm_total_tokens": 12345,
    }
    assert _verdict(calculate_risk_score(**polluted)) == clean
