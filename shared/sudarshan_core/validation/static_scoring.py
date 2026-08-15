"""
The static half of the analysis pipeline, callable without a web framework.

`backend/app/routes/upload.py` is the reference implementation of how an APK
becomes a score, but it cannot be imported outside the gateway: its module
imports pull FastAPI, the database, auth, the RAG knowledge base and the worker
queue. So the sequence is reproduced here rather than imported.

Reproducing rather than importing is a duplication risk, and this codebase has
already been bitten by it twice - both times a call site quietly stopped passing
a keyword argument and every score through that path shifted without raising
(`audit/DETECTION_VALIDATION.md` Bug 4, and the `ai_confidence` omission fixed
2026-08-16). `backend/tests/test_static_scoring_wiring.py` compares the keyword
sets of all three call sites structurally so this file cannot drift from the
gateway unnoticed.

Static-only means: no emulator, no Frida, no threat-intel keys, no VIDE. Those
axes are reported as excluded rather than scored as zero - scoring an absent
axis as 0 is what `DETECTION_VALIDATION.md` Bug 2 was, and it made 25% of every
score structurally unreachable.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

from sudarshan_core.analyzers.apk_analyzer import analyze_apk
from sudarshan_core.engines.classification_engine import classify_family
from sudarshan_core.engines.risk_engine import calculate_risk_score

# What the risk engine is told about the axes we are not running. `None` for
# dynamic and an explicit unavailable-marker for correlation both route to the
# same renormalisation path (risk_engine.py:932,953) - the axis is dropped and
# the remaining weights are rescaled to sum to 1.0.
_CORRELATION_UNAVAILABLE: Dict[str, Any] = {"available": False}


@dataclass
class StaticScoringResult:
    """Everything one APK produced, kept together for the caller to flatten."""

    package_name: str
    family: str
    matched_rule: str
    ai_confidence: float
    permissions: List[str]
    flags: Dict[str, Any]
    risk: Dict[str, Any]

    @property
    def frs(self) -> float:
        return float(self.risk.get("final_risk_score", 0.0))

    @property
    def band(self) -> str:
        return str(self.risk.get("risk_band", "Unknown"))

    @property
    def confidence(self) -> float:
        return float(self.risk.get("confidence", 0.0))

    @property
    def breakdown(self) -> Dict[str, Any]:
        return self.risk.get("frs_breakdown") or {}


def _flags_to_dict(flags: Any) -> Dict[str, Any]:
    """
    Mirror of `upload.py:_flags_to_dict`.

    Dumps the model rather than listing fields, for the reason given there: a
    hand-maintained field list silently dropped `has_concealed_payload` when it
    was added, so packed malware scored Safe through the gateway.
    """
    if hasattr(flags, "model_dump"):        # pydantic v2
        return flags.model_dump()
    if hasattr(flags, "dict"):              # pydantic v1
        return flags.dict()
    if isinstance(flags, dict):
        return dict(flags)
    return {k: v for k, v in vars(flags).items() if not k.startswith("_")}


def score_apk_static(apk_path: str | Path) -> StaticScoringResult:
    """
    Analyse and score one APK with every optional stage switched off.

    Deterministic for a given APK and androguard version: no clock, no network,
    no randomness. List ordering from the analyser derives from DEX string-pool
    iteration, which is stable within an androguard version but not guaranteed
    across them - callers that persist results should record the version.
    """
    androguard_output = analyze_apk(str(apk_path))

    flags_dict = _flags_to_dict(androguard_output.flags)
    family, matched_rule = classify_family(androguard_output.flags)

    # Same derivation as upload.py:768. A classified family is corroborating
    # evidence, so it earns a modest multiplier; Unknown earns none.
    ai_confidence = 1.0 if family == "Unknown" else 1.2

    risk = calculate_risk_score(
        flags=flags_dict,
        ai_confidence=ai_confidence,
        dynamic_result=None,
        correlation_result=_CORRELATION_UNAVAILABLE,
        family=family,
        all_permissions=androguard_output.permissions,
        vide_result=None,
    )

    return StaticScoringResult(
        package_name=androguard_output.package_name,
        family=family,
        matched_rule=matched_rule,
        ai_confidence=ai_confidence,
        permissions=list(androguard_output.permissions or []),
        flags=flags_dict,
        risk=risk,
    )
