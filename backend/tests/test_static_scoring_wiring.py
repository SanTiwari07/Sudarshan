"""
Guard: every caller of calculate_risk_score must pass the same keyword set.

Two production defects of exactly this shape have already shipped:

  Bug 4 (audit/DETECTION_VALIDATION.md:108-116)
      analysis-engine/app/main.py called the scorer without `all_permissions=`,
      so the Permission Risk axis - 0.10 of STEI - was silently always 0.
      Teabot reported `pr 0.0` while declaring 17 permissions.

  ai_confidence (fixed 2026-08-16)
      the same call site omitted `ai_confidence=`, so it defaulted to 1.0
      (risk_engine.py:848) while the gateway passed 1.2 for a classified
      family. Every recognised sample scored at 1/1.2 of the gateway's value,
      through the path production actually runs.

Both were invisible to every existing test, because both produce a *plausible*
score rather than an error, and both only diverge on inputs the unit fixtures
did not cover. A value-level test cannot catch the next one either - the point
of failure is the call site, not the arithmetic.

So this compares call sites structurally. It parses each file with `ast`, finds
the calls to the scorer (under any import alias), and asserts the keyword sets
agree. It never imports the modules: backend/app/routes/upload.py pulls FastAPI,
the DB, auth, RAG and the worker queue, and analysis-engine is not on this
package's path at all.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Dict, List, Set

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

# The scorer's real name, plus every alias it is imported under.
SCORER_NAMES = {"calculate_risk_score", "compute_fraud_risk_score"}

# The reference call site: the gateway path, which has been correct throughout
# and is what audit/DETECTION_VALIDATION.md measured against.
REFERENCE = REPO_ROOT / "backend" / "app" / "routes" / "upload.py"

# Every other call site that must agree with it.
CALL_SITES = [
    REPO_ROOT / "analysis-engine" / "app" / "main.py",
    REPO_ROOT / "shared" / "sudarshan_core" / "validation" / "static_scoring.py",
]


def _scorer_kwargs(path: Path) -> List[Set[str]]:
    """
    Keyword names on every call to the scorer in `path`, one set per call site.

    Handles both direct calls and `asyncio.to_thread(scorer, **kwargs)`, which
    is how analysis-engine invokes it - the callee is a positional argument
    there, so a naive scan of `node.func` misses it entirely.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: List[Set[str]] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        func = node.func
        name = getattr(func, "id", None) or getattr(func, "attr", None)

        # Direct call: scorer(...)
        if name in SCORER_NAMES:
            found.append({kw.arg for kw in node.keywords if kw.arg})
            continue

        # Indirect: asyncio.to_thread(scorer, ...) / run_in_executor(None, scorer, ...)
        if name in ("to_thread", "run_in_executor"):
            for arg in node.args:
                if getattr(arg, "id", None) in SCORER_NAMES:
                    found.append({kw.arg for kw in node.keywords if kw.arg})
                    break

    return found


def _existing_call_sites() -> Dict[Path, List[Set[str]]]:
    return {p: _scorer_kwargs(p) for p in CALL_SITES if p.is_file()}


def test_reference_call_site_is_present():
    """If upload.py stops calling the scorer, this whole guard is meaningless."""
    calls = _scorer_kwargs(REFERENCE)
    assert calls, f"No calculate_risk_score call found in {REFERENCE}"
    assert len(calls) == 1, f"Expected exactly one scorer call in {REFERENCE}, found {len(calls)}"


def test_reference_passes_the_known_load_bearing_kwargs():
    """
    Pin the two kwargs that have each already caused a silent scoring defect.

    Named explicitly rather than left implicit in the cross-file comparison: if
    someone drops one from upload.py too, the sets would still match and the
    comparison below would pass while both paths score wrongly.
    """
    (kwargs,) = _scorer_kwargs(REFERENCE)
    for required in ("all_permissions", "ai_confidence"):
        assert required in kwargs, (
            f"{REFERENCE.name} no longer passes {required}= to the risk scorer. "
            "Both of these have previously been dropped and silently skewed every "
            "score - see audit/DETECTION_VALIDATION.md Bug 4."
        )


@pytest.mark.parametrize("path", CALL_SITES, ids=lambda p: p.name)
def test_call_site_matches_reference(path: Path):
    """Every scorer call site must pass at least what the gateway passes."""
    if not path.is_file():
        pytest.skip(f"{path} does not exist yet")

    (reference_kwargs,) = _scorer_kwargs(REFERENCE)
    calls = _scorer_kwargs(path)
    assert calls, f"No calculate_risk_score call found in {path}"

    for kwargs in calls:
        missing = reference_kwargs - kwargs
        assert not missing, (
            f"{path.relative_to(REPO_ROOT)} calls the risk scorer without "
            f"{sorted(missing)}, which {REFERENCE.name} does pass. Omitted "
            f"kwargs fall back to defaults and skew every score through this "
            f"path without raising - exactly the Bug 4 failure mode."
        )


def test_guard_detects_a_removed_kwarg():
    """
    The guard must actually fail when a kwarg goes missing.

    A structural test that cannot fail is worse than no test, since it reads as
    coverage. This parses a synthetic call site with `ai_confidence` removed and
    asserts the comparison catches it.
    """
    source = (
        "risk = calculate_risk_score(\n"
        "    flags=f, dynamic_result=None, correlation_result=None,\n"
        "    family=fam, all_permissions=perms, vide_result=None,\n"
        ")\n"
    )
    tree = ast.parse(source)
    call = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
    kwargs = {kw.arg for kw in call.keywords if kw.arg}

    (reference_kwargs,) = _scorer_kwargs(REFERENCE)
    assert "ai_confidence" in reference_kwargs - kwargs, (
        "The kwarg-set comparison would not have caught a dropped ai_confidence="
    )
