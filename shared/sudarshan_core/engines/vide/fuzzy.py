"""Fuzzy string matching for VIDE's string axis.

Set equality is the wrong test for UI labels. A clone author who retypes a
login screen produces ``"Enter your User ID"`` where the bank ships
``"User ID"``, ``"Mobile No."`` for ``"Mobile Number"``, ``"Login "`` with a
stray space. Every one of those is a zero under exact matching and a near-one
to a victim, and the string axis carries 40% of the VIDE confidence score - so
the rigid comparison did not merely under-score those clones, it reported them
as clean.

Matching is therefore **token set ratio**: both strings reduce to their sorted
token sets, and the score is driven by the tokens they share rather than by
character order or by the extra words one side carries. That is what makes
``"User ID"`` match ``"Enter your User ID"`` at a high ratio while keeping
``"Settings"`` and ``"Login"`` far apart.

RapidFuzz does this in C when it is installed. It is a soft dependency: a pure
Python fallback implements the same algorithm so an environment without the
wheel gets the same verdicts, only slower. VIDE is a verdict source, so the two
paths must agree - the fallback is the same algorithm, not an approximation of
it.
"""

from __future__ import annotations

import re
from difflib import SequenceMatcher
from typing import Dict, List, Optional, Sequence, Tuple

try:  # pragma: no cover - exercised by whichever path is installed
    from rapidfuzz import fuzz as _rf_fuzz
    from rapidfuzz import process as _rf_process
    from rapidfuzz import utils as _rf_utils

    HAVE_RAPIDFUZZ = True
except ImportError:  # pragma: no cover
    _rf_fuzz = None  # type: ignore[assignment]
    _rf_process = None  # type: ignore[assignment]
    _rf_utils = None  # type: ignore[assignment]
    HAVE_RAPIDFUZZ = False

# RapidFuzz's scorers are case-sensitive and punctuation-sensitive unless a
# processor is supplied. Without this, "FORGOT MPIN?" and "Forgot MPIN" score
# 52 - a miss - while the pure-Python path (which tokenises through a
# lowercasing regex) scores them 100. The two backends must not disagree, and
# UI labels differ in case and trailing punctuation constantly.
_PROCESSOR = _rf_utils.default_process if HAVE_RAPIDFUZZ else None

#: Ratio at or above which two labels are "the same label, reworded".
#: Below this, shared tokens are coincidental - "Account Balance" and "Account
#: Statement" share a token and are different screens.
MATCH_THRESHOLD = 82.0

_TOKEN_RE = re.compile(r"[a-z0-9]+")


def normalize(value: str) -> str:
    """Lowercase, strip punctuation, collapse whitespace."""
    return " ".join(_TOKEN_RE.findall((value or "").lower()))


def _token_set_ratio_py(a: str, b: str) -> float:
    """Pure-Python token set ratio, same construction as RapidFuzz's."""
    tokens_a = set(_TOKEN_RE.findall(a.lower()))
    tokens_b = set(_TOKEN_RE.findall(b.lower()))
    if not tokens_a or not tokens_b:
        return 0.0
    if tokens_a == tokens_b:
        return 100.0

    common = sorted(tokens_a & tokens_b)
    rest_a = sorted(tokens_a - tokens_b)
    rest_b = sorted(tokens_b - tokens_a)

    joined_common = " ".join(common)
    combined_a = " ".join(common + rest_a).strip()
    combined_b = " ".join(common + rest_b).strip()

    return max(
        SequenceMatcher(None, joined_common, combined_a).ratio(),
        SequenceMatcher(None, joined_common, combined_b).ratio(),
        SequenceMatcher(None, combined_a, combined_b).ratio(),
    ) * 100.0


def token_set_ratio(a: str, b: str) -> float:
    """Similarity of two labels in 0..100, order- and padding-insensitive."""
    if not a or not b:
        return 0.0
    if HAVE_RAPIDFUZZ:
        return float(_rf_fuzz.token_set_ratio(a, b, processor=_PROCESSOR))
    return _token_set_ratio_py(a, b)


def best_match(
    needle: str,
    haystack: Sequence[str],
    threshold: float = MATCH_THRESHOLD,
) -> Tuple[Optional[str], float]:
    """Closest entry in ``haystack`` to ``needle``, or ``(None, 0.0)``."""
    if not needle or not haystack:
        return None, 0.0
    if HAVE_RAPIDFUZZ:
        hit = _rf_process.extractOne(
            needle,
            haystack,
            scorer=_rf_fuzz.token_set_ratio,
            processor=_PROCESSOR,
            score_cutoff=threshold,
        )
        return (hit[0], float(hit[1])) if hit else (None, 0.0)

    best: Optional[str] = None
    best_score = 0.0
    for candidate in haystack:
        score = _token_set_ratio_py(needle, candidate)
        if score > best_score:
            best_score, best = score, candidate
    if best_score < threshold:
        return None, 0.0
    return best, best_score


def fuzzy_containment(
    targets: Sequence[str],
    candidates: Sequence[str],
    threshold: float = MATCH_THRESHOLD,
) -> Tuple[float, List[str], List[Dict[str, object]]]:
    """
    How much of ``targets`` the ``candidates`` reproduce, allowing rewording.

    Containment rather than a symmetric ratio, deliberately: the question is
    "how much of this bank's UI text does the suspect carry", and a suspect
    with a large string table must not be rewarded for diluting the
    denominator.

    Returns ``(score, matched_targets, match_details)``.
    """
    wanted = [t for t in targets if t and t.strip()]
    if not wanted:
        return 0.0, [], []
    pool = [c for c in candidates if c and c.strip()]
    if not pool:
        return 0.0, [], []

    # One `extractOne` per target rather than `process.cdist`: cdist is faster
    # still, but it imports numpy, which this project does not otherwise
    # depend on. extractOne stays entirely inside RapidFuzz's C extension.
    matched: List[str] = []
    details: List[Dict[str, object]] = []
    for target in wanted:
        found, score = best_match(target, pool, threshold)
        if found is not None:
            matched.append(target)
            details.append(
                {"baseline": target, "suspect": found, "ratio": round(score, 1)}
            )

    return len(matched) / len(wanted), matched, details


def shares_any(
    a: Sequence[str],
    b: Sequence[str],
    threshold: float = MATCH_THRESHOLD,
) -> int:
    """Count of entries in ``a`` that have a fuzzy counterpart in ``b``."""
    pool = [s for s in b if s and s.strip()]
    if not pool:
        return 0
    return sum(1 for s in a if s and s.strip() and best_match(s, pool, threshold)[0])
