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

import math
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


#: Length at or below which an alphabetic token is treated as a credential name
#: rather than a word, and compared strictly.
#:
#: Token-set ratio is the right tool for rewording and the wrong one for short
#: credential names. ``"Forgot IPIN"`` and ``"Forgot MPIN?"`` score 90.9 - well
#: over the threshold - because the shared word dominates and the two four-letter
#: tokens differ by one character. But an IPIN is HDFC's netbanking password and
#: an MPIN is a generic app PIN; they are different credentials belonging to
#: different banks, not one label reworded. During calibration that single false
#: match was worth an eighth of HDFC's string score against every app in the
#: set, and it decided one attribution outright.
SHORT_TOKEN_CHARS = 5


def _confusable(a: str, b: str) -> bool:
    """Same length, differing in at most one character."""
    if len(a) != len(b) or a == b:
        return False
    return sum(1 for x, y in zip(a, b) if x != y) <= 1


def same_label(baseline: str, suspect: str) -> bool:
    """
    Do these two strings name the same thing, once short tokens are respected?

    The distinction that matters is **substitution versus omission**.

    A suspect that carries a *different* short token where the baseline has one
    -- ``MPIN`` where the baseline says ``IPIN`` -- is naming a different
    credential, and the shared surrounding word must not carry it over the
    threshold. A suspect that simply *lacks* one of the baseline's short tokens
    -- ``MPIN`` against ``6-digit MPIN``, ``YONO`` against ``YONO SBI`` -- is
    the same label with a qualifier dropped, which is exactly the rewording
    fuzzy matching exists to absorb.

    So an absent short token is forgiven unless the suspect offers a confusable
    stand-in for it. Assumes the pair already cleared :data:`MATCH_THRESHOLD`;
    this is the second half of the test, not a replacement for it.
    """
    wanted = _TOKEN_RE.findall((baseline or "").lower())
    present = _TOKEN_RE.findall((suspect or "").lower())
    present_set = set(present)
    short_present = [
        t for t in present_set if len(t) <= SHORT_TOKEN_CHARS and t.isalpha()
    ]
    for token in wanted:
        if len(token) > SHORT_TOKEN_CHARS or not token.isalpha():
            continue
        if token in present_set:
            continue
        if any(_confusable(token, other) for other in short_present):
            return False
    return True


def label_weights(baseline_label_sets: Sequence[Sequence[str]]) -> Dict[str, float]:
    """
    How much each label is worth as *attribution* evidence, by rarity.

    A label every bank ships - "Login", "OTP", "Customer ID" - proves the app is
    a banking UI and says nothing about which bank it imitates. A label only one
    bank ships - "PNB ONE", "iMobile Pay" - is close to proof on its own.
    Counting them equally lets a bank win on generic vocabulary, which is the
    same reasoning :mod:`corpus_compare` already applies when it excludes
    structure from attribution.

    Standard inverse document frequency over the baseline set, so the weights
    move with the corpus instead of being a hand-kept list of "generic" words
    that would drift the moment a baseline is added.
    """
    frequency: Dict[str, int] = {}
    for labels in baseline_label_sets:
        for label in {normalize(s) for s in labels if s and s.strip()}:
            if label:
                frequency[label] = frequency.get(label, 0) + 1
    total = len(baseline_label_sets)
    if not total:
        return {}
    return {
        label: math.log(1.0 + total / count) for label, count in frequency.items()
    }


def fuzzy_containment(
    targets: Sequence[str],
    candidates: Sequence[str],
    threshold: float = MATCH_THRESHOLD,
    weights: Optional[Dict[str, float]] = None,
) -> Tuple[float, List[str], List[Dict[str, object]]]:
    """
    How much of ``targets`` the ``candidates`` reproduce, allowing rewording.

    Containment rather than a symmetric ratio, deliberately: the question is
    "how much of this bank's UI text does the suspect carry", and a suspect
    with a large string table must not be rewarded for diluting the
    denominator.

    ``weights`` scores the targets by attribution value (see
    :func:`label_weights`); without it every label counts the same.

    Returns ``(score, matched_targets, match_details)``.
    """
    wanted = [t for t in targets if t and t.strip()]
    if not wanted:
        return 0.0, [], []
    pool = [c for c in candidates if c and c.strip()]
    if not pool:
        return 0.0, [], []

    def _weight(label: str) -> float:
        if not weights:
            return 1.0
        return weights.get(normalize(label), 1.0)

    # One `extractOne` per target rather than `process.cdist`: cdist is faster
    # still, but it imports numpy, which this project does not otherwise
    # depend on. extractOne stays entirely inside RapidFuzz's C extension.
    matched: List[str] = []
    details: List[Dict[str, object]] = []
    earned = 0.0
    available = 0.0
    for target in wanted:
        weight = _weight(target)
        available += weight
        found, score = best_match(target, pool, threshold)
        # `best_match` returns only the single closest candidate, so a target
        # whose closest match fails the short-token test scores zero rather than
        # falling through to a lesser one. That costs a match in the rare case
        # where both are present; it never invents one.
        if found is not None and same_label(target, found):
            matched.append(target)
            earned += weight
            details.append(
                {"baseline": target, "suspect": found, "ratio": round(score, 1)}
            )

    return (earned / available if available else 0.0), matched, details


def shares_any(
    a: Sequence[str],
    b: Sequence[str],
    threshold: float = MATCH_THRESHOLD,
) -> int:
    """Count of entries in ``a`` that have a fuzzy counterpart in ``b``."""
    pool = [s for s in b if s and s.strip()]
    if not pool:
        return 0
    hits = 0
    for label in a:
        if not label or not label.strip():
            continue
        found, _ = best_match(label, pool, threshold)
        if found is not None and same_label(label, found):
            hits += 1
    return hits
