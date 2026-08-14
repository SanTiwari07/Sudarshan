"""Fuzzy string matching - the axis that decides whether a reworded clone scores.

These tests pin behaviour, not the backend: RapidFuzz is a soft dependency and
the pure-Python fallback must reach the same verdicts, so every assertion here
is run against both paths.
"""

import pytest

from sudarshan_core.engines.vide import fuzzy
from sudarshan_core.engines.vide.fuzzy import (
    MATCH_THRESHOLD,
    best_match,
    fuzzy_containment,
    token_set_ratio,
)


@pytest.fixture(params=[True, False], ids=["rapidfuzz", "pure-python"])
def backend(request, monkeypatch):
    """Run each test on both matching backends."""
    if request.param and not fuzzy.HAVE_RAPIDFUZZ:
        pytest.skip("rapidfuzz not installed")
    monkeypatch.setattr(fuzzy, "HAVE_RAPIDFUZZ", request.param)
    return request.param


# ── token set ratio ────────────────────────────────────────────────────────


def test_identical_strings_score_full(backend):
    assert token_set_ratio("User ID", "User ID") == pytest.approx(100.0)


def test_reworded_label_still_matches(backend):
    """The failure mode the rigid comparer had: a retyped label scored zero."""
    assert token_set_ratio("User ID", "Enter your User ID") >= MATCH_THRESHOLD
    assert token_set_ratio("Login", "Login ") >= MATCH_THRESHOLD
    assert token_set_ratio("Enter 6-digit MPIN", "Enter 6 digit MPIN") >= MATCH_THRESHOLD


def test_case_and_punctuation_are_ignored(backend):
    assert token_set_ratio("FORGOT MPIN?", "Forgot MPIN") >= MATCH_THRESHOLD


def test_unrelated_labels_stay_apart(backend):
    assert token_set_ratio("Settings", "Login") < MATCH_THRESHOLD
    assert token_set_ratio("Bluetooth", "Available Balance") < MATCH_THRESHOLD


def test_shared_token_alone_is_not_a_match(backend):
    """Two different screens that happen to share a word are not the same label."""
    assert token_set_ratio("Account Balance", "Account Statement") < MATCH_THRESHOLD


def test_empty_input_scores_zero(backend):
    assert token_set_ratio("", "Login") == 0.0
    assert token_set_ratio("Login", "") == 0.0


# ── best match / containment ───────────────────────────────────────────────


def test_best_match_picks_closest_candidate(backend):
    found, score = best_match("User ID", ["Bluetooth", "Enter User ID", "Balance"])
    assert found == "Enter User ID"
    assert score >= MATCH_THRESHOLD


def test_best_match_returns_none_below_threshold(backend):
    found, score = best_match("Wi-Fi", ["Login", "MPIN", "Available Balance"])
    assert found is None
    assert score == 0.0


def test_containment_measures_baseline_coverage(backend):
    targets = ["User ID", "Password", "Login", "Forgot MPIN?"]
    suspect = ["Enter your User ID", "Password", "Log In Now", "Something else"]
    score, matched, details = fuzzy_containment(targets, suspect)
    assert "User ID" in matched
    assert "Password" in matched
    assert "Forgot MPIN?" not in matched
    assert 0.0 < score <= 1.0
    assert all(d["baseline"] in targets for d in details)


def test_containment_is_not_diluted_by_a_large_suspect(backend):
    """A suspect with 200 extra strings must not score lower for carrying them."""
    targets = ["User ID", "Password"]
    small = fuzzy_containment(targets, ["User ID", "Password"])[0]
    large = fuzzy_containment(
        targets, ["User ID", "Password"] + [f"noise {i}" for i in range(200)]
    )[0]
    assert small == large == pytest.approx(1.0)


def test_containment_of_nothing_is_zero(backend):
    assert fuzzy_containment([], ["Login"])[0] == 0.0
    assert fuzzy_containment(["Login"], [])[0] == 0.0


def test_backends_agree_on_verdicts():
    """The fallback is the same algorithm, not an approximation of it."""
    if not fuzzy.HAVE_RAPIDFUZZ:
        pytest.skip("rapidfuzz not installed")
    # Case and trailing punctuation are included deliberately: RapidFuzz's
    # scorers are sensitive to both unless a processor is passed, and that
    # divergence is silent - it reads as a clean app rather than as an error.
    pairs = [
        ("User ID", "Enter your User ID"),
        ("FORGOT MPIN?", "Forgot MPIN"),
        ("Available Balance", "available balance"),
        ("Login", "Settings"),
        ("Account Balance", "Account Statement"),
        ("Pay Bills", "PAY BILLS!"),
    ]
    for a, b in pairs:
        fuzzy.HAVE_RAPIDFUZZ = True
        with_rf = token_set_ratio(a, b)
        fuzzy.HAVE_RAPIDFUZZ = False
        try:
            without_rf = token_set_ratio(a, b)
        finally:
            fuzzy.HAVE_RAPIDFUZZ = True
        assert (with_rf >= MATCH_THRESHOLD) == (without_rf >= MATCH_THRESHOLD), (
            f"backends disagree on {a!r} vs {b!r}: "
            f"rapidfuzz={with_rf:.1f} pure-python={without_rf:.1f}"
        )
