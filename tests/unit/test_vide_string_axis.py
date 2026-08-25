"""The string axis: short-token strictness, and rarity as attribution weight.

Both rules exist because the string axis carries 40% of the confidence score and
was spending it on evidence that does not identify a bank.
"""

import math

from sudarshan_core.engines.vide.fuzzy import (
    SHORT_TOKEN_CHARS,
    fuzzy_containment,
    label_weights,
    same_label,
    shares_any,
    token_set_ratio,
)


# ───────────────────── substitution versus omission ─────────────────────────


def test_a_different_short_credential_is_not_the_same_label():
    """
    ``IPIN`` is HDFC's netbanking password; ``MPIN`` is a generic app PIN.

    Token-set ratio scores the pair over threshold because the shared word
    dominates, which is the behaviour that made every app in the calibration set
    reproduce an HDFC label it does not carry.
    """
    assert token_set_ratio("Forgot IPIN", "Forgot MPIN?") >= 82.0
    assert same_label("Forgot IPIN", "Forgot MPIN?") is False
    assert same_label("IPIN", "MPIN") is False
    assert same_label("CRN", "CIN") is False


def test_a_dropped_qualifier_is_still_the_same_label():
    """The rewording case fuzzy matching exists for, and must keep absorbing."""
    assert same_label("6-digit MPIN", "MPIN") is True
    assert same_label("YONO SBI", "YONO") is True
    assert same_label("User ID", "Enter User ID") is True
    assert same_label("Cust ID", "Customer ID") is True


def test_identical_labels_always_match():
    assert same_label("Forgot IPIN", "Forgot IPIN") is True
    assert same_label("Net Banking", "Net Banking") is True


def test_long_tokens_are_left_to_the_fuzzy_scorer():
    """Only short tokens are read as credential names."""
    assert len("password") > SHORT_TOKEN_CHARS
    # 'Password' vs 'Passcode' differ by more than a character anyway, but the
    # point is that the strict rule does not reach words of this length.
    assert same_label("Profile Password", "Forgot Password") is True


def test_containment_drops_the_substituted_label():
    baseline = ["Customer ID", "IPIN", "HDFC Bank", "Login"]
    suspect = ["Customer ID", "Enter MPIN to login", "Login"]

    score, matched, _ = fuzzy_containment(baseline, suspect)
    assert "IPIN" not in matched
    assert "Customer ID" in matched
    assert score == 2 / 4


def test_shares_any_honours_the_same_rule():
    assert shares_any(["IPIN"], ["MPIN"]) == 0
    assert shares_any(["IPIN"], ["Forgot IPIN"]) == 1


# ─────────────────────────── rarity weighting ───────────────────────────────


def test_a_label_every_bank_ships_is_worth_less_than_a_bank_specific_one():
    """
    Attribution evidence, not banking-ness evidence.

    "Login" and "OTP" establish that an app is a banking UI and say nothing
    about which bank it imitates; "PNB ONE" is close to proof on its own.
    """
    weights = label_weights([
        ["Login", "OTP", "PNB ONE"],
        ["Login", "OTP", "iMobile Pay"],
        ["Login", "OTP", "YONO SBI"],
    ])
    assert weights["pnb one"] > weights["login"]
    assert weights["login"] == weights["otp"]
    # log(1 + N/df): three baselines, "login" in all three, "pnb one" in one.
    assert weights["login"] == math.log(2.0)
    assert weights["pnb one"] == math.log(4.0)


def test_weighting_lets_a_distinctive_label_outscore_generic_vocabulary():
    """
    Sized to the real deployment: ten protected institutions.

    The spread is what does the work, and it depends on the set. Across ten
    baselines a label only one bank ships is worth log(11)/log(2) - about three
    and a half times - a label all ten ship, so a suspect reproducing one bank's
    own name outranks one reproducing three labels of shared banking vocabulary.
    With only two or three baselines the spread is too narrow for that, which is
    why the weights are derived from the set rather than fixed.
    """
    generic_labels = ["Login", "OTP", "Customer ID"]
    banks = [generic_labels + [f"Bank {n} App"] for n in range(10)]
    weights = label_weights(banks)

    assert weights["bank 0 app"] / weights["login"] > 3.0

    distinctive, matched, _ = fuzzy_containment(
        banks[0], ["Bank 0 App"], weights=weights
    )
    generic, _, _ = fuzzy_containment(
        banks[1], ["Login", "OTP", "Customer ID"], weights=weights
    )
    assert matched == ["Bank 0 App"]
    assert distinctive > generic


def test_unweighted_containment_is_the_plain_fraction():
    score, matched, _ = fuzzy_containment(["A label", "Another"], ["A label"])
    assert matched == ["A label"]
    assert score == 0.5


def test_empty_baseline_set_yields_no_weights():
    assert label_weights([]) == {}
