"""
Corpus-wide feature weighting - the layer that separates the ten banks.

The arithmetic tests here run on synthetic baselines so they hold whether or not
a corpus checkout is present. The tests at the bottom run against the real
corpus and pin the specific collisions this work was done to fix.
"""

import pytest

from sudarshan_core.engines.vide.baseline_store import get_baselines
from sudarshan_core.engines.vide.corpus_loader import BaselineScreen, find_corpus_root
from sudarshan_core.engines.vide.discriminative import (
    ATTRIBUTION_MAX_DELTA_E,
    CorpusDiscriminators,
    attribution_color_score,
    discriminative_weight,
    discriminators_for,
    identity_coverage,
    weighted_label_containment,
    weighted_palette_match,
)
from sudarshan_core.engines.vide.ui_profile import UIProfile

requires_corpus = pytest.mark.skipif(
    find_corpus_root() is None, reason="banking baseline corpus not available"
)


class _FakeBaseline:
    """Minimum surface :class:`CorpusDiscriminators` reads."""

    def __init__(self, institution_id, app_name, bank, strings, colors, signatures=()):
        self.institution_id = institution_id
        self.baseline_id = institution_id
        self.app_name = app_name
        self.display_name = app_name
        self.bank = bank
        self.version = "1.0"
        self.package_names = []
        self.profile = UIProfile(source="test", strings=list(strings), colors=list(colors))
        self.screens = [
            BaselineScreen(screen_id=f"S{i}", structural_signature=s)
            for i, s in enumerate(signatures)
        ]


def _corpus(n=4):
    """``n`` banks sharing a template, each with one private label and colour."""
    shared = ["User ID", "Password", "Login"]
    palette = ["#1b4aa0", "#2e9e4b", "#97144d", "#f0ab00"]
    return [
        _FakeBaseline(
            institution_id=f"BASE-0{i + 1}-B{i + 1}",
            app_name=f"Bank{i + 1} Mobile",
            bank=f"Bank Number {i + 1}",
            strings=shared + [f"Bank{i + 1} exclusive label"],
            colors=[palette[i], "#808000"],  # one private, one shared by all
            signatures=("AUTH_FORM_VERTICAL_PRIMARY_CTA",),
        )
        for i in range(n)
    ]


# ── weighting ──────────────────────────────────────────────────────────────


def test_a_feature_every_baseline_carries_is_worth_nothing():
    """The property the whole design rests on."""
    assert discriminative_weight(df=10, corpus_size=10) == 0.0
    assert discriminative_weight(df=4, corpus_size=4) == 0.0


def test_an_exclusive_feature_is_worth_everything():
    assert discriminative_weight(df=1, corpus_size=10) == 1.0


def test_weight_falls_as_a_feature_spreads():
    weights = [discriminative_weight(df, 10) for df in range(1, 11)]
    assert weights == sorted(weights, reverse=True)
    assert weights[1] == pytest.approx(0.4444, abs=1e-4)


def test_degenerate_inputs_do_not_raise():
    assert discriminative_weight(df=0, corpus_size=10) == 0.0
    assert discriminative_weight(df=1, corpus_size=1) == 0.0
    assert discriminative_weight(df=1, corpus_size=0) == 0.0


# ── labels ─────────────────────────────────────────────────────────────────


def test_template_labels_carry_no_attribution_weight():
    index = CorpusDiscriminators(_corpus())
    entry = index.for_institution("BASE-01-B1")
    assert "user id" not in entry.label_weights
    assert "password" not in entry.label_weights
    assert entry.label_weights["bank1 exclusive label"] == 1.0


def test_reproducing_the_template_scores_zero_on_every_bank():
    index = CorpusDiscriminators(_corpus())
    for baseline in _corpus():
        entry = index.for_institution(baseline.institution_id)
        score, matched = weighted_label_containment(
            ["User ID", "Password", "Login"], entry.label_weights, entry.label_display
        )
        assert score == 0.0
        assert matched == []


def test_reproducing_an_exclusive_label_scores_fully():
    index = CorpusDiscriminators(_corpus())
    entry = index.for_institution("BASE-02-B2")
    score, matched = weighted_label_containment(
        ["User ID", "Bank2 exclusive label"], entry.label_weights, entry.label_display
    )
    assert score == 1.0
    assert matched == ["Bank2 exclusive label"]


# ── structural signatures ──────────────────────────────────────────────────


def test_a_universal_structural_signature_carries_no_attribution_weight():
    index = CorpusDiscriminators(_corpus())
    assert index.for_institution("BASE-01-B1").signature_weights == {}


# ── colour ─────────────────────────────────────────────────────────────────


def test_a_colour_every_bank_uses_carries_no_weight():
    index = CorpusDiscriminators(_corpus())
    entry = index.for_institution("BASE-01-B1")
    assert "#808000" not in entry.color_weights
    assert entry.color_weights["#1b4aa0"] == 1.0


def test_colour_frequency_is_counted_perceptually_not_by_hex():
    """
    Two banks whose brand colour differs in the last hex digit share it.

    Counting by string equality would call both unique and hand each a weight of
    1.0, which is how palettes that collide at ΔE 0 came to attribute suspects
    to whichever bank happened to sort first.
    """
    near_identical = _corpus(2)
    near_identical[1].profile.colors = ["#1b4aa1", "#808000"]  # ΔE ~0 from #1b4aa0
    index = CorpusDiscriminators(near_identical)

    assert index.for_institution("BASE-01-B1").color_weights.get("#1b4aa0", 0.0) < 1.0
    assert index.for_institution("BASE-02-B2").color_weights.get("#1b4aa1", 0.0) < 1.0


def test_the_attribution_colour_curve_is_tighter_than_the_perceptual_one():
    """Separating ten banks needs a stricter test than "a victim sees the same"."""
    assert attribution_color_score(0.0) == 1.0
    assert attribution_color_score(2.0) == 1.0
    assert 0.0 < attribution_color_score(5.0) < 1.0
    assert attribution_color_score(ATTRIBUTION_MAX_DELTA_E) == 0.0
    # The generic curve still credits this distance; attribution must not.
    assert attribution_color_score(12.0) == 0.0


def test_weighted_palette_ignores_the_shared_colour():
    index = CorpusDiscriminators(_corpus())
    entry = index.for_institution("BASE-03-B3")
    score, matches = weighted_palette_match(["#808000"], entry.color_weights)
    assert score == 0.0
    assert matches == []


# ── identity ───────────────────────────────────────────────────────────────


def test_the_longest_name_wins_an_overlapping_match():
    """"Bank of India" must not claim a string that says "Union Bank of India"."""
    banks = [
        _FakeBaseline("BASE-07-BOI", "BOI Mobile", "Bank of India", [], []),
        _FakeBaseline("BASE-10-UNION", "Vyom", "Union Bank of India", [], []),
    ]
    hits = CorpusDiscriminators(banks).identity_hits(["Union Bank of India"])
    assert set(hits) == {"BASE-10-UNION"}


def test_a_generic_name_is_not_identity_evidence():
    """"Mobile Banking" names a sector, not an institution."""
    banks = [
        _FakeBaseline("BASE-01-A", "Mobile Banking", "Bank", [], []),
        _FakeBaseline("BASE-02-B", "Kotak811", "Kotak Mahindra Bank", [], []),
    ]
    hits = CorpusDiscriminators(banks).identity_hits(["Mobile Banking"])
    assert "BASE-01-A" not in hits


def test_wearing_a_name_outscores_mentioning_it():
    """
    The Union-names-ICICI case: mock payee data names an unrelated bank once,
    while a clone puts the name it is impersonating on several screens.
    """
    banks = _corpus(2)
    index = CorpusDiscriminators(banks)
    entry = index.for_institution("BASE-01-B1")

    mentioned = index.identity_hits(["Paid to Bank1 Mobile"])["BASE-01-B1"]
    worn = index.identity_hits(
        ["Bank1 Mobile", "Welcome to Bank1 Mobile", "New to Bank1 Mobile?"]
    )["BASE-01-B1"]

    assert identity_coverage(worn, entry) > identity_coverage(mentioned, entry)


def test_package_aliases_do_not_dilute_identity_coverage():
    """A bank with four package names must not be harder to attribute to."""
    plain = _FakeBaseline("BASE-01-A", "Alpha Mobile", "Alpha Bank", [], [])
    aliased = _FakeBaseline("BASE-02-B", "Beta Mobile", "Beta Bank", [], [])
    aliased.package_names = ["com.beta.one", "com.beta.two", "com.fss.betamob"]

    index = CorpusDiscriminators([plain, aliased])
    plain_score = identity_coverage(
        index.identity_hits(["Alpha Mobile"])["BASE-01-A"],
        index.for_institution("BASE-01-A"),
    )
    aliased_score = identity_coverage(
        index.identity_hits(["Beta Mobile"])["BASE-02-B"],
        index.for_institution("BASE-02-B"),
    )
    assert plain_score == pytest.approx(aliased_score)


# ── caching ────────────────────────────────────────────────────────────────


def test_the_index_is_cached_per_baseline_set():
    """Colour df is quadratic; it must not be recomputed per comparison."""
    banks = _corpus()
    assert discriminators_for(banks) is discriminators_for(list(banks))


# ── against the real corpus ────────────────────────────────────────────────


@requires_corpus
@pytest.mark.parametrize(
    "institution_id",
    ["BASE-03-ICICI", "BASE-06-PNB", "BASE-07-BOI"],
)
def test_every_named_bank_can_still_be_told_apart(institution_id):
    """Down-weighting shared features must not leave a bank unattributable."""
    corpus = [b for b in get_baselines() if b.source == "corpus"]
    entry = discriminators_for(corpus).for_institution(institution_id)
    assert entry.has_discriminative_evidence()
    assert entry.identity, f"{institution_id} has no identity evidence"


@requires_corpus
def test_the_corpus_reports_no_indistinguishable_baseline():
    corpus = [b for b in get_baselines() if b.source == "corpus"]
    assert discriminators_for(corpus).degenerate_institutions() == []


@requires_corpus
@pytest.mark.parametrize(
    "shared_color",
    ["#f26522", "#f37021", "#f4a81d"],
)
def test_the_oranges_boi_bob_and_icici_share_carry_no_attribution(shared_color):
    """
    The exact collision behind the reported false positives.

    BOI's ``#f26522`` is bit-identical to BOB's and sits ΔE 0.0 from ICICI's
    ``#f37021``. Whichever bank a hex-equality matcher assigned it to, it won a
    three-way tie on a colour that says nothing.
    """
    corpus = [b for b in get_baselines() if b.source == "corpus"]
    index = discriminators_for(corpus)
    for baseline in corpus:
        entry = index.for_institution(baseline.institution_id)
        score, _ = weighted_palette_match([shared_color], entry.color_weights)
        assert score < 0.5, (
            f"{shared_color} alone scored {score:.2f} against "
            f"{baseline.institution_id}"
        )
