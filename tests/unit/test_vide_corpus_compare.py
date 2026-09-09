"""VIDE corpus comparison: view AST, perceptual colour, bank attribution."""

import pytest

from sudarshan_core.engines.vide.ast_builders import (
    build_from_html,
    build_from_uiautomator,
)
from sudarshan_core.engines.vide.baseline_store import get_baselines
from sudarshan_core.engines.vide.color_match import (
    IDENTICAL_DELTA_E,
    MAX_MATCH_DELTA_E,
    color_distance,
    is_brand_color,
    match_score,
    palette_similarity,
    parse_hex,
)
from sudarshan_core.engines.vide.corpus_compare import compare_against_corpus
from sudarshan_core.engines.vide.corpus_loader import find_corpus_root
from sudarshan_core.engines.vide.ui_profile import UIProfile
from sudarshan_core.engines.vide.view_ast import (
    ROLE_BUTTON,
    ROLE_INPUT,
    SIG_AUTH_FORM,
    SIG_PINPAD,
    infer_structural_signatures,
    signature_score,
    skeleton,
    tree_similarity,
)

requires_corpus = pytest.mark.skipif(
    find_corpus_root() is None, reason="banking baseline corpus not available"
)


def _corpus():
    return [b for b in get_baselines() if b.source == "corpus"]


def _baseline(institution_id: str):
    return next(b for b in _corpus() if b.institution_id == institution_id)


def generic_bank_strings() -> list:
    """
    Labels that are NOT distinctive to any one bank.

    Derived from the corpus rather than hardcoded so the tests keep testing what
    they claim as the fingerprints evolve: these are the strings a generic
    banking UI shares, so they establish banking *shape* without leaking
    attribution evidence.
    """
    per_bank = [{s.lower() for s in b.profile.strings} for b in _corpus()]
    shared = set.intersection(*per_bank) if per_bank else set()
    # Top up with common banking vocabulary so shape evidence is realistic.
    return sorted(shared) + ["Login", "Available Balance", "Transfer", "Enter MPIN"]

LOGIN_HTML = """
<html><body><div>
  <h1>SecureBank</h1>
  <label>User ID</label><input placeholder="User ID"/>
  <label>Password</label><input type="password"/>
  <button>Login</button><button>Forgot Password?</button>
</div></body></html>
"""

LOGIN_NATIVE = """
<hierarchy><node class="android.widget.LinearLayout">
  <node class="android.widget.TextView" text="User ID"/>
  <node class="android.widget.EditText"/>
  <node class="android.widget.EditText"/>
  <node class="android.widget.Button" text="Login"/>
</node></hierarchy>
"""

SETTINGS_HTML = """
<html><body><div><h1>Settings</h1>
  <ul><li>About phone</li><li>Battery</li><li>Storage</li></ul>
</div></body></html>
"""


# ── colour ─────────────────────────────────────────────────────────────────

def test_parse_hex_forms():
    assert parse_hex("#1B4AA0") == (27, 74, 160)
    assert parse_hex("1b4aa0") == (27, 74, 160)
    assert parse_hex("#abc") == (170, 187, 204)
    assert parse_hex("#1B4AA0FF") == (27, 74, 160)  # alpha dropped
    assert parse_hex("nonsense") is None


def test_near_colors_match_and_far_colors_do_not():
    """Distances are CIE ΔE₂₀₀₀: ~1 is the just-noticeable difference."""
    # A clone re-drawn by hand lands a few units off the official brand colour,
    # which is invisible to a victim and must score as a full match.
    assert color_distance("#004c8f", "#014d91") < IDENTICAL_DELTA_E
    assert match_score(color_distance("#004c8f", "#014d91")) == 1.0
    # The PRD's worked example: two renderings of the same SBI blue.
    assert color_distance("#1B4AA0", "#1C4CA5") < IDENTICAL_DELTA_E
    # Different banks' brand colours must stay distinguishable - far enough
    # apart to score zero, not merely a larger number.
    assert color_distance("#004c8f", "#97144d") > MAX_MATCH_DELTA_E
    assert match_score(color_distance("#004c8f", "#97144d")) == 0.0


def test_achromatic_colors_are_not_brand_colors():
    for neutral in ("#ffffff", "#000000", "#f5f5f5", "#888888"):
        assert not is_brand_color(neutral), neutral
    for brand in ("#004c8f", "#ed232a", "#97144d"):
        assert is_brand_color(brand), brand


def test_palette_similarity_is_coverage_not_symmetric():
    """A suspect carrying extra colours is not penalised for them."""
    exact = palette_similarity(["#004c8f", "#ed232a"], ["#004c8f", "#ed232a"])
    assert exact["score"] == pytest.approx(1.0)

    padded = palette_similarity(
        ["#004c8f", "#ed232a", "#123456", "#654321"], ["#004c8f", "#ed232a"]
    )
    assert padded["score"] == pytest.approx(1.0)

    none = palette_similarity(["#00ff00"], ["#004c8f", "#ed232a"])
    assert none["score"] == 0.0


# ── AST ────────────────────────────────────────────────────────────────────

def test_html_ast_keeps_nesting_and_roles():
    node = build_from_html(LOGIN_HTML)
    assert node is not None
    counts = node.role_counts()
    assert counts[ROLE_INPUT] == 2
    assert counts[ROLE_BUTTON] == 2
    # Nesting is preserved, not flattened to a tag list.
    assert "(" in skeleton(node)


def test_ast_matches_across_toolkits():
    """A Capacitor clone must compare structurally against a native baseline."""
    web = build_from_html(LOGIN_HTML)
    native = build_from_uiautomator(LOGIN_NATIVE)
    unrelated = build_from_html(SETTINGS_HTML)

    assert tree_similarity(web, native) > 0.75
    assert tree_similarity(web, unrelated) < 0.5
    # And the gap must be decisive, not marginal.
    assert tree_similarity(web, native) - tree_similarity(web, unrelated) > 0.3


def test_malformed_html_does_not_raise():
    assert build_from_html("<div><p>unclosed<div><span>") is not None
    assert build_from_html("") is None
    assert build_from_uiautomator("<not xml") is None


def test_signature_inference():
    login = build_from_html(LOGIN_HTML)
    sigs = infer_structural_signatures(login, ["User ID", "Password", "Login"])
    assert SIG_AUTH_FORM in sigs
    # "Forgot MPIN?" on a login screen is a link, not a PIN pad.
    assert SIG_PINPAD not in infer_structural_signatures(
        login, ["User ID", "Password", "Login", "Forgot MPIN?"]
    )

    pinpad_html = (
        "<html><body><div><h2>Enter 6-Digit MPIN</h2><input type='password'/>"
        + "".join(f"<button>{d}</button>" for d in range(10))
        + "</div></body></html>"
    )
    assert SIG_PINPAD in infer_structural_signatures(
        build_from_html(pinpad_html), ["Enter 6-Digit MPIN"]
    )


def test_signature_score_credits_partial_clone():
    """One exactly-copied screen must score well against a 3-screen baseline."""
    baseline = [SIG_AUTH_FORM, SIG_PINPAD, "DASHBOARD_CARD_GRID_QUICKACTIONS"]
    partial = signature_score([SIG_AUTH_FORM], baseline)
    full = signature_score(baseline, baseline)

    assert 0.5 <= partial < full
    assert full == pytest.approx(1.0)
    assert signature_score([], baseline) == 0.0
    assert signature_score(["UNRELATED"], baseline) == 0.0


# ── attribution ────────────────────────────────────────────────────────────

def _verdict(strings, colors, html):
    return compare_against_corpus(
        UIProfile(source="test", strings=strings, colors=colors),
        get_baselines(),
        build_from_html(html),
    )


@requires_corpus
@pytest.mark.parametrize(
    "colors,expected",
    [
        (["#004c8f", "#ed232a"], "BASE-02-HDFC"),
        (["#014d91", "#ee2530"], "BASE-02-HDFC"),  # hand-redrawn clone
        (["#97144d", "#da1884"], "BASE-04-AXIS"),
        (["#1b4aa0", "#2e9e4b"], "BASE-01-SBI"),
    ],
)
def test_brand_palette_attributes_the_right_bank(colors, expected):
    """With only generic banking text, the palette must decide attribution."""
    verdict = _verdict(generic_bank_strings(), colors, LOGIN_HTML)
    assert verdict.best.institution_id == expected
    assert verdict.attribution_ambiguous is False


@requires_corpus
@pytest.mark.parametrize(
    "institution_id",
    ["BASE-01-SBI", "BASE-03-ICICI", "BASE-08-KOTAK", "BASE-10-UNION"],
)
def test_the_institution_name_attributes_the_right_bank(institution_id):
    """
    A clone that puts a bank's name on screen is attributed to that bank even
    when its colours are neutral.

    Tier 1: names are exclusive by construction, which is what makes this work
    on a corpus whose label sets and structural signatures are identical across
    all ten baselines.
    """
    baseline = _baseline(institution_id)
    name = baseline.app_name or baseline.display_name
    # As a clone renders it: on the splash, the header and the welcome copy.
    branding = [name, f"Welcome to {name}", f"New to {name}?"]
    verdict = _verdict(generic_bank_strings() + branding, ["#888888"], LOGIN_HTML)

    assert verdict.best.institution_id == institution_id
    assert verdict.attribution_ambiguous is False
    assert any(
        hit.startswith("name:") for hit in verdict.best.attribution.exclusive_hits
    )





@requires_corpus
def test_full_clone_is_detected():
    """Distinctive labels plus the brand palette must fire the rule."""
    baseline = _baseline("BASE-02-HDFC")
    verdict = _verdict(
        list(baseline.profile.strings), ["#004c8f", "#ed232a"], LOGIN_HTML
    )
    assert verdict.detected is True
    assert verdict.best.institution_id == "BASE-02-HDFC"
    # Well above the 0.20 detection threshold: this suspect reproduces the
    # baseline nearly exactly, so a bare "over threshold" assertion would pass
    # on far weaker evidence than the case is testing.
    assert verdict.best.confidence >= 0.72


@requires_corpus
def test_banking_shape_without_distinctive_evidence_is_ambiguous_not_asserted():
    """
    Generic banking text and no brand colour leaves nothing to attribute. VIDE
    must say so rather than naming an arbitrary bank in a report.
    """
    verdict = _verdict(generic_bank_strings(), ["#888888", "#ffffff"], LOGIN_HTML)

    assert verdict.attribution_ambiguous is True
    assert verdict.detected is False
    assert any("ambiguous" in line.lower() for line in verdict.evidence_lines)


@requires_corpus
def test_non_banking_app_in_bank_colours_is_not_flagged():
    """Brand colours alone must not trigger impersonation."""
    verdict = _verdict(
        ["Sports", "Weather", "Subscribe", "Daily News"],
        ["#004c8f", "#ed232a"],
        SETTINGS_HTML,
    )
    assert verdict.detected is False
    assert verdict.banking_shape_score < 0.35


@requires_corpus
def test_verdict_is_deterministic():
    strings = generic_bank_strings()
    first = _verdict(strings, ["#004c8f", "#ed232a"], LOGIN_HTML).to_dict()
    second = _verdict(strings, ["#004c8f", "#ed232a"], LOGIN_HTML).to_dict()
    assert first == second


@requires_corpus
def test_empty_suspect_is_safe():
    verdict = compare_against_corpus(UIProfile(source="empty"), get_baselines(), None)
    assert verdict.detected is False
    assert verdict.best is None
    assert verdict.to_dict()["institution_id"] == ""
