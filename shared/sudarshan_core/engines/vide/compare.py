"""Deterministic UI structural comparison (VIDE verdict source).

Rule ``VIDE-F001``: this app reproduces a protected bank's user interface
without being that bank's app.

Three axes, weighted as the VIDE specification mandates:

* **strings** (0.40) - fuzzy token-set containment of the bank's labels, so a
  reworded clone still scores (see :mod:`fuzzy`),
* **structure** (0.35) - view sequence compared over a normalised role
  vocabulary, so a Capacitor ``<input>`` matches a native ``EditText``, and
* **colour** (0.25) - perceptual ΔE₂₀₀₀ brand palette match (see
  :mod:`color_match`).

The finding fires on confidence alone *only if* the app is not entitled to the
identity it wears. Reproducing a bank's UI is exactly what that bank's own app
does; what makes it impersonation is doing so under a package name and signing
certificate that are not the bank's.
"""

from __future__ import annotations

from difflib import SequenceMatcher
from typing import Dict, List, Optional, Sequence

from sudarshan_core.engines.vide.baseline_store import InstitutionBaseline, shortlist_baselines
from sudarshan_core.engines.vide.color_match import describe_color_match, palette_similarity
from sudarshan_core.engines.vide.forensics import build_forensic_breakdown
from sudarshan_core.engines.vide.fuzzy import fuzzy_containment, label_weights
from sudarshan_core.engines.vide.ui_profile import UIProfile, VIDECompareResult
from sudarshan_core.engines.vide.view_ast import normalize_view_sequence

RULE_ID = "VIDE-F001"

# Confidence at or above which the app is reported as an impersonation.
#
# Calibrated to 0.20 deliberately. The weighting means a suspect that
# reproduces a bank's palette and nothing else caps out around 0.25, and one
# that reproduces the login vocabulary without the brand colours around 0.30 -
# both are clones worth an analyst's attention, and both scored clean under the
# previous 0.72 gate, which only fired when all three axes were near-perfect.
# The floor against noise is not this number: it is the per-axis evidence
# minimums below plus the official-identity allowlist, which together stop a
# non-banking app from ever reaching a verdict.
DETECTION_THRESHOLD = 0.20

W_STRINGS = 0.40
W_STRUCTURE = 0.35
W_COLOR = 0.25

# Minimum evidence on a discriminating axis. Confidence alone can be carried
# past the threshold by structure, which every banking app shares, so a finding
# also has to show that this app reproduces *this* bank's text or palette.
#
# Both floors are lowered alongside the threshold, and for the same reason: a
# Capacitor clone whose labels live in a minified bundle surfaces only a
# fraction of the baseline's string table to static extraction, so an 0.08
# string floor was rejecting real clones on the basis of how thoroughly the
# extractor happened to work rather than on what the app is.
MIN_STRING_EVIDENCE = 0.02
MIN_COLOR_EVIDENCE = 0.10

# Structure is *supporting* evidence and is checked separately below, because
# at a 0.20 threshold it can no longer be allowed to carry a verdict alone.
# It is worth 0.35 of the confidence score, so any app whose layout resembles a
# login screen clears 0.20 on structure by itself - during calibration a device
# settings screen (``Settings`` / ``Wi-Fi`` / ``Bluetooth``, black on white,
# zero string and zero palette overlap) scored 0.21 against the SBI baseline
# and would have been reported as an SBI clone. Every banking app shares that
# skeleton, so it establishes shape and cannot establish identity.
MIN_STRUCTURE_EVIDENCE = 0.10


def _tree_similarity(a: Sequence[str], b: Sequence[str]) -> float:
    """
    Structural similarity over the normalised role vocabulary.

    Both sides are translated first, so the comparison is not defeated by the
    two apps having been built with different toolkits - which is the normal
    case, since a clone of a native app is usually a WebView shell.
    """
    if not a or not b:
        return 0.0
    sa = " ".join(normalize_view_sequence(a)[:80])
    sb = " ".join(normalize_view_sequence(b)[:80])
    return SequenceMatcher(None, sa, sb).ratio()


def claims_official_identity(
    baseline: InstitutionBaseline,
    package_name: str,
    signer_sha256: str,
) -> bool:
    """
    Is this app genuinely the institution's own, per the official records?

    Both halves are required. A matching package name alone proves nothing -
    anyone can build an APK under ``com.sbi.lotus``; it is the signature that
    makes the claim true. So an app is treated as genuine only when it carries
    a registered package name *and* a signing certificate on file for that
    institution.
    """
    if not package_name or not signer_sha256:
        return False
    if package_name not in baseline.package_names:
        return False
    allowed = {s.lower() for s in baseline.allowed_signers_sha256 if s}
    return bool(allowed) and signer_sha256.lower() in allowed


def compare_profiles(
    suspect: UIProfile,
    baseline: InstitutionBaseline,
    package_name: str = "",
    signer_sha256: str = "",
    string_weights: Optional[Dict[str, float]] = None,
) -> VIDECompareResult:
    """
    Score a suspect UI profile against one institution baseline.

    ``string_weights`` scores each baseline label by how rare it is across the
    baseline set, so a bank is not credited for shared banking vocabulary as
    heavily as for its own name. It is supplied by
    :func:`compare_against_baselines`, which is the only caller that can see the
    whole set; scoring one baseline in isolation falls back to equal weights.
    """
    base = baseline.profile

    string_score, matched, match_details = fuzzy_containment(
        base.strings, suspect.strings, weights=string_weights
    )
    tree_score = _tree_similarity(suspect.view_sequence, base.view_sequence)

    color_result = palette_similarity(suspect.color_palette, base.color_palette)
    color_score = float(color_result["score"])  # type: ignore[arg-type]

    confidence = (
        W_STRINGS * string_score + W_STRUCTURE * tree_score + W_COLOR * color_score
    )

    official = claims_official_identity(baseline, package_name, signer_sha256)
    over_threshold = confidence >= DETECTION_THRESHOLD
    # At least one axis that can tell *this* bank from another one. Either
    # suffices, so a clone whose text extracted but whose palette did not - or
    # the reverse, which is the normal case for a minified Capacitor bundle -
    # still reaches a verdict.
    has_evidence = (
        string_score >= MIN_STRING_EVIDENCE or color_score >= MIN_COLOR_EVIDENCE
    )
    structural_support = tree_score >= MIN_STRUCTURE_EVIDENCE
    detected = over_threshold and has_evidence and not official

    color_matches = list(color_result["matches"])  # type: ignore[arg-type]

    evidence = [
        f"UI text: {string_score:.2f} "
        f"({len(matched)}/{len(base.strings)} baseline labels reproduced, fuzzy)",
        f"View hierarchy: {tree_score:.2f} structural similarity (normalised roles)"
        + (
            " - corroborates the layout"
            if structural_support
            else " - below the support floor, not counted as corroboration"
        ),
        f"Brand colour scheme: {color_score:.2f} palette match "
        f"({color_result['matched_count']}/{color_result['target_count']} "
        f"{baseline.display_name} brand colours reproduced, CIE ΔE2000)",
    ]
    if matched:
        evidence.append("Matched UI text: " + ", ".join(matched[:8]))
    for detail in match_details[:3]:
        if str(detail["baseline"]).lower() != str(detail["suspect"]).lower():
            evidence.append(
                f"Label '{detail['baseline']}' reproduced as "
                f"'{detail['suspect']}' (ratio {detail['ratio']})"
            )
    # Named swatch pairs, not just the aggregate score: "0.91 palette match" is
    # not something an analyst can check, whereas "#EB6E1F vs #EB6E1F, ΔE=0.0"
    # is the actual finding and survives into the CERT-In annexure.
    for match in color_matches[:4]:
        evidence.append(describe_color_match(match))
    if detected:
        evidence.append(
            f"{RULE_ID}: confidence {confidence:.2f} exceeds threshold "
            f"{DETECTION_THRESHOLD:.2f} and the app does not carry "
            f"{baseline.display_name}'s registered package name and signing "
            f"certificate"
        )
    elif official and over_threshold:
        evidence.append(
            f"VIDE suppressed: package {package_name} and its signer are on "
            f"record as {baseline.display_name}'s own app"
        )

    return VIDECompareResult(
        rule_id=RULE_ID,
        detected=detected,
        institution_id=baseline.institution_id if detected else "",
        institution_display=baseline.display_name if detected else "",
        confidence=confidence,
        string_jaccard=string_score,
        tree_similarity=tree_score,
        color_match=color_score,
        matched_strings=matched,
        evidence_lines=evidence,
        forensics=build_forensic_breakdown(
            confidence=confidence,
            threshold=DETECTION_THRESHOLD,
            # The breakdown names the bank it scored against whether or not the
            # finding fired: "closest baseline, and here is why it did not
            # qualify" is the analyst's starting point on a near miss.
            institution_id=baseline.institution_id,
            institution_display=baseline.display_name,
            string_score=string_score,
            matched_strings=matched,
            baseline_string_count=len(base.strings),
            reworded_labels=match_details,
            structure_score=tree_score,
            color_score=color_score,
            color_matches=color_matches,
            color_target_count=int(color_result["target_count"]),  # type: ignore[arg-type]
        ),
    )


def compare_against_baselines(
    suspect: UIProfile,
    baselines: List[InstitutionBaseline],
    package_name: str = "",
    signer_sha256: str = "",
) -> VIDECompareResult:
    """Best-scoring institution match for a suspect UI profile."""
    if not suspect.strings and not suspect.view_sequence:
        return VIDECompareResult(
            rule_id=RULE_ID,
            evidence_lines=["VIDE: no extractable UI structure from suspect"],
        )
    candidates = shortlist_baselines(suspect, baselines)
    if not candidates:
        return VIDECompareResult(
            rule_id=RULE_ID,
            detected=False,
            evidence_lines=["VIDE: no baseline candidates (insufficient string overlap)"],
        )
    # Rarity is computed over every baseline, not just the shortlisted ones:
    # a label's attribution value is a property of the protected set, and
    # deriving it from the shortlist would make it depend on which candidates
    # this particular suspect happened to surface.
    weights = label_weights([bl.profile.strings for bl in baselines])

    best: Optional[VIDECompareResult] = None
    for bl in candidates:
        result = compare_profiles(
            suspect, bl, package_name, signer_sha256, string_weights=weights
        )
        if best is None or result.confidence > best.confidence:
            best = result
    return best or VIDECompareResult(rule_id=RULE_ID, evidence_lines=["VIDE: no baselines loaded"])
