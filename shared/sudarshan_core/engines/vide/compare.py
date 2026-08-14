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
from typing import List, Optional, Sequence

from sudarshan_core.engines.vide.baseline_store import InstitutionBaseline, shortlist_baselines
from sudarshan_core.engines.vide.color_match import palette_similarity
from sudarshan_core.engines.vide.fuzzy import fuzzy_containment
from sudarshan_core.engines.vide.ui_profile import UIProfile, VIDECompareResult
from sudarshan_core.engines.vide.view_ast import normalize_view_sequence

RULE_ID = "VIDE-F001"
DETECTION_THRESHOLD = 0.72

W_STRINGS = 0.40
W_STRUCTURE = 0.35
W_COLOR = 0.25

# Minimum evidence on a discriminating axis. Confidence alone can be carried
# past the threshold by structure, which every banking app shares, so a finding
# also has to show that this app reproduces *this* bank's text or palette.
MIN_STRING_EVIDENCE = 0.08
MIN_STRUCTURE_EVIDENCE = 0.35


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
) -> VIDECompareResult:
    """Score a suspect UI profile against one institution baseline."""
    base = baseline.profile

    string_score, matched, match_details = fuzzy_containment(
        base.strings, suspect.strings
    )
    tree_score = _tree_similarity(suspect.view_sequence, base.view_sequence)

    color_result = palette_similarity(suspect.color_palette, base.color_palette)
    color_score = float(color_result["score"])  # type: ignore[arg-type]

    confidence = (
        W_STRINGS * string_score + W_STRUCTURE * tree_score + W_COLOR * color_score
    )

    official = claims_official_identity(baseline, package_name, signer_sha256)
    over_threshold = confidence >= DETECTION_THRESHOLD
    has_evidence = (
        string_score >= MIN_STRING_EVIDENCE or tree_score >= MIN_STRUCTURE_EVIDENCE
    )
    detected = over_threshold and has_evidence and not official

    evidence = [
        f"VIDE string match {string_score:.2f} "
        f"({len(matched)}/{len(base.strings)} baseline labels reproduced, fuzzy)",
        f"VIDE view-tree similarity={tree_score:.2f} (normalised roles)",
        f"VIDE brand palette match (ΔE2000)={color_score:.2f}",
    ]
    if matched:
        evidence.append("Matched strings: " + ", ".join(matched[:8]))
    for detail in match_details[:3]:
        if str(detail["baseline"]).lower() != str(detail["suspect"]).lower():
            evidence.append(
                f"Label '{detail['baseline']}' reproduced as "
                f"'{detail['suspect']}' (ratio {detail['ratio']})"
            )
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
    best: Optional[VIDECompareResult] = None
    for bl in candidates:
        result = compare_profiles(suspect, bl, package_name, signer_sha256)
        if best is None or result.confidence > best.confidence:
            best = result
    return best or VIDECompareResult(rule_id=RULE_ID, evidence_lines=["VIDE: no baselines loaded"])
