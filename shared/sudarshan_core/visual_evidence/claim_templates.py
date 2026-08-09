"""Deterministic investigative claim templates - no LLM."""

from __future__ import annotations

import re
from typing import Any, Dict, Mapping, Optional, Set

from sudarshan_core.visual_evidence.constants import (
    ALL_CLAIM_TYPES,
    CLAIM_ACCESSIBILITY_GUIDANCE,
    CLAIM_ANTI_ANALYSIS_UI,
    CLAIM_BANKING_TARGET_UI,
    CLAIM_BENIGN_NEGATIVE_PROOF,
    CLAIM_CREDENTIAL_COLLECTION_UI,
    CLAIM_DROPPER_UI,
    CLAIM_FAKE_LOGIN_UI,
    CLAIM_FINAL_STATE,
    CLAIM_INCONCLUSIVE_VISUAL,
    CLAIM_LAUNCH_CONTEXT,
    CLAIM_OTP_UI,
    CLAIM_OVERLAY_OBSERVED,
    CLAIM_PAYMENT_UI,
    CLAIM_VISUAL_IMPERSONATION,
    FORBIDDEN_CLAIM_SUBSTRINGS,
)

_REQUIRED_PARAMS: Dict[str, frozenset] = {
    CLAIM_VISUAL_IMPERSONATION: frozenset({"baseline_name", "rule_id"}),
    CLAIM_OVERLAY_OBSERVED: frozenset(),
    CLAIM_FAKE_LOGIN_UI: frozenset(),
    CLAIM_CREDENTIAL_COLLECTION_UI: frozenset(),
    CLAIM_ACCESSIBILITY_GUIDANCE: frozenset(),
    CLAIM_OTP_UI: frozenset(),
    CLAIM_PAYMENT_UI: frozenset(),
    CLAIM_BANKING_TARGET_UI: frozenset(),
    CLAIM_ANTI_ANALYSIS_UI: frozenset(),
    CLAIM_DROPPER_UI: frozenset(),
    CLAIM_BENIGN_NEGATIVE_PROOF: frozenset(),
    CLAIM_LAUNCH_CONTEXT: frozenset(),
    CLAIM_FINAL_STATE: frozenset(),
    CLAIM_INCONCLUSIVE_VISUAL: frozenset(),
}

_TEMPLATES: Dict[str, str] = {
    CLAIM_VISUAL_IMPERSONATION: (
        "UI observed during analysis is visually consistent with {baseline_name} "
        "banking interface patterns (VIDE rule {rule_id})."
    ),
    CLAIM_OVERLAY_OBSERVED: (
        "A system overlay window was displayed while overlay-related runtime activity was observed."
    ),
    CLAIM_FAKE_LOGIN_UI: (
        "UI displayed input fields consistent with a login or credential collection screen."
    ),
    CLAIM_CREDENTIAL_COLLECTION_UI: (
        "UI displayed fields consistent with collection of banking credentials or PIN entry."
    ),
    CLAIM_ACCESSIBILITY_GUIDANCE: (
        "UI displayed accessibility settings or guidance consistent with enabling an accessibility service."
    ),
    CLAIM_OTP_UI: (
        "UI displayed elements consistent with OTP or one-time code entry."
    ),
    CLAIM_PAYMENT_UI: (
        "UI displayed elements consistent with a payment or UPI workflow screen."
    ),
    CLAIM_BANKING_TARGET_UI: (
        "UI was displayed while target banking application context was active in the sandbox session."
    ),
    CLAIM_ANTI_ANALYSIS_UI: (
        "UI displayed messages or screens consistent with emulator, root, or analysis detection."
    ),
    CLAIM_DROPPER_UI: (
        "UI displayed elements consistent with application update, download, or secondary payload loading."
    ),
    CLAIM_BENIGN_NEGATIVE_PROOF: (
        "During the observed decoy-banking session, no overlay deployment was observed "
        "and the expected application UI remained visible."
    ),
    CLAIM_LAUNCH_CONTEXT: (
        "Initial application UI observed after launch and settle period."
    ),
    CLAIM_FINAL_STATE: (
        "Application UI state observed immediately before session end."
    ),
    CLAIM_INCONCLUSIVE_VISUAL: (
        "Visual capture completed but insufficient corroborating runtime evidence was available "
        "to assign a specific investigative claim."
    ),
}


class ClaimTemplateError(ValueError):
    """Invalid claim type, parameters, or forbidden wording."""


def lint_investigative_claim(text: str) -> None:
    """Raise ClaimTemplateError if claim contains forbidden phrasing."""
    lower = (text or "").lower()
    for phrase in FORBIDDEN_CLAIM_SUBSTRINGS:
        if phrase in lower:
            raise ClaimTemplateError(f"Forbidden phrasing in claim: {phrase!r}")
    if re.search(r"\bdefinitely\b", lower):
        raise ClaimTemplateError("Forbidden wording: 'definitely'")
    if re.search(r"\bhacked\b", lower):
        raise ClaimTemplateError("Forbidden wording: 'hacked'")
    if re.search(r"\bcompromised\b", lower):
        raise ClaimTemplateError("Forbidden wording: 'compromised'")
    if re.search(r"\bproves\b", lower):
        raise ClaimTemplateError("Forbidden wording: 'proves'")


def render_investigative_claim(
    claim_type: str,
    params: Optional[Mapping[str, Any]] = None,
) -> str:
    """
    Render a deterministic investigative claim for the given claim_type.
    """
    if claim_type not in ALL_CLAIM_TYPES:
        raise ClaimTemplateError(f"Unknown claim_type: {claim_type!r}")

    params = dict(params or {})
    required = _REQUIRED_PARAMS.get(claim_type, frozenset())
    missing = [k for k in required if not str(params.get(k, "")).strip()]
    if missing:
        raise ClaimTemplateError(
            f"Missing required parameters for {claim_type}: {', '.join(missing)}"
        )

    template = _TEMPLATES[claim_type]
    try:
        text = template.format(**{k: str(params.get(k, "")) for k in _template_keys(template)})
    except KeyError as exc:
        raise ClaimTemplateError(f"Template parameter error for {claim_type}: {exc}") from exc

    lint_investigative_claim(text)
    return text


def _template_keys(template: str) -> Set[str]:
    return set(re.findall(r"\{(\w+)\}", template))
