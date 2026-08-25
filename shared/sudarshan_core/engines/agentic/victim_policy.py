"""
SUDARSHAN - Autonomous Victim Decision Policy
=============================================
Deterministic action scoring that prioritizes positive, permissive, and
journey-advancing actions while penalizing negative, cancelling, and
destructive ones.

The engine already had a semantic role model (semantic_action.py) and an
exploration prioritizer (exploration_engine.ActionPrioritizer). Neither is a
victim: the role model answers "what kind of control is this", the prioritizer
answers "what is worth exploring". Both leave a CANCEL adjacent to an ALLOW at
a survivable score, and a simulated victim that occasionally cancels never
reaches the second stage of a dropper.

This module answers one narrower question - "what would a gullible user tap" -
and answers it by keyword, so the decision is reproducible across runs and
reviewable in a report. It ranks; it never executes.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

# Positive action weights: +50 to +120
VICTIM_POSITIVE_KEYWORDS: Dict[str, int] = {
    # Permissions & VPN confirmation
    "allow": 100,
    "always allow": 110,
    "while using the app": 105,
    "only this time": 80,
    "grant": 100,
    "accept": 100,
    "permit": 100,
    "agree": 95,
    "i agree": 95,
    "ok": 90,
    "continue": 90,
    "proceed": 90,
    "confirm": 90,
    "yes": 85,
    "got it": 80,

    # Updates & installations
    "install": 100,
    "install anyway": 110,
    "update": 100,
    "update now": 105,
    "download": 95,
    "download update": 100,
    "upgrade": 95,
    "install application": 100,
    "allow from this source": 110,  # Unknown-sources toggle
    "install unknown apps": 105,

    # System settings & services (accessibility, device admin, VPN)
    "enable": 95,
    "enable service": 100,
    "activate": 95,
    "activate this device admin app": 110,
    "turn on": 95,
    "start": 90,
    "start now": 95,  # Screen capture / cast dialog
    "open": 85,
    "set up": 85,
}

# Negative action weights, so the victim never cancels by default.
VICTIM_NEGATIVE_KEYWORDS: Dict[str, int] = {
    "deny": -100,
    "dont allow": -100,
    "don't allow": -100,
    "do not allow": -100,
    "cancel": -100,
    "no": -90,
    "not now": -90,
    "skip": -80,
    "remind me later": -80,
    "later": -80,
    "dismiss": -80,
    "exit": -95,
    "close": -90,
    "close app": -95,
    "uninstall": -100,
    "block": -100,
    "reject": -95,
}

#: Screens where a permissive answer is the whole point of being there, so the
#: affirmative control is worth more than the same word elsewhere in the app.
VICTIM_BOUNDARY_SCREEN_TYPES: frozenset[str] = frozenset({
    "VPN_REQUEST",
    "SYSTEM_PERMISSION",
    "PACKAGE_INSTALLER",
    "EXTERNAL_APK",
    "ACCESSIBILITY_DIALOG",
    "UPDATE_PROMPT",
    "DOWNLOAD_PROMPT",
})

#: Below this, an action is a way OUT of the malware journey. Filtered by
#: callers until the affirmative options on a screen are exhausted.
VICTIM_REJECT_THRESHOLD: int = -50

#: Boundary-screen bonus for an affirmative control.
_BOUNDARY_BONUS: int = 15

#: A caption longer than this is prose, not a button label.
#:
#: The AOSP VPN consent dialog reads "<app> wants to set up a VPN connection
#: that allows it to monitor network traffic" - 90-odd characters containing
#: every affirmative keyword this module knows. On a dialog whose body sits in
#: a clickable container, that paragraph scored exactly as high as the OK
#: button beside it, and the victim tapped the sentence.
_PROSE_LENGTH: int = 60

#: Classes whose captions are labels by construction, however long.
_CONTROL_CLASS_HINTS: Tuple[str, ...] = (
    "button", "switch", "checkbox", "togglebutton", "radiobutton", "chip",
)

#: Longest keywords first, so "do not allow" is tested before "allow" and
#: "install anyway" before "install". Dict order is insertion order, which is
#: authored order, which is not match order - relying on it would make the
#: score depend on where a maintainer added the entry.
_NEGATIVE_RULES: Tuple[Tuple[re.Pattern[str], int], ...] = tuple(
    (re.compile(r"\b" + re.escape(kw) + r"\b"), penalty)
    for kw, penalty in sorted(
        VICTIM_NEGATIVE_KEYWORDS.items(), key=lambda kv: -len(kv[0])
    )
)

_POSITIVE_RULES: Tuple[Tuple[re.Pattern[str], int], ...] = tuple(
    (re.compile(r"\b" + re.escape(kw) + r"\b"), score)
    for kw, score in sorted(
        VICTIM_POSITIVE_KEYWORDS.items(), key=lambda kv: -len(kv[0])
    )
)


def _structural_score(cls_lower: str) -> int:
    """Score a control by what it IS when its caption says nothing."""
    if "switch" in cls_lower or "checkbox" in cls_lower:
        return 60
    if "edittext" in cls_lower or "input" in cls_lower:
        return 50
    if "button" in cls_lower:
        return 35
    return 0


def score_ui_node(
    node_text: str,
    node_desc: str,
    resource_id: str,
    class_name: str,
    screen_type: str = "",
) -> int:
    """
    Score an actionable UI element on victim heuristics.

    Higher score = higher priority for the simulated victim. Negative scores
    are ways out of the journey and are filtered by the callers rather than
    clamped here, so a report can still show what the victim declined to tap.
    """
    text_clean = (node_text or "").strip().lower()
    desc_clean = (node_desc or "").strip().lower()
    res_clean = (resource_id or "").strip().lower()
    combined = f"{text_clean} {desc_clean} {res_clean}"

    cls_lower = (class_name or "").lower()

    if not combined.strip():
        # No caption of any kind. The control type is then the only signal
        # there is, and it is a real one: an unlabelled toggle on an
        # accessibility screen is exactly the switch the victim has to flip.
        return _structural_score(cls_lower)

    # 1. Negatives first: "Do not allow" must never be read as "allow".
    for pattern, penalty in _NEGATIVE_RULES:
        if pattern.search(combined):
            return penalty

    # 2. Affirmatives, longest match wins.
    is_control = any(h in cls_lower for h in _CONTROL_CLASS_HINTS)
    is_prose = len(text_clean) > _PROSE_LENGTH and not is_control
    for pattern, score in _POSITIVE_RULES:
        if pattern.search(combined):
            if is_prose:
                # The keyword is in the explanation, not on a control. Still
                # positive - it is a screen the victim wants to get through -
                # but it must not outrank the button that gets them through it.
                return 15
            if screen_type in VICTIM_BOUNDARY_SCREEN_TYPES:
                return score + _BOUNDARY_BONUS
            return score

    # 3. Structural heuristics for a captioned control no keyword matched.
    structural = _structural_score(cls_lower)
    return structural if structural else 10


def score_label(label: str, screen_type: str = "", class_name: str = "") -> int:
    """Score a control that is known only by its rendered label."""
    return score_ui_node(label, "", "", class_name, screen_type)


def rank_action_candidates(
    ui_nodes: List[Any], screen_type: str = "",
) -> List[Tuple[Any, int]]:
    """
    Sort UINode-like objects in descending order of victim priority.

    Stable within a score band: the input order decides ties, so two runs over
    the same hierarchy produce the same walk.
    """
    scored: List[Tuple[Any, int]] = []
    for node in ui_nodes:
        t = getattr(node, "text", "") or ""
        d = getattr(node, "desc", "") or ""
        r = getattr(node, "resource_id", "") or ""
        c = getattr(node, "class_name", "") or ""
        scored.append((node, score_ui_node(t, d, r, c, screen_type)))

    scored.sort(key=lambda x: x[1], reverse=True)
    return scored


def is_victim_rejected(score: int) -> bool:
    """Whether a score is low enough that the victim should not tap it yet."""
    return score < VICTIM_REJECT_THRESHOLD
