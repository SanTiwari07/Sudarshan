"""
Generic semantic action model for unknown-APK dynamic analysis.

Maps UI controls to semantic roles (ACCEPT, DECLINE, PROGRESS, etc.) using
control type, surrounding context, and linguistic patterns — not fixed button
labels or package-specific rules.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, List, Optional, Sequence, Tuple


class SemanticRole(str, Enum):
    ACCEPT = "ACCEPT"
    DECLINE = "DECLINE"
    CANCEL = "CANCEL"
    PROGRESS = "PROGRESS"
    NAVIGATE = "NAVIGATE"
    SUBMIT = "SUBMIT"
    DOWNLOAD = "DOWNLOAD"
    INSTALL = "INSTALL"
    ENABLE = "ENABLE"
    DISABLE = "DISABLE"
    OPEN = "OPEN"
    CLOSE = "CLOSE"
    BACK = "BACK"
    EXPAND = "EXPAND"
    COLLAPSE = "COLLAPSE"
    SELECT = "SELECT"
    INPUT = "INPUT"
    UNKNOWN = "UNKNOWN"


# Linguistic patterns — examples, not an exhaustive allowlist.
_ACCEPT_PATTERNS: Tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.I) for p in (
        r"\ballow\b", r"\byes\b", r"\bok\b", r"\bokay\b", r"\bagree\b",
        r"\baccept\b", r"\bconfirm\b", r"\bcontinue\b", r"\bproceed\b",
        r"\bnext\b", r"\bstart\b", r"\bget started\b", r"\bbegin\b",
        r"\binstall\b", r"\bupdate\b", r"\bdownload\b", r"\benable\b",
        r"\bgrant\b", r"\bactivate\b", r"\bverify\b", r"\bclaim\b",
        r"\bopen\b", r"\bfinish\b", r"\bdone\b", r"\bsubmit\b",
        r"\bgo\b", r"\blet'?s go\b", r"\bget access\b", r"\bcomplete\b",
        r"\bturn on\b", r"\bset up\b", r"\bconnect\b", r"\bsign in\b",
        r"\blog in\b", r"\bregister\b", r"\bsign up\b",
    )
)

_DECLINE_PATTERNS: Tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.I) for p in (
        r"\bdeny\b", r"\bno\b", r"\bdecline\b", r"\breject\b",
        r"\bnot now\b", r"\blater\b", r"\bskip\b", r"\bnever\b",
        r"\bdisagree\b", r"\brefuse\b", r"\bdisable\b", r"\bturn off\b",
    )
)

_CANCEL_PATTERNS: Tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.I) for p in (
        r"\bcancel\b", r"\bdismiss\b", r"\bclose\b", r"\bexit\b",
        r"\bback\b", r"\bx\b",
    )
)

_PROGRESS_PATTERNS: Tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.I) for p in (
        r"\bnext\b", r"\bcontinue\b", r"\bproceed\b", r"\bforward\b",
        r"\bskip\b", r"\bmore\b", r"\bview\b", r"\bsee\b", r"\bexplore\b",
    )
)

_DOWNLOAD_PATTERNS: Tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.I) for p in (
        r"\bdownload\b", r"\bfetch\b", r"\bget update\b", r"\bretrieve\b",
    )
)

_INSTALL_PATTERNS: Tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.I) for p in (
        r"\binstall\b", r"\bsetup\b", r"\badd app\b",
    )
)

_ENABLE_PATTERNS: Tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.I) for p in (
        r"\benable\b", r"\bturn on\b", r"\bactivate\b", r"\bgrant\b",
        r"\ballow\b",
    )
)

_INPUT_CLASS_HINTS = ("edittext", "input", "textfield", "autocomplete")
_BUTTON_CLASS_HINTS = ("button", "imagebutton", "materialbutton", "chip")
_SWITCH_CLASS_HINTS = ("switch", "checkbox", "toggle", "radiobutton", "check")


def _match_any(text: str, patterns: Sequence[re.Pattern[str]]) -> bool:
    return any(p.search(text) for p in patterns)


def _score_patterns(text: str, patterns: Sequence[re.Pattern[str]]) -> float:
    if not text:
        return 0.0
    hits = sum(1 for p in patterns if p.search(text))
    return min(1.0, hits * 0.35)


@dataclass(frozen=True)
class SemanticClassification:
    role: SemanticRole
    confidence: float
    reasons: Tuple[str, ...] = ()


def classify_semantic_role(
    *,
    label: str = "",
    class_name: str = "",
    context_text: str = "",
    is_checkable: bool = False,
    is_clickable: bool = True,
    is_input: bool = False,
    is_scrollable: bool = False,
    checked: Optional[bool] = None,
    bounds_area: int = 0,
) -> SemanticClassification:
    """
    Infer the semantic role of a UI control from generic signals.

    Does not depend on exact malware button labels or package names.
    """
    text = " ".join(filter(None, [label.strip(), context_text.strip()[:200]]))
    cls = (class_name or "").lower()
    reasons: List[str] = []
    scores: dict[SemanticRole, float] = {r: 0.0 for r in SemanticRole}

    if is_input or any(h in cls for h in _INPUT_CLASS_HINTS):
        return SemanticClassification(SemanticRole.INPUT, 0.95, ("input_control",))

    if is_scrollable:
        return SemanticClassification(SemanticRole.EXPAND, 0.9, ("scrollable_region",))

    if is_checkable or any(h in cls for h in _SWITCH_CLASS_HINTS):
        if checked is True:
            return SemanticClassification(SemanticRole.ENABLE, 0.85, ("already_checked",))
        if _match_any(text, _DECLINE_PATTERNS):
            return SemanticClassification(SemanticRole.DECLINE, 0.8, ("checkable_decline",))
        return SemanticClassification(SemanticRole.ENABLE, 0.75, ("checkable_toggle",))

    # Pattern scoring
    if _match_any(text, _ACCEPT_PATTERNS):
        scores[SemanticRole.ACCEPT] += 0.55 + _score_patterns(text, _ACCEPT_PATTERNS)
        reasons.append("accept_pattern")
    if _match_any(text, _DECLINE_PATTERNS):
        scores[SemanticRole.DECLINE] += 0.55 + _score_patterns(text, _DECLINE_PATTERNS)
        reasons.append("decline_pattern")
    if _match_any(text, _CANCEL_PATTERNS):
        scores[SemanticRole.CANCEL] += 0.5 + _score_patterns(text, _CANCEL_PATTERNS)
        reasons.append("cancel_pattern")
    if _match_any(text, _DOWNLOAD_PATTERNS):
        scores[SemanticRole.DOWNLOAD] += 0.6
        scores[SemanticRole.ACCEPT] += 0.25
        reasons.append("download_pattern")
    if _match_any(text, _INSTALL_PATTERNS):
        scores[SemanticRole.INSTALL] += 0.65
        scores[SemanticRole.ACCEPT] += 0.3
        reasons.append("install_pattern")
    if _match_any(text, _ENABLE_PATTERNS):
        scores[SemanticRole.ENABLE] += 0.55
        scores[SemanticRole.ACCEPT] += 0.2
        reasons.append("enable_pattern")
    if _match_any(text, _PROGRESS_PATTERNS):
        scores[SemanticRole.PROGRESS] += 0.45
        scores[SemanticRole.ACCEPT] += 0.15
        reasons.append("progress_pattern")

    # Control-type heuristics
    if any(h in cls for h in _BUTTON_CLASS_HINTS):
        scores[SemanticRole.ACCEPT] += 0.1
        reasons.append("button_class")
    if "tab" in cls:
        return SemanticClassification(SemanticRole.NAVIGATE, 0.8, ("tab_control",))
    if "menu" in cls or "drawer" in cls:
        return SemanticClassification(SemanticRole.EXPAND, 0.75, ("menu_control",))

    # Contextual dialog hints — body text mentioning update/permission/install
    ctx = context_text.lower()
    if any(k in ctx for k in ("permission", "allow", "access", "grant")):
        if scores[SemanticRole.ACCEPT] >= scores[SemanticRole.DECLINE]:
            scores[SemanticRole.ACCEPT] += 0.15
            reasons.append("permission_context")
    if any(k in ctx for k in ("update", "version", "upgrade", "download")):
        scores[SemanticRole.INSTALL] += 0.1
        scores[SemanticRole.ACCEPT] += 0.1
        reasons.append("update_context")

    # Large clickable regions in lower half often primary CTAs in dialogs
    if bounds_area > 8000 and is_clickable:
        scores[SemanticRole.ACCEPT] += 0.05

    best_role = max(scores, key=lambda r: scores[r])
    best_score = scores[best_role]
    if best_score < 0.25:
        if is_clickable:
            return SemanticClassification(
                SemanticRole.PROGRESS, 0.4, ("clickable_unlabeled",)
            )
        return SemanticClassification(SemanticRole.UNKNOWN, 0.2, ("insufficient_signal",))

    confidence = min(0.99, 0.35 + best_score)
    return SemanticClassification(best_role, confidence, tuple(reasons))


def is_acceptance_role(role: SemanticRole) -> bool:
    return role in {
        SemanticRole.ACCEPT,
        SemanticRole.PROGRESS,
        SemanticRole.SUBMIT,
        SemanticRole.DOWNLOAD,
        SemanticRole.INSTALL,
        SemanticRole.ENABLE,
        SemanticRole.OPEN,
        SemanticRole.SELECT,
    }


def is_rejection_role(role: SemanticRole) -> bool:
    return role in {SemanticRole.DECLINE, SemanticRole.CANCEL, SemanticRole.DISABLE, SemanticRole.CLOSE}


#: Controls that END the process under analysis rather than navigating within
#: it. These are the system's own words, not the app's: Android renders them on
#: the ANR ("<app> isn't responding") and crash ("<app> keeps stopping")
#: dialogs, and on the Settings App-info page.
_SAMPLE_TERMINATING_LABELS: Tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.I) for p in (
        r"\bclose app\b",
        r"\bforce ?stop\b",
        r"\bforce close\b",
        r"\buninstall\b",
        r"\bclear (data|storage|cache)\b",
        r"\bapp info\b",
        r"\bquit\b",
    )
)

#: The ANR dialog's keep-alive control. Pressing it is how an analysis survives
#: an app that is merely slow - which, on an emulator running a Frida agent
#: that has just deoptimized the boot image, is the common case.
_ANR_WAIT_LABELS: Tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.I) for p in (r"^\s*wait\s*$", r"\bwait\b")
)


def terminates_sample(label: str) -> bool:
    """
    Whether tapping this control would kill the app being analysed.

    The explorer must never choose one. "Close app" on an ANR dialog scores
    like any other low-value control - it is a CANCEL, worth -20 - so once the
    dialog's other options had been tried it was the highest-ranked action left
    and got clicked. That ends the process under analysis: the remaining
    exploration budget is spent on a dead app, every runtime hook goes silent,
    and the run reports no behaviour for a sample that was mid-form.

    Matched on the label alone because these strings come from the Android
    framework, not from the sample, so they are stable across apps and are not
    attacker-controlled in the cases that matter.
    """
    return _match_any((label or "").strip(), _SAMPLE_TERMINATING_LABELS)


def is_anr_wait_control(label: str) -> bool:
    """Whether this control is the ANR dialog's "keep waiting" option."""
    return _match_any((label or "").strip(), _ANR_WAIT_LABELS)


def acceptance_priority_boost(role: SemanticRole) -> int:
    """Deterministic priority adjustment for simulated unsuspecting user."""
    if role == SemanticRole.ACCEPT:
        return 40
    if role in {SemanticRole.INSTALL, SemanticRole.DOWNLOAD, SemanticRole.ENABLE}:
        return 35
    if role in {SemanticRole.PROGRESS, SemanticRole.SUBMIT, SemanticRole.OPEN}:
        return 25
    if role == SemanticRole.INPUT:
        return 10
    if is_rejection_role(role):
        return -25
    return 0


def infer_affirmative_choice(
    candidates: Sequence[Any],
    *,
    context_text: str = "",
) -> Optional[Any]:
    """
    When the UI presents a decision, pick the application's intended affirmative
    option using semantic roles and generic pairwise heuristics.
    """
    if not candidates:
        return None

    scored: List[Tuple[float, Any]] = []
    for c in candidates:
        role = getattr(c, "semantic_role", SemanticRole.UNKNOWN)
        if isinstance(role, str):
            try:
                role = SemanticRole(role)
            except ValueError:
                role = SemanticRole.UNKNOWN
        conf = float(getattr(c, "confidence", 0.5) or 0.5)
        label = getattr(c, "label", "") or ""
        cls = classify_semantic_role(
            label=label,
            class_name=getattr(c, "class_name", ""),
            context_text=context_text,
            is_checkable=getattr(c, "is_checkable", False),
            is_clickable=getattr(c, "is_clickable", True),
            is_input=getattr(c, "is_input", False),
        )
        if role == SemanticRole.UNKNOWN:
            role = cls.role
        score = conf
        if is_acceptance_role(role):
            score += 0.5 + acceptance_priority_boost(role) / 100.0
        elif is_rejection_role(role):
            score -= 0.4
        scored.append((score, c))

    scored.sort(key=lambda t: t[0], reverse=True)
    best_score, best = scored[0]
    if best_score < 0.3:
        return None
    # Require separation from best rejection candidate
    reject_scores = [
        s for s, c in scored
        if is_rejection_role(
            SemanticRole(getattr(c, "semantic_role", SemanticRole.UNKNOWN))
            if isinstance(getattr(c, "semantic_role", ""), str)
            else getattr(c, "semantic_role", SemanticRole.UNKNOWN)
        )
    ]
    if reject_scores and best_score - max(reject_scores) < 0.05:
        # Tie-break: prefer lower on screen (primary CTA convention)
        acceptables = [
            c for s, c in scored
            if s >= best_score - 0.05 and is_acceptance_role(
                SemanticRole(getattr(c, "semantic_role", SemanticRole.UNKNOWN))
                if isinstance(getattr(c, "semantic_role", ""), str)
                else getattr(c, "semantic_role", SemanticRole.UNKNOWN)
            )
        ]
        if acceptables:
            return max(acceptables, key=lambda c: getattr(c, "center_y", 0))
    return best


def validate_coordinates_for_screen(
    x: int,
    y: int,
    *,
    screen_width: int,
    screen_height: int,
    bounds: str = "",
    package: str = "",
    expected_package: str = "",
) -> Tuple[bool, str]:
    """
    Reject stale, host, or out-of-bounds coordinates before execution.
    """
    if screen_width <= 0 or screen_height <= 0:
        return False, "invalid_screen_dimensions"
    if x < 0 or y < 0 or x > screen_width or y > screen_height:
        return False, f"out_of_bounds ({x},{y}) vs {screen_width}x{screen_height}"
    # Absurd coordinates often indicate host/desktop leakage
    if x > _MAX_DIMENSION or y > _MAX_DIMENSION:
        return False, "coordinates_exceed_maximum"
    if expected_package and package and package != expected_package:
        return False, f"package_mismatch expected={expected_package} got={package}"
    if bounds:
        m = re.match(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", bounds)
        if m:
            x1, y1, x2, y2 = map(int, m.groups())
            if not (x1 <= x <= x2 and y1 <= y <= y2):
                return False, f"coords_outside_bounds {bounds}"
    return True, "ok"


_MAX_DIMENSION = 8192
