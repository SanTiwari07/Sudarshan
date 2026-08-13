"""View-hierarchy AST for VIDE structural comparison.

The original extractor flattened a layout into a list of tag names, which loses
nesting entirely: a login form and a settings page with the same widget counts
produced the same signature. This module keeps the tree, normalises it to a
role vocabulary that is comparable across Android XML, UIAutomator dumps and
WebView HTML, and scores structural similarity over that shared vocabulary.

Roles matter because a suspect app is rarely built with the same toolkit as the
baseline. A Capacitor clone renders ``<input>`` where a native app declares
``EditText``; both are the role ``INPUT``, and only the role comparison sees
that they are the same screen.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Any, Dict, Iterable, List, Optional, Sequence

# ── role vocabulary ────────────────────────────────────────────────────────

ROLE_CONTAINER = "CONTAINER"
ROLE_TEXT = "TEXT"
ROLE_INPUT = "INPUT"
ROLE_BUTTON = "BUTTON"
ROLE_IMAGE = "IMAGE"
ROLE_LIST = "LIST"
ROLE_WEBVIEW = "WEBVIEW"
ROLE_NAV = "NAV"
ROLE_OTHER = "OTHER"

_ANDROID_ROLES = (
    (ROLE_INPUT, ("edittext", "textinputedittext", "autocompletetextview", "searchview")),
    (ROLE_BUTTON, ("button", "imagebutton", "materialbutton", "floatingactionbutton", "chip")),
    (ROLE_LIST, ("recyclerview", "listview", "gridview", "viewpager", "viewpager2")),
    (ROLE_NAV, ("bottomnavigationview", "navigationview", "tablayout", "toolbar", "actionbar")),
    (ROLE_WEBVIEW, ("webview",)),
    (ROLE_IMAGE, ("imageview", "shapeableimageview", "circleimageview")),
    (ROLE_TEXT, ("textview", "materialtextview", "checkedtextview")),
    (ROLE_CONTAINER, (
        "linearlayout", "relativelayout", "framelayout", "constraintlayout",
        "scrollview", "nestedscrollview", "cardview", "materialcardview",
        "coordinatorlayout", "tablerow", "tablelayout", "flexboxlayout",
        "appbarlayout", "collapsingtoolbarlayout", "swiperefreshlayout",
    )),
)

_HTML_ROLES = {
    "input": ROLE_INPUT,
    "textarea": ROLE_INPUT,
    "select": ROLE_INPUT,
    "button": ROLE_BUTTON,
    "a": ROLE_BUTTON,
    "img": ROLE_IMAGE,
    "svg": ROLE_IMAGE,
    "ul": ROLE_LIST,
    "ol": ROLE_LIST,
    "table": ROLE_LIST,
    "nav": ROLE_NAV,
    "header": ROLE_NAV,
    "footer": ROLE_NAV,
    "iframe": ROLE_WEBVIEW,
    "html": ROLE_CONTAINER,
    "body": ROLE_CONTAINER,
    "form": ROLE_CONTAINER,
    "div": ROLE_CONTAINER,
    "section": ROLE_CONTAINER,
    "main": ROLE_CONTAINER,
    "article": ROLE_CONTAINER,
    "span": ROLE_TEXT,
    "p": ROLE_TEXT,
    "label": ROLE_TEXT,
    "h1": ROLE_TEXT,
    "h2": ROLE_TEXT,
    "h3": ROLE_TEXT,
    "h4": ROLE_TEXT,
    "h5": ROLE_TEXT,
    "h6": ROLE_TEXT,
    "li": ROLE_TEXT,
}


def classify_android(tag: str) -> str:
    """Map an Android view class name to a toolkit-independent role."""
    short = tag.rsplit(".", 1)[-1].lower()
    for role, needles in _ANDROID_ROLES:
        if short in needles:
            return role
    # Fall back to suffix shape for vendor/custom widgets.
    if short.endswith("layout") or short.endswith("group"):
        return ROLE_CONTAINER
    if short.endswith("button"):
        return ROLE_BUTTON
    if short.endswith("edittext"):
        return ROLE_INPUT
    if short.endswith("textview"):
        return ROLE_TEXT
    if short.endswith("imageview"):
        return ROLE_IMAGE
    if short.endswith("view"):
        return ROLE_OTHER
    return ROLE_OTHER


def classify_html(tag: str) -> str:
    return _HTML_ROLES.get(tag.strip().lower(), ROLE_OTHER)


# ── tree ───────────────────────────────────────────────────────────────────


@dataclass
class ViewNode:
    """One node of a normalised view hierarchy."""

    role: str
    tag: str = ""
    text: str = ""
    children: List["ViewNode"] = field(default_factory=list)

    def walk(self) -> Iterable["ViewNode"]:
        yield self
        for child in self.children:
            yield from child.walk()

    def depth(self) -> int:
        if not self.children:
            return 1
        return 1 + max(child.depth() for child in self.children)

    def count(self) -> int:
        return sum(1 for _ in self.walk())

    def role_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for node in self.walk():
            counts[node.role] = counts.get(node.role, 0) + 1
        return counts

    def to_dict(self, max_nodes: int = 400) -> Dict[str, Any]:
        """Serialise for the frontend diff viewer (bounded)."""
        budget = [max_nodes]

        def _emit(node: "ViewNode") -> Optional[Dict[str, Any]]:
            if budget[0] <= 0:
                return None
            budget[0] -= 1
            out: Dict[str, Any] = {"role": node.role, "tag": node.tag}
            if node.text:
                out["text"] = node.text[:80]
            kids = []
            for child in node.children:
                emitted = _emit(child)
                if emitted is None:
                    break
                kids.append(emitted)
            if kids:
                out["children"] = kids
            return out

        return _emit(self) or {"role": self.role, "tag": self.tag}


def skeleton(node: ViewNode, max_depth: int = 6) -> str:
    """
    Parenthesised role skeleton, e.g. ``CONTAINER(TEXT,INPUT,INPUT,BUTTON)``.

    This is the string the structural similarity is computed over; it encodes
    nesting, which a flat tag list cannot.
    """
    def _render(current: ViewNode, depth: int) -> str:
        if depth >= max_depth or not current.children:
            return current.role
        inner = ",".join(_render(c, depth + 1) for c in current.children)
        return f"{current.role}({inner})"

    return _render(node, 0)


# Containers and loose text exist in every screen ever built, so counting them
# equally with inputs and buttons makes a settings page look like a login form.
# Weights are discriminative power, not importance.
_ROLE_WEIGHTS = {
    ROLE_INPUT: 3.0,
    ROLE_BUTTON: 2.0,
    ROLE_LIST: 2.0,
    ROLE_NAV: 2.0,
    ROLE_WEBVIEW: 2.0,
    ROLE_IMAGE: 1.0,
    ROLE_TEXT: 0.5,
    ROLE_CONTAINER: 0.3,
    ROLE_OTHER: 0.2,
}


def tree_similarity(a: Optional[ViewNode], b: Optional[ViewNode]) -> float:
    """
    Structural isomorphism score in [0, 1].

    Blends skeleton edit-similarity (nesting-sensitive) with a role-histogram
    cosine weighted by discriminative power, so neither reordering nor a single
    inserted wrapper collapses the score - while two screens that merely share
    generic containers do not score as similar.
    """
    if a is None or b is None:
        return 0.0
    if not a.children and not b.children:
        return 1.0 if a.role == b.role else 0.0

    skeleton_score = SequenceMatcher(
        None, skeleton(a)[:4000], skeleton(b)[:4000]
    ).ratio()

    counts_a, counts_b = a.role_counts(), b.role_counts()
    roles = set(counts_a) | set(counts_b)

    def _vec(counts: Dict[str, int]) -> Dict[str, float]:
        return {r: counts.get(r, 0) * _ROLE_WEIGHTS.get(r, 0.2) for r in roles}

    vec_a, vec_b = _vec(counts_a), _vec(counts_b)
    dot = sum(vec_a[r] * vec_b[r] for r in roles)
    norm_a = sum(v * v for v in vec_a.values()) ** 0.5
    norm_b = sum(v * v for v in vec_b.values()) ** 0.5
    histogram_score = dot / (norm_a * norm_b) if norm_a and norm_b else 0.0

    return 0.45 * skeleton_score + 0.55 * histogram_score


# ── structural signatures ──────────────────────────────────────────────────

SIG_AUTH_FORM = "AUTH_FORM_VERTICAL_PRIMARY_CTA"
SIG_PINPAD = "PINPAD_NUMERIC_ENTRY"
SIG_DASHBOARD = "DASHBOARD_CARD_GRID_QUICKACTIONS"

_AUTH_HINTS = re.compile(
    r"(user\s*id|customer\s*id|password|ipin|login|sign\s*in|forgot)", re.IGNORECASE
)
_PIN_HINTS = re.compile(r"(mpin|\bpin\b|passcode|otp|6-digit|six digit)", re.IGNORECASE)
# "Forgot MPIN?" on a login screen is a link, not a PIN pad. Only an explicit
# entry prompt is strong enough to claim a pinpad without a numeric keypad.
_PIN_ENTRY_HINTS = re.compile(
    r"(enter\s+\d?\s*-?\s*digit|enter\s+(m?pin|passcode)|\d\s*-\s*digit\s+(m?pin|otp))",
    re.IGNORECASE,
)
_DASH_HINTS = re.compile(
    r"(balance|quick\s*transfer|pay\s*bills|recent\s*activity|accounts?|transactions?)",
    re.IGNORECASE,
)
_DIGIT_ONLY = re.compile(r"^\d$")


def infer_structural_signatures(
    root: Optional[ViewNode],
    strings: Sequence[str],
) -> List[str]:
    """
    Which corpus structural signatures this screen matches.

    Uses widget shape first and text only as corroboration, so an app that
    localises its labels still matches on structure.
    """
    found: List[str] = []
    blob = " ".join(strings)[:8000]
    counts = root.role_counts() if root else {}
    inputs = counts.get(ROLE_INPUT, 0)
    buttons = counts.get(ROLE_BUTTON, 0)

    digit_buttons = 0
    if root:
        for node in root.walk():
            if node.role == ROLE_BUTTON and _DIGIT_ONLY.match(node.text.strip()):
                digit_buttons += 1

    if (inputs >= 2 and buttons >= 1) or (_AUTH_HINTS.search(blob) and inputs >= 1):
        found.append(SIG_AUTH_FORM)
    # A pinpad needs either a real numeric keypad, or an explicit entry prompt
    # on a screen that is not already a multi-field credential form.
    if digit_buttons >= 9 or (
        digit_buttons >= 6 and _PIN_HINTS.search(blob)
    ) or (
        _PIN_ENTRY_HINTS.search(blob) and inputs <= 1
    ):
        found.append(SIG_PINPAD)
    if _DASH_HINTS.search(blob) and (
        counts.get(ROLE_LIST, 0) >= 1 or counts.get(ROLE_NAV, 0) >= 1 or buttons >= 4
    ):
        found.append(SIG_DASHBOARD)

    return found


def signature_overlap(suspect: Sequence[str], baseline: Sequence[str]) -> float:
    """Fraction of the baseline's screen signatures the suspect reproduces."""
    if not baseline:
        return 0.0
    base = {s for s in baseline if s}
    if not base:
        return 0.0
    return len(base & {s for s in suspect if s}) / len(base)


def signature_score(suspect: Sequence[str], baseline: Sequence[str]) -> float:
    """
    Structural agreement balancing coverage against precision.

    Coverage alone under-scores a real finding: a statically analysed sample
    often only exposes its login screen, so it can never match all three of a
    baseline's screen signatures no matter how exactly it copies that one.
    Precision alone over-scores, since every banking app has an auth form.
    Averaging the two credits an exact partial clone without rewarding an app
    that merely happens to contain a login form.
    """
    base = {s for s in baseline if s}
    susp = {s for s in suspect if s}
    if not base or not susp:
        return 0.0
    matched = len(base & susp)
    if not matched:
        return 0.0
    coverage = matched / len(base)
    precision = matched / len(susp)
    return 0.5 * coverage + 0.5 * precision
