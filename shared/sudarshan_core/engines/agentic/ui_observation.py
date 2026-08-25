"""
SUDARSHAN - Perceptual screen description
=========================================
Describe what is VISIBLY on a screen, from the screen itself.

Every screenshot description in the report used to be looked up by the REASON
the capture happened: `LIFECYCLE` -> "Lifecycle capture - 01_app_opened",
`SUSPICIOUS_UI` -> "Suspicious or unreadable UI state captured for vision
analysis". Those sentences are true of the capture and say nothing about the
picture, so an analyst reading the Screenshot Appendix saw the same handful of
templates repeated down the page and had to open every image to learn anything.

This module answers the other question - "what is on screen?" - from the UI
hierarchy that was dumped alongside the frame: the screen's classification, its
Activity, its input fields and their captions, its action controls, and the
headline text it is showing. That is a perceptual reading, not a claim: nothing
here decides whether a screen is malicious, and nothing here feeds the risk
engine. The investigative claim remains the linker's job (see
:mod:`sudarshan_core.visual_evidence.linker`), and keeping the two apart is what
stops the modal printing the same sentence twice.

It is also the FALLBACK for vision captioning. When Gemini is configured the
caption generator describes the pixels; when it is not - the common case, and
the only case on an air-gapped deployment - this module still produces a
specific, screen-derived sentence rather than a template.

Never raises: a malformed dump, a missing attribute or an empty node list all
degrade to a shorter sentence, never to an exception. A description is
presentation metadata, and no report should fail to render because a screen was
unreadable.
"""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

#: How many field captions / control captions are named before the sentence
#: switches to a count. Four fits a PDF table cell and a modal line.
MAX_LISTED_LABELS: int = 4

#: A caption longer than this is truncated. Long "labels" are usually a
#: paragraph of body text that happened to sit on a clickable container.
MAX_LABEL_CHARS: int = 32

#: Hard bound on the rendered sentence, for the same reason.
MAX_OBSERVATION_CHARS: int = 320

#: A control this large is the page, not a button on it. Mirrors
#: exploration_engine._FULLSCREEN_AREA_PX - a full-bleed clickable WebView is
#: the document, and naming it as a control describes nothing.
_FULLSCREEN_AREA_PX: int = 900_000

#: Human-readable names for ScreenType values. Kept here rather than on
#: ScreenType itself because these are presentation strings: they are read by
#: analysts, not matched by rules.
SCREEN_TYPE_LABELS: Dict[str, str] = {
    "BANK_LOGIN":           "Bank login screen",
    "OTP_SCREEN":           "OTP entry screen",
    "DATA_ENTRY_FORM":      "Data entry form",
    "ACCESSIBILITY_DIALOG": "Accessibility service dialog",
    "SYSTEM_PERMISSION":    "Runtime permission dialog",
    "OVERLAY_ATTACK":       "Overlay window",
    "HOME":                 "Application home screen",
    "HOME_LAUNCHER":        "Device launcher",
    "SETTINGS":             "Settings screen",
    "UPDATE_PROMPT":        "Update prompt",
    "VPN_REQUEST":          "VPN connection request",
    "EXTERNAL_APK":         "External APK install request",
    "DOWNLOAD_PROMPT":      "Download prompt",
    "PACKAGE_INSTALLER":    "Package installer screen",
    "DIALOG":               "Dialog",
    "WEBVIEW":              "WebView screen",
    "EXTERNAL_APP":         "Screen owned by another application",
    "CRASH_STATE":          "Application crash dialog",
    "APP_NOT_RESPONDING":   "Application-not-responding dialog",
    "TRANSITION":           "Screen in transition",
    "UNKNOWN":              "Application screen",
}

_DEFAULT_SCREEN_LABEL = "Application screen"

#: Classes that hold other views rather than being controls themselves.
_CONTAINER_CLASSES: Tuple[str, ...] = (
    "webview", "scrollview", "viewgroup", "framelayout", "linearlayout",
    "relativelayout", "recyclerview", "listview", "gridview",
    "constraintlayout", "coordinatorlayout", "nestedscrollview", "viewpager",
)

_BOUNDS_RE = re.compile(r"\[(-?\d+),(-?\d+)\]\[(-?\d+),(-?\d+)\]")


# ─── Widget view over a heterogeneous hierarchy ───────────────────────────────

@dataclass
class _Widget:
    """The few attributes a description actually needs, from any node shape."""
    text: str = ""
    desc: str = ""
    field_label: str = ""
    hint: str = ""
    resource_id: str = ""
    class_name: str = ""
    bounds: str = ""
    is_input: bool = False
    is_password: bool = False
    is_clickable: bool = False
    is_checkable: bool = False

    @property
    def area(self) -> int:
        m = _BOUNDS_RE.match(self.bounds or "")
        if not m:
            return 0
        x1, y1, x2, y2 = map(int, m.groups())
        return max(0, (x2 - x1) * (y2 - y1))

    @property
    def is_container(self) -> bool:
        cls = (self.class_name or "").lower()
        if not any(c in cls for c in _CONTAINER_CLASSES):
            return False
        return self.area >= _FULLSCREEN_AREA_PX

    def input_caption(self) -> str:
        """What this field is asking for, by the most reliable name available."""
        for candidate in (self.field_label, self.hint, self.desc, self.resource_id):
            cleaned = _clean_label(candidate)
            if cleaned:
                return cleaned
        return "Password" if self.is_password else ""

    def control_caption(self) -> str:
        for candidate in (self.text, self.desc, self.resource_id):
            cleaned = _clean_label(candidate)
            if cleaned:
                return cleaned
        return ""


def _clean_label(value: Any) -> str:
    """Collapse whitespace, drop placeholder ids, and bound the length."""
    text = " ".join(str(value or "").split()).strip()
    if not text:
        return ""
    # Positional node ids ("n0", "n17") name nothing.
    if re.fullmatch(r"n\d+", text, re.IGNORECASE):
        return ""
    # A masked value is the CONTENTS of a field, not its name.
    if set(text) <= {"•", "*", "·", "."} :
        return ""
    if len(text) > MAX_LABEL_CHARS:
        text = text[: MAX_LABEL_CHARS - 3].rstrip() + "..."
    return text


def _attr_bool(node: Any, *names: str) -> bool:
    for name in names:
        value = getattr(node, name, None)
        if value is None and isinstance(node, dict):
            value = node.get(name)
        if isinstance(value, bool):
            if value:
                return True
        elif isinstance(value, str) and value.lower() == "true":
            return True
    return False


def _attr_str(node: Any, *names: str) -> str:
    for name in names:
        value = getattr(node, name, None)
        if value is None and isinstance(node, dict):
            value = node.get(name)
        if value:
            return str(value)
    return ""


def _widgets_from_nodes(ui_nodes: Sequence[Any]) -> List[_Widget]:
    """Adapt parsed UINode objects (or plain dicts) to _Widget."""
    out: List[_Widget] = []
    for node in ui_nodes or []:
        class_name = _attr_str(node, "class_name", "class")
        is_input = _attr_bool(node, "is_input") or "edittext" in class_name.lower()
        out.append(_Widget(
            text=_attr_str(node, "text"),
            desc=_attr_str(node, "desc", "content_desc", "content-desc"),
            field_label=_attr_str(node, "field_label"),
            hint=_attr_str(node, "hint"),
            resource_id=_attr_str(node, "resource_id", "resource-id"),
            class_name=class_name,
            bounds=_attr_str(node, "bounds"),
            is_input=is_input,
            is_password=_attr_bool(node, "is_password", "password"),
            is_clickable=_attr_bool(node, "is_clickable", "clickable"),
            is_checkable=_attr_bool(node, "is_checkable", "checkable"),
        ))
    return out


def _widgets_from_xml(ui_xml: str) -> List[_Widget]:
    """
    Parse a uiautomator dump into _Widget records.

    Deliberately self-contained rather than reusing PerceptionPipeline's
    parser: this runs from the lifecycle capture path in frida_sandbox, where
    no perception pipeline exists, and from the linker, where nothing is on a
    device at all. It only needs the attributes a sentence is built from.
    """
    out: List[_Widget] = []
    if not ui_xml or "<" not in ui_xml:
        return out
    try:
        root = ET.fromstring(ui_xml)
    except ET.ParseError as exc:
        logger.debug("[UIObservation] Could not parse UI XML: %s", exc)
        return out

    # An input's caption is a separate node rendered just above it, so the last
    # text walked past in document order is that caption. Same rule perception
    # uses; without it a WebView login form has two unnamed boxes.
    pending_label = ""
    for elem in root.iter("node"):
        attrib = elem.attrib
        class_name = attrib.get("class", "") or ""
        text = (attrib.get("text", "") or "").strip()
        is_input = class_name == "android.widget.EditText" or "edittext" in class_name.lower()
        widget = _Widget(
            text=text,
            desc=(attrib.get("content-desc", "") or "").strip(),
            field_label=pending_label if is_input else "",
            hint=(attrib.get("hint", "") or "").strip(),
            resource_id=(attrib.get("resource-id", "") or "").split("/")[-1],
            class_name=class_name,
            bounds=attrib.get("bounds", "") or "",
            is_input=is_input,
            is_password=attrib.get("password") == "true",
            is_clickable=attrib.get("clickable") == "true",
            is_checkable=attrib.get("checkable") == "true",
        )
        out.append(widget)
        if text and not is_input:
            pending_label = text
    return out


# ─── Result ───────────────────────────────────────────────────────────────────

@dataclass
class ScreenObservation:
    """A perceptual reading of one screen. Presentation metadata only."""

    visual_observation: str = ""
    screen_summary: str = ""
    screen_type: str = ""
    activity: str = ""
    input_count: int = 0
    password_input_count: int = 0
    control_count: int = 0
    input_labels: List[str] = field(default_factory=list)
    control_labels: List[str] = field(default_factory=list)
    headline_texts: List[str] = field(default_factory=list)
    keyboard_visible: Optional[bool] = None
    source: str = "ui_tree"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def short_activity(activity: str) -> str:
    """`com.bank/com.bank.ui.LoginActivity` -> `LoginActivity`."""
    name = str(activity or "").strip()
    if not name:
        return ""
    if "/" in name:
        name = name.split("/", 1)[1]
    name = name.lstrip(".")
    if "." in name:
        name = name.rsplit(".", 1)[-1]
    return name


def screen_type_label(screen_type: str) -> str:
    """Human-readable name for a ScreenType value."""
    key = str(screen_type or "").strip().upper()
    return SCREEN_TYPE_LABELS.get(key, _DEFAULT_SCREEN_LABEL)


def _dedupe(labels: Sequence[str]) -> List[str]:
    seen: set = set()
    out: List[str] = []
    for label in labels:
        key = label.lower()
        if not label or key in seen:
            continue
        seen.add(key)
        out.append(label)
    return out


def _join_labels(labels: Sequence[str]) -> str:
    shown = list(labels[:MAX_LISTED_LABELS])
    extra = len(labels) - len(shown)
    joined = ", ".join(shown)
    if extra > 0:
        joined = f"{joined}, +{extra} more"
    return joined


def _plural(count: int, singular: str, plural: str = "") -> str:
    word = singular if count == 1 else (plural or f"{singular}s")
    return f"{count} {word}"


def describe_screen(
    *,
    activity: str = "",
    ui_nodes: Optional[Sequence[Any]] = None,
    ui_xml: str = "",
    screen_type: str = "",
    keyboard_visible: Optional[bool] = None,
    app_label: str = "",
) -> ScreenObservation:
    """
    Read a screen and describe what is on it.

    `ui_nodes` (already parsed, as the explorer holds them) is preferred;
    `ui_xml` is parsed when only the raw dump is available, as on the lifecycle
    capture path. Supplying neither still yields a description built from the
    Activity and the screen classification - shorter, but still specific to
    this screen rather than to the reason it was captured.
    """
    widgets: List[_Widget] = []
    source = "metadata"
    if ui_nodes:
        widgets = _widgets_from_nodes(ui_nodes)
        source = "ui_tree"
    elif ui_xml:
        widgets = _widgets_from_xml(ui_xml)
        source = "ui_xml"

    inputs = [w for w in widgets if w.is_input]
    controls = [
        w for w in widgets
        if not w.is_input and (w.is_clickable or w.is_checkable) and not w.is_container
    ]

    input_labels = _dedupe([w.input_caption() for w in inputs])
    control_labels = _dedupe([w.control_caption() for w in controls])

    # Headline text: prominent static captions that are not themselves controls
    # and not the caption of a field. This is what makes "YONO SBI" appear in
    # the sentence instead of a generic "login screen".
    named_elsewhere = {label.lower() for label in input_labels + control_labels}
    headlines = _dedupe([
        _clean_label(w.text)
        for w in widgets
        if not w.is_input
        and not w.is_clickable
        and not w.is_checkable
        and _clean_label(w.text)
        and _clean_label(w.text).lower() not in named_elsewhere
    ])[:2]

    activity_short = short_activity(activity)
    type_label = screen_type_label(screen_type)
    app_name = _clean_label(app_label)

    summary_parts = [type_label]
    if app_name:
        summary_parts.append(f"of {app_name}")
    if activity_short:
        summary_parts.append(f"({activity_short})")
    screen_summary = " ".join(summary_parts)

    observation = _render_observation(
        screen_summary=screen_summary,
        input_labels=input_labels,
        control_labels=control_labels,
        headlines=headlines,
        input_count=len(inputs),
        control_count=len(controls),
        keyboard_visible=keyboard_visible,
        had_hierarchy=bool(widgets) or source != "metadata",
    )

    return ScreenObservation(
        visual_observation=observation,
        screen_summary=screen_summary,
        screen_type=str(screen_type or ""),
        activity=str(activity or ""),
        input_count=len(inputs),
        password_input_count=sum(1 for w in inputs if w.is_password),
        control_count=len(controls),
        input_labels=input_labels[:MAX_LISTED_LABELS],
        control_labels=control_labels[:MAX_LISTED_LABELS],
        headline_texts=headlines,
        keyboard_visible=keyboard_visible,
        source=source,
    )


def _render_observation(
    *,
    screen_summary: str,
    input_labels: Sequence[str],
    control_labels: Sequence[str],
    headlines: Sequence[str],
    input_count: int,
    control_count: int,
    keyboard_visible: Optional[bool],
    had_hierarchy: bool,
) -> str:
    clauses: List[str] = []

    if input_count:
        clause = _plural(input_count, "input field")
        if input_labels:
            clause += f" ({_join_labels(input_labels)})"
        clauses.append(clause)

    if control_count:
        clause = _plural(control_count, "action control")
        if control_labels:
            clause += f" ({_join_labels(control_labels)})"
        clauses.append(clause)

    sentence = screen_summary
    if clauses:
        sentence += " showing " + " and ".join(clauses)
    elif had_hierarchy:
        sentence += " with no readable interactive elements"
    else:
        # No hierarchy was captured alongside this frame. Say that plainly
        # rather than describing a screen we did not read.
        sentence += "; UI hierarchy not captured with this frame"

    if headlines:
        quoted = ", ".join(f'"{h}"' for h in headlines)
        sentence += f". On-screen text: {quoted}"

    sentence += "."

    if keyboard_visible is True:
        sentence += " Software keyboard active."
    elif keyboard_visible is False and input_count:
        sentence += " Software keyboard not shown."

    sentence = " ".join(sentence.split())
    if len(sentence) > MAX_OBSERVATION_CHARS:
        sentence = sentence[: MAX_OBSERVATION_CHARS - 3].rstrip() + "..."
    return sentence


def describe_from_metadata(
    *,
    activity: str = "",
    screen_type: str = "",
    label: str = "",
    reason: str = "",
    explorer_action: str = "",
) -> str:
    """
    Last-resort description for a frame whose hierarchy was never recorded.

    Used by the visual-evidence linker for manifest rows written before this
    module existed, and for captures taken by paths that hold no UI dump. It is
    still screen-specific - the Activity and the classification come from the
    frame itself - and it deliberately does NOT restate the capture reason as
    if it were an observation.
    """
    obs = describe_screen(activity=activity, screen_type=screen_type)
    sentence = obs.visual_observation
    context = _clean_label(explorer_action) or _clean_label(label)
    if context:
        sentence = sentence.rstrip(".") + f". Captured at: {context}."
    return sentence
