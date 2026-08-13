"""Build a normalised :class:`ViewNode` tree from each UI source VIDE sees.

Three sources, one vocabulary:

* Android layout XML  (Tier 2, apktool ``res/layout/*.xml``)
* UIAutomator dumps   (Tier 4, live screen hierarchy)
* HTML                (Capacitor/React assets and intercepted WebView overlays)

The banking baseline corpus is Capacitor-based, so its real UI lives in
``assets/public/*.html`` rather than ``res/layout`` - the HTML builder is the
primary path for that corpus, not a fallback.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from typing import List, Optional

from sudarshan_core.engines.vide.view_ast import (
    ROLE_CONTAINER,
    ROLE_OTHER,
    ViewNode,
    classify_android,
    classify_html,
)

_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
_VOID_HTML_TAGS = frozenset(
    {"area", "base", "br", "col", "embed", "hr", "img", "input", "link",
     "meta", "param", "source", "track", "wbr"}
)
_SKIP_HTML_TAGS = frozenset({"script", "style", "head", "meta", "link", "title"})

MAX_NODES = 1200


def _local_tag(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


# ── Android layout XML ─────────────────────────────────────────────────────


def build_from_layout_xml(
    root: ET.Element,
    string_table: Optional[dict] = None,
) -> ViewNode:
    """Android layout XML element -> role tree, resolving @string references."""
    table = string_table or {}
    budget = [MAX_NODES]

    def _text_of(element: ET.Element) -> str:
        for attr in (f"{_ANDROID_NS}text", "android:text", f"{_ANDROID_NS}hint", "android:hint"):
            value = element.attrib.get(attr)
            if not value:
                continue
            if value.startswith("@string/"):
                return table.get(value.split("/", 1)[-1], "")
            if not value.startswith("@"):
                return value
        return ""

    def _build(element: ET.Element) -> Optional[ViewNode]:
        if budget[0] <= 0:
            return None
        budget[0] -= 1
        tag = _local_tag(element.tag)
        # <include>/<merge> are structural directives, not widgets.
        role = ROLE_CONTAINER if tag in ("merge", "include") else classify_android(tag)
        node = ViewNode(role=role, tag=tag, text=_text_of(element))
        for child in element:
            built = _build(child)
            if built is None:
                break
            node.children.append(built)
        return node

    return _build(root) or ViewNode(role=ROLE_OTHER, tag=_local_tag(root.tag))


# ── UIAutomator dump ───────────────────────────────────────────────────────


def build_from_uiautomator(xml_text: str) -> Optional[ViewNode]:
    """UIAutomator ``dump`` XML -> role tree."""
    if not xml_text or not xml_text.strip():
        return None
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None

    budget = [MAX_NODES]

    def _build(element: ET.Element) -> Optional[ViewNode]:
        if budget[0] <= 0:
            return None
        budget[0] -= 1
        cls = element.attrib.get("class", "") or element.tag
        text = (
            element.attrib.get("text")
            or element.attrib.get("content-desc")
            or ""
        ).strip()
        node = ViewNode(role=classify_android(cls), tag=cls.rsplit(".", 1)[-1], text=text)
        for child in element:
            built = _build(child)
            if built is None:
                break
            node.children.append(built)
        return node

    built = _build(root)
    if built is None:
        return None
    # The <hierarchy> wrapper is noise; unwrap to the single real root.
    if built.tag == "hierarchy" and len(built.children) == 1:
        return built.children[0]
    return built


# ── HTML ───────────────────────────────────────────────────────────────────


class _HTMLTreeParser(HTMLParser):
    """Builds a role tree from HTML, tolerating unclosed tags."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.root = ViewNode(role=ROLE_CONTAINER, tag="document")
        self._stack: List[ViewNode] = [self.root]
        self._skip_depth = 0
        self._budget = MAX_NODES

    def handle_starttag(self, tag: str, attrs) -> None:
        if self._skip_depth or tag in _SKIP_HTML_TAGS:
            if tag in _SKIP_HTML_TAGS:
                self._skip_depth += 1
            return
        if self._budget <= 0:
            return
        self._budget -= 1

        attr_map = {k: (v or "") for k, v in attrs}
        # An <input placeholder="..."> carries its label in an attribute.
        text = attr_map.get("placeholder") or attr_map.get("aria-label") or ""
        node = ViewNode(role=classify_html(tag), tag=tag, text=text.strip())
        self._stack[-1].children.append(node)
        if tag not in _VOID_HTML_TAGS:
            self._stack.append(node)

    def handle_startendtag(self, tag: str, attrs) -> None:
        if self._skip_depth or self._budget <= 0:
            return
        self._budget -= 1
        attr_map = {k: (v or "") for k, v in attrs}
        text = attr_map.get("placeholder") or attr_map.get("aria-label") or ""
        self._stack[-1].children.append(
            ViewNode(role=classify_html(tag), tag=tag, text=text.strip())
        )

    def handle_endtag(self, tag: str) -> None:
        if tag in _SKIP_HTML_TAGS:
            self._skip_depth = max(0, self._skip_depth - 1)
            return
        if self._skip_depth or tag in _VOID_HTML_TAGS:
            return
        # Unwind to the matching open tag; ignore strays.
        for index in range(len(self._stack) - 1, 0, -1):
            if self._stack[index].tag == tag:
                del self._stack[index:]
                return

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        text = data.strip()
        if not text or len(self._stack) < 2:
            return
        current = self._stack[-1]
        if not current.text:
            current.text = text[:120]


def build_from_html(html: str) -> Optional[ViewNode]:
    """HTML (assets bundle or intercepted WebView payload) -> role tree."""
    if not html or len(html) < 20:
        return None
    parser = _HTMLTreeParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        # Malformed markup from a hostile sample must not break analysis.
        pass
    root = parser.root
    if not root.children:
        return None
    # Skip past document/html/body/root-div wrappers to the first subtree that
    # actually branches - otherwise every page shares a generic 3-node prefix.
    node = root
    while (
        len(node.children) == 1
        and node.tag in ("document", "html", "body", "div", "main")
        and node.children[0].children
    ):
        node = node.children[0]
    return node


def merge_forest(nodes: List[Optional[ViewNode]]) -> Optional[ViewNode]:
    """Combine per-screen trees under one synthetic root for whole-app compare."""
    real = [n for n in nodes if n is not None]
    if not real:
        return None
    if len(real) == 1:
        return real[0]
    return ViewNode(role=ROLE_CONTAINER, tag="app", children=real)
