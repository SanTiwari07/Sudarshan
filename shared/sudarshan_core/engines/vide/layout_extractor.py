"""Extract a UIProfile from a decoded APK, from whichever source survives.

Three extraction paths, applied in order and merged, because no single one
covers the app shapes VIDE has to handle:

1. **Native resources** - ``res/layout/*.xml`` plus ``values/strings.xml`` and
   ``values/colors.xml``. The classic Android path.
2. **Web bundle** - ``assets/public/`` for a Capacitor/Cordova app, whose entire
   UI is an ``index.html`` plus a minified JS bundle and a CSS token file.
   ``res/layout`` in such an APK holds nothing but the bridge activity, so
   path 1 alone reports an app with no UI at all.
3. **DEX constant pool** - reached only when 1 and 2 come up empty, which is
   what a packed or obfuscated APK looks like. See :mod:`dex_strings`.

Path 3 is a fallback rather than an always-on source on purpose: the constant
pool of a normal app also holds library literals, and mixing those into a
profile that already has real UI text would dilute the string axis.
"""

from __future__ import annotations

import hashlib
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterable, List, Set, Tuple

from sudarshan_core.engines.vide.dex_strings import mine_from_decode_dir
from sudarshan_core.engines.vide.js_bundle import extract_ui_strings
from sudarshan_core.engines.vide.ui_profile import UIProfile

_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
_VIEW_TAGS = frozenset(
    {
        "LinearLayout",
        "RelativeLayout",
        "FrameLayout",
        "ConstraintLayout",
        "ScrollView",
        "TextView",
        "EditText",
        "Button",
        "MaterialButton",
        "TextInputEditText",
        "ImageView",
        "WebView",
        "androidx.constraintlayout.widget.ConstraintLayout",
    }
)
_STRING_REF = re.compile(r"@string/(\w+)")
_COLOR_HEX = re.compile(r"#[0-9A-Fa-f]{6,8}")
_BANKING_STRING_HINTS = re.compile(
    r"(upi|mpin|pin|otp|login|password|account|balance|transfer|ifsc|"
    r"customer\s*id|net\s*banking|yono|paytm|phonepe|gpay)",
    re.IGNORECASE,
)

# ── web bundle (Capacitor / Cordova / any WebView shell) ───────────────────

# Where a Capacitor build puts its web root, most specific first. ``assets/``
# itself is included so a Cordova-era or hand-rolled shell is still covered.
_WEB_ROOTS = ("assets/public", "assets/www", "assets")
# Framework shims: identical in every such app, so they add noise, not identity.
_BRIDGE_SCRIPTS = frozenset(
    {"cordova.js", "cordova_plugins.js", "native-bridge.js", "capacitor.js"}
)
_WEB_TEXT_SUFFIXES = (".html", ".htm", ".xhtml", ".js", ".css")
_MAX_WEB_FILES = 24
_MAX_WEB_BYTES = 4_000_000

_HTML_TAG = re.compile(r"<[^>]+>")
# Visible text a WebView renders that is not a text node: placeholders, labels
# and submit captions all read as UI copy to a victim.
_HTML_TEXT_ATTR = re.compile(
    r"\b(?:placeholder|title|alt|aria-label|value|label)\s*=\s*[\"']([^\"']{3,80})[\"']",
    re.IGNORECASE,
)
_WS = re.compile(r"\s+")

# ``--color-primary: #005A9C`` / ``background: rgb(0, 90, 156)``. The CSS token
# file is where a modern banking app actually declares its brand palette.
_CSS_HEX = re.compile(r"#[0-9A-Fa-f]{8}\b|#[0-9A-Fa-f]{6}\b|#[0-9A-Fa-f]{3}\b")
_CSS_RGB = re.compile(
    r"rgba?\(\s*(\d{1,3})\s*[, ]\s*(\d{1,3})\s*[, ]\s*(\d{1,3})", re.IGNORECASE
)


def _local_tag(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag


def _parse_strings_xml(path: Path) -> dict[str, str]:
    mapping: dict[str, str] = {}
    if not path.is_file():
        return mapping
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return mapping
    for child in root:
        if _local_tag(child.tag) != "string":
            continue
        name = child.attrib.get("name")
        if name and child.text:
            mapping[name] = child.text.strip()
    return mapping


def _parse_colors_xml(path: Path) -> List[str]:
    colors: List[str] = []
    if not path.is_file():
        return colors
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return colors
    for child in root:
        if _local_tag(child.tag) not in ("color", "item"):
            continue
        text = (child.text or "").strip()
        if text.startswith("#"):
            colors.append(text.lower())
    return colors


def _walk_layout(node: ET.Element, seq: List[str], strings: Set[str], string_table: dict[str, str]) -> None:
    tag = _local_tag(node.tag)
    if tag in _VIEW_TAGS or tag.endswith("Layout") or tag.endswith("View"):
        seq.append(tag)
    text = node.attrib.get(f"{_ANDROID_NS}text") or node.attrib.get("android:text")
    if text:
        if text.startswith("@string/"):
            key = text.split("/", 1)[-1]
            resolved = string_table.get(key, "")
            if resolved:
                strings.add(resolved)
        else:
            strings.add(text)
    hint = node.attrib.get(f"{_ANDROID_NS}hint") or node.attrib.get("android:hint")
    if hint and not hint.startswith("@"):
        strings.add(hint)
    content = node.attrib.get(f"{_ANDROID_NS}contentDescription")
    if content and not content.startswith("@"):
        strings.add(content)
    for child in node:
        _walk_layout(child, seq, strings, string_table)


def _expand_hex(digits: str) -> str:
    if len(digits) == 3:
        return "#" + "".join(c * 2 for c in digits)
    return "#" + digits[:6]


def extract_css_colors(text: str) -> List[str]:
    """Brand colours from a stylesheet or inline style blob, in source order.

    Declaration order is preserved because a token file leads with the brand
    colours and trails into state and neutral shades; sorting would throw that
    ranking away.
    """
    colors: List[str] = []
    for match in _CSS_HEX.finditer(text):
        colors.append(_expand_hex(match.group(0)[1:]).lower())
    for match in _CSS_RGB.finditer(text):
        try:
            rgb = [min(255, int(match.group(i))) for i in (1, 2, 3)]
        except ValueError:
            continue
        colors.append("#{:02x}{:02x}{:02x}".format(*rgb))
    return list(dict.fromkeys(colors))


def extract_html_strings(html: str) -> List[str]:
    """Rendered text and visible attribute copy from an HTML document."""
    found: List[str] = []
    seen: Set[str] = set()

    def _add(value: str) -> None:
        text = _WS.sub(" ", value).strip()
        if not (3 <= len(text) <= 80) or not re.search(r"[A-Za-z]{2,}", text):
            return
        key = text.lower()
        if key not in seen:
            seen.add(key)
            found.append(text)

    for match in _HTML_TEXT_ATTR.finditer(html):
        _add(match.group(1))
    for chunk in _HTML_TAG.split(html):
        _add(chunk)
    return found


def iter_web_asset_files(decode_dir: Path) -> Iterable[Tuple[Path, str]]:
    """Yield ``(path, kind)`` for each web-bundle file worth parsing.

    ``kind`` is one of ``html`` / ``js`` / ``css``. The first web root that
    exists wins, so a Capacitor app's ``assets/public`` is read without also
    re-reading the whole of ``assets``.
    """
    emitted = 0
    for relative in _WEB_ROOTS:
        root = decode_dir / Path(relative)
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            suffix = path.suffix.lower()
            if suffix not in _WEB_TEXT_SUFFIXES:
                continue
            if path.name.lower() in _BRIDGE_SCRIPTS:
                continue
            try:
                if path.stat().st_size > _MAX_WEB_BYTES:
                    continue
            except OSError:
                continue
            kind = "css" if suffix == ".css" else ("js" if suffix == ".js" else "html")
            yield path, kind
            emitted += 1
            if emitted >= _MAX_WEB_FILES:
                return
        return


def extract_web_bundle(decode_dir: Path) -> UIProfile:
    """
    UIProfile from a Capacitor/Cordova web bundle.

    Covers ``assets/public/index.html``, ``assets/public/assets/*.js`` and
    ``assets/public/assets/*.css`` - between them the complete UI of a hybrid
    banking app, none of which appears in ``res/``.
    """
    strings: List[str] = []
    colors: List[str] = []
    seen: Set[str] = set()

    def _add_strings(values: Iterable[str]) -> None:
        for value in values:
            key = value.strip().lower()
            if key and key not in seen:
                seen.add(key)
                strings.append(value.strip())

    for path, kind in iter_web_asset_files(decode_dir):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if kind == "html":
            _add_strings(extract_html_strings(text))
            colors.extend(extract_css_colors(text))
        elif kind == "js":
            # The bundle is minified: labels survive as string/template
            # literals, which needs the quote-aware scanner, not a regex.
            _add_strings(extract_ui_strings(text))
            colors.extend(extract_css_colors(text))
        else:
            colors.extend(extract_css_colors(text))

    return UIProfile(
        source="web_bundle",
        strings=strings[:150],
        view_sequence=[],
        colors=list(dict.fromkeys(colors))[:40],
    )


def extract_from_decode_dir(decode_dir: Path) -> UIProfile:
    """Build a UIProfile from an apktool output directory."""
    res = decode_dir / "res"
    values = res / "values"
    string_table = _parse_strings_xml(values / "strings.xml")
    for extra in res.glob("values-*/strings.xml"):
        string_table.update(_parse_strings_xml(extra))

    colors: List[str] = []
    colors.extend(_parse_colors_xml(values / "colors.xml"))
    for extra in res.glob("values-*/colors.xml"):
        colors.extend(_parse_colors_xml(extra))

    seq: List[str] = []
    strings: Set[str] = set(string_table.values())
    layout_dir = res / "layout"
    if layout_dir.is_dir():
        for layout_file in sorted(layout_dir.glob("*.xml"))[:40]:
            try:
                root = ET.parse(layout_file).getroot()
                _walk_layout(root, seq, strings, string_table)
            except ET.ParseError:
                continue

    # Banking-relevant strings from all res XML
    for xml_path in res.rglob("*.xml"):
        try:
            text = xml_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in _STRING_REF.findall(text):
            if m in string_table:
                strings.add(string_table[m])
        for m in _COLOR_HEX.findall(text):
            colors.append(m.lower())

    asset_hashes: List[str] = []
    for drawable in (res / "drawable", res / "drawable-hdpi", res / "mipmap-hdpi"):
        if not drawable.is_dir():
            continue
        for img in sorted(drawable.glob("*"))[:15]:
            if img.suffix.lower() in (".png", ".webp", ".jpg"):
                try:
                    digest = hashlib.sha256(img.read_bytes()).hexdigest()
                    asset_hashes.append(digest[:16])
                except OSError:
                    pass

    filtered_strings = sorted(
        s for s in strings if len(s) >= 3 and (_BANKING_STRING_HINTS.search(s) or len(s) <= 64)
    )[:120]

    # Ordered colour list: native `colors.xml` first (it is the app's own
    # declaration), then the web palette. `dict.fromkeys` keeps first-seen
    # order, which the brand comparer treats as significance ranking.
    native_colors = list(dict.fromkeys(c.lower() for c in colors))
    source = "apktool_layout"

    web = extract_web_bundle(decode_dir)
    if web.strings or web.colors:
        merged = list(dict.fromkeys(filtered_strings + web.strings))
        filtered_strings = merged[:150]
        native_colors = list(dict.fromkeys(native_colors + web.colors))
        source = "apktool_layout+web_bundle" if seq else "web_bundle"

    # Packed or obfuscated: nothing decoded, nothing bundled. The literals a
    # user reads are still in the DEX constant pool.
    if not filtered_strings:
        mined = mine_from_decode_dir(decode_dir)
        if mined:
            filtered_strings = mined[:150]
            source = "dex_constant_pool"

    return UIProfile(
        source=source,
        strings=filtered_strings,
        view_sequence=seq[:200],
        colors=native_colors[:40],
        asset_hashes=asset_hashes[:20],
    )
