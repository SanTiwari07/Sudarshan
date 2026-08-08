"""Extract UIProfile from apktool-decompiled APK resources."""

from __future__ import annotations

import hashlib
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Set

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

    return UIProfile(
        source="apktool_layout",
        strings=filtered_strings,
        view_sequence=seq[:200],
        colors=sorted(set(colors))[:30],
        asset_hashes=asset_hashes[:20],
    )
