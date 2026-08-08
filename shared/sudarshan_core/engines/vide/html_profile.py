"""Build UIProfile from HTML (assets or WebView dumps)."""

from __future__ import annotations

import re
from typing import List, Set

from sudarshan_core.engines.vide.ui_profile import UIProfile

_TAG_RE = re.compile(r"<(input|button|form|h1|h2|h3|label|select|textarea)\b", re.IGNORECASE)
_STRIP_TAGS = re.compile(r"<[^>]+>")
_COLOR_HEX = re.compile(r"#[0-9A-Fa-f]{6,8}")
_WS = re.compile(r"\s+")


def profile_from_html(html: str, source: str = "html") -> UIProfile:
    if not html or len(html) < 20:
        return UIProfile(source=source)

    tags: List[str] = [m.group(1).lower() for m in _TAG_RE.finditer(html)]
    strings: Set[str] = set()
    for phrase in re.split(r"<[^>]+>|\n", html):
        phrase = _WS.sub(" ", phrase).strip()
        if not phrase:
            continue
        if 3 <= len(phrase) <= 120:
            strings.add(phrase)
        for token in phrase.split():
            token = token.strip(".,;:!?\"'()")
            if 3 <= len(token) <= 80:
                strings.add(token)
    text_blob = _STRIP_TAGS.sub(" ", html)
    text_blob = _WS.sub(" ", text_blob).strip()
    for chunk in re.split(r"[.|\n]", text_blob):
        chunk = chunk.strip()
        if 3 <= len(chunk) <= 120:
            strings.add(chunk)
    colors = [c.lower() for c in _COLOR_HEX.findall(html)]

    return UIProfile(
        source=source,
        strings=sorted(strings)[:80],
        view_sequence=tags[:100],
        colors=sorted(set(colors))[:20],
    )
