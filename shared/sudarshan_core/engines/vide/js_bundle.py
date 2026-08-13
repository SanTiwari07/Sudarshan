r"""Extract UI evidence from bundled JavaScript (Capacitor / React / Cordova).

A modern banking clone is usually a WebView app: the APK ships a Vite/webpack
bundle and ``res/layout`` contains nothing but the bridge activity. All of the
UI - every label the victim reads, every input they type into - is inside
``assets/public/assets/index-*.js``.

Two extraction quirks make a naive scan miss it entirely:

* Minifiers rewrite ``"Login"`` into a **template literal** ``` `Login` ```, so
  a scan for quoted strings finds nothing.
* JSX compiles to ``jsx(\`div\`, ...)`` calls, so element structure survives as
  call arguments rather than as markup.

Nesting is *not* recoverable from a minified bundle - call order does not
reliably encode the tree. This module therefore returns role composition (what
widgets exist, how many) and leaves depth to the HTML/UIAutomator builders,
which do see real structure.
"""

from __future__ import annotations

import re
from typing import Iterator, List, Optional, Set

from sudarshan_core.engines.vide.view_ast import (
    ROLE_CONTAINER,
    ViewNode,
    classify_html,
)
from sudarshan_core.engines.vide.ui_profile import UIProfile

_QUOTES = ("`", '"', "'")
# jsx(`div`, ...) / jsxs(`h1`, ...) / createElement("div", ...) and the minified
# sequence-expression form a bundler emits: (0,j.jsx)(`div`, ...) - note the
# `)` between the callee and its argument list.
_JSX_TAG_RE = re.compile(
    r"(?:jsxs?|createElement)\s*\)?\s*\(\s*[`\"']([a-z][a-z0-9]{0,9})[`\"']"
)

# UI text is human-readable prose, not code. These reject the bundle's own
# identifiers, module paths, MIME types and CSS fragments.
_CODEY = re.compile(
    r"(^[a-z]+[A-Z])"                 # camelCase identifier
    r"|[{}()\[\];<>$\\]"              # code punctuation
    r"|^[./#@]"                       # paths, selectors, at-rules
    r"|^\d+(px|rem|em|%|vh|vw|s|ms)$" # CSS dimensions
    r"|^(use|application|text)/"      # directives / MIME
    r"|^-{1,2}[a-z]"                  # CSS custom properties
    r"|^[A-Z_]{2,}$"                  # SCREAMING constants
    r"|^(https?|data|blob):"          # URLs
)
_HAS_LETTERS = re.compile(r"[A-Za-z]{2,}")
_MOSTLY_WORDS = re.compile(r"^[A-Za-z0-9 &?!.,'’()/₹%+-]{2,60}$")

_MAX_BUNDLE_BYTES = 4_000_000
_MAX_STRINGS = 160
_MAX_TAGS = 400


def _is_ui_string(value: str) -> bool:
    text = value.strip()
    if len(text) < 3 or len(text) > 60:
        return False
    if not _HAS_LETTERS.search(text):
        return False
    if not _MOSTLY_WORDS.match(text):
        return False
    if _CODEY.search(text):
        return False
    # Require a capital or a space: "Login", "Available Balance" pass;
    # bare lowercase tokens like "flex" or "column" do not.
    return text[0].isupper() or " " in text


def iter_string_literals(text: str) -> Iterator[str]:
    """
    Yield every JS string/template literal, keeping quote pairing aligned.

    A regex with a bounded body cannot do this: one template literal that is
    longer than the bound - or that contains a backslash escape - fails to
    match, its closing backtick is then read as an *opening* one, and every
    literal after it is mispaired. In a minified bundle that silently drops the
    entire application's UI text, because framework code (which contains the
    long literals) is bundled ahead of app code.
    """
    index = 0
    length = len(text)
    while index < length:
        quote = text[index]
        if quote not in _QUOTES:
            index += 1
            continue
        cursor = index + 1
        while cursor < length:
            char = text[cursor]
            if char == "\\":
                cursor += 2
                continue
            if char == quote:
                break
            # A plain quote never spans a line; a template literal may.
            if quote != "`" and char == "\n":
                break
            cursor += 1
        if cursor < length and text[cursor] == quote:
            yield text[index + 1 : cursor]
            index = cursor + 1
        else:
            index += 1


def extract_ui_strings(bundle: str) -> List[str]:
    """Human-readable UI labels from a minified JS bundle."""
    found: List[str] = []
    seen: Set[str] = set()
    for raw in iter_string_literals(bundle):
        if len(raw) > 60:
            continue
        text = raw.strip()
        if not _is_ui_string(text):
            continue
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        found.append(text)
        if len(found) >= _MAX_STRINGS:
            break
    return found


def extract_jsx_tags(bundle: str) -> List[str]:
    """HTML tag names from compiled JSX / createElement calls."""
    return [m.group(1).lower() for m in _JSX_TAG_RE.finditer(bundle)][:_MAX_TAGS]


def build_bundle_ast(bundle: str) -> Optional[ViewNode]:
    """
    Flat role composition for the bundle.

    Deliberately one level deep: minified call order does not encode nesting,
    and inventing a tree here would feed the structural comparer a shape the
    app does not actually have.
    """
    tags = extract_jsx_tags(bundle)
    if not tags:
        return None
    root = ViewNode(role=ROLE_CONTAINER, tag="bundle")
    for tag in tags:
        root.children.append(ViewNode(role=classify_html(tag), tag=tag))
    return root


def profile_from_js_bundle(bundle: str, source: str = "js_bundle") -> UIProfile:
    """UIProfile from a bundled JS file."""
    if not bundle:
        return UIProfile(source=source)
    text = bundle[:_MAX_BUNDLE_BYTES]
    tags = extract_jsx_tags(text)
    return UIProfile(
        source=source,
        strings=extract_ui_strings(text),
        view_sequence=tags,
        colors=[],  # handled by the stylesheet/colour pass
    )
