"""
Optional Gemini Vision captioning for screenshots.

DISABLED BY DEFAULT. Enable with SUDARSHAN_VISION_CAPTIONS=1.

Scope. When the flag is on, EVERY capture is eligible by default - a run's
screenshots are the report's primary evidence, and a lifecycle frame labelled
"Application launched - initial screen state" tells an analyst nothing that the
word "launch" did not. This used to be restricted to AMBIGUOUS_REASONS, which
meant the three frames a login-gated sample actually produces - launch, state
discovery, session end - were the exact three the model never looked at. Set
SUDARSHAN_VISION_CAPTION_SCOPE=ambiguous to restore the narrow policy, and
SUDARSHAN_VISION_CAPTION_MAX to bound the calls a run may make.

Relationship to the UI-tree reading. This describes PIXELS; `ui_observation`
describes the HIERARCHY. The hierarchy reading always runs, needs no key and no
network, and is what fills `visual_observation` on an air-gapped deployment;
vision refines it when it is available. The hierarchy reading is also passed to
the model as grounding, so a caption is corrected by the image rather than
invented from nothing.

Design constraints:
  - Off by default. A run with the flag unset makes zero network calls and
    behaves exactly as before.
  - Never raises. Any failure (no key, no SDK, timeout, malformed reply)
    returns "" so the caller keeps its deterministic caption.
  - Honest about uncertainty. The prompt instructs the model to return
    UNCLEAR_CAPTION verbatim rather than guess at an ambiguous screen.
  - Never feeds the risk engine. Captions are presentation-only metadata.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

from sudarshan_core.engines.screenshot_manager import UNCLEAR_CAPTION

logger = logging.getLogger(__name__)

VISION_CAPTION_MODEL: str = (
    os.getenv("GEMINI_MODEL") or os.getenv("SUDARSHAN_AGENT_MODEL", "gemini-2.5-flash")
)

# Screenshot reasons whose deterministic caption carries no real signal. Still
# the eligible set under SCOPE_AMBIGUOUS; under the default scope every reason
# is eligible and this only decides which frames go first when a run hits its
# call budget.
AMBIGUOUS_REASONS = frozenset({"OTHER", "SUSPICIOUS_UI", "EXPLORER_ACTION"})

#: Caption every eligible capture (default when vision is enabled).
SCOPE_ALL = "all"
#: Legacy policy: only AMBIGUOUS_REASONS and captions the table gave up on.
SCOPE_AMBIGUOUS = "ambiguous"

#: Upper bound on vision calls per run. A long walk can produce a hundred
#: frames, and captioning all of them would add minutes of latency and cost to
#: a stage whose output is presentation metadata.
DEFAULT_CAPTION_BUDGET: int = 40

_MAX_CAPTION_CHARS = 200

_PROMPT = """You are labelling a screenshot taken from an Android app during \
automated malware analysis. Describe ONLY what is visibly on screen in one \
factual sentence of at most 25 words.

Rules:
- Describe what you see: the kind of screen, its input fields, its buttons, \
and any clearly legible heading or brand name.
- Do not speculate about intent, malice, or risk.
- Do not invent text, brand names, or UI elements you cannot clearly read.
- If the screen is blank, corrupted, or too ambiguous to describe, reply with \
exactly: {unclear}

Context hint (may be empty, and may be wrong - trust the image over the hint): {hint}"""


def caption_scope() -> str:
    """Which captures are eligible for a vision call."""
    raw = (os.getenv("SUDARSHAN_VISION_CAPTION_SCOPE", "") or SCOPE_ALL).strip().lower()
    return SCOPE_AMBIGUOUS if raw == SCOPE_AMBIGUOUS else SCOPE_ALL


def caption_budget() -> int:
    """Maximum vision calls this run may make. Zero disables captioning."""
    try:
        return max(0, int(os.getenv("SUDARSHAN_VISION_CAPTION_MAX", "")
                          or DEFAULT_CAPTION_BUDGET))
    except ValueError:
        return DEFAULT_CAPTION_BUDGET


def caption_priority(reason: str, current_caption: str) -> int:
    """
    Ordering for a budget-limited run. Lower goes first.

    A frame whose deterministic caption already gave up carries the least
    information, so it gains the most from a look at the pixels.
    """
    if current_caption == UNCLEAR_CAPTION:
        return 0
    if (reason or "") in AMBIGUOUS_REASONS:
        return 1
    return 2


def _image_part(img_bytes: bytes):
    """
    Wrap PNG bytes for the genai SDK.

    Falls back to the equivalent inline-data dict the SDK also accepts, so the
    module stays importable and testable where google-genai is not installed.
    """
    try:
        from google.genai import types
        return types.Part.from_bytes(data=img_bytes, mime_type="image/png")
    except Exception:
        return {"inline_data": {"mime_type": "image/png", "data": img_bytes}}


def vision_captions_enabled() -> bool:
    """True only when the operator has explicitly opted in."""
    return os.getenv("SUDARSHAN_VISION_CAPTIONS", "").lower() in ("1", "true", "yes")


def should_caption(reason: str, current_caption: str) -> bool:
    """
    Decide whether a screenshot warrants a vision call.

    Under the default scope every capture is eligible once the operator has
    turned vision captions on: a lifecycle frame is exactly as worth describing
    as an ambiguous one, and excluding it is what left the three frames a
    login-gated sample produces uncaptioned. SCOPE_AMBIGUOUS restores the old
    narrow policy for a deployment that wants to spend fewer calls.

    Always False with the feature flag unset - the no-network guarantee.
    """
    if not vision_captions_enabled():
        return False
    if caption_scope() == SCOPE_AMBIGUOUS:
        return reason in AMBIGUOUS_REASONS or current_caption == UNCLEAR_CAPTION
    return True


def generate_caption(
    image_path: str | Path,
    hint_context: str = "",
    client: Optional[object] = None,
) -> str:
    """
    Return a one-sentence caption for the screenshot, or "" if unavailable.

    A "" return means "keep whatever caption you already had" - it is never an
    error the caller must handle.
    """
    if not vision_captions_enabled():
        return ""

    path = Path(image_path)
    if not path.is_file():
        logger.debug("[Caption] No such screenshot: %s", path)
        return ""

    try:
        if client is None:
            from sudarshan_core.ai.gemini_provider import gemini_is_configured, get_gemini_manager
            if not gemini_is_configured():
                logger.debug("[Caption] SUDARSHAN_VISION_CAPTIONS set but no Gemini API key")
                return ""
            img_bytes = path.read_bytes()
            result = get_gemini_manager().generate_content(
                contents=[
                    _PROMPT.format(unclear=UNCLEAR_CAPTION, hint=hint_context or "(none)"),
                    _image_part(img_bytes),
                ],
            )
            text = (result.text or "").strip()
        else:
            img_bytes = path.read_bytes()
            resp = client.models.generate_content(
                model=VISION_CAPTION_MODEL,
                contents=[
                    _PROMPT.format(unclear=UNCLEAR_CAPTION, hint=hint_context or "(none)"),
                    _image_part(img_bytes),
                ],
            )
            text = (getattr(resp, "text", "") or "").strip()
        if not text:
            return ""
        # Collapse to a single line and bound the length; a model that ignores
        # the word limit must not blow out the PDF table cell.
        text = " ".join(text.split())
        return text[:_MAX_CAPTION_CHARS]

    except Exception as e:
        logger.warning(
            "[Caption] Vision captioning failed (%s: %s) - keeping deterministic caption",
            type(e).__name__, e,
        )
        return ""
