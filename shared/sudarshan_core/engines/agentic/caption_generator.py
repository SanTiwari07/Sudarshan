"""
Optional Gemini Vision captioning for screenshots the lookup table cannot label.

DISABLED BY DEFAULT. Enable with SUDARSHAN_VISION_CAPTIONS=1.

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

# Screenshot reasons whose deterministic caption carries no real signal and are
# therefore worth spending a vision call on.
AMBIGUOUS_REASONS = frozenset({"OTHER", "SUSPICIOUS_UI", "EXPLORER_ACTION"})

_MAX_CAPTION_CHARS = 200

_PROMPT = """You are labelling a screenshot taken from an Android app during \
automated malware analysis. Describe ONLY what is visibly on screen in one \
factual sentence of at most 20 words.

Rules:
- Describe what you see. Do not speculate about intent, malice, or risk.
- Do not invent text, brand names, or UI elements you cannot clearly read.
- If the screen is blank, corrupted, or too ambiguous to describe, reply with \
exactly: {unclear}

Context hint (may be empty, and may be wrong - trust the image over the hint): {hint}"""


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

    Only ambiguous reasons, or ones the lookup table already gave up on,
    are eligible - and only when the feature flag is on.
    """
    if not vision_captions_enabled():
        return False
    return reason in AMBIGUOUS_REASONS or current_caption == UNCLEAR_CAPTION


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
            api_key = os.getenv("GEMINI_API_KEY")
            if not api_key:
                logger.debug("[Caption] SUDARSHAN_VISION_CAPTIONS set but no GEMINI_API_KEY")
                return ""
            from google import genai
            client = genai.Client(api_key=api_key)

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
