"""Build merged static UIProfile from apktool decode dir (before temp cleanup)."""

from __future__ import annotations

from pathlib import Path
from typing import Tuple

from sudarshan_core.engines.vide.html_profile import profile_from_html
from sudarshan_core.engines.vide.layout_extractor import extract_from_decode_dir
from sudarshan_core.engines.vide.pipeline import _merge_profiles, extract_html_from_assets
from sudarshan_core.engines.vide.ui_profile import UIProfile


def build_static_ui_profile(decode_dir: Path) -> Tuple[UIProfile, int]:
    """
    Layout + strings + colors + assets/*.html merged into one profile.
    Returns (profile, overlay_html_asset_count).
    """
    profile = extract_from_decode_dir(decode_dir)
    html_snippets = extract_html_from_assets(decode_dir)
    for html in html_snippets:
        profile = _merge_profiles(profile, profile_from_html(html, "assets_html"))
    if html_snippets:
        profile.source = "apktool_layout+assets_html"
    return profile, len(html_snippets)
