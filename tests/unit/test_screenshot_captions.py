"""Deterministic screenshot captions and the manifest -> PDF relay.

Covers B-1 (presentation fields on ScreenshotRecord), B-2 (REASON_TO_CAPTION
lookup) and the pdf_generator manifest-unwrap fix that makes both observable.
"""

import dataclasses
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

from sudarshan_core.engines.screenshot_manager import (
    REASON_TO_CAPTION,
    UNCLEAR_CAPTION,
    ScreenshotReason,
    ScreenshotRecord,
    build_caption,
)


# ── B-2: caption lookup ───────────────────────────────────────────────────────

def test_every_reason_enum_member_has_a_table_entry():
    """No ScreenshotReason may be missing from the table."""
    missing = [r.value for r in ScreenshotReason if r.value not in REASON_TO_CAPTION]
    assert missing == [], f"reasons absent from REASON_TO_CAPTION: {missing}"


def test_every_reason_yields_a_non_empty_caption():
    for reason in ScreenshotReason:
        caption = build_caption(
            reason.value,
            category="overlay",
            label="app_opened",
            explorer_action="tap",
        )
        assert caption, f"{reason.value} produced an empty caption"


def test_known_reason_renders_static_template():
    assert build_caption(ScreenshotReason.OVERLAY.value) == (
        "Overlay window displayed over target app"
    )


def test_template_placeholder_is_substituted():
    assert build_caption(
        ScreenshotReason.EXPLORER_ACTION.value, explorer_action="tap(Login)"
    ) == "Screen state after explorer action - tap(Login)"


def test_missing_placeholder_value_falls_back_to_unclear():
    """A template needing explorer_action must not emit a half-formed sentence."""
    assert build_caption(ScreenshotReason.EXPLORER_ACTION.value) == UNCLEAR_CAPTION


def test_unknown_reason_falls_back_to_unclear():
    assert build_caption("NOT_A_REAL_REASON") == UNCLEAR_CAPTION
    assert build_caption("") == UNCLEAR_CAPTION


def test_other_reason_is_honest_about_uncertainty():
    assert build_caption(ScreenshotReason.OTHER.value) == UNCLEAR_CAPTION


# ── B-1: presentation fields survive serialisation ────────────────────────────

def _record(**kw):
    base = dict(
        screenshot_id="SCR-001", filename="screenshots/001.png", label="overlay",
        trigger_event="", timestamp_ms=0, category="overlay", source="auto",
        gated=True,
    )
    base.update(kw)
    return ScreenshotRecord(**base)


def test_record_exposes_pdf_fields():
    rec = _record()
    for f in ("description", "capture_trigger", "title", "quality"):
        assert hasattr(rec, f), f"ScreenshotRecord missing {f}"


def test_asdict_carries_description_to_manifest():
    rec = _record(description="Overlay window displayed over target app",
                  capture_trigger="OVERLAY", title="SCR-001 - overlay")
    d = dataclasses.asdict(rec)
    assert d["description"] == "Overlay window displayed over target app"
    assert d["capture_trigger"] == "OVERLAY"
    assert d["title"] == "SCR-001 - overlay"


# ── Relay: pdf_generator must unwrap the dict manifest payload ────────────────

def test_pdf_build_report_data_reads_dict_manifest(tmp_path):
    """flush_manifest writes a dict; the PDF loader must not discard it."""
    from sudarshan_core.engines.pdf_generator import build_report_data

    shots = tmp_path / "screenshots"
    shots.mkdir()
    (shots / "manifest.json").write_text(json.dumps({
        "generated_at": "2026-01-01T00:00:00Z",
        "total_screenshots": 1,
        "screenshots": [{
            "screenshot_id": "SCR-001",
            "filename": "screenshots/001.png",
            "description": "Overlay window displayed over target app",
            "capture_trigger": "OVERLAY",
            "title": "SCR-001 - overlay",
        }],
    }), encoding="utf-8")

    data = build_report_data({"package_name": "com.test"}, apk_dir=tmp_path)
    assert len(data.screenshots) == 1
    scr = data.screenshots[0]
    assert isinstance(scr, dict), "manifest entries must reach the PDF as dicts"
    assert scr["description"] == "Overlay window displayed over target app"
    assert scr["capture_trigger"] == "OVERLAY"


# ── Relay: _collect_screenshots must not discard record metadata ──────────────

def test_collect_screenshots_returns_enriched_dicts():
    from sudarshan_core.engines.frida_sandbox import _collect_screenshots

    rec = _record(description="Overlay window displayed over target app",
                  capture_trigger="OVERLAY", title="SCR-001 - overlay")

    class _Mgr:
        def get_manifest(self):
            return [rec]

    class _Session:
        screenshot_manager = _Mgr()

    out = _collect_screenshots(_Session())
    assert len(out) == 1
    assert isinstance(out[0], dict), "records must reach the report as dicts"
    assert out[0]["description"] == "Overlay window displayed over target app"
    assert out[0]["filename"] == "screenshots/001.png"


def test_collect_screenshots_without_manager_yields_empty():
    from sudarshan_core.engines.frida_sandbox import _collect_screenshots

    class _Session:
        screenshot_manager = None

    assert _collect_screenshots(_Session()) == []


def test_collect_screenshots_never_raises_on_broken_manager():
    from sudarshan_core.engines.frida_sandbox import _collect_screenshots

    class _Mgr:
        def get_manifest(self):
            raise RuntimeError("manifest unreadable")

    class _Session:
        screenshot_manager = _Mgr()

    assert _collect_screenshots(_Session()) == []
