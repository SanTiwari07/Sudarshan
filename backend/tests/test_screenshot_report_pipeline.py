"""Screenshot manifest paths must match report generator resolution."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[2] / "shared"))

from sudarshan_core.engines.report_generator import _load_screenshot_entries, build_report


def test_report_gallery_reads_canonical_manifest(tmp_path):
    shots_dir = tmp_path / "screenshots"
    shots_dir.mkdir()
    png = shots_dir / "001_1_test.png"
    png.write_bytes(b"\x89PNG\r\n\x1a\n" + b"x" * 64)

    manifest = {
        "screenshots": [{
            "screenshot_id": "SCR-001",
            "filename": "screenshots/001_1_test.png",
            "label": "test",
            "source": "lifecycle",
        }]
    }
    (shots_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    entries = _load_screenshot_entries(tmp_path, {})
    assert len(entries) == 1

    html = build_report({"package_name": "com.test", "final_risk_score": 1}, tmp_path)
    assert "Visual UI" in html
    assert "SCR-001" in html
    assert "data:image/png;base64," in html


def test_report_gallery_reads_legacy_screenshots_json(tmp_path):
    shots_dir = tmp_path / "screenshots"
    shots_dir.mkdir()
    png = shots_dir / "001_1_legacy.png"
    png.write_bytes(b"\x89PNG\r\n\x1a\n" + b"y" * 64)

    legacy = {
        "screenshots": [{
            "screenshot_id": "SCR-001",
            "filename": "screenshots/001_1_legacy.png",
            "label": "legacy",
        }]
    }
    (tmp_path / "screenshots.json").write_text(json.dumps(legacy), encoding="utf-8")

    entries = _load_screenshot_entries(tmp_path, {})
    assert len(entries) == 1
