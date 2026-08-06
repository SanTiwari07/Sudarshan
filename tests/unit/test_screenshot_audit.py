"""Screenshot validation must match report_generator base64 embedding."""

import base64
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

from sudarshan_core.engines.report_generator import build_report
from sudarshan_core.validation.screenshot_audit import validate_screenshots


def test_validator_accepts_base64_without_filename_in_html(tmp_path):
    shots = tmp_path / "screenshots"
    shots.mkdir()
    png = shots / "001_test.png"
    png_bytes = b"\x89PNG\r\n\x1a\n" + b"x" * 128
    png.write_bytes(png_bytes)

    manifest = {
        "screenshots": [{
            "screenshot_id": "SCR-001",
            "filename": "screenshots/001_test.png",
            "label": "test",
            "source": "lifecycle",
        }]
    }
    (shots / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    report = {"package_name": "com.test", "final_risk_score": 10, "risk_band": "Test"}
    html = build_report(report, apk_dir=tmp_path)
    assert "data:image/png;base64," in html
    assert "001_test.png" not in html

    results = validate_screenshots(tmp_path, report, html)
    assert len(results) == 1
    assert results[0].html_embedded is True
    assert results[0].errors == []


def test_validator_rejects_external_file_reference_only(tmp_path):
    shots = tmp_path / "screenshots"
    shots.mkdir()
    png = shots / "001_test.png"
    png.write_bytes(b"\x89PNG\r\n\x1a\n" + b"y" * 128)
    (shots / "manifest.json").write_text(
        json.dumps({
            "screenshots": [{
                "screenshot_id": "SCR-001",
                "filename": "screenshots/001_test.png",
                "label": "test",
            }]
        }),
        encoding="utf-8",
    )
    html = '<html><img src="screenshots/001_test.png" alt="SCR-001"/></html>'
    results = validate_screenshots(tmp_path, {}, html)
    assert results[0].in_html
    assert not results[0].html_embedded
    assert any("data URI" in e for e in results[0].errors)
