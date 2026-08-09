"""Phase 3 visual evidence: causal linkage, enrichment, idempotency."""

import json
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "shared"))

from sudarshan_core.visual_evidence.constants import (
    CLAIM_ANTI_ANALYSIS_UI,
    CLAIM_OVERLAY_OBSERVED,
    CLAIM_VISUAL_IMPERSONATION,
    CORRELATION_CAUSAL,
    CORRELATION_LINKED,
    CORRELATION_NOT_APPLICABLE,
    CORRELATION_TEMPORAL,
    CORRELATION_UNRESOLVED,
    QUALITY_B,
)
from sudarshan_core.visual_evidence.enrich import enrich_visual_evidence_artifact
from sudarshan_core.visual_evidence.linker import VisualEvidenceLinker, write_visual_evidence_artifact
from sudarshan_core.visual_evidence.static_sources import load_static_flags_from_artifact


FIXTURE_ROOT = (
    Path(__file__).resolve().parents[2]
    / "tests"
    / "apks"
    / "categories"
    / "sudarshan_artifacts"
    / "insecurebankv2_2ebde24e"
)


def _png(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"\x89PNG\r\n\x1a\n" + b"y" * 40)


def test_causal_priority_over_temporal_and_hash(tmp_path):
    evid_uuid = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    png = "screenshots/s.png"
    _png(tmp_path / png)
    (tmp_path / "screenshots" / "manifest.json").write_text(
        json.dumps({
            "screenshots": [{
                "screenshot_id": "SCR-001",
                "filename": png,
                "timestamp_ms": 50_000,
                "trigger_event": evid_uuid,
                "screen_hash": "hash_a",
                "reason": "OVERLAY",
            }]
        }),
        encoding="utf-8",
    )
    (tmp_path / "evidence.json").write_text(
        json.dumps({
            "records": [
                {
                    "id": evid_uuid,
                    "finding_id": "EVID-001",
                    "timestamp_ms": 1_000,
                    "category": "overlay",
                    "severity": "CRITICAL",
                    "api": "WindowManager.addView",
                    "extra": {"screen_hash": "hash_b"},
                },
                {
                    "id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                    "finding_id": "EVID-002",
                    "timestamp_ms": 49_900,
                    "category": "overlay",
                    "severity": "CRITICAL",
                    "api": "WindowManager.addView",
                    "extra": {"screen_hash": "hash_a"},
                },
            ]
        }),
        encoding="utf-8",
    )
    rec = VisualEvidenceLinker(tmp_path).link()[0]
    assert rec.correlation_status == CORRELATION_CAUSAL
    assert rec.linked_evidence_ids[0] == "EVID-001"


def test_hash_fallback_when_no_causal(tmp_path):
    png = "screenshots/h.png"
    _png(tmp_path / png)
    (tmp_path / "screenshots" / "manifest.json").write_text(
        json.dumps({
            "screenshots": [{
                "screenshot_id": "SCR-001",
                "filename": png,
                "timestamp_ms": 10_000,
                "screen_hash": "same_hash",
                "reason": "OVERLAY",
            }]
        }),
        encoding="utf-8",
    )
    (tmp_path / "evidence.json").write_text(
        json.dumps({
            "records": [{
                "finding_id": "EVID-001",
                "timestamp_ms": 99_000,
                "category": "overlay",
                "severity": "HIGH",
                "api": "WindowManager.addView",
                "extra": {"screen_hash": "same_hash"},
            }]
        }),
        encoding="utf-8",
    )
    rec = VisualEvidenceLinker(tmp_path).link()[0]
    assert rec.correlation_status == CORRELATION_LINKED
    assert "EVID-001" in rec.linked_evidence_ids


def test_static_flags_from_investigation_manifest(tmp_path):
    (tmp_path / "manifest.json").write_text(
        json.dumps({
            "sha256": "abc",
            "package_name": "com.test",
            "capability_flags": {
                "has_accessibility_abuse": True,
                "targets_indian_banks": True,
            },
        }),
        encoding="utf-8",
    )
    flags = load_static_flags_from_artifact(tmp_path)
    assert flags["has_accessibility_abuse"] is True
    assert flags["targets_indian_banks"] is True


def test_vide_post_enrichment(tmp_path):
    png = "screenshots/v.png"
    _png(tmp_path / png)
    (tmp_path / "screenshots" / "manifest.json").write_text(
        json.dumps({
            "screenshots": [{
                "screenshot_id": "SCR-001",
                "filename": png,
                "timestamp_ms": 5_000,
                "reason": "EXPLORER_ACTION",
            }]
        }),
        encoding="utf-8",
    )
    write_visual_evidence_artifact(
        tmp_path, analysis_id="a" * 64, package_name="com.app", vide_result={}
    )
    enrich_visual_evidence_artifact(
        tmp_path,
        analysis_id="a" * 64,
        package_name="com.app",
        vide_result={
            "visual_impersonation_detected": True,
            "vide_compare": {"detected": True, "baseline_name": "HDFC"},
        },
    )
    data = json.loads((tmp_path / "visual_evidence.json").read_text(encoding="utf-8"))
    assert data["records"][0]["claim_type"] == CLAIM_VISUAL_IMPERSONATION


def test_enrichment_idempotent(tmp_path):
    png = "screenshots/i.png"
    _png(tmp_path / png)
    (tmp_path / "screenshots" / "manifest.json").write_text(
        json.dumps({
            "screenshots": [{
                "screenshot_id": "SCR-001",
                "filename": png,
                "timestamp_ms": 1_000,
                "reason": "LIFECYCLE",
                "label": "01_app_opened",
            }]
        }),
        encoding="utf-8",
    )
    kwargs = dict(analysis_id="b" * 64, package_name="com.app")
    enrich_visual_evidence_artifact(tmp_path, **kwargs)
    first = json.loads((tmp_path / "visual_evidence.json").read_text(encoding="utf-8"))
    enrich_visual_evidence_artifact(tmp_path, **kwargs)
    second = json.loads((tmp_path / "visual_evidence.json").read_text(encoding="utf-8"))
    assert first["records"] == second["records"]


def test_stale_trigger_event_unresolved(tmp_path):
    png = "screenshots/x.png"
    _png(tmp_path / png)
    (tmp_path / "screenshots" / "manifest.json").write_text(
        json.dumps({
            "screenshots": [{
                "screenshot_id": "SCR-001",
                "filename": png,
                "timestamp_ms": 1_000,
                "trigger_event": "00000000-0000-0000-0000-000000000099",
                "reason": "OVERLAY",
            }]
        }),
        encoding="utf-8",
    )
    (tmp_path / "evidence.json").write_text(json.dumps({"records": []}), encoding="utf-8")
    rec = VisualEvidenceLinker(tmp_path).link()[0]
    assert rec.correlation_status == CORRELATION_UNRESOLVED


def test_insecurebank_fixture_causal_regression(tmp_path):
    if not FIXTURE_ROOT.is_dir():
        pytest.skip("fixture artifact not present")
    shutil.copytree(FIXTURE_ROOT, tmp_path, dirs_exist_ok=True)
    records = VisualEvidenceLinker(
        tmp_path,
        analysis_id="2ebde24e",
        package_name="com.android.insecurebankv2",
    ).link()
    scr1 = next(r for r in records if r.screenshot_id == "SCR-001")
    assert scr1.correlation_status == CORRELATION_CAUSAL
    assert "EVID-001" in scr1.linked_evidence_ids
    assert scr1.claim_type == CLAIM_ANTI_ANALYSIS_UI


def test_screenshot_on_event_passes_trigger_uuid(monkeypatch, tmp_path):
    from unittest.mock import MagicMock

    from sudarshan_core.engines.screenshot_manager import ScreenshotManager

    captured = {}

    def fake_capture(self, *args, **kwargs):
        captured["trigger_evid"] = kwargs.get("trigger_evid")
        return None

    monkeypatch.setattr(ScreenshotManager, "capture", fake_capture)
    bus = MagicMock()
    mgr = ScreenshotManager(
        device_serial="emulator-5554",
        output_dir=tmp_path,
        event_bus=bus,
        evidence_store=MagicMock(count=MagicMock(return_value=1)),
    )
    mgr._on_event({
        "category": "anti_analysis",
        "data": {"severity": "HIGH"},
        "evidence_record_id": "uuid-for-hook",
    })
    mgr.wait_pending(2.0)
    assert captured.get("trigger_evid") == "uuid-for-hook"
