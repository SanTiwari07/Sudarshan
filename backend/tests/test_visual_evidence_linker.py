"""Tests for VisualEvidenceLinker."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "shared"))

from sudarshan_core.visual_evidence.constants import (
    CLAIM_ACCESSIBILITY_GUIDANCE,
    CLAIM_ANTI_ANALYSIS_UI,
    CLAIM_FINAL_STATE,
    CLAIM_INCONCLUSIVE_VISUAL,
    CLAIM_LAUNCH_CONTEXT,
    CLAIM_OVERLAY_OBSERVED,
    CLAIM_VISUAL_IMPERSONATION,
    CORRELATION_CAUSAL,
    CORRELATION_LINKED,
    CORRELATION_TEMPORAL,
    CORRELATION_UNRESOLVED,
    QUALITY_A,
    QUALITY_B,
    QUALITY_C,
    QUALITY_D,
)
from sudarshan_core.visual_evidence.linker import (
    VisualEvidenceLinker,
    write_visual_evidence_artifact,
    _sha256_file,
)


def _write_png(path: Path, content: bytes = b"\x89PNG\r\n\x1a\n" + b"x" * 32) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return _sha256_file(path) or ""


def _manifest_entry(scr_id: str, ts: int, filename: str, **extra) -> dict:
    return {
        "screenshot_id": scr_id,
        "filename": filename,
        "timestamp_ms": ts,
        "label": extra.get("label", "test"),
        "reason": extra.get("reason", ""),
        "source": extra.get("source", "explorer"),
        "screen_hash": extra.get("screen_hash", f"hash_{scr_id}"),
        **{k: v for k, v in extra.items() if k not in ("label", "reason", "source", "screen_hash")},
    }


def _evidence(finding_id: str, ts: int, api: str, severity: str = "CRITICAL", category: str = "overlay"):
    return {
        "finding_id": finding_id,
        "id": "uuid-" + finding_id,
        "timestamp_ms": ts,
        "api": api,
        "severity": severity,
        "category": category,
        "description": "test event",
    }


@pytest.fixture
def artifact(tmp_path):
    shots = tmp_path / "screenshots"
    shots.mkdir()
    return tmp_path


def test_overlay_correlation(artifact):
    png = "screenshots/001_overlay.png"
    _write_png(artifact / png)
    manifest = {
        "screenshots": [
            _manifest_entry("SCR-001", 10_000, png, reason="OVERLAY"),
        ]
    }
    (artifact / "screenshots" / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    evidence = {
        "records": [
            _evidence("EVID-001", 10_500, "WindowManager.addView"),
        ]
    }
    (artifact / "evidence.json").write_text(json.dumps(evidence), encoding="utf-8")

    records = VisualEvidenceLinker(artifact).link()
    assert len(records) == 1
    assert records[0].claim_type == CLAIM_OVERLAY_OBSERVED
    assert records[0].correlation_status == CORRELATION_TEMPORAL
    assert "EVID-001" in records[0].linked_evidence_ids
    assert records[0].quality == QUALITY_B
    assert len(records[0].png_sha256) == 64


def test_sms_hook_does_not_create_visual_claim_on_hook(artifact):
    png = "screenshots/001.png"
    _write_png(artifact / png)
    (artifact / "screenshots" / "manifest.json").write_text(
        json.dumps({"screenshots": [_manifest_entry("SCR-001", 5_000, png)]}),
        encoding="utf-8",
    )
    (artifact / "evidence.json").write_text(
        json.dumps({
            "records": [
                _evidence("EVID-001", 5_100, "SmsMessage.getMessageBody", category="sms"),
            ]
        }),
        encoding="utf-8",
    )
    records = VisualEvidenceLinker(artifact).link()
    assert records[0].linked_evidence_ids == []
    assert records[0].claim_type == CLAIM_INCONCLUSIVE_VISUAL


def test_accessibility_correlation(artifact):
    png = "screenshots/001.png"
    _write_png(artifact / png)
    (artifact / "screenshots" / "manifest.json").write_text(
        json.dumps({"screenshots": [_manifest_entry("SCR-001", 20_000, png)]}),
        encoding="utf-8",
    )
    (artifact / "evidence.json").write_text(
        json.dumps({
            "records": [
                _evidence(
                    "EVID-002",
                    20_200,
                    "AccessibilityManager.isEnabled",
                    severity="HIGH",
                    category="accessibility",
                ),
            ]
        }),
        encoding="utf-8",
    )
    records = VisualEvidenceLinker(artifact).link()
    assert records[0].claim_type == CLAIM_ACCESSIBILITY_GUIDANCE
    assert "EVID-002" in records[0].linked_evidence_ids


def test_max_three_evid_links(artifact):
    shots = []
    for i in range(1, 6):
        png = f"screenshots/{i:03d}.png"
        _write_png(artifact / png)
        shots.append(_manifest_entry(f"SCR-{i:03d}", 30_000 + i * 100, png, screen_hash=f"h{i}"))
    (artifact / "screenshots" / "manifest.json").write_text(
        json.dumps({"screenshots": shots}), encoding="utf-8"
    )
    evs = [
        _evidence(f"EVID-{i:03d}", 30_050, "WindowManager.addView")
        for i in range(1, 6)
    ]
    (artifact / "evidence.json").write_text(json.dumps({"records": evs}), encoding="utf-8")
    records = VisualEvidenceLinker(artifact).link()
    linked_scr = next(r for r in records if r.screenshot_id == "SCR-001")
    assert len(linked_scr.linked_evidence_ids) <= 3


def test_timestamp_selection_prefers_closer(artifact):
    png1 = "screenshots/a.png"
    png2 = "screenshots/b.png"
    _write_png(artifact / png1)
    _write_png(artifact / png2)
    (artifact / "screenshots" / "manifest.json").write_text(
        json.dumps({
            "screenshots": [
                _manifest_entry("SCR-001", 40_000, png1, screen_hash="h1"),
                _manifest_entry("SCR-002", 50_000, png2, screen_hash="h2"),
            ]
        }),
        encoding="utf-8",
    )
    (artifact / "evidence.json").write_text(
        json.dumps({"records": [_evidence("EVID-001", 40_800, "WindowManager.addView")]}),
        encoding="utf-8",
    )
    records = VisualEvidenceLinker(artifact).link()
    by_id = {r.screenshot_id: r for r in records}
    assert "EVID-001" in by_id["SCR-001"].linked_evidence_ids
    assert "EVID-001" not in by_id["SCR-002"].linked_evidence_ids


def test_screen_hash_preference(artifact):
    png1 = "screenshots/a.png"
    png2 = "screenshots/b.png"
    _write_png(artifact / png1)
    _write_png(artifact / png2)
    (artifact / "screenshots" / "manifest.json").write_text(
        json.dumps({
            "screenshots": [
                _manifest_entry("SCR-001", 60_000, png1, screen_hash="match"),
                _manifest_entry("SCR-002", 60_100, png2, screen_hash="other"),
            ]
        }),
        encoding="utf-8",
    )
    (artifact / "evidence.json").write_text(
        json.dumps({
            "records": [
                {
                    **_evidence("EVID-001", 60_050, "WindowManager.addView"),
                    "extra": {"screen_hash": "match"},
                }
            ]
        }),
        encoding="utf-8",
    )
    records = VisualEvidenceLinker(artifact).link()
    by_id = {r.screenshot_id: r for r in records}
    assert "EVID-001" in by_id["SCR-001"].linked_evidence_ids


def test_lifecycle_launch_and_final(artifact):
    launch_png = "screenshots/launch.png"
    final_png = "screenshots/final.png"
    _write_png(artifact / launch_png)
    _write_png(artifact / final_png)
    (artifact / "screenshots" / "manifest.json").write_text(
        json.dumps({
            "screenshots": [
                _manifest_entry(
                    "SCR-001", 1_000, launch_png,
                    label="01_app_opened", reason="LIFECYCLE",
                ),
                _manifest_entry(
                    "SCR-002", 99_000, final_png,
                    label="99_final_screen", reason="LIFECYCLE",
                ),
            ]
        }),
        encoding="utf-8",
    )
    records = VisualEvidenceLinker(artifact).link()
    by_id = {r.screenshot_id: r for r in records}
    assert by_id["SCR-001"].claim_type == CLAIM_LAUNCH_CONTEXT
    assert by_id["SCR-002"].claim_type == CLAIM_FINAL_STATE
    assert by_id["SCR-001"].quality == QUALITY_C


def test_missing_png_quality_d(artifact):
    (artifact / "screenshots" / "manifest.json").write_text(
        json.dumps({
            "screenshots": [_manifest_entry("SCR-001", 1_000, "screenshots/missing.png")],
        }),
        encoding="utf-8",
    )
    records = VisualEvidenceLinker(artifact).link()
    assert records[0].png_sha256 == ""
    assert records[0].quality == QUALITY_D


def test_duplicate_screen_hash_quality_d(artifact):
    png1 = "screenshots/a.png"
    png2 = "screenshots/b.png"
    _write_png(artifact / png1)
    _write_png(artifact / png2)
    (artifact / "screenshots" / "manifest.json").write_text(
        json.dumps({
            "screenshots": [
                _manifest_entry("SCR-001", 1_000, png1, screen_hash="same"),
                _manifest_entry("SCR-002", 2_000, png2, screen_hash="same"),
            ]
        }),
        encoding="utf-8",
    )
    records = VisualEvidenceLinker(artifact).link()
    dup = next(r for r in records if r.screenshot_id == "SCR-002")
    assert dup.quality == QUALITY_D


def test_vide_correlation(artifact):
    png = "screenshots/v.png"
    _write_png(artifact / png)
    (artifact / "screenshots" / "manifest.json").write_text(
        json.dumps({"screenshots": [_manifest_entry("SCR-001", 8_000, png)]}),
        encoding="utf-8",
    )
    records = VisualEvidenceLinker(
        artifact,
        vide_result={
            "visual_impersonation_detected": True,
            "vide_compare": {"detected": True, "baseline_name": "HDFC", "baseline_id": "hdfc-1"},
        },
    ).link()
    assert records[0].claim_type == CLAIM_VISUAL_IMPERSONATION
    assert records[0].vide_rule_id


def test_no_match_unresolved(artifact):
    png = "screenshots/x.png"
    _write_png(artifact / png)
    (artifact / "screenshots" / "manifest.json").write_text(
        json.dumps({
            "screenshots": [
                _manifest_entry("SCR-001", 5_000, png, label="random", reason="EXPLORER_ACTION"),
            ]
        }),
        encoding="utf-8",
    )
    records = VisualEvidenceLinker(artifact).link()
    assert records[0].correlation_status == CORRELATION_UNRESOLVED
    assert records[0].linked_evidence_ids == []


def test_write_visual_evidence_artifact(artifact):
    png = "screenshots/w.png"
    _write_png(artifact / png)
    (artifact / "screenshots" / "manifest.json").write_text(
        json.dumps({"screenshots": [_manifest_entry("SCR-001", 1_000, png)]}),
        encoding="utf-8",
    )
    n = write_visual_evidence_artifact(
        artifact, analysis_id="abc" * 21 + "a", package_name="com.test"
    )
    assert n == 1
    data = json.loads((artifact / "visual_evidence.json").read_text(encoding="utf-8"))
    assert data["schema_version"] == 1
    assert len(data["records"]) == 1
    assert "proves" not in data["records"][0]["investigative_claim"].lower()


def test_evidence_json_updated_with_links(artifact):
    png = "screenshots/l.png"
    _write_png(artifact / png)
    (artifact / "screenshots" / "manifest.json").write_text(
        json.dumps({"screenshots": [_manifest_entry("SCR-001", 10_000, png)]}),
        encoding="utf-8",
    )
    (artifact / "evidence.json").write_text(
        json.dumps({"records": [_evidence("EVID-001", 10_200, "WindowManager.addView")]}),
        encoding="utf-8",
    )
    write_visual_evidence_artifact(artifact, analysis_id="x" * 64, package_name="com.app")
    ev = json.loads((artifact / "evidence.json").read_text(encoding="utf-8"))
    row = ev["records"][0]
    assert row["screenshot_id"] == "SCR-001"
    assert row["screenshot_ref"] == png


def test_causal_trigger_event_uuid_ignores_timestamp_gap(artifact):
    evid_uuid = "b9995dbf-f23a-4c1a-978f-3b4b40c86a13"
    png = "screenshots/001_anti.png"
    _write_png(artifact / png)
    (artifact / "screenshots" / "manifest.json").write_text(
        json.dumps({
            "screenshots": [
                _manifest_entry(
                    "SCR-001",
                    1_785_998_517_533,
                    png,
                    reason="ROOT_DETECTION",
                    trigger_event=evid_uuid,
                ),
            ]
        }),
        encoding="utf-8",
    )
    (artifact / "evidence.json").write_text(
        json.dumps({
            "records": [
                {
                    "id": evid_uuid,
                    "finding_id": "EVID-001",
                    "timestamp_ms": 1_785_997_432_137,
                    "category": "anti_analysis",
                    "severity": "HIGH",
                    "api": "Build.<static fields>",
                    "description": "anti-analysis",
                    "extra": {},
                }
            ]
        }),
        encoding="utf-8",
    )
    records = VisualEvidenceLinker(artifact).link()
    assert records[0].correlation_status == CORRELATION_CAUSAL
    assert records[0].linked_evidence_ids == ["EVID-001"]
    assert records[0].claim_type == CLAIM_ANTI_ANALYSIS_UI
