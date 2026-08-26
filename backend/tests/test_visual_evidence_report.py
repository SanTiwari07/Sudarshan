"""Report sections for visual evidence."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "shared"))

from sudarshan_core.visual_evidence.report_sections import (
    build_appendix_visual_html,
    build_executive_visual_html,
    build_technical_visual_html,
)


def _write_ver(tmp_path: Path, records: list) -> Path:
    import json

    (tmp_path / "visual_evidence.json").write_text(
        json.dumps({"records": records}),
        encoding="utf-8",
    )
    return tmp_path


def test_executive_caps_at_two_and_excludes_d(tmp_path):
    _write_ver(
        tmp_path,
        [
            {
                "screenshot_id": "SCR-001",
                "report_tier": "executive_key",
                "quality": "B",
                "correlation_status": "causal",
                "investigative_claim": "Claim one",
                "linked_evidence_ids": ["EVID-001"],
            },
            {
                "screenshot_id": "SCR-002",
                "report_tier": "executive_key",
                "quality": "A",
                "correlation_status": "linked",
                "investigative_claim": "Claim two",
            },
            {
                "screenshot_id": "SCR-003",
                "report_tier": "executive_key",
                "quality": "A",
                "correlation_status": "causal",
                "investigative_claim": "Claim three",
            },
            {
                "screenshot_id": "SCR-D",
                "report_tier": "executive_key",
                "quality": "D",
                "correlation_status": "causal",
                "investigative_claim": "Should not appear",
            },
        ],
    )
    html = build_executive_visual_html(tmp_path)
    assert "SCR-D" not in html
    # Executive frames render as full-width plates, not gallery cards.
    assert html.count('class="plate"') == 2


def test_technical_includes_ab_quality_only(tmp_path):
    _write_ver(
        tmp_path,
        [
            {
                "screenshot_id": "SCR-001",
                "quality": "B",
                "correlation_status": "causal",
                "investigative_claim": "Technical claim",
                "linked_evidence_ids": ["EVID-019"],
                "workflow_stage_label": "Phishing Overlay",
            },
            {
                "screenshot_id": "SCR-C",
                "quality": "C",
                "correlation_status": "causal",
                "investigative_claim": "Appendix only",
            },
        ],
    )
    html = build_technical_visual_html(tmp_path)
    assert "SCR-001" in html
    assert "EVID-019" in html
    assert "SCR-C" not in html


def test_appendix_quality_c_only(tmp_path):
    _write_ver(
        tmp_path,
        [
            {
                "screenshot_id": "SCR-C",
                "quality": "C",
                "report_tier": "appendix_only",
                "investigative_claim": "Lower priority context",
            },
            {
                "screenshot_id": "SCR-D",
                "quality": "D",
                "report_tier": "appendix_only",
                "investigative_claim": "Excluded",
            },
        ],
    )
    html = build_appendix_visual_html(tmp_path)
    assert "SCR-C" in html
    assert "Excluded" not in html
