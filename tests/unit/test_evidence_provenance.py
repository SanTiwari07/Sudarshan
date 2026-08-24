"""Regression tests for causal evidence provenance (§40)."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "shared"))

from sudarshan_core.engines.agentic.exploration_engine import (
    ExplorationGraph,
    EvidenceMomentType,
)
from sudarshan_core.engines.agentic.screenshot_policy import (
    ScreenshotPolicy,
    ScreenshotRequest,
    ScreenshotDecision,
)
from sudarshan_core.visual_evidence.constants import (
    CLAIM_ACCESSIBILITY_GUIDANCE,
    CLAIM_ANTI_ANALYSIS_UI,
    CLAIM_UPDATE_REQUEST,
    CLAIM_VPN_REQUEST,
    CORRELATION_CAUSAL,
    CORRELATION_TEMPORAL,
    CORRELATION_UNRESOLVED,
)
from sudarshan_core.visual_evidence.linker import VisualEvidenceLinker, _sha256_file


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


def _evidence(finding_id: str, ts: int, api: str, severity: str = "HIGH", category: str = "accessibility"):
    return {
        "finding_id": finding_id,
        "id": "uuid-" + finding_id,
        "timestamp_ms": ts,
        "api": api,
        "severity": severity,
        "category": category,
        "description": "test event",
    }


class TestEvidenceProvenanceLinker(unittest.TestCase):
    def setUp(self):
        self.artifact = Path(self._testMethodName + "_art")
        self.artifact.mkdir(exist_ok=True)
        (self.artifact / "screenshots").mkdir(exist_ok=True)

    def tearDown(self):
        import shutil
        if self.artifact.exists():
            shutil.rmtree(self.artifact, ignore_errors=True)

    def _write_case(self, shots, evidence_records):
        (self.artifact / "screenshots" / "manifest.json").write_text(
            json.dumps({"screenshots": shots}), encoding="utf-8"
        )
        (self.artifact / "evidence.json").write_text(
            json.dumps({"records": evidence_records}), encoding="utf-8"
        )

    def test_vpn_screenshot_not_linked_to_accessibility_by_proximity(self):
        png = "screenshots/vpn.png"
        _write_png(self.artifact / png, b"\x89PNG\r\n\x1a\n" + b"v" * 32)
        self._write_case(
            [
                _manifest_entry(
                    "SCR-003", 20_000, png,
                    reason="VPN_REQUEST",
                    category="evidence_moment",
                    evidence_moment_id="EVM-vpn01",
                    screen_hash="vpn_hash",
                ),
            ],
            [
                _evidence("EVID-010", 20_500, "AccessibilityManager.isEnabled", category="accessibility"),
            ],
        )
        records = VisualEvidenceLinker(self.artifact).link()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].claim_type, CLAIM_VPN_REQUEST)
        self.assertNotIn("EVID-010", records[0].linked_evidence_ids)
        self.assertNotEqual(records[0].workflow_stage_label, "Accessibility Service Activation")

    def test_update_screenshot_not_linked_to_root_detection_by_proximity(self):
        png = "screenshots/update.png"
        _write_png(self.artifact / png, b"\x89PNG\r\n\x1a\n" + b"u" * 32)
        self._write_case(
            [
                _manifest_entry(
                    "SCR-001", 10_000, png,
                    reason="UPDATE_PROMPT",
                    category="evidence_moment",
                    evidence_moment_id="EVM-upd01",
                    screen_hash="update_hash",
                ),
            ],
            [
                _evidence(
                    "EVID-001", 10_200,
                    "Debug.isDebuggerConnected",
                    category="anti_analysis",
                ),
            ],
        )
        records = VisualEvidenceLinker(self.artifact).link()
        self.assertEqual(records[0].claim_type, CLAIM_UPDATE_REQUEST)
        self.assertNotIn("EVID-001", records[0].linked_evidence_ids)
        self.assertNotEqual(records[0].claim_type, CLAIM_ANTI_ANALYSIS_UI)

    def test_causal_trigger_still_links_compatible_hook(self):
        png = "screenshots/overlay.png"
        _write_png(self.artifact / png)
        self._write_case(
            [
                _manifest_entry(
                    "SCR-002", 15_000, png,
                    reason="OVERLAY",
                    trigger_event="uuid-EVID-002",
                    screen_hash="overlay_hash",
                ),
            ],
            [
                _evidence("EVID-002", 15_000, "WindowManager.addView", category="overlay"),
            ],
        )
        records = VisualEvidenceLinker(self.artifact).link()
        self.assertIn("EVID-002", records[0].linked_evidence_ids)
        self.assertEqual(records[0].correlation_status, CORRELATION_CAUSAL)

    def test_evidence_ordered_by_event_timestamp(self):
        png_a = "screenshots/a.png"
        png_b = "screenshots/b.png"
        _write_png(self.artifact / png_a, b"\x89PNG\r\n\x1a\n" + b"a" * 32)
        _write_png(self.artifact / png_b, b"\x89PNG\r\n\x1a\n" + b"b" * 32)
        self._write_case(
            [
                _manifest_entry("SCR-004", 40_000, png_a, reason="LIFECYCLE", label="99_final"),
                _manifest_entry("SCR-002", 20_000, png_b, reason="VPN_REQUEST",
                                evidence_moment_id="EVM-1", category="evidence_moment"),
            ],
            [],
        )
        records = VisualEvidenceLinker(self.artifact).link()
        self.assertEqual([r.screenshot_id for r in records], ["SCR-002", "SCR-004"])


class TestScreenshotPolicyStateAware(unittest.TestCase):
    def test_same_screen_polled_many_times_captures_once(self):
        policy = ScreenshotPolicy(target_package="com.example.app")
        captures = 0
        for i in range(100):
            req = ScreenshotRequest(
                trigger_type="OBSERVATION",
                reason="OBSERVATION",
                foreground_package="com.example.app",
                target_package="com.example.app",
                screen_hash="same_hash",
                layout_hash="same_layout",
                state_id="ST-001",
            )
            decision, _, _ = policy.should_capture(req)
            if decision == ScreenshotDecision.CAPTURE:
                captures += 1
                policy.register_capture("SCR-001", req.ownership, "same_layout", "same_layout")
        self.assertLessEqual(captures, 1)


class TestExplorationGraphActionMatching(unittest.TestCase):
    def test_record_action_matches_by_action_id_only(self):
        graph = ExplorationGraph(package_name="com.test")
        from sudarshan_core.engines.agentic.exploration_engine import ActionItem

        state_id = "ST-test"
        graph.states[state_id] = type("S", (), {
            "state_id": state_id,
            "actionable_elements": [
                ActionItem(action_id="ACT-1", node_id="n1", action_type="click", label=""),
                ActionItem(action_id="ACT-2", node_id="n2", action_type="click", label="Install"),
            ],
            "unexplored_actions": lambda self=None: [],
            "explored": False,
        })()

        graph.record_action(
            source_state_id=state_id,
            target_state_id=state_id,
            action_type="click_text",
            target_description="Install",
            success=True,
            verified=True,
            action_id="ACT-2",
        )
        self.assertTrue(graph.states[state_id].actionable_elements[1].verified)
        self.assertFalse(graph.states[state_id].actionable_elements[0].verified)


if __name__ == "__main__":
    unittest.main()
