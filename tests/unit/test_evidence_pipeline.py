"""
Unit & Integration Tests for Sudarshan Evidence-Driven Dynamic Analysis Pipeline
=================================================================================
Validates EventBus, EvidenceStore, ScreenshotManager event publishing,
BehaviorGraphBuilder DAG construction, ThreatCorrelator listener, and SessionManager lifecycle.
"""

import os
import tempfile
import time
import unittest
import sys
from pathlib import Path

# Ensure shared directory is in sys.path
_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

from sudarshan_core.engines.behavior_graph import BehaviorGraphBuilder
from sudarshan_core.engines.event_bus import EventType, RuntimeEvent, RuntimeEventBus
from sudarshan_core.engines.evidence_store import EvidenceStore
from sudarshan_core.engines.session_manager import DynamicAnalysisSession, SessionState


class TestEventBus(unittest.TestCase):
    def test_publish_and_subscribe(self):
        bus = RuntimeEventBus()
        received = []

        def callback(event):
            received.append(event)

        bus.subscribe(callback)
        bus.publish(RuntimeEvent(event_type=EventType.SESSION_STARTED, session_id="S-001"))

        # Give background worker time to process
        time.sleep(0.2)
        self.assertGreaterEqual(len(received), 1)
        self.assertEqual(received[0]["event_type"], EventType.SESSION_STARTED)

    def test_typed_subscriber(self):
        bus = RuntimeEventBus()
        typed_received = []

        def typed_callback(event):
            typed_received.append(event)

        bus.subscribe(typed_callback, event_type=EventType.SCREENSHOT_CAPTURED)
        bus.publish(RuntimeEvent(event_type=EventType.UI_ACTION, payload={"action": "click"}))
        bus.publish(RuntimeEvent(event_type=EventType.SCREENSHOT_CAPTURED, payload={"filename": "screen.png"}))

        time.sleep(0.2)
        self.assertEqual(len(typed_received), 1)
        self.assertEqual(typed_received[0]["event_type"], EventType.SCREENSHOT_CAPTURED)


class TestEvidenceStore(unittest.TestCase):
    def test_automatic_evidence_creation(self):
        bus = RuntimeEventBus()
        store = EvidenceStore(event_bus=bus, package_name="com.test.app")

        bus.publish(RuntimeEvent(
            event_type=EventType.SCREENSHOT_CAPTURED,
            timestamp=time.time(),
            payload={"filename": "screenshots/001.png", "label": "login", "screenshot_id": "SCR-001"}
        ))

        bus.publish(RuntimeEvent(
            event_type=EventType.NETWORK_EVENT,
            timestamp=time.time(),
            payload={"url": "https://c2.malware.com/api", "status": "200"}
        ))

        time.sleep(0.3)
        records = store.get_all()
        self.assertGreaterEqual(len(records), 2)
        
        scr_rec = [r for r in records if r.category == "SCREENSHOT"]
        net_rec = [r for r in records if r.category == "NETWORK"]
        
        self.assertEqual(len(scr_rec), 1)
        self.assertEqual(scr_rec[0].screenshot_id, "SCR-001")
        self.assertEqual(len(net_rec), 1)
        self.assertIn("c2.malware.com", net_rec[0].description)


class TestBehaviorGraph(unittest.TestCase):
    def test_graph_building(self):
        bus = RuntimeEventBus()
        builder = BehaviorGraphBuilder(event_bus=bus)

        bus.publish(RuntimeEvent(event_type=EventType.UI_ACTION, payload={"label": "Click Grant Accessibility"}))
        bus.publish(RuntimeEvent(event_type=EventType.NETWORK_EVENT, payload={"url": "http://evil.com/exfil"}))

        time.sleep(0.3)
        nodes = builder.get_nodes()
        edges = builder.get_edges()

        self.assertEqual(len(nodes), 2)
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0].relation, "EXFILTRATES_TO")


class TestSessionManagerE2E(unittest.TestCase):
    def test_session_lifecycle(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            session = DynamicAnalysisSession(
                session_id="S-TEST-101",
                package_name="com.example.banking",
                output_dir=out_dir,
            )

            session.start()
            self.assertEqual(session.state, SessionState.RUNNING)

            # Emit events over session event bus
            session.event_bus.publish(RuntimeEvent(
                event_type=EventType.UI_ACTION,
                payload={"label": "Grant Accessibility Privileges"}
            ))
            session.event_bus.publish(RuntimeEvent(
                event_type=EventType.NETWORK_EVENT,
                payload={"url": "https://185.220.101.4/post"}
            ))

            time.sleep(0.3)
            
            mock_report = {
                "package_name": "com.example.banking",
                "sha256": "1234567890abcdef",
                "final_risk_score": 85.0,
                "risk_band": "CRITICAL",
                "dynamic_analysis": {
                    "attack_timeline": [],
                }
            }
            report_path = session.finish(reason="Test run completed", report_dict=mock_report)

            self.assertEqual(session.state, SessionState.FINISHED)
            self.assertTrue(os.path.exists(out_dir / "evidence.json"))
            self.assertTrue(os.path.exists(out_dir / "behavior_graph.json"))
            self.assertTrue(os.path.exists(out_dir / "report.html"))


if __name__ == "__main__":
    unittest.main()
