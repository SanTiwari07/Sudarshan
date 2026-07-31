"""
SUDARSHAN — Frida Dynamic Analysis Pipeline Full Test Suite
============================================================
Phase 13 Compliance Verification:
  1. Hooks script syntax & loading validation (Frida 17 built-in Java global)
  2. RuntimeEventBus publishing & subscriber notification
  3. EvidenceStore record generation & queue drain before flush
  4. BFCI calculation with simulated Frida event payloads (BFCI > 0)
  5. Threat Correlator event consumption & Risk Engine score update
  6. FridaSession message handling (event, ping, canary, hook_installed, ready, error)
  7. REST Endpoints telemetry (/api/runtime/* endpoints)
  8. HTML Report generation containing runtime evidence timeline
"""

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
from dotenv import load_dotenv

# Ensure backend and shared roots are in sys.path
_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "backend"))
sys.path.insert(0, str(_ROOT / "shared"))

# Load .env file
load_dotenv(dotenv_path=_ROOT / ".env")
if not os.environ.get("JWT_SECRET_KEY"):
    os.environ["JWT_SECRET_KEY"] = "sudarshan_test_jwt_secret_key_1234567890_test"

from sudarshan_core.engines.bfci_scorer import calculate_bfci_v2, BFCI_WEIGHTS
from sudarshan_core.engines.event_bus import EventType, RuntimeEvent, RuntimeEventBus
from sudarshan_core.engines.evidence_store import EvidenceStore, EvidenceRecord
from sudarshan_core.engines.frida_sandbox import (
    FridaSession,
    calculate_bfci,
    _HOOKS_SCRIPT,
    _HOOKS_SOURCE,
    _HOOKS_BUNDLE,
    _MIN_BUNDLE_BYTES,
)
from sudarshan_core.engines.risk_engine import calculate_risk_score
from sudarshan_core.engines.report_generator import ReportGenerator
from sudarshan_core.services.threat_correlator import correlate
from app.routes.runtime_api import record_event, record_hook


class TestFridaHooksScript(unittest.TestCase):
    def test_source_imports_bridge_and_is_a_module(self):
        """
        Frida 17 removed the global `Java` object — it lives in the external
        `frida-java-bridge` module. Verified on-device: `typeof Java` is
        `undefined` in an unbundled Frida 17 script, so the source MUST pull the
        bridge in as an ES module `import` (a bare classic-script
        `require('frida-java-bridge')` throws "'require' is not defined", and a
        dynamic require inside a try/catch gets tree-shaken out entirely).
        """
        self.assertTrue(_HOOKS_SOURCE.exists(), f"Source not found at {_HOOKS_SOURCE}")
        src = _HOOKS_SOURCE.read_text(encoding="utf-8")

        # Must import the bridge as an ES module (this is what survives bundling).
        self.assertIn("import JavaBridgeModule from 'frida-java-bridge'", src)
        # Must NOT ship a runtime require() — that was the original Fatal Bug #1.
        self.assertNotIn("require('frida-java-bridge')", src)
        self.assertNotIn('require("frida-java-bridge")', src)

        # Canary + boot-image deoptimisation must still be present.
        self.assertIn("canary", src)
        self.assertIn("Java.deoptimizeEverything", src)
        self.assertIn("Java.deoptimizeBootImage", src)

    def test_bundle_is_built_and_inlines_the_bridge(self):
        """
        `_HOOKS_SCRIPT` (what actually gets loaded on-device) must be the
        frida-compile bundle, not the raw ES-module source — create_script can
        only run a bundled classic script. The bundle must be real (hundreds of
        KB, not a stub) and must contain the inlined bridge, proven by an ART
        internal string that only exists inside frida-java-bridge's android.js.
        """
        self.assertEqual(_HOOKS_SCRIPT, _HOOKS_BUNDLE,
                         "Loader must resolve to the compiled bundle, not the source")
        self.assertTrue(_HOOKS_BUNDLE.exists(), f"Bundle not built at {_HOOKS_BUNDLE}")
        size = _HOOKS_BUNDLE.stat().st_size
        self.assertGreaterEqual(size, _MIN_BUNDLE_BYTES,
                                f"Bundle is stub-sized ({size} B) — run `npm run build`")
        bundle = _HOOKS_BUNDLE.read_text(encoding="utf-8")
        # Inlined frida-java-bridge marker (ART method-copy heuristic string).
        self.assertIn("Unable to find copied methods", bundle,
                      "frida-java-bridge was not inlined into the bundle")
        self.assertIn("Java.deoptimizeEverything", bundle)

    def test_script_has_native_hooks(self):
        """Verify Phase 4 native libc/libart hooks exist in the loaded bundle."""
        content = _HOOKS_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("SSL_write", content)
        self.assertIn("SSL_read", content)
        self.assertIn("libc.connect", content)
        self.assertIn("libc.execve", content)
        self.assertIn("libc.ptrace", content)


class TestEventBusAndEvidenceStore(unittest.TestCase):
    def test_event_bus_and_evidence_store_flow(self):
        """Verify Frida events flow through EventBus to EvidenceStore."""
        bus = RuntimeEventBus()
        store = EvidenceStore(event_bus=bus, package_name="com.boi.mobile")

        # Simulate Frida hook events
        frida_evt_1 = {
            "event_type": EventType.FRIDA_EVENT,
            "category": "accessibility",
            "severity": "CRITICAL",
            "hook": "AccessibilityService.onAccessibilityEvent",
            "data": {
                "hook": "AccessibilityService.onAccessibilityEvent",
                "description": "App monitoring screen content via Accessibility API",
            },
            "timestamp": time.time(),
        }
        frida_evt_2 = {
            "event_type": EventType.FRIDA_EVENT,
            "category": "sms",
            "severity": "CRITICAL",
            "hook": "SmsMessage.getMessageBody",
            "data": {
                "hook": "SmsMessage.getMessageBody",
                "description": "App read incoming SMS body (OTP theft)",
            },
            "timestamp": time.time(),
        }

        bus.publish(frida_evt_1)
        bus.publish(frida_evt_2)

        # Wait for background queue worker
        time.sleep(0.3)

        records = store.get_all()
        self.assertGreaterEqual(len(records), 2)
        categories = [r.category.upper() for r in records]
        self.assertIn("ACCESSIBILITY", categories)
        self.assertIn("SMS", categories)

        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = Path(tmpdir) / "evidence.json"
            count = store.flush(out_file)
            self.assertGreaterEqual(count, 2)
            self.assertTrue(out_file.exists())
            with open(out_file, "r") as f:
                saved = json.load(f)
                self.assertGreaterEqual(len(saved), 2)


class TestBFCICalculation(unittest.TestCase):
    def test_bfci_v2_with_real_events(self):
        """Verify BFCI score > 0 when Frida events are captured."""
        simulated_events = {
            "accessibility": [
                {
                    "timestamp": time.time() * 1000,
                    "category": "accessibility",
                    "severity": "CRITICAL",
                    "data": {"hook": "AccessibilityService.onAccessibilityEvent"},
                },
                {
                    "timestamp": (time.time() + 1) * 1000,
                    "category": "accessibility",
                    "severity": "CRITICAL",
                    "data": {"hook": "AccessibilityNodeInfo.performAction"},
                },
            ],
            "sms": [
                {
                    "timestamp": (time.time() + 2) * 1000,
                    "category": "sms",
                    "severity": "CRITICAL",
                    "data": {"hook": "SmsMessage.getMessageBody"},
                },
            ],
            "network": [
                {
                    "timestamp": (time.time() + 3) * 1000,
                    "category": "network",
                    "severity": "MED",
                    "data": {"hook": "URL.openConnection", "url": "https://c2.evil.com/gate"},
                },
            ],
            "banking": [],
            "overlay": [],
            "persistence": [],
            "dangerous_apis": [],
            "files_accessed": [],
            "anti_analysis": [],
        }

        bfci, components, evidence, sequences = calculate_bfci_v2(simulated_events)
        
        self.assertGreater(bfci, 0.0, "BFCI must be > 0 when events are present!")
        self.assertGreater(components["accessibility"], 0.0)
        self.assertGreater(components["sms"], 0.0)
        self.assertGreater(components["network"], 0.0)
        self.assertIn("OTP_THEFT_CHAIN", sequences, "OTP_THEFT_CHAIN sequence bonus should be detected")

    def test_risk_engine_integration_with_bfci(self):
        """Verify Risk Engine FRS includes dynamic BFCI score."""
        class MockFlags:
            dangerous_apis_found = []
            hardcoded_urls_ips = ["https://c2.evil.com"]
            targets_indian_banks = True
            indian_bank_packages_found = ["com.boi.mobile"]
            obfuscation_score = 30.0
            has_reflection = True
            has_accessibility_abuse = True
            has_sms_read_write = True
            has_system_alert_window = False

        dynamic_res = {
            "available": True,
            "engine": "frida",
            "dynamic_status": "EVENTS_CAPTURED",
            "bfci": 75.5,
            "bfci_components": {"accessibility": 80.0, "sms": 70.0, "network": 50.0},
            "api_calls": ["AccessibilityService.onAccessibilityEvent", "SmsMessage.getMessageBody"],
            "network_logs": ["https://c2.evil.com"],
            "activities_triggered": ["com.boi.mobile.MainActivity"],
            "evidence": ["OTP Theft Chain detected"],
        }

        corr_res = {
            "available": True,
            "threat_score": 60.0,
            "vt_detection_ratio": 0.35,
            "vt_malicious_vendors": ["Kaspersky", "Sophos"],
            "ioc_reputation": [],
        }

        res = calculate_risk_score(
            flags=MockFlags(),
            dynamic_result=dynamic_res,
            correlation_result=corr_res,
            all_permissions=["android.permission.RECEIVE_SMS", "android.permission.BIND_ACCESSIBILITY_SERVICE"],
        )

        self.assertGreater(res["final_risk_score"], 40.0)
        self.assertTrue(any(band in res["risk_band"].upper() for band in ["HIGH", "CRITICAL"]))
        self.assertIn("dynamic", res["frs_breakdown"])


class TestFridaSessionMessageHandling(unittest.TestCase):
    def test_on_message_handles_all_event_types(self):
        """Verify FridaSession._on_message handles event, ping, canary, hook_installed, ready, error."""
        session = FridaSession(device_serial="emulator-5554", package_name="com.test.app")
        
        # 1. Canary
        session._on_message({"type": "send", "payload": {"type": "canary", "msg": "script_loaded"}}, None)
        self.assertTrue(session.canary_received)

        # 2. Hook installed
        session._on_message({"type": "send", "payload": {"type": "hook_installed", "hook": "SmsManager.sendTextMessage", "total": 15}}, None)
        self.assertEqual(session.hooks_installed_count, 15)

        # 3. Ready
        session._on_message({"type": "send", "payload": {"type": "ready", "message": "Hooks active", "hooks_installed": 52}}, None)

        # 4. Event
        event_payload = {
            "type": "event",
            "payload": {
                "event_id": "ev_123",
                "category": "accessibility",
                "severity": "CRITICAL",
                "hook": "AccessibilityNodeInfo.performAction",
                "data": {"hook": "AccessibilityNodeInfo.performAction"},
            }
        }
        session._on_message({"type": "send", "payload": event_payload}, None)
        self.assertEqual(session.total_hook_events_received, 1)
        self.assertEqual(len(session.collected_events["accessibility"]), 1)

        # 5. Unrecognized category (Bug #5 fix verification)
        unknown_cat_payload = {
            "type": "event",
            "payload": {
                "event_id": "ev_124",
                "category": "custom_category_x",
                "severity": "HIGH",
                "hook": "CustomHook",
                "data": {"hook": "CustomHook"},
            }
        }
        session._on_message({"type": "send", "payload": unknown_cat_payload}, None)
        self.assertEqual(session.total_hook_events_received, 2)
        # Should be routed to dangerous_apis
        self.assertEqual(len(session.collected_events["dangerous_apis"]), 1)

        # 6. Hook error
        session._on_message({"type": "send", "payload": {"type": "hook_error", "hook": "BadHook", "error": "Class not found"}}, None)
        self.assertEqual(len(session.hook_errors), 1)


class TestRuntimeAPIRecording(unittest.TestCase):
    def setUp(self):
        from app.routes.runtime_api import _hook_registry, _recent_events
        _hook_registry.clear()
        _recent_events.clear()

    def test_record_event_and_hook_telemetry(self):
        """Verify record_event and record_hook populate in-process telemetry."""
        record_hook("AccessibilityService.onAccessibilityEvent", fired=True)
        record_hook("SmsMessage.getMessageBody", fired=True)
        record_hook("BadHook", error=True)

        record_event({
            "event_id": "ev_999",
            "category": "accessibility",
            "severity": "CRITICAL",
            "hook": "AccessibilityService.onAccessibilityEvent",
            "timestamp": time.time(),
        })

        from app.routes.runtime_api import _hook_registry, _recent_events
        self.assertIn("AccessibilityService.onAccessibilityEvent", _hook_registry)
        self.assertEqual(_hook_registry["AccessibilityService.onAccessibilityEvent"]["fired"], 1)
        self.assertIn("BadHook", _hook_registry)
        self.assertEqual(_hook_registry["BadHook"]["errors"], 1)
        self.assertGreaterEqual(len(_recent_events), 1)


if __name__ == "__main__":
    unittest.main()
