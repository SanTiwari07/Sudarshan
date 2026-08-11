"""Regression: Frida hook event → RuntimeEventBus → EvidenceStore with case_id."""

import time

from sudarshan_core.engines.event_bus import EventType, RuntimeEventBus
from sudarshan_core.engines.evidence_store import EvidenceStore


def test_frida_event_reaches_evidence_store_with_case_id():
    bus = RuntimeEventBus()
    store = EvidenceStore(
        event_bus=bus,
        package_name="com.example.malware",
        case_id="abc123deadbeef",
    )

    bus.publish(
        {
            "event_type": EventType.FRIDA_EVENT,
            "timestamp": time.time(),
            "category": "sms",
            "severity": "HIGH",
            "payload": {
                "hook": "SmsManager.sendTextMessage",
                "class": "android.telephony.SmsManager",
                "method": "sendTextMessage",
            },
            "data": {"hook": "SmsManager.sendTextMessage"},
        }
    )

    assert bus.drain(2.0)
    assert len(store._records) >= 1
    rec = store._records[0]
    assert rec.runtime_context.get("sha256") == "abc123deadbeef"
    assert rec.runtime_context.get("case_id") == "abc123deadbeef"
    assert rec.api or rec.description
