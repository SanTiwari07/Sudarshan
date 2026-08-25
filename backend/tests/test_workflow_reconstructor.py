"""
Unit tests for Sudarshan Fraud Workflow Reconstructor (sudarshan_core.engines.workflow_reconstructor)
"""

import pytest
from sudarshan_core.engines.workflow_reconstructor import WorkflowReconstructor, FraudWorkflow

def test_reconstruct_empty():
    recon = WorkflowReconstructor()
    wf = recon.reconstruct([])
    assert isinstance(wf, FraudWorkflow)
    assert not wf.fraud_sequence_detected
    assert wf.stages == []
    assert wf.sequence_label == "NONE"

def test_reconstruct_otp_theft_chain():
    records = [
        {
            "id": "1",
            "category": "accessibility",
            "hook": "AccessibilityService.onAccessibilityEvent",
            "timestamp_ms": 1000,
        },
        {
            "id": "2",
            "category": "sms",
            "hook": "SmsMessage.getMessageBody",
            "timestamp_ms": 2000,
        },
        {
            "id": "3",
            "category": "network",
            "hook": "OkHttp.RealCall.execute",
            "timestamp_ms": 3000,
        },
    ]
    recon = WorkflowReconstructor()
    wf = recon.reconstruct(records)

    assert wf.fraud_sequence_detected
    assert wf.sequence_label == "OTP_THEFT_CHAIN"
    assert len(wf.stages) == 3
    labels = [s.label for s in wf.stages]
    assert "Accessibility Service Activation" in labels
    assert "SMS / OTP Interception" in labels
    assert "C2 Network Communication" in labels

def test_reconstruct_narrative():
    records = [
        {
            "id": "1",
            "category": "overlay",
            "hook": "WindowManager.addView",
            "timestamp_ms": 1000,
        },
        {
            "id": "2",
            "category": "banking",
            "hook": "PackageManager.getInstalledPackages",
            "timestamp_ms": 1500,
        },
    ]
    recon = WorkflowReconstructor()
    wf = recon.reconstruct(records)
    narrative = wf.to_narrative()
    assert "OVERLAY_PHISHING_CHAIN" in narrative
    assert "Phishing Overlay Deployment" in narrative
