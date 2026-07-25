"""
Unit tests for Sudarshan BFCI v2 Scoring Engine (app.engines.bfci_scorer)
"""

import pytest
from app.engines.bfci_scorer import (
    score_component,
    detect_fraud_sequences,
    calculate_bfci_v2,
    BFCI_WEIGHTS,
    SEQUENCE_MULTIPLIER,
)

def test_score_component_empty():
    assert score_component([], "accessibility") == 0.0

def test_score_component_single_event():
    # 1 event on cap=3 should give ~50 points
    score = score_component([{"timestamp": 1000}], "accessibility")
    assert 40.0 <= score <= 60.0

def test_score_component_cap_reached():
    # 3 events on cap=3 should give 100.0 points
    events = [{"timestamp": 1000}, {"timestamp": 2000}, {"timestamp": 3000}]
    score = score_component(events, "accessibility")
    assert score == 100.0

def test_detect_fraud_sequences_none():
    events = {
        "accessibility": [{"timestamp": 1000}],
    }
    seqs = detect_fraud_sequences(events, window_s=30.0)
    assert seqs == []

def test_detect_fraud_sequences_otp_theft():
    # OTP_THEFT_CHAIN requires accessibility + sms + network within 30s
    events = {
        "accessibility": [{"timestamp": 10000}],
        "sms":           [{"timestamp": 15000}],
        "network":       [{"timestamp": 20000}],
    }
    seqs = detect_fraud_sequences(events, window_s=30.0)
    assert "OTP_THEFT_CHAIN" in seqs

def test_detect_fraud_sequences_outside_window():
    # Events > 30s apart should not trigger sequence bonus
    events = {
        "accessibility": [{"timestamp": 10000}],
        "sms":           [{"timestamp": 50000}],  # 40s later
        "network":       [{"timestamp": 90000}],  # 40s later
    }
    seqs = detect_fraud_sequences(events, window_s=30.0)
    assert "OTP_THEFT_CHAIN" not in seqs

def test_calculate_bfci_v2_with_sequence_bonus():
    events = {
        "accessibility": [{"timestamp": 10000}, {"timestamp": 11000}, {"timestamp": 12000}],
        "sms":           [{"timestamp": 13000}, {"timestamp": 14000}],
        "network":       [{"timestamp": 15000}],
    }
    score, components, evidence, sequences = calculate_bfci_v2(events)
    assert score > 0.0
    assert "OTP_THEFT_CHAIN" in sequences
    assert any("[SEQ]" in ev for ev in evidence)
