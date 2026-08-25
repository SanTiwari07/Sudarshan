"""
SUDARSHAN - BFCI v2 Scoring Engine
=====================================
Behavioral Fraud Confidence Index calculation with volume-aware scoring
and temporal sequence detection.

BFCI v2 improvements over v1
-----------------------------
v1 counted distinct hook *names* per category. Problems:
  - Three unrelated AccessibilityService events scored identically to a
    real OTP theft chain.
  - Any non-zero event count scored the same as many events.
  - No concept of event ordering or temporal correlation.

v2 introduces three scoring tiers:
  1. Presence tier   (base): any hook fires -> category is active.
  2. Volume tier  (multiplier): more events over time -> higher score
     up to the category cap. Uses a logarithmic scale so a single event
     is not over-penalised relative to many events.
  3. Sequence bonus: if events from multiple weighted categories occur
     within SEQUENCE_WINDOW_SECONDS in a fraud-relevant order, the BFCI
     receives a SEQUENCE_MULTIPLIER bonus (capped at 100.0).

The module is intentionally decoupled from frida_sandbox.py so every
function can be unit-tested without an active Frida session.
"""

from __future__ import annotations

import logging
import math
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ─── BFCI Weights (validated against Indian banking trojans) ──────────────────

#: Share of the model given to the code-execution axis, added after Drinik - a
#: labelled banking trojan - was observed calling ProcessBuilder.start and
#: native execve("/bin/sh") in a live run and scored BFCI 0.0, because those
#: events landed in `dangerous_apis`, which carries no weight.
#:
#: The existing six are scaled by (1 - this) rather than re-tuned. That keeps
#: their relative ordering exactly as validated against the corpus: adding an
#: axis is a claim about what was MISSING, not a reason to re-rank what was
#: already there. Every axis loses the same 10% of its share.
CODE_EXECUTION_WEIGHT: float = 0.10

_BASE_WEIGHTS: Dict[str, float] = {
    "accessibility": 0.35,   # wa - heaviest: present in 87% of banking trojans
    "sms":           0.25,   # ws - OTP theft
    "overlay":       0.20,   # wo - phishing screens
    "banking":       0.10,   # wb - confirms target is a banking app
    "network":       0.05,   # wn - C2 communication
    "persistence":   0.05,   # wp - device admin / lockdown
}

BFCI_WEIGHTS: Dict[str, float] = {
    **{k: round(v * (1.0 - CODE_EXECUTION_WEIGHT), 4)
       for k, v in _BASE_WEIGHTS.items()},
    # wx - shell execution, dynamic DEX loading, writing an APK to storage.
    # Contains only hooks an ordinary app does not reach: PathClassLoader and
    # System.loadLibrary stay in the unscored `dangerous_apis` bucket precisely
    # because every app and every app-with-native-code trigger them.
    "code_execution": CODE_EXECUTION_WEIGHT,
}

# raw_bfci is sum(weight * component) with no normalisation, so the weights
# have to sum to 1.0 or the scale silently shifts.
assert abs(sum(BFCI_WEIGHTS.values()) - 1.0) < 1e-6, (
    f"BFCI weights must sum to 1.0, got {sum(BFCI_WEIGHTS.values())}"
)

# ─── Unscored categories - collected as evidence, never scored ────────────────
#
# Membership of a SCORED category is a strong claim. The caps below are 2-3
# events with logarithmic scaling, so ONE event scores 50-63/100 for its
# component. A scored category that also catches ordinary application behaviour
# is not a weak signal - it is a constant, and it inflates every verdict equally.
#
# These categories exist so that behaviour which is worth RECORDING but is not
# by itself evidence of fraud has somewhere to go. calculate_bfci_v2 iterates
# `for cat in BFCI_WEIGHTS`, and detect_fraud_sequences skips anything not in
# it, so a category listed here is inert by construction. This tuple is
# documentation and a test anchor - nothing reads it to make a decision.
#
# Reviewer note: `device_fingerprint`, `notification` and `dangerous_apis` all
# carry real evidential value and are candidates for their own weights. Adding
# one is a MODEL CHANGE - it raises existing verdicts - and must be done against
# the labelled corpus, not by intuition. See audit/12_Frida_Agent_Audit.md §7.
UNSCORED_CATEGORIES: tuple = (
    "dangerous_apis",       # DexClassLoader, Runtime.exec, InMemoryDexClassLoader, execve
    "files_accessed",
    "anti_analysis",
    "device_fingerprint",   # IMEI / IMSI / ICCID / MSISDN, app + account enumeration
    "app_telemetry",        # activity lifecycle, keyboard, generic crypto / prefs / windows
    "notification",         # notification interception
)

assert not (set(UNSCORED_CATEGORIES) & set(BFCI_WEIGHTS)), (
    "A category cannot be both scored and unscored"
)

# ─── Scoring parameters ────────────────────────────────────────────────────────

# Per-category event count cap. Beyond this the component score is 100.0.
_CATEGORY_CAPS: Dict[str, int] = {
    "accessibility": 3,
    "sms":           2,
    "overlay":       2,
    "banking":       3,
    "network":       10,
    "persistence":   2,
    # Two events reaches the cap, matching sms/overlay/persistence. A single
    # Runtime.exec or DexClassLoader is already the whole signal - an app that
    # spawns one shell has demonstrated the capability, and spawning ten does
    # not make it ten times more true.
    "code_execution": 2,
}

# Temporal window for sequence bonus detection (seconds).
SEQUENCE_WINDOW_SECONDS: float = 30.0

# Multiplier applied to BFCI when a fraud-relevant event sequence is detected.
# 1.25 = +25% bonus capped at 100.0.
SEQUENCE_MULTIPLIER: float = 1.25

# ─── Fraud sequence definitions ───────────────────────────────────────────────
# Each entry: (label, [required_categories]) - all categories must have events
# within SEQUENCE_WINDOW_SECONDS of each other to detect the sequence.

FRAUD_SEQUENCES: List[Tuple[str, List[str]]] = [
    # OTP theft: accessibility-scraped credentials + SMS read + network exfil
    ("OTP_THEFT_CHAIN",        ["accessibility", "sms", "network"]),
    # Overlay phishing + banking app interaction
    ("OVERLAY_BANKING_CHAIN",  ["overlay", "banking"]),
    # Full account takeover: accessibility + overlay + SMS
    ("ACCOUNT_TAKEOVER_CHAIN", ["accessibility", "overlay", "sms"]),
    # Persistence + network (dropper downloading secondary payload)
    ("DROPPER_CHAIN",          ["persistence", "network"]),
]


# ─── Core scoring functions ────────────────────────────────────────────────────

def score_component(
    events: List[Dict],
    category: str,
    max_events: Optional[int] = None,
) -> float:
    """
    Convert a list of events for one category to a 0-100 component score.

    Scoring model (logarithmic):
      - 0 events  -> 0.0
      - 1 event   -> ~50.0  (sensitively detects first activity)
      - cap events -> 100.0

    The log scale avoids the v1 problem of a single event and five events
    scoring identically (both just needed distinct_hooks > 0).

    Args:
        events:     List of event dicts for this category.
        category:   Category name (used for cap lookup).
        max_events: Override cap. Defaults to _CATEGORY_CAPS[category].

    Returns:
        Component score in [0.0, 100.0].
    """
    if not events:
        return 0.0

    cap = max_events if max_events is not None else _CATEGORY_CAPS.get(category, 5)
    count = len(events)

    if cap <= 0:
        return 0.0

    # ln(count + 1) / ln(cap + 1) gives ~0.5 at count=1 for typical caps.
    raw = math.log(count + 1) / math.log(cap + 1)
    score = min(raw, 1.0) * 100.0
    return round(score, 2)


def detect_fraud_sequences(
    events_by_category: Dict[str, List[Dict]],
    window_s: float = SEQUENCE_WINDOW_SECONDS,
) -> List[str]:
    """
    Detect fraud-relevant temporal event sequences.

    For each sequence definition, check whether ALL required categories
    had at least one event whose timestamp (ms) falls within a common
    sliding window_s window.

    Returns:
        List of detected sequence labels (e.g. ["OTP_THEFT_CHAIN"]).
    """
    detected: List[str] = []

    # Build per-category sorted timestamp lists.
    all_timestamps: Dict[str, List[float]] = {}
    for cat, evts in events_by_category.items():
        if cat not in BFCI_WEIGHTS:
            continue
        times = []
        for ev in evts:
            ts = ev.get("timestamp")
            if ts is not None:
                try:
                    times.append(float(ts))
                except (TypeError, ValueError):
                    times.append(0.0)
            else:
                times.append(0.0)
        if times:
            all_timestamps[cat] = sorted(times)

    for seq_label, required_cats in FRAUD_SEQUENCES:
        # All required categories must have at least one event.
        if not all(cat in all_timestamps for cat in required_cats):
            continue

        # Anchor on each event in the first category; check whether all
        # other categories have an event within window_s.
        anchor_cat = required_cats[0]
        found_window = False
        for anchor_ts in all_timestamps[anchor_cat]:
            window_end_ms   = anchor_ts + window_s * 1000
            window_start_ms = anchor_ts - window_s * 1000

            all_in_window = True
            for other_cat in required_cats[1:]:
                cat_times = all_timestamps.get(other_cat, [])
                if not any(window_start_ms <= t <= window_end_ms for t in cat_times):
                    all_in_window = False
                    break

            if all_in_window:
                found_window = True
                break

        if found_window:
            detected.append(seq_label)
            logger.info(
                f"[BFCI] Fraud sequence detected: {seq_label} "
                f"(categories: {required_cats}, window={window_s}s)"
            )

    return detected


def calculate_bfci_v2(
    collected_events: Dict[str, List[Dict]],
) -> Tuple[float, Dict[str, float], List[str], List[str]]:
    """
    Compute the Behavioral Fraud Confidence Index (BFCI) v2.

    BFCI = (wa*A + ws*S + wo*O + wb*B + wn*N + wp*P) x sequence_multiplier

    Returns:
        Tuple of:
          (bfci_score, component_scores, evidence_list, detected_sequences)
    """
    # ── Scoring Input Pre-validation ──────────────────────────────────────────
    if collected_events is None:
        collected_events = {}
    
    assert isinstance(collected_events, dict), "collected_events must be a dict"

    # ── Component scores (volume-aware) ────────────────────────────────────────
    components: Dict[str, float] = {
        cat: score_component(collected_events.get(cat, []), cat)
        for cat in BFCI_WEIGHTS
    }

    # ── Raw BFCI (pre-sequence-bonus) ─────────────────────────────────────────
    raw_bfci = sum(BFCI_WEIGHTS[k] * v for k, v in components.items())

    # ── Temporal sequence detection ────────────────────────────────────────────
    bfci_events = {k: v for k, v in collected_events.items() if k in BFCI_WEIGHTS}
    detected_sequences = detect_fraud_sequences(bfci_events)

    if detected_sequences:
        bfci = min(raw_bfci * SEQUENCE_MULTIPLIER, 100.0)
        logger.info(
            f"[BFCI] Sequence bonus applied: {raw_bfci:.2f} x {SEQUENCE_MULTIPLIER} "
            f"-> {bfci:.2f} (sequences: {detected_sequences})"
        )
    else:
        bfci = raw_bfci

    bfci = round(min(bfci, 100.0), 2)

    # ── Evidence strings ────────────────────────────────────────────────────────
    weight_labels = {
        "accessibility": ("A", "Accessibility abuse"),
        "sms":           ("S", "SMS/OTP interception"),
        "overlay":       ("O", "Overlay window attack"),
        "banking":       ("B", "Banking app targeting"),
        "network":       ("N", "C2 network communication"),
        "persistence":   ("P", "Persistence mechanism"),
    }
    evidence: List[str] = []
    for key, (symbol, label) in weight_labels.items():
        score = components[key]
        weight = BFCI_WEIGHTS[key]
        if score > 0:
            contribution = round(weight * score, 2)
            event_count = len(collected_events.get(key, []))
            evidence.append(
                f"[{symbol}] {label}: {event_count} event(s) - "
                f"component score {score:.1f}/100 x weight {weight} = +{contribution:.1f} to BFCI"
            )
    if detected_sequences:
        evidence.append(
            f"[SEQ] Temporal fraud sequence(s): {', '.join(detected_sequences)} "
            f"x{SEQUENCE_MULTIPLIER} bonus (raw={raw_bfci:.2f}, final={bfci:.2f})"
        )

    return bfci, components, evidence, detected_sequences
