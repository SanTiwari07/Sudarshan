"""
SUDARSHAN — Fraud Workflow Reconstructor
==========================================
Deterministic causal chain engine that converts raw EvidenceStore records
into a structured FraudWorkflow.

This is the component described in the platform pitch as "turning Accessibility
+ Overlay + SMS + Network observations into a single reconstructed fraud
sequence." It does NOT exist in any earlier version of the codebase. This
module implements it.

Design principles
-----------------
1. Fully deterministic — no LLM, no randomness.
2. Rule-based: causal chain rules defined as a declarative table, not
   hardcoded if/else branches. New rules require only a new table entry.
3. Consumes EvidenceRecord objects from EvidenceStore (or a plain dict list
   when EvidenceStore is unavailable).
4. Outputs a FraudWorkflow dataclass that is JSON-serialisable and can be
   indexed directly by the Gemini RAG engine.

Usage
-----
    from sudarshan_core.engines.workflow_reconstructor import WorkflowReconstructor

    reconstructor = WorkflowReconstructor()
    workflow = reconstructor.reconstruct(evidence_records)
    workflow_dict = workflow.to_dict()
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ─── Output data model ─────────────────────────────────────────────────────────

@dataclass
class WorkflowStage:
    """A single causal stage in a reconstructed fraud workflow."""
    label:        str            # Human-readable stage name
    technique_id: str            # MITRE ATT&CK for Mobile technique ID
    description:  str            # Plain-English description
    start_ms:     int            # Earliest event timestamp in stage (ms)
    end_ms:       int            # Latest event timestamp in stage (ms)
    evidence_ids: List[str]      # EvidenceRecord IDs that constitute this stage
    hook_names:   List[str]      # Hook names that fired
    confidence:   float          # 0.0–1.0 confidence based on evidence strength

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class FraudWorkflow:
    """
    A reconstructed behavioral fraud workflow derived from runtime evidence.

    Represents the causal sequence of actions an app performed during
    dynamic analysis, expressed as an ordered list of WorkflowStage objects.
    """
    stages:                  List[WorkflowStage]
    fraud_sequence_detected: bool
    sequence_label:          str    # Highest-confidence detected chain
    chain_confidence:        float  # Overall chain confidence (avg of stages)
    total_events_analyzed:   int

    def to_dict(self) -> Dict:
        return {
            "stages":                  [s.to_dict() for s in self.stages],
            "fraud_sequence_detected": self.fraud_sequence_detected,
            "sequence_label":          self.sequence_label,
            "chain_confidence":        self.chain_confidence,
            "total_events_analyzed":   self.total_events_analyzed,
            "stage_count":             len(self.stages),
        }

    def to_narrative(self) -> str:
        """Return a plain-English summary for the RAG evidence index."""
        if not self.fraud_sequence_detected:
            return (
                "No fraud workflow was reconstructed from dynamic evidence. "
                "Either no behavioral hooks fired or the evidence is insufficient "
                "to establish a causal chain."
            )

        lines = [
            f"Fraud Workflow: {self.sequence_label} "
            f"(confidence: {self.chain_confidence:.0%})",
            f"Stages detected: {len(self.stages)}",
            "",
        ]
        for i, stage in enumerate(self.stages, 1):
            duration_s = (stage.end_ms - stage.start_ms) / 1000
            lines.append(
                f"  Stage {i}: {stage.label} [{stage.technique_id}] "
                f"— {stage.description} "
                f"({len(stage.evidence_ids)} events, {duration_s:.1f}s duration, "
                f"confidence={stage.confidence:.0%})"
            )
        return "\n".join(lines)


# ─── Causal chain rules ────────────────────────────────────────────────────────
# Each rule defines one WorkflowStage. The rule fires when a trigger event
# (hook name) is observed. The stage label, MITRE ID, and description are
# then attributed to that event cluster.

@dataclass
class _StageRule:
    label:          str
    technique_id:   str
    description:    str
    trigger_hooks:  List[str]   # Any one of these hooks fires the rule
    category:       str         # Primary evidence category
    confidence_base: float      # Base confidence when trigger fires (0–1)


# Ordered by fraud workflow stage (earlier stages first).
_STAGE_RULES: List[_StageRule] = [
    _StageRule(
        label="Accessibility Service Activation",
        technique_id="T1417",
        description=(
            "Application activated an Accessibility Service to monitor "
            "screen content, extract credentials, and intercept UI events."
        ),
        trigger_hooks=[
            "AccessibilityService.onAccessibilityEvent",
            "AccessibilityManager.isEnabled",
        ],
        category="accessibility",
        confidence_base=0.85,
    ),
    _StageRule(
        label="UI Credential Scraping",
        technique_id="T1417",
        description=(
            "Application extracted text from UI elements using Accessibility "
            "API, likely to harvest credentials or OTP values."
        ),
        trigger_hooks=[
            "AccessibilityNodeInfo.getText",
            "AccessibilityNodeInfo.performAction",
        ],
        category="accessibility",
        confidence_base=0.80,
    ),
    _StageRule(
        label="Phishing Overlay Deployment",
        technique_id="T1411",
        description=(
            "Application drew a system-level overlay window on top of a "
            "legitimate banking application to capture credentials."
        ),
        trigger_hooks=[
            "WindowManager.addView",
            "View.setType/TYPE_APPLICATION_OVERLAY",
            "Settings.canDrawOverlays",
        ],
        category="overlay",
        confidence_base=0.90,
    ),
    _StageRule(
        label="SMS / OTP Interception",
        technique_id="T1412",
        description=(
            "Application read or monitored incoming SMS messages, "
            "likely to intercept OTP codes sent by banking services."
        ),
        trigger_hooks=[
            "SmsMessage.getMessageBody",
            "ContentResolver.query",
        ],
        category="sms",
        confidence_base=0.90,
    ),
    _StageRule(
        label="SMS Forwarding / Exfiltration",
        technique_id="T1412",
        description=(
            "Application sent an SMS message, likely forwarding intercepted "
            "OTP codes or credentials to the attacker's device."
        ),
        trigger_hooks=[
            "SmsManager.sendTextMessage",
            "SmsManager.sendMultipartTextMessage",
        ],
        category="sms",
        confidence_base=0.95,
    ),
    _StageRule(
        label="Banking App Detection",
        technique_id="T1418",
        description=(
            "Application enumerated installed banking applications to identify "
            "targets for overlay phishing or credential theft."
        ),
        trigger_hooks=[
            "PackageManager.getInstalledPackages",
            "PackageManager.getInstalledApplications",
            "PackageManager.queryIntentActivities",
        ],
        category="banking",
        confidence_base=0.75,
    ),
    _StageRule(
        label="C2 Network Communication",
        technique_id="T1623",
        description=(
            "Application established a network connection to a command-and-control "
            "endpoint, likely to exfiltrate harvested data or receive instructions."
        ),
        trigger_hooks=[
            "URL.openConnection",
            "HttpURLConnection.connect",
            "OkHttpClient.newCall",
            "Socket.connect",
        ],
        category="network",
        confidence_base=0.70,
    ),
    _StageRule(
        label="Dynamic Code Loading",
        technique_id="T1623",
        description=(
            "Application loaded external DEX bytecode at runtime, suggesting "
            "a dropper mechanism or evasion of static analysis."
        ),
        trigger_hooks=[
            "DexClassLoader.<init>",
            "PathClassLoader.<init>",
            "InMemoryDexClassLoader.<init>",
            "Runtime.load",
        ],
        category="dangerous_apis",
        confidence_base=0.80,
    ),
    _StageRule(
        label="Persistence / Device Admin",
        technique_id="T1624",
        description=(
            "Application requested Device Administrator privileges or scheduled "
            "persistent background execution to survive reboots."
        ),
        trigger_hooks=[
            "DevicePolicyManager.setActiveAdmin",
            "AlarmManager.setRepeating",
            "JobScheduler.schedule",
        ],
        category="persistence",
        confidence_base=0.85,
    ),
]

# ─── Sequence labels for the overall workflow ──────────────────────────────────
# Maps sets of detected stage labels to a composite sequence name.
_CHAIN_LABELS: List[Tuple[str, List[str]]] = [
    ("FULL_ACCOUNT_TAKEOVER", [
        "Accessibility Service Activation",
        "Phishing Overlay Deployment",
        "SMS / OTP Interception",
        "C2 Network Communication",
    ]),
    ("OTP_THEFT_CHAIN", [
        "Accessibility Service Activation",
        "SMS / OTP Interception",
        "C2 Network Communication",
    ]),
    ("OVERLAY_PHISHING_CHAIN", [
        "Phishing Overlay Deployment",
        "Banking App Detection",
    ]),
    ("DROPPER_CHAIN", [
        "Dynamic Code Loading",
        "C2 Network Communication",
    ]),
    ("CREDENTIAL_SCRAPE", [
        "UI Credential Scraping",
        "C2 Network Communication",
    ]),
]


# ─── WorkflowReconstructor ────────────────────────────────────────────────────

class WorkflowReconstructor:
    """
    Converts raw evidence records into a structured FraudWorkflow.

    Usage:
        reconstructor = WorkflowReconstructor()
        workflow = reconstructor.reconstruct(evidence_records_list)
    """

    def reconstruct(
        self,
        evidence_records: List[Dict],
    ) -> FraudWorkflow:
        """
        Build a FraudWorkflow from a list of evidence record dicts.

        Each record must have at minimum:
            {
                "id":           str,        # unique evidence ID
                "category":     str,        # e.g. "accessibility"
                "hook":         str,        # e.g. "AccessibilityService.onAccessibilityEvent"
                "timestamp_ms": int,        # epoch ms
            }

        Records from EvidenceStore.get_all_records() already have this shape.

        Returns:
            FraudWorkflow — always non-None. fraud_sequence_detected=False
            when no evidence is present or no rules fire.
        """
        if not evidence_records:
            return FraudWorkflow(
                stages=[],
                fraud_sequence_detected=False,
                sequence_label="NONE",
                chain_confidence=0.0,
                total_events_analyzed=0,
            )

        # Sort by timestamp
        sorted_records = sorted(
            evidence_records,
            key=lambda r: r.get("timestamp_ms", 0)
        )

        stages: List[WorkflowStage] = []
        seen_rule_labels: set = set()  # Avoid duplicate stages

        for rule in _STAGE_RULES:
            matching = [
                r for r in sorted_records
                if r.get("hook", "") in rule.trigger_hooks
                or r.get("category", "") == rule.category
                and r.get("hook", "") in rule.trigger_hooks
            ]

            if not matching or rule.label in seen_rule_labels:
                continue

            seen_rule_labels.add(rule.label)
            timestamps = [r.get("timestamp_ms", 0) for r in matching]
            evidence_ids = [r.get("id", "") for r in matching]
            hook_names = list({r.get("hook", "") for r in matching})

            # Scale confidence by evidence volume (more events = more certain)
            count_factor = min(len(matching) / 3.0, 1.0)
            confidence = round(
                rule.confidence_base * 0.7 + count_factor * rule.confidence_base * 0.3,
                2
            )

            stages.append(WorkflowStage(
                label=rule.label,
                technique_id=rule.technique_id,
                description=rule.description,
                start_ms=min(timestamps),
                end_ms=max(timestamps),
                evidence_ids=evidence_ids,
                hook_names=hook_names,
                confidence=confidence,
            ))

        if not stages:
            return FraudWorkflow(
                stages=[],
                fraud_sequence_detected=False,
                sequence_label="NONE",
                chain_confidence=0.0,
                total_events_analyzed=len(evidence_records),
            )

        # ── Detect composite chain label ───────────────────────────────────────
        detected_labels = {s.label for s in stages}
        sequence_label = "BEHAVIORAL_ANOMALY"  # Default when stages exist but no named chain
        chain_confidence = round(
            sum(s.confidence for s in stages) / len(stages), 2
        )

        for chain_name, required_stages in _CHAIN_LABELS:
            if all(lbl in detected_labels for lbl in required_stages):
                sequence_label = chain_name
                logger.info(
                    f"[WorkflowReconstructor] Chain detected: {chain_name} "
                    f"(stages: {required_stages})"
                )
                break

        logger.info(
            f"[WorkflowReconstructor] Reconstruction complete: "
            f"{len(stages)} stages, sequence={sequence_label}, "
            f"confidence={chain_confidence:.0%}"
        )

        return FraudWorkflow(
            stages=stages,
            fraud_sequence_detected=True,
            sequence_label=sequence_label,
            chain_confidence=chain_confidence,
            total_events_analyzed=len(evidence_records),
        )
