"""
SUDARSHAN - Fraud Workflow Reconstructor
==========================================
Deterministic causal chain engine that converts raw EvidenceStore records
into a structured FraudWorkflow.

This is the component described in the platform pitch as "turning Accessibility
+ Overlay + SMS + Network observations into a single reconstructed fraud
sequence." It does NOT exist in any earlier version of the codebase. This
module implements it.

Design principles
-----------------
1. Fully deterministic - no LLM, no randomness.
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

    # True when this stage records something the SANDBOX did, not something the
    # sample did - enabling accessibility, allowing an overlay. Preconditions
    # belong in the chain because they explain what made later behaviour
    # possible, but they are excluded from fraud detection and from chain
    # confidence: a capability we granted is not evidence against the app.
    # Defaults False so every existing rule and serialised stage is unchanged.
    is_precondition: bool = False

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
                f" - {stage.description} "
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
    is_precondition: bool = False   # Sandbox action, not sample behaviour


# Ordered by fraud workflow stage (earlier stages first).
_STAGE_RULES: List[_StageRule] = [
    _StageRule(
        label="Accessibility Service Activation",
        technique_id="T1417",
        description=(
            "Application activated an Accessibility Service to monitor "
            "screen content, extract credentials, and intercept UI events."
        ),
        # "AccessibilityManager.isEnabled" was listed here and is never emitted.
        # The obvious substitute, AccessibilityManager.sendAccessibilityEvent, is
        # deliberately NOT used: every app emits it whenever the UI changes so
        # screen readers can announce it, and both benign corpus samples fired
        # it. It would turn this rule into a detector for "app has a UI".
        trigger_hooks=[
            "AccessibilityService.onAccessibilityEvent",
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
        # View.setType/TYPE_APPLICATION_OVERLAY and Settings.canDrawOverlays are
        # gone: the agent hooks neither, and there is no near-equivalent to swap
        # in. Overlay deployment rests on WindowManager.addView, which is emitted.
        trigger_hooks=[
            "WindowManager.addView",
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
        # The agent does hook HTTP and OkHttp - under different names than the
        # two listed here, which never fired. Corrected to the emitted ones.
        trigger_hooks=[
            "URL.openConnection",
            "HttpURLConnection.getInputStream",
            "HttpsURLConnection.connect",
            "OkHttp.RealCall.execute",
            "OkHttp.RealCall.enqueue",
            "Retrofit.OkHttpCall.execute",
            "WebView.loadUrl",
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
        ],
        # "Runtime.load" is dropped rather than swapped for the emitted
        # "Runtime.exec": loading a native library and executing a shell command
        # are different techniques, and folding one into the other would make
        # this stage claim something the evidence does not show.
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
        # setActiveAdmin and setRepeating are not emitted by the agent. Measured
        # on Cerberus: it fired DevicePolicyManager.isAdminActive 47 times while
        # this rule listened for a name that never appears, which is why 0 of its
        # 103 evidence records matched any stage.
        #
        # isAdminActive is a CHECK rather than an acquisition, and is included
        # deliberately: repeatedly polling device-admin state is what a trojan
        # managing its own persistence does, the evidence store already rates it
        # HIGH, and neither benign corpus sample emits it at all.
        trigger_hooks=[
            "DevicePolicyManager.isAdminActive",
            "DevicePolicyManager.lockNow",
            "AlarmManager.setExact",
            "JobScheduler.schedule",
        ],
        category="persistence",
        confidence_base=0.85,
    ),

    _StageRule(
        label="Launcher Icon Removal",
        technique_id="T1628.001",
        description=(
            "The application removed itself from the launcher: its launcher "
            "component no longer resolves, so the user cannot find or open it "
            "again. Classic self-hiding behaviour in banking trojans."
        ),
        # Inferred from Android refusing to relaunch the component, NOT from a
        # hooked API call - the agent does not hook setComponentEnabledSetting.
        # The hook name says so, rather than implying an observation we did not
        # make.
        trigger_hooks=["launcher.component_unresolvable"],
        category="persistence",
        confidence_base=0.85,
    ),

    # ── Sandbox preconditions ────────────────────────────────────────────────
    #
    # Capabilities the HARNESS enabled so the sample could be exercised. They
    # belong in the chain because the reader otherwise cannot tell how the app
    # came to hold accessibility or overlay - but `is_precondition` keeps them
    # out of fraud detection and chain confidence. Without that flag a benign
    # app we granted accessibility to would report a fraud sequence.
    #
    # Only VERIFIED grants reach these rules: the explorer emits them from the
    # permission investigator after the device confirmed the capability is
    # actually held, so a grant that silently failed produces no stage.
    _StageRule(
        label="Accessibility Enabled by Sandbox",
        technique_id="T1417",
        description=(
            "The analysis sandbox enabled this application's Accessibility "
            "Service so accessibility-gated behaviour could be observed. This "
            "records a harness action, not application behaviour."
        ),
        trigger_hooks=["sandbox.grant.accessibility"],
        category="sandbox_precondition",
        confidence_base=1.0,
        is_precondition=True,
    ),
    _StageRule(
        label="Overlay Permission Enabled by Sandbox",
        technique_id="T1411",
        description=(
            "The analysis sandbox allowed SYSTEM_ALERT_WINDOW so overlay "
            "behaviour could be observed. Harness action, not application "
            "behaviour."
        ),
        trigger_hooks=["sandbox.grant.overlay"],
        category="sandbox_precondition",
        confidence_base=1.0,
        is_precondition=True,
    ),
    _StageRule(
        label="Runtime Permissions Granted by Sandbox",
        technique_id="T1401",
        description=(
            "The analysis sandbox granted runtime permissions the application "
            "declared, so no permission dialog was shown. Harness action, not "
            "application behaviour."
        ),
        trigger_hooks=["sandbox.grant.runtime_permission"],
        category="sandbox_precondition",
        confidence_base=1.0,
        is_precondition=True,
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
            FraudWorkflow - always non-None. fraud_sequence_detected=False
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
                is_precondition=rule.is_precondition,
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
        #
        # Only stages describing the SAMPLE's behaviour count toward detection.
        # Preconditions the sandbox performed are shown in the chain - they
        # explain what enabled later behaviour - but a capability we granted
        # ourselves must never be what makes a run look fraudulent.
        behavioural = [s for s in stages if not s.is_precondition]
        detected_labels = {s.label for s in behavioural}
        sequence_label = "BEHAVIORAL_ANOMALY" if behavioural else "PRECONDITIONS_ONLY"
        chain_confidence = round(
            sum(s.confidence for s in behavioural) / len(behavioural), 2
        ) if behavioural else 0.0

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
            fraud_sequence_detected=bool(behavioural),
            sequence_label=sequence_label,
            chain_confidence=chain_confidence,
            total_events_analyzed=len(evidence_records),
        )


# ─── Investigation-derived records ─────────────────────────────────────────────

def investigation_records(
    granted_permissions: Optional[List[str]] = None,
    accessibility_enabled: bool = False,
    overlay_granted: bool = False,
    crash_findings: Optional[List[Dict]] = None,
    base_timestamp_ms: int = 0,
) -> List[Dict]:
    """
    Turn what the investigation itself established into reconstructor records.

    The reconstructor was fed only Frida hook events, so §24's own example chain
    could not form: its first link, "Accessibility Enabled", is a capability the
    sandbox grants, not a hook the app calls. A run where we enabled
    accessibility and the sample then intercepted SMS showed the interception
    with no account of what made it reachable.

    Records use the SAME shape the reconstructor already consumes - id,
    category, hook, timestamp_ms - so no schema is introduced (§23) and every
    existing consumer is unaffected.

    Only VERIFIED grants should be passed in. A grant that reported success
    without taking effect must not appear in a causal chain, because the
    behaviour downstream of it never actually had the capability.
    """
    records: List[Dict] = []
    stamp = int(base_timestamp_ms or 0)

    def _add(hook: str, description: str, severity: str = "INFO") -> None:
        records.append({
            "id":           f"investigation_{hook}_{len(records)}",
            "category":     "sandbox_precondition",
            "hook":         hook,
            "timestamp_ms": stamp + len(records),
            "severity":     severity,
            "description":  description,
        })

    if accessibility_enabled:
        _add(
            "sandbox.grant.accessibility",
            "Accessibility service enabled by the sandbox and confirmed on device",
        )
    if overlay_granted:
        _add(
            "sandbox.grant.overlay",
            "SYSTEM_ALERT_WINDOW allowed by the sandbox and confirmed via appops",
        )
    for permission in granted_permissions or []:
        _add(
            "sandbox.grant.runtime_permission",
            f"{permission} granted by the sandbox and confirmed held",
        )

    # Crashes are carried so the chain can show that the run ended early. They
    # are not preconditions and match no stage rule; they exist here so a caller
    # merging record lists does not have to special-case them.
    for finding in crash_findings or []:
        if not isinstance(finding, dict):
            continue
        records.append({
            "id":           f"crash_{len(records)}",
            "category":     "app_telemetry",
            "hook":         "process_crash",
            "timestamp_ms": stamp + len(records),
            "severity":     str(finding.get("severity") or "INFO"),
            "description":  str(finding.get("summary") or finding.get("crash_type") or ""),
        })

    return records
